import { errMessage, log } from '../log.js';
import { BackendError, isOutage } from './http.js';
import type { BackendHealth, BackendModule, ConnectionResult, HealthCheck, HealthStatus } from './types.js';

/**
 * Backend health (DESIGN §3.4): a scheduled `health(rt)` per enabled backend,
 * and a gate in front of every backend call with a concurrency limit and a
 * circuit breaker, so a hung or failing backend cannot tie up request slots
 * and a model can tell "backend down" from "no results".
 */

/** How long a health result is reused before the backend is asked again. */
export const HEALTH_TTL_MS = 60_000;
/** How often the scheduler re-checks every enabled backend. */
export const HEALTH_INTERVAL_MS = 60_000;
/** A health check that takes longer than this counts as down. */
export const HEALTH_TIMEOUT_MS = 10_000;

const RANK: Record<HealthStatus, number> = { ok: 0, degraded: 1, down: 2 };

/** The worst of several statuses (`ok` for none). */
export function worst(statuses: HealthStatus[]): HealthStatus {
  return statuses.reduce<HealthStatus>((w, s) => (RANK[s] > RANK[w] ? s : w), 'ok');
}

/** Builds a result whose overall status is the worst of its checks. */
export function fromChecks(checks: HealthCheck[]): BackendHealth {
  return { status: worst(checks.map((c) => c.status)), checks };
}

/** Health for modules without `health()`: one check from the connection test. */
export function fromConnection(r: ConnectionResult): BackendHealth {
  return fromChecks([{ name: 'connection', status: r.ok ? 'ok' : 'down', message: r.message }]);
}

/** Runs one probe and turns a throw into a `down` check. */
export async function probe(name: string, fn: () => Promise<string | Omit<HealthCheck, 'name'>>): Promise<HealthCheck> {
  try {
    const r = await fn();
    return typeof r === 'string' ? { name, status: 'ok', message: r } : { name, ...r };
  } catch (err) {
    return { name, status: 'down', message: errMessage(err) };
  }
}

export function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`No answer within ${ms / 1000} s`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

export interface HealthSnapshot {
  health: BackendHealth;
  /** When the check finished (ms since epoch). */
  at: number;
}

interface Entry {
  at: number;
  health?: BackendHealth;
  pending?: Promise<BackendHealth>;
}

/**
 * Runs health checks. Results are cached per runtime object: the registry
 * builds a new runtime whenever a backend's settings change, so a settings
 * change is re-checked on the next request without explicit invalidation.
 * Concurrent requests share one check.
 */
export class HealthMonitor {
  private entries = new WeakMap<object, Entry>();
  private timer?: NodeJS.Timeout;

  constructor(
    private readonly ttlMs = HEALTH_TTL_MS,
    private readonly timeoutMs = HEALTH_TIMEOUT_MS,
  ) {}

  /** Last result without triggering a check, or undefined if none has finished yet. */
  peek(runtime: object): HealthSnapshot | undefined {
    const e = this.entries.get(runtime);
    return e?.health ? { health: e.health, at: e.at } : undefined;
  }

  async check(mod: BackendModule<any, any>, runtime: object, force = false): Promise<HealthSnapshot> {
    let e = this.entries.get(runtime);
    if (e?.pending) {
      const health = await e.pending;
      return { health, at: e.at };
    }
    if (e?.health && !force && Date.now() - e.at < this.ttlMs) return { health: e.health, at: e.at };
    if (!e) {
      e = { at: 0 };
      this.entries.set(runtime, e);
    }
    const entry = e;
    const run = mod.health ? mod.health(runtime) : mod.testConnection(runtime).then(fromConnection);
    entry.pending = withTimeout(run, this.timeoutMs)
      .catch((err): BackendHealth => fromChecks([{ name: 'health', status: 'down', message: errMessage(err) }]))
      .then((health) => {
        entry.health = health;
        entry.at = Date.now();
        entry.pending = undefined;
        return health;
      });
    return { health: await entry.pending, at: entry.at };
  }

  /**
   * Re-checks every backend `list()` returns, now and then every
   * `intervalMs`. Errors are logged, never thrown. Idempotent.
   */
  start(list: () => { mod: BackendModule<any, any>; runtime: unknown }[], intervalMs = HEALTH_INTERVAL_MS): void {
    if (this.timer) return;
    const tick = () => {
      for (const { mod, runtime } of list()) {
        if (mod.maturity !== 'ready') continue;
        this.check(mod, runtime as object, true).catch((err) => log.warn('Health check failed', { backend: mod.id, error: errMessage(err) }));
      }
    };
    tick();
    this.timer = setInterval(tick, intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }
}

// ---------------------------------------------------------------- gate

export class GateRejected extends Error {
  constructor(
    message: string,
    /** The same without the backend's own error text. */
    readonly publicMessage = message,
  ) {
    super(message);
  }
}

export interface GateOptions {
  /** Calls running against the backend at once. */
  concurrency: number;
  /** Calls waiting for a slot before new ones are refused. */
  maxQueue: number;
  /** How long a call may wait for a slot. */
  queueTimeoutMs: number;
  /** Consecutive failures that open the circuit. */
  failureThreshold: number;
  /** How long the circuit stays open before one trial call is let through. */
  openMs: number;
}

export const DEFAULT_GATE: GateOptions = {
  concurrency: 4,
  maxQueue: 16,
  queueTimeoutMs: 15_000,
  failureThreshold: 5,
  openMs: 30_000,
};

export type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Per-backend concurrency limit plus circuit breaker. After
 * `failureThreshold` consecutive failures the circuit opens: calls fail fast
 * for `openMs`, then one trial call is let through (half-open); success closes
 * the circuit, failure opens it again.
 */
export class BackendGate {
  private running = 0;
  private queue: { resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout }[] = [];
  private failures = 0;
  private openedAt = 0;
  private trial = false;
  private lastError = '';

  constructor(
    readonly title: string,
    private readonly opts: GateOptions = DEFAULT_GATE,
  ) {}

  get state(): CircuitState {
    if (this.failures < this.opts.failureThreshold) return 'closed';
    return Date.now() - this.openedAt >= this.opts.openMs ? 'half-open' : 'open';
  }

  view(): { circuit: CircuitState; running: number; queued: number; consecutive_failures: number; last_error?: string } {
    return {
      circuit: this.state,
      running: this.running,
      queued: this.queue.length,
      consecutive_failures: this.failures,
      ...(this.failures && this.lastError ? { last_error: this.lastError } : {}),
    };
  }

  /**
   * Runs `fn` under the gate. Only an outage (see `isOutage`) counts as a
   * failure. A 4xx answer shows the backend is up; any other error (e.g. an
   * argument rejected before the backend was asked) says nothing either way.
   */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    const st = this.state;
    if (st === 'open') {
      const wait = Math.ceil((this.opts.openMs - (Date.now() - this.openedAt)) / 1000);
      throw new GateRejected(
        `${this.title} is failing (${this.failures} calls in a row; last: ${this.lastError || 'unknown'}). ` +
          `Not calling it for another ${wait} s. This is an outage, not an empty result.`,
        `${this.title} is failing. Not calling it for another ${wait} s. This is an outage, not an empty result.`,
      );
    }
    if (st === 'half-open') {
      if (this.trial) throw new GateRejected(`${this.title} is failing; a trial call is in progress. Retry shortly.`);
      this.trial = true;
    }
    try {
      await this.acquire();
    } catch (err) {
      if (st === 'half-open') this.trial = false;
      throw err;
    }
    try {
      const v = await fn();
      this.succeed();
      return v;
    } catch (err) {
      if (isOutage(err)) this.fail(errMessage(err));
      else if (err instanceof BackendError && err.status !== undefined) this.succeed();
      throw err;
    } finally {
      if (st === 'half-open') this.trial = false;
      this.release();
    }
  }

  private succeed(): void {
    this.failures = 0;
    this.lastError = '';
  }

  private fail(message: string): void {
    this.failures++;
    this.lastError = message.slice(0, 300);
    if (this.failures >= this.opts.failureThreshold) this.openedAt = Date.now();
  }

  private acquire(): Promise<void> {
    if (this.running < this.opts.concurrency) {
      this.running++;
      return Promise.resolve();
    }
    if (this.queue.length >= this.opts.maxQueue) {
      return Promise.reject(new GateRejected(`${this.title} is busy (${this.running} calls running, ${this.queue.length} waiting). Retry shortly.`));
    }
    return new Promise((resolve, reject) => {
      const item = {
        resolve: () => {
          clearTimeout(item.timer);
          this.running++;
          resolve();
        },
        reject,
        timer: setTimeout(() => {
          this.queue = this.queue.filter((q) => q !== item);
          reject(new GateRejected(`${this.title} did not free a slot within ${this.opts.queueTimeoutMs / 1000} s. Retry shortly.`));
        }, this.opts.queueTimeoutMs),
      };
      this.queue.push(item);
    });
  }

  private release(): void {
    this.running--;
    this.queue.shift()?.resolve();
  }
}
