import { createHash } from 'node:crypto';
import type { ConfigStore } from '../config/store.js';
import type { BackendSettings } from '../config/schema.js';
import { defectdojo } from './defectdojo/index.js';
import { graylog } from './graylog/index.js';
import { BackendGate, HealthMonitor } from './health.js';
import { intel } from './intel/index.js';
import { trivy } from './trivy/index.js';
import type { BackendId, BackendModule, ConnectionResult, ToolDescriptor } from './types.js';
import { wazuh } from './wazuh/index.js';

export const BACKENDS: readonly BackendModule<any, any>[] = [wazuh, trivy, defectdojo, graylog, intel];

export function getModule(id: string): BackendModule<any, any> | undefined {
  return BACKENDS.find((b) => b.id === id);
}

/** The module's own settings: without the core's flags, which do not change the runtime. */
function settingsWithoutFlag(s: BackendSettings | undefined): Record<string, unknown> {
  const { enabled: _enabled, allowWrite: _w, tools: _t, ...rest } = s ?? { enabled: false };
  return rest;
}

/** Whether an allowlist entry (exact name or `<prefix>*`) covers a tool name. */
export function patternMatches(pattern: string, name: string): boolean {
  return pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : pattern === name;
}

/**
 * Installation allowlist (DESIGN §4). Until an administrator edits it, a
 * backend gets its module's default subset: read tools not marked
 * `default: false`. Write tools are never in the default subset.
 */
export function allowlisted(settings: Pick<BackendSettings, 'tools'> | undefined, d: Pick<ToolDescriptor, 'name' | 'access' | 'default'>): boolean {
  const list = settings?.tools;
  if (!list) return d.access === 'read' && d.default !== false;
  return list.some((p) => patternMatches(p, d.name));
}

/** Static tool list of a module for the Backends page. */
export function toolCatalog(mod: BackendModule<any, any>) {
  return mod.tools.map((d) => ({
    name: d.name,
    title: d.title,
    access: d.access,
    destructive: d.destructive === true,
    default: d.access === 'read' && d.default !== false,
  }));
}

export type ValidationResult =
  | { ok: true; value: unknown }
  | { ok: false; issues: string[] };

export function validateSettings(mod: BackendModule<any, any>, settings: Record<string, unknown>): ValidationResult {
  const r = mod.schema.safeParse(settings);
  if (r.success) return { ok: true, value: r.data };
  return { ok: false, issues: r.error.issues.map((i) => `${i.path.join('.') || 'settings'}: ${i.message}`) };
}

/**
 * Caches one runtime per backend, keyed by a hash of its settings, so API
 * clients (and things like Wazuh's JWT) survive across stateless MCP requests
 * and are rebuilt as soon as an admin changes the settings.
 */
export class BackendRegistry {
  private cache = new Map<BackendId, { fingerprint: string; runtime: unknown }>();
  private gates = new WeakMap<object, BackendGate>();
  /** Scheduled, cached health per runtime; shared by the status bar, the UI and `socbridge_backends`. */
  readonly health = new HealthMonitor();

  constructor(private readonly store: ConfigStore) {}

  /** Live configuration (for scope checks). */
  config() {
    return this.store.get();
  }

  /** Enabled backends whose settings validate, with their runtimes. */
  active(): { mod: BackendModule<any, any>; runtime: unknown }[] {
    const out: { mod: BackendModule<any, any>; runtime: unknown }[] = [];
    for (const mod of BACKENDS) {
      const s = this.store.get().backends[mod.id];
      if (!s?.enabled) continue;
      const rt = this.runtimeFor(mod, settingsWithoutFlag(s));
      if (rt.ok) out.push({ mod, runtime: rt.runtime });
    }
    return out;
  }

  /** Runtime for one backend if it is enabled and validly configured, else null. */
  runtime<Rt>(id: BackendId): Rt | null {
    const found = this.active().find((a) => a.mod.id === id);
    return found ? (found.runtime as Rt) : null;
  }

  /**
   * Concurrency limit and circuit breaker for one backend's current runtime.
   * Keyed by runtime, so changed settings start with a closed circuit.
   */
  gate(mod: BackendModule<any, any>, runtime: object): BackendGate {
    let g = this.gates.get(runtime);
    if (!g) {
      g = new BackendGate(mod.title);
      this.gates.set(runtime, g);
    }
    return g;
  }

  /** Peeks at a gate without creating one (for status views). */
  peekGate(runtime: object): BackendGate | undefined {
    return this.gates.get(runtime);
  }

  /** Starts the scheduled health checks of every active backend. */
  startHealthChecks(intervalMs?: number): void {
    this.health.start(() => this.active(), intervalMs);
  }

  status(id: BackendId): { enabled: boolean; configured: boolean; issues: string[] } {
    const mod = getModule(id)!;
    const s = this.store.get().backends[id];
    const v = validateSettings(mod, settingsWithoutFlag(s));
    return { enabled: !!s?.enabled, configured: v.ok, issues: v.ok ? [] : v.issues };
  }

  async test(id: BackendId): Promise<ConnectionResult> {
    const mod = getModule(id)!;
    const rt = this.runtimeFor(mod, settingsWithoutFlag(this.store.get().backends[id]));
    if (!rt.ok) return { ok: false, message: `Invalid settings: ${rt.issues.join('; ')}` };
    return mod.testConnection(rt.runtime);
  }

  /** Tests unsaved settings; nothing is cached or stored. */
  async testSettings(id: BackendId, settings: Record<string, unknown>): Promise<ConnectionResult> {
    const mod = getModule(id)!;
    const v = validateSettings(mod, settings);
    if (!v.ok) return { ok: false, message: `Invalid settings: ${v.issues.join('; ')}` };
    return mod.testConnection(mod.createRuntime(v.value));
  }

  private runtimeFor(
    mod: BackendModule<any, any>,
    settings: Record<string, unknown>,
  ): { ok: true; runtime: unknown } | { ok: false; issues: string[] } {
    const fingerprint = createHash('sha256').update(JSON.stringify(settings)).digest('hex');
    const cached = this.cache.get(mod.id);
    if (cached?.fingerprint === fingerprint) return { ok: true, runtime: cached.runtime };
    const v = validateSettings(mod, settings);
    if (!v.ok) return v;
    const runtime = mod.createRuntime(v.value);
    this.cache.set(mod.id, { fingerprint, runtime });
    return { ok: true, runtime };
  }
}
