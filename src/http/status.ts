import express, { type Router } from 'express';
import { BACKENDS } from '../backends/registry.js';
import type { CircuitState } from '../backends/health.js';
import { ONLINE_LABEL, transportOf, type Transport } from '../backends/transport.js';
import type { BackendHealth, HealthCheck, HealthStatus } from '../backends/types.js';
import { assistantView } from './chat.js';
import { requireAdmin, type AppContext } from './context.js';
import { sourceList } from './findings.js';

/** Certificates closer to expiry than this are shown as degraded. */
const CERT_WARN_DAYS = 14;

/**
 * `up` works, `degraded` works with a limitation, `down` is enabled but
 * failing, `off` is not enabled (or not applicable).
 */
export type Health = 'up' | 'degraded' | 'down' | 'off';

export interface ServiceStatus {
  id: string;
  title: string;
  kind: 'backend' | 'assistant' | 'tls';
  health: Health;
  /** A few words for the status bar. */
  summary: string;
  /** Longer explanation; may name hosts and errors. */
  detail?: string;
  /** Individual health checks (backends only). */
  checks?: HealthCheck[];
  /** Circuit breaker state when not closed (backends only). */
  circuit?: CircuitState;
  /** When the live check ran (backends only). */
  checkedAt?: string;
  /** How SocBridge connects to the backend (configured backends only). */
  transport?: Transport;
  /** Per-connection transport, e.g. "Indexer URL: https, certificate verified". */
  connections?: string[];
  /** Whether the backend has write tools, and whether this installation allows them. */
  write?: { supported: boolean; allowed: boolean };
}

const TO_BAR: Record<HealthStatus, Health> = { ok: 'up', degraded: 'degraded', down: 'down' };

/** Status-bar words for a health result: the first check that is not ok names the problem. */
export function healthSummary(h: BackendHealth, transport: Transport = 'local'): string {
  if (h.status === 'ok') return ONLINE_LABEL[transport];
  const bad = h.checks.filter((c) => c.status === h.status);
  if (h.checks.length === 1 && h.status === 'down') return 'Unreachable';
  if (bad.length === 1 && bad[0]!.name === 'indexer' && /not configured/i.test(bad[0]!.message)) return 'No indexer';
  return `${h.status === 'down' ? 'Down' : 'Degraded'}: ${bad.map((c) => c.name).join(', ')}`;
}

async function backendStatuses(ctx: AppContext, force: boolean): Promise<ServiceStatus[]> {
  const sources = sourceList(ctx.registry, true);
  return Promise.all(
    BACKENDS.map(async (mod): Promise<ServiceStatus> => {
      const src = sources.find((s) => s.id === mod.id)!;
      const stored = ctx.store.get().backends[mod.id];
      const write = { supported: mod.tools.some((d) => d.access === 'write'), allowed: !!stored?.allowWrite };
      const base = { id: mod.id, title: mod.title, kind: 'backend' as const, write };
      const st = ctx.registry.status(mod.id);
      const runtime = st.enabled && st.configured ? ctx.registry.runtime<object>(mod.id) : null;

      if (!runtime) {
        if (st.enabled) {
          return { ...base, health: 'down', summary: 'Settings incomplete', detail: src.issues?.join('; ') };
        }
        const summary =
          mod.maturity === 'stub' ? 'Planned' : src.state === 'disabled' ? 'Disabled' : 'Not configured';
        return { ...base, health: 'off', summary };
      }

      const { transport, connections } = transportOf(mod, stored as Record<string, unknown> | undefined);
      Object.assign(base, { transport, connections });
      const { health, at } = await ctx.registry.health.check(mod, runtime, force);
      const checkedAt = new Date(at).toISOString();
      const detail = { detail: health.checks.map((c) => `${c.name}: ${c.message}`).join('; '), checks: health.checks };
      const gate = ctx.registry.peekGate(runtime)?.view();
      if (gate && gate.circuit !== 'closed') {
        const why = gate.last_error ? { detail: `Calls refused after ${gate.consecutive_failures} failures in a row; last: ${gate.last_error}` } : {};
        return { ...base, health: 'down', summary: 'Failing calls', circuit: gate.circuit, checkedAt, ...detail, ...why };
      }
      if (mod.maturity === 'stub' && health.status === 'ok') {
        return { ...base, health: 'degraded', summary: 'Connected, no tools yet', checkedAt, ...detail };
      }
      return { ...base, health: TO_BAR[health.status], summary: healthSummary(health, transport), checkedAt, ...detail };
    }),
  );
}

function assistantStatus(ctx: AppContext): ServiceStatus {
  const v = assistantView(ctx);
  const base = { id: 'assistant', title: 'Assistant', kind: 'assistant' as const };
  if (!v.enabled) return { ...base, health: 'off', summary: 'Off' };
  if (!v.ready) return { ...base, health: 'down', summary: 'Not configured', ...(v.reason ? { detail: v.reason } : {}) };
  const provider = { anthropic: 'Claude', openai: 'OpenAI', local: 'Local model' }[v.provider];
  return { ...base, health: 'up', summary: provider };
}

function tlsStatus(ctx: AppContext): ServiceStatus {
  const base = { id: 'tls', title: 'Certificate', kind: 'tls' as const };
  if (!ctx.tls) return { ...base, health: 'off', summary: 'Reverse proxy' };
  const v = ctx.tls.view();
  const cert = v.certificate;
  const source = v.serving === 'builtin' ? 'Built-in CA' : v.serving === 'file' ? 'From file' : "Let's Encrypt";
  const err = v.lastError ? { detail: v.lastError } : {};
  if (!cert) return { ...base, health: 'down', summary: 'No certificate', ...err };
  const expiry = { detail: [`Valid until ${cert.validTo}`, v.lastError].filter(Boolean).join('; ') };
  if (cert.daysLeft < 0) return { ...base, health: 'down', summary: 'Expired', ...expiry };
  if (v.staging) return { ...base, health: 'degraded', summary: 'Staging (untrusted)', ...expiry };
  if (cert.daysLeft < CERT_WARN_DAYS) return { ...base, health: 'degraded', summary: `Expires in ${cert.daysLeft} d`, ...expiry };
  // ACME chosen but still on the built-in certificate: issuance is failing.
  if (v.settings.mode === 'acme' && v.serving === 'builtin' && v.lastError) {
    return { ...base, health: 'degraded', summary: "Let's Encrypt failing", ...expiry };
  }
  return { ...base, health: 'up', summary: source, ...expiry };
}

/** Status of every service for the status bar. Administrators only: details may name hosts and errors. */
export function statusRouter(ctx: AppContext): Router {
  const r = express.Router();
  r.get('/status', requireAdmin, async (req, res) => {
    const backends = await backendStatuses(ctx, req.query.refresh === '1');
    res.json({ services: [...backends, assistantStatus(ctx), tlsStatus(ctx)] });
  });
  return r;
}
