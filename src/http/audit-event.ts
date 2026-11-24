import type { AuditLog } from '../audit/audit-log.js';
import type { User } from '../config/schema.js';
import { errMessage, log } from '../log.js';

export interface AuditEvent {
  /** Who did it; a string for an actor without an account (`setup token`, `anonymous`). */
  by: Pick<User, 'id' | 'name'> | string;
  /** `admin.*` for configuration and accounts, `auth.*` for sign-in and credentials. */
  action: string;
  /** Text for the process log. */
  text: string;
  details?: Record<string, unknown>;
  outcome?: 'ok' | 'denied';
  message?: string;
  /** Sign-ins change nothing; everything else is a change (the default). */
  access?: 'read' | 'write';
  backend?: string;
}

/**
 * Records an administrative or sign-in event in the audit log, next to the
 * tool calls, and in the process log. A failing audit log does not block the
 * change (an administrator may be fixing it), but is logged as an error.
 * Never pass secrets: name what changed, not its value.
 */
export async function auditEvent(ctx: { audit: AuditLog }, e: AuditEvent): Promise<void> {
  const by = typeof e.by === 'string' ? { id: '', name: e.by } : e.by;
  const outcome = e.outcome ?? 'ok';
  log[outcome === 'ok' ? 'info' : 'warn'](e.text, { by: by.name, ...e.details, ...(e.message ? { reason: e.message } : {}) });
  try {
    await ctx.audit.record({
      source: 'admin',
      user: by.name,
      userId: by.id,
      credential: by.id ? `session:${by.id}` : 'none',
      credentialLabel: 'console',
      tool: e.action,
      backend: e.backend ?? 'core',
      access: e.access ?? 'write',
      args: e.details ?? {},
      outcome,
      ...(e.message ? { message: e.message } : {}),
      durationMs: 0,
    });
  } catch (err) {
    log.error('Event not audited', { action: e.action, by: by.name, error: errMessage(err) });
  }
}
