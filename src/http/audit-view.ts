import type { NextFunction, Request, Response } from 'express';
import type { AuditLog } from '../audit/audit-log.js';
import type { User } from '../config/schema.js';
import { errMessage, log } from '../log.js';

/** Pages refresh themselves (the map polls), so the same view by the same user is recorded once per this time. */
const REPEAT_MS = 10 * 60 * 1000;

/**
 * Records views of backend data in the web console (A-007): who looked at
 * which page, next to the tool calls. `backendOf` names the backend, or null
 * for requests that read none.
 */
export function auditView(ctx: { audit: AuditLog }, backendOf: (req: Request) => string | null) {
  const seen = new Map<string, number>();
  return (req: Request, res: Response, next: NextFunction): void => {
    const backend = backendOf(req);
    const user = res.locals.user as User | undefined;
    if (!backend || !user || req.method !== 'GET') return next();
    const started = Date.now();
    const path = (req.baseUrl + req.path).replace(/^\/api\//, '').slice(0, 200);
    res.on('finish', () => {
      const outcome = res.statusCode < 400 ? 'ok' : res.statusCode === 403 ? 'denied' : 'error';
      const now = Date.now();
      const key = `${user.id} ${outcome} ${path}`;
      if (now - (seen.get(key) ?? -Infinity) < REPEAT_MS) return;
      if (seen.size > 1000) for (const [k, t] of seen) if (now - t >= REPEAT_MS) seen.delete(k);
      seen.set(key, now);
      ctx.audit
        .record({
          source: 'web',
          user: user.name,
          userId: user.id,
          credential: `session:${user.id}`,
          credentialLabel: 'console',
          tool: 'web.view',
          backend,
          access: 'read',
          args: { path, ...req.query },
          outcome,
          durationMs: now - started,
        })
        .catch((err) => log.error('View not audited', { path, by: user.name, error: errMessage(err) }));
    });
    next();
  };
}
