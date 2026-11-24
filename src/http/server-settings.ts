import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import { z } from 'zod';
import { safeEqualString } from '../auth/secrets.js';
import type { User } from '../config/schema.js';
import { TlsSettingsError } from '../tls/manager.js';
import { auditEvent } from './audit-event.js';
import { HttpError, requireFresh, type AppContext } from './context.js';

/** Header carrying the first-admin setup token for the pre-setup certificate step. */
export const SETUP_TOKEN_HEADER = 'x-setup-token';

/**
 * Admins may always use these routes. Before the first admin exists, the
 * one-time setup token also grants access, so a new installation can get a
 * certificate the browser trusts *before* it has to create a passkey
 * (WebAuthn refuses to run on a page with a certificate error). The token
 * reaches nothing else, and stops working here the moment an admin enrols.
 */
function requireAdminOrSetupToken(ctx: AppContext) {
  return (req: Request, res: Response, next: NextFunction) => {
    const u = res.locals.user as User | undefined;
    if (u?.role === 'admin') return next();
    const presented = req.get(SETUP_TOKEN_HEADER);
    const expected = ctx.setupToken();
    if (presented !== undefined && expected) {
      const key = req.ip ?? 'unknown';
      if (ctx.authLimiter.isBlocked(key)) return next(new HttpError(429, 'Too many failed attempts; try again later'));
      if (!safeEqualString(presented.trim(), expected)) {
        ctx.authLimiter.fail(key);
        void auditEvent(ctx, { by: 'anonymous', action: 'auth.setup', text: 'Invalid setup token', outcome: 'denied', access: 'read', message: 'invalid setup token', details: { ip: req.ip, path: req.originalUrl.slice(0, 100) } });
        return next(new HttpError(403, 'Invalid setup token'));
      }
      res.locals.setupActor = true;
      return next();
    }
    if (!u) return next(new HttpError(401, 'Not signed in'));
    next(new HttpError(403, 'Administrator role required'));
  };
}

function actor(res: Response): User | string {
  if (res.locals.setupActor) return 'setup token';
  return res.locals.user as User;
}

/** Server settings (the TLS certificate page): admins, or the setup token before the first admin exists. */
export function serverSettingsRouter(ctx: AppContext): Router {
  const r = express.Router();
  r.use(requireAdminOrSetupToken(ctx));

  const Input = z.object({
    mode: z.enum(['builtin', 'acme']),
    acmeEmail: z.string().trim().max(254).optional(),
    acmeStaging: z.boolean().default(false),
    acmeAgreeTos: z.boolean().default(false),
    cloudflareToken: z.string().trim().max(200).optional(),
  });

  const tls = () => {
    if (!ctx.tls) throw new HttpError(409, 'TLS is off (TLS_MODE=off): certificates are handled by the reverse proxy');
    return ctx.tls;
  };
  const parse = (body: unknown) => {
    const p = Input.safeParse(body);
    if (!p.success) throw new HttpError(400, p.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
    if (p.data.acmeEmail && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(p.data.acmeEmail)) throw new HttpError(400, 'acmeEmail is not a valid address');
    return p.data;
  };
  const guarded = async <T>(fn: () => T | Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof TlsSettingsError) throw new HttpError(409, err.message);
      throw err;
    }
  };

  r.get('/tls', (_req, res) => {
    if (!ctx.tls) {
      res.json({ locked: true, lockedReason: 'TLS_MODE=off is set in the environment', envMode: 'off', job: null });
      return;
    }
    res.json(ctx.tls.view());
  });

  // The first-admin setup token has no session to refresh.
  const fresh = (req: Request, res: Response, next: NextFunction) => (res.locals.setupActor ? next() : requireFresh(ctx)(req, res, next));
  r.put('/tls', fresh, async (req, res) => {
    const input = parse(req.body);
    await guarded(() => tls().save(input));
    await auditEvent(ctx, { by: actor(res), action: 'admin.tls.update', text: 'Certificate settings saved', details: { mode: input.mode, staging: input.acmeStaging, dnsKeyChanged: !!input.cloudflareToken } });
    res.json(tls().view());
  });

  const CheckInput = z.object({ cloudflareToken: z.string().trim().max(200).optional() });
  r.post('/tls/check-token', async (req, res) => {
    const p = CheckInput.safeParse(req.body);
    if (!p.success) throw new HttpError(400, 'cloudflareToken: invalid');
    const result = await guarded(() => tls().checkCloudflare(p.data));
    await auditEvent(ctx, { by: actor(res), action: 'admin.tls.check', text: 'Cloudflare token checked', access: 'read', details: { source: result.source, ok: result.ok, ...(result.error ? { error: result.error } : {}) } });
    res.json(result);
  });

  r.post('/tls/test', async (req, res) => {
    const input = parse(req.body);
    await guarded(() => tls().startTest(input));
    await auditEvent(ctx, { by: actor(res), action: 'admin.tls.test', text: 'Certificate staging test started' });
    res.status(202).json(tls().view());
  });

  return r;
}
