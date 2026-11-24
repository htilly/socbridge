import type { NextFunction, Request, Response } from 'express';
import type { AuditLog } from '../audit/audit-log.js';
import type { FailureLimiter } from '../auth/ratelimit.js';
import type { OAuthService } from '../auth/oauth.js';
import type { SessionManager } from '../auth/sessions.js';
import type { BackendRegistry } from '../backends/registry.js';
import type { User } from '../config/schema.js';
import type { ConfigStore } from '../config/store.js';
import type { Env } from '../env.js';
import type { TlsManager } from '../tls/manager.js';

export interface AppContext {
  env: Env;
  store: ConfigStore;
  sessions: SessionManager;
  registry: BackendRegistry;
  /** Append-only record of every tool call (MCP and chat). */
  audit: AuditLog;
  /** Failed bearer-token attempts on /mcp. */
  tokenLimiter: FailureLimiter;
  /** OAuth authorization server for clients such as Claude custom connectors. */
  oauth: OAuthService;
  /** OAuth dynamic client registrations, counted per address. */
  registerLimiter: FailureLimiter;
  /** Failed setup-token / invite / passkey attempts on the web API. */
  authLimiter: FailureLimiter;
  /** One-time token required to enrol the first admin; null once an admin exists. */
  setupToken: () => string | null;
  caCertPem?: string;
  /** Certificate management; null when TLS is off (behind a proxy). */
  tls: TlsManager | null;
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** Machine-readable reason, e.g. `reauth`. */
    readonly code?: string,
  ) {
    super(message);
  }
}

export function currentUser(res: Response): User {
  const u = res.locals.user as User | undefined;
  if (!u) throw new HttpError(401, 'Not signed in');
  return u;
}

/**
 * Cross-site request protection for the JSON API. The session cookie is
 * SameSite=Strict; additionally every state-changing call must carry a custom
 * header (which a cross-origin page cannot send without a CORS preflight we
 * never approve) and, if the browser sent an Origin, it must be ours.
 */
export function csrfGuard(ctx: AppContext) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    if (req.get('x-socbridge') !== '1') return next(new HttpError(403, 'Missing request header'));
    const origin = req.get('origin');
    if (origin && origin !== ctx.env.origin) return next(new HttpError(403, 'Cross-origin request refused'));
    next();
  };
}

/** Attaches the signed-in user (if any) to res.locals.user. */
export function sessionUser(ctx: AppContext) {
  return (req: Request, res: Response, next: NextFunction) => {
    const userId = ctx.sessions.resolve(req);
    if (userId) {
      const user = ctx.store.get().users.find((u) => u.id === userId);
      if (user && !user.disabled) res.locals.user = user;
      else ctx.sessions.destroy(req, res);
    }
    next();
  };
}

export function requireUser(_req: Request, res: Response, next: NextFunction) {
  if (!res.locals.user) return next(new HttpError(401, 'Not signed in'));
  next();
}

export function requireAdmin(_req: Request, res: Response, next: NextFunction) {
  const u = res.locals.user as User | undefined;
  if (!u) return next(new HttpError(401, 'Not signed in'));
  if (u.role !== 'admin') return next(new HttpError(403, 'Administrator role required'));
  next();
}

/**
 * Changes that create lasting access or move data need a recent passkey check,
 * so a hijacked or unattended session is not enough. The console answers the
 * `reauth` code by asking for the passkey and repeating the request.
 */
export function requireFresh(ctx: Pick<AppContext, 'sessions'>) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!ctx.sessions.isFresh(req)) return next(new HttpError(403, 'Confirm with your passkey to continue', 'reauth'));
    next();
  };
}

/** Express 5 forwards rejected promises to the error handler; this keeps types tidy. */
export type Handler = (req: Request, res: Response) => Promise<void> | void;
