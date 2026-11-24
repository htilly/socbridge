import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import { z } from 'zod';
import { OAUTH_SCOPE, OAuthError, type OAuthService } from '../auth/oauth.js';
import { scopeProblem } from '../auth/scopes.js';
import { randomToken } from '../auth/secrets.js';
import { readCookie } from '../auth/sessions.js';
import { AccessLevelSchema, type OAuthGrant, type User } from '../config/schema.js';
import { log } from '../log.js';
import { backendIds, scopeOptions } from './api.js';
import { RequestLimiter } from '../auth/ratelimit.js';
import { auditEvent } from './audit-event.js';
import { currentUser, HttpError, requireAdmin, requireFresh, requireUser, type AppContext } from './context.js';

/** Path of the protected resource metadata document for /mcp (RFC 9728 section 3.1). */
export const RESOURCE_METADATA_PATH = '/.well-known/oauth-protected-resource/mcp';

/**
 * Discovery and token endpoints are called by OAuth clients, some of them
 * from a browser on another origin. They never read cookies, so allowing any
 * origin exposes nothing a direct request could not get.
 */
function cors(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('access-control-allow-origin', '*');
  if (req.method === 'OPTIONS') {
    res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
    res.setHeader('access-control-allow-headers', 'authorization, content-type, mcp-protocol-version');
    res.setHeader('access-control-max-age', '600');
    res.status(204).end();
    return;
  }
  next();
}

function oauthError(res: Response, err: OAuthError): void {
  if (err.status === 401) res.setHeader('www-authenticate', 'Basic realm="socbridge"');
  res.status(err.status).json({ error: err.code, error_description: err.message });
}

/** Client credentials from HTTP Basic (client_secret_basic) or the form body. */
function clientCredentials(req: Request, body: Record<string, unknown>): { id?: string; secret?: string } {
  const m = /^Basic\s+(\S+)$/i.exec(req.headers.authorization ?? '');
  if (m) {
    const decoded = Buffer.from(m[1]!, 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    if (i > 0) {
      const dec = (s: string) => {
        try {
          return decodeURIComponent(s.replace(/\+/g, ' '));
        } catch {
          return s;
        }
      };
      return { id: dec(decoded.slice(0, i)), secret: dec(decoded.slice(i + 1)) };
    }
  }
  const s = (k: string) => (typeof body[k] === 'string' ? (body[k] as string) : undefined);
  return { id: s('client_id'), secret: s('client_secret') };
}

function plainPage(res: Response, status: number, title: string, text: string): void {
  res.status(status).type('text/plain; charset=utf-8').send(`${title}\n\n${text}\n`);
}

/**
 * Per-browser nonce tying a consent request to the browser that started it
 * (O-002). Lax, so it is stored and sent on the top-level navigation from the
 * client's site; HttpOnly, so the console's script never sees it.
 */
export const OAUTH_BROWSER_COOKIE = 'socbridge_oauth';
const OAUTH_BROWSER_MAX_AGE_MS = 15 * 60 * 1000;

function oauthBrowser(req: Request, res: Response): string {
  const have = readCookie(req, OAUTH_BROWSER_COOKIE);
  const nonce = have && /^[A-Za-z0-9_-]{32,128}$/.test(have) ? have : randomToken(32);
  res.cookie(OAUTH_BROWSER_COOKIE, nonce, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: OAUTH_BROWSER_MAX_AGE_MS });
  return nonce;
}

/** Public OAuth endpoints: metadata, registration, authorize, token, revoke. */
export function oauthRouter(ctx: AppContext, oauth: OAuthService, registerLimiter: { isBlocked(k: string): boolean; fail(k: string): void }): Router {
  const r = express.Router();
  const origin = ctx.env.origin;

  const resourceMetadata = {
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    scopes_supported: [OAUTH_SCOPE],
    bearer_methods_supported: ['header'],
    resource_name: 'SocBridge',
  };
  const serverMetadata = {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    revocation_endpoint: `${origin}/oauth/revoke`,
    scopes_supported: [OAUTH_SCOPE],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    authorization_response_iss_parameter_supported: true,
  };

  const json = (doc: object) => (_req: Request, res: Response) => {
    res.setHeader('cache-control', 'public, max-age=300');
    res.json(doc);
  };
  // While turned off, none of these exist (the app's 404 handler answers).
  const OAUTH_PATHS = [
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-authorization-server',
    '/oauth',
  ];
  r.use(OAUTH_PATHS, (_req, _res, next) => (oauth.enabled() ? next() : next('router')));
  r.use(['/.well-known/oauth-protected-resource', '/.well-known/oauth-authorization-server', '/oauth/register', '/oauth/token', '/oauth/revoke'], cors);
  r.get(['/.well-known/oauth-protected-resource', RESOURCE_METADATA_PATH], json(resourceMetadata));
  r.get(['/.well-known/oauth-authorization-server', '/.well-known/oauth-authorization-server/mcp'], json(serverMetadata));

  r.post('/oauth/register', express.json({ limit: '32kb' }), async (req, res) => {
    const ip = req.ip ?? 'unknown';
    if (registerLimiter.isBlocked(ip)) {
      res.setHeader('retry-after', '3600');
      res.status(429).json({ error: 'temporarily_unavailable', error_description: 'Too many registrations' });
      return;
    }
    registerLimiter.fail(ip); // counts every registration, not only failures
    try {
      const { client, secret } = await oauth.register((req.body ?? {}) as Record<string, unknown>);
      log.info('OAuth client registered', { clientId: client.id, name: client.name, redirectUris: client.redirectUris });
      res.setHeader('cache-control', 'no-store');
      res.status(201).json({
        client_id: client.id,
        client_id_issued_at: Math.floor(Date.parse(client.createdAt) / 1000),
        ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
        client_name: client.name,
        redirect_uris: client.redirectUris,
        token_endpoint_auth_method: client.authMethod,
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: OAUTH_SCOPE,
      });
    } catch (err) {
      if (err instanceof OAuthError) {
        log.warn('OAuth client registration refused', { ip, reason: err.message });
        return oauthError(res, err);
      }
      throw err;
    }
  });

  const authorizeLimiter = new RequestLimiter(30);
  r.get('/oauth/authorize', (req, res) => {
    res.setHeader('cache-control', 'no-store');
    if (!authorizeLimiter.take(req.ip ?? 'unknown')) {
      res.setHeader('retry-after', '60');
      return plainPage(res, 429, 'SocBridge: too many requests', 'Too many authorization requests from this address. Try again in a minute.');
    }
    const q = (k: string) => (typeof req.query[k] === 'string' ? (req.query[k] as string) : undefined);
    try {
      const browser = oauthBrowser(req, res);
      const out = oauth.startAuthorization({
        response_type: q('response_type'),
        client_id: q('client_id'),
        redirect_uri: q('redirect_uri'),
        state: q('state'),
        code_challenge: q('code_challenge'),
        code_challenge_method: q('code_challenge_method'),
        scope: q('scope'),
        resource: q('resource'),
      }, browser);
      if ('redirect' in out) return res.redirect(303, out.redirect);
      // The console signs the user in (if needed) and shows the consent screen.
      res.redirect(303, `/#/authorize/${out.requestId}`);
    } catch (err) {
      if (err instanceof OAuthError) return plainPage(res, 400, 'SocBridge: authorization request refused', err.message);
      throw err;
    }
  });

  const form = [express.urlencoded({ extended: false, limit: '16kb' }), express.json({ limit: '16kb' })];

  r.post('/oauth/token', ...form, async (req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('pragma', 'no-cache');
    const ip = req.ip ?? 'unknown';
    if (ctx.tokenLimiter.isBlocked(ip)) {
      res.setHeader('retry-after', '300');
      res.status(429).json({ error: 'temporarily_unavailable', error_description: 'Too many failed attempts' });
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const s = (k: string) => (typeof body[k] === 'string' ? (body[k] as string) : undefined);
    try {
      const creds = clientCredentials(req, body);
      const client = oauth.authenticateClient(creds.id, creds.secret);
      const grantType = s('grant_type');
      let out;
      if (grantType === 'authorization_code') {
        out = await oauth.exchangeCode(client, {
          code: s('code'),
          redirect_uri: s('redirect_uri'),
          code_verifier: s('code_verifier'),
          resource: s('resource'),
        });
        log.info('OAuth grant issued', { clientId: client.id, client: client.name });
      } else if (grantType === 'refresh_token') {
        out = await oauth.refresh(client, s('refresh_token'));
      } else {
        throw new OAuthError('unsupported_grant_type', 'Only authorization_code and refresh_token are supported');
      }
      res.json(out);
    } catch (err) {
      if (err instanceof OAuthError) {
        if (err.code === 'invalid_grant' || err.code === 'invalid_client') ctx.tokenLimiter.fail(ip);
        log.warn('OAuth token request refused', { ip, error: err.code, reason: err.message });
        return oauthError(res, err);
      }
      throw err;
    }
  });

  r.post('/oauth/revoke', ...form, async (req, res) => {
    res.setHeader('cache-control', 'no-store');
    const body = (req.body ?? {}) as Record<string, unknown>;
    try {
      const creds = clientCredentials(req, body);
      const client = oauth.authenticateClient(creds.id, creds.secret);
      await oauth.revoke(client, typeof body.token === 'string' ? body.token : undefined);
      res.status(200).end();
    } catch (err) {
      if (err instanceof OAuthError) return oauthError(res, err);
      throw err;
    }
  });

  return r;
}

const publicGrant = (g: OAuthGrant, users: readonly User[]) => ({
  id: g.id,
  clientName: g.clientName,
  userId: g.userId,
  userName: users.find((u) => u.id === g.userId)?.name ?? '(deleted)',
  createdAt: g.createdAt,
  lastUsedAt: g.lastUsedAt,
  expiresAt: g.refreshExpiresAt,
  access: g.access,
});

/** Session-authenticated console API: consent screen and connected apps. Mounted at /api/oauth. */
export function oauthApiRouter(ctx: AppContext, oauth: OAuthService): Router {
  const r = express.Router();

  const view = () => ({ enabled: oauth.enabled(), mcpUrl: `${ctx.env.origin}/mcp`, redirectHosts: ctx.env.oauthRedirectHosts });

  r.get('/settings', requireAdmin, (_req, res) => {
    res.json(view());
  });

  r.put('/settings', requireAdmin, requireFresh(ctx), async (req, res) => {
    const me = currentUser(res);
    const body = z.object({ enabled: z.boolean() }).safeParse(req.body);
    if (!body.success) throw new HttpError(400, 'enabled must be true or false');
    await ctx.store.mutate((draft) => {
      draft.server.oauth = { ...(draft.server.oauth ?? {}), enabled: body.data.enabled };
    });
    await auditEvent(ctx, { by: me, action: 'admin.oauth.settings', text: 'OAuth connectors ' + (body.data.enabled ? 'enabled' : 'disabled'), details: { enabled: body.data.enabled } });
    res.json(view());
  });

  r.get('/requests/:id', requireUser, (req, res) => {
    const d = oauth.describeRequest(String(req.params.id), readCookie(req, OAUTH_BROWSER_COOKIE));
    if (!d) throw new HttpError(404, oauth.enabled() ? 'This authorization request has expired or was started in another browser. Start the connection again from your client.' : 'Connectors are turned off on this server.');
    // The consent screen offers the same per-backend choice as the token form.
    res.json({ ...d, scopes: scopeOptions(ctx.store.get(), currentUser(res)) });
  });

  r.post('/requests/:id', requireUser, requireFresh(ctx), async (req, res) => {
    const me = currentUser(res);
    const body = z
      .object({
        approve: z.boolean(),
        /** What the app may do per backend. Required to approve: nothing is granted by default. */
        access: z.object({ backends: z.record(z.string(), AccessLevelSchema) }).optional(),
      })
      .safeParse(req.body);
    if (!body.success) throw new HttpError(400, 'approve must be true or false; access must be { backends: { <id>: "read" | "write" } }');
    const access = body.data.access ?? { backends: {} };
    if (body.data.approve) {
      if (Object.keys(access.backends).length === 0) throw new HttpError(400, 'Choose at least one backend the app may use.');
      const problem = scopeProblem(access, me, backendIds);
      if (problem) throw new HttpError(problem.includes('write grant') ? 403 : 400, `access: ${problem}`);
    }
    const id = String(req.params.id);
    const browser = readCookie(req, OAUTH_BROWSER_COOKIE);
    const d = oauth.describeRequest(id, browser);
    const redirect = oauth.decide(id, me, body.data.approve, access, browser);
    if (!redirect) throw new HttpError(404, oauth.enabled() ? 'This authorization request has expired or was started in another browser. Start the connection again from your client.' : 'Connectors are turned off on this server.');
    await auditEvent(ctx, {
      by: me,
      action: body.data.approve ? 'auth.app.approve' : 'auth.app.decline',
      text: body.data.approve ? 'OAuth client approved' : 'OAuth client declined',
      details: { client: d?.clientName, ...(body.data.approve ? { access: access.backends } : {}) },
    });
    res.json({ redirect });
  });

  r.get('/grants', requireUser, (req, res) => {
    const me = currentUser(res);
    const cfg = ctx.store.get();
    const all = req.query.all === '1' && me.role === 'admin';
    const now = Date.now();
    res.json(
      cfg.oauthGrants
        .filter((g) => (all || g.userId === me.id) && Date.parse(g.refreshExpiresAt) > now)
        .map((g) => publicGrant(g, cfg.users)),
    );
  });

  /**
   * Changes what a connected app may do, without reconnecting it: the owner
   * or an administrator, checked against the owner's write grants, effective
   * from the app's next call.
   */
  r.patch('/grants/:id', requireUser, requireFresh(ctx), async (req, res) => {
    const me = currentUser(res);
    const body = z.object({ access: z.object({ backends: z.record(z.string(), AccessLevelSchema) }) }).safeParse(req.body);
    if (!body.success) throw new HttpError(400, 'access must be { backends: { <id>: "read" | "write" } }');
    const id = String(req.params.id);
    const before = await ctx.store.mutate((draft) => {
      const g = draft.oauthGrants.find((x) => x.id === id);
      if (!g || (g.userId !== me.id && me.role !== 'admin')) throw new HttpError(404, 'Connection not found');
      const owner = draft.users.find((u) => u.id === g.userId);
      if (!owner) throw new HttpError(404, 'Connection not found');
      const problem = scopeProblem(body.data.access, owner, backendIds);
      if (problem) {
        const whose = owner.id === me.id ? problem : problem.replace('you have no write grant', `${owner.name} has no write grant`);
        throw new HttpError(problem.includes('write grant') ? 403 : 400, `access: ${whose}`);
      }
      const prev = g.access;
      g.access = body.data.access;
      return prev;
    });
    await auditEvent(ctx, { by: me, action: 'auth.app.scope', text: 'OAuth grant scope changed', details: { id, from: before.backends, to: body.data.access.backends } });
    const cfg = ctx.store.get();
    res.json(publicGrant(cfg.oauthGrants.find((g) => g.id === id)!, cfg.users));
  });

  r.delete('/grants/:id', requireUser, async (req, res) => {
    const me = currentUser(res);
    await ctx.store.mutate((draft) => {
      const g = draft.oauthGrants.find((x) => x.id === req.params.id);
      if (!g || (g.userId !== me.id && me.role !== 'admin')) throw new HttpError(404, 'Connection not found');
      draft.oauthGrants = draft.oauthGrants.filter((x) => x.id !== g.id);
    });
    await auditEvent(ctx, { by: me, action: 'auth.app.revoke', text: 'OAuth grant revoked', details: { id: req.params.id } });
    res.json({ ok: true });
  });

  return r;
}
