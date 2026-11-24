import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import express, { type NextFunction, type Request, type Response } from 'express';
import { errMessage, log } from '../log.js';
import { apiRouter } from './api.js';
import { RequestLimiter } from '../auth/ratelimit.js';
import { auditRouter } from './audit.js';
import { chatRouter } from './chat.js';
import { csrfGuard, HttpError, sessionUser, type AppContext } from './context.js';
import { findingsRouter } from './findings.js';
import { prioritiesRouter } from './priorities.js';
import { serverSettingsRouter } from './server-settings.js';
import { servicesRouter } from './services.js';
import { statusRouter } from './status.js';
import { mcpRouter } from './mcp.js';
import { oauthApiRouter, oauthRouter, RESOURCE_METADATA_PATH } from './oauth.js';
import { passkeyRouter } from './passkeys.js';

/** UI assets ship in /public and are inlined into the page so a strict nonce CSP covers them. */
function loadAsset(name: string): string {
  return readFileSync(new URL(`../../public/${name}`, import.meta.url), 'utf8');
}

function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  res.setHeader('cross-origin-resource-policy', 'same-origin');
  res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)');
  // PUBLIC_URL is always https, so HSTS is correct even when TLS terminates at a proxy.
  res.setHeader('strict-transport-security', 'max-age=31536000');
  if (!res.getHeader('content-security-policy')) {
    res.setHeader('content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  }
  next();
}

export function createApp(ctx: AppContext): express.Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', ctx.env.trustProxy);
  app.use(securityHeaders);

  const html = loadAsset('index.html');
  // Design system: tokens first, then fonts, then components (which reference tokens only).
  const css = ['design/tokens.css', 'design/fonts.css', 'design/components.css'].map(loadAsset).join('\n');
  const js = loadAsset('app.js');

  // Logo, favicon and self-hosted fonts. Same origin, so the UI works offline.
  app.use(
    '/design',
    express.static(fileURLToPath(new URL('../../public/design/', import.meta.url)), {
      index: false,
      dotfiles: 'ignore',
      maxAge: '7d',
      setHeaders: (res, file) => {
        if (file.endsWith('.txt')) res.setHeader('content-type', 'text/plain; charset=utf-8');
      },
    }),
  );

  // Unauthenticated liveness probe for deploy checks. Reveals nothing about backends.
  app.get('/health', (_req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.json({ status: 'ok' });
  });

  if (ctx.caCertPem) {
    const pem = ctx.caCertPem;
    app.get('/ca.crt', (_req, res) => {
      res.setHeader('content-type', 'application/x-pem-file');
      res.setHeader('content-disposition', 'attachment; filename="socbridge-ca.crt"');
      res.send(pem);
    });
  }

  app.use(oauthRouter(ctx, ctx.oauth, ctx.registerLimiter));
  app.use(mcpRouter(ctx.store, ctx.registry, ctx.tokenLimiter, ctx.oauth, `${ctx.env.origin}${RESOURCE_METADATA_PATH}`, ctx.audit));

  const api = express.Router();
  api.use(express.json({ limit: '256kb' }));
  api.use(csrfGuard(ctx));
  api.use(sessionUser(ctx));
  api.use((_req, res, next) => {
    res.setHeader('cache-control', 'no-store');
    next();
  });
  // Every change a signed-in user makes is audited; a loop must not push older records out.
  const changes = new RequestLimiter(120);
  api.use((req, res, next) => {
    const u = res.locals.user as { id: string } | undefined;
    if (u && req.method !== 'GET' && req.method !== 'HEAD' && !changes.take(u.id)) {
      res.setHeader('retry-after', '60');
      return next(new HttpError(429, 'Too many requests; slow down'));
    }
    next();
  });
  api.use('/auth', passkeyRouter(ctx));
  api.use('/oauth', oauthApiRouter(ctx, ctx.oauth));
  api.use('/findings', findingsRouter(ctx));
  api.use('/priorities', prioritiesRouter(ctx));
  api.use('/services', servicesRouter(ctx));
  api.use('/server', serverSettingsRouter(ctx));
  api.use(chatRouter(ctx));
  api.use(statusRouter(ctx));
  api.use(auditRouter(ctx));
  api.use(apiRouter(ctx));
  api.use((_req, _res, next) => next(new HttpError(404, 'Not found')));
  app.use('/api', api);

  app.get('/', (_req, res) => {
    const nonce = randomBytes(16).toString('base64');
    res.setHeader(
      'content-security-policy',
      [
        "default-src 'none'",
        `script-src 'nonce-${nonce}'`,
        `style-src 'nonce-${nonce}'`,
        "connect-src 'self'",
        "font-src 'self'",
        "img-src 'self' data:",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    res.setHeader('cache-control', 'no-store');
    res.type('html').send(
      html
        .replace('/*__CSS__*/', () => css)
        .replace('/*__JS__*/', () => js)
        .replaceAll('__NONCE__', nonce),
    );
  });

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message, ...(err.code ? { code: err.code } : {}) });
      return;
    }
    const status = (err as { status?: number }).status;
    if (status && status >= 400 && status < 500) {
      res.status(status).json({ error: 'Bad request' });
      return;
    }
    log.error('Unhandled request error', { path: req.path, error: errMessage(err) });
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
