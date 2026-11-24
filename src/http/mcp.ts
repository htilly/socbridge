import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type Request, type Response, type Router } from 'express';
import type { AuditLog } from '../audit/audit-log.js';
import type { OAuthService } from '../auth/oauth.js';
import { RequestLimiter, type FailureLimiter } from '../auth/ratelimit.js';
import { credentialName, type Principal } from '../auth/scopes.js';
import { bearerFrom, verifyAccessToken } from '../auth/tokens.js';
import { BACKENDS, type BackendRegistry } from '../backends/registry.js';
import type { ConfigStore } from '../config/store.js';
import { errMessage, log } from '../log.js';
import { buildMcpServer } from '../mcp/server.js';

function jsonRpcError(res: Response, status: number, message: string, headers: Record<string, string> = {}): void {
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32000, message }, id: null });
}

/** Messages one user (over all their tokens and apps) may send per minute. */
const MAX_PER_MINUTE = 300;
const MAX_BATCH = 20;

/**
 * Streamable HTTP endpoint in stateless mode: every POST gets a new server and
 * transport, no session ID is issued, and GET/DELETE (used for server-initiated
 * streams and session teardown) are not offered.
 */
export function mcpRouter(
  store: ConfigStore,
  registry: BackendRegistry,
  limiter: FailureLimiter,
  oauth: OAuthService,
  resourceMetadataUrl: string,
  audit: AuditLog,
  requests = new RequestLimiter(MAX_PER_MINUTE),
): Router {
  const router = express.Router();
  // RFC 9728: tells OAuth clients (e.g. Claude custom connectors) where to start.
  const challenge = () =>
    oauth.enabled() ? `Bearer realm="socbridge", resource_metadata="${resourceMetadataUrl}"` : 'Bearer realm="socbridge"';

  /** Static access tokens (msec_…) or OAuth access tokens (msat_…). */
  const authenticate = (presented: string): Principal | null => {
    const t = verifyAccessToken(store, presented);
    if (t) return { kind: 'token', id: t.token.id, userId: t.user.id, userName: t.user.name, label: t.token.label };
    const o = oauth.verifyAccessToken(presented);
    if (o) return { kind: 'oauth', id: o.grant.id, userId: o.user.id, userName: o.user.name, label: o.grant.clientName };
    return null;
  };

  router.post('/mcp', express.json({ limit: '1mb' }), async (req: Request, res: Response) => {
    const ip = req.ip ?? 'unknown';
    const presented = bearerFrom(req.headers.authorization);
    const principal = presented ? authenticate(presented) : null;
    if (!principal) {
      // Only failures are throttled: a valid token works even if others on the same address are guessing.
      if (limiter.isBlocked(ip)) {
        jsonRpcError(res, 429, 'Too many failed authentication attempts; try again later', { 'retry-after': '300' });
        return;
      }
      // A client probing without a token (the OAuth discovery step) is not a failed guess.
      if (presented) limiter.fail(ip);
      log.warn('MCP request rejected', { ip, reason: presented ? 'invalid token' : 'missing token' });
      const www = presented ? `${challenge()}, error="invalid_token"` : challenge();
      jsonRpcError(res, 401, 'Unauthorized', { 'www-authenticate': www });
      return;
    }

    // A JSON-RPC batch carries several calls in one request; each counts.
    const batch: unknown[] = Array.isArray(req.body) ? req.body : [req.body];
    if (batch.length > MAX_BATCH) {
      jsonRpcError(res, 400, `A batch may hold at most ${MAX_BATCH} messages`);
      return;
    }
    if (!requests.take(principal.userId, Math.max(1, batch.length))) {
      log.warn('MCP request rate limited', { user: principal.userName, credential: credentialName(principal) });
      jsonRpcError(res, 429, 'Too many requests; slow down', { 'retry-after': '60' });
      return;
    }

    const { server, tools } = await buildMcpServer(registry, principal, { audit });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      for (const body of batch as ({ method?: string; params?: { name?: unknown; arguments?: unknown } } | null | undefined)[]) {
        if (body?.method !== 'tools/call') continue;
        const name = String(body.params?.name ?? '');
        log.info('Tool call', { user: principal.userName, credential: credentialName(principal), tool: name.slice(0, 128) });
        // A tool this credential was not given (out of scope, not allowlisted, a write tool on a read
        // token) is not registered, so the SDK answers "not found". Record the attempt as denied.
        if (!tools.has(name)) {
          await audit
            .record({
              source: 'mcp',
              user: principal.userName,
              userId: principal.userId,
              credential: credentialName(principal),
              ...(principal.label ? { credentialLabel: principal.label } : {}),
              tool: name.slice(0, 128),
              backend: /^([a-z]{1,32})_/.exec(name)?.[1] ?? 'unknown',
              access: BACKENDS.flatMap((m) => m.tools).find((d) => d.name === name)?.access ?? 'read',
              args: body.params?.arguments ?? {},
              outcome: 'denied',
              message: 'tool not available to this credential',
              durationMs: 0,
            })
            .catch(() => undefined);
        }
      }
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      log.error('MCP request failed', { error: errMessage(err) });
      if (!res.headersSent) jsonRpcError(res, 500, 'Internal server error');
    }
  });

  const notAllowed = (_req: Request, res: Response) =>
    jsonRpcError(res, 405, 'Method not allowed: this server is stateless, use POST', { allow: 'POST' });
  router.get('/mcp', notAllowed);
  router.delete('/mcp', notAllowed);

  return router;
}
