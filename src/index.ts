import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { OAuthService } from './auth/oauth.js';
import { FailureLimiter } from './auth/ratelimit.js';
import { randomToken } from './auth/secrets.js';
import { SessionManager } from './auth/sessions.js';
import { startSetupAnnouncements } from './auth/setup-banner.js';
import { AuditLog } from './audit/audit-log.js';
import { insecureBackend, transportPolicy } from './backends/transport.js';
import { BACKENDS, BackendRegistry, getModule } from './backends/registry.js';
import type { WazuhClient } from './backends/wazuh/client.js';
import { useSnapshots, VulnerabilitySnapshots } from './backends/wazuh/snapshots.js';
import { ConfigStore } from './config/store.js';
import { EnvError, loadEnv } from './env.js';
import { auditEvent } from './http/audit-event.js';
import { createApp } from './http/app.js';
import { errMessage, log } from './log.js';
import { TlsManager } from './tls/manager.js';
import { VERSION } from './version.js';

async function main(): Promise<void> {
  const env = loadEnv();
  const store = ConfigStore.forDataDir(env.dataDir, env.encryptionKey);
  await store.load();

  // The first admin enrols with a one-time setup token. It is never stored:
  // either supplied via SETUP_TOKEN or generated and printed once per start.
  const generatedSetup = env.setupToken ?? randomToken(24);
  const setupToken = () => (store.get().users.some((u) => u.role === 'admin') ? null : generatedSetup);
  startSetupAnnouncements({ origin: env.origin, generated: env.setupToken ? undefined : generatedSetup }, () => setupToken() !== null);

  const tls = await TlsManager.create(env, store);
  const registry = new BackendRegistry(store);
  const audit = AuditLog.forDataDir(env.dataDir, env.encryptionKey, {
    gelfUrl: () => store.get().server.audit?.gelfUrl,
    anchor: {
      get: (chain) => store.get().server.audit?.anchors?.[chain],
      set: (chain, seq) =>
        store.touch((d) => {
          d.server.audit = { ...d.server.audit, anchors: { ...d.server.audit?.anchors, [chain]: seq } };
        }),
    },
  });
  const oauth = new OAuthService(store, `${env.origin}/mcp`, { httpsHosts: env.oauthRedirectHosts });
  transportPolicy.requireSecure = env.requireSecureTransport;
  for (const mod of BACKENDS) {
    const s = store.get().backends[mod.id];
    const why = s?.enabled ? insecureBackend(mod, s) : null;
    if (why) log.warn('Backend credentials travel over an insecure connection', { backend: mod.id, connection: why });
  }
  // O-003: every client behind a proxy shares its address unless the proxy is trusted to say who they are.
  if (env.tlsMode === 'off' && env.trustProxy === false) {
    log.warn('TLS_MODE=off without TRUST_PROXY: all clients share the proxy address for rate limiting. Set TRUST_PROXY, e.g. to 1.');
  }
  if (env.trustProxy === true) log.warn('TRUST_PROXY=true believes any X-Forwarded-For header; use a hop count or subnets instead.');
  // Scheduled backend health (DESIGN §3.4): the status bar and socbridge_backends read cached results.
  registry.startHealthChecks();
  // Open findings are compared over time for the vulnerability trend.
  const snapshots = VulnerabilitySnapshots.forDataDir(env.dataDir, env.encryptionKey);
  await snapshots.load();
  useSnapshots(snapshots);
  snapshots.start(async (fn) => {
    const client = registry.runtime<WazuhClient>('wazuh');
    if (client?.hasIndexer) await registry.gate(getModule('wazuh')!, client).run(() => fn(client));
  });
  const app = createApp({
    env,
    store,
    sessions: new SessionManager(),
    registry,
    audit,
    tokenLimiter: new FailureLimiter(20, 5 * 60 * 1000),
    authLimiter: new FailureLimiter(10, 15 * 60 * 1000),
    oauth,
    registerLimiter: new FailureLimiter(20, 60 * 60 * 1000),
    setupToken,
    caCertPem: tls?.caCertPem,
    tls,
  });

  oauth.onRevoked = (e) =>
    void auditEvent({ audit }, { by: { id: e.userId, name: e.userName }, action: 'auth.app.replay', text: 'Connection revoked after token replay', details: { id: e.grantId, client: e.client }, message: e.why });

  let server: Server;
  if (tls) {
    const https = createHttpsServer({ ...tls.initial, minVersion: 'TLSv1.2' }, app);
    tls.onSwap((ctx) => https.setSecureContext({ ...ctx, minVersion: 'TLSv1.2' }));
    server = https;
  } else {
    server = createHttpServer(app);
  }
  // Tool calls against slow backends can take a while; keep generous but bounded timeouts.
  server.requestTimeout = 120_000;
  server.headersTimeout = 30_000;

  server.listen(env.port, env.host, () => {
    log.info('SocBridge listening', {
      version: VERSION,
      address: `${env.host}:${env.port}`,
      tls: env.tlsMode,
      publicUrl: env.origin,
      mcpEndpoint: `${env.origin}/mcp`,
    });
  });

  const shutdown = (signal: string) => {
    log.info('Shutting down', { signal });
    server.close();
    store
      .flush()
      .catch((err) => log.error('Final config flush failed', { error: errMessage(err) }))
      .finally(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  if (err instanceof EnvError) log.error(`Configuration error: ${err.message}`);
  else log.error('Fatal startup error', { error: errMessage(err), stack: (err as Error)?.stack });
  process.exit(1);
});
