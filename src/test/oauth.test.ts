import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import express from 'express';
import { AuditLog } from '../audit/audit-log.js';
import { OAuthService, pkceS256, redirectAllowed } from '../auth/oauth.js';
import { FailureLimiter, RequestLimiter } from '../auth/ratelimit.js';
import { newAccessToken } from '../auth/secrets.js';
import { BackendRegistry } from '../backends/registry.js';
import { ConfigSchema, readAllScope, type User } from '../config/schema.js';
import { ConfigStore } from '../config/store.js';
import type { AppContext } from '../http/context.js';
import { mcpRouter } from '../http/mcp.js';
import { oauthRouter, RESOURCE_METADATA_PATH } from '../http/oauth.js';

const ORIGIN = 'https://mcp.example.com';
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

async function setup() {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-oauth-'));
  const store = ConfigStore.forDataDir(dir, randomBytes(32));
  await store.load();
  const now = new Date().toISOString();
  await store.mutate((d) => {
    d.users.push({ id: 'u1', name: 'alice', role: 'user', disabled: false, webauthnUserId: 'x', passkeys: [], createdAt: now });
    d.server.oauth = { enabled: true };
  });
  const user = store.get().users[0] as User;
  const oauth = new OAuthService(store, `${ORIGIN}/mcp`, { httpsHosts: ['claude.ai', 'claude.com'] });
  return { dir, store, user, oauth, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

async function serve(s: Awaited<ReturnType<typeof setup>>) {
  const tokenLimiter = new FailureLimiter(20, 60_000);
  const ctx = { env: { origin: ORIGIN }, store: s.store, tokenLimiter } as unknown as AppContext;
  const app = express();
  app.use(oauthRouter(ctx, s.oauth, new FailureLimiter(20, 60_000)));
  app.use(mcpRouter(s.store, new BackendRegistry(s.store), tokenLimiter, s.oauth, `${ORIGIN}${RESOURCE_METADATA_PATH}`, AuditLog.forDataDir(s.dir, randomBytes(32))));
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, close: () => new Promise((r) => server.close(r)) };
}

test('/mcp: per-user rate limit counts batch entries; refused calls in a batch are audited', async () => {
  const s = await setup();
  const { token, hash, hint } = newAccessToken();
  await s.store.mutate((d) => {
    d.tokens.push({ id: 't1', userId: s.user.id, label: 'test', hash, hint, createdAt: new Date().toISOString(), scope: { backends: {} } });
  });
  const audit = AuditLog.forDataDir(s.dir, randomBytes(32));
  const app = express();
  app.use(mcpRouter(s.store, new BackendRegistry(s.store), new FailureLimiter(20, 60_000), s.oauth, ORIGIN, audit, new RequestLimiter(5)));
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  const post = (body: unknown) =>
    fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
  const call = (id: number) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: `wazuh_nope_${id}`, arguments: {} } });
  try {
    assert.equal((await post(Array.from({ length: 21 }, (_, i) => call(i)))).status, 400, 'oversized batch');
    assert.equal((await post([call(1), call(2)])).status, 200);
    assert.equal((await audit.list({ outcome: 'denied' })).length, 2, 'every refused call in the batch is recorded');
    assert.equal((await post([call(3), call(4), call(5)])).status, 200);
    const limited = await post(call(6));
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '60');
    assert.equal((await audit.list()).length, 5, 'rate-limited calls are not recorded');
  } finally {
    await new Promise((r) => server.close(r));
    await s.cleanup();
  }
});

test('redirect URI policy', () => {
  const policy = { httpsHosts: ['claude.ai', 'claude.com'] };
  assert.ok(redirectAllowed(CALLBACK, policy));
  assert.ok(redirectAllowed('https://claude.com/api/mcp/auth_callback', policy));
  assert.ok(redirectAllowed('http://localhost:6274/callback', policy));
  assert.ok(redirectAllowed('http://127.0.0.1:33418/cb', policy));
  assert.ok(!redirectAllowed('https://evil.example/cb', policy));
  assert.ok(!redirectAllowed('http://claude.ai/cb', policy));
  assert.ok(!redirectAllowed('https://claude.ai.evil.example/cb', policy));
  assert.ok(!redirectAllowed('https://claude.ai/cb#frag', policy));
  assert.ok(!redirectAllowed('javascript:alert(1)', policy));
  assert.ok(redirectAllowed('https://anything.example/cb', { httpsHosts: ['*'] }));
});

test('OAuth: full connector flow over HTTP', async () => {
  const s = await setup();
  const srv = await serve(s);
  try {
    // 1. Unauthenticated MCP call points at the resource metadata.
    const probe = await fetch(`${srv.base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(probe.status, 401);
    assert.match(probe.headers.get('www-authenticate') ?? '', /resource_metadata="https:\/\/mcp\.example\.com\/\.well-known\/oauth-protected-resource\/mcp"/);

    // 2. Discovery.
    const prm = (await (await fetch(`${srv.base}${RESOURCE_METADATA_PATH}`)).json()) as { resource: string; authorization_servers: string[] };
    assert.equal(prm.resource, `${ORIGIN}/mcp`);
    assert.deepEqual(prm.authorization_servers, [ORIGIN]);
    const asm = (await (await fetch(`${srv.base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    assert.equal(asm.issuer, ORIGIN);
    assert.deepEqual(asm.code_challenge_methods_supported, ['S256']);

    // 3. Dynamic client registration: disallowed redirect is refused, Claude's is accepted.
    const bad = await fetch(`${srv.base}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'x', redirect_uris: ['https://evil.example/cb'] }),
    });
    assert.equal(bad.status, 400);
    const reg = await fetch(`${srv.base}/oauth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Claude', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' }),
    });
    assert.equal(reg.status, 201);
    const client = (await reg.json()) as { client_id: string; client_secret?: string };
    assert.equal(client.client_secret, undefined);

    // 4. Authorize redirects into the console consent screen.
    const verifier = randomBytes(32).toString('base64url');
    const q = new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: CALLBACK,
      state: 'st4te',
      code_challenge: pkceS256(verifier),
      code_challenge_method: 'S256',
      resource: `${ORIGIN}/mcp`,
    });
    const auth = await fetch(`${srv.base}/oauth/authorize?${q}`, { redirect: 'manual' });
    assert.equal(auth.status, 303);
    const loc = auth.headers.get('location') ?? '';
    const requestId = /^\/#\/authorize\/([A-Za-z0-9_-]+)$/.exec(loc)?.[1];
    assert.ok(requestId, loc);

    // Unknown redirect URI must not redirect anywhere.
    const evil = new URLSearchParams(q);
    evil.set('redirect_uri', 'https://claude.ai/other');
    assert.equal((await fetch(`${srv.base}/oauth/authorize?${evil}`, { redirect: 'manual' })).status, 400);

    // The request is bound to the browser that started it (O-002).
    const browser = /socbridge_oauth=([^;]+)/.exec(auth.headers.get('set-cookie') ?? '')?.[1];
    assert.ok(browser, 'authorize sets the browser cookie');
    assert.match(auth.headers.get('set-cookie') ?? '', /HttpOnly/i);
    assert.equal(s.oauth.describeRequest(requestId), null, 'no cookie: not visible');
    assert.equal(s.oauth.describeRequest(requestId, 'x'.repeat(43)), null, 'another browser: not visible');
    assert.equal(s.oauth.decide(requestId, s.user, true, undefined, 'x'.repeat(43)), null, 'another browser cannot approve');

    // 5. User approves (what the console API does).
    const d = s.oauth.describeRequest(requestId, browser);
    assert.equal(d?.clientName, 'Claude');
    assert.equal(d?.redirectUri, CALLBACK);
    assert.equal(d?.previouslyApproved, false);
    const back = new URL(s.oauth.decide(requestId, s.user, true, undefined, browser)!);
    assert.equal(back.origin + back.pathname, CALLBACK);
    assert.equal(back.searchParams.get('state'), 'st4te');
    assert.equal(back.searchParams.get('iss'), ORIGIN);
    const code = back.searchParams.get('code')!;
    assert.equal(s.oauth.decide(requestId, s.user, true, undefined, browser), null, 'request is single use');

    // 6. Token exchange: wrong verifier burns the code.
    const tokenReq = (body: Record<string, string>) =>
      fetch(`${srv.base}/oauth/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(body),
      });
    const good = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: CALLBACK, code_verifier: verifier, client_id: client.client_id });
    assert.equal(good.status, 200);
    const tokens = (await good.json()) as { access_token: string; refresh_token: string; token_type: string; expires_in: number };
    assert.equal(tokens.token_type, 'Bearer');
    assert.ok(tokens.access_token.startsWith('msat_'));
    // 7. The access token works on /mcp.
    const mcp = (token: string) =>
      fetch(`${srv.base}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
    assert.equal((await mcp(tokens.access_token)).status, 200);

    // 8. Refresh rotates both tokens; the old ones stop working.
    const ref = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
    assert.equal(ref.status, 200);
    const next = (await ref.json()) as { access_token: string; refresh_token: string };
    assert.notEqual(next.refresh_token, tokens.refresh_token);
    assert.equal((await mcp(tokens.access_token)).status, 401);
    assert.equal((await mcp(next.access_token)).status, 200);
    const reused = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
    assert.equal(reused.status, 400);
    assert.equal((await mcp(next.access_token)).status, 200, 'an immediate retry does not end the connection');

    // 9. Disabling the user, then revoking the grant, cuts access immediately.
    await s.store.mutate((d) => {
      d.users[0]!.disabled = true;
    });
    assert.equal((await mcp(next.access_token)).status, 401);
    await s.store.mutate((d) => {
      d.users[0]!.disabled = false;
    });
    assert.equal((await mcp(next.access_token)).status, 200);
    const revoke = await fetch(`${srv.base}/oauth/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: next.refresh_token, client_id: client.client_id }),
    });
    assert.equal(revoke.status, 200);
    assert.equal((await mcp(next.access_token)).status, 401);
    assert.equal(s.store.get().oauthGrants.length, 0);
  } finally {
    await srv.close();
    await s.cleanup();
  }
});

test('OAuth: replayed codes and refresh tokens end the connection; refreshing cannot outlive the maximum age', async () => {
  const s = await setup();
  const events: string[] = [];
  s.oauth.onRevoked = (e) => events.push(e.why);
  const { client } = await s.oauth.register({ redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' });
  const verifier = 'v'.repeat(50);
  const connect = async () => {
    const started = s.oauth.startAuthorization({ response_type: 'code', client_id: client.id, redirect_uri: CALLBACK, code_challenge: pkceS256(verifier), code_challenge_method: 'S256' });
    const back = new URL(s.oauth.decide((started as { requestId: string }).requestId, s.user, true)!);
    const code = back.searchParams.get('code')!;
    return { code, tokens: await s.oauth.exchangeCode(client, { code, code_verifier: verifier }) };
  };
  try {
    const a = await connect();
    assert.ok(s.oauth.verifyAccessToken(a.tokens.access_token));
    await assert.rejects(s.oauth.exchangeCode(client, { code: a.code, code_verifier: verifier }), /already used/);
    assert.equal(s.oauth.verifyAccessToken(a.tokens.access_token), null, 'code replay');

    const b = await connect();
    const second = await s.oauth.refresh(client, b.tokens.refresh_token);
    const third = await s.oauth.refresh(client, second.refresh_token);
    await assert.rejects(s.oauth.refresh(client, b.tokens.refresh_token), /revoked/);
    assert.equal(s.oauth.verifyAccessToken(third.access_token), null, 'refresh replay');
    assert.deepEqual(events, ['authorization code replayed', 'refresh token replayed']);

    const c = await connect();
    await s.store.mutate((d) => { d.oauthGrants[0]!.createdAt = new Date(Date.now() - 181 * 86_400_000).toISOString(); });
    await assert.rejects(s.oauth.refresh(client, c.tokens.refresh_token), /maximum age/);

    let refused = 0;
    for (let i = 0; i < 60; i++) if ('redirect' in s.oauth.startAuthorization({ response_type: 'code', client_id: client.id, redirect_uri: CALLBACK, code_challenge: pkceS256(verifier), code_challenge_method: 'S256' })) refused++;
    assert.equal(refused, 10, 'one client cannot fill the request table');
  } finally {
    await s.cleanup();
  }
});

test('OAuth: off by default, and turning it off shuts every entry point', async () => {
  const s = await setup();
  const srv = await serve(s);
  const setEnabled = (on: boolean) =>
    s.store.mutate((d) => {
      d.server.oauth = { enabled: on };
    });
  try {
    // A fresh config has it off.
    const fresh = await mkdtemp(path.join(tmpdir(), 'socbridge-oauth-'));
    const fs = ConfigStore.forDataDir(fresh, randomBytes(32));
    await fs.load();
    assert.equal(new OAuthService(fs, `${ORIGIN}/mcp`, { httpsHosts: ['claude.ai'] }).enabled(), false);
    await rm(fresh, { recursive: true, force: true });

    // Get a working token while on.
    const { client } = await s.oauth.register({ client_name: 'c', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' });
    const verifier = randomBytes(32).toString('base64url');
    const r = s.oauth.startAuthorization({ response_type: 'code', client_id: client.id, redirect_uri: CALLBACK, code_challenge: pkceS256(verifier), code_challenge_method: 'S256' });
    assert.ok('requestId' in r);
    const pendingId = (s.oauth.startAuthorization({ response_type: 'code', client_id: client.id, redirect_uri: CALLBACK, code_challenge: pkceS256(verifier), code_challenge_method: 'S256' }) as { requestId: string }).requestId;
    const code = new URL(s.oauth.decide(r.requestId, s.user, true)!).searchParams.get('code')!;
    const tokens = await s.oauth.exchangeCode(client, { code, code_verifier: verifier });
    const mcp = () =>
      fetch(`${srv.base}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tokens.access_token}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
    assert.equal((await mcp()).status, 200);

    await setEnabled(false);
    for (const p of [RESOURCE_METADATA_PATH, '/.well-known/oauth-protected-resource', '/.well-known/oauth-authorization-server', '/oauth/authorize?client_id=x']) {
      const res = await fetch(`${srv.base}${p}`, { redirect: 'manual' });
      assert.equal(res.status, 404, p);
    }
    for (const p of ['/oauth/register', '/oauth/token', '/oauth/revoke']) {
      assert.equal((await fetch(`${srv.base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 404, p);
    }
    const probe = await fetch(`${srv.base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(probe.headers.get('www-authenticate'), 'Bearer realm="socbridge"');
    assert.equal((await mcp()).status, 401, 'existing OAuth token refused while off');
    assert.equal(s.oauth.describeRequest(pendingId), null, 'consent screen refuses while off');
    assert.equal(s.oauth.decide(pendingId, s.user, true), null);
    assert.equal(s.store.get().oauthGrants.length, 1, 'grants are kept');

    await setEnabled(true);
    assert.equal((await mcp()).status, 200, 'turning it back on restores the grant');
  } finally {
    await srv.close();
    await s.cleanup();
  }
});

test('OAuth: PKCE is required and verified; denial returns access_denied', async () => {
  const s = await setup();
  try {
    const { client } = await s.oauth.register({ client_name: 'c', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' });
    const noPkce = s.oauth.startAuthorization({ response_type: 'code', client_id: client.id, redirect_uri: CALLBACK, state: 's' });
    assert.ok('redirect' in noPkce && new URL(noPkce.redirect).searchParams.get('error') === 'invalid_request');

    const verifier = randomBytes(32).toString('base64url');
    const start = (): string => {
      const r = s.oauth.startAuthorization({
        response_type: 'code',
        client_id: client.id,
        redirect_uri: CALLBACK,
        code_challenge: pkceS256(verifier),
        code_challenge_method: 'S256',
      });
      assert.ok('requestId' in r);
      return r.requestId;
    };
    const denied = new URL(s.oauth.decide(start(), s.user, false)!);
    assert.equal(denied.searchParams.get('error'), 'access_denied');

    const code = new URL(s.oauth.decide(start(), s.user, true)!).searchParams.get('code')!;
    await assert.rejects(
      s.oauth.exchangeCode(client, { code, code_verifier: randomBytes(32).toString('base64url') }),
      (e: Error & { code?: string }) => e.code === 'invalid_grant',
    );
    // A failed attempt consumed the code.
    await assert.rejects(s.oauth.exchangeCode(client, { code, code_verifier: verifier }));
  } finally {
    await s.cleanup();
  }
});

test('OAuth: confidential clients must authenticate', async () => {
  const s = await setup();
  try {
    const { client, secret } = await s.oauth.register({ client_name: 'c', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'client_secret_post' });
    assert.ok(secret);
    assert.throws(() => s.oauth.authenticateClient(client.id, undefined));
    assert.throws(() => s.oauth.authenticateClient(client.id, 'wrong'));
    assert.equal(s.oauth.authenticateClient(client.id, secret).id, client.id);
  } finally {
    await s.cleanup();
  }
});

test('oauth: the access approved on the consent screen is stored on the grant and survives refresh', async () => {
  const s = await setup();
  try {
    const { client } = await s.oauth.register({ client_name: 'c', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' });
    const verifier = randomBytes(32).toString('base64url');
    const start = () =>
      (s.oauth.startAuthorization({ response_type: 'code', client_id: client.id, redirect_uri: CALLBACK, code_challenge: pkceS256(verifier), code_challenge_method: 'S256' }) as { requestId: string }).requestId;

    const access = { backends: { defectdojo: 'write' as const, wazuh: 'read' as const } };
    const code = new URL(s.oauth.decide(start(), s.user, true, access)!).searchParams.get('code')!;
    const t = await s.oauth.exchangeCode(client, { code, code_verifier: verifier });
    assert.deepEqual(s.store.get().oauthGrants[0]!.access, access);
    await s.oauth.refresh(client, t.refresh_token);
    assert.deepEqual(s.store.get().oauthGrants[0]!.access, access, 'refresh keeps the approved access');

    // Without a choice (older clients of the API) the grant reads every backend.
    const code2 = new URL(s.oauth.decide(start(), s.user, true)!).searchParams.get('code')!;
    await s.oauth.exchangeCode(client, { code: code2, code_verifier: verifier });
    assert.deepEqual(s.store.get().oauthGrants[1]!.access, readAllScope());
  } finally {
    await s.cleanup();
  }
});

test('oauth: grants stored before scopes existed load as read on every backend', async () => {
  const s = await setup();
  try {
    const now = new Date().toISOString();
    const legacy = { id: 'g0', userId: 'u1', clientId: 'c', clientName: 'Claude', scope: 'mcp', accessHash: 'a'.repeat(64), accessExpiresAt: now, refreshHash: 'b'.repeat(64), refreshExpiresAt: now, createdAt: now };
    const parsed = ConfigSchema.parse({ version: 1, oauthGrants: [legacy] });
    assert.deepEqual(parsed.oauthGrants[0]!.access, readAllScope());
  } finally {
    await s.cleanup();
  }
});
