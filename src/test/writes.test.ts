import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, beforeEach, test } from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AuditLog, redact } from '../audit/audit-log.js';
import { scopeProblem, backendAccess, type Principal } from '../auth/scopes.js';
import { defectdojo } from '../backends/defectdojo/index.js';
import { allowlisted, BackendRegistry } from '../backends/registry.js';
import { wazuh } from '../backends/wazuh/index.js';
import { readAllScope, type Config, type TokenScope } from '../config/schema.js';
import { ConfigStore } from '../config/store.js';
import { encryptJson, decryptJson } from '../crypto/secretbox.js';
import { encrypt } from '../crypto/secretbox.js';
import { insecureUrl, transportPolicy } from '../backends/transport.js';
import { auditEvent } from '../http/audit-event.js';
import { buildMcpServer } from '../mcp/server.js';

// ---------------------------------------------------------------- mocks

type Call = { method: string; path: string; query: Record<string, string>; body?: unknown };
let calls: Call[] = [];
let mock: http.Server;
let base = '';
/** Mutable mock state, reset before each test. */
let finding: Record<string, unknown>;
let agentGroups: string[];
let failNext = 0;

function resetState() {
  calls = [];
  failNext = 0;
  finding = { id: 11, title: 'xz-utils backdoor', active: true, verified: true, is_mitigated: false, false_p: false, risk_accepted: false };
  agentGroups = ['default'];
}

before(async () => {
  mock = http.createServer(async (req, res) => {
    const u = new URL(req.url!, 'http://x');
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString();
    const body = raw ? JSON.parse(raw) : undefined;
    calls.push({ method: req.method!, path: u.pathname, query: Object.fromEntries(u.searchParams), body });
    const send = (s: number, o: unknown, text = false) => {
      res.writeHead(s, { 'content-type': text ? 'text/plain' : 'application/json' });
      res.end(text ? String(o) : JSON.stringify(o));
    };
    if (failNext > 0) {
      failNext--;
      return send(500, { detail: 'boom' });
    }
    // --- DefectDojo
    if (u.pathname.startsWith('/dd/')) {
      if (req.headers.authorization !== 'Token k') return send(401, { detail: 'Invalid token.' });
      const p = u.pathname.slice(3);
      if (p === '/api/v2/findings/11/' && req.method === 'GET') return send(200, finding);
      if (p === '/api/v2/findings/404/') return send(404, { detail: 'Not found.' });
      if (p === '/api/v2/findings/11/notes/') return send(201, { id: 1, entry: body.entry });
      if (p === '/api/v2/findings/11/close/') {
        Object.assign(finding, { active: false, is_mitigated: true, mitigated: body.mitigated });
        return send(200, {});
      }
      if (p === '/api/v2/findings/11/' && req.method === 'PATCH') {
        Object.assign(finding, body);
        return send(200, finding);
      }
      if (p === '/api/v2/user_profile/') return send(200, { user: { id: 7, username: 'socbridge' } });
      if (p === '/api/v2/risk_acceptance/') {
        Object.assign(finding, { risk_accepted: true, active: false });
        return send(201, { id: 99, ...body });
      }
      return send(404, { detail: 'Not found.' });
    }
    // --- Wazuh manager
    if (u.pathname === '/security/user/authenticate') return send(200, 'JWT', true);
    if (u.pathname === '/agents') {
      const id = u.searchParams.get('agents_list');
      const items = id === '001' ? [{ id: '001', name: 'web-01', status: 'active', group: [...agentGroups] }] : [];
      return send(200, { data: { affected_items: items, total_affected_items: items.length } });
    }
    if (u.pathname === '/groups') {
      const g = u.searchParams.get('groups_list');
      const items = ['default', 'webservers'].filter((x) => !g || x === g).map((name) => ({ name, count: 1 }));
      return send(200, { data: { affected_items: items, total_affected_items: items.length } });
    }
    const gm = /^\/agents\/001\/group\/([^/]+)$/.exec(u.pathname);
    if (gm) {
      const g = decodeURIComponent(gm[1]!);
      if (req.method === 'PUT') agentGroups.push(g);
      if (req.method === 'DELETE') agentGroups = agentGroups.filter((x) => x !== g);
      return send(200, { data: { affected_items: ['001'], total_affected_items: 1, failed_items: [] }, message: 'done' });
    }
    if (u.pathname === '/active-response' && req.method === 'PUT') {
      return send(200, { data: { affected_items: ['001'], total_affected_items: 1, failed_items: [] }, message: 'AR command was sent' });
    }
    send(404, { title: 'Not found' });
  });
  mock.listen(0, '127.0.0.1');
  await new Promise((r) => mock.once('listening', r));
  base = `http://127.0.0.1:${(mock.address() as AddressInfo).port}`;
});
after(() => new Promise<void>((r) => mock.close(() => r())));
beforeEach(resetState);

// ---------------------------------------------------------------- fixtures

const now = new Date().toISOString();

async function setup(opts: { allowWrite?: boolean; grant?: string[]; scope?: TokenScope; allowlist?: string[] } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-w-'));
  const key = randomBytes(32);
  const store = ConfigStore.forDataDir(dir, key);
  await store.load();
  await store.mutate((d) => {
    d.users.push({ id: 'u1', name: 'alice', role: 'user', disabled: false, webauthnUserId: 'x', passkeys: [], writeBackends: opts.grant ?? [], createdAt: now });
    d.tokens.push({ id: 't1', userId: 'u1', label: 'laptop', hash: 'a'.repeat(64), hint: 'msec_aaaa', createdAt: now, scope: opts.scope ?? readAllScope() });
    d.backends.defectdojo = {
      enabled: true,
      url: `${base}/dd`,
      apiKey: 'k',
      ...(opts.allowWrite ? { allowWrite: true } : {}),
      ...(opts.allowlist ? { tools: opts.allowlist } : {}),
    };
    d.backends.wazuh = {
      enabled: true,
      managerUrl: base,
      managerUser: 'u',
      managerPassword: 'p',
      activeResponseCommands: '!firewall-drop',
      ...(opts.allowWrite ? { allowWrite: true } : {}),
      ...(opts.allowlist ? { tools: opts.allowlist } : {}),
    };
  });
  const registry = new BackendRegistry(store);
  const audit = AuditLog.forDataDir(dir, key);
  return { dir, key, store, registry, audit, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

const tokenPrincipal: Principal = { kind: 'token', id: 't1', userId: 'u1', userName: 'alice', label: 'laptop' };
const WRITE_SCOPE: TokenScope = { backends: { defectdojo: 'write', wazuh: 'write' } };
const ALL_TOOLS = ['defectdojo_*', 'wazuh_*'];

async function connect(s: Awaited<ReturnType<typeof setup>>, p: Principal = tokenPrincipal, source: 'mcp' | 'chat' = 'mcp') {
  const { server, tools } = await buildMcpServer(s.registry, p, { audit: s.audit, source });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const c = new Client({ name: 'c', version: '0' });
  await server.connect(b);
  await c.connect(a);
  return { c, tools, close: () => c.close() };
}

const text = (r: unknown) => (((r as { content: { text: string }[] }).content)[0] ?? { text: '' }).text;

// ---------------------------------------------------------------- migration

test('scopes: tokens stored before scopes existed load as read on every backend and are saved that way', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-mig-'));
  try {
    const key = randomBytes(32);
    const file = path.join(dir, 'config.enc.json');
    const legacy = {
      version: 1,
      users: [{ id: 'u1', name: 'alice', role: 'user', disabled: false, webauthnUserId: 'x', passkeys: [], createdAt: now }],
      tokens: [{ id: 't1', userId: 'u1', label: 'old', hash: 'b'.repeat(64), hint: 'msec_bbbb', createdAt: now }],
      backends: { wazuh: { enabled: true } },
    };
    await writeFile(file, encryptJson(key, 'config', legacy));
    const store = new ConfigStore(file, key);
    await store.load();
    assert.deepEqual(store.get().tokens[0]!.scope, { backends: { wazuh: 'read', trivy: 'read', defectdojo: 'read', graylog: 'read', intel: 'read' } });
    assert.equal(store.get().users[0]!.writeBackends, undefined, 'no write grant appears out of nowhere');
    assert.equal(store.get().backends.wazuh!.allowWrite, undefined);
    await store.flush();
    const saved = decryptJson<Config>(key, 'config', await readFile(file, 'utf8'));
    assert.deepEqual(saved.tokens[0]!.scope, readAllScope());
    const level = backendAccess(store.get(), { kind: 'token', id: 't1', userId: 'u1', userName: 'alice' }, 'wazuh').level;
    assert.equal(level, 'read');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- access matrix

test('scopes: write needs installation, user grant and token scope; everything else degrades to read', async () => {
  const s = await setup({ scope: WRITE_SCOPE });
  try {
    const cfg = () => s.store.get();
    assert.deepEqual(backendAccess(cfg(), tokenPrincipal, 'defectdojo'), { level: 'read', reason: 'write tools are off for this backend' });
    await s.store.mutate((d) => (d.backends.defectdojo!.allowWrite = true));
    assert.deepEqual(backendAccess(cfg(), tokenPrincipal, 'defectdojo'), { level: 'read', reason: 'user has no write grant for this backend' });
    await s.store.mutate((d) => (d.users[0]!.writeBackends = ['defectdojo']));
    assert.deepEqual(backendAccess(cfg(), tokenPrincipal, 'defectdojo'), { level: 'write' });
    // Not in the token's scope at all: no access.
    assert.equal(backendAccess(cfg(), tokenPrincipal, 'trivy').level, 'none');
    // The chat never writes, whatever the grants say.
    assert.equal(backendAccess(cfg(), { kind: 'chat', id: 'u1', userId: 'u1', userName: 'alice' }, 'defectdojo').level, 'read');
    // OAuth grants follow the access approved on the consent screen, with the same three levels.
    const grant = (id: string, access: TokenScope) => ({
      id, userId: 'u1', clientId: 'c', clientName: 'Claude', scope: 'mcp', access,
      accessHash: 'c'.repeat(64), accessExpiresAt: now, refreshHash: 'd'.repeat(64), refreshExpiresAt: now, createdAt: now,
    });
    await s.store.mutate((d) => {
      d.oauthGrants.push(grant('g1', { backends: { defectdojo: 'write' } }), grant('g2', readAllScope()));
    });
    const app = (id: string): Principal => ({ kind: 'oauth', id, userId: 'u1', userName: 'alice' });
    assert.equal(backendAccess(cfg(), app('g1'), 'defectdojo').level, 'write');
    assert.deepEqual(backendAccess(cfg(), app('g1'), 'wazuh'), { level: 'none', reason: 'not in the scope approved for this app' });
    assert.equal(backendAccess(cfg(), app('g2'), 'defectdojo').level, 'read');
    await s.store.mutate((d) => (d.users[0]!.writeBackends = []));
    assert.equal(backendAccess(cfg(), app('g1'), 'defectdojo').level, 'read', 'removing the grant demotes the app too');
    // Revoked token, disabled user.
    await s.store.mutate((d) => (d.users[0]!.disabled = true));
    assert.equal(backendAccess(cfg(), tokenPrincipal, 'defectdojo').level, 'none');
  } finally {
    await s.cleanup();
  }
});

test('allowlist: defaults are the read tools; write tools only when listed; patterns', () => {
  const read = { name: 'wazuh_list_agents', access: 'read' as const };
  const write = { name: 'wazuh_add_agent_group', access: 'write' as const, default: true };
  assert.equal(allowlisted(undefined, read), true);
  assert.equal(allowlisted({}, write), false, 'write tools are never default, even if a module says so');
  assert.equal(allowlisted({ tools: ['wazuh_*'] }, write), true);
  assert.equal(allowlisted({ tools: ['wazuh_list_agents'] }, write), false);
  assert.equal(allowlisted({ tools: ['wazuh_get_agent'] }, read), false);
  assert.equal(allowlisted(undefined, { name: 'x', access: 'read', default: false }), false);
});

// ---------------------------------------------------------------- registration

test('registration: a read-only token sees no write tools and nothing outside its scope', async () => {
  const s = await setup({ allowWrite: true, grant: ['defectdojo', 'wazuh'], allowlist: ALL_TOOLS, scope: { backends: { defectdojo: 'read' } } });
  const { c, close } = await connect(s);
  try {
    const tools = (await c.listTools()).tools;
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('defectdojo_list_findings'));
    assert.ok(!names.some((n) => n.startsWith('wazuh_')), 'wazuh is not in the scope');
    assert.ok(!names.includes('defectdojo_close_finding'));
    assert.ok(tools.every((t) => t.annotations?.readOnlyHint === true));
  } finally {
    await close();
    await s.cleanup();
  }
});

test('registration: write tools need all three levels and the allowlist, and are marked as writes', async () => {
  // Granted and scoped, but not on the allowlist (module defaults): still no write tools.
  const a = await setup({ allowWrite: true, grant: ['defectdojo', 'wazuh'], scope: WRITE_SCOPE });
  const ca = await connect(a);
  try {
    assert.ok(!(await ca.c.listTools()).tools.some((t) => t.annotations?.readOnlyHint === false));
  } finally {
    await ca.close();
    await a.cleanup();
  }

  const s = await setup({ allowWrite: true, grant: ['defectdojo', 'wazuh'], scope: WRITE_SCOPE, allowlist: ALL_TOOLS });
  const { c, close } = await connect(s);
  try {
    const tools = (await c.listTools()).tools;
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    for (const n of ['defectdojo_close_finding', 'defectdojo_risk_accept_finding', 'defectdojo_mark_false_positive', 'wazuh_add_agent_group', 'wazuh_remove_agent_group', 'wazuh_run_active_response']) {
      assert.ok(byName[n], `${n} registered`);
      assert.equal(byName[n]!.annotations?.readOnlyHint, false);
      assert.match(byName[n]!.description ?? '', /^\[WRITE — changes (DefectDojo|Wazuh)\]/);
    }
    assert.equal(byName.wazuh_run_active_response!.annotations?.destructiveHint, true);
    assert.equal(byName.defectdojo_close_finding!.annotations?.destructiveHint, false);
    assert.match(byName.wazuh_run_active_response!.description ?? '', /Only these commands are allowed: !firewall-drop\./);
    assert.equal(byName.defectdojo_list_findings!.annotations?.readOnlyHint, true);
  } finally {
    await close();
  }
  // The chat, as the same user, never gets them.
  const chat = await connect(s, { kind: 'chat', id: 'u1', userId: 'u1', userName: 'alice' }, 'chat');
  try {
    const tools = (await chat.c.listTools()).tools;
    assert.ok(tools.length > 5);
    assert.ok(tools.every((t) => t.annotations?.readOnlyHint === true), 'chat tool list is read-only');
  } finally {
    await chat.close();
    await s.cleanup();
  }
});

// ---------------------------------------------------------------- call time + audit

test('call time: access is checked again; a grant removed after registration denies the call and audits it', async () => {
  const s = await setup({ allowWrite: true, grant: ['defectdojo'], scope: WRITE_SCOPE, allowlist: ALL_TOOLS });
  const { c, close } = await connect(s);
  try {
    await s.store.mutate((d) => (d.users[0]!.writeBackends = []));
    const r = await c.callTool({ name: 'defectdojo_close_finding', arguments: { finding_id: 11, note: 'fixed in build 812' } });
    assert.equal(r.isError, true);
    assert.match(text(r), /defectdojo_close_finding refused: user has no write grant/);
    assert.equal(calls.length, 0, 'the backend was not called');
    // A read on the same backend still works.
    const ok = await c.callTool({ name: 'defectdojo_get_finding', arguments: { finding_id: 11 } });
    assert.notEqual(ok.isError, true);
    // Switching the backend's write tools off denies too.
    await s.store.mutate((d) => {
      d.users[0]!.writeBackends = ['defectdojo'];
      d.backends.defectdojo!.allowWrite = false;
    });
    const r2 = await c.callTool({ name: 'defectdojo_mark_false_positive', arguments: { finding_id: 11, reason: 'not reachable in prod' } });
    assert.match(text(r2), /refused: write tools are off for this backend/);

    const recs = await s.audit.list();
    assert.deepEqual(recs.map((x) => [x.tool, x.outcome]), [
      ['defectdojo_mark_false_positive', 'denied'],
      ['defectdojo_get_finding', 'ok'],
      ['defectdojo_close_finding', 'denied'],
    ]);
    assert.equal(recs[2]!.access, 'write');
    assert.equal(recs[2]!.credential, 'token:t1');
    assert.equal(recs[2]!.credentialLabel, 'laptop');
    assert.deepEqual(recs[2]!.args, { finding_id: 11, note: 'fixed in build 812' });
  } finally {
    await close();
    await s.cleanup();
  }
});

test('audit: successful, failed and denied calls are recorded with duration and result hash, not the result', async () => {
  const s = await setup({ scope: { backends: { defectdojo: 'read' } } });
  const { c, close } = await connect(s);
  try {
    await c.callTool({ name: 'defectdojo_get_finding', arguments: { finding_id: 11 } });
    failNext = 1;
    const bad = await c.callTool({ name: 'defectdojo_get_finding', arguments: { finding_id: 11 } });
    assert.equal(bad.isError, true);
    const shown = JSON.stringify(bad.content);
    assert.match(shown, /The backend responded 500 \(reference [0-9a-f]{8}\)/);
    assert.ok(!shown.includes('127.0.0.1') && !shown.includes('boom'), 'host and response are not shown to non-administrators');
    await s.store.mutate((d) => (d.tokens[0]!.scope = { backends: {} }));
    await c.callTool({ name: 'defectdojo_get_finding', arguments: { finding_id: 11 } });
    const [denied, failed, ok] = await s.audit.list();
    assert.equal(ok!.outcome, 'ok');
    assert.match(ok!.resultSha256 ?? '', /^[0-9a-f]{64}$/);
    assert.ok((ok!.resultChars ?? 0) > 10);
    assert.ok(!JSON.stringify(ok).includes('xz-utils'), 'the result itself is not stored');
    assert.equal(failed!.outcome, 'error');
    assert.match(failed!.message ?? '', /responded 500/);
    assert.equal(denied!.outcome, 'denied');
    assert.match(denied!.message ?? '', /not in token scope/);
    assert.ok([ok, failed, denied].every((r) => r!.user === 'alice' && r!.source === 'mcp' && typeof r!.durationMs === 'number'));
    assert.deepEqual(await s.audit.list({ outcome: 'error' }), [failed]);
  } finally {
    await close();
    await s.cleanup();
  }
});

test('audit: secrets are redacted; the file is encrypted and hash-chained; tampering is detected', async () => {
  assert.deepEqual(redact({ api_key: 'x', nested: { password: 'p', ok: 'Bearer abc.def', t: 'use msec_0123456789abcdef' } }), {
    api_key: '[redacted]',
    nested: { password: '[redacted]', ok: '[redacted]', t: 'use [redacted]' },
  });
  assert.match(String(redact('a'.repeat(1500))), /… \[500 more\]$/);

  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-audit-'));
  try {
    const key = randomBytes(32);
    const audit = AuditLog.forDataDir(dir, key, { maxBytes: 4000, keep: 2 });
    const base = { source: 'mcp' as const, user: 'alice', userId: 'u1', credential: 'token:t1', backend: 'wazuh', access: 'read' as const, outcome: 'ok' as const, durationMs: 1 };
    await Promise.all(Array.from({ length: 12 }, (_, i) => audit.record({ ...base, tool: `wazuh_tool_${i}`, args: { i, token: 'secret-value' } })));
    const raw = await readFile(path.join(dir, 'audit.log'), 'utf8');
    assert.ok(!raw.includes('alice') && !raw.includes('secret-value'), 'encrypted at rest');
    const all = await audit.list({}, 50);
    assert.ok(all.length >= 6, 'reads across rotated files');
    assert.ok(all.every((r) => (r.args as { token: string }).token === '[redacted]'));
    assert.deepEqual((await audit.verify()).ok, true);

    // Drop one line from the middle of the current file.
    const lines = raw.split('\n').filter(Boolean);
    assert.ok(lines.length >= 3);
    lines.splice(1, 1);
    await writeFile(path.join(dir, 'audit.log'), lines.join('\n') + '\n');
    const v = await new AuditLog(path.join(dir, 'audit.log'), key, { keep: 2 }).verify();
    assert.equal(v.ok, false);
    assert.match(v.problems.join(), /audit\.log:2: chain broken/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('audit: a flood of reads and refusals cannot evict writes or administrative events', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-audit-flood-'));
  try {
    const key = randomBytes(32);
    const audit = AuditLog.forDataDir(dir, key, { maxBytes: 4000, keep: 2 });
    const base = { source: 'mcp' as const, user: 'mallory', userId: 'u1', credential: 'token:t1', backend: 'wazuh', durationMs: 1, args: {} };
    await audit.record({ ...base, tool: 'wazuh_run_active_response', access: 'write', outcome: 'ok' });
    await auditEvent({ audit }, { by: { id: 'u2', name: 'alice' }, action: 'admin.user.update', text: 'User updated', details: { id: 'u1' } });
    for (let i = 0; i < 60; i++) await audit.record({ ...base, tool: 'x'.repeat(5000), backend: 'y'.repeat(5000), access: 'write', outcome: 'denied', args: { pad: 'z'.repeat(5000) } });
    const all = await audit.list({}, 500);
    assert.ok(all.length < 62, 'the flood rotated');
    assert.deepEqual(all.filter((r) => r.outcome === 'ok').map((r) => r.tool).sort(), ['admin.user.update', 'wazuh_run_active_response']);
    const denied = all.find((r) => r.outcome === 'denied')!;
    assert.equal(denied.tool.length, 128);
    assert.equal(denied.backend.length, 128);
    assert.ok(JSON.stringify(denied.args).length < 600);
    const v = await audit.verify();
    assert.equal(v.ok, true);
    assert.equal(v.dropped, 62 - all.length, 'verify reports what rotation dropped');
    assert.equal((await audit.stats()).totals.writes, 1 + denied_writes(all), 'administrative events are not usage');

    // Numbering and chain continue after a restart.
    const again = AuditLog.forDataDir(dir, key, { maxBytes: 4000, keep: 2 });
    const r = await again.record({ ...base, tool: 'wazuh_run_active_response', access: 'write', outcome: 'ok' });
    assert.equal(r.seq, 3);
    assert.equal((await again.verify()).ok, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const denied_writes = (rs: { outcome: string; access: string }[]) => rs.filter((r) => r.outcome === 'denied' && r.access === 'write').length;

test('tool errors: administrators see the backend error itself', async () => {
  const s = await setup({ scope: { backends: { defectdojo: 'read' } } });
  await s.store.mutate((d) => (d.users[0]!.role = 'admin'));
  const { c, close } = await connect(s);
  try {
    failNext = 1;
    assert.match(JSON.stringify((await c.callTool({ name: 'defectdojo_get_finding', arguments: { finding_id: 11 } })).content), /127\.0\.0\.1:\d+ responded 500: boom/);
  } finally {
    await close();
    await s.cleanup();
  }
});

test('audit: removing a log together with its head file is noticed', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-audit-rm-'));
  try {
    const key = randomBytes(32);
    const base = { source: 'mcp' as const, user: 'a', userId: 'u', credential: 'token:t', tool: 'wazuh_list_agents', backend: 'wazuh', access: 'read' as const, outcome: 'ok' as const, durationMs: 1, args: {} };
    const kept = new Map<string, number>();
    const anchor = { get: (c: string) => kept.get(c), set: (c: string, n: number) => void kept.set(c, n) };
    const audit = AuditLog.forDataDir(dir, key, { anchor });
    for (let i = 0; i < 5; i++) await audit.record(base);
    assert.equal((await audit.verify()).ok, true);
    kept.set('audit.log', 5);
    const wipe = async () => {
      await rm(path.join(dir, 'audit.log'));
      await rm(path.join(dir, 'audit.log.head'));
    };
    await wipe();
    const again = AuditLog.forDataDir(dir, key, { anchor });
    assert.match((await again.verify()).problems.join(), /5 newest record\(s\) missing/);
    assert.equal((await again.record(base)).seq, 6);
    assert.match((await again.verify()).problems.join(), /5 oldest record\(s\) missing/, 'still visible after new records');
    // While running, the position in memory is enough.
    await wipe();
    await again.record(base);
    assert.equal((await again.verify()).ok, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('audit: records cut off the end are noticed, also after more are written', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-audit-cut-'));
  try {
    const key = randomBytes(32);
    const base = { source: 'mcp' as const, user: 'a', userId: 'u', credential: 'token:t', tool: 'wazuh_list_agents', backend: 'wazuh', access: 'read' as const, outcome: 'ok' as const, durationMs: 1, args: {} };
    const audit = AuditLog.forDataDir(dir, key);
    for (let i = 0; i < 5; i++) await audit.record(base);
    const file = path.join(dir, 'audit.log');
    await writeFile(file, (await readFile(file, 'utf8')).split('\n').slice(0, 3).join('\n') + '\n');
    const again = AuditLog.forDataDir(dir, key);
    assert.match((await again.verify()).problems.join(), /2 newest record\(s\) missing/);
    assert.equal((await again.record(base)).seq, 6);
    assert.equal((await again.verify()).ok, false, 'the gap stays visible');
    await rm(file);
    assert.match((await AuditLog.forDataDir(dir, key).verify()).problems.join(), /6 newest record/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('scopes: a user limited to some backends reads nothing else and cannot grant it', async () => {
  const s = await setup();
  try {
    await s.store.mutate((d) => { d.users[0]!.readBackends = ['wazuh']; });
    const cfg = s.store.get();
    assert.equal(backendAccess(cfg, tokenPrincipal, 'wazuh').level, 'read');
    assert.equal(backendAccess(cfg, tokenPrincipal, 'defectdojo').level, 'none');
    assert.equal(backendAccess(cfg, { ...tokenPrincipal, kind: 'chat', id: 'u1' }, 'defectdojo').level, 'none');
    assert.match(scopeProblem({ backends: { defectdojo: 'read' } }, cfg.users[0]!, new Set(['defectdojo']))!, /no read access/);
  } finally {
    await s.cleanup();
  }
});

test('write tools: refused over plain http when secure transport is required', async () => {
  const s = await writer();
  transportPolicy.requireSecure = true;
  try {
    assert.equal(insecureUrl('http://127.0.0.1:1'), null, 'loopback is exempt');
    assert.equal(insecureUrl('http://graylog:9000'), 'plain http');
    assert.equal(insecureUrl('https://graylog', false), 'certificate not verified');
    await s.store.mutate((d) => { d.backends.defectdojo!.url = 'http://dd.example.com'; });
    const { c, close } = await connect(s);
    const r = await c.callTool({ name: 'defectdojo_close_finding', arguments: { finding_id: 11, note: 'upgraded the package' } });
    assert.match(text(r), /write tools need an encrypted/);
    await close();
  } finally {
    transportPolicy.requireSecure = false;
    await s.cleanup();
  }
});

test('audit: logs written before sequence numbers existed stay valid and continue', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-audit-legacy-'));
  try {
    const key = randomBytes(32);
    const base = { source: 'mcp' as const, user: 'a', userId: 'u', credential: 'token:t', tool: 'wazuh_list_agents', backend: 'wazuh', access: 'read' as const, outcome: 'ok' as const, durationMs: 1, args: {} };
    let prev = '';
    let text = '';
    for (let i = 0; i < 3; i++) {
      const line = JSON.stringify(encrypt(key, 'audit', JSON.stringify({ ...base, id: String(i), at: new Date(1e12 + i).toISOString(), prev })));
      prev = createHash('sha256').update(line).digest('hex');
      text += line + '\n';
    }
    await writeFile(path.join(dir, 'audit.log'), text);
    const audit = AuditLog.forDataDir(dir, key);
    assert.equal((await audit.record(base)).seq, 4);
    assert.equal((await audit.record(base)).seq, 5);
    assert.deepEqual(await audit.verify(), { ok: true, records: 5, dropped: 0, problems: [] });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- write tools against the mock

async function writer() {
  return setup({ allowWrite: true, grant: ['defectdojo', 'wazuh'], scope: WRITE_SCOPE, allowlist: ALL_TOOLS });
}

test('defectdojo_close_finding: note first, then close, by ID; before and after', async () => {
  const s = await writer();
  const { c, close } = await connect(s);
  try {
    const r = await c.callTool({ name: 'defectdojo_close_finding', arguments: { finding_id: 11, note: 'upgraded xz-utils to 5.6.1' } });
    const out = JSON.parse(text(r));
    assert.equal(out.changed, true);
    assert.deepEqual([out.before.active, out.after.active, out.after.is_mitigated], [true, false, true]);
    const writes = calls.filter((x) => x.method !== 'GET');
    assert.deepEqual(writes.map((x) => x.path), ['/dd/api/v2/findings/11/notes/', '/dd/api/v2/findings/11/close/']);
    assert.equal((writes[0]!.body as { entry: string }).entry, '[SocBridge] Closed as mitigated on behalf of alice: upgraded xz-utils to 5.6.1');
    assert.equal((writes[1]!.body as { is_mitigated: boolean }).is_mitigated, true);
    // Closing again changes nothing.
    calls = [];
    const again = JSON.parse(text(await c.callTool({ name: 'defectdojo_close_finding', arguments: { finding_id: 11, note: 'upgraded xz-utils to 5.6.1' } })));
    assert.equal(again.changed, false);
    assert.equal(calls.filter((x) => x.method !== 'GET').length, 0);
    // A note is required; a missing finding is an error, not a write.
    const short = await c.callTool({ name: 'defectdojo_close_finding', arguments: { finding_id: 11, note: 'x' } });
    assert.equal(short.isError, true);
    calls = [];
    const missing = await c.callTool({ name: 'defectdojo_close_finding', arguments: { finding_id: 404, note: 'upgraded the package' } });
    assert.match(text(missing), /No finding with id 404/);
    assert.equal(calls.filter((x) => x.method !== 'GET').length, 0);
    const [rec, intent] = (await s.audit.list({ tool: 'defectdojo_close_finding' }, 10)).reverse().slice(0, 2).reverse();
    assert.equal(intent!.outcome, 'started', 'recorded before the change');
    assert.ok(rec);
    assert.equal(rec.outcome, 'ok');
    assert.equal(rec.access, 'write');
  } finally {
    await close();
    await s.cleanup();
  }
});

test('defectdojo_mark_false_positive and defectdojo_risk_accept_finding', async () => {
  const s = await writer();
  const { c, close } = await connect(s);
  try {
    const fp = JSON.parse(text(await c.callTool({ name: 'defectdojo_mark_false_positive', arguments: { finding_id: 11, reason: 'package not installed in image' } })));
    assert.equal(fp.after.false_p, true);
    const patch = calls.find((x) => x.method === 'PATCH')!;
    assert.deepEqual(patch.body, { false_p: true, active: false, verified: false });

    resetState();
    const ra = JSON.parse(
      text(await c.callTool({ name: 'defectdojo_risk_accept_finding', arguments: { finding_id: 11, reason: 'compensating WAF rule 9912', expiration_date: '2099-01-31' } })),
    );
    assert.equal(ra.changed, true);
    assert.equal(ra.risk_acceptance_id, 99);
    assert.equal(ra.after.risk_accepted, true);
    const post = calls.find((x) => x.path === '/dd/api/v2/risk_acceptance/')!;
    assert.deepEqual((post.body as Record<string, unknown>).accepted_findings, [11]);
    assert.equal((post.body as Record<string, unknown>).owner, 7);
    assert.equal((post.body as Record<string, unknown>).decision, 'A');
    assert.equal((post.body as Record<string, unknown>).expiration_date, '2099-01-31');
    const past = await c.callTool({ name: 'defectdojo_risk_accept_finding', arguments: { finding_id: 404, reason: 'compensating WAF rule', expiration_date: '2000-01-01' } });
    assert.equal(past.isError, true);
  } finally {
    await close();
    await s.cleanup();
  }
});

test('wazuh group write tools check the agent and group, then change membership', async () => {
  const s = await writer();
  const { c, close } = await connect(s);
  try {
    const add = JSON.parse(text(await c.callTool({ name: 'wazuh_add_agent_group', arguments: { agent_id: '1', group: 'webservers' } })));
    assert.deepEqual([add.changed, add.groups_before, add.groups_after], [true, ['default'], ['default', 'webservers']]);
    assert.ok(calls.some((x) => x.method === 'PUT' && x.path === '/agents/001/group/webservers'));
    const noGroup = await c.callTool({ name: 'wazuh_add_agent_group', arguments: { agent_id: '001', group: 'nope' } });
    assert.match(text(noGroup), /No group named nope/);
    const badName = await c.callTool({ name: 'wazuh_add_agent_group', arguments: { agent_id: '001', group: '../etc' } });
    assert.match(text(badName), /Invalid group/);
    const noAgent = await c.callTool({ name: 'wazuh_remove_agent_group', arguments: { agent_id: '002', group: 'webservers' } });
    assert.match(text(noAgent), /No agent with id 002/);
    const rm1 = JSON.parse(text(await c.callTool({ name: 'wazuh_remove_agent_group', arguments: { agent_id: '001', group: 'webservers' } })));
    assert.deepEqual(rm1.groups_after, ['default']);
    assert.ok(calls.some((x) => x.method === 'DELETE' && x.path === '/agents/001/group/webservers'));
  } finally {
    await close();
    await s.cleanup();
  }
});

test('wazuh_run_active_response sends only allowed commands, no free-form arguments, and only exists when configured', async () => {
  const s = await writer();
  const { c, close } = await connect(s);
  try {
    const denied = await c.callTool({ name: 'wazuh_run_active_response', arguments: { agent_id: '001', command: '!restart-wazuh' } });
    assert.match(text(denied), /not allowed; an administrator allows: !firewall-drop/);
    const badIp = await c.callTool({ name: 'wazuh_run_active_response', arguments: { agent_id: '001', command: '!firewall-drop', srcip: '1.2.3.4; rm -rf /' } });
    assert.match(text(badIp), /Invalid srcip/);
    assert.ok(!calls.some((x) => x.path === '/active-response'));
    const ok = JSON.parse(text(await c.callTool({ name: 'wazuh_run_active_response', arguments: { agent_id: '001', command: '!firewall-drop', srcip: '203.0.113.9' } })));
    assert.equal(ok.sent, true);
    const ar = calls.find((x) => x.path === '/active-response')!;
    assert.deepEqual(ar.query, { agents_list: '001' });
    assert.deepEqual(ar.body, { command: '!firewall-drop', arguments: [], alert: { data: { srcip: '203.0.113.9' } } });
  } finally {
    await close();
  }
  // Without configured commands the tool is not there at all.
  await s.store.mutate((d) => {
    delete d.backends.wazuh!.activeResponseCommands;
  });
  const again = await connect(s);
  try {
    const names = (await again.c.listTools()).tools.map((t) => t.name);
    assert.ok(names.includes('wazuh_add_agent_group'));
    assert.ok(!names.includes('wazuh_run_active_response'));
  } finally {
    await again.close();
    await s.cleanup();
  }
});

test('wazuh settings: active-response commands are validated names', () => {
  const ok = wazuh.schema.safeParse({ managerUrl: 'https://m:55000', managerUser: 'u', managerPassword: 'p', activeResponseCommands: '!firewall-drop, host-deny !firewall-drop' });
  assert.equal(ok.success, true);
  assert.deepEqual((ok.data as { activeResponseCommands: string[] }).activeResponseCommands, ['!firewall-drop', 'host-deny']);
  const bad = wazuh.schema.safeParse({ managerUrl: 'https://m:55000', managerUser: 'u', managerPassword: 'p', activeResponseCommands: 'rm;-rf' });
  assert.equal(bad.success, false);
  assert.ok(defectdojo.tools.filter((t) => t.access === 'write').every((t) => t.default === false));
});

test('audit stats: counts per backend, tool, user and day, across rotated files, and honour since', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-audit-stats-'));
  try {
    const audit = AuditLog.forDataDir(dir, randomBytes(32), { maxBytes: 3000, keep: 5 });
    const base = { source: 'mcp' as const, userId: 'u1', credential: 'token:t1', credentialLabel: 'laptop', access: 'read' as const, outcome: 'ok' as const, durationMs: 10, args: {} };
    for (let i = 0; i < 6; i++) await audit.record({ ...base, user: 'alice', tool: 'wazuh_list_agents', backend: 'wazuh' });
    await audit.record({ ...base, user: 'alice', tool: 'trivy_find_cve', backend: 'trivy', outcome: 'error', durationMs: 30 });
    await audit.record({ ...base, user: 'bob', source: 'chat', credential: 'chat:u2', tool: 'defectdojo_close_finding', backend: 'defectdojo', access: 'write' });
    await audit.record({ ...base, user: 'bob', tool: 'defectdojo_close_finding', backend: 'defectdojo', access: 'write', outcome: 'denied' });

    const s = await audit.stats();
    assert.equal(s.totals.calls, 9);
    assert.equal(s.totals.users, 2);
    assert.equal(s.totals.writes, 2);
    assert.equal(s.totals.errors, 1);
    assert.equal(s.totals.denied, 1);
    assert.deepEqual(s.bySource, { mcp: 8, chat: 1 });
    assert.deepEqual(s.byBackend.map((b) => [b.backend, b.calls]), [['wazuh', 6], ['defectdojo', 2], ['trivy', 1]]);
    assert.equal(s.byTool[0]!.tool, 'wazuh_list_agents');
    const alice = s.byUser.find((u) => u.user === 'alice')!;
    assert.deepEqual(alice.backends, { wazuh: 6, trivy: 1 });
    assert.deepEqual(alice.credentials, [{ credential: 'token:t1', label: 'laptop', calls: 7 }]);
    const bob = s.byUser.find((u) => u.user === 'bob')!;
    assert.deepEqual(bob.credentials.map((c) => c.label).sort(), ['Assistant', 'laptop']);
    assert.equal(s.byDay.reduce((n, d) => n + d.calls, 0), 9);
    assert.ok(!JSON.stringify(s).includes('"args"'), 'arguments are not part of the stats');

    assert.equal((await audit.stats(new Date(Date.now() + 60_000).toISOString())).totals.calls, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
