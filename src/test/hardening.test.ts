import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { listModels } from '../ai/providers.js';
import { test } from 'node:test';
import type { Request, Response } from 'express';
import { SESSION_COOKIE, SessionManager } from '../auth/sessions.js';
import { forbiddenAddress, HttpClient, MAX_RESPONSE_BYTES } from '../backends/http.js';
import { checkAlertQuery } from '../backends/wazuh/queries.js';
import { ConfigStore } from '../config/store.js';
import { decrypt, decryptJson, encrypt, encryptJson, needsRekey } from '../crypto/secretbox.js';
import { requireFresh } from '../http/context.js';
import { createCa, issueLeaf, outsideConstraints } from '../tls/ca.js';

test('encryption: per-purpose keys, key change and tag length', async () => {
  const a = randomBytes(32);
  const b = randomBytes(32);
  const v2 = { current: a, previous: [], v2: true };
  const blob = encrypt(v2, 'config', 'x');
  assert.equal(blob.v, 2);
  assert.equal(decrypt(v2, 'config', blob).toString(), 'x');
  assert.throws(() => decrypt(v2, 'tls', { ...blob, purpose: 'tls' }));
  assert.throws(() => decrypt(v2, 'config', { ...blob, v: 1 }));
  assert.equal(encrypt(a, 'config', 'x').v, 1, 'the old format stays the default');
  assert.equal(decrypt(v2, 'config', encrypt(a, 'config', 'old')).toString(), 'old');
  const tag = Buffer.from(blob.tag, 'base64').subarray(0, 4).toString('base64');
  assert.throws(() => decrypt(v2, 'config', { ...blob, tag }));

  const rotated = { current: b, previous: [a], v2: true };
  assert.equal(decrypt(rotated, 'config', blob).toString(), 'x');
  assert.equal(needsRekey(rotated, 'config', JSON.stringify(blob)), true);
  assert.throws(() => decrypt(b, 'config', blob));

  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-key-'));
  try {
    const file = path.join(dir, 'config.enc.json');
    await writeFile(file, encryptJson(a, 'config', { version: 1 }));
    await new ConfigStore(file, rotated).load();
    assert.ok(decryptJson({ current: b, previous: [], v2: true }, 'config', await readFile(file, 'utf8')), 're-encrypted on start');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('built-in CA: certifies its own names only', async (t) => {
  const ca = createCa('test', ['mcp.example.com', '192.0.2.5']);
  assert.deepEqual(outsideConstraints(ca, ['mcp.example.com', 'a.mcp.example.com', 'other.example.com', '192.0.2.6']), ['other.example.com', '192.0.2.6']);
  assert.deepEqual(outsideConstraints({}, ['anything']), [], 'older CAs are unconstrained');
  assert.ok(Date.parse(new X509Certificate(ca.caCertPem).validTo) < Date.now() + 5.1 * 365 * 86_400_000);
  let openssl = true;
  try { execFileSync('openssl', ['version']); } catch { openssl = false; }
  if (!openssl) return t.skip('openssl not available');
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-ca-'));
  const verify = async (c: typeof ca, sans: string[]) => {
    await writeFile(path.join(dir, 'ca.pem'), c.caCertPem);
    await writeFile(path.join(dir, 'leaf.pem'), issueLeaf(c, sans).certPem);
    try {
      execFileSync('openssl', ['verify', '-CAfile', path.join(dir, 'ca.pem'), path.join(dir, 'leaf.pem')], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  };
  try {
    assert.equal(await verify(ca, ['mcp.example.com', '192.0.2.5']), true);
    assert.equal(await verify(ca, ['bank.example.org']), false);
    assert.equal(await verify(ca, ['mcp.example.com', '198.51.100.1']), false);
    const dnsOnly = createCa('test', ['mcp.example.com']);
    assert.equal(await verify(dnsOnly, ['mcp.example.com']), true);
    assert.equal(await verify(dnsOnly, ['mcp.example.com', '192.0.2.5']), false, 'no address may be certified');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('sessions: passkey check ages, and removing a passkey or ending others closes sessions', () => {
  const m = new SessionManager();
  const open = (user: string, pk: string) => {
    let sid = '';
    m.create({ cookie: (_n: string, v: string) => { sid = v; } } as unknown as Response, user, pk);
    return { headers: { cookie: `${SESSION_COOKIE}=${sid}` } } as Request;
  };
  const a = open('u1', 'k1');
  const b = open('u1', 'k2');
  const other = open('u2', 'k3');
  const gate = (req: Request) => {
    let err: unknown;
    requireFresh({ sessions: m })(req, {} as Response, (e?: unknown) => { err = e; });
    return err as { status: number; code: string } | undefined;
  };
  assert.equal(gate(a), undefined);
  const now = Date.now;
  try {
    Date.now = () => now() + 16 * 60_000;
    assert.deepEqual([gate(a)!.status, gate(a)!.code], [403, 'reauth']);
    m.refresh(a, 'u2');
    assert.ok(gate(a), 'another user cannot refresh it');
    m.refresh(a, 'u1');
    assert.equal(gate(a), undefined);
  } finally {
    Date.now = now;
  }
  m.destroyForPasskey('u1', 'k2');
  assert.equal(m.resolve(b), null);
  const c = open('u1', 'k1');
  assert.equal(m.destroyOthers(a, 'u1'), 1);
  assert.equal(m.resolve(c), null);
  assert.equal(m.resolve(a), 'u1');
  assert.equal(m.resolve(other), 'u2');
});

test('backend client: response size, redirects and link-local addresses', async () => {
  const srv = createServer((req, res) => {
    if (req.url === '/big') {
      res.writeHead(200);
      const chunk = Buffer.alloc(1024 * 1024, 32);
      let n = 0;
      const push = () => { while (n++ < MAX_RESPONSE_BYTES / chunk.length + 2) if (!res.write(chunk)) return void res.once('drain', push); res.end(); };
      push();
      res.on('error', () => undefined);
    } else if (req.url === '/same') res.writeHead(302, { location: '/ok' }).end();
    else if (req.url === '/away') res.writeHead(302, { location: 'http://example.invalid/' }).end();
    else res.end('{"ok":true}');
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const http = new HttpClient({ baseUrl: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` });
    assert.deepEqual(await http.request('/same'), { ok: true });
    await assert.rejects(http.request('/away'), /redirects to http:\/\/example\.invalid/);
    await assert.rejects(http.request('/same', { method: 'POST', json: {} }), /redirects/);
    await assert.rejects(http.request('/big', { text: true }), /more than 32 MB/);
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
  assert.ok(forbiddenAddress('169.254.169.254') && forbiddenAddress('[fe80::1]') && forbiddenAddress('::ffff:169.254.169.254'));
  assert.ok(!forbiddenAddress('10.0.0.1') && !forbiddenAddress('127.0.0.1'));
  assert.throws(() => new HttpClient({ baseUrl: 'http://169.254.169.254/' }), /link-local/);
});

test('wazuh alert query: expensive Lucene syntax is refused', () => {
  for (const ok of ['sshd AND failed', '"/var/log/auth.log"', 'data.srcip:10.0.*', 'a\\/b', 'rule.id:[5000 TO 6000]']) checkAlertQuery(ok);
  for (const bad of ['/.*a.*/', 'roam~2', 'a* b* c* d* e* f*', '"x" /y/']) assert.throws(() => checkAlertQuery(bad), /Query:/);
});

test('assistant: no link-local base URL, no redirects, bounded error text', async () => {
  const srv = createServer((req, res) => {
    if (req.url === '/r/models') res.writeHead(302, { location: 'http://127.0.0.1:1/x' }).end();
    else if (req.url === '/e/models') res.writeHead(500).end('internal page');
    else res.end('{"data":[{"id":"m"}]}');
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const models = (baseUrl: string) => listModels({ provider: 'local', baseUrl });
  try {
    assert.deepEqual((await models(`${base}/v1`)).map((m) => m.id), ['m'], 'local servers still work');
    await assert.rejects(models(`${base}/r`), /redirects elsewhere/);
    await assert.rejects(models(`${base}/e`), (e: Error) => /HTTP 500/.test(e.message) && !e.message.includes('internal page'));
    for (const h of ['169.254.169.254', '[fe80::1]', '[::ffff:169.254.169.254]']) await assert.rejects(models(`http://${h}/v1`), /link-local/);
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
});
