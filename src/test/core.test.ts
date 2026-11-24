import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { X509Certificate, randomBytes } from 'node:crypto';
import { newAccessToken } from '../auth/secrets.js';
import { verifyAccessToken } from '../auth/tokens.js';
import { normaliseAgentId, parseTime } from '../backends/wazuh/client.js';
import { readAllScope } from '../config/schema.js';
import { ConfigStore } from '../config/store.js';
import { DecryptError, decryptJson, encryptJson } from '../crypto/secretbox.js';
import { EnvError, parseEncryptionKey, parsePublicUrl } from '../env.js';
import { createCa, issueLeaf } from '../tls/ca.js';

test('secretbox round-trips and binds purpose', () => {
  const key = randomBytes(32);
  const blob = encryptJson(key, 'config', { a: 1, s: 'secret' });
  assert.ok(!blob.includes('secret'));
  assert.deepEqual(decryptJson(key, 'config', blob), { a: 1, s: 'secret' });
  assert.throws(() => decryptJson(key, 'tls', blob), DecryptError);
  assert.throws(() => decryptJson(randomBytes(32), 'config', blob), DecryptError);
});

test('secretbox detects tampering', () => {
  const key = randomBytes(32);
  const env = JSON.parse(encryptJson(key, 'config', { a: 1 }));
  const ct = Buffer.from(env.ct, 'base64');
  ct[0] = ct[0]! ^ 1;
  env.ct = ct.toString('base64');
  assert.throws(() => decryptJson(key, 'config', JSON.stringify(env)), DecryptError);
});

test('encryption key parsing', () => {
  assert.equal(parseEncryptionKey('a'.repeat(64)).length, 32);
  assert.equal(parseEncryptionKey(randomBytes(32).toString('base64')).length, 32);
  assert.throws(() => parseEncryptionKey('short'), EnvError);
});

test('PUBLIC_URL validation', () => {
  assert.equal(parsePublicUrl('https://mcp.example.com').hostname, 'mcp.example.com');
  assert.equal(parsePublicUrl('https://mcp.example.com:8443').port, '8443');
  assert.throws(() => parsePublicUrl(undefined), EnvError);
  assert.throws(() => parsePublicUrl('http://mcp.example.com'), EnvError);
  assert.throws(() => parsePublicUrl('https://192.0.2.10'), EnvError);
  assert.throws(() => parsePublicUrl('https://[2001:db8::1]'), EnvError);
  assert.throws(() => parsePublicUrl('https://mcp.example.com/sub'), EnvError);
});

test('access tokens: verify, expire and revoke take effect immediately', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-'));
  try {
    const store = ConfigStore.forDataDir(dir, randomBytes(32));
    await store.load();
    const { token, hash, hint } = newAccessToken();
    const now = new Date().toISOString();
    await store.mutate((d) => {
      d.users.push({ id: 'u1', name: 'alice', role: 'user', disabled: false, webauthnUserId: 'x', passkeys: [], createdAt: now });
      d.tokens.push({ id: 't1', userId: 'u1', label: 'test', hash, hint, createdAt: now, scope: readAllScope() });
    });
    assert.equal(verifyAccessToken(store, token)?.user.name, 'alice');
    assert.equal(verifyAccessToken(store, token + 'x'), null);
    assert.equal(verifyAccessToken(store, 'not-a-token'), null);

    await store.mutate((d) => {
      d.users[0]!.disabled = true;
    });
    assert.equal(verifyAccessToken(store, token), null, 'disabled user');

    await store.mutate((d) => {
      d.users[0]!.disabled = false;
      d.tokens = [];
    });
    assert.equal(verifyAccessToken(store, token), null, 'revoked token');

    // Persisted file is encrypted and reloads.
    const raw = await readFile(path.join(dir, 'config.enc.json'), 'utf8');
    assert.ok(!raw.includes('alice'));
    const again = ConfigStore.forDataDir(dir, (store as unknown as { key: Buffer }).key);
    await again.load();
    assert.equal(again.get().users[0]?.name, 'alice');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('built-in CA issues a leaf that chains to it', () => {
  const ca = createCa('test CA');
  const leaf = issueLeaf(ca, ['mcp.example.com', '192.0.2.5']);
  const caX = new X509Certificate(ca.caCertPem);
  const leafX = new X509Certificate(leaf.certPem);
  assert.ok(caX.ca);
  assert.ok(!leafX.ca);
  assert.ok(leafX.verify(caX.publicKey));
  assert.ok(leafX.checkHost('mcp.example.com'));
  assert.ok(leafX.checkIP('192.0.2.5'));
});

test('wazuh helpers', () => {
  assert.equal(normaliseAgentId('1'), '001');
  assert.equal(normaliseAgentId('1234'), '1234');
  assert.throws(() => normaliseAgentId('abc'));
  assert.equal(parseTime('24h'), 'now-24h');
  assert.equal(parseTime('7d'), 'now-7d');
  assert.equal(parseTime('2026-01-01T00:00:00Z'), '2026-01-01T00:00:00.000Z');
  assert.throws(() => parseTime('yesterday'));
});
