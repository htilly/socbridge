import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { ConfigStore } from '../config/store.js';
import { loadEnv } from '../env.js';
import type { AcmeOptions, AcmeState } from '../tls/acme.js';
import { createCa, issueLeaf } from '../tls/ca.js';
import { TlsManager, TlsSettingsError } from '../tls/manager.js';

async function setup(extraEnv: Record<string, string> = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-tls-'));
  const key = randomBytes(32).toString('hex');
  const env = loadEnv({ PUBLIC_URL: 'https://mcp.example.com:9443', CONFIG_ENCRYPTION_KEY: key, DATA_DIR: dir, ...extraEnv });
  const store = ConfigStore.forDataDir(dir, env.encryptionKey);
  await store.load();
  const calls: AcmeOptions[] = [];
  const fakeCa = createCa(extraEnv.FAKE_CA_NAME ?? 'fake ACME CA');
  const issue = async (opts: AcmeOptions, _state: AcmeState | undefined, log: (m: string) => void): Promise<AcmeState> => {
    calls.push(opts);
    log('fake issuance');
    if (opts.cloudflareToken === 'bad') throw new Error('Cloudflare API: Invalid API Token');
    const leaf = issueLeaf(fakeCa, opts.domains);
    return { staging: opts.staging, accountKeyPem: 'k', keyPem: leaf.keyPem, certPem: leaf.certPem, domains: opts.domains };
  };
  const checked: string[] = [];
  const check = async (token: string, domains: string[]) => {
    checked.push(token);
    if (token === 'bad') throw new Error('Cloudflare does not recognise this API token (401).');
    return domains.map((d) => ({ domain: d, zone: 'example.com' }));
  };
  const mgr = (await TlsManager.create(env, store, issue, check))!;
  const swaps: unknown[] = [];
  mgr.onSwap((c) => swaps.push(c));
  return { dir, mgr, calls, swaps, store, checked };
}

const settle = async (mgr: TlsManager) => {
  for (let i = 0; i < 100 && mgr.view().job?.state === 'running'; i++) await new Promise((r) => setTimeout(r, 20));
};

test('managed TLS: starts on the built-in CA, switches to ACME at runtime and back', async () => {
  const { dir, mgr, calls, swaps } = await setup();
  try {
    let v = mgr.view();
    assert.equal(v.locked, false);
    assert.equal(v.serving, 'builtin');
    assert.deepEqual(v.domains, ['mcp.example.com']);
    assert.match(v.certificate!.issuer, /SocBridge local CA/);

    await assert.rejects(mgr.save({ mode: 'acme', acmeStaging: false, acmeAgreeTos: false, cloudflareToken: 't' }), TlsSettingsError);
    await assert.rejects(mgr.save({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true }), TlsSettingsError);

    await mgr.save({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'secret-token' });
    await settle(mgr);
    v = mgr.view();
    assert.equal(v.job?.state, 'ok');
    assert.equal(v.serving, 'acme');
    assert.match(v.certificate!.issuer, /fake ACME CA/);
    assert.equal(calls.at(-1)?.staging, false);
    assert.equal(swaps.length, 1);
    assert.equal(v.settings.cloudflareTokenSet, true);
    assert.ok(!JSON.stringify(v).includes('secret-token'), 'token must never appear in the view');

    // Token left empty keeps the stored one; switching back is immediate.
    await mgr.save({ mode: 'builtin', acmeStaging: false, acmeAgreeTos: true });
    v = mgr.view();
    assert.equal(v.serving, 'builtin');
    assert.equal(v.settings.cloudflareTokenSet, true);

    // A stored, fresh certificate is reused without a new request.
    const before = calls.length;
    await mgr.save({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true });
    assert.equal(mgr.view().serving, 'acme');
    assert.equal(calls.length, before);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('staging test never activates anything; failures keep the built-in CA', async () => {
  const { dir, mgr, calls, swaps } = await setup();
  try {
    mgr.startTest({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'tok' });
    await settle(mgr);
    assert.equal(mgr.view().job?.state, 'ok');
    assert.equal(calls.at(-1)?.staging, true, 'tests always use staging');
    assert.equal(mgr.view().serving, 'builtin');
    assert.equal(swaps.length, 0);

    await mgr.save({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'bad' });
    await settle(mgr);
    const v = mgr.view();
    assert.equal(v.job?.state, 'error');
    assert.equal(v.serving, 'builtin');
    assert.match(v.lastError ?? '', /Invalid API Token/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('TLS_MODE in the environment locks the settings', async () => {
  const { dir, mgr } = await setup({ TLS_MODE: 'builtin' });
  try {
    assert.equal(mgr.view().locked, true);
    await assert.rejects(mgr.save({ mode: 'builtin', acmeStaging: false, acmeAgreeTos: false }), TlsSettingsError);
    assert.throws(() => mgr.startTest({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'x' }), TlsSettingsError);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('caFingerprint matches the built-in CA certificate', async () => {
  const { dir, mgr } = await setup();
  try {
    const { X509Certificate } = await import('node:crypto');
    assert.equal(mgr.caFingerprint(), new X509Certificate(mgr.caCertPem!).fingerprint256);
    assert.match(mgr.caFingerprint()!, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('managed TLS: token check reports which token it used; status shows a hint and save time', async () => {
  const { dir, mgr, checked } = await setup();
  try {
    await assert.rejects(mgr.checkCloudflare({}), TlsSettingsError);

    const typed = await mgr.checkCloudflare({ cloudflareToken: 'cfat_typed_but_not_saved_0001' });
    assert.deepEqual(typed, { source: 'entered', ok: true, zones: [{ domain: 'mcp.example.com', zone: 'example.com' }] });
    assert.equal(mgr.view().settings.cloudflareTokenSet, false, 'checking must not store the token');

    // The staging test does not store the token either.
    mgr.startTest({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'cfat_typed_but_not_saved_0001' });
    await settle(mgr);
    assert.match(mgr.view().job!.log.map((l) => l.msg).join('\n'), /token typed in the form \(not saved/);
    assert.equal(mgr.view().settings.cloudflareTokenSet, false);

    await mgr.save({ mode: 'builtin', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'cfat_abcdefghijklmnop_3e1f' });
    const st = mgr.view().settings;
    assert.equal(st.cloudflareTokenHint, 'cfat...3e1f');
    assert.ok(st.cloudflareTokenSavedAt);
    assert.ok(!JSON.stringify(mgr.view()).includes('abcdefghijklmnop'), 'the token itself is never returned');

    const stored = await mgr.checkCloudflare({});
    assert.equal(stored.source, 'stored');
    assert.equal(checked.at(-1), 'cfat_abcdefghijklmnop_3e1f');

    const bad = await mgr.checkCloudflare({ cloudflareToken: 'bad' });
    assert.equal(bad.ok, false);
    assert.match(bad.error ?? '', /401/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('ACME names: bare host names, IPs and private suffixes are left out', async () => {
  const { acmeNames, isPublicDnsName } = await import('../tls/acme.js');
  assert.deepEqual(acmeNames('socbridge.example.com', ['socbridge', '10.0.0.5', 'mcp.lan', 'box.local', 'alt.example.com', 'socbridge.example.com']), {
    names: ['socbridge.example.com', 'alt.example.com'],
    skipped: ['socbridge', '10.0.0.5', 'mcp.lan', 'box.local'],
  });
  assert.equal(isPublicDnsName('mcp.example.com'), true);
  assert.equal(isPublicDnsName('x.home.arpa'), false);
});

test('managed TLS: a bare TLS_EXTRA_SANS name is not sent to Let\'s Encrypt', async () => {
  const { dir, mgr, calls } = await setup({ TLS_EXTRA_SANS: 'mcp,10.1.2.3' });
  try {
    assert.deepEqual(mgr.view().skippedNames, ['mcp', '10.1.2.3']);
    mgr.startTest({ mode: 'acme', acmeStaging: false, acmeAgreeTos: true, cloudflareToken: 'tok' });
    await settle(mgr);
    assert.deepEqual(calls.at(-1)!.domains, ['mcp.example.com']);
    assert.match(mgr.view().job!.log.map((l) => l.msg).join('\n'), /Leaving out mcp, 10\.1\.2\.3/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('managed TLS: a staging certificate is flagged so the UI can warn (passkeys fail on it)', async () => {
  const { dir, mgr } = await setup({ FAKE_CA_NAME: '(STAGING) Artificial Amaranth YE1' });
  try {
    assert.equal(mgr.view().staging, false);
    await mgr.save({ mode: 'acme', acmeStaging: true, acmeAgreeTos: true, cloudflareToken: 'tok' });
    await settle(mgr);
    assert.equal(mgr.view().serving, 'acme');
    assert.equal(mgr.view().staging, true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
