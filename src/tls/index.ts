import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type { SecureContextOptions } from 'node:tls';
import { decryptJson, encryptJson, needsRekey } from '../crypto/secretbox.js';
import type { Env } from '../env.js';
import { errMessage, log } from '../log.js';
import { writeFileAtomic } from '../util/fs.js';
import { acmeNames, issueCertificate, type AcmeState } from './acme.js';
import { createCa, daysRemaining, fingerprint256, issueLeaf, outsideConstraints, RENEW_BEFORE_DAYS, type CaMaterial, type LeafMaterial } from './ca.js';

const PURPOSE = 'tls';
const CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;
const FILE_POLL_MS = 60 * 1000;

export interface TlsProvider {
  mode: 'builtin' | 'file' | 'acme';
  initial: SecureContextOptions;
  /** Public CA certificate (builtin mode only) so clients can trust it. */
  caCertPem?: string;
  /** Start background renewal/reload; calls `apply` with new material. */
  watch(apply: (ctx: SecureContextOptions) => void): void;
}

interface StoredTls {
  ca: CaMaterial;
  leaf?: LeafMaterial;
}

function sameSans(a: string[], b: string[]): boolean {
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.length === sb.length && sa.every((v, i) => v === sb[i]);
}

/**
 * Built-in CA: root + server cert are kept in one encrypted file under
 * DATA_DIR/tls. The CA certificate (public) is also written in plain PEM so it
 * can be distributed to clients. The leaf is re-issued when it nears expiry
 * or when the configured names change.
 */
export async function builtin(env: Env): Promise<TlsProvider> {
  const dir = path.join(env.dataDir, 'tls');
  const encFile = path.join(dir, 'tls.enc.json');
  const caFile = path.join(dir, 'ca.crt');
  const sans = [env.publicUrl.hostname, ...env.tlsExtraSans.filter((s) => s !== env.publicUrl.hostname)];

  const load = async () => decryptJson<StoredTls>(env.encryptionKey, PURPOSE, await readFile(encFile, 'utf8'));
  let stored: StoredTls | undefined;
  let rekey = false;
  try {
    stored = await load();
    rekey = needsRekey(env.encryptionKey, PURPOSE, await readFile(encFile, 'utf8'));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  if (!stored) {
    log.info('Creating built-in certificate authority');
    stored = { ca: createCa(`SocBridge CA (${env.publicUrl.hostname})`, sans) };
    await writeFileAtomic(encFile, encryptJson(env.encryptionKey, PURPOSE, stored));
  } else if (rekey) await writeFileAtomic(encFile, encryptJson(env.encryptionKey, PURPOSE, stored));

  const outside = outsideConstraints(stored.ca, sans);
  if (outside.length) {
    log.error('The built-in CA may not certify these names. Remove them from TLS_EXTRA_SANS, or delete tls/tls.enc.json in the data directory to create a new CA (every device must then trust it again).', { names: outside });
  } else if (!stored.ca.names) {
    log.warn('The built-in CA predates name constraints and could certify any site. Delete tls/tls.enc.json in the data directory to replace it (every device must then trust the new one).');
  }
  // The CA key is only read while issuing; it is not kept in memory.
  stored.ca = { ...stored.ca, caKeyPem: '' };

  const ensureLeaf = async (): Promise<boolean> => {
    const leaf = stored!.leaf;
    const needs = !leaf || !sameSans(leaf.sans, sans) || daysRemaining(leaf.certPem) < RENEW_BEFORE_DAYS;
    if (!needs) return false;
    const full = await load();
    full.leaf = issueLeaf(full.ca, sans);
    await writeFileAtomic(encFile, encryptJson(env.encryptionKey, PURPOSE, full));
    stored!.leaf = full.leaf;
    await writeFileAtomic(caFile, stored!.ca.caCertPem, 0o644);
    log.info('Issued server certificate from built-in CA', {
      sans,
      validDays: Math.round(daysRemaining(stored!.leaf.certPem)),
    });
    return true;
  };

  await ensureLeaf();
  await writeFileAtomic(caFile, stored.ca.caCertPem, 0o644);
  log.info('Built-in CA ready', { caFingerprint: fingerprint256(stored.ca.caCertPem), caFile });

  const toCtx = (): SecureContextOptions => ({
    key: stored!.leaf!.keyPem,
    cert: stored!.leaf!.certPem + stored!.ca.caCertPem,
  });

  return {
    mode: 'builtin',
    initial: toCtx(),
    caCertPem: stored.ca.caCertPem,
    watch(apply) {
      setInterval(() => {
        ensureLeaf()
          .then((changed) => changed && apply(toCtx()))
          .catch((err) => log.error('Certificate renewal failed', { error: errMessage(err) }));
      }, CHECK_INTERVAL_MS).unref();
    },
  };
}

/** Operator-supplied cert/key files, re-read when either file changes. */
async function fromFiles(env: Env): Promise<TlsProvider> {
  const certFile = env.tlsCertFile!;
  const keyFile = env.tlsKeyFile!;
  const read = async (): Promise<SecureContextOptions> => ({
    cert: await readFile(certFile, 'utf8'),
    key: await readFile(keyFile, 'utf8'),
  });
  const mtimes = async () => `${(await stat(certFile)).mtimeMs}:${(await stat(keyFile)).mtimeMs}`;

  const initial = await read();
  const remaining = daysRemaining(String(initial.cert));
  if (remaining < 0) log.warn('TLS certificate file is expired', { certFile });
  else if (remaining < 14) log.warn('TLS certificate file expires soon', { days: Math.floor(remaining) });

  let last = await mtimes();
  return {
    mode: 'file',
    initial,
    watch(apply) {
      setInterval(() => {
        mtimes()
          .then(async (m) => {
            if (m === last) return;
            last = m;
            apply(await read());
            log.info('Reloaded TLS certificate from files');
          })
          .catch((err) => log.error('TLS certificate reload failed', { error: errMessage(err) }));
      }, FILE_POLL_MS).unref();
    },
  };
}

/** While serving a fallback certificate, retry ACME this often. */
const ACME_RETRY_MS = 30 * 60 * 1000;
/** Inside the renewal window (certificate still valid), retry this often. */
const ACME_RENEW_RETRY_MS = 6 * 60 * 60 * 1000;

/**
 * Let's Encrypt via dns-01 (Cloudflare). Account key, certificate and key are
 * stored encrypted. If no valid certificate can be obtained at startup, the
 * built-in CA serves a temporary certificate so the service (and /health)
 * still comes up, and issuance is retried in the background.
 */
async function acmeProvider(env: Env): Promise<TlsProvider> {
  const opts = env.acme!;
  const file = path.join(env.dataDir, 'tls', 'acme.enc.json');
  const host = env.publicUrl.hostname;
  const { names: domains, skipped } = acmeNames(host, env.tlsExtraSans);
  if (skipped.length) log.warn('Names that are not in public DNS cannot be in a Let\'s Encrypt certificate; leaving them out', { skipped });
  if (!domains.length) throw new Error(`PUBLIC_URL host ${host} is not a public DNS name, so Let's Encrypt cannot issue for it`);

  let state: AcmeState | undefined;
  try {
    const content = await readFile(file, 'utf8');
    state = decryptJson<AcmeState>(env.encryptionKey, 'acme', content);
    if (needsRekey(env.encryptionKey, 'acme', content)) await writeFileAtomic(file, encryptJson(env.encryptionKey, 'acme', state));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  const matches = () => !!state?.certPem && !!state.domains && sameSans(state.domains, domains);
  const usable = () => matches() && daysRemaining(state!.certPem!) > 1;
  const fresh = () => matches() && daysRemaining(state!.certPem!) > RENEW_BEFORE_DAYS;
  const toCtx = (): SecureContextOptions => ({ key: state!.keyPem!, cert: state!.certPem! });

  let lastAttempt = 0;
  const attempt = async (): Promise<boolean> => {
    lastAttempt = Date.now();
    try {
      state = await issueCertificate({ ...opts, domains }, state);
      await writeFileAtomic(file, encryptJson(env.encryptionKey, 'acme', state));
      log.info('Certificate issued', { domains, validDays: Math.round(daysRemaining(state.certPem!)), staging: opts.staging });
      return true;
    } catch (err) {
      log.error('ACME certificate request failed', { domains, error: errMessage(err) });
      return false;
    }
  };

  if (!fresh()) await attempt();
  let servingFallback = !usable();
  let initial: SecureContextOptions;
  if (servingFallback) {
    log.warn('No valid ACME certificate yet; serving a temporary certificate from the built-in CA', { retryMinutes: ACME_RETRY_MS / 60_000 });
    initial = (await builtin(env)).initial;
  } else {
    initial = toCtx();
  }

  return {
    mode: 'acme',
    initial,
    watch(apply) {
      setInterval(() => {
        if (fresh() && !servingFallback) return;
        const wait = servingFallback ? ACME_RETRY_MS : ACME_RENEW_RETRY_MS;
        if (Date.now() - lastAttempt < wait - 60_000) return;
        void attempt().then((ok) => {
          if (ok || (servingFallback && usable())) {
            apply(toCtx());
            servingFallback = false;
          }
        });
      }, Math.min(ACME_RETRY_MS, CHECK_INTERVAL_MS)).unref();
    },
  };
}

export async function createTlsProvider(env: Env): Promise<TlsProvider | null> {
  switch (env.tlsMode) {
    case 'builtin':
      return builtin(env);
    case 'acme':
      return acmeProvider(env);
    case 'file':
      return fromFiles(env);
    case 'off':
      return null;
  }
}
