import type { Key } from './crypto/secretbox.js';
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import path from 'node:path';

export type TlsMode = 'builtin' | 'file' | 'acme' | 'off';

export interface Env {
  publicUrl: URL;
  /** WebAuthn relying party ID: the hostname of PUBLIC_URL. */
  rpId: string;
  /** Origin expected in WebAuthn client data and in browser Origin headers. */
  origin: string;
  host: string;
  port: number;
  dataDir: string;
  /** MaxMind-format city database for the attack map; optional. */
  geoipDb: string;
  tlsMode: TlsMode;
  /** True when TLS_MODE was set in the environment; certificate settings are then locked in the UI. */
  tlsModeFromEnv: boolean;
  tlsCertFile?: string;
  tlsKeyFile?: string;
  tlsExtraSans: string[];
  acme?: {
    email?: string;
    staging: boolean;
    cloudflareToken: string;
    resolvers: string[];
  };
  encryptionKey: Key;
  /** Commit the image was built from (set at build time), reported by /health. */
  buildSha?: string;
  setupToken?: string;
  /** Hosts allowed in https OAuth redirect URIs (`*` = any). Loopback http is always allowed. */
  oauthRedirectHosts: string[];
  trustProxy: boolean | number | string;
  /** Refuse plain http and unverified TLS towards backends and the GELF input. */
  requireSecureTransport: boolean;
}

export class EnvError extends Error {}

/**
 * PUBLIC_URL must be https and name a host (not an IP literal): passkeys are
 * bound to a registrable domain name, and browsers refuse WebAuthn on IPs.
 */
export function parsePublicUrl(raw: string | undefined): URL {
  if (!raw) throw new EnvError('PUBLIC_URL is required (e.g. https://socbridge.example.com)');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new EnvError(`PUBLIC_URL is not a valid URL: ${raw}`);
  }
  if (url.protocol !== 'https:') throw new EnvError('PUBLIC_URL must use https://');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) !== 0) throw new EnvError('PUBLIC_URL must use a hostname, not an IP address');
  if (!host.includes('.') && host !== 'localhost') {
    throw new EnvError('PUBLIC_URL hostname should be a fully qualified name');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new EnvError('PUBLIC_URL must be an origin only (no path, query or fragment)');
  }
  return url;
}

/** Accepts 64 hex characters or base64/base64url that decodes to exactly 32 bytes. */
export function parseEncryptionKey(raw: string): Buffer {
  const value = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, 'hex');
  const b64 = Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  if (b64.length === 32) return b64;
  throw new EnvError('Encryption key must be 32 bytes, given as 64 hex chars or base64 (try: openssl rand -hex 32)');
}

function loadEncryptionKey(e: NodeJS.ProcessEnv): Buffer {
  if (e.CONFIG_ENCRYPTION_KEY && e.CONFIG_ENCRYPTION_KEY_FILE) {
    throw new EnvError('Set only one of CONFIG_ENCRYPTION_KEY and CONFIG_ENCRYPTION_KEY_FILE');
  }
  if (e.CONFIG_ENCRYPTION_KEY_FILE) {
    let content: string;
    try {
      content = readFileSync(e.CONFIG_ENCRYPTION_KEY_FILE, 'utf8');
    } catch (err) {
      throw new EnvError(`Cannot read CONFIG_ENCRYPTION_KEY_FILE: ${(err as Error).message}`);
    }
    return parseEncryptionKey(content);
  }
  if (e.CONFIG_ENCRYPTION_KEY) return parseEncryptionKey(e.CONFIG_ENCRYPTION_KEY);
  throw new EnvError('CONFIG_ENCRYPTION_KEY or CONFIG_ENCRYPTION_KEY_FILE is required');
}

/** Earlier keys (comma separated) and the envelope format, see README "Changing the encryption key". */
function loadKeyring(e: NodeJS.ProcessEnv): Key {
  const current = loadEncryptionKey(e);
  const previous = (readSecret(e, 'CONFIG_ENCRYPTION_KEY_PREVIOUS') ?? '')
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(parseEncryptionKey);
  const format = e.ENCRYPTION_FORMAT?.trim() || '1';
  if (format !== '1' && format !== '2') throw new EnvError('ENCRYPTION_FORMAT must be 1 or 2');
  return { current, previous, v2: format === '2' };
}

function readSecret(e: NodeJS.ProcessEnv, name: string): string | undefined {
  const file = e[`${name}_FILE`];
  if (e[name] && file) throw new EnvError(`Set only one of ${name} and ${name}_FILE`);
  if (file) {
    try {
      return readFileSync(file, 'utf8').trim();
    } catch (err) {
      throw new EnvError(`Cannot read ${name}_FILE: ${(err as Error).message}`);
    }
  }
  return e[name]?.trim() || undefined;
}

function parseAcme(e: NodeJS.ProcessEnv): Env['acme'] {
  if ((e.ACME_DNS_PROVIDER ?? 'cloudflare') !== 'cloudflare') {
    throw new EnvError('ACME_DNS_PROVIDER: only "cloudflare" is supported');
  }
  if (e.ACME_AGREE_TOS !== 'true') {
    throw new EnvError("TLS_MODE=acme requires ACME_AGREE_TOS=true (you accept the CA's subscriber agreement)");
  }
  const token = readSecret(e, 'CLOUDFLARE_DNS_API_TOKEN');
  if (!token) throw new EnvError('TLS_MODE=acme requires CLOUDFLARE_DNS_API_TOKEN or CLOUDFLARE_DNS_API_TOKEN_FILE');
  return {
    email: e.ACME_EMAIL?.trim() || undefined,
    staging: e.ACME_STAGING === 'true',
    cloudflareToken: token,
    resolvers: (e.ACME_DNS_RESOLVERS ?? '1.1.1.1,8.8.8.8')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  };
}

function parseTrustProxy(raw: string | undefined): boolean | number | string {
  if (raw === undefined || raw === '' || raw === 'false') return false;
  if (raw === 'true') return true;
  if (/^\d+$/.test(raw)) return Number(raw);
  return raw; // e.g. "loopback" or a comma-separated list of subnets
}

export function loadEnv(e: NodeJS.ProcessEnv = process.env): Env {
  const publicUrl = parsePublicUrl(e.PUBLIC_URL);
  const tlsMode = (e.TLS_MODE ?? 'builtin') as TlsMode;
  if (!['builtin', 'file', 'acme', 'off'].includes(tlsMode)) {
    throw new EnvError('TLS_MODE must be one of: builtin, file, acme, off');
  }
  if (tlsMode === 'file' && (!e.TLS_CERT_FILE || !e.TLS_KEY_FILE)) {
    throw new EnvError('TLS_MODE=file requires TLS_CERT_FILE and TLS_KEY_FILE');
  }
  const port = Number(e.PORT ?? (tlsMode === 'off' ? 8080 : 8443));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new EnvError('PORT is invalid');

  const setupToken = e.SETUP_TOKEN?.trim();
  if (setupToken !== undefined && setupToken !== '' && setupToken.length < 24) {
    throw new EnvError('SETUP_TOKEN must be at least 24 characters');
  }

  return {
    publicUrl,
    rpId: publicUrl.hostname,
    origin: publicUrl.origin,
    host: e.HOST ?? '0.0.0.0',
    port,
    dataDir: path.resolve(e.DATA_DIR ?? '/data'),
    geoipDb: path.resolve(e.GEOIP_DB?.trim() || path.join(e.DATA_DIR ?? '/data', 'geoip.mmdb')),
    tlsMode,
    tlsModeFromEnv: (e.TLS_MODE ?? '') !== '',
    tlsCertFile: e.TLS_CERT_FILE,
    tlsKeyFile: e.TLS_KEY_FILE,
    tlsExtraSans: (e.TLS_EXTRA_SANS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    acme: tlsMode === 'acme' ? parseAcme(e) : undefined,
    encryptionKey: loadKeyring(e),
    buildSha: /^[0-9a-f]{7,40}$/.test(e.BUILD_SHA ?? '') ? e.BUILD_SHA!.slice(0, 7) : undefined,
    setupToken: setupToken || undefined,
    oauthRedirectHosts: (e.OAUTH_REDIRECT_HOSTS ?? 'claude.ai,claude.com')
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
    trustProxy: parseTrustProxy(e.TRUST_PROXY),
    requireSecureTransport: e.REQUIRE_SECURE_TRANSPORT === 'true',
  };
}
