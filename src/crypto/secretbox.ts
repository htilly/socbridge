import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';

/**
 * Authenticated encryption for data at rest (AES-256-GCM).
 *
 * Every blob carries a `purpose` that is bound in as additional authenticated
 * data, so a ciphertext produced for one file (e.g. TLS material) cannot be
 * swapped in for another (e.g. the main config) without failing to decrypt.
 */

// Kept from the project's former name (mcp-sec): the marker is part of the AAD,
// so changing it would make every existing encrypted file unreadable.
const FORMAT = 'mcp-sec-enc';
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface EncryptedEnvelope {
  format: typeof FORMAT;
  /** 1: encrypted with the installation key itself. 2: with a key derived for the purpose. */
  v: 1 | 2;
  /** Which installation key (v2). */
  kid?: string;
  alg: 'AES-256-GCM';
  purpose: string;
  iv: string;
  tag: string;
  ct: string;
}

export class DecryptError extends Error {}

/**
 * The installation key, plus earlier ones that may still be needed to read old
 * data after a key change. `v2` writes purpose-derived keys; it is opt-in
 * because versions before it cannot read the result (a rollback would fail).
 */
export interface Keyring {
  current: Buffer;
  previous: Buffer[];
  v2: boolean;
}

/** A plain key behaves as a keyring with no earlier keys, writing v1. */
export type Key = Buffer | Keyring;

const ring = (k: Key): Keyring => (Buffer.isBuffer(k) ? { current: k, previous: [], v2: false } : k);
const keyId = (k: Buffer): string => createHash('sha256').update('socbridge-kid:').update(k).digest('hex').slice(0, 8);
const derive = (k: Buffer, purpose: string): Buffer => Buffer.from(hkdfSync('sha256', k, Buffer.alloc(0), `socbridge:v2:${purpose}`, 32));

function aad(purpose: string, v: 1 | 2): Buffer {
  return Buffer.from(`${FORMAT}:v${v}:${purpose}`, 'utf8');
}

export function encrypt(k: Key, purpose: string, plaintext: Buffer | string): EncryptedEnvelope {
  const { current, v2 } = ring(k);
  const v = v2 ? 2 : 1;
  const key = v2 ? derive(current, purpose) : current;
  if (current.length !== 32) throw new Error('AES-256-GCM requires a 32-byte key');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad(purpose, v));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: FORMAT,
    v,
    ...(v2 ? { kid: keyId(current) } : {}),
    alg: 'AES-256-GCM',
    purpose,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  };
}

export function decrypt(k: Key, purpose: string, envelope: unknown): Buffer {
  const env = envelope as Partial<EncryptedEnvelope> | null;
  if (!env || env.format !== FORMAT || (env.v !== 1 && env.v !== 2) || env.alg !== 'AES-256-GCM') {
    throw new DecryptError('Unrecognised encrypted file format');
  }
  if (env.purpose !== purpose) throw new DecryptError(`Encrypted blob is for "${env.purpose}", expected "${purpose}"`);
  const r = ring(k);
  const tag = Buffer.from(env.tag ?? '', 'base64');
  if (tag.length === TAG_BYTES) {
    for (const key of [r.current, ...r.previous]) {
      if (env.v === 2 && env.kid !== keyId(key)) continue;
      try {
        const decipher = createDecipheriv('aes-256-gcm', env.v === 2 ? derive(key, purpose) : key, Buffer.from(env.iv ?? '', 'base64'), { authTagLength: TAG_BYTES });
        decipher.setAAD(aad(purpose, env.v));
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(Buffer.from(env.ct ?? '', 'base64')), decipher.final()]);
      } catch {
        /* not this key */
      }
    }
  }
  throw new DecryptError('Decryption failed: wrong CONFIG_ENCRYPTION_KEY or corrupted file');
}

/** Whether a file is not yet encrypted the way new data would be (an earlier key, or the older format). */
export function needsRekey(k: Key, purpose: string, fileContent: string): boolean {
  const r = ring(k);
  try {
    const env = JSON.parse(fileContent) as Partial<EncryptedEnvelope>;
    if (env.v !== (r.v2 ? 2 : 1)) return true;
    decrypt({ ...r, previous: [] }, purpose, env);
    return false;
  } catch {
    return true;
  }
}

export function encryptJson(key: Key, purpose: string, value: unknown): string {
  return JSON.stringify(encrypt(key, purpose, JSON.stringify(value)), null, 2) + '\n';
}

export function decryptJson<T = unknown>(key: Key, purpose: string, fileContent: string): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fileContent);
  } catch {
    throw new DecryptError('Encrypted file is not valid JSON');
  }
  return JSON.parse(decrypt(key, purpose, parsed).toString('utf8')) as T;
}
