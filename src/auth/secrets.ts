import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

/** Prefix makes leaked tokens easy to recognise in secret scanners and logs. */
export const TOKEN_PREFIX = 'msec_';

export function newId(): string {
  return randomUUID();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Tokens are 256-bit random values, so a single unsalted SHA-256 is adequate
 * for storage: there is nothing to brute-force that is cheaper than guessing
 * the token itself.
 */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function newAccessToken(): { token: string; hash: string; hint: string } {
  const token = TOKEN_PREFIX + randomToken(32);
  return { token, hash: sha256Hex(token), hint: token.slice(0, TOKEN_PREFIX.length + 6) };
}

export function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && ba.length > 0 && timingSafeEqual(ba, bb);
}

export function safeEqualString(a: string, b: string): boolean {
  return safeEqualHex(sha256Hex(a), sha256Hex(b));
}
