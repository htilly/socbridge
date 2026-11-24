import type { ConfigStore } from '../config/store.js';
import type { AccessToken, User } from '../config/schema.js';
import { safeEqualHex, sha256Hex, TOKEN_PREFIX } from './secrets.js';

export interface TokenPrincipal {
  user: User;
  token: AccessToken;
}

/**
 * Resolve a bearer token against the live config. Called on every MCP request,
 * so revoking a token (or disabling its user) takes effect immediately.
 */
export function verifyAccessToken(store: ConfigStore, presented: string): TokenPrincipal | null {
  if (!presented.startsWith(TOKEN_PREFIX) || presented.length > 200) return null;
  const hash = sha256Hex(presented);
  const cfg = store.get();
  const token = cfg.tokens.find((t) => safeEqualHex(t.hash, hash));
  if (!token) return null;
  if (token.expiresAt && Date.parse(token.expiresAt) <= Date.now()) return null;
  const user = cfg.users.find((u) => u.id === token.userId);
  if (!user || user.disabled) return null;

  const now = new Date().toISOString();
  store.touch((draft) => {
    const t = draft.tokens.find((x) => x.id === token.id);
    if (t) t.lastUsedAt = now;
  });
  return { user, token };
}

export function bearerFrom(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return m?.[1] ?? null;
}
