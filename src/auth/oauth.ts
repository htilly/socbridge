import { createHash } from 'node:crypto';
import { readAllScope, type OAuthClient, type OAuthGrant, type TokenScope, type User } from '../config/schema.js';
import type { ConfigStore } from '../config/store.js';
import { newId, randomToken, safeEqualHex, safeEqualString, sha256Hex } from './secrets.js';

/**
 * OAuth 2.1 authorization server for MCP clients that cannot be given a
 * static bearer token, such as Claude custom connectors. It implements the
 * pieces the MCP authorization spec asks for: protected resource metadata
 * (RFC 9728), authorization server metadata (RFC 8414), dynamic client
 * registration (RFC 7591), the authorization code flow with PKCE (S256 only)
 * and rotating refresh tokens.
 *
 * Users approve a client in the web console after signing in with their
 * passkey, so OAuth adds no new way to authenticate a person.
 *
 * Pending authorization requests and codes live in memory (short-lived);
 * clients and grants are persisted in the encrypted config.
 */

export const ACCESS_PREFIX = 'msat_';
export const REFRESH_PREFIX = 'msrt_';
export const OAUTH_SCOPE = 'mcp';

const ACCESS_TTL_MS = 60 * 60 * 1000;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** A grant ends this long after approval, however often it is refreshed. */
const GRANT_MAX_MS = 180 * 24 * 60 * 60 * 1000;
/** A client that lost the answer may retry its last refresh token this soon without losing the grant. */
const REPLAY_GRACE_MS = 30 * 1000;
const MAX_USED_REFRESH = 50;
const CODE_REPLAY_MS = 10 * 60 * 1000;
const REQUEST_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
const MAX_CLIENTS = 200;
/** Unused registrations (no grant) are dropped after this long. */
const UNUSED_CLIENT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_GRANTS_PER_USER = 20;
const MAX_PENDING = 500;
/** Open requests per client, so one registration cannot fill the table. */
const MAX_PENDING_PER_CLIENT = 50;

/** Protocol error with an RFC 6749 error code. */
export class OAuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export interface RedirectPolicy {
  /**
   * Hosts allowed in https redirect URIs. `*` allows any https host.
   * Loopback http redirects (native clients, RFC 8252) are always allowed.
   */
  httpsHosts: string[];
}

export const DEFAULT_REDIRECT_HOSTS = ['claude.ai', 'claude.com'];

export function isLoopback(url: URL): boolean {
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

export function redirectAllowed(raw: string, policy: RedirectPolicy): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.hash || url.username || url.password) return false;
  if (isLoopback(url)) return true;
  if (url.protocol !== 'https:') return false;
  return policy.httpsHosts.includes('*') || policy.httpsHosts.includes(url.hostname.toLowerCase());
}

/**
 * Exact string match, except that a loopback redirect may use any port
 * (RFC 8252 section 7.3: native apps pick an ephemeral port per request).
 */
function redirectMatches(registered: string, presented: string): boolean {
  if (registered === presented) return true;
  try {
    const a = new URL(registered);
    const b = new URL(presented);
    return isLoopback(a) && isLoopback(b) && a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
  } catch {
    return false;
  }
}

export function pkceS256(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

interface PendingRequest {
  id: string;
  /**
   * sha256 of the nonce in the browser cookie set by /oauth/authorize (O-002).
   * Only that browser can see or answer the request, so a consent link sent
   * to someone else is useless.
   */
  browserHash?: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  scope: string;
  resource?: string;
  expiresAt: number;
}

interface IssuedCode {
  userId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  /** Per-backend access the user approved. */
  access: TokenScope;
  resource?: string;
  expiresAt: number;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  scope: string;
}

export interface AuthorizeParams {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  scope?: string;
  resource?: string;
}

export interface RegistrationRequest {
  client_name?: unknown;
  redirect_uris?: unknown;
  token_endpoint_auth_method?: unknown;
  grant_types?: unknown;
  response_types?: unknown;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

export class OAuthService {
  private pending = new Map<string, PendingRequest>();
  private spentCodes = new Map<string, { grantId: string; at: number }>();
  /** Called when a replayed code or refresh token ended a connection. */
  onRevoked?: (e: { grantId: string; client: string; userId: string; userName: string; why: string }) => void;
  private codes = new Map<string, IssuedCode>();

  constructor(
    private readonly store: ConfigStore,
    /** Canonical resource identifier: `${origin}/mcp`. */
    private readonly resource: string,
    private readonly policy: RedirectPolicy,
  ) {
    setInterval(() => this.sweep(), 60_000).unref();
  }

  /** Admin switch (Server page). Every entry point checks it. */
  enabled(): boolean {
    return this.store.get().server.oauth?.enabled === true;
  }

  // --- Dynamic client registration -----------------------------------------

  async register(req: RegistrationRequest): Promise<{ client: OAuthClient; secret?: string }> {
    const uris = req.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every((u) => typeof u === 'string')) {
      throw new OAuthError('invalid_redirect_uri', 'redirect_uris must be a non-empty array of strings');
    }
    for (const u of uris as string[]) {
      if (u.length > 500 || !redirectAllowed(u, this.policy)) {
        throw new OAuthError('invalid_redirect_uri', `Redirect URI not allowed by this server: ${u.slice(0, 200)}`);
      }
    }
    const method = str(req.token_endpoint_auth_method) ?? 'client_secret_basic';
    if (!['none', 'client_secret_post', 'client_secret_basic'].includes(method)) {
      throw new OAuthError('invalid_client_metadata', `Unsupported token_endpoint_auth_method: ${method}`);
    }
    const grants = req.grant_types;
    if (grants !== undefined && (!Array.isArray(grants) || grants.some((g) => g !== 'authorization_code' && g !== 'refresh_token'))) {
      throw new OAuthError('invalid_client_metadata', 'Only authorization_code and refresh_token grants are supported');
    }
    const responses = req.response_types;
    if (responses !== undefined && (!Array.isArray(responses) || responses.some((r) => r !== 'code'))) {
      throw new OAuthError('invalid_client_metadata', 'Only the code response type is supported');
    }

    const name = (str(req.client_name) ?? '').trim().slice(0, 100) || 'Unnamed client';
    const secret = method === 'none' ? undefined : randomToken(32);
    const client: OAuthClient = {
      id: newId(),
      name,
      redirectUris: uris as string[],
      authMethod: method as OAuthClient['authMethod'],
      ...(secret ? { secretHash: sha256Hex(secret) } : {}),
      createdAt: new Date().toISOString(),
    };
    await this.store.mutate((draft) => {
      const now = Date.now();
      const used = new Set(draft.oauthGrants.map((g) => g.clientId));
      draft.oauthClients = draft.oauthClients.filter((c) => used.has(c.id) || now - Date.parse(c.createdAt) < UNUSED_CLIENT_TTL_MS);
      if (draft.oauthClients.length >= MAX_CLIENTS) {
        throw new OAuthError('temporarily_unavailable', 'Too many registered clients; try again later', 503);
      }
      draft.oauthClients.push(client);
    });
    return { client, secret };
  }

  client(id: string | undefined): OAuthClient | undefined {
    return id ? this.store.get().oauthClients.find((c) => c.id === id) : undefined;
  }

  // --- Authorization endpoint ----------------------------------------------

  /**
   * Validates an authorization request. Errors about the client or redirect
   * URI throw with `redirect: false` (they must not be sent to an unverified
   * redirect URI); the rest are returned to the client via its redirect.
   */
  startAuthorization(p: AuthorizeParams, browser?: string): { requestId: string } | { redirect: string } {
    const client = this.client(p.client_id);
    if (!client) throw new OAuthError('invalid_client', 'Unknown client_id. Remove and re-add the connector.');
    const redirectUri = p.redirect_uri ?? (client.redirectUris.length === 1 ? client.redirectUris[0] : undefined);
    if (!redirectUri || !client.redirectUris.some((r) => redirectMatches(r, redirectUri))) {
      throw new OAuthError('invalid_request', 'redirect_uri does not match the registered client');
    }
    const fail = (code: string, description: string) => ({ redirect: withParams(redirectUri, { error: code, error_description: description, state: p.state }) });

    if (p.response_type !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported');
    if (!p.code_challenge || p.code_challenge_method !== 'S256') {
      return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
    }
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(p.code_challenge)) return fail('invalid_request', 'Malformed code_challenge');
    if (p.resource !== undefined && !this.resourceOk(p.resource)) return fail('invalid_target', 'Unknown resource');
    if (this.pending.size >= MAX_PENDING) this.sweep();
    if (this.pending.size >= MAX_PENDING) return fail('temporarily_unavailable', 'Too many pending requests');

    let mine = 0;
    for (const r of this.pending.values()) if (r.clientId === client.id && r.expiresAt > Date.now()) mine++;
    if (mine >= MAX_PENDING_PER_CLIENT) return fail('temporarily_unavailable', 'Too many pending requests for this client');

    const id = randomToken(32);
    this.pending.set(id, {
      id,
      ...(browser ? { browserHash: sha256Hex(browser) } : {}),
      clientId: client.id,
      redirectUri,
      state: p.state,
      codeChallenge: p.code_challenge,
      scope: OAUTH_SCOPE,
      resource: p.resource,
      expiresAt: Date.now() + REQUEST_TTL_MS,
    });
    return { requestId: id };
  }

  /**
   * What the consent screen shows. Everything about the client is what it said
   * about itself when it registered, so the screen also shows how new it is and
   * whether anyone here has approved it before.
   */
  describeRequest(
    id: string,
    browser?: string,
  ): {
    clientName: string;
    redirectHost: string;
    redirectUri: string;
    clientRegisteredAt: string;
    previouslyApproved: boolean;
    scope: string;
    expiresAt: string;
  } | null {
    if (!this.enabled()) return null;
    const r = this.livePending(id, browser);
    if (!r) return null;
    const client = this.client(r.clientId);
    if (!client) return null;
    return {
      clientName: client.name,
      redirectHost: new URL(r.redirectUri).host,
      redirectUri: r.redirectUri,
      clientRegisteredAt: client.createdAt,
      previouslyApproved: this.store.get().oauthGrants.some((g) => g.clientId === client.id),
      scope: r.scope,
      expiresAt: new Date(r.expiresAt).toISOString(),
    };
  }

  /** The signed-in user answers the consent screen. Returns where to send the browser. */
  decide(id: string, user: User, approve: boolean, access: TokenScope = readAllScope(), browser?: string): string | null {
    if (!this.enabled()) return null;
    const r = this.livePending(id, browser);
    if (!r) return null;
    this.pending.delete(id);
    if (!approve) {
      return withParams(r.redirectUri, { error: 'access_denied', error_description: 'The user declined', state: r.state });
    }
    const code = randomToken(32);
    this.codes.set(sha256Hex(code), {
      userId: user.id,
      clientId: r.clientId,
      redirectUri: r.redirectUri,
      codeChallenge: r.codeChallenge,
      scope: r.scope,
      access,
      resource: r.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    return withParams(r.redirectUri, { code, state: r.state, iss: new URL(this.resource).origin });
  }

  // --- Token endpoint ------------------------------------------------------

  /** Authenticates the client per its registered method. */
  authenticateClient(clientId: string | undefined, secret: string | undefined): OAuthClient {
    const client = this.client(clientId);
    if (!client) throw new OAuthError('invalid_client', 'Unknown client', 401);
    if (client.secretHash) {
      if (!secret || !safeEqualHex(client.secretHash, sha256Hex(secret))) {
        throw new OAuthError('invalid_client', 'Client authentication failed', 401);
      }
    }
    return client;
  }

  async exchangeCode(
    client: OAuthClient,
    p: { code?: string; redirect_uri?: string; code_verifier?: string; resource?: string },
  ): Promise<TokenResponse> {
    if (!p.code || !p.code_verifier) throw new OAuthError('invalid_request', 'code and code_verifier are required');
    const key = sha256Hex(p.code);
    const spent = this.spentCodes.get(key);
    if (spent) {
      // RFC 6749 4.1.2: a code used twice was stolen; revoke what it produced.
      this.spentCodes.delete(key);
      await this.dropGrant(spent.grantId, 'authorization code replayed');
      throw new OAuthError('invalid_grant', 'Authorization code already used; the connection was revoked');
    }
    const c = this.codes.get(key);
    // Single use: a code is consumed by the first attempt, right or wrong.
    this.codes.delete(key);
    if (!c || c.expiresAt <= Date.now() || c.clientId !== client.id) {
      throw new OAuthError('invalid_grant', 'Invalid or expired authorization code');
    }
    if (p.redirect_uri !== undefined && p.redirect_uri !== c.redirectUri) {
      throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
    }
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(p.code_verifier) || !safeEqualString(pkceS256(p.code_verifier), c.codeChallenge)) {
      throw new OAuthError('invalid_grant', 'PKCE verification failed');
    }
    if (p.resource !== undefined && !this.resourceOk(p.resource)) throw new OAuthError('invalid_target', 'Unknown resource');
    const user = this.store.get().users.find((u) => u.id === c.userId);
    if (!user || user.disabled) throw new OAuthError('invalid_grant', 'User is not active');

    const tokens = newTokenPair();
    const now = Date.now();
    const grant: OAuthGrant = {
      id: newId(),
      userId: user.id,
      clientId: client.id,
      clientName: client.name,
      scope: c.scope,
      access: c.access,
      accessHash: tokens.accessHash,
      accessExpiresAt: new Date(now + ACCESS_TTL_MS).toISOString(),
      refreshHash: tokens.refreshHash,
      refreshExpiresAt: new Date(now + REFRESH_TTL_MS).toISOString(),
      createdAt: new Date(now).toISOString(),
    };
    for (const [k, v] of this.spentCodes) if (v.at + CODE_REPLAY_MS <= now) this.spentCodes.delete(k);
    this.spentCodes.set(key, { grantId: grant.id, at: now });
    await this.store.mutate((draft) => {
      draft.oauthGrants = draft.oauthGrants.filter((g) => Date.parse(g.refreshExpiresAt) > now);
      const mine = draft.oauthGrants
        .filter((g) => g.userId === user.id)
        .sort((a, b) => (a.lastUsedAt ?? a.createdAt).localeCompare(b.lastUsedAt ?? b.createdAt));
      const drop = new Set(mine.slice(0, Math.max(0, mine.length - MAX_GRANTS_PER_USER + 1)).map((g) => g.id));
      draft.oauthGrants = draft.oauthGrants.filter((g) => !drop.has(g.id));
      draft.oauthGrants.push(grant);
    });
    return tokenResponse(tokens, c.scope);
  }

  async refresh(client: OAuthClient, refreshToken: string | undefined): Promise<TokenResponse> {
    if (!refreshToken?.startsWith(REFRESH_PREFIX)) throw new OAuthError('invalid_grant', 'Invalid refresh token');
    const hash = sha256Hex(refreshToken);
    const tokens = newTokenPair();
    const now = Date.now();
    const replayed = this.store.get().oauthGrants.find((x) => x.clientId === client.id && x.usedRefresh?.includes(hash));
    if (replayed) {
      const last = replayed.usedRefresh!.at(-1) === hash && now - Date.parse(replayed.rotatedAt ?? '') < REPLAY_GRACE_MS;
      if (!last) await this.dropGrant(replayed.id, 'refresh token replayed');
      throw new OAuthError('invalid_grant', last ? 'Refresh token already used' : 'Refresh token already used; the connection was revoked');
    }
    const scope = await this.store.mutate((draft) => {
      const g = draft.oauthGrants.find((x) => safeEqualHex(x.refreshHash, hash));
      if (!g || g.clientId !== client.id || Date.parse(g.refreshExpiresAt) <= now) {
        throw new OAuthError('invalid_grant', 'Invalid or expired refresh token');
      }
      const ends = Date.parse(g.createdAt) + GRANT_MAX_MS;
      if (ends <= now) throw new OAuthError('invalid_grant', 'The connection has reached its maximum age; connect again');
      const user = draft.users.find((u) => u.id === g.userId);
      if (!user || user.disabled) throw new OAuthError('invalid_grant', 'User is not active');
      g.usedRefresh = [...(g.usedRefresh ?? []), g.refreshHash].slice(-MAX_USED_REFRESH);
      g.rotatedAt = new Date(now).toISOString();
      g.accessHash = tokens.accessHash;
      g.accessExpiresAt = new Date(now + ACCESS_TTL_MS).toISOString();
      g.refreshHash = tokens.refreshHash;
      g.refreshExpiresAt = new Date(Math.min(now + REFRESH_TTL_MS, ends)).toISOString();
      g.lastUsedAt = new Date(now).toISOString();
      return g.scope;
    });
    return tokenResponse(tokens, scope);
  }

  private async dropGrant(id: string, why: string): Promise<void> {
    const g = this.store.get().oauthGrants.find((x) => x.id === id);
    if (!g) return;
    await this.store.mutate((draft) => {
      draft.oauthGrants = draft.oauthGrants.filter((x) => x.id !== id);
    });
    const user = this.store.get().users.find((u) => u.id === g.userId);
    this.onRevoked?.({ grantId: id, client: g.clientName, userId: g.userId, userName: user?.name ?? '(deleted)', why });
  }

  /** RFC 7009: revoking either token of a grant removes the whole grant. Unknown tokens are not an error. */
  async revoke(client: OAuthClient, token: string | undefined): Promise<void> {
    if (!token) return;
    const hash = sha256Hex(token);
    const g = this.store.get().oauthGrants.find((x) => x.clientId === client.id && (x.accessHash === hash || x.refreshHash === hash));
    if (!g) return;
    await this.store.mutate((draft) => {
      draft.oauthGrants = draft.oauthGrants.filter((x) => x.id !== g.id);
    });
  }

  // --- Resource server -----------------------------------------------------

  /** Resolves an OAuth access token presented to /mcp. */
  verifyAccessToken(presented: string): { user: User; grant: OAuthGrant } | null {
    if (!this.enabled()) return null;
    if (!presented.startsWith(ACCESS_PREFIX) || presented.length > 200) return null;
    const hash = sha256Hex(presented);
    const cfg = this.store.get();
    const grant = cfg.oauthGrants.find((g) => safeEqualHex(g.accessHash, hash));
    if (!grant || Date.parse(grant.accessExpiresAt) <= Date.now()) return null;
    const user = cfg.users.find((u) => u.id === grant.userId);
    if (!user || user.disabled) return null;
    const now = new Date().toISOString();
    this.store.touch((draft) => {
      const g = draft.oauthGrants.find((x) => x.id === grant.id);
      if (g) g.lastUsedAt = now;
    });
    return { user, grant };
  }

  private resourceOk(r: string): boolean {
    const origin = new URL(this.resource).origin;
    return r === this.resource || r === origin || r === `${origin}/`;
  }

  private livePending(id: string, browser?: string): PendingRequest | null {
    const r = this.pending.get(id);
    if (!r) return null;
    // A request started from a browser can only be seen and answered there.
    if (r.browserHash && !(browser && safeEqualHex(r.browserHash, sha256Hex(browser)))) return null;
    if (r.expiresAt <= Date.now()) {
      this.pending.delete(id);
      return null;
    }
    return r;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.pending) if (v.expiresAt <= now) this.pending.delete(k);
    for (const [k, v] of this.codes) if (v.expiresAt <= now) this.codes.delete(k);
  }
}

function newTokenPair() {
  const access = ACCESS_PREFIX + randomToken(32);
  const refresh = REFRESH_PREFIX + randomToken(32);
  return { access, refresh, accessHash: sha256Hex(access), refreshHash: sha256Hex(refresh) };
}

function tokenResponse(t: ReturnType<typeof newTokenPair>, scope: string): TokenResponse {
  return { access_token: t.access, token_type: 'Bearer', expires_in: ACCESS_TTL_MS / 1000, refresh_token: t.refresh, scope };
}

function withParams(base: string, params: Record<string, string | undefined>): string {
  const url = new URL(base);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  return url.toString();
}
