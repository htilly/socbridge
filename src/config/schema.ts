import { z } from 'zod';
import { BACKEND_IDS } from '../backends/types.js';

export const RoleSchema = z.enum(['admin', 'user']);
export type Role = z.infer<typeof RoleSchema>;

export const PasskeySchema = z.object({
  /** base64url credential ID as reported by the authenticator. */
  id: z.string().min(1),
  /** base64url COSE public key. */
  publicKey: z.string().min(1),
  counter: z.number().int().nonnegative(),
  transports: z.array(z.string()).default([]),
  label: z.string().max(100).default('Passkey'),
  createdAt: z.string(),
  lastUsedAt: z.string().optional(),
});
export type Passkey = z.infer<typeof PasskeySchema>;

export const UserSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).max(64),
  role: RoleSchema,
  disabled: z.boolean().default(false),
  /** base64url random handle given to authenticators; never the internal ID. */
  webauthnUserId: z.string().min(1),
  passkeys: z.array(PasskeySchema).default([]),
  /**
   * Backends on which an administrator lets this user hold write access
   * (DESIGN §5). Without a grant, a token's write scope acts as read.
   */
  writeBackends: z.array(z.string()).optional(),
  /** Backends this user may read. Absent: every enabled backend. */
  readBackends: z.array(z.string()).optional(),
  createdAt: z.string(),
});
export type User = z.infer<typeof UserSchema>;

export const AccessLevelSchema = z.enum(['read', 'write']);
export type AccessLevel = z.infer<typeof AccessLevelSchema>;

/**
 * What a token may do, per backend (DESIGN §5). A backend that is absent
 * means no access. Chosen at creation and stored with the token hash.
 */
export const TokenScopeSchema = z.object({
  backends: z.record(z.string(), AccessLevelSchema),
});
export type TokenScope = z.infer<typeof TokenScopeSchema>;

/** Read on every backend: what every token could do before scopes existed. */
export function readAllScope(): TokenScope {
  return { backends: Object.fromEntries(BACKEND_IDS.map((id) => [id, 'read' as const])) };
}

export const AccessTokenSchema = z.object({
  id: z.string().min(1),
  userId: z.string().min(1),
  label: z.string().max(100),
  /** hex SHA-256 of the full token. The token itself is never stored. */
  hash: z.string().regex(/^[0-9a-f]{64}$/),
  /** Non-secret prefix shown in the UI so users can tell tokens apart. */
  hint: z.string(),
  createdAt: z.string(),
  expiresAt: z.string().optional(),
  lastUsedAt: z.string().optional(),
  /** Tokens created before scopes existed migrate to read on all backends. */
  scope: TokenScopeSchema.default(readAllScope),
});
export type AccessToken = z.infer<typeof AccessTokenSchema>;

/**
 * OAuth client registered through dynamic client registration (RFC 7591),
 * e.g. a Claude custom connector. Clients are public unless they asked for a
 * secret; only its hash is kept.
 */
export const OAuthClientSchema = z.object({
  id: z.string().min(1),
  name: z.string().max(100),
  redirectUris: z.array(z.string().max(500)).min(1).max(10),
  authMethod: z.enum(['none', 'client_secret_post', 'client_secret_basic']),
  secretHash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  createdAt: z.string(),
});
export type OAuthClient = z.infer<typeof OAuthClientSchema>;

/**
 * A user's approval of one OAuth client. Holds the hashes of the current
 * access token and refresh token; both rotate on every refresh. Deleting the
 * grant revokes both.
 */
export const OAuthGrantSchema = z.object({
  id: z.string().min(1),
  userId: z.string().min(1),
  clientId: z.string().min(1),
  clientName: z.string().max(100),
  /** The OAuth `scope` string (always `mcp`). What the grant may do is `access`. */
  scope: z.string().max(200),
  /**
   * Per-backend access the user chose on the consent screen, enforced like a
   * token's scope. Grants from before it existed read every backend.
   */
  access: TokenScopeSchema.default(readAllScope),
  accessHash: z.string().regex(/^[0-9a-f]{64}$/),
  accessExpiresAt: z.string(),
  refreshHash: z.string().regex(/^[0-9a-f]{64}$/),
  refreshExpiresAt: z.string(),
  /** Hashes of refresh tokens already rotated away; presenting one means it leaked. */
  usedRefresh: z.array(z.string().regex(/^[0-9a-f]{64}$/)).max(50).optional(),
  /** When the refresh token last rotated. */
  rotatedAt: z.string().optional(),
  createdAt: z.string(),
  lastUsedAt: z.string().optional(),
});
export type OAuthGrant = z.infer<typeof OAuthGrantSchema>;

export const InviteSchema = z.object({
  id: z.string().min(1),
  hash: z.string().regex(/^[0-9a-f]{64}$/),
  role: RoleSchema,
  name: z.string().max(64).optional(),
  createdBy: z.string(),
  createdAt: z.string(),
  expiresAt: z.string(),
});
export type Invite = z.infer<typeof InviteSchema>;

/**
 * Backend settings are stored loosely here and validated by each backend
 * module's own schema when used. This keeps the stored config forward
 * compatible when a backend gains new fields.
 */
export const BackendSettingsSchema = z
  .object({
    enabled: z.boolean().default(false),
    /** Installation-level switch for this backend's write tools (DESIGN §6). Off by default. */
    allowWrite: z.boolean().optional(),
    /**
     * Installation allowlist (DESIGN §4): exact tool names or `<backend>_*`
     * patterns. Absent means the module's default subset.
     */
    tools: z.array(z.string().max(128)).max(200).optional(),
  })
  .catchall(z.unknown());
export type BackendSettings = z.infer<typeof BackendSettingsSchema>;

/**
 * Certificate settings managed in the web UI. Only used when TLS_MODE is not
 * set in the environment (environment always wins). `cloudflareToken` is a
 * write-only secret: never returned by the API.
 */
export const ServerTlsSchema = z.object({
  mode: z.enum(['builtin', 'acme']).default('builtin'),
  acmeEmail: z.string().max(254).optional(),
  acmeStaging: z.boolean().default(false),
  acmeAgreeTos: z.boolean().default(false),
  cloudflareToken: z.string().optional(),
  cloudflareTokenSavedAt: z.string().optional(),
});
export type ServerTls = z.infer<typeof ServerTlsSchema>;

/**
 * Built-in chat assistant. One provider is active at a time; API keys are
 * kept per provider so switching back does not lose a key. Keys are
 * write-only: never returned by the API.
 *   anthropic – Claude API
 *   openai    – OpenAI (chat completions)
 *   local     – any OpenAI-compatible server (Ollama, LM Studio, vLLM, …)
 */
export const AiProviderSchema = z.enum(['anthropic', 'openai', 'local']);
export type AiProvider = z.infer<typeof AiProviderSchema>;

export const ServerAiSchema = z.object({
  enabled: z.boolean().default(false),
  provider: AiProviderSchema.default('anthropic'),
  model: z.string().max(200).default(''),
  /** OpenAI-compatible base URL, e.g. http://ollama:11434/v1. Used by openai (optional) and local (required). */
  baseUrl: z.string().max(500).optional(),
  keys: z.object({ anthropic: z.string().optional(), openai: z.string().optional(), local: z.string().optional() }).default({}),
  /**
   * The base URL each stored key was entered for. A stored key is only ever
   * sent there (or to the provider's own default URL); pointing the assistant
   * anywhere else needs the key to be entered again.
   */
  keyUrls: z.object({ openai: z.string().optional(), local: z.string().optional() }).optional(),
});
export type ServerAi = z.infer<typeof ServerAiSchema>;

/**
 * OAuth for connectors (e.g. Claude custom connectors). Off by default: while
 * off, discovery, registration, authorization and token endpoints return 404
 * and existing OAuth access tokens are refused. Grants are kept, so turning it
 * back on restores them.
 */
export const ServerOAuthSchema = z.object({
  enabled: z.boolean().default(false),
});
export type ServerOAuth = z.infer<typeof ServerOAuthSchema>;

/** Audit log options. The log itself is a separate append-only file. */
export const ServerAuditSchema = z.object({
  /** Graylog GELF HTTP input, e.g. http://graylog:12201/gelf. Empty = no forwarding. */
  gelfUrl: z.string().max(500).optional(),
  /** Newest known position per audit chain, so removing the log's files is noticed. */
  anchors: z.record(z.string(), z.number().int().nonnegative()).optional(),
});
export type ServerAudit = z.infer<typeof ServerAuditSchema>;

/**
 * One service in the administrator's service map. The backends share no key
 * (Wazuh knows hosts, Trivy images, DefectDojo endpoints), so the links are
 * stated here and never guessed by the tools that use them.
 */
const portNumber = z.number().int().min(1).max(65535);
export const ServiceInputSchema = z.object({
  name: z.string().trim().min(1).max(100),
  importance: z.enum(['critical', 'high', 'normal', 'low']).default('normal'),
  exposure: z.enum(['internet', 'internal', 'unknown']).default('unknown'),
  /** Public addresses. The IP and its DNS names are aliases of one endpoint; no port means any port. */
  endpoints: z
    .array(
      z.object({
        hosts: z.array(z.string().trim().toLowerCase().min(1).max(253).regex(/^[^\s/"\\]+$/, 'host name or IP only')).min(1).max(20),
        port: portNumber.optional(),
      }),
    )
    .max(50)
    .default([]),
  /** Wazuh agent IDs. */
  agents: z.array(z.string().regex(/^\d{3,6}$/, 'agent ID, e.g. 001')).max(50).default([]),
  /** Trivy artifact names, exactly as in the report. */
  images: z.array(z.string().trim().min(1).max(512)).max(100).default([]),
  /** Targets as firewall logs show them, when they differ from the endpoints (after NAT). */
  logTargets: z.array(z.object({ ip: z.ipv4().or(z.ipv6()), port: portNumber.optional() })).max(50).default([]),
  note: z.string().trim().max(500).optional(),
});
export const ServiceSchema = ServiceInputSchema.extend({ id: z.string().min(1) });
export type Service = z.infer<typeof ServiceSchema>;
export const MAX_SERVICES = 500;

export const ConfigSchema = z.object({
  version: z.literal(1),
  users: z.array(UserSchema).default([]),
  tokens: z.array(AccessTokenSchema).default([]),
  invites: z.array(InviteSchema).default([]),
  oauthClients: z.array(OAuthClientSchema).default([]),
  oauthGrants: z.array(OAuthGrantSchema).default([]),
  backends: z.record(z.string(), BackendSettingsSchema).default({}),
  services: z.array(ServiceSchema).max(MAX_SERVICES).default([]),
  server: z
    .object({
      tls: ServerTlsSchema.optional(),
      ai: ServerAiSchema.optional(),
      oauth: ServerOAuthSchema.optional(),
      audit: ServerAuditSchema.optional(),
    })
    .default({}),
});
export type Config = z.infer<typeof ConfigSchema>;

export function emptyConfig(): Config {
  return { version: 1, users: [], tokens: [], invites: [], oauthClients: [], oauthGrants: [], backends: {}, services: [], server: {} };
}
