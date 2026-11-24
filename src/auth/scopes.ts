import type { BackendId, ToolAccess } from '../backends/types.js';
import type { Config, TokenScope, User } from '../config/schema.js';

/**
 * Who is calling tools. Only identities are kept here; what they may do is
 * looked up in the live config every time (at registration and again at call
 * time), so a revoked token, a removed grant or a switched-off backend takes
 * effect on the very next call.
 */
export interface Principal {
  /** `token`: access token (msec_), `oauth`: OAuth grant (msat_), `chat`: the built-in assistant. */
  kind: 'token' | 'oauth' | 'chat';
  /** Token ID, grant ID, or the user ID for the chat. */
  id: string;
  userId: string;
  userName: string;
  /** Token label or OAuth client name, for the audit log. */
  label?: string;
}

/** Whether an administrator lets this user read a backend at all (absent list: every backend). */
export function canRead(user: Pick<User, 'readBackends'>, backend: string): boolean {
  return !user.readBackends || user.readBackends.includes(backend);
}

export type Level = 'none' | ToolAccess;

export interface BackendAccess {
  level: Level;
  /** Why the level is lower than the credential asks for, if it is. */
  reason?: string;
}

/** `token:<id>`, `oauth:<id>`, `chat:<user id>`: how a credential is named in logs. */
export function credentialName(p: Principal): string {
  return `${p.kind}:${p.id}`;
}

/**
 * What a principal may do on one backend right now (DESIGN §5, §6).
 *
 * Read needs a live credential and, for access tokens, the backend in the
 * token's scope. Write needs all three levels to say yes: the installation
 * (the backend's `allowWrite`), the user (an administrator's grant) and the
 * credential (a token or OAuth grant scoped `write`). The chat is read-only by
 * construction. When any level says no, write degrades to read.
 */
export function backendAccess(cfg: Readonly<Config>, p: Principal, backend: BackendId): BackendAccess {
  const user = cfg.users.find((u) => u.id === p.userId);
  if (!user || user.disabled) return { level: 'none', reason: 'user disabled or deleted' };

  if (!canRead(user, backend)) return { level: 'none', reason: 'user has no read access to this backend' };

  let asked: Level;
  if (p.kind === 'token') {
    const t = cfg.tokens.find((x) => x.id === p.id && x.userId === p.userId);
    if (!t) return { level: 'none', reason: 'token revoked' };
    if (t.expiresAt && Date.parse(t.expiresAt) <= Date.now()) return { level: 'none', reason: 'token expired' };
    asked = t.scope.backends[backend] ?? 'none';
    if (asked === 'none') return { level: 'none', reason: 'not in token scope' };
  } else if (p.kind === 'oauth') {
    const g = cfg.oauthGrants.find((x) => x.id === p.id && x.userId === p.userId);
    if (!g) return { level: 'none', reason: 'grant revoked' };
    asked = g.access.backends[backend] ?? 'none';
    if (asked === 'none') return { level: 'none', reason: 'not in the scope approved for this app' };
  } else {
    asked = 'read';
  }

  if (asked !== 'write') return { level: 'read' };
  if (!cfg.backends[backend]?.allowWrite) return { level: 'read', reason: 'write tools are off for this backend' };
  if (!(user.writeBackends ?? []).includes(backend)) return { level: 'read', reason: 'user has no write grant for this backend' };
  return { level: 'write' };
}

/** Whether a level covers a tool of the given access. */
export function permits(level: Level, access: ToolAccess): boolean {
  return access === 'read' ? level !== 'none' : level === 'write';
}

/**
 * Why a user may not give a credential (token or OAuth grant) this scope, or
 * null. A user can only give what the user has: read on any known backend,
 * write only where an administrator granted it. Whether the installation
 * allows write is checked live at call time.
 */
export function scopeProblem(scope: TokenScope, user: User, known: ReadonlySet<string>): string | null {
  const entries = Object.entries(scope.backends);
  if (!entries.length) return 'choose at least one backend';
  for (const [id, level] of entries) {
    if (!known.has(id)) return `unknown backend ${id}`;
    if (!canRead(user, id)) return `you have no read access to ${id}; ask an administrator`;
    if (level === 'write' && !(user.writeBackends ?? []).includes(id)) return `you have no write grant for ${id}; ask an administrator`;
  }
  return null;
}
