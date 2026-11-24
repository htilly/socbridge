import express, { type Router } from 'express';
import { z } from 'zod';
import { redirectAllowed } from '../auth/oauth.js';
import { canRead, scopeProblem } from '../auth/scopes.js';
import { newAccessToken, newId, randomToken, sha256Hex } from '../auth/secrets.js';
import { BACKENDS, getModule, toolCatalog } from '../backends/registry.js';
import { insecureBackend, transportOf, transportPolicy } from '../backends/transport.js';
import type { BackendId, BackendModule } from '../backends/types.js';
import { AccessLevelSchema, readAllScope, RoleSchema, type AccessToken, type Config, type User } from '../config/schema.js';
import { VERSION } from '../version.js';
import { auditEvent } from './audit-event.js';
import { currentUser, HttpError, requireAdmin, requireFresh, requireUser, type AppContext } from './context.js';

const INVITE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_TOKENS_PER_USER = 25;

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const r = schema.safeParse(value);
  if (!r.success) throw new HttpError(400, r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
  return r.data;
}

const publicUser = (u: User) => ({
  id: u.id,
  name: u.name,
  role: u.role,
  disabled: u.disabled,
  createdAt: u.createdAt,
  passkeys: u.passkeys.length,
  writeBackends: u.writeBackends ?? [],
  readBackends: u.readBackends ?? null,
});

const publicToken = (t: AccessToken, users: readonly User[]) => ({
  id: t.id,
  label: t.label,
  hint: t.hint,
  userId: t.userId,
  userName: users.find((u) => u.id === t.userId)?.name ?? '(deleted)',
  createdAt: t.createdAt,
  expiresAt: t.expiresAt,
  lastUsedAt: t.lastUsedAt,
  expired: t.expiresAt ? Date.parse(t.expiresAt) <= Date.now() : false,
  scope: t.scope,
});

export const backendIds = new Set<string>(BACKENDS.map((b) => b.id));

/** What the token form offers: per backend, whether this user may ask for write and what it would add. */
export function scopeOptions(cfg: Readonly<Config>, user: User) {
  return BACKENDS.filter((m) => canRead(user, m.id)).map((m) => ({
    id: m.id,
    title: m.title,
    enabled: !!cfg.backends[m.id]?.enabled,
    writeAllowed: !!cfg.backends[m.id]?.allowWrite,
    writeGranted: (user.writeBackends ?? []).includes(m.id),
    writeTools: m.tools.filter((d) => d.access === 'write').map((d) => d.name),
  }));
}

const backendValues = z.record(z.string(), z.union([z.string(), z.boolean(), z.number()]));

const normUrl = (v: unknown) => (typeof v === 'string' ? v.trim().replace(/\/+$/, '') : '');
const normPem = (v: unknown) => (typeof v === 'string' ? v.replace(/\s+/g, '') : '');
/** Leading lower-case word of a field key: `manager` for managerUrl / managerPassword. */
const keyWord = (k: string) => /^[a-z]+/.exec(k)?.[0] ?? k;

/**
 * Which settings decide where (and how safely) a stored secret is sent: the
 * URL fields that share the secret's leading word (managerUrl for
 * managerPassword), or every URL field if none does, plus the TLS trust
 * settings, which cover every URL of the backend.
 */
export function secretTargetChange(
  mod: BackendModule<any, any>,
  secretKey: string,
  prev: Record<string, unknown>,
  next: Record<string, unknown>,
): string | null {
  const urls = mod.fields.filter((f) => f.type === 'url');
  const own = urls.filter((f) => keyWord(f.key) === keyWord(secretKey));
  for (const f of own.length ? own : urls) if (normUrl(prev[f.key]) !== normUrl(next[f.key])) return f.label;
  for (const f of mod.fields) {
    if (f.type === 'pem' && normPem(prev[f.key]) !== normPem(next[f.key])) return f.label;
    // Turning verification off weakens every connection; turning it on does not.
    if (f.key === 'tlsVerify' && prev[f.key] !== false && next[f.key] === false) return f.label;
  }
  return null;
}

/**
 * Applies form values onto stored backend settings. Secrets are write-only:
 * an empty value keeps the stored one, but only while the settings that decide
 * where it is sent stay the same (A-005). Otherwise the secret has to be
 * entered again, so a changed URL can never receive a stored credential.
 * Empty non-secret values are dropped.
 */
export function mergeBackendValues(
  mod: BackendModule<any, any>,
  prev: Record<string, unknown>,
  values: Record<string, string | boolean | number>,
): Record<string, unknown> {
  const known = new Set(mod.fields.map((f) => f.key));
  for (const k of Object.keys(values)) if (!known.has(k)) throw new HttpError(400, `Unknown field ${k}`);
  const next: Record<string, unknown> = {};
  const kept: string[] = [];
  for (const f of mod.fields) {
    const incoming = values[f.key];
    if (f.type === 'secret' && (incoming === undefined || incoming === '')) {
      if (prev[f.key] !== undefined) {
        next[f.key] = prev[f.key];
        kept.push(f.key);
      }
      continue;
    }
    if (incoming === undefined || incoming === '') continue;
    next[f.key] = incoming;
  }
  for (const key of kept) {
    const changed = secretTargetChange(mod, key, prev, next);
    if (changed) {
      const label = mod.fields.find((f) => f.key === key)?.label ?? key;
      throw new HttpError(400, `${changed} changed. Enter the ${label} again: a stored secret is only sent where it was entered for.`);
    }
  }
  return next;
}

/** Which settings differ, for the audit log: names only, except URLs (without credentials), which decide where data goes. */
export function backendChanges(mod: BackendModule<any, any>, prev: Record<string, unknown>, next: Record<string, unknown>) {
  const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  const changed = mod.fields.filter((f) => !same(prev[f.key], next[f.key]));
  const bare = (v: unknown) => {
    try {
      const u = new URL(String(v));
      return u.origin + u.pathname;
    } catch {
      return v === undefined ? '' : '(not a URL)';
    }
  };
  const urls = changed.filter((f) => f.type === 'url').map((f) => ({ field: f.key, from: bare(prev[f.key]), to: bare(next[f.key]) }));
  return { changed: changed.map((f) => f.key), ...(urls.length ? { urls } : {}) };
}

/** Where ChatGPT connectors send the OAuth code back. */
const CHATGPT_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';

export function apiRouter(ctx: AppContext): Router {
  const r = express.Router();
  const fresh = requireFresh(ctx);

  r.get('/me', (_req, res) => {
    const u = res.locals.user as User | undefined;
    res.json({
      ...(u ? { version: VERSION, buildSha: ctx.env.buildSha ?? null } : {}),
      setupRequired: ctx.setupToken() !== null,
      publicUrl: ctx.env.origin,
      caAvailable: !!ctx.caCertPem,
      oauthEnabled: ctx.oauth.enabled(),
      // Whether OAUTH_REDIRECT_HOSTS lets ChatGPT connectors finish sign-in;
      // the Access tokens page says what to change when it does not.
      chatgptRedirectAllowed: redirectAllowed(CHATGPT_REDIRECT, { httpsHosts: ctx.env.oauthRedirectHosts }),
      // Public anyway (/ca.crt, the TLS handshake); the setup guide uses it to
      // tell people what to compare before trusting the built-in CA.
      caFingerprint: ctx.tls?.caFingerprint() ?? null,
      tlsServing: ctx.tls ? ctx.tls.view().serving : 'off',
      tlsStaging: ctx.tls ? ctx.tls.view().staging : false,
      user: u ? publicUser(u) : null,
    });
  });

  // --- Access tokens ---------------------------------------------------------
  r.get('/tokens', requireUser, (req, res) => {
    const me = currentUser(res);
    const cfg = ctx.store.get();
    const all = req.query.all === '1' && me.role === 'admin';
    res.json(cfg.tokens.filter((t) => all || t.userId === me.id).map((t) => publicToken(t, cfg.users)));
  });

  r.post('/tokens', requireUser, fresh, async (req, res) => {
    const me = currentUser(res);
    const body = parse(
      z.object({
        label: z.string().trim().min(1).max(100),
        expiresInDays: z.number().int().min(1).max(3650).optional(),
        /** Absent: read on every backend, as before scopes existed. */
        scope: z.object({ backends: z.record(z.string(), AccessLevelSchema) }).optional(),
      }),
      req.body,
    );
    const scope = body.scope ?? { backends: Object.fromEntries(Object.entries(readAllScope().backends).filter(([id]) => canRead(me, id))) };
    const problem = scopeProblem(scope, me, backendIds);
    if (problem) throw new HttpError(problem.includes('write grant') ? 403 : 400, `scope: ${problem}`);
    const { token, hash, hint } = newAccessToken();
    const now = Date.now();
    const record: AccessToken = {
      id: newId(),
      userId: me.id,
      label: body.label,
      hash,
      hint,
      createdAt: new Date(now).toISOString(),
      scope,
      ...(body.expiresInDays ? { expiresAt: new Date(now + body.expiresInDays * 86_400_000).toISOString() } : {}),
    };
    await ctx.store.mutate((draft) => {
      if (draft.tokens.filter((t) => t.userId === me.id).length >= MAX_TOKENS_PER_USER) {
        throw new HttpError(409, `Token limit reached (${MAX_TOKENS_PER_USER}); revoke unused tokens first`);
      }
      draft.tokens.push(record);
    });
    await auditEvent(ctx, { by: me, action: 'auth.token.create', text: 'Access token created', details: { id: record.id, label: record.label, scope: scope.backends, expiresAt: record.expiresAt ?? null } });
    // The plaintext token is returned exactly once and never stored.
    res.status(201).json({ token, ...publicToken(record, ctx.store.get().users) });
  });

  r.get('/tokens/scopes', requireUser, (req, res) => {
    const me = currentUser(res);
    const cfg = ctx.store.get();
    // Administrators editing someone else's token see that user's grants.
    const userId = typeof req.query.user === 'string' && me.role === 'admin' ? req.query.user : me.id;
    const user = cfg.users.find((u) => u.id === userId);
    if (!user) throw new HttpError(404, 'User not found');
    res.json(scopeOptions(cfg, user));
  });

  /**
   * Changes a token's scope in place; the token itself stays the same, so
   * clients keep working. The owner or an administrator may do it, and the
   * new scope is checked against the owner's write grants. Takes effect on
   * the token's next call.
   */
  r.patch('/tokens/:id', requireUser, fresh, async (req, res) => {
    const me = currentUser(res);
    const body = parse(z.object({ scope: z.object({ backends: z.record(z.string(), AccessLevelSchema) }) }), req.body);
    const id = String(req.params.id);
    const before = await ctx.store.mutate((draft) => {
      const t = draft.tokens.find((x) => x.id === id);
      if (!t || (t.userId !== me.id && me.role !== 'admin')) throw new HttpError(404, 'Token not found');
      const owner = draft.users.find((u) => u.id === t.userId);
      if (!owner) throw new HttpError(404, 'Token not found');
      const problem = scopeProblem(body.scope, owner, backendIds);
      if (problem) {
        const whose = owner.id === me.id ? problem : problem.replace('you have no write grant', `${owner.name} has no write grant`);
        throw new HttpError(problem.includes('write grant') ? 403 : 400, `scope: ${whose}`);
      }
      const prev = t.scope;
      t.scope = body.scope;
      return prev;
    });
    await auditEvent(ctx, { by: me, action: 'auth.token.scope', text: 'Access token scope changed', details: { id, from: before.backends, to: body.scope.backends } });
    const cfg = ctx.store.get();
    res.json(publicToken(cfg.tokens.find((t) => t.id === id)!, cfg.users));
  });

  r.delete('/tokens/:id', requireUser, async (req, res) => {
    const me = currentUser(res);
    await ctx.store.mutate((draft) => {
      const t = draft.tokens.find((x) => x.id === req.params.id);
      if (!t || (t.userId !== me.id && me.role !== 'admin')) throw new HttpError(404, 'Token not found');
      draft.tokens = draft.tokens.filter((x) => x.id !== t.id);
    });
    await auditEvent(ctx, { by: me, action: 'auth.token.revoke', text: 'Access token revoked', details: { id: req.params.id } });
    res.json({ ok: true });
  });

  // --- Own sessions ----------------------------------------------------------
  r.get('/sessions', requireUser, (_req, res) => {
    res.json({ count: ctx.sessions.countForUser(currentUser(res).id) });
  });

  r.delete('/sessions/others', requireUser, async (req, res) => {
    const me = currentUser(res);
    const ended = ctx.sessions.destroyOthers(req, me.id);
    await auditEvent(ctx, { by: me, action: 'auth.sessions.end', text: 'Other sessions ended', details: { ended } });
    res.json({ ended });
  });

  // --- Own passkeys ----------------------------------------------------------
  r.get('/passkeys', requireUser, (_req, res) => {
    const me = currentUser(res);
    res.json(me.passkeys.map((p) => ({ id: p.id, label: p.label, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt })));
  });

  r.delete('/passkeys/:id', requireUser, fresh, async (req, res) => {
    const me = currentUser(res);
    await ctx.store.mutate((draft) => {
      const u = draft.users.find((x) => x.id === me.id)!;
      if (!u.passkeys.some((p) => p.id === req.params.id)) throw new HttpError(404, 'Passkey not found');
      if (u.passkeys.length <= 1) throw new HttpError(409, 'Cannot remove your only passkey');
      u.passkeys = u.passkeys.filter((p) => p.id !== req.params.id);
    });
    ctx.sessions.destroyForPasskey(me.id, String(req.params.id));
    await auditEvent(ctx, { by: me, action: 'auth.passkey.remove', text: 'Passkey removed', details: { id: req.params.id } });
    res.json({ ok: true });
  });

  // --- Users (admin) ---------------------------------------------------------
  r.get('/users', requireAdmin, (_req, res) => {
    res.json(ctx.store.get().users.map(publicUser));
  });

  r.patch('/users/:id', requireAdmin, fresh, async (req, res) => {
    const me = currentUser(res);
    const body = parse(
      z.object({
        role: RoleSchema.optional(),
        disabled: z.boolean().optional(),
        /** Backends this user may hold write access on (replaces the list). */
        writeBackends: z.array(z.string()).max(20).optional(),
        /** Backends this user may read; null lifts the limit. */
        readBackends: z.array(z.string()).max(20).nullable().optional(),
      }),
      req.body,
    );
    for (const id of [...(body.writeBackends ?? []), ...(body.readBackends ?? [])]) if (!backendIds.has(id)) throw new HttpError(400, `Unknown backend ${id}`);
    const target = String(req.params.id);
    const before = await ctx.store.mutate((draft) => {
      const u = draft.users.find((x) => x.id === target);
      if (!u) throw new HttpError(404, 'User not found');
      const was = { name: u.name, role: u.role, disabled: u.disabled, writeBackends: [...(u.writeBackends ?? [])], readBackends: u.readBackends ?? null };
      if (u.id === me.id && (body.disabled || body.role === 'user')) {
        throw new HttpError(409, 'You cannot disable or demote yourself');
      }
      if (body.role) u.role = body.role;
      if (body.disabled !== undefined) u.disabled = body.disabled;
      if (body.readBackends !== undefined) {
        if (body.readBackends === null) delete u.readBackends;
        else u.readBackends = [...new Set(body.readBackends)];
      }
      // A-010: invites do not outlive the rights of the administrator who made them.
      if (u.disabled || u.role !== 'admin') draft.invites = draft.invites.filter((i) => i.createdBy !== u.id);
      if (body.writeBackends) u.writeBackends = [...new Set(body.writeBackends)];
      if (!draft.users.some((x) => x.role === 'admin' && !x.disabled)) {
        throw new HttpError(409, 'At least one active administrator is required');
      }
      return was;
    });
    if (body.disabled) ctx.sessions.destroyForUser(target);
    await auditEvent(ctx, { by: me, action: 'admin.user.update', text: 'User updated', details: { id: target, name: before.name, from: before, to: body } });
    res.json({ ok: true });
  });

  r.delete('/users/:id', requireAdmin, fresh, async (req, res) => {
    const me = currentUser(res);
    const target = String(req.params.id);
    if (target === me.id) throw new HttpError(409, 'You cannot delete yourself');
    const name = await ctx.store.mutate((draft) => {
      const u = draft.users.find((x) => x.id === target);
      if (!u) throw new HttpError(404, 'User not found');
      draft.users = draft.users.filter((x) => x.id !== target);
      draft.invites = draft.invites.filter((i) => i.createdBy !== target);
      draft.tokens = draft.tokens.filter((t) => t.userId !== target);
      draft.oauthGrants = draft.oauthGrants.filter((g) => g.userId !== target);
      return u.name;
    });
    ctx.sessions.destroyForUser(target);
    await auditEvent(ctx, { by: me, action: 'admin.user.delete', text: 'User deleted', details: { id: target, name } });
    res.json({ ok: true });
  });

  // --- Invites (admin) -------------------------------------------------------
  r.get('/invites', requireAdmin, (_req, res) => {
    const now = Date.now();
    res.json(
      ctx.store
        .get()
        .invites.filter((i) => Date.parse(i.expiresAt) > now)
        .map((i) => ({ id: i.id, role: i.role, name: i.name, createdAt: i.createdAt, expiresAt: i.expiresAt })),
    );
  });

  r.post('/invites', requireAdmin, fresh, async (req, res) => {
    const me = currentUser(res);
    const body = parse(z.object({ role: RoleSchema.default('user'), name: z.string().trim().max(64).optional() }), req.body);
    const code = randomToken(24);
    const now = Date.now();
    const invite = {
      id: newId(),
      hash: sha256Hex(code),
      role: body.role,
      name: body.name || undefined,
      createdBy: me.id,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + INVITE_TTL_MS).toISOString(),
    };
    await ctx.store.mutate((draft) => {
      draft.invites = draft.invites.filter((i) => Date.parse(i.expiresAt) > now);
      draft.invites.push(invite);
    });
    await auditEvent(ctx, { by: me, action: 'admin.invite.create', text: 'Invite created', details: { id: invite.id, role: body.role, name: invite.name ?? null } });
    res.status(201).json({ id: invite.id, expiresAt: invite.expiresAt, url: `${ctx.env.origin}/#/invite/${code}` });
  });

  r.delete('/invites/:id', requireAdmin, async (req, res) => {
    const found = await ctx.store.mutate((draft) => {
      const n = draft.invites.length;
      draft.invites = draft.invites.filter((i) => i.id !== req.params.id);
      return draft.invites.length < n;
    });
    if (found) await auditEvent(ctx, { by: currentUser(res), action: 'admin.invite.delete', text: 'Invite deleted', details: { id: req.params.id } });
    res.json({ ok: true });
  });

  // --- Backends (admin) ------------------------------------------------------
  r.get('/backends', requireAdmin, (_req, res) => {
    const cfg = ctx.store.get();
    res.json(
      BACKENDS.map((m) => {
        const stored = cfg.backends[m.id] ?? { enabled: false };
        const values: Record<string, unknown> = {};
        const secretsSet: string[] = [];
        for (const f of m.fields) {
          const v = stored[f.key];
          if (f.type === 'secret') {
            if (typeof v === 'string' && v !== '') secretsSet.push(f.key);
          } else if (v !== undefined) values[f.key] = v;
        }
        return {
          id: m.id,
          title: m.title,
          description: m.description,
          maturity: m.maturity,
          plannedTools: m.plannedTools ?? [],
          guide: m.guide ?? null,
          fields: m.fields,
          values,
          secretsSet,
          allowWrite: !!stored.allowWrite,
          /** null: the module's default subset applies. */
          allowlist: stored.tools ?? null,
          tools: toolCatalog(m),
          dynamicToolPattern: m.dynamicToolPattern ?? null,
          ...transportOf(m, stored as Record<string, unknown>),
          ...ctx.registry.status(m.id),
        };
      }),
    );
  });

  r.put('/backends/:id', requireAdmin, fresh, async (req, res) => {
    const me = currentUser(res);
    const mod = getModule(String(req.params.id));
    if (!mod) throw new HttpError(404, 'Unknown backend');
    const body = parse(
      z.object({
        enabled: z.boolean(),
        values: backendValues,
        /** Omitted: unchanged. */
        allowWrite: z.boolean().optional(),
        /** Omitted: unchanged; null: back to the module's defaults. */
        allowlist: z.array(z.string().trim().min(1).max(128)).max(200).nullable().optional(),
      }),
      req.body,
    );
    for (const p of body.allowlist ?? []) {
      if (!p.startsWith(`${mod.id}_`) || /\*./.test(p) || !/^[a-z0-9_*-]+$/i.test(p)) {
        throw new HttpError(400, `allowlist: "${p}" must be a ${mod.id}_ tool name or a ${mod.id}_… prefix ending in *`);
      }
    }
    const { prev, next } = await ctx.store.mutate((draft) => {
      const prev = draft.backends[mod.id] ?? { enabled: false };
      const allowWrite = body.allowWrite ?? prev.allowWrite;
      const tools = body.allowlist === undefined ? prev.tools : (body.allowlist ?? undefined);
      draft.backends[mod.id] = {
        enabled: body.enabled,
        ...(allowWrite ? { allowWrite: true } : {}),
        ...(tools ? { tools: [...new Set(tools)] } : {}),
        ...mergeBackendValues(mod, prev, body.values),
      };
      if (body.enabled && transportPolicy.requireSecure) {
        const why = insecureBackend(mod, draft.backends[mod.id]);
        if (why) throw new HttpError(400, `${why}. This installation requires encrypted, verified connections (REQUIRE_SECURE_TRANSPORT).`);
      }
      return { prev, next: draft.backends[mod.id]! };
    });
    await auditEvent(ctx, {
      by: me,
      action: 'admin.backend.update',
      text: 'Backend settings updated',
      backend: mod.id,
      details: {
        backend: mod.id,
        enabled: { from: !!prev.enabled, to: body.enabled },
        allowWrite: { from: !!prev.allowWrite, to: !!next.allowWrite },
        ...(body.allowlist !== undefined ? { allowlist: body.allowlist } : {}),
        ...backendChanges(mod, prev, next),
      },
    });
    res.json(ctx.registry.status(mod.id as BackendId));
  });

  r.post('/backends/:id/test', requireAdmin, async (req, res) => {
    const mod = getModule(String(req.params.id));
    if (!mod) throw new HttpError(404, 'Unknown backend');
    const body = parse(z.object({ values: backendValues.optional() }), req.body ?? {});
    // With values, test what is in the form (merged with stored secrets) without saving it.
    if (body.values) {
      const prev = ctx.store.get().backends[mod.id] ?? { enabled: false };
      res.json(await ctx.registry.testSettings(mod.id, mergeBackendValues(mod, prev, body.values)));
    } else res.json(await ctx.registry.test(mod.id));
  });

  return r;
}
