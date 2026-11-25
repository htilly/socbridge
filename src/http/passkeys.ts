import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import express, { type Request, type Router } from 'express';
import { z } from 'zod';
import { RequestLimiter } from '../auth/ratelimit.js';
import { newId, randomToken, safeEqualHex, safeEqualString, sha256Hex } from '../auth/secrets.js';
import type { Config, Role, User } from '../config/schema.js';
import { errMessage, log } from '../log.js';
import { auditEvent } from './audit-event.js';
import { currentUser, HttpError, requireFresh, type AppContext } from './context.js';

/**
 * Passkey (WebAuthn) ceremonies. There are no passwords anywhere:
 *  - setup:  first admin enrols with the one-time setup token
 *  - invite: a new user enrols with an admin-issued invite code
 *  - add:    a signed-in user adds another passkey to their account
 *  - login:  discoverable-credential sign-in (no username prompt)
 */

const FLOW_TTL_MS = 5 * 60 * 1000;
/** Time to answer the browser's prompt: scanning a QR code with a phone takes longer than the usual minute. */
const PROMPT_MS = 3 * 60 * 1000;
const MAX_FLOWS = 1000;
/** Ceremonies one address may start per minute. */
const STARTS_PER_MINUTE = 30;

type Flow =
  | { kind: 'register'; challenge: string; expires: number; mode: 'setup' | 'invite' | 'add'; user: PendingUser; inviteId?: string }
  /** `reauth`: the signed-in user confirming with a passkey, not a new sign-in. */
  | { kind: 'login'; challenge: string; expires: number; reauth?: string };

interface PendingUser {
  id: string;
  name: string;
  role: Role;
  webauthnUserId: string;
  existing: boolean;
}

const NameSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[\p{L}\p{N} ._@-]+$/u, 'Name may contain letters, digits, spaces and . _ @ -');

const LabelSchema = z.string().trim().max(100).optional();

/** Most credentials a browser is handed in allowCredentials (Chromium caps the list at 64). */
const MAX_ALLOW = 64;

/**
 * Credentials that can be used from a phone, each marked as reachable only over 'hybrid' (QR code + Bluetooth).
 * Windows Hello, and with it Edge and Chrome on Windows, ignores the WebAuthn `hints` field and opens on the
 * local PIN prompt; a list whose every entry is hybrid-only makes it, and other browsers, go straight to the QR code.
 * Passkeys known to live only on this computer or a security key are left out. An empty result means a normal,
 * discoverable sign-in with all choices.
 */
export function phoneCredentials(users: readonly User[]): { id: string; transports: AuthenticatorTransport[] }[] {
  return users
    .filter((u) => !u.disabled)
    .flatMap((u) => u.passkeys)
    .filter((p) => p.transports.length === 0 || p.transports.includes('hybrid'))
    .sort((a, b) => (b.lastUsedAt ?? '').localeCompare(a.lastUsedAt ?? ''))
    .slice(0, MAX_ALLOW)
    .map((p) => ({ id: p.id, transports: ['hybrid'] }));
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const r = schema.safeParse(value);
  if (!r.success) throw new HttpError(400, r.error.issues.map((i) => i.message).join('; '));
  return r.data;
}

/** An invite is only as good as the administrator who issued it. */
function issuerActive(cfg: Readonly<Config>, id: string): boolean {
  return cfg.users.some((u) => u.id === id && u.role === 'admin' && !u.disabled);
}

function clientKey(req: Request): string {
  return req.ip ?? 'unknown';
}

export function passkeyRouter(ctx: AppContext): Router {
  const router = express.Router();
  const flows = new Map<string, Flow>();
  setInterval(() => {
    const now = Date.now();
    for (const [k, f] of flows) if (f.expires <= now) flows.delete(k);
  }, 60_000).unref();

  const starts = new RequestLimiter(STARTS_PER_MINUTE);
  /** Starting a ceremony costs memory and needs no session, so it is limited per address and in total. */
  const addFlow = (id: string, flow: Flow) => {
    if (flows.size >= MAX_FLOWS) flows.delete(flows.keys().next().value!);
    flows.set(id, flow);
  };
  const guardStart = (req: Request) => {
    guardAttempts(req);
    if (!starts.take(clientKey(req))) throw new HttpError(429, 'Too many sign-in attempts; try again in a minute');
  };

  const takeFlow = (id: unknown, kind: Flow['kind']): Flow => {
    if (typeof id !== 'string') throw new HttpError(400, 'Missing flowId');
    const f = flows.get(id);
    flows.delete(id); // single use, success or not
    if (!f || f.kind !== kind || f.expires <= Date.now()) throw new HttpError(400, 'Sign-in attempt expired; start again');
    return f;
  };

  const guardAttempts = (req: Request) => {
    if (ctx.authLimiter.isBlocked(clientKey(req))) throw new HttpError(429, 'Too many failed attempts; try again later');
  };

  const nameTaken = (name: string) =>
    ctx.store.get().users.some((u) => u.name.toLowerCase() === name.toLowerCase());

  const startRegistration = async (pending: PendingUser, mode: 'setup' | 'invite' | 'add', exclude: User['passkeys'], inviteId?: string) => {
    const options = await generateRegistrationOptions({
      rpName: 'SocBridge',
      timeout: PROMPT_MS,
      rpID: ctx.env.rpId,
      userName: pending.name,
      userDisplayName: pending.name,
      userID: Buffer.from(pending.webauthnUserId, 'base64url'),
      attestationType: 'none',
      excludeCredentials: exclude.map((p) => ({ id: p.id, transports: p.transports as AuthenticatorTransport[] })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
    const flowId = randomToken(16);
    addFlow(flowId, { kind: 'register', challenge: options.challenge, expires: Date.now() + FLOW_TTL_MS, mode, user: pending, inviteId });
    return { flowId, options };
  };

  const newPending = (name: string, role: Role): PendingUser => ({
    id: newId(),
    name,
    role,
    webauthnUserId: randomToken(32),
    existing: false,
  });

  // --- First admin -------------------------------------------------------
  router.post('/setup/options', async (req, res) => {
    guardStart(req);
    const body = parse(z.object({ setupToken: z.string(), name: NameSchema }), req.body);
    const expected = ctx.setupToken();
    if (!expected) throw new HttpError(409, 'Setup is already complete');
    if (!safeEqualString(body.setupToken.trim(), expected)) {
      ctx.authLimiter.fail(clientKey(req));
      await auditEvent(ctx, { by: 'anonymous', action: 'auth.setup', text: 'Invalid setup token', outcome: 'denied', access: 'read', message: 'invalid setup token', details: { ip: req.ip } });
      throw new HttpError(403, 'Invalid setup token');
    }
    res.json(await startRegistration(newPending(body.name, 'admin'), 'setup', []));
  });

  // --- Invited user ------------------------------------------------------
  router.post('/invite/options', async (req, res) => {
    guardStart(req);
    const body = parse(z.object({ code: z.string().min(10).max(200), name: NameSchema }), req.body);
    const hash = sha256Hex(body.code);
    const invite = ctx.store.get().invites.find((i) => safeEqualHex(i.hash, hash));
    if (!invite || Date.parse(invite.expiresAt) <= Date.now() || !issuerActive(ctx.store.get(), invite.createdBy)) {
      ctx.authLimiter.fail(clientKey(req));
      await auditEvent(ctx, { by: 'anonymous', action: 'auth.invite', text: 'Invalid invite', outcome: 'denied', access: 'read', message: 'invalid or expired invite', details: { ip: req.ip } });
      throw new HttpError(403, 'Invite is invalid or has expired');
    }
    if (nameTaken(body.name)) throw new HttpError(409, 'That name is already in use');
    res.json(await startRegistration(newPending(body.name, invite.role), 'invite', [], invite.id));
  });

  // --- Additional passkey for the signed-in user -------------------------
  router.post('/add/options', requireFresh(ctx), async (_req, res) => {
    const user = currentUser(res);
    const pending: PendingUser = { id: user.id, name: user.name, role: user.role, webauthnUserId: user.webauthnUserId, existing: true };
    res.json(await startRegistration(pending, 'add', user.passkeys));
  });

  // --- Finish any registration ------------------------------------------
  router.post('/register/verify', async (req, res) => {
    const body = parse(z.object({ flowId: z.string(), response: z.unknown(), label: LabelSchema }), req.body);
    const flow = takeFlow(body.flowId, 'register');
    if (flow.kind !== 'register') throw new HttpError(400, 'Wrong flow');
    if (flow.mode === 'add' && currentUser(res).id !== flow.user.id) throw new HttpError(403, 'Session changed');

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.response as RegistrationResponseJSON,
        expectedChallenge: flow.challenge,
        expectedOrigin: ctx.env.origin,
        expectedRPID: ctx.env.rpId,
        requireUserVerification: true,
      });
    } catch (err) {
      ctx.authLimiter.fail(clientKey(req));
      throw new HttpError(400, `Passkey registration failed: ${errMessage(err)}`);
    }
    if (!verification.verified || !verification.registrationInfo) throw new HttpError(400, 'Passkey could not be verified');
    const cred = verification.registrationInfo.credential;
    const now = new Date().toISOString();
    const passkey = {
      id: cred.id,
      publicKey: Buffer.from(cred.publicKey).toString('base64url'),
      counter: cred.counter,
      transports: cred.transports ?? [],
      label: body.label || 'Passkey',
      createdAt: now,
    };

    const user = await ctx.store.mutate((draft) => {
      if (draft.users.some((u) => u.passkeys.some((p) => p.id === passkey.id))) {
        throw new HttpError(409, 'This passkey is already registered');
      }
      if (flow.mode === 'add') {
        const u = draft.users.find((x) => x.id === flow.user.id);
        if (!u) throw new HttpError(404, 'User no longer exists');
        u.passkeys.push(passkey);
        return u;
      }
      // Re-check conditions inside the mutation to close races between options and verify.
      if (flow.mode === 'setup' && draft.users.some((u) => u.role === 'admin')) {
        throw new HttpError(409, 'Setup is already complete');
      }
      if (flow.mode === 'invite') {
        const idx = draft.invites.findIndex((i) => i.id === flow.inviteId);
        if (idx === -1 || Date.parse(draft.invites[idx]!.expiresAt) <= Date.now() || !issuerActive(draft, draft.invites[idx]!.createdBy)) {
          throw new HttpError(403, 'Invite is invalid or has expired');
        }
        draft.invites.splice(idx, 1);
      }
      if (draft.users.some((u) => u.name.toLowerCase() === flow.user.name.toLowerCase())) {
        throw new HttpError(409, 'That name is already in use');
      }
      const u: User = {
        id: flow.user.id,
        name: flow.user.name,
        role: flow.user.role,
        disabled: false,
        webauthnUserId: flow.user.webauthnUserId,
        passkeys: [passkey],
        createdAt: now,
      };
      draft.users.push(u);
      return u;
    });

    await auditEvent(ctx, { by: user, action: 'auth.passkey.add', text: 'Passkey registered', details: { mode: flow.mode, role: user.role, label: passkey.label, ip: req.ip } });
    if (flow.mode !== 'add') ctx.sessions.create(res, user.id, passkey.id);
    res.json({ ok: true });
  });

  // --- Sign in -----------------------------------------------------------
  router.post('/login/options', async (req, res) => {
    guardStart(req);
    const { phone } = parse(z.object({ phone: z.boolean().optional() }), req.body ?? {});
    const options = await generateAuthenticationOptions({
      rpID: ctx.env.rpId,
      timeout: PROMPT_MS,
      userVerification: 'required',
      allowCredentials: phone ? phoneCredentials(ctx.store.get().users) : undefined,
    });
    const flowId = randomToken(16);
    addFlow(flowId, { kind: 'login', challenge: options.challenge, expires: Date.now() + FLOW_TTL_MS });
    res.json({ flowId, options });
  });

  router.post('/reauth/options', async (req, res) => {
    guardStart(req);
    const user = currentUser(res);
    const options = await generateAuthenticationOptions({
      rpID: ctx.env.rpId,
      timeout: PROMPT_MS,
      userVerification: 'required',
      allowCredentials: user.passkeys.map((p) => ({ id: p.id, transports: p.transports as AuthenticatorTransport[] })),
    });
    const flowId = randomToken(16);
    addFlow(flowId, { kind: 'login', challenge: options.challenge, expires: Date.now() + FLOW_TTL_MS, reauth: user.id });
    res.json({ flowId, options });
  });

  router.post('/login/verify', async (req, res) => {
    guardAttempts(req);
    const body = parse(z.object({ flowId: z.string(), response: z.unknown() }), req.body);
    const flow = takeFlow(body.flowId, 'login');
    if (flow.kind !== 'login') throw new HttpError(400, 'Wrong flow');
    const response = body.response as AuthenticationResponseJSON;
    const fail = async (msg: string, by: User | string = 'anonymous'): Promise<never> => {
      ctx.authLimiter.fail(clientKey(req));
      await auditEvent(ctx, { by, action: 'auth.sign_in', text: 'Sign-in refused', outcome: 'denied', access: 'read', message: msg, details: { ip: req.ip } });
      throw new HttpError(401, msg);
    };

    const user = ctx.store.get().users.find((u) => u.passkeys.some((p) => p.id === response?.id));
    const passkey = user?.passkeys.find((p) => p.id === response?.id);
    if (!user || !passkey) return fail('Unknown passkey');
    if (flow.reauth && (flow.reauth !== user.id || (res.locals.user as User | undefined)?.id !== user.id)) return fail('Passkey does not belong to the signed-in user', user);
    if (user.disabled) return fail('Account is disabled', user);
    const handle = response.response?.userHandle;
    if (handle && handle !== user.webauthnUserId) return fail('Passkey does not belong to this account', user);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: flow.challenge,
        expectedOrigin: ctx.env.origin,
        expectedRPID: ctx.env.rpId,
        credential: {
          id: passkey.id,
          publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64url')),
          counter: passkey.counter,
          transports: passkey.transports as AuthenticatorTransport[],
        },
        requireUserVerification: true,
      });
    } catch (err) {
      return fail(`Sign-in failed: ${errMessage(err)}`, user);
    }
    if (!verification.verified) return fail('Sign-in failed', user);

    const now = new Date().toISOString();
    await ctx.store.mutate((draft) => {
      const p = draft.users.find((u) => u.id === user.id)?.passkeys.find((x) => x.id === passkey.id);
      if (p) {
        p.counter = verification.authenticationInfo.newCounter;
        p.lastUsedAt = now;
      }
    });
    if (flow.reauth) {
      ctx.sessions.refresh(req, user.id);
      await auditEvent(ctx, { by: user, action: 'auth.confirm', text: 'Passkey confirmed', access: 'read', details: { ip: req.ip } });
      res.json({ ok: true });
      return;
    }
    ctx.sessions.create(res, user.id, passkey.id);
    await auditEvent(ctx, { by: user, action: 'auth.sign_in', text: 'User signed in', access: 'read', details: { ip: req.ip } });
    res.json({ ok: true });
  });

  router.post('/logout', async (req, res) => {
    const user = res.locals.user as User | undefined;
    ctx.sessions.destroy(req, res);
    if (user) await auditEvent(ctx, { by: user, action: 'auth.sign_out', text: 'User signed out', access: 'read' });
    res.json({ ok: true });
  });

  return router;
}
