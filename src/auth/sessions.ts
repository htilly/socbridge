import type { Request, Response } from 'express';
import { randomToken, sha256Hex } from './secrets.js';

/**
 * Browser sessions for the web UI, kept in memory (a restart logs everyone
 * out, which is fine for an admin console). The cookie holds a random ID; only
 * its hash is used as the map key.
 *
 * `__Host-` prefix forces Secure, Path=/ and no Domain attribute. This also
 * works with TLS_MODE=off because the browser still talks HTTPS to the proxy.
 */
export const SESSION_COOKIE = '__Host-socbridge_sid';
const IDLE_MS = 2 * 60 * 60 * 1000;
const ABSOLUTE_MS = 12 * 60 * 60 * 1000;
/** How long a passkey check counts as recent for sensitive changes. */
const FRESH_MS = 15 * 60 * 1000;

interface Session {
  userId: string;
  /** The passkey it was opened with; removing that passkey ends the session. */
  passkeyId: string;
  /** Last passkey check. */
  verifiedAt: number;
  createdAt: number;
  lastSeen: number;
}

export class SessionManager {
  private sessions = new Map<string, Session>();

  constructor() {
    setInterval(() => this.sweep(), 10 * 60 * 1000).unref();
  }

  create(res: Response, userId: string, passkeyId: string): void {
    const sid = randomToken(32);
    const now = Date.now();
    this.sessions.set(sha256Hex(sid), { userId, passkeyId, verifiedAt: now, createdAt: now, lastSeen: now });
    res.cookie(SESSION_COOKIE, sid, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
      maxAge: ABSOLUTE_MS,
    });
  }

  /** Returns the user ID for a valid session and slides the idle timeout. */
  resolve(req: Request): string | null {
    const sid = readCookie(req, SESSION_COOKIE);
    if (!sid) return null;
    const key = sha256Hex(sid);
    const s = this.sessions.get(key);
    if (!s) return null;
    const now = Date.now();
    if (now - s.lastSeen > IDLE_MS || now - s.createdAt > ABSOLUTE_MS) {
      this.sessions.delete(key);
      return null;
    }
    s.lastSeen = now;
    return s.userId;
  }

  private find(req: Request): Session | undefined {
    const sid = readCookie(req, SESSION_COOKIE);
    return sid ? this.sessions.get(sha256Hex(sid)) : undefined;
  }

  isFresh(req: Request): boolean {
    const s = this.find(req);
    return !!s && Date.now() - s.verifiedAt <= FRESH_MS;
  }

  /** The user proved possession of a passkey again in this session. */
  refresh(req: Request, userId: string): void {
    const s = this.find(req);
    if (s?.userId === userId) s.verifiedAt = Date.now();
  }

  countForUser(userId: string): number {
    let n = 0;
    for (const s of this.sessions.values()) if (s.userId === userId) n++;
    return n;
  }

  destroyForPasskey(userId: string, passkeyId: string): void {
    for (const [k, v] of this.sessions) if (v.userId === userId && v.passkeyId === passkeyId) this.sessions.delete(k);
  }

  /** Ends the user's other sessions; returns how many. */
  destroyOthers(req: Request, userId: string): number {
    const keep = this.find(req);
    let n = 0;
    for (const [k, v] of this.sessions) if (v.userId === userId && v !== keep && this.sessions.delete(k)) n++;
    return n;
  }

  destroy(req: Request, res: Response): void {
    const sid = readCookie(req, SESSION_COOKIE);
    if (sid) this.sessions.delete(sha256Hex(sid));
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' });
  }

  /** Drop every session for a user, e.g. when they are disabled or deleted. */
  destroyForUser(userId: string): void {
    for (const [k, v] of this.sessions) if (v.userId === userId) this.sessions.delete(k);
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, s] of this.sessions) {
      if (now - s.lastSeen > IDLE_MS || now - s.createdAt > ABSOLUTE_MS) this.sessions.delete(k);
    }
  }
}

export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}
