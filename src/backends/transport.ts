import type { BackendModule } from './types.js';

/** Set from REQUIRE_SECURE_TRANSPORT at startup. */
export const transportPolicy = { requireSecure: false };

/** Why a URL may not carry credentials under REQUIRE_SECURE_TRANSPORT, or null. Loopback is exempt. */
export function insecureUrl(raw: string, verify = true): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) return null;
  if (u.protocol !== 'https:') return 'plain http';
  return verify ? null : 'certificate not verified';
}

/** The first insecure connection of a backend's settings, or null. */
export function insecureBackend(mod: Pick<BackendModule<unknown, unknown>, 'fields'>, values: Record<string, unknown> | undefined): string | null {
  for (const f of mod.fields) {
    const raw = values?.[f.key];
    if (f.type !== 'url' || typeof raw !== 'string') continue;
    const why = insecureUrl(raw, values?.tlsVerify !== false);
    if (why) return `${f.label}: ${why}`;
  }
  return null;
}

/**
 * How SocBridge talks to a backend, from its saved settings:
 *  - `tls`            every connection is https with certificate verification
 *  - `tls-unverified` https, but "Verify TLS certificates" is off
 *  - `plaintext`      at least one connection is plain http
 *  - `local`          no network connection (Trivy reads a directory)
 * Mixed settings report the weakest connection.
 */
export type Transport = 'tls' | 'tls-unverified' | 'plaintext' | 'local';

export interface TransportView {
  transport: Transport;
  /** One line per connection, e.g. "Manager API URL: https, verified". Admins only. */
  connections: string[];
}

const RANK: Record<Transport, number> = { local: 0, tls: 1, 'tls-unverified': 2, plaintext: 3 };

export function transportOf(mod: Pick<BackendModule<unknown, unknown>, 'fields'>, stored: Record<string, unknown> | undefined): TransportView {
  const values = stored ?? {};
  // Backends default to verifying certificates; only an explicit false turns it off.
  const verify = values.tlsVerify !== false;
  let worst: Transport = 'local';
  const connections: string[] = [];
  for (const f of mod.fields) {
    if (f.type !== 'url') continue;
    const raw = values[f.key];
    if (typeof raw !== 'string' || raw.trim() === '') continue;
    let protocol: string;
    try {
      protocol = new URL(raw).protocol;
    } catch {
      continue;
    }
    const t: Transport = protocol === 'https:' ? (verify ? 'tls' : 'tls-unverified') : 'plaintext';
    connections.push(`${f.label}: ${t === 'tls' ? 'https, certificate verified' : t === 'tls-unverified' ? 'https, certificate not verified' : 'plain http, not encrypted'}`);
    if (RANK[t] > RANK[worst]) worst = t;
  }
  return { transport: worst, connections };
}

/** Status-bar words for a working backend, by transport. */
export const ONLINE_LABEL: Record<Transport, string> = {
  tls: 'Online · encrypted',
  'tls-unverified': 'Online · not verified',
  plaintext: 'Online · unencrypted',
  local: 'Online · local',
};
