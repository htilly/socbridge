import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';
import * as acme from 'acme-client';
import { BackendError, HttpClient } from '../backends/http.js';
import { errMessage, log as logger } from '../log.js';

/**
 * ACME (Let's Encrypt) issuance with the dns-01 challenge via Cloudflare.
 *
 * dns-01 needs nothing reachable from the internet, so it works for a
 * service that is only exposed on an internal network: the name only has to
 * exist as a TXT record in the public zone during validation, while local DNS
 * points the name at the internal address.
 */

export interface AcmeOptions {
  domains: string[];
  email?: string;
  staging: boolean;
  cloudflareToken: string;
  /** Public resolvers used to confirm the TXT record before asking the CA. */
  resolvers: string[];
}

export type AcmeLog = (msg: string) => void;

export interface AcmeState {
  /** Which CA directory the account (and certificate) belongs to. */
  staging?: boolean;
  accountKeyPem: string;
  accountUrl?: string;
  keyPem?: string;
  certPem?: string;
  domains?: string[];
}

const CF_API = 'https://api.cloudflare.com/client/v4/';

/** Suffixes that never exist in public DNS, so no public CA can validate them. */
const PRIVATE_SUFFIXES = ['local', 'localhost', 'lan', 'home', 'internal', 'intranet', 'corp', 'private', 'home.arpa', 'test', 'invalid', 'example'];

/** True for a name Let's Encrypt can validate: has a dot, is not an IP, not a private-use suffix. */
export function isPublicDnsName(name: string): boolean {
  const n = name.toLowerCase().replace(/\.$/, '');
  if (isIP(n) !== 0 || !n.includes('.')) return false;
  return !PRIVATE_SUFFIXES.some((s) => n === s || n.endsWith(`.${s}`));
}

/**
 * Splits the server's names into those a Let's Encrypt certificate can cover
 * and the rest (bare host names like "socbridge", IPs, .local/.lan names), which
 * only the built-in CA can put in a certificate.
 */
export function acmeNames(host: string, extra: string[]): { names: string[]; skipped: string[] } {
  const all = [host, ...extra.filter((s) => s !== host)];
  return { names: all.filter(isPublicDnsName), skipped: all.filter((s) => !isPublicDnsName(s)) };
}
const PROPAGATION_TIMEOUT_MS = 180_000;
const PROPAGATION_POLL_MS = 5_000;

interface CfResponse<T> {
  success: boolean;
  result: T;
  errors?: { message: string }[];
}

/**
 * What the Cloudflare API token needs. Shown in the UI and in error messages,
 * so keep the wording in step with Cloudflare's token editor.
 */
export const CF_TOKEN_HELP =
  'Create it under My Profile → API Tokens or Manage Account → Account API Tokens (both work) with the permissions ' +
  'Zone → Zone → Read and Zone → DNS → Edit, and Zone Resources set to the zone that holds the name.';

type CfMethod = 'GET' | 'POST' | 'DELETE';

/** One zone the token can see and read DNS records in. */
export interface CfZoneCheck {
  domain: string;
  zone: string;
}

export class Cloudflare {
  private http = new HttpClient({ baseUrl: CF_API, timeoutMs: 20_000 });
  private zoneCache = new Map<string, { id: string; name: string }>();

  constructor(private readonly token: string) {}

  /**
   * `need` names the permission the call depends on, so a 403 can say which
   * one is missing instead of Cloudflare's generic message.
   */
  private async call<T>(
    path: string,
    need: string,
    init: { method?: CfMethod; json?: unknown; query?: Record<string, string> } = {},
  ): Promise<T> {
    let r: CfResponse<T>;
    try {
      r = await this.http.request<CfResponse<T>>(path, { ...init, headers: { authorization: `Bearer ${this.token}` } });
    } catch (err) {
      if (err instanceof BackendError && err.status === 401) {
        throw new Error(
          'Cloudflare does not recognise this API token (401). Paste the token value Cloudflare showed once when it was created; ' +
            'the Global API Key, the Origin CA key and the token ID do not work here.',
        );
      }
      if (err instanceof BackendError && err.status === 403) {
        throw new Error(`Cloudflare refused the request (403): the token is missing ${need} for this zone. ${CF_TOKEN_HELP}`);
      }
      throw err;
    }
    if (!r.success) throw new Error(`Cloudflare API: ${(r.errors ?? []).map((e) => e.message).join('; ') || 'request failed'}`);
    return r.result;
  }

  /** Finds the zone for a name by trying it and each parent domain in turn. */
  async zoneFor(name: string): Promise<{ id: string; name: string }> {
    const labels = name.replace(/\.$/, '').split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join('.');
      const cached = this.zoneCache.get(candidate);
      if (cached) return cached;
      const zones = await this.call<{ id: string; name: string }[]>('zones', 'Zone → Zone → Read', { query: { name: candidate } });
      if (zones[0]) {
        const z = { id: zones[0].id, name: zones[0].name };
        this.zoneCache.set(candidate, z);
        return z;
      }
    }
    throw new Error(
      `The token cannot see a Cloudflare zone for ${name.replace(/^_acme-challenge\./, '')}. ` +
        `Either the domain is not on this Cloudflare account, or the token lacks Zone → Zone → Read for it. ${CF_TOKEN_HELP}`,
    );
  }

  /**
   * Checks that the token works for every domain: the zone is visible and its
   * DNS records readable. Deliberately not `user/tokens/verify`: that endpoint
   * only knows user-owned tokens and answers 401 for a valid account token.
   * DNS → Edit itself can only be proven by creating a record (the staging test).
   */
  async check(domains: string[]): Promise<CfZoneCheck[]> {
    const out: CfZoneCheck[] = [];
    for (const d of domains) {
      const zone = await this.zoneFor(`_acme-challenge.${d}`);
      await this.call(`zones/${zone.id}/dns_records`, 'Zone → DNS → Edit', { query: { per_page: '1' } });
      out.push({ domain: d, zone: zone.name });
    }
    return out;
  }

  async createTxt(name: string, content: string): Promise<{ zoneId: string; id: string }> {
    const zoneId = (await this.zoneFor(name)).id;
    const rec = await this.call<{ id: string }>(`zones/${zoneId}/dns_records`, 'Zone → DNS → Edit', {
      method: 'POST',
      json: { type: 'TXT', name, content, ttl: 60, comment: 'SocBridge ACME challenge (temporary)' },
    });
    return { zoneId, id: rec.id };
  }

  async deleteRecord(zoneId: string, id: string): Promise<void> {
    await this.call(`zones/${zoneId}/dns_records/${id}`, 'Zone → DNS → Edit', { method: 'DELETE' });
  }
}

/** Quick token check without talking to Let's Encrypt. */
export async function checkCloudflareToken(token: string, domains: string[]): Promise<CfZoneCheck[]> {
  return new Cloudflare(token).check(domains);
}

async function waitForTxt(resolvers: string[], name: string, value: string, log: AcmeLog): Promise<void> {
  const resolver = new Resolver({ timeout: 5_000, tries: 2 });
  resolver.setServers(resolvers);
  const deadline = Date.now() + PROPAGATION_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const records = await resolver.resolveTxt(name);
      if (records.some((parts) => parts.join('') === value)) {
        log(`TXT record visible on ${resolvers.join(', ')}`);
        return;
      }
    } catch {
      /* NXDOMAIN / no data yet */
    }
    await new Promise((r) => setTimeout(r, PROPAGATION_POLL_MS));
  }
  throw new Error(`TXT record ${name} not visible on ${resolvers.join(', ')} after ${PROPAGATION_TIMEOUT_MS / 1000}s`);
}

/**
 * Obtain a certificate for `opts.domains`. Returns the new state; `state` is
 * reused only if it belongs to the same CA directory (staging vs production).
 */
export async function issueCertificate(opts: AcmeOptions, state: AcmeState | undefined, log: AcmeLog = () => undefined): Promise<AcmeState> {
  const reuse = state?.accountKeyPem && !!state.staging === opts.staging;
  const next: AcmeState = reuse
    ? { ...state! }
    : { staging: opts.staging, accountKeyPem: (await acme.crypto.createPrivateEcdsaKey('P-256')).toString() };

  const client = new acme.Client({
    directoryUrl: opts.staging ? acme.directory.letsencrypt.staging : acme.directory.letsencrypt.production,
    accountKey: next.accountKeyPem,
    ...(next.accountUrl ? { accountUrl: next.accountUrl } : {}),
  });

  const [keyBuf, csr] = await acme.crypto.createCsr(
    { commonName: opts.domains[0], altNames: opts.domains },
    await acme.crypto.createPrivateEcdsaKey('P-256'),
  );

  const cf = new Cloudflare(opts.cloudflareToken);
  log('Checking the Cloudflare API token');
  for (const z of await cf.check(opts.domains)) log(`Token OK for ${z.domain}: zone ${z.zone} visible, DNS records readable`);
  const created = new Map<string, { zoneId: string; id: string }>();

  const ca = opts.staging ? "Let's Encrypt staging" : "Let's Encrypt";
  log(`Requesting a certificate for ${opts.domains.join(', ')} from ${ca}`);
  const certPem = await client.auto({
    csr,
    email: opts.email,
    termsOfServiceAgreed: true,
    challengePriority: ['dns-01'],
    // We confirm propagation against public resolvers ourselves; the library's
    // own check would use the container's resolver, which may be internal DNS.
    skipChallengeVerification: true,
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== 'dns-01') throw new Error(`Unsupported challenge ${challenge.type}`);
      const name = `_acme-challenge.${authz.identifier.value}`;
      created.set(`${name}|${keyAuthorization}`, await cf.createTxt(name, keyAuthorization));
      log(`Created TXT ${name}; waiting for public DNS`);
      await waitForTxt(opts.resolvers, name, keyAuthorization, log);
    },
    challengeRemoveFn: async (authz, _challenge, keyAuthorization) => {
      const name = `_acme-challenge.${authz.identifier.value}`;
      const rec = created.get(`${name}|${keyAuthorization}`);
      if (!rec) return;
      await cf
        .deleteRecord(rec.zoneId, rec.id)
        .then(() => log(`Removed TXT ${name}`))
        .catch((err) => logger.warn('Could not remove ACME TXT record', { name, error: errMessage(err) }));
    },
  });

  log('Certificate issued');
  next.accountUrl = client.getAccountUrl();
  next.keyPem = keyBuf.toString();
  next.certPem = certPem;
  next.domains = [...opts.domains];
  return next;
}
