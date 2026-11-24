import type { MapTarget } from './attacks.js';
import { basicAuth, BackendError, HttpClient } from '../http.js';

/**
 * Wazuh access goes through two services:
 *  - the manager REST API (agents, manager info) — JWT from basic auth
 *  - the indexer (OpenSearch) — alerts and vulnerability state indices
 *
 * Since Wazuh 4.8 vulnerability detection results live in the indexer
 * (`wazuh-states-vulnerabilities-*`), not behind the manager API.
 */

export interface WazuhConfig {
  managerUrl: string;
  managerUser: string;
  managerPassword: string;
  indexerUrl?: string;
  indexerUser?: string;
  indexerPassword?: string;
  alertsIndex: string;
  vulnerabilitiesIndex: string;
  tlsVerify: boolean;
  caCert?: string;
  /**
   * Active-response commands an administrator allows `wazuh_run_active_response`
   * to send, exactly as Wazuh names them (e.g. `!firewall-drop`). Empty: the
   * tool does not exist.
   */
  activeResponseCommands: string[];
  /** Where the monitored machines are, for the attack map. */
  mapTargets?: MapTarget[];
}

/** Manager JWTs default to 900 s; refresh well before that. */
const TOKEN_TTL_MS = 10 * 60 * 1000;

export class WazuhClient {
  private readonly manager: HttpClient;
  private readonly indexer?: HttpClient;
  private jwt?: { token: string; expires: number };
  private jwtPending?: Promise<string>;

  constructor(readonly cfg: WazuhConfig) {
    const tls = { tlsVerify: cfg.tlsVerify, caCert: cfg.caCert };
    this.manager = new HttpClient({ baseUrl: cfg.managerUrl, ...tls });
    if (cfg.indexerUrl) this.indexer = new HttpClient({ baseUrl: cfg.indexerUrl, ...tls, timeoutMs: 30_000 });
  }

  get hasIndexer(): boolean {
    return this.indexer !== undefined;
  }

  private async token(force = false): Promise<string> {
    if (!force && this.jwt && this.jwt.expires > Date.now()) return this.jwt.token;
    // Collapse concurrent refreshes into one authentication call.
    this.jwtPending ??= this.manager
      .request<string>('/security/user/authenticate', {
        method: 'POST',
        query: { raw: true },
        headers: { authorization: basicAuth(this.cfg.managerUser, this.cfg.managerPassword) },
        text: true,
      })
      .then((t) => {
        const token = t.trim();
        if (!token) throw new BackendError('Wazuh manager returned an empty token', undefined, true);
        this.jwt = { token, expires: Date.now() + TOKEN_TTL_MS };
        return token;
      })
      .finally(() => {
        this.jwtPending = undefined;
      });
    return this.jwtPending;
  }

  /** Manager API call with one transparent retry if the JWT was invalidated. */
  async api<T = unknown>(p: string, query?: Record<string, string | number | boolean | undefined>): Promise<T> {
    const call = async (force: boolean) =>
      this.manager.request<T>(p, { query, headers: { authorization: `Bearer ${await this.token(force)}` } });
    try {
      return await call(false);
    } catch (err) {
      if (err instanceof BackendError && err.status === 401) return call(true);
      throw err;
    }
  }

  /** Manager API call that changes state (PUT/DELETE), with the same JWT retry. */
  async apiWrite<T = unknown>(
    method: 'PUT' | 'POST' | 'DELETE',
    p: string,
    opts: { query?: Record<string, string | number | boolean | undefined>; json?: unknown } = {},
  ): Promise<T> {
    const call = async (force: boolean) =>
      this.manager.request<T>(p, { method, ...opts, headers: { authorization: `Bearer ${await this.token(force)}` } });
    try {
      return await call(false);
    } catch (err) {
      if (err instanceof BackendError && err.status === 401) return call(true);
      throw err;
    }
  }

  async search<T = unknown>(index: string, body: unknown): Promise<T> {
    if (!this.indexer) throw new BackendError('Wazuh indexer is not configured');
    return this.indexer.request<T>(`/${encodeURIComponent(index)}/_search`, {
      method: 'POST',
      json: body,
      headers: { authorization: basicAuth(this.cfg.indexerUser ?? '', this.cfg.indexerPassword ?? '') },
    });
  }

  async indexerInfo(): Promise<{ version?: { number?: string; distribution?: string }; cluster_name?: string }> {
    if (!this.indexer) throw new BackendError('Wazuh indexer is not configured');
    return this.indexer.request('/', {
      headers: { authorization: basicAuth(this.cfg.indexerUser ?? '', this.cfg.indexerPassword ?? '') },
    });
  }
}

/** Wazuh agent IDs are zero-padded to at least three digits ("001"). */
export function normaliseAgentId(raw: string): string {
  const v = raw.trim();
  if (!/^\d{1,6}$/.test(v)) throw new BackendError(`Invalid agent id "${raw}": expected digits, e.g. 001`);
  return v.padStart(3, '0');
}

/**
 * Accepts a relative window ("15m", "24h", "7d", "2w") or an ISO-8601
 * timestamp and returns something OpenSearch range queries understand.
 */
export function parseTime(raw: string): string {
  const v = raw.trim();
  const rel = /^(\d{1,4})([smhdw])$/.exec(v);
  if (rel) return `now-${rel[1]}${rel[2]}`;
  if (/^now(-\d{1,4}[smhdw])?$/.test(v)) return v;
  const t = Date.parse(v);
  if (!Number.isNaN(t)) return new Date(t).toISOString();
  throw new BackendError(`Invalid time "${raw}": use e.g. 24h, 7d or an ISO-8601 timestamp`);
}

export interface WazuhListResponse<T> {
  data: { affected_items: T[]; total_affected_items: number; failed_items?: unknown[] };
  message?: string;
  error?: number;
}

export interface SearchResponse<S = Record<string, unknown>> {
  hits: { total: { value: number; relation: string } | number; hits: { _id: string; _index: string; _source: S }[] };
  aggregations?: Record<string, { buckets?: { key: string | number; doc_count: number }[] }>;
}

export function totalHits(r: SearchResponse): number {
  const t = r.hits.total;
  return typeof t === 'number' ? t : t.value;
}

export function buckets(r: SearchResponse, name: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const b of r.aggregations?.[name]?.buckets ?? []) out[String(b.key)] = b.doc_count;
  return out;
}
