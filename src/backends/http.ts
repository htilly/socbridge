import { lookup, type LookupAddress } from 'node:dns';
import { isIP, type LookupFunction } from 'node:net';
import { Agent, fetch, type Dispatcher } from 'undici';

/**
 * Small HTTP client shared by backends: per-backend TLS trust (custom CA or,
 * explicitly, no verification), timeouts, and errors that never echo
 * credentials back to the caller.
 */

export interface HttpClientOptions {
  baseUrl: string;
  /** PEM bundle to trust. When set it replaces the system CA store for this backend. */
  caCert?: string;
  /** Set false only for lab setups with self-signed certificates. */
  tlsVerify?: boolean;
  timeoutMs?: number;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  query?: Record<string, string | number | boolean | undefined>;
  headers?: Record<string, string>;
  json?: unknown;
  /** Expect a text body instead of JSON. */
  text?: boolean;
}

export class BackendError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    /** True when the backend could not be reached or did not answer usefully, whatever was asked. */
    readonly outage = status !== undefined && (status === 401 || status === 429 || status >= 500),
    /** The same without host names or the backend's own text, for callers who are not administrators. */
    readonly publicMessage = message,
  ) {
    super(message);
  }
}

/**
 * Whether an error says the backend itself is failing, so that it may count
 * towards the circuit breaker. Bad arguments, unknown IDs and other 4xx
 * answers do not: otherwise one caller could take a backend away from
 * everybody by sending invalid input.
 */
export function isOutage(err: unknown): boolean {
  if (err instanceof BackendError) return err.outage;
  if (!(err instanceof Error)) return false;
  return err.name === 'TimeoutError' || err.name === 'AbortError' || (err instanceof TypeError && err.cause !== undefined);
}

const MAX_ERROR_BODY = 500;
/** A backend answering with more than this is broken or hostile. */
export const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAX_REDIRECTS = 3;

/** Link-local addresses, where cloud metadata services live. Never a backend. */
export function forbiddenAddress(ip: string): boolean {
  const a = ip.toLowerCase().replace(/^\[|\]$/g, '').replace(/^::ffff:(?=\d+\.)/, '');
  return /^169\.254\./.test(a) || /^fe[89ab][0-9a-f]:/.test(a) || /^::ffff:a9fe:/.test(a) || a === 'fd00:ec2::254' || a === '100.100.100.200';
}

/** A client agent that never connects to a forbidden address, whether a name resolves to it or the URL gives it. */
export function guardedAgent(): Dispatcher {
  return new Agent({ connect: { lookup: guardedLookup } });
}

/** Why a URL may not be called (it gives a forbidden address), or null. Names are checked when connecting. */
export function forbiddenUrl(raw: string | URL): string | null {
  const host = new URL(raw).hostname.replace(/^\[|\]$/g, '');
  return isIP(host) && forbiddenAddress(host) ? `${host} is a link-local address` : null;
}

/** DNS lookup that refuses names pointing at forbidden addresses. */
const guardedLookup: LookupFunction = (hostname, options, cb) => {
  lookup(hostname, { ...options, all: true }, (err, found) => {
    if (err) return cb(err, [], 0);
    const list = found as unknown as LookupAddress[];
    if (list.some((x) => forbiddenAddress(x.address))) {
      return cb(Object.assign(new Error(`${hostname} resolves to a link-local address`), { code: 'EFORBIDDEN' }), [], 0);
    }
    if (options.all) cb(null, list);
    else cb(null, list[0]!.address, list[0]!.family);
  });
};

export class HttpClient {
  private readonly base: URL;
  private readonly dispatcher: Dispatcher;
  private readonly timeoutMs: number;

  constructor(opts: HttpClientOptions) {
    this.base = new URL(opts.baseUrl.endsWith('/') ? opts.baseUrl : opts.baseUrl + '/');
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    const host = this.base.hostname.replace(/^\[|\]$/g, '');
    if (isIP(host) && forbiddenAddress(host)) throw new BackendError(`${host} is a link-local address and cannot be a backend`);
    this.dispatcher = new Agent({
      connect: {
        lookup: guardedLookup,
        rejectUnauthorized: opts.tlsVerify !== false,
        ...(opts.caCert ? { ca: opts.caCert } : {}),
      },
      keepAliveTimeout: 30_000,
    });
  }

  /**
   * `fetch` bound to this backend's TLS trust and timeout, for clients that do
   * their own HTTP (the MCP client used for Graylog's MCP passthrough).
   */
  readonly rawFetch = (url: string | URL, init?: RequestInit): Promise<Response> => {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    return fetch(url, { ...(init as object), signal, dispatcher: this.dispatcher } as Parameters<typeof fetch>[1]) as unknown as Promise<Response>;
  };

  url(p: string, query?: RequestOptions['query']): URL {
    const u = new URL(p.replace(/^\//, ''), this.base);
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined && v !== '') u.searchParams.set(k, String(v));
    }
    return u;
  }

  async request<T = unknown>(p: string, opts: RequestOptions = {}): Promise<T> {
    const u = this.url(p, opts.query);
    const headers: Record<string, string> = { accept: 'application/json', ...opts.headers };
    let body: string | undefined;
    if (opts.json !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(opts.json);
    }
    const unreachable = (err: unknown) => {
      const cause = (err as { cause?: { code?: string; message?: string } }).cause;
      const detail = cause?.code ?? cause?.message ?? (err as Error).message;
      return new BackendError(`Request to ${u.host} failed: ${detail}`, undefined, true, 'The backend could not be reached');
    };
    let res;
    try {
      const method = opts.method ?? (body ? 'POST' : 'GET');
      const signal = AbortSignal.timeout(this.timeoutMs);
      let target = u;
      for (let hops = 0; ; hops++) {
        res = await fetch(target, { method, headers, body, dispatcher: this.dispatcher, signal, redirect: 'manual' });
        const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
        if (!location) break;
        await res.body?.cancel();
        // Credentials are for this origin only, and a write is never repeated elsewhere.
        const next = new URL(location, target);
        if (next.origin !== this.base.origin || method !== 'GET' || hops >= MAX_REDIRECTS) {
          throw new BackendError(`${u.host} redirects to ${next.origin}; enter the final URL in the backend settings`, res.status, false, 'The backend redirects elsewhere; an administrator needs to correct its URL');
        }
        target = next;
      }
    } catch (err) {
      if (err instanceof BackendError) throw err;
      throw unreachable(err);
    }
    let raw: string;
    try {
      raw = await readCapped(res, u.host);
    } catch (err) {
      if (err instanceof BackendError) throw err;
      throw unreachable(err);
    }
    if (!res.ok) {
      throw new BackendError(`${u.host} responded ${res.status}: ${summarise(raw)}`, res.status, undefined, `The backend responded ${res.status}`);
    }
    if (opts.text) return raw as T;
    if (raw === '') return undefined as T;
    try {
      return JSON.parse(raw) as T;
    } catch {
      throw new BackendError(`${u.host} returned non-JSON response`, undefined, true, 'The backend returned an unexpected response');
    }
  }
}

export async function readCapped(res: { body: AsyncIterable<Uint8Array> | null; headers: { get(n: string): string | null } }, host: string): Promise<string> {
  const tooLarge = () => new BackendError(`${host} returned more than ${MAX_RESPONSE_BYTES / 1024 / 1024} MB; narrow the query`, undefined, undefined, `The backend returned more than ${MAX_RESPONSE_BYTES / 1024 / 1024} MB; narrow the query`);
  if (Number(res.headers.get('content-length') ?? '0') > MAX_RESPONSE_BYTES) throw tooLarge();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const c of res.body ?? []) {
    size += c.length;
    if (size > MAX_RESPONSE_BYTES) throw tooLarge();
    chunks.push(c);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

function summarise(body: string): string {
  try {
    const j = JSON.parse(body) as Record<string, unknown>;
    // Cloudflare style: { errors: [{ code, message, error_chain: [...] }] }
    if (Array.isArray(j.errors) && j.errors.length) {
      const parts = (j.errors as { message?: string; error_chain?: { message?: string }[] }[]).flatMap((e) => [
        e.message,
        ...(e.error_chain ?? []).map((c) => c.message),
      ]);
      const text = parts.filter(Boolean).join(': ');
      if (text) return text.slice(0, MAX_ERROR_BODY);
    }
    const msg = j.detail ?? j.message ?? j.title ?? (j.error as Record<string, unknown> | undefined)?.reason ?? j.error;
    if (msg) return String(typeof msg === 'object' ? JSON.stringify(msg) : msg).slice(0, MAX_ERROR_BODY);
  } catch {
    /* not JSON */
  }
  return body.replace(/\s+/g, ' ').slice(0, MAX_ERROR_BODY) || '(empty body)';
}

export function basicAuth(user: string, password: string): string {
  return 'Basic ' + Buffer.from(`${user}:${password}`, 'utf8').toString('base64');
}
