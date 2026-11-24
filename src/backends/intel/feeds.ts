import { gunzipSync } from 'node:zlib';
import { errMessage, log } from '../../log.js';
import { normaliseCve } from '../cve.js';
import { BackendError, HttpClient } from '../http.js';

/**
 * Threat-intelligence feeds, downloaded whole and kept in memory:
 *
 *  - CISA KEV (Known Exploited Vulnerabilities), JSON, ~1 800 entries.
 *  - FIRST EPSS (Exploit Prediction Scoring System), a gzipped CSV of every
 *    published CVE (~400 000 rows) with the probability of exploitation in
 *    the next 30 days and its percentile.
 *
 * Both are fetched as bulk files rather than per-CVE API calls, so the list
 * of CVEs on your hosts never leaves the network. EPSS is stored as three
 * typed arrays (about 6 MB) and looked up by binary search.
 */

export const DEFAULT_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const DEFAULT_EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

/** A feed larger than this is refused (the EPSS file is ~3 MB gzipped, ~15 MB unpacked). */
export const MAX_FEED_BYTES = 64 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 120_000;
/** After a failed download, wait this long before trying again. */
export const RETRY_AFTER_MS = 5 * 60_000;
const MAX_TEXT = 600;

export interface KevEntry {
  cve: string;
  vendor?: string;
  product?: string;
  name?: string;
  date_added?: string;
  due_date?: string;
  /** CISA: "Known" when the CVE is known to be used in ransomware campaigns. */
  ransomware: boolean;
  required_action?: string;
  description?: string;
}

export interface KevCatalog {
  version?: string;
  released?: string;
  entries: Map<string, KevEntry>;
}

const str = (v: unknown, max = MAX_TEXT): string | undefined => {
  if (typeof v !== 'string' || v.trim() === '') return undefined;
  const t = v.trim();
  return t.length > max ? t.slice(0, max) + '…' : t;
};

export function parseKev(doc: unknown): KevCatalog {
  const d = doc as { catalogVersion?: unknown; dateReleased?: unknown; vulnerabilities?: unknown } | null;
  if (!d || typeof d !== 'object' || !Array.isArray(d.vulnerabilities)) {
    throw new BackendError('KEV feed: not a CISA KEV catalog (no "vulnerabilities" array)', undefined, true);
  }
  const entries = new Map<string, KevEntry>();
  for (const raw of d.vulnerabilities as Record<string, unknown>[]) {
    const cve = normaliseCve(raw?.cveID);
    if (!cve) continue;
    entries.set(cve, {
      cve,
      vendor: str(raw.vendorProject, 120),
      product: str(raw.product, 120),
      name: str(raw.vulnerabilityName, 200),
      date_added: str(raw.dateAdded, 10),
      due_date: str(raw.dueDate, 10),
      ransomware: typeof raw.knownRansomwareCampaignUse === 'string' && raw.knownRansomwareCampaignUse.toLowerCase() === 'known',
      required_action: str(raw.requiredAction),
      description: str(raw.shortDescription),
    });
  }
  if (entries.size === 0) throw new BackendError('KEV feed: the catalog has no CVE entries', undefined, true);
  return { version: str(d.catalogVersion, 40), released: str(d.dateReleased, 40), entries };
}

/** CVE-YYYY-N as one exactly representable number: YYYY·10⁹ + N. */
export function cveKey(cve: string): number | undefined {
  const m = /^CVE-(\d{4})-(\d{4,9})$/.exec(cve);
  return m ? Number(m[1]) * 1e9 + Number(m[2]) : undefined;
}

export class EpssTable {
  constructor(
    private readonly keys: Float64Array,
    private readonly scores: Float32Array,
    private readonly percentiles: Float32Array,
    readonly modelVersion?: string,
    readonly scoreDate?: string,
  ) {}

  get size(): number {
    return this.keys.length;
  }

  get(cve: string): { epss: number; percentile: number } | undefined {
    const k = cveKey(cve);
    if (k === undefined) return undefined;
    let lo = 0;
    let hi = this.keys.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const v = this.keys[mid]!;
      if (v === k) return { epss: round(this.scores[mid]!), percentile: round(this.percentiles[mid]!) };
      if (v < k) lo = mid + 1;
      else hi = mid - 1;
    }
    return undefined;
  }
}

/** Float32 noise off: EPSS publishes five decimals. */
const round = (n: number) => Math.round(n * 1e5) / 1e5;

/**
 * Parses the EPSS CSV: an optional `#model_version:…,score_date:…` line, a
 * `cve,epss,percentile` header, then one row per CVE.
 */
export function parseEpss(text: string): EpssTable {
  let modelVersion: string | undefined;
  let scoreDate: string | undefined;
  const rows: [number, number, number][] = [];
  let header = false;
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf('\n', start);
    if (end === -1) end = text.length;
    const line = text.slice(start, end).trim();
    start = end + 1;
    if (!line) continue;
    if (line.startsWith('#')) {
      for (const part of line.slice(1).split(',')) {
        const i = part.indexOf(':');
        if (i === -1) continue;
        const k = part.slice(0, i).trim();
        const v = part.slice(i + 1).trim();
        if (k === 'model_version') modelVersion = v;
        if (k === 'score_date') scoreDate = v;
      }
      continue;
    }
    if (!header) {
      if (!/^cve\s*,\s*epss\s*,\s*percentile/i.test(line)) throw new BackendError('EPSS feed: expected a "cve,epss,percentile" header', undefined, true);
      header = true;
      continue;
    }
    const [c, e, p] = line.split(',');
    const k = cveKey((c ?? '').trim().toUpperCase());
    const epss = Number(e);
    const pct = Number(p);
    if (k === undefined || !Number.isFinite(epss) || !Number.isFinite(pct)) continue;
    rows.push([k, epss, pct]);
  }
  if (!rows.length) throw new BackendError('EPSS feed: no scores found', undefined, true);
  rows.sort((a, b) => a[0] - b[0]);
  const keys = new Float64Array(rows.length);
  const scores = new Float32Array(rows.length);
  const percentiles = new Float32Array(rows.length);
  rows.forEach(([k, e, p], i) => {
    keys[i] = k;
    scores[i] = e;
    percentiles[i] = p;
  });
  return new EpssTable(keys, scores, percentiles, modelVersion, scoreDate);
}

export interface FeedState<T> {
  data?: T;
  fetchedAt?: number;
  error?: string;
  errorAt?: number;
}

export interface IntelConfig {
  kevUrl: string;
  epssUrl: string;
  /** Re-download each feed when it is older than this. */
  refreshHours: number;
  /** DefectDojo product names whose findings are seen from the internet, comma or newline separated. */
  exposedProducts?: string;
  caCert?: string;
  tlsVerify: boolean;
}

/** Downloads one URL, following redirects, with a size cap. */
export type Fetcher = (url: string) => Promise<Buffer>;

export function httpFetcher(cfg: Pick<IntelConfig, 'caCert' | 'tlsVerify'>, baseUrl: string): Fetcher {
  const http = new HttpClient({ baseUrl, caCert: cfg.caCert, tlsVerify: cfg.tlsVerify, timeoutMs: FETCH_TIMEOUT_MS });
  return async (url) => {
    const host = new URL(url).host;
    let res: Response;
    try {
      res = await http.rawFetch(url, { headers: { accept: '*/*', 'user-agent': 'socbridge' }, redirect: 'follow' });
    } catch (err) {
      const cause = (err as { cause?: { code?: string; message?: string } }).cause;
      throw new BackendError(`Download from ${host} failed: ${cause?.code ?? cause?.message ?? errMessage(err)}`, undefined, true);
    }
    if (!res.ok) throw new BackendError(`${host} responded ${res.status}`, res.status, true);
    const declared = Number(res.headers.get('content-length') ?? '0');
    if (declared > MAX_FEED_BYTES) throw new BackendError(`${host}: feed is larger than ${MAX_FEED_BYTES} bytes`, undefined, true);
    const chunks: Uint8Array[] = [];
    let size = 0;
    for await (const c of (res.body ?? []) as AsyncIterable<Uint8Array>) {
      size += c.length;
      if (size > MAX_FEED_BYTES) break;
      chunks.push(c);
    }
    const buf = Buffer.concat(chunks);
    if (size > MAX_FEED_BYTES) throw new BackendError(`${host}: feed is larger than ${MAX_FEED_BYTES} bytes`, undefined, true);
    return buf;
  };
}

/** Unpacks gzip by its magic bytes, whatever the URL or content type says. */
export function maybeGunzip(buf: Buffer): Buffer {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    const out = gunzipSync(buf, { maxOutputLength: MAX_FEED_BYTES });
    return out;
  }
  return buf;
}

/**
 * The intel runtime: both feeds with their download state, refreshed lazily
 * (on first use and when older than `refreshHours`), one download at a time
 * per feed. A failed refresh keeps the previous data and is retried after
 * RETRY_AFTER_MS.
 */
export class IntelFeeds {
  readonly kev: FeedState<KevCatalog> = {};
  readonly epss: FeedState<EpssTable> = {};
  private pending = new Map<'kev' | 'epss', Promise<void>>();
  readonly exposedProducts: string[];
  /** Cross-backend inventories, cached per source runtime (see index.ts). */
  readonly inventoryCache = new WeakMap<object, Map<string, { at: number; value: Promise<unknown> }>>();

  constructor(
    readonly cfg: IntelConfig,
    private readonly fetch: Fetcher = httpFetcher(cfg, cfg.kevUrl),
    private readonly now: () => number = Date.now,
  ) {
    this.exposedProducts = (cfg.exposedProducts ?? '')
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  private get maxAgeMs(): number {
    return this.cfg.refreshHours * 3600_000;
  }

  /** Whether a feed has data younger than twice the refresh interval. */
  fresh(which: 'kev' | 'epss'): boolean {
    const s = this[which];
    return !!s.data && s.fetchedAt !== undefined && this.now() - s.fetchedAt < 2 * this.maxAgeMs;
  }

  private due(which: 'kev' | 'epss'): boolean {
    const s = this[which];
    if (s.errorAt !== undefined && this.now() - s.errorAt < RETRY_AFTER_MS) return false;
    return !s.data || s.fetchedAt === undefined || this.now() - s.fetchedAt >= this.maxAgeMs;
  }

  private load(which: 'kev' | 'epss'): Promise<void> {
    let p = this.pending.get(which);
    if (p) return p;
    const url = which === 'kev' ? this.cfg.kevUrl : this.cfg.epssUrl;
    const state = this[which] as FeedState<unknown>;
    p = this.fetch(url)
      .then((buf) => {
        const body = maybeGunzip(buf).toString('utf8');
        state.data = which === 'kev' ? parseKev(JSON.parse(body)) : parseEpss(body);
        state.fetchedAt = this.now();
        state.error = undefined;
        state.errorAt = undefined;
      })
      .catch((err) => {
        state.error = err instanceof SyntaxError ? `${which.toUpperCase()} feed: not valid JSON` : errMessage(err);
        state.errorAt = this.now();
        log.warn('Intel feed download failed', { feed: which, error: state.error });
      })
      .finally(() => this.pending.delete(which));
    this.pending.set(which, p);
    return p;
  }

  /** Downloads whatever is missing or due, and waits for it. Never throws. */
  async ensure(): Promise<void> {
    await Promise.all((['kev', 'epss'] as const).filter((w) => this.due(w) || this.pending.has(w)).map((w) => this.load(w)));
  }

  /** Starts due downloads without waiting (health checks). */
  refreshInBackground(): void {
    for (const w of ['kev', 'epss'] as const) if (this.due(w)) void this.load(w);
  }

  loading(which: 'kev' | 'epss'): boolean {
    return this.pending.has(which);
  }

  /** What the tools report about the feeds they used. */
  view() {
    const at = (t?: number) => (t === undefined ? undefined : new Date(t).toISOString());
    const k = this.kev;
    const e = this.epss;
    return {
      kev: k.data
        ? { catalog_version: k.data.version, entries: k.data.entries.size, fetched_at: at(k.fetchedAt), ...(this.fresh('kev') ? {} : { stale: true }), ...(k.error ? { last_error: k.error } : {}) }
        : { unavailable: k.error ?? 'not downloaded yet' },
      epss: e.data
        ? { model_version: e.data.modelVersion, score_date: e.data.scoreDate, cves: e.data.size, fetched_at: at(e.fetchedAt), ...(this.fresh('epss') ? {} : { stale: true }), ...(e.error ? { last_error: e.error } : {}) }
        : { unavailable: e.error ?? 'not downloaded yet' },
    };
  }
}
