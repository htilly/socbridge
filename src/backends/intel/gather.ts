import { BackendError } from '../http.js';
import { publicError } from '../result.js';
import type { CveInventory, CveOccurrence, CveSource, SeenEndpoint } from '../cve.js';
import { cveOccurrences as defectdojoCves, type DefectDojoRuntime } from '../defectdojo/queries.js';
import { cveOccurrences as trivyCves, type TrivyReports } from '../trivy/reports.js';
import type { SourceHandle, ToolContext } from '../types.js';
import type { WazuhClient } from '../wazuh/client.js';
import { cveOccurrences as wazuhCves } from '../wazuh/queries.js';
import type { IntelFeeds } from './feeds.js';

/** Collects the CVE inventories of the other backends, cached per runtime. */

export const SOURCES = ['wazuh', 'trivy', 'defectdojo'] as const satisfies readonly CveSource[];

/** Collected inventories are reused for this long (per source runtime), unless the call asks for a refresh. */
export const INVENTORY_TTL_MS = 10 * 60_000;

export interface SourceReport {
  source: CveSource;
  status: 'ok' | 'unavailable' | 'error';
  message?: string;
  occurrences?: number;
  cves?: number;
  cached?: boolean;
}

export interface Gathered {
  occurrences: CveOccurrence[];
  sources: SourceReport[];
  notes: string[];
  /** What could not be read. */
  gaps: string[];
  endpoints: SeenEndpoint[];
}

/** One result per source runtime (so changed settings start fresh) and key, reused for `ttl`. */
export async function cached<T>(rt: IntelFeeds, runtime: object, key: string, refresh: boolean, load: () => Promise<T>, ttl = INVENTORY_TTL_MS) {
  let m = rt.inventoryCache.get(runtime);
  if (!m) {
    m = new Map();
    rt.inventoryCache.set(runtime, m);
  }
  const hit = m.get(key);
  if (hit && !refresh && Date.now() - hit.at < ttl) return { inv: (await hit.value) as T, cached: true };
  for (const [k, v] of m) if (Date.now() - v.at >= INVENTORY_TTL_MS) m.delete(k);
  const value = load();
  m.set(key, { at: Date.now(), value });
  try {
    return { inv: await value, cached: false };
  } catch (err) {
    m.delete(key);
    throw err;
  }
}

/** Collects CVE occurrences from every wanted source this credential may read. A failing source is reported, not fatal. */
export async function gather(rt: IntelFeeds, ctx: ToolContext, wanted: readonly CveSource[], refresh = false): Promise<Gathered> {
  const handles = new Map<CveSource, SourceHandle<unknown>>();
  const sources: SourceReport[] = [];
  for (const id of wanted) {
    const h = ctx.source(id);
    if ('unavailable' in h) sources.push({ source: id, status: 'unavailable', message: h.unavailable });
    else handles.set(id, h);
  }
  const trivyToo = handles.has('trivy');

  const loaders: Record<CveSource, (h: SourceHandle<unknown>) => Promise<{ inv: CveInventory; cached: boolean }>> = {
    wazuh: (h) => {
      const c = h.runtime as WazuhClient;
      if (!c.hasIndexer) throw new BackendError('the Wazuh indexer is not configured; vulnerabilities live there');
      return cached(rt, c, 'cves', refresh, () => h.run(() => wazuhCves(c)));
    },
    trivy: (h) => cached(rt, h.runtime as object, 'cves', refresh, () => h.run(() => trivyCves(h.runtime as TrivyReports))),
    defectdojo: (h) => {
      const o = { skipScanTypes: trivyToo ? ['Trivy Scan'] : [], exposedProducts: rt.exposedProducts };
      return cached(rt, h.runtime as object, JSON.stringify(o), refresh, () => h.run(() => defectdojoCves(h.runtime as DefectDojoRuntime, o)));
    },
  };

  const occurrences: CveOccurrence[] = [];
  const notes: string[] = [];
  const gaps: string[] = [];
  const endpoints: SeenEndpoint[] = [];
  const results = await Promise.all(
    [...handles].map(async ([id, h]) => {
      try {
        return { id, ...(await loaders[id](h)) };
      } catch (err) {
        return { id, error: publicError(err) };
      }
    }),
  );
  for (const r of results) {
    if ('error' in r) {
      sources.push({ source: r.id, status: 'error', message: r.error });
      continue;
    }
    occurrences.push(...r.inv.occurrences);
    const missing = [...(r.inv.gaps ?? []), ...(r.inv.truncated ? [r.inv.truncated] : [])];
    gaps.push(...missing);
    notes.push(...(r.inv.notes ?? []), ...missing);
    endpoints.push(...(r.inv.endpoints ?? []));
    sources.push({
      source: r.id,
      status: 'ok',
      occurrences: r.inv.occurrences.length,
      cves: new Set(r.inv.occurrences.map((o) => o.cve)).size,
      ...(r.cached ? { cached: true } : {}),
    });
  }
  sources.sort((a, b) => SOURCES.indexOf(a.source as (typeof SOURCES)[number]) - SOURCES.indexOf(b.source as (typeof SOURCES)[number]));
  return { occurrences, sources, notes, gaps, endpoints };
}
