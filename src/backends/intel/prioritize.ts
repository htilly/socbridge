import { CVE_SEVERITIES, type CveOccurrence, type CveSeverity, type CveSource } from '../cve.js';
import type { EpssTable, KevCatalog, KevEntry } from './feeds.js';

/**
 * Turns CVE occurrences from several backends into one ranked list.
 *
 * Priority tiers, first match wins:
 *   P1  in CISA KEV: exploited in the wild, fix now.
 *   P2  EPSS ≥ EPSS_HIGH, or Critical/High on an asset seen from the internet.
 *   P3  Critical/High severity, or EPSS ≥ EPSS_MEDIUM.
 *   P4  everything else.
 * Within a tier: known ransomware use, exposed, higher EPSS, higher CVSS,
 * more affected assets.
 *
 * The rules are deliberately few and stated in every result (`reasons`), so a
 * reader can see why a CVE ranks where it does and disagree with it.
 */

export const PRIORITIES = ['P1', 'P2', 'P3', 'P4'] as const;
export type Priority = (typeof PRIORITIES)[number];

/** EPSS above this: likely to be exploited soon (top ~2 % of CVEs). */
export const EPSS_HIGH = 0.1;
/** EPSS above this: noticeably more likely than most. */
export const EPSS_MEDIUM = 0.01;
/** Affected assets listed per CVE; the count covers all of them. */
export const MAX_ASSETS_PER_CVE = 20;

const SEV_RANK: Record<CveSeverity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };

export interface RankedAsset {
  source: CveSource;
  asset: string;
  ref?: string;
  package?: string;
  installed?: string;
  fixed?: string;
  exposed?: boolean;
}

export interface RankedCve {
  cve: string;
  priority: Priority;
  reasons: string[];
  kev?: Omit<KevEntry, 'cve'>;
  epss?: { score: number; percentile: number };
  severity: CveSeverity;
  cvss?: number;
  fix_available: boolean;
  exposed: boolean;
  sources: CveSource[];
  asset_count: number;
  assets: RankedAsset[];
  assets_truncated?: number;
}

const pct = (p: number) => `${Math.round(p * 1000) / 10}th percentile`;

function rank(cve: string, occ: CveOccurrence[], kev: KevCatalog | undefined, epssTable: EpssTable | undefined): RankedCve {
  const assets = new Map<string, RankedAsset>();
  let severity: CveSeverity = 'Unknown';
  let cvss: number | undefined;
  for (const o of occ) {
    if (SEV_RANK[o.severity] < SEV_RANK[severity]) severity = o.severity;
    if (o.cvss !== undefined && (cvss === undefined || o.cvss > cvss)) cvss = o.cvss;
    const key = [o.source, o.asset, o.package ?? '', o.installed ?? ''].join('\u0000');
    const cur = assets.get(key);
    if (cur) {
      cur.fixed ??= o.fixed;
      if (o.exposed) cur.exposed = true;
    } else {
      assets.set(key, {
        source: o.source,
        asset: o.asset,
        ...(o.ref ? { ref: o.ref } : {}),
        ...(o.package ? { package: o.package } : {}),
        ...(o.installed ? { installed: o.installed } : {}),
        ...(o.fixed ? { fixed: o.fixed } : {}),
        ...(o.exposed ? { exposed: true } : {}),
      });
    }
  }
  const list = [...assets.values()].sort((a, b) => Number(!!b.exposed) - Number(!!a.exposed) || a.asset.localeCompare(b.asset));
  const exposed = list.some((a) => a.exposed);
  const fixAvailable = list.some((a) => a.fixed);
  const k = kev?.entries.get(cve);
  const e = epssTable?.get(cve);
  const severe = severity === 'Critical' || severity === 'High';

  const reasons: string[] = [];
  let priority: Priority;
  if (k) {
    priority = 'P1';
    reasons.push(`In CISA KEV (exploited in the wild)${k.date_added ? ` since ${k.date_added}` : ''}${k.due_date ? `, federal due date ${k.due_date}` : ''}`);
    if (k.ransomware) reasons.push('Known use in ransomware campaigns');
  } else if ((e && e.epss >= EPSS_HIGH) || (exposed && severe)) {
    priority = 'P2';
  } else if (severe || (e && e.epss >= EPSS_MEDIUM)) {
    priority = 'P3';
  } else {
    priority = 'P4';
  }
  if (e) reasons.push(`EPSS ${e.epss} (${pct(e.percentile)}): ${e.epss >= EPSS_HIGH ? 'likely' : e.epss >= EPSS_MEDIUM ? 'possible' : 'unlikely'} exploitation in the next 30 days`);
  else if (epssTable) reasons.push('No EPSS score (too new or not yet scored)');
  if (exposed) reasons.push('Seen from the internet: ' + [...new Set(list.filter((a) => a.exposed).map((a) => a.asset))].join(', '));
  reasons.push(`Severity ${severity}${cvss !== undefined ? `, CVSS ${cvss}` : ''}`);
  reasons.push(fixAvailable ? 'A fixed version is available' : 'No fixed version reported');

  const { cve: _c, ...kevRest } = k ?? ({} as KevEntry);
  return {
    cve,
    priority,
    reasons,
    ...(k ? { kev: kevRest } : {}),
    ...(e ? { epss: { score: e.epss, percentile: e.percentile } } : {}),
    severity,
    ...(cvss !== undefined ? { cvss } : {}),
    fix_available: fixAvailable,
    exposed,
    sources: [...new Set(list.map((a) => a.source))],
    asset_count: list.length,
    assets: list.slice(0, MAX_ASSETS_PER_CVE),
    ...(list.length > MAX_ASSETS_PER_CVE ? { assets_truncated: list.length - MAX_ASSETS_PER_CVE } : {}),
  };
}

function compare(a: RankedCve, b: RankedCve): number {
  return (
    PRIORITIES.indexOf(a.priority) - PRIORITIES.indexOf(b.priority) ||
    Number(!!b.kev?.ransomware) - Number(!!a.kev?.ransomware) ||
    Number(b.exposed) - Number(a.exposed) ||
    (b.epss?.score ?? -1) - (a.epss?.score ?? -1) ||
    (b.cvss ?? -1) - (a.cvss ?? -1) ||
    SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
    b.asset_count - a.asset_count ||
    a.cve.localeCompare(b.cve)
  );
}

/** Groups occurrences by CVE and ranks them, most urgent first. */
export function rankCves(occ: CveOccurrence[], kev: KevCatalog | undefined, epss: EpssTable | undefined): RankedCve[] {
  const byCve = new Map<string, CveOccurrence[]>();
  for (const o of occ) {
    const g = byCve.get(o.cve);
    if (g) g.push(o);
    else byCve.set(o.cve, [o]);
  }
  return [...byCve].map(([cve, list]) => rank(cve, list, kev, epss)).sort(compare);
}

export interface RankFilter {
  priority?: Priority[];
  kev_only?: boolean;
  min_epss?: number;
  min_severity?: CveSeverity;
  exposed_only?: boolean;
  fixable_only?: boolean;
  /** Text contained in an asset name (host, image, product). */
  asset?: string;
  cve?: string;
}

export function filterRanked(list: RankedCve[], f: RankFilter): RankedCve[] {
  const needle = f.asset?.toLowerCase();
  const minSev = f.min_severity ? SEV_RANK[f.min_severity] : undefined;
  return list.filter(
    (c) =>
      (!f.priority?.length || f.priority.includes(c.priority)) &&
      (!f.kev_only || !!c.kev) &&
      (f.min_epss === undefined || (c.epss?.score ?? 0) >= f.min_epss) &&
      (minSev === undefined || SEV_RANK[c.severity] <= minSev) &&
      (!f.exposed_only || c.exposed) &&
      (!f.fixable_only || c.fix_available) &&
      (!needle || c.assets.some((a) => a.asset.toLowerCase().includes(needle))) &&
      (!f.cve || c.cve === f.cve.toUpperCase()),
  );
}

/** Counts for the whole ranked list, before filters and paging. */
export function summarise(list: RankedCve[]) {
  const by_priority = Object.fromEntries(PRIORITIES.map((p) => [p, 0])) as Record<Priority, number>;
  const by_severity = Object.fromEntries(CVE_SEVERITIES.map((s) => [s, 0])) as Record<CveSeverity, number>;
  let inKev = 0;
  let ransomware = 0;
  let exposed = 0;
  let epssHigh = 0;
  for (const c of list) {
    by_priority[c.priority]++;
    by_severity[c.severity]++;
    if (c.kev) inKev++;
    if (c.kev?.ransomware) ransomware++;
    if (c.exposed) exposed++;
    if ((c.epss?.score ?? 0) >= EPSS_HIGH) epssHigh++;
  }
  return { cves: list.length, by_priority, by_severity, in_kev: inKev, kev_ransomware: ransomware, epss_high: epssHigh, exposed };
}
