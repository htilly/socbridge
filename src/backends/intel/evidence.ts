import { BackendError } from '../http.js';
import { publicError } from '../result.js';
import type { Service } from '../../config/schema.js';
import type { CveSource } from '../cve.js';
import { attacksByTarget, type FirewallRuntime } from '../graylog/firewall.js';
import type { ToolContext } from '../types.js';
import { attacksByAgent } from '../wazuh/attacks.js';
import type { WazuhClient } from '../wazuh/client.js';
import { cveWanted, correlate, investigate, logTargets, TIER_RULES, type Action, type Correlated, type CorrelateInput, type Evidence, type InvestigateFilter, type Tier } from './correlate.js';
import type { IntelFeeds } from './feeds.js';
import { cached, gather, SOURCES, type SourceReport } from './gather.js';

/**
 * Reads everything the correlation needs through the caller's own access
 * (`ctx.source`), and answers the two questions built on it. Shared by the MCP
 * tools and the web UI so both always agree.
 */

const ATTACK_TTL_MS = 60_000;
/** CVEs listed per action; the count covers all. */
const MAX_CVES = 10;
/** Services or actions without a place in the main list that are listed anyway. */
const MAX_SIDE = 50;

type Report = Omit<SourceReport, 'source'> & { source: string };

export async function collect(rt: IntelFeeds, ctx: ToolContext, hours: number, refresh = false) {
  await rt.ensure();
  const services: readonly Service[] = ctx.services();
  const to = Date.now();
  const from = to - hours * 3_600_000;
  const gaps: string[] = [];

  const wazuh = async (): Promise<[Report, Awaited<ReturnType<typeof attacksByAgent>> | undefined]> => {
    const h = ctx.source<WazuhClient>('wazuh');
    if ('unavailable' in h) return [{ source: 'wazuh_attacks', status: 'unavailable', message: h.unavailable }, undefined];
    try {
      if (!h.runtime.hasIndexer) throw new BackendError('the Wazuh indexer is not configured; alerts live there');
      const r = await cached(rt, h.runtime, `attacks:${hours}`, refresh, () => h.run((c) => attacksByAgent(c, { from, to })), ATTACK_TTL_MS);
      return [{ source: 'wazuh_attacks', status: 'ok', ...(r.cached ? { cached: true } : {}) }, r.inv];
    } catch (err) {
      return [{ source: 'wazuh_attacks', status: 'error', message: publicError(err) }, undefined];
    }
  };
  const graylog = async (): Promise<[Report, Awaited<ReturnType<typeof attacksByTarget>> | undefined]> => {
    const h = ctx.source<FirewallRuntime>('graylog');
    if ('unavailable' in h) return [{ source: 'graylog_blocks', status: 'unavailable', message: h.unavailable }, undefined];
    try {
      const ips = [...new Set(services.flatMap((s) => logTargets(s).map((t) => t.ip)))].sort();
      const r = await cached(rt, h.runtime, `blocks:${hours}:${ips.join(',')}`, refresh, () => h.run((g) => attacksByTarget(g, { from, to, ips })), ATTACK_TTL_MS);
      return [{ source: 'graylog_blocks', status: 'ok', ...(r.cached ? { cached: true } : {}) }, r.inv];
    } catch (err) {
      return [{ source: 'graylog_blocks', status: 'error', message: publicError(err) }, undefined];
    }
  };
  const [g, [wReport, attacks], [gReport, edge]] = await Promise.all([gather(rt, ctx, SOURCES, refresh), wazuh(), graylog()]);

  const sources: Report[] = [...g.sources, wReport, gReport];
  for (const s of sources) if (s.status !== 'ok') gaps.push(`${s.source}: ${s.message ?? s.status}`);
  gaps.push(...g.gaps);
  if (attacks?.truncated) gaps.push('Wazuh: too many agents; attacks on some are missing');
  if (edge?.truncated) gaps.push('Graylog: too many targets; some blocked traffic is missing');
  if (edge?.ips_without_target) gaps.push(`Graylog: ${edge.ips_without_target} IPS blocks do not say what they were aimed at, so they are not tied to any service`);
  if (edge?.signature_cves.length) gaps.push(`Graylog: IPS signatures named ${edge.signature_cves.slice(0, 20).join(', ')} without a usable target; check whether you have them`);
  if (!rt.kev.data) gaps.push('The KEV catalog is not available: known exploited CVEs are not marked');
  if (!rt.epss.data) gaps.push('EPSS scores are not available');

  // Incomplete when the source failed or any of its gaps was reported.
  const prefix: Record<CveSource, string> = { wazuh: 'Wazuh:', trivy: 'Trivy:', defectdojo: 'DefectDojo:' };
  const complete = new Set<CveSource>(
    g.sources.filter((s) => s.status === 'ok' && !g.gaps.some((x) => x.startsWith(prefix[s.source]))).map((s) => s.source),
  );

  const input: CorrelateInput = {
    services,
    occurrences: g.occurrences,
    endpoints: g.endpoints,
    kev: rt.kev.data,
    epss: rt.epss.data,
    attacks: attacks && !attacks.truncated ? attacks.attacks : undefined,
    edge: edge?.targets,
    edgeComplete: !!edge && !edge.truncated,
    complete,
    window: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
    now: to,
  };
  const correlated = correlate(input);
  gaps.push(...correlated.gaps);

  const mappedImages = new Set(services.flatMap((s) => s.images));
  const mappedAgents = new Set(services.flatMap((s) => s.agents));
  const loose = (src: CveSource, key: (o: (typeof g.occurrences)[number]) => string | undefined, mapped: Set<string>) =>
    new Set(g.occurrences.filter((o) => o.source === src).flatMap((o) => { const k = key(o); return k && !mapped.has(k) ? [k] : []; })).size;
  const images = loose('trivy', (o) => o.asset, mappedImages);
  const agents = loose('wazuh', (o) => o.ref, mappedAgents);
  if (!services.length) gaps.push('The service map is empty: exposure and attacks cannot be tied to vulnerabilities. An administrator can fill it under Services.');
  else if (images || agents) gaps.push(`Not in the service map: ${images} image${images === 1 ? '' : 's'} and ${agents} host${agents === 1 ? '' : 's'} with vulnerabilities`);

  return { input, correlated, sources, gaps, notes: g.notes.filter((n) => !g.gaps.includes(n)) };
}

type Collected = Awaited<ReturnType<typeof collect>>;

/** The evidence behind a set of items, so IDs always resolve within the result. */
function evidenceFor(c: Correlated, ids: string[]): Evidence[] {
  return [...new Set(ids)].flatMap((id) => c.evidence.get(id) ?? []);
}

const listed = (a: Action, keep: (c: Action['cves'][number]) => boolean = () => true) => {
  const cves = a.cves.filter(keep);
  return {
    ...a,
    cves: cves.slice(0, MAX_CVES).map((c) => ({ ...c, ...(c.kev ? { kev: { date_added: c.kev.date_added, due_date: c.kev.due_date, ransomware: c.kev.ransomware, name: c.kev.name } } : {}) })),
    ...(cves.length > MAX_CVES ? { cves_truncated: cves.length - MAX_CVES } : {}),
  };
};

const head = (rt: IntelFeeds, c: Collected) => ({
  rules: TIER_RULES,
  window: c.input.window,
  feeds: rt.view(),
  sources: c.sources,
  ...(c.notes.length ? { notes: c.notes } : {}),
  gaps: c.gaps,
});

export interface FixFirstInput {
  hours: number;
  tier?: Tier[];
  service?: string;
  fixable_only: boolean;
  attacked_only: boolean;
  limit: number;
  offset: number;
  refresh: boolean;
}

export async function fixFirst(rt: IntelFeeds, ctx: ToolContext, a: FixFirstInput) {
  const c = await collect(rt, ctx, a.hours, a.refresh);
  const needle = a.service?.toLowerCase();
  const list = c.correlated.actions.filter(
    (x) =>
      (!a.tier?.length || a.tier.includes(x.tier)) &&
      (!needle || x.services.some((s) => s.name.toLowerCase().includes(needle))) &&
      (!a.fixable_only || x.fix_available) &&
      (!a.attacked_only || x.services.some((s) => s.attack === 'reached' || s.attack === 'cve_matched')),
  );
  const page = list.slice(a.offset, a.offset + a.limit);
  const by_tier = { A1: 0, A2: 0, A3: 0, A4: 0 };
  for (const x of c.correlated.actions) by_tier[x.tier]++;
  return {
    ...head(rt, c),
    total: c.correlated.actions.length,
    by_tier,
    matching: list.length,
    returned: page.length,
    offset: a.offset,
    actions: page.map((x) => listed(x)),
    evidence: evidenceFor(c.correlated, page.flatMap((x) => x.evidence)),
  };
}

export type InvestigateInput = InvestigateFilter & { hours: number; limit: number; refresh: boolean };

export async function investigateTool(rt: IntelFeeds, ctx: ToolContext, a: InvestigateInput) {
  const c = await collect(rt, ctx, a.hours, a.refresh);
  const r = investigate(c.correlated, c.input, a);
  const keep = (v: Action['cves'][number]) => cveWanted(v, a);
  const matches = r.matches.slice(0, a.limit);
  const possible = r.possible.slice(0, a.limit);
  const show = (x: { view: (typeof r.matches)[number]['view']; actions: Action[] }) => {
    const { gaps: _g, ...view } = x.view;
    return { ...view, actions_total: x.actions.length, actions: x.actions.slice(0, 10).map((y) => listed(y, keep)) };
  };
  const used = [...matches, ...possible];
  const unmapped = r.unmapped.slice(0, MAX_SIDE);
  return {
    ...head(rt, c),
    question: { hours: a.hours, exposure: a.exposure, kev_only: a.kev_only, ...(a.min_epss !== undefined ? { min_epss: a.min_epss } : {}), ...(a.attack ? { attack: a.attack } : {}) },
    services_in_map: c.input.services.length,
    matching: r.matches.length,
    matches: matches.map(show),
    possible_total: r.possible.length,
    possible: possible.map((x) => ({ ...show(x), unresolved: x.unresolved })),
    // Vulnerable as asked, but in no service: their exposure and attacks are unknown.
    unmapped_total: r.unmapped.length,
    unmapped: unmapped.map((x) => ({ target: x.target, source: x.source, cves: x.cves.filter(keep).slice(0, MAX_CVES).map((v) => v.cve) })),
    evidence: evidenceFor(c.correlated, used.flatMap((x) => [...x.view.evidence, ...x.actions.slice(0, 10).flatMap((y) => y.evidence)])),
  };
}
