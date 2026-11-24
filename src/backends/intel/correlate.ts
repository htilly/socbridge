import type { Service } from '../../config/schema.js';
import type { CveOccurrence, CveSeverity, CveSource, SeenEndpoint } from '../cve.js';
import { isPublicIp } from '../cve.js';
import type { EdgeTarget } from '../graylog/firewall.js';
import { LOGIN_CATEGORIES, type AgentAttack } from '../wazuh/attacks.js';
import type { EpssTable, KevCatalog, KevEntry } from './feeds.js';
import { EPSS_HIGH } from './prioritize.js';

/**
 * Joins CVEs, exposure and attacks per service, through the administrator's
 * service map, and turns them into ranked actions. Pure: everything it uses
 * is passed in, so a result can always be explained by its input.
 *
 * Unknown is kept apart from no throughout: a missing link or an unreadable
 * backend never reads as "not exposed" or "not attacked".
 */

export const TIERS = ['A1', 'A2', 'A3', 'A4'] as const;
export type Tier = (typeof TIERS)[number];
export type Confidence = 'high' | 'medium' | 'low';
export type Exposure = 'confirmed' | 'declared' | 'observed' | 'internal' | 'unknown';
/** Strongest first. */
export type AttackStrength = 'cve_matched' | 'reached' | 'blocked' | 'none' | 'unknown';

export const TIER_RULES =
  `A1 fix now: in CISA KEV, internet-facing, and attack traffic reached the host or names the CVE. ` +
  `A2 fix next: in KEV and internet-facing; or EPSS ≥ ${EPSS_HIGH}, internet-facing and reached by attacks. ` +
  `A3 plan: in KEV elsewhere or with unknown exposure; EPSS ≥ ${EPSS_HIGH}; or Critical/High and internet-facing. A4 routine: the rest. ` +
  'Within a tier: service importance, ransomware use, attacks, EPSS, CVSS, CVEs closed. ' +
  'Attacked does not mean exploited: attacks and vulnerabilities on the same host only coincide unless a rule names the CVE.';

const STALE_MS = 7 * 86_400_000;
const IMPORTANCE = ['critical', 'high', 'normal', 'low'] as const;
const ATTACK_ORDER: AttackStrength[] = ['cve_matched', 'reached', 'blocked', 'unknown', 'none'];
const SEV_ORDER: CveSeverity[] = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
/** Scans and drops: traffic was seen, but not shown to have reached a service. */
const WEAK = new Set(['scan']);

export interface Evidence {
  id: string;
  source: CveSource | 'graylog' | 'intel' | 'service_map';
  kind: 'vulnerability' | 'attack' | 'blocked' | 'exposure' | 'kev';
  ref?: string;
  observed_at?: string;
  summary: string;
  /** The tool call that shows the original record. */
  lookup?: { tool: string; args: Record<string, unknown> };
}

export interface CorrelateInput {
  services: readonly Service[];
  occurrences: CveOccurrence[];
  /** Every endpoint DefectDojo knows. */
  endpoints: SeenEndpoint[];
  kev?: KevCatalog;
  epss?: EpssTable;
  /** Undefined: could not be read. */
  attacks?: AgentAttack[];
  edge?: EdgeTarget[];
  /** False when blocked traffic was not (completely) read. */
  edgeComplete: boolean;
  /** Sources whose CVEs were read completely. */
  complete: ReadonlySet<CveSource>;
  window: { from: string; to: string };
  now: number;
}

export interface ServiceView {
  id: string;
  name: string;
  importance: Service['importance'];
  exposure: Exposure;
  exposure_reason: string;
  exposure_conflict?: string;
  attack: AttackStrength;
  attack_reason: string;
  shared_host: boolean;
  matched_cves: string[];
  attacks: { category: string; title: string; strength: AttackStrength; attempts: number; unique_ips: number; last_seen?: string; evidence: string[] }[];
  evidence: string[];
  gaps: string[];
}

export interface ActionCve {
  cve: string;
  severity: CveSeverity;
  cvss?: number;
  kev?: Omit<KevEntry, 'cve'>;
  epss?: number;
}

export interface Action {
  id: string;
  kind: 'image' | 'package' | 'finding';
  source: CveSource;
  target: string;
  tier: Tier;
  confidence: Confidence;
  confidence_reasons: string[];
  reasons: string[];
  recommendation: string;
  caveat: string;
  fix_available: boolean;
  services: { id: string; name: string; importance: Service['importance']; exposure: Exposure; attack: AttackStrength }[];
  cve_count: number;
  cves: ActionCve[];
  evidence: string[];
}

export interface Correlated {
  services: ServiceView[];
  actions: Action[];
  gaps: string[];
  evidence: Map<string, Evidence>;
}

export const internetFacing = (e: Exposure) => e === 'confirmed' || e === 'declared' || e === 'observed';
export const reached = (a: AttackStrength) => a === 'reached' || a === 'cve_matched';

/** Whether a seen endpoint is one of the service's. Without a port in the map, any port is. */
export function ownsEndpoint(s: Service, e: { host: string; port?: number }): boolean {
  return s.endpoints.some((x) => x.hosts.includes(e.host.toLowerCase()) && (x.port === undefined || x.port === e.port));
}

/** The addresses firewall logs may show for a service. */
export function logTargets(s: Service): { ip: string; port?: number }[] {
  const fromEndpoints = s.endpoints.flatMap((e) => e.hosts.filter(isPublicIp).map((ip) => ({ ip, ...(e.port ? { port: e.port } : {}) })));
  return [...s.logTargets, ...fromEndpoints];
}

/** Links an occurrence to the services it belongs to. */
function servicesOf(services: readonly Service[], o: CveOccurrence): Service[] {
  if (o.source === 'trivy') return services.filter((s) => s.images.includes(o.asset));
  if (o.source === 'wazuh') return services.filter((s) => o.ref !== undefined && s.agents.includes(o.ref));
  return services.filter((s) => (o.endpoints ?? []).some((e) => ownsEndpoint(s, e)));
}

function viewOf(s: Service, x: CorrelateInput, add: (e: Evidence) => string): ServiceView {
  const evidence: string[] = [];
  const gaps: string[] = [];

  const seen = x.endpoints.filter((e) => e.external && ownsEndpoint(s, e));
  let exposure: Exposure;
  let exposure_reason: string;
  let exposure_conflict: string | undefined;
  if (seen.length) {
    const where = [...new Set(seen.map((e) => `${e.host}${e.port ? `:${e.port}` : ''}`))].slice(0, 5).join(', ');
    exposure = s.exposure === 'internet' ? 'confirmed' : 'observed';
    exposure_reason = `Seen in DefectDojo from outside: ${where}${s.exposure === 'internet' ? '; the service map agrees' : ''}`;
    if (s.exposure === 'internal') exposure_conflict = 'The service map says internal, but DefectDojo has it as an external endpoint; treated as internet-facing';
    evidence.push(
      add({
        id: `defectdojo:exposure:${s.id}`,
        source: 'defectdojo',
        kind: 'exposure',
        summary: exposure_reason,
        lookup: { tool: 'defectdojo_list_endpoints', args: { host: seen[0]!.host } },
      }),
    );
  } else if (s.exposure === 'internet') {
    exposure = 'declared';
    exposure_reason = 'Internet-facing according to the service map; not confirmed by a scan';
  } else if (s.exposure === 'internal') {
    exposure = 'internal';
    exposure_reason = 'Internal according to the service map';
  } else {
    exposure = 'unknown';
    exposure_reason = 'The service map does not say, and no external scan shows it';
  }
  if (exposure !== 'observed') {
    evidence.push(add({ id: `service_map:exposure:${s.id}`, source: 'service_map', kind: 'exposure', summary: `Service map: ${s.name} is ${s.exposure}` }));
  }
  if (exposure_conflict) gaps.push(`${s.name}: ${exposure_conflict}`);

  // Attacks seen on the hosts.
  const shared_host = s.agents.some((id) => x.services.some((o) => o.id !== s.id && o.agents.includes(id)));
  const own = new Set(x.occurrences.filter((o) => servicesOf([s], o).length).map((o) => o.cve));
  const matched = new Set<string>();
  const attacks: ServiceView['attacks'] = [];
  let withheld = 0;
  let sourceless = 0;
  for (const a of x.attacks ?? []) {
    if (!s.agents.includes(a.agent)) continue;
    const sharedHere = x.services.some((o) => o.id !== s.id && o.agents.includes(a.agent));
    if (LOGIN_CATEGORIES.has(a.category) && sharedHere) {
      withheld += a.attempts;
      sourceless += a.other_source;
      continue;
    }
    sourceless += WEAK.has(a.category) ? 0 : a.other_source;
    if (!a.attempts) continue;
    const named = a.cves.filter((c) => own.has(c));
    named.forEach((c) => matched.add(c));
    const strength: AttackStrength = named.length ? 'cve_matched' : WEAK.has(a.category) ? 'blocked' : 'reached';
    const ids = [
      add({
        id: `wazuh:attack:${a.agent}:${a.category}`,
        source: 'wazuh',
        kind: 'attack',
        ref: `agent ${a.agent}`,
        ...(a.last_seen ? { observed_at: a.last_seen } : {}),
        summary: `${a.title}: ${a.attempts} alerts from ${a.unique_ips} public addresses on agent ${a.agent}`,
        ...(a.alert_ids[0] ? { lookup: { tool: 'wazuh_get_alert', args: { alert_id: a.alert_ids[0] } } } : {}),
      }),
    ];
    attacks.push({ category: a.category, title: a.title, strength, attempts: a.attempts, unique_ips: a.unique_ips, ...(a.last_seen ? { last_seen: a.last_seen } : {}), evidence: ids });
    evidence.push(...ids);
  }

  // Blocked at the edge.
  const targets = logTargets(s);
  for (const e of x.edge ?? []) {
    if (!targets.some((t) => t.ip === e.ip && (t.port === undefined || t.port === e.port))) continue;
    const id = add({
      id: `graylog:${e.kind}:${e.ip}:${e.port ?? '-'}`,
      source: 'graylog',
      kind: 'blocked',
      ref: `${e.ip}${e.port ? `:${e.port}` : ''}`,
      summary: `${e.kind === 'ips' ? 'IPS' : 'Firewall'} blocked ${e.blocked} attempts to ${e.ip}${e.port ? `:${e.port}` : ''}`,
      lookup: { tool: 'graylog_search', args: { query: e.query, from: x.window.from, to: x.window.to } },
    });
    evidence.push(id);
    attacks.push({
      category: e.kind,
      title: e.kind === 'ips' ? 'IPS blocks' : 'Firewall blocks',
      strength: 'blocked',
      attempts: e.blocked,
      unique_ips: e.unique_ips,
      evidence: [id],
    });
  }

  let attack: AttackStrength;
  let attack_reason: string;
  const best = attacks.map((a) => a.strength).sort((a, b) => ATTACK_ORDER.indexOf(a) - ATTACK_ORDER.indexOf(b))[0];
  const unsure: string[] = [];
  if (!x.attacks) unsure.push('Wazuh attack alerts could not be read');
  if (!s.agents.length) unsure.push('no Wazuh agent is linked');
  if (withheld) unsure.push(`${withheld} login alerts on a host shared with other services cannot be tied to this one`);
  if (sourceless) unsure.push(`${sourceless} attack alerts have no public source address (local, or hidden by a proxy or NAT)`);
  if (best === 'cve_matched') {
    attack = best;
    attack_reason = `Alerts name ${[...matched].join(', ')}`;
  } else if (best === 'reached') {
    attack = best;
    attack_reason = `Attack traffic from the internet reached the host${shared_host ? ', which it shares with other services' : ''}`;
  } else if (unsure.length) {
    attack = 'unknown';
    attack_reason = `Not known whether attacks reached it: ${unsure.join('; ')}${best === 'blocked' ? '. Blocked or scan traffic was seen' : ''}`;
  } else if (best === 'blocked') {
    attack = 'blocked';
    attack_reason = 'Only blocked or scan traffic was seen';
  } else {
    attack = 'none';
    attack_reason = 'No attack alerts on the linked hosts';
  }
  if (unsure.length) gaps.push(`${s.name}: ${unsure.join('; ')}`);

  if (!s.agents.length && !s.images.length) gaps.push(`${s.name}: no Wazuh agent or image is linked, so its vulnerabilities are unknown`);
  return {
    id: s.id, name: s.name, importance: s.importance, exposure, exposure_reason, ...(exposure_conflict ? { exposure_conflict } : {}),
    attack, attack_reason, shared_host, matched_cves: [...matched], attacks, evidence, gaps,
  };
}

interface Group {
  kind: Action['kind'];
  source: CveSource;
  target: string;
  occ: CveOccurrence[];
}

function groupKey(o: CveOccurrence): Omit<Group, 'occ'> & { key: string } {
  if (o.source === 'trivy') return { key: `image:${o.asset}`, kind: 'image', source: o.source, target: o.asset };
  if (o.source === 'wazuh') return { key: `package:${o.ref ?? o.asset}:${o.package ?? ''}`, kind: 'package', source: o.source, target: `${o.package ?? 'package'} on ${o.asset}` };
  return { key: `finding:${o.ref ?? `${o.asset}:${o.cve}`}`, kind: 'finding', source: o.source, target: `${o.asset}, ${o.ref ?? o.cve}` };
}

function tierOf(kev: boolean, epss: number | undefined, severe: boolean, inet: boolean, hit: boolean): Tier {
  const likely = (epss ?? 0) >= EPSS_HIGH;
  if (kev && inet && hit) return 'A1';
  if ((kev && inet) || (likely && inet && hit)) return 'A2';
  if (kev || likely || (severe && inet)) return 'A3';
  return 'A4';
}

export function correlate(x: CorrelateInput): Correlated {
  const evidence = new Map<string, Evidence>();
  const add = (e: Evidence) => {
    evidence.set(e.id, e);
    return e.id;
  };
  const views = x.services.map((s) => viewOf(s, x, add));
  const viewById = new Map(views.map((v) => [v.id, v]));

  const groups = new Map<string, Group>();
  for (const o of x.occurrences) {
    const { key, ...g } = groupKey(o);
    const cur = groups.get(key);
    if (cur) cur.occ.push(o);
    else groups.set(key, { ...g, occ: [o] });
  }

  const actions = [...groups].map(([id, g]): Action => {
    const linked = [...new Set(g.occ.flatMap((o) => servicesOf(x.services, o)))].map((s) => viewById.get(s.id)!);
    // A finding outside the map can still have been seen from outside.
    const looseExternal = !linked.length && g.occ.some((o) => o.exposed || o.endpoints?.some((e) => e.external));

    const byCve = new Map<string, { o: CveOccurrence; info: ActionCve }>();
    for (const o of g.occ) {
      const k = x.kev?.entries.get(o.cve);
      const e = x.epss?.get(o.cve);
      const cur = byCve.get(o.cve);
      if (!cur) {
        const { cve: _c, ...kev } = k ?? ({} as KevEntry);
        byCve.set(o.cve, { o, info: { cve: o.cve, severity: o.severity, ...(o.cvss !== undefined ? { cvss: o.cvss } : {}), ...(k ? { kev } : {}), ...(e ? { epss: e.epss } : {}) } });
      } else {
        if (SEV_ORDER.indexOf(o.severity) < SEV_ORDER.indexOf(cur.info.severity)) cur.info.severity = o.severity;
        if (o.cvss !== undefined) cur.info.cvss = Math.max(cur.info.cvss ?? 0, o.cvss);
        if (!cur.o.fixed && o.fixed) cur.o = o;
      }
    }

    const contexts: (ServiceView | null)[] = linked.length ? linked : [null];
    let best: { tier: Tier; cve: ActionCve; view: ServiceView | null } | undefined;
    for (const { info } of byCve.values()) {
      const severe = info.severity === 'Critical' || info.severity === 'High';
      for (const v of contexts) {
        const inet = v ? internetFacing(v.exposure) : looseExternal;
        const tier = tierOf(!!info.kev, info.epss, severe, inet, !!v && reached(v.attack));
        const better =
          !best ||
          TIERS.indexOf(tier) - TIERS.indexOf(best.tier) ||
          (v && best.view ? IMPORTANCE.indexOf(v.importance) - IMPORTANCE.indexOf(best.view.importance) : 0) ||
          (best.cve.kev ? 1 : 0) - (info.kev ? 1 : 0) ||
          (best.cve.epss ?? 0) - (info.epss ?? 0) ||
          (best.cve.cvss ?? 0) - (info.cvss ?? 0);
        if (better === true || (typeof better === 'number' && better < 0)) best = { tier, cve: info, view: v };
      }
    }
    const { tier, cve: lead, view } = best!;
    const occ = byCve.get(lead.cve)!.o;

    const reasons: string[] = [];
    if (lead.kev) reasons.push(`${lead.cve} is in CISA KEV (exploited in the wild)${lead.kev.ransomware ? ', with known ransomware use' : ''}`);
    else reasons.push(`${lead.cve} is the most urgent: ${lead.severity}${lead.cvss !== undefined ? `, CVSS ${lead.cvss}` : ''}`);
    if (lead.epss !== undefined) reasons.push(`EPSS ${lead.epss}: probability of exploitation in the next 30 days`);
    if (view) {
      reasons.push(`${view.name}: ${view.exposure_reason}`);
      if (view.exposure_conflict) reasons.push(view.exposure_conflict);
      reasons.push(`${view.name}: ${view.attack_reason}`);
      reasons.push(`Importance of ${view.name}: ${view.importance}`);
    } else if (looseExternal) reasons.push('Seen from outside in DefectDojo, but not linked to a service, so attacks on it are unknown');
    else reasons.push('Not linked to a service, so exposure and attacks are unknown');

    const doubts: string[] = [];
    if (!view) doubts.push('Not in the service map');
    else {
      if (view.exposure === 'internal') doubts.push('That it is internal is declared, not verified');
      if (view.exposure === 'declared') doubts.push('Exposure is declared, not confirmed by a scan');
      if (view.exposure === 'unknown') doubts.push('Exposure is unknown');
      if (view.exposure_conflict) doubts.push('The service map and the scan disagree about exposure');
      if (view.attack === 'unknown') doubts.push('Whether attacks reached it is unknown');
      if (view.shared_host && reached(view.attack)) doubts.push('Attacks are seen on a host shared by several services');
    }
    if (g.kind !== 'finding' && !occ.installed) doubts.push('The installed version is not reported');
    if (g.kind === 'package') doubts.push('A host package; not shown that the service uses it');
    if (occ.scanned_at && x.now - Date.parse(occ.scanned_at) > STALE_MS) doubts.push(`The scan is old (${occ.scanned_at.slice(0, 10)})`);
    if (!x.complete.has(g.source)) doubts.push(`${g.source} was not read completely`);
    const confidence: Confidence = !view || doubts.length > 1 ? 'low' : doubts.length ? 'medium' : 'high';

    const fixed = g.occ.filter((o) => o.fixed);
    const n = byCve.size;
    const closes = new Set(fixed.map((o) => o.cve)).size;
    const cvesText = (k: number) => `${k} CVE${k === 1 ? '' : 's'}`;
    let recommendation: string;
    let caveat: string;
    const req = lead.kev?.required_action ? ` CISA's required action: ${lead.kev.required_action}` : '';
    if (g.kind === 'image') {
      recommendation = occ.fixed
        ? `Update ${occ.package ?? 'the package'} to ${occ.fixed} or later by pulling or rebuilding ${g.target}, then recreate its containers. Fixes are reported for ${closes} of ${cvesText(n)}.`
        : fixed.length
          ? `No fix is reported for ${lead.cve}. A newer ${g.target} would fix ${closes} of ${cvesText(n)}; until then, limit access to the service.${req}`
          : `No fixed version is reported for ${g.target}; limit access to the service.${req}`;
      caveat = 'The package is in the image. That does not show that the vulnerable code is used or reachable, or that a running container uses this scan\'s image.';
    } else if (g.kind === 'package') {
      recommendation = `Update ${g.target}${occ.installed ? ` (installed ${occ.installed})` : ''}. Wazuh does not report the fixed version; check the distribution's advisory for ${lead.cve}.${req}`;
      caveat = 'The package is installed on the host. That does not show that a service uses it.';
    } else {
      recommendation = `Remediate ${lead.cve} as described in DefectDojo ${occ.ref ?? ''}.${req}`.replace(' .', '.');
      caveat = 'Scanners that infer CVEs from a version banner can be wrong where the distribution backports fixes; verify first.';
    }

    const ids: string[] = [];
    const shown = [...byCve.values()].sort(
      (a, b) =>
        Number(b.info.cve === lead.cve) - Number(a.info.cve === lead.cve) ||
        Number(!!b.info.kev) - Number(!!a.info.kev) ||
        (b.info.epss ?? 0) - (a.info.epss ?? 0) ||
        (b.info.cvss ?? 0) - (a.info.cvss ?? 0),
    );
    for (const { o, info } of shown.slice(0, 3)) {
      ids.push(add(vulnEvidence(o)));
      if (info.kev) {
        ids.push(
          add({
            id: `intel:kev:${info.cve}`,
            source: 'intel',
            kind: 'kev',
            ref: info.cve,
            ...(info.kev.date_added ? { observed_at: info.kev.date_added } : {}),
            summary: `${info.cve} in CISA KEV: ${info.kev.name ?? ''}`.trim(),
            lookup: { tool: 'intel_cve_lookup', args: { cves: [info.cve] } },
          }),
        );
      }
    }
    for (const v of linked) ids.push(...v.evidence);

    return {
      id, kind: g.kind, source: g.source, target: g.target, tier, confidence,
      confidence_reasons: doubts.length ? doubts : ['Exposure, version and attacks are all backed by records'],
      reasons, recommendation, caveat,
      fix_available: g.kind === 'image' && fixed.length > 0,
      services: linked.map((v) => ({ id: v.id, name: v.name, importance: v.importance, exposure: v.exposure, attack: v.attack })),
      cve_count: n,
      cves: shown.map((c) => c.info),
      evidence: [...new Set(ids)],
    };
  });

  const importance = (a: Action) => Math.min(IMPORTANCE.length, ...a.services.map((s) => IMPORTANCE.indexOf(s.importance)));
  const attack = (a: Action) => Math.min(ATTACK_ORDER.length, ...a.services.map((s) => ATTACK_ORDER.indexOf(s.attack)));
  const max = (a: Action, f: (c: ActionCve) => number) => a.cves.reduce((m, c) => Math.max(m, f(c)), 0);
  actions.sort(
    (a, b) =>
      TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier) ||
      importance(a) - importance(b) ||
      max(b, (c) => Number(!!c.kev?.ransomware)) - max(a, (c) => Number(!!c.kev?.ransomware)) ||
      attack(a) - attack(b) ||
      max(b, (c) => c.epss ?? 0) - max(a, (c) => c.epss ?? 0) ||
      max(b, (c) => c.cvss ?? 0) - max(a, (c) => c.cvss ?? 0) ||
      b.cve_count - a.cve_count ||
      a.id.localeCompare(b.id),
  );

  return { services: views, actions, gaps: views.flatMap((v) => v.gaps), evidence };
}

function vulnEvidence(o: CveOccurrence): Evidence {
  const what = `${o.cve} in ${[o.package, o.installed].filter(Boolean).join(' ') || 'the target'}, ${o.asset}`;
  const base = { source: o.source, kind: 'vulnerability' as const, ...(o.ref ? { ref: o.ref } : {}), ...(o.scanned_at ? { observed_at: o.scanned_at } : {}), summary: what.slice(0, 300) };
  const id = `${o.source}:vuln:${o.ref ?? o.asset}:${o.package ?? ''}:${o.cve}`;
  if (o.source === 'trivy') return { id, ...base, lookup: { tool: 'trivy_report_findings', args: { report: o.ref, ...(o.package ? { package: o.package } : {}) } } };
  if (o.source === 'wazuh') return { id, ...base, ...(o.ref ? { lookup: { tool: 'wazuh_agent_vulnerabilities', args: { agent_id: o.ref, cve: o.cve } } } : {}) };
  const n = Number(/^finding (\d+)$/.exec(o.ref ?? '')?.[1]);
  return { id, ...base, ...(n ? { lookup: { tool: 'defectdojo_get_finding', args: { finding_id: n } } } : {}) };
}

// ---------------------------------------------------------------- questions

type Answer = 'yes' | 'no' | 'unknown';

export interface InvestigateFilter {
  exposure: 'internet' | 'any';
  kev_only: boolean;
  min_epss?: number;
  attack?: 'any' | 'reached' | 'cve_matched' | 'none';
  service?: string;
}

/** Whether a CVE is one the question asks about. */
export function cveWanted(c: ActionCve, f: Pick<InvestigateFilter, 'kev_only' | 'min_epss'>): boolean {
  if (!f.kev_only && f.min_epss === undefined) return true;
  return (f.kev_only && !!c.kev) || (f.min_epss !== undefined && (c.epss ?? 0) >= f.min_epss);
}

/** Services that meet every condition, and those that might if an unknown were resolved. */
export function investigate(c: Correlated, x: CorrelateInput, f: InvestigateFilter) {
  const needle = f.service?.toLowerCase();
  const wanted = c.actions.filter((a) => a.cves.some((v) => cveWanted(v, f)));
  const matches: { view: ServiceView; actions: Action[] }[] = [];
  const possible: { view: ServiceView; actions: Action[]; unresolved: string[] }[] = [];
  for (const s of x.services) {
    const view = c.services.find((v) => v.id === s.id)!;
    if (needle && !view.name.toLowerCase().includes(needle)) continue;
    const unresolved: string[] = [];
    const ask = (a: Answer, why: string): Answer => {
      if (a === 'unknown') unresolved.push(why);
      return a;
    };

    const exposure: Answer = f.exposure === 'any' || internetFacing(view.exposure) ? 'yes' : view.exposure === 'unknown' ? 'unknown' : 'no';
    const actions = wanted.filter((a) => a.services.some((v) => v.id === s.id));
    const missing = vulnerabilityGaps(s, x, f);
    const vulnerable: Answer = actions.length ? 'yes' : missing.length ? 'unknown' : 'no';
    let attacked: Answer = 'yes';
    const a = view.attack;
    const unseen = a === 'unknown' || !x.edgeComplete;
    if (f.attack === 'any') attacked = view.attacks.length ? 'yes' : unseen ? 'unknown' : 'no';
    else if (f.attack === 'reached') attacked = reached(a) ? 'yes' : a === 'unknown' ? 'unknown' : 'no';
    else if (f.attack === 'cve_matched') attacked = a === 'cve_matched' ? 'yes' : a === 'unknown' ? 'unknown' : 'no';
    else if (f.attack === 'none') attacked = view.attacks.length ? 'no' : unseen ? 'unknown' : 'yes';

    const answers = [ask(exposure, view.exposure_reason), ask(vulnerable, missing.join('; ')), ask(attacked, a === 'unknown' || x.edgeComplete ? view.attack_reason : 'Blocked traffic could not be read completely')];
    if (answers.includes('no')) continue;
    if (answers.includes('unknown')) possible.push({ view, actions, unresolved });
    else matches.push({ view, actions });
  }
  return { matches, possible, unmapped: needle ? [] : wanted.filter((a) => !a.services.length) };
}

function vulnerabilityGaps(s: Service, x: CorrelateInput, f: InvestigateFilter): string[] {
  const out: string[] = [];
  if (!s.agents.length && !s.images.length) out.push('No Wazuh agent or image is linked, so its vulnerabilities are unknown');
  if (s.images.length && !x.complete.has('trivy')) out.push('Trivy was not read completely');
  if (s.agents.length && !x.complete.has('wazuh')) out.push('Wazuh vulnerabilities were not read completely');
  if (s.endpoints.length && !x.complete.has('defectdojo')) out.push('DefectDojo was not read completely');
  if (f.kev_only && !x.kev) out.push('The KEV catalog is not available');
  if (f.min_epss !== undefined && !x.epss) out.push('EPSS scores are not available');
  return out;
}
