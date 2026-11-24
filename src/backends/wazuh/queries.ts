import { normaliseCve, normaliseSeverity, type CveInventory, type CveOccurrence } from '../cve.js';
import { BackendError } from '../http.js';
import { buckets, normaliseAgentId, parseTime, totalHits, type SearchResponse, type WazuhClient, type WazuhListResponse } from './client.js';
import { snapshotHistory, type SnapshotHistory } from './snapshots.js';

/**
 * Wazuh read queries, shared by the MCP tools and the web UI's findings view so
 * both always show the same data. Each function validates its own input.
 */

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const AGENT_STATUS = ['active', 'disconnected', 'pending', 'never_connected'] as const;

const AGENT_FIELDS =
  'id,name,ip,status,os.name,os.platform,os.version,version,group,lastKeepAlive,dateAdd,node_name';

const VULN_SOURCE = [
  'agent.id',
  'agent.name',
  'package.name',
  'package.version',
  'package.type',
  'vulnerability.id',
  'vulnerability.severity',
  'vulnerability.score.base',
  'vulnerability.description',
  'vulnerability.reference',
  'vulnerability.detected_at',
  'vulnerability.published_at',
  'vulnerability.under_evaluation',
];

const ALERT_SOURCE = [
  'timestamp',
  'agent.id',
  'agent.name',
  'rule.id',
  'rule.level',
  'rule.description',
  'rule.groups',
  'rule.mitre',
  'location',
  'full_log',
  'data.srcip',
  'data.srcuser',
  'data.dstuser',
  'syscheck.path',
  'syscheck.event',
];

export interface ListAgentsInput {
  status?: (typeof AGENT_STATUS)[number];
  group?: string;
  os_platform?: string;
  search?: string;
  limit: number;
  offset: number;
}

export async function listAgents(client: WazuhClient, a: ListAgentsInput) {
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>('/agents', {
    status: a.status,
    group: a.group,
    'os.platform': a.os_platform,
    search: a.search,
    limit: a.limit,
    offset: a.offset,
    select: AGENT_FIELDS,
    sort: '+id',
  });
  return {
    total: r.data.total_affected_items,
    returned: r.data.affected_items.length,
    offset: a.offset,
    agents: r.data.affected_items,
  };
}

export async function getAgent(client: WazuhClient, agentId: string) {
  const id = normaliseAgentId(agentId);
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>('/agents', { agents_list: id });
  return r.data.affected_items[0] ?? null;
}

export interface AgentVulnInput {
  agent_id: string;
  severity?: Severity[];
  package?: string;
  cve?: string;
  limit: number;
}

export async function agentVulnerabilities(client: WazuhClient, a: AgentVulnInput) {
  const id = normaliseAgentId(a.agent_id);
  const base = [{ term: { 'agent.id': id } }];
  const filter: unknown[] = [...base];
  if (a.severity?.length) filter.push({ terms: { 'vulnerability.severity': a.severity } });
  if (a.package) filter.push({ term: { 'package.name': a.package } });
  if (a.cve) filter.push({ term: { 'vulnerability.id': a.cve.toUpperCase() } });
  const r = await client.search<SearchResponse>(client.cfg.vulnerabilitiesIndex, {
    size: a.limit,
    track_total_hits: true,
    _source: VULN_SOURCE,
    query: { bool: { filter } },
    sort: [{ 'vulnerability.score.base': { order: 'desc', missing: '_last' } }],
    // Severity breakdown for the whole agent, independent of the filters above.
    aggs: {
      all: {
        global: {},
        aggs: {
          agent: {
            filter: { bool: { filter: base } },
            aggs: { by_severity: { terms: { field: 'vulnerability.severity', size: 10 } } },
          },
        },
      },
    },
  });
  const agg = (r.aggregations?.all as unknown as { agent?: { by_severity?: { buckets?: { key: string; doc_count: number }[] } } })
    ?.agent?.by_severity?.buckets;
  return {
    agent_id: id,
    severity_counts: Object.fromEntries((agg ?? []).map((b) => [b.key, b.doc_count])) as Record<string, number>,
    matching: totalHits(r),
    returned: r.hits.hits.length,
    vulnerabilities: r.hits.hits.map((h) => h._source),
  };
}

interface AgentBucket {
  key: string;
  doc_count: number;
  name?: { buckets?: { key: string }[] };
  by_severity?: { buckets?: { key: string; doc_count: number }[] };
}

export async function vulnerabilityOverview(client: WazuhClient, a: { severity?: Severity[]; top: number }) {
  const filter = a.severity?.length ? [{ terms: { 'vulnerability.severity': a.severity } }] : [];
  const r = await client.search<SearchResponse>(client.cfg.vulnerabilitiesIndex, {
    size: 0,
    track_total_hits: true,
    query: { bool: { filter } },
    aggs: {
      by_severity: { terms: { field: 'vulnerability.severity', size: 10 } },
      by_agent: {
        terms: { field: 'agent.id', size: a.top },
        aggs: {
          name: { terms: { field: 'agent.name', size: 1 } },
          by_severity: { terms: { field: 'vulnerability.severity', size: 10 } },
        },
      },
      by_cve: { terms: { field: 'vulnerability.id', size: a.top } },
    },
  });
  const agents = ((r.aggregations?.by_agent?.buckets ?? []) as unknown as AgentBucket[]).map((b) => ({
    agent_id: String(b.key),
    agent_name: b.name?.buckets?.[0]?.key ?? null,
    total: b.doc_count,
    by_severity: Object.fromEntries((b.by_severity?.buckets ?? []).map((s) => [s.key, s.doc_count])) as Record<string, number>,
  }));
  return {
    total: totalHits(r),
    by_severity: buckets(r, 'by_severity'),
    top_agents: agents,
    top_cves: buckets(r, 'by_cve'),
  };
}

// ── Vulnerability trend (indexer) ────────────────────────────────────────────
// The states index only holds what is open now. Since Wazuh 4.8 the vulnerability
// detector also raises an alert each time a CVE starts affecting a package
// (data.vulnerability.status "Active") and when it no longer does after an
// update or removal ("Solved"). Counting those alerts per day gives new and
// resolved findings for the time before the first snapshot (see snapshots.ts). They
// miss CVEs that appear or disappear through a feed update.

export const TREND_STATUS = { new: 'Active', resolved: 'Solved' } as const;

// A package upgrade raises both kinds for every CVE the new version still has:
// "Active" for the new version and, seconds later, "Solved" for the old one. The
// finding never went away, so such a pair is neither new nor resolved. Pairs are
// matched on agent + CVE + package in the same or an adjacent time slot: far
// enough apart for a large batch of alerts, close enough that a CVE which appears
// one day and is fixed a later day still counts as both.
const PAIR_SLOT_MS = 10 * 60_000;
const DAY_MS = 86_400_000;
const TREND_PAGE = 1000;
const TREND_MAX_PAGES = 100;

interface TrendBucket {
  key: { slot: number; agent: string; cve: string; package: string | null; status: string; severity: string | null };
  doc_count: number;
}
interface TrendEvent {
  agent: string;
  severity: string | null;
  slot: number;
  count: number;
}
interface AgentBucket {
  key: string;
  doc_count: number;
  name?: { buckets?: { key: string }[] };
}

/** Removes the Active/Solved pairs of one finding (counts are lowered in place); returns the number of pairs. */
function cancelPairs(active: TrendEvent[], solved: TrendEvent[]): number {
  let pairs = 0;
  for (const offset of [0, 1, -1]) {
    for (const s of solved) {
      for (const a of active) {
        if (s.slot - a.slot !== offset * PAIR_SLOT_MS) continue;
        const n = Math.min(a.count, s.count);
        a.count -= n;
        s.count -= n;
        pairs += n;
      }
    }
  }
  return pairs;
}

export async function vulnerabilityTrend(client: WazuhClient, a: { days: number; severity?: Severity[]; top: number }, now = Date.now(), history: SnapshotHistory | null = snapshotHistory(client)) {
  const from = Math.floor(now / DAY_MS) * DAY_MS - (a.days - 1) * DAY_MS;
  // Severity is applied after pairing: the two alerts of a pair may carry different severities.
  const query = {
    bool: {
      filter: [
        { range: { timestamp: { gte: new Date(from).toISOString() } } },
        { terms: { 'data.vulnerability.status': [TREND_STATUS.new, TREND_STATUS.resolved] } },
      ],
    },
  };
  const openFilter = a.severity?.length ? [{ terms: { 'vulnerability.severity': a.severity } }] : [];
  const byAgent = { terms: { field: 'agent.id', size: 1000 }, aggs: { name: { terms: { field: 'agent.name', size: 1 } } } };

  // Paged, so the indexer never has to build every bucket at once. Newest first: hitting the cap drops the oldest.
  const readEvents = async () => {
    const list: TrendBucket[] = [];
    const names = new Map<string, string | null>();
    let after: unknown;
    for (let page = 0; page < TREND_MAX_PAGES; page++) {
      const r = await client.search<SearchResponse>(client.cfg.alertsIndex, {
        size: 0,
        track_total_hits: false,
        query,
        aggs: {
          findings: {
            composite: {
              size: TREND_PAGE,
              sources: [
                { slot: { date_histogram: { field: 'timestamp', fixed_interval: '10m', order: 'desc' } } },
                { agent: { terms: { field: 'agent.id' } } },
                { cve: { terms: { field: 'data.vulnerability.cve' } } },
                { package: { terms: { field: 'data.vulnerability.package.name', missing_bucket: true } } },
                { status: { terms: { field: 'data.vulnerability.status' } } },
                { severity: { terms: { field: 'data.vulnerability.severity', missing_bucket: true } } },
              ],
              ...(after ? { after } : {}),
            },
          },
          ...(page === 0 ? { by_agent: byAgent } : {}),
        },
      });
      const agg = r.aggregations as unknown as { findings?: { buckets?: TrendBucket[]; after_key?: unknown }; by_agent?: { buckets?: AgentBucket[] } };
      for (const b of agg?.by_agent?.buckets ?? []) names.set(String(b.key), b.name?.buckets?.[0]?.key ?? null);
      const got = agg?.findings?.buckets ?? [];
      list.push(...got);
      after = agg?.findings?.after_key;
      if (got.length < TREND_PAGE || !after) return { list, names, truncated: false };
    }
    return { list, names, truncated: true };
  };

  // Alerts cover the time before the first snapshot, snapshots the time after it.
  const alertsUntil = history?.since ?? Infinity;
  const [events, open] = await Promise.all([
    from >= alertsUntil ? { list: [], names: new Map<string, string | null>(), truncated: false } : readEvents(),
    client.search<SearchResponse>(client.cfg.vulnerabilitiesIndex, {
      size: 0,
      track_total_hits: true,
      query: { bool: { filter: openFilter } },
      aggs: { by_agent: byAgent },
    }),
  ]);

  const findings = new Map<string, { active: TrendEvent[]; solved: TrendEvent[] }>();
  for (const { key: k, doc_count } of events.list) {
    const id = JSON.stringify([k.agent, k.cve, k.package]);
    let f = findings.get(id);
    if (!f) findings.set(id, (f = { active: [], solved: [] }));
    (k.status === TREND_STATUS.new ? f.active : f.solved).push({ agent: String(k.agent), severity: k.severity, slot: k.slot, count: doc_count });
  }

  const emptyDays = () => Array.from({ length: a.days }, (_, i) => ({ day: new Date(from + i * DAY_MS).toISOString().slice(0, 10), new: 0, resolved: 0 }));
  const wanted = (severity: string | null) => !a.severity?.length || (a.severity as string[]).includes(severity ?? '');
  const total = { new: 0, resolved: 0, redetected: 0 };
  const byDay = emptyDays();
  const agents = new Map<string, { agent_id: string; agent_name: string | null; open: number; new: number; resolved: number; redetected: number; net: number; days: ReturnType<typeof emptyDays> }>();
  const row = (id: string, name: string | null) => {
    let r = agents.get(id);
    if (!r) agents.set(id, (r = { agent_id: id, agent_name: name, open: 0, new: 0, resolved: 0, redetected: 0, net: 0, days: [] }));
    return r;
  };
  const add = (agent: string, i: number, kind: 'new' | 'resolved', n: number) => {
    const r = row(agent, events.names.get(agent) ?? null);
    if (!r.days.length) r.days = emptyDays();
    for (const d of [byDay[i], r.days[i]]) if (d) d[kind] += n;
    r[kind] += n;
    total[kind] += n;
  };
  for (const f of findings.values()) {
    const first = f.active[0] ?? f.solved[0]!;
    const shown = [...f.active, ...f.solved].some((e) => wanted(e.severity));
    const pairs = cancelPairs(f.active, f.solved);
    const beforeSnapshots = first.slot < alertsUntil;
    if (shown && pairs && beforeSnapshots) {
      total.redetected += pairs;
      row(first.agent, events.names.get(first.agent) ?? null).redetected += pairs;
    }
    for (const kind of ['new', 'resolved'] as const) {
      for (const e of kind === 'new' ? f.active : f.solved) {
        if (!e.count || !wanted(e.severity) || e.slot >= alertsUntil) continue;
        add(e.agent, Math.floor((e.slot - from) / DAY_MS), kind, e.count);
      }
    }
  }
  for (const c of history?.changes ?? []) {
    const i = Math.floor((Date.parse(c.day) - from) / DAY_MS);
    if (i < 0 || i >= a.days || !wanted(c.severity)) continue;
    if (c.new) add(c.agent, i, 'new', c.new);
    if (c.resolved) add(c.agent, i, 'resolved', c.resolved);
  }
  // Agents with open findings but no change in the window are steady, which is a trend too.
  for (const b of (open.aggregations?.by_agent?.buckets ?? []) as unknown as AgentBucket[]) {
    const name = b.name?.buckets?.[0]?.key ?? null;
    const r = row(String(b.key), name);
    r.open = b.doc_count;
    r.agent_name ??= name;
  }
  for (const r of agents.values()) r.net = r.new - r.resolved;
  return {
    days: a.days,
    open: totalHits(open),
    ...total,
    net: total.new - total.resolved,
    ...(events.truncated ? { truncated: true } : {}),
    // Before this time only alerts are known, which miss CVEs that appear through a feed update.
    snapshots_since: history ? new Date(history.since).toISOString() : null,
    by_day: byDay,
    // Growing backlogs first, then the most open findings.
    agents: [...agents.values()].sort((x, y) => y.net - x.net || y.open - x.open || x.agent_id.localeCompare(y.agent_id)).slice(0, a.top),
  };
}

export interface SearchAlertsInput {
  query?: string;
  since: string;
  until?: string;
  min_level?: number;
  agent_id?: string;
  rule_id?: string;
  rule_group?: string;
  limit: number;
}

/**
 * Lucene syntax that is expensive on the indexer is refused: regular
 * expressions, fuzzy and proximity matching, and many wildcards. Text in
 * double quotes is taken literally, so paths can be searched quoted.
 */
export function checkAlertQuery(q: string): void {
  const bare = q.replace(/\\./g, '').replace(/"[^"]*"/g, '""');
  if (bare.includes('/')) throw new BackendError('Query: put text containing "/" in double quotes; regular expressions are not supported');
  if (bare.includes('~')) throw new BackendError('Query: "~" (fuzzy and proximity search) is not supported; use quotes to search it literally');
  if ((bare.match(/[*?]/g) ?? []).length > 5) throw new BackendError('Query: at most 5 wildcards');
  if ((bare.match(/\(/g) ?? []).length > 10) throw new BackendError('Query: at most 10 groups');
}

export async function searchAlerts(client: WazuhClient, a: SearchAlertsInput) {
  const range: Record<string, string> = { gte: parseTime(a.since) };
  if (a.until) range.lte = parseTime(a.until);
  const filter: unknown[] = [{ range: { timestamp: range } }];
  if (a.min_level !== undefined) filter.push({ range: { 'rule.level': { gte: a.min_level } } });
  if (a.agent_id) filter.push({ term: { 'agent.id': normaliseAgentId(a.agent_id) } });
  if (a.rule_id) filter.push({ term: { 'rule.id': a.rule_id } });
  if (a.rule_group) filter.push({ term: { 'rule.groups': a.rule_group } });
  if (a.query) checkAlertQuery(a.query);
  const must = a.query
    ? [{ query_string: { query: a.query, default_operator: 'AND', allow_leading_wildcard: false, lenient: true, analyze_wildcard: false, max_determinized_states: 1000 } }]
    : [];
  const r = await client.search<SearchResponse & { timed_out?: boolean }>(client.cfg.alertsIndex, {
    size: a.limit,
    timeout: '15s',
    track_total_hits: true,
    _source: ALERT_SOURCE,
    query: { bool: { filter, must } },
    sort: [{ timestamp: { order: 'desc' } }],
    aggs: { by_level: { terms: { field: 'rule.level', size: 17 } } },
  });
  return {
    // Never let a search cut short look like a complete (or empty) answer.
    ...(r.timed_out ? { incomplete: 'The search timed out after 15 s; these are partial results. Narrow the time range or the query.' } : {}),
    matching: totalHits(r),
    returned: r.hits.hits.length,
    by_level: buckets(r, 'by_level'),
    alerts: r.hits.hits.map((h) => ({ id: h._id, ...h._source })),
  };
}

// ── Security configuration assessment (manager API) ─────────────────────────

export const SCA_RESULTS = ['passed', 'failed', 'not applicable'] as const;

const POLICY_ID = /^[A-Za-z0-9_.-]{1,128}$/;

export async function agentSca(client: WazuhClient, a: { agent_id: string; search?: string }) {
  const id = normaliseAgentId(a.agent_id);
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>(`/sca/${id}`, { search: a.search, limit: 100 });
  return {
    agent_id: id,
    total: r.data.total_affected_items,
    policies: r.data.affected_items.map((p) => ({
      policy_id: p.policy_id,
      name: p.name,
      score: p.score,
      pass: p.pass,
      fail: p.fail,
      invalid: p.invalid,
      total_checks: p.total_checks,
      end_scan: p.end_scan,
    })),
  };
}

export interface ScaChecksInput {
  agent_id: string;
  policy_id: string;
  result?: (typeof SCA_RESULTS)[number];
  search?: string;
  limit: number;
  offset: number;
}

const SCA_CHECK_FIELDS = ['id', 'title', 'result', 'reason', 'description', 'rationale', 'remediation', 'compliance', 'file', 'command'];

export async function scaChecks(client: WazuhClient, a: ScaChecksInput) {
  const id = normaliseAgentId(a.agent_id);
  if (!POLICY_ID.test(a.policy_id)) throw new BackendError(`Invalid policy id "${a.policy_id}"`);
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>(
    `/sca/${id}/checks/${encodeURIComponent(a.policy_id)}`,
    { result: a.result, search: a.search, limit: a.limit, offset: a.offset, sort: '+id' },
  );
  return {
    agent_id: id,
    policy_id: a.policy_id,
    total: r.data.total_affected_items,
    returned: r.data.affected_items.length,
    offset: a.offset,
    checks: r.data.affected_items.map((c) => Object.fromEntries(SCA_CHECK_FIELDS.filter((k) => c[k] !== undefined).map((k) => [k, c[k]]))),
  };
}

// ── Syscollector inventory (manager API) ─────────────────────────────────────

/** Inventory kinds that are a single object per agent (no paging parameters). */
const INVENTORY_SINGLE = ['os', 'hardware'] as const;
/** Inventory kinds that are lists and accept search, sort and paging. */
const INVENTORY_LIST = ['packages', 'processes', 'ports', 'netaddr', 'netiface', 'netproto', 'hotfixes'] as const;
export const INVENTORY_KINDS = [...INVENTORY_SINGLE, ...INVENTORY_LIST] as const;
export type InventoryKind = (typeof INVENTORY_KINDS)[number];

export interface InventoryInput {
  agent_id: string;
  kind: InventoryKind;
  search?: string;
  limit: number;
  offset: number;
}

export async function agentInventory(client: WazuhClient, a: InventoryInput) {
  const id = normaliseAgentId(a.agent_id);
  if (!(INVENTORY_KINDS as readonly string[]).includes(a.kind)) throw new BackendError(`Unknown inventory kind "${a.kind}"`);
  const single = (INVENTORY_SINGLE as readonly string[]).includes(a.kind);
  // The manager rejects unknown query parameters, so os/hardware get none.
  const query = single ? undefined : { search: a.search, limit: a.limit, offset: a.offset };
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>(`/syscollector/${id}/${a.kind}`, query);
  const items = r.data.affected_items.map(({ agent_id: _a, ...rest }) => rest);
  return single
    ? { agent_id: id, kind: a.kind, [a.kind]: items[0] ?? null }
    : { agent_id: id, kind: a.kind, total: r.data.total_affected_items, returned: items.length, offset: a.offset, items };
}

// ── Rules (manager API) ──────────────────────────────────────────────────────

export async function getRules(client: WazuhClient, ruleIds: string[]) {
  const ids = ruleIds.map((r) => r.trim());
  for (const r of ids) if (!/^\d{1,7}$/.test(r)) throw new BackendError(`Invalid rule id "${r}": expected digits, e.g. 5710`);
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>('/rules', { rule_ids: ids.join(','), limit: ids.length });
  const found = r.data.affected_items;
  const missing = ids.filter((i) => !found.some((f) => String(f.id) === String(Number(i))));
  return { rules: found, ...(missing.length ? { not_found: missing } : {}) };
}

// ── File integrity monitoring events (indexer) ───────────────────────────────

export const FIM_EVENTS = ['added', 'modified', 'deleted'] as const;

const FIM_SOURCE = [
  'timestamp',
  'agent.id',
  'agent.name',
  'rule.id',
  'rule.level',
  'rule.description',
  'syscheck.path',
  'syscheck.event',
  'syscheck.mode',
  'syscheck.changed_attributes',
  'syscheck.size_before',
  'syscheck.size_after',
  'syscheck.perm_after',
  'syscheck.uname_after',
  'syscheck.gname_after',
  'syscheck.mtime_after',
  'syscheck.sha256_after',
  'syscheck.diff',
  'syscheck.audit.user.name',
  'syscheck.audit.process.name',
  'syscheck.value_name',
];

export interface FimEventsInput {
  agent_id?: string;
  path?: string;
  event?: (typeof FIM_EVENTS)[number][];
  since: string;
  until?: string;
  limit: number;
}

export async function fimEvents(client: WazuhClient, a: FimEventsInput) {
  const range: Record<string, string> = { gte: parseTime(a.since) };
  if (a.until) range.lte = parseTime(a.until);
  const filter: unknown[] = [{ range: { timestamp: range } }, { term: { 'rule.groups': 'syscheck' } }];
  if (a.agent_id) filter.push({ term: { 'agent.id': normaliseAgentId(a.agent_id) } });
  if (a.event?.length) filter.push({ terms: { 'syscheck.event': a.event } });
  if (a.path) {
    // A trailing * means "this directory and below"; otherwise an exact path.
    const p = a.path.trim();
    filter.push(p.endsWith('*') ? { prefix: { 'syscheck.path': p.slice(0, -1) } } : { term: { 'syscheck.path': p } });
  }
  const r = await client.search<SearchResponse>(client.cfg.alertsIndex, {
    size: a.limit,
    track_total_hits: true,
    _source: FIM_SOURCE,
    query: { bool: { filter } },
    sort: [{ timestamp: { order: 'desc' } }],
    aggs: {
      by_event: { terms: { field: 'syscheck.event', size: 5 } },
      by_agent: { terms: { field: 'agent.name', size: 10 } },
      top_paths: { terms: { field: 'syscheck.path', size: 10 } },
    },
  });
  return {
    matching: totalHits(r),
    returned: r.hits.hits.length,
    by_event: buckets(r, 'by_event'),
    by_agent: buckets(r, 'by_agent'),
    top_paths: buckets(r, 'top_paths'),
    events: r.hits.hits.map((h) => ({ id: h._id, ...h._source })),
  };
}

// ── Single alert (indexer) ───────────────────────────────────────────────────

const ALERT_ID = /^[A-Za-z0-9_-]{1,128}$/;

export async function getAlert(client: WazuhClient, alertId: string) {
  const v = alertId.trim();
  if (!ALERT_ID.test(v)) throw new BackendError(`Invalid alert id "${alertId}"`);
  // The alerts index is a pattern, so look the document up by _id across it.
  const r = await client.search<SearchResponse>(client.cfg.alertsIndex, { size: 1, query: { ids: { values: [v] } } });
  const hit = r.hits.hits[0];
  return hit ? { id: hit._id, index: hit._index, alert: hit._source } : null;
}

// ── Agent groups (manager API) ───────────────────────────────────────────────

export async function listGroups(client: WazuhClient, a: { search?: string; limit: number; offset: number }) {
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>('/groups', {
    search: a.search,
    limit: a.limit,
    offset: a.offset,
    sort: '+name',
  });
  return {
    total: r.data.total_affected_items,
    returned: r.data.affected_items.length,
    offset: a.offset,
    groups: r.data.affected_items.map((g) => ({ name: g.name, count: g.count, configSum: g.configSum, mergedSum: g.mergedSum })),
  };
}

// ── Decoders (manager API) ───────────────────────────────────────────────────

export async function listDecoders(client: WazuhClient, a: { names?: string[]; search?: string; limit: number; offset: number }) {
  const names = (a.names ?? []).map((n) => n.trim());
  for (const n of names) if (!/^[A-Za-z0-9_.-]{1,128}$/.test(n)) throw new BackendError(`Invalid decoder name "${n}"`);
  const r = await client.api<WazuhListResponse<Record<string, unknown>>>('/decoders', {
    decoder_names: names.length ? names.join(',') : undefined,
    search: a.search,
    limit: a.limit,
    offset: a.offset,
  });
  return {
    total: r.data.total_affected_items,
    returned: r.data.affected_items.length,
    offset: a.offset,
    // One decoder name can have several entries (parent and children), one per file position.
    decoders: r.data.affected_items.map((d) => ({
      name: d.name,
      position: d.position,
      filename: d.filename,
      relative_dirname: d.relative_dirname,
      status: d.status,
      details: d.details,
    })),
  };
}

// ── FIM state (manager API) ──────────────────────────────────────────────────

export const FIM_TYPES = ['file', 'registry_key', 'registry_value'] as const;

export interface FimFilesInput {
  agent_id: string;
  file?: string;
  search?: string;
  type?: (typeof FIM_TYPES)[number];
  hash?: string;
  limit: number;
  offset: number;
}

/**
 * The files (and Windows registry entries) the FIM database currently holds
 * for an agent, with their last known attributes, plus when the last scan ran.
 */
export async function fimFiles(client: WazuhClient, a: FimFilesInput) {
  const id = normaliseAgentId(a.agent_id);
  const hash = a.hash?.trim().toLowerCase();
  if (hash && !/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(hash)) throw new BackendError('hash must be an MD5, SHA-1 or SHA-256 hex digest');
  const [r, scan] = await Promise.all([
    client.api<WazuhListResponse<Record<string, unknown>>>(`/syscheck/${id}`, {
      file: a.file,
      search: a.search,
      type: a.type,
      hash,
      limit: a.limit,
      offset: a.offset,
    }),
    client
      .api<WazuhListResponse<{ start?: string; end?: string }>>(`/syscheck/${id}/last_scan`)
      .then((s) => s.data.affected_items[0] ?? null)
      .catch(() => null),
  ]);
  return {
    agent_id: id,
    last_scan: scan,
    total: r.data.total_affected_items,
    returned: r.data.affected_items.length,
    offset: a.offset,
    entries: r.data.affected_items,
  };
}

// ── CVE inventory for cross-backend tools (intel) ───────────────────────────

/** Documents per page when reading the whole vulnerability state index. */
const CVE_PAGE = 5000;
/** Stop after this many documents; the result says it was cut short. */
export const MAX_CVE_DOCS = 100_000;

interface CveDoc {
  agent?: { id?: string; name?: string };
  package?: { name?: string; version?: string };
  vulnerability?: { id?: string; severity?: string; score?: { base?: number } };
}

/**
 * Every open CVE on every agent, from `wazuh-states-vulnerabilities-*`, as
 * occurrences for the intel module. Paged with `search_after` on
 * (agent, CVE, package, version): documents that tie on all four describe
 * the same occurrence, so a tie skipped between pages loses nothing.
 */
export async function cveOccurrences(client: WazuhClient, max = MAX_CVE_DOCS): Promise<CveInventory> {
  const occurrences: CveOccurrence[] = [];
  let after: unknown[] | undefined;
  let docs = 0;
  for (;;) {
    const size = Math.min(CVE_PAGE, max - docs);
    const r = await client.search<SearchResponse<CveDoc> & { hits: { hits: { sort?: unknown[] }[] } }>(client.cfg.vulnerabilitiesIndex, {
      size,
      track_total_hits: false,
      _source: ['agent.id', 'agent.name', 'package.name', 'package.version', 'vulnerability.id', 'vulnerability.severity', 'vulnerability.score.base'],
      query: { bool: { filter: [{ prefix: { 'vulnerability.id': 'CVE-' } }] } },
      sort: [{ 'agent.id': 'asc' }, { 'vulnerability.id': 'asc' }, { 'package.name': 'asc' }, { 'package.version': 'asc' }],
      ...(after ? { search_after: after } : {}),
    });
    const hits = r.hits.hits;
    docs += hits.length;
    for (const h of hits) {
      const s = h._source;
      const cve = normaliseCve(s.vulnerability?.id);
      if (!cve) continue;
      const score = s.vulnerability?.score?.base;
      occurrences.push({
        cve,
        source: 'wazuh',
        asset: s.agent?.name ?? s.agent?.id ?? 'unknown agent',
        ...(s.agent?.id ? { ref: s.agent.id } : {}),
        ...(s.package?.name ? { package: s.package.name } : {}),
        ...(s.package?.version ? { installed: s.package.version } : {}),
        severity: normaliseSeverity(s.vulnerability?.severity),
        ...(typeof score === 'number' && score > 0 ? { cvss: score } : {}),
      });
    }
    const last = hits[hits.length - 1];
    if (hits.length < size || !last?.sort) return { occurrences };
    if (docs >= max) return { occurrences, truncated: `Wazuh: stopped after ${max} vulnerability documents` };
    after = last.sort;
  }
}
