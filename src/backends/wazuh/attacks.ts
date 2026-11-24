import { attackWindow, HOUR, iso, reachesBack, type AttackRange } from '../attack-window.js';
import { cvesIn } from '../cve.js';
import { BackendError } from '../http.js';
import { buckets, totalHits, type SearchResponse, type WazuhClient } from './client.js';

/**
 * Attacks over time, from Wazuh alerts. Alerts are sorted into categories by
 * rule group. The order matters: an alert belongs to the first category that
 * matches, so no alert is counted twice. Mere membership of a service group
 * (e.g. dovecot) is not enough; that would also count normal sessions.
 *
 * The catch-all categories are split further by the service each alert's rule
 * names, so a service nobody listed here gets its own chart when it is attacked.
 */

interface CategoryDef {
  id: string;
  title: string;
  description: string;
  match: ReturnType<typeof groups>[];
  /** Set on a catch-all: the title of one service found in it. */
  split?: (service: string) => string;
}

const groups = (...names: string[]) => ({ terms: { 'rule.groups': names } });
/** Wazuh's correlation of repeated failures; it replaces the alert of the attempt that triggered it. */
const BRUTE_FORCE = groups('authentication_failures');
const FAILED_LOGIN = groups('authentication_failed', 'invalid_login', 'win_authentication_failed', 'authentication_failures');
const WEB = groups('web', 'accesslog', 'nginx', 'apache');

const CATEGORIES: CategoryDef[] = [
  { id: 'ssh', title: 'SSH login', description: 'Failed SSH logins and unknown users', match: [groups('sshd'), FAILED_LOGIN] },
  {
    id: 'smtp',
    title: 'SMTP login',
    description: 'Failed logins to the mail server for sending',
    match: [groups('poste', 'postfix', 'sendmail', 'exim', 'smtpd', 'smtp'), FAILED_LOGIN],
  },
  {
    id: 'imap',
    title: 'IMAP/POP3 login',
    description: 'Failed mailbox logins',
    match: [groups('dovecot', 'courier', 'imapd', 'vpopmail', 'cyrus'), FAILED_LOGIN],
  },
  {
    id: 'ftp',
    title: 'FTP login',
    description: 'Failed and denied FTP logins',
    match: [groups('ftp', 'ftpd', 'vsftpd', 'proftpd', 'pure-ftpd', 'pureftpd', 'msftp'), groups(...FAILED_LOGIN.terms['rule.groups'], 'access_denied')],
  },
  {
    id: 'other_login',
    title: 'Other logins',
    description: 'Failed logins to any other service',
    match: [FAILED_LOGIN],
    split: (service) => `${service} login`,
  },
  {
    id: 'web',
    title: 'Web attacks',
    description: 'Attack patterns and scans in web server logs',
    match: [WEB, groups('attack', 'web_attack', 'web_scan', 'recon', 'sqlinjection', 'sql_injection', 'appsec')],
  },
  {
    id: 'scan',
    title: 'Scans and IDS',
    description: 'Port scans, intrusion detection and firewall drops seen by Wazuh',
    match: [groups('recon', 'portscan', 'ids', 'suricata', 'snort', 'firewall_drop', 'multiple_drops')],
  },
  {
    id: 'other_attack',
    title: 'Other attacks',
    description: 'Attacks and exploit attempts against any other service',
    match: [groups('attack', 'attacks', 'exploit_attempt')],
    split: (service) => `${service} attacks`,
  },
];

/** Categories about logging in: an alert concerns one service on the host, not all of them. */
export const LOGIN_CATEGORIES: ReadonlySet<string> = new Set(CATEGORIES.filter((c) => /logins?$/i.test(c.title)).map((c) => c.id));

/** Groups that say what happened or where the rule came from, not which service was attacked. */
const GENERIC_GROUPS = new Set([
  ...CATEGORIES.flatMap((c) => (c.split ? c.match.flatMap((m) => m.terms['rule.groups']) : [])),
  'syslog', 'local', 'custom', 'linux', 'unix', 'authentication', 'authentication_success', 'access_denied', 'access_control',
  'login_denied', 'login_failed', 'failed_login', 'account_locked', 'connection_attempt', 'errors', 'system_error', 'service_availability',
  'policy_violation', 'policy_changed', 'automatic_attack', 'web', 'accesslog', 'windows_security', 'json', 'adduser',
]);
const COMPLIANCE = /^(pci_dss|gdpr|gpg13|hipaa|nist|tsc|mitre|cis)(_|$)/;
const SERVICE_NAMES: Record<string, string> = {
  pam: 'PAM', su: 'su', sudo: 'sudo', rdp: 'RDP', mysql_log: 'MySQL', postgresql_log: 'PostgreSQL', mssql: 'MS SQL', mongodb: 'MongoDB',
  wordpress: 'WordPress', openvpn: 'OpenVPN', vpn: 'VPN', smbd: 'Samba', vnc: 'VNC', office365: 'Office 365', github: 'GitHub', aws: 'AWS', gcp: 'Google Cloud',
};

/** The service a rule is about: its first group that is not generic. Depends on the rule alone, so every view agrees. */
function serviceOf(ruleGroups: string[]): string | undefined {
  return ruleGroups.find((g) => g.length <= 64 && !GENERIC_GROUPS.has(g) && !COMPLIANCE.test(g));
}

interface Category {
  id: string;
  title: string;
  description: string;
  query: unknown;
}

function serviceCategory(base: CategoryDef, service: string) {
  const name = SERVICE_NAMES[service] ?? service.charAt(0).toUpperCase() + service.slice(1).replace(/[_-]+/g, ' ');
  return { id: `${base.id}:${service}`, title: base.split!(name), description: `${base.title} that Wazuh attributes to ${name} (rule group ${service})` };
}

/** A listed category, or one service in a catch-all: "other_login:pam". */
export function isAttackCategory(id: string): boolean {
  const i = id.indexOf(':');
  if (i < 0) return CATEGORIES.some((c) => c.id === id);
  return id.length <= 100 && i < id.length - 1 && CATEGORIES.some((c) => c.split && c.id === id.slice(0, i));
}

/** The categories for a time range: the listed ones, each catch-all preceded by the services found in it. */
async function findCategories(client: WazuhClient, range: unknown): Promise<Category[]> {
  const split = CATEGORIES.filter((c) => c.split);
  const r = await client.search<SearchResponse>(client.cfg.alertsIndex, {
    size: 0,
    query: { bool: { filter: [range, anyCategory()] } },
    aggs: {
      services: {
        filters: { filters: Object.fromEntries(split.map((c) => [c.id, categoryQuery(c.id)])) },
        aggs: {
          rules: {
            terms: { field: 'rule.id', size: 1000 },
            // The group list of one alert, because an aggregation on groups loses their order.
            aggs: { newest: { top_hits: { size: 1, sort: [{ timestamp: { order: 'desc' } }], _source: ['rule.groups'] } } },
          },
        },
      },
    },
  });
  interface RuleBucket { key: string; newest?: { hits?: { hits?: { _source?: { rule?: { groups?: string[] } } }[] } } }
  const found = (r.aggregations as unknown as { services?: { buckets?: Record<string, { rules?: { buckets?: RuleBucket[] } }> } } | undefined)?.services?.buckets;

  return CATEGORIES.flatMap((c) => {
    const own = { id: c.id, title: c.title, description: c.description };
    const base = categoryQuery(c.id);
    const services = new Map<string, string[]>();
    for (const b of found?.[c.id]?.rules?.buckets ?? []) {
      const service = serviceOf(b.newest?.hits?.hits?.[0]?._source?.rule?.groups ?? []);
      if (service) services.set(service, [...(services.get(service) ?? []), b.key]);
    }
    if (!services.size) return [{ ...own, query: base }];
    const rules = (ids: string[]) => ({ terms: { 'rule.id': ids } });
    return [
      ...[...services].map(([service, ids]) => ({ ...serviceCategory(c, service), query: { bool: { ...base.bool, filter: [...base.bool.filter, rules(ids)] } } })),
      { ...own, query: { bool: { ...base.bool, must_not: [...base.bool.must_not, rules([...services.values()].flat())] } } },
    ];
  });
}

/** Cardinality counts are exact up to this many distinct addresses. */
const PRECISION = 10_000;
const UNIQUE_IPS = { cardinality: { field: 'data.srcip', precision_threshold: PRECISION } };

function categoryQuery(id: string) {
  const i = CATEGORIES.findIndex((c) => c.id === id);
  if (i < 0) throw new BackendError(`Unknown attack category "${id}"`);
  return { bool: { filter: CATEGORIES[i]!.match, must_not: CATEGORIES.slice(0, i).map((c) => ({ bool: { filter: c.match } })) } };
}

function anyCategory() {
  return { bool: { should: CATEGORIES.map((c) => ({ bool: { filter: c.match } })), minimum_should_match: 1 } };
}

interface Counted {
  doc_count: number;
  brute?: { doc_count: number };
  ips?: { value: number };
}
interface CategoryBucket extends Counted {
  by_time?: { buckets?: ({ key: number } & Counted)[] };
}
interface TrendAggs {
  current?: { categories?: { buckets?: Record<string, CategoryBucket> } } & Counted;
  previous?: { categories?: { buckets?: Record<string, Counted> } };
}

const brute = (b: Counted | undefined) => ({ brute_force: b?.brute?.doc_count ?? 0 });
const counts = (b: Counted | undefined) => ({ attempts: b?.doc_count ?? 0, unique_ips: b?.ips?.value ?? 0 });

export async function attackTrend(client: WazuhClient, a: AttackRange, now = Date.now()) {
  const { step, columns, from, to, gridFrom, previousFrom } = attackWindow(a, now);
  const range = (gte: number, end: Record<string, string>) => ({ range: { timestamp: { gte: iso(gte), ...end } } });
  const defs = await findCategories(client, range(previousFrom, { lt: iso(to) }));
  const filters = Object.fromEntries(defs.map((c) => [c.id, c.query]));

  const [r, oldest] = await Promise.all([
    client.search<SearchResponse>(client.cfg.alertsIndex, {
      size: 0,
      query: { bool: { filter: [range(previousFrom, { lt: iso(to) }), anyCategory()] } },
      aggs: {
        current: {
          filter: range(from, { lt: iso(to) }),
          aggs: {
            ips: UNIQUE_IPS,
            categories: {
              filters: { filters },
              aggs: {
                ips: UNIQUE_IPS,
                brute: { filter: BRUTE_FORCE },
                by_time: {
                  date_histogram: {
                    field: 'timestamp',
                    fixed_interval: `${step / HOUR}h`,
                    min_doc_count: 0,
                    extended_bounds: { min: gridFrom, max: to - 1 },
                  },
                  aggs: { ips: UNIQUE_IPS, brute: { filter: BRUTE_FORCE } },
                },
              },
            },
          },
        },
        previous: {
          filter: range(previousFrom, { lt: iso(from) }),
          aggs: { categories: { filters: { filters }, aggs: { ips: UNIQUE_IPS } } },
        },
      },
    }),
    // How far back the alerts go: before that a chart is empty and a comparison would mislead.
    client.search<SearchResponse>(client.cfg.alertsIndex, { size: 0, aggs: { oldest: { min: { field: 'timestamp' } } } }),
  ]);

  const aggs = r.aggregations as unknown as TrendAggs | undefined;
  const dataFrom = (oldest.aggregations as unknown as { oldest?: { value: number | null } } | undefined)?.oldest?.value ?? null;
  const comparable = reachesBack(dataFrom, previousFrom, step);
  const categories = defs.map((c) => {
    const cur = aggs?.current?.categories?.buckets?.[c.id];
    const byTime = new Map((cur?.by_time?.buckets ?? []).map((b) => [b.key, b]));
    return {
      id: c.id,
      title: c.title,
      description: c.description,
      ...counts(cur),
      ...brute(cur),
      previous: comparable ? counts(aggs?.previous?.categories?.buckets?.[c.id]) : null,
      points: Array.from({ length: columns }, (_, i) => {
        const b = byTime.get(gridFrom + i * step);
        return { ...counts(b), ...brute(b) };
      }),
    };
  });
  return {
    from: iso(from),
    to: iso(to),
    columns_from: iso(gridFrom),
    data_from: dataFrom === null ? null : iso(dataFrom),
    step_seconds: step / 1000,
    attempts: categories.reduce((n, c) => n + c.attempts, 0),
    unique_ips: aggs?.current?.ips?.value ?? 0,
    categories,
  };
}

export interface AttackDetailsInput {
  category: string;
  from: string;
  to: string;
  top: number;
  limit: number;
}

/** Who and what is behind one category in a time range (from inclusive, to exclusive). */
export async function attackDetails(client: WazuhClient, a: AttackDetailsInput) {
  const from = Date.parse(a.from);
  const to = Date.parse(a.to);
  if (Number.isNaN(from) || Number.isNaN(to) || from >= to) throw new BackendError('Invalid time range: from must be before to');
  if (!isAttackCategory(a.category)) throw new BackendError(`Unknown attack category "${a.category}"`);
  const range = { range: { timestamp: { gte: iso(from), lt: iso(to) } } };
  // A service without alerts in this range is not found: nothing matches.
  const query = (await findCategories(client, range)).find((c) => c.id === a.category)?.query ?? { match_none: {} };
  const top = (field: string) => ({ terms: { field, size: a.top } });
  const r = await client.search<SearchResponse>(client.cfg.alertsIndex, {
    size: a.limit,
    track_total_hits: true,
    _source: ['timestamp', 'agent.id', 'agent.name', 'rule.id', 'rule.level', 'rule.description', 'data.srcip', 'data.srcuser', 'data.dstuser', 'GeoLocation.country_name'],
    query: { bool: { filter: [range, query] } },
    sort: [{ timestamp: { order: 'desc' } }],
    aggs: {
      ips: UNIQUE_IPS,
      by_ip: top('data.srcip'),
      by_country: top('GeoLocation.country_name'),
      // sshd puts the attempted user in srcuser, most other decoders in dstuser.
      by_dstuser: top('data.dstuser'),
      by_srcuser: top('data.srcuser'),
      by_agent: top('agent.name'),
      by_rule: top('rule.description'),
    },
  });
  const list = (name: string) => Object.entries(buckets(r, name)).map(([key, count]) => ({ key, count }));
  const users = new Map<string, number>();
  for (const { key, count } of [...list('by_dstuser'), ...list('by_srcuser')]) users.set(key, (users.get(key) ?? 0) + count);
  const ranked = (xs: { key: string; count: number }[]) => xs.sort((x, y) => y.count - x.count).slice(0, a.top);
  return {
    category: a.category,
    from: iso(from),
    to: iso(to),
    attempts: totalHits(r),
    unique_ips: (r.aggregations as unknown as { ips?: { value: number } } | undefined)?.ips?.value ?? 0,
    // buckets() keys an object, which reorders number-like keys, so rank again.
    top_ips: ranked(list('by_ip')),
    top_countries: ranked(list('by_country')),
    top_users: ranked([...users].map(([key, count]) => ({ key, count }))),
    top_agents: ranked(list('by_agent')),
    top_rules: ranked(list('by_rule')),
    alerts: r.hits.hits.map((h) => ({ id: h._id, ...h._source })),
  };
}

/** Enough for a week of ordinary background noise; more would make the page slow to load. */
const MAP_LIMIT = 8000;

/** Same rules as the queries, for one alert. */
function categoryOf(ruleGroups: string[]): { id: string; title: string } {
  const c = CATEGORIES.find((x) => x.match.every((m) => m.terms['rule.groups'].some((g) => ruleGroups.includes(g)))) ?? CATEGORIES.find((x) => x.id === 'other_login')!;
  const service = c.split && serviceOf(ruleGroups);
  const { id, title } = service ? serviceCategory(c, service) : c;
  return { id, title };
}

const order = (id: string) => CATEGORIES.findIndex((c) => c.id === id.split(':')[0]);

interface MapSource {
  timestamp: string;
  agent?: { name?: string };
  rule?: { groups?: string[] };
  data?: { srcip?: string };
  GeoLocation?: { country_name?: string; location?: { lat?: unknown; lon?: unknown } };
}

/**
 * Attack alerts with the coordinates Wazuh's GeoIP lookup gave the source, newest
 * `MAP_LIMIT` of them, for the map. Alerts without a location are only counted.
 */
export async function attackMap(client: WazuhClient, a: { since: string }) {
  const since = Date.parse(a.since);
  if (Number.isNaN(since)) throw new BackendError('Invalid start time');
  const r = await client.search<SearchResponse<MapSource>>(client.cfg.alertsIndex, {
    size: MAP_LIMIT,
    track_total_hits: true,
    _source: ['timestamp', 'agent.name', 'rule.groups', 'data.srcip', 'GeoLocation.country_name', 'GeoLocation.location'],
    query: { bool: { filter: [{ range: { timestamp: { gte: iso(since) } } }, anyCategory()] } },
    sort: [{ timestamp: { order: 'desc' } }],
  });
  const total = totalHits(r as unknown as SearchResponse);
  const seen = new Map<string, string>();
  const events = r.hits.hits.flatMap((h) => {
    const x = h._source;
    const { lat, lon } = x.GeoLocation?.location ?? {};
    if (typeof lat !== 'number' || typeof lon !== 'number' || Math.abs(lat) > 90 || Math.abs(lon) > 180) return [];
    const category = categoryOf(x.rule?.groups ?? []);
    seen.set(category.id, category.title);
    return [{
      id: h._id,
      at: Date.parse(x.timestamp),
      category: category.id,
      ip: x.data?.srcip ?? null,
      country: x.GeoLocation?.country_name ?? null,
      lat,
      lon,
      agent: x.agent?.name ?? null,
    }];
  });
  return {
    since: iso(since),
    total,
    // Older alerts than this were cut off.
    complete_from: total > r.hits.hits.length ? (r.hits.hits.at(-1)?._source.timestamp ?? null) : iso(since),
    without_location: r.hits.hits.length - events.length,
    targets: client.cfg.mapTargets ?? [],
    // Only what is on the map, listed categories first and in their usual order.
    categories: [...seen].map(([id, title]) => ({ id, title })).sort((x, y) => order(x.id) - order(y.id) || (x.title < y.title ? -1 : 1)),
    events: events.reverse(),
  };
}

export interface MapTarget {
  /** Agent name; null is the default for every agent without its own. */
  agent: string | null;
  lat: number;
  lon: number;
}

/** "59.33,18.07; mailserver=55.60,13.00" — null when malformed. */
export function parseMapTargets(text: string): MapTarget[] | null {
  const out: MapTarget[] = [];
  for (const part of text.split(/[;\n]/).map((p) => p.trim()).filter(Boolean)) {
    const m = /^(?:([^=]{1,128})=)?\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)$/.exec(part);
    const lat = Number(m?.[2]);
    const lon = Number(m?.[3]);
    if (!m || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
    out.push({ agent: m[1]?.trim() || null, lat, lon });
  }
  return out;
}

/** Sources that cannot be an attacker on the internet: private, loopback, link-local and shared addresses. */
const PRIVATE_PREFIXES = ['0.', '10.', '127.', '169.254.', '192.168.', '::1', 'fe80:', 'fc', 'fd', '::ffff:'].concat(
  Array.from({ length: 16 }, (_, i) => `172.${16 + i}.`),
  Array.from({ length: 64 }, (_, i) => `100.${64 + i}.`),
);
const PUBLIC_SOURCE = {
  bool: {
    filter: [{ exists: { field: 'data.srcip' } }],
    must_not: PRIVATE_PREFIXES.map((p) => ({ prefix: { 'data.srcip': p } })),
  },
};
const MAX_AGENTS = 1000;

export interface AgentAttack {
  agent: string;
  category: string;
  title: string;
  /** Alerts with a public source address. */
  attempts: number;
  /** Alerts without one (local users, or a proxy or NAT that hides the source). */
  other_source: number;
  unique_ips: number;
  first_seen?: string;
  last_seen?: string;
  /** CVEs named by the rules that fired. */
  cves: string[];
  alert_ids: string[];
}

interface AgentAggs {
  by_agent?: {
    sum_other_doc_count?: number;
    buckets: {
      key: string;
      categories: {
        buckets: Record<
          string,
          {
            doc_count: number;
            public: {
              doc_count: number;
              ips?: { value: number };
              first?: { value: number | null };
              last?: { value: number | null };
              rules?: { buckets: { key: string }[] };
              rule_cves?: { buckets: { key: string }[] };
              latest?: { hits: { hits: { _id: string }[] } };
            };
          }
        >;
      };
    }[];
  };
}

/** Attack alerts per agent and category, for joining with the service map. */
export async function attacksByAgent(client: WazuhClient, a: { from: number; to: number }) {
  const r = await client.search<SearchResponse>(client.cfg.alertsIndex, {
    size: 0,
    query: { bool: { filter: [{ range: { timestamp: { gte: iso(a.from), lt: iso(a.to) } } }, anyCategory()] } },
    aggs: {
      by_agent: {
        terms: { field: 'agent.id', size: MAX_AGENTS },
        aggs: {
          categories: {
            filters: { filters: Object.fromEntries(CATEGORIES.map((c) => [c.id, categoryQuery(c.id)])) },
            aggs: {
              public: {
                filter: PUBLIC_SOURCE,
                aggs: {
                  ips: UNIQUE_IPS,
                  first: { min: { field: 'timestamp' } },
                  last: { max: { field: 'timestamp' } },
                  rules: { terms: { field: 'rule.description', size: 100 } },
                  rule_cves: { terms: { field: 'rule.cve', size: 50 } },
                  latest: { top_hits: { size: 3, sort: [{ timestamp: { order: 'desc' } }], _source: false } },
                },
              },
            },
          },
        },
      },
    },
  });
  const agg = (r.aggregations as unknown as AgentAggs | undefined)?.by_agent;
  const at = (v: number | null | undefined) => (typeof v === 'number' ? iso(v) : undefined);
  const attacks: AgentAttack[] = [];
  for (const b of agg?.buckets ?? []) {
    for (const c of CATEGORIES) {
      const x = b.categories.buckets[c.id];
      if (!x?.doc_count) continue;
      const texts = [...(x.public.rules?.buckets ?? []), ...(x.public.rule_cves?.buckets ?? [])].map((t) => t.key);
      const first = at(x.public.first?.value);
      const last = at(x.public.last?.value);
      attacks.push({
        agent: b.key,
        category: c.id,
        title: c.title,
        attempts: x.public.doc_count,
        other_source: x.doc_count - x.public.doc_count,
        unique_ips: x.public.ips?.value ?? 0,
        ...(first ? { first_seen: first } : {}),
        ...(last ? { last_seen: last } : {}),
        cves: cvesIn(texts),
        alert_ids: (x.public.latest?.hits.hits ?? []).map((h) => h._id),
      });
    }
  }
  return { attacks, truncated: (agg?.sum_other_doc_count ?? 0) > 0 };
}
