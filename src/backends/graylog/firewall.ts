import { attackWindow, DAY, HOUR, iso, reachesBack, type AttackRange } from '../attack-window.js';
import { cvesIn } from '../cve.js';
import { BackendError } from '../http.js';
import type { GeoLookup } from '../../geoip.js';
import { searchMessages, type GraylogRuntime } from './queries.js';

/**
 * Attacks seen at the network edge, from firewall and IPS logs in Graylog.
 * Uses the scripting API's aggregation (`POST /api/search/aggregate`), a read.
 * Expects the parsed fields src_ip, dst_ip and dst_port on the messages.
 */

export const DEFAULT_FIREWALL_QUERY = 'fw_action:drop AND fw_chain:WAN_LOCAL';
export const DEFAULT_IPS_QUERY = 'name:"Threat Detected and Blocked"';

export interface FirewallRuntime extends GraylogRuntime {
  firewallQuery: string;
  ipsQuery: string;
}

/** A source that tries this many different ports within the period counts as a scanner. */
export const SCAN_PORTS = 10;
/**
 * Counting distinct ports costs OpenSearch a fixed amount of memory per source
 * (kilobytes each), so it is done once, for the sources blocked most, and never
 * per source and column. Sorting by the number of ports is avoided for the same
 * reason: it would count ports for every address before picking the top.
 */
const SCAN_SOURCES = 300;
/** A port with more than this share of all blocks is background noise (often peer-to-peer). */
const NOISY_SHARE = 0.05;

const CATEGORIES = [
  { id: 'port_scan', title: 'Port scans', description: `Sources that tried ${SCAN_PORTS} or more ports in the period, among the ${SCAN_SOURCES} blocked most` },
  { id: 'firewall', title: 'Firewall blocks', description: 'Traffic from the internet that the firewall dropped' },
  { id: 'ips', title: 'IPS blocks', description: 'Attack signatures blocked by intrusion prevention' },
] as const;
export const FIREWALL_CATEGORIES = CATEGORIES.map((c) => c.id) as ['port_scan', 'firewall', 'ips'];
export type FirewallCategory = (typeof FIREWALL_CATEGORIES)[number];

interface Grouping {
  field: string;
  limit?: number;
  timeunit?: string;
}
interface Metric {
  function: 'count' | 'card';
  field?: string;
}

const COUNT: Metric = { function: 'count' };
const UNIQUE_IPS: Metric = { function: 'card', field: 'src_ip' };

/** Missing values come back as "-". */
const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : Number(v) || 0);

async function aggregate(rt: GraylogRuntime, query: string, from: number, to: number, groupBy: Grouping[], metrics: Metric[]) {
  const r = await rt.http.request<{ datarows?: unknown[][] }>('/api/search/aggregate', {
    method: 'POST',
    json: { query, timerange: { type: 'absolute', from: iso(from), to: iso(to) }, group_by: groupBy, metrics },
    headers: rt.headers,
  });
  return r.datarows ?? [];
}

/**
 * Totals for a period. The API requires a grouping, so this groups by log
 * source; with several firewalls an address seen by two is counted twice.
 */
async function totals(rt: GraylogRuntime, query: string, from: number, to: number) {
  const rows = await aggregate(rt, query, from, to, [{ field: 'source', limit: 50 }], [COUNT, UNIQUE_IPS]);
  return rows.reduce<Counts>((t, r) => ({ attempts: t.attempts + num(r[1]), unique_ips: t.unique_ips + num(r[2]) }), { attempts: 0, unique_ips: 0 });
}

interface Counts {
  attempts: number;
  unique_ips: number;
}

const real = (key: unknown) => key !== '-' && key !== '(Empty Value)';

/** Sources that tried many ports, most ports first. Ports that are mostly noise are left out so they cannot crowd out scanners. */
async function scanners(rt: FirewallRuntime, from: number, to: number) {
  const total = (await aggregate(rt, rt.firewallQuery, from, to, [{ field: 'source', limit: 50 }], [COUNT])).reduce((n, r) => n + num(r[1]), 0);
  const ports = await aggregate(rt, rt.firewallQuery, from, to, [{ field: 'dst_port', limit: 10 }], [COUNT]);
  const noisy = ports.filter((r) => /^\d+$/.test(String(r[0])) && num(r[1]) > total * NOISY_SHARE).map((r) => `NOT dst_port:${r[0]}`);
  const query = [`(${rt.firewallQuery})`, ...noisy].join(' AND ');
  const rows = await aggregate(rt, query, from, to, [{ field: 'src_ip', limit: SCAN_SOURCES }], [COUNT, { function: 'card', field: 'dst_port' }]);
  return rows
    .map((r) => ({ key: String(r[0]), count: num(r[1]), ports: num(r[2]) }))
    .filter((r) => real(r.key) && r.ports >= SCAN_PORTS)
    .sort((x, y) => y.ports - x.ports);
}

/** Restricts a query to addresses. They come from log data: quoted, so they can only ever be a value. */
const quoted = (ip: string) => `"${ip.replace(/[\\"]/g, '\\$&')}"`;
const onlyFrom = (query: string, ips: string[]) => `(${query}) AND src_ip:(${ips.map(quoted).join(' OR ')})`;

const onlyTo = (query: string, ips: string[]) => `(${query}) AND dst_ip:(${ips.map(quoted).join(' OR ')})`;

export async function firewallTrend(rt: FirewallRuntime, a: AttackRange, now = Date.now()) {
  const { step, columns, from, to, gridFrom, previousFrom } = attackWindow(a, now);
  const timestamp: Grouping = { field: 'timestamp', timeunit: step >= DAY ? `${step / DAY}d` : `${step / HOUR}h` };
  const column = (key: unknown) => Math.floor((Date.parse(String(key)) - gridFrom) / step);
  const empty = () => Array.from({ length: columns }, (): Counts => ({ attempts: 0, unique_ips: 0 }));

  const timeline = async (query: string) => {
    const points = empty();
    for (const [key, count, ips] of await aggregate(rt, query, from, to, [timestamp], [COUNT, UNIQUE_IPS])) {
      const p = points[column(key)];
      if (p) {
        p.attempts += num(count);
        p.unique_ips = Math.max(p.unique_ips, num(ips));
      }
    }
    return points;
  };

  // One query at a time: this runs on the log server people depend on.
  const counted = async (query: string) => ({
    points: await timeline(query),
    ...(await totals(rt, query, from, to)),
    previous: await totals(rt, query, previousFrom, from),
  });

  const scans = async () => {
    const found = await scanners(rt, from, to);
    const before = await scanners(rt, previousFrom, from);
    const sum = (xs: { count: number }[]) => xs.reduce((n, x) => n + x.count, 0);
    const points = found.length ? await timeline(onlyFrom(rt.firewallQuery, found.map((x) => x.key))) : empty();
    return { attempts: sum(found), unique_ips: found.length, previous: { attempts: sum(before), unique_ips: before.length }, points };
  };

  /** One failing category must not hide the others. */
  const errors: unknown[] = [];
  const attempt = async (run: () => Promise<Counts & { previous: Counts; points: Counts[] }>) => {
    try {
      return { ...(await run()), error: null };
    } catch (err) {
      errors.push(err);
      return { attempts: 0, unique_ips: 0, previous: null, points: empty(), error: err instanceof Error ? err.message : String(err) };
    }
  };
  const firewall = await attempt(() => counted(rt.firewallQuery));
  const ips = await attempt(() => counted(rt.ipsQuery));
  if (errors.length === 2) throw errors[0];
  const port_scan = await attempt(scans);
  // How far back the firewall logs go: before that a chart is empty and a comparison would mislead.
  const oldest = await searchMessages(rt, { query: rt.firewallQuery, from: iso(previousFrom), to: iso(to), fields: ['timestamp'], limit: 1, offset: 0, sort_order: 'asc' });
  const oldestMs = Date.parse(String(oldest.messages[0]?.timestamp));
  const dataFrom = Number.isNaN(oldestMs) ? null : oldestMs;
  const comparable = reachesBack(dataFrom, previousFrom, step);
  const results = { port_scan, firewall, ips };
  return {
    from: iso(from),
    to: iso(to),
    columns_from: iso(gridFrom),
    data_from: dataFrom === null ? null : iso(dataFrom),
    step_seconds: step / 1000,
    categories: CATEGORIES.map((c) => ({ ...c, ...results[c.id], previous: comparable ? results[c.id].previous : null })),
  };
}

export interface FirewallDetailsInput {
  category: FirewallCategory;
  from: string;
  to: string;
  top: number;
  limit: number;
}

export async function firewallDetails(rt: FirewallRuntime, a: FirewallDetailsInput) {
  const from = Date.parse(a.from);
  const to = Date.parse(a.to);
  if (Number.isNaN(from) || Number.isNaN(to) || from >= to) throw new BackendError('Invalid time range: from must be before to');
  const base = a.category === 'ips' ? rt.ipsQuery : rt.firewallQuery;
  const top = async (query: string, field: string) =>
    (await aggregate(rt, query, from, to, [{ field, limit: a.top }], [COUNT]))
      .filter((r) => real(r[0]))
      .map((r) => ({ key: String(r[0]), count: num(r[1]) }))
      .sort((x, y) => y.count - x.count);

  let query = base;
  let topIps;
  if (a.category === 'port_scan') {
    topIps = (await scanners(rt, from, to)).slice(0, a.top);
    if (!topIps.length) return { category: a.category, from: iso(from), to: iso(to), top_ips: [], top_ports: [], top_targets: [], top_signatures: [], messages: [] };
    query = onlyFrom(base, topIps.map((r) => r.key));
  }
  const ips = topIps ?? (await top(query, 'src_ip'));
  const ports = await top(query, 'dst_port');
  const targets = await top(query, 'dst_ip');
  const signatures = a.category === 'ips' ? await top(query, 'UNIFIipsSignature') : [];
  const recent = await searchMessages(rt, {
    query,
    from: iso(from),
    to: iso(to),
    fields: ['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'UNIFIipsSignature'],
    limit: a.limit,
    offset: 0,
    sort_order: 'desc',
  });
  return { category: a.category, from: iso(from), to: iso(to), top_ips: ips, top_ports: ports, top_targets: targets, top_signatures: signatures, messages: recent.messages };
}

const MAX_TARGETS = 1000;
const MAX_SIGNATURES = 200;

export interface EdgeTarget {
  kind: 'firewall' | 'ips';
  ip: string;
  port?: number;
  blocked: number;
  unique_ips: number;
  /** Graylog query that shows the messages behind this count. */
  query: string;
}

/**
 * Blocked traffic per target address, for joining with the service map. IPS
 * logs often carry no target (UniFi's do not); those are only counted, since
 * they cannot be tied to a service.
 */
export async function attacksByTarget(rt: FirewallRuntime, a: { from: number; to: number; ips: string[] }) {
  const targets: EdgeTarget[] = [];
  let truncated = false;
  for (const [kind, base] of [['firewall', rt.firewallQuery], ['ips', rt.ipsQuery]] as const) {
    if (!a.ips.length) continue;
    const rows = await aggregate(rt, onlyTo(base, a.ips), a.from, a.to, [{ field: 'dst_ip', limit: 200 }, { field: 'dst_port', limit: MAX_TARGETS }], [COUNT, UNIQUE_IPS]);
    truncated ||= rows.length >= MAX_TARGETS;
    for (const [ip, port, count, ips] of rows) {
      if (!real(ip) || !a.ips.includes(String(ip))) continue;
      const p = /^\d+$/.test(String(port)) ? Number(port) : undefined;
      targets.push({
        kind,
        ip: String(ip),
        ...(p !== undefined ? { port: p } : {}),
        blocked: num(count),
        unique_ips: num(ips),
        query: onlyTo(base, [String(ip)]) + (p !== undefined ? ` AND dst_port:${p}` : ''),
      });
    }
  }
  const signatures = await aggregate(rt, rt.ipsQuery, a.from, a.to, [{ field: 'UNIFIipsSignature', limit: MAX_SIGNATURES }], [COUNT]);
  const total = signatures.reduce((n, r) => n + num(r[1]), 0);
  return {
    targets,
    truncated,
    ips_without_target: Math.max(0, total - targets.filter((t) => t.kind === 'ips').reduce((n, t) => n + t.blocked, 0)),
    signature_cves: cvesIn(signatures.map((r) => String(r[0]))),
  };
}

/** Sources per category on the map: the busiest. */
const MAP_SOURCES = 150;
const MINUTE = 60_000;
/** Log lines arrive a little late; a minute that is still filling up is left for the next request. */
const MAP_LAG = MINUTE;
const SCANNERS_TTL = 10 * MINUTE;
const MAP_TTL = 5 * MINUTE;

/** Answers shared by everyone watching: ranges are whole minutes in the past, so they do not change. */
const shared = new WeakMap<object, Map<string, { at: number; value: Promise<unknown> }>>();
function once<T>(rt: object, key: string, ttl: number, now: number, run: () => Promise<T>): Promise<T> {
  let m = shared.get(rt);
  if (!m) shared.set(rt, (m = new Map()));
  for (const [k, v] of m) if (now - v.at > SCANNERS_TTL) m.delete(k);
  const hit = m.get(key);
  if (hit && now - hit.at < ttl) return hit.value as Promise<T>;
  const value = run();
  m.set(key, { at: now, value });
  value.catch(() => m.delete(key));
  return value;
}

/**
 * Blocked traffic for the map: per category, source and time slot, for the
 * busiest sources. Logs are summed because single dropped packets number in the
 * tens of thousands a day. Scanners are left out of the firewall blocks here, so
 * nothing is drawn twice.
 */
export async function edgeMap(rt: FirewallRuntime, geo: GeoLookup, a: { since: string; layers: FirewallCategory[] }, now = Date.now()) {
  const since = Date.parse(a.since);
  if (Number.isNaN(since)) throw new BackendError('Invalid start time');
  const from = Math.floor(since / MINUTE) * MINUTE;
  const to = Math.floor((now - MAP_LAG) / MINUTE) * MINUTE;
  if (from >= to) return { since: iso(from), to: iso(from), step_seconds: 60, sources_limit: MAP_SOURCES, without_location: 0, categories: [], events: [] };
  const span = to - from;
  const step = span <= 15 * MINUTE ? MINUTE : span <= DAY + HOUR ? HOUR : 6 * HOUR;
  const timestamp: Grouping = { field: 'timestamp', timeunit: step >= HOUR ? `${step / HOUR}h` : '1m' };

  const scannerIps = async () => {
    const found = await once(rt, `scan:${span > DAY ? from : 'day'}`, SCANNERS_TTL, now, () => scanners(rt, Math.min(from, to - DAY), to));
    return found.map((s) => s.key);
  };
  const rows = async (id: FirewallCategory): Promise<unknown[][]> => {
    const scan = id === 'ips' ? [] : await scannerIps();
    let query = id === 'ips' ? rt.ipsQuery : rt.firewallQuery;
    if (id === 'port_scan') {
      if (!scan.length) return [];
      query = onlyFrom(query, scan);
    } else if (scan.length) query = `(${query}) AND NOT src_ip:(${scan.map(quoted).join(' OR ')})`;
    const top = (await aggregate(rt, query, from, to, [{ field: 'src_ip', limit: MAP_SOURCES }], [COUNT])).map((r) => r[0]).filter(real).map(String);
    if (!top.length) return [];
    return aggregate(rt, onlyFrom(query, top), from, to, [{ field: 'src_ip', limit: MAP_SOURCES }, timestamp], [COUNT]);
  };

  // One query at a time, and one failing category must not hide the others.
  const errors: unknown[] = [];
  const categories = [];
  const events = [];
  const homeless = new Set<string>();
  for (const c of CATEGORIES.filter((x) => a.layers.includes(x.id))) {
    let error: string | null = null;
    try {
      const key = `map:${c.id}:${from}:${to}`;
      for (const [ip, time, count] of await once(rt, key, MAP_TTL, now, () => rows(c.id))) {
        const start = Date.parse(String(time));
        const n = num(count);
        if (!real(ip) || Number.isNaN(start) || !n) continue;
        const place = geo.lookup(String(ip));
        if (!place) {
          homeless.add(String(ip));
          continue;
        }
        // Only the slot is known: spread the sources over it, always the same way.
        const lo = Math.max(start, from);
        const hi = Math.min(start + step, to);
        if (hi <= lo) continue;
        const id = `${c.id}:${ip}:${lo}`;
        events.push({ id, at: lo + (hash(id) % (hi - lo)), category: c.id, ip: String(ip), ...place, agent: null, n });
      }
    } catch (err) {
      errors.push(err);
      error = 'could not be read from Graylog';
    }
    categories.push({ id: c.id, title: c.title, error });
  }
  if (errors.length && errors.length === categories.length) throw errors[0];
  events.sort((x, y) => x.at - y.at);
  return { since: iso(from), to: iso(to), step_seconds: step / 1000, sources_limit: MAP_SOURCES, without_location: homeless.size, categories, events };
}

/** FNV-1a. */
function hash(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193) >>> 0;
  return h;
}
