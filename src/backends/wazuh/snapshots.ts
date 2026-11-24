import { createHash } from 'node:crypto';
import { readFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { decryptJson, encryptJson, type Key } from '../../crypto/secretbox.js';
import { errMessage, log } from '../../log.js';
import { writeFileAtomic } from '../../util/fs.js';
import { BackendError } from '../http.js';
import type { SearchResponse, WazuhClient } from './client.js';

/**
 * Snapshots of the open vulnerability findings, compared over time.
 *
 * Wazuh raises detector alerts when a package changes, but not when a CVE
 * appears through a feed update, and `detected_at` is reset whenever the state
 * index is rebuilt. Comparing what is open now with what was open before is the
 * only way to see every new and resolved finding.
 *
 * A finding is agent + CVE + package, without the version: a package upgrade
 * that still has the CVE changes nothing. Only the latest set and per-day counts
 * are kept, encrypted, in DATA_DIR.
 */

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
/** How often the open findings are read. */
const SNAPSHOT_INTERVAL_MS = HOUR_MS;
const TICK_MS = 5 * 60_000;
/** A finding must stay away this long before it counts as resolved, so a rebuild of the index does not resolve everything. */
const RESOLVE_AFTER_MS = 6 * HOUR_MS;
/** Longer than the widest trend window (365 days). */
const KEEP_DAYS = 400;
/** An agent without any findings for this long is forgotten. */
const FORGET_AGENT_MS = 90 * DAY_MS;
const PAGE = 1000;
const MAX_PAGES = 500;
const PURPOSE = 'vulnerability-snapshots';

/** severity, and since when the finding is missing (if it is). */
interface Finding {
  s: string;
  m?: number;
}
interface AgentState {
  seen: number;
  findings: Record<string, Finding>;
}
interface DayCount {
  new: number;
  resolved: number;
}
interface State {
  target: string;
  /** Time of the first snapshot: changes after it are known. */
  since: number;
  at: number;
  agents: Record<string, AgentState>;
  /** day → agent → severity → counts */
  days: Record<string, Record<string, Record<string, DayCount>>>;
}

/** What the trend needs. */
export interface SnapshotHistory {
  since: number;
  changes: { day: string; agent: string; severity: string; new: number; resolved: number }[];
}

export interface OpenFinding {
  agent: string;
  cve: string;
  package: string;
  severity: string;
}

/** Identifies the index the snapshots were taken from; another index starts a new history. */
function targetOf(client: WazuhClient): string {
  return createHash('sha256').update(JSON.stringify([client.cfg.indexerUrl, client.cfg.vulnerabilitiesIndex])).digest('hex');
}

/** Every open finding. Throws rather than returning an incomplete set. */
export async function readOpenFindings(client: WazuhClient): Promise<OpenFinding[]> {
  const out: OpenFinding[] = [];
  let after: unknown;
  for (let page = 0; page < MAX_PAGES; page++) {
    const r = await client.search<SearchResponse & { timed_out?: boolean; _shards?: { failed?: number } }>(client.cfg.vulnerabilitiesIndex, {
      size: 0,
      track_total_hits: false,
      aggs: {
        findings: {
          composite: {
            size: PAGE,
            sources: [
              { agent: { terms: { field: 'agent.id' } } },
              { cve: { terms: { field: 'vulnerability.id' } } },
              { package: { terms: { field: 'package.name', missing_bucket: true } } },
              { severity: { terms: { field: 'vulnerability.severity', missing_bucket: true } } },
            ],
            ...(after ? { after } : {}),
          },
        },
      },
    });
    if (r.timed_out || r._shards?.failed) throw new BackendError('The Wazuh indexer returned an incomplete list of findings');
    const agg = r.aggregations?.findings as unknown as { buckets?: { key: Record<string, string | null> }[]; after_key?: unknown } | undefined;
    if (!agg?.buckets) throw new BackendError('The Wazuh indexer returned no list of findings');
    for (const { key: k } of agg.buckets) out.push({ agent: String(k.agent), cve: String(k.cve), package: k.package ?? '', severity: k.severity ?? '' });
    after = agg.after_key;
    if (agg.buckets.length < PAGE || !after) return out;
  }
  throw new BackendError('Too many open findings for a snapshot');
}

/** Applies one snapshot to the state (changed in place). */
export function applySnapshot(state: State, open: OpenFinding[], now: number): void {
  const day = (t: number) => new Date(t).toISOString().slice(0, 10);
  const count = (t: number, agent: string, severity: string, kind: keyof DayCount) => {
    const sev = ((state.days[day(t)] ??= {})[agent] ??= {});
    (sev[severity] ??= { new: 0, resolved: 0 })[kind]++;
  };
  const current = new Map<string, Map<string, string>>();
  for (const f of open) {
    let list = current.get(f.agent);
    if (!list) current.set(f.agent, (list = new Map()));
    list.set(JSON.stringify([f.cve, f.package]), f.severity);
  }
  for (const [agent, list] of current) {
    const known = state.agents[agent];
    if (!known) {
      // First sight of an agent: its findings are the starting point, not new.
      state.agents[agent] = { seen: now, findings: Object.fromEntries([...list].map(([k, s]) => [k, { s }])) };
      continue;
    }
    known.seen = now;
    for (const [k, f] of Object.entries(known.findings)) {
      if (list.has(k)) continue;
      if (f.m === undefined) f.m = now;
      else if (now - f.m >= RESOLVE_AFTER_MS) {
        count(f.m, agent, f.s, 'resolved');
        delete known.findings[k];
      }
    }
    for (const [k, s] of list) {
      if (!known.findings[k]) count(now, agent, s, 'new');
      known.findings[k] = { s };
    }
  }
  // An agent without any findings is left as it was: no data does not mean all fixed.
  for (const [agent, a] of Object.entries(state.agents)) {
    if (current.has(agent)) continue;
    for (const f of Object.values(a.findings)) delete f.m;
    if (now - a.seen > FORGET_AGENT_MS) delete state.agents[agent];
  }
  const oldest = day(now - KEEP_DAYS * DAY_MS);
  for (const d of Object.keys(state.days)) if (d < oldest) delete state.days[d];
  state.at = now;
}

export class VulnerabilitySnapshots {
  private state: State | null = null;
  private timer?: NodeJS.Timeout;
  private running = false;

  constructor(
    private readonly file: string,
    private readonly key: Key,
  ) {}

  static forDataDir(dataDir: string, key: Key): VulnerabilitySnapshots {
    return new VulnerabilitySnapshots(path.join(dataDir, 'vulnerability-snapshots.enc.json'), key);
  }

  async load(): Promise<void> {
    let raw: string;
    try {
      raw = await readFile(this.file, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }
    try {
      this.state = decryptJson<State>(this.key, PURPOSE, raw);
    } catch (err) {
      // Kept aside rather than overwritten by the next snapshot.
      log.error('Vulnerability snapshots unreadable; starting a new history', { error: errMessage(err) });
      await rename(this.file, `${this.file}.unreadable`);
    }
  }

  /** Takes a snapshot when one is due. Returns whether it did. */
  async take(client: WazuhClient, now = Date.now()): Promise<boolean> {
    const target = targetOf(client);
    const prev = this.state?.target === target ? this.state : null;
    if (prev && now - prev.at < SNAPSHOT_INTERVAL_MS) return false;
    const open = await readOpenFindings(client);
    // An empty index is being rebuilt or has lost its data: nothing to compare with.
    if (open.length === 0) return false;
    const next: State = prev ? structuredClone(prev) : { target, since: now, at: now, agents: {}, days: {} };
    applySnapshot(next, open, now);
    await writeFileAtomic(this.file, encryptJson(this.key, PURPOSE, next));
    this.state = next;
    return true;
  }

  /** The recorded changes, if they belong to this client's index. */
  history(client: WazuhClient): SnapshotHistory | null {
    const s = this.state;
    if (!s || s.target !== targetOf(client)) return null;
    const changes: SnapshotHistory['changes'] = [];
    for (const [day, agents] of Object.entries(s.days)) {
      for (const [agent, sevs] of Object.entries(agents)) {
        for (const [severity, c] of Object.entries(sevs)) changes.push({ day, agent, severity, ...c });
      }
    }
    return { since: s.since, changes };
  }

  /** Takes snapshots on a schedule. `withClient` runs the work under the backend's gate, or does nothing when Wazuh is off. */
  start(withClient: (fn: (c: WazuhClient) => Promise<unknown>) => Promise<unknown>): void {
    if (this.timer) return;
    const tick = async () => {
      if (this.running) return;
      this.running = true;
      try {
        await withClient((c) => this.take(c));
      } catch (err) {
        log.warn('Vulnerability snapshot failed', { error: errMessage(err) });
      } finally {
        this.running = false;
      }
    };
    void tick();
    this.timer = setInterval(() => void tick(), TICK_MS);
    this.timer.unref();
  }
}

let current: VulnerabilitySnapshots | null = null;
/** The process's snapshots, used by every trend query (web UI and MCP). */
export function useSnapshots(s: VulnerabilitySnapshots | null): void {
  current = s;
}
export function snapshotHistory(client: WazuhClient): SnapshotHistory | null {
  return current?.history(client) ?? null;
}
