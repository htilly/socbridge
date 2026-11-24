import { BackendError } from '../http.js';
import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { errMessage } from '../../log.js';
import { normaliseCve, normaliseSeverity, type CveInventory, type CveOccurrence } from '../cve.js';

/**
 * Reads Trivy JSON reports (`trivy image|fs|repo --format json`, schema v2)
 * from a read-only directory. Parsed reports are cached by file name and
 * re-read only when the file's mtime or size changes, so tools that scan
 * every report (trivy_find_cve) stay cheap across requests.
 *
 * Secret findings are reported by rule, file and line only: the matched text
 * is never returned, even though Trivy masks most of it.
 */

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;
export type Severity = (typeof SEVERITIES)[number];
const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

/** Larger files are skipped rather than parsed (a full SBOM-style report can be huge). */
export const MAX_REPORT_BYTES = 64 * 1024 * 1024;
const MAX_TEXT = 1000;
const READ_CONCURRENCY = 8;

export interface Vuln {
  id: string;
  severity: Severity;
  pkg: string;
  installed?: string;
  fixed?: string;
  status?: string;
  title?: string;
  description?: string;
  cvss?: number;
  url?: string;
  published?: string;
  target: string;
  type?: string;
}

export interface Misconfig {
  id: string;
  severity: Severity;
  title?: string;
  message?: string;
  resolution?: string;
  url?: string;
  target: string;
  type?: string;
}

export interface Secret {
  rule: string;
  severity: Severity;
  title?: string;
  category?: string;
  target: string;
  start_line?: number;
  end_line?: number;
}

export interface Report {
  file: string;
  artifact: string;
  artifact_type?: string;
  created_at?: string;
  os?: string;
  image_id?: string;
  repo_digests?: string[];
  vulnerabilities: Vuln[];
  misconfigurations: Misconfig[];
  secrets: Secret[];
}

export type ReportEntry = { file: string; report: Report } | { file: string; error: string };

type Obj = Record<string, unknown>;

const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? (v.filter((x) => x && typeof x === 'object') as Obj[]) : []);

function sev(v: unknown): Severity {
  const s = typeof v === 'string' ? v.toUpperCase() : '';
  return (s in RANK ? s : 'UNKNOWN') as Severity;
}

export function cap(v: string | undefined, max = MAX_TEXT): string | undefined {
  if (!v || v.length <= max) return v;
  return v.slice(0, max) + ` … [truncated ${v.length - max} characters]`;
}

/** Highest CVSS score across sources (nvd, redhat, ghsa, …), v3 preferred over v2. */
function cvssScore(v: unknown): number | undefined {
  if (!v || typeof v !== 'object') return undefined;
  let v3: number | undefined;
  let v2: number | undefined;
  for (const src of Object.values(v as Obj)) {
    if (!src || typeof src !== 'object') continue;
    const s = src as Obj;
    const a = num(s.V40Score) ?? num(s.V3Score);
    const b = num(s.V2Score);
    if (a !== undefined) v3 = Math.max(v3 ?? 0, a);
    if (b !== undefined) v2 = Math.max(v2 ?? 0, b);
  }
  return v3 ?? v2;
}

/** Parses one Trivy JSON report. Throws if the document is not a Trivy report. */
export function parseReport(file: string, doc: unknown): Report {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Not a Trivy JSON report');
  const d = doc as Obj;
  if (d.SchemaVersion === undefined || !('ArtifactName' in d)) throw new Error('Not a Trivy JSON report (no SchemaVersion/ArtifactName)');
  const meta = (d.Metadata ?? {}) as Obj;
  const os = (meta.OS ?? {}) as Obj;
  const r: Report = {
    file,
    artifact: str(d.ArtifactName) ?? file,
    artifact_type: str(d.ArtifactType),
    created_at: str(d.CreatedAt),
    os: [str(os.Family), str(os.Name)].filter(Boolean).join(' ') || undefined,
    image_id: str(meta.ImageID),
    repo_digests: Array.isArray(meta.RepoDigests) ? (meta.RepoDigests as unknown[]).filter((x): x is string => typeof x === 'string') : undefined,
    vulnerabilities: [],
    misconfigurations: [],
    secrets: [],
  };
  for (const res of arr(d.Results)) {
    const target = str(res.Target) ?? '';
    const type = str(res.Type);
    for (const v of arr(res.Vulnerabilities)) {
      const id = str(v.VulnerabilityID);
      if (!id) continue;
      r.vulnerabilities.push({
        id,
        severity: sev(v.Severity),
        pkg: str(v.PkgName) ?? str(v.PkgID) ?? '',
        installed: str(v.InstalledVersion),
        fixed: str(v.FixedVersion),
        status: str(v.Status),
        title: str(v.Title),
        description: str(v.Description),
        cvss: cvssScore(v.CVSS),
        url: str(v.PrimaryURL),
        published: str(v.PublishedDate),
        target,
        type,
      });
    }
    for (const m of arr(res.Misconfigurations)) {
      if (str(m.Status) && m.Status !== 'FAIL') continue;
      r.misconfigurations.push({
        id: str(m.ID) ?? str(m.AVDID) ?? '',
        severity: sev(m.Severity),
        title: str(m.Title),
        message: str(m.Message),
        resolution: str(m.Resolution),
        url: str(m.PrimaryURL),
        target,
        type,
      });
    }
    for (const s of arr(res.Secrets)) {
      r.secrets.push({
        rule: str(s.RuleID) ?? '',
        severity: sev(s.Severity),
        title: str(s.Title),
        category: str(s.Category),
        target,
        start_line: num(s.StartLine),
        end_line: num(s.EndLine),
      });
    }
  }
  return r;
}

export function severityCounts(items: { severity: Severity }[]): Partial<Record<Severity, number>> {
  const out: Partial<Record<Severity, number>> = {};
  for (const s of SEVERITIES) {
    const n = items.filter((i) => i.severity === s).length;
    if (n) out[s] = n;
  }
  return out;
}

const bySeverity = <T extends { severity: Severity }>(a: T, b: T) => (RANK[a.severity] ?? 4) - (RANK[b.severity] ?? 4);

async function mapLimit<T, R>(items: T[], limit: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** How deep `files()` descends below the report directory (0 = top level only). */
export const MAX_DEPTH = 6;
/** At most this many report files are read; the rest are reported as not scanned. */
export const MAX_FILES = 5000;

export class TrivyReports {
  private cache = new Map<string, { mtimeMs: number; size: number; entry: ReportEntry }>();
  /** Set by the last `files()` call when the depth or file-count limit cut the scan short. */
  lastScanLimited?: string;

  constructor(readonly dir: string) {}

  /**
   * `.json` files in the report directory and its subdirectories, as
   * relative `/`-separated paths sorted by name. Dot files and dot
   * directories are skipped. Symlinked directories are never descended into;
   * symlinked files are listed and later read only if they resolve to a
   * file inside the report directory.
   */
  async files(): Promise<string[]> {
    const out: string[] = [];
    let limited: string | undefined;
    const walk = async (rel: string, depth: number): Promise<void> => {
      const entries = await readdir(rel ? path.join(this.dir, ...rel.split('/')) : this.dir, { withFileTypes: true });
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const subdirs: string[] = [];
      for (const e of entries) {
        if (e.name.startsWith('.')) continue;
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) subdirs.push(r);
        else if ((e.isFile() || e.isSymbolicLink()) && e.name.endsWith('.json')) {
          if (out.length >= MAX_FILES) {
            limited ??= `Stopped after ${MAX_FILES} report files; the rest were not read`;
            return;
          }
          out.push(r);
        }
      }
      for (const d of subdirs) {
        if (depth >= MAX_DEPTH) {
          limited ??= `Subdirectories deeper than ${MAX_DEPTH} levels were not read (e.g. ${d})`;
          continue;
        }
        try {
          await walk(d, depth + 1);
        } catch {
          // An unreadable subdirectory is skipped; the top level must be readable.
        }
        if (out.length >= MAX_FILES) break;
      }
    };
    await walk('', 0);
    this.lastScanLimited = limited;
    return out.sort();
  }

  /**
   * Resolves a relative report path (`a/b.json`) inside the report directory;
   * rejects absolute paths, `..`, backslashes and anything else that would
   * leave it.
   */
  private pathOf(file: string): string {
    const parts = file.split('/');
    if (
      !file ||
      file.includes('\\') ||
      file.includes('\0') ||
      path.isAbsolute(file) ||
      parts.some((p) => p === '' || p === '.' || p === '..')
    ) {
      throw new BackendError(`Invalid report name: ${file}`);
    }
    const p = path.resolve(this.dir, ...parts);
    const root = path.resolve(this.dir);
    if (!p.startsWith(root + path.sep)) throw new BackendError(`Invalid report name: ${file}`);
    return p;
  }

  /** Rejects a path whose real location (after symlinks) is outside the report directory. */
  private async insideRoot(p: string): Promise<boolean> {
    const [root, real] = await Promise.all([realpath(this.dir), realpath(p)]);
    return real.startsWith(root + path.sep);
  }

  private async load(file: string): Promise<ReportEntry> {
    try {
      const p = this.pathOf(file);
      if (!(await this.insideRoot(p))) return { file, error: 'Symlink points outside the report directory' };
      const st = await stat(p);
      if (!st.isFile()) return { file, error: 'Not a regular file' };
      const hit = this.cache.get(file);
      if (hit && hit.mtimeMs === st.mtimeMs && hit.size === st.size) return hit.entry;
      let entry: ReportEntry;
      if (st.size > MAX_REPORT_BYTES) {
        entry = { file, error: `Skipped: ${st.size} bytes is over the ${MAX_REPORT_BYTES}-byte limit` };
      } else {
        try {
          entry = { file, report: parseReport(file, JSON.parse(await readFile(p, 'utf8'))) };
        } catch (err) {
          entry = { file, error: errMessage(err) };
        }
      }
      this.cache.set(file, { mtimeMs: st.mtimeMs, size: st.size, entry });
      return entry;
    } catch (err) {
      return { file, error: errMessage(err) };
    }
  }

  /** Every report in the directory (parse failures included as `error` entries). */
  async all(): Promise<ReportEntry[]> {
    const files = await this.files();
    const live = new Set(files);
    for (const k of this.cache.keys()) if (!live.has(k)) this.cache.delete(k);
    return mapLimit(files, READ_CONCURRENCY, (f) => this.load(f));
  }

  /**
   * Finds one report by file name, or by artifact name (newest report wins
   * when several files scanned the same artifact).
   */
  async find(ref: string): Promise<Report | { error: string }> {
    const files = await this.files();
    if (files.includes(ref)) {
      const e = await this.load(ref);
      return 'report' in e ? e.report : { error: `${ref}: ${e.error}` };
    }
    const matches = (await this.all())
      .filter((e): e is { file: string; report: Report } => 'report' in e && e.report.artifact === ref)
      .sort((a, b) => (b.report.created_at ?? '').localeCompare(a.report.created_at ?? ''));
    if (matches[0]) return matches[0].report;
    return { error: `No report file or artifact named "${ref}". Use trivy_list_reports to see what exists.` };
  }
}

// ---------------------------------------------------------------- tool queries

type Loaded = { file: string; report: Report };
const isReport = (e: ReportEntry): e is Loaded => 'report' in e;

/** Reports of the same artifact share this key: artifact name plus type (an image and a directory can share a name). */
export const artifactKey = (r: Report) => `${r.artifact_type ?? ''}\u0000${r.artifact}`;

/** Oldest scan first; reports without CreatedAt sort first, ties broken by file name. */
const byScanTime = (x: Report, y: Report) => (x.created_at ?? '').localeCompare(y.created_at ?? '') || x.file.localeCompare(y.file);

/** Groups reports by artifact, each group ordered oldest scan first. */
export function groupByArtifact(reports: Report[]): Map<string, Report[]> {
  const groups = new Map<string, Report[]>();
  for (const r of reports) {
    const k = artifactKey(r);
    const g = groups.get(k);
    if (g) g.push(r);
    else groups.set(k, [r]);
  }
  for (const g of groups.values()) g.sort(byScanTime);
  return groups;
}

export async function listReports(rt: TrivyReports, a: { artifact?: string; latest_only?: boolean; limit: number; offset: number }) {
  const entries = await rt.all();
  const needle = a.artifact?.toLowerCase();
  let ok = entries
    .filter(isReport)
    .map((e) => e.report)
    .filter((r) => !needle || r.artifact.toLowerCase().includes(needle) || r.file.toLowerCase().includes(needle));
  const scans = new Map<string, number>();
  if (a.latest_only) {
    const groups = groupByArtifact(ok);
    ok = [...groups.values()].map((g) => g[g.length - 1]!);
    for (const [k, g] of groups) scans.set(k, g.length);
  }
  ok.sort((x, y) => byScanTime(y, x));
  const errors = entries.filter((e): e is { file: string; error: string } => 'error' in e);
  return {
    directory: rt.dir,
    total: ok.length,
    reports: ok.slice(a.offset, a.offset + a.limit).map((r) => ({
      file: r.file,
      artifact: r.artifact,
      artifact_type: r.artifact_type,
      created_at: r.created_at,
      os: r.os,
      vulnerabilities: r.vulnerabilities.length,
      by_severity: severityCounts(r.vulnerabilities),
      fixable: r.vulnerabilities.filter((v) => v.fixed).length,
      misconfigurations: r.misconfigurations.length || undefined,
      secrets: r.secrets.length || undefined,
      ...(a.latest_only ? { scans: scans.get(artifactKey(r)) } : {}),
    })),
    ...(errors.length ? { unreadable: errors } : {}),
    ...(rt.lastScanLimited ? { scan_limited: rt.lastScanLimited } : {}),
  };
}

/** One vulnerability ID in a scan, with the packages it was found in and the worst severity. */
function byVulnId(r: Report): Map<string, { severity: Severity; packages: Set<string>; fixed?: string }> {
  const m = new Map<string, { severity: Severity; packages: Set<string>; fixed?: string }>();
  for (const v of r.vulnerabilities) {
    const cur = m.get(v.id);
    if (!cur) m.set(v.id, { severity: v.severity, packages: new Set([v.pkg]), fixed: v.fixed });
    else {
      cur.packages.add(v.pkg);
      if ((RANK[v.severity] ?? 4) < (RANK[cur.severity] ?? 4)) cur.severity = v.severity;
      cur.fixed ??= v.fixed;
    }
  }
  return m;
}

/**
 * Scans of one artifact over time, oldest first, with counts per scan, and a
 * diff between two scans (default: the latest two): vulnerability IDs that
 * disappeared (fixed) and that appeared (new).
 */
export async function artifactHistory(
  rt: TrivyReports,
  a: { artifact: string; artifact_type?: string; from?: string; to?: string; limit: number },
) {
  const reports = (await rt.all()).filter(isReport).map((e) => e.report);
  const typeOk = (r: Report) => !a.artifact_type || r.artifact_type === a.artifact_type;
  let candidates = reports.filter((r) => r.artifact === a.artifact && typeOk(r));
  if (!candidates.length) {
    const needle = a.artifact.toLowerCase();
    candidates = reports.filter((r) => r.artifact.toLowerCase().includes(needle) && typeOk(r));
  }
  const groups = groupByArtifact(candidates);
  if (groups.size === 0) {
    return { error: `No reports for artifact "${a.artifact}". Use trivy_list_reports to see what exists.` };
  }
  if (groups.size > 1) {
    return {
      error: `"${a.artifact}" matches ${groups.size} artifacts; give the exact artifact name (and artifact_type if names collide).`,
      candidates: [...groups.values()].map((g) => ({ artifact: g[0]!.artifact, artifact_type: g[0]!.artifact_type, scans: g.length })),
    };
  }
  const scans = [...groups.values()][0]!;
  const first = scans[0]!;

  const pick = (ref: string | undefined, fallback: Report | undefined, label: string) => {
    if (ref === undefined) return fallback;
    const r = scans.find((s) => s.file === ref || s.created_at === ref);
    if (!r) throw new BackendError(`${label} "${ref}" is not a scan of ${first.artifact}; use a file name or created_at from the scans list.`);
    return r;
  };
  let from: Report | undefined;
  let to: Report | undefined;
  try {
    to = pick(a.to, scans[scans.length - 1], 'to');
    from = pick(a.from, a.to === undefined ? scans[scans.length - 2] : scans[scans.indexOf(to!) - 1], 'from');
  } catch (err) {
    return { error: errMessage(err) };
  }

  type Change = { id: string; severity: Severity; packages: string[]; fixed_version?: string };
  let comparison:
    | {
        from: { file: string; created_at?: string };
        to: { file: string; created_at?: string };
        fixed_count: number;
        new_count: number;
        unchanged_count: number;
        severity_change: Partial<Record<Severity, number>>;
        fixed: Change[];
        new: Change[];
        truncated?: boolean;
      }
    | undefined;
  if (from && to && from !== to) {
    if (byScanTime(from, to) > 0) [from, to] = [to, from];
    const before = byVulnId(from);
    const now = byVulnId(to);
    const list = (m: typeof now, ids: string[]): Change[] =>
      ids
        .map((id) => ({ id, ...m.get(id)! }))
        .sort((x, y) => (RANK[x.severity] ?? 4) - (RANK[y.severity] ?? 4) || x.id.localeCompare(y.id))
        .map((v) => ({ id: v.id, severity: v.severity, packages: [...v.packages].sort(), ...(v.fixed ? { fixed_version: v.fixed } : {}) }));
    const fixed = list(before, [...before.keys()].filter((id) => !now.has(id)));
    const added = list(now, [...now.keys()].filter((id) => !before.has(id)));
    const delta: Partial<Record<Severity, number>> = {};
    const b = severityCounts(from.vulnerabilities);
    const n = severityCounts(to.vulnerabilities);
    for (const s of SEVERITIES) {
      const d = (n[s] ?? 0) - (b[s] ?? 0);
      if (d) delta[s] = d;
    }
    comparison = {
      from: { file: from.file, created_at: from.created_at },
      to: { file: to.file, created_at: to.created_at },
      fixed_count: fixed.length,
      new_count: added.length,
      unchanged_count: [...now.keys()].filter((id) => before.has(id)).length,
      severity_change: delta,
      fixed: fixed.slice(0, a.limit),
      new: added.slice(0, a.limit),
      ...(fixed.length > a.limit || added.length > a.limit ? { truncated: true } : {}),
    };
  }

  return {
    artifact: first.artifact,
    artifact_type: first.artifact_type,
    scan_count: scans.length,
    scans: scans.map((r) => ({
      file: r.file,
      created_at: r.created_at,
      vulnerabilities: r.vulnerabilities.length,
      by_severity: severityCounts(r.vulnerabilities),
      fixable: r.vulnerabilities.filter((v) => v.fixed).length,
    })),
    comparison,
    note: comparison ? undefined : scans.length < 2 ? 'Only one scan of this artifact; nothing to compare.' : 'No earlier scan to compare with.',
  };
}

export async function reportFindings(
  rt: TrivyReports,
  a: {
    report: string;
    severity?: Severity[];
    fixable_only: boolean;
    package?: string;
    include_misconfigurations: boolean;
    include_secrets: boolean;
    limit: number;
    offset: number;
  },
) {
  const r = await rt.find(a.report);
  if ('error' in r) return r;
  const sevOk = (s: Severity) => !a.severity?.length || a.severity.includes(s);
  const pkg = a.package?.toLowerCase();
  const vulns = r.vulnerabilities
    .filter((v) => sevOk(v.severity) && (!a.fixable_only || v.fixed) && (!pkg || v.pkg.toLowerCase().includes(pkg)))
    .sort((x, y) => bySeverity(x, y) || (y.cvss ?? 0) - (x.cvss ?? 0) || x.id.localeCompare(y.id));
  return {
    file: r.file,
    artifact: r.artifact,
    artifact_type: r.artifact_type,
    created_at: r.created_at,
    os: r.os,
    image_id: r.image_id,
    summary: {
      vulnerabilities: r.vulnerabilities.length,
      by_severity: severityCounts(r.vulnerabilities),
      fixable: r.vulnerabilities.filter((v) => v.fixed).length,
      misconfigurations: r.misconfigurations.length,
      secrets: r.secrets.length,
    },
    matched: vulns.length,
    vulnerabilities: vulns.slice(a.offset, a.offset + a.limit).map(({ description: _d, ...v }) => v),
    ...(a.include_misconfigurations
      ? {
          misconfigurations: r.misconfigurations
            .filter((m) => sevOk(m.severity))
            .sort(bySeverity)
            .slice(0, a.limit)
            .map((m) => ({ ...m, message: cap(m.message, 500), resolution: cap(m.resolution, 500) })),
        }
      : {}),
    ...(a.include_secrets ? { secrets: r.secrets.filter((s) => sevOk(s.severity)).sort(bySeverity).slice(0, a.limit) } : {}),
  };
}

export async function findCve(rt: TrivyReports, a: { vulnerability_id: string; limit: number }) {
  const want = a.vulnerability_id.trim().toUpperCase();
  const entries = await rt.all();
  let detail: Vuln | undefined;
  const affected: Obj[] = [];
  let reportsScanned = 0;
  for (const e of entries) {
    if (!('report' in e)) continue;
    reportsScanned++;
    for (const v of e.report.vulnerabilities) {
      if (v.id.toUpperCase() !== want) continue;
      if (!detail || (!detail.description && v.description)) detail = v;
      affected.push({
        file: e.report.file,
        artifact: e.report.artifact,
        created_at: e.report.created_at,
        target: v.target,
        pkg: v.pkg,
        installed: v.installed,
        fixed: v.fixed,
        status: v.status,
      });
    }
  }
  return {
    vulnerability_id: want,
    reports_scanned: reportsScanned,
    found: affected.length > 0,
    ...(detail
      ? {
          severity: detail.severity,
          cvss: detail.cvss,
          title: detail.title,
          description: cap(detail.description),
          url: detail.url,
          published: detail.published,
        }
      : {}),
    artifacts: new Set(affected.map((x) => x.artifact)).size,
    affected: affected.slice(0, a.limit),
    ...(affected.length > a.limit ? { truncated: affected.length - a.limit } : {}),
  };
}

/**
 * Every CVE in the newest report of each artifact, as occurrences for the
 * intel module. Older scans of the same artifact are history, not state.
 */
export async function cveOccurrences(rt: TrivyReports): Promise<CveInventory> {
  const entries = await rt.all();
  const reports = entries.filter(isReport).map((e) => e.report);
  const latest = [...groupByArtifact(reports).values()].map((g) => g[g.length - 1]!);
  const occurrences: CveOccurrence[] = [];
  for (const r of latest) {
    for (const v of r.vulnerabilities) {
      const cve = normaliseCve(v.id);
      if (!cve) continue;
      occurrences.push({
        cve,
        source: 'trivy',
        asset: r.artifact,
        ref: r.file,
        ...(r.created_at ? { scanned_at: r.created_at } : {}),
        package: v.pkg,
        ...(v.installed ? { installed: v.installed } : {}),
        ...(v.fixed ? { fixed: v.fixed } : {}),
        severity: normaliseSeverity(v.severity),
        ...(v.cvss !== undefined ? { cvss: v.cvss } : {}),
      });
    }
  }
  const unreadable = entries.length - reports.length;
  const gaps = [
    ...(unreadable ? [`Trivy: ${unreadable} report file(s) could not be read`] : []),
    ...(rt.lastScanLimited ? [`Trivy: ${rt.lastScanLimited}`] : []),
  ];
  return { occurrences, ...(gaps.length ? { gaps } : {}) };
}
