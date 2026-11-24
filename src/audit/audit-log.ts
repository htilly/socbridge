import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, stat } from 'node:fs/promises';
import path from 'node:path';
import { fetch } from 'undici';
import { forbiddenUrl, guardedAgent } from '../backends/http.js';
import { decrypt, encrypt, type Key } from '../crypto/secretbox.js';
import { writeFileAtomic } from '../util/fs.js';
import { errMessage, log } from '../log.js';

/**
 * Append-only audit log of tool calls and of administrative and sign-in
 * events (DESIGN §6, §11.6; BACKLOG P1-7).
 *
 * One line per record in `DATA_DIR/audit.log`, each line an AES-256-GCM
 * envelope (purpose `audit`) around the JSON record, so arguments are
 * encrypted at rest like the config. Each record carries the SHA-256 of the
 * previous line (`prev`), across rotated files too, so a removed or reordered
 * line breaks the chain and `verify()` finds it. Lines are never rewritten; when the file passes
 * `maxBytes` it is renamed to `audit.1.log` (older ones shift up to `keep`).
 *
 * Completed write calls and administrative events go to a separate chain,
 * `audit-protected.log`, with its own longer rotation. Reads and refused calls,
 * which any credential can produce in bulk, therefore cannot push them out.
 * Every record has a sequence number per chain, so `verify()` can say how many
 * records rotation has dropped.
 *
 * Tool results are not stored, only their size and a hash, so a result can be
 * matched with the backend's own logs without copying sensitive data here.
 */

/** `started`: a write tool is about to run; its result follows as a second record. */
export type AuditOutcome = 'ok' | 'error' | 'denied' | 'started';

export interface AuditRecord {
  id: string;
  at: string;
  /** `mcp` (an MCP client), `chat` (the built-in assistant) `admin` (a change or sign-in in the web console) or `web` (a view of backend data there). */
  source: 'mcp' | 'chat' | 'admin' | 'web';
  user: string;
  userId: string;
  /** `token:<id>`, `oauth:<grant id>`, `chat:<user id>` or `session:<user id>`. */
  credential: string;
  /** Token label or OAuth client name. */
  credentialLabel?: string;
  tool: string;
  /** Backend id, or `core` for socbridge_backends. */
  backend: string;
  access: 'read' | 'write';
  /** Arguments as called, with secrets redacted and long values cut. */
  args: unknown;
  outcome: AuditOutcome;
  /** Error text or the reason a call was denied. */
  message?: string;
  durationMs: number;
  resultChars?: number;
  resultSha256?: string;
  /** Position in its chain, from 1. Absent on records written before sequence numbers existed. */
  seq?: number;
  /** SHA-256 of the previous line ('' for the very first record). */
  prev: string;
}

export type AuditInput = Omit<AuditRecord, 'id' | 'at' | 'prev' | 'seq'>;

export interface AuditFilter {
  user?: string;
  tool?: string;
  backend?: string;
  outcome?: AuditOutcome;
  access?: 'read' | 'write';
  /** Only records strictly older than this ISO time (paging). */
  before?: string;
}

const PURPOSE = 'audit';
const HEAD_PURPOSE = 'audit-head';
const SECRET_KEY = /pass(word)?|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key/i;
const SECRET_VALUE = /\b(msec|msat|msrt)_[A-Za-z0-9_-]{8,}|\bBearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----/g;
const MAX_STRING = 1000;
const MAX_ARGS_CHARS = 8000;
/** Refused calls never reached a backend; a short excerpt shows what was tried. */
const MAX_DENIED_ARGS_CHARS = 500;
const MAX_FIELD_CHARS = 128;
/** Rotating out records younger than this is logged as a warning. */
const RAPID_ROTATION_MS = 30 * 86_400_000;

/**
 * Removes what must never land in a log: values under secret-looking keys,
 * SocBridge tokens and bearer headers inside strings, private keys. Long strings
 * and large argument objects are cut.
 */
export function redact(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') {
    const s = value.replace(SECRET_VALUE, '[redacted]');
    return s.length > MAX_STRING ? s.slice(0, MAX_STRING) + `… [${s.length - MAX_STRING} more]` : s;
  }
  if (value === null || typeof value !== 'object') return value;
  if (depth > 6) return '[nested too deep]';
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) out[k] = SECRET_KEY.test(k) ? '[redacted]' : redact(v, depth + 1);
  return out;
}

function capArgs(args: unknown, max: number): unknown {
  const r = redact(args);
  const text = JSON.stringify(r) ?? '';
  return text.length > max ? { truncated: text.slice(0, max) } : r;
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

export interface AuditOptions {
  maxBytes?: number;
  keep?: number;
  /** Rotated files kept of the protected chain (writes and administrative events). */
  keepProtected?: number;
  /** Where to forward records as GELF (read on every record, so changes apply at once). */
  gelfUrl?: () => string | undefined;
  /** Positions kept outside the log's own files, so removing those together is noticed. */
  anchor?: AuditAnchor;
}

export interface AuditAnchor {
  get(chain: string): number | undefined;
  set(chain: string, seq: number): void;
}

/** The anchor is moved at most this often; records since then are covered by the head file alone. */
const ANCHOR_EVERY_MS = 60_000;
const agent = guardedAgent();

/** One hash-chained, rotated file. */
class Chain {
  failing = false;
  private queue: Promise<void> = Promise.resolve();
  private tail: { prev: string; seq: number } | undefined;

  constructor(
    readonly file: string,
    private readonly key: Key,
    private readonly maxBytes: number,
    private readonly keep: number,
    private readonly anchor?: AuditAnchor,
  ) {}

  private anchored = 0;

  private get name(): string {
    return path.basename(this.file);
  }

  /** Newest position, kept outside the log so records cut off its end are noticed. */
  private get headFile(): string {
    return `${this.file}.head`;
  }

  private async readHead(): Promise<{ prev: string; seq: number } | null> {
    try {
      return JSON.parse(decrypt(this.key, HEAD_PURPOSE, JSON.parse(await readFile(this.headFile, 'utf8'))).toString('utf8')) as { prev: string; seq: number };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
  }

  /** Appends one record, fsynced. Appends are serialised so the chain stays intact under concurrent calls. */
  append(rec: Omit<AuditRecord, 'prev' | 'seq'>): Promise<AuditRecord> {
    const run = this.queue.then(async () => {
      const tail = (this.tail ??= await this.readTail());
      const full: AuditRecord = { ...rec, seq: tail.seq + 1, prev: tail.prev };
      const line = JSON.stringify(encrypt(this.key, PURPOSE, JSON.stringify(full)));
      await this.rotateIfNeeded(line.length + 1);
      await this.write(line + '\n');
      this.tail = { prev: sha256(line), seq: tail.seq + 1 };
      await writeFileAtomic(this.headFile, JSON.stringify(encrypt(this.key, HEAD_PURPOSE, JSON.stringify(this.tail))));
      if (this.anchor && Date.now() - this.anchored >= ANCHOR_EVERY_MS) {
        this.anchored = Date.now();
        this.anchor.set(this.name, full.seq!);
      }
      return full;
    });
    this.queue = run.then(
      () => {
        this.failing = false;
      },
      () => {
        this.failing = true;
        this.tail = undefined; // re-read the tail next time
      },
    );
    return run;
  }

  /** After a failure: checks whether the file can be opened for appending again. */
  async recheck(): Promise<void> {
    const h = await open(this.file, 'a', 0o600).catch(() => null);
    if (!h) return;
    await h.close();
    this.failing = false;
  }

  idle(): Promise<void> {
    return this.queue;
  }

  /** Records newest first; undecryptable lines are skipped. */
  async *newestFirst(): AsyncGenerator<AuditRecord> {
    for (const f of this.files()) {
      const lines = await readLines(f);
      for (let i = lines.length - 1; i >= 0; i--) {
        const r = this.parse(lines[i]!);
        if (r) yield r;
      }
    }
  }

  async verify(): Promise<{ records: number; problems: string[]; dropped: number }> {
    const problems: string[] = [];
    let records = 0;
    let dropped = 0;
    let head: Awaited<ReturnType<Chain['readHead']>> = null;
    try {
      head = await this.readHead();
    } catch {
      problems.push(`${path.basename(this.headFile)}: cannot decrypt`);
    }
    // Oldest file first; the chain runs across rotations. The very first record kept may point at a
    // line in a file that has since been dropped, so it is the only one whose link is not checked.
    let prev: string | undefined;
    let seq: number | undefined;
    for (const f of this.files().reverse()) {
      const lines = await readLines(f);
      lines.forEach((line, i) => {
        const at = `${path.basename(f)}:${i + 1}`;
        const r = this.parse(line);
        if (!r) problems.push(`${at}: cannot decrypt`);
        else {
          records++;
          if (prev !== undefined && r.prev !== prev) problems.push(`${at}: chain broken`);
          else if (seq !== undefined && r.seq !== seq + 1) problems.push(`${at}: sequence broken`);
          if (prev === undefined && r.seq !== undefined) dropped = r.seq - 1;
          seq = r.seq;
        }
        prev = sha256(line);
        if (head && r?.seq === head.seq && prev !== head.prev) problems.push(`${at}: differs from the recorded head`);
      });
    }
    // Rotation drops records only once every kept file exists; otherwise they were removed.
    if (dropped > 0 && !(await exists(this.rotated(this.keep)))) problems.push(`${this.name}: ${dropped} oldest record(s) missing`);
    const anchor = this.anchor?.get(this.name) ?? 0;
    if (anchor > Math.max(seq ?? 0, head?.seq ?? 0)) problems.push(`${this.name}: ${anchor - (seq ?? 0)} newest record(s) missing`);
    if (head && (seq ?? 0) < head.seq) problems.push(`${path.basename(this.file)}: ${head.seq - (seq ?? 0)} newest record(s) missing`);
    return { records, problems, dropped };
  }

  private async write(text: string): Promise<void> {
    await mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const h = await open(this.file, 'a', 0o600);
    try {
      await h.write(text);
      await h.datasync();
    } finally {
      await h.close();
    }
  }

  private parse(line: string): AuditRecord | null {
    try {
      return JSON.parse(decrypt(this.key, PURPOSE, JSON.parse(line)).toString('utf8')) as AuditRecord;
    } catch {
      return null;
    }
  }

  /** Current file first, then audit.1.log, audit.2.log, … */
  private files(): string[] {
    const out = [this.file];
    for (let i = 1; i <= this.keep; i++) out.push(this.rotated(i));
    return out;
  }

  private rotated(i: number): string {
    const ext = path.extname(this.file);
    return path.join(path.dirname(this.file), `${path.basename(this.file, ext)}.${i}${ext}`);
  }

  private async readTail(): Promise<{ prev: string; seq: number }> {
    const head = await this.readHead().catch(() => null);
    const tail = await this.lastLine();
    if (head && tail.seq < head.seq) {
      // Continue after the missing records instead of reusing their numbers, so verify() keeps reporting the gap.
      log.error('Audit log is missing its newest records', { file: path.basename(this.file), missing: head.seq - tail.seq });
      return head;
    }
    const anchor = this.anchor?.get(this.name) ?? 0;
    if (tail.seq < anchor) {
      log.error('Audit log files have been removed or replaced', { file: this.name, missing: anchor - tail.seq });
      return { prev: tail.prev, seq: anchor };
    }
    return tail;
  }

  private async lastLine(): Promise<{ prev: string; seq: number }> {
    // The current file is missing if the process stopped between rotating and writing.
    for (const f of this.files()) {
      const line = (await readLines(f)).at(-1);
      if (!line) continue;
      const seq = this.parse(line)?.seq;
      return { prev: sha256(line), seq: seq ?? (await this.countRecords()) };
    }
    return { prev: '', seq: 0 };
  }

  /** Where numbering starts in a log written before sequence numbers existed. */
  private async countRecords(): Promise<number> {
    let n = 0;
    for (const f of this.files()) n += (await readLines(f)).length;
    return n;
  }

  private async rotateIfNeeded(adding: number): Promise<void> {
    const size = await stat(this.file).then((s) => s.size, () => 0);
    if (size === 0 || size + adding <= this.maxBytes) return;
    const last = (await readLines(this.rotated(this.keep))).at(-1);
    const newest = last ? this.parse(last)?.at : undefined;
    if (newest && Date.now() - Date.parse(newest) < RAPID_ROTATION_MS) {
      log.warn('Audit log is rotating fast; recent records are being dropped', { file: path.basename(this.file), droppedUpTo: newest });
    }
    for (let i = this.keep - 1; i >= 1; i--) await rename(this.rotated(i), this.rotated(i + 1)).catch(() => undefined);
    await rename(this.file, this.rotated(1));
  }
}

export class AuditLog {
  private readonly calls: Chain;
  private readonly protectedChain: Chain;
  private gelfWarned = 0;

  constructor(
    file: string,
    key: Key,
    private readonly opts: AuditOptions = {},
  ) {
    const maxBytes = opts.maxBytes ?? 10 * 1024 * 1024;
    const ext = path.extname(file);
    const protectedFile = path.join(path.dirname(file), `${path.basename(file, ext)}-protected${ext}`);
    this.calls = new Chain(file, key, maxBytes, opts.keep ?? 5, opts.anchor);
    this.protectedChain = new Chain(protectedFile, key, maxBytes, opts.keepProtected ?? 20, opts.anchor);
  }

  static forDataDir(dataDir: string, key: Key, opts?: AuditOptions): AuditLog {
    return new AuditLog(path.join(dataDir, 'audit.log'), key, opts);
  }

  /** False after a failed append, until one succeeds. Write tools are refused while false. */
  writable(): boolean {
    return !this.calls.failing && !this.protectedChain.failing;
  }

  /** Appends one record and resolves once it is on disk (fsynced). */
  async record(input: AuditInput): Promise<AuditRecord> {
    const denied = input.outcome === 'denied';
    const rec: Omit<AuditRecord, 'prev' | 'seq'> = {
      id: randomBytes(8).toString('hex'),
      at: new Date().toISOString(),
      ...input,
      tool: input.tool.slice(0, MAX_FIELD_CHARS),
      backend: input.backend.slice(0, MAX_FIELD_CHARS),
      args: capArgs(input.args, denied ? MAX_DENIED_ARGS_CHARS : MAX_ARGS_CHARS),
      ...(input.message ? { message: String(redact(input.message)).slice(0, 2000) } : {}),
    };
    // Refusals can be produced in bulk by any credential, so they never go to the protected chain.
    const chain = !denied && (input.access === 'write' || input.source === 'admin') ? this.protectedChain : this.calls;
    try {
      const done = await chain.append(rec);
      // Write tools are refused while the protected chain is failing, so nothing else would retry it.
      if (this.protectedChain.failing) await this.protectedChain.recheck();
      this.forward(done);
      return done;
    } catch (err) {
      log.error('Audit log write failed', { error: errMessage(err) });
      throw err;
    }
  }

  /** Newest first, across both chains and their rotated files, until `limit` records match. */
  async list(filter: AuditFilter = {}, limit = 100): Promise<AuditRecord[]> {
    const pick = async (c: Chain) => {
      await c.idle();
      const out: AuditRecord[] = [];
      for await (const r of c.newestFirst()) {
        if (matches(r, filter) && out.push(r) >= limit) break;
      }
      return out;
    };
    const found = (await Promise.all([pick(this.calls), pick(this.protectedChain)])).flat();
    return found.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0)).slice(0, limit);
  }

  /**
   * Usage summary of every tool call at or after `since` (all when omitted):
   * totals, and calls per backend, tool, user and day. Arguments and
   * administrative events are not part of it.
   */
  async stats(since?: string): Promise<AuditStats> {
    const acc = new UsageCounter();
    for (const c of [this.calls, this.protectedChain]) {
      await c.idle();
      for await (const r of c.newestFirst()) {
        if (since && r.at < since) break;
        if (r.source !== 'admin' && r.source !== 'web' && r.outcome !== 'started') acc.add(r);
      }
    }
    return acc.result(since ?? null);
  }

  /**
   * Checks every line decrypts and that both hash chains are unbroken.
   * `dropped` is how many older records rotation has removed (records from
   * before sequence numbers are not counted).
   */
  async verify(): Promise<{ ok: boolean; records: number; dropped: number; problems: string[] }> {
    const out = { ok: true, records: 0, dropped: 0, problems: [] as string[] };
    for (const c of [this.calls, this.protectedChain]) {
      await c.idle();
      const v = await c.verify();
      out.records += v.records;
      out.dropped += v.dropped;
      out.problems.push(...v.problems);
    }
    out.ok = out.problems.length === 0;
    return out;
  }

  /** GELF over HTTP to Graylog, fire and forget; failures are logged at most once a minute. */
  private forward(r: AuditRecord): void {
    const url = this.opts.gelfUrl?.();
    if (!url) return;
    const level = r.outcome === 'ok' || r.outcome === 'started' ? 6 : r.outcome === 'denied' ? 4 : 3;
    const gelf = {
      version: '1.1',
      host: 'socbridge',
      short_message: `${r.tool} ${r.outcome} (${r.access}) by ${r.user}`,
      timestamp: Date.parse(r.at) / 1000,
      level,
      _audit_id: r.id,
      // An external anchor for the chain: compare with the log if it may have been cut.
      _seq: r.seq,
      _prev: r.prev,
      _source: r.source,
      _user: r.user,
      _credential: r.credential,
      _tool: r.tool,
      _backend: r.backend,
      _access: r.access,
      _outcome: r.outcome,
      _duration_ms: r.durationMs,
      _args: JSON.stringify(r.args),
      ...(r.message ? { _message: r.message } : {}),
      ...(r.resultSha256 ? { _result_sha256: r.resultSha256, _result_chars: r.resultChars } : {}),
    };
    if (forbiddenUrl(url)) return;
    fetch(url, {
      dispatcher: agent,
      redirect: 'error',
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(gelf),
      signal: AbortSignal.timeout(5000),
    })
      .then((res) => {
        if (!res.ok) throw new Error(`GELF input responded ${res.status}`);
        return res.body?.cancel();
      })
      .catch((err) => {
        if (Date.now() - this.gelfWarned < 60_000) return;
        this.gelfWarned = Date.now();
        log.warn('Audit forwarding to Graylog failed', { error: errMessage(err) });
      });
  }
}

async function exists(file: string): Promise<boolean> {
  return stat(file).then(() => true, () => false);
}

async function readLines(file: string): Promise<string[]> {
  try {
    return (await readFile(file, 'utf8')).split('\n').filter(Boolean);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}

function matches(r: AuditRecord, f: AuditFilter): boolean {
  if (f.before && r.at >= f.before) return false;
  if (f.user && r.user !== f.user) return false;
  if (f.tool && !r.tool.includes(f.tool)) return false;
  if (f.backend && r.backend !== f.backend) return false;
  if (f.outcome && r.outcome !== f.outcome) return false;
  if (f.access && r.access !== f.access) return false;
  return true;
}

export interface UsageCount {
  calls: number;
  errors: number;
  denied: number;
  writes: number;
  totalMs: number;
}

export interface AuditStats {
  since: string | null;
  totals: UsageCount & { users: number; first: string | null; last: string | null };
  bySource: Record<string, number>;
  byBackend: Array<UsageCount & { backend: string }>;
  byTool: Array<UsageCount & { tool: string; backend: string }>;
  byDay: Array<{ day: string; calls: number; errors: number }>;
  byUser: Array<
    UsageCount & {
      user: string;
      lastAt: string;
      sources: Record<string, number>;
      backends: Record<string, number>;
      tools: Array<{ tool: string; calls: number }>;
      credentials: Array<{ credential: string; label: string; calls: number }>;
    }
  >;
}

const zero = (): UsageCount => ({ calls: 0, errors: 0, denied: 0, writes: 0, totalMs: 0 });
function bump(c: UsageCount, r: AuditRecord): void {
  c.calls++;
  if (r.outcome === 'error') c.errors++;
  if (r.outcome === 'denied') c.denied++;
  if (r.access === 'write') c.writes++;
  c.totalMs += r.durationMs || 0;
}
const byCalls = (a: { calls: number }, b: { calls: number }) => b.calls - a.calls;

class UsageCounter {
  private total = zero();
  private first: string | null = null;
  private last: string | null = null;
  private sources: Record<string, number> = {};
  private backends = new Map<string, UsageCount>();
  private tools = new Map<string, UsageCount & { backend: string }>();
  private days = new Map<string, { calls: number; errors: number }>();
  private users = new Map<
    string,
    UsageCount & { lastAt: string; sources: Record<string, number>; backends: Record<string, number>; tools: Map<string, number>; creds: Map<string, { label: string; calls: number }> }
  >();

  add(r: AuditRecord): void {
    bump(this.total, r);
    if (!this.last || r.at > this.last) this.last = r.at;
    if (!this.first || r.at < this.first) this.first = r.at;
    this.sources[r.source] = (this.sources[r.source] ?? 0) + 1;

    let b = this.backends.get(r.backend);
    if (!b) this.backends.set(r.backend, (b = zero()));
    bump(b, r);

    let t = this.tools.get(r.tool);
    if (!t) this.tools.set(r.tool, (t = { ...zero(), backend: r.backend }));
    bump(t, r);

    const day = r.at.slice(0, 10);
    const d = this.days.get(day) ?? { calls: 0, errors: 0 };
    d.calls++;
    if (r.outcome !== 'ok') d.errors++;
    this.days.set(day, d);

    let u = this.users.get(r.user);
    if (!u) this.users.set(r.user, (u = { ...zero(), lastAt: r.at, sources: {}, backends: {}, tools: new Map(), creds: new Map() }));
    bump(u, r);
    if (r.at > u.lastAt) u.lastAt = r.at;
    u.sources[r.source] = (u.sources[r.source] ?? 0) + 1;
    u.backends[r.backend] = (u.backends[r.backend] ?? 0) + 1;
    u.tools.set(r.tool, (u.tools.get(r.tool) ?? 0) + 1);
    const label = r.source === 'chat' ? 'Assistant' : r.credentialLabel || r.credential;
    const c = u.creds.get(r.credential) ?? { label, calls: 0 };
    c.calls++;
    u.creds.set(r.credential, c);
  }

  result(since: string | null): AuditStats {
    return {
      since,
      totals: { ...this.total, users: this.users.size, first: this.first, last: this.last },
      bySource: this.sources,
      byBackend: [...this.backends].map(([backend, c]) => ({ backend, ...c })).sort(byCalls),
      byTool: [...this.tools].map(([tool, c]) => ({ tool, ...c })).sort(byCalls),
      byDay: [...this.days].map(([day, c]) => ({ day, ...c })).sort((a, b) => a.day.localeCompare(b.day)),
      byUser: [...this.users]
        .map(([user, u]) => ({
          user,
          calls: u.calls,
          errors: u.errors,
          denied: u.denied,
          writes: u.writes,
          totalMs: u.totalMs,
          lastAt: u.lastAt,
          sources: u.sources,
          backends: u.backends,
          tools: [...u.tools].map(([tool, calls]) => ({ tool, calls })).sort(byCalls).slice(0, 10),
          credentials: [...u.creds].map(([credential, c]) => ({ credential, ...c })).sort(byCalls),
        }))
        .sort(byCalls),
    };
  }
}
