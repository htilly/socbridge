import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { readOpenFindings, VulnerabilitySnapshots, type OpenFinding } from '../backends/wazuh/snapshots.js';

const T0 = Date.parse('2026-11-20T06:00:00Z');
const H = 3_600_000;
const KEY = Buffer.alloc(32, 7);
const f = (agent: string, cve: string, pkg = 'curl', severity = 'High'): OpenFinding => ({ agent, cve, package: pkg, severity });

async function setup() {
  const dir = await mkdtemp(path.join(tmpdir(), 'snap-'));
  let open: OpenFinding[] = [];
  let extra: object = {};
  const client = {
    cfg: { indexerUrl: 'https://i', vulnerabilitiesIndex: 'v' },
    search: async () => ({ ...extra, aggregations: { findings: { buckets: open.map((key) => ({ key, doc_count: 1 })) } } }),
  } as never;
  const snaps = VulnerabilitySnapshots.forDataDir(dir, KEY);
  const at = (hours: number, list: OpenFinding[]) => ((open = list), snaps.take(client, T0 + hours * H));
  const sum = (s = snaps) => (s.history(client)?.changes ?? []).map((c) => [c.day, c.agent, c.severity, c.new, c.resolved]);
  return { dir, client, snaps, at, sum, setExtra: (e: object) => (extra = e) };
}

test('snapshots: the first snapshot is the starting point, later additions are new', async () => {
  const { at, sum, snaps, client } = await setup();
  assert.equal(await at(0, [f('001', 'A')]), true);
  assert.deepEqual(sum(), []);
  assert.equal(await at(0.5, [f('001', 'A'), f('001', 'B')]), false, 'not due yet');
  await at(1, [f('001', 'A'), f('001', 'B'), f('002', 'A')]);
  // 002 is seen for the first time: a starting point as well
  assert.deepEqual(sum(), [['2026-11-20', '001', 'High', 1, 0]]);
  assert.equal(snaps.history(client)!.since, T0);
});

test('snapshots: resolved only after staying away, on the day it went', async () => {
  const { at, sum } = await setup();
  await at(0, [f('001', 'A'), f('001', 'B')]);
  await at(17, [f('001', 'A')]); // 23:00
  await at(19, [f('001', 'A'), f('001', 'B')]); // back: the index was rebuilt
  assert.deepEqual(sum(), []);
  await at(20, [f('001', 'A')]); // 02:00 the next day
  await at(25, [f('001', 'A')]);
  assert.deepEqual(sum(), []);
  await at(26, [f('001', 'A')]);
  assert.deepEqual(sum(), [['2026-11-21', '001', 'High', 0, 1]]);
  await at(30, [f('001', 'A'), f('001', 'B')]); // really back
  assert.deepEqual(sum(), [['2026-11-21', '001', 'High', 1, 1]]);
});

test('snapshots: an agent or index without data resolves nothing', async () => {
  const { at, sum } = await setup();
  await at(0, [f('001', 'A'), f('002', 'A')]);
  await at(8, []);
  await at(16, [f('001', 'A')]);
  await at(24, [f('001', 'A')]);
  await at(32, [f('001', 'A'), f('002', 'A')]);
  assert.deepEqual(sum(), []);
});

test('snapshots: incomplete answers are refused', async () => {
  const { at, sum, setExtra, client } = await setup();
  await at(0, [f('001', 'A')]);
  for (const bad of [{ timed_out: true }, { _shards: { failed: 1 } }]) {
    setExtra(bad);
    await assert.rejects(at(2, [f('001', 'B')]), /incomplete/);
  }
  assert.deepEqual(sum(), []);
  await assert.rejects(readOpenFindings({ ...(client as object), search: async () => ({}) } as never), /no list/);
});

test('snapshots: persisted encrypted, kept per index, unreadable file kept aside', async () => {
  const { dir, at, sum, client } = await setup();
  await at(0, [f('001', 'CVE-X')]);
  await at(1, [f('001', 'CVE-X'), f('001', 'CVE-Y')]);
  const file = path.join(dir, 'vulnerability-snapshots.enc.json');
  assert.equal((await readFile(file, 'utf8')).includes('CVE-'), false);
  const again = VulnerabilitySnapshots.forDataDir(dir, KEY);
  await again.load();
  assert.deepEqual(sum(again), [['2026-11-20', '001', 'High', 1, 0]]);
  assert.equal(again.history({ ...(client as object), cfg: { indexerUrl: 'https://other', vulnerabilitiesIndex: 'v' } } as never), null);
  await writeFile(file, 'broken');
  const fresh = VulnerabilitySnapshots.forDataDir(dir, KEY);
  await fresh.load();
  assert.equal(fresh.history(client), null);
  assert.deepEqual(await readdir(dir), ['vulnerability-snapshots.enc.json.unreadable']);
});

test('snapshots: reads every page', async () => {
  const afters: unknown[] = [];
  const pages = [Array.from({ length: 1000 }, (_, i) => f('001', `C${i}`)), [f('002', 'Z')]];
  const list = await readOpenFindings({
    cfg: {},
    search: async (_: string, b: any) => {
      const n = afters.push(b.aggs.findings.composite.after);
      return { aggregations: { findings: { buckets: pages[n - 1]!.map((key) => ({ key })), after_key: { n } } } };
    },
  } as never);
  assert.equal(list.length, 1001);
  assert.deepEqual(afters, [undefined, { n: 1 }]);
});
