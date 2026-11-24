import assert from 'node:assert/strict';
import { mkdtemp, rm, utimes, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { edgeMap } from '../backends/graylog/firewall.js';
import { GeoIp, type GeoLookup } from '../geoip.js';

const { buildMmdb, SAMPLE } = (await import(new URL('../../scripts/e2e/mmdb.mjs', import.meta.url).href)) as {
  buildMmdb: (n: object, type?: string) => Buffer;
  SAMPLE: object;
};
const NOW = Date.parse('2026-11-24T10:30:20Z');
const geo: GeoLookup = { lookup: (ip) => (ip === 'nowhere' ? null : { lat: 1, lon: 2, country: 'X' }) };

function stub(answer: (b: any) => unknown[][]) {
  const bodies: any[] = [];
  const request = async (_p: string, o: { json: any }) => {
    bodies.push(o.json);
    return { datarows: answer(o.json) };
  };
  return { rt: { headers: {}, firewallQuery: 'fw OR x', ipsQuery: 'ips', http: { request } } as never, bodies };
}
const answer = (b: any): unknown[][] => {
  const [g, t] = b.group_by;
  if (t) return b.query.includes('"scan"') && !b.query.includes('NOT src_ip') ? [['scan', '2026-11-24T09:00:00.000Z', 40]] : [['a', '2026-11-24T10:00:00.000Z', 7], ['nowhere', '2026-11-24T10:00:00.000Z', 3]];
  if (g.field === 'src_ip') return b.metrics.length === 2 ? [['scan', 90, 30], ['a', 50, 1]] : b.query.startsWith('((') || !b.query.includes('"scan"') || b.query.includes('NOT') ? [['a" OR *', 9], ['nowhere', 3], ['-', 2]] : [['scan', 40]];
  return [['fw1', 100]];
};
const since = '2026-11-23T10:30:20Z';

test('edge map: sums per source and slot, leaves scanners out of firewall blocks', async () => {
  const { rt, bodies } = stub(answer);
  const m = await edgeMap(rt, geo, { since, layers: ['port_scan', 'firewall'] }, NOW);
  assert.deepEqual([m.since, m.to], ['2026-11-23T10:30:00.000Z', '2026-11-24T10:29:00.000Z']);
  assert.deepEqual(m.events.map((e) => [e.category, e.ip, e.n]), [['port_scan', 'scan', 40], ['firewall', 'a', 7]]);
  assert.equal(m.without_location, 1);
  const at = m.events[1]!.at;
  assert.ok(at >= Date.parse('2026-11-24T10:00:00Z') && at < Date.parse(m.to));
  const slots = bodies.filter((b) => b.group_by.length === 2);
  assert.ok(slots.some((b) => b.query.startsWith('((fw OR x) AND NOT src_ip:("scan")) AND src_ip:("a\\" OR *"')), slots[1]?.query);
  // Never distinct counts per source and slot: OpenSearch runs out of memory.
  assert.ok(slots.every((b) => b.metrics.length === 1 && b.metrics[0].function === 'count'));
  const before = bodies.length;
  await edgeMap(rt, geo, { since, layers: ['port_scan', 'firewall'] }, NOW + 5000);
  assert.equal(bodies.length, before, 'viewers share one answer');
});

test('edge map: follow-up requests do not overlap, and only asked layers are read', async () => {
  const { rt, bodies } = stub(answer);
  const m = await edgeMap(rt, geo, { since: '2026-11-24T10:27:00Z', layers: ['ips'] }, NOW);
  assert.equal(m.step_seconds, 60);
  assert.ok(bodies.every((b) => b.query.includes('ips')));
  const n = bodies.length;
  assert.deepEqual((await edgeMap(rt, geo, { since: m.to, layers: ['ips'] }, NOW)).events, []);
  assert.equal(bodies.length, n);
});

test('edge map: one failing layer does not hide the others; all failing is an error', async () => {
  const { rt } = stub((b) => {
    if (b.query.includes('ips')) throw new Error('host secret');
    return answer(b);
  });
  const m = await edgeMap(rt, geo, { since, layers: ['port_scan', 'ips'] }, NOW);
  assert.deepEqual(m.categories.map((c) => c.error), [null, 'could not be read from Graylog']);
  await assert.rejects(edgeMap(rt, geo, { since, layers: ['ips'] }, NOW), /secret/);
});

test('geoip: reads a city database, picks up a new file, refuses one without positions', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'geo-'));
  t.after(() => rm(dir, { recursive: true }));
  const file = path.join(dir, 'g.mmdb');
  const g = new GeoIp(file);
  assert.equal(await g.ready(0), false);
  await writeFile(file, buildMmdb(SAMPLE));
  assert.equal(await g.ready(1000), false); // not looked for again yet
  assert.equal(await g.ready(61_000), true);
  assert.deepEqual(g.lookup('203.0.113.9'), { lat: 52.37, lon: 4.9, country: 'Netherlands' });
  assert.equal(g.lookup('203.0.113.77')?.country, 'Brazil');
  for (const ip of ['198.51.100.1', '2001:db8::1', 'x" OR *']) assert.equal(g.lookup(ip), null);
  await writeFile(file, 'broken');
  await utimes(file, 1, 1);
  assert.equal(await g.ready(200_000), true); // the previous one stays in use
  assert.ok(g.lookup('203.0.113.9'));
  await writeFile(file, buildMmdb(SAMPLE, 'GeoLite2-Country'));
  const other = new GeoIp(file);
  assert.equal(await other.ready(0), false);
});
