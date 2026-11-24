import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attackWindow, ATTACK_WINDOWS, iso } from '../backends/attack-window.js';
import { firewallDetails, firewallTrend } from '../backends/graylog/firewall.js';
import { graylog } from '../backends/graylog/index.js';

const NOW = Date.parse('2026-11-23T17:30:00Z');

test('attack window: presets and any range get a readable number of columns', () => {
  for (const window of ATTACK_WINDOWS) {
    const w = attackWindow({ window }, NOW);
    assert.ok(w.columns >= 24 && w.columns <= 62, `${window}: ${w.columns}`);
    assert.equal(w.from, w.gridFrom);
  }
  const range = (from: string, to?: string) => attackWindow({ window: '7d', from, to }, NOW);
  const months = range('2026-03-01T23:00:00Z', '2026-06-01T22:00:00Z');
  assert.equal(iso(months.from), '2026-03-01T23:00:00.000Z');
  assert.ok(months.gridFrom <= months.from && months.columns <= 62);
  assert.equal(months.previousFrom, months.from - (months.to - months.from));
  assert.equal(range('2026-11-20T00:00:00Z', '2027-01-01T00:00:00Z').to, NOW); // never into the future
  assert.ok(range('2021-12-01T00:00:00Z').columns <= 62);
  assert.throws(() => range('2026-11-20T00:00:00Z', '2026-11-19T00:00:00Z'), /Invalid time range/);
  assert.throws(() => range('2027-01-01T00:00:00Z'), /Invalid time range/);
  assert.throws(() => range('2010-01-01T00:00:00Z'), /limited/);
  assert.throws(() => attackWindow({ window: '7d', to: '2026-11-20T00:00:00Z' }, NOW), /to needs from/);
});

/** Graylog stub: answers aggregations from a function, records bodies. */
function stub(answer: (b: any) => unknown[][], oldest = '2026-10-06T00:00:00.000Z', firewallQuery = 'fw') {
  const bodies: any[] = [];
  const rt = {
    headers: {},
    firewallQuery,
    ipsQuery: 'ips',
    http: {
      request: async (p: string, o: { json: any }) => {
        bodies.push({ path: p, ...o.json });
        return p.endsWith('/messages') ? { schema: [{ field: 'timestamp' }], datarows: [[oldest]] } : { datarows: answer(o.json) };
      },
    },
  };
  return { rt: rt as never, bodies };
}

const trendAnswer = (b: any) => {
  const [g] = b.group_by;
  if (g.field === 'src_ip') return [['p2p', 900, 1], ['a', 70, 30], ['-', 50, 40]];
  if (g.field === 'dst_port') return [['58333', 600], ['23', 4], ['-', 100]];
  if (g.timeunit) return b.query.includes('src_ip:') ? [['2026-11-23T16:00:00.000Z', 50, 1], ['2026-11-23T17:00:00.000Z', 20, 1]] : [['2026-11-23T17:00:00.000Z', 7, 3]];
  return [['fw1', 1000, 3]];
};

test('graylog: firewall trend finds scanners without counting ports per source and column', async () => {
  const { rt, bodies } = stub(trendAnswer);
  const t = await firewallTrend(rt, { window: '24h' }, NOW);
  const [scan, firewall] = t.categories;
  assert.deepEqual([scan!.id, scan!.attempts, scan!.unique_ips], ['port_scan', 70, 1]);
  assert.deepEqual(scan!.points.slice(-2), [{ attempts: 50, unique_ips: 1 }, { attempts: 20, unique_ips: 1 }]);
  assert.deepEqual(firewall!.points.at(-1), { attempts: 7, unique_ips: 3 });
  assert.deepEqual(firewall!.previous, { attempts: 1000, unique_ips: 3 });
  const aggs = bodies.filter((b) => b.group_by);
  // OpenSearch runs out of memory when distinct values are counted per source and column, or sorted on.
  for (const b of aggs) {
    assert.equal(b.group_by.length, 1);
    assert.ok(b.metrics.every((m: any) => !m.sort));
    assert.ok(!(b.group_by[0].limit && b.group_by[0].timeunit));
  }
  // The noisy port is left out of the scanner search, ordinary ones are not.
  assert.equal(aggs.find((b) => b.group_by[0].field === 'src_ip').query, '(fw) AND NOT dst_port:58333');
  assert.ok(aggs.some((b) => b.group_by[0].timeunit && b.query === '(fw) AND src_ip:("a")'));
  const short = await firewallTrend(stub(trendAnswer, '2026-11-22T20:00:00.000Z').rt, { window: '24h' }, NOW);
  assert.ok(short.categories.every((c) => c.previous === null));
  assert.equal(short.data_from, '2026-11-22T20:00:00.000Z');
});

test('graylog: one failing firewall category does not hide the others', async () => {
  const { rt } = stub((b) => {
    if (b.group_by[0].field === 'src_ip') throw new Error('Data too large');
    return trendAnswer(b);
  });
  const t = await firewallTrend(rt, { window: '24h' }, NOW);
  assert.deepEqual(t.categories.map((c) => c.error), ['Data too large', null, null]);
  const { rt: dead } = stub(() => { throw new Error('down'); });
  await assert.rejects(firewallTrend(dead, { window: '24h' }, NOW), /down/);
});

test('graylog: scan details keep the configured query apart and quote addresses', async () => {
  const { rt, bodies } = stub((b) => {
    const f = b.group_by[0].field;
    return f === 'src_ip' ? [['p2p', 900, 1], ['1.2.3.4" OR *', 9, 12]] : f === 'source' ? [['fw1', 1000]] : [['23', 4], ['-', 2]];
  }, undefined, 'a OR b');
  const d = await firewallDetails(rt, { category: 'port_scan', from: '2026-11-22T00:00:00Z', to: '2026-11-23T00:00:00Z', top: 10, limit: 5 });
  assert.deepEqual(d.top_ips.map((x) => x.key), ['1.2.3.4" OR *']);
  assert.deepEqual(d.top_ports, [{ key: '23', count: 4 }]);
  assert.equal(bodies.find((b) => b.path.endsWith('/messages')).query, '(a OR b) AND src_ip:("1.2.3.4\\" OR *")');
});

test('graylog: firewall queries fall back to the defaults when empty', () => {
  const r = graylog.schema.safeParse({ url: 'https://g:9000', apiToken: 't', firewallQuery: ' ', ipsQuery: 'x' });
  assert.ok(r.success);
  const cfg = r.data as { firewallQuery: string; ipsQuery: string };
  assert.deepEqual([cfg.firewallQuery, cfg.ipsQuery], ['fw_action:drop AND fw_chain:WAN_LOCAL', 'x']);
});
