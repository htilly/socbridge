import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import { registerAllTools } from '../mcp/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { wazuh } from '../backends/wazuh/index.js';
import { attackDetails, attackMap, attackTrend, isAttackCategory, parseMapTargets } from '../backends/wazuh/attacks.js';
import { agentInventory, agentSca, fimEvents, fimFiles, getAlert, getRules, listDecoders, listGroups, scaChecks, vulnerabilityTrend } from '../backends/wazuh/queries.js';

/** One mock answers both the manager API and the indexer, like the e2e mock. */
const seen: { method: string; path: string; query: Record<string, string>; body?: Record<string, unknown> }[] = [];
let server: http.Server;
let url: string;

const list = (items: unknown[], total = items.length) => ({ data: { affected_items: items, total_affected_items: total } });

before(async () => {
  server = http.createServer(async (req, res) => {
    const u = new URL(req.url!, 'http://x');
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString();
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    seen.push({ method: req.method!, path: u.pathname, query: Object.fromEntries(u.searchParams), body });
    const send = (s: number, o: unknown, text = false) => {
      res.writeHead(s, { 'content-type': text ? 'text/plain' : 'application/json' });
      res.end(text ? String(o) : JSON.stringify(o));
    };
    if (u.pathname === '/security/user/authenticate') return send(200, 'JWT', true);
    if (u.pathname === '/groups') return send(200, list([{ name: 'default', count: 4, configSum: 'a', mergedSum: 'b', extra: 'x' }]));
    if (u.pathname === '/sca/001') {
      return send(200, list([{ policy_id: 'cis_ubuntu22-04', name: 'CIS Ubuntu 22.04', score: 61, pass: 120, fail: 77, invalid: 3, total_checks: 200, end_scan: 't', description: 'long' }]));
    }
    if (u.pathname === '/sca/001/checks/cis_ubuntu22-04') {
      return send(200, list([{ id: 28500, title: 'Ensure /tmp is a separate partition', result: 'failed', remediation: 'r', compliance: [{ key: 'cis', value: '1.1.2' }], rules: ['x'] }], 77));
    }
    if (u.pathname === '/syscollector/001/os') {
      if (u.searchParams.size) return send(400, { title: 'extra parameter' });
      return send(200, list([{ agent_id: '001', os: { name: 'Ubuntu', version: '22.04' }, hostname: 'web-01' }]));
    }
    if (u.pathname === '/syscollector/001/packages') {
      return send(200, list([{ agent_id: '001', name: 'openssl', version: '3.0.2' }], 812));
    }
    if (u.pathname === '/rules') {
      return send(200, list([{ id: 5710, level: 5, description: 'sshd: Attempt to login using a non-existent user', groups: ['sshd'] }]));
    }
    if (u.pathname === '/decoders') {
      return send(200, list([{ name: 'sshd', position: 0, filename: '0310-ssh_decoders.xml', relative_dirname: 'ruleset/decoders', status: 'enabled', details: { program_name: '^sshd' } }]));
    }
    if (u.pathname === '/syscheck/001/last_scan') return send(200, list([{ start: '2026-11-21T06:00:00Z', end: '2026-11-21T06:02:00Z' }]));
    if (u.pathname === '/syscheck/002/last_scan') return send(403, { title: 'Permission denied' });
    if (u.pathname === '/syscheck/001' || u.pathname === '/syscheck/002') {
      return send(200, list([{ file: '/etc/passwd', type: 'file', size: 2048, perm: 'rw-r--r--', uname: 'root', sha256: 'ab'.repeat(32) }], 3120));
    }
    if (u.pathname.includes('states-vulnerabilities') && u.pathname.endsWith('/_search')) {
      return send(200, {
        hits: { total: { value: 12, relation: 'eq' }, hits: [] },
        aggregations: { by_agent: { buckets: [{ key: '002', doc_count: 10, name: { buckets: [{ key: 'db' }] } }, { key: '003', doc_count: 2, name: { buckets: [{ key: 'nas' }] } }] } },
      });
    }
    if (u.pathname.endsWith('/_search')) {
      const q = body as { query?: { ids?: { values: string[] } } };
      if (q.query?.ids) {
        const hits = q.query.ids.values[0] === 'abc123' ? [{ _id: 'abc123', _index: 'wazuh-alerts-4.x-2026.11.21', _source: { rule: { id: '5710' } } }] : [];
        return send(200, { hits: { total: { value: hits.length, relation: 'eq' }, hits } });
      }
      return send(200, {
        hits: { total: { value: 1, relation: 'eq' }, hits: [{ _id: 'f1', _index: 'i', _source: { syscheck: { path: '/etc/passwd', event: 'modified' } } }] },
        aggregations: { by_event: { buckets: [{ key: 'modified', doc_count: 1 }] }, by_agent: { buckets: [] }, top_paths: { buckets: [{ key: '/etc/passwd', doc_count: 1 }] } },
      });
    }
    send(404, { title: 'Not found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((r) => server.close(() => r())));

const rt = (indexer = true) =>
  wazuh.createRuntime({
    managerUrl: url,
    managerUser: 'ro',
    managerPassword: 'x',
    ...(indexer ? { indexerUrl: url, indexerUser: 'ro', indexerPassword: 'x' } : {}),
    alertsIndex: 'wazuh-alerts-*',
    vulnerabilitiesIndex: 'wazuh-states-vulnerabilities-*',
    tlsVerify: true,
  } as never);

const last = () => seen.at(-1)!;

test('wazuh: groups keep only the useful fields', async () => {
  const r = await listGroups(rt(), { limit: 10, offset: 0 });
  assert.deepEqual(r.groups, [{ name: 'default', count: 4, configSum: 'a', mergedSum: 'b' }]);
  assert.equal(last().query.sort, '+name');
});

test('wazuh: SCA policies and checks', async () => {
  const p = await agentSca(rt(), { agent_id: '1' });
  assert.equal(p.agent_id, '001');
  assert.equal(p.policies[0]!.score, 61);
  assert.equal((p.policies[0] as Record<string, unknown>).description, undefined);

  const c = await scaChecks(rt(), { agent_id: '001', policy_id: 'cis_ubuntu22-04', result: 'failed', limit: 5, offset: 0 });
  assert.equal(last().query.result, 'failed');
  assert.equal(c.total, 77);
  assert.equal(c.checks[0]!.remediation, 'r');
  assert.equal(c.checks[0]!.rules, undefined, 'only the listed check fields are kept');
  await assert.rejects(scaChecks(rt(), { agent_id: '001', policy_id: '../agents', limit: 5, offset: 0 }), /Invalid policy id/);
});

test('wazuh: inventory sends no paging for os, pages lists, drops agent_id', async () => {
  const os = await agentInventory(rt(), { agent_id: '001', kind: 'os', search: 'x', limit: 10, offset: 0 });
  assert.deepEqual(last().query, {});
  assert.equal(((os as Record<string, unknown>).os as Record<string, unknown>).hostname, 'web-01');
  assert.equal(((os as Record<string, unknown>).os as Record<string, unknown>).agent_id, undefined);

  const pk = await agentInventory(rt(), { agent_id: '001', kind: 'packages', search: 'openssl', limit: 10, offset: 20 });
  assert.equal(last().query.search, 'openssl');
  assert.equal(last().query.offset, '20');
  assert.equal(pk.total, 812);
  await assert.rejects(agentInventory(rt(), { agent_id: '001', kind: 'secrets' as never, limit: 1, offset: 0 }), /Unknown inventory kind/);
});

test('wazuh: rules by id report the ones not found', async () => {
  const r = await getRules(rt(), ['5710', '99999']);
  assert.equal(last().query.rule_ids, '5710,99999');
  assert.equal(r.rules.length, 1);
  assert.deepEqual(r.not_found, ['99999']);
  await assert.rejects(getRules(rt(), ['5710 OR 1']), /Invalid rule id/);
});

test('wazuh: FIM events filter on syscheck group, path prefix and event', async () => {
  const r = await fimEvents(rt(), { agent_id: '2', path: '/etc/*', event: ['modified', 'deleted'], since: '7d', limit: 10 });
  const filter = (last().body as { query: { bool: { filter: unknown[] } } }).query.bool.filter;
  assert.deepEqual(filter, [
    { range: { timestamp: { gte: 'now-7d' } } },
    { term: { 'rule.groups': 'syscheck' } },
    { term: { 'agent.id': '002' } },
    { terms: { 'syscheck.event': ['modified', 'deleted'] } },
    { prefix: { 'syscheck.path': '/etc/' } },
  ]);
  assert.deepEqual(r.by_event, { modified: 1 });
  assert.equal(r.events[0]!.id, 'f1');

  await fimEvents(rt(), { path: '/etc/passwd', since: '24h', limit: 10 });
  const f2 = (last().body as { query: { bool: { filter: unknown[] } } }).query.bool.filter;
  assert.deepEqual(f2.at(-1), { term: { 'syscheck.path': '/etc/passwd' } });
});

test('wazuh: alert by id', async () => {
  const a = await getAlert(rt(), 'abc123');
  assert.equal(a?.index, 'wazuh-alerts-4.x-2026.11.21');
  assert.equal(await getAlert(rt(), 'nope'), null);
  await assert.rejects(getAlert(rt(), 'a/b'), /Invalid alert id/);
});

test('wazuh: decoders by name, names are validated', async () => {
  const r = await listDecoders(rt(), { names: ['sshd'], limit: 10, offset: 0 });
  assert.equal(last().query.decoder_names, 'sshd');
  assert.equal(r.decoders[0]!.filename, '0310-ssh_decoders.xml');
  await assert.rejects(listDecoders(rt(), { names: ['a,b'], limit: 1, offset: 0 }), /Invalid decoder name/);
});

test('wazuh: FIM state with last scan; a failing last_scan is null, not an error', async () => {
  const r = await fimFiles(rt(), { agent_id: '1', search: 'passwd', hash: 'AB'.repeat(32), limit: 10, offset: 0 });
  const call = seen.find((c) => c.path === '/syscheck/001')!;
  assert.equal(call.query.search, 'passwd');
  assert.equal(call.query.hash, 'ab'.repeat(32), 'hash is lower-cased');
  assert.equal(r.total, 3120);
  assert.deepEqual(r.last_scan, { start: '2026-11-21T06:00:00Z', end: '2026-11-21T06:02:00Z' });
  const r2 = await fimFiles(rt(), { agent_id: '2', limit: 10, offset: 0 });
  assert.equal(r2.last_scan, null);
  assert.equal(r2.entries.length, 1);
  await assert.rejects(fimFiles(rt(), { agent_id: '1', hash: 'nothex', limit: 1, offset: 0 }), /hash must be/);
});

async function toolNames(indexer: boolean) {
  const s = new McpServer({ name: 't', version: '0' });
  await registerAllTools(s, wazuh, rt(indexer));
  const [a, b] = InMemoryTransport.createLinkedPair();
  const c = new Client({ name: 'c', version: '0' });
  await s.connect(b);
  await c.connect(a);
  const names = (await c.listTools()).tools.map((t) => t.name).sort();
  await c.close();
  return names;
}

test('wazuh: manager tools without an indexer, all tools with one', async () => {
  // Every tool the module has (registerAllTools ignores scopes): the group write tools need no indexer,
  // active response needs configured commands.
  const managerOnly = ['wazuh_add_agent_group', 'wazuh_agent_inventory', 'wazuh_agent_sca', 'wazuh_fim_files', 'wazuh_get_agent', 'wazuh_get_rule', 'wazuh_list_agents', 'wazuh_list_decoders', 'wazuh_list_groups', 'wazuh_remove_agent_group', 'wazuh_sca_checks'];
  assert.deepEqual(await toolNames(false), managerOnly);
  assert.deepEqual(
    await toolNames(true),
    [...managerOnly, 'wazuh_agent_vulnerabilities', 'wazuh_attack_details', 'wazuh_attack_trend', 'wazuh_fim_events', 'wazuh_get_alert', 'wazuh_search_alerts', 'wazuh_vulnerability_overview', 'wazuh_vulnerability_trend'].sort(),
  );
});

/** Client stub that answers indexer searches from a function and records the bodies. */
function stub(answer: (body: any) => unknown) {
  const bodies: any[] = [];
  const client = { cfg: { alertsIndex: 'wazuh-alerts-*' }, search: async (_i: string, b: unknown) => (bodies.push(b), answer(b)) };
  return { client: client as never, bodies };
}
const NOW = Date.parse('2026-11-23T17:30:00Z');

function trendStub(pages: [string, string, string, string, string, string | null, number?][][]) {
  let page = 0;
  return stub((b) => {
    if (!b.aggs.findings) return { hits: { total: 12, hits: [] }, aggregations: { by_agent: { buckets: [{ key: '002', doc_count: 10, name: { buckets: [{ key: 'db' }] } }, { key: '003', doc_count: 2, name: { buckets: [{ key: 'nas' }] } }] } } };
    const rows = pages[page++] ?? [];
    const buckets = rows.map(([time, agent, cve, pkg, status, severity, n]) => ({ key: { slot: Date.parse(time), agent, cve, package: pkg, status, severity }, doc_count: n ?? 1 }));
    return { hits: { total: 0, hits: [] }, aggregations: { findings: { buckets, ...(buckets.length ? { after_key: { page } } : {}) }, by_agent: { buckets: [{ key: '001', doc_count: 1, name: { buckets: [{ key: 'web-01' }] } }] } } };
  });
}

test('wazuh: vulnerability trend does not count package upgrades as new and resolved', async () => {
  const { client, bodies } = trendStub([[
    // upgrade: the same CVE and package closed and reopened, also across midnight
    ['2026-11-22T14:00:00Z', '001', 'CVE-1', 'linux', 'Active', 'High'],
    ['2026-11-22T14:00:00Z', '001', 'CVE-1', 'linux', 'Solved', 'High'],
    ['2026-11-21T23:50:00Z', '001', 'CVE-2', 'linux', 'Active', 'High'],
    ['2026-11-22T00:00:00Z', '001', 'CVE-2', 'linux', 'Solved', 'High'],
    // really new one day and fixed the next
    ['2026-11-21T10:00:00Z', '002', 'CVE-3', 'curl', 'Active', 'Critical'],
    ['2026-11-22T10:00:00Z', '002', 'CVE-3', 'curl', 'Solved', 'Critical'],
    // same CVE at the same time, but another package or another agent
    ['2026-11-22T14:00:00Z', '002', 'CVE-1', 'linux', 'Active', 'High'],
    ['2026-11-22T14:00:00Z', '002', 'CVE-1', 'linux-doc', 'Solved', 'High'],
    // surplus of a partial pair, without a severity
    ['2026-11-23T14:00:00Z', '001', 'CVE-4', 'krb5', 'Active', null, 1],
    ['2026-11-23T14:00:00Z', '001', 'CVE-4', 'krb5', 'Solved', null, 3],
  ]]);
  const t = await vulnerabilityTrend(client, { days: 3, top: 25 }, NOW);
  assert.deepEqual([t.open, t.new, t.resolved, t.redetected, t.net], [12, 2, 4, 3, -2]);
  assert.deepEqual(t.by_day, [
    { day: '2026-11-21', new: 1, resolved: 0 },
    { day: '2026-11-22', new: 1, resolved: 2 },
    { day: '2026-11-23', new: 0, resolved: 2 },
  ]);
  assert.deepEqual(t.agents.map((a) => [a.agent_id, a.agent_name, a.net, a.redetected, a.open]), [['002', 'db', 0, 0, 10], ['003', 'nas', 0, 0, 2], ['001', 'web-01', -2, 3, 0]]);
  const body = bodies.find((b) => b.aggs.findings);
  assert.deepEqual(body.query.bool.filter, [{ range: { timestamp: { gte: '2026-11-21T00:00:00.000Z' } } }, { terms: { 'data.vulnerability.status': ['Active', 'Solved'] } }]);
});

test('wazuh: vulnerability trend pairs before filtering on severity', async () => {
  const { client, bodies } = trendStub([[
    ['2026-11-22T14:00:00Z', '001', 'CVE-1', 'linux', 'Active', null],
    ['2026-11-22T14:00:00Z', '001', 'CVE-1', 'linux', 'Solved', 'Critical'],
    ['2026-11-22T14:00:00Z', '001', 'CVE-2', 'linux', 'Active', 'Critical'],
    ['2026-11-22T14:00:00Z', '001', 'CVE-3', 'linux', 'Active', 'Low'],
  ]]);
  const t = await vulnerabilityTrend(client, { days: 3, severity: ['Critical'], top: 25 }, NOW);
  assert.deepEqual([t.new, t.resolved, t.redetected, t.snapshots_since], [1, 0, 1, null]);
  assert.deepEqual(bodies.find((b) => !b.aggs.findings).query.bool.filter, [{ terms: { 'vulnerability.severity': ['Critical'] } }]);
});

test('wazuh: vulnerability trend uses alerts before the first snapshot and snapshots after it', async () => {
  const { client, bodies } = trendStub([[
    ['2026-11-21T10:00:00Z', '001', 'CVE-1', 'a', 'Active', 'High'],
    ['2026-11-22T14:00:00Z', '001', 'CVE-2', 'a', 'Active', 'High'], // after the first snapshot: left to the snapshots
  ]]);
  const history = {
    since: Date.parse('2026-11-22T12:00:00Z'),
    changes: [
      { day: '2026-11-22', agent: '002', severity: 'High', new: 2, resolved: 0 },
      { day: '2026-11-23', agent: '002', severity: 'Low', new: 0, resolved: 5 },
      { day: '2026-10-01', agent: '002', severity: 'High', new: 9, resolved: 9 },
    ],
  };
  const t = await vulnerabilityTrend(client, { days: 3, severity: ['High'], top: 25 }, NOW, history);
  assert.deepEqual(t.by_day.map((d) => [d.new, d.resolved]), [[1, 0], [2, 0], [0, 0]]);
  assert.equal(t.snapshots_since, '2026-11-22T12:00:00.000Z');
  // A window entirely after the first snapshot needs no alerts.
  bodies.length = 0;
  const day = await vulnerabilityTrend(client, { days: 1, top: 25 }, NOW, history);
  assert.deepEqual([day.new, day.resolved], [0, 5]);
  assert.equal(bodies.length, 1);
});

test('wazuh: vulnerability trend pairs alerts that fall on different pages', async () => {
  const full = Array.from({ length: 1000 }, (_, i) => ['2026-11-22T14:10:00Z', '001', `CVE-${i}`, 'linux', 'Solved', 'High'] as [string, string, string, string, string, string]);
  const { client, bodies } = trendStub([full, [['2026-11-22T14:00:00Z', '001', 'CVE-0', 'linux', 'Active', 'High']]]);
  const t = await vulnerabilityTrend(client, { days: 3, top: 25 }, NOW);
  assert.deepEqual([t.new, t.resolved, t.redetected], [0, 999, 1]);
  assert.equal('truncated' in t, false);
  assert.deepEqual(bodies.filter((b) => b.aggs.findings).map((b) => b.aggs.findings.composite.after), [undefined, { page: 1 }]);
});

test('wazuh: attack trend fills every column, compares equal periods and counts each alert once', async () => {
  for (const reachesBack of [true, false]) {
    const { client, bodies } = stub((b) =>
      b.aggs.services
        ? { hits: { total: 0, hits: [] } }
        : b.aggs.current
        ? {
            hits: { total: 5, hits: [] },
            aggregations: {
              current: {
                doc_count: 5,
                ips: { value: 4 },
                categories: { buckets: { smtp: { doc_count: 5, ips: { value: 4 }, brute: { doc_count: 2 }, by_time: { buckets: [{ key: Date.parse('2026-11-23T17:00:00Z'), doc_count: 5, ips: { value: 4 } }] } } } },
              },
              previous: { categories: { buckets: { smtp: { doc_count: 2, ips: { value: 1 } } } } },
            },
          }
        : { hits: { total: 0, hits: [] }, aggregations: { oldest: { value: reachesBack ? Date.parse('2026-10-01T00:00:00Z') : Date.parse('2026-11-22T00:00:00Z') } } },
    );
    const t = await attackTrend(client, { window: '24h' }, NOW);
    assert.equal(t.from, '2026-11-22T18:00:00.000Z');
    const smtp = t.categories.find((c) => c.id === 'smtp')!;
    assert.equal(smtp.points.length, 24);
    assert.equal(smtp.brute_force, 2);
    assert.deepEqual(smtp.points.at(-1), { attempts: 5, unique_ips: 4, brute_force: 0 });
    assert.deepEqual(smtp.points[0], { attempts: 0, unique_ips: 0, brute_force: 0 });
    assert.ok(t.categories.every((c) => c.id !== 'brute_force'));
    assert.deepEqual(smtp.previous, reachesBack ? { attempts: 2, unique_ips: 1 } : null);
    assert.deepEqual([t.attempts, t.unique_ips], [5, 4]);
    const main = bodies.find((x) => x.aggs.current);
    // 23.5 hours shown, so 23.5 hours before that.
    assert.deepEqual(main.aggs.previous.filter.range.timestamp, { gte: '2026-11-21T18:30:00.000Z', lt: '2026-11-22T18:00:00.000Z' });
    // A category excludes all earlier ones.
    const f = main.aggs.current.aggs.categories.filters.filters;
    assert.deepEqual(f.imap.bool.must_not.map((m: any) => m.bool.filter), [f.ssh, f.smtp].map((x: any) => x.bool.filter));
  }
});

test('wazuh: attack details merge user fields and reject bad input', async () => {
  const b = (o: Record<string, number>) => ({ buckets: Object.entries(o).map(([key, doc_count]) => ({ key, doc_count })) });
  const { client } = stub(() => ({
    hits: { total: 9, hits: [] },
    aggregations: { ips: { value: 3 }, by_dstuser: b({ root: 2, info: 4 }), by_srcuser: b({ root: 3 }), by_agent: b({ mail: 9 }) },
  }));
  const a = { category: 'ssh', from: '2026-11-22T00:00:00Z', to: '2026-11-23T00:00:00Z', top: 10, limit: 5 };
  const d = await attackDetails(client, a);
  assert.deepEqual(d.top_users, [{ key: 'root', count: 5 }, { key: 'info', count: 4 }]);
  assert.deepEqual([d.attempts, d.unique_ips], [9, 3]);
  await assert.rejects(attackDetails(client, { ...a, category: 'nope' }), /Unknown attack category/);
  await assert.rejects(attackDetails(client, { ...a, to: a.from }), /Invalid time range/);
});

test('wazuh: services found in the catch-all get their own category', async () => {
  const rule = (key: string, ...groups: string[]) => ({ key, doc_count: 1, newest: { hits: { hits: [{ _source: { rule: { groups } } }] } } });
  const { client, bodies } = stub((b) => ({
    hits: { total: 0, hits: [] },
    aggregations: b.aggs.services
      ? { services: { buckets: { other_login: { rules: { buckets: [rule('5503', 'pam', 'syslog', 'authentication_failed'), rule('100', 'local', 'pci_dss_10.2.4', 'my_app', 'authentication_failed'), rule('101', 'syslog', 'invalid_login'), rule('5551', 'pam', 'authentication_failures')] } } } } }
      : {},
  }));
  const t = await attackTrend(client, { window: '24h' }, NOW);
  assert.deepEqual(t.categories.map((c) => c.id), ['ssh', 'smtp', 'imap', 'ftp', 'other_login:pam', 'other_login:my_app', 'other_login', 'web', 'scan', 'other_attack']);
  assert.deepEqual(t.categories.slice(4, 6).map((c) => c.title), ['PAM login', 'My app login']);
  const f = bodies.find((b) => b.aggs.current).aggs.current.aggs.categories.filters.filters;
  assert.deepEqual(f['other_login:pam'].bool.filter.at(-1), { terms: { 'rule.id': ['5503', '5551'] } });
  // Each alert once: the catch-all leaves out what the services took.
  assert.deepEqual(f.other_login.bool.must_not.at(-1), { terms: { 'rule.id': ['5503', '5551', '100'] } });

  const range = { from: '2026-11-22T00:00:00Z', to: '2026-11-23T00:00:00Z', top: 1, limit: 0 };
  await attackDetails(client, { ...range, category: 'other_login:my_app' });
  assert.deepEqual(bodies.at(-1).query.bool.filter[1], f['other_login:my_app']);
  await attackDetails(client, { ...range, category: 'other_login:gone' });
  assert.deepEqual(bodies.at(-1).query.bool.filter[1], { match_none: {} });
  for (const bad of ['ssh:x', 'other_login:', 'nope:x', ':']) assert.equal(isAttackCategory(bad), false, bad);

  const hit = (_id: string, ...groups: string[]) => ({ _id, _index: 'i', _source: { timestamp: '2026-11-23T17:00:00Z', rule: { groups }, GeoLocation: { location: { lat: 1, lon: 2 } } } });
  const m = await attackMap(stub(() => ({ hits: { total: 3, hits: [hit('c', 'local', 'my_app', 'invalid_login'), hit('b', 'syslog', 'vsftpd', 'access_denied'), hit('a', 'redis', 'exploit_attempt')] } })).client, { since: '2026-11-22T00:00:00Z' });
  assert.deepEqual(m.categories.map((c) => [c.id, c.title]), [['ftp', 'FTP login'], ['other_login:my_app', 'My app login'], ['other_attack:redis', 'Redis attacks']]);
});

test('wazuh: attack map keeps located alerts, oldest first, in the same categories as the trend', async () => {
  const hit = (id: string, groups: string[], location?: unknown) => ({ _id: id, _index: 'i', _source: { timestamp: '2026-11-23T17:00:00Z', rule: { groups }, GeoLocation: { location } } });
  const { client } = stub(() => ({
    hits: {
      total: 9,
      hits: [
        hit('d', ['poste', 'authentication_failures'], { lat: 1, lon: 2 }),
        hit('c', ['syslog', 'sshd', 'recon'], { lat: 0, lon: 0 }),
        hit('b', ['dovecot', 'invalid_login'], { lat: 999, lon: 2 }),
        hit('a', ['sshd', 'invalid_login']),
      ],
    },
  }));
  const m = await attackMap(client, { since: '2026-11-22T00:00:00Z' });
  assert.deepEqual(m.events.map((e) => [e.id, e.category]), [['c', 'scan'], ['d', 'smtp']]);
  assert.equal(m.without_location, 2);
  assert.equal(m.complete_from, '2026-11-23T17:00:00Z');
});

test('wazuh: map targets', () => {
  assert.deepEqual(parseMapTargets('59.33, 18.07; mail=-33.9,151.2'), [{ agent: null, lat: 59.33, lon: 18.07 }, { agent: 'mail', lat: -33.9, lon: 151.2 }]);
  assert.deepEqual(parseMapTargets(' '), []);
  for (const bad of ['stockholm', '95,10', '10,181', '1;2']) assert.equal(parseMapTargets(bad), null);
});
