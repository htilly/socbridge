import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import express from 'express';
import { cvesIn, isPublicIp, type CveOccurrence } from '../backends/cve.js';
import { attacksByTarget, type FirewallRuntime } from '../backends/graylog/firewall.js';
import { correlate, investigate, type CorrelateInput } from '../backends/intel/correlate.js';
import { fixFirst, investigateTool } from '../backends/intel/evidence.js';
import { IntelFeeds, parseEpss, parseKev, type Fetcher, type IntelConfig } from '../backends/intel/feeds.js';
import { imageName, suggestServices } from '../backends/intel/suggest.js';
import { BackendRegistry } from '../backends/registry.js';
import type { SourceLookup, ToolContext } from '../backends/types.js';
import { attacksByAgent, LOGIN_CATEGORIES, type AgentAttack } from '../backends/wazuh/attacks.js';
import type { WazuhClient } from '../backends/wazuh/client.js';
import { ConfigSchema, ServiceInputSchema, type Service } from '../config/schema.js';
import { ConfigStore } from '../config/store.js';
import { HttpError, type AppContext } from '../http/context.js';
import { servicesRouter } from '../http/services.js';

const KEV = 'CVE-2024-3094';
const LIKELY = 'CVE-2024-0001';
const PLAIN = 'CVE-2024-0002';
const KEV_JSON = {
  catalogVersion: '1', dateReleased: '2026-11-20T00:00:00Z', count: 1,
  vulnerabilities: [{ cveID: KEV, vendorProject: 'T', product: 'xz', vulnerabilityName: 'XZ', dateAdded: '2026-11-18', dueDate: '2026-12-09', knownRansomwareCampaignUse: 'Unknown', requiredAction: 'Downgrade.', shortDescription: 'x' }],
};
const EPSS_CSV = `#model_version:v1,score_date:2026-11-20T00:00:00+0000\ncve,epss,percentile\n${LIKELY},0.25,0.96\n${PLAIN},0.001,0.1\n${KEV},0.8,0.99\n`;
const kev = parseKev(KEV_JSON);
const epss = parseEpss(EPSS_CSV);
const NOW = Date.parse('2026-11-23T12:00:00Z');

const svc = (name: string, o: Record<string, unknown> = {}): Service => ({ ...ServiceInputSchema.parse({ name, ...o }), id: name });
const img = (cve: string, asset: string, o: Partial<CveOccurrence> = {}): CveOccurrence => ({ cve, source: 'trivy', asset, ref: `${asset}.json`, package: 'p', installed: '1', fixed: '2', severity: 'High', scanned_at: '2026-11-23T01:00:00Z', ...o });
const atk = (agent: string, category: string, o: Partial<AgentAttack> = {}): AgentAttack => ({ agent, category, title: category, attempts: 10, other_source: 0, unique_ips: 3, cves: [], alert_ids: ['a1'], ...o });
const input = (o: Partial<CorrelateInput>): CorrelateInput => ({
  services: [], occurrences: [], endpoints: [], kev, epss, attacks: [], edge: [], edgeComplete: true,
  complete: new Set(['wazuh', 'trivy', 'defectdojo']), window: { from: 'f', to: 't' }, now: NOW, ...o,
});
const web = (o: Record<string, unknown> = {}) => svc('web', { exposure: 'internet', endpoints: [{ hosts: ['203.0.113.1', 'web.example'], port: 443 }], agents: ['001'], images: ['nginx:1'], ...o });
const seen = { host: '203.0.113.1', port: 443, external: true };
const tierOf = (o: Partial<CorrelateInput>) => correlate(input(o)).actions[0]!.tier;
const HEADLINE = { exposure: 'internet', kev_only: true, attack: 'reached' } as const;

test('tiers: each rule, and blocked traffic never counts as reached', () => {
  const s = [web()];
  const hit = [atk('001', 'web')];
  assert.equal(tierOf({ services: s, occurrences: [img(KEV, 'nginx:1')], attacks: hit }), 'A1');
  assert.equal(tierOf({ services: s, occurrences: [img(KEV, 'nginx:1')] }), 'A2');
  assert.equal(tierOf({ services: s, occurrences: [img(LIKELY, 'nginx:1')], attacks: hit }), 'A2');
  assert.equal(tierOf({ services: s, occurrences: [img(LIKELY, 'nginx:1')] }), 'A3');
  assert.equal(tierOf({ services: s, occurrences: [img(PLAIN, 'nginx:1')], attacks: hit }), 'A3');
  assert.equal(tierOf({ services: s, occurrences: [img(PLAIN, 'nginx:1', { severity: 'Low' })], attacks: hit }), 'A4');
  assert.equal(tierOf({ occurrences: [img(KEV, 'nginx:1')] }), 'A3', 'KEV without a service');
  assert.equal(tierOf({ services: [web({ exposure: 'internal' })], occurrences: [img(KEV, 'nginx:1')], attacks: hit }), 'A3');
  const blocked = input({
    services: s, occurrences: [img(KEV, 'nginx:1')], attacks: [atk('001', 'scan')],
    edge: [{ kind: 'firewall', ip: '203.0.113.1', port: 443, blocked: 900, unique_ips: 5, query: 'q' }],
  });
  const c = correlate(blocked);
  assert.equal(c.services[0]!.attack, 'blocked');
  assert.equal(c.actions[0]!.tier, 'A2');
  assert.equal(investigate(c, blocked, HEADLINE).matches.length, 0);
  assert.equal(investigate(c, blocked, { ...HEADLINE, attack: 'any' }).matches.length, 1);
});

test('an alert naming a CVE counts only when the service has that CVE', () => {
  const run = (cves: string[]) => correlate(input({ services: [web()], occurrences: [img(KEV, 'nginx:1')], attacks: [atk('001', 'web', { cves })] })).services[0]!;
  assert.equal(run([KEV]).attack, 'cve_matched');
  assert.equal(run(['CVE-2014-6271']).attack, 'reached');
});

test('importance orders within a tier but never changes it', () => {
  const services = [web({ images: ['low:1'] }), { ...web({ images: ['crit:1'], importance: 'critical' }), id: 'b', name: 'b', agents: ['002'] }];
  const c = correlate(input({ services, occurrences: [img(PLAIN, 'low:1', { severity: 'Low' }), img(PLAIN, 'crit:1', { severity: 'Low' })] }));
  assert.deepEqual(c.actions.map((a) => [a.target, a.tier]), [['crit:1', 'A4'], ['low:1', 'A4']]);
});

test('exposure: confirmed, observed, conflict, alias and port', () => {
  const ex = (s: Service, e = seen) => correlate(input({ services: [s], endpoints: [e] })).services[0]!;
  assert.equal(ex(web()).exposure, 'confirmed');
  assert.equal(ex(web(), { host: 'web.example', port: 443, external: true }).exposure, 'confirmed', 'DNS alias');
  assert.equal(ex(web(), { ...seen, port: 8443 }).exposure, 'declared', 'other port is another endpoint');
  assert.equal(ex(web(), { ...seen, external: false }).exposure, 'declared');
  assert.equal(ex(web({ exposure: 'unknown' })).exposure, 'observed');
  const conflict = ex(web({ exposure: 'internal' }));
  assert.equal(conflict.exposure, 'observed');
  assert.match(conflict.exposure_conflict!, /map says internal/);
});

test('confidence falls with each doubt and says why', () => {
  const run = (s: Service, o: Partial<CorrelateInput> = {}) =>
    correlate(input({ services: [s], occurrences: [img(KEV, 'nginx:1')], endpoints: [seen], attacks: [atk('001', 'web')], ...o })).actions[0]!;
  assert.equal(run(web()).confidence, 'high');
  const declared = run(web(), { endpoints: [] });
  assert.equal(declared.confidence, 'medium');
  assert.match(declared.confidence_reasons[0]!, /declared/);
  assert.equal(run(web(), { occurrences: [img(KEV, 'nginx:1', { scanned_at: '2026-11-01T00:00:00Z' })] }).confidence, 'medium');
  assert.equal(run(web(), { complete: new Set() , endpoints: [] }).confidence, 'low');
  assert.equal(run(svc('other')).confidence, 'low', 'unmapped');
});

test('unknown exposure or an unread source is possible, never a no', () => {
  const x = input({ services: [web({ exposure: 'unknown' })], occurrences: [img(KEV, 'nginx:1')], attacks: [atk('001', 'web')] });
  const r = investigate(correlate(x), x, HEADLINE);
  assert.equal(r.matches.length, 0);
  assert.match(r.possible[0]!.unresolved[0]!, /does not say/);

  const noAlerts = input({ services: [web()], occurrences: [img(KEV, 'nginx:1')], attacks: undefined });
  const r2 = investigate(correlate(noAlerts), noAlerts, HEADLINE);
  assert.equal(r2.matches.length, 0);
  assert.match(r2.possible[0]!.unresolved[0]!, /could not be read/);

  const noTrivy = input({ services: [web()], attacks: [atk('001', 'web')], complete: new Set(['wazuh', 'defectdojo']) });
  assert.match(investigate(correlate(noTrivy), noTrivy, HEADLINE).possible[0]!.unresolved[0]!, /Trivy was not read/);

  const hidden = input({ services: [web()], occurrences: [img(KEV, 'nginx:1')], attacks: [atk('001', 'web', { attempts: 0, other_source: 8 })] });
  assert.match(investigate(correlate(hidden), hidden, HEADLINE).possible[0]!.unresolved[0]!, /no public source/);

  const noEdge = input({ services: [web()], occurrences: [img(KEV, 'nginx:1')], edgeComplete: false, edge: undefined });
  assert.equal(investigate(correlate(noEdge), noEdge, { ...HEADLINE, attack: 'none' }).possible.length, 1);

  const clean = input({ services: [web()], occurrences: [img(PLAIN, 'nginx:1')], attacks: [atk('001', 'web')] });
  const r3 = investigate(correlate(clean), clean, HEADLINE);
  assert.deepEqual([r3.matches.length, r3.possible.length], [0, 0], 'a read source without the CVE is a no');

  const loose = input({ services: [web()], occurrences: [img(KEV, 'other:1')] });
  assert.deepEqual(investigate(correlate(loose), loose, HEADLINE).unmapped.map((a) => a.target), ['other:1']);
});

test('shared host: logins are not pinned on a service, and shared attacks lower confidence', () => {
  const two = [web(), { ...web({ images: ['mail:1'], endpoints: [] }), id: 'mail', name: 'mail' }];
  assert.deepEqual([...LOGIN_CATEGORIES].sort(), ['ftp', 'imap', 'other_login', 'smtp', 'ssh']);
  const logins = correlate(input({ services: two, attacks: [...LOGIN_CATEGORIES].map((c) => atk('001', c)) }));
  assert.ok(logins.services.every((s) => s.attack === 'unknown' && s.attacks.length === 0));
  const both = correlate(input({ services: two, occurrences: [img(KEV, 'nginx:1')], endpoints: [seen], attacks: [atk('001', 'web')] }));
  assert.equal(both.services[0]!.shared_host, true);
  assert.equal(both.actions[0]!.confidence, 'medium');
  assert.equal(correlate(input({ services: [web()], attacks: [atk('001', 'ssh')] })).services[0]!.attack, 'reached');
});

test('one image in two services is one action; one finding on two aliases is one action', () => {
  const two = [web(), { ...web({ agents: ['002'] }), id: 'b', name: 'b', endpoints: [] }];
  const c = correlate(input({ services: two, occurrences: [img(KEV, 'nginx:1'), img(PLAIN, 'nginx:1')] }));
  assert.equal(c.actions.length, 1);
  assert.equal(c.actions[0]!.cve_count, 2);
  assert.deepEqual(c.actions[0]!.services.map((s) => s.id), ['web', 'b']);
  for (const id of c.actions[0]!.evidence) assert.ok(c.evidence.has(id), id);

  const dd: CveOccurrence = { cve: KEV, source: 'defectdojo', asset: 'Ext', ref: 'finding 9', severity: 'High', endpoints: [seen, { host: 'web.example', port: 443, external: false }] };
  const f = correlate(input({ services: [web()], endpoints: [seen], occurrences: [dd] })).actions;
  assert.equal(f.length, 1);
  assert.equal(f[0]!.services.length, 1);
  assert.equal(correlate(input({ occurrences: [dd] })).actions[0]!.tier, 'A2', 'seen from outside without a service');
});

test('addresses and CVEs in text', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.2.2', '192.168.1.1', '127.0.0.1', '100.64.0.1', '169.254.1.1', 'web.example', '999.1.1.1', 'fe80::1']) assert.equal(isPublicIp(ip), false, ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '100.128.0.1', '2001:db8::1']) assert.equal(isPublicIp(ip), true, ip);
  assert.deepEqual(cvesIn(['ET EXPLOIT cve-2021-44228 x', 'CVE-2021-44228', 'none']), ['CVE-2021-44228']);
  assert.equal(imageName('ghcr.io/org/nginx-proxy:1.2'), 'nginx-proxy');
});

test('Wazuh: attacks per agent, public sources only', async () => {
  let body: any;
  const client = {
    cfg: { alertsIndex: 'a' },
    search: async (_i: string, b: unknown) => {
      body = b;
      return { hits: { hits: [] }, aggregations: { by_agent: { sum_other_doc_count: 0, buckets: [{ key: '001', categories: { buckets: {
        web: { doc_count: 12, public: { doc_count: 9, ips: { value: 4 }, first: { value: NOW - 1000 }, last: { value: NOW }, rules: { buckets: [{ key: 'Shellshock CVE-2014-6271' }] }, rule_cves: { buckets: [{ key: 'CVE-2021-44228' }] }, latest: { hits: { hits: [{ _id: 'x' }] } } } },
        ssh: { doc_count: 0, public: { doc_count: 0 } },
      } } }] } } };
    },
  } as unknown as WazuhClient;
  const r = await attacksByAgent(client, { from: NOW - 1000, to: NOW });
  assert.deepEqual(r.attacks, [{ agent: '001', category: 'web', title: 'Web attacks', attempts: 9, other_source: 3, unique_ips: 4, first_seen: new Date(NOW - 1000).toISOString(), last_seen: new Date(NOW).toISOString(), cves: ['CVE-2014-6271', 'CVE-2021-44228'], alert_ids: ['x'] }]);
  assert.equal(body.aggs.by_agent.terms.field, 'agent.id');
  const not = JSON.stringify(body.aggs.by_agent.aggs.categories.aggs.public.filter);
  for (const p of ['"10."', '"172.16."', '"172.31."', '"100.64."']) assert.ok(not.includes(p), p);
});

test('Graylog: only mapped targets are asked for, values stay quoted, IPS without a target is counted', async () => {
  const queries: string[] = [];
  const rt = {
    firewallQuery: 'fw', ipsQuery: 'ips', headers: {},
    http: { request: async (_p: string, o: any) => {
      queries.push(o.json.query);
      if (o.json.group_by[0].field === 'UNIFIipsSignature') return { datarows: [['ET CVE-2021-44228', 7]] };
      return { datarows: o.json.query.includes('(fw)') ? [['203.0.113.1', 443, 50, 4], ['203.0.113.9', 443, 1, 1], ['-', '-', 3, 1]] : [] };
    } },
  } as unknown as FirewallRuntime;
  const r = await attacksByTarget(rt, { from: 0, to: NOW, ips: ['203.0.113.1', 'x" OR *:*'] });
  assert.deepEqual(r.targets.map((t) => [t.ip, t.port, t.blocked]), [['203.0.113.1', 443, 50]]);
  assert.equal(r.targets[0]!.query, '(fw) AND dst_ip:("203.0.113.1") AND dst_port:443');
  assert.ok(queries[0]!.includes('"x\\" OR *:*"'));
  assert.equal(r.ips_without_target, 7);
  assert.deepEqual(r.signature_cves, ['CVE-2021-44228']);
});

// ---------------------------------------------------------------- tools and scope

const cfg = { kevUrl: 'https://k.example/k', epssUrl: 'https://e.example/e', refreshHours: 24, tlsVerify: true } as IntelConfig;
const fetcher = (async (url: string) => Buffer.from(url.includes('k.example') ? JSON.stringify(KEV_JSON) : EPSS_CSV)) as unknown as Fetcher;

test('tools: a source outside the scope becomes a gap and leaks nothing', async () => {
  const rt = new IntelFeeds(cfg, fetcher);
  const trivy = { all: async () => [{ file: 'n.json', report: { file: 'n.json', artifact: 'nginx:1', created_at: '2026-11-23T00:00:00Z', vulnerabilities: [{ id: KEV, pkg: 'xz', installed: '1', fixed: '2', severity: 'CRITICAL' }], misconfigurations: [], secrets: [] } }] };
  const source: SourceLookup = <Rt>(id: string) =>
    id === 'trivy' ? { runtime: trivy as Rt, run: <T>(fn: (r: Rt) => Promise<T>) => fn(trivy as Rt) } : { unavailable: `${id}: not in token scope` };
  const ctx: ToolContext = { userName: 't', source, services: () => [web({ agents: ['777'] })] };
  const fix = await fixFirst(rt, ctx, { hours: 24, fixable_only: false, attacked_only: false, limit: 10, offset: 0, refresh: false });
  assert.equal(fix.actions[0]!.tier, 'A2');
  assert.match(fix.actions[0]!.recommendation, /Update xz to 2/);
  assert.ok(fix.gaps.some((g) => /wazuh_attacks: wazuh: not in token scope/.test(g)));
  assert.ok(fix.gaps.some((g) => /graylog_blocks/.test(g)));
  const ids = new Set(fix.evidence.map((e) => e.id));
  for (const id of fix.actions[0]!.evidence) assert.ok(ids.has(id), `${id} resolves in the result`);
  assert.ok(!JSON.stringify(fix).includes('777'), 'agent ID of an unreadable backend');
  const inv = await investigateTool(rt, ctx, { ...HEADLINE, hours: 24, limit: 10, refresh: false });
  assert.equal(inv.matching, 0);
  assert.equal(inv.possible_total, 1);
});

// ---------------------------------------------------------------- map and suggestions

test('service map: old configs load, input is validated', () => {
  assert.deepEqual(ConfigSchema.parse({ version: 1 }).services, []);
  assert.equal(ServiceInputSchema.safeParse({ name: 'x', endpoints: [{ hosts: ['a" OR b'] }] }).success, false);
  assert.equal(ServiceInputSchema.safeParse({ name: 'x', logTargets: [{ ip: 'host' }] }).success, false);
  assert.equal(ServiceInputSchema.safeParse({ name: 'x', agents: ['1'] }).success, false);
  assert.equal(ServiceInputSchema.parse({ name: 'x', endpoints: [{ hosts: ['WEB.Example'] }] }).endpoints[0]!.hosts[0], 'web.example');
});

test('suggestions: ports pair with the one host listening, mapped things are left out, failures are shown', async () => {
  const wazuh = {
    api: async (p: string) =>
      p === '/agents'
        ? { data: { total_affected_items: 3, affected_items: [{ id: '000', name: 'manager' }, { id: '001', name: 'webhost' }, { id: '002', name: 'other' }] } }
        : { data: { total_affected_items: 2, affected_items: p.includes('/001/') ? [{ local: { ip: '0.0.0.0', port: 443 }, protocol: 'tcp', state: 'listening', process: 'nginx' }, { local: { ip: '127.0.0.1', port: 25 }, protocol: 'tcp', state: 'listening' }] : [] } },
  };
  const broken = { http: { request: async () => { throw new Error('boom'); } } };
  const dd = { http: { request: async () => ({ count: 2, results: [{ id: 1, host: '203.0.113.1', port: 443 }, { id: 2, host: 'mail.example', port: 25 }] }) } };
  const look = (d: unknown): SourceLookup => <Rt>(id: string) => {
    const rt = (id === 'wazuh' ? wazuh : id === 'defectdojo' ? d : null) as Rt | null;
    return rt ? { runtime: rt, run: <T>(fn: (r: Rt) => Promise<T>) => fn(rt) } : { unavailable: `${id} is not enabled` };
  };
  const r = await suggestServices(look(dd), [svc('o', { agents: ['002'] })]);
  const https = r.suggestions.find((s) => s.endpoints[0]?.port === 443)!;
  assert.deepEqual([https.agents, https.exposure], [['001'], 'internet']);
  assert.deepEqual(r.suggestions.find((s) => s.endpoints[0]?.port === 25)!.agents, [], 'loopback does not count');
  assert.ok(!r.suggestions.some((s) => s.agents.includes('000') || s.agents.includes('002')));
  assert.deepEqual(r.coverage.agents, { mapped: 1, total: 2 });
  assert.ok(r.errors.some((e) => e.source === 'trivy'));
  assert.equal(r.coverage.images, null);
  const bad = await suggestServices(look(broken), []);
  assert.match(bad.errors.find((e) => e.source === 'defectdojo')!.message, /boom/);
});

test('service API: administrators only, with the whole life of a service', async () => {
  const data = await mkdtemp(path.join(tmpdir(), 'socbridge-services-'));
  const store = ConfigStore.forDataDir(data, randomBytes(32));
  await store.load();
  let role = 'user';
  const app = express();
  app.use(express.json());
  app.use((_q, res, next) => { res.locals.user = { id: 'u', name: 'u', role }; next(); });
  app.use('/s', servicesRouter({ store, registry: new BackendRegistry(store) } as unknown as AppContext));
  app.use((err: unknown, _q: express.Request, res: express.Response, _n: express.NextFunction) => { res.status(err instanceof HttpError ? err.status : 500).json({}); });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/s`;
  const call = async (m: string, p = '', body?: unknown) => {
    const r = await fetch(base + p, { method: m, headers: { 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const t = await r.text();
    return { status: r.status, data: t ? JSON.parse(t) : null };
  };
  try {
    for (const [m, p] of [['GET', ''], ['GET', '/suggestions'], ['POST', ''], ['PUT', '/x'], ['DELETE', '/x']] as const) {
      assert.equal((await call(m, p, m === 'GET' ? undefined : { name: 'a' })).status, 403, `${m} ${p}`);
    }
    role = 'admin';
    const made = await call('POST', '', { name: 'web' });
    assert.equal(made.status, 201);
    assert.equal((await call('POST', '', { name: 'WEB' })).status, 409);
    assert.equal((await call('POST', '', { name: '' })).status, 400);
    assert.equal((await call('PUT', `/${made.data.id}`, { name: 'web2', importance: 'high' })).data.importance, 'high');
    assert.equal((await call('PUT', '/nope', { name: 'q' })).status, 404);
    assert.equal(store.get().services[0]!.name, 'web2');
    assert.equal((await call('DELETE', `/${made.data.id}`)).status, 204);
    assert.equal(store.get().services.length, 0);
  } finally {
    await new Promise((r) => server.close(r));
    await rm(data, { recursive: true, force: true });
  }
});
