import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { after, before, test } from 'node:test';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Principal } from '../auth/scopes.js';
import { normaliseCve, normaliseSeverity, type CveOccurrence } from '../backends/cve.js';
import { cveOccurrences as defectdojoCves } from '../backends/defectdojo/queries.js';
import { HttpClient } from '../backends/http.js';
import { cveKey, IntelFeeds, parseEpss, parseKev, RETRY_AFTER_MS, type Fetcher, type IntelConfig } from '../backends/intel/feeds.js';
import { gather, intel, intelHealth } from '../backends/intel/index.js';
import { filterRanked, rankCves, summarise } from '../backends/intel/prioritize.js';
import { BackendRegistry, validateSettings } from '../backends/registry.js';
import { TrivyReports } from '../backends/trivy/reports.js';
import type { SourceLookup, ToolContext } from '../backends/types.js';
import { readAllScope } from '../config/schema.js';
import { ConfigStore } from '../config/store.js';
import { sourceLookup } from '../mcp/server.js';

// ---------------------------------------------------------------- fixtures

const KEV = {
  catalogVersion: '2026.11.20',
  dateReleased: '2026-11-20T17:48:39Z',
  count: 3,
  vulnerabilities: [
    { cveID: 'CVE-2024-3094', vendorProject: 'Tukaani', product: 'xz', vulnerabilityName: 'XZ backdoor', dateAdded: '2026-11-18', dueDate: '2026-12-09', knownRansomwareCampaignUse: 'Unknown', requiredAction: 'Downgrade xz.', shortDescription: 'Backdoor.' },
    { cveID: 'cve-2023-4863', vendorProject: 'Google', product: 'libwebp', vulnerabilityName: 'Heap overflow', dateAdded: '2023-09-13', dueDate: '2023-10-04', knownRansomwareCampaignUse: 'Known', requiredAction: 'Update.' },
    { cveID: 'not-a-cve', vendorProject: 'x' },
  ],
};

const EPSS = [
  '#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z',
  'cve,epss,percentile',
  'CVE-2024-3094,0.85,0.999',
  'CVE-2024-0001,0.25,0.97',
  'CVE-2024-0002,0.02,0.80',
  'CVE-2023-4863,0.5,0.99',
  'CVE-2026-129448,0.00043,0.1',
  'garbage line',
].join('\n');

const cfg: IntelConfig = { kevUrl: 'https://kev.test/kev.json', epssUrl: 'https://epss.test/epss.csv.gz', refreshHours: 24, tlsVerify: true, exposedProducts: 'Extern yta' };

function fakeFetcher(over: Partial<Record<'kev' | 'epss', () => Buffer>> = {}) {
  const calls: string[] = [];
  const fetcher: Fetcher = async (url) => {
    calls.push(url);
    if (url.includes('kev')) return over.kev ? over.kev() : Buffer.from(JSON.stringify(KEV));
    return over.epss ? over.epss() : gzipSync(EPSS);
  };
  return { fetcher, calls };
}

const occ = (cve: string, asset: string, o: Partial<CveOccurrence> = {}): CveOccurrence => ({ cve, source: 'wazuh', asset, severity: 'Medium', ...o });

const text = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);
const tool = (name: string) => intel.tools.find((d) => d.name === name)!;

// ---------------------------------------------------------------- parsing

test('cve helpers normalise IDs and severities', () => {
  assert.equal(normaliseCve(' cve-2024-3094 '), 'CVE-2024-3094');
  assert.equal(normaliseCve('GHSA-xxxx-yyyy'), undefined);
  assert.equal(normaliseCve('CVE-24-1'), undefined);
  assert.equal(normaliseSeverity('CRITICAL'), 'Critical');
  assert.equal(normaliseSeverity('-'), 'Unknown');
  assert.equal(normaliseSeverity('Info'), 'Low');
  assert.equal(cveKey('CVE-2026-129448'), 2026e9 + 129448);
  assert.equal(cveKey('CVE-2024-9'), undefined);
});

test('KEV catalog parses entries, ransomware flag and skips non-CVEs', () => {
  const k = parseKev(KEV);
  assert.equal(k.version, '2026.11.20');
  assert.equal(k.entries.size, 2);
  assert.equal(k.entries.get('CVE-2023-4863')!.ransomware, true);
  assert.equal(k.entries.get('CVE-2024-3094')!.ransomware, false);
  assert.equal(k.entries.get('CVE-2024-3094')!.due_date, '2026-12-09');
  assert.throws(() => parseKev({ nope: 1 }), /not a CISA KEV catalog/);
  assert.throws(() => parseKev({ vulnerabilities: [] }), /no CVE entries/);
});

test('EPSS table parses metadata, skips bad rows and looks up by binary search', () => {
  const e = parseEpss(EPSS);
  assert.equal(e.size, 5);
  assert.equal(e.modelVersion, 'v2026.06.15');
  assert.equal(e.scoreDate, '2026-11-21T12:00:24Z');
  assert.deepEqual(e.get('CVE-2024-3094'), { epss: 0.85, percentile: 0.999 });
  assert.deepEqual(e.get('CVE-2026-129448'), { epss: 0.00043, percentile: 0.1 });
  assert.equal(e.get('CVE-2025-0001'), undefined);
  assert.equal(e.get('nonsense'), undefined);
  assert.throws(() => parseEpss('foo,bar\n1,2'), /header/);
  assert.throws(() => parseEpss('cve,epss,percentile\n'), /no scores/);
});

// ---------------------------------------------------------------- feeds runtime

test('feeds download once, gunzip, refresh when due and keep old data on failure', async () => {
  let now = Date.parse('2026-11-22T12:00:00Z');
  let failEpss = false;
  const f = fakeFetcher({ epss: () => { if (failEpss) throw new Error('offline'); return gzipSync(EPSS); } });
  const rt = new IntelFeeds(cfg, f.fetcher, () => now);
  await Promise.all([rt.ensure(), rt.ensure()]);
  assert.equal(f.calls.length, 2, 'concurrent ensure() downloads each feed once');
  assert.equal(rt.kev.data!.entries.size, 2);
  assert.equal(rt.epss.data!.size, 5);
  await rt.ensure();
  assert.equal(f.calls.length, 2, 'fresh feeds are not downloaded again');

  now += 25 * 3600_000;
  failEpss = true;
  await rt.ensure();
  assert.equal(f.calls.length, 4);
  assert.equal(rt.epss.data!.size, 5, 'failed refresh keeps the old table');
  assert.equal(rt.epss.error, 'offline');
  assert.ok(rt.fresh('epss'), 'still within twice the refresh interval');
  await rt.ensure();
  assert.equal(f.calls.length, 4, 'no retry before RETRY_AFTER_MS');
  now += RETRY_AFTER_MS;
  failEpss = false;
  await rt.ensure();
  assert.equal(rt.epss.error, undefined);
  assert.equal(intelHealth(rt).status, 'ok');
});

test('health: missing feeds are down, one missing is degraded, invalid JSON is reported', async () => {
  const rt = new IntelFeeds(cfg, fakeFetcher({ kev: () => Buffer.from('<html>') }).fetcher);
  await rt.ensure();
  const h = intelHealth(rt);
  assert.equal(h.status, 'degraded');
  assert.match(h.checks.find((c) => c.name === 'kev')!.message, /not valid JSON/);
  const none = new IntelFeeds(cfg, async () => { throw new Error('no route'); });
  await none.ensure();
  assert.equal(intelHealth(none).status, 'down');
});

test('settings: empty fields fall back to the official feeds and 24 hours', () => {
  const v = validateSettings(intel, { kevUrl: '', epssUrl: '', refreshHours: '', exposedProducts: '', caCert: '', tlsVerify: true });
  assert.ok(v.ok);
  const c = (v as { value: IntelConfig }).value;
  assert.match(c.kevUrl, /cisa\.gov/);
  assert.match(c.epssUrl, /epss/);
  assert.equal(c.refreshHours, 24);
  assert.equal(c.exposedProducts, undefined);
  assert.ok(!validateSettings(intel, { refreshHours: '0.5' }).ok);
  assert.ok(validateSettings(intel, { refreshHours: '12' }).ok);
});

// ---------------------------------------------------------------- ranking

test('ranking: KEV first, then EPSS/exposure, severity, with reasons', () => {
  const kev = parseKev(KEV);
  const epss = parseEpss(EPSS);
  const ranked = rankCves(
    [
      occ('CVE-2024-0002', 'host-a', { severity: 'Critical', cvss: 9.8 }),
      occ('CVE-2024-3094', 'host-a', { severity: 'Critical', package: 'xz-utils', installed: '5.6.0' }),
      occ('CVE-2024-3094', 'nginx:1.27', { source: 'trivy', severity: 'High', fixed: '5.6.1', package: 'xz-utils', installed: '5.6.0' }),
      occ('CVE-2024-3094', 'host-a', { severity: 'Critical', package: 'xz-utils', installed: '5.6.0' }),
      occ('CVE-2023-4863', 'host-b', { severity: 'High' }),
      occ('CVE-2024-0001', 'host-b', { severity: 'Low' }),
      occ('CVE-2025-7777', 'Extern yta', { source: 'defectdojo', severity: 'High', exposed: true }),
      occ('CVE-2025-8888', 'host-c', { severity: 'Low' }),
      occ('CVE-2024-9999', 'host-c', { severity: 'Unknown' }),
    ],
    kev,
    epss,
  );
  assert.deepEqual(
    ranked.map((c) => [c.cve, c.priority]),
    [
      ['CVE-2023-4863', 'P1'], // KEV with ransomware outranks a higher EPSS
      ['CVE-2024-3094', 'P1'],
      ['CVE-2025-7777', 'P2'], // exposed and High
      ['CVE-2024-0001', 'P2'], // EPSS 0.25
      ['CVE-2024-0002', 'P3'], // Critical, EPSS 0.02
      ['CVE-2025-8888', 'P4'], // Low before Unknown
      ['CVE-2024-9999', 'P4'],
    ],
  );
  const xz = ranked.find((c) => c.cve === 'CVE-2024-3094')!;
  assert.equal(xz.asset_count, 2, 'duplicate occurrences collapse');
  assert.deepEqual(xz.sources.sort(), ['trivy', 'wazuh']);
  assert.equal(xz.fix_available, true);
  assert.equal(xz.severity, 'Critical');
  assert.equal(xz.kev!.due_date, '2026-12-09');
  assert.match(xz.reasons[0]!, /CISA KEV/);
  assert.ok(ranked.find((c) => c.cve === 'CVE-2025-7777')!.reasons.some((r) => /internet: Extern yta/.test(r)));
  assert.ok(ranked.find((c) => c.cve === 'CVE-2025-8888')!.reasons.some((r) => /No EPSS score/.test(r)));

  const s = summarise(ranked);
  assert.deepEqual(s.by_priority, { P1: 2, P2: 2, P3: 1, P4: 2 });
  assert.equal(s.in_kev, 2);
  assert.equal(s.kev_ransomware, 1);
  assert.equal(s.exposed, 1);

  assert.deepEqual(filterRanked(ranked, { kev_only: true }).map((c) => c.cve), ['CVE-2023-4863', 'CVE-2024-3094']);
  assert.deepEqual(filterRanked(ranked, { asset: 'NGINX' }).map((c) => c.cve), ['CVE-2024-3094']);
  assert.deepEqual(filterRanked(ranked, { min_epss: 0.3 }).map((c) => c.cve), ['CVE-2023-4863', 'CVE-2024-3094']);
  assert.deepEqual(filterRanked(ranked, { fixable_only: true }).map((c) => c.cve), ['CVE-2024-3094']);
  assert.equal(filterRanked(ranked, { min_severity: 'High' }).length, 4);
});

test('ranking without feeds still orders by severity and says nothing about EPSS', () => {
  const r = rankCves([occ('CVE-2024-1', 'a', { severity: 'Low' }), occ('CVE-2024-2', 'a', { severity: 'Critical' })], undefined, undefined);
  assert.deepEqual(r.map((c) => [c.cve, c.priority]), [['CVE-2024-2', 'P3'], ['CVE-2024-1', 'P4']]);
  assert.ok(!r[0]!.reasons.some((x) => /EPSS/.test(x)));
});

// ---------------------------------------------------------------- sources

let dir: string;
let dd: http.Server;
let ddBase = '';
let ddFindingCalls = 0;

before(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'socbridge-intel-'));
  const report = (created: string, vulns: object[]) => ({
    SchemaVersion: 2,
    CreatedAt: created,
    ArtifactName: 'nginx:1.27',
    ArtifactType: 'container_image',
    Results: [{ Target: 'nginx', Type: 'debian', Vulnerabilities: vulns }],
  });
  await writeFile(path.join(dir, 'old.json'), JSON.stringify(report('2026-11-20T00:00:00Z', [{ VulnerabilityID: 'CVE-2023-4863', PkgName: 'libwebp', Severity: 'HIGH' }])));
  await writeFile(
    path.join(dir, 'new.json'),
    JSON.stringify(report('2026-11-21T00:00:00Z', [
      { VulnerabilityID: 'CVE-2024-3094', PkgName: 'xz-utils', InstalledVersion: '5.6.0', FixedVersion: '5.6.1', Severity: 'CRITICAL', CVSS: { nvd: { V3Score: 10 } } },
      { VulnerabilityID: 'GHSA-aaaa-bbbb-cccc', PkgName: 'npm-thing', Severity: 'HIGH' },
    ])),
  );

  dd = http.createServer((req, res) => {
    const u = new URL(req.url!, 'http://x');
    const send = (body: unknown) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== 'Token k') { res.statusCode = 401; return send({ detail: 'no' }); }
    if (u.pathname === '/api/v2/test_types/') return send({ results: u.searchParams.get('name') === 'Trivy Scan' ? [{ id: 250, name: 'Trivy Scan' }] : [] });
    if (u.pathname === '/api/v2/products/') return send({ count: 2, results: [{ id: 1, name: 'Extern yta' }, { id: 2, name: 'Containrar' }] });
    if (u.pathname === '/api/v2/findings/') {
      ddFindingCalls++;
      assert.equal(u.searchParams.get('active'), 'true');
      assert.equal(u.searchParams.get('duplicate'), 'false');
      const product = u.searchParams.get('test__engagement__product');
      const results =
        product === '1'
          ? [
              { id: 67, severity: 'High', found_by: [112], vulnerability_ids: [{ vulnerability_id: 'CVE-2025-7777' }, { vulnerability_id: 'cve-2025-7777' }], cvssv3_score: 8.1 },
              { id: 68, severity: 'Info', found_by: [20], vulnerability_ids: [] },
            ]
          : [{ id: 900, severity: 'Critical', found_by: [250], vulnerability_ids: [{ vulnerability_id: 'CVE-2024-3094' }], component_name: 'xz-utils' }];
      return send({ count: results.length, results });
    }
    res.statusCode = 404;
    send({ detail: 'not found' });
  });
  await new Promise<void>((r) => dd.listen(0, '127.0.0.1', r));
  ddBase = `http://127.0.0.1:${(dd.address() as AddressInfo).port}`;
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
  await new Promise((r) => dd.close(r));
});

const ddRuntime = () => ({ http: new HttpClient({ baseUrl: ddBase }), auth: 'Token k' });

test('DefectDojo inventory: per product, exposed flag, Trivy imports left out', async () => {
  const all = await defectdojoCves(ddRuntime(), { exposedProducts: ['extern YTA'] });
  assert.deepEqual(all.occurrences.map((o) => [o.cve, o.asset, !!o.exposed]), [
    ['CVE-2025-7777', 'Extern yta', true],
    ['CVE-2024-3094', 'Containrar', false],
  ]);
  const noTrivy = await defectdojoCves(ddRuntime(), { skipScanTypes: ['Trivy Scan'] });
  assert.deepEqual(noTrivy.occurrences.map((o) => o.cve), ['CVE-2025-7777']);
  assert.match(noTrivy.notes![0]!, /1 finding\(s\) from Trivy imports left out/);
});

/** A ToolContext whose sources are given directly (no registry). */
function ctxWith(sources: Partial<Record<string, unknown>>): ToolContext {
  const source: SourceLookup = <Rt>(id: string) =>
    id in sources ? { runtime: sources[id] as Rt, run: <T>(fn: (rt: Rt) => Promise<T>) => fn(sources[id] as Rt) } : { unavailable: `${id}: not in token scope` };
  return { userName: 'test', source, services: () => [] };
}

test('prioritize tool: merges Trivy and DefectDojo, reports unavailable sources, caches inventories', async () => {
  const rt = new IntelFeeds(cfg, fakeFetcher().fetcher);
  const ctx = ctxWith({ trivy: new TrivyReports(dir), defectdojo: ddRuntime() });
  const before = ddFindingCalls;
  const out = text(await tool('intel_prioritize_cves').run(rt, { limit: 25, offset: 0, kev_only: false, exposed_only: false, fixable_only: false, refresh: false }, ctx));
  assert.deepEqual(out.sources.map((s: { source: string; status: string }) => [s.source, s.status]), [['wazuh', 'unavailable'], ['trivy', 'ok'], ['defectdojo', 'ok']]);
  assert.match(out.sources[0].message, /not in token scope/);
  assert.deepEqual(out.cves.map((c: { cve: string; priority: string }) => [c.cve, c.priority]), [['CVE-2024-3094', 'P1'], ['CVE-2025-7777', 'P2']]);
  const xz = out.cves[0];
  assert.deepEqual(xz.assets, [{ source: 'trivy', asset: 'nginx:1.27', ref: 'new.json', package: 'xz-utils', installed: '5.6.0', fixed: '5.6.1' }], 'only the newest Trivy scan; the DefectDojo copy of the Trivy import is skipped');
  assert.ok(out.notes.some((n: string) => /Trivy imports left out/.test(n)));
  assert.equal(out.feeds.kev.entries, 2);
  assert.match(out.rules, /P1: in CISA KEV/);

  const calls = ddFindingCalls - before;
  const again = text(await tool('intel_prioritize_cves').run(rt, { limit: 1, offset: 1, kev_only: false, exposed_only: false, fixable_only: false, refresh: false }, ctx));
  assert.equal(ddFindingCalls - before, calls, 'second call uses the cached inventory');
  assert.equal(again.sources.find((s: { source: string }) => s.source === 'defectdojo').cached, true);
  assert.equal(again.matching, 2);
  assert.equal(again.returned, 1);
  assert.equal(again.cves[0].cve, 'CVE-2025-7777');
  await tool('intel_prioritize_cves').run(rt, { limit: 1, offset: 0, kev_only: false, exposed_only: false, fixable_only: false, refresh: true }, ctx);
  assert.ok(ddFindingCalls - before > calls, 'refresh re-reads');
});

test('prioritize tool: a failing source is reported and the rest still ranks', async () => {
  const rt = new IntelFeeds(cfg, fakeFetcher().fetcher);
  const broken = { http: new HttpClient({ baseUrl: ddBase }), auth: 'Token wrong' };
  const g = await gather(rt, ctxWith({ trivy: new TrivyReports(dir), defectdojo: broken }), ['trivy', 'defectdojo']);
  assert.equal(g.sources.find((s) => s.source === 'defectdojo')!.status, 'error');
  assert.match(g.sources.find((s) => s.source === 'defectdojo')!.message!, /401/);
  assert.equal(g.sources.find((s) => s.source === 'trivy')!.status, 'ok');
  assert.ok(g.occurrences.length > 0);
  const wazuhNoIndexer = await gather(rt, ctxWith({ wazuh: { hasIndexer: false } }), ['wazuh']);
  assert.match(wazuhNoIndexer.sources[0]!.message!, /indexer is not configured/);
});

test('KEV recent and lookup tools', async () => {
  const rt = new IntelFeeds(cfg, fakeFetcher().fetcher);
  const ctx = ctxWith({ trivy: new TrivyReports(dir) });
  const recent = text(await tool('intel_kev_recent').run(rt, { days: 30, affecting_only: false, limit: 50, refresh: false }, ctx));
  // 2026-11-18 is within 30 days of now only if the test runs near that date; compute from the data instead.
  const inWindow = Date.now() - Date.parse('2026-11-18') <= 30 * 86_400_000;
  assert.equal(recent.added, inWindow ? 1 : 0);
  if (inWindow) {
    assert.equal(recent.entries[0].cve, 'CVE-2024-3094');
    assert.equal(recent.entries[0].affects_you, true);
    assert.deepEqual(recent.entries[0].found_in, [{ source: 'trivy', asset: 'nginx:1.27', ref: 'new.json' }]);
    assert.equal(recent.entries[0].epss.epss, 0.85);
  }
  const long = text(await tool('intel_kev_recent').run(rt, { days: 365, affecting_only: true, limit: 50, refresh: false }, ctx));
  assert.ok(long.entries.every((e: { affects_you: boolean }) => e.affects_you));

  const look = text(await tool('intel_cve_lookup').run(rt, { cves: ['cve-2023-4863', 'CVE-2099-0001', 'GHSA-x'] }, ctx));
  assert.deepEqual(look.results.map((r: { cve: string; in_kev?: boolean }) => [r.cve, r.in_kev]), [['CVE-2023-4863', true], ['CVE-2099-0001', false], ['GHSA-X', undefined]]);
  assert.equal(look.results[0].kev.ransomware, true);
  assert.equal(look.results[0].epss.percentile, 0.99);
  assert.equal(look.results[1].epss, null);
  assert.match(look.results[2].error, /Not a CVE ID/);
});

// ---------------------------------------------------------------- scope

test('sourceLookup: only backends the credential may read, never write', async () => {
  const data = await mkdtemp(path.join(tmpdir(), 'socbridge-intel-scope-'));
  try {
    const store = ConfigStore.forDataDir(data, randomBytes(32));
    await store.load();
    const now = new Date().toISOString();
    await store.mutate((d) => {
      d.users.push({ id: 'u1', name: 'alice', role: 'user', disabled: false, webauthnUserId: 'x', passkeys: [], createdAt: now });
      const scope = readAllScope();
      delete scope.backends.wazuh;
      d.tokens.push({ id: 't1', userId: 'u1', label: 'l', hash: 'a'.repeat(64), hint: 'msec_aaaa', createdAt: now, scope });
      d.backends.trivy = { enabled: true, reportsDir: dir };
      d.backends.wazuh = { enabled: true, managerUrl: 'https://w:55000', managerUser: 'u', managerPassword: 'p' };
    });
    const registry = new BackendRegistry(store);
    const p: Principal = { kind: 'token', id: 't1', userId: 'u1', userName: 'alice' };
    const lookup = sourceLookup(registry, p);
    const tr = lookup<TrivyReports>('trivy');
    assert.ok('runtime' in tr);
    assert.equal(await tr.run(async (r) => r.dir), dir, 'runs under the trivy gate');
    const wz = lookup('wazuh');
    assert.ok('unavailable' in wz && /not in token scope/.test(wz.unavailable));
    const ddl = lookup('defectdojo');
    assert.ok('unavailable' in ddl && /not enabled/.test(ddl.unavailable));
    await store.mutate((d) => { delete d.tokens[0]!.scope.backends.trivy; });
    assert.ok('unavailable' in lookup('trivy'), 'checked live, at the time of the call');
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});
