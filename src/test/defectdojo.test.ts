import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import { defectdojo } from '../backends/defectdojo/index.js';
import {
  getFinding,
  listEndpoints,
  listEngagements,
  listFindings,
  listImports,
  listProducts,
  listTests,
  slaOverview,
  type DefectDojoRuntime,
} from '../backends/defectdojo/queries.js';

const seen: { path: string; query: URLSearchParams; auth?: string }[] = [];
let server: http.Server;
let rt: DefectDojoRuntime;
/** When set, /endpoints/ answers 400 to this ordering (older DefectDojo without active_finding_count). */
let rejectOrdering: string | undefined;

const OPEN: Record<string, number> = { Critical: 3, High: 5, Medium: 0, Low: 1, Info: 0 };
const BREACHED: Record<string, number> = { Critical: 2, High: 1, Medium: 0, Low: 0, Info: 0 };
const tests: Record<string, object[]> = {
  '2': [{ id: 3, title: 'Trivy scan', engagement: 2, test_type: 9, test_type_name: 'Trivy Scan', scan_type: 'Trivy Scan', created: '2026-11-02T10:00:00Z', notes: [], finding_groups: [] }],
  '4': [
    { id: 8, title: 'ZAP', engagement: 4, test_type: 5, created: '2026-11-05T10:00:00Z' },
    { id: 6, title: 'Older', engagement: 4, test_type: 5, created: '2026-10-01T10:00:00Z' },
  ],
};

const finding = {
  id: 7,
  title: 'xz backdoor',
  severity: 'Critical',
  active: true,
  verified: true,
  duplicate: false,
  date: '2026-11-01',
  test: 3,
  description: 'x'.repeat(5000),
  mitigation: '',
  vulnerability_ids: [{ vulnerability_id: 'CVE-2024-3094' }],
  related_fields: { test: { id: 3, title: 'Trivy scan', test_type: { name: 'Trivy Scan' }, engagement: { id: 2, name: 'CI', product: { id: 1, name: 'web' } } } },
};

before(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url!, 'http://x');
    seen.push({ path: u.pathname, query: u.searchParams, auth: req.headers.authorization });
    const send = (s: number, o: unknown) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/api/v2/findings/' && u.searchParams.get('limit') === '1') {
      const sev = u.searchParams.get('severity');
      if (sev) return send(200, { count: (u.searchParams.get('outside_of_sla') === '1' ? BREACHED : OPEN)[sev] ?? 0, results: [] });
      return send(200, { count: Number(u.searchParams.get('test') ?? 0) * 10, results: [] });
    }
    if (u.pathname === '/api/v2/findings/') return send(200, { count: 1, results: [finding] });
    if (u.pathname === '/api/v2/tests/') {
      const eng = u.searchParams.get('engagement');
      const r = eng ? (tests[eng] ?? []) : Object.values(tests).flat();
      return send(200, { count: r.length, results: r });
    }
    if (u.pathname === '/api/v2/endpoints/') {
      if (rejectOrdering && u.searchParams.get('o') === rejectOrdering) return send(400, { o: ['Select a valid choice.'] });
      return send(200, { count: 1, results: [{ id: 4, protocol: 'https', host: 'shop.example', port: 443, path: '/login', product: 1, active_finding_count: 2, endpoint_params: [], findings: [1, 2] }] });
    }
    if (u.pathname === '/api/v2/test_imports/') {
      return send(200, {
        count: 1,
        results: [{
          id: 30, test: 3, type: 'reimport', created: '2026-11-20T08:00:00Z', branch_tag: 'main',
          import_settings: { active: true, minimum_severity: 'Info', push_to_jira: false, close_old_findings: true },
          findings_affected: [1, 2, 3, 4],
          test_import_finding_action_set: [{ action: 'N' }, { action: 'N' }, { action: 'C' }, { action: 'R' }, { action: 'U' }],
        }],
        prefetch: { test: { '3': { id: 3, title: 'Trivy scan', engagement: 2, scan_type: 'Trivy Scan' } } },
      });
    }
    if (u.pathname === '/api/v2/findings/7/') return send(200, finding);
    if (u.pathname === '/api/v2/engagements/' && u.searchParams.get('product') === '5') return send(200, { count: 3, results: [{ id: 2 }, { id: 4 }] });
    if (u.pathname === '/api/v2/engagements/') return send(200, { count: 1, results: [{ id: 2, name: 'CI', product: 1, status: 'In Progress', extra: 'dropped' }] });
    if (u.pathname === '/api/v2/products/') return send(200, { count: 2, results: [{ id: 1, name: 'web', findings_count: 4, findings_list: [1, 2] }, { id: 2, name: 'api' }] });
    send(404, { detail: 'Not found.' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  rt = defectdojo.createRuntime({ url: `http://127.0.0.1:${port}`, apiKey: 'k123', tlsVerify: true });
});

after(() => new Promise<void>((r) => server.close(() => r())));

test('defectdojo: list findings sends filters and flattens related fields', async () => {
  const r = await listFindings(rt, {
    product_name: 'web',
    severity: 'Critical',
    active: true,
    include_duplicates: false,
    include_false_positives: false,
    discovered_after: '2026-10-01',
    limit: 10,
    offset: 0,
  });
  const q = seen.at(-1)!;
  assert.equal(q.auth, 'Token k123');
  assert.equal(q.query.get('product_name'), 'web');
  assert.equal(q.query.get('severity'), 'Critical');
  assert.equal(q.query.get('active'), 'true');
  assert.equal(q.query.get('duplicate'), 'false');
  assert.equal(q.query.get('false_p'), 'false');
  assert.equal(q.query.get('discovered_after'), '2026-10-01');
  assert.equal(q.query.get('related_fields'), 'true');
  assert.equal(q.query.has('verified'), false);
  assert.equal(r.total, 1);
  const f = r.findings[0]!;
  assert.deepEqual(f.vulnerability_ids, ['CVE-2024-3094']);
  assert.equal(f.product_name, 'web');
  assert.equal(f.engagement_name, 'CI');
  assert.equal(f.test_type, 'Trivy Scan');
  assert.equal('description' in f, false, 'list output stays compact');
  assert.equal('related_fields' in f, false);
});

test('defectdojo: include_duplicates drops the duplicate filter', async () => {
  await listFindings(rt, { include_duplicates: true, include_false_positives: true, limit: 5, offset: 0 });
  const q = seen.at(-1)!.query;
  assert.equal(q.has('duplicate'), false);
  assert.equal(q.has('false_p'), false);
});

test('defectdojo: get finding caps long text and maps 404 to null', async () => {
  const f = await getFinding(rt, 7);
  assert.ok(f);
  assert.ok(String(f.description).length < 4200);
  assert.match(String(f.description), /truncated/);
  assert.equal('mitigation' in f, false, 'empty fields are dropped');
  assert.equal(await getFinding(rt, 99), null);
});

test('defectdojo: engagements and products keep only known fields', async () => {
  const e = await listEngagements(rt, { product_id: 1, status: 'In Progress', limit: 10, offset: 0 });
  assert.equal(seen.at(-1)!.query.get('status'), 'In Progress');
  assert.equal(e.engagements[0]!.extra, undefined);
  const p = await listProducts(rt, { limit: 10, offset: 0 });
  assert.equal(p.total, 2);
  assert.equal(p.products[0]!.findings_count, 4);
  assert.equal(p.products[0]!.findings_list, undefined);
});

test('defectdojo: list tests in an engagement with open finding counts', async () => {
  const r = await listTests(rt, { engagement_id: 2, scan_type: 'Trivy Scan', include_finding_counts: true, limit: 10, offset: 0 });
  const q = seen.find((s) => s.path === '/api/v2/tests/' && s.query.get('engagement') === '2')!.query;
  assert.equal(q.get('scan_type'), 'Trivy Scan');
  assert.equal(q.get('o'), '-created');
  const count = seen.at(-1)!.query;
  assert.equal(count.get('test'), '3');
  assert.equal(count.get('active'), 'true');
  assert.equal(count.get('duplicate'), 'false');
  assert.equal(r.total, 1);
  assert.equal(r.tests[0]!.test_type_name, 'Trivy Scan');
  assert.equal(r.tests[0]!.open_findings, 30);
  assert.equal(r.tests[0]!.notes, undefined);
});

test('defectdojo: list tests per product merges engagements, newest first', async () => {
  const before = seen.length;
  const r = await listTests(rt, { product_id: 5, include_finding_counts: false, limit: 2, offset: 0 });
  assert.equal(r.total, 3);
  assert.deepEqual(r.tests.map((t) => t.id), [8, 3]);
  assert.match(String((r as { note?: string }).note), /3 engagements/);
  assert.equal(seen.slice(before).some((s) => s.path === '/api/v2/findings/'), false, 'no counts unless asked');
});

test('defectdojo: endpoints sorted by active findings, falling back on old servers', async () => {
  const r = await listEndpoints(rt, { product_id: 1, host: 'shop.example', limit: 10, offset: 0 });
  const q = seen.at(-1)!.query;
  assert.equal(q.get('host'), 'shop.example');
  assert.equal(q.get('product'), '1');
  assert.equal(q.get('o'), '-active_finding_count');
  assert.deepEqual(r.endpoints[0], { id: 4, protocol: 'https', host: 'shop.example', port: 443, path: '/login', product: 1, active_finding_count: 2 });
  rejectOrdering = '-active_finding_count';
  try {
    const old = await listEndpoints(rt, { limit: 10, offset: 0 });
    assert.equal(seen.at(-1)!.query.get('o'), 'host');
    assert.equal(old.total, 1);
  } finally {
    rejectOrdering = undefined;
  }
});

test('defectdojo: imports count finding actions and name the test', async () => {
  const r = await listImports(rt, { test_id: 3, limit: 5, offset: 0 });
  const q = seen.at(-1)!.query;
  assert.equal(q.get('test'), '3');
  assert.equal(q.get('prefetch'), 'test');
  assert.equal(q.get('o'), '-created');
  const i = r.imports[0]!;
  assert.equal(i.type, 'reimport');
  assert.equal(i.test_title, 'Trivy scan');
  assert.equal(i.scan_type, 'Trivy Scan');
  assert.equal(i.engagement_id, 2);
  assert.deepEqual(i.findings, { created: 2, closed: 1, reactivated: 1, untouched: 1 });
  assert.deepEqual(i.settings, { active: true, minimum_severity: 'Info', close_old_findings: true });
  assert.equal('findings_affected' in i, false);
});

test('defectdojo: SLA overview counts open and breached findings per severity', async () => {
  const before = seen.length;
  const r = await slaOverview(rt, { product_id: 1, overdue_limit: 3 });
  const reqs = seen.slice(before);
  assert.equal(reqs.filter((s) => s.query.get('limit') === '1').length, 10);
  for (const s of reqs) {
    assert.equal(s.query.get('test__engagement__product'), '1');
    assert.equal(s.query.get('active'), 'true');
    assert.equal(s.query.get('false_p'), 'false');
  }
  assert.equal(r.total_open, 9);
  assert.equal(r.total_breached, 3);
  assert.deepEqual((r.by_severity as object[])[0], { severity: 'Critical', open: 3, breached: 2 });
  assert.deepEqual(r.scope, { product_id: 1 });
  const top = reqs.at(-1)!.query;
  assert.equal(top.get('outside_of_sla'), '1');
  assert.equal(top.get('o'), 'sla_expiration_date');
  assert.equal(top.get('limit'), '3');
  const f = (r.most_overdue as Record<string, unknown>[])[0]!;
  assert.equal(f.title, 'xz backdoor');
  assert.equal(f.product_name, 'web');
  assert.equal('description' in f, false);
});

test('defectdojo: SLA overview without overdue list', async () => {
  const r = await slaOverview(rt, { overdue_limit: 0 });
  assert.equal('most_overdue' in r, false);
  assert.deepEqual(r.scope, {});
});

test('defectdojo: connection test reports product count', async () => {
  const r = await defectdojo.testConnection(rt);
  assert.deepEqual(r, { ok: true, message: 'Connected; 2 products visible.' });
});
