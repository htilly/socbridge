import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { trivy } from '../backends/trivy/index.js';
import { artifactHistory, findCve, listReports, MAX_DEPTH, parseReport, reportFindings, type TrivyReports } from '../backends/trivy/reports.js';

let dir: string;
let outside: string;
let rt: TrivyReports;

const nginx = {
  SchemaVersion: 2,
  CreatedAt: '2026-11-20T03:00:00Z',
  ArtifactName: 'nginx:1.27',
  ArtifactType: 'container_image',
  Metadata: { OS: { Family: 'debian', Name: '12.8' }, ImageID: 'sha256:abc', RepoDigests: ['nginx@sha256:def'] },
  Results: [
    {
      Target: 'nginx:1.27 (debian 12.8)',
      Class: 'os-pkgs',
      Type: 'debian',
      Vulnerabilities: [
        { VulnerabilityID: 'CVE-2024-0001', PkgName: 'libssl3', InstalledVersion: '3.0.1', FixedVersion: '3.0.2', Severity: 'HIGH', Title: 'ssl bug', CVSS: { nvd: { V3Score: 7.5 }, redhat: { V3Score: 8.1 } } },
        { VulnerabilityID: 'CVE-2024-3094', PkgName: 'xz-utils', InstalledVersion: '5.6.0', Severity: 'CRITICAL', Title: 'xz backdoor', Description: 'd'.repeat(3000), CVSS: { nvd: { V3Score: 10 } } },
        { VulnerabilityID: 'CVE-2023-9999', PkgName: 'zlib', InstalledVersion: '1.2', Severity: 'LOW' },
      ],
    },
    { Target: 'Dockerfile', Class: 'config', Type: 'dockerfile', Misconfigurations: [{ ID: 'DS002', Title: 'root user', Severity: 'HIGH', Status: 'FAIL' }, { ID: 'DS001', Severity: 'LOW', Status: 'PASS' }] },
    { Target: '/app/.env', Class: 'secret', Secrets: [{ RuleID: 'aws-access-key-id', Severity: 'CRITICAL', Title: 'AWS key', StartLine: 3, EndLine: 3, Match: 'AWS_KEY=AKIA****' }] },
  ],
};

const api = {
  SchemaVersion: 2,
  CreatedAt: '2026-11-21T03:00:00Z',
  ArtifactName: '/srv/api',
  ArtifactType: 'filesystem',
  Results: [{ Target: 'package-lock.json', Class: 'lang-pkgs', Type: 'npm', Vulnerabilities: [{ VulnerabilityID: 'CVE-2024-3094', PkgName: 'fake', InstalledVersion: '1.0.0', FixedVersion: '1.0.1', Severity: 'critical' }] }],
};

/** Two later scans of nginx:1.27, in nested folders: CVE-2024-0001 fixed, CVE-2025-1111 new. */
const vuln = (id: string, pkg: string, severity: string, fixed?: string) => ({ VulnerabilityID: id, PkgName: pkg, InstalledVersion: '1', FixedVersion: fixed, Severity: severity });
const nginxScan = (createdAt: string, vulns: object[]) => ({ ...nginx, CreatedAt: createdAt, Results: [{ Target: 'nginx:1.27 (debian 12.8)', Type: 'debian', Vulnerabilities: vulns }] });
const nginx2 = nginxScan('2026-11-21T03:00:00Z', [
  vuln('CVE-2024-0001', 'libssl3', 'HIGH', '3.0.2'),
  vuln('CVE-2024-3094', 'xz-utils', 'CRITICAL'),
  vuln('CVE-2023-9999', 'zlib', 'LOW'),
]);
const nginx3 = nginxScan('2026-11-22T03:00:00Z', [
  vuln('CVE-2024-3094', 'xz-utils', 'CRITICAL'),
  vuln('CVE-2023-9999', 'zlib', 'LOW'),
  vuln('CVE-2025-1111', 'libcurl4', 'MEDIUM', '8.1'),
  vuln('CVE-2025-1111', 'curl', 'MEDIUM', '8.1'),
]);
/** Same artifact name as an image, but a filesystem: a separate history. */
const nginxFs = { SchemaVersion: 2, CreatedAt: '2026-11-22T04:00:00Z', ArtifactName: 'nginx:1.27', ArtifactType: 'filesystem', Results: [] };

before(async () => {
  dir = await mkdtemp(path.join(tmpdir(), 'socbridge-trivy-'));
  outside = await mkdtemp(path.join(tmpdir(), 'socbridge-trivy-outside-'));
  await writeFile(path.join(dir, 'nginx.json'), JSON.stringify(nginx));
  await writeFile(path.join(dir, 'api.json'), JSON.stringify(api));
  await writeFile(path.join(dir, 'junk.json'), '{"hello":1}');
  await writeFile(path.join(dir, 'notes.txt'), 'ignored');
  rt = trivy.createRuntime({ reportsDir: dir });
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
  await rm(outside, { recursive: true, force: true });
});

/** Adds the nested history fixtures; the earlier tests run against the flat directory only. */
async function addNested() {
  await mkdir(path.join(dir, '2026-11-21', 'images'), { recursive: true });
  await mkdir(path.join(dir, '2026-11-22'), { recursive: true });
  await mkdir(path.join(dir, '.hidden'), { recursive: true });
  await writeFile(path.join(dir, '2026-11-21', 'images', 'nginx.json'), JSON.stringify(nginx2));
  await writeFile(path.join(dir, '2026-11-22', 'nginx.json'), JSON.stringify(nginx3));
  await writeFile(path.join(dir, '2026-11-22', 'nginx-fs.json'), JSON.stringify(nginxFs));
  await writeFile(path.join(dir, '.hidden', 'x.json'), JSON.stringify(api));
  // A symlinked file and a symlinked directory that both lead out of the report directory.
  await writeFile(path.join(outside, 'secret.json'), JSON.stringify({ ...api, ArtifactName: 'outside' }));
  await symlink(path.join(outside, 'secret.json'), path.join(dir, 'escape.json'));
  await symlink(outside, path.join(dir, 'linked-dir'));
  // Too deep to be read.
  const deep = path.join(dir, ...Array.from({ length: MAX_DEPTH + 1 }, (_, i) => `d${i}`));
  await mkdir(deep, { recursive: true });
  await writeFile(path.join(deep, 'deep.json'), JSON.stringify({ ...api, ArtifactName: 'deep' }));
}

test('trivy: parseReport rejects non-Trivy JSON', () => {
  assert.throws(() => parseReport('x.json', { hello: 1 }), /Not a Trivy/);
  assert.throws(() => parseReport('x.json', [1]), /Not a Trivy/);
});

test('trivy: list reports, newest first, with counts and unreadable files', async () => {
  const r = await listReports(rt, { limit: 10, offset: 0 });
  assert.equal(r.total, 2);
  assert.deepEqual(r.reports.map((x) => x.file), ['api.json', 'nginx.json']);
  const n = r.reports[1]!;
  assert.equal(n.os, 'debian 12.8');
  assert.deepEqual(n.by_severity, { CRITICAL: 1, HIGH: 1, LOW: 1 });
  assert.equal(n.fixable, 1);
  assert.equal(n.misconfigurations, 1, 'PASS results are not findings');
  assert.equal(n.secrets, 1);
  assert.deepEqual(r.unreadable?.map((e) => e.file), ['junk.json']);
  assert.equal((await listReports(rt, { artifact: 'NGINX', limit: 10, offset: 0 })).total, 1);
});

test('trivy: report findings sort by severity and filter', async () => {
  const r = await reportFindings(rt, { report: 'nginx.json', fixable_only: false, include_misconfigurations: true, include_secrets: true, limit: 10, offset: 0 });
  assert.ok(!('error' in r));
  assert.deepEqual(r.vulnerabilities.map((v) => v.id), ['CVE-2024-3094', 'CVE-2024-0001', 'CVE-2023-9999']);
  assert.equal(r.vulnerabilities[1]!.cvss, 8.1, 'highest score across sources');
  assert.ok(!('description' in r.vulnerabilities[0]!), 'descriptions are left to trivy_find_cve');
  assert.equal(r.misconfigurations?.length, 1);
  assert.equal(r.secrets?.[0]?.start_line, 3);
  assert.ok(!JSON.stringify(r).includes('AKIA'), 'secret match text is never returned');

  const f = await reportFindings(rt, { report: 'nginx:1.27', severity: ['HIGH', 'CRITICAL'], fixable_only: true, include_misconfigurations: false, include_secrets: false, limit: 10, offset: 0 });
  assert.ok(!('error' in f));
  assert.deepEqual(f.vulnerabilities.map((v) => v.id), ['CVE-2024-0001']);
  assert.equal(f.misconfigurations, undefined);
});

test('trivy: report lookup refuses paths outside the directory', async () => {
  for (const bad of ['../etc/passwd', '/etc/passwd', 'sub/x.json', 'missing.json']) {
    const r = await reportFindings(rt, { report: bad, fixable_only: false, include_misconfigurations: false, include_secrets: false, limit: 1, offset: 0 });
    assert.ok('error' in r, bad);
  }
});

test('trivy: find CVE across reports', async () => {
  const r = await findCve(rt, { vulnerability_id: 'cve-2024-3094', limit: 10 });
  assert.equal(r.found, true);
  assert.equal(r.reports_scanned, 2);
  assert.equal(r.artifacts, 2);
  assert.equal(r.title, 'xz backdoor');
  assert.ok((r.description?.length ?? 0) < 1100, 'description is capped');
  assert.deepEqual(r.affected.map((x) => [x.artifact, x.fixed]), [['/srv/api', '1.0.1'], ['nginx:1.27', undefined]]);
  assert.equal((await findCve(rt, { vulnerability_id: 'CVE-2000-0000', limit: 10 })).found, false);
});

test('trivy: cache picks up a rewritten report', async () => {
  const p = path.join(dir, 'api.json');
  await writeFile(p, JSON.stringify({ ...api, Results: [] }));
  const later = new Date(Date.now() + 5000);
  await utimes(p, later, later);
  const r = await findCve(rt, { vulnerability_id: 'CVE-2024-3094', limit: 10 });
  assert.equal(r.artifacts, 1);
  await writeFile(p, JSON.stringify(api));
});

test('trivy: connection test summarises the directory', async () => {
  const ok = await trivy.testConnection(rt);
  assert.equal(ok.ok, true);
  assert.match(ok.message, /Read 2 Trivy report\(s\).*1 file\(s\) skipped/);
  const missing = await trivy.testConnection(trivy.createRuntime({ reportsDir: path.join(dir, 'nope') }));
  assert.equal(missing.ok, false);
});

test('trivy: nested folders are read, symlinks out of the directory and over-deep folders are not', async () => {
  await addNested();
  const files = await rt.files();
  assert.ok(files.includes('2026-11-21/images/nginx.json'));
  assert.ok(files.includes('2026-11-22/nginx.json'));
  assert.ok(!files.some((f) => f.startsWith('.hidden') || f.startsWith('linked-dir') || f.endsWith('deep.json')), files.join());
  assert.match(rt.lastScanLimited ?? '', /deeper than/);

  const r = await listReports(rt, { limit: 50, offset: 0 });
  assert.ok(!r.reports.some((x) => x.artifact === 'outside' || x.artifact === 'deep'));
  assert.match(r.unreadable?.find((e) => e.file === 'escape.json')?.error ?? '', /outside the report directory/);
  assert.match(r.scan_limited ?? '', /deeper than/);

  const f = await reportFindings(rt, { report: '2026-11-21/images/nginx.json', fixable_only: false, include_misconfigurations: false, include_secrets: false, limit: 10, offset: 0 });
  assert.ok(!('error' in f));
  assert.equal(f.created_at, '2026-11-21T03:00:00Z');
  for (const bad of ['2026-11-22/../api.json', '2026-11-22//nginx.json', './api.json', '2026-11-22\\nginx.json', 'linked-dir/secret.json']) {
    const e = await reportFindings(rt, { report: bad, fixable_only: false, include_misconfigurations: false, include_secrets: false, limit: 1, offset: 0 });
    assert.ok('error' in e, bad);
  }
  // By artifact name, the newest scan wins.
  const latest = await reportFindings(rt, { report: 'nginx:1.27', fixable_only: false, include_misconfigurations: false, include_secrets: false, limit: 10, offset: 0 });
  assert.ok(!('error' in latest));
  assert.equal(latest.created_at, '2026-11-22T04:00:00Z');
});

test('trivy: list only the latest report per artifact', async () => {
  const r = await listReports(rt, { latest_only: true, limit: 50, offset: 0 });
  const rows = r.reports.map((x) => [x.artifact, x.artifact_type, x.file, x.scans]);
  assert.deepEqual(rows, [
    ['nginx:1.27', 'filesystem', '2026-11-22/nginx-fs.json', 1],
    ['nginx:1.27', 'container_image', '2026-11-22/nginx.json', 3],
    ['/srv/api', 'filesystem', 'api.json', 1],
  ]);
});

test('trivy: artifact history diffs the latest two scans', async () => {
  const ambiguous = await artifactHistory(rt, { artifact: 'nginx:1.27', limit: 10 });
  assert.ok('error' in ambiguous && 'candidates' in ambiguous, 'image and filesystem share the name');
  assert.equal(ambiguous.candidates?.length, 2);

  const h = await artifactHistory(rt, { artifact: 'nginx:1.27', artifact_type: 'container_image', limit: 10 });
  assert.ok(!('error' in h));
  assert.equal(h.scan_count, 3);
  assert.deepEqual(h.scans.map((s) => s.file), ['nginx.json', '2026-11-21/images/nginx.json', '2026-11-22/nginx.json']);
  assert.deepEqual(h.scans[2]!.by_severity, { CRITICAL: 1, MEDIUM: 2, LOW: 1 });
  const c = h.comparison!;
  assert.equal(c.from.file, '2026-11-21/images/nginx.json');
  assert.equal(c.to.file, '2026-11-22/nginx.json');
  assert.deepEqual(c.fixed, [{ id: 'CVE-2024-0001', severity: 'HIGH', packages: ['libssl3'], fixed_version: '3.0.2' }]);
  assert.deepEqual(c.new, [{ id: 'CVE-2025-1111', severity: 'MEDIUM', packages: ['curl', 'libcurl4'], fixed_version: '8.1' }]);
  assert.equal(c.unchanged_count, 2);
  assert.deepEqual(c.severity_change, { HIGH: -1, MEDIUM: 2 });
});

test('trivy: artifact history compares chosen scans', async () => {
  const h = await artifactHistory(rt, { artifact: 'nginx:1.27', artifact_type: 'container_image', from: '2026-11-22/nginx.json', to: 'nginx.json', limit: 10 });
  assert.ok(!('error' in h));
  const c = h.comparison!;
  assert.equal(c.from.file, 'nginx.json', 'from/to are put in scan order');
  assert.deepEqual(c.fixed.map((v) => v.id), ['CVE-2024-0001']);
  assert.deepEqual(c.new.map((v) => v.id), ['CVE-2025-1111']);

  const byTime = await artifactHistory(rt, { artifact: 'nginx:1.27', artifact_type: 'container_image', to: '2026-11-21T03:00:00Z', limit: 10 });
  assert.ok(!('error' in byTime));
  assert.equal(byTime.comparison?.from.file, 'nginx.json', 'defaults to the scan before "to"');

  const bad = await artifactHistory(rt, { artifact: 'nginx:1.27', artifact_type: 'container_image', from: 'api.json', limit: 10 });
  assert.match(bad.error ?? '', /not a scan of/);

  const single = await artifactHistory(rt, { artifact: '/srv/api', limit: 10 });
  assert.ok(!('error' in single));
  assert.equal(single.scan_count, 1);
  assert.equal(single.comparison, undefined);

  const partial = await artifactHistory(rt, { artifact: 'srv/a', limit: 10 });
  assert.ok(!('error' in partial));
  assert.equal(partial.artifact, '/srv/api');
  assert.ok('error' in (await artifactHistory(rt, { artifact: 'nope', limit: 10 })));
});
