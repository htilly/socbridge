import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import express, { type NextFunction, type Request, type Response } from 'express';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { BackendRegistry } from '../backends/registry.js';
import { ConfigStore } from '../config/store.js';
import { HttpError, type AppContext } from '../http/context.js';
import { findingsRouter, sourceList } from '../http/findings.js';

test('findings sources: says what each backend lacks', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-src-'));
  try {
    const store = ConfigStore.forDataDir(dir, randomBytes(32));
    await store.load();
    const registry = new BackendRegistry(store);
    const state = (admin = true) => {
      const list = sourceList(registry, admin);
      const get = (id: string) => list.find((b) => b.id === id)!;
      return { wazuh: get('wazuh'), defectdojo: get('defectdojo'), trivy: get('trivy'), graylog: get('graylog') };
    };

    let s = state();
    assert.equal(s.wazuh.state, 'not-configured');
    assert.equal(s.defectdojo.state, 'not-configured');
    assert.equal(s.trivy.state, 'not-configured');
    assert.equal(s.graylog.state, 'not-configured');
    for (const id of ['wazuh', 'trivy', 'defectdojo', 'graylog'] as const) assert.equal(s[id].findings, true, `${id} is on the Findings page`);

    await store.mutate((d) => { d.backends.wazuh = { enabled: true, managerUrl: 'https://w:55000' }; });
    s = state();
    assert.equal(s.wazuh.state, 'incomplete');
    assert.ok((s.wazuh.issues ?? []).length > 0);
    assert.equal(state(false).wazuh.issues, undefined, 'issues are for admins only');

    await store.mutate((d) => { d.backends.wazuh = { enabled: true, managerUrl: 'https://w:55000', managerUser: 'u', managerPassword: 'p' }; });
    s = state();
    assert.equal(s.wazuh.state, 'incomplete');
    assert.match(s.wazuh.issues?.[0] ?? '', /Indexer/);

    await store.mutate((d) => {
      d.backends.wazuh = { enabled: true, managerUrl: 'https://w:55000', managerUser: 'u', managerPassword: 'p', indexerUrl: 'https://i:9200', indexerUser: 'u', indexerPassword: 'p' };
    });
    assert.equal(state().wazuh.state, 'ready');

    await store.mutate((d) => { d.backends.wazuh = { ...d.backends.wazuh, enabled: false }; });
    assert.equal(state().wazuh.state, 'disabled');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const report = {
  SchemaVersion: 2,
  CreatedAt: '2026-11-20T03:00:00Z',
  ArtifactName: 'nginx:1.27',
  ArtifactType: 'container_image',
  Results: [
    {
      Target: 'nginx',
      Vulnerabilities: [
        { VulnerabilityID: 'CVE-2024-0001', PkgName: 'libssl3', InstalledVersion: '3.0.1', FixedVersion: '3.0.2', Severity: 'HIGH' },
        { VulnerabilityID: 'CVE-2024-3094', PkgName: 'xz-utils', InstalledVersion: '5.6.0', Severity: 'CRITICAL' },
        { VulnerabilityID: 'CVE-2023-9999', PkgName: 'zlib', InstalledVersion: '1.2', Severity: 'LOW' },
      ],
    },
  ],
};

test('findings routes: each source on its own; a failing backend does not hide the others', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-fr-'));
  const reports = path.join(dir, 'reports');
  await mkdir(reports);
  await writeFile(path.join(reports, 'nginx.json'), JSON.stringify(report));
  const store = ConfigStore.forDataDir(dir, randomBytes(32));
  await store.load();
  await store.mutate((d) => {
    d.backends.trivy = { enabled: true, reportsDir: reports };
    // Nothing listens on port 9: every call fails like an outage.
    d.backends.defectdojo = { enabled: true, url: 'http://127.0.0.1:9', apiKey: 'k', tlsVerify: true };
  });
  const registry = new BackendRegistry(store);
  const app = express();
  app.use((_req, res, next) => { res.locals.user = { id: 'u', name: 'u', role: 'user' }; next(); });
  const views: { user: string; source: string; backend: string; outcome: string; args: { path: string } }[] = [];
  app.use('/findings', findingsRouter({ audit: { record: async (r: unknown) => void views.push(r as (typeof views)[number]) }, env: { geoipDb: '/nonexistent' }, registry } as unknown as AppContext));
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(err instanceof HttpError ? err.status : 500).json({ error: (err as Error).message });
  });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/findings`;
  const get = async (p: string) => {
    const r = await fetch(base + p);
    return { status: r.status, body: (await r.json()) as Record<string, any> };
  };
  try {
    let r = await get('/trivy');
    assert.equal(r.status, 200);
    assert.equal(r.body.total, 3);
    assert.deepEqual(r.body.by_severity, { CRITICAL: 1, HIGH: 1, LOW: 1 });
    r = await get('/trivy?severity=Critical,High');
    assert.equal(r.body.total, 2, 'severity filter uses the shared scale');
    r = await get('/trivy/reports/nginx.json?severity=Critical');
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.vulnerabilities.map((v: { id: string }) => v.id), ['CVE-2024-3094']);
    assert.equal((await get('/trivy/reports/missing.json')).status, 404);
    assert.equal((await get('/trivy?severity=Bogus')).status, 400);

    r = await get('/defectdojo');
    assert.equal(r.status, 502, 'an unreachable backend is a gateway error, not an empty list');
    assert.match(r.body.error, /did not answer this request \(reference [0-9a-f]{8}\)/);
    assert.doesNotMatch(r.body.error, /127\.0\.0\.1/, 'hosts are not shown to non-administrators');
    assert.equal((await get('/trivy')).status, 200, 'Trivy still answers');

    assert.equal((await get('/graylog')).status, 409, 'not enabled');
    assert.equal((await get('/overview')).status, 409);

    // Repeated failures open DefectDojo's circuit: the page gets a fast 503 saying so.
    for (let i = 0; i < 2; i++) await get('/defectdojo');
    r = await get('/defectdojo');
    assert.equal(r.status, 503);
    assert.match(r.body.error, /outage, not an empty result/);
    const ok = views.filter((v) => v.outcome === 'ok' && v.args.path.endsWith('/trivy'));
    assert.equal(ok.length, 1, 'a repeated view is recorded once');
    assert.deepEqual([ok[0]!.user, ok[0]!.source, ok[0]!.backend], ['u', 'web', 'trivy']);
    assert.ok(views.some((v) => v.backend === 'defectdojo' && v.outcome === 'error'));
  } finally {
    srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});
