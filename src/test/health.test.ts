import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { graylogHealth } from '../backends/graylog/health.js';
import { BackendGate, fromChecks, GateRejected, HealthMonitor, worst } from '../backends/health.js';
import { basicAuth, HttpClient } from '../backends/http.js';
import { BackendRegistry } from '../backends/registry.js';
import { trivy } from '../backends/trivy/index.js';
import type { BackendModule } from '../backends/types.js';
import { BackendError, isOutage } from '../backends/http.js';
import { wazuhHealth } from '../backends/wazuh/health.js';
import type { WazuhClient } from '../backends/wazuh/client.js';
import { ConfigStore } from '../config/store.js';
import { healthSummary } from '../http/status.js';
import { backendsView, gatedCall } from '../mcp/server.js';

const GATE = { concurrency: 2, maxQueue: 1, queueTimeoutMs: 200, failureThreshold: 3, openMs: 50 };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('health: worst status wins', () => {
  assert.equal(worst([]), 'ok');
  assert.equal(worst(['ok', 'degraded', 'ok']), 'degraded');
  assert.equal(worst(['degraded', 'down']), 'down');
  assert.equal(fromChecks([{ name: 'a', status: 'ok', message: '' }, { name: 'b', status: 'degraded', message: '' }]).status, 'degraded');
});

function fakeModule(results: boolean[], withHealth = false) {
  let calls = 0;
  const next = () => results[Math.min(calls++, results.length - 1)]!;
  const mod = {
    id: 'trivy',
    title: 'Fake',
    maturity: 'ready',
    testConnection: async () => {
      const ok = next();
      return { ok, message: ok ? 'fine' : 'boom' };
    },
    ...(withHealth ? { health: async () => fromChecks([{ name: 'x', status: next() ? 'ok' : 'degraded', message: 'h' }]) } : {}),
  } as unknown as BackendModule<any, any>;
  return { mod, calls: () => calls };
}

test('health monitor: caches per runtime, shares concurrent checks, re-checks on force', async () => {
  const monitor = new HealthMonitor();
  const { mod, calls } = fakeModule([true, false]);
  const rt = {};

  const [a, b] = await Promise.all([monitor.check(mod, rt), monitor.check(mod, rt)]);
  assert.equal(calls(), 1, 'concurrent checks share one call');
  assert.equal(a.health.status, 'ok');
  assert.equal(b.health.checks[0]!.name, 'connection', 'without health(), the connection test is the check');

  await monitor.check(mod, rt);
  assert.equal(calls(), 1, 'fresh result is reused');
  assert.equal(monitor.peek(rt)?.health.status, 'ok');

  const forced = await monitor.check(mod, rt, true);
  assert.equal(calls(), 2, 'force re-checks');
  assert.equal(forced.health.status, 'down');

  await monitor.check(mod, {});
  assert.equal(calls(), 3, 'a new runtime (changed settings) is checked again');
  assert.equal(monitor.peek({}), undefined);
});

test('health monitor: uses health() when present; throws and timeouts are down', async () => {
  const { mod } = fakeModule([false], true);
  assert.equal((await new HealthMonitor().check(mod, {})).health.status, 'degraded');

  const throwing = { health: async () => { throw new Error('nope'); } } as unknown as BackendModule<any, any>;
  const t = await new HealthMonitor().check(throwing, {});
  assert.equal(t.health.status, 'down');
  assert.match(t.health.checks[0]!.message, /nope/);

  const hung = { health: () => new Promise(() => {}) } as unknown as BackendModule<any, any>;
  const h = await new HealthMonitor(60_000, 30).check(hung, {});
  assert.equal(h.health.status, 'down');
  assert.match(h.health.checks[0]!.message, /No answer/);
});

test('health monitor: the schedule checks ready backends and skips stubs', async () => {
  const monitor = new HealthMonitor();
  const ready = fakeModule([true]);
  const stub = fakeModule([true]);
  (stub.mod as { maturity: string }).maturity = 'stub';
  const rt = {};
  monitor.start(() => [{ mod: ready.mod, runtime: rt }, { mod: stub.mod, runtime: {} }], 20);
  await sleep(70);
  monitor.stop();
  assert.ok(ready.calls() >= 2, `ran on a schedule (${ready.calls()} checks)`);
  assert.equal(stub.calls(), 0);
  assert.equal(monitor.peek(rt)?.health.status, 'ok');
});

test('gate: limits concurrency and refuses when the queue is full', async () => {
  const gate = new BackendGate('Fake', GATE);
  let running = 0;
  let peak = 0;
  const slow = () =>
    gate.run(async () => {
      running++;
      peak = Math.max(peak, running);
      await sleep(30);
      running--;
      return 'ok';
    });
  const calls = [slow(), slow(), slow(), slow()].map((p) => p.then((v) => v, (e: Error) => e));
  const out = await Promise.all(calls);
  assert.equal(peak, 2);
  assert.deepEqual(out.slice(0, 3), ['ok', 'ok', 'ok'], 'two run, one waits');
  assert.ok(out[3] instanceof GateRejected && /busy/.test(out[3].message), 'the fourth is refused');
});

test('gate: circuit opens after consecutive failures, half-opens, and closes on success', async () => {
  const gate = new BackendGate('Fake', GATE);
  const fail = () => gate.run(async () => { throw new BackendError('ECONNREFUSED', undefined, true); }).catch((e: Error) => e);
  for (let i = 0; i < 3; i++) assert.match((await fail()).message, /ECONNREFUSED/);
  assert.equal(gate.state, 'open');
  const refused = await fail();
  assert.ok(refused instanceof GateRejected);
  assert.match(refused.message, /outage, not an empty result/);
  assert.match(refused.message, /ECONNREFUSED/);

  await sleep(60);
  assert.equal(gate.state, 'half-open');
  assert.match((await fail()).message, /ECONNREFUSED/, 'one trial call goes through');
  assert.equal(gate.state, 'open', 'and failing reopens');

  await sleep(60);
  assert.equal(await gate.run(async () => 'back'), 'back');
  assert.equal(gate.state, 'closed');
  assert.equal(gate.view().consecutive_failures, 0);

  // A success in between resets the count.
  await fail();
  await fail();
  await gate.run(async () => 'good');
  await fail();
  assert.equal(gate.state, 'closed');
});

test('gate: bad input and 4xx answers never open the circuit; invalid input does not hide an outage', async () => {
  const gate = new BackendGate('Fake', GATE);
  const run = (err: Error) => gate.run(async () => { throw err; }).catch(() => undefined);
  for (let i = 0; i < 10; i++) {
    await run(new BackendError('Invalid agent id "x"'));
    await run(new BackendError('responded 404', 404));
    await run(new Error('bad argument'));
  }
  assert.equal(gate.state, 'closed');
  assert.equal(gate.view().consecutive_failures, 0);
  for (let i = 0; i < 3; i++) {
    await run(new BackendError('responded 503', 503));
    await run(new BackendError('Invalid agent id "x"'));
  }
  assert.equal(gate.state, 'open');
  assert.ok(isOutage(new DOMException('timed out', 'TimeoutError')));
});

test('gated tool calls: outages open the circuit; refused calls say why', async () => {
  const gate = new BackendGate('Fake', GATE);
  let calls = 0;
  const handler = async () => {
    calls++;
    throw new BackendError('responded 502', 502);
  };
  const call = () => gatedCall('fake_tool', gate, handler, {});
  for (let i = 0; i < 3; i++) await call();
  const r = await call();
  assert.equal(calls, 3, 'the backend is not called while the circuit is open');
  assert.equal(r.isError, true);
  assert.match((r.content[0] as { text: string }).text, /fake_tool refused: Fake is failing \(3 calls in a row; last: responded 502\)/);
});

test('backend health: Wazuh without indexer is degraded; manager failure is down', async () => {
  const client = (managerOk: boolean, hasIndexer: boolean) =>
    ({
      hasIndexer,
      api: async () => {
        if (!managerOk) throw new Error('ECONNREFUSED');
        return { data: { api_version: '4.9.0' } };
      },
      indexerInfo: async () => ({ version: { number: '2.13.0', distribution: 'opensearch' } }),
    }) as unknown as WazuhClient;
  const a = await wazuhHealth(client(true, false));
  assert.equal(a.status, 'degraded');
  assert.equal(healthSummary(a), 'No indexer');
  assert.equal((await wazuhHealth(client(true, true))).status, 'ok');
  const c = await wazuhHealth(client(false, true));
  assert.equal(c.status, 'down');
  assert.deepEqual(c.checks.map((x) => `${x.name}:${x.status}`), ['manager:down', 'indexer:ok']);
  assert.equal(healthSummary(c), 'Down: manager');
});

test('backend health: Trivy directory states', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-th-'));
  try {
    const rt = trivy.createRuntime({ reportsDir: dir });
    assert.equal((await trivy.health!(rt)).status, 'ok', 'empty directory is fine');
    await writeFile(path.join(dir, 'junk.json'), '{"x":1}');
    assert.equal((await trivy.health!(rt)).status, 'down', 'nothing readable');
    await writeFile(path.join(dir, 'ok.json'), JSON.stringify({ SchemaVersion: 2, ArtifactName: 'a', Results: [] }));
    const h = await trivy.health!(rt);
    assert.equal(h.status, 'degraded');
    assert.match(h.checks[0]!.message, /1 report\(s\) readable, 1 skipped/);
    const gone = await trivy.health!(trivy.createRuntime({ reportsDir: path.join(dir, 'missing') }));
    assert.equal(gone.status, 'down');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('backend health: Graylog cluster colour and forbidden cluster status', async () => {
  let cluster: { status: number; body: unknown } = { status: 200, body: { status: 'green' } };
  const srv = http.createServer((req, res) => {
    const send = (s: number, o: unknown) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.url === '/api/system') return send(200, { version: '7.0.1', lifecycle: 'running', is_processing: true });
    if (req.url === '/api/system/indexer/cluster/health') return send(cluster.status, cluster.body);
    send(404, {});
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const rt = {
      http: new HttpClient({ baseUrl: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` }),
      headers: { authorization: basicAuth('t', 'token'), 'x-requested-by': 'socbridge' },
      mcp: null,
    };
    assert.equal((await graylogHealth(rt)).status, 'ok');
    cluster = { status: 200, body: { status: 'yellow' } };
    assert.equal((await graylogHealth(rt)).status, 'degraded');
    cluster = { status: 200, body: { status: 'red' } };
    assert.equal((await graylogHealth(rt)).status, 'down');
    cluster = { status: 403, body: { message: 'forbidden' } };
    const h = await graylogHealth(rt);
    assert.equal(h.status, 'degraded');
    assert.match(h.checks.find((c) => c.name === 'indexer')!.message, /not visible/);
  } finally {
    srv.close();
  }
});

test('socbridge_backends: states, health and open circuit', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'socbridge-bv-'));
  try {
    const store = ConfigStore.forDataDir(dir, randomBytes(32));
    await store.load();
    const registry = new BackendRegistry(store);
    const reports = path.join(dir, 'reports');
    await mkdir(reports);
    await store.mutate((d) => {
      d.backends.trivy = { enabled: true, reportsDir: reports };
      d.backends.defectdojo = { enabled: true };
    });
    const byId = async () => Object.fromEntries((await backendsView(registry)).map((b) => [b.id, b as Record<string, any>]));
    let v = await byId();
    assert.equal(v.wazuh!.state, 'disabled');
    assert.equal(v.defectdojo!.state, 'misconfigured');
    assert.equal(v.trivy!.state, 'ok');
    assert.equal(v.trivy!.health.checks[0].name, 'reports');
    assert.ok(v.trivy!.health.checked_at);

    const { mod, runtime } = registry.active().find((a) => a.mod.id === 'trivy')!;
    const gate = registry.gate(mod, runtime as object);
    for (let i = 0; i < 5; i++) await gate.run(async () => { throw new BackendError('EIO', undefined, true); }).catch(() => {});
    v = await byId();
    assert.equal(v.trivy!.state, 'down', 'an open circuit means down even if the last health check was fine');
    assert.equal(v.trivy!.circuit, 'open');
    assert.equal(v.trivy!.last_error, 'EIO');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
