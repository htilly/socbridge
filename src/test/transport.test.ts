import assert from 'node:assert/strict';
import { test } from 'node:test';
import { defectdojo } from '../backends/defectdojo/index.js';
import { transportOf } from '../backends/transport.js';
import { trivy } from '../backends/trivy/index.js';
import { wazuh } from '../backends/wazuh/index.js';
import { healthSummary } from '../http/status.js';

test('transport: https with verification is tls; verification off is tls-unverified', () => {
  assert.equal(transportOf(defectdojo, { url: 'https://dd.example' }).transport, 'tls', 'tlsVerify defaults to on');
  assert.equal(transportOf(defectdojo, { url: 'https://dd.example', tlsVerify: true }).transport, 'tls');
  assert.equal(transportOf(defectdojo, { url: 'https://dd.example', tlsVerify: false }).transport, 'tls-unverified');
});

test('transport: the weakest connection wins and each is listed', () => {
  const v = transportOf(wazuh, { managerUrl: 'https://wazuh.manager:55000', indexerUrl: 'http://wazuh.indexer:9200' });
  assert.equal(v.transport, 'plaintext');
  assert.deepEqual(v.connections, ['Manager API URL: https, certificate verified', 'Indexer URL: plain http, not encrypted']);
  assert.equal(transportOf(wazuh, { managerUrl: 'https://m:55000', indexerUrl: '' }).transport, 'tls', 'unset URLs are ignored');
});

test('transport: no URL fields (Trivy) or nothing saved is local', () => {
  assert.equal(transportOf(trivy, { reportsDir: '/reports' }).transport, 'local');
  assert.equal(transportOf(defectdojo, undefined).transport, 'local');
});

test('status summary says online and how', () => {
  const ok = { status: 'ok' as const, checks: [{ name: 'api', status: 'ok' as const, message: 'fine' }] };
  assert.equal(healthSummary(ok, 'tls'), 'Online · encrypted');
  assert.equal(healthSummary(ok, 'plaintext'), 'Online · unencrypted');
  assert.equal(healthSummary(ok, 'tls-unverified'), 'Online · not verified');
});
