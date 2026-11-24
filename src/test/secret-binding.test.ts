import assert from 'node:assert/strict';
import { test } from 'node:test';
import { storedKeyMayGoTo } from '../ai/providers.js';
import { getModule } from '../backends/registry.js';
import type { ServerAi } from '../config/schema.js';
import { mergeBackendValues } from '../http/api.js';

// A-005: a stored secret is only sent to the place it was entered for.

const wazuh = getModule('wazuh')!;
const graylog = getModule('graylog')!;
const stored = {
  managerUrl: 'https://wazuh:55000',
  managerUser: 'ro',
  managerPassword: 'm-secret',
  indexerUrl: 'https://wazuh-indexer:9200',
  indexerUser: 'ro',
  indexerPassword: 'i-secret',
  tlsVerify: true,
};
const form = (over: Record<string, string | boolean> = {}) => ({
  managerUrl: stored.managerUrl,
  managerUser: 'ro',
  managerPassword: '',
  indexerUrl: stored.indexerUrl,
  indexerUser: 'ro',
  indexerPassword: '',
  tlsVerify: true,
  ...over,
});

test('backend secrets: unchanged target keeps the stored secret', () => {
  const next = mergeBackendValues(wazuh, stored, form({ managerUrl: 'https://wazuh:55000/' }));
  assert.equal(next.managerPassword, 'm-secret');
  assert.equal(next.indexerPassword, 'i-secret');
});

test('backend secrets: a changed URL needs that secret again', () => {
  assert.throws(() => mergeBackendValues(wazuh, stored, form({ managerUrl: 'https://evil.example.com' })), /Manager API password again/);
  // Only the secret belonging to the changed URL is affected.
  const next = mergeBackendValues(wazuh, stored, form({ indexerUrl: 'https://new-indexer:9200', indexerPassword: 'new' }));
  assert.equal(next.managerPassword, 'm-secret');
  assert.equal(next.indexerPassword, 'new');
  // Re-entering the secret allows the change.
  assert.equal(mergeBackendValues(wazuh, stored, form({ managerUrl: 'https://evil.example.com', managerPassword: 'typed' })).managerPassword, 'typed');
});

test('backend secrets: weaker TLS or a new CA needs every stored secret again', () => {
  assert.throws(() => mergeBackendValues(wazuh, stored, form({ tlsVerify: false })), /Verify TLS/);
  assert.throws(() => mergeBackendValues(wazuh, stored, form({ caCert: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----' })), /CA certificate/);
  // Turning verification back on is not a weakening.
  const off = { ...stored, tlsVerify: false };
  assert.equal(mergeBackendValues(wazuh, off, form({ tlsVerify: true })).managerPassword, 'm-secret');
});

test('backend secrets: a backend whose secret has no matching URL name binds to all its URLs', () => {
  const prev = { url: 'https://graylog:9000', apiToken: 'tok', tlsVerify: true };
  assert.throws(() => mergeBackendValues(graylog, prev, { url: 'https://evil.example.com', tlsVerify: true }), /Access token again/);
  assert.equal(mergeBackendValues(graylog, prev, { url: 'https://graylog:9000', tlsVerify: true }).apiToken, 'tok');
});

const ai = (over: Partial<ServerAi> = {}): ServerAi => ({ enabled: true, provider: 'local', model: 'm', baseUrl: 'http://ollama:11434/v1', keys: { local: 'k', openai: 'o' }, ...over });

test('assistant key: goes only to the URL it was entered for', () => {
  const s = ai({ keyUrls: { local: 'http://ollama:11434/v1' } });
  assert.equal(storedKeyMayGoTo(s, 'local', 'http://ollama:11434/v1/'), true);
  assert.equal(storedKeyMayGoTo(s, 'local', 'https://evil.example.com/v1'), false);
  assert.equal(storedKeyMayGoTo(s, 'local', ''), false);
});

test('assistant key: provider defaults are always fine, other URLs need a binding', () => {
  const s = ai();
  assert.equal(storedKeyMayGoTo(s, 'anthropic', 'https://evil.example.com'), true, 'the Anthropic key never uses a base URL');
  assert.equal(storedKeyMayGoTo(s, 'openai', ''), true, 'default api.openai.com');
  assert.equal(storedKeyMayGoTo(s, 'openai', 'https://evil.example.com/v1'), false, 'no binding for a custom OpenAI URL');
  // Keys stored before keyUrls existed are bound to the saved base URL.
  assert.equal(storedKeyMayGoTo(s, 'local', 'http://ollama:11434/v1'), true);
  assert.equal(storedKeyMayGoTo(s, 'local', 'http://other:11434/v1'), false);
});
