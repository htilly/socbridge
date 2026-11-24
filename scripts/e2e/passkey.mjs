// End-to-end: real WebAuthn ceremonies (software ES256 authenticator) plus findings API.
const BASE = process.env.E2E_BASE ?? 'http://localhost:18080';
const ORIGIN = process.env.E2E_ORIGIN ?? 'https://localhost:18080';
const RPID = new URL(ORIGIN).hostname;
const SETUP = process.env.SETUP_TOKEN ?? 'e2e-setup-token-0123456789abcdef';
const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
const b64u = (b) => Buffer.from(b).toString('base64url');
const cat = (...a) => Uint8Array.from(Buffer.concat(a.map((x) => Buffer.from(x))));
const sha = async (d) => new Uint8Array(await subtle.digest('SHA-256', d));
const head = (m, n) => (n < 24 ? Uint8Array.of((m << 5) | n) : n < 256 ? Uint8Array.of((m << 5) | 24, n) : Uint8Array.of((m << 5) | 25, n >> 8, n & 255));
function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') { const b = enc.encode(v); return cat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (v instanceof Map) { const p = [head(5, v.size)]; for (const [k, x] of v) p.push(cbor(k), cbor(x)); return cat(...p); }
}
function der(raw) {
  const int = (x) => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++; x = x.slice(i); if (x[0] & 0x80) x = cat(Uint8Array.of(0), x); return cat(Uint8Array.of(2, x.length), x); };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32)); return cat(Uint8Array.of(0x30, r.length + s.length), r, s);
}
let cookie = '';
async function api(method, path, body, origin = ORIGIN) {
  const res = await fetch(BASE + '/api' + path, { method, headers: { 'content-type': 'application/json', 'x-socbridge': '1', origin, ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const sc = res.headers.get('set-cookie'); if (sc && sc.includes('socbridge_sid=')) cookie = sc.split(';')[0];
  const data = await res.json(); return { status: res.status, data };
}
let cred;
async function create(o, origin = ORIGIN) {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await subtle.exportKey('jwk', kp.publicKey);
  const id = crypto.getRandomValues(new Uint8Array(16));
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]].map(([k, v]) => [k, v instanceof Buffer ? new Uint8Array(v) : v])));
  const authData = cat(await sha(enc.encode(RPID)), Uint8Array.of(0x45), new Uint8Array(4), new Uint8Array(16), Uint8Array.of(0, id.length), id, cose);
  const cdj = enc.encode(JSON.stringify({ type: 'webauthn.create', challenge: o.challenge, origin, crossOrigin: false }));
  cred = { id, key: kp.privateKey, user: o.user.id, counter: 0 };
  return { id: b64u(id), rawId: b64u(id), type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64u(cdj), attestationObject: b64u(cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))), transports: ['internal'] } };
}
async function get(o, { origin = ORIGIN, counter } = {}) {
  cred.counter = counter ?? cred.counter + 1;
  const authData = cat(await sha(enc.encode(RPID)), Uint8Array.of(0x05), Uint8Array.of(0, 0, 0, cred.counter));
  const cdj = enc.encode(JSON.stringify({ type: 'webauthn.get', challenge: o.challenge, origin, crossOrigin: false }));
  const sig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cred.key, cat(authData, await sha(cdj))));
  return { id: b64u(cred.id), rawId: b64u(cred.id), type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64u(cdj), authenticatorData: b64u(authData), signature: b64u(der(sig)), userHandle: cred.user } };
}
let failures = 0;
const check = (name, cond, extra = '') => { if (!cond) failures++; console.log((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  ' + extra : '')); };

// Pre-setup certificate step: the setup token (and nothing else) opens /server/tls until an admin exists.
const tlsGet = async (token) => {
  const res = await fetch(BASE + '/api/server/tls', { headers: { 'x-socbridge': '1', origin: ORIGIN, ...(token !== undefined ? { 'x-setup-token': token } : {}) } });
  return { status: res.status, data: await res.json() };
};
let pre = await tlsGet();
check('pre-setup: /server/tls needs a session or the setup token', pre.status === 401, pre.data.error);
pre = await tlsGet('wrong-token-wrong-token-wrong');
check('pre-setup: wrong setup token refused on /server/tls', pre.status === 403, pre.data.error);
pre = await tlsGet(SETUP);
check('pre-setup: setup token opens /server/tls', pre.status === 200 && pre.data.envMode === 'off', JSON.stringify(pre.data));
const preUsers = await fetch(BASE + '/api/users', { headers: { 'x-socbridge': '1', 'x-setup-token': SETUP } });
check('pre-setup: setup token opens nothing else', preUsers.status === 401, String(preUsers.status));
const preMe = await api('GET', '/me');
check('/me reports TLS serving mode for the setup guide', preMe.data.tlsServing === 'off' && preMe.data.caFingerprint === null, JSON.stringify(preMe.data));

let r = await api('POST', '/auth/setup/options', { setupToken: 'wrong-token-wrong-token-wrong', name: 'alice' });
check('wrong setup token rejected', r.status === 403, r.data.error);
r = await api('POST', '/auth/setup/options', { setupToken: SETUP, name: 'alice' });
check('setup options', r.status === 200 && r.data.options.authenticatorSelection.userVerification === 'required');
r = await api('POST', '/auth/register/verify', { flowId: r.data.flowId, response: await create(r.data.options), label: 'Test key' });
check('admin passkey registered + session', r.status === 200 && cookie !== '', r.data.error ?? '');
r = await api('GET', '/me'); check('/me is admin', r.data.user?.role === 'admin' && r.data.setupRequired === false);
r = await api('POST', '/auth/setup/options', { setupToken: SETUP, name: 'eve' });
check('setup token dead after first admin', r.status === 409, r.data.error);
r = await api('POST', '/auth/reauth/options', {});
check('passkey confirmation: offers the account\'s own passkeys', r.status === 200 && r.data.options.allowCredentials.length === 1);
const beforeConfirm = cookie;
r = await api('POST', '/auth/login/verify', { flowId: r.data.flowId, response: await get(r.data.options) });
check('passkey confirmation: accepted without a new session', r.status === 200 && cookie === beforeConfirm, r.data.error ?? '');
const meId = (await api('GET', '/me')).data.user.id;
r = await api('PATCH', '/users/' + meId, { readBackends: ['trivy'] });
check('read limit: other backends refuse the user', r.status === 200 && (await api('GET', '/findings/overview')).status === 403);
r = await api('PATCH', '/users/' + meId, { readBackends: null });
check('read limit: lifted again', r.status === 200 && (await api('GET', '/findings/overview')).status === 200);
r = await api('POST', '/invites', { role: 'admin' });
check('invite created', r.status === 201);
await api('DELETE', '/invites/' + r.data.id);
r = await api('DELETE', '/sessions/others');
check('other sessions: none to end', r.status === 200 && r.data.ended === 0);
const health = await (await fetch(BASE + '/health')).json();
check('/health names no version or build', JSON.stringify(health) === '{"status":"ok"}');
await api('POST', '/auth/logout', {}); const old = cookie; cookie = '';
r = await api('GET', '/me'); check('logged out', r.data.user === null);
pre = await tlsGet(SETUP);
check('setup token no longer opens /server/tls once an admin exists', pre.status === 401, pre.data.error);
let o = await api('POST', '/auth/login/options', {});
r = await api('POST', '/auth/login/verify', { flowId: o.data.flowId, response: await get(o.data.options, { origin: 'https://evil.example.com' }) });
check('wrong origin in clientData rejected', r.status === 401, r.data.error?.slice(0, 80));
o = await api('POST', '/auth/login/options', {});
r = await api('POST', '/auth/login/verify', { flowId: o.data.flowId, response: await get(o.data.options) });
check('login with passkey', r.status === 200 && cookie !== '', r.data.error ?? '');
const replayFlow = o.data.flowId;
o = await api('POST', '/auth/login/options', {});
r = await api('POST', '/auth/login/verify', { flowId: o.data.flowId, response: await get(o.data.options, { counter: 1 }) });
check('counter regression rejected', r.status === 401, r.data.error?.slice(0, 80));
r = await api('POST', '/auth/login/verify', { flowId: replayFlow, response: await get({ challenge: 'x' }) });
check('challenge flow is single-use', r.status === 400, r.data.error);
r = await api('POST', '/tokens', { label: 'x' }, 'https://evil.example.com');
check('cross-origin API write refused', r.status === 403, r.data.error);
r = await api('GET', '/findings/overview'); check('findings overview', r.status === 200 && r.data.total > 0, `total=${r.data.total} agents=${r.data.top_agents?.length}`);
r = await api('GET', '/findings/agents/1?severity=Critical,High'); check('agent findings filtered', r.status === 200 && r.data.vulnerabilities.every((v) => ['Critical', 'High'].includes(v.vulnerability.severity)), `n=${r.data.returned}`);
r = await api('GET', '/findings/trend?days=30'); check('vulnerability trend per agent', r.status === 200 && r.data.by_day.length === 30 && r.data.new > 0 && r.data.resolved > 0 && r.data.agents.length === 6 && r.data.agents[0].net >= r.data.agents[5].net && !!r.data.snapshots_since, `new=${r.data.new} resolved=${r.data.resolved} agents=${r.data.agents?.length}`);
r = await api('GET', '/findings/trend?days=12'); check('trend window outside the offered ones rejected', r.status === 400);
r = await api('GET', '/findings/attacks?window=7d'); check('attack trend', r.status === 200 && r.data.attempts > 0 && r.data.categories.every((c) => c.points.length === 56) && r.data.categories.find((c) => c.id === 'smtp').previous !== null, `attempts=${r.data.attempts}`);
const attackRange = `from=${encodeURIComponent(r.data.from)}&to=${encodeURIComponent(r.data.to)}`;
r = await api('GET', '/findings/attacks/imap?' + attackRange); check('attack details', r.status === 200 && r.data.attempts === 42 && r.data.top_users[0].key === 'info@example.com', JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/attacks/' + encodeURIComponent('other_login:pam') + '?' + attackRange); check('details of a service found in the alerts', r.status === 200 && r.data.attempts === 42, JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/attacks/bogus?' + attackRange); check('unknown attack category rejected', r.status === 400);
r = await api('GET', '/findings/attacks?window=5d'); check('attack window outside the offered ones rejected', r.status === 400);
r = await api('GET', '/findings/attacks?from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z'); check('attack trend for chosen dates', r.status === 200 && r.data.from === '2026-01-01T00:00:00.000Z' && r.data.categories[0].points.length <= 62, JSON.stringify(r.data).slice(0, 150));
r = await api('GET', '/findings/attack-map?since=' + new Date(Date.now() - 86400000).toISOString()); check('attack map events', r.status === 200 && r.data.events.length > 1000 && r.data.without_location > 0 && r.data.events[0].at < r.data.events.at(-1).at, `n=${r.data.events?.length}`);
r = await api('GET', '/findings/attack-map?since=2020-01-01T00:00:00Z'); check('attack map start too far back rejected', r.status === 400);
const daySince = '&since=' + new Date(Date.now() - 86400000).toISOString();
r = await api('GET', '/findings/edge-map?layers=port_scan,ips' + daySince); check('edge map: scanners placed with the GeoIP file', r.status === 200 && r.data.geoip === 'GeoLite2-City' && r.data.without_location > 0 && ['Netherlands', 'Brazil'].every((c) => r.data.events.some((e) => e.category === 'port_scan' && e.country === c)), JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/edge-map?layers=bogus' + daySince); check('unknown map layer rejected', r.status === 400);
r = await api('GET', '/findings/firewall?window=90d'); check('firewall trend', r.status === 200 && r.data.categories.map((c) => c.id).join() === 'port_scan,firewall,ips' && r.data.categories[0].unique_ips === 2 && r.data.categories.every((c) => c.previous === null), JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/firewall/port_scan?' + attackRange); check('port scan details: only sources that try many ports', r.status === 200 && r.data.top_ips.length === 2 && r.data.top_ips[0].ports === 44 && r.data.messages.length === 1, JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/firewall/bogus?' + attackRange); check('unknown firewall category rejected', r.status === 400);
r = await api('GET', '/findings/overview?severity=Bogus'); check('bad severity rejected', r.status === 400);
r = await api('GET', '/findings/sources'); check('findings sources: all four on the page and ready', r.status === 200 && ['wazuh', 'trivy', 'defectdojo', 'graylog'].every((id) => r.data.backends.some((b) => b.id === id && b.findings && b.state === 'ready')) && r.data.backends.find((b) => b.id === 'intel')?.findings === false, JSON.stringify(r.data.backends?.map((b) => [b.id, b.state])));
r = await api('GET', '/services/suggestions'); check('service suggestions pair a port with the host listening on it', r.status === 200 && r.data.errors.length === 0 && r.data.suggestions.some((s) => s.endpoints[0]?.port === 443 && s.agents[0] === '001'), JSON.stringify(r.data).slice(0, 300));
r = await api('POST', '/services', { name: 'Shop', importance: 'critical', exposure: 'internet', endpoints: [{ hosts: ['203.0.113.10', 'shop.example'], port: 443 }], agents: ['001'], images: ['nginx:1.27'] }); check('service added', r.status === 201, JSON.stringify(r.data));
r = await api('POST', '/services', { name: 'Bad', agents: ['x'] }); check('invalid service rejected', r.status === 400, r.data.error);
r = await api('GET', '/priorities'); check('fix first: the exposed, attacked KEV image leads, with evidence', r.status === 200 && r.data.actions[0]?.tier === 'A1' && r.data.actions.some((a) => a.target === 'nginx:1.27' && a.tier === 'A1' && a.services[0].exposure === 'confirmed') && r.data.sources.every((s) => s.status === 'ok') && r.data.actions.every((a) => a.evidence.every((id) => r.data.evidence.some((e) => e.id === id))), JSON.stringify(r.data).slice(0, 400));
r = await api('GET', '/priorities?tier=Z9'); check('bad tier rejected', r.status === 400);
r = await api('GET', '/findings/trivy?severity=Critical,High'); check('trivy findings', r.status === 200 && r.data.reports.length === 2 && r.data.total === 3, JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/trivy/reports/nginx.json?severity=Critical'); check('trivy report filtered', r.status === 200 && r.data.vulnerabilities.length === 1 && r.data.vulnerabilities[0].id === 'CVE-2024-3094', JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/defectdojo'); check('defectdojo findings', r.status === 200 && r.data.total === 2 && r.data.by_severity.Critical === 1 && r.data.findings[0].product_name === 'web-shop', JSON.stringify(r.data).slice(0, 200));
r = await api('GET', '/findings/graylog'); check('graylog events', r.status === 200 && r.data.returned === 3 && r.data.messages[0].level === 3, JSON.stringify(r.data).slice(0, 200));
check('graylog triggered events on the Findings page', r.data.events?.total === 1 && r.data.events.events[0].definition === 'SSH brute force' && r.data.events.events[0].priority === 'high', JSON.stringify(r.data.events).slice(0, 200));
r = await api('GET', '/status');
{
  const svc = Object.fromEntries((r.data.services ?? []).map((s) => [s.id, s]));
  check('status bar: wazuh up', svc.wazuh?.health === 'up', JSON.stringify(svc.wazuh));
  check('status bar: every backend up', ['wazuh', 'trivy', 'defectdojo', 'graylog'].every((id) => svc[id]?.health === 'up'), JSON.stringify(Object.values(svc).map((s) => [s.id, s.health, s.summary])));
  check('status bar: transport per backend (mocks are plain http, Trivy is local)', ['wazuh', 'defectdojo', 'graylog'].every((id) => svc[id]?.transport === 'plaintext' && svc[id]?.summary === 'Online · unencrypted') && svc.trivy?.transport === 'local', JSON.stringify(Object.values(svc).map((s) => [s.id, s.transport, s.summary])));
  check('status bar: write support per backend', svc.defectdojo?.write?.supported === true && svc.wazuh?.write?.supported === true && svc.trivy?.write?.supported === false, JSON.stringify(Object.values(svc).map((s) => [s.id, s.write])));
  check('status bar: individual health checks', svc.wazuh?.checks?.map((c) => c.name).join(',') === 'manager,indexer' && svc.graylog?.checks?.some((c) => c.name === 'indexer'), JSON.stringify(svc.wazuh?.checks));
  check('status bar: assistant and certificate listed', !!svc.assistant && !!svc.tls, Object.keys(svc).join(','));
}

// --- Assistant (local OpenAI-compatible provider against mock-llm.mjs) ---
const LLM = process.env.MOCK_LLM_URL ?? 'http://127.0.0.1:19300';
async function chat(messages) {
  const res = await fetch(BASE + '/api/chat', { method: 'POST', headers: { 'content-type': 'application/json', 'x-socbridge': '1', origin: ORIGIN, cookie }, body: JSON.stringify({ messages }) });
  const text = await res.text();
  return { status: res.status, events: res.ok ? text.split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [], text };
}
r = await api('GET', '/chat/status'); check('assistant off by default', r.status === 200 && r.data.enabled === false, JSON.stringify(r.data));
let c = await chat([{ role: 'user', text: 'hi' }]); check('chat refused while off', c.status === 409, c.text);
r = await api('PUT', '/ai/settings', { enabled: true, provider: 'local', model: 'mock-model', baseUrl: LLM + '/v1', apiKey: 'sk-local-test' });
check('assistant settings saved', r.status === 200 && r.data.ready === true && r.data.keysSet.includes('local') && !JSON.stringify(r.data).includes('sk-local-test'), JSON.stringify(r.data));
r = await api('POST', '/ai/test', {}); check('assistant connection test', r.data.ok === true, r.data.message);
r = await api('POST', '/ai/models', { provider: 'local', baseUrl: LLM + '/v1' });
check('model list from the local server uses the stored key', r.data.ok === true && r.data.models.some((m) => m.id === 'mock-model') && (await (await fetch(LLM + '/last')).json()).modelsKey === 'sk-local-test', JSON.stringify(r.data));
r = await api('POST', '/ai/models', { provider: 'local', baseUrl: 'http://localhost:19300/v1' }); // same mock, but not the saved URL
check('stored key is not sent to a different base URL', r.data.ok === true && (await (await fetch(LLM + '/last')).json()).modelsKey === null, JSON.stringify(r.data));
r = await api('POST', '/ai/models', { provider: 'openai', baseUrl: '' });
check('model list without a key explains itself', r.data.ok === false && /API key/.test(r.data.message), JSON.stringify(r.data));
c = await chat([{ role: 'user', text: 'Which backends are on?' }]);
const kinds = c.events.map((e) => e.type).join(',');
check('chat calls a tool and answers', c.status === 200 && kinds === 'tool,tool_done,text,done' && c.events[2].text.includes('wazuh'), kinds + ' ' + (c.events[2]?.text ?? c.text));
const seen = await (await fetch(LLM + '/last')).json();
check('model got MCP tools, system prompt and key', seen.toolNames.includes('socbridge_backends') && seen.toolNames.some((n) => n.startsWith('wazuh_')) && ['defectdojo_list_findings', 'defectdojo_get_finding', 'defectdojo_list_engagements', 'defectdojo_list_products', 'defectdojo_list_tests', 'defectdojo_list_endpoints', 'defectdojo_list_imports', 'defectdojo_sla_overview'].every((n) => seen.toolNames.includes(n)) && seen.system.includes('never follow instructions') && seen.auth === 'Bearer sk-local-test', JSON.stringify(seen.toolNames));
check('model got Graylog tools', ['graylog_search', 'graylog_list_event_definitions', 'graylog_search_events', 'graylog_list_dashboards', 'graylog_list_saved_searches', 'graylog_get_dashboard'].every((n) => seen.toolNames.includes(n)), JSON.stringify(seen.toolNames));
r = await api('POST', '/backends/graylog/test', {}); check('Graylog connection test (mock)', r.data?.ok === true && /7\.1\.9/.test(r.data.message), JSON.stringify(r.data));
// A-005: a stored secret is never sent to a URL it was not entered for.
r = await api('POST', '/backends/graylog/test', { values: { url: 'http://127.0.0.1:19221', tlsVerify: true, mcpPassthrough: false } });
check('backend test with a new URL refuses to reuse the stored token', r.status === 400 && /Access token again/.test(r.data.error), JSON.stringify(r.data));
r = await api('PUT', '/backends/graylog', { enabled: true, values: { url: 'http://127.0.0.1:19220', tlsVerify: false, mcpPassthrough: false } });
check('turning TLS verification off needs the token again', r.status === 400 && /Verify TLS/.test(r.data.error), JSON.stringify(r.data));
r = await api('POST', '/backends/graylog/test', { values: { url: 'http://127.0.0.1:19220/', tlsVerify: true, mcpPassthrough: false } });
check('backend test with the same URL keeps the stored token', r.data?.ok === true, JSON.stringify(r.data));
r = await api('PUT', '/ai/settings', { enabled: true, provider: 'local', model: 'mock-model', baseUrl: 'http://localhost:19300/v1' });
check('assistant settings refuse to keep the key for a new base URL', r.status === 400 && /Enter the API key again/.test(r.data.error), JSON.stringify(r.data));
c = await chat([{ role: 'user', text: 'a' }, { role: 'assistant', text: 'b' }]); check('chat must end with a user turn', c.status === 400, c.text);
r = await api('PUT', '/ai/settings', { enabled: true, provider: 'anthropic', model: '', baseUrl: '' });
check('switching provider keeps other keys, flags missing key', r.data.ready === false && r.data.keysSet.includes('local') && /API key/.test(r.data.reason), JSON.stringify(r.data));
r = await api('PUT', '/ai/settings', { enabled: true, provider: 'anthropic', model: '', baseUrl: '', apiKey: 'sk-ant-test' });
check('Claude provider ready with default model', r.data.ready === true && r.data.keysSet.includes('anthropic'), JSON.stringify(r.data));
r = await api('POST', '/ai/models', { provider: 'anthropic' });
check('Claude model list', r.data.ok === true && r.data.models.some((m) => m.id === 'claude-opus-5-5' && m.label === 'Claude Opus 5.5 (claude-opus-5-5)'), JSON.stringify(r.data));
r = await api('POST', '/ai/test', {}); check('Claude connection test', r.data.ok === true && r.data.message.includes('claude-opus-5-5'), r.data.message);
c = await chat([{ role: 'user', text: 'Which backends are on?' }]);
const ck = c.events.map((e) => e.type).join(',');
check('Claude chat runs the tool loop', ck === 'text,tool,tool_done,text,done' && c.events[3].text.includes('wazuh'), ck + ' ' + c.text.slice(0, 200));
const sa = (await (await fetch(LLM + '/last')).json()).anthropic;
const turn2 = sa.messages;
check('Claude request: key, fallbacks, tools, results in one user turn', sa.key === 'sk-ant-test' && sa.fallbacks === 'default' && /server-side-fallback/.test(sa.beta) && sa.toolNames.includes('wazuh_list_agents') && turn2.length === 3 && turn2[2].content[0].type === 'tool_result', JSON.stringify({ key: sa.key, beta: sa.beta, n: turn2.length }));

// --- OAuth (Claude custom connector) ----------------------------------------
{
  const CB = 'https://claude.ai/api/mcp/auth_callback';
  r = await api('GET', '/me');
  check('oauth: off by default', r.data.oauthEnabled === false, String(r.data.oauthEnabled));
  const off = await fetch(BASE + '/.well-known/oauth-authorization-server');
  const offProbe = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  check('oauth: while off, no metadata and no resource_metadata hint', off.status === 404 && offProbe.headers.get('www-authenticate') === 'Bearer realm="socbridge"', offProbe.headers.get('www-authenticate'));
  r = await api('PUT', '/oauth/settings', { enabled: true });
  check('oauth: admin turns connectors on', r.status === 200 && r.data.enabled === true, JSON.stringify(r.data));
  const probe = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  check('oauth: 401 names the resource metadata', probe.status === 401 && probe.headers.get('www-authenticate').includes(ORIGIN + '/.well-known/oauth-protected-resource/mcp'), probe.headers.get('www-authenticate'));
  const asm = await (await fetch(BASE + '/.well-known/oauth-authorization-server')).json();
  check('oauth: authorization server metadata', asm.issuer === ORIGIN && asm.registration_endpoint === ORIGIN + '/oauth/register', asm.issuer);
  const reg = await (await fetch(BASE + '/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Claude', redirect_uris: [CB], token_endpoint_auth_method: 'none' }) })).json();
  check('oauth: dynamic client registration', typeof reg.client_id === 'string', JSON.stringify(reg).slice(0, 120));
  const verifier = b64u(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64u(await sha(enc.encode(verifier)));
  const q = new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: CB, state: 'xyz', code_challenge: challenge, code_challenge_method: 'S256', resource: ORIGIN + '/mcp' });
  const az = await fetch(BASE + '/oauth/authorize?' + q, { redirect: 'manual' });
  const reqId = (az.headers.get('location') ?? '').split('/authorize/')[1];
  const browserCookie = (az.headers.get('set-cookie') ?? '').split(';')[0];
  check('oauth: authorize sends the browser to the consent screen with a browser cookie', az.status === 303 && !!reqId && browserCookie.startsWith('socbridge_oauth='), az.headers.get('location'));
  // O-002: another browser (the victim of a forwarded consent link) cannot see or answer it.
  r = await api('GET', '/oauth/requests/' + reqId);
  check('oauth: consent request is invisible to another browser', r.status === 404, JSON.stringify(r.data));
  r = await api('POST', '/oauth/requests/' + reqId, { approve: true, access: { backends: { wazuh: 'read' } } });
  check('oauth: consent request cannot be approved from another browser', r.status === 404, JSON.stringify(r.data));
  const sessionCookie = cookie;
  cookie = sessionCookie + '; ' + browserCookie;
  r = await api('GET', '/oauth/requests/' + reqId);
  check('oauth: consent screen describes the request and offers per-backend access', r.status === 200 && r.data.clientName === 'Claude' && r.data.redirectHost === 'claude.ai' && r.data.redirectUri === CB && r.data.previouslyApproved === false && !!r.data.clientRegisteredAt && r.data.scopes.length === 5 && r.data.scopes.every((b) => b.writeGranted === false), JSON.stringify(r.data));
  r = await api('POST', '/oauth/requests/' + reqId, { approve: true, access: { backends: { wazuh: 'write' } } });
  check('oauth: consent cannot give an app write without a grant', r.status === 403 && /write grant/.test(r.data.error), r.data.error);
  r = await api('POST', '/oauth/requests/' + reqId, { approve: true, access: { backends: {} } });
  check('oauth: approving needs at least one backend', r.status === 400 && /at least one backend/.test(r.data.error), r.data.error);
  r = await api('POST', '/oauth/requests/' + reqId, { approve: true, access: { backends: { wazuh: 'read' } } });
  cookie = sessionCookie;
  const back = new URL(r.data.redirect);
  check('oauth: approval returns a code to the client', back.origin === 'https://claude.ai' && back.searchParams.get('state') === 'xyz' && !!back.searchParams.get('code'), r.data.redirect?.slice(0, 80));
  const tok = await (await fetch(BASE + '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: back.searchParams.get('code'), redirect_uri: CB, code_verifier: verifier, client_id: reg.client_id }) })).json();
  check('oauth: code exchanged for tokens', tok.access_token?.startsWith('msat_') && tok.refresh_token?.startsWith('msrt_'), JSON.stringify(tok).slice(0, 80));
  const list = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + tok.access_token }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
  const tools = (await list.json()).result?.tools ?? [];
  check('oauth: access token lists the tools of the approved backends only', list.status === 200 && tools.some((t) => t.name.startsWith('wazuh_')) && tools.every((t) => t.name.startsWith('wazuh_') || t.name === 'socbridge_backends'), 'n=' + tools.length);
  r = await api('GET', '/oauth/grants');
  check('oauth: connected app shows its approved scope', r.data[0]?.access?.backends?.wazuh === 'read' && !r.data[0].access.backends.defectdojo, JSON.stringify(r.data[0]?.access));
  {
    const gid = r.data[0]?.id;
    const listAs = async () => ((await (await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + tok.access_token }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) })).json()).result?.tools ?? []).map((t) => t.name);
    let p = await api('PATCH', '/oauth/grants/' + gid, { access: { backends: { defectdojo: 'read' } } });
    const after = await listAs();
    check('oauth: changing a connected app\'s scope applies at once without reconnecting', p.status === 200 && p.data.access.backends.defectdojo === 'read' && after.includes('defectdojo_list_findings') && !after.some((n) => n.startsWith('wazuh_')), after.length + ' tools');
    p = await api('PATCH', '/oauth/grants/' + gid, { access: { backends: { defectdojo: 'write' } } });
    check('oauth: scope change to write without a grant refused', p.status === 403 && /write grant/.test(p.data.error), p.data.error);
    p = await api('PATCH', '/oauth/grants/no-such-grant', { access: { backends: { wazuh: 'read' } } });
    check('oauth: scope change on an unknown connection is 404', p.status === 404, String(p.status));
  }
  r = await api('GET', '/oauth/grants');
  check('oauth: connection shows under connected apps', r.status === 200 && r.data.length === 1 && r.data[0].clientName === 'Claude', JSON.stringify(r.data));
  r = await api('DELETE', '/oauth/grants/' + r.data[0].id);
  const after = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + tok.access_token }, body: '{}' });
  check('oauth: disconnecting revokes the token at once', r.status === 200 && after.status === 401, String(after.status));
}

// --- Token scopes, write tools and the audit log ------------------------------
{
  async function mcp(token, method, params = {}) {
    const res = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: 'Bearer ' + token }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    return { status: res.status, data: await res.json() };
  }
  const WRITE_TOOLS = ['defectdojo_close_finding', 'defectdojo_risk_accept_finding', 'defectdojo_mark_false_positive', 'wazuh_add_agent_group', 'wazuh_remove_agent_group', 'wazuh_run_active_response'];
  const me = (await api('GET', '/me')).data.user;

  // A token created without a scope reads every backend, like tokens from before scopes existed.
  r = await api('POST', '/tokens', { label: 'read-only' });
  check('scopes: token without scope gets read on every backend', r.status === 201 && ['wazuh', 'trivy', 'defectdojo', 'graylog'].every((id) => r.data.scope.backends[id] === 'read'), JSON.stringify(r.data.scope));
  const readTok = r.data.token;
  r = await api('POST', '/tokens', { label: 'too much', scope: { backends: { defectdojo: 'write' } } });
  check('scopes: write scope refused without an admin grant', r.status === 403 && /write grant/.test(r.data.error), r.data.error);

  // Grant write, switch on DefectDojo write tools and allowlist them; Wazuh stays read-only at installation level.
  r = await api('PATCH', '/users/' + me.id, { writeBackends: ['defectdojo', 'wazuh'] });
  check('scopes: admin grants write per backend', r.status === 200, JSON.stringify(r.data));
  r = await api('GET', '/backends');
  const ddCat = r.data.find((b) => b.id === 'defectdojo');
  check('backends page lists tools with access; write tools off by default', ddCat.allowWrite === false && ddCat.allowlist === null && ddCat.tools.some((t) => t.name === 'defectdojo_close_finding' && t.access === 'write' && t.default === false), JSON.stringify(ddCat.tools.map((t) => [t.name, t.access, t.default])));
  r = await api('PUT', '/backends/defectdojo', { enabled: true, values: { url: 'http://127.0.0.1:19210', tlsVerify: true }, allowWrite: true, allowlist: ['defectdojo_*'] });
  check('backends: allow write and allowlist saved', r.status === 200 && r.data.configured === true, JSON.stringify(r.data));
  r = await api('PUT', '/backends/defectdojo', { enabled: true, values: { url: 'http://127.0.0.1:19210', tlsVerify: true }, allowlist: ['wazuh_list_agents'] });
  check('backends: allowlist entries must belong to the backend', r.status === 400, r.data.error);

  r = await api('POST', '/tokens', { label: 'dd-writer', scope: { backends: { defectdojo: 'write', wazuh: 'read' } } });
  check('scopes: write-scoped token created after the grant', r.status === 201 && r.data.scope.backends.defectdojo === 'write' && !r.data.scope.backends.trivy, JSON.stringify(r.data.scope));
  const writeTok = r.data.token;
  const writeTokId = r.data.id;

  // Read-only token: no write tools listed, and calling one is refused and audited.
  let l = await mcp(readTok, 'tools/list');
  let names = (l.data.result?.tools ?? []).map((t) => t.name);
  check('read-only token: no write tools in tools/list', l.status === 200 && names.includes('defectdojo_get_finding') && !names.some((n) => WRITE_TOOLS.includes(n)) && l.data.result.tools.every((t) => t.annotations?.readOnlyHint === true), names.filter((n) => WRITE_TOOLS.includes(n)).join(','));
  let callR = await mcp(readTok, 'tools/call', { name: 'defectdojo_close_finding', arguments: { finding_id: 12, note: 'should never happen' } });
  const refused = callR.data.error || callR.data.result?.isError === true;
  check('read-only token: calling a write tool is refused', refused, JSON.stringify(callR.data).slice(0, 160));
  r = await api('GET', '/findings/defectdojo');
  check('read-only token: the finding was not changed', r.data.findings.some((f) => f.id === 12), JSON.stringify(r.data.findings?.map((f) => f.id)));

  // Write token: DefectDojo write tools listed as writes, Wazuh write tools not (read scope, and off at installation level).
  l = await mcp(writeTok, 'tools/list');
  const tools = l.data.result?.tools ?? [];
  names = tools.map((t) => t.name);
  const close = tools.find((t) => t.name === 'defectdojo_close_finding');
  check('write token: DefectDojo write tools listed and marked', !!close && close.annotations.readOnlyHint === false && /^\[WRITE — changes DefectDojo\]/.test(close.description) && names.includes('defectdojo_mark_false_positive'), JSON.stringify(close?.annotations));
  check('write token: no Wazuh write tools (read scope, off at installation level)', !names.some((n) => n.startsWith('wazuh_') && WRITE_TOOLS.includes(n)) && names.includes('wazuh_list_agents') && !names.some((n) => n.startsWith('trivy_')), names.filter((n) => n.startsWith('wazuh_')).length + ' wazuh tools');
  callR = await mcp(writeTok, 'tools/call', { name: 'defectdojo_close_finding', arguments: { finding_id: 12, note: 'Fixed by upgrading openssh-server to 9.8p1' } });
  const closed = JSON.parse(callR.data.result?.content?.[0]?.text ?? '{}');
  check('write token: close a finding by ID', callR.data.result?.isError !== true && closed.changed === true && closed.after.is_mitigated === true && closed.after.active === false, JSON.stringify(callR.data).slice(0, 200));
  const notes = await (await fetch('http://127.0.0.1:19210/api/v2/notes/', { headers: { authorization: 'Token dd-test-key' } })).json();
  check('write token: the reason was written to DefectDojo as a note', notes.results.some((n) => n.entry.includes('Fixed by upgrading openssh-server') && n.entry.includes('alice')), JSON.stringify(notes.results));

  // Changing a token's scope in place: same token, new tools from the next call.
  r = await api('PATCH', '/tokens/' + writeTokId, { scope: { backends: { wazuh: 'read' } } });
  l = await mcp(writeTok, 'tools/list');
  names = (l.data.result?.tools ?? []).map((t) => t.name);
  check('scope change: narrowing drops the tools at once, the token keeps working', r.status === 200 && r.data.scope.backends.wazuh === 'read' && !r.data.scope.backends.defectdojo && l.status === 200 && names.includes('wazuh_list_agents') && !names.some((n) => n.startsWith('defectdojo_')), names.length + ' tools');
  r = await api('PATCH', '/tokens/' + writeTokId, { scope: { backends: { trivy: 'write' } } });
  check('scope change: write without a grant refused', r.status === 403 && /write grant for trivy/.test(r.data.error), r.data.error);
  r = await api('PATCH', '/tokens/no-such-token', { scope: { backends: { wazuh: 'read' } } });
  check('scope change: unknown token is 404', r.status === 404, String(r.status));
  r = await api('PATCH', '/tokens/' + writeTokId, { scope: { backends: { defectdojo: 'write', wazuh: 'read' } } });
  l = await mcp(writeTok, 'tools/list');
  check('scope change: widening back to write brings the write tools back', r.status === 200 && (l.data.result?.tools ?? []).some((t) => t.name === 'defectdojo_close_finding'), JSON.stringify(r.data.scope));

  // Revoking the grant takes effect on the next call, even for an already-issued write token.
  r = await api('PATCH', '/users/' + me.id, { writeBackends: [] });
  l = await mcp(writeTok, 'tools/list');
  check('grant removed: write token no longer sees write tools', !(l.data.result?.tools ?? []).some((t) => WRITE_TOOLS.includes(t.name)), String(l.data.result?.tools?.length));

  // Audit log: the denied attempt, the write and the chat's calls; admins only.
  r = await api('GET', '/audit?tool=defectdojo_close_finding');
  const recs = r.data.records ?? [];
  const okRec = recs.find((x) => x.outcome === 'ok');
  const deniedRec = recs.find((x) => x.outcome === 'denied');
  check('audit: write call recorded with user, token, arguments and outcome', !!okRec && okRec.user === 'alice' && okRec.access === 'write' && okRec.credentialLabel === 'dd-writer' && okRec.args.finding_id === 12 && typeof okRec.durationMs === 'number' && /^[0-9a-f]{64}$/.test(okRec.resultSha256), JSON.stringify(okRec));
  check('audit: refused write attempt by the read-only token recorded as denied', !!deniedRec && deniedRec.credentialLabel === 'read-only', JSON.stringify(deniedRec));
  r = await api('GET', '/audit?outcome=ok&limit=500');
  check('audit: assistant tool calls recorded too', r.data.records.some((x) => x.source === 'chat' && x.tool === 'socbridge_backends' && x.credential.startsWith('chat:')), String(r.data.records.length));
  r = await api('GET', '/audit/verify');
  check('audit: log decrypts and the hash chain is intact', r.status === 200 && r.data.ok === true && r.data.records > 3, JSON.stringify(r.data));

  // The assistant stays read-only whatever the user's grants.
  await api('PATCH', '/users/' + me.id, { writeBackends: ['defectdojo'] });
  await api('PUT', '/ai/settings', { enabled: true, provider: 'local', model: 'mock-model', baseUrl: LLM + '/v1' });
  c = await chat([{ role: 'user', text: 'Close finding 11' }]);
  const seenW = await (await fetch(LLM + '/last')).json();
  check('assistant: no write tools offered even with a write grant', c.status === 200 && seenW.toolNames.includes('defectdojo_get_finding') && !seenW.toolNames.some((n) => WRITE_TOOLS.includes(n)), JSON.stringify(seenW.toolNames.filter((n) => n.startsWith('defectdojo_'))));
}

if (process.argv.includes('--print-session')) console.log('SID=' + cookie.split('=')[1]);
if (failures) process.exit(1);
