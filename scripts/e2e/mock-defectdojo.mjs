// Mock of the DefectDojo REST API v2 with synthetic data. Used by the end-to-end test.
import http from 'node:http';
const products = [{ id: 1, name: 'web-shop', findings_count: 2 }, { id: 2, name: 'billing-api', findings_count: 1 }];
const findings = [
  // is_mitigated / false_p / risk_accepted change through the write endpoints below.
  { id: 11, title: 'xz-utils backdoor', severity: 'Critical', active: true, verified: true, date: '2026-11-02', endpoints: [8], vulnerability_ids: [{ vulnerability_id: 'CVE-2024-3094' }], related_fields: { test: { id: 5, engagement: { id: 3, name: 'CI', product: products[0] } } } },
  { id: 12, title: 'regreSSHion', severity: 'High', active: true, verified: false, date: '2026-11-05', vulnerability_ids: [{ vulnerability_id: 'CVE-2024-6387' }], related_fields: { test: { id: 5, engagement: { id: 3, name: 'CI', product: products[0] } } } },
];
const page = (r) => ({ count: r.length, next: null, previous: null, results: r });
// Write endpoints used by the write tools; they change the in-memory findings.
const notes = [];
http.createServer((req, res) => { let raw = ''; req.on('data', (c) => (raw += c)); req.on('end', () => {
  const body = raw ? JSON.parse(raw) : undefined;
  const u = new URL(req.url, 'http://x');
  const send = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.headers.authorization !== 'Token dd-test-key') return send(401, { detail: 'Invalid token.' });
  if (u.pathname === '/api/v2/test_types/') return send(200, page([{ id: 9, name: 'Trivy Scan' }]));
  if (u.pathname === '/api/v2/products/') return send(200, page(products));
  if (u.pathname === '/api/v2/findings/') return send(200, page(findings.filter((f) => !u.searchParams.get('severity') || f.severity === u.searchParams.get('severity'))));
  const w = u.pathname.match(/^\/api\/v2\/findings\/(\d+)\/(notes|close)\/$/);
  if (w && req.method === 'POST') {
    const f = findings.find((x) => x.id === Number(w[1]));
    if (!f) return send(404, { detail: 'Not found.' });
    if (w[2] === 'notes') { notes.push({ finding: f.id, entry: body.entry }); return send(201, { id: notes.length, entry: body.entry }); }
    Object.assign(f, { active: false, is_mitigated: true, mitigated: body.mitigated }); return send(200, {});
  }
  if (u.pathname === '/api/v2/notes/') return send(200, page(notes));
  const m = u.pathname.match(/^\/api\/v2\/findings\/(\d+)\/$/);
  if (m) {
    const f = findings.find((x) => x.id === Number(m[1]));
    if (!f) return send(404, { detail: 'Not found.' });
    if (req.method === 'PATCH') Object.assign(f, body);
    return send(200, f);
  }
  if (u.pathname === '/api/v2/tests/') return send(200, page([{ id: 5, title: 'Trivy scan', engagement: 3, test_type: 9, test_type_name: 'Trivy Scan', scan_type: 'Trivy Scan', created: '2026-11-02T10:00:00Z' }]));
  if (u.pathname === '/api/v2/endpoints/') return send(200, page([{ id: 7, protocol: 'https', host: 'shop.example', port: 443, path: '/', product: 1, active_finding_count: 2 }, { id: 8, host: '203.0.113.10', port: 443, product: 1, active_finding_count: 1 }]));
  if (u.pathname === '/api/v2/test_imports/') return send(200, { ...page([{ id: 20, test: 5, type: 'reimport', created: '2026-11-20T08:00:00Z', import_settings: { active: true }, test_import_finding_action_set: [{ action: 'N' }, { action: 'U' }] }]), prefetch: { test: { 5: { id: 5, title: 'Trivy scan', engagement: 3, scan_type: 'Trivy Scan' } } } });
  if (u.pathname === '/api/v2/engagements/') return send(200, page([{ id: 3, name: 'CI', product: 1, status: 'In Progress' }]));
  send(404, { detail: 'Not found.' });
}); }).listen(Number(process.env.MOCK_DEFECTDOJO_PORT ?? 19210), '127.0.0.1');
