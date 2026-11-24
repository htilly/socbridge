// Mock of the Graylog 7 REST API with synthetic data. Used by the end-to-end test.
import http from 'node:http';
const AUTH = 'Basic ' + Buffer.from('gl-test-token:token').toString('base64');
const def = { id: '65b000000000000000000001', title: 'SSH brute force', priority: 3, alert: true, state: 'ENABLED', config: { type: 'aggregation-v1', query: 'action:ssh_failed', series: [{ id: 's1', type: 'count' }], conditions: { expression: { expr: '>', left: { expr: 'number-ref', ref: 's1' }, right: { expr: 'number', value: 10 } } } }, notifications: [] };
const dash = { id: '65c000000000000000000001', type: 'DASHBOARD', title: 'Firewall overview', owner: 'admin', state: { q1: { titles: { tab: { title: 'Main' } }, widgets: [{ id: 'w1', type: 'aggregation', config: { visualization: 'table', row_pivots: [{ fields: ['source_ip'] }], series: [{ function: 'count()' }] } }] } } };
// Messages for the Findings page (level error or worse); columns as in MESSAGE_FIELDS.
const MESSAGE_FIELDS = ['timestamp', 'source', 'level', 'message'];
const now = Date.now();
const rows = [
  [new Date(now - 60_000).toISOString(), 'fw1', 3, 'kernel: nf_conntrack: table full, dropping packet'],
  [new Date(now - 300_000).toISOString(), 'web01', 2, 'nginx: worker process exited on signal 11'],
  [new Date(now - 900_000).toISOString(), 'db01', 3, 'postgres: FATAL: password authentication failed for user "app"'],
];
// Firewall logs for the attack trend page (documentation address ranges).
function aggregate(b) {
  const [g] = b.group_by;
  if (g.field === 'src_ip' && b.group_by[1]) {
    // Per source and slot, for the map.
    const unit = b.group_by[1].timeunit;
    const step = unit === '1m' ? 60000 : parseInt(unit) * 3600000;
    const out = [];
    for (const ip of ['203.0.113.9', '203.0.113.77', '198.51.100.1'].filter((x) => b.query.includes(`"${x}"`) && !(b.query.includes('NOT src_ip') && x.startsWith('203.')))) {
      for (let t = Math.floor(Date.parse(b.timerange.from) / step) * step; t < Date.parse(b.timerange.to); t += step) out.push([ip, new Date(t).toISOString(), 12]);
    }
    return out;
  }
  if (g.timeunit) {
    const step = parseInt(g.timeunit) * (g.timeunit.endsWith('d') ? 86400000 : 3600000);
    const out = [];
    for (let t = Math.floor(Date.parse(b.timerange.from) / step) * step, i = 0; t < Date.parse(b.timerange.to); t += step, i++) {
      if (t < now - 45 * 86400000) continue;
      const k = new Date(t).toISOString();
      if (b.query.includes('src_ip:')) out.push([k, 20 + (i * 13) % 50, 1 + i % 3]);
      else out.push([k, b.query.includes('Threat') ? i % 4 : 300 + (i * 37) % 200, 20 + i % 9]);
    }
    return out;
  }
  if (g.field === 'dst_ip' && b.group_by[1]) return b.query.includes('Threat') ? [] : [['203.0.113.10', 443, 320, 41]];
  if (g.field === 'UNIFIipsSignature') return [['ET CINS poor reputation', 12]];
  if (g.field === 'source') return [['fw1', b.query.includes('Threat') ? 80 : 18000, 640]];
  if (g.field === 'src_ip') return [['203.0.113.9', 1240, 44], ['203.0.113.77', 640, 19], ['198.51.100.1', 9000, 1]];
  if (g.field === 'dst_port') return [['23', 80], ['-', 5]];
  return [['192.0.2.1', 100]];
}
http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const send = (s, o) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  let raw = '';
  for await (const c of req) raw += c;
  if (req.headers.authorization !== AUTH) return send(401, { message: 'Unauthorized' });
  if (!req.headers['x-requested-by']) return send(400, { message: 'X-Requested-By missing' });
  if (u.pathname === '/api/system') return send(200, { version: '7.1.9', lifecycle: 'running', hostname: 'gl-mock', is_processing: true });
  if (u.pathname === '/api/system/indexer/cluster/health') return send(200, { status: 'green', shards: { active: 10 } });
  if (u.pathname === '/api/system/journal') return send(200, { enabled: true, uncommitted_journal_entries: 0 });
  if (u.pathname === '/api/system/notifications') return send(200, { total: 0, notifications: [] });
  if (u.pathname === '/api/streams') return send(200, { total: 1, streams: [{ id: '000000000000000000000001', title: 'All messages', is_default: true }] });
  if (u.pathname === '/api/search/aggregate' && req.method === 'POST') return send(200, { schema: [], datarows: aggregate(JSON.parse(raw)), metadata: {} });
  if (u.pathname === '/api/search/messages' && req.method === 'POST') {
    const body = JSON.parse(raw || '{}');
    const fields = body.fields ?? ['timestamp', 'source', 'message'];
    if (fields.includes('src_ip') || fields.length === 1) {
      const fw = { timestamp: new Date(Math.max(Date.parse(body.timerange.from), now - 45 * 86400000)).toISOString(), src_ip: '203.0.113.9', dst_ip: '192.0.2.1', dst_port: 23 };
      return send(200, { schema: fields.map((f) => ({ field: f })), datarows: [fields.map((f) => fw[f] ?? '-')], metadata: {} });
    }
    return send(200, {
      schema: fields.map((f) => ({ column_type: 'field', field: f, name: `field: ${f}` })),
      datarows: rows.slice(body.from ?? 0, (body.from ?? 0) + (body.size ?? 150)).map((r) => fields.map((f) => r[MESSAGE_FIELDS.indexOf(f)] ?? null)),
      metadata: { effective_timerange: body.timerange },
    });
  }
  if (u.pathname === '/api/events/definitions') return send(200, { total: 1, event_definitions: [def] });
  if (u.pathname === '/api/events/notifications') return send(200, { notifications: [] });
  if (u.pathname === '/api/events/search') return send(200, { total_events: 1, events: [{ event: { id: 'e1', event_definition_id: def.id, timestamp: '2026-11-21T08:00:00.000Z', priority: 3, alert: true, message: 'SSH brute force: 42 failures' } }], context: { event_definitions: { [def.id]: def } } });
  if (u.pathname === '/api/dashboards') return send(200, { total: 1, elements: [{ ...dash, state: undefined }] });
  if (u.pathname === '/api/search/saved') return send(200, { total: 0, elements: [] });
  if (u.pathname === `/api/views/${dash.id}`) return send(200, dash);
  send(404, { message: 'Not found' });
}).listen(Number(process.env.MOCK_GRAYLOG_PORT ?? 19220), '127.0.0.1');
