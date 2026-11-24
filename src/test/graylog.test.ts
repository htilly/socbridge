import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import { registerAllTools } from '../mcp/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { graylog } from '../backends/graylog/index.js';
import { parseAllowlist, proxyName } from '../backends/graylog/mcp-proxy.js';
import {
  getView,
  listEventDefinitions,
  listStreams,
  listViews,
  renderExpr,
  searchEvents,
  searchMessages,
  systemHealth,
  timerange,
} from '../backends/graylog/queries.js';

const TOKEN = 'gl-token';
const seen: { method: string; path: string; query: URLSearchParams; body?: Record<string, unknown>; auth?: string; xrb?: string }[] = [];
let server: http.Server;
let url: string;
let mcpCalls: { name: string; args: unknown }[] = [];

const streams = [
  { id: '000000000000000000000001', title: 'All messages', is_default: true, disabled: false, rules: ['x'] },
  { id: '65a1b2c3d4e5f60718293a4b', title: 'Firewall', disabled: false },
  { id: '65a1b2c3d4e5f60718293a4c', title: 'Old', disabled: true },
];

const definitions = [
  {
    id: '65b000000000000000000001',
    title: 'SSH brute force',
    description: 'Many failed logins',
    priority: 3,
    alert: true,
    state: 'ENABLED',
    config: {
      type: 'aggregation-v1',
      query: 'action:ssh_failed',
      streams: ['65a1b2c3d4e5f60718293a4b'],
      search_within_ms: 300_000,
      execute_every_ms: 60_000,
      group_by: ['source_ip'],
      series: [{ id: 's1', type: 'count' }],
      conditions: { expression: { expr: '>', left: { expr: 'number-ref', ref: 's1' }, right: { expr: 'number', value: 10 } } },
    },
    notifications: [{ notification_id: 'n1' }, { notification_id: 'n-gone' }],
    field_spec: { big: 'drop' },
  },
  { id: '65b000000000000000000002', title: 'Every error', priority: 1, alert: false, config: { type: 'aggregation-v1', query: 'level:3', series: [] } },
];

const dashboard = {
  id: '65c000000000000000000001',
  type: 'DASHBOARD',
  title: 'Firewall overview',
  summary: 'Denies by source',
  owner: 'admin',
  search_id: '65c0000000000000000000ff',
  last_updated_at: '2026-11-01T00:00:00Z',
  state: {
    q1: {
      titles: { tab: { title: 'Main' }, widget: { w1: 'Top sources' } },
      widgets: [
        {
          id: 'w1',
          type: 'aggregation',
          query: { type: 'elasticsearch', query_string: 'action:deny' },
          timerange: { type: 'relative', range: 3600 },
          streams: [],
          config: { visualization: 'table', row_pivots: [{ fields: ['source_ip'], type: 'values' }], column_pivots: [], series: [{ function: 'count()' }] },
        },
        { id: 'w2', type: 'messages', config: { fields: ['timestamp', 'message'] } },
      ],
      positions: { w1: {} },
    },
  },
};

/** A stand-in for Graylog's MCP server: one read-only tool, one unannotated. */
function graylogMcp(): McpServer {
  const s = new McpServer({ name: 'graylog', version: '7.0.0' });
  s.registerTool(
    'search_messages',
    { description: 'Search messages', inputSchema: { query: z.string(), limit: z.number().int().optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      mcpCalls.push({ name: 'search_messages', args: a });
      return { content: [{ type: 'text', text: 'x'.repeat(70_000) }] };
    },
  );
  s.registerTool('create_dashboard', { description: 'Creates a dashboard', inputSchema: { title: z.string() } }, async (a) => {
    mcpCalls.push({ name: 'create_dashboard', args: a });
    return { content: [{ type: 'text', text: 'created' }] };
  });
  return s;
}

before(async () => {
  server = http.createServer(async (req, res) => {
    const u = new URL(req.url!, 'http://x');
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString();
    const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : undefined;
    seen.push({ method: req.method!, path: u.pathname, query: u.searchParams, body, auth: req.headers.authorization, xrb: req.headers['x-requested-by'] as string });
    const send = (s: number, o: unknown) => {
      res.writeHead(s, { 'content-type': 'application/json' });
      res.end(JSON.stringify(o));
    };
    if (req.headers.authorization !== 'Basic ' + Buffer.from(`${TOKEN}:token`).toString('base64')) return send(401, { message: 'no' });
    if (u.pathname === '/api/mcp') {
      const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      const s = graylogMcp();
      res.on('close', () => void s.close());
      await s.connect(t);
      return t.handleRequest(req, res, body);
    }
    if (u.pathname === '/api/system') return send(200, { version: '7.0.1', lifecycle: 'running', hostname: 'gl1', is_processing: true, secret: 'drop' });
    if (u.pathname === '/api/streams') return send(200, { total: streams.length, streams });
    if (u.pathname === '/api/search/messages' && req.method === 'POST') {
      return send(200, {
        schema: [
          { column_type: 'field', type: 'date', field: 'timestamp', name: 'field: timestamp' },
          { column_type: 'field', type: 'string', field: 'source', name: 'field: source' },
          { column_type: 'field', type: 'string', field: 'message', name: 'field: message' },
        ],
        datarows: [
          ['2026-11-21T08:00:00.000Z', 'fw1', 'm'.repeat(3000)],
          ['2026-11-21T07:59:00.000Z', 'fw2', null],
        ],
        metadata: { effective_timerange: { type: 'absolute', from: 'a', to: 'b' } },
      });
    }
    if (u.pathname === '/api/events/definitions') {
      return send(200, { total: 7, event_definitions: definitions, context: { scheduler: { '65b000000000000000000002': { status: 'DISABLED' } } } });
    }
    if (u.pathname === '/api/events/notifications') return send(200, { notifications: [{ id: 'n1', title: 'Mail SOC' }] });
    if (u.pathname === '/api/events/search' && req.method === 'POST') {
      return send(200, {
        total_events: 3,
        events: [
          {
            event: {
              id: 'e1',
              event_definition_id: '65b000000000000000000001',
              timestamp: '2026-11-21T08:00:00.000Z',
              priority: 3,
              alert: true,
              message: 'SSH brute force: 42 failures',
              source: 'gl1',
              key: '10.0.0.5',
              fields: {},
              group_by_fields: { source_ip: '10.0.0.5' },
              origin_context: 'urn:x',
              replay_info: { query: 'drop' },
            },
            index_name: 'gl-events_0',
          },
        ],
        context: { event_definitions: { '65b000000000000000000001': { id: '65b000000000000000000001', title: 'SSH brute force' } } },
      });
    }
    if (u.pathname === '/api/dashboards') return send(200, { total: 1, elements: [{ ...dashboard, state: undefined }, { id: 'x', type: 'SEARCH', title: 'wrong type' }] });
    if (u.pathname === '/api/search/saved') return send(200, { total: 30, views: [{ id: '65c000000000000000000002', type: 'SEARCH', title: 'Failed logins', owner: 'bob' }] });
    if (u.pathname === `/api/views/${dashboard.id}`) return send(200, dashboard);
    if (u.pathname === `/api/views/search/${dashboard.search_id}`) {
      return send(200, { id: dashboard.search_id, queries: [{ id: 'q1', query: { type: 'elasticsearch', query_string: 'source:fw*' }, timerange: { type: 'relative', range: 300 } }] });
    }
    if (u.pathname === '/api/system/indexer/cluster/health') return send(200, { status: 'green', shards: { active: 10, unassigned: 0 } });
    if (u.pathname === '/api/system/journal') return send(403, { message: 'Not authorized' });
    if (u.pathname === '/api/system/notifications') return send(200, { total: 1, notifications: [{ type: 'no_master', severity: 'urgent', timestamp: 't', details: {} }] });
    send(404, { message: 'Not found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
});

after(() => new Promise<void>((r) => server.close(() => r())));

const rt = (extra: Record<string, unknown> = {}) =>
  graylog.createRuntime({ url, apiToken: TOKEN, tlsVerify: true, mcpPassthrough: false, ...extra } as never);

test('graylog: search posts query, timerange, resolved streams; flattens rows', async () => {
  const r = await searchMessages(rt(), { query: 'action:deny', streams: ['firewall'], limit: 2, offset: 0, sort_order: 'desc' });
  const call = seen.at(-1)!;
  assert.equal(call.method, 'POST');
  assert.equal(call.path, '/api/search/messages');
  assert.equal(call.xrb, 'socbridge');
  assert.deepEqual(call.body!.streams, ['65a1b2c3d4e5f60718293a4b']);
  assert.deepEqual(call.body!.timerange, { type: 'relative', range: 900 });
  assert.deepEqual(call.body!.fields, ['timestamp', 'source', 'message']);
  assert.equal(call.body!.size, 2);
  assert.equal(r.returned, 2);
  assert.equal(r.messages[0]!.source, 'fw1');
  assert.match(String(r.messages[0]!.message), /truncated 1000 characters/);
  assert.equal('message' in r.messages[1]!, false, 'null cells are dropped');
  assert.ok(r.more, 'a full page hints at more results');
});

test('graylog: unknown stream title is an error, absolute range is ISO', async () => {
  await assert.rejects(searchMessages(rt(), { query: '*', streams: ['nope'], limit: 5, offset: 0, sort_order: 'desc' }), /Unknown stream "nope"/);
  assert.deepEqual(timerange({ from: '2026-11-20T00:00:00Z', to: '2026-11-21T00:00:00Z' }), {
    type: 'absolute',
    from: '2026-11-20T00:00:00.000Z',
    to: '2026-11-21T00:00:00.000Z',
  });
});

test('graylog: streams hide disabled by default and filter by title', async () => {
  const all = await listStreams(rt(), { include_disabled: false });
  assert.equal(all.total, 2);
  assert.equal(all.streams[0]!.rules, undefined);
  const fw = await listStreams(rt(), { title: 'fire', include_disabled: true });
  assert.deepEqual(fw.streams.map((s) => s.title), ['Firewall']);
});

test('graylog: health keeps going when one part is forbidden', async () => {
  const h = await systemHealth(rt());
  assert.equal((h.node as Record<string, unknown>).version, '7.0.1');
  assert.equal((h.node as Record<string, unknown>).secret, undefined);
  assert.equal((h.indexer_cluster as Record<string, unknown>).status, 'green');
  assert.match(String((h.journal as { unavailable: string }).unavailable), /403/);
  assert.equal((h.notifications as { total: number }).total, 1);
});

test('graylog: connection test without and with MCP passthrough', async () => {
  assert.deepEqual(await graylog.testConnection(rt()), { ok: true, message: 'Connected to Graylog 7.0.1 (running).' });
  const r = await graylog.testConnection(rt({ mcpPassthrough: true }));
  assert.equal(r.ok, true);
  assert.match(r.message, /offers 2 tools; exposed: search_messages\. Not exposed: create_dashboard/);
});

async function toolsOf(extra: Record<string, unknown>) {
  const s = new McpServer({ name: 't', version: '0' });
  await registerAllTools(s, graylog, rt(extra));
  const [a, b] = InMemoryTransport.createLinkedPair();
  const c = new Client({ name: 'c', version: '0' });
  await s.connect(b);
  await c.connect(a);
  return { c, close: () => c.close() };
}

test('graylog: passthrough exposes only read-only remote tools by default, capped', async () => {
  mcpCalls = [];
  const { c, close } = await toolsOf({ mcpPassthrough: true });
  try {
    const names = (await c.listTools()).tools.map((t) => t.name).sort();
    assert.deepEqual(names, [
      'graylog_firewall_details', 'graylog_firewall_trend', 'graylog_get_dashboard',
      'graylog_list_dashboards',
      'graylog_list_event_definitions',
      'graylog_list_saved_searches',
      'graylog_list_streams',
      'graylog_mcp_search_messages',
      'graylog_search',
      'graylog_search_events',
      'graylog_system_health',
    ]);
    const proxied = (await c.listTools()).tools.find((t) => t.name === 'graylog_mcp_search_messages')!;
    assert.deepEqual(Object.keys((proxied.inputSchema as { properties: object }).properties).sort(), ['limit', 'query']);
    const r = await c.callTool({ name: 'graylog_mcp_search_messages', arguments: { query: 'a', limit: 3 } });
    assert.deepEqual(mcpCalls, [{ name: 'search_messages', args: { query: 'a', limit: 3 } }]);
    const text = (r.content as { text: string }[])[0]!.text;
    assert.ok(text.length < 61_000);
    assert.match(text, /truncated/);
  } finally {
    await close();
  }
});

test('graylog: allowlist replaces the read-only default; passthrough off adds nothing', async () => {
  const a = await toolsOf({ mcpPassthrough: true, mcpTools: 'create_dashboard' });
  try {
    const names = (await a.c.listTools()).tools.map((t) => t.name);
    assert.ok(names.includes('graylog_mcp_create_dashboard'));
    assert.ok(!names.includes('graylog_mcp_search_messages'));
  } finally {
    await a.close();
  }
  const b = await toolsOf({ mcpTools: 'create_dashboard' });
  try {
    assert.equal((await b.c.listTools()).tools.filter((t) => t.name.startsWith('graylog_mcp_')).length, 0);
  } finally {
    await b.close();
  }
});

test('graylog: passthrough failure keeps REST tools', async () => {
  const s = new McpServer({ name: 't', version: '0' });
  const broken = graylog.createRuntime({ url, apiToken: 'wrong', tlsVerify: true, mcpPassthrough: true } as never);
  await registerAllTools(s, graylog, broken);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const c = new Client({ name: 'c', version: '0' });
  await s.connect(b);
  await c.connect(a);
  assert.equal((await c.listTools()).tools.length, 10);
  await c.close();
});

test('graylog: allowlist parsing and proxied names', () => {
  assert.deepEqual([...parseAllowlist(' a, b\nc  ,,')], ['a', 'b', 'c']);
  assert.equal(proxyName('get.stream info'), 'graylog_mcp_get_stream_info');
  assert.equal(proxyName('x'.repeat(100)).length, 64);
});

test('graylog: event definitions summarise condition, state and notifications', async () => {
  const r = await listEventDefinitions(rt(), { query: 'ssh', page: 1, per_page: 2 });
  const call = seen.find((c) => c.path === '/api/events/definitions')!;
  assert.equal(call.query.get('query'), 'ssh');
  assert.equal(call.query.get('per_page'), '2');
  assert.equal(r.total, 7);
  assert.ok(r.more);
  const [ssh, err] = r.event_definitions as Record<string, unknown>[];
  assert.equal(ssh!.priority, 'high');
  assert.equal(ssh!.enabled, true);
  assert.deepEqual(ssh!.notifications, ['Mail SOC', 'n-gone']);
  assert.deepEqual(ssh!.condition, {
    type: 'aggregation-v1',
    query: 'action:ssh_failed',
    streams: ['65a1b2c3d4e5f60718293a4b'],
    search_within: '5m',
    execute_every: '1m',
    group_by: ['source_ip'],
    condition: 'count() > 10',
  });
  assert.equal(ssh!.field_spec, undefined);
  assert.equal(err!.enabled, false, 'falls back to the scheduler status');
  assert.equal((err!.condition as Record<string, unknown>).condition, 'every matching message');
});

test('graylog: condition expressions render nested logic', () => {
  const series = new Map([
    ['a', 'count()'],
    ['b', 'avg(took_ms)'],
  ]);
  const e = {
    expr: '&&',
    left: { expr: '>', left: { expr: 'number-ref', ref: 'a' }, right: { expr: 'number', value: 5 } },
    right: { expr: 'group', child: { expr: '>=', left: { expr: 'number-ref', ref: 'b' }, right: { expr: 'number', value: 500 } } },
  };
  assert.equal(renderExpr(e, series), '(count() > 5 AND avg(took_ms) >= 500)');
});

test('graylog: event search builds filter, priority query and resolves definition titles', async () => {
  const r = await searchEvents(rt(), {
    query: 'source:gl1',
    event_definitions: ['ssh brute force'],
    priority: ['high', 'critical'],
    alerts_only: true,
    page: 1,
    per_page: 1,
  });
  const call = seen.at(-1)!;
  assert.equal(call.path, '/api/events/search');
  assert.equal(call.body!.query, '(source:gl1) AND (priority:(3 OR 4))');
  assert.deepEqual(call.body!.filter, { alerts: 'only', event_definitions: ['65b000000000000000000001'] });
  assert.deepEqual(call.body!.timerange, { type: 'relative', range: 86_400 });
  assert.equal(r.total, 3);
  assert.ok(r.more);
  const e = r.events[0] as Record<string, unknown>;
  assert.equal(e.definition, 'SSH brute force');
  assert.equal(e.priority, 'high');
  assert.equal(e.fields, undefined, 'empty fields are dropped');
  assert.deepEqual(e.group_by_fields, { source_ip: '10.0.0.5' });
  assert.equal(e.replay_info, undefined);

  await searchEvents(rt(), { query: '', alerts_only: false, page: 1, per_page: 10, from: '2026-11-20T00:00:00Z', to: '2026-11-21T00:00:00Z' });
  const c2 = seen.at(-1)!;
  assert.equal(c2.body!.query, '');
  assert.deepEqual(c2.body!.filter, { alerts: 'include', event_definitions: [] });
  assert.equal((c2.body!.timerange as Record<string, unknown>).type, 'absolute');
  await assert.rejects(
    searchEvents(rt(), { query: '', event_definitions: ['nope'], alerts_only: false, page: 1, per_page: 10 }),
    /Unknown event definition "nope"/,
  );
});

test('graylog: dashboards and saved searches list by type with paging', async () => {
  const d = (await listViews(rt(), 'DASHBOARD', { page: 1, per_page: 25 })) as Record<string, unknown>;
  assert.equal(seen.at(-1)!.path, '/api/dashboards');
  assert.deepEqual(d.dashboards, [
    { id: dashboard.id, title: 'Firewall overview', owner: 'admin', last_updated_at: '2026-11-01T00:00:00Z', summary: 'Denies by source' },
  ]);
  const s = (await listViews(rt(), 'SEARCH', { query: 'login', page: 1, per_page: 1 })) as Record<string, unknown>;
  assert.equal(seen.at(-1)!.query.get('query'), 'login');
  assert.equal(s.total, 30);
  assert.ok(s.more);
  assert.equal((s.saved_searches as Record<string, unknown>[])[0]!.title, 'Failed logins');
});

test('graylog: one dashboard gives pages and widget setup, not results', async () => {
  const v = (await getView(rt(), dashboard.id)) as Record<string, unknown>;
  assert.equal(v.title, 'Firewall overview');
  assert.equal('state' in v, false);
  const [page] = v.pages as Record<string, unknown>[];
  assert.equal(page!.title, 'Main');
  assert.equal(page!.query, 'source:fw*');
  const [w1, w2] = page!.widgets as Record<string, unknown>[];
  assert.deepEqual(w1, {
    id: 'w1',
    type: 'aggregation',
    title: 'Top sources',
    query: 'action:deny',
    timerange: { type: 'relative', range: 3600 },
    visualization: 'table',
    group_by: ['source_ip'],
    series: ['count()'],
  });
  assert.deepEqual(w2, { id: 'w2', type: 'messages', fields: ['timestamp', 'message'] });
  await assert.rejects(getView(rt(), '../system'), /not a view ID/);
});

test('graylog: event search tool rejects a bad window', async () => {
  const { c, close } = await toolsOf({});
  try {
    const r = await c.callTool({ name: 'graylog_search_events', arguments: { to: '2026-11-21T00:00:00Z' } });
    assert.match((r.content as { text: string }[])[0]!.text, /`to` needs `from`/);
  } finally {
    await close();
  }
});
