import { z } from 'zod';
import { errMessage } from '../../log.js';
import { basicAuth, HttpClient } from '../http.js';
import { jsonResult } from '../result.js';
import { defineBackend, toolsFor } from '../types.js';
import { attackRangeShape } from '../attack-window.js';
import { DEFAULT_FIREWALL_QUERY, DEFAULT_IPS_QUERY, FIREWALL_CATEGORIES, firewallDetails, firewallTrend, SCAN_PORTS, type FirewallRuntime } from './firewall.js';
import { graylogHealth } from './health.js';
import { describeRemote, parseAllowlist, PROXY_PREFIX, proxiedTools, type RemoteMcp } from './mcp-proxy.js';
import {
  DEFAULT_FIELDS,
  getView,
  listEventDefinitions,
  listStreams,
  listViews,
  searchEvents,
  searchMessages,
  systemHealth,
} from './queries.js';

/**
 * Graylog (6/7): read-only log search, streams and system health over the
 * REST API, plus an optional passthrough to Graylog's own MCP server.
 *
 * Authentication uses an access token as basic-auth user with the literal
 * password "token". Graylog requires `X-Requested-By` on API calls.
 */

interface GraylogConfig {
  url: string;
  apiToken: string;
  tlsVerify: boolean;
  caCert?: string;
  mcpPassthrough: boolean;
  mcpTools?: string;
  firewallQuery: string;
  ipsQuery: string;
}

const queryWithDefault = (fallback: string) =>
  z
    .string()
    .max(1000)
    .optional()
    .transform((v) => v?.trim() || fallback);

const schema = z.object({
  url: z.string().url(),
  apiToken: z.string().min(1),
  tlsVerify: z.boolean().default(true),
  caCert: z
    .string()
    .optional()
    .transform((v) => v?.trim() || undefined),
  mcpPassthrough: z.boolean().default(false),
  mcpTools: z
    .string()
    .max(4000)
    .optional()
    .transform((v) => v?.trim() || undefined),
  firewallQuery: queryWithDefault(DEFAULT_FIREWALL_QUERY),
  ipsQuery: queryWithDefault(DEFAULT_IPS_QUERY),
}) as z.ZodType<GraylogConfig>;

interface Runtime extends FirewallRuntime {
  mcp: RemoteMcp | null;
}


/** Thirty days: long enough for an investigation, short enough to keep searches cheap. */
const MAX_RANGE_SECONDS = 30 * 24 * 3600;

const isoTime = z.string().refine((v) => !Number.isNaN(Date.parse(v)), 'Use an ISO 8601 time, e.g. 2026-11-21T08:00:00Z');

/** Checks an absolute from/to window; returns an error message or undefined. */
function windowError(a: { from?: string; to?: string }): string | undefined {
  if (a.to && !a.from) return '`to` needs `from`; use range_seconds for relative searches';
  if (a.from && a.to && Date.parse(a.from) >= Date.parse(a.to)) return '`from` must be before `to`';
  if (a.from && (Date.parse(a.to ?? new Date().toISOString()) - Date.parse(a.from)) / 1000 > MAX_RANGE_SECONDS) {
    return 'Time range is limited to 30 days; narrow from/to';
  }
  return undefined;
}

const paging = {
  page: z.number().int().min(1).max(1000).default(1),
  per_page: z.number().int().min(1).max(100).default(25),
};
const viewList = {
  query: z.string().max(256).optional().describe('Text in the title (Graylog search syntax for views)'),
  ...paging,
};

const t = toolsFor<Runtime>();

const tools = [
  t.read({
    name: 'graylog_search',
    title: 'Search Graylog messages',
    description:
      'Search log messages in Graylog, newest first. Query uses Graylog/Lucene syntax (e.g. `source:web01 AND level:3`, ' +
      '`"connection refused"`, `_exists_:user`). Defaults to the last 15 minutes and fields timestamp, source, message. ' +
      'Give either range_seconds (relative) or from/to (absolute ISO times). Streams may be IDs or titles.',
    inputSchema: {
      query: z.string().max(2000).default('*').describe('Graylog search query; * for everything'),
      range_seconds: z.number().int().min(1).max(MAX_RANGE_SECONDS).optional().describe('Look back this many seconds (default 900)'),
      from: isoTime.optional().describe('Absolute start, ISO 8601; overrides range_seconds'),
      to: isoTime.optional().describe('Absolute end, ISO 8601; default now'),
      streams: z.array(z.string().max(256)).max(20).optional().describe('Stream IDs or titles (see graylog_list_streams)'),
      fields: z
        .array(z.string().max(128))
        .max(30)
        .optional()
        .describe(`Fields to return (default ${DEFAULT_FIELDS.join(', ')})`),
      limit: z.number().int().min(1).max(500).default(50),
      offset: z.number().int().min(0).max(10_000).default(0),
      sort_order: z.enum(['desc', 'asc']).default('desc'),
    },
    run: async (rt, a) => {
      const error = windowError(a);
      if (error) return jsonResult({ error });
      return jsonResult(await searchMessages(rt, a));
    },
  }),

  t.read({
    name: 'graylog_list_streams',
    title: 'List Graylog streams',
    description: 'List the Graylog streams this token may read, with IDs and titles to use in graylog_search.',
    inputSchema: {
      title: z.string().max(256).optional().describe('Text contained in the stream title'),
      include_disabled: z.boolean().default(false),
    },
    run: async (rt, a) => jsonResult(await listStreams(rt, a)),
  }),

  t.read({
    name: 'graylog_system_health',
    title: 'Graylog system health',
    description:
      'Graylog node version and processing state, indexer cluster health (green/yellow/red, shards), journal backlog and system notifications. ' +
      'Parts the token may not read are reported as unavailable.',
    inputSchema: {},
    run: async (rt) => jsonResult(await systemHealth(rt)),
  }),

  t.read({
    name: 'graylog_list_event_definitions',
    title: 'List Graylog event definitions',
    description:
      'Alert/event definitions configured in Graylog: title, priority, whether it raises an alert, enabled state, ' +
      'a summary of the query and condition (e.g. `count() > 10` over 5m, every 1m) and the notifications it sends.',
    inputSchema: {
      query: z.string().max(256).optional().describe('Text in the title'),
      ...paging,
    },
    run: async (rt, a) => jsonResult(await listEventDefinitions(rt, a)),
  }),

  t.read({
    name: 'graylog_firewall_trend',
    title: 'Firewall blocks, port scans and IPS blocks over time',
    description:
      `Blocked traffic from the internet over time, in three categories: port_scan (sources that tried ${SCAN_PORTS} or more ports in the period, among those blocked most; ports that are mostly noise left out), firewall (all dropped traffic) and ips. ` +
      'Attempts and distinct source IPs per step, with the preceding period for comparison (null when the logs do not reach back that far; data_from is the oldest firewall message). ' +
      'Port scans are part of the firewall category, and longer periods find slower scans, so compare scan counts only between periods of equal length. A category that could not be read has error set.',
    inputSchema: attackRangeShape,
    run: async (rt, a) => jsonResult(await firewallTrend(rt, a)),
  }),

  t.read({
    name: 'graylog_firewall_details',
    title: 'Details of one firewall category',
    description: 'Who is behind one category of graylog_firewall_trend in a time range: top source IPs, ports, targets and IPS signatures, and the newest messages.',
    inputSchema: {
      category: z.enum(FIREWALL_CATEGORIES),
      from: isoTime.describe('Start, ISO 8601'),
      to: isoTime.describe('End, ISO 8601'),
      top: z.number().int().min(1).max(50).default(10),
      limit: z.number().int().min(1).max(100).default(20).describe('Number of messages to return'),
    },
    run: async (rt, a) => jsonResult(await firewallDetails(rt, a)),
  }),

  t.read({
    name: 'graylog_search_events',
    title: 'Search Graylog events and alerts',
    description:
      'Events and alerts Graylog triggered, newest first. Defaults to the last 24 hours. Give either range_seconds or from/to ' +
      '(ISO times, up to 30 days). Filter by event definition (IDs or titles, see graylog_list_event_definitions), priority, ' +
      'alerts only, and an optional query over event fields (e.g. `source:fw1`).',
    inputSchema: {
      query: z.string().max(2000).default('').describe('Optional query over events; empty for all'),
      range_seconds: z.number().int().min(1).max(MAX_RANGE_SECONDS).optional().describe('Look back this many seconds (default 86400)'),
      from: isoTime.optional().describe('Absolute start, ISO 8601; overrides range_seconds'),
      to: isoTime.optional().describe('Absolute end, ISO 8601; default now'),
      event_definitions: z.array(z.string().max(256)).max(20).optional().describe('Event definition IDs or titles'),
      priority: z.array(z.enum(['low', 'medium', 'high', 'critical'])).max(4).optional(),
      alerts_only: z.boolean().default(false).describe('Only events that are alerts'),
      ...paging,
    },
    run: async (rt, a) => {
      const error = windowError(a);
      if (error) return jsonResult({ error });
      return jsonResult(await searchEvents(rt, a));
    },
  }),

  t.read({
    name: 'graylog_list_dashboards',
    title: 'List Graylog dashboards',
    description: 'Dashboards the token may read: ID, title, summary, owner and last update. Use graylog_get_dashboard for widgets.',
    inputSchema: viewList,
    run: async (rt, a) => jsonResult(await listViews(rt, 'DASHBOARD', a)),
  }),

  t.read({
    name: 'graylog_list_saved_searches',
    title: 'List Graylog saved searches',
    description: 'Saved searches the token may read: ID, title, summary, owner and last update.',
    inputSchema: viewList,
    run: async (rt, a) => jsonResult(await listViews(rt, 'SEARCH', a)),
  }),

  t.read({
    name: 'graylog_get_dashboard',
    title: 'Get a Graylog dashboard',
    description:
      'One dashboard or saved search by ID: its pages with their queries and time ranges, and each widget\'s type, title, ' +
      'query, visualization, group-by fields and series. Describes the layout only; it does not run the widgets ' +
      '(use graylog_search for data).',
    inputSchema: { id: z.string().max(64).describe('Dashboard or saved search ID') },
    run: async (rt, a) => jsonResult(await getView(rt, a.id)),
  }),

];

export const graylog = defineBackend<GraylogConfig, Runtime>({
  id: 'graylog',
  title: 'Graylog',
  description: 'Centralised log search, events and alerts, dashboards.',
  maturity: 'ready',
  schema,
  health: graylogHealth,
  guide: {
    intro:
      'Searches logs and events, lists streams, alert definitions, dashboards and saved searches, and reports Graylog health over the REST API. Optionally forwards an allowlisted set of Graylog\'s own MCP tools.',
    before: ['SocBridge must reach Graylog\'s web/API port over the network (from inside its container when run with Docker).'],
    items: [
      {
        title: 'Graylog URL',
        fields: ['url'],
        steps: ['The web/API address including the port, e.g. https://graylog.example.com:9000 (the API is under /api).'],
      },
      {
        title: 'Access token (reader user)',
        fields: ['apiToken'],
        steps: [
          'An admin allows tokens once: System → Configurations → Users → allow access token creation.',
          'System → Users and Teams → Create user (e.g. socbridge) with the "Reader" role, and share the streams it may search with it.',
          'Open the user → Edit tokens → name it socbridge → Create token → copy the token (it is shown once).',
        ],
        code: 'curl -u <token>:token -H "X-Requested-By: socbridge" https://graylog.example.com:9000/api/system',
      },
      {
        title: 'Graylog MCP passthrough (optional)',
        fields: ['mcpPassthrough', 'mcpTools'],
        steps: [
          'Turn on System → Configurations → MCP → Remote MCP access in Graylog.',
          'Tick "Forward Graylog MCP tools". The same token is used; the user\'s permissions still limit what the tools can see.',
          'Test connection lists every tool Graylog offers. Put the names of the ones you want, read-only only, in the allowlist (comma or newline separated). Empty = only tools Graylog marks read-only.',
          'Forwarded tools appear as graylog_mcp_<name>.',
        ],
      },
      {
        title: 'Certificates',
        fields: ['caCert', 'tlsVerify'],
        steps: ['Needed only with a private CA: paste the CA certificate (PEM) that signed the Graylog certificate.'],
      },
    ],
    verify: [
      'Tick Enabled, Save, then Test connection: it should report the Graylog version, and with passthrough on, the MCP tools.',
      'EHOSTUNREACH or ETIMEDOUT means SocBridge cannot route to Graylog: check firewalls, VLANs and the Docker network, not the token.',
    ],
    docs: [
      { label: 'Graylog REST API and access tokens', url: 'https://go2docs.graylog.org/current/setting_up_graylog/rest_api.html' },
    ],
  },
  fields: [
    { key: 'url', label: 'Graylog URL', type: 'url', required: true, placeholder: 'https://graylog.example.com:9000' },
    { key: 'apiToken', label: 'Access token', type: 'secret', required: true, help: 'User → Edit tokens. Use a reader-role user.' },
    { key: 'tlsVerify', label: 'Verify TLS certificates', type: 'boolean' },
    { key: 'caCert', label: 'CA certificate (PEM)', type: 'pem' },
    { key: 'mcpPassthrough', label: 'Forward Graylog MCP tools', type: 'boolean', help: 'Needs Remote MCP access on in Graylog.' },
    {
      key: 'mcpTools',
      label: 'Graylog MCP tool allowlist',
      type: 'string',
      placeholder: 'e.g. list_streams, search_messages',
      help: 'Comma-separated Graylog MCP tool names. Empty = only tools Graylog marks read-only.',
    },
    {
      key: 'firewallQuery',
      label: 'Firewall blocks query',
      type: 'string',
      placeholder: DEFAULT_FIREWALL_QUERY,
      help: 'Attack trend: messages that are blocked traffic from the internet. They need the fields src_ip, dst_ip and dst_port. Leave out noise such as peer-to-peer with e.g. AND NOT dst_port:6881.',
    },
    {
      key: 'ipsQuery',
      label: 'IPS query',
      type: 'string',
      placeholder: DEFAULT_IPS_QUERY,
      help: 'Attack trend: messages that are attacks blocked by intrusion prevention.',
    },
  ],
  createRuntime: (cfg) => {
    const http = new HttpClient({ baseUrl: cfg.url, tlsVerify: cfg.tlsVerify, caCert: cfg.caCert });
    const headers = { authorization: basicAuth(cfg.apiToken, 'token'), 'x-requested-by': 'socbridge' };
    return {
      http,
      headers,
      firewallQuery: cfg.firewallQuery,
      ipsQuery: cfg.ipsQuery,
      mcp: cfg.mcpPassthrough ? { url: http.url('/api/mcp'), http, headers, allow: parseAllowlist(cfg.mcpTools) } : null,
    };
  },
  async testConnection(rt) {
    let base: string;
    try {
      const r = await rt.http.request<{ version?: string; lifecycle?: string }>('/api/system', { headers: rt.headers });
      base = `Connected to Graylog ${r.version ?? ''} (${r.lifecycle ?? 'unknown'}).`;
    } catch (err) {
      return { ok: false, message: errMessage(err) };
    }
    if (!rt.mcp) return { ok: true, message: base };
    try {
      return { ok: true, message: `${base} ${await describeRemote(rt.mcp)}` };
    } catch (err) {
      return { ok: false, message: `${base} MCP passthrough failed: ${errMessage(err)} (is Remote MCP access on?)` };
    }
  },
  tools,
  dynamicTools: async (rt) => (rt.mcp ? proxiedTools(rt.mcp) : []),
  dynamicToolPattern: `${PROXY_PREFIX}*`,
});
