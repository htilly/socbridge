import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ErrorCode, McpError, type Tool } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { errMessage, log } from '../../log.js';
import { VERSION } from '../../version.js';
import { BackendError, type HttpClient } from '../http.js';
import { cappedResult } from '../result.js';
import type { ToolDescriptor } from '../types.js';

/**
 * Optional passthrough to Graylog's built-in MCP server (System →
 * Configurations → MCP → Remote MCP access), at `<graylog>/api/mcp`.
 *
 * SocBridge stays the only endpoint clients talk to, so its tokens, rate limit,
 * call log and result cap still apply. Only an allowlisted subset of Graylog's
 * tools is exposed, renamed `graylog_mcp_<name>`. With an empty allowlist only
 * tools that Graylog itself marks read-only are exposed.
 */

export const PROXY_PREFIX = 'graylog_mcp_';
const LIST_TTL_MS = 5 * 60_000;
const MAX_EXPOSED = 50;
/** After a failed discovery, how long requests go on without these tools before Graylog is asked again. */
const FAILURE_TTL_MS = 60_000;
const MAX_DESCRIPTION = 500;

export interface RemoteMcp {
  url: URL;
  http: HttpClient;
  headers: Record<string, string>;
  /** Remote tool names an admin allowed. Empty = only tools annotated read-only. */
  allow: Set<string>;
  cache?: { at: number; tools: Tool[] };
  failedAt?: number;
}

export function parseAllowlist(v: string | undefined): Set<string> {
  return new Set((v ?? '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean));
}

export function proxyName(remote: string): string {
  return (PROXY_PREFIX + remote.replace(/[^A-Za-z0-9_-]/g, '_')).slice(0, 64);
}

async function withClient<T>(m: RemoteMcp, fn: (c: Client) => Promise<T>): Promise<T> {
  const transport = new StreamableHTTPClientTransport(m.url, { requestInit: { headers: m.headers }, fetch: m.http.rawFetch });
  const client = new Client({ name: 'socbridge', version: VERSION });
  try {
    await client.connect(transport);
    return await fn(client);
  } catch (err) {
    if (err instanceof BackendError) throw err;
    // A JSON-RPC error is Graylog answering (bad arguments, unknown tool); anything else means it did not.
    const answered = err instanceof McpError && err.code !== ErrorCode.ConnectionClosed && err.code !== ErrorCode.RequestTimeout;
    const http = err instanceof StreamableHTTPError && err.code !== undefined && err.code >= 100 ? err.code : undefined;
    const message = `Graylog MCP (${m.url.host}): ${errMessage(err)}`;
    throw http !== undefined
      ? new BackendError(message, http, undefined, `Graylog MCP responded ${http}`)
      : new BackendError(message, undefined, !answered, answered ? `Graylog MCP: ${errMessage(err)}` : 'Graylog MCP could not be reached');
  } finally {
    await client.close().catch(() => undefined);
  }
}

/** All tools Graylog's MCP server offers, cached for a few minutes per runtime. */
export async function listRemoteTools(m: RemoteMcp, force = false): Promise<Tool[]> {
  if (!force && m.cache && Date.now() - m.cache.at < LIST_TTL_MS) return m.cache.tools;
  const tools = await withClient(m, async (c) => {
    const out: Tool[] = [];
    let cursor: string | undefined;
    do {
      const page = await c.listTools(cursor ? { cursor } : undefined);
      out.push(...page.tools);
      cursor = page.nextCursor;
    } while (cursor && out.length < 500);
    return out;
  });
  m.cache = { at: Date.now(), tools };
  return tools;
}

export function isExposed(m: RemoteMcp, t: Tool): boolean {
  return m.allow.size ? m.allow.has(t.name) : t.annotations?.readOnlyHint === true;
}

/** Converts Graylog's JSON Schema to zod so the SDK can advertise and validate it. */
export function inputSchemaFor(t: Tool): z.ZodObject {
  try {
    const { $schema: _drop, ...schema } = t.inputSchema as Record<string, unknown>;
    const s = z.fromJSONSchema(schema as Parameters<typeof z.fromJSONSchema>[0]);
    if (s instanceof z.ZodObject) return s;
  } catch {
    /* unsupported schema construct: fall through */
  }
  return z.looseObject({});
}

/** Summary for the connection test: what Graylog offers and what SocBridge exposes. */
export async function describeRemote(m: RemoteMcp): Promise<string> {
  const tools = await listRemoteTools(m, true);
  const exposed = tools.filter((t) => isExposed(m, t)).map((t) => t.name);
  const hidden = tools.filter((t) => !isExposed(m, t)).map((t) => t.name);
  const missing = [...m.allow].filter((n) => !tools.some((t) => t.name === n));
  const parts = [`Graylog MCP offers ${tools.length} tools; exposed: ${exposed.join(', ') || 'none'}.`];
  if (hidden.length) parts.push(`Not exposed: ${hidden.join(', ')}.`);
  if (missing.length) parts.push(`Allowlisted but not offered: ${missing.join(', ')}.`);
  if (!m.allow.size) parts.push('Allowlist empty, so only tools Graylog marks read-only are exposed.');
  return parts.join(' ');
}

/**
 * Read or write, for SocBridge's scopes: only a tool Graylog itself marks
 * read-only (and not destructive) is a read tool. Anything else an
 * administrator allowlisted is a write tool, so it needs write access at
 * installation, user and token level like any other write tool.
 */
export function accessOf(t: Tool): 'read' | 'write' {
  return t.annotations?.readOnlyHint === true && t.annotations?.destructiveHint !== true ? 'read' : 'write';
}

/**
 * The exposed Graylog MCP tools as descriptors for this request. Failure to
 * reach Graylog's MCP endpoint only drops these tools; the REST tools stay.
 */
export async function proxiedTools<Rt>(m: RemoteMcp): Promise<ToolDescriptor<Rt>[]> {
  let tools: Tool[];
  if (m.failedAt !== undefined && Date.now() - m.failedAt < FAILURE_TTL_MS) return [];
  try {
    tools = (await listRemoteTools(m)).filter((t) => isExposed(m, t)).slice(0, MAX_EXPOSED);
    m.failedAt = undefined;
  } catch (err) {
    m.failedAt = Date.now();
    log.warn('Graylog MCP passthrough unavailable', { error: errMessage(err) });
    return [];
  }
  return tools.map((t) => {
    const access = accessOf(t);
    return {
      name: proxyName(t.name),
      access,
      destructive: access === 'write' && t.annotations?.destructiveHint !== false,
      title: t.title ?? t.annotations?.title ?? `Graylog MCP: ${t.name}`,
      description:
        (access === 'write' ? 'Changes Graylog (forwarded write tool). ' : '') +
        `[Forwarded to Graylog's MCP server as ${t.name}; the description is Graylog's own and not verified] ${(t.description ?? '').slice(0, MAX_DESCRIPTION)}`.trim(),
      inputSchema: inputSchemaFor(t),
      run: async (_rt: Rt, args: Record<string, unknown>) =>
        cappedResult(await withClient(m, (c) => c.callTool({ name: t.name, arguments: args }))),
    };
  });
}
