import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { Service } from '../config/schema.js';

export const BACKEND_IDS = ['wazuh', 'trivy', 'defectdojo', 'graylog', 'intel'] as const;
export type BackendId = (typeof BACKEND_IDS)[number];

/**
 * `ready`  – tools are implemented and registered when the backend is enabled.
 * `stub`   – configuration and connection test exist, tools do not yet. A
 *            stub backend never registers tools, even when enabled.
 */
export type Maturity = 'ready' | 'stub';

/** Describes one settings field for the web UI. */
export interface FieldSpec {
  key: string;
  label: string;
  type: 'url' | 'string' | 'secret' | 'boolean' | 'pem' | 'number';
  required?: boolean;
  help?: string;
  placeholder?: string;
}

/**
 * Step-by-step setup help shown next to a backend in the web UI: what is
 * needed, where to find each value, and which field it goes into.
 */
export interface SetupGuide {
  /** What SocBridge uses the backend for, in one or two sentences. */
  intro: string;
  /** Before you start: access and network prerequisites. */
  before?: string[];
  /** One entry per value to collect. `fields` names the form fields it fills. */
  items: { title: string; fields?: string[]; steps: string[]; code?: string }[];
  /** How to confirm it works. */
  verify: string[];
  docs?: { label: string; url: string }[];
}

export interface ConnectionResult {
  ok: boolean;
  message: string;
}

/**
 * Structured health (DESIGN §3.4). `ok` works fully, `degraded` works with a
 * limitation (one sub-service failing, some reports unreadable, a yellow
 * cluster), `down` cannot serve its tools.
 */
export type HealthStatus = 'ok' | 'degraded' | 'down';

export interface HealthCheck {
  /** Short stable name, e.g. `manager`, `indexer`, `reports`. */
  name: string;
  status: HealthStatus;
  message: string;
}

export interface BackendHealth {
  status: HealthStatus;
  checks: HealthCheck[];
}

/**
 * Read access to another backend from inside a tool (cross-backend tools such
 * as the intel module's prioritisation). `run` executes under that backend's
 * gate, so its concurrency limit and circuit breaker apply as for its own tools.
 */
export interface SourceHandle<Rt> {
  runtime: Rt;
  run<T>(fn: (rt: Rt) => Promise<T>): Promise<T>;
}

/**
 * Looks up another backend for the calling credential. Returns a handle only
 * when that backend is enabled, ready and the credential may read it right
 * now (the same live check as for the backend's own read tools); otherwise
 * says why not. Never grants write.
 */
export type SourceLookup = <Rt>(id: BackendId) => SourceHandle<Rt> | { unavailable: string };

/** Who is calling a tool; passed to handlers for logging and notes written to backends. */
export interface ToolContext {
  /** Name of the user whose credential made the request. */
  userName: string;
  /** Other backends this credential may read. */
  source: SourceLookup;
  /** The administrator's service map, read live. */
  services(): readonly Service[];
}

/**
 * Read tools only look; write tools change state in the backend (DESIGN §6).
 * The registry derives the MCP annotations from this, so a module cannot
 * forget to mark a write tool.
 */
export type ToolAccess = 'read' | 'write';

/**
 * One MCP tool of a backend, declared rather than registered (DESIGN §6). The
 * core decides per request whether the caller gets it (enabled backend ∩
 * installation allowlist ∩ credential scope) and wraps the handler with the
 * call-time scope check, the audit log, the backend gate and error handling.
 */
export interface ToolDescriptor<Rt = unknown> {
  name: string;
  access: ToolAccess;
  /**
   * Write tools only: the change destroys or overrides something that cannot
   * simply be set back (running a command on a host). Maps to `destructiveHint`.
   */
  destructive?: boolean;
  /**
   * Part of the module's default allowlist (what an installation gets until
   * an administrator edits the list). Defaults to true for read tools; write
   * tools are never in the default list, whatever this says.
   */
  default?: boolean;
  title: string;
  /** May depend on the runtime, e.g. to list the commands an administrator allowed. */
  description: string | ((rt: Rt) => string);
  inputSchema: z.ZodRawShape | z.ZodObject;
  /** Whether the tool exists for this runtime (e.g. Wazuh tools that need the indexer). */
  available?: (rt: Rt) => boolean;
  run: (rt: Rt, args: any, ctx: ToolContext) => Promise<CallToolResult>;
}

/**
 * Typed helpers for declaring a module's tools: `const t = toolsFor<Client>()`,
 * then `t.read({...})` / `t.write({...})`. `args` is inferred from the schema.
 */
export function toolsFor<Rt>() {
  type Decl<S extends z.ZodRawShape> = Omit<ToolDescriptor<Rt>, 'access' | 'inputSchema' | 'run'> & {
    inputSchema: S;
    run: (rt: Rt, args: z.infer<z.ZodObject<S>>, ctx: ToolContext) => Promise<CallToolResult>;
  };
  return {
    read: <S extends z.ZodRawShape>(d: Decl<S>): ToolDescriptor<Rt> => ({ ...d, access: 'read' }),
    write: <S extends z.ZodRawShape>(d: Decl<S>): ToolDescriptor<Rt> => ({ ...d, access: 'write', default: false }),
  };
}

/**
 * Common contract every backend module implements.
 *
 * `Cfg` is the validated settings object; `Rt` is a long-lived runtime (API
 * client, cached auth token, …). The MCP transport is stateless and builds a
 * new server per request, so runtimes are cached by the registry and only
 * rebuilt when the backend's settings change.
 */
export interface BackendModule<Cfg = unknown, Rt = unknown> {
  id: BackendId;
  title: string;
  description: string;
  maturity: Maturity;
  fields: FieldSpec[];
  /** Validates stored settings (without the `enabled` flag). */
  schema: z.ZodType<Cfg>;
  createRuntime(cfg: Cfg): Rt;
  testConnection(rt: Rt): Promise<ConnectionResult>;
  /**
   * Structured health, run on a schedule by the registry's health monitor
   * (never per tool call). Optional: without it, health is derived from
   * `testConnection` as a single `connection` check.
   */
  health?(rt: Rt): Promise<BackendHealth>;
  /** Every tool the module can offer. Names are `<id>_<verb>_<object>`. */
  tools: ToolDescriptor<Rt>[];
  /**
   * Tools discovered at runtime (Graylog's MCP passthrough). A failure should
   * resolve to an empty list rather than reject, so the static tools stay.
   */
  dynamicTools?(rt: Rt): Promise<ToolDescriptor<Rt>[]>;
  /** Allowlist pattern that covers the dynamic tools, e.g. `graylog_mcp_*` (for the Backends page). */
  dynamicToolPattern?: string;
  /** MCP `openWorldHint`: the tools talk to a system outside SocBridge. Default true. */
  openWorld?: boolean;
  /** Tools that are planned but not implemented, shown in the UI for stubs. */
  plannedTools?: string[];
  guide?: SetupGuide;
}

export function defineBackend<Cfg, Rt>(m: BackendModule<Cfg, Rt>): BackendModule<Cfg, Rt> {
  return m;
}
