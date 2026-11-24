import { BackendError, type HttpClient } from '../http.js';

/**
 * Graylog read queries against the REST API (Graylog 6/7).
 *
 * Search uses the "simple scripting API" (`POST /api/search/messages`), which
 * returns a column schema plus rows. It is a read: POST only because the query
 * goes in the body. Every call carries `X-Requested-By`, which Graylog requires.
 */

export interface GraylogRuntime {
  http: HttpClient;
  headers: Record<string, string>;
}

type Obj = Record<string, unknown>;

/** Long message fields are capped so one noisy log line cannot fill the model context. */
const MAX_CELL = 2000;
export const DEFAULT_FIELDS = ['timestamp', 'source', 'message'] as const;
const STREAM_ID = /^[a-f0-9]{24}$/i;

function get<T>(rt: GraylogRuntime, p: string, query?: Record<string, string | number | boolean | undefined>) {
  return rt.http.request<T>(p, { query, headers: rt.headers });
}

function cap(v: unknown): unknown {
  if (typeof v !== 'string' || v.length <= MAX_CELL) return v;
  return v.slice(0, MAX_CELL) + ` … [truncated ${v.length - MAX_CELL} characters]`;
}

function pick(o: Obj, keys: readonly string[]): Obj {
  const out: Obj = {};
  for (const k of keys) if (o[k] !== undefined && o[k] !== null && o[k] !== '') out[k] = o[k];
  return out;
}

// ---------------------------------------------------------------- streams

interface StreamsResponse {
  total?: number;
  streams?: Obj[];
}

export async function listStreams(rt: GraylogRuntime, a: { title?: string; include_disabled: boolean }) {
  const r = await get<StreamsResponse>(rt, '/api/streams');
  const needle = a.title?.toLowerCase();
  const streams = (r.streams ?? [])
    .filter((s) => a.include_disabled || s.disabled !== true)
    .filter((s) => !needle || String(s.title ?? '').toLowerCase().includes(needle))
    .map((s) => pick(s, ['id', 'title', 'description', 'disabled', 'is_default', 'index_set_id', 'created_at']));
  return { total: streams.length, streams };
}

/**
 * Accepts stream IDs or titles (case-insensitive) and returns IDs. Titles are
 * friendlier for the model; IDs are what the search API wants.
 */
export async function resolveStreams(rt: GraylogRuntime, wanted: string[]): Promise<string[]> {
  if (wanted.every((w) => STREAM_ID.test(w))) return wanted;
  const { streams } = await get<StreamsResponse>(rt, '/api/streams');
  return wanted.map((w) => {
    if (STREAM_ID.test(w)) return w;
    const hit = (streams ?? []).find((s) => String(s.title ?? '').toLowerCase() === w.toLowerCase());
    if (!hit) throw new BackendError(`Unknown stream "${w}" (see graylog_list_streams)`);
    return String(hit.id);
  });
}

// ---------------------------------------------------------------- search

export interface SearchArgs {
  query: string;
  range_seconds?: number;
  from?: string;
  to?: string;
  streams?: string[];
  fields?: string[];
  limit: number;
  offset: number;
  sort_order: 'asc' | 'desc';
}

interface SearchResponse {
  schema?: { name?: string; field?: string; column_type?: string }[];
  datarows?: unknown[][];
  metadata?: { effective_timerange?: Obj };
}

export function timerange(a: Pick<SearchArgs, 'range_seconds' | 'from' | 'to'>): Obj {
  if (a.from) {
    return { type: 'absolute', from: new Date(a.from).toISOString(), to: new Date(a.to ?? Date.now()).toISOString() };
  }
  return { type: 'relative', range: a.range_seconds ?? 900 };
}

export async function searchMessages(rt: GraylogRuntime, a: SearchArgs) {
  const fields = a.fields?.length ? a.fields : [...DEFAULT_FIELDS];
  const streams = a.streams?.length ? await resolveStreams(rt, a.streams) : undefined;
  const body = {
    query: a.query.trim() || '*',
    timerange: timerange(a),
    fields,
    from: a.offset,
    size: a.limit,
    sort: 'timestamp',
    sort_order: a.sort_order,
    ...(streams ? { streams } : {}),
  };
  const r = await rt.http.request<SearchResponse>('/api/search/messages', { method: 'POST', json: body, headers: rt.headers });
  const columns = (r.schema ?? []).map((c, i) => c.field ?? c.name ?? fields[i] ?? `col${i}`);
  const messages = (r.datarows ?? []).map((row) => {
    const m: Obj = {};
    row.forEach((v, i) => {
      if (v !== null && v !== undefined && v !== '') m[columns[i] ?? `col${i}`] = cap(v);
    });
    return m;
  });
  return {
    query: body.query,
    timerange: r.metadata?.effective_timerange ?? body.timerange,
    returned: messages.length,
    ...(messages.length === a.limit ? { more: `Probably more results; raise offset to ${a.offset + a.limit} or narrow the query.` } : {}),
    messages,
  };
}

// ---------------------------------------------------------------- health

async function settle<T>(p: Promise<T>): Promise<T | { unavailable: string }> {
  try {
    return await p;
  } catch (err) {
    return { unavailable: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Node, indexer cluster, journal and system notifications. Each part is
 * fetched independently: a reader user may lack permission for some of them,
 * and one failing part should not hide the others.
 */
export async function systemHealth(rt: GraylogRuntime) {
  const [system, cluster, journal, notifications] = await Promise.all([
    settle(get<Obj>(rt, '/api/system')),
    settle(get<Obj>(rt, '/api/system/indexer/cluster/health')),
    settle(get<Obj>(rt, '/api/system/journal')),
    settle(get<{ total?: number; notifications?: Obj[] }>(rt, '/api/system/notifications')),
  ]);
  const ok = <T extends object>(v: T | { unavailable: string }): v is T => !('unavailable' in v);
  return {
    node: ok(system) ? pick(system, ['version', 'hostname', 'lifecycle', 'is_processing', 'lb_status', 'timezone', 'started_at']) : system,
    indexer_cluster: ok(cluster) ? pick(cluster, ['status', 'shards']) : cluster,
    journal: ok(journal)
      ? pick(journal, ['enabled', 'uncommitted_journal_entries', 'append_events_per_second', 'read_events_per_second', 'journal_size', 'journal_size_limit'])
      : journal,
    notifications: ok(notifications)
      ? {
          total: notifications.total ?? notifications.notifications?.length ?? 0,
          items: (notifications.notifications ?? []).slice(0, 50).map((n) => pick(n, ['type', 'severity', 'timestamp', 'node_id', 'key'])),
        }
      : notifications,
  };
}

// ---------------------------------------------------------------- events

/** Graylog's event priorities (6/7). */
const PRIORITY: Record<number, string> = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' };
const priorityLabel = (p: unknown) => (typeof p === 'number' ? (PRIORITY[p] ?? String(p)) : undefined);

const minutes = (ms: unknown) => (typeof ms === 'number' ? `${Math.round(ms / 60_000)}m` : undefined);

/** Renders an aggregation condition tree like `count() > 10 AND avg(took_ms) >= 500`. */
export function renderExpr(e: unknown, series: Map<string, string>): string {
  if (!e || typeof e !== 'object') return '?';
  const x = e as Obj;
  switch (x.expr) {
    case 'number':
      return String(x.value);
    case 'number-ref':
      return series.get(String(x.ref)) ?? String(x.ref);
    case '&&':
    case '||':
      return `(${renderExpr(x.left, series)} ${x.expr === '&&' ? 'AND' : 'OR'} ${renderExpr(x.right, series)})`;
    case 'group':
      return renderExpr(x.child, series);
    default:
      return `${renderExpr(x.left, series)} ${String(x.expr)} ${renderExpr(x.right, series)}`;
  }
}

function conditionSummary(config: Obj): Obj {
  const series = new Map<string, string>();
  for (const s of (config.series as Obj[] | undefined) ?? []) {
    const fn = String(s.type ?? s.function ?? '?');
    series.set(String(s.id), `${fn}(${s.field ?? ''})`);
  }
  const expr = (config.conditions as Obj | undefined)?.expression;
  return pick(
    {
      type: config.type,
      query: config.query ? cap(config.query) : undefined,
      streams: (config.streams as unknown[] | undefined)?.length ? config.streams : undefined,
      search_within: minutes(config.search_within_ms),
      execute_every: minutes(config.execute_every_ms),
      group_by: (config.group_by as unknown[] | undefined)?.length ? config.group_by : undefined,
      condition: expr ? renderExpr(expr, series) : series.size ? undefined : 'every matching message',
    },
    ['type', 'query', 'streams', 'search_within', 'execute_every', 'group_by', 'condition'],
  );
}

interface DefinitionsResponse {
  total?: number;
  event_definitions?: Obj[];
  elements?: Obj[];
  context?: { scheduler?: Record<string, { status?: string }> };
}

export interface DefinitionArgs {
  query?: string;
  page: number;
  per_page: number;
}

export async function listEventDefinitions(rt: GraylogRuntime, a: DefinitionArgs) {
  const [r, notifs] = await Promise.all([
    get<DefinitionsResponse>(rt, '/api/events/definitions', { page: a.page, per_page: a.per_page, query: a.query ?? '' }),
    settle(get<{ notifications?: Obj[]; elements?: Obj[] }>(rt, '/api/events/notifications', { per_page: 500 })),
  ]);
  const names = new Map<string, string>();
  if (!('unavailable' in notifs)) {
    for (const n of notifs.notifications ?? notifs.elements ?? []) names.set(String(n.id), String(n.title ?? n.id));
  }
  const defs = (r.event_definitions ?? r.elements ?? []).map((d) => {
    const scheduler = r.context?.scheduler?.[String(d.id)]?.status;
    const state = typeof d.state === 'string' ? d.state : scheduler;
    return pick(
      {
        id: d.id,
        title: d.title,
        description: d.description ? cap(d.description) : undefined,
        priority: priorityLabel(d.priority),
        alert: d.alert,
        enabled: state ? String(state).toUpperCase() === 'ENABLED' : undefined,
        condition: d.config && typeof d.config === 'object' ? conditionSummary(d.config as Obj) : undefined,
        notifications: ((d.notifications as Obj[] | undefined) ?? []).map((n) => names.get(String(n.notification_id)) ?? n.notification_id),
        updated_at: d.updated_at,
        matched_at: d.matched_at,
      },
      ['id', 'title', 'description', 'priority', 'alert', 'enabled', 'condition', 'notifications', 'updated_at', 'matched_at'],
    );
  });
  const total = r.total ?? defs.length;
  return {
    total,
    page: a.page,
    returned: defs.length,
    ...(a.page * a.per_page < total ? { more: `More definitions; use page ${a.page + 1}.` } : {}),
    event_definitions: defs,
  };
}

const PRIORITY_IN: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** Event definition IDs or titles (case-insensitive) to IDs. */
async function resolveDefinitions(rt: GraylogRuntime, wanted: string[]): Promise<string[]> {
  if (wanted.every((w) => STREAM_ID.test(w))) return wanted;
  const r = await get<DefinitionsResponse>(rt, '/api/events/definitions', { page: 1, per_page: 500 });
  const defs = r.event_definitions ?? r.elements ?? [];
  return wanted.map((w) => {
    if (STREAM_ID.test(w)) return w;
    const hit = defs.find((d) => String(d.title ?? '').toLowerCase() === w.toLowerCase());
    if (!hit) throw new BackendError(`Unknown event definition "${w}" (see graylog_list_event_definitions)`);
    return String(hit.id);
  });
}

export interface EventSearchArgs {
  query: string;
  range_seconds?: number;
  from?: string;
  to?: string;
  event_definitions?: string[];
  priority?: ('low' | 'medium' | 'high' | 'critical')[];
  alerts_only: boolean;
  page: number;
  per_page: number;
}

interface EventsResponse {
  events?: { event?: Obj }[];
  total_events?: number;
  context?: { event_definitions?: Record<string, Obj> };
}

export async function searchEvents(rt: GraylogRuntime, a: EventSearchArgs) {
  const defs = a.event_definitions?.length ? await resolveDefinitions(rt, a.event_definitions) : [];
  const parts = [a.query.trim()].filter((q) => q && q !== '*');
  if (a.priority?.length) parts.push(`priority:(${a.priority.map((p) => PRIORITY_IN[p]).join(' OR ')})`);
  const query = parts.length > 1 ? parts.map((p) => `(${p})`).join(' AND ') : (parts[0] ?? '');
  const body = {
    query,
    page: a.page,
    per_page: a.per_page,
    timerange: timerange({ range_seconds: a.range_seconds ?? 86_400, from: a.from, to: a.to }),
    filter: { alerts: a.alerts_only ? 'only' : 'include', event_definitions: defs },
    sort_by: 'timestamp',
    sort_direction: 'desc',
  };
  const r = await rt.http.request<EventsResponse>('/api/events/search', { method: 'POST', json: body, headers: rt.headers });
  const titles = r.context?.event_definitions ?? {};
  const events = (r.events ?? []).map(({ event: e = {} }) =>
    pick(
      {
        id: e.id,
        timestamp: e.timestamp,
        priority: priorityLabel(e.priority),
        alert: e.alert,
        definition: titles[String(e.event_definition_id)]?.title ?? e.event_definition_id,
        event_definition_id: e.event_definition_id,
        message: cap(e.message),
        source: e.source,
        key: e.key,
        timerange_start: e.timerange_start,
        timerange_end: e.timerange_end,
        fields: e.fields && Object.keys(e.fields as Obj).length ? capObj(e.fields as Obj) : undefined,
        group_by_fields: e.group_by_fields && Object.keys(e.group_by_fields as Obj).length ? e.group_by_fields : undefined,
      },
      ['id', 'timestamp', 'priority', 'alert', 'definition', 'event_definition_id', 'message', 'source', 'key', 'timerange_start', 'timerange_end', 'fields', 'group_by_fields'],
    ),
  );
  const total = r.total_events ?? events.length;
  return {
    query: body.query || '*',
    timerange: body.timerange,
    total,
    page: a.page,
    returned: events.length,
    ...(a.page * a.per_page < total ? { more: `More events; use page ${a.page + 1} or narrow the window.` } : {}),
    events,
  };
}

function capObj(o: Obj): Obj {
  const out: Obj = {};
  for (const [k, v] of Object.entries(o).slice(0, 50)) out[k] = cap(v);
  return out;
}

// ---------------------------------------------------------------- views (dashboards, saved searches)

interface ViewsResponse {
  total?: number;
  views?: Obj[];
  elements?: Obj[];
}

export interface ViewListArgs {
  query?: string;
  page: number;
  per_page: number;
}

const VIEW_PATH = { DASHBOARD: '/api/dashboards', SEARCH: '/api/search/saved' } as const;

/**
 * Dashboards and saved searches are both "views" in Graylog. The list
 * endpoints are type-specific; responses use `views` (older) or `elements`
 * (6.1+), so both are accepted.
 */
export async function listViews(rt: GraylogRuntime, type: keyof typeof VIEW_PATH, a: ViewListArgs) {
  const r = await get<ViewsResponse>(rt, VIEW_PATH[type], {
    page: a.page,
    per_page: a.per_page,
    query: a.query ?? '',
    sort: 'title',
    order: 'asc',
  });
  const views = (r.views ?? r.elements ?? [])
    .filter((v) => !v.type || v.type === type)
    .map((v) => ({
      ...pick(v, ['id', 'title', 'owner', 'created_at', 'last_updated_at', 'favorite']),
      ...(v.summary ? { summary: cap(v.summary) } : {}),
      ...(v.description ? { description: cap(v.description) } : {}),
    }));
  const total = r.total ?? views.length;
  const key = type === 'DASHBOARD' ? 'dashboards' : 'saved_searches';
  return {
    total,
    page: a.page,
    returned: views.length,
    ...(a.page * a.per_page < total ? { more: `More results; use page ${a.page + 1}.` } : {}),
    [key]: views,
  };
}

const fieldsOf = (pivots: unknown) =>
  ((pivots as Obj[] | undefined) ?? []).flatMap((p) => (Array.isArray(p.fields) ? p.fields : p.field ? [p.field] : []));

function widgetSummary(w: Obj, title: unknown): Obj {
  const c = (w.config as Obj | undefined) ?? {};
  const q = (w.query as Obj | undefined)?.query_string;
  const series = ((c.series as Obj[] | undefined) ?? []).map((s) => s.function ?? s.type).filter(Boolean);
  return pick(
    {
      id: w.id,
      type: w.type,
      title,
      query: q ? cap(q) : undefined,
      timerange: w.timerange,
      streams: (w.streams as unknown[] | undefined)?.length ? w.streams : undefined,
      visualization: c.visualization,
      group_by: fieldsOf(c.row_pivots).length ? fieldsOf(c.row_pivots) : undefined,
      split_by: fieldsOf(c.column_pivots).length ? fieldsOf(c.column_pivots) : undefined,
      series: series.length ? series : undefined,
      fields: Array.isArray(c.fields) && c.fields.length ? c.fields : undefined,
    },
    ['id', 'type', 'title', 'query', 'timerange', 'streams', 'visualization', 'group_by', 'split_by', 'series', 'fields'],
  );
}

/**
 * One dashboard or saved search: its pages (queries) and widgets with their
 * queries and aggregation setup. Never runs the widgets.
 */
export async function getView(rt: GraylogRuntime, id: string) {
  if (!STREAM_ID.test(id)) throw new BackendError(`"${id}" is not a view ID (see graylog_list_dashboards)`);
  const v = await get<Obj>(rt, `/api/views/${id}`);
  const search = v.search_id
    ? await settle(get<{ queries?: Obj[] }>(rt, `/api/views/search/${encodeURIComponent(String(v.search_id))}`))
    : ({ unavailable: 'no search' } as const);
  const queries = new Map<string, Obj>();
  if (!('unavailable' in search)) for (const q of search.queries ?? []) queries.set(String(q.id), q);
  const state = (v.state as Record<string, Obj> | undefined) ?? {};
  const pages = Object.entries(state).map(([qid, s]) => {
    const titles = (s.titles as { tab?: Obj; widget?: Obj } | undefined) ?? {};
    const q = queries.get(qid);
    const widgets = ((s.widgets as Obj[] | undefined) ?? []).slice(0, 100);
    return pick(
      {
        query_id: qid,
        title: titles.tab?.title,
        query: (q?.query as Obj | undefined)?.query_string ? cap((q!.query as Obj).query_string) : undefined,
        timerange: q?.timerange,
        widgets: widgets.map((w) => widgetSummary(w, titles.widget?.[String(w.id)])),
      },
      ['query_id', 'title', 'query', 'timerange', 'widgets'],
    );
  });
  return {
    ...pick(v, ['id', 'type', 'title', 'owner', 'created_at', 'last_updated_at']),
    ...(v.summary ? { summary: cap(v.summary) } : {}),
    ...(v.description ? { description: cap(v.description) } : {}),
    pages,
  };
}
