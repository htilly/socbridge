import { randomBytes } from 'node:crypto';
import express, { type Response, type Router } from 'express';
import { z } from 'zod';
import { listFindings, type DefectDojoRuntime } from '../backends/defectdojo/queries.js';
import { searchEvents, searchMessages, type GraylogRuntime } from '../backends/graylog/queries.js';
import { GateRejected } from '../backends/health.js';
import { canRead } from '../auth/scopes.js';
import { BackendError } from '../backends/http.js';
import { BACKENDS, getModule, type BackendRegistry } from '../backends/registry.js';
import { listReports, reportFindings, type Severity as TrivySeverity, type TrivyReports } from '../backends/trivy/reports.js';
import type { BackendId } from '../backends/types.js';
import type { User } from '../config/schema.js';
import { attackRangeShape, DAY, MAX_RANGE_DAYS } from '../backends/attack-window.js';
import { FIREWALL_CATEGORIES, edgeMap, firewallDetails, firewallTrend, type FirewallRuntime } from '../backends/graylog/firewall.js';
import { attackDetails, attackMap, attackTrend, isAttackCategory } from '../backends/wazuh/attacks.js';
import type { WazuhClient } from '../backends/wazuh/client.js';
import { agentVulnerabilities, SEVERITIES, vulnerabilityOverview, vulnerabilityTrend } from '../backends/wazuh/queries.js';
import { GeoIp } from '../geoip.js';
import { errMessage, log } from '../log.js';
import { auditView } from './audit-view.js';
import { HttpError, requireUser, type AppContext } from './context.js';

/**
 * Graylog has no findings as such; the Findings page shows recent messages at
 * syslog level error or worse (0 emergency … 3 error) from the last day.
 */
export const GRAYLOG_EVENTS = {
  query: 'level:<=3',
  range_seconds: 24 * 3600,
  fields: ['timestamp', 'source', 'level', 'message'],
  limit: 100,
} as const;

/** Turns a failed backend read into the status the UI shows. */
export function backendFailure(err: unknown, res: Response): never {
  if (err instanceof HttpError) throw err;
  if (err instanceof GateRejected) throw new HttpError(503, (res.locals.user as User).role === 'admin' ? err.message : err.publicMessage);
  // Backend errors name hosts and quote responses: administrators see them, others a reference to the log.
  const admin = (res.locals.user as User).role === 'admin';
  if (admin && err instanceof BackendError) throw new HttpError(502, err.message);
  const ref = randomBytes(4).toString('hex');
  log.warn('Findings request failed', { ref, path: res.req.path, error: errMessage(err) });
  throw new HttpError(err instanceof BackendError ? 502 : 500, `The backend did not answer this request (reference ${ref})`);
}

/** How many triggered Graylog events the page lists. */
const GRAYLOG_ALERTS_LIMIT = 50;

/** Trend windows the page offers, in days. */
export const TREND_DAYS = [7, 30, 90];

/** Per severity, how many DefectDojo findings the page lists. */
const DEFECTDOJO_PER_SEVERITY = 50;

/**
 * Read-only findings for the web UI. Uses the same queries as the MCP tools so
 * the browser and MCP clients always agree, and runs them under the same
 * per-backend gate (concurrency limit and circuit breaker). Available to every
 * signed-in user. Each source has its own routes, so one failing backend never
 * hides another's findings.
 */
export function findingsRouter(ctx: AppContext): Router {
  const r = express.Router();
  r.use(requireUser);
  r.use(
    auditView(ctx, (req) => {
      const page = req.path.split('/')[1] ?? '';
      if (page === 'sources') return null;
      if (page === 'trivy' || page === 'defectdojo' || page === 'graylog') return page;
      return page === 'firewall' || page === 'edge-map' ? 'graylog' : 'wazuh';
    }),
  );
  const geo = new GeoIp(ctx.env.geoipDb);

  /** A user limited to some backends (readBackends) sees only those here too. */
  const mayRead = (res: Response, id: BackendId): void => {
    if (!canRead(res.locals.user as User, id)) throw new HttpError(403, `You have no read access to ${getModule(id)!.title}; ask an administrator`);
  };

  const wazuh = (res: Response): WazuhClient => {
    mayRead(res, 'wazuh');
    const client = ctx.registry.runtime<WazuhClient>('wazuh');
    if (!client) throw new HttpError(409, 'The Wazuh backend is not enabled');
    if (!client.hasIndexer) throw new HttpError(409, 'The Wazuh indexer is not configured');
    return client;
  };

  /** Runtime of a backend the page can query, or 409 saying why not. */
  const source = <Rt>(res: Response, id: BackendId): Rt => {
    mayRead(res, id);
    const rt = ctx.registry.runtime<Rt>(id);
    if (!rt) throw new HttpError(409, `The ${getModule(id)!.title} backend is not enabled`);
    return rt;
  };

  /** Runs a query under the backend's gate, like MCP tool calls. */
  const gated = <T>(id: BackendId, rt: unknown, fn: () => Promise<T>): Promise<T> =>
    ctx.registry.gate(getModule(id)!, rt as object).run(fn);

  const severityList = z
    .string()
    .optional()
    .transform((v) => (v ? v.split(',').filter(Boolean) : undefined))
    .pipe(z.array(z.enum(SEVERITIES)).optional());

  r.get('/sources', (_req, res) => {
    const client = ctx.registry.runtime<WazuhClient>('wazuh');
    res.json({
      wazuh: client ? (client.hasIndexer ? 'ready' : 'no-indexer') : 'disabled',
      backends: sourceList(ctx.registry, (res.locals.user as User).role === 'admin'),
    });
  });

  r.get('/overview', async (req, res) => {
    const q = z.object({ severity: severityList }).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid severity filter');
    try {
      const client = wazuh(res);
      res.json(await gated('wazuh', client, () => vulnerabilityOverview(client, { severity: q.data.severity, top: 25 })));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  // New and resolved findings per day and per agent, for the trend on the front page.
  r.get('/trend', async (req, res) => {
    const q = z.object({ severity: severityList, days: z.coerce.number().int().refine((d) => TREND_DAYS.includes(d)).default(30) }).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid trend filter');
    try {
      const client = wazuh(res);
      res.json(await gated('wazuh', client, () => vulnerabilityTrend(client, { days: q.data.days, severity: q.data.severity, top: 50 })));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  // Attack trend page: every category over time, then one category in a time range.
  r.get('/attacks', async (req, res) => {
    const q = z.object(attackRangeShape).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid attack time range');
    try {
      const client = wazuh(res);
      res.json(await gated('wazuh', client, () => attackTrend(client, q.data)));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  r.get('/attacks/:category', async (req, res) => {
    const time = z.string().datetime();
    const q = z
      .object({ category: z.string().max(100).refine(isAttackCategory), from: time, to: time })
      .refine((v) => Date.parse(v.from) < Date.parse(v.to))
      .safeParse({ ...req.query, category: req.params.category });
    if (!q.success) throw new HttpError(400, 'Invalid attack filter');
    try {
      const client = wazuh(res);
      res.json(await gated('wazuh', client, () => attackDetails(client, { ...q.data, top: 10, limit: 20 })));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  r.get('/attack-map', async (req, res) => {
    const q = z.object({ since: z.string().datetime() }).safeParse(req.query);
    if (!q.success || Date.now() - Date.parse(q.data.since) > 8 * DAY) throw new HttpError(400, 'Invalid start time');
    try {
      const client = wazuh(res);
      res.json(await gated('wazuh', client, () => attackMap(client, q.data)));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  // The map's network edge layers: addresses in firewall logs are placed with a local GeoIP file.
  r.get('/edge-map', async (req, res) => {
    const layers = z.string().max(100).transform((v) => v.split(',')).pipe(z.array(z.enum(FIREWALL_CATEGORIES)).min(1));
    const q = z.object({ since: z.string().datetime(), layers }).safeParse(req.query);
    if (!q.success || Date.now() - Date.parse(q.data.since) > 8 * DAY) throw new HttpError(400, 'Invalid map filter');
    try {
      const rt = source<FirewallRuntime>(res, 'graylog');
      const admin = (res.locals.user as User).role === 'admin';
      if (!(await geo.ready())) {
        res.json({ geoip: null, ...(admin ? { geoip_file: geo.file } : {}), categories: [], events: [] });
        return;
      }
      res.json({ geoip: geo.database, ...(await gated('graylog', rt, () => edgeMap(rt, geo, q.data))) });
    } catch (err) {
      backendFailure(err, res);
    }
  });

  // The network edge on the same page: firewall and IPS logs from Graylog.
  r.get('/firewall', async (req, res) => {
    const q = z.object(attackRangeShape).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid attack time range');
    try {
      const rt = source<FirewallRuntime>(res, 'graylog');
      res.json(await gated('graylog', rt, () => firewallTrend(rt, q.data)));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  r.get('/firewall/:category', async (req, res) => {
    const time = z.string().datetime();
    const q = z
      .object({ category: z.enum(FIREWALL_CATEGORIES), from: time, to: time })
      .refine((v) => Date.parse(v.from) < Date.parse(v.to) && Date.parse(v.to) - Date.parse(v.from) <= MAX_RANGE_DAYS * DAY)
      .safeParse({ ...req.query, category: req.params.category });
    if (!q.success) throw new HttpError(400, 'Invalid attack filter');
    try {
      const rt = source<FirewallRuntime>(res, 'graylog');
      res.json(await gated('graylog', rt, () => firewallDetails(rt, { ...q.data, top: 10, limit: 20 })));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  r.get('/agents/:id', async (req, res) => {
    const q = z.object({ severity: severityList }).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid severity filter');
    try {
      const client = wazuh(res);
      res.json(await gated('wazuh', client, () => agentVulnerabilities(client, { agent_id: String(req.params.id), severity: q.data.severity, limit: 200 })));
    } catch (err) {
      backendFailure(err, res);
    }
  });

  // Trivy: reports with counts, then one report's vulnerabilities. Severity
  // names arrive as on the Wazuh scale and map to Trivy's upper case.
  const trivySeverity = (sev?: string[]): TrivySeverity[] | undefined => sev?.map((s) => s.toUpperCase() as TrivySeverity);

  r.get('/trivy', async (req, res) => {
    const q = z.object({ severity: severityList }).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid severity filter');
    try {
      const rt = source<TrivyReports>(res, 'trivy');
      const list = await gated('trivy', rt, () => listReports(rt, { limit: 500, offset: 0 }));
      const wanted = trivySeverity(q.data.severity);
      const by_severity: Record<string, number> = {};
      for (const rep of list.reports) {
        for (const [k, n] of Object.entries(rep.by_severity)) {
          if (!wanted || wanted.includes(k as TrivySeverity)) by_severity[k] = (by_severity[k] ?? 0) + (n ?? 0);
        }
      }
      res.json({
        total: Object.values(by_severity).reduce((a, b) => a + b, 0),
        by_severity,
        reports: list.reports,
        unreadable: list.unreadable?.length ?? 0,
      });
    } catch (err) {
      backendFailure(err, res);
    }
  });

  r.get('/trivy/reports/:file', async (req, res) => {
    const q = z.object({ severity: severityList }).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid severity filter');
    try {
      const rt = source<TrivyReports>(res, 'trivy');
      const out = await gated('trivy', rt, () =>
        reportFindings(rt, {
          report: String(req.params.file),
          severity: trivySeverity(q.data.severity),
          fixable_only: false,
          include_misconfigurations: false,
          include_secrets: false,
          limit: 200,
          offset: 0,
        }),
      );
      if ('error' in out) throw new HttpError(404, out.error);
      res.json(out);
    } catch (err) {
      backendFailure(err, res);
    }
  });

  // DefectDojo: active findings, one query per selected severity so the
  // page gets an exact count for each and the most severe are never crowded out.
  r.get('/defectdojo', async (req, res) => {
    const q = z.object({ severity: severityList }).safeParse(req.query);
    if (!q.success) throw new HttpError(400, 'Invalid severity filter');
    try {
      const rt = source<DefectDojoRuntime>(res, 'defectdojo');
      const sevs = q.data.severity ?? [...SEVERITIES];
      const pages = await Promise.all(
        sevs.map((severity) =>
          gated('defectdojo', rt, () =>
            listFindings(rt, {
              severity,
              active: true,
              include_duplicates: false,
              include_false_positives: false,
              limit: DEFECTDOJO_PER_SEVERITY,
              offset: 0,
            }),
          ),
        ),
      );
      const by_severity = Object.fromEntries(sevs.map((s, i) => [s, pages[i]!.total]));
      res.json({
        total: pages.reduce((n, p) => n + p.total, 0),
        by_severity,
        per_severity_limit: DEFECTDOJO_PER_SEVERITY,
        findings: pages.flatMap((p) => p.findings),
      });
    } catch (err) {
      backendFailure(err, res);
    }
  });

  r.get('/graylog', async (_req, res) => {
    try {
      const rt = source<GraylogRuntime>(res, 'graylog');
      const out = await gated('graylog', rt, () =>
        searchMessages(rt, { ...GRAYLOG_EVENTS, fields: [...GRAYLOG_EVENTS.fields], offset: 0, sort_order: 'desc' }),
      );
      // Triggered events/alerts from Graylog's own alerting. The token may lack
      // the events permission, so a failure here is shown in place of the list
      // and never hides the messages above.
      let events: Awaited<ReturnType<typeof searchEvents>> | { error: string };
      try {
        events = await gated('graylog', rt, () =>
          searchEvents(rt, { query: '', range_seconds: GRAYLOG_EVENTS.range_seconds, alerts_only: false, page: 1, per_page: GRAYLOG_ALERTS_LIMIT }),
        );
      } catch (err) {
        events = { error: (res.locals.user as User).role === 'admin' ? errMessage(err) : 'Graylog did not answer this request' };
      }
      res.json({ ...out, rule: GRAYLOG_EVENTS, events });
    } catch (err) {
      backendFailure(err, res);
    }
  });

  return r;
}

/** Backends the Findings page shows, in tab order. */
export const FINDINGS_SOURCES: readonly BackendId[] = ['wazuh', 'trivy', 'defectdojo', 'graylog'];

export type SourceState = 'planned' | 'ready' | 'incomplete' | 'disabled' | 'not-configured';

/**
 * Every data source and why it is (not) usable, so an empty Findings page can
 * say what is missing instead of only "Wazuh is not enabled". Field-level
 * issues are for admins only (they are the ones who can fix them).
 */
export function sourceList(registry: BackendRegistry, admin: boolean) {
  const wazuh = registry.runtime<WazuhClient>('wazuh');
  return BACKENDS.map((mod) => {
    const st = registry.status(mod.id);
    let state: SourceState;
    let issues: string[] = [];
    if (mod.maturity === 'stub') state = 'planned';
    else if (st.enabled && st.configured) {
      state = 'ready';
      if (mod.id === 'wazuh' && wazuh && !wazuh.hasIndexer) {
        state = 'incomplete';
        issues = ['Indexer URL and credentials (needed for vulnerability findings)'];
      }
    } else if (st.enabled) {
      state = 'incomplete';
      issues = st.issues;
    } else state = st.configured ? 'disabled' : 'not-configured';
    // Last scheduled health result, so the page can flag an outage next to the source.
    const rt = state === 'ready' || state === 'incomplete' ? registry.runtime<object>(mod.id) : null;
    const health = rt ? registry.health.peek(rt)?.health.status : undefined;
    return {
      id: mod.id,
      title: mod.title,
      description: mod.description,
      findings: FINDINGS_SOURCES.includes(mod.id),
      state,
      ...(health ? { health } : {}),
      ...(admin ? { issues } : {}),
    };
  });
}
