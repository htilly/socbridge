import { isPublicIp, normaliseCve, normaliseSeverity, type CveInventory, type CveOccurrence, type SeenEndpoint } from '../cve.js';
import { BackendError, type HttpClient } from '../http.js';

/**
 * DefectDojo read queries against REST API v2 (open-source edition).
 * List endpoints are paginated with limit/offset and return
 * `{ count, next, previous, results }`.
 */

export interface DefectDojoRuntime {
  http: HttpClient;
  auth: string;
}

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ENGAGEMENT_STATUS = [
  'Not Started',
  'Blocked',
  'Cancelled',
  'Completed',
  'In Progress',
  'On Hold',
  'Scheduled',
  'Waiting for Resource',
] as const;

interface Page<T> {
  count?: number;
  results?: T[];
}

type Obj = Record<string, unknown>;

/** Long free-text fields are capped so one finding cannot fill the model context. */
const MAX_TEXT = 4000;

function get<T>(rt: DefectDojoRuntime, p: string, query?: Record<string, string | number | boolean | undefined>) {
  return rt.http.request<T>(p, { query, headers: { authorization: rt.auth } });
}

function cap(v: unknown): unknown {
  if (typeof v !== 'string' || v.length <= MAX_TEXT) return v;
  return v.slice(0, MAX_TEXT) + ` … [truncated ${v.length - MAX_TEXT} characters]`;
}

function pick(o: Obj, keys: readonly string[]): Obj {
  const out: Obj = {};
  for (const k of keys) if (o[k] !== undefined && o[k] !== null && o[k] !== '') out[k] = o[k];
  return out;
}

function vulnIds(f: Obj): string[] {
  const ids = Array.isArray(f.vulnerability_ids) ? (f.vulnerability_ids as Obj[]).map((v) => v.vulnerability_id) : [];
  return ids.filter((v): v is string => typeof v === 'string');
}

/** Product and engagement names from `?related_fields=true` (test → engagement → product). */
function related(f: Obj): Obj {
  const test = (f.related_fields as Obj | undefined)?.test as Obj | undefined;
  const eng = test?.engagement as Obj | undefined;
  const prod = eng?.product as Obj | undefined;
  return pick(
    {
      product_id: prod?.id,
      product_name: prod?.name,
      engagement_id: eng?.id,
      engagement_name: eng?.name,
      test_id: test?.id ?? f.test,
      test_title: test?.title,
      test_type: (test?.test_type as Obj | undefined)?.name,
    },
    ['product_id', 'product_name', 'engagement_id', 'engagement_name', 'test_id', 'test_title', 'test_type'],
  );
}

const FINDING_SUMMARY = [
  'id',
  'title',
  'severity',
  'cvssv3_score',
  'cwe',
  'active',
  'verified',
  'false_p',
  'duplicate',
  'risk_accepted',
  'is_mitigated',
  'out_of_scope',
  'date',
  'sla_expiration_date',
  'component_name',
  'component_version',
  'file_path',
  'line',
  'tags',
] as const;

const FINDING_DETAIL = [
  ...FINDING_SUMMARY,
  'cvssv3',
  'epss_score',
  'epss_percentile',
  'known_exploited',
  'mitigated',
  'last_status_update',
  'found_by',
  'service',
  'unique_id_from_tool',
  'vuln_id_from_tool',
  'endpoints',
  'description',
  'mitigation',
  'impact',
  'references',
  'steps_to_reproduce',
  'severity_justification',
] as const;

function summariseFinding(f: Obj): Obj {
  return { ...pick(f, FINDING_SUMMARY), vulnerability_ids: vulnIds(f), ...related(f) };
}

export interface ListFindingsInput {
  product_id?: number;
  product_name?: string;
  engagement_id?: number;
  severity?: Severity;
  active?: boolean;
  verified?: boolean;
  include_duplicates: boolean;
  include_false_positives: boolean;
  vulnerability_id?: string;
  title?: string;
  discovered_after?: string;
  discovered_before?: string;
  limit: number;
  offset: number;
}

export async function listFindings(rt: DefectDojoRuntime, a: ListFindingsInput) {
  const r = await get<Page<Obj>>(rt, '/api/v2/findings/', {
    test__engagement__product: a.product_id,
    product_name: a.product_name,
    test__engagement: a.engagement_id,
    severity: a.severity,
    active: a.active,
    verified: a.verified,
    duplicate: a.include_duplicates ? undefined : false,
    false_p: a.include_false_positives ? undefined : false,
    vulnerability_id: a.vulnerability_id,
    title: a.title,
    discovered_after: a.discovered_after,
    discovered_before: a.discovered_before,
    related_fields: true,
    o: 'numerical_severity,-date',
    limit: a.limit,
    offset: a.offset,
  });
  const results = r.results ?? [];
  return {
    total: r.count ?? results.length,
    returned: results.length,
    offset: a.offset,
    findings: results.map(summariseFinding),
  };
}

export async function getFinding(rt: DefectDojoRuntime, id: number) {
  try {
    const f = await get<Obj>(rt, `/api/v2/findings/${id}/`, { related_fields: true });
    const out: Obj = { ...pick(f, FINDING_DETAIL), vulnerability_ids: vulnIds(f), ...related(f) };
    for (const k of Object.keys(out)) out[k] = cap(out[k]);
    return out;
  } catch (err) {
    if (err instanceof BackendError && err.status === 404) return null;
    throw err;
  }
}

const ENGAGEMENT_FIELDS = [
  'id',
  'name',
  'product',
  'status',
  'engagement_type',
  'target_start',
  'target_end',
  'active',
  'version',
  'branch_tag',
  'build_id',
  'commit_hash',
  'lead',
  'tags',
  'updated',
  'created',
] as const;

export interface ListEngagementsInput {
  product_id?: number;
  status?: (typeof ENGAGEMENT_STATUS)[number];
  name?: string;
  limit: number;
  offset: number;
}

export async function listEngagements(rt: DefectDojoRuntime, a: ListEngagementsInput) {
  const r = await get<Page<Obj>>(rt, '/api/v2/engagements/', {
    product: a.product_id,
    status: a.status,
    name: a.name,
    o: '-target_start',
    limit: a.limit,
    offset: a.offset,
  });
  const results = r.results ?? [];
  return {
    total: r.count ?? results.length,
    returned: results.length,
    offset: a.offset,
    engagements: results.map((e) => pick(e, ENGAGEMENT_FIELDS)),
  };
}

const PRODUCT_FIELDS = [
  'id',
  'name',
  'description',
  'prod_type',
  'business_criticality',
  'platform',
  'lifecycle',
  'origin',
  'findings_count',
  'tags',
  'created',
] as const;

export interface ListProductsInput {
  name?: string;
  limit: number;
  offset: number;
}

export async function listProducts(rt: DefectDojoRuntime, a: ListProductsInput) {
  const r = await get<Page<Obj>>(rt, '/api/v2/products/', {
    name: a.name,
    o: 'name',
    limit: a.limit,
    offset: a.offset,
  });
  const results = r.results ?? [];
  return {
    total: r.count ?? results.length,
    returned: results.length,
    offset: a.offset,
    products: results.map((p) => {
      const out = pick(p, PRODUCT_FIELDS);
      if ('description' in out) out.description = cap(out.description);
      return out;
    }),
  };
}

/** Runs `fn` over `items` with at most `n` requests in flight, keeping order. */
async function mapLimit<T, R>(items: readonly T[], n: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

/** Filters that make a findings query mean "open": active, not duplicate, not false positive. */
const OPEN_FINDINGS = { active: true, duplicate: false, false_p: false } as const;

async function countFindings(rt: DefectDojoRuntime, query: Record<string, string | number | boolean | undefined>) {
  const r = await get<Page<Obj>>(rt, '/api/v2/findings/', { ...query, limit: 1 });
  return r.count ?? 0;
}

const TEST_FIELDS = [
  'id',
  'title',
  'engagement',
  'test_type',
  'test_type_name',
  'scan_type',
  'target_start',
  'target_end',
  'percent_complete',
  'version',
  'branch_tag',
  'build_id',
  'commit_hash',
  'tags',
  'created',
  'updated',
] as const;

/** Engagements fanned out to when tests are listed per product (API v2 has no product filter on tests). */
const MAX_PRODUCT_ENGAGEMENTS = 50;

export interface ListTestsInput {
  engagement_id?: number;
  product_id?: number;
  test_type_id?: number;
  scan_type?: string;
  include_finding_counts: boolean;
  limit: number;
  offset: number;
}

export async function listTests(rt: DefectDojoRuntime, a: ListTestsInput) {
  const filters = { test_type: a.test_type_id, scan_type: a.scan_type, o: '-created' };
  let total: number;
  let tests: Obj[];
  const note: Obj = {};
  if (a.product_id !== undefined && a.engagement_id === undefined) {
    // /tests/ only filters by engagement, so collect the product's engagements and merge their tests.
    const e = await get<Page<Obj>>(rt, '/api/v2/engagements/', {
      product: a.product_id,
      o: '-target_start',
      limit: MAX_PRODUCT_ENGAGEMENTS,
    });
    const engIds = (e.results ?? []).map((x) => x.id).filter((v): v is number => typeof v === 'number');
    if ((e.count ?? engIds.length) > engIds.length) {
      note.note = `Product has ${e.count} engagements; only tests in the ${engIds.length} newest were listed.`;
    }
    const pages = await mapLimit(engIds, 5, (id) =>
      get<Page<Obj>>(rt, '/api/v2/tests/', { ...filters, engagement: id, limit: a.offset + a.limit }),
    );
    total = pages.reduce((n, p) => n + (p.count ?? p.results?.length ?? 0), 0);
    tests = pages
      .flatMap((p) => p.results ?? [])
      .sort((x, y) => String(y.created ?? '').localeCompare(String(x.created ?? '')))
      .slice(a.offset, a.offset + a.limit);
  } else {
    const r = await get<Page<Obj>>(rt, '/api/v2/tests/', {
      ...filters,
      engagement: a.engagement_id,
      limit: a.limit,
      offset: a.offset,
    });
    tests = r.results ?? [];
    total = r.count ?? tests.length;
  }
  const out = tests.map((t) => pick(t, TEST_FIELDS));
  if (a.include_finding_counts) {
    const counts = await mapLimit(out, 5, (t) => countFindings(rt, { ...OPEN_FINDINGS, test: t.id as number }));
    out.forEach((t, i) => (t.open_findings = counts[i]));
  }
  return { total, returned: out.length, offset: a.offset, ...note, tests: out };
}

const ENDPOINT_FIELDS = [
  'id',
  'protocol',
  'host',
  'port',
  'path',
  'query',
  'product',
  'active_finding_count',
  'mitigated',
  'tags',
] as const;

export interface ListEndpointsInput {
  product_id?: number;
  host?: string;
  limit: number;
  offset: number;
}

export async function listEndpoints(rt: DefectDojoRuntime, a: ListEndpointsInput) {
  const query = { product: a.product_id, host: a.host, limit: a.limit, offset: a.offset };
  let r: Page<Obj>;
  try {
    r = await get<Page<Obj>>(rt, '/api/v2/endpoints/', { ...query, o: '-active_finding_count' });
  } catch (err) {
    // Older DefectDojo releases do not have active_finding_count and reject ordering by it.
    if (!(err instanceof BackendError && err.status === 400)) throw err;
    r = await get<Page<Obj>>(rt, '/api/v2/endpoints/', { ...query, o: 'host' });
  }
  const results = r.results ?? [];
  return {
    total: r.count ?? results.length,
    returned: results.length,
    offset: a.offset,
    endpoints: results.map((e) => pick(e, ENDPOINT_FIELDS)),
  };
}

/** Test_Import_Finding_Action.action codes. */
const IMPORT_ACTIONS: Record<string, string> = { N: 'created', C: 'closed', R: 'reactivated', U: 'untouched' };

const IMPORT_SETTINGS = ['active', 'verified', 'minimum_severity', 'close_old_findings', 'scan_date', 'service', 'tags'] as const;

export interface ListImportsInput {
  test_id?: number;
  limit: number;
  offset: number;
}

export async function listImports(rt: DefectDojoRuntime, a: ListImportsInput) {
  const r = await get<Page<Obj> & { prefetch?: { test?: Record<string, Obj> } }>(rt, '/api/v2/test_imports/', {
    test: a.test_id,
    prefetch: 'test',
    o: '-created',
    limit: a.limit,
    offset: a.offset,
  });
  const results = r.results ?? [];
  const tests = r.prefetch?.test ?? {};
  return {
    total: r.count ?? results.length,
    returned: results.length,
    offset: a.offset,
    imports: results.map((i): Obj => {
      const findings: Record<string, number> = { created: 0, closed: 0, reactivated: 0, untouched: 0 };
      const actions = Array.isArray(i.test_import_finding_action_set) ? (i.test_import_finding_action_set as Obj[]) : [];
      for (const act of actions) {
        const k = IMPORT_ACTIONS[String(act.action)];
        if (k) findings[k]!++;
      }
      const t = tests[String(i.test)];
      const settings = i.import_settings && typeof i.import_settings === 'object' ? (i.import_settings as Obj) : {};
      return {
        ...pick(
          {
            id: i.id,
            created: i.created,
            type: i.type,
            test_id: i.test,
            test_title: t?.title,
            scan_type: t?.scan_type ?? t?.test_type_name,
            engagement_id: t?.engagement,
            version: i.version,
            branch_tag: i.branch_tag,
            build_id: i.build_id,
            commit_hash: i.commit_hash,
          },
          ['id', 'created', 'type', 'test_id', 'test_title', 'scan_type', 'engagement_id', 'version', 'branch_tag', 'build_id', 'commit_hash'],
        ),
        findings,
        settings: pick(settings, IMPORT_SETTINGS),
      };
    }),
  };
}

export interface SlaOverviewInput {
  product_id?: number;
  product_name?: string;
  overdue_limit: number;
}

/**
 * Open findings per severity and how many are past their SLA date
 * (`outside_of_sla=1`: active, not mitigated/accepted/out of scope, `sla_expiration_date` before today).
 */
export async function slaOverview(rt: DefectDojoRuntime, a: SlaOverviewInput) {
  const scope = { test__engagement__product: a.product_id, product_name: a.product_name };
  const rows = await mapLimit(SEVERITIES, 5, async (severity) => {
    const [open, breached] = await Promise.all([
      countFindings(rt, { ...scope, ...OPEN_FINDINGS, severity }),
      countFindings(rt, { ...scope, ...OPEN_FINDINGS, severity, outside_of_sla: 1 }),
    ]);
    return { severity, open, breached };
  });
  const out: Obj = {
    scope: pick({ product_id: a.product_id, product_name: a.product_name }, ['product_id', 'product_name']),
    total_open: rows.reduce((n, r) => n + r.open, 0),
    total_breached: rows.reduce((n, r) => n + r.breached, 0),
    by_severity: rows,
  };
  if (a.overdue_limit > 0) {
    const r = await get<Page<Obj>>(rt, '/api/v2/findings/', {
      ...scope,
      ...OPEN_FINDINGS,
      outside_of_sla: 1,
      related_fields: true,
      o: 'sla_expiration_date',
      limit: a.overdue_limit,
    });
    out.most_overdue = (r.results ?? []).map((f) =>
      pick(
        { ...pick(f, ['id', 'title', 'severity', 'sla_expiration_date', 'sla_days_remaining', 'date']), ...related(f) },
        ['id', 'title', 'severity', 'sla_expiration_date', 'sla_days_remaining', 'date', 'product_name', 'engagement_name'],
      ),
    );
  }
  return out;
}

// ── CVE inventory for cross-backend tools (intel) ───────────────────────────

const CVE_PAGE = 500;
/** Stop after this many findings in total; the result says it was cut short. */
export const MAX_CVE_FINDINGS = 20_000;

export interface CveOccurrenceOptions {
  /** Leave out findings imported from Trivy scans (when the Trivy backend reports the same images). */
  skipScanTypes?: string[];
  /** Product names (case-insensitive) whose findings are seen from the internet. */
  exposedProducts?: string[];
  max?: number;
}

/**
 * Open CVE findings (active, not duplicate, not false positive) per product,
 * as occurrences for the intel module. Fetched per product so each finding
 * carries its product name without `related_fields`; findings whose test
 * type is in `skipScanTypes` are left out (matched through `found_by`).
 */
export async function cveOccurrences(rt: DefectDojoRuntime, o: CveOccurrenceOptions = {}): Promise<CveInventory> {
  const max = o.max ?? MAX_CVE_FINDINGS;
  const exposed = new Set((o.exposedProducts ?? []).map((p) => p.trim().toLowerCase()).filter(Boolean));

  const skipTypes = new Set<number>();
  for (const name of o.skipScanTypes ?? []) {
    const r = await get<Page<Obj>>(rt, '/api/v2/test_types/', { name, limit: 10 });
    for (const t of r.results ?? []) if (typeof t.id === 'number' && t.name === name) skipTypes.add(t.id);
  }

  const products: { id: number; name: string }[] = [];
  for (let offset = 0; ; offset += 200) {
    const r = await get<Page<Obj>>(rt, '/api/v2/products/', { limit: 200, offset });
    for (const p of r.results ?? []) if (typeof p.id === 'number') products.push({ id: p.id, name: String(p.name ?? `product ${p.id}`) });
    if ((r.results ?? []).length < 200) break;
  }

  // Where findings were seen. Optional: a failure here must not hide the findings.
  const exposedIds = new Set(products.filter((x) => exposed.has(x.name.toLowerCase())).map((x) => x.id));
  const endpointById = new Map<number, SeenEndpoint>();
  const gaps: string[] = [];
  try {
    for (let offset = 0; ; offset += 200) {
      const r = await get<Page<Obj>>(rt, '/api/v2/endpoints/', { limit: 200, offset });
      for (const e of r.results ?? []) {
        if (typeof e.id !== 'number' || typeof e.host !== 'string' || !e.host || e.mitigated === true) continue;
        const host = e.host.toLowerCase();
        endpointById.set(e.id, {
          host,
          ...(typeof e.port === 'number' ? { port: e.port } : {}),
          external: exposedIds.has(e.product as number) || isPublicIp(host),
        });
      }
      if ((r.results ?? []).length < 200) break;
      if (offset >= MAX_CVE_FINDINGS) {
        gaps.push(`DefectDojo: stopped after ${MAX_CVE_FINDINGS} endpoints`);
        break;
      }
    }
  } catch (err) {
    gaps.push(`DefectDojo: endpoints could not be read (${err instanceof Error ? err.message : String(err)})`);
  }
  const extra = { endpoints: [...endpointById.values()], ...(gaps.length ? { gaps } : {}) };

  const occurrences: CveOccurrence[] = [];
  let seen = 0;
  let skipped = 0;
  for (const p of products) {
    for (let offset = 0; ; offset += CVE_PAGE) {
      if (seen >= max) return { occurrences, truncated: `DefectDojo: stopped after ${max} findings`, ...skippedNote(skipped), ...extra };
      const limit = Math.min(CVE_PAGE, max - seen);
      const r = await get<Page<Obj>>(rt, '/api/v2/findings/', {
        test__engagement__product: p.id,
        active: true,
        duplicate: false,
        false_p: false,
        limit,
        offset,
      });
      const results = r.results ?? [];
      seen += results.length;
      for (const f of results) {
        const foundBy = Array.isArray(f.found_by) ? (f.found_by as unknown[]) : [];
        if (skipTypes.size && foundBy.some((id) => skipTypes.has(id as number))) {
          skipped++;
          continue;
        }
        const cves = [...new Set(vulnIds(f).map(normaliseCve).filter((c): c is string => !!c))];
        const cvss = typeof f.cvssv3_score === 'number' ? f.cvssv3_score : undefined;
        const at = (Array.isArray(f.endpoints) ? (f.endpoints as unknown[]) : []).flatMap((id) => endpointById.get(id as number) ?? []);
        for (const cve of cves) {
          occurrences.push({
            cve,
            source: 'defectdojo',
            asset: p.name,
            ref: `finding ${String(f.id)}`,
            ...(typeof f.component_name === 'string' && f.component_name ? { package: f.component_name } : {}),
            ...(typeof f.component_version === 'string' && f.component_version ? { installed: f.component_version } : {}),
            severity: normaliseSeverity(f.severity),
            ...(cvss !== undefined ? { cvss } : {}),
            ...(exposed.has(p.name.toLowerCase()) ? { exposed: true } : {}),
            ...(at.length ? { endpoints: at } : {}),
          });
        }
      }
      if (results.length < limit) break;
    }
  }
  return { occurrences, ...skippedNote(skipped), ...extra };
}

function skippedNote(n: number): { notes?: string[] } {
  return n ? { notes: [`DefectDojo: ${n} finding(s) from Trivy imports left out; the Trivy backend reports the same images`] } : {};
}
