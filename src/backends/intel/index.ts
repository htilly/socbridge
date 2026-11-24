import { z } from 'zod';
import { CVE_SEVERITIES, normaliseCve, type CveSource } from '../cve.js';
import { jsonResult } from '../result.js';
import { defineBackend, toolsFor, type BackendHealth, type HealthCheck } from '../types.js';
import { DEFAULT_EPSS_URL, DEFAULT_KEV_URL, IntelFeeds, type IntelConfig } from './feeds.js';
import { gather, INVENTORY_TTL_MS, SOURCES } from './gather.js';
import { TIERS } from './correlate.js';
import { fixFirst, investigateTool } from './evidence.js';
import { EPSS_HIGH, EPSS_MEDIUM, filterRanked, PRIORITIES, rankCves, summarise } from './prioritize.js';

/**
 * Threat intelligence: CISA KEV and FIRST EPSS, downloaded in bulk
 * (feeds.ts), joined with the CVEs that Wazuh (hosts), Trivy (images) and
 * DefectDojo (external scans and other imports) report, to rank what to fix
 * first (prioritize.ts).
 *
 * The other backends are read through `ctx.source`, which checks the calling
 * credential's read access to each of them at call time: a token that may
 * not read Wazuh gets a ranking without Wazuh's hosts, and the result says so.
 */

export { gather, INVENTORY_TTL_MS };

const blank = (v: unknown) => v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
const orDefault = <T>(d: T) => (v: unknown) => (blank(v) ? d : v);

const schema = z.object({
  kevUrl: z.preprocess(orDefault(DEFAULT_KEV_URL), z.string().url()),
  epssUrl: z.preprocess(orDefault(DEFAULT_EPSS_URL), z.string().url()),
  refreshHours: z.preprocess(
    (v) => (blank(v) ? 24 : typeof v === 'string' ? Number(v) : v),
    z.number().int('Whole hours').min(1).max(168),
  ),
  exposedProducts: z
    .string()
    .max(4000)
    .optional()
    .transform((v) => v?.trim() || undefined),
  tlsVerify: z.boolean().default(true),
  caCert: z
    .string()
    .optional()
    .transform((v) => v?.trim() || undefined),
}) as unknown as z.ZodType<IntelConfig>;

const RULES =
  `P1: in CISA KEV (exploited in the wild). P2: EPSS ≥ ${EPSS_HIGH}, or Critical/High on an asset seen from the internet. ` +
  `P3: Critical/High, or EPSS ≥ ${EPSS_MEDIUM}. P4: the rest. Within a tier: ransomware use, internet exposure, EPSS, CVSS, affected assets.`;

const t = toolsFor<IntelFeeds>();

const sourcesArg = z
  .array(z.enum(SOURCES))
  .min(1)
  .optional()
  .describe('Backends to take CVEs from (default: all of wazuh, trivy, defectdojo that this credential may read)');

const hoursArg = z.number().int().min(1).max(168).default(24).describe('How far back to look for attacks');

const tools = [
  t.read({
    name: 'intel_investigate',
    title: 'Investigate across backends',
    description:
      'Which services meet several conditions at once: internet-facing, with exploited vulnerabilities, and attacked. Joins Wazuh, ' +
      'Trivy, DefectDojo and Graylog through the service map. The defaults answer "which internet-facing hosts have exploited ' +
      'vulnerabilities and were attacked in the last 24 hours". matches meet every condition; possible would if an unknown were ' +
      'resolved; unmapped are vulnerable assets in no service. Every claim cites evidence with the tool call that shows the record. ' +
      'No matches does not mean no risk: report possible, unmapped and gaps too. Attacked does not mean exploited.',
    inputSchema: {
      hours: hoursArg,
      exposure: z.enum(['internet', 'any']).default('internet'),
      kev_only: z.boolean().default(true).describe('Only known exploited CVEs (CISA KEV). With min_epss: KEV or that score'),
      min_epss: z.number().min(0).max(1).optional().describe('Also CVEs with at least this EPSS score'),
      attack: z
        .enum(['any', 'reached', 'cve_matched', 'none', 'ignore'])
        .default('reached')
        .describe('reached: alerts on the host from public addresses; any: also blocked or scan traffic; cve_matched: an alert names one of its CVEs; none: no attacks seen; ignore: no condition'),
      service: z.string().max(100).optional().describe('Text contained in the service name'),
      limit: z.number().int().min(1).max(100).default(20),
      refresh: z.boolean().default(false),
    },
    run: async (rt, { attack, ...a }, ctx) => jsonResult(await investigateTool(rt, ctx, { ...a, ...(attack === 'ignore' ? {} : { attack }) })),
  }),

  t.read({
    name: 'intel_fix_first',
    title: 'What to fix first, and why',
    description:
      'Ranked remediation actions (update an image, a host package, or fix a scan finding), each with a tier A1–A4, the reasons, ' +
      'a recommendation, the confidence in the evidence and why, the services affected, and the records behind it. Considers CISA ' +
      'KEV, EPSS, internet exposure, attacks seen, and service importance. Use it to answer "what should I fix first". ' +
      'Report confidence and gaps with the answer.',
    inputSchema: {
      hours: hoursArg,
      tier: z.array(z.enum(TIERS)).optional(),
      service: z.string().max(100).optional().describe('Text contained in the service name'),
      fixable_only: z.boolean().default(false).describe('Only actions where a fixed version is reported (images)'),
      attacked_only: z.boolean().default(false).describe('Only services that attack traffic reached'),
      limit: z.number().int().min(1).max(50).default(10),
      offset: z.number().int().min(0).default(0),
      refresh: z.boolean().default(false),
    },
    run: async (rt, a, ctx) => jsonResult(await fixFirst(rt, ctx, a)),
  }),

  t.read({
    name: 'intel_prioritize_cves',
    title: 'Prioritise CVEs by exploitation',
    description:
      'Every open CVE that Wazuh (hosts), Trivy (container images) and DefectDojo (external scans and other imports) report, ' +
      'merged per CVE and ranked by real-world risk: CISA KEV (known exploited), FIRST EPSS (probability of exploitation in ' +
      'the next 30 days), internet exposure, severity and CVSS. Each CVE gets a priority P1–P4 with the reasons, the KEV ' +
      'entry (required action, due date, ransomware use), the affected hosts/images/products with package, installed and ' +
      'fixed version. Use it to answer "what should I fix first". Sources this credential may not read are left out and ' +
      'listed under sources.',
    inputSchema: {
      sources: sourcesArg,
      priority: z.array(z.enum(PRIORITIES)).optional().describe('Only these priorities'),
      kev_only: z.boolean().default(false).describe('Only CVEs in CISA KEV'),
      min_epss: z.number().min(0).max(1).optional().describe('Only CVEs with at least this EPSS score (0–1)'),
      min_severity: z.enum(CVE_SEVERITIES).optional().describe('Only this severity or worse'),
      exposed_only: z.boolean().default(false).describe('Only CVEs on assets seen from the internet'),
      fixable_only: z.boolean().default(false).describe('Only CVEs with a fixed version available'),
      asset: z.string().max(256).optional().describe('Text contained in a host, image or product name'),
      cve: z.string().max(32).optional().describe('One CVE, e.g. CVE-2024-3094'),
      limit: z.number().int().min(1).max(200).default(25),
      offset: z.number().int().min(0).default(0),
      refresh: z.boolean().default(false).describe(`Re-read the sources instead of using results up to ${INVENTORY_TTL_MS / 60_000} minutes old`),
    },
    run: async (rt, a, ctx) => {
      await rt.ensure();
      const g = await gather(rt, ctx, a.sources ?? SOURCES, a.refresh);
      const ranked = rankCves(g.occurrences, rt.kev.data, rt.epss.data);
      const matching = filterRanked(ranked, a);
      return jsonResult({
        rules: RULES,
        feeds: rt.view(),
        sources: g.sources,
        ...(g.notes.length ? { notes: g.notes } : {}),
        summary: summarise(ranked),
        matching: matching.length,
        returned: Math.min(a.limit, Math.max(0, matching.length - a.offset)),
        offset: a.offset,
        cves: matching.slice(a.offset, a.offset + a.limit),
      });
    },
  }),

  t.read({
    name: 'intel_kev_recent',
    title: 'Recently added known exploited CVEs',
    description:
      'CVEs CISA added to the Known Exploited Vulnerabilities catalog in the last N days, newest first: vendor, product, ' +
      'name, required action, due date and ransomware use. Each is marked with where it occurs in your environment (hosts ' +
      'from Wazuh, images from Trivy, products from DefectDojo, as far as this credential may read them). Use it to see ' +
      'which newly exploited vulnerabilities affect you.',
    inputSchema: {
      days: z.number().int().min(1).max(365).default(30).describe('How far back, by KEV date added'),
      affecting_only: z.boolean().default(false).describe('Only entries found in your environment'),
      sources: sourcesArg,
      limit: z.number().int().min(1).max(200).default(50),
      refresh: z.boolean().default(false),
    },
    run: async (rt, a, ctx) => {
      await rt.ensure();
      const kev = rt.kev.data;
      if (!kev) return jsonResult({ feeds: rt.view(), error: 'The KEV catalog is not available; see feeds.kev' });
      const since = new Date(Date.now() - a.days * 86_400_000).toISOString().slice(0, 10);
      const g = await gather(rt, ctx, a.sources ?? SOURCES, a.refresh);
      const where = new Map<string, Map<string, { source: CveSource; asset: string; ref?: string }>>();
      for (const o of g.occurrences) {
        let m = where.get(o.cve);
        if (!m) where.set(o.cve, (m = new Map()));
        m.set(`${o.source}\u0000${o.asset}`, { source: o.source, asset: o.asset, ...(o.ref ? { ref: o.ref } : {}) });
      }
      const recent = [...kev.entries.values()]
        .filter((e) => (e.date_added ?? '') >= since)
        .sort((x, y) => (y.date_added ?? '').localeCompare(x.date_added ?? '') || x.cve.localeCompare(y.cve))
        .map((e) => {
          const found = [...(where.get(e.cve)?.values() ?? [])];
          const ep = rt.epss.data?.get(e.cve);
          return { ...e, ...(ep ? { epss: ep } : {}), affects_you: found.length > 0, found_in: found };
        });
      const list = a.affecting_only ? recent.filter((e) => e.affects_you) : recent;
      return jsonResult({
        feeds: rt.view(),
        since,
        sources: g.sources,
        ...(g.notes.length ? { notes: g.notes } : {}),
        added: recent.length,
        affecting_you: recent.filter((e) => e.affects_you).length,
        returned: Math.min(a.limit, list.length),
        entries: list.slice(0, a.limit),
      });
    },
  }),

  t.read({
    name: 'intel_cve_lookup',
    title: 'Look up CVEs in KEV and EPSS',
    description:
      'For up to 200 CVE IDs: whether each is in CISA KEV (with required action, due date and ransomware use) and its ' +
      'FIRST EPSS score and percentile. Uses the downloaded feeds only; nothing about the CVEs is sent anywhere.',
    inputSchema: {
      cves: z.array(z.string().max(32)).min(1).max(200).describe('CVE IDs, e.g. ["CVE-2024-3094"]'),
    },
    run: async (rt, a) => {
      await rt.ensure();
      const results = [...new Set(a.cves.map((c) => c.trim().toUpperCase()))].map((raw) => {
        const cve = normaliseCve(raw);
        if (!cve) return { cve: raw, error: 'Not a CVE ID (CVE-YYYY-NNNN)' };
        const k = rt.kev.data?.entries.get(cve);
        const e = rt.epss.data?.get(cve);
        return { cve, in_kev: !!k, ...(k ? { kev: k } : {}), ...(e ? { epss: e } : { epss: null }) };
      });
      return jsonResult({ feeds: rt.view(), results });
    },
  }),
];

function feedCheck(rt: IntelFeeds, which: 'kev' | 'epss'): HealthCheck {
  const s = rt[which];
  const label = which === 'kev' ? 'CISA KEV' : 'FIRST EPSS';
  if (!s.data) {
    if (rt.loading(which)) return { name: which, status: 'degraded', message: `${label}: downloading` };
    return { name: which, status: 'down', message: `${label}: ${s.error ?? 'not downloaded yet'}` };
  }
  const age = s.fetchedAt ? `fetched ${new Date(s.fetchedAt).toISOString()}` : '';
  const what =
    which === 'kev'
      ? `catalog ${rt.kev.data!.version ?? '?'}, ${rt.kev.data!.entries.size} CVEs`
      : `scores of ${rt.epss.data!.scoreDate?.slice(0, 10) ?? '?'}, ${rt.epss.data!.size} CVEs`;
  if (!rt.fresh(which)) return { name: which, status: 'degraded', message: `${label}: stale (${what}, ${age}); ${s.error ?? 'refresh pending'}` };
  return { name: which, status: 'ok', message: `${label}: ${what}, ${age}${s.error ? `; last refresh failed: ${s.error}` : ''}` };
}

/** Feeds download in the background so the scheduled check stays fast; one feed missing is degraded, both is down. */
export function intelHealth(rt: IntelFeeds): BackendHealth {
  rt.refreshInBackground();
  const checks = [feedCheck(rt, 'kev'), feedCheck(rt, 'epss')];
  const down = checks.filter((c) => c.status === 'down').length;
  const status = down === checks.length ? 'down' : down || checks.some((c) => c.status === 'degraded') ? 'degraded' : 'ok';
  return { status, checks };
}

export const intel = defineBackend<IntelConfig, IntelFeeds>({
  id: 'intel',
  title: 'Threat intel',
  description:
    'CISA KEV and FIRST EPSS, joined with the CVEs from Wazuh, Trivy and DefectDojo to rank what to fix first and to show newly exploited CVEs that affect you.',
  maturity: 'ready',
  schema,
  health: async (rt) => intelHealth(rt),
  guide: {
    intro:
      'Downloads two public feeds and uses them to rank the CVEs the other backends report: CISA KEV (vulnerabilities ' +
      'known to be exploited) and FIRST EPSS (how likely a CVE is to be exploited in the next 30 days). The feeds are ' +
      'fetched as whole files, so which CVEs you have is never sent anywhere.',
    before: [
      'SocBridge needs outbound HTTPS to www.cisa.gov and epss.empiricalsecurity.com, or to a mirror you set below.',
      'Enable at least one of Wazuh (with the indexer), Trivy and DefectDojo; intel reads their CVEs with the caller’s own read access.',
      'Existing access tokens and connected apps do not include Threat intel: edit their scope to add it.',
    ],
    items: [
      {
        title: 'Feed URLs (optional)',
        fields: ['kevUrl', 'epssUrl'],
        steps: [
          'Leave empty for the official feeds.',
          'For a network without internet access, mirror the two files on an internal web server and enter its URLs. ' +
            'The EPSS file may be gzipped or plain CSV.',
        ],
      },
      {
        title: 'Refresh interval',
        fields: ['refreshHours'],
        steps: ['Hours between downloads; empty means 24. CISA updates KEV on working days, EPSS is published daily.'],
      },
      {
        title: 'Internet-facing DefectDojo products',
        fields: ['exposedProducts'],
        steps: [
          'Names of the DefectDojo products whose findings come from scans of what is reachable from the internet, comma separated. ',
          'CVEs found there rank higher (Critical/High becomes P2).',
        ],
      },
      {
        title: 'Certificates (mirror only)',
        fields: ['caCert', 'tlsVerify'],
        steps: ['Only for an internal mirror with a private CA. A CA set here replaces the public roots, so the official feeds stop working.'],
      },
    ],
    verify: [
      'Tick Enabled, Save, then Test connection: it downloads both feeds and reports their size and date.',
      'Ask for intel_prioritize_cves; under sources, every backend you expect should say ok.',
    ],
    docs: [
      { label: 'CISA KEV catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
      { label: 'FIRST EPSS', url: 'https://www.first.org/epss/' },
    ],
  },
  fields: [
    { key: 'kevUrl', label: 'KEV feed URL', type: 'url', placeholder: DEFAULT_KEV_URL, help: 'Empty: the official CISA feed.' },
    { key: 'epssUrl', label: 'EPSS feed URL', type: 'url', placeholder: DEFAULT_EPSS_URL, help: 'Empty: the official EPSS file (gzipped CSV).' },
    { key: 'refreshHours', label: 'Refresh interval (hours)', type: 'number', placeholder: '24' },
    {
      key: 'exposedProducts',
      label: 'Internet-facing DefectDojo products',
      type: 'string',
      placeholder: 'External attack surface',
      help: 'Comma separated product names. CVEs found in them count as seen from the internet.',
    },
    { key: 'tlsVerify', label: 'Verify TLS certificates', type: 'boolean' },
    { key: 'caCert', label: 'CA certificate for a mirror (PEM)', type: 'pem' },
  ],
  createRuntime: (cfg) => new IntelFeeds(cfg),
  async testConnection(rt) {
    await rt.ensure();
    const h = intelHealth(rt);
    return { ok: h.status !== 'down', message: h.checks.map((c) => c.message).join(' · ') };
  },
  tools,
});
