import { z } from 'zod';
import { errMessage } from '../../log.js';
import { HttpClient } from '../http.js';
import { jsonResult } from '../result.js';
import { defineBackend, toolsFor } from '../types.js';
import { defectdojoHealth } from './health.js';
import { closeFinding, markFalsePositive, riskAcceptFinding } from './writes.js';
import {
  ENGAGEMENT_STATUS,
  getFinding,
  listEndpoints,
  listEngagements,
  listFindings,
  listImports,
  listProducts,
  listTests,
  SEVERITIES,
  slaOverview,
  type DefectDojoRuntime,
} from './queries.js';

/**
 * DefectDojo (open-source edition) over REST API v2: read tools, and three
 * write tools on single findings (writes.ts), off unless allowed.
 * The API uses `Authorization: Token <key>`; queries live in queries.ts.
 */

interface DefectDojoConfig {
  url: string;
  apiKey: string;
  tlsVerify: boolean;
  caCert?: string;
}

const schema = z.object({
  url: z.string().url(),
  apiKey: z.string().min(1),
  tlsVerify: z.boolean().default(true),
  caCert: z
    .string()
    .optional()
    .transform((v) => v?.trim() || undefined),
}) as z.ZodType<DefectDojoConfig>;


const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Use YYYY-MM-DD');

const t = toolsFor<DefectDojoRuntime>();

const tools = [
  t.read({
    name: 'defectdojo_list_findings',
    title: 'List DefectDojo findings',
    description:
      'List DefectDojo findings, most severe and newest first, with product, engagement and test names. ' +
      'Defaults to active findings without duplicates or false positives. Filter by product, engagement, severity, ' +
      'verified state, vulnerability ID (CVE/GHSA), title text and discovery date.',
    inputSchema: {
      product_id: z.number().int().positive().optional().describe('Product ID (see defectdojo_list_products)'),
      product_name: z.string().max(256).optional().describe('Exact product name'),
      engagement_id: z.number().int().positive().optional().describe('Engagement ID (see defectdojo_list_engagements)'),
      severity: z.enum(SEVERITIES).optional(),
      active: z.boolean().default(true).describe('true = open findings only, false = closed only'),
      verified: z.boolean().optional(),
      include_duplicates: z.boolean().default(false),
      include_false_positives: z.boolean().default(false),
      vulnerability_id: z.string().max(64).optional().describe('e.g. CVE-2024-3094'),
      title: z.string().max(256).optional().describe('Text contained in the title'),
      discovered_after: isoDate.optional().describe('YYYY-MM-DD'),
      discovered_before: isoDate.optional().describe('YYYY-MM-DD'),
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listFindings(rt, a)),
  }),

  t.read({
    name: 'defectdojo_get_finding',
    title: 'Get DefectDojo finding',
    description:
      'Full details for one DefectDojo finding: description, mitigation, impact, references, endpoints, CVSS/EPSS and status flags.',
    inputSchema: { finding_id: z.number().int().positive().describe('Finding ID') },
    run: async (rt, a) => {
      const f = await getFinding(rt, a.finding_id);
      return jsonResult(f ?? { error: `No finding with id ${a.finding_id} (or not visible to this API key)` });
    },
  }),

  t.read({
    name: 'defectdojo_list_engagements',
    title: 'List DefectDojo engagements',
    description: 'List DefectDojo engagements, newest target start first. Filter by product, status or name.',
    inputSchema: {
      product_id: z.number().int().positive().optional().describe('Product ID'),
      status: z.enum(ENGAGEMENT_STATUS).optional(),
      name: z.string().max(256).optional().describe('Exact engagement name'),
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listEngagements(rt, a)),
  }),

  t.read({
    name: 'defectdojo_list_products',
    title: 'List DefectDojo products',
    description: 'List DefectDojo products visible to the API key, with IDs, criticality, lifecycle and finding counts.',
    inputSchema: {
      name: z.string().max(256).optional().describe('Text contained in the product name'),
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listProducts(rt, a)),
  }),

  t.read({
    name: 'defectdojo_list_tests',
    title: 'List DefectDojo tests',
    description:
      'List DefectDojo tests (one per scan or manual test), newest first, in an engagement or product. ' +
      'Filter by test type ID or scan type. Optionally adds the number of open findings per test (one extra request per test).',
    inputSchema: {
      engagement_id: z.number().int().positive().optional().describe('Engagement ID (see defectdojo_list_engagements)'),
      product_id: z.number().int().positive().optional().describe('Product ID; tests of its 50 newest engagements'),
      test_type_id: z.number().int().positive().optional().describe('Test type ID'),
      scan_type: z.string().max(256).optional().describe('Exact scan type, e.g. "Trivy Scan"'),
      include_finding_counts: z.boolean().default(false).describe('Add open_findings per test'),
      limit: z.number().int().min(1).max(100).default(25),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listTests(rt, a)),
  }),

  t.read({
    name: 'defectdojo_list_endpoints',
    title: 'List DefectDojo endpoints',
    description:
      'List DefectDojo endpoints (protocol, host, port, path) with their active finding counts, most findings first. ' +
      'Filter by product and exact host name.',
    inputSchema: {
      product_id: z.number().int().positive().optional().describe('Product ID'),
      host: z.string().max(256).optional().describe('Exact host name or IP'),
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listEndpoints(rt, a)),
  }),

  t.read({
    name: 'defectdojo_list_imports',
    title: 'List DefectDojo scan imports',
    description:
      'Recent scan imports and reimports, newest first: when, import or reimport, test and scan type, ' +
      'and how many findings were created, closed, reactivated or left untouched. Filter by test.',
    inputSchema: {
      test_id: z.number().int().positive().optional().describe('Test ID (see defectdojo_list_tests)'),
      limit: z.number().int().min(1).max(50).default(20),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listImports(rt, a)),
  }),

  t.read({
    name: 'defectdojo_sla_overview',
    title: 'DefectDojo SLA overview',
    description:
      'Open findings per severity (active, not duplicate, not false positive) and how many are past their SLA date, ' +
      'for all products or one product, plus the most overdue findings.',
    inputSchema: {
      product_id: z.number().int().positive().optional().describe('Product ID'),
      product_name: z.string().max(256).optional().describe('Exact product name'),
      overdue_limit: z.number().int().min(0).max(50).default(10).describe('Most overdue findings to list; 0 = none'),
    },
    run: async (rt, a) => jsonResult(await slaOverview(rt, a)),
  }),

  t.write({
    name: 'defectdojo_close_finding',
    title: 'Close a DefectDojo finding as mitigated',
    description:
      'Closes one DefectDojo finding as mitigated (inactive, mitigated now). Takes the exact finding ID and a required note ' +
      'saying what fixed it; the note is added to the finding first. Returns the finding state before and after.',
    inputSchema: {
      finding_id: z.number().int().positive().describe('Finding ID from defectdojo_list_findings or defectdojo_get_finding'),
      note: z.string().trim().min(10).max(2000).describe('Why it is closed, e.g. "Fixed by upgrading xz-utils to 5.6.1 in build 812"'),
    },
    run: async (rt, a, ctx) => jsonResult(await closeFinding(rt, a, ctx.userName)),
  }),

  t.write({
    name: 'defectdojo_risk_accept_finding',
    title: 'Risk-accept a DefectDojo finding',
    description:
      'Accepts the risk of one DefectDojo finding: creates a risk acceptance holding that finding, with the required reason as ' +
      'justification and an optional expiry date after which DefectDojo reactivates it. Takes the exact finding ID.',
    inputSchema: {
      finding_id: z.number().int().positive().describe('Finding ID'),
      reason: z.string().trim().min(10).max(2000).describe('Justification for accepting the risk'),
      expiration_date: isoDate.optional().describe('YYYY-MM-DD; the acceptance expires then and the finding is reactivated'),
    },
    run: async (rt, a, ctx) => jsonResult(await riskAcceptFinding(rt, a, ctx.userName)),
  }),

  t.write({
    name: 'defectdojo_mark_false_positive',
    title: 'Mark a DefectDojo finding as false positive',
    description:
      'Marks one DefectDojo finding as a false positive (and inactive, unverified). Takes the exact finding ID and a required ' +
      'reason, which is added to the finding as a note first. Returns the finding state before and after.',
    inputSchema: {
      finding_id: z.number().int().positive().describe('Finding ID'),
      reason: z.string().trim().min(10).max(2000).describe('Why this is not a real issue'),
    },
    run: async (rt, a, ctx) => jsonResult(await markFalsePositive(rt, a, ctx.userName)),
  }),
];

export const defectdojo = defineBackend<DefectDojoConfig, DefectDojoRuntime>({
  id: 'defectdojo',
  title: 'DefectDojo',
  description: 'Vulnerability management: findings, engagements, products, tests, endpoints, imports and SLA (open-source edition).',
  maturity: 'ready',
  schema,
  health: defectdojoHealth,
  guide: {
    intro: 'Reads findings, engagements, products, tests, endpoints, scan imports and SLA status through the REST API v2.',
    items: [
      {
        title: 'DefectDojo URL',
        fields: ['url'],
        steps: ['The address you open DefectDojo on, without a path, e.g. https://defectdojo.example.com.'],
      },
      {
        title: 'API v2 key (read-only user)',
        fields: ['apiKey'],
        steps: [
          'Create a user for SocBridge: Users → Add user. Do not make it superuser or staff.',
          'Give it Reader access: Global role "Reader", or the Reader role on the products it may see.',
          'Sign in as that user → user menu (top right) → API v2 Key → copy the key (the part after "Token ").',
          'Only if you will use the write tools (close, risk-accept, false positive): give that user the Writer role instead, ' +
            'then tick "Allow write tools" below, grant DefectDojo write to the users who need it and create a write-scoped token.',
        ],
        code: 'curl -H "Authorization: Token <key>" https://defectdojo.example.com/api/v2/products/?limit=1',
      },
      {
        title: 'Certificates',
        fields: ['caCert', 'tlsVerify'],
        steps: ['Needed only with a private CA: paste the CA certificate (PEM) that signed the DefectDojo certificate.'],
      },
    ],
    verify: ['Tick Enabled, Save, then Test connection: it should report how many products are visible.'],
    docs: [{ label: 'DefectDojo API v2', url: 'https://docs.defectdojo.com/en/api/api-v2-docs/' }],
  },
  fields: [
    { key: 'url', label: 'DefectDojo URL', type: 'url', required: true, placeholder: 'https://defectdojo.example.com' },
    { key: 'apiKey', label: 'API v2 key', type: 'secret', required: true, help: 'From the user menu → API v2 Key. Use a read-only user.' },
    { key: 'tlsVerify', label: 'Verify TLS certificates', type: 'boolean' },
    { key: 'caCert', label: 'CA certificate (PEM)', type: 'pem' },
  ],
  createRuntime: (cfg) => ({
    http: new HttpClient({ baseUrl: cfg.url, tlsVerify: cfg.tlsVerify, caCert: cfg.caCert }),
    auth: `Token ${cfg.apiKey}`,
  }),
  async testConnection(rt) {
    try {
      const r = await rt.http.request<{ count?: number }>('/api/v2/products/', {
        query: { limit: 1 },
        headers: { authorization: rt.auth },
      });
      return { ok: true, message: `Connected; ${r.count ?? 0} products visible.` };
    } catch (err) {
      return { ok: false, message: errMessage(err) };
    }
  },
  tools,
});
