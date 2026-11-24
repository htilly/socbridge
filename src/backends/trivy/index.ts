import { z } from 'zod';
import { errMessage } from '../../log.js';
import { jsonResult } from '../result.js';
import { defineBackend, toolsFor } from '../types.js';
import { trivyHealth } from './health.js';
import { artifactHistory, findCve, listReports, reportFindings, SEVERITIES, TrivyReports } from './reports.js';

/**
 * Trivy, read-only tools over JSON reports.
 *
 * Trivy has no query API of its own: `trivy server` only serves the
 * vulnerability DB to Trivy clients. SocBridge therefore reads JSON reports
 * (`trivy image|fs --format json --output …`) that a scheduled scan job
 * writes to a directory shared with this service, read-only. Parsing lives in
 * reports.ts.
 *
 * Running scans on demand from an MCP tool is deliberately out of scope: it
 * would require Docker socket or registry access from this service.
 */

interface TrivyConfig {
  reportsDir: string;
}

const schema = z.object({
  reportsDir: z.string().min(1).startsWith('/', 'Must be an absolute path inside the container'),
}) as z.ZodType<TrivyConfig>;

const t = toolsFor<TrivyReports>();

const tools = [
  t.read({
    name: 'trivy_list_reports',
    title: 'List Trivy reports',
    description:
      'List Trivy scan reports (one per container image or filesystem), newest scan first, with artifact name, OS, ' +
      'scan time and vulnerability counts by severity. Reports in subdirectories are included (file is the relative path). ' +
      'Use the file name or artifact with trivy_report_findings, and trivy_artifact_history for changes across scans.',
    inputSchema: {
      artifact: z.string().max(256).optional().describe('Text contained in the artifact (image) name or file name'),
      latest_only: z.boolean().default(false).describe('Only the newest report per artifact (name + type), with the number of scans'),
      limit: z.number().int().min(1).max(500).default(100),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await listReports(rt, a)),
  }),

  t.read({
    name: 'trivy_report_findings',
    title: 'Trivy report findings',
    description:
      'Vulnerabilities in one Trivy report, most severe and highest CVSS first: CVE, package, installed and fixed version, ' +
      'target (OS layer or lockfile). Filter by severity, package or fixable only. Optionally include misconfigurations ' +
      'and secret findings (rule, file and line only; secret values are never returned).',
    inputSchema: {
      report: z.string().min(1).max(512).describe('Report file name or exact artifact name (see trivy_list_reports)'),
      severity: z.array(z.enum(SEVERITIES)).optional().describe('Only these severities'),
      fixable_only: z.boolean().default(false).describe('Only vulnerabilities with a fixed version available'),
      package: z.string().max(256).optional().describe('Text contained in the package name'),
      include_misconfigurations: z.boolean().default(false),
      include_secrets: z.boolean().default(false),
      limit: z.number().int().min(1).max(500).default(100),
      offset: z.number().int().min(0).default(0),
    },
    run: async (rt, a) => jsonResult(await reportFindings(rt, a)),
  }),

  t.read({
    name: 'trivy_artifact_history',
    title: 'Trivy artifact history',
    description:
      'All scans of one image or filesystem (reports with the same artifact name and type), oldest first, with ' +
      'vulnerability counts by severity per scan; and between the latest two scans (or the two chosen with from/to) ' +
      'which vulnerability IDs were fixed and which are new, with severity and packages.',
    inputSchema: {
      artifact: z.string().min(1).max(256).describe('Artifact name (exact, or a unique part of it), e.g. nginx:1.27'),
      artifact_type: z.string().max(64).optional().describe('e.g. container_image or filesystem, when two artifacts share a name'),
      from: z.string().max(512).optional().describe('Older scan to compare: report file or created_at (default: second-latest)'),
      to: z.string().max(512).optional().describe('Newer scan to compare: report file or created_at (default: latest)'),
      limit: z.number().int().min(1).max(500).default(100).describe('Max fixed and new entries listed each'),
    },
    run: async (rt, a) => jsonResult(await artifactHistory(rt, a)),
  }),

  t.read({
    name: 'trivy_find_cve',
    title: 'Find CVE in Trivy reports',
    description:
      'Search every Trivy report for one vulnerability ID (CVE, GHSA, …): which images or filesystems are affected, ' +
      'through which package and version, and whether a fix exists. Includes the vulnerability title, severity and CVSS.',
    inputSchema: {
      vulnerability_id: z.string().min(3).max(64).describe('e.g. CVE-2024-3094'),
      limit: z.number().int().min(1).max(500).default(200),
    },
    run: async (rt, a) => jsonResult(await findCve(rt, a)),
  }),
];

export const trivy = defineBackend<TrivyConfig, TrivyReports>({
  id: 'trivy',
  title: 'Trivy',
  description: 'Container image and filesystem scan results, read from Trivy JSON reports.',
  maturity: 'ready',
  schema,
  health: trivyHealth,
  guide: {
    intro:
      'Trivy has no query API, so SocBridge reads the JSON reports that a scheduled scan writes to a shared directory, ' +
      'one file per image or filesystem.',
    items: [
      {
        title: 'A scan job that writes JSON reports',
        steps: ['Run Trivy on a schedule (cron, CI) and write one JSON file per image or filesystem into a directory on the host.'],
        code: 'trivy image --format json --output /srv/trivy-reports/nginx.json nginx:latest',
      },
      {
        title: 'Mount the directory into SocBridge (read-only)',
        steps: ['Add a volume to the socbridge service in docker-compose.yml and recreate the container.'],
        code: 'volumes:\n  - /srv/trivy-reports:/reports/trivy:ro',
      },
      {
        title: 'Report directory',
        fields: ['reportsDir'],
        steps: [
          'The path inside the container, e.g. /reports/trivy. .json files in it and in subdirectories (up to 6 levels, 5000 files) are read; ' +
            'symlinks that lead outside it are ignored. Keep several scans of one image (e.g. one folder per day) to get history.',
        ],
      },
    ],
    verify: ['Tick Enabled, Save, then Test connection: it should report how many reports it found and could read.'],
    docs: [{ label: 'Trivy JSON report format', url: 'https://trivy.dev/latest/docs/configuration/reporting/' }],
  },
  fields: [
    {
      key: 'reportsDir',
      label: 'Report directory',
      type: 'string',
      required: true,
      placeholder: '/reports/trivy',
      help: 'Directory (mounted read-only) containing Trivy JSON reports.',
    },
  ],
  createRuntime: (cfg) => new TrivyReports(cfg.reportsDir),
  async testConnection(rt) {
    try {
      const entries = await rt.all();
      if (entries.length === 0) return { ok: true, message: 'Directory is readable but contains no .json reports yet.' };
      const bad = entries.flatMap((e) => ('error' in e ? [`${e.file}: ${e.error}`] : []));
      const ok = entries.length - bad.length;
      if (ok === 0) return { ok: false, message: `Found ${entries.length} JSON file(s), none readable as a Trivy report. ${bad[0]}` };
      const vulns = entries.reduce((n, e) => n + ('report' in e ? e.report.vulnerabilities.length : 0), 0);
      const skipped = bad.length ? ` ${bad.length} file(s) skipped, e.g. ${bad[0]}` : '';
      const limited = rt.lastScanLimited ? ` ${rt.lastScanLimited}.` : '';
      return { ok: true, message: `Read ${ok} Trivy report(s) with ${vulns} vulnerabilities.${skipped}${limited}` };
    } catch (err) {
      return { ok: false, message: errMessage(err) };
    }
  },
  tools,
  /** Local files only, so not open-world. */
  openWorld: false,
});
