import { z } from 'zod';
import { errMessage } from '../../log.js';
import { jsonResult } from '../result.js';
import { defineBackend, toolsFor } from '../types.js';
import { attackRangeShape } from '../attack-window.js';
import { attackDetails, attackTrend, isAttackCategory, parseMapTargets } from './attacks.js';
import { wazuhHealth } from './health.js';
import { WazuhClient, type WazuhConfig } from './client.js';
import { changeAgentGroup, runActiveResponse } from './writes.js';
import {
  AGENT_STATUS,
  agentInventory,
  agentSca,
  agentVulnerabilities,
  FIM_EVENTS,
  FIM_TYPES,
  fimEvents,
  fimFiles,
  getAgent,
  getAlert,
  getRules,
  INVENTORY_KINDS,
  listAgents,
  listDecoders,
  listGroups,
  SCA_RESULTS,
  scaChecks,
  searchAlerts,
  SEVERITIES,
  vulnerabilityOverview,
  vulnerabilityTrend,
} from './queries.js';

const optionalString = z
  .string()
  .optional()
  .transform((v) => (v && v.trim() !== '' ? v.trim() : undefined));

const schema = z
  .object({
    managerUrl: z.string().url(),
    managerUser: z.string().min(1),
    managerPassword: z.string().min(1),
    indexerUrl: optionalString.pipe(z.string().url().optional()),
    indexerUser: optionalString,
    indexerPassword: optionalString,
    alertsIndex: z.string().min(1).default('wazuh-alerts-*'),
    vulnerabilitiesIndex: z.string().min(1).default('wazuh-states-vulnerabilities-*'),
    tlsVerify: z.boolean().default(true),
    caCert: optionalString,
    activeResponseCommands: z
      .string()
      .max(2000)
      .optional()
      .transform((v) => [...new Set((v ?? '').split(/[\s,]+/).map((c) => c.trim()).filter(Boolean))])
      .pipe(z.array(z.string().regex(/^!?[A-Za-z0-9._-]{1,64}$/, 'command names are letters, digits, . _ - (optionally starting with !)'))),
    mapTargets: z
      .string()
      .max(2000)
      .optional()
      .transform((v) => parseMapTargets(v ?? ''))
      .refine((v) => v !== null, 'use latitude,longitude or agent=latitude,longitude, separated by ;'),
  })
  .refine((c) => !c.indexerUrl || (c.indexerUser && c.indexerPassword), {
    message: 'indexerUser and indexerPassword are required when indexerUrl is set',
  }) as z.ZodType<WazuhConfig>;


const t = toolsFor<WazuhClient>();
/** Alert, FIM and vulnerability tools read the indexer; without it only the manager tools exist. */
const needsIndexer = (c: WazuhClient) => c.hasIndexer;

const tools = [
  t.read({
    name: 'wazuh_list_agents',
    title: 'List Wazuh agents',
    description:
      'List Wazuh agents with status, OS, version, groups and last keep-alive. Filter by connection status, group, OS platform or free-text search.',
    inputSchema: {
      status: z.enum(AGENT_STATUS).optional().describe('Connection status filter'),
      group: z.string().max(128).optional().describe('Only agents in this group'),
      os_platform: z.string().max(64).optional().describe('e.g. ubuntu, windows, darwin'),
      search: z.string().max(128).optional().describe('Free-text search across agent fields'),
      limit: z.number().int().min(1).max(500).default(100),
      offset: z.number().int().min(0).default(0),
    },
    run: async (client, a) => jsonResult(await listAgents(client, a)),
  }),

  t.read({
    name: 'wazuh_get_agent',
    title: 'Get Wazuh agent',
    description: 'Full details for one Wazuh agent, including OS and configuration sync status.',
    inputSchema: { agent_id: z.string().describe('Agent ID, e.g. "001" (leading zeros optional)') },
    run: async (client, a) => {
      const agent = await getAgent(client, a.agent_id);
      return jsonResult(agent ?? { error: `No agent with id ${a.agent_id}` });
    },
  }),

  t.read({
    name: 'wazuh_list_groups',
    title: 'List Wazuh agent groups',
    description: 'Agent groups with the number of agents in each. Use wazuh_list_agents with group to see the members.',
    inputSchema: {
      search: z.string().max(128).optional().describe('Free-text search on group name'),
      limit: z.number().int().min(1).max(500).default(100),
      offset: z.number().int().min(0).default(0),
    },
    run: async (client, a) => jsonResult(await listGroups(client, a)),
  }),

  t.read({
    name: 'wazuh_agent_sca',
    title: 'Configuration assessment (SCA) for an agent',
    description:
      'Security configuration assessment policies scanned on one agent (e.g. CIS benchmarks) with score and passed/failed/not-applicable counts. Use wazuh_sca_checks for the individual checks.',
    inputSchema: {
      agent_id: z.string().describe('Agent ID, e.g. "001"'),
      search: z.string().max(128).optional().describe('Free-text search on policy fields'),
    },
    run: async (client, a) => jsonResult(await agentSca(client, a)),
  }),

  t.read({
    name: 'wazuh_sca_checks',
    title: 'SCA checks of a policy on an agent',
    description:
      'Individual checks of one SCA policy on one agent, with result, rationale, remediation and compliance mappings. Filter result=failed to see what to fix.',
    inputSchema: {
      agent_id: z.string().describe('Agent ID, e.g. "001"'),
      policy_id: z.string().max(128).describe('Policy ID from wazuh_agent_sca, e.g. cis_ubuntu22-04'),
      result: z.enum(SCA_RESULTS).optional().describe('Only checks with this result'),
      search: z.string().max(128).optional().describe('Free-text search across check fields'),
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
    },
    run: async (client, a) => jsonResult(await scaChecks(client, a)),
  }),

  t.read({
    name: 'wazuh_agent_inventory',
    title: 'System inventory of an agent',
    description:
      'Syscollector inventory for one agent: os, hardware, packages, processes, ports (listening/open sockets), netaddr, netiface, netproto or hotfixes (Windows). search, limit and offset apply to the list kinds.',
    inputSchema: {
      agent_id: z.string().describe('Agent ID, e.g. "001"'),
      kind: z.enum(INVENTORY_KINDS).describe('Which inventory to read'),
      search: z.string().max(128).optional().describe('Free-text search, e.g. a package or process name'),
      limit: z.number().int().min(1).max(500).default(100),
      offset: z.number().int().min(0).default(0),
    },
    run: async (client, a) => jsonResult(await agentInventory(client, a)),
  }),

  t.read({
    name: 'wazuh_get_rule',
    title: 'Get Wazuh rules',
    description:
      'Definition of one or more Wazuh rules by ID: description, level, groups, compliance mappings (PCI DSS, GDPR, NIST, MITRE) and the rule file. Useful to explain an alert.',
    inputSchema: {
      rule_ids: z.array(z.string().max(16)).min(1).max(20).describe('Rule IDs, e.g. ["5710", "5712"]'),
    },
    run: async (client, a) => jsonResult(await getRules(client, a.rule_ids)),
  }),

  t.read({
    name: 'wazuh_list_decoders',
    title: 'List Wazuh decoders',
    description:
      'Decoder definitions by name or free-text search: file, position and details such as prematch, regex and parent. Useful to see how a log line is parsed into the fields an alert shows.',
    inputSchema: {
      names: z.array(z.string().max(128)).max(20).optional().describe('Exact decoder names, e.g. ["sshd"]'),
      search: z.string().max(128).optional().describe('Free-text search across decoder fields'),
      limit: z.number().int().min(1).max(200).default(50),
      offset: z.number().int().min(0).default(0),
    },
    run: async (client, a) => jsonResult(await listDecoders(client, a)),
  }),

  t.read({
    name: 'wazuh_fim_files',
    title: 'FIM database of an agent',
    description:
      'Files and registry entries file integrity monitoring currently tracks on one agent, with size, permissions, owner, hashes and modification time, plus when the last FIM scan ran. Look up one path, search, or find which files have a given hash. For changes over time use wazuh_fim_events.',
    inputSchema: {
      agent_id: z.string().describe('Agent ID, e.g. "001"'),
      file: z.string().max(1024).optional().describe('Exact full path'),
      search: z.string().max(256).optional().describe('Free-text search, e.g. part of a path'),
      type: z.enum(FIM_TYPES).optional(),
      hash: z.string().max(64).optional().describe('MD5, SHA-1 or SHA-256 to look for'),
      limit: z.number().int().min(1).max(500).default(100),
      offset: z.number().int().min(0).default(0),
    },
    run: async (client, a) => jsonResult(await fimFiles(client, a)),
  }),


  t.read({
    name: 'wazuh_agent_vulnerabilities',
    available: needsIndexer,
    title: 'Vulnerabilities on a Wazuh agent',
    description:
      'Vulnerabilities currently detected on one agent (Wazuh vulnerability detection state), highest CVSS first, with per-severity counts. Filter by severity, package or CVE.',
    inputSchema: {
      agent_id: z.string().describe('Agent ID, e.g. "001"'),
      severity: z.array(z.enum(SEVERITIES)).optional().describe('Only these severities'),
      package: z.string().max(128).optional().describe('Exact package name'),
      cve: z.string().max(64).optional().describe('Exact vulnerability ID, e.g. CVE-2024-3094'),
      limit: z.number().int().min(1).max(500).default(50),
    },
    run: async (client, a) => jsonResult(await agentVulnerabilities(client, a)),
  }),

  t.read({
    name: 'wazuh_vulnerability_overview',
    available: needsIndexer,
    title: 'Vulnerability overview across agents',
    description:
      'Fleet-wide vulnerability summary: counts per severity, the agents with the most findings and the most widespread CVEs.',
    inputSchema: {
      severity: z.array(z.enum(SEVERITIES)).optional().describe('Restrict the overview to these severities'),
      top: z.number().int().min(1).max(50).default(10).describe('Number of agents and CVEs to list'),
    },
    run: async (client, a) => jsonResult(await vulnerabilityOverview(client, a)),
  }),

  t.read({
    name: 'wazuh_vulnerability_trend',
    available: needsIndexer,
    title: 'Vulnerability trend per agent',
    description:
      'New and resolved vulnerability findings over the last N days, per day and per agent, with the number open now. ' +
      'From snapshots_since on, built from hourly snapshots of the open findings; a finding counts as resolved once it has been gone for 6 hours. Before that (or when snapshots_since is null), built from vulnerability detector alerts, which miss CVEs that appear or disappear through a feed update, so new may be too low. ' +
      'A CVE that Wazuh closes and reopens because its package was upgraded counts as redetected, not as new and resolved.',
    inputSchema: {
      days: z.number().int().min(1).max(365).default(30).describe('Window in days, ending today'),
      severity: z.array(z.enum(SEVERITIES)).optional().describe('Restrict to these severities'),
      top: z.number().int().min(1).max(100).default(25).describe('Number of agents to list'),
    },
    run: async (client, a) => jsonResult(await vulnerabilityTrend(client, a)),
  }),

  t.read({
    name: 'wazuh_attack_trend',
    available: needsIndexer,
    title: 'Attacks over time',
    description:
      'Attack attempts over time per category (failed SSH, SMTP, IMAP/POP3 and FTP logins, web attacks, scans, and one category for every other service found in the alerts, with an id such as other_login:pam), with attempts, distinct source IPs and brute_force (how many of the attempts Wazuh flagged as repeated failures) per time step and the preceding period for comparison (null when the alerts do not reach back that far; data_from is the oldest alert). Many source IPs with few attempts each point to a distributed attack.',
    inputSchema: {
      ...attackRangeShape,
    },
    run: async (client, a) => jsonResult(await attackTrend(client, a)),
  }),

  t.read({
    name: 'wazuh_attack_details',
    available: needsIndexer,
    title: 'Details of one attack category',
    description:
      'Who is behind one attack category in a time range: top source IPs, countries, user names tried, targeted agents and rules, and the newest alerts.',
    inputSchema: {
      category: z.string().max(100).refine(isAttackCategory, 'Unknown attack category').describe('Category id from wazuh_attack_trend'),
      from: z.string().max(40).describe('Start, ISO-8601'),
      to: z.string().max(40).describe('End (exclusive), ISO-8601'),
      top: z.number().int().min(1).max(50).default(10),
      limit: z.number().int().min(0).max(100).default(20).describe('Number of alerts to return'),
    },
    run: async (client, a) => jsonResult(await attackDetails(client, a)),
  }),

  t.read({
    name: 'wazuh_search_alerts',
    available: needsIndexer,
    title: 'Search Wazuh alerts',
    description:
      'Search Wazuh alerts, newest first. Combine a time window with filters on rule level, agent, rule ID or rule group, and an optional Lucene query (e.g. "rule.groups:authentication_failed AND data.srcip:10.*").',
    inputSchema: {
      query: z.string().max(1000).optional().describe('Lucene query string'),
      since: z.string().default('24h').describe('Start of window: relative (15m, 24h, 7d) or ISO-8601'),
      until: z.string().optional().describe('End of window: relative or ISO-8601 (default now)'),
      min_level: z.number().int().min(0).max(16).optional().describe('Minimum rule level (0–16)'),
      agent_id: z.string().optional(),
      rule_id: z.string().max(16).optional(),
      rule_group: z.string().max(64).optional().describe('e.g. sshd, authentication_failed, syscheck'),
      limit: z.number().int().min(1).max(500).default(50),
    },
    run: async (client, a) => jsonResult(await searchAlerts(client, a)),
  }),
  t.read({
    name: 'wazuh_get_alert',
    available: needsIndexer,
    title: 'Get a Wazuh alert',
    description: 'The complete alert document for one alert ID (the id field returned by wazuh_search_alerts or wazuh_fim_events).',
    inputSchema: { alert_id: z.string().max(128).describe('Alert document ID') },
    run: async (client, a) => jsonResult((await getAlert(client, a.alert_id)) ?? { error: `No alert with id ${a.alert_id}` }),
  }),

  t.read({
    name: 'wazuh_fim_events',
    available: needsIndexer,
    title: 'File integrity monitoring events',
    description:
      'File and registry changes detected by Wazuh FIM (syscheck), newest first, with counts per event type, agent and path. Filter by agent, path (exact, or a prefix ending in *, e.g. /etc/*) and event type.',
    inputSchema: {
      agent_id: z.string().optional(),
      path: z.string().max(1024).optional().describe('Exact path, or a prefix ending in * (e.g. /etc/ssh/*)'),
      event: z.array(z.enum(FIM_EVENTS)).optional().describe('Only these change types'),
      since: z.string().default('24h').describe('Start of window: relative (15m, 24h, 7d) or ISO-8601'),
      until: z.string().optional().describe('End of window: relative or ISO-8601 (default now)'),
      limit: z.number().int().min(1).max(500).default(50),
    },
    run: async (client, a) => jsonResult(await fimEvents(client, a)),
  }),

  t.write({
    name: 'wazuh_add_agent_group',
    title: 'Add a Wazuh agent to a group',
    description:
      'Adds one agent to one existing agent group, so the group\'s shared configuration is pushed to that agent. ' +
      'Takes the exact agent ID and group name (from wazuh_list_agents and wazuh_list_groups); does nothing if the agent is already a member.',
    inputSchema: {
      agent_id: z.string().max(16).describe('Agent ID, e.g. "001"'),
      group: z.string().max(128).describe('Exact group name'),
    },
    run: async (client, a) => jsonResult(await changeAgentGroup(client, { ...a, action: 'add' })),
  }),

  t.write({
    name: 'wazuh_remove_agent_group',
    title: 'Remove a Wazuh agent from a group',
    description:
      'Removes one agent from one agent group, so that group\'s configuration no longer applies to it (an agent left without groups ' +
      'goes back to "default"). Takes the exact agent ID and group name; does nothing if the agent is not a member.',
    inputSchema: {
      agent_id: z.string().max(16).describe('Agent ID, e.g. "001"'),
      group: z.string().max(128).describe('Exact group name'),
    },
    run: async (client, a) => jsonResult(await changeAgentGroup(client, { ...a, action: 'remove' })),
  }),

  t.write({
    name: 'wazuh_run_active_response',
    destructive: true,
    // Exists only when an administrator listed commands in the backend settings.
    available: (c) => (c.cfg.activeResponseCommands ?? []).length > 0,
    title: 'Run a Wazuh active-response command on an agent',
    description: (c) =>
      'Runs an active-response command on one connected agent (for example blocking an address in the host firewall). ' +
      `Only these commands are allowed: ${(c.cfg.activeResponseCommands ?? []).join(', ')}. ` +
      'No free-form arguments: an optional srcip (a single IP address) is passed to the script as the alert source address.',
    inputSchema: {
      agent_id: z.string().max(16).describe('Agent ID, e.g. "001"'),
      command: z.string().max(65).describe('One of the allowed commands, exactly as listed in the description'),
      srcip: z.string().max(45).optional().describe('IPv4 or IPv6 address for commands that act on an address, e.g. !firewall-drop'),
    },
    run: async (client, a) => jsonResult(await runActiveResponse(client, a)),
  }),
];

export const wazuh = defineBackend<WazuhConfig, WazuhClient>({
  id: 'wazuh',
  title: 'Wazuh',
  description: 'SIEM/XDR: agents, groups, SCA, inventory, FIM state, rules and decoders via the manager API; alerts, FIM events and vulnerability state via the indexer.',
  maturity: 'ready',
  schema,
  health: wazuhHealth,
  guide: {
    intro:
      'Two connections. The manager API (port 55000) serves agents, groups, configuration assessment (SCA), system inventory and rules. ' +
      'The indexer (port 9200) holds alerts, file integrity events and the vulnerability state; without it the Findings page and the ' +
      'alert, FIM and vulnerability tools stay off.',
    before: [
      'SocBridge must reach both the manager and the indexer over the network. If Wazuh runs in Docker on the same host, ' +
        'attach SocBridge to the Wazuh Docker network and use the service names (wazuh.manager, wazuh.indexer).',
      'Vulnerability findings need Wazuh 4.8 or later (the wazuh-states-vulnerabilities-* index).',
    ],
    items: [
      {
        title: 'Manager API URL',
        fields: ['managerUrl'],
        steps: [
          'https://<manager host>:55000. In the Wazuh Docker stack the host is wazuh.manager.',
          'Check from the socbridge host that the port answers (a 401 reply is fine, it means the API is there).',
        ],
        code: 'curl -k https://wazuh.manager:55000/',
      },
      {
        title: 'Manager API user and password (read-only)',
        fields: ['managerUser', 'managerPassword'],
        steps: [
          'Wazuh dashboard → ☰ → Server management → Security → Users → Create user (e.g. socbridge) with a password.',
          'Open the user → Roles → add the built-in role "readonly". With that role SocBridge cannot change anything in Wazuh.',
          'Quick test without a new user: the default API user is wazuh-wui. Its password is API_PASSWORD in the Docker ' +
            'compose file, or in wazuh-passwords.txt inside wazuh-install-files.tar for the installer.',
        ],
        code: 'curl -k -u socbridge:<password> -X POST https://wazuh.manager:55000/security/user/authenticate',
      },
      {
        title: 'Indexer URL',
        fields: ['indexerUrl'],
        steps: ['https://<indexer host>:9200. In the Wazuh Docker stack the host is wazuh.indexer.'],
      },
      {
        title: 'Indexer user and password (read-only)',
        fields: ['indexerUser', 'indexerPassword'],
        steps: [
          'Wazuh dashboard → ☰ → Indexer management → Security → Internal users → Create internal user (e.g. socbridge).',
          'Security → Roles → Create role (e.g. socbridge_read). Cluster permissions: cluster_composite_ops_ro and cluster:monitor/main (the version check used by Test connection). ' +
            'Index permissions: patterns wazuh-alerts-* and wazuh-states-vulnerabilities-*, allowed action read.',
          'On that role: Mapped users → map the new user. The built-in "readall" role alone is not enough: it lacks cluster:monitor/main, so the check fails with 403.',
          'Quick test without a new user: admin, with INDEXER_PASSWORD from the compose file or wazuh-passwords.txt.',
        ],
        code: 'curl -k -u socbridge:<password> "https://wazuh.indexer:9200/"',
      },
      {
        title: 'Index patterns',
        fields: ['alertsIndex', 'vulnerabilitiesIndex'],
        steps: ['Leave empty for the defaults (wazuh-alerts-*, wazuh-states-vulnerabilities-*). If yours differ, use the same patterns in the role.'],
      },
      {
        title: 'Certificates',
        fields: ['caCert', 'tlsVerify'],
        steps: [
          'Wazuh uses its own CA. Paste root-ca.pem into "CA certificate": in Docker it is config/wazuh_indexer_ssl_certs/root-ca.pem, ' +
            'for the installer it is inside wazuh-certificates.tar.',
          'The manager API has its own self-signed certificate by default (/var/ossec/api/configuration/ssl/server.crt on the manager). ' +
            'If the test fails on the manager with a certificate error, paste that PEM below root-ca.pem in the same field.',
          'Turn off "Verify TLS certificates" only for a quick lab test.',
        ],
      },
      {
        title: 'Write tools (optional, off by default)',
        fields: ['activeResponseCommands'],
        steps: [
          'Group changes and active response need the manager API user to have a role that also allows agent:modify_group ' +
            'and active-response:command. Give it that role only if you use these tools.',
          'List the active-response commands SocBridge may send, e.g. !firewall-drop. Nothing else can be sent, and there are no free-form arguments.',
          'Then tick "Allow write tools" and the tools in the list below, give the users who need it a Wazuh write grant (Users page), ' +
            'and create a token with write on Wazuh. Every call is in the audit log.',
        ],
      },
    ],
    verify: [
      'Tick Enabled, Save, then Test connection: it should say "manager OK" and "indexer OK".',
      'Open Findings: agents with vulnerabilities should appear within a minute.',
    ],
    docs: [
      { label: 'Wazuh server API', url: 'https://documentation.wazuh.com/current/user-manual/api/getting-started.html' },
      { label: 'Wazuh RBAC (API users and roles)', url: 'https://documentation.wazuh.com/current/user-manual/api/rbac/index.html' },
      { label: 'Indexer users and roles', url: 'https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html' },
    ],
  },
  fields: [
    { key: 'managerUrl', label: 'Manager API URL', type: 'url', required: true, placeholder: 'https://wazuh-manager:55000' },
    { key: 'managerUser', label: 'Manager API user', type: 'string', required: true, help: 'A read-only API user is sufficient.' },
    { key: 'managerPassword', label: 'Manager API password', type: 'secret', required: true },
    { key: 'indexerUrl', label: 'Indexer URL', type: 'url', placeholder: 'https://wazuh-indexer:9200', help: 'Required for alert and vulnerability tools.' },
    { key: 'indexerUser', label: 'Indexer user', type: 'string', help: 'Needs read access to the alerts and vulnerability indices.' },
    { key: 'indexerPassword', label: 'Indexer password', type: 'secret' },
    { key: 'alertsIndex', label: 'Alerts index pattern', type: 'string', placeholder: 'wazuh-alerts-*' },
    { key: 'vulnerabilitiesIndex', label: 'Vulnerability index pattern', type: 'string', placeholder: 'wazuh-states-vulnerabilities-*' },
    { key: 'tlsVerify', label: 'Verify TLS certificates', type: 'boolean', help: 'Turn off only for self-signed lab setups; prefer supplying the CA below.' },
    { key: 'caCert', label: 'CA certificate (PEM)', type: 'pem', help: 'Trust anchor for the manager and indexer certificates.' },
    {
      key: 'activeResponseCommands',
      label: 'Allowed active-response commands',
      type: 'string',
      placeholder: '!firewall-drop, !restart-wazuh',
      help:
        'Write tool wazuh_run_active_response may send only these commands (comma-separated, as Wazuh names them). ' +
        'Empty: the tool does not exist. Also needs write tools allowed below, a write grant and a write-scoped token.',
    },
    {
      key: 'mapTargets',
      label: 'Attack map: where your machines are',
      type: 'string',
      placeholder: '59.33,18.07; mailserver=55.60,13.00',
      help: 'Latitude,longitude for all agents, then agent=latitude,longitude for those elsewhere, separated by ;. Without it the map shows squares at the sources but no missiles.',
    },
  ],

  createRuntime: (cfg) => new WazuhClient(cfg),

  async testConnection(client) {
    const parts: string[] = [];
    let ok = true;
    try {
      const info = await client.api<{ data?: { api_version?: string; hostname?: string } }>('/');
      parts.push(`manager OK (API ${info.data?.api_version ?? 'unknown'})`);
    } catch (err) {
      ok = false;
      parts.push(`manager: ${errMessage(err)}`);
    }
    if (client.hasIndexer) {
      try {
        const info = await client.indexerInfo();
        parts.push(`indexer OK (${info.version?.distribution ?? 'opensearch'} ${info.version?.number ?? ''})`.trim());
      } catch (err) {
        ok = false;
        parts.push(`indexer: ${errMessage(err)}`);
      }
    } else {
      parts.push('indexer not configured (alert and vulnerability tools disabled)');
    }
    return { ok, message: parts.join('; ') };
  },

  tools,
});
