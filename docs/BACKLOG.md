# SocBridge backlog

Prioritised and split by phase. Phase 1 comes before phase 2, and nothing in
phase 2 starts until the phase 1 items it depends on are done. The design
behind these items is in `docs/DESIGN.md`; section references point there.

Status markers: **Done**, **In progress**, **Stub** (settings and connection
test exist, tools do not), **Not started**. Each item lists what it blocks
and what blocks it, so an item can be picked up without reading the rest.

## Done

The foundation is in place. The server speaks MCP over stateless Streamable
HTTP with per-user access tokens checked on every request, and the web
console signs users in with passkeys only, with admin and user roles, a
one-time setup token for the first admin and single-use invites for everyone
else. Configuration, including backend credentials, is encrypted at rest with
AES-256-GCM. TLS runs in four modes: a built-in offline CA, operator files,
Let's Encrypt over Cloudflare DNS-01, and off behind a reverse proxy.

Wazuh is the first complete backend, with five read-only tools (list and get
agents, vulnerabilities per agent, a fleet vulnerability overview, and alert
search). Its queries are shared with a findings view in the web UI. The web
UI is built on the approved visual identity as a design system in
`public/design`: tokens, self-hosted fonts, the aperture mark as session
indicator, and a severity scale kept separate from the brand colour, with
tests that guard those rules.

The repository has unit tests, an end-to-end test that runs real WebAuthn
ceremonies with a software authenticator against a mock Wazuh, a CI workflow
that tests on Node 24 and publishes the image to the GitHub container
registry, and a deploy workflow with health verification and automatic
rollback.

Certificates are managed from the web UI: the *Server* page switches between
the built-in CA and Let's Encrypt over Cloudflare DNS-01 at runtime, with a
staging dry run and a live job log, and the Cloudflare token stored as an
encrypted write-only secret. SocBridge is deployed on the home server and
redeploys on every push to `main`.

## Phase 1 — a modular system with full MCP support

### P1-1 First deployment to the home server — Done

Runner, compose service, encryption key, local DNS record and dashboard tile
are in place; every push to `main` deploys with health and build-SHA checks
and automatic rollback. Remaining operator step: enter the Cloudflare token
on the *Server* page to move from the built-in CA to Let's Encrypt.

### P1-2 CI — Done

`build.yml` runs unit and end-to-end tests on Node 24, publishes the private
image and smoke-tests it; `deploy.yml` follows on success.

### P1-3 Tool descriptor contract with read/write classification — Done

Modules declare `tools: ToolDescriptor[]` (`{ name, access: 'read' | 'write',
default, destructive, title, description, inputSchema, available, run }`,
built with `toolsFor<Rt>().read/write`) instead of registering them; tools
found at runtime come from `dynamicTools(rt)` (Graylog's MCP passthrough).
The core (`src/mcp/server.ts`) registers them per request, derives the MCP
annotations from `access` (write: `readOnlyHint: false`, `destructiveHint`
from `destructive`), prefixes write descriptions with `[WRITE — changes
<backend>]`, and wraps every handler with the call-time scope check, the audit
log, the per-backend gate and error handling. All four backends are converted
with every tool name kept. Graylog passthrough tools are `read` only when
Graylog marks them read-only and not destructive; anything else an
administrator allowlisted there counts as `write`. *Unblocks*: P1-5, P1-6,
P1-11, P1-12, phase 2.

### P1-4 Verify Wazuh against real data — Not started

The tools are tested against a mock. Point the backend at the real manager and
indexer with read-only users, and check field names in
`wazuh-states-vulnerabilities-*` and `wazuh-alerts-*`, aggregation keyword
fields, and behaviour with thousands of findings. Add whatever the real data
shows into the mock. *Blocked by*: P1-1.

### P1-5 Installation-wide tool allowlist — Done

Per backend in the encrypted config (`backends.<id>.tools`: exact names or
`<backend>_*` prefixes), edited on the Backends page as a checklist with
*Reset to defaults*. Until edited, a backend offers its module's default
subset: its read tools (write tools are never default). Registration is
enabled ∩ allowlist ∩ scope, and the allowlist is checked again at call time.
Not yet: the checklist saves exact names, so a hand-written prefix other than
the passthrough's `graylog_mcp_*` is replaced by the names it matched when an
administrator saves the list in the UI.

### P1-6 Token scopes per backend, read versus write — Done

Tokens carry `scope: { backends: { <id>: 'read' | 'write' } }` (absent = no
access), chosen in the token form and stored with the hash. Users carry
`writeBackends`, managed by administrators on the Users page; a token can
only be given write where its user has a grant. Write also needs the
backend's installation switch (`allowWrite`, *Allow write tools* on the
Backends page, off by default). `src/auth/scopes.ts` resolves the effective
level from the live config at registration and again at every call, so
revoking a grant, switching write off or narrowing a scope applies to the
next call of an already-issued token. Tokens stored before scopes existed load
as read on all four backends (a schema default, written back on the next
save). OAuth connectors get the same choice on the consent screen: the grant
stores the approved `access` per backend (kept across refresh), checked like
a token's scope, with write limited to the user's grants; grants from before
this read every backend. The built-in assistant is read-only by
construction. A token's scope can be changed in place (*Edit scope* on the
Access tokens page, `PATCH /api/tokens/:id`, by its owner or an
administrator, checked against the owner's grants); the token stays the same
and the new scope applies from its next call. Connected apps work the same
way (*Edit scope* under Connected apps, `PATCH /api/oauth/grants/:id`): the
app stays connected and its next call uses the new access.

### P1-7 Audit log for tool calls — Done

`DATA_DIR/audit.log` (`src/audit/audit-log.ts`): one AES-256-GCM line per
tool call from MCP clients and the assistant, with user, credential (token
ID and label, OAuth grant, or chat), tool, backend, access, arguments
(secret-looking keys, SocBridge tokens, bearer headers and private keys
redacted; long values cut), outcome (`ok`, `error`, `denied`), message and
duration. Results are not stored, only their size and SHA-256. Each line
holds the hash of the previous one, across rotation (10 MB, five old files
kept), and *Verify integrity* checks the chain. Calls to a tool the credential
was not given (e.g. a write tool on a read token) are recorded as denied.
The record is written (fsynced) before the result goes back, and write tools
are refused while the log cannot be written. Administrators read it on the
Audit page with filters; records can also be forwarded to a Graylog GELF HTTP
input. Not yet: the chat's question text and token usage (P2-5).

### P1-8 Trivy backend — Done

Implemented `trivy_list_reports`, `trivy_report_findings`,
`trivy_find_cve` and `trivy_artifact_history` over Trivy JSON reports
(schema v2, images and filesystems) in a read-only directory, with unit
tests. Reports are cached per file by mtime and size. Subdirectories are
read (up to 6 levels and 5000 files; symlinks that lead outside the
directory are ignored). Reports of the same artifact (name + type) form a
history ordered by `CreatedAt`: `trivy_artifact_history` shows counts by
severity per scan and which vulnerability IDs were fixed or are new between
the latest two scans (or two chosen ones); `trivy_list_reports` can show
only the latest report per artifact. Triggering scans stays out of scope by
design. Reports are shown on the web UI's Findings page (Trivy tab),
through the same `listReports`/`reportFindings` queries.

### P1-9 DefectDojo backend, read tools — Done

Implemented `defectdojo_list_findings`
(filters for product, severity, active, verified, date),
`defectdojo_get_finding`, `defectdojo_list_engagements` and
`defectdojo_list_products` against API v2 of the open-source edition, with
unit tests and a mock in `scripts/e2e`. Added `defectdojo_list_tests`
(per engagement or product, optional open finding counts per test),
`defectdojo_list_endpoints` (active finding counts, filter by product and
host), `defectdojo_list_imports` (`test_imports`: created/closed/reactivated/
untouched per import) and `defectdojo_sla_overview` (open and SLA-breached
findings per severity via `outside_of_sla`, plus the most overdue). API v2
has no product filter on tests, so per-product listing fans out over the
product's 50 newest engagements. Write tools are P1-11.
Active findings are shown on the web UI's Findings page (DefectDojo tab),
through the same `listFindings` query.

### P1-10 Graylog backend, read tools — Done

Implemented `graylog_search` (query, relative or absolute time range up to
30 days, streams by ID or title, fields, limit/offset; 15 minutes by
default), `graylog_list_streams` and `graylog_system_health` against the
Graylog 6/7 REST API. Added `graylog_list_event_definitions` (priority,
enabled state, condition summary, notifications), `graylog_search_events`
(triggered events/alerts in a time window, by definition, priority or
alerts only), `graylog_list_dashboards`, `graylog_list_saved_searches` and
`graylog_get_dashboard` (pages, widget queries and setup, not results).
Unit tests against a mock, and a Graylog mock in `scripts/e2e`. Added an
optional passthrough to Graylog's built-in MCP server (`/api/mcp`):
allowlisted tools, or only those Graylog marks read-only, exposed as
`graylog_mcp_<name>` with the shared result cap. Not yet: checked against a
real Graylog 7.1 (the event, dashboard and saved-search response shapes are
handled for both the older `views`/`event_definitions` keys and `elements`).
The web UI's Findings page has a Graylog tab with the events triggered in
the last 24 hours (through `searchEvents`, the same query as
`graylog_search_events`; a token without the events permission shows the
error in place of the list) and the messages at syslog level error or worse
(`level:<=3`, through `searchMessages`).

### P1-11 First write tools: DefectDojo — Done

`defectdojo_close_finding` (mitigated), `defectdojo_risk_accept_finding`
(a risk acceptance holding the one finding, owned by the API key's user,
optional expiry) and `defectdojo_mark_false_positive`, by finding ID only,
each with a required reason that is first written to the finding as a note
naming the SocBridge user. They return the state before and after, and do
nothing if the finding is already in that state. Off by default at
installation, user and token level; covered by unit tests and the e2e mock.
Not yet: checked against a real DefectDojo (the API key's user needs the
Writer role; whether a risk acceptance created through the API flags the
finding `risk_accepted` at once is reported as a warning if not).

### P1-12 Wazuh additions — Done

Implemented read tools `wazuh_get_alert` (alert by document ID),
`wazuh_fim_events` (syscheck alerts with path/prefix, event and agent
filters), `wazuh_list_groups`, `wazuh_agent_sca` and `wazuh_sca_checks`
(configuration assessment), `wazuh_agent_inventory` (syscollector: OS,
hardware, packages, processes, ports, network, hotfixes) and `wazuh_get_rule`,
`wazuh_list_decoders` and `wazuh_fim_files` (the FIM database per agent, with
the last scan time), with unit tests. Write tools: `wazuh_add_agent_group`
and `wazuh_remove_agent_group` (exact agent ID and group name, checked before
the change) and `wazuh_run_active_response`, which exists only when an
administrator lists allowed commands in the backend settings, accepts only
those, and takes no free-form arguments (an optional `srcip`, validated as an
IP address, is passed in the alert). Not yet: checked against a real manager
(the API user needs `agent:modify_group` and `active-response:command`).

### P1-13 Structured backend health — Done

`health(rt)` on the contract returns `{ status: ok | degraded | down, checks }`
(Wazuh: manager and indexer; Trivy: report directory; DefectDojo: API;
Graylog: node, indexer cluster colour, MCP passthrough). The registry's
`HealthMonitor` runs it every 60 s for enabled backends and caches per
runtime; the status bar reads the cached result and shows the individual
checks to administrators; `socbridge_backends` reports `state`, `health` and an
open circuit so a model can tell an outage from an empty result. Every MCP
tool call and Findings page query runs through a per-backend `BackendGate`:
at most 4 concurrent calls with 16 queued (15 s wait), and a circuit breaker
that opens after 5 consecutive failures for 30 s, then lets one trial call
through. Not yet: limits configurable per backend, and health history.

### P1-18 Web UI Findings page for every backend — Done

The Findings page has one tab per ready source (Wazuh, Trivy, DefectDojo,
Graylog) with a shared severity filter, each loaded through its own route
under `/api/findings/*` using the backend's query functions and gate. A
failing backend shows its error in its own tab (marked with a health dot) and
never hides the others; sources that are not set up are listed below the
tabs.

### P1-19 Threat intel backend: KEV and EPSS prioritisation — Done

New backend `intel` (`src/backends/intel/`): CISA KEV and FIRST EPSS
downloaded as whole files (no CVE list leaves the network), refreshed on
first use and every *Refresh interval*, EPSS held as typed arrays and looked
up by binary search. Tools `intel_prioritize_cves` (all open CVEs from Wazuh,
Trivy and DefectDojo merged per CVE, ranked P1–P4 with reasons),
`intel_kev_recent` (KEV additions in the last N days and where they occur)
and `intel_cve_lookup`. Cross-backend reads go through the new
`ToolContext.source`, which checks the caller's read access to each source
at call time and runs under that source's gate. Each backend exports a
`cveOccurrences` function into the shared shape in `src/backends/cve.ts`.
Unit tests with fixtures and a DefectDojo mock. Not yet: a Findings page tab,
EPSS/KEV columns on the existing tabs, and a push notification when a new KEV
entry matches an asset (see the daily digest idea).

### P1-20 Service map and cross-backend investigation — Done

A service map in the encrypted config (`services`), edited under *Services*
with suggestions computed from the backends (`intel/suggest.ts`).
`intel_investigate` joins CVEs, exposure and attacks per service: attacks per
agent from Wazuh (`attacksByAgent`), blocks per target from Graylog
(`attacksByTarget`), endpoints from DefectDojo. Not yet: which containers run
which image on which host, and IPS blocks per service (the logs have no target).

### P1-21 Explainable remediation prioritisation — Done

`intel_fix_first` and the *Fix first* page: actions rather than CVEs, tiers
A1–A4, confidence kept apart from tier, a recommendation, and evidence with
the tool call that shows each record (`intel/correlate.ts`, pure and unit
tested). Not yet: checked against real data.

### P1-22 Network edge on the Pew pew map — Done

Layers for port scans, IPS and firewall blocks from Graylog (`edgeMap`), placed
with a local GeoIP city database (`src/geoip.ts`, `GEOIP_DB`). Not yet: checked
against a real Graylog (grouping by source and time).

### P1-14 Encryption key rotation — Not started

`socbridge rotate-key` command that re-encrypts config, TLS and ACME files with
a new key atomically and verifies before exiting; documented procedure
(DESIGN §7).

### P1-15 Config schema migrations — Not started

Versioned migrations at load time with a kept backup of the previous file
(DESIGN §7). Needed before the first non-additive config change. P1-6 turned
out additive (token `scope` defaults to read on all backends at load time,
user grants and backend `allowWrite` are optional fields), so it did not need
one.

### P1-16 Design system, final piece — In progress

The tokens, fonts, mark and core components are done. Remaining: PNG
favicon and Apple touch icon fallbacks rendered from the mark, a full
light-mode review of every view, a review of the closed aperture at 18 and
30 px, a style reference page listing every token and component at
`/design/`, and screenshot regression tests in CI for the sign-in and
findings views.

### P1-17 Write the session-expiry path into the end-to-end test — Not started

The UI closes the aperture and returns to sign-in when the API answers 401
mid-session; cover expiry and revocation in `scripts/e2e`.

## Phase 2 — chat in the web UI

Phase 2 depends on P1-3 (read/write classification), P1-6 (scopes) and P1-7
(audit log), all done. The built-in assistant already gets read tools only
(it runs as a `chat` principal, which never registers or calls a write tool)
and its tool calls are in the audit log.

### P2-1 Provider abstraction with OpenAI and Anthropic adapters — Not started

The `ChatProvider` interface, provider-neutral messages and tool specs
generated from the registry, streaming events and usage reporting (DESIGN
§11.2). *Blocked by*: P1-3.

### P2-2 Server-side tool loop, read-only by construction — Not started

`POST /api/chat`, streamed. Tool list built from the registry filtered to
`access: 'read'` and the user's read scope; hard limits on tool calls and
turns; tool results returned only as tool results, delimited and labelled as
untrusted data (DESIGN §11.3). *Blocked by*: P1-6, P2-1.

### P2-3 Provider keys and model allowlist — Not started

Write-only key storage in the encrypted config (or `*_FILE` environment
variables), admin page for provider, allowed models and default; keys never
reach the browser or the logs (DESIGN §11.4). *Blocked by*: P2-1.

### P2-4 Cost control — Not started

Per-user daily and monthly token budgets, per-turn output and tool-call
limits, usage per user and model for administrators (DESIGN §11.5). *Blocked
by*: P2-1.

### P2-5 Chat audit logging — Not started

Question, model, tool calls with arguments, usage and outcome into the P1-7
audit log; results recorded by size and hash only (DESIGN §11.6). *Blocked
by*: P1-7, P2-2.

### P2-6 Chat UI — Not started

Chat panel on the design system: streamed answers rendered as plain text with
no live links or images, the tool calls and arguments shown inline, raw
results openable for verification. *Blocked by*: P2-2.

### P2-7 Prompt-injection fixtures and tests — Not started

Injection payloads in the mock data (a CVE description, a log line, an alert
field, a container label), tests that the chat's tool list never contains a
write tool, and tests that rendered output contains no active links or
images. Must pass before the chat is enabled anywhere. *Blocked by*: P2-2,
P2-6.
