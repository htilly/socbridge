import { errMessage } from '../../log.js';
import type { Service } from '../../config/schema.js';
import { isPublicIp } from '../cve.js';
import { listEndpoints, type DefectDojoRuntime } from '../defectdojo/queries.js';
import { listReports, type TrivyReports } from '../trivy/reports.js';
import type { SourceHandle, SourceLookup } from '../types.js';
import type { WazuhClient } from '../wazuh/client.js';
import { agentInventory, listAgents } from '../wazuh/queries.js';
import { ownsEndpoint } from './correlate.js';

/**
 * What is not in the service map yet, for an administrator to accept. Nothing
 * is stored here, and pairings are only proposed with the reason shown.
 */

const PAGE = 500;
const MAX_ROWS = 5000;

/** A proposed service: what to put in the form, and why. */
export interface Suggestion {
  name: string;
  exposure: Service['exposure'];
  endpoints: Service['endpoints'];
  agents: string[];
  images: string[];
  reasons: string[];
}

/** "ghcr.io/org/nginx-proxy:1.2" → "nginx-proxy". */
export function imageName(artifact: string): string {
  const last = artifact.split('@')[0]!.split('/').at(-1)!;
  return last.split(':')[0]!.toLowerCase();
}

const words = (s: string) => s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 4);

async function paged<T>(load: (offset: number) => Promise<{ total?: number; rows: T[] }>): Promise<{ rows: T[]; truncated: boolean }> {
  const rows: T[] = [];
  for (;;) {
    const r = await load(rows.length);
    rows.push(...r.rows);
    if (!r.rows.length || rows.length >= (r.total ?? rows.length)) return { rows, truncated: false };
    if (rows.length >= MAX_ROWS) return { rows, truncated: true };
  }
}

export async function suggestServices(source: SourceLookup, services: readonly Service[]) {
  const errors: { source: string; message: string }[] = [];
  const read = async <Rt, T>(id: 'wazuh' | 'trivy' | 'defectdojo', fn: (h: SourceHandle<Rt>) => Promise<{ rows: T[]; truncated: boolean }>): Promise<T[] | null> => {
    const h = source<Rt>(id);
    if ('unavailable' in h) {
      errors.push({ source: id, message: h.unavailable });
      return null;
    }
    try {
      const r = await fn(h);
      if (r.truncated) errors.push({ source: id, message: `only the first ${MAX_ROWS} were read` });
      return r.rows;
    } catch (err) {
      errors.push({ source: id, message: errMessage(err) });
      return null;
    }
  };

  const [agents, images, endpoints] = await Promise.all([
    read<WazuhClient, Record<string, unknown>>('wazuh', (h) =>
      paged(async (offset) => {
        const r = await h.run((c) => listAgents(c, { limit: PAGE, offset }));
        return { total: r.total, rows: r.agents as Record<string, unknown>[] };
      }),
    ),
    read<TrivyReports, string>('trivy', (h) =>
      paged(async (offset) => {
        const r = await h.run((t) => listReports(t, { latest_only: true, limit: PAGE, offset }));
        return { total: r.total, rows: (r.reports as { artifact?: string }[]).map((x) => x.artifact ?? '') };
      }),
    ),
    read<DefectDojoRuntime, Record<string, unknown>>('defectdojo', (h) =>
      paged(async (offset) => {
        const r = await h.run((d) => listEndpoints(d, { limit: 200, offset }));
        return { total: r.total, rows: r.endpoints };
      }),
    ),
  ]);

  const hosts = (agents ?? []).filter((x) => x.id !== '000').map((x) => ({ id: String(x.id), name: String(x.name ?? x.id) }));
  const artifacts = [...new Set((images ?? []).filter(Boolean))];
  const mappedAgents = new Set(services.flatMap((s) => s.agents));
  const mappedImages = new Set(services.flatMap((s) => s.images));
  const seen = (endpoints ?? [])
    .filter((e) => typeof e.host === 'string' && e.host && e.mitigated !== true)
    .map((e) => ({ host: (e.host as string).toLowerCase(), ...(typeof e.port === 'number' ? { port: e.port } : {}) }));
  const open = seen.filter((e) => !services.some((s) => ownsEndpoint(s, e)));

  // Which host listens on which of the open ports (on an address others can reach).
  const listening = new Map<number, { id: string; name: string; process: string }[]>();
  const wanted = new Set(open.flatMap((e) => (e.port ? [e.port] : [])));
  const wz = source<WazuhClient>('wazuh');
  if (wanted.size && !('unavailable' in wz)) {
    for (const agent of hosts.slice(0, 200)) {
      try {
        const { rows } = await paged(async (offset) => {
          const r = (await wz.run((c) => agentInventory(c, { agent_id: agent.id, kind: 'ports', limit: PAGE, offset }))) as { total?: number; items?: Record<string, unknown>[] };
          return { total: r.total, rows: r.items ?? [] };
        });
        for (const p of rows) {
          const local = p.local as { ip?: string; port?: number } | undefined;
          const udp = String(p.protocol ?? '').startsWith('udp');
          if (!local?.port || !wanted.has(local.port) || (!udp && p.state !== 'listening')) continue;
          if (/^(127\.|::1$)/.test(local.ip ?? '')) continue;
          const at = listening.get(local.port) ?? [];
          if (!at.some((x) => x.id === agent.id)) at.push({ ...agent, process: String(p.process ?? '').trim() });
          listening.set(local.port, at);
        }
      } catch (err) {
        errors.push({ source: 'wazuh', message: `ports of ${agent.name}: ${errMessage(err)}` });
      }
    }
    if (hosts.length > 200) errors.push({ source: 'wazuh', message: 'ports were read for the first 200 agents only' });
  }

  // One suggestion per open port; the same port under several host names may be aliases, which the administrator decides.
  const byPort = new Map<number | undefined, Set<string>>();
  for (const e of open) byPort.set(e.port, (byPort.get(e.port) ?? new Set()).add(e.host));
  const suggestions: Suggestion[] = [];
  for (const [port, names] of [...byPort].sort((a, b) => (a[0] ?? 0) - (b[0] ?? 0))) {
    const list = [...names].sort();
    const at = port ? (listening.get(port) ?? []) : [];
    const external = list.some(isPublicIp);
    const reasons = [`DefectDojo has ${list.join(', ')}${port ? ` port ${port}` : ''}`];
    if (external) reasons.push('A public IP address, so probably reachable from the internet');
    if (list.length > 1) reasons.push('Several host names with this port: check that they are the same service');
    if (at.length === 1) reasons.push(`Only ${at[0]!.name} listens on port ${port}${at[0]!.process ? ` (${at[0]!.process})` : ''}; port forwarding may lead elsewhere`);
    else if (at.length > 1) reasons.push(`Several hosts listen on port ${port}: ${at.map((x) => x.name).join(', ')}; choose one`);
    // Cut to what a service accepts.
    suggestions.push({
      name: at.length === 1 && at[0]!.process ? `${at[0]!.process} (${port})`.slice(0, 100) : port ? `Port ${port}` : list[0]!.slice(0, 100),
      exposure: external ? 'internet' : 'unknown',
      endpoints: [{ hosts: list.slice(0, 20), ...(port ? { port } : {}) }],
      agents: at.length === 1 ? [at[0]!.id] : [],
      images: [],
      reasons,
    });
  }
  for (const a of hosts.filter((x) => !mappedAgents.has(x.id))) {
    const pair = artifacts.filter((i) => !mappedImages.has(i) && words(a.name).some((w) => words(imageName(i)).includes(w)));
    suggestions.push({
      name: a.name.slice(0, 100),
      exposure: 'unknown',
      endpoints: [],
      agents: [a.id],
      images: pair.slice(0, 5),
      reasons: ['Wazuh agent without a service', ...(pair.length ? [`Image with a matching name: ${pair.slice(0, 5).join(', ')}`] : [])],
    });
  }
  for (const i of artifacts.filter((x) => !mappedImages.has(x))) {
    suggestions.push({ name: imageName(i).slice(0, 100) || i.slice(0, 100), exposure: 'unknown', endpoints: [], agents: [], images: [i], reasons: ['Trivy image without a service'] });
  }

  return {
    suggestions,
    errors,
    coverage: {
      agents: agents ? { mapped: hosts.filter((x) => mappedAgents.has(x.id)).length, total: hosts.length } : null,
      images: images ? { mapped: artifacts.filter((x) => mappedImages.has(x)).length, total: artifacts.length } : null,
      endpoints: endpoints ? { mapped: seen.length - open.length, total: seen.length } : null,
    },
    known: { agents: hosts, images: artifacts },
  };
}
