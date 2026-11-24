import { isIP } from 'node:net';
import { BackendError } from '../http.js';
import { normaliseAgentId, type WazuhClient, type WazuhListResponse } from './client.js';

/**
 * Wazuh write operations (BACKLOG P1-12). Each takes exact IDs, checks the
 * target exists first so a typo fails before anything changes, and reports
 * what Wazuh says it changed. They need a manager API user whose RBAC policy
 * allows the action (`agent:modify_group`, `active-response:command`).
 */

/** Wazuh group names: letters, digits, `.`, `_`, `-`; not `.` or `..`. */
export function normaliseGroup(raw: string): string {
  const g = raw.trim();
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(g) || g === '.' || g === '..') {
    throw new BackendError(`Invalid group "${raw}": use the exact group name from wazuh_list_groups`);
  }
  return g;
}

async function agentOrFail(client: WazuhClient, raw: string) {
  const id = normaliseAgentId(raw);
  const r = await client.api<WazuhListResponse<{ id: string; name?: string; group?: string[]; status?: string }>>('/agents', {
    agents_list: id,
    select: 'id,name,group,status',
  });
  const agent = r.data.affected_items[0];
  if (!agent) throw new BackendError(`No agent with id ${id}`);
  return agent;
}

/** Throws with Wazuh's own reason when it reports the item as failed. */
function failedReason(r: WazuhListResponse<unknown>): string | null {
  const f = r.data?.failed_items?.[0] as { error?: { message?: string; code?: number } } | undefined;
  if (!f) return null;
  return f.error?.message ?? 'Wazuh reported the change as failed';
}

export async function changeAgentGroup(client: WazuhClient, a: { agent_id: string; group: string; action: 'add' | 'remove' }) {
  const group = normaliseGroup(a.group);
  const agent = await agentOrFail(client, a.agent_id);
  const before = agent.group ?? [];
  if (a.action === 'add') {
    const groups = await client.api<WazuhListResponse<{ name: string }>>('/groups', { groups_list: group });
    if (!groups.data.affected_items.some((g) => g.name === group)) throw new BackendError(`No group named ${group}`);
    if (before.includes(group)) return { agent_id: agent.id, group, changed: false, groups: before, message: 'Agent already in group' };
  } else if (!before.includes(group)) {
    return { agent_id: agent.id, group, changed: false, groups: before, message: 'Agent is not in that group' };
  }
  const path = `/agents/${encodeURIComponent(agent.id)}/group/${encodeURIComponent(group)}`;
  const r = await client.apiWrite<WazuhListResponse<unknown>>(a.action === 'add' ? 'PUT' : 'DELETE', path);
  const failed = failedReason(r);
  if (failed) throw new BackendError(`Wazuh refused: ${failed}`);
  const after = (await agentOrFail(client, agent.id)).group ?? [];
  return { agent_id: agent.id, agent_name: agent.name, group, action: a.action, changed: true, groups_before: before, groups_after: after, message: r.message };
}

export async function runActiveResponse(client: WazuhClient, a: { agent_id: string; command: string; srcip?: string }) {
  const allowed = client.cfg.activeResponseCommands ?? [];
  if (!allowed.includes(a.command)) {
    throw new BackendError(`Command "${a.command}" is not allowed; an administrator allows: ${allowed.join(', ') || 'none'}`);
  }
  if (a.srcip !== undefined && !isIP(a.srcip)) throw new BackendError(`Invalid srcip "${a.srcip}": expected an IPv4 or IPv6 address`);
  const agent = await agentOrFail(client, a.agent_id);
  if (agent.status && agent.status !== 'active') throw new BackendError(`Agent ${agent.id} is ${agent.status}; active response needs a connected agent`);
  // No free-form arguments: the only input that reaches the script is a validated address in the alert.
  const r = await client.apiWrite<WazuhListResponse<unknown>>('PUT', '/active-response', {
    query: { agents_list: agent.id },
    json: { command: a.command, arguments: [], ...(a.srcip ? { alert: { data: { srcip: a.srcip } } } : {}) },
  });
  const failed = failedReason(r);
  if (failed) throw new BackendError(`Wazuh refused: ${failed}`);
  return { agent_id: agent.id, agent_name: agent.name, command: a.command, ...(a.srcip ? { srcip: a.srcip } : {}), sent: true, message: r.message };
}
