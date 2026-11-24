import { BackendError } from '../http.js';
import type { DefectDojoRuntime } from './queries.js';

/**
 * DefectDojo write operations (BACKLOG P1-11), by finding ID only. Each one
 * first writes the caller's reason as a note on the finding (so DefectDojo's
 * own history says who did what and why), then changes the finding, then
 * reads it back and returns the state before and after. The API key's user
 * needs write permission on the finding's product (e.g. the Writer role).
 */

type Obj = Record<string, unknown>;

const STATE = ['active', 'verified', 'is_mitigated', 'mitigated', 'false_p', 'risk_accepted', 'out_of_scope', 'duplicate'] as const;

function state(f: Obj): Obj {
  const out: Obj = {};
  for (const k of STATE) if (f[k] !== undefined) out[k] = f[k];
  return out;
}

function call<T>(rt: DefectDojoRuntime, method: 'GET' | 'POST' | 'PATCH', p: string, json?: unknown): Promise<T> {
  return rt.http.request<T>(p, { method, ...(json !== undefined ? { json } : {}), headers: { authorization: rt.auth } });
}

async function findingOrFail(rt: DefectDojoRuntime, id: number): Promise<Obj> {
  if (!Number.isInteger(id) || id <= 0) throw new BackendError(`Invalid finding id ${id}`);
  try {
    return await call<Obj>(rt, 'GET', `/api/v2/findings/${id}/`);
  } catch (err) {
    if (err instanceof BackendError && err.status === 404) throw new BackendError(`No finding with id ${id}`);
    throw err;
  }
}

async function addNote(rt: DefectDojoRuntime, id: number, entry: string): Promise<void> {
  await call(rt, 'POST', `/api/v2/findings/${id}/notes/`, { entry });
}

const noteText = (action: string, user: string, reason: string) => `[SocBridge] ${action} on behalf of ${user}: ${reason}`;

function result(id: number, action: string, before: Obj, after: Obj, extra: Obj = {}) {
  return { finding_id: id, title: after.title ?? before.title, action, before: state(before), after: state(after), ...extra };
}

export async function closeFinding(rt: DefectDojoRuntime, a: { finding_id: number; note: string }, user: string) {
  const before = await findingOrFail(rt, a.finding_id);
  if (before.is_mitigated === true && before.active === false) {
    return { ...result(a.finding_id, 'close', before, before), changed: false, message: 'Finding is already closed (mitigated)' };
  }
  await addNote(rt, a.finding_id, noteText('Closed as mitigated', user, a.note));
  await call(rt, 'POST', `/api/v2/findings/${a.finding_id}/close/`, {
    is_mitigated: true,
    mitigated: new Date().toISOString(),
    false_p: false,
    out_of_scope: false,
    duplicate: false,
  });
  return { ...result(a.finding_id, 'close', before, await findingOrFail(rt, a.finding_id)), changed: true };
}

export async function markFalsePositive(rt: DefectDojoRuntime, a: { finding_id: number; reason: string }, user: string) {
  const before = await findingOrFail(rt, a.finding_id);
  if (before.false_p === true) {
    return { ...result(a.finding_id, 'false_positive', before, before), changed: false, message: 'Finding is already a false positive' };
  }
  await addNote(rt, a.finding_id, noteText('Marked false positive', user, a.reason));
  await call(rt, 'PATCH', `/api/v2/findings/${a.finding_id}/`, { false_p: true, active: false, verified: false });
  return { ...result(a.finding_id, 'false_positive', before, await findingOrFail(rt, a.finding_id)), changed: true };
}

/**
 * Creates a DefectDojo risk acceptance (decision "accept") holding just this
 * finding, owned by the API key's user, with the reason as decision details
 * and an optional expiry after which DefectDojo reactivates the finding.
 */
export async function riskAcceptFinding(
  rt: DefectDojoRuntime,
  a: { finding_id: number; reason: string; expiration_date?: string },
  user: string,
) {
  const before = await findingOrFail(rt, a.finding_id);
  if (before.risk_accepted === true) {
    return { ...result(a.finding_id, 'risk_accept', before, before), changed: false, message: 'Finding is already risk-accepted' };
  }
  if (a.expiration_date && Date.parse(a.expiration_date) <= Date.now()) throw new BackendError('expiration_date must be in the future');
  const me = await call<{ user?: { id?: number } }>(rt, 'GET', '/api/v2/user_profile/');
  const owner = me.user?.id;
  if (typeof owner !== 'number') throw new BackendError('Could not tell which DefectDojo user the API key belongs to');
  await addNote(rt, a.finding_id, noteText('Risk accepted', user, a.reason));
  const ra = await call<Obj>(rt, 'POST', '/api/v2/risk_acceptance/', {
    name: `SocBridge: finding ${a.finding_id}`.slice(0, 300),
    accepted_findings: [a.finding_id],
    owner,
    decision: 'A',
    decision_details: `${a.reason}\n\n(Accepted via SocBridge on behalf of ${user}.)`,
    ...(a.expiration_date ? { expiration_date: a.expiration_date } : {}),
  });
  const after = await findingOrFail(rt, a.finding_id);
  return {
    ...result(a.finding_id, 'risk_accept', before, after, { risk_acceptance_id: ra.id }),
    changed: true,
    ...(after.risk_accepted === true ? {} : { warning: 'DefectDojo created the risk acceptance but does not report the finding as risk-accepted yet' }),
  };
}
