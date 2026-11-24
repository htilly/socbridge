import { fromChecks, probe } from '../health.js';
import type { BackendHealth, HealthCheck } from '../types.js';
import { describeRemote, type RemoteMcp } from './mcp-proxy.js';
import type { GraylogRuntime } from './queries.js';

/**
 * Node state and indexer cluster status. Search works on a yellow cluster but
 * not on a red one. The cluster endpoint may be forbidden for a reader user;
 * that is reported as degraded (unknown), not down.
 */
export async function graylogHealth(rt: GraylogRuntime & { mcp: RemoteMcp | null }): Promise<BackendHealth> {
  const get = <T>(p: string) => rt.http.request<T>(p, { headers: rt.headers });
  const checks: Promise<HealthCheck>[] = [
    probe('node', async () => {
      const s = await get<{ version?: string; lifecycle?: string; is_processing?: boolean }>('/api/system');
      const what = `Graylog ${s.version ?? ''} ${s.lifecycle ?? 'unknown'}`.replace(/\s+/g, ' ');
      if (s.is_processing === false) return { status: 'degraded', message: `${what}, message processing paused` };
      if (s.lifecycle && !['running', 'override_lb_alive'].includes(s.lifecycle)) return { status: 'degraded', message: what };
      return what;
    }),
    probe('indexer', async () => {
      try {
        const c = await get<{ status?: string }>('/api/system/indexer/cluster/health');
        const st = String(c.status ?? '').toLowerCase();
        if (st === 'red') return { status: 'down', message: 'Indexer cluster red' };
        if (st === 'yellow') return { status: 'degraded', message: 'Indexer cluster yellow' };
        return `Indexer cluster ${st || 'unknown'}`;
      } catch (err) {
        if ((err as { status?: number }).status === 403) return { status: 'degraded', message: 'Cluster status not visible to this user' };
        throw err;
      }
    }),
  ];
  if (rt.mcp) {
    const m = rt.mcp;
    checks.push(probe('mcp', async () => describeRemote(m)).then((c) => (c.status === 'down' ? { ...c, status: 'degraded' as const } : c)));
  }
  return fromChecks(await Promise.all(checks));
}
