import { fromChecks, probe } from '../health.js';
import type { BackendHealth } from '../types.js';
import type { DefectDojoRuntime } from './queries.js';

export async function defectdojoHealth(rt: DefectDojoRuntime): Promise<BackendHealth> {
  return fromChecks([
    await probe('api', async () => {
      const r = await rt.http.request<{ count?: number }>('/api/v2/products/', { query: { limit: 1 }, headers: { authorization: rt.auth } });
      return `API v2 answers; ${r.count ?? 0} product(s) visible`;
    }),
  ]);
}
