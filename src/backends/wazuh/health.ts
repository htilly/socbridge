import { fromChecks, probe } from '../health.js';
import type { BackendHealth } from '../types.js';
import type { WazuhClient } from './client.js';

/** Manager API and indexer are checked separately: agent tools work without the indexer. */
export async function wazuhHealth(client: WazuhClient): Promise<BackendHealth> {
  const checks = await Promise.all([
    probe('manager', async () => {
      const info = await client.api<{ data?: { api_version?: string } }>('/');
      return `Manager API ${info.data?.api_version ?? 'unknown'} answers`;
    }),
    client.hasIndexer
      ? probe('indexer', async () => {
          const info = await client.indexerInfo();
          return `${info.version?.distribution ?? 'opensearch'} ${info.version?.number ?? ''}`.trim() + ' answers';
        })
      : Promise.resolve({ name: 'indexer', status: 'degraded' as const, message: 'Not configured: alert and vulnerability tools are off' }),
  ]);
  return fromChecks(checks);
}
