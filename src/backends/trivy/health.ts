import { fromChecks, probe } from '../health.js';
import type { BackendHealth } from '../types.js';
import type { TrivyReports } from './reports.js';

/** The report directory must be readable; unreadable files degrade, none readable is down. */
export async function trivyHealth(rt: TrivyReports): Promise<BackendHealth> {
  return fromChecks([
    await probe('reports', async () => {
      const entries = await rt.all();
      const bad = entries.filter((e) => 'error' in e).length;
      const ok = entries.length - bad;
      if (entries.length === 0) return { status: 'ok', message: 'Directory readable, no reports yet' };
      if (ok === 0) return { status: 'down', message: `${bad} JSON file(s), none readable as a Trivy report` };
      if (bad) return { status: 'degraded', message: `${ok} report(s) readable, ${bad} skipped` };
      return `${ok} report(s) readable`;
    }),
  ]);
}
