import { z } from 'zod';
import { BackendError } from './http.js';

/** Time windows of the attack trend, shared so every source has the same columns. */

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

/** Column widths on offer; the narrowest that keeps a chart readable is used. */
const STEPS = [HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 3 * DAY, 7 * DAY, 30 * DAY];
const MAX_COLUMNS = 62;
export const MAX_RANGE_DAYS = 1830;

const PRESET_DAYS = { '24h': 1, '7d': 7, '30d': 30, '90d': 90, '1y': 365, '3y': 1095 } as const;
export type AttackWindow = keyof typeof PRESET_DAYS;
export const ATTACK_WINDOWS = Object.keys(PRESET_DAYS) as [AttackWindow, ...AttackWindow[]];

/** A preset ending now, or an absolute range when from is given (to defaults to now). */
export interface AttackRange {
  window: AttackWindow;
  from?: string;
  to?: string;
}

/** Input of the trend tools and routes. */
export const attackRangeShape = {
  window: z.enum(ATTACK_WINDOWS).default('7d').describe('Window ending now; ignored when from is given'),
  from: z.string().datetime().optional().describe('Absolute start, ISO-8601 UTC, for any range up to 5 years'),
  to: z.string().datetime().optional().describe('Absolute end, ISO-8601 UTC (default now); needs from'),
};

export const iso = (ms: number) => new Date(ms).toISOString();

const stepFor = (length: number) => STEPS.find((s) => length / s <= MAX_COLUMNS - 1) ?? STEPS.at(-1)!;

export function attackWindow(a: AttackRange, now: number) {
  let from: number;
  let to = now;
  let step: number;
  if (a.from) {
    from = Date.parse(a.from);
    to = Math.min(now, a.to ? Date.parse(a.to) : now);
    if (Number.isNaN(from) || Number.isNaN(to) || from >= to) throw new BackendError('Invalid time range: from must be in the past and before to');
    if (to - from > MAX_RANGE_DAYS * DAY) throw new BackendError(`Time range is limited to ${MAX_RANGE_DAYS} days`);
    step = stepFor(to - from);
  } else {
    if (a.to) throw new BackendError('to needs from');
    const length = PRESET_DAYS[a.window] * DAY;
    step = stepFor(length);
    // Whole columns; the last one is still filling.
    from = Math.floor(now / step) * step - (Math.ceil(length / step) - 1) * step;
  }
  // Columns are aligned like the indexers' histograms (UTC), so a range that starts mid-column has a partial first one.
  const gridFrom = Math.floor(from / step) * step;
  return {
    step,
    from,
    to,
    gridFrom,
    columns: Math.ceil((to - gridFrom) / step),
    // The same length of time just before, so partly filled columns do not skew the comparison.
    previousFrom: from - (to - from),
  };
}

/** Whether the data reaches back far enough for the previous period to mean anything. */
export const reachesBack = (oldest: number | null, previousFrom: number, step: number) =>
  oldest !== null && oldest <= previousFrom + Math.min(step, DAY);
