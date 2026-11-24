/**
 * Minimal structured logger. Writes one JSON object per line to stdout/stderr.
 * Never pass secrets (tokens, passwords, keys) into log fields.
 */

type Level = 'debug' | 'info' | 'warn' | 'error';

const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function threshold(): number {
  const raw = (process.env.LOG_LEVEL ?? 'info').toLowerCase() as Level;
  return ORDER[raw] ?? ORDER.info;
}

function emit(level: Level, msg: string, fields?: Record<string, unknown>): void {
  if (ORDER[level] < threshold()) return;
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields });
  if (level === 'error' || level === 'warn') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}

export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => emit('debug', msg, fields),
  info: (msg: string, fields?: Record<string, unknown>) => emit('info', msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => emit('warn', msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => emit('error', msg, fields),
};

export function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
