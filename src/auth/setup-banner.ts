import { log } from '../log.js';

/**
 * The first-admin setup token has to be found in the container log, often
 * among many other lines. It is never a field of a structured log line, which
 * may be shipped elsewhere. Print a plain-text
 * banner that stands out, is easy to grep ("SETUP TOKEN"), and repeat it while
 * no administrator exists so it does not scroll out of `docker logs --tail`.
 */

export const SETUP_REMINDER_MS = 15 * 60 * 1000;

export interface SetupAnnouncement {
  origin: string;
  /** The generated token, or undefined when it comes from SETUP_TOKEN (never printed then). */
  generated?: string;
}

export function setupBanner(a: SetupAnnouncement): string {
  const tokenLine = a.generated ? `SETUP TOKEN:  ${a.generated}` : 'SETUP TOKEN:  the value of SETUP_TOKEN in the service environment';
  const lifetime = a.generated
    ? ['A new token is generated on every restart; set SETUP_TOKEN to keep one fixed.']
    : ['It stays the same across restarts.'];
  const body = [
    'SocBridge · FIRST-TIME SETUP',
    'No administrator exists yet.',
    '',
    tokenLine,
    '',
    `1. Open ${a.origin}`,
    '2. Paste the setup token in step 1 of the setup guide.',
    '',
    'The token works only until the first administrator is created.',
    ...lifetime,
  ];
  const width = Math.max(...body.map((l) => l.length)) + 4;
  const rule = '='.repeat(width);
  return ['', rule, ...body.map((l) => (l ? `  ${l}` : '')), rule, ''].join('\n');
}

export function announceSetupToken(a: SetupAnnouncement, write: (s: string) => void = (s) => process.stderr.write(s + '\n')): void {
  write(setupBanner(a));
  if (a.generated) {
    log.warn('No administrator yet. Open the web UI and enrol with the one-time setup token in the banner on stderr.', { url: a.origin });
  } else {
    log.info('No administrator yet. Open the web UI and enrol with SETUP_TOKEN.', { url: a.origin });
  }
}

/**
 * Prints the banner now and again every SETUP_REMINDER_MS until `pending()`
 * turns false (the first administrator exists).
 */
export function startSetupAnnouncements(a: SetupAnnouncement, pending: () => boolean, intervalMs = SETUP_REMINDER_MS): () => void {
  if (!pending()) return () => undefined;
  announceSetupToken(a);
  const timer = setInterval(() => {
    if (!pending()) {
      clearInterval(timer);
      log.info('First administrator created; the setup token no longer works');
      return;
    }
    announceSetupToken(a);
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
