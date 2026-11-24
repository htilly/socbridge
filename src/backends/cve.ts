/**
 * A CVE as one backend sees it on one asset: the common shape that backends
 * export for cross-backend tools (the intel module's prioritisation). Each
 * backend maps its own data to this in its queries file, so the knowledge of
 * field names stays in the module that owns them.
 */

export type CveSource = 'wazuh' | 'trivy' | 'defectdojo';

export const CVE_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Unknown'] as const;
export type CveSeverity = (typeof CVE_SEVERITIES)[number];

export interface CveOccurrence {
  cve: string;
  source: CveSource;
  /** Host (Wazuh agent name), image (Trivy artifact) or DefectDojo product. */
  asset: string;
  /** Agent ID, report file or finding ID: what to pass to the backend's own tools. */
  ref?: string;
  package?: string;
  installed?: string;
  /** Version that fixes it, where the backend knows one. */
  fixed?: string;
  severity: CveSeverity;
  cvss?: number;
  /** Seen from the internet (a DefectDojo product an administrator marked as exposed). */
  exposed?: boolean;
  /** When the backend last scanned the asset, where it knows. */
  scanned_at?: string;
  /** DefectDojo: where the finding was seen. */
  endpoints?: SeenEndpoint[];
}

export interface SeenEndpoint {
  host: string;
  port?: number;
  /** Seen from outside: in a product marked as exposed, or a public IP address. */
  external: boolean;
}

export interface CveInventory {
  occurrences: CveOccurrence[];
  /** Set when a size limit cut the collection short. */
  truncated?: string;
  notes?: string[];
  /** What could not be read, so absence proves nothing. */
  gaps?: string[];
  /** DefectDojo: every endpoint, with or without findings. */
  endpoints?: SeenEndpoint[];
}

/** Globally routable, i.e. not private, loopback, link-local, shared or reserved. False for names. */
export function isPublicIp(v: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (m.slice(1).some((x) => Number(x) > 255)) return false;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168));
  }
  return /^[23][0-9a-f]{3}:[0-9a-f:]+$/i.test(v);
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

/** Upper-cased CVE ID, or undefined for anything that is not one (GHSA, vendor IDs). */
export function normaliseCve(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const id = raw.trim().toUpperCase();
  return CVE_RE.test(id) ? id : undefined;
}

/** Maps the backends' severity words (CRITICAL, High, "-", …) onto one scale. */
export function normaliseSeverity(raw: unknown): CveSeverity {
  const s = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium' || s === 'moderate') return 'Medium';
  if (s === 'low' || s === 'info' || s === 'informational' || s === 'negligible') return 'Low';
  return 'Unknown';
}

/** CVE IDs named in free text (rule descriptions, IPS signatures). */
export function cvesIn(texts: string[]): string[] {
  return [...new Set(texts.flatMap((t) => t.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((c) => c.toUpperCase()))];
}
