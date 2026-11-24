/**
 * Fixed-window failure counter keyed by client address. Used to slow down
 * token guessing and repeated failed passkey/setup attempts. In-memory only:
 * a restart resets it, which is acceptable for a single-instance service.
 */
export class FailureLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly maxFailures: number,
    private readonly windowMs: number,
  ) {
    setInterval(() => this.sweep(), windowMs).unref();
  }

  isBlocked(key: string): boolean {
    const entry = this.hits.get(key);
    if (!entry) return false;
    if (entry.resetAt <= Date.now()) {
      this.hits.delete(key);
      return false;
    }
    return entry.count >= this.maxFailures;
  }

  fail(key: string): void {
    const now = Date.now();
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
    else entry.count++;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
  }
}

/** Fixed-window request counter for authenticated callers, keyed by user. In-memory, like FailureLimiter. */
export class RequestLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs = 60_000,
  ) {
    setInterval(() => {
      const now = Date.now();
      for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
    }, windowMs).unref();
  }

  /** Counts `n` requests; false when the caller is over the limit. */
  take(key: string, n = 1): boolean {
    const now = Date.now();
    let e = this.hits.get(key);
    if (!e || e.resetAt <= now) this.hits.set(key, (e = { count: 0, resetAt: now + this.windowMs }));
    e.count += n;
    return e.count <= this.max;
  }
}
