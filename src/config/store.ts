import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { decryptJson, encryptJson, needsRekey, type Key } from '../crypto/secretbox.js';
import { log } from '../log.js';
import { writeFileAtomic } from '../util/fs.js';
import { ConfigSchema, emptyConfig, type Config } from './schema.js';

const PURPOSE = 'config';
/** Debounce for "touch" writes such as last-used timestamps. */
const TOUCH_FLUSH_MS = 60_000;

/**
 * Holds the decrypted config in memory and persists it, encrypted, on change.
 *
 * All authorization decisions read from the in-memory copy, so a revoked token
 * or disabled user is rejected on the very next request after `mutate()`
 * resolves — no cache to expire.
 */
export class ConfigStore {
  private current: Config = emptyConfig();
  private rev = 0;
  private writeChain: Promise<void> = Promise.resolve();
  private touchTimer: NodeJS.Timeout | undefined;
  private listeners = new Set<(cfg: Config) => void>();

  constructor(
    private readonly file: string,
    private readonly key: Key,
  ) {}

  static forDataDir(dataDir: string, key: Key): ConfigStore {
    return new ConfigStore(path.join(dataDir, 'config.enc.json'), key);
  }

  async load(): Promise<void> {
    let content: string;
    try {
      content = await readFile(this.file, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        log.info('No config found, starting with an empty configuration', { file: this.file });
        this.current = emptyConfig();
        await this.persist();
        return;
      }
      throw err;
    }
    this.current = ConfigSchema.parse(decryptJson(this.key, PURPOSE, content));
    this.rev++;
    if (needsRekey(this.key, PURPOSE, content)) {
      log.info('Re-encrypting the configuration with the current key and format');
      await this.persist();
    }
  }

  /** Read-only snapshot. Do not mutate the returned object. */
  get(): Readonly<Config> {
    return this.current;
  }

  /** Increments on every change; used to invalidate derived caches. */
  revision(): number {
    return this.rev;
  }

  onChange(fn: (cfg: Config) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /**
   * Apply a change and persist it. The mutator receives a deep copy; if it
   * throws, or the result fails validation, nothing changes.
   */
  async mutate<T>(fn: (draft: Config) => T): Promise<T> {
    const draft = structuredClone(this.current) as Config;
    const result = fn(draft);
    const next = ConfigSchema.parse(draft);
    this.current = next;
    this.rev++;
    await this.persist();
    for (const l of this.listeners) l(next);
    return result;
  }

  /**
   * Low-priority change (e.g. last-used timestamps) applied in memory
   * immediately and flushed to disk at most once per TOUCH_FLUSH_MS.
   * Does not bump the revision, as nothing derived depends on it.
   */
  touch(fn: (draft: Config) => void): void {
    fn(this.current);
    if (this.touchTimer) return;
    this.touchTimer = setTimeout(() => {
      this.touchTimer = undefined;
      this.persist().catch((err) => log.error('Failed to flush config', { error: String(err) }));
    }, TOUCH_FLUSH_MS);
    this.touchTimer.unref();
  }

  async flush(): Promise<void> {
    if (this.touchTimer) {
      clearTimeout(this.touchTimer);
      this.touchTimer = undefined;
    }
    await this.persist();
  }

  private persist(): Promise<void> {
    const snapshot = encryptJson(this.key, PURPOSE, this.current);
    // A failed earlier write must not block later ones.
    this.writeChain = this.writeChain.catch(() => undefined).then(() => writeFileAtomic(this.file, snapshot));
    return this.writeChain;
  }
}
