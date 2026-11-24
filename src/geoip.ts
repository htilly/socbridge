import { readFile, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { Reader, type CityResponse } from 'mmdb-lib';
import { errMessage, log } from './log.js';

export interface Place {
  lat: number;
  lon: number;
  country: string | null;
}

/** The part of the reader that is used, so tests need no file. */
export interface GeoLookup {
  lookup(ip: string): Place | null;
}

const RECHECK_MS = 60_000;

/**
 * Positions of addresses from a local MaxMind-format city database
 * (GeoLite2-City, DB-IP City Lite). No address leaves the server. A replaced
 * file is picked up within a minute; a broken one keeps the previous in use.
 */
export class GeoIp implements GeoLookup {
  private reader: Reader<CityResponse> | null = null;
  private loaded = '';
  private checked = -Infinity;
  private pending: Promise<void> | null = null;

  constructor(readonly file: string) {}

  /** Makes sure the newest file is loaded. False when there is none to use. */
  async ready(now = Date.now()): Promise<boolean> {
    if (now - this.checked >= RECHECK_MS) {
      this.pending ??= this.refresh().finally(() => {
        this.checked = now;
        this.pending = null;
      });
      await this.pending;
    }
    return this.reader !== null;
  }

  /** Database type, e.g. `GeoLite2-City`; the licences ask for the source to be named. */
  get database(): string | null {
    return this.reader?.metadata.databaseType ?? null;
  }

  private async refresh(): Promise<void> {
    let version = '';
    try {
      const s = await stat(this.file);
      version = `${s.ino}:${s.mtimeMs}:${s.size}`;
      if (version === this.loaded) return;
      this.loaded = version;
      const reader = new Reader<CityResponse>(await readFile(this.file));
      if (!/city|enterprise/i.test(reader.metadata.databaseType)) throw new Error(`${reader.metadata.databaseType} has no positions; a city database is needed`);
      this.reader = reader;
      log.info('GeoIP database loaded', { file: this.file, type: reader.metadata.databaseType });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        this.reader = null;
        this.loaded = '';
      } else log.warn('GeoIP database cannot be used', { file: this.file, error: errMessage(err) });
    }
  }

  lookup(ip: string): Place | null {
    if (!this.reader || !isIP(ip)) return null;
    let r: CityResponse | null;
    try {
      r = this.reader.get(ip);
    } catch {
      return null; // a damaged record, or IPv6 in an IPv4-only database
    }
    const { latitude: lat, longitude: lon } = r?.location ?? {};
    if (typeof lat !== 'number' || typeof lon !== 'number' || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
    return { lat, lon, country: r?.country?.names?.en ?? r?.registered_country?.names?.en ?? null };
  }
}
