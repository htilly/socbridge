import { X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { SecureContextOptions } from 'node:tls';
import type { ServerTls } from '../config/schema.js';
import type { ConfigStore } from '../config/store.js';
import { decryptJson, encryptJson, needsRekey } from '../crypto/secretbox.js';
import type { Env } from '../env.js';
import { errMessage, log } from '../log.js';
import { writeFileAtomic } from '../util/fs.js';
import { acmeNames, checkCloudflareToken, issueCertificate, type AcmeLog, type AcmeOptions, type AcmeState, type CfZoneCheck } from './acme.js';
import { daysRemaining, RENEW_BEFORE_DAYS } from './ca.js';
import { builtin, createTlsProvider } from './index.js';

/**
 * Owns the server certificate at runtime.
 *
 * When TLS_MODE is set in the environment the manager is *locked*: it wraps
 * the environment-driven provider and the UI shows the settings read-only.
 * Otherwise the mode (built-in CA or Let's Encrypt over Cloudflare DNS-01) is
 * read from the encrypted config and can be changed from the web UI without a
 * restart. The built-in CA always exists as a fallback, so the service keeps
 * serving while a Let's Encrypt certificate is being obtained or if it fails.
 */

export type IssueFn = (opts: AcmeOptions, state: AcmeState | undefined, log: AcmeLog) => Promise<AcmeState>;
export type CheckTokenFn = (token: string, domains: string[]) => Promise<CfZoneCheck[]>;

const ACME_RETRY_MS = 30 * 60 * 1000;
const ACME_RENEW_RETRY_MS = 6 * 60 * 60 * 1000;
const TICK_MS = 5 * 60 * 1000;
const JOB_LOG_LIMIT = 200;
const DEFAULT_RESOLVERS = ['1.1.1.1', '8.8.8.8'];

export interface JobView {
  kind: 'test' | 'apply';
  state: 'running' | 'ok' | 'error';
  startedAt: string;
  finishedAt?: string;
  log: { ts: string; msg: string }[];
}

export interface CertView {
  issuer: string;
  subject: string;
  sans: string[];
  validTo: string;
  daysLeft: number;
  fingerprint: string;
}

export interface TlsView {
  locked: boolean;
  lockedReason?: string;
  envMode: string;
  settings: {
    mode: 'builtin' | 'acme';
    acmeEmail?: string;
    acmeStaging: boolean;
    acmeAgreeTos: boolean;
    cloudflareTokenSet: boolean;
    /** Last four characters of the stored token, so the admin can tell which one it is. */
    cloudflareTokenHint?: string;
    cloudflareTokenSavedAt?: string;
  };
  domains: string[];
  /** Configured names a Let's Encrypt certificate cannot contain. */
  skippedNames: string[];
  serving: 'builtin' | 'acme' | 'file' | 'env-acme';
  certificate: CertView | null;
  /** The served certificate comes from Let's Encrypt staging: browsers do not trust it, so passkeys fail. */
  staging: boolean;
  lastError?: string;
  lastAttempt?: string;
  job: JobView | null;
  caAvailable: boolean;
}

export interface TlsSettingsInput {
  mode: 'builtin' | 'acme';
  acmeEmail?: string;
  acmeStaging: boolean;
  acmeAgreeTos: boolean;
  /** Empty or undefined keeps the stored token. */
  cloudflareToken?: string;
}

export class TlsSettingsError extends Error {}

export interface TokenCheckResult {
  /** Which token was checked: the one typed in the form (not saved) or the stored one. */
  source: 'entered' | 'stored';
  ok: boolean;
  zones?: CfZoneCheck[];
  error?: string;
}

function certView(pem: string | undefined): CertView | null {
  if (!pem) return null;
  try {
    const x = new X509Certificate(pem);
    return {
      issuer: x.issuer.split('\n').join(', '),
      subject: x.subject.split('\n').join(', '),
      sans: (x.subjectAltName ?? '').split(',').map((s) => s.trim().replace(/^(DNS|IP Address):/, '')).filter(Boolean),
      validTo: new Date(x.validTo).toISOString(),
      daysLeft: Math.floor(daysRemaining(pem)),
      fingerprint: x.fingerprint256,
    };
  } catch {
    return null;
  }
}

/** Same shape Cloudflare's token list uses ("cfat...3e1f"), so the two can be compared. */
function tokenHint(token: string): string {
  return token.length > 12 ? `${token.slice(0, 4)}...${token.slice(-4)}` : '...';
}

function firstCert(pem: string): string {
  const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem);
  return m ? m[0] : pem;
}

export class TlsManager {
  private swapListeners: ((ctx: SecureContextOptions) => void)[] = [];
  private current!: SecureContextOptions;
  private serving: TlsView['serving'] = 'builtin';
  private builtinCtx?: SecureContextOptions;
  private acmeState?: AcmeState;
  private lastAttempt = 0;
  private lastError?: string;
  private job: JobView | null = null;
  private lockedReason?: string;
  caCertPem?: string;

  private constructor(
    private readonly env: Env,
    private readonly store: ConfigStore,
    private readonly issue: IssueFn,
    private readonly checkToken: CheckTokenFn,
  ) {}

  /** Returns null when TLS is off (plain HTTP behind a proxy). */
  static async create(
    env: Env,
    store: ConfigStore,
    issue: IssueFn = issueCertificate,
    checkToken: CheckTokenFn = checkCloudflareToken,
  ): Promise<TlsManager | null> {
    if (env.tlsMode === 'off') return null;
    const m = new TlsManager(env, store, issue, checkToken);
    if (env.tlsModeFromEnv) await m.initLocked();
    else await m.initManaged();
    return m;
  }

  get initial(): SecureContextOptions {
    return this.current;
  }

  onSwap(fn: (ctx: SecureContextOptions) => void): void {
    this.swapListeners.push(fn);
  }

  /** SHA-256 fingerprint of the built-in CA certificate, as logged at startup ("Built-in CA ready"). */
  caFingerprint(): string | null {
    if (!this.caCertPem) return null;
    try {
      return new X509Certificate(this.caCertPem).fingerprint256;
    } catch {
      return null;
    }
  }

  /** Names a Let's Encrypt certificate covers (public DNS names only). */
  domains(): string[] {
    return acmeNames(this.env.publicUrl.hostname, this.env.tlsExtraSans).names;
  }

  /** Configured names left out of the Let's Encrypt certificate (bare host names, IPs, .local …). */
  skippedNames(): string[] {
    return acmeNames(this.env.publicUrl.hostname, this.env.tlsExtraSans).skipped;
  }

  private settings(): ServerTls {
    return this.store.get().server?.tls ?? { mode: 'builtin', acmeStaging: false, acmeAgreeTos: false };
  }

  private swap(ctx: SecureContextOptions, serving: TlsView['serving']): void {
    this.current = ctx;
    this.serving = serving;
    for (const fn of this.swapListeners) fn(ctx);
  }

  // --- locked: environment decides ---------------------------------------

  private async initLocked(): Promise<void> {
    this.lockedReason = `TLS_MODE=${this.env.tlsMode} is set in the environment`;
    const provider = (await createTlsProvider(this.env))!;
    this.caCertPem = provider.caCertPem;
    this.current = provider.initial;
    this.serving = this.env.tlsMode === 'file' ? 'file' : this.env.tlsMode === 'acme' ? 'env-acme' : 'builtin';
    provider.watch((ctx) => this.swap(ctx, this.serving));
  }

  // --- managed: web UI decides ---------------------------------------------

  private stateFile(staging: boolean): string {
    return path.join(this.env.dataDir, 'tls', staging ? 'acme-staging.enc.json' : 'acme.enc.json');
  }

  private async loadState(staging: boolean): Promise<AcmeState | undefined> {
    try {
      const content = await readFile(this.stateFile(staging), 'utf8');
      const state = decryptJson<AcmeState>(this.env.encryptionKey, 'acme', content);
      if (needsRekey(this.env.encryptionKey, 'acme', content)) await writeFileAtomic(this.stateFile(staging), encryptJson(this.env.encryptionKey, 'acme', state));
      return state;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw err;
    }
  }

  private matches(state: AcmeState | undefined): boolean {
    const want = [...this.domains()].sort().join(',');
    return !!state?.certPem && !!state.domains && [...state.domains].sort().join(',') === want;
  }

  private usable(state: AcmeState | undefined): boolean {
    return this.matches(state) && daysRemaining(state!.certPem!) > 1;
  }

  private fresh(state: AcmeState | undefined): boolean {
    return this.matches(state) && daysRemaining(state!.certPem!) > RENEW_BEFORE_DAYS;
  }

  private acmeCtx(state: AcmeState): SecureContextOptions {
    return { key: state.keyPem!, cert: state.certPem! };
  }

  private async initManaged(): Promise<void> {
    const fallback = await builtin(this.env);
    this.caCertPem = fallback.caCertPem;
    this.builtinCtx = fallback.initial;
    // The built-in leaf renews itself; only serve it while it is the active mode.
    fallback.watch((ctx) => {
      this.builtinCtx = ctx;
      if (this.serving === 'builtin') this.swap(ctx, 'builtin');
    });

    const s = this.settings();
    this.current = this.builtinCtx;
    if (s.mode === 'acme') {
      this.acmeState = await this.loadState(s.acmeStaging);
      if (this.usable(this.acmeState)) {
        this.current = this.acmeCtx(this.acmeState!);
        this.serving = 'acme';
      }
      if (!this.fresh(this.acmeState)) this.startApply();
    }
    setInterval(() => this.tick(), TICK_MS).unref();
  }

  private tick(): void {
    const s = this.settings();
    if (this.lockedReason || s.mode !== 'acme' || this.job?.state === 'running') return;
    if (this.serving === 'acme' && this.fresh(this.acmeState)) return;
    const wait = this.serving === 'builtin' ? ACME_RETRY_MS : ACME_RENEW_RETRY_MS;
    if (Date.now() - this.lastAttempt < wait) return;
    this.startApply();
  }

  private logSkipped(add: AcmeLog): void {
    const skipped = this.skippedNames();
    if (skipped.length) {
      add(`Leaving out ${skipped.join(', ')}: not a public DNS name, so Let's Encrypt cannot validate it (TLS_EXTRA_SANS). Use the full name, e.g. ${this.env.publicUrl.hostname}.`);
    }
  }

  private acmeOptions(s: ServerTls, staging: boolean): AcmeOptions {
    if (!s.cloudflareToken) throw new TlsSettingsError('A Cloudflare API token is required');
    if (!this.domains().length) {
      throw new TlsSettingsError(`${this.env.publicUrl.hostname} (from PUBLIC_URL) is not a public DNS name, so Let's Encrypt cannot issue a certificate for it`);
    }
    return {
      domains: this.domains(),
      email: s.acmeEmail || undefined,
      staging,
      cloudflareToken: s.cloudflareToken,
      resolvers: DEFAULT_RESOLVERS,
    };
  }

  private runJob(kind: JobView['kind'], work: (log: AcmeLog) => Promise<void>): void {
    const job: JobView = { kind, state: 'running', startedAt: new Date().toISOString(), log: [] };
    this.job = job;
    const add: AcmeLog = (msg) => {
      job.log.push({ ts: new Date().toISOString(), msg });
      if (job.log.length > JOB_LOG_LIMIT) job.log.shift();
    };
    work(add)
      .then(() => {
        job.state = 'ok';
      })
      .catch((err) => {
        job.state = 'error';
        add(`Failed: ${errMessage(err)}`);
      })
      .finally(() => {
        job.finishedAt = new Date().toISOString();
      });
  }

  private startApply(): void {
    this.runJob('apply', async (add) => {
      const s = this.settings();
      if (s.mode !== 'acme') return;
      this.lastAttempt = Date.now();
      this.logSkipped(add);
      try {
        const state = await this.issue(this.acmeOptions(s, s.acmeStaging), await this.loadState(s.acmeStaging), add);
        await writeFileAtomic(this.stateFile(s.acmeStaging), encryptJson(this.env.encryptionKey, 'acme', state));
        // Settings may have changed while we waited; only activate if still wanted.
        const now = this.settings();
        if (now.mode !== 'acme' || now.acmeStaging !== s.acmeStaging) {
          add('Settings changed during issuance; certificate stored but not activated');
          return;
        }
        this.acmeState = state;
        this.lastError = undefined;
        this.swap(this.acmeCtx(state), 'acme');
        add(`Now serving the ${s.acmeStaging ? 'staging (untrusted) ' : ''}Let's Encrypt certificate`);
        log.info('Switched to Let\'s Encrypt certificate', { domains: state.domains, staging: s.acmeStaging });
      } catch (err) {
        this.lastError = errMessage(err);
        log.error('ACME certificate request failed', { error: this.lastError });
        if (this.serving === 'builtin') add('Still serving the built-in CA certificate; will retry in 30 minutes');
        throw err;
      }
    });
  }

  // --- API ---------------------------------------------------------------

  view(): TlsView {
    const s = this.settings();
    const current = typeof this.current?.cert === 'string' ? firstCert(this.current.cert) : undefined;
    const cert = certView(current);
    return {
      locked: !!this.lockedReason,
      lockedReason: this.lockedReason,
      envMode: this.env.tlsMode,
      settings: {
        mode: this.lockedReason ? (this.env.tlsMode === 'acme' ? 'acme' : 'builtin') : s.mode,
        acmeEmail: s.acmeEmail,
        acmeStaging: s.acmeStaging,
        acmeAgreeTos: s.acmeAgreeTos,
        cloudflareTokenSet: !!s.cloudflareToken,
        cloudflareTokenHint: s.cloudflareToken ? tokenHint(s.cloudflareToken) : undefined,
        cloudflareTokenSavedAt: s.cloudflareToken ? s.cloudflareTokenSavedAt : undefined,
      },
      domains: this.domains(),
      skippedNames: this.skippedNames(),
      serving: this.serving,
      certificate: cert,
      staging: !!cert && /STAGING/i.test(cert.issuer),
      lastError: this.lastError,
      lastAttempt: this.lastAttempt ? new Date(this.lastAttempt).toISOString() : undefined,
      job: this.job,
      caAvailable: !!this.caCertPem,
    };
  }

  private assertUnlocked(): void {
    if (this.lockedReason) throw new TlsSettingsError(`Certificate settings are managed by the environment (${this.lockedReason})`);
  }

  private assertIdle(): void {
    if (this.job?.state === 'running') throw new TlsSettingsError('A certificate job is already running');
  }

  private merged(input: TlsSettingsInput): ServerTls {
    const prev = this.settings();
    return {
      mode: input.mode,
      acmeEmail: input.acmeEmail?.trim() || undefined,
      acmeStaging: input.acmeStaging,
      acmeAgreeTos: input.acmeAgreeTos,
      cloudflareToken: input.cloudflareToken?.trim() || prev.cloudflareToken,
      cloudflareTokenSavedAt: input.cloudflareToken?.trim() ? new Date().toISOString() : prev.cloudflareTokenSavedAt,
    };
  }

  /** Save settings and apply them: switch back to the built-in CA at once, or start issuance. */
  async save(input: TlsSettingsInput): Promise<void> {
    this.assertUnlocked();
    this.assertIdle();
    const next = this.merged(input);
    if (next.mode === 'acme') {
      if (!next.acmeAgreeTos) throw new TlsSettingsError("Accept the Let's Encrypt subscriber agreement to use ACME");
      if (!next.cloudflareToken) throw new TlsSettingsError('A Cloudflare API token is required');
    }
    await this.store.mutate((d) => {
      d.server = { ...(d.server ?? {}), tls: next };
    });
    if (next.mode === 'builtin') {
      if (this.serving !== 'builtin') this.swap(this.builtinCtx!, 'builtin');
      this.lastError = undefined;
      return;
    }
    const stored = await this.loadState(next.acmeStaging);
    if (this.fresh(stored)) {
      this.acmeState = stored;
      this.swap(this.acmeCtx(stored!), 'acme');
      return;
    }
    this.startApply();
  }

  /**
   * Checks the typed (or stored) Cloudflare token against the zones for this
   * server's names, without contacting Let's Encrypt. Takes a few seconds.
   */
  async checkCloudflare(input: { cloudflareToken?: string }): Promise<TokenCheckResult> {
    this.assertUnlocked();
    const typed = input.cloudflareToken?.trim();
    const token = typed || this.settings().cloudflareToken;
    if (!token) throw new TlsSettingsError('Enter a Cloudflare API token first');
    const source = typed ? 'entered' : 'stored';
    try {
      return { source, ok: true, zones: await this.checkToken(token, this.domains()) };
    } catch (err) {
      return { source, ok: false, error: errMessage(err) };
    }
  }

  /**
   * Dry run against Let's Encrypt staging with the given (or stored) settings.
   * Verifies the token, zone lookup, TXT record creation and propagation, and
   * obtains an untrusted test certificate. Nothing is stored or activated.
   */
  startTest(input: TlsSettingsInput): void {
    this.assertUnlocked();
    this.assertIdle();
    const s = this.merged({ ...input, mode: 'acme' });
    const opts = this.acmeOptions(s, true);
    const entered = !!input.cloudflareToken?.trim();
    this.runJob('test', async (add) => {
      add('Dry run against Let\'s Encrypt staging; nothing will be stored or activated');
      this.logSkipped(add);
      add(entered ? 'Using the token typed in the form (not saved; press "Save & apply" to keep it)' : `Using the stored token ${tokenHint(s.cloudflareToken!)}`);
      await this.issue(opts, undefined, add);
      add('Test succeeded. Save with "Let\'s Encrypt" selected to switch for real.');
    });
  }
}
