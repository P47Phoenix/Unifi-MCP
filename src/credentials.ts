/**
 * API key resolution: OS keychain first, mounted file second, environment third
 * (FR-14, FR-15, FR-78).
 *
 * Two invariants this module exists to hold:
 *
 *  1. The server NEVER writes a key to disk. There is no cache file, no state
 *     directory, no debug dump. Resolved keys live only in the in-memory map
 *     below and in the private capture object of `captureCredentialEnv`, and
 *     the redacted-summary path (FR-55) never sees this module. FR-78's
 *     `*_FILE` delivery does not weaken this: reading a secret an operator
 *     mounted is a READ, performed once, of a file this process never creates,
 *     never rewrites and never copies anywhere else. The invariant is about
 *     this server emitting key material onto disk, and nothing here does.
 *  2. Elicitation is never used to obtain a credential (FR-16). A missing key
 *     is a configuration error with a named remedy, not an interactive prompt.
 *
 * ## The capture-then-delete scrub (FR-78, NFR-31)
 *
 * `docker inspect` and `kubectl describe pod` render a container's environment,
 * so a UniFi key delivered by `-e` is disclosed to anyone who can read either.
 * §5.15.1b answers that with a `*_FILE` sibling for every credential variable,
 * and NFR-31 answers the rest by deleting the variables once they are resolved.
 *
 * The ORDER is the whole mechanism, and getting it wrong is not visible at
 * startup. `CredentialStore` resolves LAZILY — `lookup()` reads `this.env` on
 * the first tool call, not in the constructor — so a scrub that only DELETES
 * passes every startup check, binds, logs a green ready line, and then throws
 * on the operator's first tool call. `captureCredentialEnv` therefore copies
 * every resolved value into a private object FIRST; the store is constructed
 * with that object as `options.env`; only then does `scrubCredentialEnv` delete
 * the names from the environment the process was handed.
 *
 * `scrubCredentialEnv` deletes from the object it is given and never from
 * `process.env` by default. In production the runtime hands it `process.env`,
 * so NFR-31 holds; a test that injects its own environment object leaves the
 * real one untouched, which is what keeps fixtures in one file independent
 * (architecture §10.1).
 */
import { readFileSync, statSync } from 'node:fs';

import type { ServerConfig } from './config.js';
import { CLOUD_API_KEY_ENV } from './config.js';
import type { ServiceId, TransportMode } from './types.js';
import { UnifiError } from './types.js';
import { localError } from './http/errors.js';

/** Keychain service name. One entry per env-var name, so the two paths agree. */
const KEYCHAIN_SERVICE = 'unifi-mcp';

/**
 * The slice of keytar's surface used here, declared locally so the optional
 * dependency is not a compile-time dependency.
 *
 * Exported ONLY so a test can type the stub it injects through
 * `CredentialStoreOptions.keychain`; nothing in `src/` imports it.
 */
export interface KeytarLike {
  getPassword(service: string, account: string): Promise<string | null>;
}

export interface CredentialStoreOptions {
  env?: NodeJS.ProcessEnv;
  /** Diagnostics go to stderr, never stdout (NFR-19). */
  warn?: (message: string) => void;
  /**
   * The keychain collaborator, and the third named bounded exception to the
   * core-unchanged invariant (architecture §10.3).
   *
   * `null` skips `loadKeytar()` entirely; `undefined` is production behaviour,
   * unchanged. It exists because `keytar` is an `optionalDependency` that
   * `npm ci` installs on the macOS and Windows CI legs, so a test exercising
   * FR-78's real credential path would otherwise query the runner's — or a
   * developer's — real login keychain. Node 20 has no `mock.module`, and the
   * alternative (a subclass overriding the load) would satisfy the
   * "real credential path" criterion with a substitute, which is the one thing
   * that criterion exists to prevent.
   */
  keychain?: KeytarLike | null;
}

export class CredentialStore {
  private readonly env: NodeJS.ProcessEnv;
  private readonly warn: (message: string) => void;
  private readonly cache = new Map<string, string>();
  private keytar: KeytarLike | null | undefined;
  private warnedNoKeychain = false;

  constructor(
    private readonly config: ServerConfig,
    options: CredentialStoreOptions = {},
  ) {
    this.env = options.env ?? process.env;
    this.warn = options.warn ?? ((m) => process.stderr.write(`${m}\n`));
    // Seeds the ONE existing memoisation point in `loadKeytar`. `undefined`
    // assigns `undefined`, which is the field's initial value, so production
    // takes exactly the path it took before this field existed.
    this.keytar = options.keychain;
  }

  /**
   * The key for a given request.
   *
   * FR-14: the single cloud key covers Site Manager, Mobility, AND all Cloud
   * Connector traffic — connector requests terminate at api.ui.com, so the
   * console's own local key is not the credential that authenticates them.
   * Only local-direct requests use a console-bound key.
   */
  async resolveFor(service: ServiceId, mode: TransportMode, host?: string): Promise<string> {
    if (mode !== 'local') return this.resolveCloudKey(service);

    const target = host ?? this.config.defaultLocalHost;
    if (!target) {
      throw new UnifiError(
        localError(
          service,
          'config',
          `A local-direct ${service} request was attempted with no console host configured.`,
          'Set UNIFI_LOCAL_HOST to the console address and UNIFI_LOCAL_API_KEY to a key created ' +
            'on that console.',
        ),
      );
    }

    const console_ = this.config.localConsoles.find((c) => c.host === target);
    if (!console_) {
      throw new UnifiError(
        localError(
          service,
          'config',
          `No credential is bound to local console host \`${target}\`.`,
          `Configure that host and its key: set UNIFI_LOCAL_HOST=${target} and ` +
            `UNIFI_LOCAL_API_KEY, or for an additional console set ` +
            `UNIFI_LOCAL_HOST_<LABEL>=${target} and UNIFI_LOCAL_API_KEY_<LABEL>.`,
        ),
      );
    }

    const key = await this.lookup(console_.apiKeyEnvVar);
    if (!key) {
      throw new UnifiError(
        localError(
          service,
          'config',
          `Local console host \`${target}\` has no API key configured.`,
          `Set the environment variable \`${console_.apiKeyEnvVar}\` to a key created on ` +
            `${target}, or store it in the OS keychain under service "${KEYCHAIN_SERVICE}" ` +
            `account "${console_.apiKeyEnvVar}".`,
        ),
      );
    }
    return key;
  }

  private async resolveCloudKey(service: ServiceId): Promise<string> {
    const key = await this.lookup(CLOUD_API_KEY_ENV);
    if (!key) {
      throw new UnifiError(
        localError(
          service,
          'config',
          `No cloud API key is configured, so ${service} cannot be reached.`,
          `Set the environment variable \`${CLOUD_API_KEY_ENV}\`, or store it in the OS keychain ` +
            `under service "${KEYCHAIN_SERVICE}" account "${CLOUD_API_KEY_ENV}". Create the key ` +
            `at https://unifi.ui.com.`,
        ),
      );
    }
    return key;
  }

  /**
   * Keychain first (FR-15), then file, then environment (FR-78). Cached in
   * memory only — never on disk.
   *
   * The file step is normally INERT: in the wired startup path
   * `captureCredentialEnv` has already resolved every `*_FILE` into the private
   * object this store was handed, so `this.env[account]` hits first and the
   * path variable is not even present. It is reached when a store is
   * constructed over an environment that still carries the path — which is
   * what makes file delivery work rather than being accepted and discarded.
   */
  private async lookup(account: string): Promise<string | null> {
    const cached = this.cache.get(account);
    if (cached !== undefined) return cached;

    const keytar = await this.loadKeytar();
    if (keytar) {
      try {
        const stored = await keytar.getPassword(KEYCHAIN_SERVICE, account);
        if (stored) {
          this.cache.set(account, stored);
          return stored;
        }
      } catch (e) {
        // A locked or unavailable keychain must not take the server down when
        // the env path would have worked.
        this.warn(
          `unifi-mcp: keychain lookup for "${account}" failed (${(e as Error).message}); ` +
            `falling back to the environment.`,
        );
      }
    }

    const fromFile = this.readCredentialFile(account);
    if (fromFile) {
      this.cache.set(account, fromFile);
      return fromFile;
    }

    const fromEnv = this.env[account]?.trim();
    if (fromEnv) {
      if (!keytar) this.warnKeychainUnavailable();
      this.cache.set(account, fromEnv);
      return fromEnv;
    }
    return null;
  }

  /**
   * FR-78 file delivery for one account, resolved on demand.
   *
   * Diagnostics only: a delivery problem here is reported on stderr naming the
   * variable and the path — never the content — and resolution then falls
   * through to the existing structured refusal, which names the plain variable.
   * The FATAL form of the same three problems belongs at startup, where
   * `captureCredentialEnv` produces them before anything binds.
   */
  private readCredentialFile(account: string): string | null {
    const path = this.env[credentialFileVar(account)];
    if (path === undefined || path === '') return null;

    const read = readCredentialFile(account, path);
    for (const warning of read.warnings) this.warn(`unifi-mcp: WARNING ${warning}`);
    for (const problem of read.problems) this.warn(`unifi-mcp: ${problem}`);
    return read.value;
  }

  /**
   * `keytar` is an optionalDependency with a native build step. On a machine
   * where it failed to compile, or in a headless container with no keychain at
   * all, the import throws — and the server must still run (FR-15). The module
   * specifier is held in a variable so TypeScript does not turn an optional
   * runtime dependency into a required compile-time one.
   */
  private async loadKeytar(): Promise<KeytarLike | null> {
    if (this.keytar !== undefined) return this.keytar;
    const moduleName = 'keytar';
    try {
      const loaded = (await import(moduleName)) as { default?: KeytarLike } & KeytarLike;
      const resolved = typeof loaded.getPassword === 'function' ? loaded : loaded.default;
      this.keytar = resolved && typeof resolved.getPassword === 'function' ? resolved : null;
    } catch {
      this.keytar = null;
    }
    return this.keytar;
  }

  private warnKeychainUnavailable(): void {
    if (this.warnedNoKeychain) return;
    this.warnedNoKeychain = true;
    this.warn(
      'unifi-mcp: OS keychain storage is not in use — the `keytar` optional dependency is ' +
        'unavailable, so API keys are being read from environment variables. This is supported ' +
        'for CI and headless use; on a workstation, install keytar to keep keys out of the ' +
        'process environment.',
    );
  }
}

// ===========================================================================
// FR-78 / §5.15.1b — file delivery, capture, and the environment scrub
// ===========================================================================

/**
 * The reserved suffix that turns a credential variable into its file sibling.
 *
 * DELIBERATELY DUPLICATED from `RESERVED_FILE_SUFFIX` in `src/serve/auth.ts`
 * and from the `_FILE` names registered in `src/config.ts`. Nothing under
 * `src/` outside `src/serve/` may import `src/serve/*` (architecture §11.1),
 * and `src/config.ts` may import neither, so the three copies are pinned to
 * each other by `test/credentials-file.test.ts` instead — the same treatment
 * `config.ts` already gives the path canonicaliser and the auth-mode grammar.
 */
export const CREDENTIAL_FILE_SUFFIX = '_FILE';

/**
 * The 4 KiB cap on a `*_FILE` payload, compared against the RAW bytes read.
 * Exactly 4096 bytes is accepted; 4097 is refused. Matches
 * `MAX_SECRET_FILE_BYTES` in `src/serve/auth.ts` — a file bigger than this is
 * almost always a certificate or a key bundle pointed at the wrong variable.
 */
export const MAX_CREDENTIAL_FILE_BYTES = 4096;

/** `UNIFI_API_KEY` -> `UNIFI_API_KEY_FILE` (§5.15.1b). */
export function credentialFileVar(account: string): string {
  return `${account}${CREDENTIAL_FILE_SUFFIX}`;
}

/** The outcome of resolving one credential account's `{ plain, file }` pair. */
export interface CredentialDelivery {
  /** The PLAINTEXT key, or `null` when none resolved. */
  readonly value: string | null;
  readonly source: 'env' | 'file' | null;
  /** Fatal at startup. Names the variable and the path, never the content. */
  readonly problems: string[];
  /** Non-fatal. The §3.7 permissions finding. */
  readonly warnings: string[];
}

/**
 * Resolve one credential account: file first, environment second (FR-78).
 *
 * Pure over `env`, and `readFile` is a default parameter so every rule below is
 * exercisable with no filesystem at all — Node 20 has no `mock.module`, so a
 * default parameter is the only seam available.
 *
 * Every rule here mirrors `resolveFileBackedSecret` in `src/serve/auth.ts`,
 * which owns the identical mechanism for the INBOUND secret: the 4 KiB cap, the
 * single trailing newline and no other transformation, the both-set refusal,
 * the three delivery refusals and the permissions warning. The two copies exist
 * because the import direction forbids sharing one; `test/credentials-file.test.ts`
 * asserts they agree case for case, so a divergence fails the build.
 */
export function resolveCredentialDelivery(
  env: NodeJS.ProcessEnv,
  account: string,
  readFile: (p: string) => Buffer = readFileSync,
): CredentialDelivery {
  const file = credentialFileVar(account);
  const plain = env[account];
  const path = env[file];
  const hasPlain = plain !== undefined && plain !== '';
  const hasFile = path !== undefined && path !== '';

  if (hasPlain && hasFile) {
    return { value: null, source: null, problems: [bothSetProblem(account)], warnings: [] };
  }
  if (hasFile && path !== undefined) return readCredentialFile(account, path, readFile);
  if (hasPlain && plain !== undefined) {
    return { value: plain, source: 'env', problems: [], warnings: [] };
  }
  return { value: null, source: null, problems: [], warnings: [] };
}

/**
 * Read one `*_FILE` payload. The three delivery refusals — unreadable, empty,
 * larger than 4 KiB — name the variable and the path and NEVER the content.
 */
export function readCredentialFile(
  account: string,
  path: string,
  readFile: (p: string) => Buffer = readFileSync,
): CredentialDelivery {
  let bytes: Buffer;
  try {
    bytes = readFile(path);
  } catch {
    return { value: null, source: null, problems: [unreadableProblem(account, path)], warnings: [] };
  }

  const warnings = exposedFilePermissionWarnings(account, path);
  if (bytes.byteLength > MAX_CREDENTIAL_FILE_BYTES) {
    return { value: null, source: null, problems: [oversizeProblem(account, path)], warnings };
  }

  const text = bytes.toString('utf8');
  // Exactly one trailing newline, and no other transformation whatsoever
  // (FR-78). No trim: a key written by `printf '%s' "$K"` and one written by
  // `echo "$K"` must both authenticate, and nothing else may be silently eaten.
  const value = text.endsWith('\n') ? text.slice(0, -1) : text;
  if (value === '') {
    return { value: null, source: null, problems: [emptyProblem(account, path)], warnings };
  }
  return { value, source: 'file', problems: [], warnings };
}

/** Everything the scrub must delete, and the private object the store reads. */
export interface CredentialEnvCapture {
  /**
   * The private environment object: resolved PLAINTEXT under each account's
   * plain variable name, and nothing else. Hand this to
   * `new CredentialStore(config, { env: capture.env, ... })`.
   */
  readonly env: NodeJS.ProcessEnv;
  /** Every credential variable name — plain and `*_FILE` — for both classes. */
  readonly variables: readonly string[];
  /** Fatal at startup, before anything binds. Never carries file content. */
  readonly problems: readonly string[];
  readonly warnings: readonly string[];
}

/**
 * Every UniFi credential variable this configuration can read: the cloud key
 * and each local console's key, each with its `*_FILE` sibling.
 *
 * The INBOUND secret's four variables are deliberately absent — `lookup()` is
 * never called with them, so they have no place in a store's environment. The
 * scrub still has to delete them; the runtime passes them alongside this list
 * from `INBOUND_SECRET_ENV_KEYS`, which `src/serve/auth.ts` owns because it is
 * their only reader (architecture §1.4).
 */
export function credentialEnvKeys(config: ServerConfig): string[] {
  const names: string[] = [];
  for (const account of credentialAccounts(config)) {
    for (const name of [account, credentialFileVar(account)]) {
      if (!names.includes(name)) names.push(name);
    }
  }
  return names;
}

/**
 * CAPTURE. Step one of the two-step scrub: resolve every credential the
 * process can reach into a private object, BEFORE anything is deleted.
 *
 * Returns the object to construct `CredentialStore` with. The caller then
 * calls `scrubCredentialEnv` — in that order, and only in that order.
 */
export function captureCredentialEnv(
  config: ServerConfig,
  env: NodeJS.ProcessEnv,
  readFile: (p: string) => Buffer = readFileSync,
): CredentialEnvCapture {
  const captured: NodeJS.ProcessEnv = {};
  const problems: string[] = [];
  const warnings: string[] = [];

  for (const account of credentialAccounts(config)) {
    const resolved = resolveCredentialDelivery(env, account, readFile);
    problems.push(...resolved.problems);
    warnings.push(...resolved.warnings);
    if (resolved.value !== null) captured[account] = resolved.value;
  }

  return { env: captured, variables: credentialEnvKeys(config), problems, warnings };
}

/**
 * DELETE. Step two: remove the named variables from the environment object the
 * process was handed — never unconditionally from `process.env`.
 *
 * Returns the names actually removed, so a caller can assert the scrub did
 * something rather than trusting that it did.
 */
export function scrubCredentialEnv(env: NodeJS.ProcessEnv, names: Iterable<string>): string[] {
  const removed: string[] = [];
  for (const name of names) {
    if (env[name] === undefined) continue;
    delete env[name];
    removed.push(name);
  }
  return removed;
}

function credentialAccounts(config: ServerConfig): string[] {
  const accounts = [config.cloudApiKeyEnvVar, ...config.localConsoles.map((c) => c.apiKeyEnvVar)];
  return [...new Set(accounts)];
}

/**
 * Contract §3.7, best effort. A `0644` secret file on a shared volume
 * reintroduces the exposure `*_FILE` exists to avoid — but a read-only mount
 * whose mode is not the operator's to change is a legitimate deployment, so
 * this is a warning and never a refusal. Mode bits are meaningless on Windows,
 * and a failed `stat` is not evidence of exposure.
 */
function exposedFilePermissionWarnings(account: string, path: string): string[] {
  if (process.platform === 'win32') return [];
  try {
    if ((statSync(path).mode & 0o077) !== 0) return [permissionsWarning(account, path)];
  } catch {
    // Unreadable metadata is not evidence of exposure; stay silent.
  }
  return [];
}

function bothSetProblem(account: string): string {
  return (
    `${account} and ${credentialFileVar(account)} are both set and only one API key can be live. ` +
    `Set exactly one.`
  );
}

function unreadableProblem(account: string, path: string): string {
  return (
    `${credentialFileVar(account)}=${path} is not readable. Set it to a path this process can ` +
    `read, or set ${account} instead.`
  );
}

function emptyProblem(account: string, path: string): string {
  return (
    `${credentialFileVar(account)}=${path} is empty. Write the API key into that file, or set ` +
    `${account} instead.`
  );
}

function oversizeProblem(account: string, path: string): string {
  return (
    `${credentialFileVar(account)}=${path} is larger than the 4 KiB maximum. It should contain ` +
    `the API key and nothing else; check you have not pointed it at a certificate or a key bundle.`
  );
}

function permissionsWarning(account: string, path: string): string {
  return (
    `${credentialFileVar(account)}=${path} is readable by group or other. Restrict it to the ` +
    `process user; a secret file on a shared volume is the exposure the *_FILE mechanism exists ` +
    `to avoid.`
  );
}
