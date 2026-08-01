/**
 * API key resolution: OS keychain first, environment second (FR-14, FR-15).
 *
 * Two invariants this module exists to hold:
 *
 *  1. The server NEVER writes a key to disk. There is no cache file, no state
 *     directory, no debug dump. Resolved keys live only in the in-memory map
 *     below, and the redacted-summary path (FR-55) never sees this module.
 *  2. Elicitation is never used to obtain a credential (FR-16). A missing key
 *     is a configuration error with a named remedy, not an interactive prompt.
 */
import type { ServerConfig } from './config.js';
import { CLOUD_API_KEY_ENV } from './config.js';
import type { ServiceId, TransportMode } from './types.js';
import { UnifiError } from './types.js';
import { localError } from './http/errors.js';

/** Keychain service name. One entry per env-var name, so the two paths agree. */
const KEYCHAIN_SERVICE = 'unifi-mcp';

/** The slice of keytar's surface used here, declared locally so the optional
 * dependency is not a compile-time dependency. */
interface KeytarLike {
  getPassword(service: string, account: string): Promise<string | null>;
}

export interface CredentialStoreOptions {
  env?: NodeJS.ProcessEnv;
  /** Diagnostics go to stderr, never stdout (NFR-19). */
  warn?: (message: string) => void;
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

  /** Keychain first, env second (FR-15). Cached in memory only — never on disk. */
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

    const fromEnv = this.env[account]?.trim();
    if (fromEnv) {
      if (!keytar) this.warnKeychainUnavailable();
      this.cache.set(account, fromEnv);
      return fromEnv;
    }
    return null;
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
