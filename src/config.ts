/**
 * Startup configuration, derived from the environment alone (FR-22, FR-52, FR-54).
 *
 * Traceability: identifiers like FR-52 refer to requirements in docs/prd.md.
 *
 * IMPORTANT: `ServerConfig` deliberately carries NO key material — only the
 * NAMES of the environment variables that supply keys, plus presence flags.
 * That is what makes `redactedSummary` (FR-55) safe by construction rather than
 * by remembering to omit fields; `CredentialStore` reads the values itself.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServiceId, TransportMode } from './types.js';
import { SERVICE_IDS } from './types.js';

/** A local console the server may talk to directly (FR-08, FR-14). */
export interface LocalConsole {
  /** `default` for the unsuffixed vars; otherwise the `_<LABEL>` suffix. */
  label: string;
  /** Hostname or IP with no scheme and no path. */
  host: string;
  /** The exact variable a user must set. Named verbatim in errors (FR-14). */
  apiKeyEnvVar: string;
  hasApiKey: boolean;
}

/** Token-bucket sizing, in requests per minute (FR-12, NFR-15). */
export interface RateLimitConfig {
  /** 100/min per console, published for the Cloud Connector. */
  connectorPerMinute: number;
  /** Site Manager stable `/v1/` paths. */
  siteManagerPerMinute: number;
  /** Site Manager `/ea/` paths carry their own, much smaller bucket (FR-30). */
  siteManagerEarlyAccessPerMinute: number;
  /** PROVISIONAL — see PROVISIONAL_RATE_LIMIT_PER_MINUTE. */
  mobilityPerMinute: number;
  /** PROVISIONAL — see PROVISIONAL_RATE_LIMIT_PER_MINUTE. */
  localPerMinute: number;
}

export interface RetryConfig {
  /** Total attempts including the first, for idempotent reads only (FR-26). */
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Ceiling on honouring a `Retry-After`; beyond it we surface the error. */
  maxRetryAfterSeconds: number;
}

export interface ServerConfig {
  enabledServices: Set<ServiceId>;
  /** Resolved per service; transport is a config decision only (FR-11). */
  transport: Record<ServiceId, TransportMode>;
  localConsoles: LocalConsole[];
  /** Host used when a local request does not name one. */
  defaultLocalHost: string | null;
  /** Console ID for Cloud Connector proxying (FR-10). */
  consoleId: string | null;
  caBundlePath: string | null;
  /** NEVER applies to api.ui.com — enforced in src/http/client.ts (FR-09). */
  localTlsInsecure: boolean;
  /** Empty unless explicitly configured. No tool argument can add to it (FR-44). */
  writesEnabled: Set<ServiceId>;
  /** Presence only. The value lives in the environment / OS keychain. */
  cloudApiKeyEnvVar: string;
  hasCloudApiKey: boolean;
  /** Pinned spec version per service, read from specs/manifest.json (FR-01). */
  specVersions: Record<ServiceId, string>;
  rateLimits: RateLimitConfig;
  retry: RetryConfig;
  /** NFR-16: connector calls are abandoned at this deadline. */
  connectorTimeoutMs: number;
  /** NFR-16: responses larger than this are refused, not buffered. */
  maxResponseBytes: number;
}

/**
 * Conservative stand-in for two unresolved limits.
 *
 * OQ-01: Ubiquiti's own docs give Mobility both 100/min and 10,000/min in
 * different places. OQ-02: local Network/Protect limits are unpublished
 * entirely. Hard-coding either number would encode a guess as a fact, so this
 * is the smaller, safer value and is overridable per bucket via env.
 */
export const PROVISIONAL_RATE_LIMIT_PER_MINUTE = 100;

export const CLOUD_API_KEY_ENV = 'UNIFI_API_KEY';
const DEFAULT_LOCAL_HOST_ENV = 'UNIFI_LOCAL_HOST';
const DEFAULT_LOCAL_KEY_ENV = 'UNIFI_LOCAL_API_KEY';
const LOCAL_HOST_PREFIX = 'UNIFI_LOCAL_HOST_';
const LOCAL_KEY_PREFIX = 'UNIFI_LOCAL_API_KEY_';

/** Env spelling of a service id: `site-manager` -> `SITE_MANAGER`. */
function envToken(service: ServiceId): string {
  return service.toUpperCase().replace(/-/g, '_');
}

const SCALAR_ENV_KEYS: readonly string[] = [
  CLOUD_API_KEY_ENV,
  DEFAULT_LOCAL_HOST_ENV,
  DEFAULT_LOCAL_KEY_ENV,
  'UNIFI_CONSOLE_ID',
  'UNIFI_LOCAL_TLS_INSECURE',
  'UNIFI_LOCAL_CA_BUNDLE',
  'UNIFI_ENABLE_WRITES',
  'UNIFI_NETWORK_TRANSPORT',
  'UNIFI_PROTECT_TRANSPORT',
  'UNIFI_RATE_LIMIT_CONNECTOR_PER_MIN',
  'UNIFI_RATE_LIMIT_SITE_MANAGER_PER_MIN',
  'UNIFI_RATE_LIMIT_SITE_MANAGER_EA_PER_MIN',
  'UNIFI_RATE_LIMIT_MOBILITY_PER_MIN',
  'UNIFI_RATE_LIMIT_LOCAL_PER_MIN',
  'UNIFI_RETRY_MAX_ATTEMPTS',
  'UNIFI_RETRY_BASE_DELAY_MS',
  'UNIFI_RETRY_MAX_DELAY_MS',
  'UNIFI_RETRY_MAX_RETRY_AFTER_SECONDS',
  'UNIFI_CONNECTOR_TIMEOUT_MS',
  'UNIFI_MAX_RESPONSE_BYTES',
  ...SERVICE_IDS.map((s) => `UNIFI_ENABLE_${envToken(s)}`),
];

const TRUE_WORDS = new Set(['1', 'true', 'yes', 'on', 'enabled']);
const FALSE_WORDS = new Set(['0', 'false', 'no', 'off', 'disabled', '']);

/** Tri-state: `undefined` means "not configured", which is not the same as `false`. */
function readBool(env: NodeJS.ProcessEnv, key: string, problems: string[]): boolean | undefined {
  const raw = env[key];
  if (raw === undefined) return undefined;
  const v = raw.trim().toLowerCase();
  if (TRUE_WORDS.has(v)) return true;
  if (FALSE_WORDS.has(v)) return false;
  problems.push(`${key}="${raw}" is not a boolean (use true/false).`);
  return undefined;
}

function readInt(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
  problems: string[],
): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
    problems.push(`${key}="${raw}" is not a positive integer.`);
    return fallback;
  }
  return n;
}

function readString(env: NodeJS.ProcessEnv, key: string): string | null {
  const raw = env[key];
  if (raw === undefined) return null;
  const trimmed = raw.trim();
  return trimmed === '' ? null : trimmed;
}

/** Strip a scheme/path a user may have pasted; base URLs are assembled, not copied. */
function normalizeHost(raw: string): string {
  return raw
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .replace(/\/.*$/, '');
}

function readTransport(
  env: NodeJS.ProcessEnv,
  key: string,
  problems: string[],
): TransportMode | undefined {
  const raw = readString(env, key);
  if (raw === null) return undefined;
  const v = raw.toLowerCase();
  if (v === 'local' || v === 'connector') return v;
  problems.push(`${key}="${raw}" must be \`local\` or \`connector\`.`);
  return undefined;
}

function collectLocalConsoles(env: NodeJS.ProcessEnv, problems: string[]): LocalConsole[] {
  const hosts = new Map<string, string>();

  const primary = readString(env, DEFAULT_LOCAL_HOST_ENV);
  if (primary) hosts.set('default', normalizeHost(primary));

  for (const [key, value] of Object.entries(env)) {
    if (!key.startsWith(LOCAL_HOST_PREFIX) || value === undefined) continue;
    const label = key.slice(LOCAL_HOST_PREFIX.length);
    if (label === '') continue;
    const host = normalizeHost(value);
    if (host === '') {
      problems.push(`${key} is set but empty.`);
      continue;
    }
    hosts.set(label, host);
  }

  return [...hosts.entries()].map(([label, host]) => {
    const apiKeyEnvVar = label === 'default' ? DEFAULT_LOCAL_KEY_ENV : LOCAL_KEY_PREFIX + label;
    return { label, host, apiKeyEnvVar, hasApiKey: Boolean(readString(env, apiKeyEnvVar)) };
  });
}

function readSpecVersions(repoRoot: string): Record<ServiceId, string> {
  const versions = {} as Record<ServiceId, string>;
  try {
    const manifest = JSON.parse(readFileSync(join(repoRoot, 'specs/manifest.json'), 'utf8')) as {
      services?: Record<string, { version?: string }>;
    };
    for (const service of SERVICE_IDS) {
      versions[service] = manifest.services?.[service]?.version ?? 'unknown';
    }
  } catch {
    // The registry build reports missing/corrupt specs with a far better
    // message (FR-04); config must not pre-empt it with a worse one.
    for (const service of SERVICE_IDS) versions[service] = 'unknown';
  }
  return versions;
}

/** Repo root, from this module's location, so `dist/` and `src/` both resolve. */
function defaultRepoRoot(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..');
}

export interface LoadConfigOptions {
  repoRoot?: string;
}

export function loadConfig(env: NodeJS.ProcessEnv, options: LoadConfigOptions = {}): ServerConfig {
  // Malformed values are collected here and re-reported by validateConfig, so
  // that loadConfig never half-fails: it always returns a usable object.
  const problems: string[] = [];

  const hasCloudApiKey = Boolean(readString(env, CLOUD_API_KEY_ENV));
  const consoleId = readString(env, 'UNIFI_CONSOLE_ID');
  const localConsoles = collectLocalConsoles(env, problems);
  const defaultLocalHost = localConsoles.find((c) => c.label === 'default')?.host
    ?? localConsoles[0]?.host
    ?? null;

  // FR-11: transport is a property of the deployment, not of the action. A
  // console ID means the user opted into cloud proxying; otherwise a configured
  // local host means direct. Neither present leaves the service disabled, and
  // FR-52 requires that no TLS or host decision be demanded in that case.
  const transportFor = (service: 'network' | 'protect'): TransportMode => {
    const explicit = readTransport(env, `UNIFI_${envToken(service)}_TRANSPORT`, problems);
    if (explicit) return explicit;
    if (consoleId) return 'connector';
    return 'local';
  };

  const transport: Record<ServiceId, TransportMode> = {
    'site-manager': 'cloud',
    mobility: 'cloud',
    network: transportFor('network'),
    protect: transportFor('protect'),
  };

  const credentialsPresent = (service: ServiceId): boolean => {
    if (service === 'site-manager' || service === 'mobility') return hasCloudApiKey;
    if (transport[service] === 'connector') return hasCloudApiKey && Boolean(consoleId);
    return localConsoles.some((c) => c.hasApiKey);
  };

  // FR-22: enablement is opt-in by evidence. A service is on only when the
  // config it needs is actually there; an explicit UNIFI_ENABLE_* overrides in
  // both directions, and forcing one on without credentials is a warning that
  // validateConfig reports rather than a silent no-op.
  const enabledServices = new Set<ServiceId>();
  for (const service of SERVICE_IDS) {
    const explicit = readBool(env, `UNIFI_ENABLE_${envToken(service)}`, problems);
    if (explicit ?? credentialsPresent(service)) enabledServices.add(service);
  }

  // FR-44: writes are off unless named. Accepting `all` still requires the
  // operator to have typed something; the default path can never produce a
  // non-empty set.
  const writesEnabled = new Set<ServiceId>();
  const writesRaw = readString(env, 'UNIFI_ENABLE_WRITES');
  if (writesRaw !== null) {
    const tokens = writesRaw.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
    for (const token of tokens) {
      if (TRUE_WORDS.has(token) || token === 'all') {
        for (const s of enabledServices) writesEnabled.add(s);
      } else if (FALSE_WORDS.has(token) || token === 'none') {
        writesEnabled.clear();
      } else if ((SERVICE_IDS as readonly string[]).includes(token)) {
        writesEnabled.add(token as ServiceId);
      } else {
        problems.push(
          `UNIFI_ENABLE_WRITES lists unknown service "${token}"; valid values are ` +
            `${SERVICE_IDS.join(', ')}, \`all\`, or \`none\`.`,
        );
      }
    }
  }

  const config: ServerConfig = {
    enabledServices,
    transport,
    localConsoles,
    defaultLocalHost,
    consoleId,
    caBundlePath: readString(env, 'UNIFI_LOCAL_CA_BUNDLE'),
    localTlsInsecure: readBool(env, 'UNIFI_LOCAL_TLS_INSECURE', problems) ?? false,
    writesEnabled,
    cloudApiKeyEnvVar: CLOUD_API_KEY_ENV,
    hasCloudApiKey,
    specVersions: readSpecVersions(options.repoRoot ?? defaultRepoRoot()),
    rateLimits: {
      connectorPerMinute: readInt(env, 'UNIFI_RATE_LIMIT_CONNECTOR_PER_MIN', 100, problems),
      siteManagerPerMinute: readInt(env, 'UNIFI_RATE_LIMIT_SITE_MANAGER_PER_MIN', 10_000, problems),
      siteManagerEarlyAccessPerMinute: readInt(
        env,
        'UNIFI_RATE_LIMIT_SITE_MANAGER_EA_PER_MIN',
        100,
        problems,
      ),
      mobilityPerMinute: readInt(
        env,
        'UNIFI_RATE_LIMIT_MOBILITY_PER_MIN',
        PROVISIONAL_RATE_LIMIT_PER_MINUTE,
        problems,
      ),
      localPerMinute: readInt(
        env,
        'UNIFI_RATE_LIMIT_LOCAL_PER_MIN',
        PROVISIONAL_RATE_LIMIT_PER_MINUTE,
        problems,
      ),
    },
    retry: {
      maxAttempts: readInt(env, 'UNIFI_RETRY_MAX_ATTEMPTS', 3, problems),
      baseDelayMs: readInt(env, 'UNIFI_RETRY_BASE_DELAY_MS', 500, problems),
      maxDelayMs: readInt(env, 'UNIFI_RETRY_MAX_DELAY_MS', 8_000, problems),
      maxRetryAfterSeconds: readInt(env, 'UNIFI_RETRY_MAX_RETRY_AFTER_SECONDS', 30, problems),
    },
    connectorTimeoutMs: readInt(env, 'UNIFI_CONNECTOR_TIMEOUT_MS', 25_000, problems),
    maxResponseBytes: readInt(env, 'UNIFI_MAX_RESPONSE_BYTES', 10 * 1024 * 1024, problems),
  };

  malformedValues.set(config, problems);
  return config;
}

/**
 * Value-parsing complaints found during `loadConfig`, keyed by the config they
 * came from. Kept out of `ServerConfig` so the served object stays a plain
 * description of the deployment rather than a diagnostics carrier.
 */
const malformedValues = new WeakMap<ServerConfig, string[]>();

/** The three failure classes FR-54 requires be reported distinctly, by name. */
export interface ConfigValidation {
  /** True when startup may proceed. */
  ok: boolean;
  /** Typos. Silently ignoring these is how a key ends up seemingly unset. */
  unknownEnvKeys: string[];
  /** Options that cannot both be meaningful at once. */
  mutuallyExclusiveOptions: string[];
  /** Enabled but unusable. A warning, not a stopper, if anything else works. */
  enabledWithoutCredentials: string[];
  /** Values that failed to parse. Fatal — a mistyped limit is not a default. */
  malformedValues: string[];
  /** Rendered, fatal. Startup must not proceed on a partially valid config. */
  errors: string[];
  /** Rendered, non-fatal. Emitted to stderr at startup (NFR-19). */
  warnings: string[];
}

function isKnownEnvKey(key: string): boolean {
  if (!key.startsWith('UNIFI_')) return false;
  if (SCALAR_ENV_KEYS.includes(key)) return true;
  if (key.startsWith(LOCAL_KEY_PREFIX) && key.length > LOCAL_KEY_PREFIX.length) return true;
  if (key.startsWith(LOCAL_HOST_PREFIX) && key.length > LOCAL_HOST_PREFIX.length) return true;
  return false;
}

export function validateConfig(config: ServerConfig, env: NodeJS.ProcessEnv): ConfigValidation {
  const unknownEnvKeys = Object.keys(env)
    .filter((k) => k.startsWith('UNIFI_') && !isKnownEnvKey(k))
    .sort();

  const mutuallyExclusiveOptions: string[] = [];
  // Supplying a CA bundle says "verify against this"; the insecure opt-in says
  // "verify nothing". Together the bundle is dead config and the operator
  // believes they are verifying when they are not.
  if (config.caBundlePath && config.localTlsInsecure) {
    mutuallyExclusiveOptions.push(
      `UNIFI_LOCAL_CA_BUNDLE (${config.caBundlePath}) and UNIFI_LOCAL_TLS_INSECURE=true are ` +
        `mutually exclusive: the bundle would never be consulted. Set exactly one.`,
    );
  }

  const enabledWithoutCredentials: string[] = [];
  for (const service of config.enabledServices) {
    if (service === 'site-manager' || service === 'mobility') {
      if (!config.hasCloudApiKey) {
        enabledWithoutCredentials.push(
          `${service} is enabled but ${CLOUD_API_KEY_ENV} is not set.`,
        );
      }
      continue;
    }
    if (config.transport[service] === 'connector') {
      const missing = [
        config.hasCloudApiKey ? null : CLOUD_API_KEY_ENV,
        config.consoleId ? null : 'UNIFI_CONSOLE_ID',
      ].filter((m): m is string => m !== null);
      if (missing.length) {
        enabledWithoutCredentials.push(
          `${service} is enabled in connector mode but ${missing.join(' and ')} ` +
            `${missing.length === 1 ? 'is' : 'are'} not set.`,
        );
      }
      continue;
    }
    if (!config.localConsoles.some((c) => c.hasApiKey)) {
      enabledWithoutCredentials.push(
        `${service} is enabled in local mode but no local console has a key. Set ` +
          `${DEFAULT_LOCAL_HOST_ENV} and ${DEFAULT_LOCAL_KEY_ENV}.`,
      );
    }
  }

  const malformed = malformedValues.get(config) ?? [];

  const usableServices = [...config.enabledServices].filter(
    (s) => !enabledWithoutCredentials.some((m) => m.startsWith(`${s} `)),
  );

  const errors: string[] = [];
  if (unknownEnvKeys.length) {
    errors.push(
      `Unrecognised UNIFI_* environment variable${unknownEnvKeys.length === 1 ? '' : 's'}: ` +
        `${unknownEnvKeys.join(', ')}. These are ignored at runtime, which looks identical ` +
        `to a key that was never set — fix the spelling or remove them.`,
    );
  }
  errors.push(...mutuallyExclusiveOptions, ...malformed);
  if (usableServices.length === 0) {
    // FR-52: one cloud key is enough. Say exactly that rather than listing
    // every knob the user did not set.
    errors.push(
      `No UniFi API is usable. The minimum viable configuration is a single cloud key: ` +
        `set ${CLOUD_API_KEY_ENV} to enable Site Manager and Mobility. Network and Protect ` +
        `additionally need either UNIFI_CONSOLE_ID (cloud connector) or ` +
        `${DEFAULT_LOCAL_HOST_ENV} + ${DEFAULT_LOCAL_KEY_ENV} (local).`,
    );
  }

  // An enabled-but-uncredentialed API degrades to a warning precisely because
  // at least one other API works (FR-54); with none working it is already
  // covered by the fatal error above.
  const warnings = usableServices.length === 0 ? [] : [...enabledWithoutCredentials];
  if (config.localTlsInsecure) {
    const hosts = config.localConsoles.map((c) => c.host).join(', ') || '(none configured)';
    warnings.push(
      `UNIFI_LOCAL_TLS_INSECURE=true: certificate verification is DISABLED for ${hosts}. ` +
        `It is never disabled for api.ui.com.`,
    );
  }

  return {
    ok: errors.length === 0,
    unknownEnvKeys,
    mutuallyExclusiveOptions,
    enabledWithoutCredentials,
    malformedValues: malformed,
    errors,
    warnings,
  };
}

/**
 * What the server will do, with zero key material (FR-55).
 *
 * Safe by construction: `ServerConfig` holds no secrets, so this cannot leak
 * one by adding a field. Env var NAMES are included deliberately — they are the
 * actionable half of a credential problem.
 */
export function redactedSummary(config: ServerConfig): Record<string, unknown> {
  return {
    enabledApis: [...config.enabledServices].sort(),
    specVersions: Object.fromEntries(
      [...config.enabledServices].sort().map((s) => [s, config.specVersions[s]]),
    ),
    transport: Object.fromEntries(
      [...config.enabledServices].sort().map((s) => [s, config.transport[s]]),
    ),
    writesEnabled: [...config.writesEnabled].sort(),
    writesEnabledCount: config.writesEnabled.size,
    credentials: {
      cloudKey: { envVar: config.cloudApiKeyEnvVar, present: config.hasCloudApiKey },
      localConsoles: config.localConsoles.map((c) => ({
        label: c.label,
        host: c.host,
        keyEnvVar: c.apiKeyEnvVar,
        keyPresent: c.hasApiKey,
      })),
      consoleIdConfigured: config.consoleId !== null,
    },
    tls: {
      verificationEnabled: !config.localTlsInsecure,
      caBundlePath: config.caBundlePath,
      insecureAppliesTo: config.localTlsInsecure ? config.localConsoles.map((c) => c.host) : [],
    },
    limits: {
      rateLimitsPerMinute: config.rateLimits,
      retry: config.retry,
      connectorTimeoutMs: config.connectorTimeoutMs,
      maxResponseBytes: config.maxResponseBytes,
    },
  };
}
