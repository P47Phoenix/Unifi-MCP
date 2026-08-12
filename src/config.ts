/**
 * Startup configuration, derived from the environment alone (FR-22, FR-52, FR-54).
 *
 * Traceability: identifiers like FR-52 refer to requirements in docs/prd.md.
 *
 * IMPORTANT: `ServerConfig` deliberately carries NO key material — only the
 * NAMES of the environment variables that supply keys, plus presence flags.
 * That is what makes `redactedSummary` (FR-55) safe by construction rather than
 * by remembering to omit fields; `CredentialStore` reads the values itself.
 *
 * The same rule holds for the INBOUND shared secret that authenticates MCP
 * clients over HTTP (US-12, US-14). Its plaintext and its digests live nowhere
 * on `ServerConfig`: this module never reads `UNIFI_HTTP_TOKEN` or any of its
 * three siblings for their VALUE — only to answer the yes/no question "is a
 * secret configured at all?" for refusal (a). What lands on `serving.auth` is
 * the secret-free `InboundAuthDescriptor` — an enum, two integers and two lists
 * of strings that name variables — composed by `src/serve/auth.ts` and handed
 * in through `LoadConfigOptions`. `minSlotLength` is on that descriptor and is
 * deliberately absent from `redactedSummary`, because printing it would turn
 * the start line into a length oracle for the secret.
 *
 * ARCHITECTURAL CONSTRAINT: this module MUST NOT import anything from
 * `src/serve/`. The serving transport is configured here and consumed there,
 * never the other way round, so `src/serve/*` may import `src/config.js` and a
 * cycle is impossible by construction. Two algorithms are consequently
 * duplicated rather than shared — the FR-67 path canonicalisation (see
 * `canonicalizeServingPath`) and the §2.5.1 auth-mode grammar (see
 * `parseInboundAuthMode`) — and `test/serve-config.test.ts` asserts each copy
 * agrees with its sibling so a divergence fails the build. Leaf modules that
 * BOTH sides may import (`./netliteral.js`, `./safety/sanitize.js`) are the
 * sanctioned way to share; see D-15.
 */
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { isLoopbackBind } from './netliteral.js';
import { sanitizeUntrusted } from './safety/sanitize.js';
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

/** How this process serves MCP: over stdio, or over a listening socket (§2.6). */
export type ServingTransport = 'stdio' | 'http';

/**
 * Two arms only. There is deliberately no arm reachable from an unrecognised
 * token, so a typo can never resolve to "no authentication".
 */
export type InboundAuthMode = { readonly kind: 'bearer' } | { readonly kind: 'none' };

/**
 * Structural mirror of `BearerDescriptor` in `src/serve/auth.ts`. Declared here
 * rather than imported because `config.ts` must not depend on `src/serve/`.
 *
 * Carries no digest and no plaintext, which is what makes it safe to place on
 * `ServerConfig` and to serialise — with the single exception of
 * `minSlotLength`, which is never rendered anywhere (see the module comment).
 */
export interface InboundAuthDescriptor {
  readonly mode: 'bearer' | 'none';
  /** 0, 1 or 2. */
  readonly slotCount: number;
  readonly sources: readonly ('env' | 'file')[];
  /** NEVER rendered anywhere: it would make the start line a length oracle. */
  readonly minSlotLength: number;
  readonly problems: readonly string[];
  readonly warnings: readonly string[];
}

/**
 * Which resolved values did NOT parse.
 *
 * Read by the suppression ladder (§2.7) so the process never reports a refusal
 * derived from a value that has no meaning: a combination refusal computed over
 * a default that stood in for an unparseable value is a refusal the operator
 * cannot act on, and it buries the parse failure that actually needs fixing.
 */
export type UnresolvedServingValue =
  | 'transport'
  | 'bind'
  | 'port'
  | 'path'
  | 'auth'
  | 'allowWrites';

/** Everything §5.15.1 configures about how this process is reached. */
export interface ServingConfig {
  transport: ServingTransport;
  /** As configured (trimmed); default `127.0.0.1`. */
  bind: string;
  /** The PARSED literal; null when it did not parse. */
  bindAddress: string | null;
  port: number;
  /** The NORMALISED path (§2.5.2 step 3) — what the router matches. */
  path: string;
  allowedHosts: string[];
  authMode: InboundAuthMode;
  auth: InboundAuthDescriptor;
  maxSessions: number;
  sessionIdleTtlMs: number;
  maxConnections: number;
  maxBodyBytes: number;
  maxHeaderBytes: number;
  headersTimeoutMs: number;
  requestTimeoutMs: number;
  keepAliveTimeoutMs: number;
  sseKeepaliveMs: number;
  shutdownDeadlineMs: number;
  authFailPerMin: number;
  unresolved: readonly UnresolvedServingValue[];
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
  /**
   * The EFFECTIVE write set for the serving transport this process selected —
   * `writesEnabledBySurface[activeSurface]`. Empty unless explicitly configured;
   * no tool argument can add to it (FR-44).
   *
   * The name and type are unchanged on purpose. `src/tools/definitions.ts`
   * (`writesEnabled.size === 0` ⇒ the write tool is absent from `tools/list`)
   * and `src/http/client.ts` (`config.writesEnabled.has(action.service)` ⇒ the
   * outbound refusal) both read this field, and both therefore inherit the
   * second HTTP gate with no edit and no third check anywhere.
   */
  writesEnabled: Set<ServiceId>;
  /**
   * The write set each surface would get, before selecting one. Two DISTINCT
   * `Set` instances, so a later mutation of one cannot alias the other.
   */
  writesEnabledBySurface: { readonly stdio: Set<ServiceId>; readonly http: Set<ServiceId> };
  /** The surface this process actually selected; equals `serving.transport`. */
  activeSurface: ServingTransport;
  serving: ServingConfig;
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

/**
 * §5.15.1b: the suffix that turns a credential variable into its file sibling,
 * and the suffix RESERVED across the `UNIFI_LOCAL_API_KEY_` family.
 *
 * `UNIFI_LOCAL_API_KEY_FILE` is file delivery for the DEFAULT console and is
 * never a key for a console labelled `FILE`; `UNIFI_LOCAL_API_KEY_<LABEL>_FILE`
 * is file delivery for `<LABEL>` and is never a key for `<LABEL>_FILE`. Without
 * the reservation both spellings parse as consoles, pass the unknown-key check
 * and are then silently ignored, because `collectLocalConsoles` derives its
 * label set from the HOST variables — an operator's key accepted and discarded.
 *
 * Duplicated from `RESERVED_FILE_SUFFIX` in `src/serve/auth.ts` and
 * `CREDENTIAL_FILE_SUFFIX` in `src/credentials.ts`: this module may import
 * neither (see the module comment's architectural constraint), so the three
 * copies are pinned to each other by `test/credentials-file.test.ts`.
 */
const CREDENTIAL_FILE_SUFFIX = '_FILE';
const CLOUD_API_KEY_FILE_ENV = `${CLOUD_API_KEY_ENV}${CREDENTIAL_FILE_SUFFIX}`;
const DEFAULT_LOCAL_KEY_FILE_ENV = `${DEFAULT_LOCAL_KEY_ENV}${CREDENTIAL_FILE_SUFFIX}`;

/**
 * True for a local console label the `_FILE` reservation makes unaddressable.
 * `FILENAME` and `MYFILE` are unaffected: the reservation is the trailing
 * `_FILE`, plus the bare label `FILE`.
 */
function isReservedLocalLabel(label: string): boolean {
  return label === 'FILE' || label.endsWith(CREDENTIAL_FILE_SUFFIX);
}

/** The refusal for a console the reservation makes unaddressable (§5.15.1b). */
function reservedLocalLabelProblem(label: string): string {
  return (
    `${LOCAL_HOST_PREFIX}${label} names a console whose label is unaddressable: the trailing ` +
    `${CREDENTIAL_FILE_SUFFIX} suffix is reserved for file delivery, so ${LOCAL_KEY_PREFIX}${label} ` +
    `would be read as a file path for another console and this console's key could be set but ` +
    `never read. Rename the console to a label that is not FILE and does not end in ` +
    `${CREDENTIAL_FILE_SUFFIX}.`
  );
}

/** Env spelling of a service id: `site-manager` -> `SITE_MANAGER`. */
function envToken(service: ServiceId): string {
  return service.toUpperCase().replace(/-/g, '_');
}

/**
 * The twenty-two §5.15.1 serving variables, registered as recognised keys.
 *
 * This is not bookkeeping. `validateConfig` fatals on any unrecognised `UNIFI_*`
 * key, so a variable that is READ but not REGISTERED makes the server refuse to
 * start for exactly the operators who followed the documentation. Registration
 * therefore lands in the same change as the reader, never a later one.
 *
 * The four `UNIFI_HTTP_TOKEN*` names are here even though this module never
 * reads their values — `src/serve/auth.ts` does — because the allow-list is a
 * property of the process, not of this file.
 */
export const SERVING_ENV_KEYS: readonly string[] = [
  'UNIFI_MCP_TRANSPORT',
  'UNIFI_HTTP_BIND',
  'UNIFI_HTTP_PORT',
  'UNIFI_HTTP_PATH',
  'UNIFI_HTTP_AUTH',
  'UNIFI_HTTP_TOKEN',
  'UNIFI_HTTP_TOKEN_FILE',
  'UNIFI_HTTP_TOKEN_NEXT',
  'UNIFI_HTTP_TOKEN_NEXT_FILE',
  'UNIFI_HTTP_ALLOWED_HOSTS',
  'UNIFI_HTTP_ALLOW_WRITES',
  'UNIFI_HTTP_MAX_SESSIONS',
  'UNIFI_HTTP_SESSION_IDLE_TTL_MS',
  'UNIFI_HTTP_MAX_CONNECTIONS',
  'UNIFI_HTTP_MAX_BODY_BYTES',
  'UNIFI_HTTP_MAX_HEADER_BYTES',
  'UNIFI_HTTP_HEADERS_TIMEOUT_MS',
  'UNIFI_HTTP_REQUEST_TIMEOUT_MS',
  'UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS',
  'UNIFI_HTTP_SSE_KEEPALIVE_MS',
  'UNIFI_HTTP_SHUTDOWN_DEADLINE_MS',
  'UNIFI_HTTP_AUTH_FAIL_PER_MIN',
];

/** Exported so a table-driven test can compare the recognised set in-process. */
export const SCALAR_ENV_KEYS: readonly string[] = [
  CLOUD_API_KEY_ENV,
  // §5.15.1b, registered in the SAME change as the reader (FR-78). Without the
  // registration `validateConfig` fatals on the variable the documentation
  // tells a container operator to set. The third row of that table,
  // `UNIFI_LOCAL_API_KEY_<LABEL>_FILE`, needs no entry: the local-key rule in
  // `isKnownEnvKey` already covers every `UNIFI_LOCAL_API_KEY_*` spelling.
  CLOUD_API_KEY_FILE_ENV,
  DEFAULT_LOCAL_KEY_FILE_ENV,
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
  ...SERVING_ENV_KEYS,
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

const MIN_PORT = 0;
const MAX_PORT = 65_535;

/**
 * A TCP port, which is NOT what `readInt` accepts.
 *
 * `readInt` rejects zero through `n <= 0`, so port 0 is unrepresentable there —
 * and port 0 is both a §5.15.1-accepted value (it asks the OS for an ephemeral
 * port) and the value every serving test binds. Reusing `readInt` would make
 * the feature's own test suite unable to start a listener, so this is a second,
 * separate helper rather than a widened first one; widening `readInt` would
 * quietly let a zero through for the ten `*_MS` and count limits, where zero is
 * a disabled timeout or a zero-capacity pool, not a default.
 */
function readPort(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
  problems: string[],
  onUnresolved: () => void,
): number {
  const raw = env[key];
  if (raw === undefined || raw.trim() === '') return fallback;

  const n = Number(raw);
  if (!Number.isInteger(n) || n < MIN_PORT || n > MAX_PORT) {
    problems.push(
      `${key}="${echoValue(raw)}" is not a port. Set it to an integer in ` +
        `${MIN_PORT} … ${MAX_PORT}; ${MIN_PORT} binds an OS-assigned port.`,
    );
    onUnresolved();
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

// --- the serving surface (US-14; §2.5, §2.6, §5.15.1) ------------------------

/** Contract §2.2: a scalar value is echoed only at 16 characters or fewer. */
const MAX_ECHOED_VALUE_LENGTH = 16;

/**
 * Contract §2.2's echoed-value ceiling, applied to EVERY echoed scalar: port,
 * bind, path, transport, auth mode and an unknown write-gate token.
 *
 * The count is taken from the ORIGINAL length, matching `src/serve/auth.ts`, so
 * that stripping unprintables cannot make a long value look short enough to
 * echo. A `UNIFI_HTTP_TOKEN*` value is never echoed at any length — structurally
 * rather than by rule, because this module never reads one.
 *
 * EXEMPTION, per contract §2.2's "closed vocabulary defined in this document"
 * carve-out: a rendered SERVICE LIST (`renderServiceList`) is drawn from
 * `SERVICE_IDS` and is therefore not subject to this ceiling. No operator
 * free-text can reach one: an unrecognised token is a T1 refusal that also
 * suppresses refusal (c), the only refusal that renders a list.
 */
function echoValue(raw: string): string {
  const cleaned = sanitizeUntrusted(raw).value;
  return cleaned.length <= MAX_ECHOED_VALUE_LENGTH ? cleaned : `(${raw.length} characters)`;
}

/**
 * ASCII case folding only — no locale, no Unicode special casing.
 *
 * `toLowerCase()` is locale-aware: in a Turkish locale `NONE` does not fold to
 * `none`, which would turn a documented value into an unrecognised token on one
 * operator's machine and not another's.
 */
function asciiLowerCase(value: string): string {
  return value.replace(/[A-Z]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 32));
}

/** §0.1.3: de-duplicated, ASCII-lower-cased, sorted alphabetically, `, `-joined. */
function renderServiceList(services: Iterable<ServiceId>): string {
  return [...new Set([...services].map((s) => asciiLowerCase(s)))].sort().join(', ');
}

/** `isIP` return code for IPv6, named so no bare `6` appears at a call site. */
const IPV6_FAMILY = 6;

/**
 * The address a listener actually bound, structurally — `node:net`'s
 * `AddressInfo` satisfies it.
 *
 * Declared rather than imported so this module keeps its dependency shape: it
 * describes a deployment and never opens a socket, and the two fields below are
 * the whole of what §3.3's rendering reads.
 */
export interface BoundAddress {
  readonly address: string;
  readonly port: number;
}

/** §0.1.4: `[::]:8787` for an IPv6 literal, `0.0.0.0:8787` otherwise. Never `:::8787`. */
function renderAddress(bind: string, port: number): string {
  return isIP(bind) === IPV6_FAMILY ? `[${bind}]:${port}` : `${bind}:${port}`;
}

/**
 * The two probe paths, spelled here rather than imported from
 * `src/serve/guard.ts` (which exports them as `HEALTHZ_ROUTE_PATH` and
 * `READYZ_ROUTE_PATH`) because of the import ban. Refusal (d) below and
 * `test/serve-config.test.ts` are what keep the two spellings in step.
 */
const HEALTHZ_PATH = '/healthz';
const READYZ_PATH = '/readyz';

/**
 * FR-67's request-target normalisation — A SECOND IMPLEMENTATION, ON PURPOSE.
 *
 * The sibling is `canonicalizePath` inside `src/serve/guard.ts`, which is
 * module-private and, being under `src/serve/`, unimportable from here (see the
 * module comment). Duplicating a *closed* rule is exactly the defect D-15 warns
 * about, so this copy is not left to review: `test/serve-config.test.ts` asserts
 * the two AGREE, by feeding every configured path this function produces back
 * through `createRouteNormalizer` and requiring it to resolve to the `mcp` route
 * while `/healthz` and `/readyz` still resolve to their own. A divergence in
 * either direction fails the build.
 *
 * The steps, in the order FR-67 fixes them:
 *   1. strip the query string at the FIRST `?`;
 *   2. percent-decode EXACTLY ONCE, and never throw — a `URIError` escaping
 *      config load would turn one malformed byte into a failure to start;
 *   3. collapse duplicate slashes, resolve `.` and `..` (popping past root is a
 *      no-op, not an escape), and drop a trailing slash.
 *
 * The later comparison against the probe constants is ASCII-case-SENSITIVE, so
 * `/HEALTHZ` is a legal MCP path.
 */
function canonicalizeServingPath(rawPath: string): string {
  const queryIndex = rawPath.indexOf('?');
  const withoutQuery = queryIndex === -1 ? rawPath : rawPath.slice(0, queryIndex);

  let decoded: string;
  try {
    decoded = decodeURIComponent(withoutQuery);
  } catch {
    // A malformed escape is left undecoded rather than rejected here; the
    // router will simply never match it, which is the fail-closed outcome.
    decoded = withoutQuery;
  }

  const resolved: string[] = [];
  for (const segment of decoded.split('/')) {
    // Empty segments come from duplicate and trailing slashes alike.
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      resolved.pop();
      continue;
    }
    resolved.push(segment);
  }
  return `/${resolved.join('/')}`;
}

/**
 * Contract §2.5.1, fail-closed — A SECOND IMPLEMENTATION of `parseAuthMode` in
 * `src/serve/auth.ts`, forced by the same import ban and kept honest by the
 * same test file, which asserts both modules classify every row of the §2.5.1
 * table identically and compose the same refusal byte for byte.
 *
 * (1) strip leading/trailing ASCII whitespace only; (2) fold ASCII case only;
 * (3) compare against exactly two constants. Every other value — including the
 * empty string after trimming — is a REFUSAL rather than a fallback, because a
 * parser that falls back on an unrecognised token turns a typo into an open
 * listener. The refusal resolves to `bearer`: there is deliberately no code path
 * by which an unrecognised token yields `{ kind: 'none' }`.
 */
function parseInboundAuthMode(raw: string | undefined): InboundAuthMode | null {
  if (raw === undefined) return { kind: 'bearer' };

  const normalized = asciiLowerCase(raw.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, ''));
  if (normalized === 'bearer') return { kind: 'bearer' };
  if (normalized === 'none') return { kind: 'none' };
  return null;
}

/** The descriptor used when no `resolveBearerSlots` result was supplied. */
const NEUTRAL_AUTH_DESCRIPTOR: InboundAuthDescriptor = {
  mode: 'bearer',
  slotCount: 0,
  sources: [],
  minSlotLength: 0,
  problems: [],
  warnings: [],
};

/**
 * The parts of the serving resolution `validateConfig` needs but `ServingConfig`
 * does not carry: the path AS CONFIGURED (refusal (d) echoes that, not the
 * normalised form) and the write-gate grammar's two accumulators (refusal (c)
 * distinguishes a named list from `all`). Kept off `ServerConfig` for the same
 * reason as `malformedValues` — the served object stays a description of the
 * deployment rather than a diagnostics carrier.
 */
interface ServingContext {
  readonly configuredPath: string;
  readonly namesAll: boolean;
  readonly named: ReadonlySet<ServiceId>;
}

const servingContexts = new WeakMap<ServerConfig, ServingContext>();

interface ServingResolution {
  readonly serving: ServingConfig;
  readonly context: ServingContext;
  /** §2.6's own value error. Reported on EVERY transport, never scoped. */
  readonly transportProblems: string[];
  /** Every `UNIFI_HTTP_*` value error. Reported only when transport is http. */
  readonly httpProblems: string[];
}

function resolveServing(
  env: NodeJS.ProcessEnv,
  auth: InboundAuthDescriptor,
): ServingResolution {
  const transportProblems: string[] = [];
  const httpProblems: string[] = [];
  const unresolved: UnresolvedServingValue[] = [];
  const markUnresolved = (value: UnresolvedServingValue): void => {
    if (!unresolved.includes(value)) unresolved.push(value);
  };

  const transport = resolveServingTransport(env, transportProblems, markUnresolved);
  const bind = resolveBind(env, httpProblems, markUnresolved);
  const path = resolvePath(env, httpProblems, markUnresolved);
  const authMode = resolveAuthMode(env, httpProblems, markUnresolved);
  const allowWrites = resolveAllowWrites(env, httpProblems, markUnresolved);

  const serving: ServingConfig = {
    transport,
    bind: bind.configured,
    bindAddress: bind.address,
    port: readPort(env, 'UNIFI_HTTP_PORT', 8787, httpProblems, () => markUnresolved('port')),
    path: path.normalized,
    allowedHosts: readAllowedHosts(env),
    authMode,
    auth,
    maxSessions: readInt(env, 'UNIFI_HTTP_MAX_SESSIONS', 32, httpProblems),
    sessionIdleTtlMs: readInt(env, 'UNIFI_HTTP_SESSION_IDLE_TTL_MS', 300_000, httpProblems),
    maxConnections: readInt(env, 'UNIFI_HTTP_MAX_CONNECTIONS', 64, httpProblems),
    maxBodyBytes: readInt(env, 'UNIFI_HTTP_MAX_BODY_BYTES', 1_048_576, httpProblems),
    maxHeaderBytes: readInt(env, 'UNIFI_HTTP_MAX_HEADER_BYTES', 16_384, httpProblems),
    headersTimeoutMs: readInt(env, 'UNIFI_HTTP_HEADERS_TIMEOUT_MS', 10_000, httpProblems),
    requestTimeoutMs: readInt(env, 'UNIFI_HTTP_REQUEST_TIMEOUT_MS', 30_000, httpProblems),
    keepAliveTimeoutMs: readInt(env, 'UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS', 5_000, httpProblems),
    sseKeepaliveMs: readInt(env, 'UNIFI_HTTP_SSE_KEEPALIVE_MS', 15_000, httpProblems),
    shutdownDeadlineMs: readInt(env, 'UNIFI_HTTP_SHUTDOWN_DEADLINE_MS', 35_000, httpProblems),
    authFailPerMin: readInt(env, 'UNIFI_HTTP_AUTH_FAIL_PER_MIN', 20, httpProblems),
    unresolved,
  };

  return {
    serving,
    context: {
      configuredPath: path.configured,
      namesAll: allowWrites.namesAll,
      named: allowWrites.named,
    },
    transportProblems,
    httpProblems,
  };
}

/**
 * §2.6. Unset resolves to `stdio`, and so does a value that is blank after
 * trimming: every other reader in this module treats a blank variable as unset
 * (`readString`), and an empty `UNIFI_MCP_TRANSPORT=` left in a shared Compose
 * file must not stop a stdio server from starting (IG-1). An unrecognised
 * NON-blank token is a refusal that still resolves to `stdio` — fail-closed,
 * because the fallback binds no listener at all.
 */
function resolveServingTransport(
  env: NodeJS.ProcessEnv,
  problems: string[],
  markUnresolved: (value: UnresolvedServingValue) => void,
): ServingTransport {
  const raw = env['UNIFI_MCP_TRANSPORT'];
  if (raw === undefined) return 'stdio';

  const normalized = asciiLowerCase(raw.trim());
  if (normalized === '') return 'stdio';
  if (normalized === 'stdio' || normalized === 'http') return normalized;

  problems.push(
    `UNIFI_MCP_TRANSPORT="${echoValue(raw)}" must be \`stdio\` or \`http\`. (\`local\` and ` +
      `\`connector\` are values for UNIFI_NETWORK_TRANSPORT and UNIFI_PROTECT_TRANSPORT, which ` +
      `control how this server reaches your console — a different setting.)`,
  );
  markUnresolved('transport');
  return 'stdio';
}

/**
 * §2.5. Host NAMES are refused: `localhost` is not an address, and resolving one
 * is not this server's to trust — `isLoopbackBind` would classify the resolved
 * result, not the configured string, and the two can differ.
 */
function resolveBind(
  env: NodeJS.ProcessEnv,
  problems: string[],
  markUnresolved: (value: UnresolvedServingValue) => void,
): { configured: string; address: string | null } {
  const raw = env['UNIFI_HTTP_BIND'];
  const trimmed = raw === undefined ? '' : raw.trim();
  if (trimmed === '') return { configured: '127.0.0.1', address: '127.0.0.1' };

  if (isIP(trimmed) !== 0) return { configured: trimmed, address: trimmed };

  problems.push(
    `UNIFI_HTTP_BIND="${echoValue(trimmed)}" is not an IP address. Set it to an IPv4 or IPv6 ` +
      `literal, for example 127.0.0.1, 0.0.0.0 or ::.`,
  );
  markUnresolved('bind');
  return { configured: trimmed, address: null };
}

/**
 * §2.5.2: ABSOLUTENESS FIRST, then normalisation. There is no silent promotion
 * of `mcp` to `/mcp` — a relative value is a mistake, and inventing the leading
 * slash would hide it while changing which URL clients must call.
 */
function resolvePath(
  env: NodeJS.ProcessEnv,
  problems: string[],
  markUnresolved: (value: UnresolvedServingValue) => void,
): { configured: string; normalized: string } {
  const raw = env['UNIFI_HTTP_PATH'];
  if (raw === undefined) return { configured: '/mcp', normalized: '/mcp' };

  const trimmed = raw.trim();
  if (trimmed === '' || !trimmed.startsWith('/')) {
    problems.push(
      `UNIFI_HTTP_PATH="${echoValue(trimmed)}" is not an absolute path. Set it to a path ` +
        `beginning with \`/\`; the default is /mcp.`,
    );
    markUnresolved('path');
    return { configured: trimmed, normalized: '/mcp' };
  }

  return { configured: trimmed, normalized: canonicalizeServingPath(trimmed) };
}

function resolveAuthMode(
  env: NodeJS.ProcessEnv,
  problems: string[],
  markUnresolved: (value: UnresolvedServingValue) => void,
): InboundAuthMode {
  const raw = env['UNIFI_HTTP_AUTH'];
  const parsed = parseInboundAuthMode(raw);
  if (parsed !== null) return parsed;

  problems.push(
    `UNIFI_HTTP_AUTH="${echoValue(raw ?? '')}" must be \`bearer\` or \`none\`. \`bearer\` requires ` +
      `callers to present UNIFI_HTTP_TOKEN; \`none\` disables inbound authentication entirely ` +
      `and is accepted only on a loopback UNIFI_HTTP_BIND.`,
  );
  markUnresolved('auth');
  // Fail CLOSED: the refusal resolves to the mode that demands a secret.
  return { kind: 'bearer' };
}

/** §2.5. Entries are matched by `hostAllowed`, which normalises them itself. */
function readAllowedHosts(env: NodeJS.ProcessEnv): string[] {
  const raw = env['UNIFI_HTTP_ALLOWED_HOSTS'];
  if (raw === undefined) return [];
  return raw.split(',').map((entry) => entry.trim()).filter((entry) => entry !== '');
}

/**
 * §2.5. The SAME grammar as `UNIFI_ENABLE_WRITES` and deliberately NOT a
 * boolean: `none` | `all` | a comma-separated service list.
 *
 * `true` and `false` are UNRECOGNISED TOKENS here. Reusing the `TRUE_WORDS` /
 * `FALSE_WORDS` path the enable-writes reader takes would ship a gate where
 * `UNIFI_HTTP_ALLOW_WRITES=true` silently means `all` — the broadest authority
 * in the product, granted by a word the operator plausibly typed meaning
 * "yes, the HTTP transport is on".
 */
function resolveAllowWrites(
  env: NodeJS.ProcessEnv,
  problems: string[],
  markUnresolved: (value: UnresolvedServingValue) => void,
): { namesAll: boolean; named: Set<ServiceId> } {
  const named = new Set<ServiceId>();
  let namesAll = false;

  const raw = readString(env, 'UNIFI_HTTP_ALLOW_WRITES');
  if (raw === null) return { namesAll, named };

  const tokens = raw.split(',').map((t) => asciiLowerCase(t.trim())).filter(Boolean);
  for (const token of tokens) {
    if (token === 'all') {
      namesAll = true;
    } else if (token === 'none') {
      // A later `none` resets both accumulators, so `protect,none` is `none`.
      namesAll = false;
      named.clear();
    } else if ((SERVICE_IDS as readonly string[]).includes(token)) {
      named.add(token as ServiceId);
    } else {
      problems.push(
        `UNIFI_HTTP_ALLOW_WRITES lists unknown service "${echoValue(token)}"; valid values are ` +
          `${SERVICE_IDS.join(', ')}, \`all\`, or \`none\`.`,
      );
      markUnresolved('allowWrites');
    }
  }
  return { namesAll, named };
}

/** A new Set holding the members of `left` that are also in `right`. */
function intersect(
  left: ReadonlySet<ServiceId>,
  right: ReadonlySet<ServiceId>,
): Set<ServiceId> {
  const out = new Set<ServiceId>();
  for (const member of left) if (right.has(member)) out.add(member);
  return out;
}

/**
 * PRESENCE of a credential, by either delivery mechanism (FR-78).
 *
 * Reads the file variable for its PRESENCE only and never opens the file: this
 * module does no credential I/O and `ServerConfig` carries no key material. A
 * flag that ignored the `*_FILE` sibling would disable the service, refuse
 * startup with "no UniFi API is usable", and never mention the variable the
 * operator actually set — the accepted-then-discarded failure §5.15.1b forbids.
 */
function hasCredential(env: NodeJS.ProcessEnv, account: string): boolean {
  return Boolean(
    readString(env, account) ?? readString(env, `${account}${CREDENTIAL_FILE_SUFFIX}`),
  );
}

function collectLocalConsoles(env: NodeJS.ProcessEnv, problems: string[]): LocalConsole[] {
  const hosts = new Map<string, string>();

  const primary = readString(env, DEFAULT_LOCAL_HOST_ENV);
  if (primary) hosts.set('default', normalizeHost(primary));

  for (const [key, value] of Object.entries(env)) {
    if (!key.startsWith(LOCAL_HOST_PREFIX) || value === undefined) continue;
    const label = key.slice(LOCAL_HOST_PREFIX.length);
    if (label === '') continue;
    // §5.15.1b, checked before the value: a refusal, not a warning, because the
    // alternative is a console whose key can be set but never read. The console
    // is NOT created — admitting it would leave the rest of startup reasoning
    // about a console no variable can credential.
    if (isReservedLocalLabel(label)) {
      problems.push(reservedLocalLabelProblem(label));
      continue;
    }
    const host = normalizeHost(value);
    if (host === '') {
      problems.push(`${key} is set but empty.`);
      continue;
    }
    hosts.set(label, host);
  }

  return [...hosts.entries()].map(([label, host]) => {
    const apiKeyEnvVar = label === 'default' ? DEFAULT_LOCAL_KEY_ENV : LOCAL_KEY_PREFIX + label;
    return { label, host, apiKeyEnvVar, hasApiKey: hasCredential(env, apiKeyEnvVar) };
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
  /**
   * The secret-free descriptor `resolveBearerSlots` composed. Production passes
   * the real one (see the ordering in `src/serve/auth.ts`); tests that do not
   * care about the inbound secret call `loadConfig(env)` bare and get the
   * neutral default.
   */
  auth?: InboundAuthDescriptor;
}

export function loadConfig(env: NodeJS.ProcessEnv, options: LoadConfigOptions = {}): ServerConfig {
  // Malformed values are collected here and re-reported by validateConfig, so
  // that loadConfig never half-fails: it always returns a usable object.
  const problems: string[] = [];

  const hasCloudApiKey = hasCredential(env, CLOUD_API_KEY_ENV);
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

  const servingResolution = resolveServing(env, options.auth ?? NEUTRAL_AUTH_DESCRIPTOR);
  const serving = servingResolution.serving;

  // §2.6's own value error always reports; every UNIFI_HTTP_* value error is
  // scoped to an http start (IG-1). A leftover UNIFI_HTTP_BIND or
  // UNIFI_HTTP_ALLOW_WRITES in a shell or a shared Compose file must not break
  // a stdio server that never reads either.
  problems.push(...servingResolution.transportProblems);
  if (serving.transport === 'http') problems.push(...servingResolution.httpProblems);

  // THE WRITE SECOND GATE — one narrowing, and no third check anywhere.
  //
  // `writesEnabled` above is the BASE set (UNIFI_ENABLE_WRITES). The HTTP
  // surface additionally intersects it with UNIFI_HTTP_ALLOW_WRITES, and the
  // surface this process selected becomes `config.writesEnabled`. That single
  // assignment is what makes both existing enforcement points inherit the gate
  // with no edit: `src/tools/definitions.ts` drops the write tool from
  // `tools/list` when `writesEnabled.size === 0`, and `src/http/client.ts`
  // refuses an outbound write when `!config.writesEnabled.has(action.service)`.
  // Adding a third check would give the gate a second definition to drift from.
  const httpAllowSet = servingResolution.context.namesAll
    ? new Set(enabledServices)
    : servingResolution.context.named;
  const writesEnabledBySurface = {
    // Two DISTINCT Set instances: `intersect` always allocates, so mutating one
    // surface's set can never alias the other's.
    stdio: writesEnabled,
    http: intersect(writesEnabled, httpAllowSet),
  } as const;

  const config: ServerConfig = {
    enabledServices,
    transport,
    localConsoles,
    defaultLocalHost,
    consoleId,
    caBundlePath: readString(env, 'UNIFI_LOCAL_CA_BUNDLE'),
    localTlsInsecure: readBool(env, 'UNIFI_LOCAL_TLS_INSECURE', problems) ?? false,
    writesEnabled: writesEnabledBySurface[serving.transport],
    writesEnabledBySurface,
    activeSurface: serving.transport,
    serving,
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
  servingContexts.set(config, servingResolution.context);
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

/**
 * The four variables that can carry an inbound shared secret. Read ONLY for
 * presence, never for content — refusal (a) is an ABSENCE refusal.
 */
const INBOUND_SECRET_ENV_KEYS: readonly string[] = [
  'UNIFI_HTTP_TOKEN',
  'UNIFI_HTTP_TOKEN_FILE',
  'UNIFI_HTTP_TOKEN_NEXT',
  'UNIFI_HTTP_TOKEN_NEXT_FILE',
];

/**
 * The five §2.3 startup refusals and the two §3.3 write-gate warnings.
 *
 * ALL of it is scoped to `serving.transport === 'http'`. That scoping is IG-1:
 * a leftover `UNIFI_HTTP_BIND=0.0.0.0` or `UNIFI_HTTP_ALLOW_WRITES=protect` in a
 * shell or a shared Compose file must not break a stdio start, because a stdio
 * server binds no port and none of these refusals describes a real exposure for
 * it.
 *
 * ## The suppression ladder (§2.7)
 *
 * Tiers: T1 value integrity (a value did not parse or could not be read) beats
 * T2 value validity (refusal (d), the 32-character floor) beats T3 combinations
 * (refusals (a), (b), (c), (e)). The point is that the process never reports a
 * refusal it could not have reached — a combination refusal computed over a
 * DEFAULT that silently stood in for an unparseable value is advice about a
 * configuration the operator never wrote.
 *
 * Implemented as guards on `serving.unresolved`:
 *   - `bind` unresolved       ⇒ (b) and (e) are suppressed  [cascades 1, 2]
 *   - `auth` unresolved       ⇒ (a) and (e) are suppressed, and `auth.problems`
 *                               is dropped entirely: `resolveBearerSlots` never
 *                               reaches slot resolution when the MODE is
 *                               invalid, so its only problem IS the mode
 *                               problem, and forwarding it would print the same
 *                               refusal twice
 *   - `path` unresolved       ⇒ (d) is suppressed — its normalisation is only
 *                               defined over an absolute path
 *   - `allowWrites` unresolved ⇒ (c) is suppressed          [cascade 6]
 *
 * Cascades 3, 4 and 5 need no guard at all: an unreadable `*_FILE`, both `X` and
 * `X_FILE` set, and a present-but-too-short secret each set `secretConfigured`,
 * and (a)'s own precondition is the ABSENCE of a secret. Each reports its own
 * T1/T2 refusal from `auth.problems` and (a) stays silent.
 *
 * DELIBERATELY NOT SUPPRESSED: (b) and (e) together on a parsed non-loopback
 * bind with an empty allow-list and `auth=none`. Both are true, and their
 * remedies are real and different. Nor are refusals in different tiers touching
 * different variables — an unparseable port and refusal (d) both report.
 *
 * The ORDER of the returned messages is not fixed by any requirement.
 */
function collectServingProblems(
  config: ServerConfig,
  env: NodeJS.ProcessEnv,
): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const serving = config.serving;
  if (serving.transport !== 'http') return { errors, warnings };

  const context = servingContexts.get(config) ?? {
    configuredPath: serving.path,
    namesAll: false,
    named: new Set<ServiceId>(),
  };
  const unresolved = new Set<UnresolvedServingValue>(serving.unresolved);

  if (!unresolved.has('auth')) errors.push(...serving.auth.problems);
  warnings.push(...serving.auth.warnings);

  const secretConfigured = INBOUND_SECRET_ENV_KEYS.some((key) => {
    const value = env[key];
    return typeof value === 'string' && value !== '';
  });
  const bindAddress = serving.bindAddress;
  const bindIsRoutable =
    !unresolved.has('bind') && bindAddress !== null && !isLoopbackBind(bindAddress);

  // (a) bearer with no secret at all. A resolved-but-invalid secret is NOT "no
  // secret" — that case reports its own, sharper refusal from auth.problems.
  if (!unresolved.has('auth') && serving.authMode.kind === 'bearer' && !secretConfigured) {
    errors.push(
      `UNIFI_MCP_TRANSPORT=http requires an inbound shared secret: set UNIFI_HTTP_TOKEN (or ` +
        `UNIFI_HTTP_TOKEN_FILE) to a string of at least 32 characters. This is a secret you ` +
        `invent for MCP clients to present — it is not your UniFi API key. UNIFI_HTTP_AUTH=none ` +
        `disables inbound authentication entirely and is accepted only when UNIFI_HTTP_BIND is a ` +
        `loopback address.`,
    );
  }

  // (b) reachable off-host with no Host allow-list.
  if (bindIsRoutable && serving.allowedHosts.length === 0) {
    errors.push(
      `UNIFI_HTTP_BIND=${echoValue(serving.bind)} is not a loopback address and ` +
        `UNIFI_HTTP_ALLOWED_HOSTS is empty: set UNIFI_HTTP_ALLOWED_HOSTS to the comma-separated ` +
        `host names clients will use, or set UNIFI_HTTP_BIND=127.0.0.1. Host allow-listing is a ` +
        `DNS-rebinding control that protects browsers, not an access control — also restrict who ` +
        `can reach this port with a firewall or a NetworkPolicy.`,
    );
  }

  // (c) an HTTP write gate that can never open.
  //
  // D-14: the guard is the CONDITION the refusal states — "the effective HTTP
  // write set would be empty and no write action could ever run" — and not one
  // of its causes. An empty UNIFI_ENABLE_WRITES is the obvious cause; two
  // non-empty sets that do not intersect (`UNIFI_ENABLE_WRITES=network` with
  // `UNIFI_HTTP_ALLOW_WRITES=protect`) produce exactly the same dead gate and
  // used to start. The effective set is already computed once, at load, so the
  // guard reads it rather than re-deriving the intersection here.
  const baseWrites = config.writesEnabledBySurface.stdio;
  const effectiveHttpWrites = config.writesEnabledBySurface.http;
  if (
    !unresolved.has('allowWrites') &&
    (context.namesAll || context.named.size > 0) &&
    effectiveHttpWrites.size === 0
  ) {
    const subject = context.namesAll
      ? 'UNIFI_HTTP_ALLOW_WRITES is `all`'
      : `UNIFI_HTTP_ALLOW_WRITES names ${renderServiceList(context.named)}`;
    // The two causes are named separately because the remedy differs: an empty
    // base gate is opened by setting it, whereas two disjoint gates are fixed
    // by making them overlap, and an operator told "UNIFI_ENABLE_WRITES is
    // empty" when it demonstrably is not goes looking for a variable they set.
    const cause =
      baseWrites.size === 0
        ? 'UNIFI_ENABLE_WRITES is empty'
        : `UNIFI_ENABLE_WRITES permits ${renderServiceList(baseWrites)} and the two do not overlap`;
    errors.push(
      `${subject} but ${cause}, so the effective HTTP write set would be ` +
        `empty and no write action could ever run. Set UNIFI_ENABLE_WRITES to the same services, ` +
        `or set UNIFI_HTTP_ALLOW_WRITES=none. Writes over HTTP need both gates; the effective ` +
        `set is the intersection.`,
    );
  }

  // (d) the MCP endpoint normalising onto a probe path. Without this the probe
  // exemption — unauthenticated AND exempt from Host validation — would swallow
  // the MCP endpoint and serve the whole tool surface to anyone on the port.
  if (
    !unresolved.has('path') &&
    (serving.path === HEALTHZ_PATH || serving.path === READYZ_PATH)
  ) {
    errors.push(
      `UNIFI_HTTP_PATH=${echoValue(context.configuredPath)} normalises onto a reserved probe ` +
        `path. \`${HEALTHZ_PATH}\` and \`${READYZ_PATH}\` are unauthenticated and exempt from ` +
        `Host validation, so serving MCP on either would expose the whole tool surface to anyone ` +
        `who can reach this port. Set UNIFI_HTTP_PATH to any other absolute path; the default is ` +
        `/mcp.`,
    );
  }

  // (e) auth=none off loopback. Without this, `auth=none` plus a non-loopback
  // bind plus a populated allow-list passed every other refusal while producing
  // a fully open, key-backed listener.
  if (!unresolved.has('auth') && serving.authMode.kind === 'none' && bindIsRoutable) {
    errors.push(
      `UNIFI_HTTP_AUTH=none is permitted only on a loopback bind, and ` +
        `UNIFI_HTTP_BIND=${echoValue(serving.bind)} is not one: this configuration would serve ` +
        `your UniFi estate to anyone who can reach this port. Set UNIFI_HTTP_BIND=127.0.0.1, or ` +
        `set UNIFI_HTTP_AUTH=bearer and supply UNIFI_HTTP_TOKEN.`,
    );
  }

  warnings.push(...writeGateWarnings(config, null));
  return { errors, warnings };
}

/**
 * What the operator actually wrote in `UNIFI_HTTP_ALLOW_WRITES`, rendered.
 *
 * D-13: the narrowing warning used to hardcode `` `none` `` as the cause, so a
 * narrowed-but-non-empty gate was reported as a value the operator never set —
 * and the same startup's ready line printed the real one, so the log
 * contradicted itself.
 *
 * S-08 still holds — the emitted narrowing line never names `all`. Not by
 * suppressing the truth here, but because the configuration that would produce
 * it (`all` over a base set naming no ENABLED service) has an empty effective
 * HTTP set and is refused by (c) above, so the line is composed and never
 * reaches a stream.
 */
function renderConfiguredAllowWrites(context: ServingContext): string {
  if (context.namesAll) return '`all`';
  if (context.named.size > 0) return renderServiceList(context.named);
  return '`none`';
}

/**
 * §3.3, at most one line. An operator who enabled writes and is not getting
 * them has to be told why and which variable to change; an operator who IS
 * getting them has to be told that the port now changes their estate.
 *
 * `bound` is the address the listener actually got, and it is `null` at
 * configuration load, where no listener exists yet (D-16). Under
 * `UNIFI_HTTP_PORT=0` the configured port is the literal `0`, so composing this
 * line from it renders `127.0.0.1:0` — a bind/port pair that never existed —
 * on the single most consequential security warning in the system, while the
 * adjacent serving line renders the real one. The caller that HAS a bound
 * address passes it; the fallback is exactly what this function used to do.
 */
function writeGateWarnings(config: ServerConfig, bound: BoundAddress | null): string[] {
  const base = config.writesEnabledBySurface.stdio;
  const overHttp = config.writesEnabledBySurface.http;
  const context = servingContexts.get(config);

  if (overHttp.size > 0) {
    const address = renderAddress(
      bound?.address ?? config.serving.bind,
      bound?.port ?? config.serving.port,
    );
    return [
      `WARNING WRITES ENABLED OVER HTTP for ${renderServiceList(overHttp)} on ${address} — any ` +
        `caller presenting the shared secret can change your UniFi estate. Set ` +
        `UNIFI_HTTP_ALLOW_WRITES=none to disable writes on this transport.`,
    ];
  }

  if (base.size > 0) {
    const configured = context === undefined ? '`none`' : renderConfiguredAllowWrites(context);
    return [
      `WARNING WRITES ARE DISABLED ON THIS TRANSPORT. UNIFI_ENABLE_WRITES permits ` +
        `${renderServiceList(base)}, but UNIFI_HTTP_ALLOW_WRITES is ${configured}, so the ` +
        `effective HTTP write set is empty: unifi_execute_write_action is absent from tools/list ` +
        `and every write action will be refused. If that is intended, this line is your ` +
        `confirmation. If it is not, widen UNIFI_HTTP_ALLOW_WRITES and restart.`,
    ];
  }

  return [];
}

/**
 * The startup warnings §3.3 composes, re-composed against the address the
 * listener actually bound (D-16).
 *
 * Exported because the composition has to happen TWICE and cannot happen only
 * once in either place: `validateConfig` reports it as part of the validation
 * verdict, before any listener exists, and the startup announcer emits it after
 * `listen()` has resolved, which is the only moment the real port is knowable.
 * One composer, two moments — the alternative is a second implementation of the
 * §3.3 text somewhere with access to an `AddressInfo`, which is the duplication
 * this module's own D-15 note warns about.
 */
export function writeGateWarningsFor(
  config: ServerConfig,
  bound: BoundAddress | null,
): readonly string[] {
  // The same IG-1 scoping `collectServingProblems` applies, stated once here so
  // the caller cannot forget it: a stdio server binds no port, and neither §3.3
  // line describes anything true of one.
  if (config.serving.transport !== 'http') return [];
  return writeGateWarnings(config, bound);
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

  // §5.15.1b / FR-78: "Ambiguity about which secret is live is not resolved
  // silently." Both spellings of one credential is exactly that ambiguity, and
  // it is decidable from the environment alone — no file is opened here. The
  // same problem is produced by `captureCredentialEnv` for a caller that
  // resolves credentials without validating first; in the wired startup path
  // this refusal is fatal before the capture runs, so it prints once.
  for (const account of [
    config.cloudApiKeyEnvVar,
    ...config.localConsoles.map((c) => c.apiKeyEnvVar),
  ]) {
    const file = `${account}${CREDENTIAL_FILE_SUFFIX}`;
    if (readString(env, account) !== null && readString(env, file) !== null) {
      mutuallyExclusiveOptions.push(
        `${account} and ${file} are both set and only one API key can be live. Set exactly one.`,
      );
    }
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
  const serving = collectServingProblems(config, env);
  errors.push(...mutuallyExclusiveOptions, ...malformed, ...serving.errors);
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
  warnings.push(...serving.warnings);

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
    serving: servingSummary(config),
  };
}

/**
 * The serving block of the start line.
 *
 * `auth` carries EXACTLY three fields. `minSlotLength` is omitted deliberately:
 * printing it would make the start line a length oracle for the inbound secret.
 * `problems` and `warnings` are omitted too — they are rendered by
 * `validateConfig` as errors and warnings, and repeating them here would put
 * operator-supplied paths into a line that is meant to be safe to paste.
 */
function servingSummary(config: ServerConfig): Record<string, unknown> {
  const serving = config.serving;
  return {
    transport: serving.transport,
    activeSurface: config.activeSurface,
    bind: echoValue(serving.bind),
    port: serving.port,
    path: echoValue(serving.path),
    allowedHosts: serving.allowedHosts,
    auth: {
      mode: serving.auth.mode,
      slotCount: serving.auth.slotCount,
      sources: serving.auth.sources,
    },
    writesEnabledBySurface: {
      stdio: [...config.writesEnabledBySurface.stdio].sort(),
      http: [...config.writesEnabledBySurface.http].sort(),
    },
    limits: {
      maxSessions: serving.maxSessions,
      sessionIdleTtlMs: serving.sessionIdleTtlMs,
      maxConnections: serving.maxConnections,
      maxBodyBytes: serving.maxBodyBytes,
      maxHeaderBytes: serving.maxHeaderBytes,
      headersTimeoutMs: serving.headersTimeoutMs,
      requestTimeoutMs: serving.requestTimeoutMs,
      keepAliveTimeoutMs: serving.keepAliveTimeoutMs,
      sseKeepaliveMs: serving.sseKeepaliveMs,
      shutdownDeadlineMs: serving.shutdownDeadlineMs,
      authFailPerMin: serving.authFailPerMin,
    },
  };
}
