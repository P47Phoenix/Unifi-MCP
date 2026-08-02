/**
 * The one sanitised stderr emitter and the request-log composer (US-13).
 *
 * Traceability: NFR-24 (the eight-field request line), NFR-19 as replaced by
 * E-21 (everything on stderr), FR-63 (probe-log suppression), AR-7 (the
 * `draining` reject reason), NFR-21 (untrusted values are defanged before they
 * are written anywhere a human or a model will read them).
 *
 * ## Why every byte goes to stderr
 *
 * On HTTP, stdout is technically free, and diagnostics still go to stderr. A
 * single logging path means no code path can acquire a stray stdout write that
 * would corrupt a stdio session when the transport is switched back. The
 * sentinel scan in the test suite runs against captured *stderr*, so a line
 * written to stdout would land outside the assertion and the scan would pass
 * while leaking — the single path is what keeps the assertion meaningful.
 *
 * ## Why `path` is a route label and never the request target
 *
 * The raw request target is attacker-controlled. Logging it would let an
 * unauthenticated caller write arbitrary bytes into the operator's log stream:
 * CRLF injection to forge a log line, terminal escape sequences aimed at
 * whoever tails the file, or eight kilobytes of junk per request to bury the
 * forensic record. The server logs which of four routes the request resolved
 * to, and nothing else. `RouteLabel` has four members, so there is no
 * expressible way to put a request target on the line.
 *
 * ## What can never be logged, structurally
 *
 * The inbound token in any form, the `Authorization` header, the session id
 * (`Mcp-Session-Id` is bearer-equivalent), request bodies, and tool results are
 * never logged. The defence is not discipline: no parameter of this module's
 * public API can carry any of them. `auth` is a two-valued enum, not a
 * credential; `body_size` is a *reason*, never a length; `status` is the HTTP
 * status, never the tool outcome; `client` is the socket peer address, which
 * comes from the kernel rather than from any header or body. The only string
 * that reaches the stream unconstrained is a diagnostic message, and that one
 * is passed through `sanitizeUntrusted` first.
 *
 * ## The asymmetry that makes the emitter necessary
 *
 * The `req` line's closed field set makes it injection-proof, and that is
 * exactly what makes the *next* line dangerous. A `\n` inside any other
 * interpolated value — an exception message, a value echoed from a request, a
 * value read from the environment — lets an attacker synthesise a
 * perfectly-formed, regex-passing `unifi-mcp: req … auth=ok … client=<address
 * of their choosing>` entry and defeat post-incident analysis. So every
 * non-`req` write goes through `emitDiagnostic`, which sanitises first. The
 * `req` line itself is exempt by construction: it has no interpolated free
 * values.
 */
import { isIP } from 'node:net';

import { sanitizeUntrusted } from '../safety/sanitize.js';
import { SERVICE_IDS, type ServiceId } from '../types.js';

/** Prefixes every line this module writes, so operator greps have one anchor. */
export const LOG_PREFIX = 'unifi-mcp: ';

/** Distinguishes the machine-readable request line from free-text diagnostics. */
export const REQUEST_MARKER = 'req';

/**
 * At most one probe line per route per interval. A fixed constant and not a
 * configuration variable, because FR-63 closes that family.
 */
export const PROBE_LOG_INTERVAL_MS = 10_000;

/**
 * Ceiling on the throttled-source tracker, so the tracker cannot itself become
 * the memory-exhaustion vector it exists to bound. Eviction is oldest-first.
 */
export const MAX_TRACKED_THROTTLED_CLIENTS = 1024;

/** Rendered when the peer address is unavailable, and when a value is unusable. */
export const UNAVAILABLE_CLIENT = '-';

/** Rendered in `reject_reason` when the request was not rejected. */
export const NO_REJECT_REASON = '-';

const HTTP_METHOD_LABELS = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
  'OTHER',
] as const;

/**
 * A closed set. Any other method logs `OTHER`, so a caller cannot choose the
 * token that lands in the field by choosing the verb they send.
 */
export type HttpMethodLabel = (typeof HTTP_METHOD_LABELS)[number];

const ROUTE_LABELS = ['mcp', 'healthz', 'readyz', 'other'] as const;

/** The four routes the transport resolves to. Never the request target. */
export type RouteLabel = (typeof ROUTE_LABELS)[number];

const AUTH_OUTCOMES = ['ok', 'rejected'] as const;

/** Two-valued by design: there is no field here that could carry a credential. */
export type AuthOutcome = (typeof AUTH_OUTCOMES)[number];

const REJECT_REASONS = [
  NO_REJECT_REASON,
  'auth',
  'host',
  'origin',
  'path',
  'method',
  'body_size',
  'rate_limit',
  'session_limit',
  'draining',
] as const;

/**
 * Always present. `-` when the request was not rejected — an absent field would
 * shift every following field's position for a log parser.
 *
 * `draining` distinguishes a rolling deploy from a capacity incident; it is
 * AR-7's amendment and postdates the operator contract's §4.2 regex listing.
 */
export type RejectReason = (typeof REJECT_REASONS)[number];

const METHOD_LABEL_SET: ReadonlySet<string> = new Set<string>(HTTP_METHOD_LABELS);
const ROUTE_LABEL_SET: ReadonlySet<string> = new Set<string>(ROUTE_LABELS);
const AUTH_OUTCOME_SET: ReadonlySet<string> = new Set<string>(AUTH_OUTCOMES);
const REJECT_REASON_SET: ReadonlySet<string> = new Set<string>(REJECT_REASONS);
const SERVICE_ID_SET: ReadonlySet<string> = new Set<string>(SERVICE_IDS);

/**
 * The closed eight-field record NFR-24 specifies. Adding a field here is a type
 * error at every call site, which is where a field-count mistake should surface
 * — not as a regex failure discovered in CI.
 */
export interface RequestLogFields {
  readonly method: HttpMethodLabel;
  /** Renders as `path=`. The route label, never the request target. */
  readonly route: RouteLabel;
  readonly status: number;
  readonly durationMs: number;
  readonly auth: AuthOutcome;
  readonly rejectReason: RejectReason;
  /** The EFFECTIVE resolved set. Empty renders `none`; `all` is never rendered. */
  readonly writes: readonly ServiceId[];
  /** Already normalised by `normalizeClientAddress`, or `-`. */
  readonly client: string;
}

/**
 * Map an inbound method to the closed vocabulary.
 *
 * Case-sensitive on purpose: HTTP methods are case-sensitive, so `post` is not
 * `POST`, and treating it as one would let a caller probe which spellings the
 * server folds. Everything unrecognised — including a method carrying a newline
 * — becomes `OTHER`.
 */
export function methodLabel(rawMethod: string | undefined): HttpMethodLabel {
  if (typeof rawMethod !== 'string') return 'OTHER';
  return METHOD_LABEL_SET.has(rawMethod) ? (rawMethod as HttpMethodLabel) : 'OTHER';
}

/** Printable ASCII with no space. Any address the kernel produces is in here. */
const SAFE_CLIENT_CHARS = /^[\x21-\x7E]+$/;

/** `::ffff:10.42.0.7` — the dotted spelling of an IPv4-mapped IPv6 address. */
const MAPPED_IPV4_DOTTED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/;

/** `::ffff:0a2a:0007` — the same address, spelled in hex groups. */
const MAPPED_IPV4_HEX = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/;

/** `[2001:db8::1]` or `[2001:db8::1]:443` — a bracketed authority form. */
const BRACKETED_HOST = /^\[([^\]]+)\](?::\d+)?$/;

/** `10.42.0.7:54321` — an IPv4 address with a port appended. */
const IPV4_WITH_PORT = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/;

/**
 * The single client-address normalisation: one function for the log field and,
 * later, for the auth-failure throttle key. Two normalisations would mean an
 * attacker could be throttled under one spelling and logged under another.
 *
 * IPv4-mapped IPv6 renders in its IPv4 form, so `::ffff:10.42.0.7` and
 * `10.42.0.7` are one source and not two. Everything else renders as the kernel
 * gave it, lower-cased, without brackets and without a port — including the
 * zone suffix of a link-local address, which identifies the interface the
 * traffic arrived on and is operationally load-bearing.
 *
 * An unavailable address renders `-`. That is attacker-inducible: send a
 * request and reset the socket before the handler reads `remoteAddress`. `-` is
 * a member of the field's domain, so inducing it changes nothing about whether
 * the line parses.
 */
export function normalizeClientAddress(rawAddress: string | null | undefined): string {
  if (typeof rawAddress !== 'string') return UNAVAILABLE_CLIENT;

  let address = rawAddress.trim().toLowerCase();

  const bracketed = BRACKETED_HOST.exec(address);
  if (bracketed?.[1] !== undefined) address = bracketed[1];

  const withPort = IPV4_WITH_PORT.exec(address);
  if (withPort?.[1] !== undefined) address = withPort[1];

  const dotted = MAPPED_IPV4_DOTTED.exec(address);
  if (dotted?.[1] !== undefined && isIP(dotted[1]) === 4) address = dotted[1];

  const hex = MAPPED_IPV4_HEX.exec(address);
  if (hex?.[1] !== undefined && hex[2] !== undefined) {
    address = renderMappedIpv4(hex[1], hex[2]);
  }

  // The grammar guard, and the reason this function can be trusted at the
  // composer's boundary: a value that would introduce a space, a newline, or a
  // control character would split one log line into two, which is the whole
  // attack the closed field set exists to prevent.
  return SAFE_CLIENT_CHARS.test(address) ? address : UNAVAILABLE_CLIENT;
}

const BITS_PER_HEX_GROUP_HIGH_BYTE = 8;
const BYTE_MASK = 0xff;

function renderMappedIpv4(highGroup: string, lowGroup: string): string {
  const high = Number.parseInt(highGroup, 16);
  const low = Number.parseInt(lowGroup, 16);
  const octets = [
    (high >> BITS_PER_HEX_GROUP_HIGH_BYTE) & BYTE_MASK,
    high & BYTE_MASK,
    (low >> BITS_PER_HEX_GROUP_HIGH_BYTE) & BYTE_MASK,
    low & BYTE_MASK,
  ];
  return octets.join('.');
}

/**
 * Render the effective write set: alphabetical, comma-separated, no space.
 *
 * Alphabetical always, never declaration order, so two lines describing the
 * same set are byte-identical and `sort | uniq -c` over a day of logs is
 * meaningful. The separator is a comma because a space is the field separator.
 * `all` is accepted *input* syntax elsewhere and is never an output value: an
 * operator reading `writes=all` cannot tell which services were actually
 * reachable, so the resolved set is always rendered explicitly.
 */
export function renderWriteSet(services: Iterable<ServiceId>): string {
  const known = new Set<string>();
  for (const service of services) {
    if (SERVICE_ID_SET.has(service)) known.add(service);
  }
  if (known.size === 0) return 'none';
  return [...known].sort().join(',');
}

/**
 * Compose the NFR-24 request line. Pure: no clock, no I/O, no suppression.
 *
 * Every coercion below is a programmer-error guard, so the composer can never
 * emit a line its own grammar rejects. Each one prefers a truthful in-vocabulary
 * value over an out-of-vocabulary one, because a line that fails to parse is
 * worth less to an incident responder than a line with one conservative field.
 */
export function composeRequestLine(fields: RequestLogFields): string {
  const parts = [
    `method=${methodLabel(fields.method)}`,
    `path=${routeField(fields.route)}`,
    `status=${statusField(fields.status)}`,
    `dur_ms=${durationField(fields.durationMs)}`,
    `auth=${authField(fields.auth)}`,
    `reject_reason=${rejectReasonField(fields.rejectReason)}`,
    `writes=${renderWriteSet(fields.writes ?? [])}`,
    `client=${clientField(fields.client)}`,
  ];
  return `${LOG_PREFIX}${REQUEST_MARKER} ${parts.join(' ')}`;
}

function routeField(route: RouteLabel): RouteLabel {
  return ROUTE_LABEL_SET.has(route) ? route : 'other';
}

const MIN_HTTP_STATUS = 100;
const MAX_HTTP_STATUS = 999;
/** Stands in for a status outside the three-digit domain: a bug is a 500. */
const FALLBACK_STATUS = 500;

function statusField(status: number): string {
  const whole = Math.trunc(status);
  if (!Number.isFinite(whole) || whole < MIN_HTTP_STATUS || whole > MAX_HTTP_STATUS) {
    return String(FALLBACK_STATUS);
  }
  return String(whole);
}

function durationField(durationMs: number): string {
  const whole = Math.trunc(durationMs);
  if (!Number.isFinite(whole) || whole < 0) return '0';
  return String(whole);
}

/** An unrecognised outcome renders `rejected`: never claim a request was allowed. */
function authField(auth: AuthOutcome): AuthOutcome {
  return AUTH_OUTCOME_SET.has(auth) ? auth : 'rejected';
}

/**
 * An unrecognised reason renders `-`. Emitting the unknown token instead would
 * put a caller-influenced string in the field, which is the injection the closed
 * vocabulary exists to prevent — the grammar is the invariant worth keeping.
 */
function rejectReasonField(reason: RejectReason): RejectReason {
  return REJECT_REASON_SET.has(reason) ? reason : NO_REJECT_REASON;
}

/** Re-applies the grammar guard: the composer trusts nothing, including itself. */
function clientField(client: string): string {
  if (typeof client !== 'string') return UNAVAILABLE_CLIENT;
  return SAFE_CLIENT_CHARS.test(client) ? client : UNAVAILABLE_CLIENT;
}

/** Emitted when there is genuinely nothing to say about a failure. */
const UNSPECIFIED_ERROR = 'unspecified error';

/**
 * Render a caught `unknown` into one safe, single-line description.
 *
 * No stack, no exception class, no source path: a stack frame names the
 * deployment layout, and the class name is a fingerprint of the dependency tree.
 * A thrown object is described by its shape and never by its contents, because
 * stringifying it is exactly how a request body, a header, or a token ends up in
 * the log stream — the thrower chooses those bytes, not this module.
 */
export function describeError(error: unknown): string {
  if (error instanceof Error) {
    return sanitizeUntrusted(error.message).value || UNSPECIFIED_ERROR;
  }
  if (typeof error === 'string') {
    return sanitizeUntrusted(error).value || UNSPECIFIED_ERROR;
  }
  if (typeof error === 'number' || typeof error === 'boolean' || typeof error === 'bigint') {
    return `non-error thrown (${String(error)})`;
  }
  if (error === null || error === undefined) return UNSPECIFIED_ERROR;
  return `non-error thrown (${typeof error})`;
}

export interface DiagnosticLoggerDeps {
  /**
   * Receives one complete line, newline-free. The default is the one write to
   * the standard error stream in the running server; tests inject a collector
   * rather than patching the process-global stream, which would be a
   * cross-test leak.
   */
  readonly write?: (line: string) => void;
  /** Monotonic milliseconds. Injected so probe suppression needs no real timer. */
  readonly now?: () => number;
  /** `ServingObserver.onRequestLog` seam. Inert in production. */
  readonly onRequestLog?: (line: string) => void;
}

export interface LogRequestOptions {
  /**
   * True when this probe changed the response state — a `/readyz` transition
   * `starting`→`ready` or `ready`→`draining`. Always logged, interval or not:
   * the transition is the single most useful line in the file during an
   * incident, and it happens exactly when the flood is most likely.
   */
  readonly probeStateChanged?: boolean;
}

export interface DiagnosticLogger {
  /** Sanitises, prefixes, and writes exactly one line. */
  emitDiagnostic(message: string): void;
  /** The exception-boundary emitter: context, then a safe error description. */
  emitError(context: string, error: unknown): void;
  /** Applies suppression, then writes. Returns whether a line was emitted. */
  logRequest(fields: RequestLogFields, options?: LogRequestOptions): boolean;
}

interface SuppressionState {
  /** Per route, when a probe line was last emitted. Absent means never. */
  readonly probeLastLoggedAt: Map<RouteLabel, number>;
  /** Insertion-ordered, so the first key is the oldest and eviction is O(1). */
  readonly throttledClients: Map<string, true>;
}

/**
 * The one and only write to the standard error stream in the running server.
 * A source scan over `src/serve/` asserts that no sibling module holds one.
 */
function writeLineToStandardError(line: string): void {
  process.stderr.write(`${line}\n`);
}

/**
 * `req` is reserved after the prefix.
 *
 * Without this, a fully caller-controlled diagnostic message beginning `req
 * method=…` would render as a syntactically perfect request line even though no
 * request happened — the newline injection blocked by sanitisation, arrived at
 * from the other side.
 */
const RESERVED_LEADER = new RegExp(`^${REQUEST_MARKER}(?=\\s|$)`);

function guardReservedMarker(body: string): string {
  return RESERVED_LEADER.test(body) ? `«reserved» ${body}` : body;
}

/**
 * Build a logger with its own suppression state.
 *
 * The state lives on the returned object rather than in the module so that two
 * loggers — and two tests — never share a counter.
 */
export function createDiagnosticLogger(deps: DiagnosticLoggerDeps = {}): DiagnosticLogger {
  const write = deps.write ?? writeLineToStandardError;
  // Monotonic, because a wall clock that steps backwards during an NTP
  // correction would suppress every probe line until it caught up.
  const now = deps.now ?? (() => performance.now());
  const onRequestLog = deps.onRequestLog;

  const state: SuppressionState = {
    probeLastLoggedAt: new Map<RouteLabel, number>(),
    throttledClients: new Map<string, true>(),
  };

  function emitDiagnostic(message: string): void {
    const sanitised = sanitizeUntrusted(String(message)).value.trim();
    write(`${LOG_PREFIX}${guardReservedMarker(sanitised || '(empty diagnostic)')}`);
  }

  function emitError(context: string, error: unknown): void {
    const safeContext = sanitizeUntrusted(String(context)).value.trim() || 'error';
    emitDiagnostic(`${safeContext} — ${describeError(error)}`);
  }

  function logRequest(fields: RequestLogFields, options: LogRequestOptions = {}): boolean {
    if (!shouldEmitRequestLine(state, fields, now(), options.probeStateChanged === true)) {
      return false;
    }
    const line = composeRequestLine(fields);
    write(line);
    onRequestLog?.(line);
    return true;
  }

  return { emitDiagnostic, emitError, logRequest };
}

function shouldEmitRequestLine(
  state: SuppressionState,
  fields: RequestLogFields,
  nowMs: number,
  probeStateChanged: boolean,
): boolean {
  const client = clientField(fields.client);

  // Throttle suppression first: one line per throttled source at the moment it
  // enters the throttled state, not one per throttled request. Otherwise an
  // attacker at 10 000 req/s still produces 10 000 lines/s and the throttle
  // contributes nothing to the log-flooding problem it appears to bound.
  if (fields.rejectReason === 'rate_limit') {
    return enterThrottledState(state, client);
  }

  const emit = isProbeRoute(fields.route)
    ? shouldLogProbe(state, fields.route, nowMs, probeStateChanged)
    : true;

  // "The state clears when that client is logged with any other outcome" — a
  // suppressed line was not logged, so it does not clear anything.
  if (emit) state.throttledClients.delete(client);
  return emit;
}

function isProbeRoute(route: RouteLabel): boolean {
  return route === 'healthz' || route === 'readyz';
}

/**
 * Probe suppression is a security control, not a volume tweak.
 *
 * The probe endpoints need no credential, are exempt from `Host` validation and
 * from the auth-failure throttle. Without suppression one unauthenticated
 * source at 10 000 req/s produces roughly 1.1 MB/s of log and buries the
 * forensic record under its own noise.
 *
 * The two routes suppress independently: `/healthz` never flips, so its line is
 * nearly content-free, while a `/readyz` line carries the phase — collapsing
 * them would let liveness traffic hide a readiness transition.
 */
function shouldLogProbe(
  state: SuppressionState,
  route: RouteLabel,
  nowMs: number,
  probeStateChanged: boolean,
): boolean {
  const lastLoggedAt = state.probeLastLoggedAt.get(route);
  const intervalElapsed =
    lastLoggedAt === undefined || nowMs - lastLoggedAt >= PROBE_LOG_INTERVAL_MS;
  if (!probeStateChanged && !intervalElapsed) return false;
  state.probeLastLoggedAt.set(route, nowMs);
  return true;
}

/**
 * Returns true the first time a source is seen in the throttled state.
 *
 * `-` is never suppressed. It is the absence of an identity, not an identity:
 * collapsing every source whose address was unavailable into one state would
 * let a single attacker's entry silence the first throttle line of every other
 * anonymous source. One line per anonymous throttled request is the cost, and
 * it is bounded by the throttle itself.
 *
 * The tracker holds at most `MAX_TRACKED_THROTTLED_CLIENTS` sources and evicts
 * the oldest insertion. Eviction is not a correctness problem: the worst
 * outcome is one extra line for a source that is still throttled, which is
 * bounded by the eviction rate rather than by the request rate.
 */
function enterThrottledState(state: SuppressionState, client: string): boolean {
  if (client === UNAVAILABLE_CLIENT) return true;
  if (state.throttledClients.has(client)) return false;

  if (state.throttledClients.size >= MAX_TRACKED_THROTTLED_CLIENTS) {
    const oldest = state.throttledClients.keys().next().value;
    if (oldest !== undefined) state.throttledClients.delete(oldest);
  }
  state.throttledClients.set(client, true);
  return true;
}

/**
 * The process-wide default, for the exception boundary and the startup path
 * where no logger instance has been threaded through yet (architecture §5.8).
 */
const defaultLogger = createDiagnosticLogger();

export function emitDiagnostic(line: string): void {
  defaultLogger.emitDiagnostic(line);
}

export function emitError(context: string, error: unknown): void {
  defaultLogger.emitError(context, error);
}
