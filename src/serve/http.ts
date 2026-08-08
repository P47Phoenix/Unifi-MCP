/**
 * The HTTP serving transport: the listener, the request-validation pipeline and
 * the inbound bounds (architecture §5.3, §5.5, §5.5.1; operator contract §5, §6).
 *
 * Traceability: FR-62 (bind, and the serving line's real port), FR-64 (inbound
 * authentication), FR-65 (`Host`), FR-66 (`Origin`, and no CORS anywhere),
 * FR-67 (the two-route probe exemption and its method scoping), FR-76 (every
 * inbound bound), FR-81 (the uniform unauthenticated rejection and the
 * rejection throttle), NFR-24 (the per-request log line), NFR-29 (nothing an
 * unauthenticated caller sends is unbounded).
 *
 * ## The one idea this module exists to enforce
 *
 * **The status code must stop being an oracle.** An unauthenticated caller who
 * sends a disallowed `Host`, a request carrying any `Origin`, a request to an
 * unknown path, a request with a disallowed method, or an over-cap body must
 * receive the SAME status, the SAME body bytes, the SAME header set and the
 * SAME post-response socket disposition as one who simply sent no credential.
 * If any of those differed, a stranger could enumerate the `Host` allow-list,
 * discover the configured MCP path, or measure the body cap without ever
 * presenting a credential — mapping the server's internal shape for free.
 *
 * The mechanism is not "compose five identical responses carefully". It is the
 * ORDER: authentication runs at step 4, and `Host`, `Origin`, route, method and
 * body are steps 6-10. An unauthenticated caller never reaches them, so there
 * is nothing for them to differ about. Uniformity is a consequence of the
 * ordering rather than a property maintained by hand.
 *
 * ## The normative pipeline order (architecture §5.3)
 *
 *   0a  connection admission, in OUR OWN `connection` handler
 *   1   header cap                     — Node's parser, pre-application `431`
 *   2   normalise the target ONCE into a `Route`; the raw target is discarded
 *   2b  headroom claim check           — uniform `401` + socket destroyed
 *   3   probe branch                   — never throttled, never counted
 *   4   authenticate                   — always performed for a non-probe request
 *   5   throttle decision              — `429` or the uniform `401`
 *   6   `Host`                         — `403 forbidden`
 *   7   `Origin`                       — `403`, byte-identical to step 6
 *   8   route                          — `404 not_found`
 *   9   method                         — `405 method_not_allowed` + `Allow`
 *   10  body cap                       — `413 payload_too_large` + `Connection: close`
 *   11  session admission
 *   12  drain gate                     — `503` + the drain body
 *   12r readiness gate                 — `503 unavailable`
 *   13  MCP dispatch
 *   X   fail-closed boundary wrapping 2-13
 *
 * Getting a step out of order breaks a byte-identity or ordering guarantee even
 * when every individual check is correct. Two orderings in particular are load
 * bearing and were changed late in design:
 *
 *   - **The probe branch precedes the throttle.** Otherwise a source key that
 *     crossed the threshold receives `429` on `GET /healthz` — and in
 *     Kubernetes the kubelet probes from the NODE address, so anything NAT'd to
 *     that node tripping the throttle makes the next liveness probe fail and
 *     `failureThreshold` consecutive failures restart the container. The rate
 *     limiter would restart the service it protects.
 *   - **The throttle follows authentication and is conditional on it.** Behind
 *     a reverse proxy — the recommended shape, and the only way to get TLS —
 *     `remoteAddress` is the proxy's address for every request, so one key
 *     covers the whole caller population. Throttling before authentication lets
 *     a stranger lock out the legitimate client, holding the correct secret,
 *     with twenty-one garbage requests a minute.
 *
 * ## The session registry is OURS IN FULL (architecture §4)
 *
 * The SDK supplies **no session registry, no map, no store, no TTL, no cap, no
 * eviction and no forced-termination API at any layer**. A transport instance
 * *is* one session and its entire session state is the public field
 * `sessionId?: string`; the internal stream maps are private with no getter.
 * The map, the reservation counter, the sweep, the eviction path and the
 * identifier generator below are therefore written from scratch rather than
 * configured on top of an SDK primitive — there is none to lean on.
 *
 * And a session is a BEARER-EQUIVALENT CREDENTIAL (NFR-24): in stateful mode
 * possession of an `Mcp-Session-Id` is sufficient to continue a session, which
 * is why identifier entropy, the TTL and eviction are security controls here
 * and not resource hygiene.
 *
 * ## What this module does NOT own
 *
 * The ordered drain sequence, the pre-drain hold, the in-flight wait, the
 * deadline and the exit-code vocabulary are US-24's. What is here is the
 * pipeline STEP the drain gate plugs into — step 12 — and `terminateSession`,
 * the single per-session close path US-24's step 7 calls for each live session.
 */
import { randomBytes } from 'node:crypto';
import {
  createServer as createNodeHttpServer,
  type IncomingMessage,
  type RequestListener,
  type Server,
  type ServerOptions,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo, Socket } from 'node:net';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  StreamableHTTPServerTransport,
  type StreamableHTTPServerTransportOptions,
} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  isInitializeRequest,
  type JSONRPCMessage,
  type RequestId,
} from '@modelcontextprotocol/sdk/types.js';

import type { ServerConfig } from '../config.js';

import type { NonEmptySlots } from './auth.js';
import {
  bearerMatches,
  createRejectionThrottle,
  createRouteNormalizer,
  hasOrigin,
  hostAllowed,
  sourceKey,
  type RejectionThrottle,
  type RejectionThrottleOptions,
  type Route,
} from './guard.js';
import {
  createReadinessState,
  handleProbe,
  type ProbeKind,
  type ProbeMethod,
  type ReadinessState,
} from './health.js';
import {
  createDiagnosticLogger,
  methodLabel,
  normalizeClientAddress,
  type DiagnosticLogger,
  type RejectReason,
  type RouteLabel,
} from './log.js';
import { createMcpServer } from './mcpServer.js';
import {
  resolveRegistry,
  type DrainReason,
  type Runtime,
  type RuntimeCore,
  type Serving,
  type ServingDeps,
  type ServingObserver,
  type Surface,
} from './runtime.js';

// ---------------------------------------------------------------------------
// Fixed constants (architecture §14 item 13: constants, not variables, because
// FR-63 closes the `UNIFI_HTTP_*` family)
// ---------------------------------------------------------------------------

/**
 * Connections reserved for requests resolving to a probe route.
 *
 * Fixed at 8 and per-source-capped at 1. Without a headroom an attacker holding
 * `UNIFI_HTTP_MAX_CONNECTIONS` sockets just under the headers timeout, and
 * re-opening as they expire, prevents the kubelet from connecting at all —
 * `/readyz` failures pull the pod from the Service and `/healthz` failures
 * restart it. That is remote, unauthenticated, on-demand restart of a healthy
 * process holding a live UniFi credential, achieved through a shared resource
 * rather than through either probe.
 *
 * Honest scope, because the previous revision of this design called the vector
 * closed and it was not: the per-source cap defeats the single-source version
 * completely. It does NOT defeat a distributed attacker holding eight distinct
 * source keys — it raises the cost from 64 sockets of arbitrary traffic to 8
 * sockets of probe-shaped traffic from 8 distinct sources. The control that
 * closes that is network reach, which is an operator obligation.
 */
export const PROBE_CONNECTION_HEADROOM = 8;

/** The MCP endpoint's method set. Fixed text, never configuration. */
const MCP_ALLOW = 'POST, GET, DELETE, HEAD';

/** A probe path's method set (FR-67: only `GET` and `HEAD` are exempt). */
const PROBE_ALLOW = 'GET, HEAD';

/** Floor on the incomplete-request sweep, so a 1 ms timeout is not a busy loop. */
const MIN_CONNECTIONS_CHECKING_INTERVAL_MS = 250;
/** The sweep runs this many times inside the tightest timeout it enforces. */
const CONNECTIONS_CHECKS_PER_TIMEOUT = 4;

/** See the call site: this is what makes `headersTimeout` the timeout in force. */
function connectionsCheckingIntervalFor(bounds: ResolvedInboundBounds): number {
  const tightest = Math.min(bounds.headersTimeout, bounds.requestTimeout);
  return Math.max(
    MIN_CONNECTIONS_CHECKING_INTERVAL_MS,
    Math.floor(tightest / CONNECTIONS_CHECKS_PER_TIMEOUT),
  );
}

const MCP_METHODS: ReadonlySet<string> = new Set(['POST', 'GET', 'DELETE', 'HEAD']);
const PROBE_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD']);

/**
 * Session identifier entropy, in bytes (architecture §4.2).
 *
 * 32 bytes is 256 bits and 43 URL-safe characters. NFR-30's floor is 128 bits;
 * the extra costs nothing and removes any argument about entropy accounting.
 *
 * **`randomUUID()` is deliberately NOT used**, departing from the SDK's own
 * documented example. A v4 UUID carries 122 bits — six of its 128 are fixed
 * version and variant markers — so it misses FR-77's floor, and the miss is
 * INVISIBLE: a test that counts characters, or asserts uniqueness across 10 000
 * draws, passes against it. That is why this story's entropy assertion is made
 * on the DECODED BYTE LENGTH of the identifier rather than on its character
 * count, which a base64 or hex encoding inflates without adding a bit.
 */
const SESSION_ID_BYTES = 32;

/** The sweep interval is a quarter of the TTL, ceilinged. See `sessionSweepIntervalMs`. */
const SESSION_SWEEP_DIVISOR = 4;
const SESSION_SWEEP_CEILING_MS = 30_000;

/**
 * What a caller arriving after the drain began is told (contract §5.14).
 *
 * Deliberately a SECOND COPY of `stdio.ts`'s `DRAIN_REFUSAL_MESSAGE` rather
 * than an import: architecture §9.4 makes an HTTP surface importing the stdio
 * module the wrong shape, and US-24 lifts the shared vocabulary into a
 * transport-neutral module when it lands. Recorded here so the duplication is a
 * known pinned pair rather than an unowned one.
 */
const DRAIN_MESSAGE =
  'The server is shutting down and is not accepting new requests. Retry against a new instance.';

/**
 * One fixed sentence for an evicted identifier, an expired one, and a
 * well-formed one that never existed — so a caller cannot use the response to
 * distinguish a live session id from a dead one. The identifier is never
 * echoed, and no configuration value is named.
 */
const SESSION_UNKNOWN_MESSAGE = 'The session identifier is not valid. Start a new session.';

/** The SDK's own answer for a non-initialisation request carrying no session id. */
const SESSION_REQUIRED_MESSAGE = 'Bad Request: Mcp-Session-Id header is required';

/**
 * The cap refusal (operator contract §5.12), verbatim.
 *
 * It names BOTH variables and that is normative rather than helpful. Naming
 * only `UNIFI_HTTP_MAX_SESSIONS` answers the wrong question in the common case:
 * a server at the cap is far more often holding N zombie sessions than serving
 * N live clients, and the second sentence is the actual fix. **Eviction is
 * never used to make room** — a caller at the cap is told to wait or to reduce
 * use, and no live session is ever terminated to admit a new one, because
 * LRU-on-cap would turn a capacity control into a denial-of-service primitive
 * that any secret-holder could aim at the operator's own client.
 *
 * No configured VALUE appears, only the variable names.
 */
const SESSION_LIMIT_MESSAGE =
  'Session limit reached. This server is at its configured maximum of concurrent MCP ' +
  'sessions. Raise UNIFI_HTTP_MAX_SESSIONS on the server and restart it, or close an idle ' +
  'session; abandoned sessions are evicted after UNIFI_HTTP_SESSION_IDLE_TTL_MS.';

/** The one JSON-RPC error code this module emits (contract §5.12, §5.14). */
const JSON_RPC_SERVER_ERROR = -32000;
/** Reserved for the unknown-session answer, so the two are never conflated. */
const JSON_RPC_SESSION_UNKNOWN = -32001;

// ---------------------------------------------------------------------------
// The session primitives — ours in full (architecture §4)
// ---------------------------------------------------------------------------

/**
 * Draw one session identifier (architecture §4.2, FR-77, NFR-30).
 *
 * THE SINGLE EXPORTED GENERATOR, and `randomSource` is FR-77's byte-source spy
 * rather than a configuration point. FR-77 requires proof that *exactly one*
 * CSPRNG draw occurs per identifier and that no `Math.random` path exists; Node
 * 20 has no `mock.module` to intercept `node:crypto`, so a default parameter is
 * not one mechanism among several — it is the only one available. Production
 * takes the default and the spy is inert.
 *
 * One `randomSource` call per identifier, by construction: there is exactly one
 * call expression in the body and no fallback, retry or rejection-sampling loop
 * that could draw twice for one identifier.
 */
export function createSessionId(
  randomSource: (size: number) => Buffer = randomBytes,
): string {
  return randomSource(SESSION_ID_BYTES).toString('base64url');
}

/**
 * The periodic sweep's interval: `min(ttl / 4, 30_000)` (architecture §4.3).
 *
 * Exported so the formula is assertable directly rather than inferred from
 * timer behaviour. Floored at 1 ms so a pathological TTL cannot ask for a
 * zero-delay interval, which Node would normalise to 1 anyway — stated so the
 * normalisation is ours rather than the runtime's.
 */
export function sessionSweepIntervalMs(idleTtlMs: number): number {
  return Math.max(1, Math.min(Math.floor(idleTtlMs / SESSION_SWEEP_DIVISOR), SESSION_SWEEP_CEILING_MS));
}

/** The bookkeeping `sessionIsIdle` reads. A subset of `SessionEntry`. */
export interface SessionActivity {
  readonly inFlightRequests: number;
  readonly openStreams: number;
  readonly lastActivityMs: number;
}

/**
 * The idle predicate (architecture §4.3), pure and exported.
 *
 * **Idle means: no request in flight, no open stream, AND no request completed
 * within the TTL.** The first two clauses are not belt-and-braces. A live,
 * correctly-behaving MCP client that finished `initialize`, holds an SSE stream
 * open and simply has nothing to ask for five minutes is idle under a
 * last-activity-only predicate — and the SDK's own keep-alive writes are
 * internal to the transport and invisible to this registry, so they cannot
 * touch `lastActivityMs` without a hook this design does not add. The
 * operator's own session, left open over lunch, would be terminated with a
 * terminal error frame for no reason its client could diagnose.
 *
 * `lastActivityMs` is touched on request ARRIVAL AND COMPLETION. The completion
 * half is the one that is easy to omit and expensive to omit: a tool call that
 * legitimately runs longer than the TTL — three attempts at 25 s plus two
 * honoured `Retry-After` waits is ~115 s at the defaults — would otherwise have
 * its session evicted mid-call the moment its in-flight count returned to zero.
 */
export function sessionIsIdle(
  session: SessionActivity,
  nowMs: number,
  idleTtlMs: number,
): boolean {
  if (session.inFlightRequests > 0) return false;
  if (session.openStreams > 0) return false;
  return nowMs - session.lastActivityMs >= idleTtlMs;
}

/**
 * Read a single header value.
 *
 * Node joins duplicate headers into an array for a few names; a session
 * identifier presented twice is not a value to reconcile, so an array is
 * rejected outright rather than having one member picked.
 */
function headerValue(raw: string | string[] | undefined): string | null {
  return typeof raw === 'string' && raw !== '' ? raw : null;
}

/**
 * The caller's own JSON-RPC id, for the one response that echoes one.
 *
 * The CLIENT's identifier, never a session identifier — NFR-24 forbids echoing
 * the latter anywhere, and nothing in this module ever does.
 */
function jsonRpcIdOf(body: unknown): RequestId | null {
  if (typeof body !== 'object' || body === null) return null;
  const id = (body as { id?: unknown }).id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}

/**
 * The request ids one inbound body leaves outstanding on its session.
 *
 * A message with no `method` is a response or an error and answers a request
 * rather than opening one, so it never joins the set the terminal frame
 * iterates. Batches are handled because the transport accepts them.
 */
function jsonRpcRequestIdsOf(body: unknown): RequestId[] {
  const messages = Array.isArray(body) ? (body as unknown[]) : [body];
  const ids: RequestId[] = [];
  for (const message of messages) {
    if (typeof message !== 'object' || message === null) continue;
    if (typeof (message as { method?: unknown }).method !== 'string') continue;
    const id = (message as { id?: unknown }).id;
    if (typeof id === 'string' || typeof id === 'number') ids.push(id);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// The single exported factory (architecture §1.2)
// ---------------------------------------------------------------------------

/**
 * The six inbound bounds, resolved from the §5.15.1 variable family.
 *
 * FR-76 asserts PROVENANCE against this object rather than against Node's
 * defaults, and the reason is specific: `keepAliveTimeout` is configured at
 * 5000 and Node's default is 5000; the header cap is configured at 16384 and
 * `--max-http-header-size` defaults to 16384. A test written as "the value is
 * not the default" fails against a correct implementation at the documented
 * defaults, and one written as "the value equals 5000" proves nothing about
 * whether this configuration wired it. Both halves of the assertion therefore
 * read THIS object and then observe behaviour at a distinct probe value.
 */
export interface ResolvedInboundBounds {
  /** `UNIFI_HTTP_HEADERS_TIMEOUT_MS` → `server.headersTimeout`. */
  readonly headersTimeout: number;
  /** `UNIFI_HTTP_REQUEST_TIMEOUT_MS` → `server.requestTimeout`. */
  readonly requestTimeout: number;
  /** `UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS` → `server.keepAliveTimeout`. */
  readonly keepAliveTimeout: number;
  /** `UNIFI_HTTP_MAX_HEADER_BYTES` → `createServer({ maxHeaderSize })`. */
  readonly maxHeaderSize: number;
  /**
   * `UNIFI_HTTP_MAX_CONNECTIONS` — the NON-PROBE budget. Total accepted is this
   * plus `PROBE_CONNECTION_HEADROOM`. Never assigned to `server.maxConnections`;
   * see `admitConnection`.
   */
  readonly maxConnections: number;
  /** `UNIFI_HTTP_MAX_BODY_BYTES`. Node exposes no property for this at all. */
  readonly maxBodyBytes: number;
}

/**
 * The single exported factory FR-65, FR-70 and FR-76 all assert against.
 *
 * It exists as ONE object rather than two because four of the six bounds are
 * properties of the `node:http` server and two are properties of the SDK
 * transport. Exporting only the transport half — the previous design — leaves
 * an implementer wiring the transport options carefully because a factory
 * exists for them, and setting the server timeouts inline at `createServer()`
 * where nothing asserts them.
 */
export interface ServingOptions {
  readonly bounds: ResolvedInboundBounds;
  transportOptionsFor(sessionId: string): StreamableHTTPServerTransportOptions;
}

/**
 * Resolve every inbound bound and the SDK transport options, in one place.
 *
 * `startHttp` applies exactly this object and reads no configuration value for
 * a bound anywhere else.
 */
export function createServingOptions(config: ServerConfig): ServingOptions {
  const serving = config.serving;

  const bounds: ResolvedInboundBounds = Object.freeze({
    headersTimeout: serving.headersTimeoutMs,
    requestTimeout: serving.requestTimeoutMs,
    keepAliveTimeout: serving.keepAliveTimeoutMs,
    maxHeaderSize: serving.maxHeaderBytes,
    maxConnections: serving.maxConnections,
    maxBodyBytes: serving.maxBodyBytes,
  });

  return {
    bounds,
    transportOptionsFor(sessionId: string): StreamableHTTPServerTransportOptions {
      return {
        // Explicit, and it has NO default: omitting `sessionIdGenerator`
        // silently yields stateless single-use mode rather than generated ids.
        sessionIdGenerator: () => sessionId,

        // Set explicitly from `UNIFI_HTTP_SSE_KEEPALIVE_MS` rather than
        // inherited from the SDK's own 15 000 ms, so the operator's value is
        // the one in force and FR-76's provenance assertion has something to
        // read.
        keepAliveMs: serving.sseKeepaliveMs,

        // ALL THREE ARE DELIBERATELY `undefined`, and this is a security
        // decision rather than an omission (FR-65, FR-66):
        //
        //   - `allowedHosts` exact-matches the FULL `Host` header, port and
        //     all, so an operator who lists `example.com` gets a 403 on every
        //     real request because every real request arrives as
        //     `example.com:8787`. Host validation that rejects the correct
        //     configuration is not a control, it is an outage.
        //   - `allowedOrigins` implements an allow-list, and this server
        //     rejects EVERY `Origin` at every value; an allow-list would be
        //     inert anyway, because no CORS header is ever emitted.
        //   - `enableDnsRebindingProtection` gates the other two, and all
        //     three are marked `@deprecated` in the SDK.
        //
        // Validation is performed by repository code in the pipeline below.
        allowedHosts: undefined,
        allowedOrigins: undefined,
        enableDnsRebindingProtection: undefined,

        // `enableJsonResponse` is deliberately NOT set, so it sits at its
        // default of `false` — SSE mode. Turning it on would also deadlock any
        // drain written against `handleRequest`'s promise, which in JSON mode
        // is settled only by a path the JSON cleanup never takes.
      };
    },
  };
}

// ---------------------------------------------------------------------------
// The handle and its injection points
// ---------------------------------------------------------------------------

/**
 * Transport-side injection for the HTTP surface.
 *
 * `createTransport` and `createHttpServer` are NOT declared on `ServingDeps` in
 * `runtime.ts`: their types come from the SDK's Streamable HTTP transport, and
 * naming them there would pull that import into `runtime.ts`'s list, which
 * architecture §9.4 fixes as `{ auth, config, credentials, http/client,
 * registry, tools, log }`. They are declared here instead.
 *
 * Node 20 has no `mock.module` — it landed in 22.3 and CI pins 20 on all three
 * platforms — so every seam below is a default parameter and every one of them
 * is inert in production.
 */
export interface HttpServingDeps extends ServingDeps {
  /** FR-64's "no transport is ever constructed" counter reads through this. */
  createTransport?: (
    options: StreamableHTTPServerTransportOptions,
  ) => StreamableHTTPServerTransport;
  createHttpServer?: (options: ServerOptions, handler: RequestListener) => Server;
  /** The rejection throttle. Wrapped in tests to count uniform-401 emissions. */
  createThrottle?: (options: RejectionThrottleOptions) => RejectionThrottle;
  /** Step 2's normaliser factory. A fault injected here must still yield a 401. */
  createRouteNormalizer?: (mcpPath: string) => (rawTarget: string) => Route;
  /** Step 4's comparator. A fault injected here must still yield a 401. */
  bearerMatches?: (presented: string | undefined, slots: NonEmptySlots) => boolean;
  /** Step 6's predicate. A fault injected here must still yield a 401. */
  hostAllowed?: (hostHeader: string | undefined, allow: readonly string[]) => boolean;
  /** Substitutes for the stderr stream, never for the composer. */
  warn?: (line: string) => void;
  /**
   * The session identifier draw. Defaults to the exported `createSessionId`,
   * whose own `randomSource` default parameter is FR-77's byte-source spy —
   * this seam substitutes the whole generator, that one substitutes its bytes.
   */
  createSessionId?: () => string;
  /**
   * The per-session `McpServer` factory.
   *
   * Exists so a test can wrap the product and count `close()` per session, and
   * so the FR-72 abort criterion can register a deliberately long-running tool
   * handler and observe its `extra.signal` fire — the production factory funnels
   * every handler through one action runner and hands it no `extra`.
   */
  createMcpServer?: (runtime: Runtime, surface: Surface) => McpServer;
  /**
   * The TTL sweep's periodic trigger. `unref()` is applied at the call site,
   * NOT here, so substituting this seam cannot accidentally hand the sweep a
   * claim on process lifetime that production does not give it.
   */
  createSweepInterval?: (onTick: () => void, intervalMs: number) => NodeJS.Timeout;
}

/**
 * The HTTP transport's handle: `Serving` plus the accessors FR-76, FR-77 and
 * NFR-29 assert against.
 *
 * `connectionCounts()` in particular is the accessor the connection-cap
 * provenance assertion targets, and it exists precisely BECAUSE
 * `server.maxConnections` is not used.
 */
export interface HttpServing extends Serving {
  sessionCount(): number;
  connectionCounts(): { total: number; headroom: number };
  sweepIdleSessions(nowMs: number): Promise<number>;
  bounds(): ResolvedInboundBounds;
  retainedRequestBuffers(): number;
}

// ---------------------------------------------------------------------------
// The response vocabulary (operator contract §5.0.2, §5.1, §5.2-§5.15)
//
// Eight tokens, one closed list, defined by the contract and nowhere else. Every
// body below is a precomputed Buffer, so no response in the rejection classes
// allocates or formats anything at emission time and the byte counts cannot
// drift from the contract's table.
// ---------------------------------------------------------------------------

interface FixedResponse {
  readonly status: number;
  /**
   * The reason phrase, written EXPLICITLY rather than taken from Node's
   * `STATUS_CODES`. Byte identity is asserted over the status line, and Node's
   * phrase for 413 is `Payload Too Large` where the contract fixes
   * `Content Too Large`. Pinning all of them here makes the wire a property of
   * this file rather than of the Node version CI happens to run.
   */
  readonly reason: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  /** True when the socket must not be reused after this response. */
  readonly closes: boolean;
}

function fixedResponse(
  status: number,
  reason: string,
  token: string,
  extra: Readonly<Record<string, string>> = {},
  closes = false,
): FixedResponse {
  const body = Buffer.from(`{"error":"${token}"}`, 'utf8');
  return Object.freeze({
    status,
    reason,
    // Insertion order IS the wire order. `Content-Type`, `Content-Length`, then
    // any per-class header, then the two universal ones, then `Connection`.
    headers: Object.freeze({
      'Content-Type': 'application/json',
      'Content-Length': String(body.byteLength),
      ...extra,
      'Cache-Control': 'no-store',
      // On EVERY response including both probes. One header, no configuration,
      // no disclosure, and it removes the only way a browser reached by DNS
      // rebinding could reinterpret a JSON error body as an active document.
      'X-Content-Type-Options': 'nosniff',
      ...(closes ? { Connection: 'close' } : {}),
    }),
    body,
    closes,
  });
}

/**
 * The uniform unauthenticated rejection (contract §5.1) — the whole point of
 * this module, and the only response an unauthenticated caller ever receives.
 *
 * `WWW-Authenticate` carries the bare scheme. NO `realm=`, because a realm is
 * operator-chosen text and would leak configuration; NO `error="invalid_token"`
 * (RFC 6750), because that is exactly the oracle FR-81 forbids — it would
 * distinguish "wrong token" from "disallowed Host".
 *
 * `Connection: close` is on this response WITHOUT EXCEPTION, and it is a
 * uniformity fix rather than a performance choice. FR-76 requires the 401 to
 * land after at most the header bytes are read, so for an over-cap body the
 * body is never read; a server that answers 401 without draining an inbound
 * body must either read-and-discard it — contradicting the byte counter — or
 * reset the socket. Resetting for a large body while keeping alive for a small
 * one makes TCP behaviour distinguish the two classes: the same leak FR-81
 * closes at the HTTP layer, reopened one layer down.
 *
 * `Date` is suppressed process-wide by `res.sendDate = false` at the top of the
 * pipeline. Without that, two responses captured at different wall-clock
 * seconds are not byte-identical and the mandated test fails spuriously against
 * a correct implementation.
 */
const UNIFORM_401 = fixedResponse(
  401,
  'Unauthorized',
  'unauthorized',
  { 'WWW-Authenticate': 'Bearer' },
  true,
);

/**
 * The throttle's answer (contract §5.10.1). Deliberately distinguishable from
 * the 401 — that is what makes it a throttle — and it discloses only how many
 * times THAT SAME CALLER has already been rejected.
 *
 * NO `Retry-After`. Its only well-behaved beneficiary is a client that trips
 * the throttle, and a client holding the correct secret never does; its actual
 * beneficiary is an attacker running a guessing campaign, to whom it is a free,
 * authoritative scheduling hint. NO `WWW-Authenticate` either: a 429 is not an
 * invitation to retry with a credential.
 */
const THROTTLED_429 = fixedResponse(429, 'Too Many Requests', 'rate_limit', {}, true);

/**
 * Contract §5.4 and §5.5. ONE body for both, so an authenticated caller learns
 * "one of the browser-facing controls rejected you" and not which. That is more
 * than FR-65 strictly requires and it costs nothing, because a trusted caller
 * who needs to know reads the log with the operator.
 */
const FORBIDDEN_403 = fixedResponse(403, 'Forbidden', 'forbidden');

/** Contract §5.6. The requested path is never echoed. */
const NOT_FOUND_404 = fixedResponse(404, 'Not Found', 'not_found');

/** Contract §5.8. The cap value is in neither the body nor the headers. */
const PAYLOAD_TOO_LARGE_413 = fixedResponse(
  413,
  'Content Too Large',
  'payload_too_large',
  {},
  true,
);

/** Contract §5.15's post-authentication arm. No message, no class, no stack. */
const SERVER_ERROR_500 = fixedResponse(
  500,
  'Internal Server Error',
  'server_error',
  {},
  true,
);

/** Contract §5.15: a request reaching the MCP endpoint before the registry resolved. */
const UNAVAILABLE_503 = fixedResponse(503, 'Service Unavailable', 'unavailable', {}, true);

/**
 * Contract §5.7. `Allow` is a fixed constant and never configuration, and
 * §5.0.1 checks the route (step 8) before the method (step 9) so an UNKNOWN
 * path is a 404 and never reaches here — `Allow` therefore cannot be used to
 * discover whether a candidate path exists.
 */
function methodNotAllowed405(allow: string): FixedResponse {
  return fixedResponse(405, 'Method Not Allowed', 'method_not_allowed', { Allow: allow });
}

const MCP_METHOD_NOT_ALLOWED = methodNotAllowed405(MCP_ALLOW);
const PROBE_METHOD_NOT_ALLOWED = methodNotAllowed405(PROBE_ALLOW);

/**
 * Write a precomputed response.
 *
 * `res.writeHead(status, reason, headers)` preserves the object's insertion
 * order on the wire, which is what makes byte identity a property of the
 * literal above rather than of Node's header bookkeeping.
 */
function sendFixed(res: ServerResponse, response: FixedResponse, method: string): void {
  if (res.headersSent) return;
  res.writeHead(response.status, response.reason, { ...response.headers });
  // RFC 9110: a HEAD response carries the identical status and headers with no
  // body. Content-Length still describes what a GET would have returned.
  res.end(method === 'HEAD' ? undefined : response.body);
}

// ---------------------------------------------------------------------------
// Connection admission — architecture §5.3 step 0a, §5.5.1
// ---------------------------------------------------------------------------

/** How a live socket was admitted. Read at step 2b. */
type Admission = 'ordinary' | 'headroom';

interface ConnectionLedger {
  /** Called from the server's `connection` event. `false` means not accepted. */
  admit(socket: Socket): boolean;
  admissionOf(socket: Socket): Admission | undefined;
  counts(): { total: number; headroom: number };
}

/**
 * Route-aware connection admission, in our own `connection` handler.
 *
 * **`server.maxConnections` is not used, and cannot be.** Node's accept-layer
 * rejection has no route information, so:
 *   - setting it to `maxConnections` makes the probe headroom impossible — the
 *     kernel-level refusal fires before any request line is read, so a probe
 *     and a flood are indistinguishable at that layer;
 *   - setting it to `maxConnections + 8` makes FR-76's `===` provenance
 *     comparison against the resolved variable fail;
 *   - leaving it unset leaves nothing to compare.
 * All three branches fail something. Admission is therefore counted here, and
 * `connectionCounts()` on the handle is the accessor FR-76 targets.
 *
 * `UNIFI_HTTP_MAX_CONNECTIONS` is the NON-PROBE budget; total accepted is
 * `UNIFI_HTTP_MAX_CONNECTIONS + PROBE_CONNECTION_HEADROOM`.
 *
 * Within the headroom, at most ONE connection per source key. Without that cap
 * the headroom is claimable by anyone, because "probe" is a property of the
 * request STRING and nothing about the caller is consulted — by design, since
 * the exemption exists precisely because a probe cannot present a credential.
 * An attacker would otherwise send `GET /healthz` on each of eight keep-alive
 * connections, re-issuing every four seconds against a 5 000 ms
 * `keepAliveTimeout`, and starve the kubelet exactly as before at a cost of
 * eight sockets and two requests per second.
 */
function createConnectionLedger(maxConnections: number): ConnectionLedger {
  const admissions = new WeakMap<Socket, Admission>();
  /** Source key → the one headroom socket that key currently holds. */
  const headroomBySource = new Map<string, Socket>();
  let ordinary = 0;
  let headroom = 0;

  function release(socket: Socket, admission: Admission, key: string): void {
    if (admissions.get(socket) !== admission) return;
    admissions.delete(socket);
    if (admission === 'ordinary') {
      ordinary -= 1;
      return;
    }
    headroom -= 1;
    if (headroomBySource.get(key) === socket) headroomBySource.delete(key);
  }

  return {
    admit(socket: Socket): boolean {
      const key = sourceKey(socket.remoteAddress);

      let admission: Admission;
      if (ordinary < maxConnections) {
        admission = 'ordinary';
        ordinary += 1;
      } else if (headroom < PROBE_CONNECTION_HEADROOM && !headroomBySource.has(key)) {
        admission = 'headroom';
        headroom += 1;
        headroomBySource.set(key, socket);
      } else {
        // Not accepted, and NO LOG LINE — a connection that was never accepted
        // produced no request, and one line per refused connection is the
        // log-flooding vector the cap itself exists to bound.
        socket.destroy();
        return false;
      }

      admissions.set(socket, admission);
      socket.once('close', () => release(socket, admission, key));
      return true;
    },

    admissionOf(socket: Socket): Admission | undefined {
      return admissions.get(socket);
    },

    counts(): { total: number; headroom: number } {
      return { total: ordinary + headroom, headroom };
    },
  };
}

// ---------------------------------------------------------------------------
// Per-request state
// ---------------------------------------------------------------------------

/** Everything one request's decisions are recorded against, for the log line. */
interface RequestContext {
  readonly req: IncomingMessage;
  readonly res: ServerResponse;
  readonly method: string;
  /** Written exactly once, by step 2, inside the fail-closed boundary. */
  route: Route;
  readonly sourceKey: string;
  readonly client: string;
  readonly startedAtMs: number;
  /** Flips only once step 4 has run to completion. Read by the fail-closed boundary. */
  authenticated: boolean;
  /** True once step 4 has produced a verdict, whatever that verdict was. */
  authComplete: boolean;
}

/**
 * Where an entry is in its life (architecture §4.3.1).
 *
 * `pending` exists because BOTH of the other available answers are wrong.
 * Inserting at `onsessioninitialized` makes the cap read a count that lags
 * every concurrent in-flight `initialize`, and — worse — a session whose
 * `onsessioninitialized` has not yet fired is not in the registry when the
 * drain iterates it, so its `McpServer` is never closed, `Protocol._onclose()`
 * never runs and its handlers are never aborted. Inserting a `live` entry
 * before dispatch makes 32 rejected `initialize` attempts fill the cap for a
 * full TTL, because sweep-before-cap cannot help entries younger than the TTL.
 * Reserve, insert `pending`, promote, and always release.
 */
type SessionState = 'pending' | 'live' | 'terminating';

/**
 * Why a session is being closed.
 *
 * `'disconnected'` is deliberately NOT a member: it is a `server.onclose`
 * CAUSE, and it enters through `onSessionGone` — the bookkeeping path — never
 * through the initiating one. Modelling it as a fourth reason is what made an
 * earlier revision's single function circular.
 */
type TerminationReason = 'delete' | 'evicted' | 'drain';

interface SessionEntry {
  /** The registry key: a reservation token while pending, the id once live. */
  key: string;
  readonly id: string;
  readonly server: McpServer;
  readonly transport: StreamableHTTPServerTransport;
  state: SessionState;
  lastActivityMs: number;
  /** `> 0` ⇒ never idle. Touched on arrival and completion. */
  inFlightRequests: number;
  /** `> 0` ⇒ never idle. A response that has not closed is an open stream. */
  openStreams: number;
  /** JSON-RPC request ids this session has not answered, for the terminal frame. */
  readonly outstanding: Set<RequestId>;
}

// ---------------------------------------------------------------------------
// startHttp
// ---------------------------------------------------------------------------

/**
 * Bind the listener and return; the registry resolves behind it.
 *
 * The bind precedes the registry because FR-62 fixes that order and operator
 * contract §5.15 answers a request arriving in the window with `503 unavailable`
 * rather than a connection refusal. Building the registry first would give the
 * `starting` readiness phase zero duration and hand an orchestrator
 * `ECONNREFUSED` for the whole startup window.
 */
export async function startHttp(
  core: RuntimeCore,
  observer?: ServingObserver,
  deps: HttpServingDeps = {},
): Promise<HttpServing> {
  const config = core.config;
  const serving = config.serving;
  const options = createServingOptions(config);
  const bounds = options.bounds;

  const logger: DiagnosticLogger = createDiagnosticLogger({
    ...(deps.warn ? { write: deps.warn } : {}),
    ...(observer?.onRequestLog ? { onRequestLog: (line) => observer.onRequestLog?.(line) } : {}),
  });

  const now = deps.now ?? Date.now;
  const normalizeRoute = (deps.createRouteNormalizer ?? createRouteNormalizer)(serving.path);
  const matchBearer = deps.bearerMatches ?? bearerMatches;
  const hostIsAllowed = deps.hostAllowed ?? hostAllowed;
  const drawSessionId = deps.createSessionId ?? createSessionId;
  const buildMcpServer = deps.createMcpServer ?? createMcpServer;
  const startSweepInterval =
    deps.createSweepInterval ??
    ((onTick: () => void, intervalMs: number) => setInterval(onTick, intervalMs));
  const createTransport =
    deps.createTransport ??
    ((transportOptions: StreamableHTTPServerTransportOptions) =>
      new StreamableHTTPServerTransport(transportOptions));

  const throttle = (deps.createThrottle ?? createRejectionThrottle)({
    maxPerMinute: serving.authFailPerMin,
    now,
  });

  const readiness: ReadinessState = createReadinessState();
  const ledger = createConnectionLedger(bounds.maxConnections);
  /**
   * The registry (architecture §4.1). Closure-scoped to one `startHttp()` call
   * and never module-global, so two listeners in one test process — which every
   * suite in this round creates — do not share sessions, a cap or a sweep.
   */
  const sessions = new Map<string, SessionEntry>();
  /**
   * THE NUMBER THE CAP IS ENFORCED AGAINST, and it is not `sessions.size`.
   *
   * Both alternatives fail, in opposite directions. Checking `sessions.size`
   * puts an `await` — the mandated pre-check sweep — in the middle of a
   * check-then-act, so two concurrent `initialize`s at cap-1 both see room and
   * take the registry over the cap. Decrementing it by firing teardown as
   * `void terminateSession(...)` makes the count drop while N `McpServer`s, N
   * transports and N sockets are still alive, so FR-77's assertion — made
   * against this counter precisely so it does not flake — passes while the real
   * resource count is over the cap. Incremented synchronously with no `await`
   * between the test and the increment, and decremented when teardown COMPLETES.
   */
  let reserved = 0;
  /** Distinguishes reservation tokens. Never derived from an identifier. */
  let reservationSeq = 0;
  /** The effective write set, rendered into every log line's `writes=` field. */
  const writes = [...config.writesEnabled];

  let retainedBuffers = 0;
  /** The last `/readyz` phase a line was emitted for, so a transition always logs. */
  let lastLoggedReadyzPhase: string | null = null;

  // -------------------------------------------------------------------------
  // The pipeline
  // -------------------------------------------------------------------------

  /**
   * THE SINGLE POINT AT WHICH THE UNIFORM 401 IS EMITTED, and therefore the
   * single point at which the per-source counter increments (contract §5.10.2).
   *
   * Incrementing inside the authentication routine instead — the natural
   * implementation — turns the throttle into a path-enumeration oracle and
   * defeats FR-81 completely: send N+1 garbage-token requests to a candidate
   * path; if only authentication failures count, a real path reached
   * authentication and answers 429 while a wrong path answers 401. One bit per
   * minute per source, parallelisable across a /64, recovering exactly the fact
   * the uniform rejection exists to hide.
   *
   * The throttle gates the RESPONSE, not the work: `record` then `isThrottled`,
   * and the request has already failed authentication by the time it arrives
   * here. A caller presenting a valid secret from a throttled source key never
   * reaches this function and is served normally.
   */
  function rejectUnauthenticated(ctx: RequestContext, reason: RejectReason): void {
    throttle.record(ctx.sourceKey);
    if (throttle.isThrottled(ctx.sourceKey)) {
      complete(ctx, THROTTLED_429, 'rate_limit', 'rejected');
      return;
    }
    complete(ctx, UNIFORM_401, reason, 'rejected');
  }

  /** Emit a fixed response and the NFR-24 line for it, exactly once. */
  function complete(
    ctx: RequestContext,
    response: FixedResponse,
    reason: RejectReason,
    auth: 'ok' | 'rejected',
  ): void {
    sendFixed(ctx.res, response, ctx.method);
    logLine(ctx, response.status, reason, auth);
  }

  function logLine(
    ctx: RequestContext,
    status: number,
    reason: RejectReason,
    auth: 'ok' | 'rejected',
  ): void {
    const probeStateChanged =
      ctx.route === 'readyz' && lastLoggedReadyzPhase !== readiness.phase;
    if (ctx.route === 'readyz') lastLoggedReadyzPhase = readiness.phase;

    logger.logRequest(
      {
        method: methodLabel(ctx.method),
        route: ctx.route as RouteLabel,
        status,
        durationMs: Math.max(0, now() - ctx.startedAtMs),
        auth,
        rejectReason: reason,
        writes,
        client: ctx.client,
      },
      { probeStateChanged },
    );
  }

  const handler: RequestListener = (req, res) => {
    // Suppressed BEFORE anything can write a header. Node adds `Date` by
    // default and it changes every second, so without this two responses
    // captured at different wall-clock seconds are not byte-identical.
    res.sendDate = false;

    const method = typeof req.method === 'string' ? req.method : '';
    const socket = req.socket;
    const key = sourceKey(socket.remoteAddress);

    // Step 2 — normalise the target EXACTLY ONCE and discard the raw target.
    // Every later decision reads this single value: the probe exemption, MCP
    // routing, the 404 branch and the `path=` log label. The dangerous
    // implementation is not one that normalises wrongly; it is one that
    // normalises correctly for ROUTING and tests the exemption against the RAW
    // target, under which `GET /healthz%2f..%2fmcp` takes the exempt branch and
    // routes to the MCP endpoint — the whole tool surface served
    // unauthenticated and un-Host-validated.
    //
    // The normaliser is total and never throws; the call is inside the
    // fail-closed boundary anyway, because an injected fault here must still
    // produce the uniform 401 rather than a 500 that names the class.
    const ctx: RequestContext = {
      req,
      res,
      method,
      route: 'other',
      sourceKey: key,
      client: normalizeClientAddress(socket.remoteAddress),
      startedAtMs: now(),
      authenticated: false,
      authComplete: false,
    };

    void (async (): Promise<void> => {
      try {
        ctx.route = normalizeRoute(typeof req.url === 'string' ? req.url : '');
        await runPipeline(ctx);
      } catch {
        // Step X — the fail-closed boundary (contract §5.15).
        //
        // Raised BEFORE authentication completes it produces the uniform 401,
        // byte for byte, and increments the counter. Raised after, `500` with
        // no message, no exception class, no stack, no source path and no
        // correlation id. Fail-OPEN here would be a class-detection oracle by
        // another route: a 500 to an unauthenticated caller is instantly
        // distinguishable from the uniform 401.
        //
        // The exception itself is deliberately not passed to the emitter with
        // the request context attached — the operator sees it through the
        // transport's own diagnostics, never through a response body.
        if (res.headersSent) {
          try {
            res.end();
          } catch {
            /* the response was already finished; nothing to do */
          }
          return;
        }
        if (ctx.authComplete && ctx.authenticated) {
          complete(ctx, SERVER_ERROR_500, '-', 'ok');
        } else {
          rejectUnauthenticated(ctx, 'auth');
        }
      }
    })();
  };

  /** Steps 2b through 13. Throws only into the boundary above. */
  async function runPipeline(ctx: RequestContext): Promise<void> {
    // Step 2b — the headroom claim check.
    //
    // A connection admitted into the probe headroom whose request does not
    // resolve to a probe route gets the BYTE-IDENTICAL uniform 401 and its
    // socket destroyed. Naming a distinct status here would be a pre-auth
    // oracle whose very existence is conditional on the connection count: an
    // attacker who can produce it learns the cap has been reached and, by
    // binary search, learns `UNIFI_HTTP_MAX_CONNECTIONS`. That is a
    // configuration value leaking through a status differential, the same class
    // the whole of this pipeline's ordering exists to prevent.
    if (
      ledger.admissionOf(ctx.req.socket) === 'headroom' &&
      ctx.route !== 'healthz' &&
      ctx.route !== 'readyz'
    ) {
      // Destroyed on `finish` rather than on the next line: destroying while
      // the response is still being flushed truncates it, and a truncated 401
      // is by definition not byte-identical to the others.
      ctx.res.once('finish', () => ctx.res.socket?.destroy());
      rejectUnauthenticated(ctx, 'auth');
      return;
    }

    // Step 3 — the probe branch. NEVER throttled and NEVER counted.
    //
    // The `Origin` condition is the third clause and it is deliberate: the
    // FR-67 exemption covers authentication and `Host` validation ONLY. An
    // `Origin`-exempt probe would let a browser page on any origin reach both
    // endpoints cross-origin — it still could not READ the response, because no
    // CORS header is ever emitted, but it could distinguish "connection
    // succeeded" from "connection refused" by fetch-failure timing, which is a
    // usable internal-network scanner running from a victim's browser.
    // Kubernetes and Docker probes never send `Origin`, so rejecting it costs
    // nothing operationally.
    if (
      (ctx.route === 'healthz' || ctx.route === 'readyz') &&
      PROBE_METHODS.has(ctx.method) &&
      !hasOrigin(ctx.req.headers)
    ) {
      handleProbe(ctx.route as ProbeKind, ctx.method as ProbeMethod, ctx.res, readiness);
      logLine(ctx, ctx.res.statusCode, '-', 'ok');
      return;
    }

    await runAuthenticatedPipeline(ctx);
  }

  /**
   * Steps 4 through 13, in the normative order.
   *
   * Everything below step 5 is invisible to an unauthenticated caller, and that
   * is the whole of FR-81: any check that PRECEDES authentication and can
   * produce a different response is an oracle. `Host` first is the seductive
   * error — it is cheap, the SDK offers an option for it, and it feels like
   * defence in depth. It is not: the `Host` header is entirely caller-supplied,
   * so validating it first buys ZERO access protection and costs the whole
   * uniform-rejection guarantee, letting a stranger enumerate
   * `UNIFI_HTTP_ALLOWED_HOSTS` by status differential — precisely what FR-65 is
   * careful not to leak in the response BODY and would then leak in the status
   * CODE.
   */
  async function runAuthenticatedPipeline(ctx: RequestContext): Promise<void> {
    // -- Step 4: authenticate -------------------------------------------------
    //
    // ALWAYS performed for a non-probe request. The branch on `kind` is at THIS
    // single authentication site and is not a second enforcement decision: it
    // selects between two admission rules that were resolved at configuration
    // load, the same shape as the write gate's per-surface set. Writing
    // `if (slots.length === 0) return true` inside the comparator instead would
    // be a fail-open branch reachable the instant any configuration path
    // yielded an empty slot list on a non-loopback bind — a mis-parsed secret
    // file, a whitespace-only value, a rotation that removed both slots.
    // `NonEmptySlots` makes that state unrepresentable and this branch makes
    // `none` explicit.
    const mode = core.auth;
    const admitted =
      mode.kind === 'none' ? true : matchBearer(ctx.req.headers.authorization, mode.slots);
    ctx.authComplete = true;
    ctx.authenticated = admitted;

    // -- Step 5: the throttle decision ---------------------------------------
    //
    // Conditional on step 4 having failed. A caller presenting a VALID secret
    // from a throttled source key is served normally, which is what stops a
    // stranger behind the same reverse proxy from locking out the only
    // legitimate client with twenty-one garbage requests.
    if (!admitted) {
      rejectUnauthenticated(ctx, 'auth');
      return;
    }

    // -- Step 6: Host ---------------------------------------------------------
    //
    // Port-agnostic on both sides, `X-Forwarded-*` never consulted — both are
    // structural properties of `hostAllowed`'s signature rather than of this
    // call site.
    //
    // AN EMPTY ALLOW-LIST MEANS HOST VALIDATION IS NOT PERFORMED, and that
    // decision belongs here rather than in the predicate. `hostAllowed` returns
    // `false` for an empty list precisely so that folding "empty ⇒ allow all"
    // into it could never turn an accidentally-empty allow-list on a routable
    // bind into an open door. It cannot do so here either: FR-73(b) REFUSES TO
    // START when the bind is non-loopback and the allow-list is empty, so this
    // branch is reachable only on a loopback bind, where the `Host` header
    // carries no access decision at all. Deleting that refusal would make this
    // line unsafe, which is why the coupling is named.
    const allow = serving.allowedHosts;
    if (allow.length > 0 && !hostIsAllowed(ctx.req.headers.host, allow)) {
      complete(ctx, FORBIDDEN_403, 'host', 'ok');
      return;
    }

    // -- Step 7: Origin -------------------------------------------------------
    //
    // Any `Origin`, at any value, including the empty string and the literal
    // `null`. There is no allow-list and one would be inert, because this
    // server emits no CORS header on any response — a browser whose request was
    // accepted still could not read the reply. The response is BYTE-IDENTICAL
    // to step 6's, which is what makes the relative order of the two
    // unobservable and therefore stops an ordering decision from being a
    // security decision.
    if (hasOrigin(ctx.req.headers)) {
      complete(ctx, FORBIDDEN_403, 'origin', 'ok');
      return;
    }

    // -- Step 8: route --------------------------------------------------------
    //
    // BEFORE the method check, so `Allow` is never returned for a path that
    // does not exist and cannot be used to discover one.
    if (ctx.route === 'other') {
      complete(ctx, NOT_FOUND_404, 'path', 'ok');
      return;
    }

    // -- Step 9: method -------------------------------------------------------
    //
    // A probe route reaching this step did so with a method outside
    // {GET, HEAD} — step 3 consumed every exempt one — so it is a 405 here and
    // the UNIFORM 401 to an unauthenticated caller, who never got this far. A
    // 405 to a stranger on a probe path is itself an oracle: it confirms both
    // that the path exists and that the method was the problem, which is more
    // than "no".
    if (ctx.route === 'healthz' || ctx.route === 'readyz') {
      complete(ctx, PROBE_METHOD_NOT_ALLOWED, 'method', 'ok');
      return;
    }
    if (!MCP_METHODS.has(ctx.method)) {
      // `OPTIONS` lands here, so a browser preflight fails. Stated rather than
      // inferred: an implementer following a CORS reflex must not add an
      // `OPTIONS` handler, and a preflight that succeeded would be useless
      // anyway because no response carries a CORS header.
      complete(ctx, MCP_METHOD_NOT_ALLOWED, 'method', 'ok');
      return;
    }

    // -- Step 10: body cap ----------------------------------------------------
    const read = await readBoundedBody(ctx.req, bounds.maxBodyBytes);
    if (read.overCap) {
      // No explicit `destroy()` here: `Connection: close` already makes Node
      // call `destroySoon()` on the socket once the response is flushed, and a
      // second destroy would only risk truncating the write.
      //
      // KNOWN AND ACCEPTED WIRE CONSEQUENCE, stated because it will otherwise
      // be reported as a bug. The remainder of the caller's body is still in
      // flight by construction — the cap is enforced by refusing to keep
      // reading — and closing a socket that still has unread inbound data makes
      // the kernel emit RST rather than FIN. A peer whose body outran the
      // socket buffers therefore sees a connection reset rather than this 413,
      // however correctly it was emitted. The alternative is to read and
      // discard the rest of the body, which is exactly the unbounded
      // pre-refusal consumption FR-76 and NFR-29 exist to forbid. The operator
      // still sees `status=413 reject_reason=body_size` in the log, which is
      // where the diagnosis lives; a caller whose body fits inside the socket
      // buffers — every ordinary over-cap request — receives the 413 itself.
      complete(ctx, PAYLOAD_TOO_LARGE_413, 'body_size', 'ok');
      return;
    }

    // -- Step 11: session admission ------------------------------------------
    //
    // After authentication, because `Mcp-Session-Id` is bearer-equivalent.
    // US-23 owns the cap, the reservation counter, the TTL sweep and the
    // eviction path; what this step owns is identifier VALIDITY, and the
    // anti-oracle rule that goes with it.
    const presentedId = headerValue(ctx.req.headers['mcp-session-id']);
    let entry: SessionEntry | undefined;
    if (presentedId !== null) {
      entry = sessions.get(presentedId);
      if (entry === undefined) {
        // One fixed response for all three cases — evicted, expired, and a
        // well-formed identifier that never existed — so a caller who has
        // harvested an identifier cannot determine whether it is still live.
        // The identifier is never echoed. `reject_reason=auth`, because
        // NFR-24's vocabulary is closed and `session_limit` means the cap was
        // reached rather than this identifier is unknown.
        sendJsonRpc(ctx, 404, 'Not Found', JSON_RPC_SESSION_UNKNOWN, SESSION_UNKNOWN_MESSAGE, 'auth');
        return;
      }
    }

    // -- Step 12: the drain gate ---------------------------------------------
    //
    // Refuses EVERY MCP method once the drain has begun, not only `initialize`.
    // Otherwise an ordinary `tools/call` arriving on an already-open keep-alive
    // connection passes the whole pipeline, reaches a handler whose outbound
    // client rejects on sight, and returns 200 with a tool error saying "rate
    // limited" for a request that was never rate limited — while its promise
    // joins the in-flight set AFTER the drain snapshotted it.
    //
    // `reject_reason=draining` rather than `session_limit`: the token was added
    // to NFR-24's vocabulary by AR-7 specifically so an operator can tell a
    // rolling deploy from a capacity incident, which have opposite remedies.
    // US-24 owns the pre-drain hold that makes this reachable for a bounded
    // window rather than only between `close()` and process exit.
    if (readiness.phase === 'draining') {
      sendJsonRpc(ctx, 503, 'Service Unavailable', JSON_RPC_SERVER_ERROR, DRAIN_MESSAGE, 'draining');
      return;
    }

    // -- Step 12r: the readiness gate ----------------------------------------
    //
    // Reachable only because the listener binds before the registry resolves.
    // `503 unavailable`, never a 500: the server is not able to serve this YET,
    // which is the same fact as the session cap and the drain and deserves the
    // same shape.
    if (readiness.phase === 'starting') {
      complete(ctx, UNAVAILABLE_503, 'session_limit', 'ok');
      return;
    }

    // -- Step 13: MCP dispatch ------------------------------------------------
    observer?.onMcpRequest?.();

    if (entry !== undefined) {
      // NFR-24's line is written AT HEADER FLUSH, not at completion, and
      // `dur_ms` is therefore time-to-first-byte. That is the contract's cadence
      // (§8.16) and on this endpoint it is the difference between an operator
      // seeing a request line immediately and seeing it when the SSE stream
      // finally closes — which for a long-lived MCP session can be hours. The
      // wrapper is on THIS response object only and is discarded with it.
      logAtHeaderFlush(ctx);
      await dispatch(entry, ctx, read.json);
      return;
    }

    if (ctx.method !== 'POST' || !isInitializeRequest(read.json)) {
      // The SDK's own answer for a non-initialisation request carrying no
      // session id, reproduced here because no transport exists to produce
      // it: this request never reached one.
      sendJsonRpc(ctx, 400, 'Bad Request', JSON_RPC_SERVER_ERROR, SESSION_REQUIRED_MESSAGE, 'auth');
      return;
    }

    await admitSession(ctx, read.json);
  }

  /**
   * The `initialize` admission decision: sweep, cap, reserve, dispatch, release.
   *
   * The ORDER of the first two is normative and was ratified rather than
   * assumed (architecture §4.3). Without the pre-check sweep, `maxSessions`
   * abandoned sessions block every new `initialize` for up to a full TTL and
   * the only signal is `reject_reason=session_limit`, which cannot distinguish
   * N live clients from N zombies — and a refusal can be wrong by up to a whole
   * sweep interval's worth of already-dead sessions. The sweep is cheap: at
   * most `maxSessions` entries against an injected clock.
   */
  async function admitSession(ctx: RequestContext, body: unknown): Promise<void> {
    // 1. Sweep FIRST, and it is allowed to await precisely because step 2's
    //    counter — not the map — is what the cap is enforced against.
    await sweepIdleSessions(now());

    // 2. Check and increment with NO `await` between them. Two concurrent
    //    `initialize`s racing at cap-1 cannot both see room, because nothing
    //    can interleave between these two statements.
    if (reserved >= serving.maxSessions) {
      // The refusal echoes the caller's own JSON-RPC id (contract §5.12); it is
      // the client's, not ours, and it is the one response family in this module
      // whose Content-Length therefore varies. AT THE CAP, EVICTION IS NEVER
      // USED TO MAKE ROOM — no live session is terminated to admit this one.
      sendJsonRpc(
        ctx,
        503,
        'Service Unavailable',
        JSON_RPC_SERVER_ERROR,
        SESSION_LIMIT_MESSAGE,
        'session_limit',
        jsonRpcIdOf(body),
      );
      return;
    }
    reserved += 1;

    let admitted: SessionEntry | null = null;
    try {
      admitted = await openSession();
      logAtHeaderFlush(ctx);
      await dispatch(admitted, ctx, body);
    } finally {
      // THE HALF THAT CLOSES A TRIVIAL DENIAL OF SERVICE. An `initialize` the
      // SDK rejects — a missing `Accept` member, a malformed message, a client
      // in a reconnect loop — never reaches `onsessioninitialized`, so the
      // entry is still `pending` here. Releasing only on success would let
      // `maxSessions` rejected attempts fill the cap for a full TTL, and
      // sweep-before-cap does not help because they are younger than it.
      if (admitted === null) {
        // Nothing was inserted; `openSession` threw. Release directly.
        reserved -= 1;
      } else if (admitted.state === 'pending') {
        await terminateSession(admitted.key, 'evicted');
      }
    }
  }

  /**
   * Hand one request to a session's transport, keeping the registry honest.
   *
   * Both idleness inputs are maintained here and nowhere else. `openStreams`
   * counts responses that have not yet closed, which is a superset of the
   * standalone `GET` SSE stream and is what makes "a session with an open
   * stream is never idle" true for a POST whose SSE reply is still flowing too.
   */
  async function dispatch(
    entry: SessionEntry,
    ctx: RequestContext,
    body: unknown,
  ): Promise<void> {
    const outstanding = jsonRpcRequestIdsOf(body);

    // Arrival — the first half of "touched on arrival and completion".
    entry.lastActivityMs = now();
    entry.inFlightRequests += 1;
    entry.openStreams += 1;
    for (const id of outstanding) entry.outstanding.add(id);

    let streamOpen = true;
    const releaseStream = (): void => {
      if (!streamOpen) return;
      streamOpen = false;
      entry.openStreams -= 1;
      entry.lastActivityMs = now();
    };
    ctx.res.once('close', releaseStream);

    try {
      await entry.transport.handleRequest(ctx.req, ctx.res, body);
    } finally {
      entry.inFlightRequests -= 1;
      for (const id of outstanding) entry.outstanding.delete(id);
      // Completion — the second half. Omitting it lets a request that ran
      // longer than the TTL have its session evicted the instant it finishes.
      entry.lastActivityMs = now();
      // `close` is emitted asynchronously after `end()`; releasing eagerly for
      // an already-finished response makes a sweep run in the very next turn
      // see the truth rather than a stream that is open only on paper.
      if (ctx.res.writableEnded || ctx.res.destroyed) releaseStream();
    }
  }

  /**
   * Emit the request line the first time this response commits its headers.
   *
   * `res.end()` without an explicit `writeHead` still routes through
   * `_implicitHeader()`, which calls `writeHead`, so a transport that never
   * calls it directly is covered too.
   */
  function logAtHeaderFlush(ctx: RequestContext): void {
    const original = ctx.res.writeHead.bind(ctx.res);
    let emitted = false;
    const emit = (): void => {
      if (emitted) return;
      emitted = true;
      logLine(ctx, ctx.res.statusCode, '-', 'ok');
    };

    ctx.res.writeHead = ((...args: Parameters<ServerResponse['writeHead']>) => {
      const result = original(...args);
      emit();
      return result;
    }) as ServerResponse['writeHead'];

    // A response that ends without ever committing headers — an aborted socket
    // — still gets exactly one line, so a dispatched request is never silent.
    ctx.res.once('close', emit);
  }

  /**
   * Create one session: one identifier, one `McpServer`, one transport.
   *
   * ONE `McpServer` per session is forced rather than chosen — `Protocol.connect`
   * throws on a second transport with no queue and no replace semantics. What is
   * NOT per session is everything expensive or shared: the registry, the
   * handlers, the credential store and the outbound client all live on the
   * runtime, and the outbound rate-limit buckets model a limit the UniFi console
   * enforces per console, so N sessions with N clients would present N times the
   * permitted rate.
   */
  async function openSession(): Promise<SessionEntry> {
    const id = drawSessionId();
    // Keyed by a reservation token until the SDK confirms initialisation. The
    // token is not a valid identifier and is never derived from one, so a
    // caller presenting a harvested id cannot reach a half-built session.
    const key = `pending#${(reservationSeq += 1)}`;

    // Declared before the transport because the SDK's callbacks close over it
    // and can, in principle, fire during `connect()`.
    let entry: SessionEntry | null = null;

    const transport = createTransport({
      ...options.transportOptionsFor(id),
      // PROMOTION. `sdk-facts` §B.3: this fires INSIDE POST handling, after an
      // await, which is exactly why the reservation exists and why the entry is
      // already in the map by the time it runs.
      onsessioninitialized: (minted: string) => {
        if (entry !== null) promoteSession(entry, minted);
      },
      // `DELETE` ONLY. It does not fire from `close()` and it does not fire for
      // an idle eviction — a design that waits for it to clean up after an
      // eviction leaks every abandoned session, which is the exact failure
      // FR-77 exists to prevent. Our registry deletes its own entry in every
      // path; this callback is the client-asked path and nothing more.
      onsessionclosed: async (closed: string) => {
        await terminateSession(closed, 'delete');
      },
    });

    // The session sees `Runtime` and never the process-scoped lifecycle type,
    // so no per-session cleanup path can reach `beginDrain()` or `close()` and
    // take the whole process down while evicting one idle session. Narrowed by
    // CONSTRUCTION rather than only by the type annotation: handing `core` over
    // with a narrower type leaves both methods reachable at runtime by anything
    // that stops trusting the annotation.
    const session: Runtime = {
      config: core.config,
      credentials: core.credentials,
      client: core.client,
      handlers: core.handlers,
      auth: core.auth,
      activeSurface: core.activeSurface,
      ready: core.ready,
      get readyError(): Error | null {
        return core.readyError;
      },
      get registry() {
        return core.registry;
      },
      advertisedToolsFor: (surface) => core.advertisedToolsFor(surface),
    };
    const server = buildMcpServer(session, 'http');

    // ==================================================================
    // `server.onclose`, and `transport.onclose` IS NEVER ASSIGNED ANYWHERE.
    //
    // `connect()` replaces `transport.onclose` with a wrapper capturing
    // whatever handler was set at that moment; assigning `transport.onclose`
    // AFTER `connect()` overwrites that wrapper and silently disables
    // `Protocol._onclose()` — no in-flight handler aborted through its
    // `AbortSignal`, no request-timeout timer cleared, no pending request
    // rejected, no error, no log line. It is a trap in the SDK's own API with
    // no symptom at the point of the mistake, so a source scan asserts the
    // literal absence rather than relying on a behavioural test alone.
    // ==================================================================
    server.server.onclose = (): void => {
      if (entry !== null) onSessionGone(entry);
    };

    await server.connect(transport);

    entry = {
      key,
      id,
      server,
      transport,
      state: 'pending',
      lastActivityMs: now(),
      inFlightRequests: 0,
      openStreams: 0,
      outstanding: new Set<RequestId>(),
    };
    sessions.set(key, entry);
    return entry;
  }

  /** Re-key a reserved entry under the identifier the SDK just minted. */
  function promoteSession(entry: SessionEntry, minted: string): void {
    if (entry.state !== 'pending') return;
    sessions.delete(entry.key);
    entry.key = minted;
    entry.state = 'live';
    entry.lastActivityMs = now();
    sessions.set(minted, entry);
  }

  /**
   * Read the request body, refusing past the cap.
   *
   * The cap is enforced STREAMING rather than by measuring `Content-Length`,
   * which a caller chooses and a chunked request omits entirely. Consumption
   * stops at the first chunk that takes the total past the bound, so at most the
   * bound plus one read chunk is ever consumed — and a body ten times the bound
   * behaves identically, because size is never the thing being measured.
   *
   * NOTHING CALLS THIS BEFORE STEP 10. That is the observable form of
   * "authentication precedes body read": a caller with no `Authorization`
   * header and a large body receives 401 having had at most their header bytes
   * read, which is what stops an unauthenticated stranger making this process
   * buffer arbitrary data.
   */
  function readBoundedBody(
    req: IncomingMessage,
    limit: number,
  ): Promise<{ overCap: boolean; json: unknown }> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      retainedBuffers += 1;

      const finish = (overCap: boolean, json: unknown): void => {
        if (settled) return;
        settled = true;
        retainedBuffers -= 1;
        chunks.length = 0;
        resolve({ overCap, json });
      };

      req.on('data', (chunk: Buffer) => {
        if (settled) return;
        total += chunk.byteLength;
        if (total > limit) {
          // `pause()`, NOT `req.destroy()`: destroying an `IncomingMessage`
          // destroys the underlying socket, which would kill the connection
          // before the 413 could be written and turn a specified rejection into
          // a bare reset.
          req.pause();
          finish(true, undefined);
          return;
        }
        chunks.push(chunk);
      });
      req.once('end', () => {
        if (total === 0) {
          finish(false, undefined);
          return;
        }
        try {
          finish(false, JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          // Not JSON. Handed on as `undefined` so the transport produces its
          // own parse error rather than this module inventing a second one.
          finish(false, undefined);
        }
      });
      // An aborted or reset socket resolves rather than hanging: a request that
      // went away is not an over-cap request and must not leave a retained
      // buffer behind.
      req.once('aborted', () => finish(false, undefined));
      req.once('error', () => finish(false, undefined));
      req.once('close', () => finish(false, undefined));
    });
  }

  /**
   * A JSON-RPC error object at a non-200 status.
   *
   * The one response family in this module whose `Content-Length` is not fixed.
   * Authenticated-only, so FR-81's byte identity does not reach it.
   */
  function sendJsonRpc(
    ctx: RequestContext,
    status: number,
    reason: string,
    code: number,
    message: string,
    rejectReason: RejectReason,
    id: RequestId | null = null,
  ): void {
    if (!ctx.res.headersSent) {
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id }),
        'utf8',
      );
      ctx.res.writeHead(status, reason, {
        'Content-Type': 'application/json',
        'Content-Length': String(body.byteLength),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        Connection: 'close',
      });
      ctx.res.end(ctx.method === 'HEAD' ? undefined : body);
    }
    logLine(ctx, status, rejectReason, 'ok');
  }

  // -------------------------------------------------------------------------
  // The listener
  // -------------------------------------------------------------------------

  const createHttpServer = deps.createHttpServer ?? createNodeHttpServer;
  const httpServer = createHttpServer(
    {
      // Step 1's bound. Node's parser emits the pre-application `431` for a
      // header block over this, BEFORE any application code runs, and emits no
      // log line — the single, closed exception to FR-81's byte identity.
      maxHeaderSize: bounds.maxHeaderSize,

      // NOT A TUNING KNOB — without it neither timeout below is the timeout in
      // force. Node does not arm a timer per socket for `headersTimeout` and
      // `requestTimeout`; it sweeps incomplete requests on an interval that
      // DEFAULTS TO 30 000 ms. At the §5.15.1 defaults that makes a slowloris
      // connection live for up to 40 seconds against a configured 10-second
      // headers timeout, and an operator who lowers `UNIFI_HTTP_HEADERS_TIMEOUT_MS`
      // to one second still gets thirty — the configured bound would be
      // decoration, and FR-76's "asserted by effect" half would be unsatisfiable
      // by any correct implementation.
      //
      // Derived from the bounds rather than configured, because FR-63 closes
      // the `UNIFI_HTTP_*` family: a quarter of the tightest timeout it
      // enforces, floored so a very small timeout cannot turn the sweep into a
      // busy loop.
      connectionsCheckingInterval: connectionsCheckingIntervalFor(bounds),
    },
    handler,
  );

  // Four of the six bounds are properties of the server object, applied from
  // the one factory rather than inline, so FR-76's provenance assertion reads
  // the same object the behaviour comes from.
  httpServer.headersTimeout = bounds.headersTimeout;
  httpServer.requestTimeout = bounds.requestTimeout;
  httpServer.keepAliveTimeout = bounds.keepAliveTimeout;
  // `httpServer.maxConnections` is deliberately NEVER assigned; see
  // `createConnectionLedger`.

  httpServer.on('connection', (socket: Socket) => {
    ledger.admit(socket);
  });

  /**
   * The sweep's SECOND trigger (architecture §4.3), driving the same function.
   *
   * The pre-`initialize` sweep is not sufficient on its own: a server that is
   * abandoned entirely receives no further `initialize`, and FR-77 requires the
   * map to return to zero after the TTL regardless of whether anyone asks.
   *
   * `unref()`'d — UNLIKE the outbound rate-limit sleep, where un-reffing would
   * be wrong — because a periodic housekeeping sweep has no correctness claim
   * on process lifetime, and a ref'd interval here would keep a finished test
   * process, or a drained server, alive for a quarter of the TTL.
   */
  const sweepTimer = startSweepInterval(() => {
    void sweepIdleSessions(now());
  }, sessionSweepIntervalMs(serving.sessionIdleTtlMs));
  sweepTimer.unref();

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    httpServer.once('error', onError);
    httpServer.listen(serving.port, serving.bindAddress ?? serving.bind, () => {
      httpServer.removeListener('error', onError);
      resolve();
    });
  });

  const bound = addressOf(httpServer);
  if (bound !== null) observer?.onListen?.(bound);

  // FR-62's third step, and FR-63's real port. `listenAddress` is read AFTER
  // the registry resolves — which is after the bind — so `UNIFI_HTTP_PORT=0`
  // reports the OS-assigned port in the serving line instead of the literal
  // `0` the operator configured. Without this the line misrenders on every
  // ephemeral-port deployment, which is every test and every sidecar.
  const resolving = resolveRegistry(core, {
    listenAddress: () => addressOf(httpServer),
  }).then(() => {
    if (core.readyError === null && readiness.phase === 'starting') {
      readiness.phase = 'ready';
      observer?.onReady?.();
    }
  });

  return buildHandle();

  // -------------------------------------------------------------------------
  // Teardown
  // -------------------------------------------------------------------------

  function buildHandle(): HttpServing {
    let outcome: Promise<'clean' | 'deadline'> | null = null;

    const teardown = async (): Promise<void> => {
      observer?.onDrainStep?.('not-ready');
      readiness.phase = 'draining';
      observer?.onDrainStep?.('begin-drain');
      try {
        core.beginDrain();
      } catch {
        /* the drain continues; every step is individually guarded */
      }

      // The periodic sweep stops before the listener does: from here on the
      // drain gate refuses every MCP method, so nothing can become idle that
      // the explicit session close below will not reach anyway.
      clearInterval(sweepTimer);

      observer?.onDrainStep?.('close-listener');
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
        // The ONLY call that kills an SSE-carrying socket: `close()` and
        // `closeIdleConnections()` both use the "not sending a request or
        // waiting for a response" predicate, and an open SSE response is by
        // definition not idle. US-24 owns the ordered sequence around this.
        httpServer.closeAllConnections();
      });

      observer?.onDrainStep?.('close-sessions');
      // Every entry, `pending` ones included: a session whose initialisation
      // has not yet been confirmed is not invisible to the drain. US-24 owns
      // the ordering, the per-session budget and the parallelism around this.
      for (const key of [...sessions.keys()]) await terminateSession(key, 'drain');

      observer?.onDrainStep?.('close-runtime');
      try {
        await core.close();
      } catch {
        /* teardown is best-effort by design */
      }
    };

    const drain = (_reason: DrainReason): Promise<'clean' | 'deadline'> => {
      outcome ??= teardown().then((): 'clean' => 'clean');
      return outcome;
    };

    return {
      kind: 'http',
      address: bound,
      drain,
      async dispose(): Promise<void> {
        await drain('disposal');
        // The registry resolution is awaited so a disposed transport leaves no
        // promise still holding a reference to the runtime.
        await resolving.catch(() => undefined);
      },
      /**
       * RESERVATIONS, not map size (architecture §4.1, §4.3).
       *
       * The two agree except during an in-flight `initialize`, and that window
       * is exactly the one the cap must not be blind to. FR-72 and FR-77 assert
       * against this accessor rather than against a heap measurement, which
       * would flake.
       */
      sessionCount(): number {
        return reserved;
      },
      connectionCounts(): { total: number; headroom: number } {
        return ledger.counts();
      },
      sweepIdleSessions,
      bounds(): ResolvedInboundBounds {
        return bounds;
      },
      retainedRequestBuffers(): number {
        return retainedBuffers;
      },
    };
  }

  /**
   * THE INITIATING PATH: we decided to end this session.
   *
   * One function for `DELETE`, eviction and drain, and US-24's drain step 7
   * calls exactly this per live session rather than reimplementing any of it.
   *
   * **An eviction is this sequence, not a map delete.** No SDK callback fires
   * for one — `onsessionclosed` is `DELETE`-only — so every step below is ours:
   *
   *   1. Look up and return if absent or already terminating (idempotent).
   *   2. Mark terminating and delete OUR OWN registry entry first, so a
   *      concurrent request cannot find a half-torn-down session — and so an
   *      evicted identifier and one that never existed take the identical
   *      step-11 branch from this instant onward.
   *   3. Attempt the terminal frame, because `transport.close()` writes no
   *      JSON-RPC frame at all and the client would otherwise see a silently
   *      truncated stream. Skipped for `'delete'`, where the client asked and
   *      gets its `200`.
   *   4. `await server.close()`. This chains `Protocol.close()` →
   *      `transport.close()` and, through the wrapper `connect()` installed,
   *      runs `Protocol._onclose()` — which is what ABORTS EVERY IN-FLIGHT
   *      REQUEST HANDLER'S `AbortController`. It also fires our `onclose` hook,
   *      which finds no entry and returns.
   *   5. Release the reservation, in a `finally`, when teardown has COMPLETED.
   *
   * NO SOCKET IS DESTROYED here, and that is a fix rather than an omission.
   * HTTP/1.1 keep-alive does not partition by session, so a client — or an
   * attacker — multiplexing two sessions over one connection would have session
   * B's live SSE stream destroyed as collateral when A was evicted. The socket
   * lingers until `keepAliveTimeout` instead. Bulk destruction stays where it
   * is unambiguous: the drain's `closeAllConnections()`.
   */
  async function terminateSession(key: string, reason: TerminationReason): Promise<void> {
    const entry = sessions.get(key);
    if (entry === undefined || entry.state === 'terminating') return;

    const wasLive = entry.state === 'live';
    entry.state = 'terminating';
    sessions.delete(key);

    try {
      if (wasLive && reason !== 'delete') await sendTerminalFrame(entry);
      await entry.server.close();
    } catch {
      /* a session that failed to close cleanly must not stop the others */
    } finally {
      reserved -= 1;
    }
  }

  /**
   * THE BOOKKEEPING PATH: the session is already gone.
   *
   * Hooked on `server.onclose`, so it also covers the cause that is not a
   * termination reason at all — a transport that closed underneath us. It never
   * calls `server.close()`, which is what stops the two paths recursing: an
   * earlier revision hooked the initiating function here and the recursion
   * terminated only by accident of ordering.
   */
  function onSessionGone(entry: SessionEntry): void {
    if (entry.state === 'terminating') return;
    if (sessions.get(entry.key) !== entry) return;
    entry.state = 'terminating';
    sessions.delete(entry.key);
    reserved -= 1;
  }

  /**
   * The terminal frame (architecture §3.4.1).
   *
   * A JSON-RPC error RESPONSE requires an `id` and a session-wide terminal
   * notice has none, so the session-level frame is a notification; the
   * per-request errors that follow carry each outstanding request's own id and
   * are what let a client fail its pending calls deterministically rather than
   * time them out. One message string for both, so an operator greps one thing.
   *
   * Every send is attempted and every failure is a no-op with no log line. The
   * SDK's "a late send is silently discarded" guarantee is guarded on its own
   * `_closed`, which is still `false` here — the normal state of a session that
   * never opened a standalone `GET` stream — so a throw is expected, not
   * exceptional.
   */
  async function sendTerminalFrame(entry: SessionEntry): Promise<void> {
    const notification: JSONRPCMessage = {
      jsonrpc: '2.0',
      method: 'notifications/message',
      params: { level: 'error', logger: 'unifi-mcp', data: DRAIN_MESSAGE },
    };
    try {
      await entry.transport.send(notification);
    } catch {
      /* no open stream, or a peer applying backpressure. Not an error here. */
    }

    for (const id of entry.outstanding) {
      const failure: JSONRPCMessage = {
        jsonrpc: '2.0',
        id,
        error: { code: JSON_RPC_SERVER_ERROR, message: DRAIN_MESSAGE },
      };
      try {
        await entry.transport.send(failure, { relatedRequestId: id });
      } catch {
        /* that request's stream is already gone; nothing to deliver it on */
      }
    }
  }

  /**
   * The sweep's SELECTION half — synchronous, pure with respect to the clock.
   *
   * Split from the eviction half so the TTL is testable against an injected
   * clock with no wall-clock waiting at all: 100 abandoned sessions are driven
   * to zero by fast-forwarding a number, not by sleeping for a TTL.
   *
   * A `pending` entry is never selected. It is mid-`initialize`, its own
   * `finally` releases it, and evicting it from underneath its dispatch would
   * double-release the reservation.
   */
  function selectExpired(nowMs: number): string[] {
    const expired: string[] = [];
    for (const entry of sessions.values()) {
      if (entry.state !== 'live') continue;
      if (sessionIsIdle(entry, nowMs, serving.sessionIdleTtlMs)) expired.push(entry.key);
    }
    return expired;
  }

  /** The sweep's EVICTION half. Returns the count actually evicted. */
  async function evictAll(keys: readonly string[]): Promise<number> {
    let evicted = 0;
    for (const key of keys) {
      if (!sessions.has(key)) continue;
      await terminateSession(key, 'evicted');
      evicted += 1;
    }
    return evicted;
  }

  async function sweepIdleSessions(nowMs: number): Promise<number> {
    return evictAll(selectExpired(nowMs));
  }

  function addressOf(server: Server): AddressInfo | null {
    const address = server.address();
    return address !== null && typeof address === 'object' ? address : null;
  }
}
