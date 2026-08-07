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
 * ## What this module does NOT own
 *
 * The session cap, the idle TTL, the eviction path and the identifier
 * generator are US-23's; the ordered drain sequence, the pre-drain hold, the
 * per-session terminal frames and the exit-code vocabulary are US-24's. What is
 * here is the pipeline STEP each of them plugs into — step 11 and step 12 — and
 * a teardown honest enough to release every handle a test opens.
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
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';

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

/** Session identifier entropy, in bytes. 24 bytes is 192 bits (NFR-30 wants ≥128). */
const SESSION_ID_BYTES = 24;

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
 * Read a single header value.
 *
 * Node joins duplicate headers into an array for a few names; a session
 * identifier presented twice is not a value to reconcile, so an array is
 * rejected outright rather than having one member picked.
 */
function headerValue(raw: string | string[] | undefined): string | null {
  return typeof raw === 'string' && raw !== '' ? raw : null;
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
  /** The session identifier draw. US-23 owns its entropy criteria. */
  createSessionId?: () => string;
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

interface SessionEntry {
  readonly id: string;
  readonly server: McpServer;
  readonly transport: StreamableHTTPServerTransport;
  lastActivityMs: number;
  inFlight: number;
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
  const drawSessionId = deps.createSessionId ?? defaultSessionId;
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
  const sessions = new Map<string, SessionEntry>();
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
        sendJsonRpc(ctx, 404, 'Not Found', -32001, SESSION_UNKNOWN_MESSAGE, 'auth');
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
      sendJsonRpc(ctx, 503, 'Service Unavailable', -32000, DRAIN_MESSAGE, 'draining');
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

    if (entry === undefined) {
      if (ctx.method !== 'POST' || !isInitializeRequest(read.json)) {
        // The SDK's own answer for a non-initialisation request carrying no
        // session id, reproduced here because no transport exists to produce
        // it: this request never reached one.
        sendJsonRpc(ctx, 400, 'Bad Request', -32000, SESSION_REQUIRED_MESSAGE, 'auth');
        return;
      }
      entry = await openSession();
    }

    // NFR-24's line is written AT HEADER FLUSH, not at completion, and
    // `dur_ms` is therefore time-to-first-byte. That is the contract's cadence
    // (§8.16) and on this endpoint it is the difference between an operator
    // seeing a request line immediately and seeing it when the SSE stream
    // finally closes — which for a long-lived MCP session can be hours. The
    // wrapper is on THIS response object only and is discarded with it.
    logAtHeaderFlush(ctx);

    entry.lastActivityMs = now();
    entry.inFlight += 1;
    try {
      await entry.transport.handleRequest(ctx.req, ctx.res, read.json);
    } finally {
      entry.inFlight -= 1;
      entry.lastActivityMs = now();
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
    const transport = createTransport({
      ...options.transportOptionsFor(id),
      onsessionclosed: (closed: string) => {
        const found = sessions.get(closed);
        if (found !== undefined) void terminateSession(found);
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
    const server = createMcpServer(session, 'http');
    await server.connect(transport);

    const entry: SessionEntry = { id, server, transport, lastActivityMs: now(), inFlight: 0 };
    sessions.set(id, entry);
    return entry;
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
  ): void {
    if (!ctx.res.headersSent) {
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }),
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
      for (const entry of [...sessions.values()]) await terminateSession(entry);

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
      sessionCount(): number {
        return sessions.size;
      },
      connectionCounts(): { total: number; headroom: number } {
        return ledger.counts();
      },
      async sweepIdleSessions(nowMs: number): Promise<number> {
        let swept = 0;
        for (const entry of [...sessions.values()]) {
          if (entry.inFlight > 0) continue;
          if (nowMs - entry.lastActivityMs < serving.sessionIdleTtlMs) continue;
          await terminateSession(entry);
          swept += 1;
        }
        return swept;
      },
      bounds(): ResolvedInboundBounds {
        return bounds;
      },
      retainedRequestBuffers(): number {
        return retainedBuffers;
      },
    };
  }

  /**
   * Close one session through the same path an eviction and a drain take.
   *
   * `server.close()` rather than `transport.onclose = …`: `connect()` installs
   * a wrapper on `onclose`, and overwriting it silently disables
   * `Protocol._onclose()`, which is what aborts a session's in-flight handlers
   * through the `AbortSignal` they received.
   */
  async function terminateSession(entry: SessionEntry): Promise<void> {
    sessions.delete(entry.id);
    try {
      await entry.server.close();
    } catch {
      /* a session that failed to close cleanly must not stop the others */
    }
  }

  function defaultSessionId(): string {
    return randomBytes(SESSION_ID_BYTES).toString('base64url');
  }

  function addressOf(server: Server): AddressInfo | null {
    const address = server.address();
    return address !== null && typeof address === 'object' ? address : null;
  }
}
