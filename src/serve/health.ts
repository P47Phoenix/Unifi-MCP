/**
 * Liveness and readiness probes for the HTTP transport (FR-67, FR-68, FR-69).
 *
 * Traceability: FR-67 (both probes are unauthenticated and exempt from Host
 * validation, and their bodies are bare status only), FR-68 (`/healthz`
 * bind-liveness, constant work, unchanged during drain), FR-69 (`/readyz`
 * readiness from process-local state, with the drain indication), NFR-25
 * (readiness reaches no third party), NFR-17 (the answer is synchronous and
 * cannot stall the event loop).
 *
 * ## Liveness never flips
 *
 * `/healthz` answers 200 `ok\n` in every phase, draining included. It reports
 * "this process is running", not "this process is useful". A liveness probe
 * that failed during drain would have the orchestrator SIGKILL the container
 * mid-drain, cutting the in-flight sessions that graceful shutdown exists to
 * preserve — the drain would be strictly worse than no drain at all. Readiness
 * is the endpoint that flips: `/readyz` fails on the first drain tick so the
 * load balancer stops sending new traffic while liveness holds the container
 * alive long enough to finish what it already accepted.
 *
 * ## Closed import allow-list
 *
 * This file may import exactly one specifier — `node:http`, for types only —
 * and nothing else, ever. Not the configuration loader, not the credential
 * store, not the action registry, not the outbound client, not the tool layer,
 * no filesystem, no third-party package. The rule is the enforcement mechanism
 * for "readiness never reaches the vendor API, never validates the UniFi key,
 * never consults the OS keychain": a handler that cannot name the credential
 * store cannot consult it, and a handler that cannot name the registry cannot
 * rebuild it. Discipline is not relied on — the module graph is.
 *
 * WARNING: adding an import to this file is a security-boundary change, not a
 * refactor. It widens what an unauthenticated caller can make the process do.
 * A test asserts the allow-list by scanning this file's source.
 *
 * ## Boundary
 *
 * Everything about *reaching* a probe belongs to the transport, not here:
 * method validation (only GET and HEAD arrive), the Host-header check exemption,
 * Origin rejection, exemption from the request throttle, and route
 * normalisation are the transport's and the guard's responsibility. This module
 * assumes a well-formed probe and answers it.
 */
import type { OutgoingHttpHeaders, ServerResponse } from 'node:http';

/**
 * Lifecycle phase of one transport. There is no fourth phase and no composite
 * "is the server usable" predicate: readiness is one field, read directly.
 *
 * `starting` runs from listener bind until the registry and promoted tools
 * resolve; `ready` from then on; `draining` from the moment a termination
 * signal arrives until exit.
 */
export type Phase = 'starting' | 'ready' | 'draining';

/** The one mutable cell the probes read. One per transport, never shared. */
export interface ReadinessState {
  phase: Phase;
}

/** The two probe routes this module answers. */
export type ProbeKind = 'healthz' | 'readyz';

/** The only methods the transport forwards here. */
export type ProbeMethod = 'GET' | 'HEAD';

/** A complete, precomputed answer: status line, headers and body bytes. */
interface ProbeResponse {
  readonly status: number;
  readonly headers: OutgoingHttpHeaders;
  readonly body: Buffer;
}

/**
 * Fixed headers. No CORS header, no `Server`, no `X-Powered-By` — the response
 * describes the payload and nothing about the process serving it.
 */
function headersFor(body: Buffer): OutgoingHttpHeaders {
  return Object.freeze({
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    // Explicit so a HEAD reply is header-identical to the GET it mirrors.
    'Content-Length': String(body.byteLength),
  });
}

function probeResponse(status: number, text: string): ProbeResponse {
  const body = Buffer.from(text, 'utf8');
  return Object.freeze({ status, headers: headersFor(body), body });
}

/**
 * Bodies are built once, at module load, and carry a bare status word only —
 * no version, build, commit, uptime, session or connection count, queue depth,
 * enabled service, spec version, bind address, port, transport path, write
 * state, credential presence, hostname or any UniFi identifier (NFR-25).
 */
const LIVENESS: ProbeResponse = probeResponse(200, 'ok\n');

const READINESS: Readonly<Record<Phase, ProbeResponse>> = Object.freeze({
  starting: probeResponse(503, 'starting\n'),
  ready: probeResponse(200, 'ready\n'),
  draining: probeResponse(503, 'draining\n'),
});

/** A fresh phase cell for one transport, before its listener is useful. */
export function createReadinessState(): ReadinessState {
  return { phase: 'starting' };
}

/**
 * Liveness (FR-68). 200 `ok\n` in every phase — see the invariant in the file
 * header. This is a bind-liveness check: it cannot fail for a process out of
 * file descriptors, wedged on every session, or leaking toward OOM.
 */
export function handleHealthz(res: ServerResponse, method: ProbeMethod): void {
  send(res, method, LIVENESS);
}

/**
 * Readiness (FR-69), answered by reading one field: no `await`, no I/O, no
 * allocation beyond the write itself (NFR-17).
 *
 * Deliberately independent of session occupancy. "Ready and not at max
 * sessions" would leak how busy the process is to an unauthenticated caller
 * through a status flip, so no occupancy input is accepted here.
 */
export function handleReadyz(
  res: ServerResponse,
  method: ProbeMethod,
  readiness: ReadinessState,
): void {
  send(res, method, READINESS[readiness.phase]);
}

/**
 * Single entry point for a router branching over the two-member probe set.
 */
export function handleProbe(
  probe: ProbeKind,
  method: ProbeMethod,
  res: ServerResponse,
  readiness: ReadinessState,
): void {
  if (probe === 'healthz') {
    handleHealthz(res, method);
    return;
  }
  handleReadyz(res, method, readiness);
}

/**
 * Writes a precomputed answer. HEAD gets the identical status and headers with
 * an empty body. Returns without throwing if the response is already committed,
 * so a probe can never be the reason the transport dies.
 */
function send(res: ServerResponse, method: ProbeMethod, response: ProbeResponse): void {
  if (res.headersSent) return;
  res.writeHead(response.status, response.headers);
  if (method === 'HEAD') {
    res.end();
    return;
  }
  res.end(response.body);
}
