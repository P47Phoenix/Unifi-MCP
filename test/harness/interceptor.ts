/**
 * The FR-75 outbound interceptor: a loopback HTTPS origin.
 *
 * This is a test HELPER, not a test file. `scripts/run-tests.mjs` discovers
 * suites with a NON-recursive `readdirSync('test')`, so nothing under
 * `test/harness/` is ever executed as a suite.
 *
 * ## Why an origin rather than a hook on UnifiClient
 *
 * `src/http/client.ts:17` statically imports `request as httpsRequest` from
 * `node:https`, and Node 20 has no `mock.module`. There is no seam BELOW the
 * client. Hooking `UnifiClient.request` — which is what
 * `test/fixtures/recording-client.ts` does, correctly, for its own purpose —
 * records the request the handler ASKED for. It cannot observe the retry loop,
 * the credential resolution, the TLS agent selection, or the header set,
 * because all four live below that hook.
 *
 * So this interceptor is a real HTTPS server on 127.0.0.1:0 that the
 * PRODUCTION client dials with zero source change. It sees the bytes: the
 * method, the request target, every header — including the `X-API-Key` value
 * the credential store resolved, which is the whole of what FR-78's A34
 * sentinel assertion and US-16/US-17's "exactly one outbound request carrying
 * the planted sentinel" criteria need.
 *
 * ## THE OPERATING ENVELOPE — stated here, not discovered
 *
 * This interceptor can carry ONLY local-direct Network and Protect traffic.
 *
 * `src/http/transport.ts` declares the vendor origin as two module-level
 * constants with no environment override and no parameter, and `resolveTarget`
 * returns them unconditionally for `site-manager`, for `mobility`, and for
 * EVERY `connector`-mode request. That file is untouchable this round — it is
 * not one of the three named bounded exceptions — so those three classes of
 * request cannot be redirected at a loopback socket by any configuration.
 *
 * WHAT THIS MEANS FOR AN ASSERTION WRITTEN AGAINST THIS INTERCEPTOR:
 *
 *   OBSERVABLE   Network and Protect in `local` transport mode: the real
 *                socket, the real method, the real URL, the real header set,
 *                the real `X-API-Key`, the real retry loop, the real
 *                `rejectUnauthorized:false` agent selection.
 *   NOT          Site Manager. Mobility. Any service in `connector` mode.
 *   OBSERVABLE   Those resolve to the hardcoded cloud origin and never reach
 *                any socket this process controls.
 *
 * For the unobservable half, `test/fixtures/recording-client.ts` records which
 * request WOULD have been built, at the `UnifiClient.request` seam. That proves
 * the verb and the target; it does not prove a socket carried them.
 * `mergeLedgers` below joins both recorders into one ordered ledger so a
 * "every tool was invoked" assertion can still be complete, and marks each
 * entry with the recorder that produced it so no reader can mistake the second
 * kind of evidence for the first.
 *
 * Closing the gap is a six-line default parameter on `resolveTarget`,
 * `resolveBaseUrl` and `buildUrl` (`cloudBaseUrl: string = CLOUD_BASE_URL`,
 * with the TLS `isCloud` test derived from it). No story creates it, the
 * architecture explicitly declined to add it, and it is the test strategy's
 * number-one residual coverage gap. It is NOT added here.
 *
 * ## The certificate
 *
 * `test/fixtures/loopback-cert.pem` and `loopback-key.pem`, minted once out of
 * band and committed. Node's standard library exposes `generateKeyPairSync` but
 * NO X.509 generation; a dev dependency is forbidden by FR-75; `openssl` at
 * test time is not portable to `windows-latest`. Each file carries its own
 * banner explaining what it is and how to regenerate it. The pair cannot rot:
 * it is reached only with `UNIFI_LOCAL_TLS_INSECURE=true`, under which
 * `agentFor` sets `rejectUnauthorized:false` and neither the expiry nor the SAN
 * is verified.
 */
import { readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer, type Server } from 'node:https';
import type { AddressInfo, Socket } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { HttpMethod, ServiceId } from '../../src/types.js';
import { LOCAL_API_KEY_SENTINEL } from '../fixtures/sentinel.js';
import type { LedgerEntry } from '../fixtures/recording-client.js';

// `fileURLToPath` rather than `URL.pathname`: on Windows the latter yields
// `/D:/a/...`, which `readFileSync` cannot open. The existing suites carry the
// same comment for the same reason.
const HARNESS_DIR = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(HARNESS_DIR, '..', 'fixtures');

/** The committed loopback pair. Read once; both files are a few hundred bytes. */
export const LOOPBACK_CERT_PATH = join(FIXTURE_DIR, 'loopback-cert.pem');
export const LOOPBACK_KEY_PATH = join(FIXTURE_DIR, 'loopback-key.pem');

/**
 * The two proxy path prefixes `resolveTarget` produces for a local console.
 *
 * Read from the request target to attribute an intercepted request to a
 * service. Not imported from `src/http/transport.ts`, which keeps them
 * module-private; a drift between the two is caught by the interceptor
 * attributing a request to `null`, which the suites assert against.
 */
const SERVICE_BY_PREFIX: ReadonlyArray<readonly [string, ServiceId]> = [
  ['/proxy/network/integration', 'network'],
  ['/proxy/protect/integration', 'protect'],
];

/** One request as it arrived on the wire. */
export interface InterceptedRequest {
  readonly method: string;
  /** Request target exactly as received: path plus query. */
  readonly path: string;
  /** The absolute URL the client dialled, reconstructed from the bound port. */
  readonly url: string;
  /** Lower-cased header names; repeated values joined with `, `. */
  readonly headers: Readonly<Record<string, string>>;
  /**
   * The `X-API-Key` value, hoisted because it is what the sentinel assertions
   * read. `undefined` when the header was absent, which is itself a finding.
   */
  readonly apiKey: string | undefined;
  /** Request body as UTF-8. Empty string for a body-less request. */
  readonly body: string;
  /** Service the prefix attributes this to, or `null` if neither matched. */
  readonly service: ServiceId | null;
}

/** What the origin answers with. Returned by the responder. */
export interface InterceptorResponse {
  readonly status: number;
  readonly body: unknown;
  readonly headers?: Readonly<Record<string, string>>;
}

export type Responder = (request: InterceptedRequest) => InterceptorResponse;

export interface LoopbackOriginOptions {
  /** Defaults to a per-service success envelope; see `defaultResponder`. */
  readonly respond?: Responder;
}

export interface LoopbackOrigin {
  /** `127.0.0.1:<ephemeral>` — the exact value `UNIFI_LOCAL_HOST` must take. */
  readonly host: string;
  readonly port: number;
  /** Every request received, in arrival order. Live; read after the call. */
  readonly requests: readonly InterceptedRequest[];
  /** Requests whose method changes state. Empty is the FR-44 default claim. */
  mutating(): readonly InterceptedRequest[];
  /** Swap the responder mid-run, for a retry or error-path case. */
  respondWith(responder: Responder): void;
  /** Idempotent. Destroys pooled keep-alive sockets so the handle releases. */
  close(): Promise<void>;
}

/** FR-44's mutating verbs. One definition, so a suite cannot narrow it. */
export const MUTATING_METHODS: ReadonlySet<string> = new Set([
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);

/**
 * Success envelopes, shaped as `normalizePage` expects for each service.
 *
 * A body of the wrong shape degrades every handler to an empty page, which
 * would still satisfy a naive "no writes happened" assertion while proving
 * nothing about the read path. These are deliberately free of anything
 * key-shaped: the point of the sentinel scan is that nothing the SERVER adds
 * leaks a credential, so the upstream body must not be what plants one.
 */
function successBody(service: ServiceId | null): unknown {
  if (service === 'protect') {
    // Protect answers with a bare top-level array and no paging of its own.
    return [
      {
        id: 'cam-loopback-01',
        name: 'Loopback Camera',
        type: 'UVC-G5-Bullet',
        state: 'CONNECTED',
        isConnected: true,
        isRecording: false,
      },
    ];
  }
  return {
    count: 1,
    totalCount: 1,
    limit: 25,
    offset: 0,
    data: [
      {
        id: 'dev-loopback-01',
        name: 'ap-loopback',
        model: 'U6-Pro',
        macAddress: '00:00:5e:00:53:11',
        ipAddress: '192.0.2.31',
        state: 'ONLINE',
        type: 'WIRED',
      },
    ],
  };
}

/** 200 with a service-appropriate envelope. Overridable per origin. */
export const defaultResponder: Responder = (request) => ({
  status: 200,
  body: successBody(request.service),
});

function serviceFor(path: string): ServiceId | null {
  for (const [prefix, service] of SERVICE_BY_PREFIX) {
    if (path.startsWith(prefix)) return service;
  }
  return null;
}

function normalizeHeaders(raw: IncomingMessage['headers']): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(raw)) {
    if (value === undefined) continue;
    headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
  }
  return headers;
}

/**
 * Start the origin on an ephemeral loopback port.
 *
 * Port `0` is not a convenience: S-09 asserts that every `.listen(` under
 * `test/` passes `0`, because a fixed port makes two concurrent test files —
 * and `run-tests.mjs` runs one child per file, concurrently — collide.
 */
export async function startLoopbackOrigin(
  options: LoopbackOriginOptions = {},
): Promise<LoopbackOrigin> {
  const requests: InterceptedRequest[] = [];
  const sockets = new Set<Socket>();
  let respond: Responder = options.respond ?? defaultResponder;

  const server: Server = createServer(
    {
      key: readFileSync(LOOPBACK_KEY_PATH),
      cert: readFileSync(LOOPBACK_CERT_PATH),
    },
    (req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        const path = req.url ?? '';
        const headers = normalizeHeaders(req.headers);
        const entry: InterceptedRequest = {
          method: req.method ?? '',
          path,
          url: `https://127.0.0.1:${port}${path}`,
          headers,
          apiKey: headers['x-api-key'],
          body: Buffer.concat(chunks).toString('utf8'),
          service: serviceFor(path),
        };
        requests.push(entry);

        const answer = respond(entry);
        const payload = Buffer.from(JSON.stringify(answer.body ?? null), 'utf8');
        res.writeHead(answer.status, {
          'content-type': 'application/json',
          'content-length': String(payload.byteLength),
          ...answer.headers,
        });
        res.end(payload);
      });
    },
  );

  // Tracked so `close()` can destroy pooled keep-alive sockets. `UnifiClient`
  // uses `keepAlive: true` agents, so without this `server.close()` waits for
  // an idle socket that nothing will ever close and the test file hangs until
  // the 60 s per-test timeout.
  server.on('connection', (socket: Socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const address = server.address() as AddressInfo;
  const port = address.port;
  let closed: Promise<void> | null = null;

  return {
    host: `127.0.0.1:${port}`,
    port,
    requests,
    mutating(): readonly InterceptedRequest[] {
      return requests.filter((entry) => MUTATING_METHODS.has(entry.method));
    },
    respondWith(responder: Responder): void {
      respond = responder;
    },
    close(): Promise<void> {
      closed ??= new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        sockets.clear();
        server.close(() => resolve());
      });
      return closed;
    },
  };
}

/**
 * The NORMATIVE environment that points the production client at the origin.
 *
 * Every element is load-bearing and none is decoration:
 *
 *   UNIFI_LOCAL_HOST          the origin's `host:port`; `collectLocalConsoles`
 *                             keeps the port, and `agentFor` matches on the
 *                             same string, so the TLS relaxation applies.
 *   UNIFI_LOCAL_API_KEY       the planted sentinel. This is the value the
 *                             interceptor reads back off `X-API-Key`.
 *   UNIFI_*_TRANSPORT=local   without it the request resolves to the cloud
 *                             origin and never reaches this socket.
 *   UNIFI_LOCAL_TLS_INSECURE  NOT optional. `agentFor` sets
 *                             `rejectUnauthorized: !insecure`, and a
 *                             self-signed loopback certificate fails the
 *                             handshake without it.
 *
 * Network and Protect enable themselves by evidence — a configured local
 * console with a key — so no `UNIFI_ENABLE_*` is set here. Site Manager and
 * Mobility stay off, which is honest: this origin cannot carry their traffic.
 */
export function loopbackEnv(
  origin: Pick<LoopbackOrigin, 'host'>,
  overrides: Readonly<Record<string, string>> = {},
): NodeJS.ProcessEnv {
  return {
    UNIFI_LOCAL_HOST: origin.host,
    UNIFI_LOCAL_API_KEY: LOCAL_API_KEY_SENTINEL,
    UNIFI_NETWORK_TRANSPORT: 'local',
    UNIFI_PROTECT_TRANSPORT: 'local',
    UNIFI_LOCAL_TLS_INSECURE: 'true',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// The merged ledger
// ---------------------------------------------------------------------------

/**
 * One outbound attempt, from either recorder, with its provenance kept.
 *
 * `source` is not bookkeeping: a `loopback` entry means a socket carried these
 * bytes, and a `synthetic` entry means the client committed to this request and
 * a stand-in answered it. An assertion that needs the first must say so.
 */
export interface OutboundAttempt {
  readonly source: 'loopback' | 'synthetic';
  readonly method: string;
  /** Absolute URL for a loopback entry; the action's path for a synthetic one. */
  readonly target: string;
  readonly service: ServiceId | null;
  /** Present only for a synthetic entry, which is attributed on the way in. */
  readonly tool: string | null;
}

export function fromIntercepted(request: InterceptedRequest): OutboundAttempt {
  return {
    source: 'loopback',
    method: request.method,
    target: request.url,
    service: request.service,
    tool: null,
  };
}

export function fromLedgerEntry(entry: LedgerEntry): OutboundAttempt {
  return {
    source: 'synthetic',
    method: entry.method as HttpMethod,
    target: entry.path,
    service: entry.service,
    tool: entry.tool,
  };
}

/**
 * Join both recorders into one ledger.
 *
 * Ordering across the two is not meaningful — they observe different layers —
 * so entries are grouped by source rather than interleaved by a timestamp that
 * would imply a causal order neither recorder can establish.
 */
export function mergeLedgers(
  intercepted: readonly InterceptedRequest[],
  synthetic: readonly LedgerEntry[],
): readonly OutboundAttempt[] {
  return [...intercepted.map(fromIntercepted), ...synthetic.map(fromLedgerEntry)];
}

/** Human-readable form, so a failure message names the offending request. */
export function describeAttempt(attempt: OutboundAttempt): string {
  const tool = attempt.tool ? `${attempt.tool} -> ` : '';
  return `${tool}${attempt.method} ${attempt.target} [${attempt.source}]`;
}
