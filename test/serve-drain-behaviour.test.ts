/**
 * US-28d — the drain, asserted as BEHAVIOUR rather than as mechanism.
 *
 * Wave J slot J4. Depends on US-24 (the drain sequence), US-25 (the harness)
 * and — by amendment 15 — **US-17** (the bounded keychain lookup).
 *
 * ## What this file adds that `test/serve-drain.test.ts` does not
 *
 * US-24's own suite proved the drain sequence CORRECT: injected drain timers so
 * the 5 000 ms hold and the 35 000 ms deadline are fast-forwarded provably
 * rather than merely quickly, an injected transport for the handler-promise
 * criterion, an injected `CredentialStore` for the FR-82 interaction, and the
 * exit-code vocabulary read off an injected `ServingDeps.exit`. Every one of
 * those is a directly-invoked `drain()` inside the test runner's own process.
 *
 * This file is the other half: **a real process, a real signal, real HTTP
 * requests on a real bound port, and the process's own exit status.** Nothing
 * in section 1 to 3 below is fast-forwarded — the 5 000 ms pre-drain hold is
 * waited out in real seconds, because the thing being asserted is what a client
 * and an orchestrator OBSERVE during that window, and a fast-forwarded clock
 * cannot be observed from outside the process.
 *
 * ## The venue, and why it is NOT `test/harness/serve-entry.ts`
 *
 * US-24's carry-forward records a wall: `serve-entry.ts`'s watchdog is
 * `setTimeout(..., holdMs)` and is **ref'd on purpose**, so a spawned child
 * holds its event loop open until `holdMs` however completely it drained. Two
 * consequences, and the second is worse than the one recorded:
 *
 *   1. exit-0 BY NATURAL DRAIN is unobservable — the watchdog, not the drain,
 *      ends the process; and
 *   2. the watchdog's callback is `process.exit(0)`, which OVERRIDES a
 *      `process.exitCode` of 75 that the hard stop had already set. So the
 *      **exit-75 hard stop is unobservable through that harness too** — a
 *      stalled child reports 0.
 *
 * On top of that, `serve-entry.ts` calls `main(deps, observer)` with no
 * `ServingDeps`, so `deps.exit` is `undefined` and the drain's `exitProcess`
 * degrades to `setExitCode`: the child never calls `process.exit` at all.
 *
 * The route around it is not a harness change (out of this story's file scope)
 * but a different child: **the production entrypoint itself**. `src/index.ts`'s
 * auto-run guard is the one place in `src/` permitted to end the process and it
 * supplies the real hook — `main({}, undefined, { exit: (code) =>
 * process.exit(code) })` — so a child spawned that way reports the genuine
 * status for both the clean and the deadline path. Spawning `src/index.ts` is
 * established practice here (`test/signals.test.ts` §5, `test/healthcheck.test.ts`
 * §5, `test/credentials-file.test.ts`); S-09 forbids IMPORTING it in-process,
 * which nothing below does.
 *
 * The cost of that route is that `RuntimeDeps` cannot be injected across the
 * process boundary. Everything the spawned cases need is therefore driven from
 * OUTSIDE the child — real sockets, real MCP frames, and a real TLS origin this
 * file starts and paces — which is the point rather than a workaround.
 *
 * ## The US-17 edge
 *
 * FR-82's drain interaction is what makes §3's in-flight case survivable at
 * all. A real `tools/call` in a real child enters `credentials.resolveFor()`
 * before any token is held; US-17 made that lookup bounded, and made its
 * abandonment RESOLVE rather than reject — a rejected long-lived promise with
 * no handler attached at the moment of rejection is what Node 20's default
 * `--unhandled-rejections=throw` turns into a dead process, which would appear
 * here as a child exiting 1 mid-drain instead of 0. §3's `in-flight request`
 * and `stalled request` cases exercise that path end to end with no injection
 * of any kind, which is the venue the test strategy prefers and the one US-24
 * could not reach (its C21 is asserted through an injected `CredentialStore`,
 * recorded as a venue deviation in the carry-forward register).
 *
 * ## MECH-SIGNAL scoping (test strategy §12, NFR-27, owner decision OQ-18)
 *
 * Sections 1, 2 and 3 deliver a real signal and are the ONLY sections carrying
 * a declared, reported skip on `windows-latest`. Section 4 is the portable half
 * of every one of them, driven through the directly-invoked `drain()` — which
 * is idempotent and directly callable precisely so this is possible — and runs
 * UNSCOPED on all three legs. The requirement is never skipped; only its
 * delivery mechanism is.
 *
 * **A green Windows leg asserts the drain state machine and never the shutdown
 * guarantee.** Windows is a supported development and stdio platform and is not
 * a supported HTTP deployment target.
 */
import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer as createTlsServer } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { connect, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { after, describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  HTTP_HARD_STOP_STEP,
  startHttp,
  type DrainTimerFactory,
  type DrainTimerKind,
  type HttpServing,
  type HttpServingDeps,
} from '../src/serve/http.js';
import {
  buildRuntimeCore,
  PREDRAIN_HOLD_MS,
  type RuntimeCore,
  type ServingObserver,
  type ToolHandler,
} from '../src/serve/runtime.js';
import { DRAIN_REFUSAL_MESSAGE, EXIT_CODES } from '../src/serve/stdio.js';

import { createInstruments } from './harness/counters.js';
import { LOOPBACK_CERT_PATH, LOOPBACK_KEY_PATH } from './harness/interceptor.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRYPOINT = join(REPO_ROOT, 'src', 'index.ts');

/** 40 characters, comfortably over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;

/** A member of the SDK's `SUPPORTED_PROTOCOL_VERSIONS`, pinned rather than imported. */
const PROTOCOL_VERSION = '2025-06-18';

/**
 * The action used for the two cases that need a REAL outbound request.
 *
 * Only Network and Protect in `local` transport mode can be pointed at a
 * loopback origin; Site Manager and Mobility resolve to a hardcoded cloud
 * origin no configuration can redirect. `site_id` is a REQUIRED parameter — a
 * call without it fails a precondition and never reaches a socket, so the
 * request would never be in flight and the case would assert nothing.
 */
const OUTBOUND_TOOL = 'unifi_list_devices';

/** The tool whose handler §4 substitutes, so no in-process case goes outbound. */
const HANDLER_TOOL = 'unifi_list_consoles';

/**
 * The shutdown deadline these tests configure, in milliseconds.
 *
 * Deliberately short. The production default is 35 000 ms and asserting a
 * real-signal drain against it would be a 36-second latency measurement per
 * case, six times over. What the cases actually need is a deadline that is
 * comfortably above the 5 000 ms pre-drain hold — which is a FIXED constant no
 * environment variable can lower (FR-63 closes the `UNIFI_HTTP_*` family) —
 * and low enough that §3's hard-stop case reaches it in a few seconds.
 */
const DEADLINE_MS = 9_000;

/**
 * The largest connector timeout that leaves the shutdown budget intact at
 * `DEADLINE_MS`: architecture §3.4's cross-field check warns when the
 * 5 000 ms hold plus the connector timeout plus a 1 000 ms margin exceeds the
 * deadline. Sitting exactly on the boundary keeps the clean cases' stderr free
 * of that warning while leaving the widest margin for §3's paced origin.
 *
 * §3's stalled case deliberately overrides this back to the 25 000 ms default:
 * an outbound attempt that cannot finish inside the budget is exactly the
 * condition the hard stop exists for, and the warning it then emits is correct.
 */
const SHORT_CONNECTOR_TIMEOUT_MS = '3000';

/**
 * How long §3's paced origin holds the in-flight request.
 *
 * Bounded on both sides. Long enough that the request is provably still in
 * flight when the signal lands — the case asserts it is unanswered immediately
 * before signalling — and comfortably shorter than
 * `SHORT_CONNECTOR_TIMEOUT_MS`, so a slow runner produces a completed response
 * rather than a connector timeout that would fail the case for the wrong reason.
 */
const PACED_RESPONSE_MS = 1_200;

/**
 * MECH-SIGNAL. The reason string is MANDATORY and must name the portable cover,
 * so a reader of the CI output can see what a skipped leg still proves. A bare
 * `skip: true` fails review — an unexplained skip is indistinguishable from an
 * abandoned assertion.
 */
const MECH_SIGNAL_SKIP =
  process.platform === 'win32'
    ? 'MECH-SIGNAL: process.kill() terminates unconditionally on Windows and no handler runs, ' +
      'so a delivered signal is unsatisfiable by any correct implementation. Section 4 of this ' +
      'file asserts the same three requirements on this leg through the directly-invoked ' +
      'drain(): the /readyz-draining//healthz-200 concurrency polled across the pre-drain hold, ' +
      'the 503-plus-log-line for a connection arriving inside the hold, and the four shutdown ' +
      'states plus the stalled-request hard stop read off an injected ServingDeps.exit. A green ' +
      'Windows leg asserts the drain STATE MACHINE and never the shutdown guarantee (NFR-27, ' +
      'owner decision OQ-18).'
    : false;

// ---------------------------------------------------------------------------
// Raw HTTP, over sockets this file owns
//
// `fetch` is not used anywhere below. Node 20's global fetch keeps a pooled
// undici agent alive in the TEST process, and a poll loop running thirty
// requests through it leaves handles behind that outlive the case. A socket
// opened, read and destroyed per request leaves nothing.
// ---------------------------------------------------------------------------

interface RawResult {
  /** Everything the server wrote, verbatim. Empty when the connection was refused. */
  readonly text: string;
  /** True when the kernel refused the connection — the listener is gone. */
  readonly refused: boolean;
  /** The status line's code, or `null` when nothing parseable arrived. */
  readonly status: number | null;
  /** Body bytes after the header terminator. */
  readonly body: string;
}

function parseRaw(text: string, refused: boolean): RawResult {
  const split = text.indexOf('\r\n\r\n');
  const status = /^HTTP\/1\.1 (\d{3})/.exec(text)?.[1];
  return {
    text,
    refused,
    status: status === undefined ? null : Number(status),
    body: split === -1 ? '' : text.slice(split + 4),
  };
}

/**
 * One request over one socket, returning the server's bytes verbatim.
 *
 * `ECONNREFUSED` is a first-class RESULT rather than a rejection: after the
 * pre-drain hold expires the listener is closed, and "the listener stopped
 * accepting" is the observation that ends §1's poll loop. A helper that threw
 * there would turn the end of the window into a failure.
 */
function rawExchange(
  port: number,
  lines: readonly string[],
  body = '',
  /**
   * Settles as soon as the bytes so far satisfy this. Required for a CHUNKED
   * reply — an SSE response declares no `Content-Length` and the server holds
   * the stream open, so `Content-Length` completion never arrives.
   */
  settleWhen?: (text: string) => boolean,
  timeoutMs = 10_000,
): Promise<RawResult> {
  return new Promise<RawResult>((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    let text = '';
    let settled = false;

    const finish = (result: RawResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(
      () => finish(parseRaw(text, false)),
      timeoutMs,
    );

    /** True once the headers and the full declared body have arrived. */
    const complete = (): boolean => {
      const split = text.indexOf('\r\n\r\n');
      if (split === -1) return false;
      const length = /content-length: *(\d+)/i.exec(text.slice(0, split))?.[1];
      if (length === undefined) return false;
      return Buffer.byteLength(text.slice(split + 4)) >= Number(length);
    };

    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      text += chunk;
      if (settleWhen !== undefined ? settleWhen(text) : complete()) finish(parseRaw(text, false));
    });
    socket.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ECONNREFUSED' || error.code === 'ECONNRESET') {
        finish(parseRaw(text, text === ''));
        return;
      }
      if (!settled) {
        clearTimeout(timer);
        reject(error);
      }
    });
    socket.once('close', () => finish(parseRaw(text, text === '')));
    socket.on('connect', () => {
      socket.write([...lines, `Content-Length: ${Buffer.byteLength(body)}`, '', body].join('\r\n'));
    });
  });
}

/** One unauthenticated probe on a fresh connection the server is told to close. */
function probe(port: number, path: '/healthz' | '/readyz'): Promise<RawResult> {
  return rawExchange(port, [`GET ${path} HTTP/1.1`, 'Host: 127.0.0.1', 'Connection: close'], '', undefined, 4_000);
}

interface OpenStream {
  /** Everything the server has written on this stream so far. */
  text(): string;
  /** True once the socket closed — which for an SSE stream means it was destroyed. */
  closed(): boolean;
  destroy(): void;
}

/**
 * Hold a standalone SSE stream open on a live session, over a raw socket.
 *
 * A raw socket rather than the SDK client, because the assertion is about the
 * SOCKET and not only about the frames: `transport.close()` ends the response
 * BODY and leaves an idle keep-alive socket alive, so a test that asserted only
 * "the stream ended" passes against the broken implementation.
 */
function openSseStream(port: number, sessionId: string): Promise<OpenStream> {
  return new Promise<OpenStream>((resolve, reject) => {
    const socket: Socket = connect({ host: '127.0.0.1', port });
    let text = '';
    let closed = false;
    let opened = false;

    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      text += chunk;
      if (!opened && text.includes('text/event-stream')) {
        opened = true;
        resolve(handle);
      }
    });
    socket.once('error', (error) => {
      if (!opened) reject(error);
    });
    socket.once('close', () => {
      closed = true;
      if (!opened) reject(new Error(`the SSE stream never opened. Got:\n${text}`));
    });

    const handle: OpenStream = {
      text: () => text,
      closed: () => closed,
      destroy: () => socket.destroy(),
    };

    socket.on('connect', () => {
      socket.write(
        [
          'GET /mcp HTTP/1.1',
          'Host: 127.0.0.1',
          `Authorization: Bearer ${SECRET}`,
          `Mcp-Session-Id: ${sessionId}`,
          'Accept: text/event-stream',
          'Connection: keep-alive',
          '',
          '',
        ].join('\r\n'),
      );
    });
  });
}

function mcpHeaders(sessionId?: string): readonly string[] {
  return [
    'POST /mcp HTTP/1.1',
    'Host: 127.0.0.1',
    `Authorization: Bearer ${SECRET}`,
    ...(sessionId === undefined ? [] : [`Mcp-Session-Id: ${sessionId}`]),
    'Accept: application/json, text/event-stream',
    'Content-Type: application/json',
  ];
}

/**
 * Open one live session over RAW SOCKETS and return its identifier.
 *
 * The SDK client is not used anywhere in this file: its
 * `StreamableHTTPClientTransport` opens the one standalone SSE stream a session
 * is permitted the moment it connects, so a second `GET` — the stream §3's SSE
 * case needs to watch die — is answered `409 Conflict`.
 */
async function openRawSession(port: number): Promise<string> {
  const initialize = await rawExchange(
    port,
    mcpHeaders(),
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'us-28d', version: '0.0.0' },
      },
    }),
    (text) => text.includes('"result"'),
  );

  const sessionId = /mcp-session-id: *([^\r\n]+)/i.exec(initialize.text)?.[1];
  assert.ok(
    sessionId !== undefined,
    `the initialize reply carried no session id. Got:\n${initialize.text}`,
  );

  await rawExchange(
    port,
    mcpHeaders(sessionId),
    JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    (text) => text.includes('\r\n\r\n'),
  );

  return sessionId;
}

/** Wait for a condition without sleeping on a fixed interval. */
async function until(predicate: () => boolean, what: string, budgetMs = 15_000): Promise<void> {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > budgetMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// A paced TLS origin
//
// `startLoopbackOrigin` answers synchronously from a `Responder` that returns a
// value, so it cannot hold a request open — and holding one open is the whole
// of §3's `in-flight` and `stalled` cases. This is the same server shape with
// one field added, not a competing instrument: the interceptor's ledger,
// sentinel and mutating-method duties are not needed here and are not
// reproduced.
// ---------------------------------------------------------------------------

interface PacedOrigin {
  /** `127.0.0.1:<ephemeral>` — the exact value `UNIFI_LOCAL_HOST` must take. */
  readonly host: string;
  /** How many requests have arrived. Live; read after the call. */
  received(): number;
  close(): Promise<void>;
}

/**
 * @param respondAfterMs `null` never answers at all — the stalled case.
 */
async function startPacedOrigin(respondAfterMs: number | null): Promise<PacedOrigin> {
  let received = 0;
  const sockets = new Set<Socket>();
  const pending = new Set<NodeJS.Timeout>();

  const server = createTlsServer(
    { key: readFileSync(LOOPBACK_KEY_PATH), cert: readFileSync(LOOPBACK_CERT_PATH) },
    (req: IncomingMessage, res: ServerResponse) => {
      req.resume();
      req.on('end', () => {
        received += 1;
        if (respondAfterMs === null) return; // held open, deliberately, forever
        const timer = setTimeout(() => {
          pending.delete(timer);
          const payload = Buffer.from(
            JSON.stringify({
              count: 1,
              totalCount: 1,
              limit: 25,
              offset: 0,
              data: [
                {
                  id: 'dev-paced-01',
                  name: 'ap-paced',
                  model: 'U6-Pro',
                  macAddress: '00:00:5e:00:53:12',
                  ipAddress: '192.0.2.32',
                  state: 'ONLINE',
                  type: 'WIRED',
                },
              ],
            }),
            'utf8',
          );
          res.writeHead(200, {
            'content-type': 'application/json',
            'content-length': String(payload.byteLength),
          });
          res.end(payload);
        }, respondAfterMs);
        pending.add(timer);
      });
    },
  );

  // Tracked so `close()` can destroy the client's pooled keep-alive sockets:
  // `UnifiClient` uses `keepAlive: true` agents, so without this `server.close()`
  // waits on an idle socket nothing will ever close.
  server.on('connection', (socket: Socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    // Port 0 everywhere (S-09): `run-tests.mjs` runs one child per test FILE,
    // concurrently, and a fixed port makes two files collide.
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const port = (server.address() as AddressInfo).port;
  let closed: Promise<void> | null = null;

  return {
    host: `127.0.0.1:${port}`,
    received: () => received,
    close(): Promise<void> {
      closed ??= new Promise<void>((resolve) => {
        for (const timer of pending) clearTimeout(timer);
        pending.clear();
        for (const socket of sockets) socket.destroy();
        sockets.clear();
        server.close(() => resolve());
      });
      return closed;
    },
  };
}

// ===========================================================================
// The spawned production entrypoint
// ===========================================================================

const children = new Set<ChildProcessWithoutNullStreams>();
after(() => {
  // A last-resort reaper only. Every case below drives its own signal and reads
  // its own exit status; a child still alive here means that case failed, and
  // leaving it running would hold a CI runner open.
  for (const child of children) if (child.exitCode === null) child.kill('SIGKILL');
});

interface Entrypoint {
  readonly proc: ChildProcessWithoutNullStreams;
  stderr(): string;
  /** Resolves with the OS-assigned port once the child has bound AND resolved. */
  ready(): Promise<number>;
  exited(): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

function entrypointEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    // Port 0 in the child too. The OS-assigned port is read back off the §3.1
    // serving line, which renders the BOUND address rather than the configured
    // one precisely so it is usable here (FR-63).
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: String(DEADLINE_MS),
    UNIFI_CONNECTOR_TIMEOUT_MS: SHORT_CONNECTOR_TIMEOUT_MS,
    ...extra,
  };
}

/**
 * Spawn the PRODUCTION entrypoint.
 *
 * `--import tsx` matches `scripts/run-tests.mjs`'s own invocation, so the child
 * loads TypeScript exactly as the suite does and no build step is implied. The
 * inherited environment is stripped of every `UNIFI_*` variable: a value
 * exported on a developer's machine must not be able to enable a service, plant
 * a credential or mask a refusal.
 */
function spawnEntrypoint(env: Record<string, string>): Entrypoint {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key, value]) => !key.startsWith('UNIFI_') && value !== undefined,
    ),
  ) as Record<string, string>;

  const proc = spawn(process.execPath, ['--import', 'tsx', ENTRYPOINT], {
    cwd: REPO_ROOT,
    env: { ...inherited, ...env },
    stdio: ['pipe', 'pipe', 'pipe'],
  }) as ChildProcessWithoutNullStreams;
  children.add(proc);

  let text = '';
  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk: string) => {
    text += chunk;
  });
  proc.stdout.resume();

  let exited: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  const exitPromise = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve) => {
      proc.once('exit', (code, signal) => {
        exited = { code, signal };
        resolve(exited);
      });
    },
  );

  return {
    proc,
    stderr: () => text,
    async ready(): Promise<number> {
      // The serving line is emitted from `announceStartup`, which runs AFTER
      // the registry resolves — so matching it proves the child is bound and
      // `/readyz` has already moved `starting` -> `ready`. A stderr matcher is
      // the only channel available: the descriptor-carried counter line belongs
      // to `serve-entry.ts`, and this child is the real entrypoint.
      await until(
        () => /serving MCP over http at /.test(text) || exited !== null,
        `the child's serving line.\n--- stderr ---\n${text}`,
      );
      assert.equal(exited, null, `the child exited before serving:\n${text}`);
      const port = /serving MCP over http at [^\s]*?:(\d+)\/mcp/.exec(text)?.[1];
      assert.ok(port !== undefined, `the serving line carried no port:\n${text}`);
      return Number(port);
    },
    exited: () => exitPromise,
  };
}

/** The one line no `windows-latest` leg can ever produce. */
async function signalAndConfirmHandled(child: Entrypoint): Promise<bigint> {
  const killedAt = process.hrtime.bigint();
  child.proc.kill('SIGTERM');
  await until(
    () => child.stderr().includes('SIGTERM received — draining'),
    `the child's signal handler to run.\n--- stderr ---\n${child.stderr()}`,
  );
  return killedAt;
}

function elapsedMsSince(startedAt: bigint): number {
  return Number(process.hrtime.bigint() - startedAt) / 1e6;
}

/**
 * Every awaited drain step is individually caught and logs one line on failure,
 * so the ABSENCE of those lines is the evidence the sequence ran to completion
 * rather than limping through it.
 */
function assertNoDrainErrors(stderr: string): void {
  assert.doesNotMatch(
    stderr,
    /unifi-mcp: drain (close-listener|begin-drain|close-connections|close-runtime) —/,
    `a drain step failed and was swallowed by its guard:\n${stderr}`,
  );
  assert.doesNotMatch(stderr, /unifi-mcp: ERROR /, `the child reported an error:\n${stderr}`);
}

// ===========================================================================
// 1. MECH-SIGNAL — /readyz says draining while /healthz stays 200, POLLED
//    across the real grace window (C13, criterion 1)
// ===========================================================================

describe('a delivered SIGTERM flips /readyz while /healthz keeps answering', {
  skip: MECH_SIGNAL_SKIP,
}, () => {
  test('both probes are polled over real HTTP for the whole grace window', async () => {
    const child = spawnEntrypoint(entrypointEnv());
    const port = await child.ready();

    // The BEFORE half of the transition. Without it "readyz says draining"
    // would be satisfied by a server that never said `ready` at all.
    const beforeReady = await probe(port, '/readyz');
    const beforeHealth = await probe(port, '/healthz');
    assert.equal(beforeReady.status, 200, `/readyz was not ready before the signal: ${beforeReady.text}`);
    assert.equal(beforeReady.body, 'ready\n');
    assert.equal(beforeHealth.status, 200);
    assert.equal(beforeHealth.body, 'ok\n');

    const killedAt = await signalAndConfirmHandled(child);

    // The poll loop. Not one sample: a liveness probe that fails at ANY point
    // during the drain gets the container killed mid-drain, converting the
    // graceful shutdown into the SIGKILL NFR-27 exists to prevent — and a
    // single sample cannot distinguish "200 throughout" from "200 once".
    const readySamples: RawResult[] = [];
    const healthSamples: RawResult[] = [];
    for (let i = 0; i < 200; i += 1) {
      const readiness = await probe(port, '/readyz');
      const liveness = await probe(port, '/healthz');
      // The listener closes when the pre-drain hold expires; a refused
      // connection is the END of the window, not a failure.
      if (readiness.refused || liveness.refused) break;
      readySamples.push(readiness);
      healthSamples.push(liveness);
      await delay(100);
    }

    const result = await child.exited();
    const stderr = child.stderr();

    assert.ok(
      readySamples.length >= 5,
      `only ${readySamples.length} probe pairs landed inside the grace window — the window was ` +
        `not observed at all.\n--- stderr ---\n${stderr}`,
    );
    for (const [index, sample] of readySamples.entries()) {
      assert.equal(sample.status, 503, `/readyz sample ${index} was ${String(sample.status)}`);
      assert.equal(sample.body, 'draining\n', `/readyz sample ${index} body: ${sample.body}`);
    }
    for (const [index, sample] of healthSamples.entries()) {
      assert.equal(sample.status, 200, `/healthz sample ${index} was ${String(sample.status)}`);
      assert.equal(sample.body, 'ok\n', `/healthz sample ${index} body: ${sample.body}`);
    }

    // The window really was the pre-drain hold, and the process really did
    // leave it. A run whose last sample landed at t+50 ms would satisfy every
    // assertion above while proving nothing about the hold.
    const observedMs = elapsedMsSince(killedAt);
    assert.ok(
      observedMs >= PREDRAIN_HOLD_MS * 0.5,
      `the listener stopped answering after ${observedMs} ms — the ${PREDRAIN_HOLD_MS} ms ` +
        `pre-drain hold did not happen`,
    );
    assert.deepEqual(result, { code: EXIT_CODES.clean, signal: null }, stderr);
    assertNoDrainErrors(stderr);
  });
});

// ===========================================================================
// 2. MECH-SIGNAL — a connection arriving inside the hold is answered 503 AND
//    logged, in the same observed request (C15, criterion 2)
// ===========================================================================

describe('a connection arriving after SIGTERM, inside the pre-drain hold', {
  skip: MECH_SIGNAL_SKIP,
}, () => {
  test('is answered 503 with the drain body and produces one log line', async () => {
    const child = spawnEntrypoint(entrypointEnv());
    const port = await child.ready();
    await signalAndConfirmHandled(child);

    // Nothing has spoken MCP to this child yet, so the count below is the count
    // of lines this ONE request produced — which is what makes "the response
    // and the log line, in the same observed request" a real pairing rather
    // than two independent observations that happen to co-occur.
    const before = child.stderr();
    assert.equal(
      (before.match(/unifi-mcp: req .*path=mcp/g) ?? []).length,
      0,
      'the child had already logged an /mcp request before the case opened one',
    );

    // A NEW TCP connection, accepted and answered — the whole point of the
    // hold. Closing the listener at t0 refuses this at the kernel, where no
    // request is parsed and no line can ever be written, so every rolling
    // deploy drops client connections and the operator sees client-side errors
    // correlated with deploys and nothing whatsoever in the logs.
    const answered = await rawExchange(
      port,
      mcpHeaders(),
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    );

    assert.equal(answered.status, 503, `expected a 503; got:\n${answered.text}`);
    assert.match(answered.text, /Connection: close/);
    assert.ok(
      answered.body.includes(DRAIN_REFUSAL_MESSAGE),
      `the drain body was not the shared message. Got:\n${answered.text}`,
    );

    // `reject_reason=draining` is the AR-7 token that stops an operator
    // conflating a rolling deploy with a capacity incident — two conditions
    // with opposite remedies. The line is read off the child's real stderr,
    // not off an in-process observer seam.
    await until(
      () => /unifi-mcp: req .*path=mcp.*reject_reason=draining/.test(child.stderr()),
      `the drain refusal line on the child's stderr.\n--- stderr ---\n${child.stderr()}`,
    );

    const lines = (child.stderr().match(/unifi-mcp: req .*path=mcp[^\n]*/g) ?? []);
    assert.equal(
      lines.length,
      1,
      `one request must produce exactly one line; got ${lines.length}:\n${lines.join('\n')}`,
    );
    const line = lines[0] ?? '';
    assert.match(line, /status=503/);
    assert.match(line, /reject_reason=draining/);
    assert.match(line, /path=mcp/);
    assert.match(line, /method=POST/);

    const result = await child.exited();
    assert.deepEqual(result, { code: EXIT_CODES.clean, signal: null }, child.stderr());
    assertNoDrainErrors(child.stderr());
  });
});

// ===========================================================================
// 3. MECH-SIGNAL — the four shutdown states, and the hard stop (C18,
//    criterion 3)
//
// Every case here reads the CHILD'S OWN exit status. That is only possible
// because the child is `src/index.ts`: its auto-run guard is the one place in
// `src/` permitted to end the process and supplies the real `exit` hook, so a
// clean drain exits 0 by natural event-loop drain and an expired deadline exits
// 75. See this file's header for why `test/harness/serve-entry.ts` cannot be
// the venue for either.
// ===========================================================================

describe('the four shutdown states each exit 0 within the deadline', {
  skip: MECH_SIGNAL_SKIP,
}, () => {
  test('idle — nothing connected', async () => {
    const child = spawnEntrypoint(entrypointEnv());
    await child.ready();

    const killedAt = await signalAndConfirmHandled(child);
    const result = await child.exited();
    const elapsed = elapsedMsSince(killedAt);

    assert.deepEqual(result, { code: EXIT_CODES.clean, signal: null }, child.stderr());
    assert.ok(elapsed < DEADLINE_MS, `the idle drain took ${elapsed} ms`);
    assertNoDrainErrors(child.stderr());
  });

  test('an IDLE KEEP-ALIVE connection is open and carries no request', async () => {
    const child = spawnEntrypoint(entrypointEnv());
    const port = await child.ready();

    // One answered request, then the socket is left open and idle. Without the
    // drain proceeding past `httpServer.close()` immediately, this hangs for
    // the whole `keepAliveTimeout` — a failure that appears ONLY in production,
    // as a pause lasting the orchestrator's entire grace period.
    const keepAlive = connect({ host: '127.0.0.1', port });
    let seen = '';
    keepAlive.setEncoding('utf8');
    keepAlive.on('data', (chunk: string) => {
      seen += chunk;
    });
    await new Promise<void>((resolve, reject) => {
      keepAlive.once('error', reject);
      keepAlive.on('connect', () => {
        keepAlive.write(
          ['GET /healthz HTTP/1.1', 'Host: 127.0.0.1', 'Connection: keep-alive', '', ''].join(
            '\r\n',
          ),
        );
        resolve();
      });
    });
    await until(() => seen.includes('ok\n'), 'the keep-alive probe response');

    const killedAt = await signalAndConfirmHandled(child);
    const result = await child.exited();
    const elapsed = elapsedMsSince(killedAt);
    keepAlive.destroy();

    assert.deepEqual(result, { code: EXIT_CODES.clean, signal: null }, child.stderr());
    assert.ok(elapsed < DEADLINE_MS, `the keep-alive drain took ${elapsed} ms`);
    assertNoDrainErrors(child.stderr());
  });

  test('an OPEN SSE STREAM receives the terminal frame and its socket is destroyed', async () => {
    const child = spawnEntrypoint(entrypointEnv());
    const port = await child.ready();

    const sessionId = await openRawSession(port);
    const stream = await openSseStream(port, sessionId);

    const killedAt = await signalAndConfirmHandled(child);
    const result = await child.exited();
    const elapsed = elapsedMsSince(killedAt);

    // BOTH halves. `transport.close()` writes no `result` and no `error` — it
    // ends the response body and leaves an idle keep-alive socket, so a client
    // would otherwise see a silently truncated stream. Only
    // `closeAllConnections()` destroys an SSE-carrying socket.
    assert.ok(
      stream.text().includes(DRAIN_REFUSAL_MESSAGE),
      `no terminal frame reached the open stream. Got:\n${stream.text()}`,
    );
    assert.ok(stream.closed(), 'the SSE-carrying socket was never destroyed');
    stream.destroy();

    assert.deepEqual(result, { code: EXIT_CODES.clean, signal: null }, child.stderr());
    assert.ok(elapsed < DEADLINE_MS, `the SSE drain took ${elapsed} ms`);
    assertNoDrainErrors(child.stderr());
  });

  test('an IN-FLIGHT request completes, and its client receives a complete response', async (t) => {
    // A REAL outbound request, paced so the signal lands while it is in flight.
    // This is the US-17 edge in its integration form: the handler is inside
    // `credentials.resolveFor()` and then inside a real socket read when
    // SIGTERM arrives, with NO injected collaborator anywhere in the child.
    const origin = await startPacedOrigin(PACED_RESPONSE_MS);
    t.after(async () => {
      await origin.close();
    });

    const child = spawnEntrypoint(
      entrypointEnv({
        UNIFI_LOCAL_HOST: origin.host,
        UNIFI_LOCAL_API_KEY: `local-${'l'.repeat(34)}`,
        UNIFI_NETWORK_TRANSPORT: 'local',
        UNIFI_LOCAL_TLS_INSECURE: 'true',
      }),
    );
    const port = await child.ready();
    const sessionId = await openRawSession(port);

    let answer: RawResult | null = null;
    const call = rawExchange(
      port,
      mcpHeaders(sessionId),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        // `site_id` is REQUIRED; without it the call fails a precondition and
        // never reaches a socket, so nothing would ever be in flight.
        params: { name: OUTBOUND_TOOL, arguments: { site_id: 'default' } },
      }),
      (text) => text.includes('"result"') || text.includes('"error"'),
      20_000,
    ).then((value) => {
      answer = value;
      return value;
    });

    await until(() => origin.received() >= 1, 'the outbound request to reach the origin');
    assert.equal(answer, null, 'the outbound request had already been answered');

    const killedAt = await signalAndConfirmHandled(child);
    const answered = await call;
    const result = await child.exited();
    const elapsed = elapsedMsSince(killedAt);

    // FR-70's reason for existing: a client with an outstanding request gets a
    // COMPLETE response rather than a truncated stream.
    assert.ok(
      answered.text.includes('"id":2'),
      `the in-flight call was truncated. Got:\n${answered.text}`,
    );
    assert.ok(
      answered.text.includes('"result"'),
      `the in-flight call did not complete successfully. Got:\n${answered.text}`,
    );
    assert.deepEqual(result, { code: EXIT_CODES.clean, signal: null }, child.stderr());
    assert.ok(elapsed < DEADLINE_MS, `the in-flight drain took ${elapsed} ms`);
    assertNoDrainErrors(child.stderr());
  });
});

describe('a STALLED request reaches the hard stop', { skip: MECH_SIGNAL_SKIP }, () => {
  test('the process destroys its sockets and exits 75 within deadline + 1 s', async (t) => {
    // The connector timeout is left at its 25 000 ms default here, so the
    // outbound attempt CANNOT finish inside the shutdown budget however
    // patiently the drain waits. That is the condition the hard stop exists
    // for, and the child says so itself at startup with the §3.5 budget
    // warning — which is why `assertNoDrainErrors` is not called below.
    const origin = await startPacedOrigin(null);
    t.after(async () => {
      await origin.close();
    });

    const child = spawnEntrypoint({
      ...entrypointEnv({
        UNIFI_LOCAL_HOST: origin.host,
        UNIFI_LOCAL_API_KEY: `local-${'l'.repeat(34)}`,
        UNIFI_NETWORK_TRANSPORT: 'local',
        UNIFI_LOCAL_TLS_INSECURE: 'true',
      }),
      UNIFI_CONNECTOR_TIMEOUT_MS: '25000',
    });
    const port = await child.ready();
    const sessionId = await openRawSession(port);

    const call = rawExchange(
      port,
      mcpHeaders(sessionId),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: OUTBOUND_TOOL, arguments: { site_id: 'default' } },
      }),
      (text) => text.includes('"result"') || text.includes('"error"'),
      30_000,
    ).catch(() => null);

    await until(() => origin.received() >= 1, 'the outbound request to reach the origin');

    const killedAt = await signalAndConfirmHandled(child);
    const result = await child.exited();
    const elapsed = elapsedMsSince(killedAt);
    await call;

    // 75 means THE DRAIN DEADLINE EXPIRED and nothing else — which is why a
    // second signal escalates to 143 or 130 rather than reusing it.
    assert.equal(
      result.code,
      EXIT_CODES.deadline,
      `expected the hard stop's exit 75; got ${JSON.stringify(result)}\n${child.stderr()}`,
    );
    assert.equal(
      result.signal,
      null,
      `the child was killed by ${String(result.signal)} — this is the SIGKILL NFR-27 prevents`,
    );
    // Both sides of the bound. Below the deadline would mean something other
    // than the deadline ended the process; above deadline + 1 s is the failure
    // NFR-27 names.
    assert.ok(
      elapsed >= DEADLINE_MS - 500,
      `the process exited after ${elapsed} ms — the ${DEADLINE_MS} ms deadline was not what ended it`,
    );
    assert.ok(
      elapsed < DEADLINE_MS + 1_000,
      `the process took ${elapsed} ms, past deadline + 1 s`,
    );
  });
});

// ===========================================================================
// 4. THE PORTABLE HALF — the same three requirements through the
//    directly-invoked drain(). UNSCOPED: runs on windows-latest too.
//
// `drain(reason)` is idempotent and directly callable precisely so this
// section can exist. It is the Windows leg's cover for sections 1 to 3 — the
// requirements are never skipped, only their delivery mechanism is — and it is
// what makes MECH_SIGNAL_SKIP's reason string true.
// ===========================================================================

interface ArmedTimer {
  readonly kind: DrainTimerKind;
  readonly ms: number;
  fired: boolean;
  cleared: boolean;
  fire(): void;
}

interface DrainClock {
  readonly armed: readonly ArmedTimer[];
  readonly factory: DrainTimerFactory;
  /** Fires every live timer of this kind. Returns how many actually fired. */
  fire(kind: DrainTimerKind): number;
}

/**
 * @param auto Kinds fired the instant they are armed.
 *
 * The 5 000 ms pre-drain hold and the 1 000 ms session budget are FIXED
 * constants no environment variable can lower (FR-63 closes the `UNIFI_HTTP_*`
 * family), so an in-process case that did not inject this seam would wait them
 * out in real seconds — and this section runs on every leg, six times.
 */
function drainClock(auto: readonly DrainTimerKind[] = ['predrain']): DrainClock {
  const armed: ArmedTimer[] = [];
  const autoSet = new Set(auto);

  const factory: DrainTimerFactory = (onFire, ms, kind) => {
    const record: ArmedTimer = {
      kind,
      ms,
      fired: false,
      cleared: false,
      fire(): void {
        if (record.fired || record.cleared) return;
        record.fired = true;
        onFire();
      },
    };
    armed.push(record);
    if (autoSet.has(kind)) record.fire();
    return {
      clear: (): void => {
        record.cleared = true;
      },
      unref: (): void => undefined,
    };
  };

  return {
    armed,
    factory,
    fire(kind): number {
      const pending = armed.filter(
        (timer) => timer.kind === kind && !timer.fired && !timer.cleared,
      );
      for (const timer of pending) timer.fire();
      return pending.length;
    },
  };
}

interface Rig {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly clock: DrainClock;
  readonly steps: readonly string[];
  /** `ServingDeps.exit` calls, in order. NEVER `process.exit`. */
  readonly exits: readonly number[];
  /** `ServingDeps.setExitCode` calls, in order. NEVER `process.exitCode`. */
  readonly codes: readonly number[];
  readonly logs: readonly string[];
}

interface RigOptions {
  readonly clock?: DrainClock;
  readonly handlers?: Record<string, ToolHandler>;
}

/**
 * One bound listener, port 0, with the drain clock and the exit hook injected.
 *
 * `exit` and `setExitCode` are injected on EVERY rig and that is not
 * convenience: without them drain step 10 mutates the test runner's own exit
 * status, and the hard stop calls the real `process.exit(75)` inside a runner
 * whose event loop is always alive — killing the file mid-suite with no
 * diagnostic. Injecting `exit` is also what makes the drain CLEAR its deadline
 * timer instead of un-reffing it, which is architecture §10.5's leak clause.
 */
async function rig(t: TestContext, options: RigOptions = {}): Promise<Rig> {
  const clock = options.clock ?? drainClock();
  const steps: string[] = [];
  const exits: number[] = [];
  const codes: number[] = [];
  const logs: string[] = [];

  const instruments = createInstruments({
    env: {
      UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_BIND: '127.0.0.1',
      UNIFI_HTTP_PORT: '0',
      UNIFI_HTTP_TOKEN: SECRET,
      UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: String(DEADLINE_MS),
    },
    keychain: null,
  });
  const observer: ServingObserver = {
    ...instruments.observer,
    onDrainStep: (step: string) => steps.push(step),
    onRequestLog: (line: string) => logs.push(line),
  };

  const core = buildRuntimeCore(instruments.deps);
  for (const [name, handler] of Object.entries(options.handlers ?? {})) {
    core.handlers[name] = handler;
  }

  const deps: HttpServingDeps = {
    setDrainTimer: clock.factory,
    exit: (code: number) => exits.push(code),
    setExitCode: (code: number) => codes.push(code),
  };
  const serving = await startHttp(core, observer, deps);
  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  await core.ready;
  assert.equal(core.readyError, null, `the rig's registry failed: ${String(core.readyError)}`);
  for (let i = 0; i < 4; i += 1) await new Promise((resolve) => setImmediate(resolve));

  return { serving, core, port: serving.address.port, clock, steps, exits, codes, logs };
}

describe('PORTABLE (all three legs) — the drain state machine, no signal delivered', () => {
  test('POLLED: /readyz reports draining and /healthz stays 200 for the whole hold', async (t) => {
    // Section 1's cover. The hold is held open by NOT auto-firing the predrain
    // timer, so the probes below are answered while the drain is genuinely
    // parked in step 2a rather than after it has completed.
    const clock = drainClock([]);
    const r = await rig(t, { clock });

    const before = await probe(r.port, '/readyz');
    assert.equal(before.body, 'ready\n');

    const outcome = r.serving.drain('signal');
    await until(() => r.steps.includes('predrain-hold'), 'the drain to park in the hold');

    const readySamples: RawResult[] = [];
    const healthSamples: RawResult[] = [];
    for (let i = 0; i < 8; i += 1) {
      readySamples.push(await probe(r.port, '/readyz'));
      healthSamples.push(await probe(r.port, '/healthz'));
    }

    for (const [index, sample] of readySamples.entries()) {
      assert.equal(sample.status, 503, `/readyz sample ${index}: ${sample.text}`);
      assert.equal(sample.body, 'draining\n');
    }
    for (const [index, sample] of healthSamples.entries()) {
      assert.equal(sample.status, 200, `/healthz sample ${index}: ${sample.text}`);
      assert.equal(sample.body, 'ok\n');
    }

    clock.fire('predrain');
    assert.equal(await outcome, 'clean');
    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
  });

  test('a connection opened inside the hold is answered 503 AND logged, once', async (t) => {
    // Section 2's cover.
    const clock = drainClock([]);
    const r = await rig(t, { clock });

    const outcome = r.serving.drain('signal');
    await until(() => r.steps.includes('predrain-hold'), 'the drain to park in the hold');

    const before = r.logs.length;
    const answered = await rawExchange(
      r.port,
      mcpHeaders(),
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    );

    assert.equal(answered.status, 503, answered.text);
    assert.match(answered.text, /Connection: close/);
    assert.ok(answered.body.includes(DRAIN_REFUSAL_MESSAGE), answered.text);

    await until(
      () => r.logs.length > before,
      'the log line for the request that was just answered',
    );
    const emitted = r.logs.slice(before);
    assert.equal(emitted.length, 1, `one request, one line; got:\n${emitted.join('\n')}`);
    assert.match(emitted[0] ?? '', /status=503/);
    assert.match(emitted[0] ?? '', /reject_reason=draining/);
    assert.match(emitted[0] ?? '', /path=mcp/);

    clock.fire('predrain');
    assert.equal(await outcome, 'clean');
  });

  test('the four shutdown states each resolve clean and set exit code 0', async (t) => {
    // Section 3's cover for the exit-0 half. The states are exercised in one
    // case because on this leg the assertion is the drain's OUTCOME and the
    // code it set, and four separate rigs would assert the same two facts four
    // times over at four times the registry-build cost.
    const held: Array<{ close: () => void }> = [];
    t.after(() => {
      for (const entry of held) entry.close();
    });

    // (a) idle
    const idle = await rig(t);
    assert.equal(await idle.serving.drain('signal'), 'clean');
    assert.deepEqual([...idle.codes], [EXIT_CODES.clean]);
    assert.ok(!idle.steps.includes(HTTP_HARD_STOP_STEP));

    // (b) idle keep-alive open
    const keepAliveRig = await rig(t);
    const socket = connect({ host: '127.0.0.1', port: keepAliveRig.port });
    let seen = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      seen += chunk;
    });
    held.push({ close: () => socket.destroy() });
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.on('connect', () => {
        socket.write(
          ['GET /healthz HTTP/1.1', 'Host: 127.0.0.1', 'Connection: keep-alive', '', ''].join(
            '\r\n',
          ),
        );
        resolve();
      });
    });
    await until(() => seen.includes('ok\n'), 'the keep-alive probe response');
    assert.equal(await keepAliveRig.serving.drain('signal'), 'clean');
    assert.deepEqual([...keepAliveRig.codes], [EXIT_CODES.clean]);

    // (c) open SSE stream
    const sseRig = await rig(t);
    const sessionId = await openRawSession(sseRig.port);
    const stream = await openSseStream(sseRig.port, sessionId);
    held.push({ close: () => stream.destroy() });
    assert.equal(await sseRig.serving.drain('signal'), 'clean');
    // Polled rather than read once: the frame is written to a real socket at
    // step 7 and this side of it reads asynchronously, so a synchronous read
    // the instant `drain()` resolves races the kernel rather than the server.
    await until(
      () => stream.text().includes(DRAIN_REFUSAL_MESSAGE),
      `the terminal frame on the open stream. Got:\n${stream.text()}`,
    );
    await until(() => stream.closed(), 'the SSE-carrying socket to be destroyed');
    assert.deepEqual([...sseRig.codes], [EXIT_CODES.clean]);

    // (d) an in-flight request
    let entered = false;
    let release = (): void => undefined;
    const inFlightRig = await rig(t, {
      handlers: {
        [HANDLER_TOOL]: async () => {
          entered = true;
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          return { content: [{ type: 'text', text: 'complete' }] };
        },
      },
    });
    const inFlightSession = await openRawSession(inFlightRig.port);
    const call = rawExchange(
      inFlightRig.port,
      mcpHeaders(inFlightSession),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: HANDLER_TOOL, arguments: {} },
      }),
      (text) => text.includes('"result"') || text.includes('"error"'),
    );
    // The handler must be INSIDE the tracked promise before the drain begins:
    // dispatch closes at step 2, so a call that had not yet arrived would be
    // refused with the drain body and this case would assert nothing about the
    // in-flight wait it exists to exercise.
    await until(() => entered, 'the tool handler to be entered');
    const draining = inFlightRig.serving.drain('signal');
    await until(() => inFlightRig.steps.includes('await-in-flight'), 'the in-flight wait');
    release();
    assert.equal(await draining, 'clean');
    const answered = await call;
    assert.ok(answered.text.includes('complete'), `truncated response:\n${answered.text}`);
    assert.deepEqual([...inFlightRig.codes], [EXIT_CODES.clean]);
  });

  test('a stalled request expires the deadline and takes exit 75', async (t) => {
    // Section 3's cover for the hard stop. The fast-forward is PROVABLE rather
    // than merely fast: the drain is asserted still pending before the deadline
    // timer is fired and `'deadline'` after, so this run reached 75 because the
    // deadline logic ran and not because the case happened not to crash.
    const clock = drainClock(['predrain']);
    let entered = false;
    const r = await rig(t, {
      clock,
      handlers: {
        [HANDLER_TOOL]: () =>
          new Promise<never>(() => {
            entered = true;
          }),
      },
    });

    const sessionId = await openRawSession(r.port);
    void rawExchange(
      r.port,
      mcpHeaders(sessionId),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: HANDLER_TOOL, arguments: {} },
      }),
      (text) => text.includes('"result"') || text.includes('"error"'),
      2_000,
    ).catch(() => null);

    // The stall must be INSIDE the tracked promise before the drain begins.
    // Without this the drain snapshots an empty in-flight set, resolves clean,
    // and the case passes for the wrong reason — the deadline never expires
    // because there was never anything to wait for.
    await until(() => entered, 'the stalled tool handler to be entered');

    const outcome = r.serving.drain('signal');
    await until(() => r.steps.includes('await-in-flight'), 'the drain to reach the in-flight wait');

    let settled = false;
    void outcome.then(() => {
      settled = true;
    });
    for (let i = 0; i < 4; i += 1) await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false, 'the drain resolved before the deadline was fired');

    assert.equal(clock.fire('deadline'), 1, 'no live deadline timer was armed');
    assert.equal(await outcome, 'deadline');

    assert.ok(r.steps.includes(HTTP_HARD_STOP_STEP), `no hard stop:\n${r.steps.join(' ')}`);
    assert.deepEqual([...r.codes], [EXIT_CODES.deadline]);
    assert.deepEqual([...r.exits], [EXIT_CODES.deadline]);
    // 75 is reserved for the deadline. `forcedTermination` and
    // `forcedInterrupt` exist so an operator pressing Ctrl-C twice never fires
    // ADR-05's reopen trigger on pure noise.
    assert.notEqual(EXIT_CODES.deadline, EXIT_CODES.forcedTermination);
    assert.notEqual(EXIT_CODES.deadline, EXIT_CODES.forcedInterrupt);
  });
});
