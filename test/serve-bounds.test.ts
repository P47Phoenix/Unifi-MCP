/**
 * US-28a (Wave J, slot J1) — the six inbound bounds, by provenance AND effect.
 *
 * Suite C of the test strategy, the bounds half: C31, C32, C33, C34.
 *
 * ## What this file is, and what it deliberately is not
 *
 * This is a VERIFICATION suite. It adds no production behaviour; every claim
 * below is asserted against the pipeline US-22 already shipped. It is written
 * to be INDEPENDENT of `test/serve-http-pipeline.test.ts` rather than a second
 * copy of it — same requirement, different instrument, different probe values,
 * and in three places a strictly stronger form:
 *
 *   - **A different byte instrument.** US-22 counts bytes with a client-side
 *     accumulator it maintains itself. This file reads `socket.bytesWritten`
 *     and `socket.bytesRead` — the kernel's own counters on the client socket.
 *     Two independent instruments agreeing is worth more than one instrument
 *     asserted twice.
 *   - **A differential, not a bracket.** "The bound moves with configuration"
 *     is asserted by running the SAME probe against TWO listeners configured at
 *     TWO distinct values and requiring OPPOSITE outcomes. A single-listener
 *     bracket can pass against an implementation that hardcoded a constant that
 *     happens to sit inside the bracket; a differential cannot.
 *   - **An exact boundary where the boundary is ours.** The body cap is
 *     enforced by this project's own `readBoundedBody` as `total > limit`, so
 *     the transition is exactly one byte wide and is asserted as such. The
 *     header cap is enforced by llhttp, whose accounting carries a small,
 *     shape-dependent constant, so the transition is LOCATED by search and then
 *     asserted to (a) be one byte wide and (b) MOVE BY EXACTLY the configured
 *     delta between two runs. That second half is an exact assertion about the
 *     configured value with no dependence on llhttp's constant at all.
 *
 * ## Why "not the Node default" is never used as evidence
 *
 * Two of the six §5.15.1 defaults coincide with Node's own: `keepAliveTimeout`
 * is configured at 5 000 and Node's default is 5 000; the header cap is
 * configured at 16 384 and `http.maxHeaderSize` defaults to 16 384. A test that
 * reads 5 000 off the server object at the documented default has learned
 * nothing about whether this configuration wired it. So every bound here is
 * exercised at a PROBE VALUE that collides with neither its §5.15.1 default nor
 * any Node default — and §1's first case asserts that non-collision property of
 * the probe set itself, so a later edit cannot quietly re-introduce a
 * coincidence and turn the rest of the file vacuous.
 *
 * ## Standing rules this file conforms to
 *
 * Every listener binds `127.0.0.1` port **0** — never a fixed port, so this
 * file cannot collide with the three sibling suites in the same wave. Nothing
 * here imports `src/index.ts` (S-09); listeners come from `buildRuntimeCore` +
 * `startHttp` directly. No case waits on a production-length timeout: the three
 * time-bounded bounds are probed at a few hundred milliseconds each.
 */
import assert from 'node:assert/strict';
import {
  createServer as createNodeHttpServer,
  maxHeaderSize as NODE_DEFAULT_MAX_HEADER_SIZE,
  type Server,
} from 'node:http';
import { connect, createServer as createTcpServer, type Socket } from 'node:net';
import { dirname, join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadConfig } from '../src/config.js';
import {
  createServingOptions,
  startHttp,
  PROBE_CONNECTION_HEADROOM,
  type HttpServing,
  type ResolvedInboundBounds,
} from '../src/serve/http.js';
import { buildRuntimeCore, type RuntimeCore } from '../src/serve/runtime.js';

import { createInstruments, type Instruments } from './harness/counters.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** The inbound shared secret. 40 characters, over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;

// ---------------------------------------------------------------------------
// The probe values
// ---------------------------------------------------------------------------

/**
 * One distinct probe value per bound.
 *
 * Chosen so that no value equals its own §5.15.1 default, no value equals any
 * Node default, and no two values are equal to each other — all three asserted
 * in §1.1 rather than asserted by the author's eye.
 *
 * The three durations are deliberately small. The requirement is about the
 * configured value being the one in force, not about how large it is, and a
 * suite that waited 10 000 ms to learn that would be paid for on every CI run
 * of every future change.
 */
const PROBE = Object.freeze({
  headersTimeout: 275,
  requestTimeout: 900,
  keepAliveTimeout: 325,
  maxHeaderSize: 3072,
  maxConnections: 7,
  maxBodyBytes: 2900,
} satisfies ResolvedInboundBounds);

/** The §5.15.1 documented defaults, transcribed from `src/config.ts:609-614`. */
const DOCUMENTED_DEFAULTS = Object.freeze({
  headersTimeout: 10_000,
  requestTimeout: 30_000,
  keepAliveTimeout: 5_000,
  maxHeaderSize: 16_384,
  maxConnections: 64,
  maxBodyBytes: 1_048_576,
} satisfies ResolvedInboundBounds);

/** The environment variable each bound is resolved from (§5.15.1). */
const VARIABLE_OF = Object.freeze({
  headersTimeout: 'UNIFI_HTTP_HEADERS_TIMEOUT_MS',
  requestTimeout: 'UNIFI_HTTP_REQUEST_TIMEOUT_MS',
  keepAliveTimeout: 'UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS',
  maxHeaderSize: 'UNIFI_HTTP_MAX_HEADER_BYTES',
  maxConnections: 'UNIFI_HTTP_MAX_CONNECTIONS',
  maxBodyBytes: 'UNIFI_HTTP_MAX_BODY_BYTES',
} satisfies Record<keyof ResolvedInboundBounds, string>);

const BOUND_NAMES = Object.keys(VARIABLE_OF) as (keyof ResolvedInboundBounds)[];

/** Every bound at its probe value, as an environment fragment. */
function probeEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of BOUND_NAMES) out[VARIABLE_OF[name]] = String(PROBE[name]);
  return out;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function httpEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    // PORT 0, in every single case in this file. A fixed port would collide
    // with the three sibling suites this wave runs concurrently.
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    ...extra,
  };
}

interface Bound {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly instruments: Instruments;
  readonly lines: string[];
  /** The `node:http` server, captured through the `createHttpServer` seam. */
  readonly server: Server;
}

/**
 * Start one listener on an ephemeral loopback port and register its teardown.
 *
 * Teardown goes on the test context rather than a file-level `after()`: an
 * in-process listener holds sockets and arms timers, and a file that leaks one
 * hangs the runner with no diagnostic instead of failing.
 */
async function boundServer(t: TestContext, env: Record<string, string>): Promise<Bound> {
  const lines: string[] = [];
  const instruments = createInstruments({
    env: { ...env },
    keychain: null,
    onLine: (line) => lines.push(line),
  });
  const core = buildRuntimeCore(instruments.deps);

  let server: Server | null = null;
  const serving = await startHttp(core, instruments.observer, {
    warn: (line) => lines.push(line),
    createHttpServer: (options, handler) => {
      server = createNodeHttpServer(options, handler);
      return server;
    },
  });

  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  assert.ok(server !== null, 'the http server seam was never used');
  return {
    serving,
    core,
    port: serving.address.port,
    instruments,
    lines,
    server: server as unknown as Server,
  };
}

/** Wait until the registry has resolved and readiness has flipped to `ready`. */
async function waitReady(bound: Bound): Promise<void> {
  await bound.core.ready;
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// The raw socket client, with the kernel's own byte counters as the instrument
// ---------------------------------------------------------------------------

interface Wire {
  readonly text: string;
  readonly statusLine: string;
  readonly body: string;
  /** `socket.bytesWritten` at settle — bytes this client put on the wire. */
  readonly bytesWritten: number;
  /** `socket.bytesRead` at settle — bytes the server put on the wire. */
  readonly bytesRead: number;
  readonly closedByServer: boolean;
  readonly errorCode: string | null;
  readonly elapsedMs: number;
}

interface WireOptions {
  /** Silence, in ms, after which the exchange is considered finished. */
  readonly idleMs?: number;
  /** Drive the socket by hand instead of writing a fixed request. */
  readonly drive?: (socket: Socket, done: () => void) => void;
  readonly localAddress?: string;
}

/**
 * One exchange over a raw `net.Socket`, reporting the kernel's byte counters.
 *
 * `fetch` and `http.request` appear nowhere in this file: both hide the status
 * line and neither exposes the socket, so neither can carry a byte-counter
 * assertion at all.
 */
function wire(port: number, request: string, options: WireOptions = {}): Promise<Wire> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const startedAt = Date.now();
    let closedByServer = false;
    let errorCode: string | null = null;
    let settled = false;
    let idle: NodeJS.Timeout | null = null;

    const socket = connect({
      host: '127.0.0.1',
      port,
      ...(options.localAddress === undefined ? {} : { localAddress: options.localAddress }),
    });

    const settle = (): void => {
      if (settled) return;
      settled = true;
      if (idle !== null) clearTimeout(idle);
      // Read the counters BEFORE destroying: `destroy()` does not clear them,
      // but reading first keeps the measurement and the teardown independent.
      const bytesWritten = socket.bytesWritten;
      const bytesRead = socket.bytesRead;
      socket.destroy();
      const text = Buffer.concat(chunks).toString('latin1');
      const split = text.indexOf('\r\n\r\n');
      resolve({
        text,
        statusLine: text.split('\r\n')[0] ?? '',
        body: split === -1 ? '' : text.slice(split + 4),
        bytesWritten,
        bytesRead,
        closedByServer,
        errorCode,
        elapsedMs: Date.now() - startedAt,
      });
    };

    const bump = (): void => {
      if (idle !== null) clearTimeout(idle);
      idle = setTimeout(settle, options.idleMs ?? 250);
    };

    socket.on('connect', () => {
      if (options.drive !== undefined) options.drive(socket, settle);
      else socket.write(request);
      bump();
    });
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      bump();
    });
    socket.on('end', () => {
      closedByServer = true;
    });
    socket.on('error', (error: NodeJS.ErrnoException) => {
      errorCode = error.code ?? 'UNKNOWN';
      closedByServer = closedByServer || errorCode === 'ECONNRESET';
    });
    socket.on('close', settle);
  });
}

/** Build a request block. Header order is the caller's, verbatim. */
function raw(startLine: string, headers: readonly string[], body = ''): string {
  return `${[startLine, ...headers].join('\r\n')}\r\n\r\n${body}`;
}

// ---------------------------------------------------------------------------
// 1. Provenance — every bound reaches the object that governs behaviour
// ---------------------------------------------------------------------------

describe('US-28a §1: the six bounds by provenance, never by equality with a default', () => {
  test('the probe set collides with no §5.15.1 default, no Node default, and no sibling', async () => {
    // Node's own defaults, read off a bare server rather than transcribed, so
    // this guard tracks the runtime instead of a comment.
    const bare = createNodeHttpServer();
    const nodeKeepAlive = bare.keepAliveTimeout;
    const nodeDefaults = new Set<number>([
      bare.headersTimeout,
      bare.requestTimeout,
      nodeKeepAlive,
      NODE_DEFAULT_MAX_HEADER_SIZE,
    ]);
    // A callback, because closing a server that never listened otherwise emits
    // `ERR_SERVER_NOT_RUNNING` as an unhandled `error` event.
    bare.close(() => undefined);

    for (const name of BOUND_NAMES) {
      assert.notEqual(
        PROBE[name],
        DOCUMENTED_DEFAULTS[name],
        `${name}'s probe value equals its own §5.15.1 default — the run cannot distinguish a wired value from an ignored one`,
      );
      assert.equal(
        nodeDefaults.has(PROBE[name]),
        false,
        `${name}'s probe value ${PROBE[name]} is one of Node's own defaults, so reading it back proves nothing`,
      );
    }

    // Distinct from each other too: six equal probe values would let a
    // cross-wired implementation (headers timeout applied to the request
    // timeout, say) pass every provenance assertion below.
    const values = BOUND_NAMES.map((name) => PROBE[name]);
    assert.equal(
      new Set(values).size,
      values.length,
      `two bounds share a probe value: ${JSON.stringify(values)}`,
    );

    // And the two coincidence-prone ones are named explicitly, because they
    // are the reason this whole guard exists: at the documented default each
    // one is INDISTINGUISHABLE from the value Node would have supplied on its
    // own, so no assertion made at the default can be evidence of wiring.
    assert.equal(DOCUMENTED_DEFAULTS.keepAliveTimeout, nodeKeepAlive);
    assert.equal(DOCUMENTED_DEFAULTS.maxHeaderSize, NODE_DEFAULT_MAX_HEADER_SIZE);
  });

  test('C34 provenance: all six probe values reach the factory, the handle and the server object', async (t) => {
    const env = httpEnv(probeEnv());
    const bound = await boundServer(t, env);
    await waitReady(bound);

    // (a) The single exported factory — the one place a bound is resolved.
    const fromFactory = createServingOptions(loadConfig(env, { repoRoot: REPO_ROOT })).bounds;
    assert.deepEqual({ ...fromFactory }, { ...PROBE });

    // (b) The live handle, which is what a running listener reports.
    const fromHandle = bound.serving.bounds();
    assert.deepEqual({ ...fromHandle }, { ...PROBE });

    // (c) The environment link, field by field. This is the assertion that
    // fails for an implementation that reads one variable and applies it to
    // two fields, or that resolves a bound from a constant.
    for (const name of BOUND_NAMES) {
      assert.equal(
        fromHandle[name],
        Number(env[VARIABLE_OF[name]]),
        `${name} did not come from ${VARIABLE_OF[name]}`,
      );
    }

    // (d) The four bounds that ARE properties of the `node:http` server: read
    // off the server object the behaviour actually comes from, not off the
    // configuration that was supposed to reach it.
    assert.equal(bound.server.headersTimeout, PROBE.headersTimeout);
    assert.equal(bound.server.requestTimeout, PROBE.requestTimeout);
    assert.equal(bound.server.keepAliveTimeout, PROBE.keepAliveTimeout);
    assert.equal(bound.server.maxHeaderSize, PROBE.maxHeaderSize);

    // (e) The fifth is deliberately NOT a server property. `maxConnections` is
    // never assigned, because Node's accept layer has no route information and
    // could not implement the probe headroom; `connectionCounts()` is the
    // accessor that replaces it, and it starts empty.
    assert.equal(
      bound.server.maxConnections,
      undefined,
      'server.maxConnections was assigned — the accept layer cannot tell a probe from a flood',
    );
    assert.deepEqual(bound.serving.connectionCounts(), { total: 0, headroom: 0 });

    // (f) The sixth, `maxBodyBytes`, has no Node property at all; §3 asserts it
    // by effect. Here we only pin that the factory's object is immutable, so no
    // consumer can rewrite a bound after resolution.
    assert.ok(Object.isFrozen(fromFactory), 'the resolved bounds object is mutable');
    assert.ok(Object.isFrozen(fromHandle), 'the handle exposed a mutable bounds object');
  });

  test('the two bounds whose defaults coincide with the Node ones are wired, not inherited', async (t) => {
    // Run A: nothing configured. `keepAliveTimeout` reads 5 000 and
    // `maxHeaderSize` reads 16 384 — which is EXACTLY what an implementation
    // that never applied the configuration would also produce. This half of
    // the case is worthless on its own, and is here to be shown worthless.
    const inherited = await boundServer(t, httpEnv());
    assert.equal(inherited.server.keepAliveTimeout, DOCUMENTED_DEFAULTS.keepAliveTimeout);
    assert.equal(inherited.server.maxHeaderSize, DOCUMENTED_DEFAULTS.maxHeaderSize);

    // Run B: the same two variables at probe values. The server object moves.
    // An implementation that ignored the variables passes run A and fails here,
    // which is the whole point of running both.
    const configured = await boundServer(
      t,
      httpEnv({
        UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: String(PROBE.keepAliveTimeout),
        UNIFI_HTTP_MAX_HEADER_BYTES: String(PROBE.maxHeaderSize),
      }),
    );
    assert.equal(configured.server.keepAliveTimeout, PROBE.keepAliveTimeout);
    assert.equal(configured.server.maxHeaderSize, PROBE.maxHeaderSize);
    assert.notEqual(configured.server.keepAliveTimeout, inherited.server.keepAliveTimeout);
    assert.notEqual(configured.server.maxHeaderSize, inherited.server.maxHeaderSize);
  });
});

// ---------------------------------------------------------------------------
// 2. Effect — the header cap, measured on the wire
// ---------------------------------------------------------------------------

/**
 * The header cap is enforced by llhttp, and llhttp's byte accounting carries a
 * small constant offset that depends on the shape of the request rather than
 * on the configured cap. Measured on Node 20.20 for the exact block shape
 * `headerBlock()` builds, that offset is 24 bytes and is identical at caps
 * 1 024, 2 048, 4 096 and 16 384.
 *
 * That constant is NOT asserted, because it is Node's and not ours. What is
 * asserted is (a) the transition is exactly one byte wide, (b) it sits within
 * this window of the configured cap, and (c) it MOVES BY EXACTLY the
 * configured delta between two runs — which is an exact statement about the
 * configured value that the offset cancels out of entirely.
 */
const HEADER_ACCOUNTING_WINDOW = 64;

/** A `POST /mcp` request whose header block is exactly `totalBytes` long. */
function headerBlock(port: number, totalBytes: number): string {
  const head = `POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Length: 0\r\nX-Pad: `;
  const tail = '\r\n\r\n';
  const padding = totalBytes - head.length - tail.length;
  assert.ok(padding >= 0, `a ${totalBytes}-byte header block cannot hold the request line`);
  // Every byte is ASCII, so string length and byte length are the same number.
  return `${head}${'p'.repeat(padding)}${tail}`;
}

async function is431(port: number, totalBytes: number): Promise<boolean> {
  // Unauthenticated, so the under-cap answer is the uniform 401 — which carries
  // `Connection: close`. Both outcomes therefore close the socket at once and
  // the search below costs no idle timer at all.
  const result = await wire(port, headerBlock(port, totalBytes));
  return /^HTTP\/1\.1 431 /.test(result.statusLine);
}

/** Locate the largest header block this listener accepts, by bisection. */
async function headerThreshold(port: number, cap: number): Promise<number> {
  let accepted = 256;
  let refused = cap * 2 + 512;
  assert.equal(await is431(port, accepted), false, 'a minimal header block was already refused');
  assert.equal(await is431(port, refused), true, 'a doubled header block was still accepted');
  while (accepted + 1 < refused) {
    const mid = Math.floor((accepted + refused) / 2);
    if (await is431(port, mid)) refused = mid;
    else accepted = mid;
  }
  return accepted;
}

describe('US-28a §2: the header cap, by effect at two distinct probe values', () => {
  /**
   * Everything except the bound under test is set out of the way: a large
   * connection budget so the bisection's sockets never contend, and a
   * throttle ceiling above the number of 401s the bisection provokes, so a
   * `429` cannot be mistaken for an accepted header block.
   */
  const quiet = {
    UNIFI_HTTP_MAX_CONNECTIONS: '48',
    UNIFI_HTTP_AUTH_FAIL_PER_MIN: '5000',
    UNIFI_HTTP_HEADERS_TIMEOUT_MS: '8000',
    UNIFI_HTTP_REQUEST_TIMEOUT_MS: '9000',
  };

  /** The second probe value for this bound, distinct from PROBE.maxHeaderSize. */
  const SECOND_CAP = 5120;

  test('C34 effect: the 431 boundary is one byte wide and moves by exactly the configured delta', async (t) => {
    const first = await boundServer(
      t,
      httpEnv({ ...quiet, UNIFI_HTTP_MAX_HEADER_BYTES: String(PROBE.maxHeaderSize) }),
    );
    const second = await boundServer(
      t,
      httpEnv({ ...quiet, UNIFI_HTTP_MAX_HEADER_BYTES: String(SECOND_CAP) }),
    );
    await waitReady(first);
    await waitReady(second);

    assert.notEqual(SECOND_CAP, PROBE.maxHeaderSize);
    assert.notEqual(SECOND_CAP, DOCUMENTED_DEFAULTS.maxHeaderSize);
    assert.notEqual(SECOND_CAP, NODE_DEFAULT_MAX_HEADER_SIZE);

    const firstThreshold = await headerThreshold(first.port, PROBE.maxHeaderSize);
    const secondThreshold = await headerThreshold(second.port, SECOND_CAP);

    // (a) One byte wide, on both listeners, asserted directly rather than
    // inferred from the bisection having terminated.
    for (const [port, threshold] of [
      [first.port, firstThreshold],
      [second.port, secondThreshold],
    ] as const) {
      assert.equal(await is431(port, threshold), false, `${threshold} bytes was refused`);
      assert.equal(await is431(port, threshold + 1), true, `${threshold + 1} bytes was accepted`);
    }

    // (b) Each threshold sits at its own configured cap, within llhttp's
    // accounting window — never at the other listener's cap, and never at the
    // §5.15.1 or Node default of 16 384.
    assert.ok(
      firstThreshold >= PROBE.maxHeaderSize &&
        firstThreshold <= PROBE.maxHeaderSize + HEADER_ACCOUNTING_WINDOW,
      `a cap of ${PROBE.maxHeaderSize} refused at ${firstThreshold}`,
    );
    assert.ok(
      secondThreshold >= SECOND_CAP && secondThreshold <= SECOND_CAP + HEADER_ACCOUNTING_WINDOW,
      `a cap of ${SECOND_CAP} refused at ${secondThreshold}`,
    );

    // (c) THE EXACT ASSERTION. llhttp's constant offset is the same on both
    // listeners, so it cancels: the distance between the two observed
    // thresholds must equal the distance between the two configured caps, to
    // the byte. A hardcoded cap, a cap read from the wrong variable, or a cap
    // scaled or rounded on its way to `createServer` all fail here.
    assert.equal(
      secondThreshold - firstThreshold,
      SECOND_CAP - PROBE.maxHeaderSize,
      `the observed thresholds moved by ${secondThreshold - firstThreshold} for a configured delta of ${SECOND_CAP - PROBE.maxHeaderSize}`,
    );

    // (d) The differential in its plainest form: ONE block, TWO listeners,
    // OPPOSITE outcomes. A bracket assertion on a single listener cannot
    // distinguish a configured cap from a constant that happens to sit inside
    // the bracket; this can.
    const between = Math.floor((firstThreshold + secondThreshold) / 2);
    assert.equal(await is431(first.port, between), true);
    assert.equal(await is431(second.port, between), false);
  });

  test('C31/C32 effect: an oversized header block is refused without being consumed, by the socket byte counter', async (t) => {
    const bound = await boundServer(
      t,
      httpEnv({ ...quiet, UNIFI_HTTP_MAX_HEADER_BYTES: String(PROBE.maxHeaderSize) }),
    );
    await waitReady(bound);

    const flood = 2 * 1024 * 1024;
    const chunk = 'h'.repeat(16 * 1024);
    let offered = 0;

    // A header block orders of magnitude over the cap, pushed with
    // backpressure until the server answers or the socket goes away.
    const result = await wire(bound.port, '', {
      idleMs: 750,
      drive: (socket) => {
        socket.write(`POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:${bound.port}\r\nX-Pad: `);
        let stop = false;
        const halt = (): void => {
          stop = true;
        };
        socket.on('data', halt);
        socket.on('error', halt);
        socket.on('close', halt);
        const pump = (): void => {
          if (stop || offered >= flood) return;
          offered += chunk.length;
          socket.write(chunk, () => setImmediate(pump));
        };
        pump();
      },
    });

    assert.match(result.statusLine, /^HTTP\/1\.1 431 /);
    assert.ok(result.closedByServer || result.errorCode !== null, 'the 431 left the socket open');

    // THE BYTE COUNTER, read off the socket rather than accumulated by hand.
    // The bound is loose ON PURPOSE and its slack is named rather than tuned:
    // loopback send and receive buffers hold hundreds of kilobytes, so no
    // counter on either side can resolve "the cap plus one read" exactly. What
    // it resolves decisively is the property NFR-29 is actually about — the
    // process refuses without consuming the flood.
    const KERNEL_BUFFER_SLACK = 1024 * 1024;
    assert.ok(
      result.bytesWritten < flood,
      `the whole ${flood}-byte header flood reached the wire before the refusal`,
    );
    assert.ok(
      result.bytesWritten <= PROBE.maxHeaderSize + KERNEL_BUFFER_SLACK,
      `${result.bytesWritten} bytes crossed the wire against a ${PROBE.maxHeaderSize}-byte cap`,
    );
    // And the reply is tiny: the refusal costs the server a fixed few hundred
    // bytes however large the offered block was.
    assert.ok(result.bytesRead > 0 && result.bytesRead < 4096, `the 431 was ${result.bytesRead} bytes`);
  });
});

// ---------------------------------------------------------------------------
// 3. Effect — the body cap, measured on the wire
// ---------------------------------------------------------------------------

describe('US-28a §3: the body cap, by effect at an exact one-byte boundary', () => {
  const quiet = {
    UNIFI_HTTP_MAX_CONNECTIONS: '48',
    UNIFI_HTTP_AUTH_FAIL_PER_MIN: '5000',
    UNIFI_HTTP_HEADERS_TIMEOUT_MS: '8000',
    UNIFI_HTTP_REQUEST_TIMEOUT_MS: '9000',
  };

  /** The second probe value for this bound, distinct from PROBE.maxBodyBytes. */
  const SECOND_CAP = 7777;

  function bodyRequest(port: number, size: number): string {
    return raw(
      'POST /mcp HTTP/1.1',
      [
        `Host: 127.0.0.1:${port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Type: application/json',
        `Content-Length: ${size}`,
      ],
      'b'.repeat(size),
    );
  }

  test('C31/C34 effect: exactly the cap passes, exactly one byte more is 413', async (t) => {
    const bound = await boundServer(
      t,
      httpEnv({ ...quiet, UNIFI_HTTP_MAX_BODY_BYTES: String(PROBE.maxBodyBytes) }),
    );
    await waitReady(bound);

    // The cap is enforced by this project's own `readBoundedBody` as
    // `total > limit`, so unlike the header cap the transition is genuinely
    // one byte wide and is asserted as such, with no window.
    const atCap = await wire(bound.port, bodyRequest(bound.port, PROBE.maxBodyBytes));
    assert.equal(
      /^HTTP\/1\.1 413 /.test(atCap.statusLine),
      false,
      `a body of exactly ${PROBE.maxBodyBytes} bytes was refused: ${atCap.statusLine}`,
    );

    const overCap = await wire(bound.port, bodyRequest(bound.port, PROBE.maxBodyBytes + 1));
    assert.match(overCap.statusLine, /^HTTP\/1\.1 413 /);

    // The byte counter on both sides of the boundary. The over-cap request is
    // one byte longer on the wire and the outcome inverts — which is what
    // "the boundary is at the configured value" means when stated as bytes.
    assert.equal(overCap.bytesWritten - atCap.bytesWritten, 1);
    assert.ok(atCap.bytesRead > 0 && overCap.bytesRead > 0);

    // Nothing is retained on either path. Without this the cap could be
    // enforced by buffering the whole body and then measuring it, which is the
    // consumption NFR-29 forbids.
    assert.equal(bound.serving.retainedRequestBuffers(), 0);

    // The refusal is in the operator's record, and named.
    const refusals = bound.instruments.counts.requestLogs.filter((line) =>
      line.includes('status=413'),
    );
    assert.equal(refusals.length, 1, `expected exactly one 413 line, saw ${refusals.length}`);
    assert.match(refusals[0] ?? '', /reject_reason=body_size/);
  });

  test('C34 effect: one body, two configured caps, opposite outcomes', async (t) => {
    const tight = await boundServer(
      t,
      httpEnv({ ...quiet, UNIFI_HTTP_MAX_BODY_BYTES: String(PROBE.maxBodyBytes) }),
    );
    const roomy = await boundServer(
      t,
      httpEnv({ ...quiet, UNIFI_HTTP_MAX_BODY_BYTES: String(SECOND_CAP) }),
    );
    await waitReady(tight);
    await waitReady(roomy);

    assert.notEqual(SECOND_CAP, PROBE.maxBodyBytes);
    assert.notEqual(SECOND_CAP, DOCUMENTED_DEFAULTS.maxBodyBytes);
    assert.ok(SECOND_CAP > PROBE.maxBodyBytes);

    // One size, between the two caps. Node exposes no body-size property, so
    // this differential is the ONLY provenance this bound can have beyond the
    // handle: the same bytes must be refused by one listener and accepted by
    // the other, and nothing but the configured value differs between them.
    const size = Math.floor((PROBE.maxBodyBytes + SECOND_CAP) / 2);
    const refused = await wire(tight.port, bodyRequest(tight.port, size));
    const accepted = await wire(roomy.port, bodyRequest(roomy.port, size));

    assert.match(refused.statusLine, /^HTTP\/1\.1 413 /);
    assert.equal(
      /^HTTP\/1\.1 413 /.test(accepted.statusLine),
      false,
      `the roomier listener also refused ${size} bytes: ${accepted.statusLine}`,
    );
    // The socket byte counter, on both halves: each listener received at least
    // the whole body, so the difference in outcome is the configured cap and
    // not a difference in what reached the wire.
    assert.ok(refused.bytesWritten >= size, `only ${refused.bytesWritten} bytes reached the wire`);
    assert.ok(accepted.bytesWritten >= size, `only ${accepted.bytesWritten} bytes reached the wire`);
    assert.equal(tight.serving.retainedRequestBuffers(), 0);
    assert.equal(roomy.serving.retainedRequestBuffers(), 0);

    // …and the boundary of the roomier listener is where ITS cap says, not
    // where the tighter one's does.
    const overSecond = await wire(roomy.port, bodyRequest(roomy.port, SECOND_CAP + 1));
    assert.match(overSecond.statusLine, /^HTTP\/1\.1 413 /);
  });
});

// ---------------------------------------------------------------------------
// 4. Effect — the connection cap and the probe headroom (C33, and AC 2)
// ---------------------------------------------------------------------------

/** Can this host reach a second loopback address, for a distinct source key? */
function secondLoopbackAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createTcpServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, '127.0.0.2', () => {
      probe.close(() => resolve(true));
    });
  });
}

interface Admission {
  readonly socket: Socket;
  readonly body: string;
  readonly bytesRead: number;
  readonly refused: boolean;
}

/**
 * Open one connection, send `GET /healthz`, and report whether it was admitted.
 *
 * The socket is LEFT OPEN on success: the whole point of the cap is that an
 * admitted connection holds a slot, and a helper that closed it would make the
 * ninth connection succeed by accident.
 */
function openHealthzConnection(port: number, localAddress?: string): Promise<Admission> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let settled = false;
    let refused = false;

    const socket = connect({
      host: '127.0.0.1',
      port,
      ...(localAddress === undefined ? {} : { localAddress }),
    });

    const settle = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const text = Buffer.concat(chunks).toString('latin1');
      const split = text.indexOf('\r\n\r\n');
      resolve({
        socket,
        body: split === -1 ? '' : text.slice(split + 4),
        bytesRead: socket.bytesRead,
        refused,
      });
    };

    const timer = setTimeout(settle, 750);
    socket.on('connect', () => {
      socket.write(`GET /healthz HTTP/1.1\r\nHost: 10.42.0.7:8787\r\n\r\n`);
    });
    // One probe response arrives in one segment; settling on it keeps the
    // nine-connection walk below at a few milliseconds per connection.
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      settle();
    });
    socket.on('error', () => {
      refused = true;
    });
    socket.on('close', () => {
      refused = chunks.length === 0;
      settle();
    });
  });
}

/** Hold a raw TCP connection open without sending anything at all. */
function holdSilent(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

describe('US-28a §4: the connection cap is the NON-probe budget, and the headroom is per source', () => {
  test('the headroom constant is 8, and it is a constant rather than a seventh bound', () => {
    // The acceptance criterion names 8 literally ("headroom is capped at 8"),
    // so the number is asserted rather than read from the import — an import
    // compared against itself proves nothing.
    assert.equal(PROBE_CONNECTION_HEADROOM, 8);
    // FR-63 closes the `UNIFI_HTTP_*` family: the reserve is deliberately NOT
    // configurable, so it is not a seventh member of the resolved bounds. This
    // is also the assertion that pins the count at SIX — a seventh bound added
    // without a matching provenance and effect case fails here.
    const resolved = createServingOptions(loadConfig(httpEnv(), { repoRoot: REPO_ROOT })).bounds;
    assert.deepEqual(Object.keys(resolved).sort(), [...BOUND_NAMES].sort());
    assert.equal(Object.keys(resolved).length, 6);
  });

  test('AC2 / C33: one source, nine GET /healthz connections, the ninth refused', async (t) => {
    const cap = PROBE.maxConnections; // 7 — so the NINTH connection is the first refusal
    const bound = await boundServer(
      t,
      httpEnv({
        UNIFI_HTTP_MAX_CONNECTIONS: String(cap),
        // Long enough that nothing under test is closed by a timer instead of
        // by the cap, short enough that a leak still cannot outlive the file.
        UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: '4000',
        UNIFI_HTTP_HEADERS_TIMEOUT_MS: '9000',
        UNIFI_HTTP_REQUEST_TIMEOUT_MS: '9500',
      }),
    );
    await waitReady(bound);

    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    const ceiling = cap + PROBE_CONNECTION_HEADROOM;
    let highWater = 0;
    let logLinesBeforeTheNinth = -1;
    const trace: { n: number; total: number; headroom: number; refused: boolean }[] = [];

    for (let n = 1; n <= 9; n += 1) {
      if (n === 9) logLinesBeforeTheNinth = bound.instruments.counts.requestLogs.length;
      const admission = await openHealthzConnection(bound.port);
      open.push(admission.socket);
      const counts = bound.serving.connectionCounts();
      highWater = Math.max(highWater, counts.total);
      trace.push({ n, ...counts, refused: admission.refused });

      // THE INVARIANT, checked after EVERY admission rather than once at the
      // end: total accepted never exceeds the cap plus the fixed headroom.
      assert.ok(
        counts.total <= ceiling,
        `connection ${n} took the total to ${counts.total}, over the ceiling of ${ceiling}`,
      );

      if (n <= cap) {
        // The non-probe budget, spent first. A probe does not get a headroom
        // slot while ordinary room remains — the headroom is a reserve, not a
        // priority lane.
        assert.deepEqual(
          { ...counts },
          { total: n, headroom: 0 },
          `connection ${n} of ${cap} was not admitted as ordinary`,
        );
        assert.equal(admission.refused, false, `connection ${n} was refused inside the cap`);
        assert.equal(admission.body, 'ok\n');
      } else if (n === cap + 1) {
        // The eighth: the budget is spent, so this one claims this source's
        // single headroom slot — and is SERVED, which is the behaviour proof
        // that `server.maxConnections` is not doing this job. Node's accept
        // layer would have destroyed this socket before a request line existed.
        assert.deepEqual(
          { ...counts },
          { total: cap + 1, headroom: 1 },
          'the first over-budget probe did not take a headroom slot',
        );
        assert.equal(admission.refused, false);
        assert.equal(admission.body, 'ok\n');
      } else {
        // THE NINTH. Refused at admission — not queued, not answered, and not
        // admitted into the remaining seven headroom slots, because within the
        // headroom at most ONE connection per source key is admitted. Without
        // that rule one source sends `GET /healthz` on eight keep-alive
        // sockets and starves the kubelet exactly as if no headroom existed.
        assert.equal(n, 9);
        assert.equal(admission.refused, true, 'the ninth connection was admitted');
        assert.equal(admission.bytesRead, 0, 'the refused connection received a response');
        assert.equal(
          admission.body,
          '',
          'the refusal carried a body, which would be an occupancy oracle',
        );
        assert.deepEqual(
          { ...counts },
          { total: cap + 1, headroom: 1 },
          'the ledger moved for a connection that was never accepted',
        );
      }
    }

    // Restated over the whole walk, in the form the acceptance criterion uses.
    assert.equal(
      highWater,
      cap + 1,
      `the high-water mark was ${highWater}; the trace was ${JSON.stringify(trace)}`,
    );
    assert.ok(highWater <= cap + PROBE_CONNECTION_HEADROOM);
    assert.equal(trace.filter((row) => row.refused).length, 1);
    assert.equal(trace.find((row) => row.refused)?.n, 9);

    // A refused connection produces NO log line: it never became a request, and
    // one line per refused connection is exactly the log-flooding vector the cap
    // itself exists to bound. Measured as a delta across the ninth connection
    // rather than as a total, because probe lines are separately suppressed to
    // one per interval and a total would be asserting that suppression instead.
    assert.ok(logLinesBeforeTheNinth >= 0);
    assert.equal(
      bound.instruments.counts.requestLogs.length,
      logLinesBeforeTheNinth,
      'the refused ninth connection produced a request log line',
    );
    // The admitted probes did reach the log, so the delta above is not zero by
    // virtue of nothing ever being logged at all.
    assert.ok(
      bound.instruments.counts.requestLogs.some((line) => line.includes('path=healthz')),
      'no probe reached the request log, so the refusal delta proves nothing',
    );
  });

  test('C33: the ninth is refused by the per-source rule, not by an exhausted headroom', async (t) => {
    if (!(await secondLoopbackAvailable())) {
      // Reported rather than silently passed. 127.0.0.2 is routable on Linux
      // and Windows but is not configured by default on macOS, and the
      // per-source rule needs two source keys to be observable at all.
      t.skip('no second loopback address (127.0.0.2) on this platform');
      return;
    }

    const cap = PROBE.maxConnections;
    const bound = await boundServer(
      t,
      httpEnv({
        UNIFI_HTTP_MAX_CONNECTIONS: String(cap),
        UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: '4000',
        UNIFI_HTTP_HEADERS_TIMEOUT_MS: '9000',
      }),
    );
    await waitReady(bound);
    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    for (let n = 0; n < cap + 1; n += 1) {
      const admission = await openHealthzConnection(bound.port);
      open.push(admission.socket);
      assert.equal(admission.refused, false);
    }
    assert.deepEqual(bound.serving.connectionCounts(), { total: cap + 1, headroom: 1 });

    // Same source: refused, exactly as the previous case found.
    const ninth = await openHealthzConnection(bound.port);
    open.push(ninth.socket);
    assert.equal(ninth.refused, true);

    // Different source key: admitted, into the SECOND of the eight headroom
    // slots. This is what proves the ninth was refused by the per-source cap
    // rather than by an exhausted reserve — seven slots were still free.
    const elsewhere = await openHealthzConnection(bound.port, '127.0.0.2');
    open.push(elsewhere.socket);
    assert.equal(elsewhere.refused, false, 'a probe from a second source key was refused');
    assert.equal(elsewhere.body, 'ok\n');
    assert.deepEqual(bound.serving.connectionCounts(), { total: cap + 2, headroom: 2 });
    assert.ok(bound.serving.connectionCounts().total <= cap + PROBE_CONNECTION_HEADROOM);
  });

  test('C34 effect: the refusal point moves with the configured cap', async (t) => {
    // A second probe value for this bound, distinct from PROBE.maxConnections,
    // from the §5.15.1 default of 64, and from anything Node would supply.
    const cap = 3;
    assert.notEqual(cap, PROBE.maxConnections);
    assert.notEqual(cap, DOCUMENTED_DEFAULTS.maxConnections);

    const bound = await boundServer(
      t,
      httpEnv({
        UNIFI_HTTP_MAX_CONNECTIONS: String(cap),
        UNIFI_HTTP_HEADERS_TIMEOUT_MS: '9000',
        UNIFI_HTTP_REQUEST_TIMEOUT_MS: '9500',
      }),
    );
    await waitReady(bound);
    assert.equal(bound.serving.bounds().maxConnections, cap);

    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    // Silent connections, so nothing resolves to a route and the ledger is the
    // only thing under observation.
    for (let n = 1; n <= cap; n += 1) {
      open.push(await holdSilent(bound.port));
      await sleep(20);
      assert.deepEqual(bound.serving.connectionCounts(), { total: n, headroom: 0 });
    }

    // Up to the cap the budget is ordinary. The NEXT connection is admitted
    // into this source's single headroom slot — and when its request turns out
    // not to be a probe it gets the byte-identical uniform 401 and loses its
    // socket. Never a distinct status: one would be a pre-auth oracle whose
    // existence is conditional on the connection count, and an attacker who
    // could produce it would learn the configured cap by binary search.
    const claimed = await wire(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(claimed.statusLine, /^HTTP\/1\.1 401 /);
    assert.ok(claimed.closedByServer || claimed.errorCode !== null);

    // The headroom slot is released on the server socket's `close`, a tick
    // after the client's end goes away. Retake it, then show the one after
    // that is refused outright — no response at all, which is a different
    // event from the 401 above and must not be conflated with it.
    await sleep(150);
    open.push(await holdSilent(bound.port));
    await sleep(20);
    assert.deepEqual(bound.serving.connectionCounts(), { total: cap + 1, headroom: 1 });

    const overflow = await holdSilent(bound.port);
    open.push(overflow);
    await sleep(120);
    assert.deepEqual(
      bound.serving.connectionCounts(),
      { total: cap + 1, headroom: 1 },
      'a connection past the headroom was admitted',
    );
    assert.ok(
      overflow.destroyed || overflow.readyState === 'closed',
      'the refused connection was left open',
    );
    assert.ok(bound.serving.connectionCounts().total <= cap + PROBE_CONNECTION_HEADROOM);
  });
});

// ---------------------------------------------------------------------------
// 5. Effect — the three time bounds, each as a two-listener differential
// ---------------------------------------------------------------------------

/**
 * Every case below runs TWO listeners at TWO distinct probe values in the same
 * run and requires opposite outcomes at one instant. A single-listener
 * "it closed within N ms" assertion is satisfied by an implementation that
 * hardcoded anything smaller than N; requiring the slow listener to still be
 * open at that instant is not.
 *
 * None of the probe values exceeds 2 400 ms, so the whole section costs a few
 * seconds rather than the 10 000 / 30 000 / 5 000 the §5.15.1 defaults would.
 */
describe('US-28a §5: the headers, request and keep-alive timeouts move with configuration', () => {
  test('C32/C34 effect: the headers timeout closes a stalled connection at the configured value', async (t) => {
    const SLOW = 1400;
    assert.notEqual(PROBE.headersTimeout, SLOW);
    for (const value of [PROBE.headersTimeout, SLOW]) {
      assert.notEqual(value, DOCUMENTED_DEFAULTS.headersTimeout);
    }

    const common = { UNIFI_HTTP_REQUEST_TIMEOUT_MS: '9000', UNIFI_HTTP_MAX_CONNECTIONS: '48' };
    const fast = await boundServer(
      t,
      httpEnv({ ...common, UNIFI_HTTP_HEADERS_TIMEOUT_MS: String(PROBE.headersTimeout) }),
    );
    const slow = await boundServer(
      t,
      httpEnv({ ...common, UNIFI_HTTP_HEADERS_TIMEOUT_MS: String(SLOW) }),
    );
    await waitReady(fast);
    await waitReady(slow);
    assert.equal(fast.server.headersTimeout, PROBE.headersTimeout);
    assert.equal(slow.server.headersTimeout, SLOW);

    /** A partial request line and then nothing at all — C32's slowloris. */
    const stall = (port: number): Promise<Wire> =>
      wire(port, '', {
        idleMs: 6_000,
        drive: (socket, done) => {
          socket.write('GET /mc');
          socket.once('close', done);
          socket.once('end', done);
        },
      });

    // Ten on the fast listener, as C32 states, plus one on the slow listener as
    // the control. Started together so both are measured against one clock.
    const startedAt = Date.now();
    const fastStalls = Promise.all(Array.from({ length: 10 }, () => stall(fast.port)));
    const slowStall = stall(slow.port);

    const settled = await fastStalls;
    const elapsed = Date.now() - startedAt;

    // The fast listener's ten are gone well inside the slow listener's bound.
    for (const one of settled) {
      assert.ok(one.closedByServer || one.errorCode !== null, 'a stalled connection was left open');
    }
    assert.ok(
      elapsed < 900,
      `ten stalled connections took ${elapsed} ms against a ${PROBE.headersTimeout} ms headers timeout`,
    );
    assert.ok(
      elapsed >= PROBE.headersTimeout - 50,
      `a stalled connection closed after ${elapsed} ms, before the configured ${PROBE.headersTimeout} ms could apply`,
    );

    // THE DIFFERENTIAL: at that same instant the slow listener's identical
    // connection is still open. An implementation that closed on a constant
    // rather than on the configured value fails exactly here.
    assert.equal(fast.serving.connectionCounts().total, 0);
    assert.ok(
      slow.serving.connectionCounts().total >= 1,
      "the slow listener closed its stalled connection at the fast listener's bound",
    );

    // …and it does eventually close, so the slow half is not passing by being
    // permanently open.
    const slowResult = await slowStall;
    assert.ok(slowResult.closedByServer || slowResult.errorCode !== null);
    assert.ok(
      slowResult.elapsedMs >= SLOW - 50,
      `the slow listener closed after ${slowResult.elapsedMs} ms, before its configured ${SLOW} ms`,
    );

    // A well-formed request still works on the fast listener in the same run —
    // the timeout bounds stalls, it does not degrade service.
    const good = await wire(
      fast.port,
      raw('POST /nope HTTP/1.1', [
        `Host: 127.0.0.1:${fast.port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(good.statusLine, /^HTTP\/1\.1 404 /);
  });

  test('C34 effect: the request timeout cuts off a dribbled body at the configured value', async (t) => {
    const SLOW = 2400;
    assert.notEqual(PROBE.requestTimeout, SLOW);
    for (const value of [PROBE.requestTimeout, SLOW]) {
      assert.notEqual(value, DOCUMENTED_DEFAULTS.requestTimeout);
    }

    /**
     * MEASURED NODE BEHAVIOUR, and the reason the headers timeout below is set
     * BELOW the request timeout rather than above it.
     *
     * On Node 20.20.2 the incomplete-request sweep does not enforce
     * `requestTimeout` independently of `headersTimeout`: a request whose
     * header block completed instantly and whose body then dribbles is
     * destroyed at approximately **max(headersTimeout, requestTimeout)**, not
     * at `requestTimeout`. Measured against a BARE `node:http` server with no
     * project code involved — h=250/r=900 cut at 1 209 ms, h=250/r=2 400 cut
     * at 2 713 ms, but h=8 000/r=900 cut at 8 281 ms and h=2 000/r=900 at
     * 2 252 ms. So this is Node's, not `src/serve/http.ts`'s: the project
     * assigns `server.requestTimeout` from the factory and §1 proves it.
     *
     * It is not a live exposure either, because the §5.15.1 defaults ship in
     * the ordering where the request timeout is the larger of the two
     * (10 000 < 30 000) and therefore the governing one. It IS a trap for an
     * operator who lowers `UNIFI_HTTP_REQUEST_TIMEOUT_MS` below
     * `UNIFI_HTTP_HEADERS_TIMEOUT_MS` and expects the smaller number to win —
     * recorded as a carry-forward finding rather than worked around here.
     *
     * The probe therefore runs in the shipped ordering, where the request
     * timeout is the bound actually in force, and the case closes with the
     * weaker claim that holds in EITHER ordering: the connection is bounded.
     */
    const common = {
      UNIFI_HTTP_HEADERS_TIMEOUT_MS: String(PROBE.headersTimeout),
      UNIFI_HTTP_MAX_BODY_BYTES: '1048576',
    };
    const fast = await boundServer(
      t,
      httpEnv({ ...common, UNIFI_HTTP_REQUEST_TIMEOUT_MS: String(PROBE.requestTimeout) }),
    );
    const slow = await boundServer(
      t,
      httpEnv({ ...common, UNIFI_HTTP_REQUEST_TIMEOUT_MS: String(SLOW) }),
    );
    await waitReady(fast);
    await waitReady(slow);
    assert.equal(fast.server.requestTimeout, PROBE.requestTimeout);
    assert.equal(slow.server.requestTimeout, SLOW);

    const dribble = (port: number): Promise<Wire> =>
      wire(port, '', {
        idleMs: 8_000,
        drive: (socket, done) => {
          socket.write(
            raw('POST /mcp HTTP/1.1', [
              `Host: 127.0.0.1:${port}`,
              `Authorization: Bearer ${SECRET}`,
              'Content-Type: application/json',
              'Content-Length: 4000',
            ]),
          );
          const drip = setInterval(() => socket.write('a'), 150);
          const stop = (): void => {
            clearInterval(drip);
            done();
          };
          socket.once('close', stop);
          socket.once('end', stop);
          socket.once('error', stop);
        },
      });

    const slowRun = dribble(slow.port);
    const fastRun = await dribble(fast.port);

    assert.ok(
      fastRun.closedByServer || fastRun.errorCode !== null,
      'the dribbled body was never cut off',
    );
    assert.ok(
      fastRun.elapsedMs >= PROBE.requestTimeout - 100,
      `the request was cut off after ${fastRun.elapsedMs} ms, before the configured ${PROBE.requestTimeout} ms`,
    );
    assert.ok(
      fastRun.elapsedMs < SLOW,
      `the request survived ${fastRun.elapsedMs} ms against a ${PROBE.requestTimeout} ms request timeout`,
    );

    // THE DIFFERENTIAL, at the instant the fast listener has already cut: the
    // slow listener's identical dribble is still connected.
    assert.ok(
      slow.serving.connectionCounts().total >= 1,
      "the slow listener cut its dribbled body at the fast listener's bound",
    );

    const slowRunResult = await slowRun;
    assert.ok(slowRunResult.closedByServer || slowRunResult.errorCode !== null);
    assert.ok(
      slowRunResult.elapsedMs >= SLOW - 100,
      `the slow listener cut off after ${slowRunResult.elapsedMs} ms, before its configured ${SLOW} ms`,
    );

    // The claim that holds in EITHER ordering of the two timeouts, and the one
    // the requirement is really about: a dribbling caller cannot hold a
    // connection slot indefinitely. Bounded by the larger of the two configured
    // values plus one sweep interval, on both listeners.
    const sweep = 250;
    assert.ok(
      fastRun.elapsedMs <= Math.max(PROBE.headersTimeout, PROBE.requestTimeout) + sweep + 600,
      `the fast listener held a dribbling caller for ${fastRun.elapsedMs} ms`,
    );
    assert.ok(
      slowRunResult.elapsedMs <= Math.max(PROBE.headersTimeout, SLOW) + sweep + 600,
      `the slow listener held a dribbling caller for ${slowRunResult.elapsedMs} ms`,
    );
  });

  test('C34 effect: an idle keep-alive socket is closed at the configured keep-alive timeout', async (t) => {
    const SLOW = 1450;
    assert.notEqual(PROBE.keepAliveTimeout, SLOW);
    for (const value of [PROBE.keepAliveTimeout, SLOW]) {
      // 5 000 is BOTH the §5.15.1 default and Node's own — the single most
      // dangerous coincidence in this feature, and the reason neither probe
      // value is allowed near it.
      assert.notEqual(value, DOCUMENTED_DEFAULTS.keepAliveTimeout);
    }

    const common = { UNIFI_HTTP_HEADERS_TIMEOUT_MS: '6000', UNIFI_HTTP_REQUEST_TIMEOUT_MS: '9000' };
    const fast = await boundServer(
      t,
      httpEnv({ ...common, UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: String(PROBE.keepAliveTimeout) }),
    );
    const slow = await boundServer(
      t,
      httpEnv({ ...common, UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: String(SLOW) }),
    );
    await waitReady(fast);
    await waitReady(slow);
    assert.equal(fast.server.keepAliveTimeout, PROBE.keepAliveTimeout);
    assert.equal(slow.server.keepAliveTimeout, SLOW);

    /**
     * A `404` deliberately carries no `Connection: close`, so the socket is
     * left idle and the keep-alive timeout is the only thing governing it.
     */
    const idleAfterResponse = (port: number): Promise<Wire> =>
      wire(port, '', {
        idleMs: 6_000,
        drive: (socket, done) => {
          socket.write(
            raw('POST /nope HTTP/1.1', [
              `Host: 127.0.0.1:${port}`,
              `Authorization: Bearer ${SECRET}`,
              'Content-Length: 0',
            ]),
          );
          socket.once('close', done);
          socket.once('end', done);
        },
      });

    const slowRun = idleAfterResponse(slow.port);
    const fastRun = await idleAfterResponse(fast.port);

    assert.match(fastRun.statusLine, /^HTTP\/1\.1 404 /);
    assert.ok(fastRun.closedByServer, 'the idle keep-alive socket was never closed');
    assert.ok(
      fastRun.elapsedMs >= PROBE.keepAliveTimeout - 100,
      `the socket closed after ${fastRun.elapsedMs} ms, before the configured ${PROBE.keepAliveTimeout} ms`,
    );
    assert.ok(
      fastRun.elapsedMs < SLOW,
      `the socket took ${fastRun.elapsedMs} ms against a ${PROBE.keepAliveTimeout} ms keep-alive timeout`,
    );

    // THE DIFFERENTIAL. If `keepAliveTimeout` were inherited rather than
    // configured, both listeners would sit at Node's 5 000 and both halves of
    // this case would read the same number.
    assert.ok(
      slow.serving.connectionCounts().total >= 1,
      "the slow listener closed its idle socket at the fast listener's bound",
    );

    const slowRunResult = await slowRun;
    assert.match(slowRunResult.statusLine, /^HTTP\/1\.1 404 /);
    assert.ok(slowRunResult.closedByServer);
    assert.ok(
      slowRunResult.elapsedMs >= SLOW - 100,
      `the slow listener closed after ${slowRunResult.elapsedMs} ms, before its configured ${SLOW} ms`,
    );
    assert.ok(
      slowRunResult.elapsedMs < DOCUMENTED_DEFAULTS.keepAliveTimeout,
      `the slow listener held the socket for ${slowRunResult.elapsedMs} ms — it is on Node's default, not its configuration`,
    );
  });
});
