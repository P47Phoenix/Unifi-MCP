/**
 * US-28b — the session lifecycle BEHAVIOUR suite (Wave J, slot J2).
 *
 * Suite C of the test strategy: the scale halves of C6.
 *
 * ## What this file is, and what it deliberately is not
 *
 * `test/serve-sessions.test.ts` is US-23's own suite. It proved the mechanisms
 * exist: the reservation counter, the sweep, the eviction path and the
 * generator each work in a small, targeted case. This file is the independent
 * verification of the same two claims from the other side, and it is written to
 * fail in the places US-23's suite cannot:
 *
 * 1. **US-23 drove the TTL by calling `serving.sweepIdleSessions(nowMs)`
 *    directly.** That proves the selection predicate and the eviction half. It
 *    does not prove that the server evicts anything when NOBODY ASKS — which is
 *    the only case that matters for an abandoned server, and the case FR-77
 *    exists for. Here the eviction is driven **only** through the production
 *    periodic trigger (`createSweepInterval`'s `onTick`), across the TTL
 *    boundary: at `TTL - 1` ms the same tick must evict **nothing**, so the
 *    subsequent return to zero is the TTL doing the work and not the tick.
 *
 * 2. **US-23 read `sessionCount()`, which reports RESERVATIONS.** The map and
 *    the counter are two separate variables in `http.ts` (`sessions` and
 *    `reserved`) that are maintained together by hand; an implementation that
 *    decremented the counter and forgot a `sessions.delete` would satisfy every
 *    counter assertion in existence while leaking a hundred live registry
 *    entries. So the map's emptiness is asserted **behaviourally** here: all
 *    100 harvested identifiers are presented back to the live server after the
 *    sweep, and each must take the never-existed branch, body-identical to an
 *    identifier that was never minted.
 *
 * 3. **US-23 exercised exactly one failed-`initialize` shape** (a `406` from
 *    the SDK's `Accept` check) against a cap of 4. A cap of 4 tolerates three
 *    leaked reservations before anything goes red. This file runs both real
 *    non-promotion branches — the SDK's rejection AND `openSession()` itself
 *    throwing, which is the `admitted === null` arm that releases the
 *    reservation directly rather than through `terminateSession` — against a
 *    cap of **1**, where a SINGLE leaked reservation turns attempt 2 into a
 *    `503`. The clock never moves, the periodic tick is captured and never
 *    fired, and a fast-forwarded sweep is asserted to find **zero** expiring
 *    entries afterwards, so "immediately" is proven positively rather than by
 *    the absence of a wait.
 *
 * 4. **US-23's 10 000-draw check asserts the DECODED BYTE LENGTH is 32.** A
 *    generator returning `Buffer.concat([randomBytes(8), Buffer.alloc(24)])`
 *    passes that check, passes the 0-duplicates check (64 bits is ample for
 *    10 000 draws) and passes the one-draw-per-identifier check — while
 *    carrying 64 bits of entropy against NFR-30's 128-bit floor. This file
 *    re-derives the three literal properties and then asserts the one that
 *    actually pins the floor: the DISTRIBUTION of the decoded bytes. The
 *    negative control is executed, not described — the same assertions are run
 *    against that padded generator and required to fail.
 *
 * ## No wall-clock TTL, port 0, and no entrypoint import
 *
 * The clock is `ServingDeps.now`, a default parameter, and it is a number this
 * file increments. Node 20 has no `mock.module`; every seam in this round is a
 * default parameter. Every listener binds port 0 and nothing here imports the
 * entrypoint — both are asserted over this file's own source in §0.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer as createNodeHttpServer, type Server } from 'node:http';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import {
  createSessionId,
  sessionSweepIntervalMs,
  startHttp,
  type HttpServing,
  type HttpServingDeps,
} from '../src/serve/http.js';
import { createMcpServer } from '../src/serve/mcpServer.js';
import { buildRuntimeCore, type Runtime, type RuntimeCore, type Surface } from '../src/serve/runtime.js';

import { createInstruments } from './harness/counters.js';

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = join(dirname(THIS_FILE), '..');

/** 40 characters, comfortably over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;
/** A member of the SDK's `SUPPORTED_PROTOCOL_VERSIONS`, pinned rather than imported. */
const PROTOCOL_VERSION = '2025-06-18';
/** The scale both session criteria are stated at. */
const SESSIONS = 100;
/** The scale the identifier criterion is stated at. */
const DRAWS = 10_000;
/** `SESSION_ID_BYTES` in `src/serve/http.ts`, restated so a change here is deliberate. */
const EXPECTED_ID_BYTES = 32;
/** NFR-30's floor, in bits. */
const ENTROPY_FLOOR_BITS = 128;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Every listener in this file binds PORT 0. There is no other value. */
function httpEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    ...extra,
  };
}

/** A clock that is a number. Nothing in this file waits on wall time for a TTL. */
interface Clock {
  ms: number;
}

/** Per-session `McpServer` construction and close counts, in construction order. */
interface InstanceLedger {
  built: number;
  closed: number;
  readonly closesByInstance: number[];
  /** FR-72's "per-session instance count": built minus closed. */
  live(): number;
}

/** The captured production sweep trigger. Fired by hand; never by wall time. */
interface SweepTrigger {
  /** The interval the production call site armed, in milliseconds. */
  intervalMs: number;
  /** How many times this file has fired it. */
  fired: number;
  /** Fire one production tick. */
  tick(): void;
}

interface BoundOptions {
  readonly env?: Record<string, string>;
  readonly deps?: HttpServingDeps;
  /** Wraps the production `createSessionId` without replacing it. */
  readonly drawBytes?: (size: number) => Buffer;
  /** Throws instead of building a session, to reach the `admitted === null` arm. */
  readonly failOpenSession?: () => boolean;
}

interface Bound {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly instances: InstanceLedger;
  readonly clock: Clock;
  readonly sweep: SweepTrigger;
  /** Every identifier the server DREW, in draw order. */
  readonly drawn: string[];
}

/**
 * Start one listener with an injected clock and a captured sweep trigger.
 *
 * The sweep seam is the point of this file. `createSweepInterval` is handed a
 * real, un-armed, `unref()`-able timer so the production call site's own
 * `unref()` and the teardown's own `clearInterval` both still run against a
 * real handle — the seam substitutes WHEN the tick fires, never what it does.
 */
async function boundServer(t: TestContext, options: BoundOptions = {}): Promise<Bound> {
  const clock: Clock = { ms: 1_700_000_000_000 };
  const closesByInstance: number[] = [];
  const instances: InstanceLedger = {
    built: 0,
    closed: 0,
    closesByInstance,
    live(): number {
      return instances.built - instances.closed;
    },
  };

  let onTick: (() => void) | null = null;
  const sweep: SweepTrigger = {
    intervalMs: -1,
    fired: 0,
    tick(): void {
      assert.ok(onTick !== null, 'the production sweep interval was never armed');
      sweep.fired += 1;
      onTick();
    },
  };

  const drawn: string[] = [];
  const instruments = createInstruments({
    env: { ...(options.env ?? httpEnv()) },
    keychain: null,
  });
  const core = buildRuntimeCore(instruments.deps);

  let server: Server | null = null;
  const serving = await startHttp(core, instruments.observer, {
    now: () => clock.ms,
    warn: () => undefined,
    createHttpServer: (serverOptions, handler) => {
      server = createNodeHttpServer(serverOptions, handler);
      return server;
    },
    // The PRODUCTION generator, with only its documented byte-source seam
    // instrumented. Substituting the algorithm would make §3's integration half
    // an assertion about the harness rather than about the server.
    createSessionId: () => {
      const id =
        options.drawBytes === undefined ? createSessionId() : createSessionId(options.drawBytes);
      drawn.push(id);
      return id;
    },
    createMcpServer: (runtime: Runtime, surface: Surface): McpServer => {
      if (options.failOpenSession?.() === true) {
        throw new Error('injected session-construction failure');
      }
      const index = instances.built;
      instances.built += 1;
      closesByInstance.push(0);
      const built = createMcpServer(runtime, surface);
      const originalClose = built.close.bind(built);
      built.close = async (): Promise<void> => {
        closesByInstance[index] = (closesByInstance[index] ?? 0) + 1;
        instances.closed += 1;
        await originalClose();
      };
      return built;
    },
    createSweepInterval: (tick, intervalMs) => {
      onTick = tick;
      sweep.intervalMs = intervalMs;
      // A real handle: production calls `unref()` on it and teardown calls
      // `clearInterval` on it, and neither should be reaching a stub. The delay
      // is long enough that it can never fire on its own inside a test run.
      return setInterval(() => undefined, 3_600_000);
    },
    ...(options.deps ?? {}),
  });

  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  assert.ok(server !== null, 'the http server seam was not used');
  return { serving, core, port: serving.address.port, instances, clock, sweep, drawn };
}

/** Wait until the registry has resolved and the readiness flag has flipped. */
async function waitReady(bound: Bound): Promise<void> {
  await bound.core.ready;
  await settle(4);
}

/** Let every already-queued continuation run. No wall-clock waiting. */
async function settle(turns = 32): Promise<void> {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/**
 * Advance the microtask/macrotask queue until `predicate` holds, or give up.
 *
 * The production sweep tick is `void sweepIdleSessions(now())` — fire and
 * forget — and each eviction awaits `server.close()`, so 100 of them need many
 * turns. This is turn-counting, not time-waiting: it never sleeps.
 */
async function until(predicate: () => boolean, turns = 5_000): Promise<boolean> {
  for (let i = 0; i < turns; i += 1) {
    if (predicate()) return true;
    await new Promise((resolve) => setImmediate(resolve));
  }
  return predicate();
}

// ---------------------------------------------------------------------------
// The raw socket client
// ---------------------------------------------------------------------------

interface Exchange {
  readonly bytes: Buffer;
  readonly text: string;
}

/**
 * One request over a raw socket, returning the server's bytes verbatim.
 *
 * `settleWhen` is throughput, not convenience: an `initialize` reply is an SSE
 * stream the server holds open, so without it each of the hundred sessions
 * below would cost a full idle window.
 */
function exchange(
  port: number,
  request: string,
  options: { idleMs?: number; settleWhen?: (text: string) => boolean } = {},
): Promise<Exchange> {
  const idleMs = options.idleMs ?? 250;
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let settled = false;
    let idle: NodeJS.Timeout | null = null;
    const socket = connect({ host: '127.0.0.1', port });

    const done = (): void => {
      if (settled) return;
      settled = true;
      if (idle !== null) clearTimeout(idle);
      // DROPPED, not closed — the shape a crashed client leaves behind, and the
      // one nothing but the TTL sweep cleans up.
      socket.destroy();
      const bytes = Buffer.concat(chunks);
      resolve({ bytes, text: bytes.toString('latin1') });
    };
    const bump = (): void => {
      if (idle !== null) clearTimeout(idle);
      idle = setTimeout(done, idleMs);
    };

    socket.on('connect', () => {
      socket.write(Buffer.from(request, 'latin1'));
      bump();
    });
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      if (options.settleWhen?.(Buffer.concat(chunks).toString('latin1')) === true) {
        done();
        return;
      }
      bump();
    });
    socket.on('error', done);
    socket.on('close', done);
  });
}

function raw(startLine: string, headers: readonly string[], body = ''): string {
  return `${[startLine, ...headers].join('\r\n')}\r\n\r\n${body}`;
}

const INITIALIZE_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'us-28b', version: '0' },
  },
});

/**
 * One `initialize` over a raw socket.
 *
 * `accept` is a parameter because the SDK's own `Accept` check is what produces
 * a REAL, unmocked failed `initialize` — a `406` raised before
 * `onsessioninitialized` can fire — which is one of the two non-promotion
 * shapes the reservation release has to survive.
 */
function initializeRequest(port: number, accept = 'application/json, text/event-stream'): string {
  return raw(
    'POST /mcp HTTP/1.1',
    [
      `Host: 127.0.0.1:${port}`,
      `Authorization: Bearer ${SECRET}`,
      'Content-Type: application/json',
      `Accept: ${accept}`,
      `Content-Length: ${Buffer.byteLength(INITIALIZE_BODY)}`,
    ],
    INITIALIZE_BODY,
  );
}

/** Present an identifier on a request that is not an initialisation. */
function callOnSession(port: number, id: string): string {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list', params: {} });
  return raw(
    'POST /mcp HTTP/1.1',
    [
      `Host: 127.0.0.1:${port}`,
      `Authorization: Bearer ${SECRET}`,
      'Content-Type: application/json',
      'Accept: application/json, text/event-stream',
      `Mcp-Session-Id: ${id}`,
      `Mcp-Protocol-Version: ${PROTOCOL_VERSION}`,
      `Content-Length: ${Buffer.byteLength(body)}`,
    ],
    body,
  );
}

function statusOf(captured: Exchange): number {
  return Number(captured.text.split('\r\n')[0]?.split(' ')[1] ?? 0);
}

function bodyOf(captured: Exchange): string {
  const split = captured.text.indexOf('\r\n\r\n');
  return split === -1 ? '' : captured.text.slice(split + 4);
}

function sessionIdOf(captured: Exchange): string | null {
  return /\r\nmcp-session-id:\s*(\S+)\r\n/i.exec(captured.text)?.[1] ?? null;
}

/** True once a fixed-length JSON reply has arrived in full. */
function completeJsonBody(text: string): boolean {
  const split = text.indexOf('\r\n\r\n');
  if (split === -1) return false;
  const declared = /\r\ncontent-length:\s*(\d+)\r\n/i.exec(text.slice(0, split))?.[1];
  if (declared === undefined) return false;
  return text.length - (split + 4) >= Number(declared);
}

/** True once the initialize reply's header block and its first SSE event have landed. */
function initializeComplete(text: string): boolean {
  return /\r\nmcp-session-id:/i.test(text) && /\n\n$/.test(text);
}

async function openSessionOverSocket(port: number): Promise<string> {
  const captured = await exchange(port, initializeRequest(port), {
    settleWhen: initializeComplete,
  });
  const id = sessionIdOf(captured);
  assert.ok(id !== null, `initialize returned no Mcp-Session-Id:\n${captured.text}`);
  return id;
}

/**
 * Run `work` over `items` with bounded concurrency.
 *
 * Bounded because `UNIFI_HTTP_MAX_CONNECTIONS` defaults to 64 and a hundred
 * simultaneous sockets would be answered by the connection cap rather than by
 * the session registry — a green test measuring the wrong refusal.
 */
async function mapLimited<T, R>(
  items: readonly T[],
  limit: number,
  work: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array<R>(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      out[index] = await work(items[index] as T, index);
    }
  });
  await Promise.all(runners);
  return out;
}

// ---------------------------------------------------------------------------
// Entropy analysis — the half a decoded-byte-length assertion cannot see
// ---------------------------------------------------------------------------

interface EntropyReport {
  /** Distinct identifiers seen. */
  readonly distinct: number;
  /** Every distinct decoded byte length observed. */
  readonly byteLengths: number[];
  /** The smallest number of distinct values any single byte POSITION took. */
  readonly minDistinctPerPosition: number;
  /** The furthest any single BIT position strayed from a balanced 0.5. */
  readonly worstBitBias: number;
}

/**
 * Measure what a length check cannot: whether the bytes are actually random.
 *
 * `Buffer.concat([randomBytes(8), Buffer.alloc(24)])` decodes to 32 bytes and
 * collides zero times in 10 000 draws. Its 24 padding positions take exactly
 * ONE value each and its 192 padding bits are 100 % zero, and those are the two
 * numbers below.
 */
function analyseDraws(ids: readonly string[]): EntropyReport {
  const distinct = new Set(ids);
  const byteLengths = new Set<number>();
  const valuesAt = new Map<number, Set<number>>();
  const onesAt = new Map<number, number>();

  for (const id of ids) {
    const decoded = Buffer.from(id, 'base64url');
    byteLengths.add(decoded.byteLength);
    for (let position = 0; position < decoded.byteLength; position += 1) {
      const byte = decoded[position] as number;
      let seen = valuesAt.get(position);
      if (seen === undefined) {
        seen = new Set<number>();
        valuesAt.set(position, seen);
      }
      seen.add(byte);
      for (let bit = 0; bit < 8; bit += 1) {
        if ((byte & (1 << bit)) !== 0) {
          const key = position * 8 + bit;
          onesAt.set(key, (onesAt.get(key) ?? 0) + 1);
        }
      }
    }
  }

  const widestByteLength = Math.max(...byteLengths);
  let minDistinctPerPosition = Number.POSITIVE_INFINITY;
  for (let position = 0; position < widestByteLength; position += 1) {
    minDistinctPerPosition = Math.min(minDistinctPerPosition, valuesAt.get(position)?.size ?? 0);
  }

  let worstBitBias = 0;
  for (let bit = 0; bit < widestByteLength * 8; bit += 1) {
    const ratio = (onesAt.get(bit) ?? 0) / ids.length;
    worstBitBias = Math.max(worstBitBias, Math.abs(ratio - 0.5));
  }

  return {
    distinct: distinct.size,
    byteLengths: [...byteLengths].sort((a, b) => a - b),
    minDistinctPerPosition,
    worstBitBias,
  };
}

/**
 * The bar every position must clear.
 *
 * With 10 000 draws a uniform byte position takes ~256 distinct values (the
 * chance of fewer than 240 is far beyond any flake budget), and a uniform bit
 * position lands at 0.5 with a standard deviation of 0.005 — so 0.06 is twelve
 * standard deviations of headroom. Both numbers are chosen so a correct
 * generator cannot fail and a padded one cannot pass.
 */
const MIN_DISTINCT_PER_POSITION = 240;
const MAX_BIT_BIAS = 0.06;

// ---------------------------------------------------------------------------
// 0. The file's own constraints (US-28 acceptance criterion 12)
// ---------------------------------------------------------------------------

describe('US-28b §0: this suite binds port 0 and never imports the entrypoint', () => {
  test('no listener in this file can bind a fixed port, and the entrypoint is not imported', () => {
    const source = readFileSync(THIS_FILE, 'utf8');

    // Every occurrence of the port variable, whatever the fixture, is '0'. The
    // variable name is assembled rather than written, so this scan does not
    // match its own pattern literal and report a phantom binding.
    const portKey = ['UNIFI', 'HTTP', 'PORT'].join('_');
    const ports = [...source.matchAll(new RegExp(`${portKey}\\W+'([^']*)'`, 'g'))].map((m) => m[1]);
    assert.ok(ports.length > 0, 'the port fixture was renamed and this scan went blind');
    assert.deepEqual([...new Set(ports)], ['0'], 'a listener in this file binds a fixed port');

    // S-09: the entrypoint is never imported in-process by a serving test.
    // Both needles are assembled for the same reason as the port key above.
    const entrypointModule = ['src', 'index.js'].join('/');
    const entrypointSource = ['src', 'index.ts'].join('/');
    assert.equal(source.includes(entrypointModule), false, 'the entrypoint module is imported');
    assert.equal(source.includes(entrypointSource), false, 'the entrypoint source is referenced');
  });
});

// ---------------------------------------------------------------------------
// 1. 100 abandoned sessions, evicted by the production periodic trigger
// ---------------------------------------------------------------------------

describe('US-28b §1: 100 abandoned sessions return the map AND the instances to 0', () => {
  test('C6: the TTL boundary at scale, driven ONLY by the production sweep interval', async (t) => {
    const TTL = 300_000;
    const bound = await boundServer(t, {
      env: httpEnv({
        UNIFI_HTTP_MAX_SESSIONS: '128',
        UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL),
      }),
    });
    await waitReady(bound);

    // The production call site armed the real formula, not a test constant.
    assert.equal(bound.sweep.intervalMs, sessionSweepIntervalMs(TTL));
    assert.equal(bound.sweep.fired, 0, 'the sweep fired before this test asked it to');

    const openedAtMs = bound.clock.ms;
    const ids: string[] = [];
    for (let i = 0; i < SESSIONS; i += 1) ids.push(await openSessionOverSocket(bound.port));
    assert.equal(new Set(ids).size, SESSIONS, 'two abandoned sessions shared an identifier');

    assert.ok(
      await until(() => bound.serving.sessionCount() === SESSIONS),
      `only ${bound.serving.sessionCount()} of ${SESSIONS} sessions were registered`,
    );
    assert.equal(bound.instances.live(), SESSIONS, 'a per-session MCP server was never built');
    assert.equal(bound.instances.closed, 0, 'a session was torn down before the TTL');

    // ---- One millisecond BEFORE the TTL -----------------------------------
    //
    // The same tick, on the same registry, at a clock one millisecond short of
    // the boundary. It must evict NOTHING. Without this half, "they all went
    // away after I fired the tick" is equally consistent with a sweep that
    // ignores the TTL entirely and evicts every idle-looking session on sight.
    bound.clock.ms = openedAtMs + TTL - 1;
    bound.sweep.tick();
    await settle(200);

    assert.equal(bound.serving.sessionCount(), SESSIONS, 'a session was evicted before its TTL');
    assert.equal(bound.instances.live(), SESSIONS);
    assert.equal(bound.instances.closed, 0);

    // ---- The boundary itself ----------------------------------------------
    //
    // One more millisecond, and the SAME production trigger. Not a single
    // millisecond of wall time has passed: the TTL here is a number.
    bound.clock.ms = openedAtMs + TTL;
    bound.sweep.tick();

    assert.ok(
      await until(() => bound.serving.sessionCount() === 0),
      `the reservation counter stalled at ${bound.serving.sessionCount()}`,
    );
    assert.equal(bound.instances.live(), 0, 'per-session MCP server instances were retained');
    assert.equal(bound.instances.built, SESSIONS);
    assert.equal(bound.instances.closed, SESSIONS);
    assert.deepEqual(
      [...new Set(bound.instances.closesByInstance)],
      [1],
      'a session was closed more than once, or not at all',
    );
    // Exactly two ticks were ever fired, and only the second one did anything.
    assert.equal(bound.sweep.fired, 2);
  });

  test('the MAP is empty, not merely the counter: all 100 identifiers now read as never-existed', async (t) => {
    const TTL = 60_000;
    const bound = await boundServer(t, {
      env: httpEnv({
        UNIFI_HTTP_MAX_SESSIONS: '128',
        UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL),
      }),
    });
    await waitReady(bound);

    const openedAtMs = bound.clock.ms;
    const ids: string[] = [];
    for (let i = 0; i < SESSIONS; i += 1) ids.push(await openSessionOverSocket(bound.port));
    assert.ok(await until(() => bound.serving.sessionCount() === SESSIONS));

    // Every one of the hundred is genuinely live and routable BEFORE the sweep,
    // so the comparison after it is against a real state change and not against
    // a set of identifiers the server never honoured in the first place.
    const beforeStatuses = await mapLimited(ids, 8, async (id) => {
      const captured = await exchange(bound.port, callOnSession(bound.port, id), {
        settleWhen: (text) => /\n\n$/.test(text) || completeJsonBody(text),
      });
      return statusOf(captured);
    });
    assert.deepEqual(
      [...new Set(beforeStatuses)],
      [200],
      'a live session did not answer on the identifier it minted',
    );

    bound.clock.ms = openedAtMs + TTL;
    bound.sweep.tick();
    assert.ok(await until(() => bound.serving.sessionCount() === 0));

    // THE ASSERTION THE COUNTER CANNOT MAKE. `sessions` and `reserved` are two
    // hand-maintained variables in `http.ts`; a `reserved -= 1` without the
    // matching `sessions.delete` satisfies `sessionCount() === 0` while a
    // hundred entries — a hundred `McpServer`s, a hundred transports and a
    // hundred bearer-equivalent identifiers — remain reachable. So the map is
    // read through the only door it has: the wire.
    const neverExisted = await exchange(
      bound.port,
      callOnSession(bound.port, createSessionId()),
      { settleWhen: completeJsonBody },
    );
    assert.equal(statusOf(neverExisted), 404);
    const expectedBody = bodyOf(neverExisted);
    assert.match(expectedBody, /-32001/, 'the unknown-session answer changed shape');

    const answers = await mapLimited(ids, 8, async (id) => {
      const captured = await exchange(bound.port, callOnSession(bound.port, id), {
        settleWhen: completeJsonBody,
      });
      return { status: statusOf(captured), body: bodyOf(captured) };
    });

    assert.deepEqual(
      [...new Set(answers.map((a) => a.status))],
      [404],
      'a swept identifier still routed to a session',
    );
    assert.deepEqual(
      [...new Set(answers.map((a) => a.body))],
      [expectedBody],
      'an evicted identifier is distinguishable from one that never existed',
    );
    // Every identifier is also absent from every answer — an evicted id is
    // never echoed back, which is what stops the reply confirming a harvest.
    for (const id of ids) {
      assert.equal(expectedBody.includes(id), false, 'the answer echoed an identifier');
    }
  });
});

// ---------------------------------------------------------------------------
// 2. 100 failed initialize attempts, released IMMEDIATELY
// ---------------------------------------------------------------------------

describe('US-28b §2: 100 failed initialize attempts return the count to 0 immediately', () => {
  test('C6: a cap of ONE, a frozen clock and a sweep that is never fired — the SDK rejection arm', async (t) => {
    const TTL = 300_000;
    const bound = await boundServer(t, {
      env: httpEnv({
        // A cap of one. A SINGLE leaked reservation turns attempt 2 into a 503
        // naming `UNIFI_HTTP_MAX_SESSIONS`, so this loop fails on the first
        // leak rather than on the fourth — US-23's cap of 4 tolerates three.
        UNIFI_HTTP_MAX_SESSIONS: '1',
        UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL),
      }),
    });
    await waitReady(bound);
    const frozenAtMs = bound.clock.ms;

    const statuses = new Set<number>();
    for (let i = 0; i < SESSIONS; i += 1) {
      const captured = await exchange(
        bound.port,
        // A REAL, unmocked rejection: the SDK refuses a POST whose `Accept`
        // omits `text/event-stream`, raised before `onsessioninitialized` can
        // fire. The entry is still `pending` when the dispatch unwinds.
        initializeRequest(bound.port, 'application/json'),
        { settleWhen: completeJsonBody },
      );
      statuses.add(statusOf(captured));
      assert.equal(sessionIdOf(captured), null, `attempt ${i} minted a session identifier`);
      // Per attempt, not merely at the end: a leak of one is caught at the
      // attempt that leaked rather than aggregated away a hundred later.
      assert.ok(
        await until(() => bound.serving.sessionCount() === 0, 200),
        `attempt ${i} left the reservation counter at ${bound.serving.sessionCount()}`,
      );
      assert.equal(bound.instances.live(), 0, `attempt ${i} left an MCP server alive`);
    }
    assert.deepEqual([...statuses], [406], 'an attempt was refused by the cap, not by the SDK');

    // OBSERVED AT SCALE, pinned with its reasoning rather than left implicit.
    // `openSession()` runs BEFORE the SDK ever inspects the request, so each of
    // the hundred rejections cost a full identifier draw and a full `McpServer`
    // construct-connect-close cycle. Nothing LEAKS — `live()` was 0 after every
    // single one, which is the criterion — but the work is real and it is
    // amplification available to any holder of the bearer secret. An
    // implementation that deferred construction until after the SDK's own
    // validation would drive both numbers to 0; that would be an improvement,
    // and this assertion exists so that it is a deliberate change rather than
    // silent drift in either direction.
    assert.equal(bound.instances.built, SESSIONS, 'a rejected initialize built no session');
    assert.equal(bound.instances.closed, SESSIONS, 'a rejected initialize left a server open');

    // ---- Why this is not the TTL -------------------------------------------
    //
    // Three independent proofs, because "the count is 0" on its own is equally
    // consistent with a TTL that happened to elapse.
    //
    // (a) The clock never moved. Not one millisecond, injected or real.
    assert.equal(bound.clock.ms, frozenAtMs, 'the injected clock advanced during the loop');
    // (b) The periodic sweep was never fired. Its production trigger is
    //     captured by this file and nothing called it.
    assert.equal(bound.sweep.fired, 0, 'the periodic sweep ran');
    // (c) POSITIVELY: nothing was ever waiting to expire. A sweep fast-forwarded
    //     ten TTLs into the future finds ZERO expiring entries — so the counter
    //     did not reach 0 because entries aged out, it reached 0 because there
    //     were no entries to age.
    assert.equal(
      await bound.serving.sweepIdleSessions(frozenAtMs + TTL * 10),
      0,
      'a failed initialize left an entry that was merely waiting for the TTL',
    );
    assert.equal(bound.serving.sessionCount(), 0);

    // The cap of one is genuinely free at the frozen clock.
    bound.clock.ms = frozenAtMs;
    assert.ok(await openSessionOverSocket(bound.port));
    assert.ok(await until(() => bound.serving.sessionCount() === 1));
    assert.equal(bound.instances.live(), 1);
  });

  test('the OTHER non-promotion arm: openSession() itself throwing releases just as immediately', async (t) => {
    const TTL = 300_000;
    let failing = true;
    const bound = await boundServer(t, {
      env: httpEnv({
        UNIFI_HTTP_MAX_SESSIONS: '1',
        UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL),
      }),
      failOpenSession: () => failing,
    });
    await waitReady(bound);
    const frozenAtMs = bound.clock.ms;

    // `admitSession` has TWO release branches and US-23's suite exercises only
    // one. This is the other: `openSession()` throws before anything is
    // inserted, so nothing exists for `terminateSession` to find and the
    // `finally` must decrement directly. Get that branch wrong and the counter
    // never comes back down, which at a cap of one is a server that refuses
    // every subsequent client for the rest of its life.
    const statuses = new Set<number>();
    for (let i = 0; i < SESSIONS; i += 1) {
      const captured = await exchange(bound.port, initializeRequest(bound.port), {
        settleWhen: completeJsonBody,
      });
      statuses.add(statusOf(captured));
      assert.ok(
        await until(() => bound.serving.sessionCount() === 0, 200),
        `attempt ${i} left the reservation counter at ${bound.serving.sessionCount()}`,
      );
    }
    // The fail-closed boundary answers an authenticated caller with a bare 500;
    // a 503 here would mean the cap had been consumed by a leaked reservation.
    assert.deepEqual([...statuses], [500], 'the construction failure did not fail closed');
    assert.equal(bound.instances.built, 0, 'a session was built despite the injected failure');

    assert.equal(bound.clock.ms, frozenAtMs);
    assert.equal(bound.sweep.fired, 0);
    assert.equal(await bound.serving.sweepIdleSessions(frozenAtMs + TTL * 10), 0);

    // And the server is still fully usable: 100 hard construction failures cost
    // it nothing at all.
    failing = false;
    assert.ok(await openSessionOverSocket(bound.port));
    assert.ok(await until(() => bound.serving.sessionCount() === 1));
    assert.equal(bound.instances.live(), 1);
  });
});

// ---------------------------------------------------------------------------
// 3. Identifiers — at the wire, and at 10 000 draws
// ---------------------------------------------------------------------------

describe('US-28b §3: identifiers, verified at the wire and by distribution', () => {
  test('the identifier the SERVER puts on the wire is the identifier it drew, one draw per session', async (t) => {
    const sizes = new Set<number>();
    let draws = 0;
    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '128', UNIFI_HTTP_SESSION_IDLE_TTL_MS: '300000' }),
      // Only the CSPRNG byte source is instrumented. The algorithm, the encoding
      // and the size are the production ones — FR-77's `randomSource` default
      // parameter exists for exactly this, and Node 20 has no `mock.module`.
      drawBytes: (size) => {
        draws += 1;
        sizes.add(size);
        return randomBytes(size);
      },
    });
    await waitReady(bound);

    const onWire: string[] = [];
    for (let i = 0; i < SESSIONS; i += 1) onWire.push(await openSessionOverSocket(bound.port));

    // US-23 asserts these properties of `createSessionId`. This asserts them of
    // the value a CLIENT actually receives, which is a different claim: between
    // the draw and the header sit `openSession`, `options.transportOptionsFor`,
    // the SDK's `sessionIdGenerator` plumbing and `promoteSession`'s re-key. A
    // truncation, a re-encode or a second draw anywhere along that path is
    // invisible to a unit test of the generator and fatal here.
    assert.equal(draws, SESSIONS, 'the server did not draw exactly once per admitted session');
    assert.deepEqual([...sizes], [EXPECTED_ID_BYTES], 'the draw size varied');
    assert.deepEqual(
      bound.drawn,
      onWire,
      'the identifier on the wire is not the identifier the server drew',
    );
    assert.equal(new Set(onWire).size, SESSIONS, 'two live sessions shared an identifier');
    for (const id of onWire) {
      assert.equal(Buffer.from(id, 'base64url').byteLength, EXPECTED_ID_BYTES);
      assert.match(id, /^[A-Za-z0-9_-]+$/, 'the identifier is not base64url on the wire');
    }
    assert.ok(
      EXPECTED_ID_BYTES * 8 >= ENTROPY_FLOOR_BITS,
      'NFR-30 floors the entropy at 128 bits',
    );
  });

  test('C6: 10 000 draws — 0 duplicates, one CSPRNG draw each, and bytes that are ACTUALLY random', () => {
    let draws = 0;
    const sizes = new Set<number>();
    const ids: string[] = [];
    for (let i = 0; i < DRAWS; i += 1) {
      ids.push(
        createSessionId((size) => {
          draws += 1;
          sizes.add(size);
          return randomBytes(size);
        }),
      );
    }

    // The three literal properties, re-derived rather than assumed.
    assert.equal(new Set(ids).size, DRAWS, 'the 10 000 draws were not all distinct');
    assert.equal(draws, DRAWS, 'the generator did not draw exactly once per identifier');
    assert.deepEqual([...sizes], [EXPECTED_ID_BYTES]);

    const report = analyseDraws(ids);
    assert.equal(report.distinct, DRAWS);
    assert.deepEqual(report.byteLengths, [EXPECTED_ID_BYTES]);
    assert.ok(
      report.byteLengths[0] !== undefined && report.byteLengths[0] * 8 >= ENTROPY_FLOOR_BITS,
      'the decoded byte length does not meet the 128-bit floor',
    );

    // THE HALF A LENGTH CHECK CANNOT MAKE. Every byte position must be doing
    // work, and every bit must be balanced. A generator whose payload is eight
    // random bytes padded to thirty-two decodes to 32 bytes, collides zero
    // times in 10 000 draws and draws exactly once — and carries 64 bits.
    assert.ok(
      report.minDistinctPerPosition >= MIN_DISTINCT_PER_POSITION,
      `a byte position took only ${report.minDistinctPerPosition} distinct values in ${DRAWS} draws`,
    );
    assert.ok(
      report.worstBitBias <= MAX_BIT_BIAS,
      `a bit position was biased by ${report.worstBitBias}`,
    );
  });

  test('the distribution assertion is not vacuous: a 32-byte, 64-bit generator FAILS it', () => {
    // The negative control is executed, not described. This is the generator
    // that passes every entropy assertion written against a decoded byte
    // length, and it must not pass the one above.
    const padded: string[] = [];
    for (let i = 0; i < DRAWS; i += 1) {
      padded.push(
        createSessionId((size) => Buffer.concat([randomBytes(8), Buffer.alloc(size - 8)])),
      );
    }

    const report = analyseDraws(padded);

    // It passes the properties US-23's suite asserts …
    assert.equal(report.distinct, DRAWS, 'the control must still be duplicate-free');
    assert.deepEqual(report.byteLengths, [EXPECTED_ID_BYTES], 'the control must still be 32 bytes');

    // … and fails both of this file's.
    assert.ok(
      report.minDistinctPerPosition < MIN_DISTINCT_PER_POSITION,
      'the byte-position assertion cannot detect a padded generator',
    );
    assert.ok(
      report.worstBitBias > MAX_BIT_BIAS,
      'the bit-balance assertion cannot detect a padded generator',
    );
  });
});
