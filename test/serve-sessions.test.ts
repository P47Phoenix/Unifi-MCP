/**
 * US-23 — session lifecycle: cap, TTL, eviction, identifiers.
 *
 * Suite C of the test strategy: C3, C4, C5 and C6.
 *
 * ## The premise this file is written against
 *
 * The MCP SDK has **no session registry, map, store, TTL, cap, eviction or
 * forced-termination API at any layer**. Everything asserted below — the map,
 * the reservation counter, the sweep, the eviction path, the identifier
 * generator — is repository code, so every assertion here targets an exported
 * accessor of ours rather than an SDK affordance. There is nothing to lean on
 * and nothing to mock.
 *
 * ## Why a session is treated as a credential
 *
 * `Mcp-Session-Id` in stateful mode is bearer-equivalent (NFR-24): possession
 * is sufficient to continue a session. That is why the entropy assertion is
 * made on the DECODED BYTE LENGTH of an identifier rather than on its character
 * count — a base64 or hex encoding inflates the character count without adding
 * a bit, and a test that counts characters passes against a weak generator —
 * and why "evicted" and "never existed" must be indistinguishable in the reply.
 *
 * ## No test in this file waits on wall time for a TTL
 *
 * The clock is a default parameter (`ServingDeps.now`), the sweep is an
 * exported function taking `nowMs`, and 100 abandoned sessions are returned to
 * zero by advancing a number. Node 20 has no `mock.module`, so every seam in
 * this round is a default parameter; the clock is the one that matters most
 * here, because the alternative is a suite that takes five minutes per case.
 *
 * ## Raw sockets where BYTES matter, an SDK client where BEHAVIOUR matters
 *
 * The evicted-versus-unknown comparison is a byte comparison and cannot be made
 * through `fetch` or `http.request`, both of which normalise and reorder. The
 * abort criterion needs a real MCP client driving a real tool call.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { createServer as createNodeHttpServer, type Server } from 'node:http';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  StreamableHTTPServerTransport,
  type StreamableHTTPServerTransportOptions,
} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';

import { loadConfig } from '../src/config.js';
import {
  createServingOptions,
  createSessionId,
  sessionIsIdle,
  sessionSweepIntervalMs,
  startHttp,
  type HttpServing,
  type HttpServingDeps,
} from '../src/serve/http.js';
import { createMcpServer } from '../src/serve/mcpServer.js';
import {
  buildRuntimeCore,
  type Runtime,
  type RuntimeCore,
  type Surface,
} from '../src/serve/runtime.js';

import { createInstruments } from './harness/counters.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SERVE_ROOT = join(REPO_ROOT, 'src', 'serve');

/** 40 characters, comfortably over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;
/** A member of the SDK's `SUPPORTED_PROTOCOL_VERSIONS`, pinned rather than imported. */
const PROTOCOL_VERSION = '2025-06-18';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

interface BoundOptions {
  readonly env?: Record<string, string>;
  readonly deps?: HttpServingDeps;
  readonly clock?: Clock;
  /** Runs on every per-session `McpServer` before `connect()`. */
  readonly decorate?: (server: McpServer, index: number) => void;
}

interface Bound {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly lines: string[];
  readonly instances: InstanceLedger;
  readonly clock: Clock;
}

/**
 * Start one listener with an injected clock and a counting session factory.
 *
 * The `createMcpServer` seam is the mechanism the test strategy names for C4
 * and C5: it is the only place a test can wrap the per-session product to count
 * `close()` per session, or register a handler that actually receives `extra`.
 * The production factory funnels every tool through one action runner and hands
 * it no `extra`, by design — so the abort criterion is unobservable without it.
 */
async function boundServer(t: TestContext, options: BoundOptions = {}): Promise<Bound> {
  const lines: string[] = [];
  const clock: Clock = options.clock ?? { ms: 1_700_000_000_000 };

  const closesByInstance: number[] = [];
  const instances: InstanceLedger = {
    built: 0,
    closed: 0,
    closesByInstance,
    live(): number {
      return instances.built - instances.closed;
    },
  };

  const instruments = createInstruments({
    env: { ...(options.env ?? httpEnv()) },
    keychain: null,
    onLine: (line) => lines.push(line),
  });
  const core = buildRuntimeCore(instruments.deps);

  let server: Server | null = null;
  const serving = await startHttp(core, instruments.observer, {
    now: () => clock.ms,
    warn: (line) => lines.push(line),
    createHttpServer: (serverOptions, handler) => {
      server = createNodeHttpServer(serverOptions, handler);
      return server;
    },
    createMcpServer: (runtime: Runtime, surface: Surface): McpServer => {
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
      options.decorate?.(built, index);
      return built;
    },
    ...(options.deps ?? {}),
  });

  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  assert.ok(server !== null, 'the http server seam was not used');
  return { serving, core, port: serving.address.port, lines, instances, clock };
}

/** Wait until the registry has resolved and the readiness flag has flipped. */
async function waitReady(bound: Bound): Promise<void> {
  await bound.core.ready;
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

/** Let every already-queued continuation run before reading the registry. */
async function settle(turns = 4): Promise<void> {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
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
 * `settleWhen` exists for throughput, not convenience: an `initialize` reply is
 * an SSE stream the server holds open, so without it every one of the hundred
 * sessions this file opens would cost a full idle window and the suite would
 * spend half a minute waiting on timers it already knows the answer to.
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
    clientInfo: { name: 'us-23', version: '0' },
  },
});

/**
 * One `initialize` over a raw socket.
 *
 * `accept` is a parameter because the SDK's own `Accept` check is what produces
 * a REAL, unmocked failed `initialize` — a `406` raised before
 * `onsessioninitialized` can fire — which is exactly the shape the reservation
 * release has to survive.
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

/** Present an identifier on a request that is not an initialisation. */
function callOnSession(port: number, id: string, method = 'tools/list'): string {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 7, method, params: {} });
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

function deleteSession(port: number, id: string): string {
  return raw('DELETE /mcp HTTP/1.1', [
    `Host: 127.0.0.1:${port}`,
    `Authorization: Bearer ${SECRET}`,
    `Mcp-Session-Id: ${id}`,
    'Content-Length: 0',
  ]);
}

/** An SDK client bound to one session, torn down with the test. */
async function connectClient(
  t: TestContext,
  port: number,
  name: string,
): Promise<{ client: Client; sessionId: string }> {
  const client = new Client({ name, version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${SECRET}` } },
  });
  t.after(async () => {
    await client.close().catch(() => undefined);
  });
  await client.connect(transport);
  assert.ok(transport.sessionId !== undefined, 'the client transport never received a session id');
  return { client, sessionId: transport.sessionId };
}

function serveSources(): { file: string; source: string }[] {
  return readdirSync(SERVE_ROOT)
    .filter((name) => name.endsWith('.ts'))
    .map((name) => ({
      file: `src/serve/${name}`,
      source: readFileSync(join(SERVE_ROOT, name), 'utf8'),
    }));
}

// ---------------------------------------------------------------------------
// 1. The identifier generator (C6, FR-77, NFR-30)
// ---------------------------------------------------------------------------

describe('US-23 §1: the identifier generator is one exported function over node:crypto', () => {
  test('C6: 10 000 draws — 0 duplicates, exactly one CSPRNG draw each, asserted on DECODED bytes', () => {
    const DRAWS = 10_000;
    let calls = 0;
    const requestedSizes = new Set<number>();
    const randomSource = (size: number): Buffer => {
      calls += 1;
      requestedSizes.add(size);
      return randomBytes(size);
    };

    const ids = new Set<string>();
    const decodedLengths = new Set<number>();
    for (let i = 0; i < DRAWS; i += 1) {
      const id = createSessionId(randomSource);
      ids.add(id);
      decodedLengths.add(Buffer.from(id, 'base64url').byteLength);
    }

    assert.equal(ids.size, DRAWS, 'the 10 000 draws were not all distinct');
    // EXACTLY one draw per identifier: not "at least one", which a retry loop
    // or a rejection-sampling implementation would also satisfy.
    assert.equal(calls, DRAWS, 'the generator did not draw exactly once per identifier');
    assert.deepEqual([...requestedSizes], [32], 'the draw size varied, or was not 32 bytes');

    // THE ASSERTION THAT MATTERS. A character count is inflated by the encoding
    // — 32 bytes render as 43 base64url characters — so a test written against
    // `id.length` passes against a generator drawing far fewer bytes and
    // encoding them wider. `randomUUID()` would land here at 122 usable bits;
    // this asserts the real payload.
    assert.deepEqual([...decodedLengths], [32], 'the decoded identifier was not 32 bytes');
    assert.ok(32 * 8 >= 128, 'NFR-30 floors the entropy at 128 bits');
  });

  test('the default parameter is the production path, and it is node:crypto', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 512; i += 1) ids.add(createSessionId());
    assert.equal(ids.size, 512);
    for (const id of ids) assert.equal(Buffer.from(id, 'base64url').byteLength, 32);

    const http = readFileSync(join(SERVE_ROOT, 'http.ts'), 'utf8');
    assert.match(http, /import \{ randomBytes \} from 'node:crypto';/);
    assert.match(http, /randomSource: \(size: number\) => Buffer = randomBytes/);
  });

  test('no Math.random path exists anywhere under src/serve/', () => {
    // Comment lines are dropped before the scan, because the prose in `http.ts`
    // NAMES the prohibited call in order to explain why the CSPRNG seam exists.
    // A scan that cannot tell an explanation from a use is a scan that pressures
    // the next author to delete the explanation.
    const offenders: string[] = [];
    for (const { file, source } of serveSources()) {
      const code = source
        .split('\n')
        .filter((line) => {
          const trimmed = line.trimStart();
          return !trimmed.startsWith('*') && !trimmed.startsWith('/*') && !trimmed.startsWith('//');
        })
        .join('\n');
      if (/Math\s*\.\s*random/.test(code)) offenders.push(file);
    }
    assert.deepEqual(offenders, []);
  });

  test('sessionIdGenerator is passed EXPLICITLY — omitting it is stateless single-use mode', async (t) => {
    const config = loadConfig(httpEnv(), { repoRoot: REPO_ROOT });
    const options = createServingOptions(config).transportOptionsFor('fixed-identifier');

    // Structural: the property is present and returns the identifier handed to
    // the factory. Absent, the SDK silently switches to stateless single-use
    // mode — `validateSession` becomes a no-op and NO `mcp-session-id` header
    // is ever emitted — which is the trap this criterion exists to close.
    assert.ok('sessionIdGenerator' in options, 'sessionIdGenerator was not set at all');
    assert.equal(options.sessionIdGenerator?.(), 'fixed-identifier');

    // Behavioural, because the structural half cannot tell a present-but-wrong
    // wiring from a correct one: a live initialize must emit the header.
    const bound = await boundServer(t);
    await waitReady(bound);
    const captured = await exchange(bound.port, initializeRequest(bound.port));
    const id = sessionIdOf(captured);
    assert.ok(id !== null, 'no Mcp-Session-Id header — the transport is in stateless mode');
    assert.equal(Buffer.from(id, 'base64url').byteLength, 32);
  });
});

// ---------------------------------------------------------------------------
// 1b. The premise: the SDK supplies no part of a session registry
// ---------------------------------------------------------------------------

describe('US-23 §1b: the registry is ours in full — the SDK supplies no part of one', () => {
  test('no session registry, store, TTL, cap, eviction or forced-termination API exists', () => {
    // Pinned as an ASSERTION rather than left as prose, so an SDK bump that
    // introduced any of these turns this red and forces a deliberate decision
    // instead of leaving two registries quietly coexisting.
    const surface = new Set<string>();
    for (
      let proto: object | null = StreamableHTTPServerTransport.prototype;
      proto !== null && proto !== Object.prototype;
      proto = Object.getPrototypeOf(proto) as object | null
    ) {
      for (const name of Object.getOwnPropertyNames(proto)) surface.add(name);
    }

    for (const absent of [
      'getSessions',
      'listSessions',
      'activeSessions',
      'sessions',
      'sessionStore',
      'evictSession',
      'terminateSession',
      'setSessionTtl',
      'maxSessions',
    ]) {
      assert.equal(surface.has(absent), false, `the SDK now offers ${absent}; reconcile the registry`);
    }

    // The transport's ENTIRE session state is one public field. Everything else
    // — the map, the reservation counter, the sweep, the eviction path — is
    // repository code, which is why every assertion in this file reads one of
    // our own accessors.
    assert.equal(surface.has('sessionId'), true, 'the one field the SDK does expose has moved');
  });
});

// ---------------------------------------------------------------------------
// 2. `transport.onclose` is never assigned — the source scan (C5, structural)
// ---------------------------------------------------------------------------

describe('US-23 §2: transport.onclose is never assigned, asserted over the source', () => {
  test('C5: no assignment to transport.onclose appears anywhere under src/serve/', () => {
    // A BEHAVIOURAL TEST ALONE IS NOT ENOUGH, which is why this scan exists
    // beside §7's abort proof. `connect()` installs its own wrapper on
    // `transport.onclose`; assigning it afterwards overwrites that wrapper and
    // silently disables `Protocol._onclose()` — no handler aborted, no timer
    // cleared, no pending request rejected, no error and no log line. A future
    // edit could reintroduce it on a path no behavioural test drives, and only
    // a test that reads the source catches it before it ships.
    const offenders: string[] = [];
    for (const { file, source } of serveSources()) {
      if (/\btransport\s*\.\s*onclose\s*=/.test(source)) offenders.push(`${file}: transport.onclose =`);
      // Any receiver, so a rename to `t.onclose = …` cannot slip through: the
      // ONLY permitted assignment target is a `server` receiver.
      for (const match of source.matchAll(/(\w+)\s*\.\s*onclose\s*=/g)) {
        if (match[1] !== 'server') offenders.push(`${file}: ${match[0]}`);
      }
    }
    assert.deepEqual(offenders, []);
  });

  test('the scan is not vacuous: server.onclose IS the wiring that is used', () => {
    const http = readFileSync(join(SERVE_ROOT, 'http.ts'), 'utf8');
    assert.match(http, /server\.onclose\s*=/, 'the per-session cleanup hook is not server.onclose');
    assert.equal(
      [...http.matchAll(/(\w+)\s*\.\s*onclose\s*=/g)].length >= 1,
      true,
      'the pattern the scan looks for does not occur at all, so the scan proves nothing',
    );
  });
});

// ---------------------------------------------------------------------------
// 3. The cap, enforced against a reservation counter (C6, FR-77, NFR-30)
// ---------------------------------------------------------------------------

describe('US-23 §3: the session cap', () => {
  test('C6: MAX_SESSIONS + 1 initialize calls — the last is refused, the others still work', async (t) => {
    const bound = await boundServer(t, { env: httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '2' }) });
    await waitReady(bound);

    const a = await connectClient(t, bound.port, 'us-23-a');
    const b = await connectClient(t, bound.port, 'us-23-b');
    assert.equal(bound.serving.sessionCount(), 2);

    const refused = await exchange(bound.port, initializeRequest(bound.port));
    assert.equal(statusOf(refused), 503);

    // Names BOTH variables, and that is normative rather than helpful. Naming
    // only the cap answers the wrong question in the common case: a server at
    // the cap is far more often holding N zombie sessions than serving N live
    // clients, and the TTL is the actual fix.
    assert.match(refused.text, /UNIFI_HTTP_MAX_SESSIONS/);
    assert.match(refused.text, /UNIFI_HTTP_SESSION_IDLE_TTL_MS/);

    const parsed = JSON.parse(bodyOf(refused)) as {
      jsonrpc: string;
      id: number | string | null;
      error: { code: number; message: string };
    };
    assert.equal(parsed.jsonrpc, '2.0');
    assert.equal(parsed.error.code, -32000);
    assert.equal(parsed.id, 1, "the caller's own JSON-RPC id is echoed (contract §5.12)");
    // The variable NAMES appear; no configured VALUE does.
    assert.equal(/\b2\b/.test(parsed.error.message), false);

    // NFR-24's closed vocabulary: `session_limit` means the cap was reached and
    // nothing else.
    assert.ok(
      bound.lines.some(
        (line) => line.includes('status=503') && line.includes('reject_reason=session_limit'),
      ),
      `no session_limit line was emitted:\n${bound.lines.join('\n')}`,
    );

    // EVICTION IS NEVER USED TO MAKE ROOM. Both existing sessions are untouched
    // and fully functional after the refusal; a caller at the cap is told to
    // wait or reduce use, never handed a slot taken from someone else.
    assert.equal(bound.serving.sessionCount(), 2);
    assert.ok((await a.client.listTools()).tools.length > 0);
    assert.ok((await b.client.listTools()).tools.length > 0);
    assert.equal(bound.instances.closed, 0, 'a live session was closed to make room');
  });

  test('the cap is a SYNCHRONOUS reservation counter, not map size', async (t) => {
    // The deterministic form of the race. `openSession` inserts its entry only
    // AFTER `server.connect(transport)` resolves, so while the first initialize
    // is parked at the gate THE MAP IS EMPTY. A cap enforced against
    // `sessions.size` admits the second request here and takes the registry to
    // two at a cap of one; a reservation counter refuses it.
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let held = 0;

    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '1' }),
      decorate: (server) => {
        const originalConnect = server.connect.bind(server);
        server.connect = async (transport): Promise<void> => {
          held += 1;
          await gate;
          await originalConnect(transport);
        };
      },
    });
    await waitReady(bound);

    const first = exchange(bound.port, initializeRequest(bound.port));
    for (let i = 0; i < 400 && held === 0; i += 1) await settle(1);
    assert.equal(held, 1, 'the first initialize never reached the connect gate');
    assert.equal(bound.serving.sessionCount(), 1, 'the reservation was not taken before the await');

    const second = await exchange(bound.port, initializeRequest(bound.port));
    assert.equal(statusOf(second), 503, 'a second initialize was admitted while the map was empty');
    assert.match(bodyOf(second), /UNIFI_HTTP_MAX_SESSIONS/);
    assert.equal(held, 1, 'a second session was constructed past the cap');

    release();
    const admitted = await first;
    assert.ok(sessionIdOf(admitted) !== null);
    assert.equal(bound.serving.sessionCount(), 1);
  });

  test('C6: 100 FAILED initialize attempts return the count to 0 immediately, not after the TTL', async (t) => {
    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '4', UNIFI_HTTP_SESSION_IDLE_TTL_MS: '300000' }),
    });
    await waitReady(bound);

    // A REAL, unmocked rejection: the SDK refuses a POST whose `Accept` omits
    // `text/event-stream` with a 406, raised before `onsessioninitialized` can
    // fire. The entry is therefore still `pending` when the dispatch unwinds,
    // and only the release in the `finally` keeps four such attempts from
    // filling a cap of four for a full five minutes.
    for (let i = 0; i < 100; i += 1) {
      const captured = await exchange(bound.port, initializeRequest(bound.port, 'application/json'), {
        settleWhen: completeJsonBody,
      });
      assert.equal(statusOf(captured), 406, `attempt ${i} did not fail as expected`);
      assert.equal(sessionIdOf(captured), null);
    }

    await settle();
    // IMMEDIATELY: the clock has not moved by a single millisecond, so nothing
    // here can be the TTL doing the work.
    assert.equal(bound.serving.sessionCount(), 0);
    assert.equal(bound.instances.live(), 0, 'a per-session MCP server survived a failed initialize');
    // And the cap is genuinely free afterwards.
    assert.ok(await openSessionOverSocket(bound.port));
    assert.equal(bound.serving.sessionCount(), 1);
  });
});

// ---------------------------------------------------------------------------
// 4. The TTL sweep (C6, FR-77, NFR-30)
// ---------------------------------------------------------------------------

describe('US-23 §4: the idle TTL sweep', () => {
  test('C6: 100 abandoned sessions return the map AND the instance count to 0', async (t) => {
    const TTL = 300_000;
    const bound = await boundServer(t, {
      env: httpEnv({
        UNIFI_HTTP_MAX_SESSIONS: '200',
        UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL),
      }),
    });
    await waitReady(bound);

    // Abandoned without `DELETE`, with the connection DROPPED rather than
    // closed — the shape a crashed client leaves behind, and the one nothing
    // else in the system cleans up.
    for (let i = 0; i < 100; i += 1) await openSessionOverSocket(bound.port);
    await settle();

    assert.equal(bound.serving.sessionCount(), 100);
    assert.equal(bound.instances.live(), 100);

    // Not one millisecond of wall time. Waiting out a real TTL is what this
    // seam exists to avoid, and a heap measurement — the other way to ask this
    // question — would flake.
    bound.clock.ms += TTL;
    const evicted = await bound.serving.sweepIdleSessions(bound.clock.ms);

    assert.equal(evicted, 100);
    assert.equal(bound.serving.sessionCount(), 0, 'the session map did not return to zero');
    assert.equal(bound.instances.live(), 0, 'per-session MCP server instances were retained');
    assert.deepEqual(
      [...new Set(bound.instances.closesByInstance)],
      [1],
      'a session was closed more than once, or not at all',
    );
  });

  test('the sweep runs BEFORE the cap check on every initialize', async (t) => {
    const TTL = 60_000;
    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '1', UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL) }),
    });
    await waitReady(bound);

    await openSessionOverSocket(bound.port);
    await settle();
    assert.equal(bound.serving.sessionCount(), 1);

    // Without the pre-check sweep this is a `503` naming the cap — a refusal
    // wrong by up to a whole sweep interval's worth of already-dead sessions,
    // whose only signal cannot distinguish one live client from one zombie.
    bound.clock.ms += TTL;
    const admitted = await exchange(bound.port, initializeRequest(bound.port));
    assert.equal(statusOf(admitted), 200, `the pre-check sweep did not run:\n${admitted.text}`);
    assert.ok(sessionIdOf(admitted) !== null);
    assert.equal(bound.serving.sessionCount(), 1);
    assert.equal(bound.instances.built, 2);
    assert.equal(
      bound.instances.closed,
      1,
      'the expired session was not evicted by the pre-check sweep',
    );
  });

  test('the interval is min(ttl/4, 30_000) and it is unref()’d', async (t) => {
    assert.equal(sessionSweepIntervalMs(40_000), 10_000);
    assert.equal(sessionSweepIntervalMs(120_000), 30_000);
    // Ceilinged, not simply a quarter: a one-hour TTL must not mean a
    // fifteen-minute gap before an abandoned server's map returns to zero.
    assert.equal(sessionSweepIntervalMs(3_600_000), 30_000);
    assert.equal(sessionSweepIntervalMs(4), 1);

    const TTL = 40_000;
    let capturedMs = -1;
    let capturedTimer: NodeJS.Timeout | null = null;
    let capturedTick: (() => void) | null = null;

    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL) }),
      deps: {
        createSweepInterval: (tick, intervalMs) => {
          capturedMs = intervalMs;
          capturedTick = tick;
          capturedTimer = setInterval(tick, intervalMs);
          return capturedTimer;
        },
      },
    });
    await waitReady(bound);

    assert.equal(capturedMs, sessionSweepIntervalMs(TTL));
    assert.equal(capturedMs, 10_000);
    const timer = capturedTimer as NodeJS.Timeout | null;
    assert.ok(timer !== null, 'the sweep interval was never armed');
    // `unref()` is applied AT THE CALL SITE rather than inside the seam, so
    // this reads the production wiring. A ref'd housekeeping sweep would hold
    // a drained server — and every test process — open for a quarter of the TTL.
    assert.equal(timer.hasRef(), false, 'the sweep timer was not unref()’d');

    // The interval drives the same eviction path, which is why it exists: a
    // server abandoned entirely receives no further `initialize`, so the
    // pre-check sweep never runs again and FR-77 still requires zero.
    await openSessionOverSocket(bound.port);
    await settle();
    assert.equal(bound.serving.sessionCount(), 1);
    bound.clock.ms += TTL;
    const tick = capturedTick as (() => void) | null;
    assert.ok(tick !== null);
    tick();
    await settle(8);
    assert.equal(bound.serving.sessionCount(), 0);
  });

  test('the idle predicate: an open stream or an in-flight request is never idle', () => {
    const TTL = 1_000;
    const base = { inFlightRequests: 0, openStreams: 0, lastActivityMs: 0 };

    assert.equal(sessionIsIdle(base, TTL, TTL), true, 'exactly at the TTL is idle');
    assert.equal(sessionIsIdle(base, TTL - 1, TTL), false, 'one millisecond short is not idle');

    // Never idle, regardless of how long ago the last activity was.
    assert.equal(sessionIsIdle({ ...base, inFlightRequests: 1 }, 10 * TTL, TTL), false);
    assert.equal(sessionIsIdle({ ...base, openStreams: 1 }, 10 * TTL, TTL), false);
    assert.equal(
      sessionIsIdle({ ...base, inFlightRequests: 1, openStreams: 1 }, 10 * TTL, TTL),
      false,
    );
  });

  test('last activity is touched on COMPLETION as well as arrival', async (t) => {
    const TTL = 10_000;
    const clock: Clock = { ms: 1_700_000_000_000 };

    // A tool whose handler advances the clock past the TTL while it runs. On
    // arrival the session's last activity is the request's start; if only
    // arrival is touched, the sweep that follows sees a full TTL of inactivity
    // and evicts a session whose request has just this instant completed. A
    // real tool call at the defaults — three attempts at 25 s plus two honoured
    // `Retry-After` waits — is ~115 s, so this is not a hypothetical shape.
    const bound = await boundServer(t, {
      clock,
      env: httpEnv({ UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL) }),
      decorate: (server) => {
        server.registerTool(
          'us23_slow_clock',
          { description: 'Advances the injected clock past the TTL.', inputSchema: {} },
          (async () => {
            clock.ms += TTL;
            await settle(1);
            return { content: [{ type: 'text' as const, text: 'done' }] };
          }) as never,
        );
      },
    });
    await waitReady(bound);

    const id = await openSessionOverSocket(bound.port);
    await settle();
    const startedAt = clock.ms;

    const called = await exchange(
      bound.port,
      raw(
        'POST /mcp HTTP/1.1',
        [
          `Host: 127.0.0.1:${bound.port}`,
          `Authorization: Bearer ${SECRET}`,
          'Content-Type: application/json',
          'Accept: application/json, text/event-stream',
          `Mcp-Session-Id: ${id}`,
          `Mcp-Protocol-Version: ${PROTOCOL_VERSION}`,
          `Content-Length: ${
            Buffer.byteLength(
              JSON.stringify({
                jsonrpc: '2.0',
                id: 9,
                method: 'tools/call',
                params: { name: 'us23_slow_clock', arguments: {} },
              }),
            )
          }`,
        ],
        JSON.stringify({
          jsonrpc: '2.0',
          id: 9,
          method: 'tools/call',
          params: { name: 'us23_slow_clock', arguments: {} },
        }),
      ),
    );
    assert.equal(statusOf(called), 200, `the tool call did not run:\n${called.text}`);
    await settle();

    assert.equal(clock.ms - startedAt, TTL, 'the handler did not advance the clock as intended');
    const evicted = await bound.serving.sweepIdleSessions(clock.ms);
    assert.equal(
      evicted,
      0,
      'the session was evicted at the instant its request completed — completion is not touching lastActivity',
    );
    assert.equal(bound.serving.sessionCount(), 1);
  });
});

// ---------------------------------------------------------------------------
// 5. Eviction is the termination path, not a map delete
// ---------------------------------------------------------------------------

describe('US-23 §5: eviction runs the same termination path as a drain', () => {
  test('an evicted identifier and one that never existed are rejected BYTE-IDENTICALLY', async (t) => {
    const TTL = 5_000;
    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL) }),
    });
    await waitReady(bound);

    const id = await openSessionOverSocket(bound.port);
    await settle();
    bound.clock.ms += TTL;
    assert.equal(await bound.serving.sweepIdleSessions(bound.clock.ms), 1);
    assert.equal(bound.instances.closed, 1, 'eviction did not close the MCP server');
    assert.equal(bound.serving.sessionCount(), 0, 'our own code did not delete the registry entry');

    const evicted = await exchange(bound.port, callOnSession(bound.port, id));
    // A well-formed identifier of exactly the same shape that never existed.
    const neverExisted = await exchange(bound.port, callOnSession(bound.port, createSessionId()));

    assert.equal(statusOf(evicted), 404);
    // Byte identity, not merely "both are 404": a caller who has harvested an
    // identifier must not be able to determine from the reply whether it was
    // ever live.
    assert.equal(
      Buffer.compare(evicted.bytes, neverExisted.bytes),
      0,
      `an evicted identifier is distinguishable from an unknown one:\n${evicted.text}\n---\n${neverExisted.text}`,
    );
    assert.equal(evicted.text.includes(id), false, 'the identifier was echoed back');
  });

  test('eviction sends the terminal frame, closes the server, and fires NO SDK callback', async (t) => {
    const TTL = 5_000;
    const sent: JSONRPCMessage[] = [];
    const sessionClosedCallbacks: string[] = [];

    const bound = await boundServer(t, {
      env: httpEnv({ UNIFI_HTTP_SESSION_IDLE_TTL_MS: String(TTL) }),
      deps: {
        createTransport: (options: StreamableHTTPServerTransportOptions) => {
          const ours = options.onsessionclosed;
          const transport = new StreamableHTTPServerTransport({
            ...options,
            onsessionclosed: async (closed: string) => {
              sessionClosedCallbacks.push(closed);
              await ours?.(closed);
            },
          });
          const originalSend = transport.send.bind(transport);
          transport.send = async (message, sendOptions): Promise<void> => {
            sent.push(message);
            await originalSend(message, sendOptions);
          };
          return transport;
        },
      },
    });
    await waitReady(bound);

    await openSessionOverSocket(bound.port);
    await settle();
    sent.length = 0;

    bound.clock.ms += TTL;
    await bound.serving.sweepIdleSessions(bound.clock.ms);
    await settle();

    // `onsessionclosed` is DELETE-ONLY. It does not fire from `close()` and it
    // does not fire for an eviction — a design that waits for it to clean up
    // after an eviction leaks every abandoned session, which is the exact
    // failure FR-77 exists to prevent.
    assert.deepEqual(sessionClosedCallbacks, [], 'an SDK callback fired for an eviction');

    const terminal = sent.find(
      (frame) => (frame as { method?: string }).method === 'notifications/message',
    ) as { params?: { level?: string; logger?: string; data?: string } } | undefined;
    assert.ok(
      terminal !== undefined,
      `no terminal frame was attempted:\n${JSON.stringify(sent, null, 2)}`,
    );
    assert.equal(terminal.params?.level, 'error');
    assert.equal(terminal.params?.logger, 'unifi-mcp');
    assert.match(String(terminal.params?.data), /not accepting new requests/);

    assert.equal(bound.instances.closed, 1, 'the MCP server was not closed');
    assert.equal(bound.serving.sessionCount(), 0);
  });
});

// ---------------------------------------------------------------------------
// 6. Two concurrent sessions (C3, C4)
// ---------------------------------------------------------------------------

describe('US-23 §6: two concurrent sessions are independent', () => {
  test('C3/C4: distinct ids, one instance each, and DELETE closes exactly one', async (t) => {
    const bound = await boundServer(t);
    await waitReady(bound);

    const idA = await openSessionOverSocket(bound.port);
    const idB = await openSessionOverSocket(bound.port);
    await settle();

    assert.notEqual(idA, idB);
    assert.equal(bound.serving.sessionCount(), 2);
    // ONE `McpServer` per session, forced rather than chosen: `Protocol.connect`
    // throws on a second transport for one instance.
    assert.equal(bound.instances.built, 2);
    assert.equal(bound.instances.live(), 2);

    const deleted = await exchange(bound.port, deleteSession(bound.port, idA));
    assert.equal(statusOf(deleted), 200);
    await settle();

    // The close SPY fired exactly once for A and zero times for B — an
    // assertion about the per-session server, not about a socket ending.
    assert.deepEqual(bound.instances.closesByInstance, [1, 0]);
    assert.equal(bound.serving.sessionCount(), 1);

    // A is gone and indistinguishable from an identifier that never existed;
    // B is fully functional.
    const goneA = await exchange(bound.port, callOnSession(bound.port, idA));
    assert.equal(statusOf(goneA), 404);
    const liveB = await exchange(bound.port, callOnSession(bound.port, idB));
    assert.equal(statusOf(liveB), 200, `session B stopped working:\n${liveB.text}`);
    assert.equal(bound.instances.closesByInstance[1], 0);
  });
});

// ---------------------------------------------------------------------------
// 7. Closing a session aborts its in-flight handlers (C5, behavioural)
// ---------------------------------------------------------------------------

describe('US-23 §7: closing a session aborts a long-running tool handler', () => {
  test('C5: the handler observes extra.signal firing — a run where it does not FAILS', async (t) => {
    let entered = (): void => undefined;
    const handlerEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let abortObserved = false;
    let handlerSettled = (): void => undefined;
    const handlerDone = new Promise<void>((resolve) => {
      handlerSettled = resolve;
    });

    const bound = await boundServer(t, {
      decorate: (server) => {
        server.registerTool(
          'us23_slow_probe',
          { description: 'Blocks until its AbortSignal fires.', inputSchema: {} },
          // The production factory funnels every tool through one action runner
          // and hands it no `extra`; this handler takes the SDK's own second
          // argument, which is the only place the signal is reachable.
          (async (_args: Record<string, unknown>, extra: { signal: AbortSignal }) => {
            entered();
            await new Promise<void>((resolve) => {
              if (extra.signal.aborted) {
                resolve();
                return;
              }
              extra.signal.addEventListener('abort', () => resolve(), { once: true });
            });
            abortObserved = true;
            handlerSettled();
            return { content: [{ type: 'text' as const, text: 'aborted' }] };
          }) as never,
        );
      },
    });
    await waitReady(bound);

    const { client, sessionId } = await connectClient(t, bound.port, 'us-23-abort');
    const call = client.callTool({ name: 'us23_slow_probe', arguments: {} }).catch(() => undefined);

    await handlerEntered;
    assert.equal(abortObserved, false, 'the handler was aborted before the session was closed');
    assert.equal(bound.serving.sessionCount(), 1);

    // Close THIS session through the same path an eviction and a drain take.
    // `server.close()` chains to `transport.close()` and, through the wrapper
    // `connect()` installed on `transport.onclose`, runs `Protocol._onclose()`
    // — which is what aborts every in-flight request handler's controller. An
    // assignment to `transport.onclose` anywhere would clobber that wrapper and
    // this await would never resolve, which is the observable signature §2's
    // source scan exists to catch earlier.
    const deleted = await exchange(bound.port, deleteSession(bound.port, sessionId));
    assert.equal(statusOf(deleted), 200);

    await handlerDone;
    assert.equal(abortObserved, true, 'extra.signal never fired for the in-flight handler');
    assert.equal(bound.instances.closed, 1);
    assert.equal(bound.serving.sessionCount(), 0);

    // `call` is deliberately NOT awaited. The client's pending request settles
    // only when the listener itself goes away — the server aborted its handler
    // and closed the session, but the client learns of it when the connection
    // does. Awaiting it here would deadlock against this test's own teardown.
    // The rejection is already handled, so nothing is left unobserved.
    t.after(async () => {
      await call;
    });
  });
});
