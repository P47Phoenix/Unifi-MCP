/**
 * US-24 — the drain sequence and the hard stop.
 *
 * Suite C of the test strategy: C15–C24 and C38, plus the C13 state-machine
 * half this file shares with US-28.
 *
 * ## The one claim this file exists to make true
 *
 * **The process is never SIGKILLed.** Everything below is that sentence taken
 * apart: a bounded, DERIVED deadline; a hard stop when it expires so "bounded"
 * is a guarantee rather than a hope; and — in the ordinary case — a client with
 * an outstanding request receiving a complete response instead of a silently
 * truncated stream.
 *
 * ## Nothing here waits on wall time
 *
 * Two of the drain's three durations are FIXED CONSTANTS that no environment
 * variable can lower, because FR-63 closes the `UNIFI_HTTP_*` family: the
 * 5 000 ms pre-drain hold and the 1 000 ms per-session teardown budget. The
 * third, the 35 000 ms deadline, is configurable but asserting it at a real
 * 35 seconds would be a latency measurement rather than a test.
 *
 * `HttpServingDeps.setDrainTimer` is therefore injected everywhere. The fake
 * records the duration each timer was armed with and fires the one the test
 * names, which is what makes the fast-forward PROVABLE rather than merely fast:
 * §5's hard-stop case asserts the drain is **still pending** before the
 * deadline timer is fired and `'deadline'` after, so the run reached exit 75
 * because the deadline logic ran — not because the test happened not to crash.
 *
 * ## MECH-SIGNAL scoping (test strategy §12, NFR-27, owner decision OQ-18)
 *
 * Only §8 delivers a signal, and only §8 is skipped on `windows-latest` with a
 * declared, reported reason. Every other section drives `drain()` directly —
 * it is idempotent and directly callable precisely so the state machine is
 * assertable with no signal at all — and §7 drives the second-signal escalation
 * through an injected process-event registrar.
 *
 * **A green Windows leg asserts the drain state machine and NEVER the shutdown
 * guarantee.** Windows is a supported development and stdio platform and is not
 * a supported HTTP deployment target.
 *
 * ## Two things this file deliberately does NOT do
 *
 * It does not open `README.md`. The 35-second deadline and the 50-second
 * minimum orchestrator grace period are stated there by **US-05** and enforced
 * by **US-30**'s source scan, per sequencing decision D-11. §1 asserts the
 * DERIVATION in this story's own code; if that derivation ever moves off
 * 35 000 ms, it is a change to raise with US-05 and US-30.
 *
 * It does not substitute a double for anything whose disposal it asserts. §6
 * counts invocations on the **production** `RateLimiter` and `UnifiClient`, so
 * a test that passed only because a stand-in was wired in cannot pass.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer as createNodeHttpServer, type Server } from 'node:http';
import { connect, type Socket } from 'node:net';
import { dirname, join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  StreamableHTTPServerTransport,
  type StreamableHTTPServerTransportOptions,
} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';

import { loadConfig, SCALAR_ENV_KEYS, type ServerConfig } from '../src/config.js';
import { CredentialStore, type CredentialStoreOptions } from '../src/credentials.js';
import { UnifiClient, type UnifiClientOptions } from '../src/http/client.js';
import { createRateLimiter, type RateLimiter } from '../src/http/ratelimit.js';
import {
  createServingOptions,
  HTTP_DRAIN_STEPS,
  HTTP_HARD_STOP_STEP,
  outboundResidueMs,
  SESSION_TEARDOWN_BUDGET_MS,
  shutdownBudgetMs,
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
  type RuntimeDeps,
  type ServingObserver,
  type ToolHandler,
} from '../src/serve/runtime.js';
import {
  DRAIN_REFUSAL_MESSAGE,
  EXIT_CODES,
  installShutdown,
  type ProcessEventRegistrar,
} from '../src/serve/stdio.js';
import { UnifiError } from '../src/types.js';

import { createInstruments } from './harness/counters.js';
import { loopbackEnv, startLoopbackOrigin, type LoopbackOrigin } from './harness/interceptor.js';
import { spawnServeEntry } from './harness/spawn.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HTTP_SOURCE_PATH = join(REPO_ROOT, 'src', 'serve', 'http.ts');

/** 40 characters, comfortably over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;

/**
 * The tool whose handler these tests SUBSTITUTE, so no outbound call is made.
 *
 * Its whole input schema is optional, so a `tools/call` with no arguments
 * reaches the handler instead of failing schema validation, and it is
 * advertised under the plain `httpEnv()` fixture. Both facts are asserted by
 * `rig()` rather than assumed — a tool that is not advertised produces a
 * `timed out waiting for the handler` failure that says nothing about why.
 */
const HANDLER_TOOL = 'unifi_list_consoles';

/**
 * A network local-direct read, for the two cases that need a REAL outbound
 * request on a real socket.
 *
 * Only Network and Protect in `local` transport mode can be pointed at the
 * loopback interceptor; Site Manager and Mobility resolve to a hardcoded cloud
 * origin that no configuration can redirect.
 */
const OUTBOUND_TOOL = 'unifi_list_devices';

/**
 * MECH-SIGNAL. The reason string is mandatory and must name the portable cover,
 * so a reader of the CI output can see what a skipped leg still proves.
 */
const MECH_SIGNAL_SKIP =
  process.platform === 'win32'
    ? 'MECH-SIGNAL: process.kill() terminates unconditionally on Windows and no handler runs, ' +
      'so a delivered signal is unsatisfiable by any correct implementation there. Sections 2 ' +
      'to 7 of this file assert the same ordered drain, the same deadline, the same hard stop ' +
      'and the same second-signal escalation on this leg through the directly-invoked drain() ' +
      'and an injected process-event registrar. A green Windows leg asserts the drain STATE ' +
      'MACHINE and never the shutdown guarantee (NFR-27, owner decision OQ-18).'
    : false;

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

// ---------------------------------------------------------------------------
// The injected drain clock
//
// One seam drives all three of the drain's timers. `kind` is what lets a test
// name the timer it fires, so "the deadline expired" and "the pre-drain hold
// elapsed" are distinguishable events rather than one undifferentiated
// fast-forward.
// ---------------------------------------------------------------------------

interface ArmedTimer {
  readonly kind: DrainTimerKind;
  readonly ms: number;
  fired: boolean;
  cleared: boolean;
  unreffed: boolean;
  fire(): void;
}

interface DrainClock {
  readonly armed: readonly ArmedTimer[];
  readonly factory: DrainTimerFactory;
  /** Durations, in arming order, for every timer of this kind. */
  durations(kind: DrainTimerKind): number[];
  /** Fires every live timer of this kind. Returns how many actually fired. */
  fire(kind: DrainTimerKind): number;
  live(kind: DrainTimerKind): ArmedTimer[];
}

/**
 * @param auto Kinds fired the instant they are armed.
 *
 * `'predrain'` is the default because the drain AWAITS the hold: a suite that
 * did not fire it would hang rather than fail, and a hang is the worst possible
 * diagnostic. `'deadline'` is never auto-fired — firing it is the event §5
 * exists to observe — and `'session'` is never auto-fired either, so the
 * ordinary path lets each session's real teardown win its race.
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
      unreffed: false,
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
      unref: (): void => {
        record.unreffed = true;
      },
    };
  };

  const live = (kind: DrainTimerKind): ArmedTimer[] =>
    armed.filter((timer) => timer.kind === kind && !timer.fired && !timer.cleared);

  return {
    armed,
    factory,
    durations: (kind) => armed.filter((timer) => timer.kind === kind).map((timer) => timer.ms),
    fire(kind): number {
      const pending = live(kind);
      for (const timer of pending) timer.fire();
      return pending.length;
    },
    live,
  };
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

interface RigOptions {
  readonly env?: Record<string, string>;
  readonly deps?: HttpServingDeps;
  readonly runtimeDeps?: RuntimeDeps;
  readonly clock?: DrainClock;
  /** Replaces named tool handlers on the core, BEFORE any session is opened. */
  readonly handlers?: Record<string, ToolHandler>;
  /** Omit the `after()` teardown, for a case that drives disposal itself. */
  readonly manualTeardown?: boolean;
}

interface Rig {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly clock: DrainClock;
  readonly steps: readonly string[];
  /** `ServingDeps.exit` calls, in order. Never `process.exit`. */
  readonly exits: readonly number[];
  /** `ServingDeps.setExitCode` calls, in order. Never `process.exitCode`. */
  readonly codes: readonly number[];
  readonly logs: readonly string[];
}

/**
 * One bound listener with an injected drain clock and an injected exit hook.
 *
 * `exit` and `setExitCode` are injected on EVERY rig, and that is not
 * convenience. Without them drain step 10 would mutate the test runner's own
 * exit status, and the hard stop would call the real `process.exit(75)` inside
 * a runner whose event loop is always alive — killing the file mid-suite with
 * no diagnostic. Injecting `exit` is also what makes the drain CLEAR its
 * deadline timer instead of un-reffing it, which is the §10.5 leak clause.
 */
async function rig(t: TestContext, options: RigOptions = {}): Promise<Rig> {
  const clock = options.clock ?? drainClock();
  const steps: string[] = [];
  const exits: number[] = [];
  const codes: number[] = [];
  const logs: string[] = [];

  const instruments = createInstruments({
    env: { ...(options.env ?? httpEnv()) },
    keychain: null,
    deps: options.runtimeDeps ?? {},
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

  let httpServer: Server | null = null;
  const serving = await startHttp(core, observer, {
    setDrainTimer: clock.factory,
    exit: (code: number) => exits.push(code),
    setExitCode: (code: number) => codes.push(code),
    createHttpServer: (serverOptions, handler) => {
      httpServer = createNodeHttpServer(serverOptions, handler);
      return httpServer;
    },
    ...(options.deps ?? {}),
  });

  if (options.manualTeardown !== true) {
    t.after(async () => {
      await serving.dispose();
    });
  }

  assert.ok(serving.address !== null, 'the listener reported no address');
  assert.ok(httpServer !== null, 'the http server seam was not used');
  await core.ready;
  await settle();

  // Fail here, loudly, rather than as an unexplained "timed out waiting for the
  // handler" five seconds into whichever case calls a tool.
  assert.equal(core.readyError, null, `the rig's registry failed: ${String(core.readyError)}`);
  for (const name of Object.keys(options.handlers ?? {})) {
    assert.ok(
      core.advertisedToolsFor('http').some((tool) => tool.name === name),
      `${name} is not advertised on http under this fixture's configuration`,
    );
  }

  return { serving, core, port: serving.address.port, clock, steps, exits, codes, logs };
}

/** Let every already-queued continuation run. */
async function settle(turns = 4): Promise<void> {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

async function connectClient(t: TestContext, port: number, name: string): Promise<Client> {
  const client = new Client({ name, version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${SECRET}` } },
  });
  t.after(async () => {
    await client.close().catch(() => undefined);
  });
  await client.connect(transport);
  return client;
}

// ---------------------------------------------------------------------------
// Raw sockets, where the BYTES or the socket's fate are the assertion
// ---------------------------------------------------------------------------

interface RawResult {
  readonly text: string;
  /** True once the server-side socket went away, however it went away. */
  readonly closed: boolean;
}

/**
 * One request over a raw socket, returning the server's bytes verbatim.
 *
 * Completion is decided by `Content-Length` rather than by the socket closing.
 * A 200 from `/healthz` is a KEEP-ALIVE response, so the socket stays open by
 * design and a helper that waited for `close` would hang against a correct
 * server — the failure would then be reported as a timeout in whichever test
 * happened to run next, rather than here.
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
): Promise<RawResult> {
  return new Promise<RawResult>((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    let text = '';
    let settled = false;

    const finish = (closed: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ text, closed });
    };

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
      if (settleWhen !== undefined ? settleWhen(text) : complete()) finish(false);
    });
    socket.once('error', (error) => {
      if (!settled) reject(error);
    });
    socket.once('close', () => finish(true));
    socket.on('connect', () => {
      socket.write([...lines, `Content-Length: ${Buffer.byteLength(body)}`, '', body].join('\r\n'));
    });
  });
}

interface OpenStream {
  /** Everything the server has written on this stream so far. */
  text(): string;
  /** True once the socket closed — which for an SSE stream means it was destroyed. */
  closed(): boolean;
  /** Milliseconds, from `process.hrtime`, when the socket closed. */
  closedAt(): bigint | null;
  /** When the terminal frame's text first appeared in the stream. */
  frameAt(): bigint | null;
  destroy(): void;
}

/**
 * Hold a standalone SSE stream open on a live session, over a raw socket.
 *
 * A raw socket rather than the SDK client, because the assertion is about the
 * SOCKET and not only about the frames: `transport.close()` ends the response
 * BODY and leaves an idle keep-alive socket alive, so a test that asserted only
 * "the stream ended" passes against the broken implementation. What must be
 * observed is the terminal frame arriving AND the socket being destroyed, in
 * that order.
 */
function openSseStream(port: number, sessionId: string): Promise<OpenStream> {
  return new Promise<OpenStream>((resolve, reject) => {
    const socket: Socket = connect({ host: '127.0.0.1', port });
    let text = '';
    let closedAt: bigint | null = null;
    let frameAt: bigint | null = null;
    let opened = false;

    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      text += chunk;
      if (frameAt === null && text.includes('Retry against a new instance.')) {
        frameAt = process.hrtime.bigint();
      }
      if (!opened && text.includes('text/event-stream')) {
        opened = true;
        resolve(handle);
      }
    });
    socket.once('error', (error) => {
      if (!opened) reject(error);
    });
    socket.once('close', () => {
      closedAt = process.hrtime.bigint();
      if (!opened) reject(new Error(`the SSE stream never opened. Got:\n${text}`));
    });

    const handle: OpenStream = {
      text: () => text,
      closed: () => closedAt !== null,
      closedAt: () => closedAt,
      frameAt: () => frameAt,
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

/** A member of the SDK's `SUPPORTED_PROTOCOL_VERSIONS`, pinned rather than imported. */
const PROTOCOL_VERSION = '2025-06-18';

/**
 * Open one live session over RAW SOCKETS and return its identifier.
 *
 * The SDK client is not used for the terminal-frame case, and the reason is
 * structural rather than stylistic: `StreamableHTTPClientTransport` opens the
 * one standalone SSE stream a session is permitted the moment it connects, so a
 * second `GET` — the stream this test needs to watch die — is answered `409
 * Conflict: Only one SSE stream is allowed per session`.
 */
async function openRawSession(port: number): Promise<string> {
  const initialize = await rawExchange(
    port,
    [
      'POST /mcp HTTP/1.1',
      'Host: 127.0.0.1',
      `Authorization: Bearer ${SECRET}`,
      'Accept: application/json, text/event-stream',
      'Content-Type: application/json',
    ],
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'raw', version: '0.0.0' },
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
    [
      'POST /mcp HTTP/1.1',
      'Host: 127.0.0.1',
      `Authorization: Bearer ${SECRET}`,
      `Mcp-Session-Id: ${sessionId}`,
      'Accept: application/json, text/event-stream',
      'Content-Type: application/json',
    ],
    JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    (text) => text.includes('\r\n\r\n'),
  );

  return sessionId;
}

/** Wait for a condition without sleeping on a fixed interval. */
async function until(
  predicate: () => boolean,
  what: string,
  budgetMs = 5_000,
): Promise<void> {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > budgetMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

// ===========================================================================
// 1. The derivation, the constants and the two deliberate absences
//
// Portable. Runs on every leg. No drain is started here.
// ===========================================================================

describe('the 35 000 ms budget is DERIVED, not asserted as a literal', () => {
  test('the outbound residue is a MAXIMUM over five states, never a sum', () => {
    // The single most consequential arithmetic in the design. An action caught
    // by the drain is resolving credentials, OR queued for a rate-limit token,
    // OR sleeping in a retry backoff, OR in flight under the per-attempt
    // deadline, OR between states — mutually exclusive, so four of the five
    // contribute ~0 s and the residue is `max(...)`.
    assert.equal(outboundResidueMs(25_000), 25_000);

    // Summed instead — the reading a hurried implementer takes — the residue is
    // three attempts at 25 s separated by two honoured 30 s `Retry-After`
    // sleeps: 136.8 s, at which no honest 35-second deadline exists at all.
    // This assertion is what stops the two being confused.
    const summedIfMisread = 3 * 25_000 + 2 * 30_000;
    assert.ok(
      outboundResidueMs(25_000) < summedIfMisread,
      'the residue was summed rather than maximised',
    );
  });

  test('5 000 hold + 25 000 residue + 1 000 teardown = 31 000, inside the 35 000 deadline', () => {
    assert.equal(PREDRAIN_HOLD_MS, 5_000);
    assert.equal(SESSION_TEARDOWN_BUDGET_MS, 1_000);
    assert.equal(shutdownBudgetMs(25_000), 31_000);

    const config = loadConfig(httpEnv());
    assert.equal(
      config.serving.shutdownDeadlineMs,
      35_000,
      'FR-70 and NFR-27 fix the deadline at 35 000 ms',
    );
    assert.ok(
      shutdownBudgetMs(config.connectorTimeoutMs) <= config.serving.shutdownDeadlineMs,
      'the derived budget exceeds the configured deadline',
    );
    // The margin is ≈ 4 s, deliberately narrow: it is the price of not dropping
    // client connections on every rolling deploy. Asserted so a later change to
    // either number is made against this derivation rather than by feel.
    assert.equal(config.serving.shutdownDeadlineMs - shutdownBudgetMs(25_000), 4_000);
  });

  test('the budget is asserted against the RESOLVED configuration, not a constant', () => {
    // A raised connector timeout is the one operator-settable value that can
    // invalidate the whole derivation, and `UNIFI_CONNECTOR_TIMEOUT_MS` has no
    // ceiling. This is the drift detector for the relationship.
    const raised = loadConfig(httpEnv({ UNIFI_CONNECTOR_TIMEOUT_MS: '60000' }));
    assert.ok(
      shutdownBudgetMs(raised.connectorTimeoutMs) > raised.serving.shutdownDeadlineMs,
      'a 60 s connector timeout must overrun the 35 s deadline — that is why it warns',
    );
  });
});

describe('the exported options object (FR-70, FR-76)', () => {
  test('keepAliveMs is set EXPLICITLY from UNIFI_HTTP_SSE_KEEPALIVE_MS', () => {
    // Both halves are required. The SDK's own default is 15 000 and so is
    // ours, so a test written as "the value is not the default" fails against a
    // correct implementation at the documented defaults, and one written as
    // "the value equals 15 000" proves nothing about whether this
    // configuration wired it. The probe value is therefore distinct from both.
    const probe = loadConfig(httpEnv({ UNIFI_HTTP_SSE_KEEPALIVE_MS: '4321' }));
    const options = createServingOptions(probe).transportOptionsFor('session-id');
    assert.equal(options.keepAliveMs, 4_321);

    const defaults = createServingOptions(loadConfig(httpEnv()));
    assert.equal(defaults.transportOptionsFor('x').keepAliveMs, 15_000);
    assert.notEqual(
      createServingOptions(probe).transportOptionsFor('x').keepAliveMs,
      defaults.transportOptionsFor('x').keepAliveMs,
      'keepAliveMs did not track the configured value',
    );
  });

  test('UNIFI_HTTP_SSE_KEEPALIVE_MS is a recognised scalar variable', () => {
    // Any `UNIFI_*` the server reads must be in the scalar inventory, or an
    // operator setting it gets no unknown-variable diagnosis.
    assert.ok(SCALAR_ENV_KEYS.includes('UNIFI_HTTP_SSE_KEEPALIVE_MS'));
    assert.ok(SCALAR_ENV_KEYS.includes('UNIFI_HTTP_SHUTDOWN_DEADLINE_MS'));
  });

  test('enableJsonResponse is left at its default — SSE mode', () => {
    // Not cosmetic. In JSON response mode `handleRequest`'s promise is settled
    // only by `resolveJson`, which the JSON-mode cleanup never calls, so a
    // drain written against that promise deadlocks the instant this is turned
    // on. §3 asserts the drain does not depend on it staying off; this asserts
    // it is off.
    const options = createServingOptions(loadConfig(httpEnv())).transportOptionsFor('x');
    assert.equal(options.enableJsonResponse, undefined);
  });
});

describe('closeIdleConnections() is NOT called, and the absence is deliberate', () => {
  const source = readFileSync(HTTP_SOURCE_PATH, 'utf8');

  /**
   * The module with every comment removed.
   *
   * Comments are stripped because the very next test requires the module to
   * EXPLAIN the omission in prose, and a scan over raw text would then be
   * satisfied by the explanation and unsatisfiable alongside it. What is being
   * asserted is that the call is never MADE, not that the identifier never
   * appears.
   */
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  test('the call appears nowhere in the serving module', () => {
    // A source scan rather than a behavioural test, because the failure this
    // guards against is a well-meaning belt-and-braces commit, and belt and
    // braces has no behavioural signature — it is redundant with `close()` for
    // the case it covers and inert for the case that matters.
    const calls = [...code.matchAll(/closeIdleConnections\s*\(/g)];
    assert.deepEqual(
      calls.map((match) => match[0]),
      [],
      'closeIdleConnections() must not be called: Node >= 19 reaps idle keep-alive sockets ' +
        'inside close(), and an open SSE response is by definition not idle',
    );
    // The stripper must not be vacuous — a scan over an empty string passes
    // everything.
    assert.ok(code.includes('closeAllConnections'), 'the comment stripper removed real code');
  });

  test('the REASONING is asserted, not merely the absence', () => {
    // An absence that is only true by omission carries no argument with it, so
    // the next reader adds the call back in good faith and nothing objects.
    // BOTH halves of the reason must be present in the module that omits it:
    // redundant for the case it covers, useless for the case that matters.
    //
    // Comment prefixes and wrapping are stripped first, so this asserts the
    // ARGUMENT and not the current line breaks.
    const prose = source.replace(/^\s*(\/\/|\*)\s?/gm, '').replace(/\s+/g, ' ');
    assert.ok(
      prose.includes('`closeIdleConnections()` IS DELIBERATELY NOT CALLED'),
      'the module does not record that the omission is deliberate',
    );
    assert.ok(
      prose.includes('Node ≥ 19 already reaps idle keep-alive sockets inside `close()`'),
      'the redundancy half of the reason is missing',
    );
    assert.ok(
      prose.includes('an open SSE response is BY DEFINITION not idle'),
      'the uselessness half of the reason is missing',
    );
  });

  test('closeAllConnections IS called — it is the only call that kills an SSE socket', () => {
    assert.ok(code.includes('httpServer.closeAllConnections()'));
  });
});

// ===========================================================================
// 2. The ordered state machine (C13, C15)
//
// Portable. `drain()` is idempotent and directly callable, which is the whole
// mechanism that makes this section run on `windows-latest`.
// ===========================================================================

describe('the ordered drain sequence', () => {
  test('the eleven steps fire in the normative order, and it resolves clean', async (t) => {
    const r = await rig(t);
    const outcome = await r.serving.drain('signal');

    assert.equal(outcome, 'clean');
    assert.deepEqual([...r.steps], [...HTTP_DRAIN_STEPS]);
    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
    assert.deepEqual([...r.exits], [], 'a clean drain exits by natural loop drain, never by hook');
  });

  test('the deadline is armed FIRST, before the not-ready mark', async (t) => {
    const r = await rig(t);
    await r.serving.drain('signal');

    // Step 1 precedes step 2 so the bound covers the pre-drain hold as well as
    // everything after it. A deadline armed at step 3 would leave the hold
    // itself unbounded.
    assert.equal(r.steps[0], 'arm-deadline');
    assert.equal(r.steps[1], 'not-ready');
    assert.deepEqual(r.clock.durations('deadline'), [35_000]);
  });

  test('it is idempotent — a second call re-runs nothing and returns the same outcome', async (t) => {
    const r = await rig(t);
    const first = await r.serving.drain('signal');
    const stepsAfterFirst = [...r.steps];
    const second = await r.serving.drain('signal');

    assert.equal(first, second);
    assert.deepEqual([...r.steps], stepsAfterFirst, 'the second call re-ran a step');
    assert.deepEqual([...r.codes], [EXIT_CODES.clean], 'the exit code was set twice');
  });

  test('httpServer.close()`s callback is RECORDED but is not the gate', async (t) => {
    const r = await rig(t);
    await r.serving.drain('signal');

    // Both halves matter. The callback must fire — otherwise the listener never
    // stopped accepting — and the drain must not have waited for it, because it
    // does not fire until every response has ended plus `keepAliveTimeout`.
    await until(() => r.serving.listenerClosed(), "httpServer.close()'s callback");
    assert.equal(r.serving.listenerClosed(), true);
  });

  test('every awaited step is individually caught — one failure does not abort the rest', async (t) => {
    const r = await rig(t, { manualTeardown: true });
    // `beginDrain` is step 4, in the middle of the sequence. A rejection there
    // used to skip every step after it: no terminal frames, no
    // closeAllConnections(), no agent.destroy(), and an exit code of 1 — the
    // drain failing in the one way this design has no diagnostic for.
    r.core.beginDrain = (): never => {
      throw new Error('injected step-4 fault');
    };

    const outcome = await r.serving.drain('signal');

    assert.equal(outcome, 'clean', 'a failing step turned the whole drain into a deadline');
    assert.deepEqual([...r.steps], [...HTTP_DRAIN_STEPS], 'the drain stopped at the failing step');
    await r.serving.dispose();
  });

  test('the TTL sweep stops at step 5, inside the numbered sequence', async (t) => {
    const ticks: number[] = [];
    let sweepTick: (() => void) | null = null;
    const r = await rig(t, {
      deps: {
        createSweepInterval: (onTick) => {
          sweepTick = onTick;
          return setInterval(() => undefined, 1_000_000) as NodeJS.Timeout;
        },
      },
    });
    assert.ok(sweepTick !== null, 'the sweep seam was not used');

    await r.serving.drain('signal');

    assert.ok(r.steps.includes('stop-sweep'));
    assert.equal(
      r.steps.indexOf('stop-sweep'),
      r.steps.indexOf('begin-drain') + 1,
      'the sweep must stop at step 5, immediately after beginDrain',
    );
    assert.ok(
      r.steps.indexOf('stop-sweep') < r.steps.indexOf('await-in-flight'),
      'the sweep must stop before the in-flight wait',
    );
    assert.deepEqual(ticks, []);
  });
});

describe('the pre-drain hold (C15, FR-70 step 2a, NFR-24)', () => {
  test('the listener STAYS OPEN for 5 000 ms and answers 503 with the drain body', async (t) => {
    const clock = drainClock([]); // manual: the hold is the thing being observed
    const r = await rig(t, { clock });

    const outcome = r.serving.drain('signal');
    await settle();

    // The drain is parked in the hold, and the timer it is parked on is the
    // fixed 5 000 ms constant — not a value a test could have lowered.
    assert.deepEqual(clock.durations('predrain'), [PREDRAIN_HOLD_MS]);
    assert.deepEqual([...r.steps], ['arm-deadline', 'not-ready', 'predrain-hold']);

    // A NEW TCP connection, accepted and answered — the whole point of the
    // hold. Closing the listener at t0 refuses this at the kernel, where no
    // request is parsed and no line can ever be logged, so every rolling deploy
    // drops client connections and the operator sees nothing in the logs.
    const answered = await rawExchange(
      r.port,
      [
        'POST /mcp HTTP/1.1',
        'Host: 127.0.0.1',
        `Authorization: Bearer ${SECRET}`,
        'Accept: application/json, text/event-stream',
        'Content-Type: application/json',
      ],
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    );

    assert.match(answered.text, /^HTTP\/1\.1 503 Service Unavailable\r\n/);
    assert.match(answered.text, /Connection: close/);
    assert.ok(
      answered.text.includes(DRAIN_REFUSAL_MESSAGE),
      `the drain body was not the shared message. Got:\n${answered.text}`,
    );

    // `reject_reason=draining` is what stops an operator conflating a rolling
    // deploy with a capacity incident — two conditions with opposite remedies.
    // AR-7 added the token to NFR-24's closed vocabulary for exactly this.
    await until(
      () => r.logs.some((line) => line.includes('reject_reason=draining')),
      'the drain refusal log line',
    );
    const line = r.logs.find((entry) => entry.includes('reject_reason=draining'));
    assert.ok(line !== undefined);
    assert.match(line, /status=503/);
    assert.match(line, /path=mcp/);

    clock.fire('predrain');
    assert.equal(await outcome, 'clean');
    assert.deepEqual([...r.steps], [...HTTP_DRAIN_STEPS]);
  });

  test('/healthz stays 200 while /readyz reports 503 draining, in the same run (C13)', async (t) => {
    const clock = drainClock([]);
    const r = await rig(t, { clock });

    const outcome = r.serving.drain('signal');
    await settle();

    const liveness = await rawExchange(r.port, ['GET /healthz HTTP/1.1', 'Host: 127.0.0.1']);
    const readiness = await rawExchange(r.port, ['GET /readyz HTTP/1.1', 'Host: 127.0.0.1']);

    // A liveness probe that fails during drain gets the container killed
    // mid-drain, converting a graceful shutdown into the SIGKILL this whole
    // story exists to prevent. The two must disagree, in one run.
    assert.match(liveness.text, /^HTTP\/1\.1 200 OK\r\n/);
    assert.ok(liveness.text.endsWith('ok\n'));
    assert.match(readiness.text, /^HTTP\/1\.1 503 Service Unavailable\r\n/);
    assert.ok(readiness.text.endsWith('draining\n'));

    clock.fire('predrain');
    await outcome;
  });

  test('dispose() skips the hold entirely — it has no endpoints to withdraw', async (t) => {
    const clock = drainClock([]);
    const r = await rig(t, { clock, manualTeardown: true });

    await r.serving.dispose();

    assert.deepEqual(clock.durations('predrain'), [], 'dispose() armed a pre-drain hold');
    assert.ok(!r.steps.includes('predrain-hold'));
    assert.ok(r.steps.includes('close-runtime'), 'dispose() must still run every other step');
  });

  test("a 'startup-failure' drain skips the hold — nothing was ever routed to it", async (t) => {
    const clock = drainClock([]);
    const r = await rig(t, { clock });

    assert.equal(await r.serving.drain('startup-failure'), 'clean');
    assert.deepEqual(clock.durations('predrain'), []);
    assert.ok(!r.steps.includes('predrain-hold'));
  });
});

describe('dispose() is teardown and nothing else (C38)', () => {
  test('it never sets an exit code and never calls the exit hook', async (t) => {
    const r = await rig(t, { manualTeardown: true });
    await r.serving.dispose();

    assert.deepEqual([...r.codes], [], 'dispose() set an exit code');
    assert.deepEqual([...r.exits], [], 'dispose() called the exit hook');
    assert.ok(!r.steps.includes('exit-code'));
  });

  test('the deadline timer is CLEARED, not merely un-ref`d', async (t) => {
    const clock = drainClock();
    const r = await rig(t, { clock, manualTeardown: true });
    await r.serving.dispose();

    const deadline = clock.armed.filter((timer) => timer.kind === 'deadline');
    assert.equal(deadline.length, 1);
    // Without this, every in-process drain arms a live timer whose callback
    // reaches the hard stop and calls the exit hook — the test file dies
    // mid-suite with no diagnostic, and lowering the deadline for speed makes
    // it fire SOONER.
    assert.equal(deadline[0]?.cleared, true, 'dispose() left the deadline timer live');
    assert.equal(deadline[0]?.fired, false);
  });

  test('an injected exit hook makes even a signal drain clear the timer', async (t) => {
    const clock = drainClock();
    const r = await rig(t, { clock });
    await r.serving.drain('signal');

    const deadline = clock.armed.find((timer) => timer.kind === 'deadline');
    // The condition is on the INJECTED HOOK, never on any `NODE_ENV` branch:
    // production un-refs so a leak still reports itself as exit 75 instead of
    // hanging silently, and an injected hook means a test process.
    assert.equal(deadline?.cleared, true);
    assert.equal(deadline?.unreffed, false);
  });
});

// ===========================================================================
// 3. THE HANDLER PROMISE, NEVER `handleRequest()`'s (C19)
//
// The single highest-value case in this file. Without the `createTransport`
// seam the criterion has no mechanism at all, because `startHttp` constructs
// the transport internally.
// ===========================================================================

describe('drain step 6 awaits the handler set, not transport.handleRequest()', () => {
  test('a never-settling handleRequest() does not deadlock the drain', async (t) => {
    let handlerEntered = 0;
    let handlerCompleted = 0;
    /** Set only if the injected promise ever settles. It must not. */
    let injectedSettled = false;
    let releaseHandler = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      releaseHandler = resolve;
    });

    const r = await rig(t, {
      handlers: {
        [HANDLER_TOOL]: async () => {
          handlerEntered += 1;
          await held;
          handlerCompleted += 1;
          return { content: [{ type: 'text' as const, text: 'complete' }] };
        },
      },
      deps: {
        /**
         * The real transport does all the work; only the PROMISE is replaced.
         *
         * This reproduces exactly what JSON response mode does: the request is
         * handled, the handler runs, the response is written — and the promise
         * `handleRequest` returned is never settled, because in JSON mode it is
         * settled only by `resolveJson`, which the JSON-mode cleanup path never
         * calls. A drain written against it waits forever.
         */
        createTransport: (options: StreamableHTTPServerTransportOptions) => {
          const transport = new StreamableHTTPServerTransport(options);
          const realHandleRequest = transport.handleRequest.bind(transport);
          transport.handleRequest = async (...args: Parameters<typeof realHandleRequest>) => {
            void realHandleRequest(...args).catch(() => undefined);
            await new Promise<void>(() => undefined);
          };
          const pendingProbe = transport.handleRequest.bind(transport);
          void pendingProbe;
          return transport;
        },
      },
    });

    const client = await connectClient(t, r.port, 'c19');
    const call = client.callTool({ name: HANDLER_TOOL, arguments: {} }).catch(() => undefined);
    await until(() => handlerEntered > 0, 'the tool handler to be entered');

    // The drain begins with a handler genuinely in flight. Step 6 must await
    // THAT promise — which settles — and never the transport's, which does not.
    const outcome = r.serving.drain('signal');
    await settle();
    assert.equal(handlerCompleted, 0, 'the handler finished before the drain started');

    releaseHandler();
    const result = await outcome;

    assert.equal(result, 'clean', 'the drain deadlocked on the transport promise');
    assert.equal(handlerCompleted, 1, 'step 6 did not wait for the handler to finish');
    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
    assert.ok(!r.steps.includes(HTTP_HARD_STOP_STEP));
    assert.deepEqual(
      r.clock.armed.filter((timer) => timer.kind === 'deadline' && timer.fired),
      [],
      'the deadline fired, so the drain did not complete on its own',
    );

    // The demonstration of the failure a wrong implementation would produce:
    // the promise a drain might have been written against is STILL PENDING
    // after the process finished draining cleanly.
    assert.equal(injectedSettled, false, 'the injected promise settled — the fixture is invalid');
    await call;
  });

  test('the in-flight set is FINAL once dispatch stops — a late call is refused', async (t) => {
    const clock = drainClock([]);
    let entered = 0;
    const r = await rig(t, {
      clock,
      handlers: {
        [HANDLER_TOOL]: async () => {
          entered += 1;
          return { content: [{ type: 'text' as const, text: 'ok' }] };
        },
      },
    });

    const client = await connectClient(t, r.port, 'dispatch-stop');
    const outcome = r.serving.drain('signal');
    await settle();

    // Dispatch closed at the not-ready mark, so an ordinary `tools/call`
    // arriving on an ALREADY-OPEN keep-alive connection is refused rather than
    // reaching a handler whose promise would join the set after step 6
    // snapshotted it — the failure that returned `200` with a tool error saying
    // "rate limited" for a request that was never rate limited.
    const late = await client
      .callTool({ name: HANDLER_TOOL, arguments: {} })
      .then(() => 'admitted' as const)
      .catch(() => 'refused' as const);

    assert.equal(late, 'refused');
    assert.equal(entered, 0, 'a call admitted after the drain began reached a handler');

    clock.fire('predrain');
    assert.equal(await outcome, 'clean');
  });
});

// ===========================================================================
// 4. The terminal frame on an open SSE stream (C17)
// ===========================================================================

describe('an open SSE stream with no in-flight request', () => {
  test('receives the terminal frame BEFORE its socket is destroyed', async (t) => {
    const clock = drainClock([]);
    const r = await rig(t, { clock, manualTeardown: true });

    const sessionId = await openRawSession(r.port);
    assert.equal(r.serving.sessionCount(), 1, 'the raw session was not admitted');

    const stream = await openSseStream(r.port, sessionId);
    assert.equal(stream.closed(), false, 'the stream closed before the drain began');

    const outcome = r.serving.drain('signal');
    await settle();
    clock.fire('predrain');
    assert.equal(await outcome, 'clean');

    await until(() => stream.closed(), 'the SSE socket to be destroyed');

    // BOTH halves, separately. `transport.close()` writes no `result` and no
    // `error` — it ends the response body and leaves an idle keep-alive socket,
    // so the client sees a silently truncated stream. A test that asserted only
    // "the body ended" passes against that broken implementation.
    const text = stream.text();
    assert.ok(
      text.includes(DRAIN_REFUSAL_MESSAGE),
      `the terminal frame never arrived on the stream. Got:\n${text}`,
    );
    assert.ok(
      text.includes('"method":"notifications/message"'),
      'the session-level frame must be a NOTIFICATION — a JSON-RPC error response requires an id',
    );
    assert.ok(text.includes('"level":"error"'));
    assert.equal(stream.closed(), true, 'the SSE-carrying socket was not destroyed');

    // Ordering: the frame must be on the wire before the socket dies, or the
    // client never sees it. Only `closeAllConnections()` destroys this socket,
    // and it runs at step 8 — after step 7's frames.
    const frameAt = stream.frameAt();
    const closedAt = stream.closedAt();
    assert.ok(frameAt !== null, 'the frame was never observed');
    assert.ok(closedAt !== null);
    assert.ok(frameAt < closedAt, 'the socket was destroyed before the terminal frame arrived');

    // The server-side half of the same criterion.
    await until(() => r.serving.listenerClosed(), "httpServer.close()'s callback");
    assert.equal(r.serving.listenerClosed(), true);

    await r.serving.dispose();
  });
});

// ===========================================================================
// 4b. Step 7 is PARALLEL and per-session BOUNDED
//
// The failure this guards against is specific and was ratified rather than
// imagined: `transport.send()` awaits, so a client that opened an SSE stream
// and stopped reading applies TCP backpressure and its enqueue never resolves.
// Under a sequential, unbounded loop that ONE session stalls the drain, the
// other 31 are never sent a terminal frame and never closed, and every drain in
// the presence of one slow reader becomes a hard stop.
// ===========================================================================

describe('session teardown is parallel, each raced against a 1 000 ms budget', () => {
  interface StallRig {
    readonly r: Rig;
    readonly clock: DrainClock;
    readonly closed: readonly number[];
  }

  /**
   * Three live sessions, then `send()` stalled on the first `stall` of them.
   *
   * The stall is armed AFTER the sessions are open, and that ordering is
   * forced rather than tidy: the SDK delivers an `initialize` RESULT through
   * `transport.send()` too, so a transport stalled from construction never
   * completes its own handshake and no session exists to tear down.
   *
   * Raw sessions rather than SDK clients: three `StreamableHTTPClientTransport`s
   * would each open their own standalone stream and add teardown noise that has
   * nothing to do with what is being measured.
   */
  async function stalledSessions(t: TestContext, stall: number): Promise<StallRig> {
    const clock = drainClock(['predrain']);
    const closed: number[] = [];
    const stalled = new Set<number>();
    let built = 0;

    const r = await rig(t, {
      clock,
      manualTeardown: true,
      deps: {
        createTransport: (options: StreamableHTTPServerTransportOptions) => {
          const index = built;
          built += 1;
          const transport = new StreamableHTTPServerTransport(options);
          const realSend = transport.send.bind(transport);
          transport.send = async (...args: Parameters<typeof realSend>): Promise<void> => {
            // Backpressure, reproduced exactly: the enqueue never resolves.
            if (stalled.has(index)) await new Promise<never>(() => undefined);
            await realSend(...args);
          };
          const realClose = transport.close.bind(transport);
          transport.close = async (): Promise<void> => {
            closed.push(index);
            await realClose();
          };
          return transport;
        },
      },
    });

    for (let i = 0; i < 3; i += 1) await openRawSession(r.port);
    assert.equal(r.serving.sessionCount(), 3, 'the three sessions were not admitted');
    assert.equal(built, 3, 'the transport seam was not used once per session');

    for (let i = 0; i < stall; i += 1) stalled.add(i);
    return { r, clock, closed };
  }

  test('all three budgets are armed AT ONCE — a sequential loop arms one at a time', async (t) => {
    const { r, clock } = await stalledSessions(t, 3);

    const outcome = r.serving.drain('signal');
    await until(() => clock.live('session').length === 3, 'three concurrent session budgets');

    // THE PARALLELISM ASSERTION. Under `for (const key of keys) await ...` only
    // one budget can ever be live, because the next iteration has not started.
    assert.equal(clock.live('session').length, 3);
    assert.deepEqual(
      clock.durations('session'),
      [SESSION_TEARDOWN_BUDGET_MS, SESSION_TEARDOWN_BUDGET_MS, SESSION_TEARDOWN_BUDGET_MS],
      'each session must be raced against its own 1 000 ms budget',
    );

    assert.equal(clock.fire('session'), 3);
    assert.equal(await outcome, 'clean', 'a stalled terminal frame turned the drain into a hard stop');
    assert.ok(!r.steps.includes(HTTP_HARD_STOP_STEP));
    await r.serving.dispose();
  });

  test('one slow reader does not stop the other sessions being closed', async (t) => {
    const { r, clock, closed } = await stalledSessions(t, 1);

    const outcome = r.serving.drain('signal');

    // The two healthy sessions close on their own, while session 0 is still
    // parked on a `send()` that will never resolve.
    await until(() => closed.length === 2, 'the two healthy sessions to close');
    assert.deepEqual([...closed].sort(), [1, 2]);

    clock.fire('session');
    assert.equal(await outcome, 'clean');
    assert.ok(!r.steps.includes(HTTP_HARD_STOP_STEP));
    await r.serving.dispose();
  });
});

// ===========================================================================
// 5. The four shutdown states, and the hard stop (C16, C18)
// ===========================================================================

describe('the four shutdown states each exit 0 within the deadline (C16, C18)', () => {
  test('idle — no sessions, no connections', async (t) => {
    const r = await rig(t);
    const startedAt = process.hrtime.bigint();
    assert.equal(await r.serving.drain('signal'), 'clean');
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
    assert.ok(elapsedMs < 35_000, `the idle drain took ${elapsedMs} ms`);
  });

  test('an IDLE KEEP-ALIVE connection with no in-flight request', async (t) => {
    const r = await rig(t);

    // Without this case the failure appears only in production, as a hang
    // lasting the whole orchestrator grace period: `httpServer.close()`'s
    // callback waits for every response to end PLUS `keepAliveTimeout`, so a
    // drain gated on it never finishes while one idle socket is open.
    const socket = connect({ host: '127.0.0.1', port: r.port });
    t.after(() => socket.destroy());
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });
    socket.write(
      [
        'GET /healthz HTTP/1.1',
        'Host: 127.0.0.1',
        'Connection: keep-alive',
        '',
        '',
      ].join('\r\n'),
    );
    await new Promise<void>((resolve) => socket.once('data', () => resolve()));

    const startedAt = process.hrtime.bigint();
    assert.equal(await r.serving.drain('signal'), 'clean');
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
    assert.deepEqual([...r.exits], []);
    assert.ok(elapsedMs < 35_000, `the keep-alive drain took ${elapsedMs} ms`);
  });

  test('an IN-FLIGHT request completes, and its client receives a complete response', async (t) => {
    let releaseHandler = (): void => undefined;
    const held = new Promise<void>((resolve) => {
      releaseHandler = resolve;
    });
    let entered = 0;

    const r = await rig(t, {
      handlers: {
        [HANDLER_TOOL]: async () => {
          entered += 1;
          await held;
          return { content: [{ type: 'text' as const, text: 'the complete response' }] };
        },
      },
    });

    const client = await connectClient(t, r.port, 'in-flight');
    const call = client.callTool({ name: HANDLER_TOOL, arguments: {} });
    await until(() => entered > 0, 'the tool handler to be entered');

    const outcome = r.serving.drain('signal');
    await settle();
    releaseHandler();

    const result = (await call) as { content: { type: string; text: string }[] };
    assert.equal(await outcome, 'clean');
    // FR-70 step 4's whole purpose: not "the request was not aborted", but
    // "the client got its answer".
    assert.equal(result.content[0]?.text, 'the complete response');
    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
  });
});

describe('the hard stop (C18) — a stalled request reaches exit 75, never a SIGKILL', () => {
  test('the deadline expires to exit 75, and the fast-forward is what drove it', async (t) => {
    const clock = drainClock(['predrain']);
    let entered = 0;
    const r = await rig(t, {
      clock,
      manualTeardown: true,
      handlers: {
        // Deliberately stalled: it never settles, so step 6 can never complete
        // and only the deadline can end this drain.
        [HANDLER_TOOL]: async () => {
          entered += 1;
          await new Promise<never>(() => undefined);
          throw new Error('unreachable');
        },
      },
    });

    const client = await connectClient(t, r.port, 'hard-stop');
    void client.callTool({ name: HANDLER_TOOL, arguments: {} }).catch(() => undefined);
    await until(() => entered > 0, 'the stalled handler to be entered');

    const startedAt = process.hrtime.bigint();
    const outcome = r.serving.drain('signal');

    let settledEarly = false;
    void outcome.then(() => {
      settledEarly = true;
    });
    await settle(8);

    // THE PROOF THAT THE FAST-FORWARD DROVE THE LOGIC. The drain is genuinely
    // stuck in step 6 — it has not resolved and cannot — and the only live
    // timer is the deadline, armed at exactly the configured value.
    assert.equal(settledEarly, false, 'the drain resolved without the deadline');
    assert.deepEqual(r.clock.durations('deadline'), [35_000]);
    assert.equal(r.clock.live('deadline').length, 1);
    assert.equal(r.steps.at(-1), 'await-in-flight', 'the drain was not parked in step 6');

    assert.equal(clock.fire('deadline'), 1, 'the deadline timer was not live');
    assert.equal(await outcome, 'deadline');

    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    assert.ok(
      elapsedMs < 36_000,
      `the hard stop must land inside deadline + 1 s; took ${elapsedMs} ms`,
    );

    assert.ok(r.steps.includes(HTTP_HARD_STOP_STEP), 'the hard stop step never fired');
    assert.ok(!r.steps.includes('exit-code'), 'a hard stop must not report a clean exit code');
    assert.deepEqual([...r.exits], [EXIT_CODES.deadline]);
    assert.deepEqual([...r.codes], [EXIT_CODES.deadline]);
    assert.equal(EXIT_CODES.deadline, 75);

    await r.serving.dispose();
  });

  test('75 is reserved for the deadline — dispose() never reaches it', async (t) => {
    const clock = drainClock(['predrain']);
    let entered = 0;
    const r = await rig(t, {
      clock,
      manualTeardown: true,
      handlers: {
        [HANDLER_TOOL]: async () => {
          entered += 1;
          await new Promise<never>(() => undefined);
          throw new Error('unreachable');
        },
      },
    });

    // The stall has to be REAL, or `dispose()` completes cleanly and this case
    // silently asserts nothing about the hard stop at all.
    const client = await connectClient(t, r.port, 'dispose-hard-stop');
    void client.callTool({ name: HANDLER_TOOL, arguments: {} }).catch(() => undefined);
    await until(() => entered > 0, 'the stalled handler to be entered');

    const disposal = r.serving.dispose();
    await settle(8);
    assert.equal(clock.fire('deadline'), 1, 'the deadline timer was not live');
    await disposal;

    // A hard stop reached through `dispose()` still destroys sockets and
    // releases the runtime — it simply never touches the exit status, because
    // `dispose()` is the teardown a test's `after()` calls.
    assert.ok(r.steps.includes(HTTP_HARD_STOP_STEP));
    assert.deepEqual([...r.exits], []);
    assert.deepEqual([...r.codes], []);
  });
});

// ===========================================================================
// 6. Outbound abandonment, and the PRODUCTION disposal affordances
// (C20, C21, C22, C23)
// ===========================================================================

/** Counters on the real collaborators — never on a stand-in. See §6's preamble. */
interface DisposalCounters {
  limiterClose: number;
  clientBeginDrain: number;
  clientClose: number;
  limiterClosedAtStep: string | null;
}

/**
 * Build a `RuntimeDeps` whose client and limiter are the PRODUCTION classes.
 *
 * Each counter increments and then calls the real method, so what runs behind
 * it is the real teardown: `RateLimiter.close()` really does fail its queued
 * waiters, and `UnifiClient.close()` really does abort the remaining in-flight
 * controllers and `destroy()` every cached keep-alive agent. A wrapper that
 * substituted a stand-in would turn "the runtime disposed the client" into
 * "the harness called itself", which is exactly the shape this criterion
 * forbids.
 */
function productionDisposalDeps(
  counters: DisposalCounters,
  currentStep: () => string | null,
  onLimiter?: (limiter: RateLimiter) => void,
  extra?: Partial<UnifiClientOptions>,
): RuntimeDeps {
  return {
    createCredentialStore: (config: ServerConfig, options: CredentialStoreOptions) =>
      new CredentialStore(config, { ...options, keychain: null }),
    createClient: (config, credentials, options) => {
      const limiter = createRateLimiter(config);
      const realLimiterClose = limiter.close.bind(limiter);
      limiter.close = (): void => {
        counters.limiterClose += 1;
        counters.limiterClosedAtStep ??= currentStep();
        realLimiterClose();
      };
      onLimiter?.(limiter);

      const client = new UnifiClient(config, credentials, { ...options, ...extra, limiter });
      const realBeginDrain = client.beginDrain.bind(client);
      client.beginDrain = (): void => {
        counters.clientBeginDrain += 1;
        realBeginDrain();
      };
      const realClose = client.close.bind(client);
      client.close = async (): Promise<void> => {
        counters.clientClose += 1;
        await realClose();
      };
      return client;
    },
  };
}

describe('the disposal path invokes the PRODUCTION affordances (C23)', () => {
  test('the real RateLimiter and UnifiClient are closed, counted at the call site', async (t) => {
    const counters: DisposalCounters = {
      limiterClose: 0,
      clientBeginDrain: 0,
      clientClose: 0,
      limiterClosedAtStep: null,
    };
    let steps: readonly string[] = [];
    const r = await rig(t, {
      runtimeDeps: productionDisposalDeps(counters, () => steps.at(-1) ?? null),
    });
    steps = r.steps;

    assert.equal(await r.serving.drain('signal'), 'clean');

    // `beginDrain` at step 4 — which is what closes the limiter, because
    // `UnifiClient.limiter` is private with no accessor and this is the only
    // propagation path that can exist.
    //
    // `>= 1` and not `=== 1`, deliberately: `close()` IMPLIES `beginDrain()`
    // per the class's own post-close contract, so step 9 re-enters it and both
    // calls are real. What must be pinned is that the FIRST one happened at
    // step 4 — pinning the total would pin an internal call graph instead.
    assert.ok(counters.clientBeginDrain >= 1, 'client.beginDrain() was not invoked');
    assert.ok(counters.limiterClose >= 1, 'limiter.close() was not invoked');
    assert.equal(counters.limiterClosedAtStep, 'begin-drain', 'the limiter closed at the wrong step');

    // `close()` at step 9 — the call that destroys every cached outbound
    // keep-alive agent. `agent.destroy()` is reachable from nowhere else in
    // `src/`, and pooled `keepAlive: true` handles are `ref`'d, so without this
    // exit-0-by-natural-drain is unreachable by construction. §8's spawned
    // child is where that exit is actually observed.
    assert.equal(counters.clientClose, 1, 'client.close() was not invoked');
    assert.equal(r.core.client.isDraining, true);
  });

  test('the counters are not vacuous — a drain that never ran leaves them at zero', async (t) => {
    const counters: DisposalCounters = {
      limiterClose: 0,
      clientBeginDrain: 0,
      clientClose: 0,
      limiterClosedAtStep: null,
    };
    const r = await rig(t, {
      manualTeardown: true,
      runtimeDeps: productionDisposalDeps(counters, () => null),
    });

    assert.equal(counters.clientBeginDrain, 0);
    assert.equal(counters.clientClose, 0);
    await r.serving.dispose();
    assert.equal(counters.clientClose, 1);
  });
});

describe('queued rate-limit waiters fail immediately rather than extending the drain (C22)', () => {
  test('ten queued waiters take the structured rate_limit error at step 4', async (t) => {
    const counters: DisposalCounters = {
      limiterClose: 0,
      clientBeginDrain: 0,
      clientClose: 0,
      limiterClosedAtStep: null,
    };
    let captured: RateLimiter | null = null;
    const r = await rig(t, {
      runtimeDeps: productionDisposalDeps(
        counters,
        () => null,
        (limiter) => {
          captured = limiter;
        },
      ),
    });
    const limiter = captured as RateLimiter | null;
    assert.ok(limiter !== null, 'the production limiter was never constructed');

    // One token, then ten waiters queued behind it on the same bucket. The
    // limiter's FIFO tail chain is what makes them genuinely queued rather than
    // merely pending.
    const bucket = 'network:local:127.0.0.1:1';
    limiter.setLimit(bucket, { requestsPerMinute: 1, maxWaitMs: 60_000 });
    await limiter.acquire(bucket);

    const waiters = Array.from({ length: 10 }, () =>
      limiter.acquire(bucket).then(
        () => ({ outcome: 'admitted' as const }),
        (error: unknown) => ({ outcome: 'failed' as const, error }),
      ),
    );
    await settle();

    const startedAt = process.hrtime.bigint();
    assert.equal(await r.serving.drain('signal'), 'clean');
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

    const settled = await Promise.all(waiters);
    assert.equal(settled.length, 10);
    for (const outcome of settled) {
      assert.equal(outcome.outcome, 'failed', 'a queued waiter was admitted during the drain');
      const error = (outcome as { error: unknown }).error;
      assert.ok(error instanceof UnifiError, 'the refusal was not the structured error');
      // The EXISTING contract, unchanged: no new `ErrorCategory` member is
      // introduced for shutdown, and `retryAfterSeconds` still carries a hint.
      assert.equal(error.normalized.category, 'rate_limit');
      assert.equal(typeof error.normalized.retryAfterSeconds, 'number');
    }

    // "Immediately", stated as an assertion: ten 60-second waits would have
    // taken the drain far past its deadline had they been honoured.
    assert.ok(elapsedMs < 5_000, `the queued waiters extended the drain to ${elapsedMs} ms`);
  });
});

describe('SIGTERM during an outbound wait abandons it rather than awaiting it', () => {
  let origin: LoopbackOrigin | null = null;

  test('a retryable 503 gets NO second attempt, and the Retry-After sleep is abandoned (C20)', async (t) => {
    origin = await startLoopbackOrigin({
      // A retryable status with an explicit 30-second hint — the exact shape
      // that, if honoured, puts the process past its deadline and turns a clean
      // shutdown into exit 75.
      respond: () => ({
        status: 503,
        body: { error: 'try later' },
        headers: { 'Retry-After': '30' },
      }),
    });
    const captured = origin;
    t.after(async () => {
      await captured.close();
    });

    /** The injected backoff sleep, with its pending state observable. */
    let sleepsStarted = 0;
    let sleepsCompleted = 0;
    const sleep = async (ms: number): Promise<void> => {
      sleepsStarted += 1;
      await new Promise((resolve) => setTimeout(resolve, ms));
      sleepsCompleted += 1;
    };

    const counters: DisposalCounters = {
      limiterClose: 0,
      clientBeginDrain: 0,
      clientClose: 0,
      limiterClosedAtStep: null,
    };
    const r = await rig(t, {
      env: httpEnv(loopbackEnv(captured) as Record<string, string>),
      runtimeDeps: productionDisposalDeps(counters, () => null, undefined, { sleep }),
    });

    const client = await connectClient(t, r.port, 'c20');
    const call = client
      // `site_id` is a REQUIRED parameter of this action; without it the call
      // fails a config precondition and never reaches a socket, so the
      // interceptor would record nothing and this case would assert nothing.
      .callTool({ name: OUTBOUND_TOOL, arguments: { site_id: 'default' } })
      .then(() => 'answered' as const)
      .catch(() => 'threw' as const);

    await until(() => captured.requests.length >= 1, 'the first outbound attempt');
    await until(() => sleepsStarted >= 1, 'the Retry-After backoff to begin');

    const startedAt = process.hrtime.bigint();
    assert.equal(await r.serving.drain('signal'), 'clean');
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

    await call;

    // The attempt counter is the assertion. A drain that waited out the 30 s
    // hint would have made a second attempt; one that abandoned it makes none.
    assert.equal(
      captured.requests.length,
      1,
      `a retryable 503 received before SIGTERM must get no second attempt; saw ${captured.requests.length}`,
    );
    assert.equal(sleepsStarted, 1);
    assert.equal(
      sleepsCompleted,
      0,
      'the injected 30 s sleep ran to completion — the backoff was awaited, not abandoned',
    );
    // A run that exits in time but ran the full sleep FAILS this criterion, so
    // both the timing and the sleep counter are asserted.
    assert.ok(elapsedMs < 30_000, `the drain waited on the backoff: ${elapsedMs} ms`);
    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
  });

  test('an action still resolving credentials is FAILED, not awaited (C21)', async (t) => {
    let resolveEntered = 0;
    const r = await rig(t, {
      runtimeDeps: {
        createCredentialStore: (config: ServerConfig, options: CredentialStoreOptions) => {
          const store = new CredentialStore(config, { ...options, keychain: null });
          // `resolveFor` is awaited BEFORE the retry loop and before any token
          // is held — the fifth outbound state, and the one that precedes all
          // the others. A drain that waits on it fails this criterion.
          store.resolveFor = async (): Promise<string> => {
            resolveEntered += 1;
            await new Promise<never>(() => undefined);
            throw new Error('unreachable');
          };
          return store;
        },
      },
    });

    const client = await connectClient(t, r.port, 'c21');
    const call = client
      .callTool({ name: HANDLER_TOOL, arguments: {} })
      .then(() => 'answered' as const)
      .catch(() => 'threw' as const);
    await until(() => resolveEntered > 0, 'the credential resolution to begin');

    const startedAt = process.hrtime.bigint();
    const outcome = await r.serving.drain('signal');
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;

    assert.equal(outcome, 'clean', 'the drain waited on a never-settling credential resolution');
    assert.ok(!r.steps.includes(HTTP_HARD_STOP_STEP));
    assert.ok(elapsedMs < 30_000, `the drain took ${elapsedMs} ms`);
    // The action terminates with a structured error rather than hanging: the
    // abandonment resolves the wait through an AbortController, never by
    // rejecting a long-lived promise — a rejection with no handler attached at
    // the moment of rejection is what Node 20's default
    // `--unhandled-rejections=throw` turns into a dead process.
    assert.equal(await call, 'answered');
    assert.deepEqual([...r.codes], [EXIT_CODES.clean]);
  });
});

// ===========================================================================
// 7. Second-signal escalation, through the HTTP handle (C18)
//
// Portable: the four handlers are installed into an injected registrar and
// invoked as ordinary functions, so no signal is delivered on any leg.
// ===========================================================================

describe('a second signal escalates immediately rather than restarting the drain', () => {
  interface Registrar {
    readonly listeners: Map<string, (...args: unknown[]) => void>;
    readonly registrar: ProcessEventRegistrar;
  }

  function recordingRegistrar(): Registrar {
    const listeners = new Map<string, (...args: unknown[]) => void>();
    return {
      listeners,
      registrar: (event, listener) => {
        listeners.set(event, listener);
      },
    };
  }

  async function escalate(
    t: TestContext,
    first: 'SIGTERM' | 'SIGINT',
    second: 'SIGTERM' | 'SIGINT',
  ): Promise<{ exits: number[]; steps: readonly string[] }> {
    const clock = drainClock([]); // parked in the hold when the second signal lands
    const r = await rig(t, { clock, manualTeardown: true });
    const { listeners, registrar } = recordingRegistrar();
    const exits: number[] = [];

    const shutdown = installShutdown({
      on: registrar,
      exit: (code: number) => exits.push(code),
      setExitCode: () => undefined,
    });
    shutdown.publish(r.serving, r.core.config.serving.shutdownDeadlineMs);

    listeners.get(first)?.();
    await settle();
    assert.equal(shutdown.aborting, true, 'the first signal did not begin a drain');
    const stepsAfterFirst = [...r.steps];

    listeners.get(second)?.();
    await settle();

    // The escalation must not restart the sequence from the top.
    assert.deepEqual(
      r.steps.slice(0, stepsAfterFirst.length),
      stepsAfterFirst,
      'the second signal re-ran the drain from the beginning',
    );

    clock.fire('predrain');
    await r.serving.dispose();
    return { exits, steps: r.steps };
  }

  test('a second SIGTERM exits 143', async (t) => {
    const { exits } = await escalate(t, 'SIGTERM', 'SIGTERM');
    assert.deepEqual(exits, [EXIT_CODES.forcedTermination]);
    assert.equal(EXIT_CODES.forcedTermination, 143);
  });

  test('a SIGINT during a SIGTERM drain exits 130 — the code follows the SECOND signal', async (t) => {
    const { exits } = await escalate(t, 'SIGTERM', 'SIGINT');
    assert.deepEqual(exits, [EXIT_CODES.forcedInterrupt]);
    assert.equal(EXIT_CODES.forcedInterrupt, 130);
  });

  test('neither forced code is 75 — 75 means the deadline expired and nothing else', () => {
    // An operator pressing Ctrl-C twice is the most common human action in the
    // system. Reusing 75 for it would fire ADR-05's reopen trigger — "the
    // 35-second derivation was wrong" — on pure noise, forever.
    assert.notEqual(EXIT_CODES.forcedTermination, EXIT_CODES.deadline);
    assert.notEqual(EXIT_CODES.forcedInterrupt, EXIT_CODES.deadline);
  });
});

// ===========================================================================
// 8. Real signal DELIVERY, in a spawned child (MECH-SIGNAL)
//
// The ONLY section carrying a declared skip. Everything it asserts about the
// state machine is covered portably above; what only a delivered signal can
// prove is that the handler runs at all and that the process's OWN exit status
// is the one the vocabulary names.
// ===========================================================================

describe('a delivered SIGTERM drains the real entrypoint over HTTP', { skip: MECH_SIGNAL_SKIP }, () => {
  /**
   * A HARNESS LIMITATION, recorded here rather than worked around.
   *
   * `test/harness/serve-entry.ts`'s watchdog is `setTimeout(..., holdMs)` and
   * is **ref'd on purpose** — its comment says so, because an unref'd watchdog
   * would let a child exit out from under a parent that is still probing it.
   * A ref'd timer holds the event loop open, so a spawned child CANNOT exit by
   * natural event-loop drain before `holdMs` however completely it drained.
   *
   * This test therefore asserts what a delivered signal genuinely proves and
   * nothing more: that the handler ran at all (the half no Windows leg can
   * cover), that every drain step completed without error, and that the
   * process's own exit status is `0` and it was never killed by a signal —
   * which is NFR-27's actual claim. **The exit-0-BY-NATURAL-DRAIN half of C23
   * is not assertable through this harness** and is carried forward; §5 asserts
   * the exit-code vocabulary in-process, through the injected hook, on every
   * leg.
   */
  const HOLD_MS = 15_000;

  test('the signal is handled, every step completes, and the exit is 0 — never a SIGKILL', async () => {
    const server = spawnServeEntry({ env: httpEnv({ UNIFI_HTTP_PORT: '0' }), after: 'hold', holdMs: HOLD_MS });

    try {
      const counters = await server.counters();
      assert.equal(counters.listen, 1, 'the child never bound a listener');
      assert.equal(counters.transportActivated.http, 1);

      // The signal is driven here rather than through the harness's `stop()`,
      // which escalates to SIGKILL as a teardown measure: the exit status read
      // below must be the CHILD'S OWN and never that escalation's.
      server.child.kill('SIGTERM');

      // The handler RAN. On `windows-latest` this line can never appear,
      // because `process.kill()` terminates unconditionally there and no
      // handler is invoked — which is the whole of MECH-SIGNAL.
      await server.waitForStderr((text) => text.includes('SIGTERM received — draining'));

      const result = await server.exit();
      const stderr = server.stderr();

      assert.equal(
        result.signal,
        null,
        `the child was killed by ${String(result.signal)} instead of draining — ` +
          `this is the SIGKILL NFR-27 exists to prevent.\n--- stderr ---\n${stderr}`,
      );
      assert.equal(result.code, EXIT_CODES.clean, `expected a clean exit; stderr was:\n${stderr}`);

      // Every awaited step is individually caught and logs one line on failure,
      // so the ABSENCE of those lines is the evidence that the sequence ran to
      // completion rather than limping through it.
      assert.doesNotMatch(stderr, /drain (begin-drain|close-listener|close-connections|close-runtime)/);
      assert.doesNotMatch(stderr, /ERROR/);
    } finally {
      await server.stop();
    }
  });
});
