/**
 * US-09 — the outbound client's bounded lifecycle (FR-70 steps 3, 4 and 7; NFR-27).
 *
 * Three things are asserted here, and the third pulls against the first two.
 *
 * The first is that `beginDrain()` stops admitting without truncating anything:
 * a request entered after it fails with the existing structured `rate_limit`
 * error, but the FR-44 write gate keeps its precedence, so a write-gated action
 * during drain still gets its `config` refusal. That ordering is the whole
 * point of the drain check sitting *after* the gate rather than before it, and
 * the obvious weaker test — asserting only that a drained read fails — passes
 * against both orderings and therefore proves nothing.
 *
 * The second is that a wait is abandoned rather than served, in both places a
 * request can be parked before it holds anything: inside a retry backoff, and
 * inside `credentials.resolveFor()`. Both are asserted through seams whose
 * promise NEVER settles, so a pass cannot mean the wait ran to completion; a
 * run in which the injected sleep is observed to finish fails. The backoff test
 * also counts outbound attempts at the socket, because "no further retry"
 * is a consequence of the rejection propagating out of `request()` and would
 * otherwise be indistinguishable from a backoff that merely finished early.
 *
 * The third is that a client which is never drained behaves exactly as it did
 * before the affordance existed. The regression group at the bottom pins the
 * write-gate refusal, the attempt count and the backoff arithmetic, none of
 * which US-09 is allowed to move.
 *
 * WHAT IS DEFERRED, AND WHY. The story phrases the backoff criterion in terms
 * of a 429 carrying `Retry-After: 30`, which needs a real HTTPS response. This
 * repo has no PEM fixtures and cannot generate a certificate with the standard
 * library alone (test/fixtures/README.md), so no HTTPS server can be stood up
 * in process. Both await sites go through the same `waitOrAbandon` wrapper, so
 * the mechanism is asserted at the reachable site — the transient-network
 * backoff — with the retry knobs configured so the abandoned wait is of the
 * same 30-second-class magnitude and "abandoned rather than served" is a
 * meaningful claim. The `Retry-After: 30` variant itself, and the exit-code
 * half of FR-70 (a real SIGTERM, exit 0 by natural drain), belong to the
 * spawned harness (test-strategy C20, US-24/US-28). They are NOT covered here.
 *
 * One further honest limit: Node 20's `http.Agent` exposes no `destroyed`
 * flag (verified — `'destroyed' in agent` is false), so "the agent is
 * destroyed" cannot be read off the object. It is asserted instead by its
 * observable consequences on the REAL pooled agent: `destroy()` is invoked once
 * per map entry through a wrapper that delegates to the real implementation,
 * the pooled socket ends `destroyed === true`, and the map is emptied. A double
 * would be worthless here — `agent.destroy()` being called nowhere in `src/` is
 * precisely why the process cannot exit by natural drain today.
 */
import { strict as assert } from 'node:assert';
import { createServer, type Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';
import type { Agent } from 'node:https';

import { loadConfig, type ServerConfig } from '../src/config.js';
import type { CredentialStore } from '../src/credentials.js';
import { UnifiClient, type UnifiResponse } from '../src/http/client.js';
import { RateLimiter } from '../src/http/ratelimit.js';
import { UnifiError, type Action, type NormalizedError, type ServiceId } from '../src/types.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

const LOCAL_API_KEY = 'test-local-key';

/** A port nothing listens on, for the cases that must never reach a socket. */
const UNCONTACTED_PORT = 9;

/**
 * Retry knobs that put the abandoned backoff in the same magnitude class as the
 * story's `Retry-After: 30`. `backoffMs` jitters by `0.5 + Math.random() / 2`,
 * so a 60 000 ms exponential yields 30 000–60 000 ms: long enough that "the
 * wait was abandoned rather than served" is a real claim rather than a race
 * this test would win anyway.
 */
const THIRTY_SECOND_CLASS_RETRY = {
  UNIFI_RETRY_MAX_ATTEMPTS: '3',
  UNIFI_RETRY_BASE_DELAY_MS: '60000',
  UNIFI_RETRY_MAX_DELAY_MS: '60000',
} as const;

/** The smallest backoff `THIRTY_SECOND_CLASS_RETRY` can produce. */
const MIN_CLASS_BACKOFF_MS = 30_000;

/** `Math.ceil(DEFAULT_MAX_WAIT_MS / 1000)` — the hint when no wait was computed. */
const CEILING_SECONDS = 30;

// --------------------------------------------------------------------------
// A console that is real at the socket level and never speaks TLS.
// --------------------------------------------------------------------------

interface FakeConsole {
  readonly port: number;
  /** Outbound attempts, counted where they actually happen. */
  readonly connections: number;
  close(): Promise<void>;
}

/**
 * A `node:net` listener standing in for a console.
 *
 * `buildUrl` produces `https://127.0.0.1:<port>/...` because `normalizeHost`
 * keeps a `host:port` string intact, so the client genuinely dials this
 * listener. What the listener then does to the socket is what selects the
 * client path under test — see the two factories below.
 */
async function startConsole(onConnection: (socket: Socket) => void): Promise<FakeConsole> {
  const live = new Set<Socket>();
  let connections = 0;

  const server = createServer((socket) => {
    connections += 1;
    live.add(socket);
    socket.on('close', () => live.delete(socket));
    // A client that resets mid-handshake makes the server end error too; it is
    // not the subject of any assertion here.
    socket.on('error', () => undefined);
    onConnection(socket);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    return assert.fail('expected the listener to report an AddressInfo');
  }

  return {
    port: address.port,
    get connections(): number {
      return connections;
    },
    close(): Promise<void> {
      for (const socket of live) socket.destroy();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** Accepts, then resets: the client sees ECONNRESET, which is retryable. */
function startResettingConsole(): Promise<FakeConsole> {
  return startConsole((socket) => socket.destroy());
}

/** Accepts and holds, never speaking TLS: the attempt stays genuinely in flight. */
function startHangingConsole(): Promise<FakeConsole> {
  return startConsole(() => undefined);
}

// --------------------------------------------------------------------------
// Client construction
// --------------------------------------------------------------------------

function configFor(port: number, overrides: Record<string, string> = {}): ServerConfig {
  return loadConfig(
    {
      UNIFI_NETWORK_TRANSPORT: 'local',
      UNIFI_LOCAL_HOST: `127.0.0.1:${port}`,
      UNIFI_LOCAL_API_KEY: LOCAL_API_KEY,
      ...overrides,
    },
    { repoRoot: REPO_ROOT },
  );
}

/** The only member of `CredentialStore` that `UnifiClient` ever calls. */
interface CredentialSource {
  resolveFor(service: ServiceId, mode: string, host?: string): Promise<string>;
}

/**
 * The real `CredentialStore` reaches the OS keychain through `keytar` before it
 * falls back to the environment — slow, machine-dependent, and capable of
 * prompting on a workstation. None of that is what US-09 is about, and the
 * client's entire dependency on the store is `resolveFor`, so a stand-in over
 * that one method is a faithful substitute for the surface under test.
 *
 * The cast is confined to this helper. It crosses a class-private boundary
 * that no interface exists for, which is the one place the suite already
 * accepts one.
 */
function asCredentialStore(source: CredentialSource): CredentialStore {
  return source as unknown as CredentialStore;
}

class StaticCredentials implements CredentialSource {
  resolveFor(): Promise<string> {
    return Promise.resolve(LOCAL_API_KEY);
  }
}

/** A store that never answers, so the client is genuinely parked at line 148. */
class NeverSettlingCredentials implements CredentialSource {
  calls = 0;

  resolveFor(): Promise<string> {
    this.calls += 1;
    return new Promise<string>(() => {});
  }
}

function readAction(): Action {
  return {
    id: 'network.test.read',
    service: 'network',
    method: 'GET',
    // `actionClass: 'read'` is what makes the attempt retry-eligible (FR-26).
    actionClass: 'read',
    path: '/v1/sites',
    summary: 'List sites',
    description: '',
    tags: [],
    parameters: [],
    earlyAccess: false,
    requiredScopes: [],
    searchText: '',
  };
}

function writeAction(): Action {
  return { ...readAction(), id: 'network.test.write', method: 'POST', actionClass: 'write' };
}

// --------------------------------------------------------------------------
// Assertion helpers
// --------------------------------------------------------------------------

/** Settle a request into a value we can inspect, without ever leaving it floating. */
function outcomeOf(promise: Promise<UnifiResponse>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

function normalizedOf(reason: unknown): NormalizedError {
  if (!(reason instanceof UnifiError)) {
    return assert.fail(`expected a UnifiError, got ${String(reason)}`);
  }
  return reason.normalized;
}

function structuredRateLimitError(reason: unknown): NormalizedError {
  const normalized = normalizedOf(reason);
  // No new ErrorCategory member: shutdown reuses the existing rate_limit one.
  assert.equal(normalized.category, 'rate_limit');
  assert.equal(
    typeof normalized.retryAfterSeconds,
    'number',
    'retryAfterSeconds must be carried as a number, never null',
  );
  assert.notEqual(normalized.recoveryHint, '');
  return normalized;
}

function shutdownErrorOf(reason: unknown): NormalizedError {
  const normalized = structuredRateLimitError(reason);
  assert.match(normalized.message, /shut ?down/i);
  return normalized;
}

/**
 * Read a private collection for observation only. Confined to this file so the
 * source keeps no test-only public accessor; behavioural assertions are used
 * wherever one is available.
 */
function privateCollection(client: UnifiClient, name: 'pendingTimers'): ReadonlySet<unknown>;
function privateCollection(client: UnifiClient, name: 'agents'): ReadonlyMap<string, Agent>;
function privateCollection(
  client: UnifiClient,
  name: string,
): ReadonlySet<unknown> | ReadonlyMap<string, Agent> {
  const value: unknown = Reflect.get(client, name);
  if (value instanceof Set) return value as ReadonlySet<unknown>;
  if (value instanceof Map) return value as ReadonlyMap<string, Agent>;
  return assert.fail(`expected private \`${name}\` to be a Set or Map`);
}

function pooledSockets(agent: Agent): Socket[] {
  return Object.values(agent.sockets)
    .flat()
    .filter((socket): socket is Socket => socket !== undefined);
}

function onlyEntry<T>(values: Iterable<T>, what: string): T {
  const items = [...values];
  assert.equal(items.length, 1, `expected exactly one ${what}, saw ${items.length}`);
  const first = items[0];
  if (first === undefined) return assert.fail(`expected one ${what}`);
  return first;
}

function backoffAt(waits: readonly number[], index: number): number {
  const value = waits[index];
  if (typeof value !== 'number') return assert.fail(`expected a backoff at index ${index}`);
  return value;
}

/** A sleep that records its waits and never resolves, so nothing settles by elapsing. */
function parkingSleep(): {
  sleep: (ms: number) => Promise<void>;
  waits: number[];
  parked: Promise<void>;
} {
  const waits: number[] = [];
  const parked = new Promise<void>(() => {});
  return {
    waits,
    parked,
    sleep: (ms: number): Promise<void> => {
      waits.push(ms);
      return parked;
    },
  };
}

/**
 * A bounded companion for a race whose failure mode is "never settles".
 * Without it, a regression reads as a 60-second suite timeout with no name on
 * it; with it, the assertion says which promise stalled.
 */
function stallGuard(ms: number): { stalled: Promise<'stalled'>; release: () => void } {
  let handle: NodeJS.Timeout | undefined;
  const stalled = new Promise<'stalled'>((resolve) => {
    handle = setTimeout(() => resolve('stalled'), ms);
  });
  return { stalled, release: (): void => clearTimeout(handle) };
}

async function waitUntil(predicate: () => boolean, what: string): Promise<void> {
  const deadlineMs = Date.now() + 10_000;
  while (!predicate()) {
    if (Date.now() > deadlineMs) assert.fail(`timed out waiting for ${what}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
}

const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

// --------------------------------------------------------------------------

describe('UnifiClient.beginDrain() — the contract (US-09)', () => {
  test('is synchronous, returns undefined, and a second call is a no-op', () => {
    const config = configFor(UNCONTACTED_PORT);
    const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
      warn: () => {},
    });

    assert.equal(client.isDraining, false);
    assert.equal(client.beginDrain(), undefined);
    assert.equal(client.isDraining, true);

    assert.doesNotThrow(() => client.beginDrain());
    assert.equal(client.isDraining, true);
  });

  test('a request entered after the drain fails with the structured shutdown error', async () => {
    const console_ = await startResettingConsole();
    try {
      const config = configFor(console_.port);
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
      });

      client.beginDrain();
      const normalized = shutdownErrorOf(await outcomeOf(client.request(readAction())));

      assert.equal(normalized.service, 'network');
      assert.equal(normalized.retryAfterSeconds, CEILING_SECONDS);
      assert.equal(normalized.httpStatus, null);
      assert.equal(normalized.upstreamCode, null);
      // Refused before anything left this process, which is the claim the
      // recovery hint makes to the caller.
      assert.equal(console_.connections, 0);
    } finally {
      await console_.close();
    }
  });

  test('a write-gated action during drain still gets its FR-44 config refusal', async () => {
    const console_ = await startResettingConsole();
    try {
      // No UNIFI_ENABLE_WRITES, so `network` writes are gated.
      const config = configFor(console_.port);
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
      });

      client.beginDrain();
      const normalized = normalizedOf(await outcomeOf(client.request(writeAction())));

      // The drain check sits AFTER the gate. Were it before, this would be
      // `rate_limit` and an operator would be told the wrong thing about why a
      // write was refused — an enforcement point silently moved by a lifecycle
      // change. Both orderings refuse; only one refuses for the right reason.
      assert.equal(normalized.category, 'config');
      assert.match(normalized.message, /writes are not enabled for network/);
      assert.equal(console_.connections, 0);
    } finally {
      await console_.close();
    }
  });

  test('closes the limiter, which is the only propagation path that can exist', () => {
    const limiter = new RateLimiter({ now: () => 0, sleep: async () => {} });
    const config = configFor(UNCONTACTED_PORT);
    const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
      limiter,
      warn: () => {},
    });

    assert.equal(limiter.isClosed, false);
    client.beginDrain();

    // `limiter` is private with no accessor, so nothing but a UnifiClient
    // method could ever reach it.
    assert.equal(limiter.isClosed, true);
  });

  test('the injected limiter is the instance the client actually acquires on', async () => {
    // NFR-26 / test-strategy C25 rests on this seam: a later parity test
    // constructs one limiter, passes it to two sessions and asserts both land
    // on it. If `UnifiClientOptions.limiter` ever stopped being honoured, that
    // test would silently compare two independent limiters and always pass.
    class RecordingLimiter extends RateLimiter {
      readonly acquired: string[] = [];

      override acquire(bucketKey: string): Promise<void> {
        this.acquired.push(bucketKey);
        return super.acquire(bucketKey);
      }
    }

    const console_ = await startResettingConsole();
    try {
      const limiter = new RecordingLimiter();
      const config = configFor(console_.port, { UNIFI_RETRY_MAX_ATTEMPTS: '1' });
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        limiter,
        warn: () => {},
      });

      const normalized = normalizedOf(await outcomeOf(client.request(readAction())));

      assert.equal(normalized.category, 'network');
      assert.deepEqual(limiter.acquired, [`network:local:127.0.0.1:${console_.port}`]);
    } finally {
      await console_.close();
    }
  });
});

describe('UnifiClient.beginDrain() — abandonment (US-09)', () => {
  test('an in-progress retry backoff is abandoned, not awaited, and nothing is retried', async () => {
    const console_ = await startResettingConsole();
    const guard = stallGuard(5_000);
    try {
      const config = configFor(console_.port, THIRTY_SECOND_CLASS_RETRY);
      const { sleep, waits, parked } = parkingSleep();
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
        sleep,
      });

      const outcome = outcomeOf(client.request(readAction()));
      await waitUntil(() => waits.length === 1, 'the first attempt to fail into a backoff');
      assert.equal(console_.connections, 1);
      assert.ok(
        backoffAt(waits, 0) >= MIN_CLASS_BACKOFF_MS,
        `expected a 30s-class backoff, got ${backoffAt(waits, 0)}ms`,
      );

      const startedAt = Date.now();
      client.beginDrain();

      // The injected sleep never resolves, so a pass here can only mean the
      // wait was abandoned — not that it ran to completion.
      const winner = await Promise.race([
        outcome.then(() => 'request' as const),
        parked.then(() => 'sleep' as const),
        guard.stalled,
      ]);
      assert.equal(winner, 'request');

      const reason = await outcome;
      const normalized = shutdownErrorOf(reason);
      const elapsedMs = Date.now() - startedAt;

      assert.equal(normalized.service, 'network');
      // Carried unchanged from the backoff this attempt had already computed,
      // rather than recomputed or nulled.
      assert.equal(normalized.retryAfterSeconds, Math.ceil(backoffAt(waits, 0) / 1000));
      assert.ok(elapsedMs < 1_000, `rejection took ${elapsedMs}ms; the backoff was served`);

      // The upstream failure that provoked the retry survives as `cause`;
      // discarding it would leave nothing to explain why the request was
      // retrying at all.
      if (!(reason instanceof UnifiError)) return assert.fail('expected a UnifiError');
      assert.equal(normalizedOf(reason.cause).category, 'network');

      // "No further attempt" is a consequence of the rejection propagating out
      // of request(), counted where an attempt actually is: at the socket.
      assert.deepEqual(waits.length, 1);
      assert.equal(console_.connections, 1);
    } finally {
      guard.release();
      await console_.close();
    }
  });

  test('the abort settles the action and close() releases the real timer', async () => {
    // The default sleep, deliberately not injected: this is the second half of
    // the mechanism. The abort stops the ACTION waiting; only the cleared
    // handle stops the PROCESS being held open, and a `ref`'d 30s timer is
    // exactly what keeps exit-0-by-natural-drain out of reach.
    const console_ = await startResettingConsole();
    const guard = stallGuard(5_000);
    try {
      const config = configFor(console_.port, THIRTY_SECOND_CLASS_RETRY);
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
      });
      const timers = privateCollection(client, 'pendingTimers');

      const outcome = outcomeOf(client.request(readAction()));
      await waitUntil(() => timers.size === 1, 'the backoff to hold a real timer');

      const startedAt = Date.now();
      client.beginDrain();
      const winner = await Promise.race([outcome.then(() => 'request' as const), guard.stalled]);
      assert.equal(winner, 'request');
      shutdownErrorOf(await outcome);
      const elapsedMs = Date.now() - startedAt;

      assert.ok(elapsedMs < 1_000, `rejection took ${elapsedMs}ms; the backoff was served`);
      assert.equal(
        timers.size,
        1,
        'beginDrain() settles the action; the timer handle is still referenced',
      );

      await client.close();
      assert.equal(timers.size, 0, 'close() must clear the handle, not merely stop awaiting it');
    } finally {
      guard.release();
      await console_.close();
    }
  });

  test('an in-progress credential resolution is failed, not awaited', async () => {
    const console_ = await startResettingConsole();
    const guard = stallGuard(5_000);
    try {
      const config = configFor(console_.port);
      const credentials = new NeverSettlingCredentials();
      const client = new UnifiClient(config, asCredentialStore(credentials), { warn: () => {} });

      const outcome = outcomeOf(client.request(readAction()));
      await waitUntil(() => credentials.calls === 1, 'the credential resolution to be entered');

      client.beginDrain();

      // `resolveFor` never settles, so a drain that awaited it would stall here.
      const winner = await Promise.race([outcome.then(() => 'request' as const), guard.stalled]);
      assert.equal(winner, 'request');

      const normalized = shutdownErrorOf(await outcome);
      assert.equal(normalized.service, 'network');
      assert.equal(normalized.retryAfterSeconds, CEILING_SECONDS);
      // Failed for the same reason a queued limiter waiter is failed: it holds
      // no rate-limit token and has issued no request.
      assert.equal(console_.connections, 0);
    } finally {
      guard.release();
      await console_.close();
    }
  });

  test('the quietest shutdown raises no unhandled rejection', async () => {
    // The rejected-promise design for abandonment fails only when nothing is in
    // flight — the deployment nobody tests — because Node's default
    // `--unhandled-rejections=throw` would kill the process on the next tick.
    const observed: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      observed.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const config = configFor(UNCONTACTED_PORT);
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
      });
      // Zero requests: nothing has a handler attached anywhere.
      client.beginDrain();
      await client.close();
      await tick();
      await tick();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    assert.deepEqual(observed, []);
  });
});

describe('UnifiClient.close() — disposal (US-09)', () => {
  test('destroys every pooled agent, aborts the in-flight attempt, and is idempotent', async () => {
    const console_ = await startHangingConsole();
    const guard = stallGuard(5_000);
    try {
      const config = configFor(console_.port);
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
      });

      const outcome = outcomeOf(client.request(readAction()));
      await waitUntil(() => console_.connections === 1, 'the attempt to reach the socket');

      const agents = privateCollection(client, 'agents');
      const agent = onlyEntry(agents.values(), 'pooled agent');
      const socket = onlyEntry(pooledSockets(agent), 'pooled socket');
      assert.equal(socket.destroyed, false);

      // FR-70 step 4: beginDrain() must leave in-flight work alone, or the
      // drain truncates the very requests it promises to let finish.
      client.beginDrain();
      await tick();
      assert.equal(agents.size, 1, 'beginDrain() must not destroy pooled agents');
      assert.equal(socket.destroyed, false, 'beginDrain() must not abort an in-flight attempt');

      // The real Agent, with its real `destroy` still doing the work; the
      // wrapper only counts the call. `agent.destroy()` appears nowhere in
      // `src/` today, so a substitute here would assert nothing about the
      // reason the process cannot exit by natural drain.
      let destroyCalls = 0;
      const destroyForReal = agent.destroy.bind(agent);
      agent.destroy = (): void => {
        destroyCalls += 1;
        destroyForReal();
      };

      await assert.doesNotReject(client.close());

      assert.equal(client.isDraining, true, 'close() implies beginDrain()');
      assert.equal(destroyCalls, 1, 'every entry of the agents map must be destroyed');
      assert.equal(socket.destroyed, true, 'the pooled socket must not survive close()');
      assert.equal(agents.size, 0, 'the agents map must be cleared');

      const winner = await Promise.race([outcome.then(() => 'request' as const), guard.stalled]);
      assert.equal(winner, 'request');

      await assert.doesNotReject(client.close(), 'a second close() must be a no-op');
    } finally {
      guard.release();
      await console_.close();
    }
  });

  test('a drain-caused abort reports shutdown, not a 25s timeout that never elapsed', async () => {
    const console_ = await startHangingConsole();
    const guard = stallGuard(5_000);
    try {
      const config = configFor(console_.port);
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
      });

      const outcome = outcomeOf(client.request(readAction()));
      await waitUntil(() => console_.connections === 1, 'the attempt to reach the socket');

      await client.close();

      const winner = await Promise.race([outcome.then(() => 'settled' as const), guard.stalled]);
      assert.equal(winner, 'settled');

      const reason = await outcome;
      const normalized = shutdownErrorOf(reason);
      // The deadline did not elapse. Reporting it would be false to the caller
      // and to the log, and `timeout` is the wrong category to act on.
      assert.notEqual(normalized.category, 'timeout');
      assert.doesNotMatch(normalized.message, /abandoned after \d+s/);
      assert.equal(normalized.service, 'network');
      // The underlying abort survives as `cause`; UnifiError's constructor
      // takes only `normalized`, so it rides on the standard Error property.
      if (!(reason instanceof UnifiError)) return assert.fail('expected a UnifiError');
      assert.notEqual(reason.cause, undefined);
    } finally {
      guard.release();
      await console_.close();
    }
  });
});

describe('UnifiClient — unchanged behaviour when never drained (US-09 regression)', () => {
  test('the write gate still refuses, with its own message and category', async () => {
    const config = configFor(UNCONTACTED_PORT);
    const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
      warn: () => {},
    });

    const normalized = normalizedOf(await outcomeOf(client.request(writeAction())));

    assert.equal(normalized.category, 'config');
    assert.equal(
      normalized.message,
      'Action `network.test.write` is a POST (state-changing) operation and writes are not ' +
        'enabled for network.',
    );
    assert.match(normalized.recoveryHint, /UNIFI_ENABLE_WRITES=network/);
    assert.equal(client.isDraining, false);
  });

  test('a read still retries maxAttempts times with the same backoff arithmetic', async () => {
    const console_ = await startResettingConsole();
    try {
      // Default retry knobs: 3 attempts, 500 ms base, 8 000 ms ceiling.
      const config = configFor(console_.port);
      const waits: number[] = [];
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
        sleep: async (ms: number) => {
          waits.push(ms);
        },
      });

      const normalized = normalizedOf(await outcomeOf(client.request(readAction())));

      assert.equal(normalized.category, 'network');
      assert.equal(console_.connections, 3, 'three attempts, as UNIFI_RETRY_MAX_ATTEMPTS says');
      assert.equal(waits.length, 2, 'two backoffs between three attempts');
      // `backoffMs` is exponential with `0.5 + Math.random() / 2` jitter:
      // 500 ms then 1 000 ms, each halved at worst. US-09 may not move either.
      assert.ok(backoffAt(waits, 0) >= 250 && backoffAt(waits, 0) <= 500, 'first backoff');
      assert.ok(backoffAt(waits, 1) >= 500 && backoffAt(waits, 1) <= 1_000, 'second backoff');
      assert.equal(client.isDraining, false);
    } finally {
      await console_.close();
    }
  });

  test('a write is still never retried, however transient the failure', async () => {
    const console_ = await startResettingConsole();
    try {
      const config = configFor(console_.port, { UNIFI_ENABLE_WRITES: 'network' });
      const waits: number[] = [];
      const client = new UnifiClient(config, asCredentialStore(new StaticCredentials()), {
        warn: () => {},
        sleep: async (ms: number) => {
          waits.push(ms);
        },
      });

      const normalized = normalizedOf(await outcomeOf(client.request(writeAction())));

      assert.equal(normalized.category, 'network');
      assert.equal(console_.connections, 1, 'FR-26: a failed write is surfaced, never replayed');
      assert.deepEqual(waits, []);
    } finally {
      await console_.close();
    }
  });
});
