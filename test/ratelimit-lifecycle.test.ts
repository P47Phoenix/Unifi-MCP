/**
 * US-08 — the rate limiter's bounded lifecycle (FR-70 steps 3 and 4, NFR-27).
 *
 * Two things are asserted here, and they pull in opposite directions.
 *
 * The first is that `close()` actually drains: a waiter parked in `sleep` is
 * otherwise invisible and unwakeable for up to the full queue ceiling past the
 * shutdown signal, so every one of the three waiter states — not yet enqueued,
 * enqueued but not running, and running inside the sleep — must settle
 * immediately, with the existing structured `rate_limit` error and a numeric
 * `retryAfterSeconds`. The quiet-shutdown case is asserted explicitly because
 * the obvious implementation (a long-lived promise rejected at drain) fails
 * only when nothing is in flight, which is the deployment nobody tests.
 *
 * The second is that a limiter which is never closed behaves exactly as it did
 * before the affordance existed. The saturation-ceiling and FIFO regressions at
 * the bottom of this file are the guard on that: they pin the wait arithmetic,
 * the error text and the queue ordering, none of which US-08 is allowed to move.
 */
import { strict as assert } from 'node:assert';
import { test, describe } from 'node:test';

import { RateLimiter } from '../src/http/ratelimit.js';
import { UnifiError, type NormalizedError } from '../src/types.js';

/** Milliseconds a single-request-per-minute bucket makes a waiter wait. */
const ONE_PER_MINUTE_WAIT_MS = 60_000;
/** `Math.ceil(DEFAULT_MAX_WAIT_MS / 1000)` — the pre-check retry hint. */
const CEILING_SECONDS = 30;

/** Settle a promise into a value we can inspect, without ever leaving it floating. */
function outcomeOf(promise: Promise<void>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

function structuredRateLimitError(reason: unknown): NormalizedError {
  if (!(reason instanceof UnifiError)) {
    return assert.fail(`expected a UnifiError, got ${String(reason)}`);
  }
  // No new ErrorCategory member: shutdown reuses the existing rate_limit one.
  assert.equal(reason.normalized.category, 'rate_limit');
  assert.equal(
    typeof reason.normalized.retryAfterSeconds,
    'number',
    'retryAfterSeconds must be carried as a number, never null',
  );
  assert.notEqual(reason.normalized.recoveryHint, '');
  return reason.normalized;
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
function privateCollection(limiter: RateLimiter, name: 'pendingTimers'): ReadonlySet<unknown>;
function privateCollection(limiter: RateLimiter, name: 'buckets'): ReadonlyMap<string, unknown>;
function privateCollection(
  limiter: RateLimiter,
  name: string,
): ReadonlySet<unknown> | ReadonlyMap<string, unknown> {
  const value: unknown = Reflect.get(limiter, name);
  if (value instanceof Set || value instanceof Map) return value;
  return assert.fail(`expected private \`${name}\` to be a Set or Map`);
}

/** A sleep that records its waits and never resolves, so nothing settles by elapsing. */
function parkingSleep(): { sleep: (ms: number) => Promise<void>; waits: number[]; parked: Promise<void> } {
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

const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

describe('RateLimiter.close() — the contract (US-08)', () => {
  test('is synchronous, returns undefined, and a second call is a no-op', () => {
    const limiter = new RateLimiter({ now: () => 0, sleep: async () => {} });

    assert.equal(limiter.isClosed, false);
    assert.equal(limiter.close(), undefined);
    assert.equal(limiter.isClosed, true);

    assert.doesNotThrow(() => limiter.close());
    assert.equal(limiter.isClosed, true);
  });

  test('clears the buckets map and flips isClosed', async () => {
    const limiter = new RateLimiter({ now: () => 0, sleep: async () => {} });
    await limiter.acquire('network:local:10.0.0.1');
    assert.equal(privateCollection(limiter, 'buckets').size, 1);

    limiter.close();

    assert.equal(privateCollection(limiter, 'buckets').size, 0);
    assert.equal(limiter.isClosed, true);
  });
});

describe('RateLimiter.close() — the three waiter states (US-08)', () => {
  test('a waiter that never enqueued is rejected before any bucket is created', async () => {
    let nowCalls = 0;
    const limiter = new RateLimiter({
      now: () => {
        nowCalls += 1;
        return 0;
      },
      sleep: async () => assert.fail('a closed limiter must not sleep'),
    });

    limiter.close();
    const callsAtClose = nowCalls;

    const normalized = shutdownErrorOf(await outcomeOf(limiter.acquire('site-manager:v1')));

    assert.equal(normalized.service, 'site-manager');
    assert.equal(normalized.retryAfterSeconds, CEILING_SECONDS);
    // bucketFor() is the only caller of now() on this path, so an unchanged
    // count is proof the closed check ran before it and nothing was enqueued.
    assert.equal(nowCalls, callsAtClose);
    assert.equal(privateCollection(limiter, 'buckets').size, 0);
  });

  test('a waiter chained behind a parked predecessor is rejected when its turn comes', async () => {
    const { sleep, waits } = parkingSleep();
    const limiter = new RateLimiter({
      now: () => 0,
      sleep,
      defaultLimit: { requestsPerMinute: 1, maxWaitMs: 600_000 },
    });

    await limiter.acquire('protect:local:10.0.0.2'); // consumes the whole burst
    const parked = outcomeOf(limiter.acquire('protect:local:10.0.0.2'));
    const chained = outcomeOf(limiter.acquire('protect:local:10.0.0.2'));
    await tick();
    assert.deepEqual(waits, [ONE_PER_MINUTE_WAIT_MS], 'the predecessor must be parked in sleep');

    limiter.close();

    const normalized = shutdownErrorOf(await chained);
    assert.equal(normalized.service, 'protect');
    assert.equal(normalized.retryAfterSeconds, CEILING_SECONDS);
    shutdownErrorOf(await parked);
    // The chained waiter never reached the wait computation.
    assert.deepEqual(waits, [ONE_PER_MINUTE_WAIT_MS]);
  });

  test('C20 — an in-progress wait is abandoned rather than awaited', async () => {
    const { sleep, waits, parked } = parkingSleep();
    const limiter = new RateLimiter({
      now: () => 0,
      sleep,
      defaultLimit: { requestsPerMinute: 1, maxWaitMs: 600_000 },
    });

    await limiter.acquire('mobility:cloud');
    const waiting = outcomeOf(limiter.acquire('mobility:cloud'));
    await tick();
    assert.deepEqual(waits, [ONE_PER_MINUTE_WAIT_MS], 'the waiter must be inside the sleep');

    limiter.close();

    // The injected sleep never resolves, so a pass here can only mean the wait
    // was abandoned — not that it ran to completion.
    const winner = await Promise.race([
      waiting.then(() => 'acquire' as const),
      parked.then(() => 'sleep' as const),
    ]);
    assert.equal(winner, 'acquire');

    const normalized = shutdownErrorOf(await waiting);
    assert.equal(normalized.service, 'mobility');
    // Carried unchanged from the wait this waiter had already computed.
    assert.equal(normalized.retryAfterSeconds, ONE_PER_MINUTE_WAIT_MS / 1000);
  });
});

describe('RateLimiter.close() — drain behaviour (US-08)', () => {
  test('C22 — ten queued waiters all fail immediately rather than extending the drain', async () => {
    const { sleep, waits } = parkingSleep();
    const limiter = new RateLimiter({
      now: () => 0,
      sleep,
      defaultLimit: { requestsPerMinute: 1, maxWaitMs: 600_000 },
    });

    await limiter.acquire('network:local:10.0.0.3'); // consumes the whole burst
    const queued = Array.from({ length: 10 }, () => limiter.acquire('network:local:10.0.0.3'));
    const settled = Promise.allSettled(queued);
    await tick();
    assert.deepEqual(waits, [ONE_PER_MINUTE_WAIT_MS], 'the head of the queue must be parked');

    limiter.close();

    const outcomes = await settled;
    assert.equal(outcomes.length, 10);
    for (const outcome of outcomes) {
      if (outcome.status !== 'rejected') assert.fail('every queued waiter must reject');
      const normalized = shutdownErrorOf(outcome.reason);
      assert.equal(normalized.category, 'rate_limit');
      assert.equal(normalized.service, 'network');
      assert.equal(typeof normalized.retryAfterSeconds, 'number');
      assert.ok((normalized.retryAfterSeconds ?? 0) > 0);
    }
    // Nothing settled by elapsing: the injected sleep never resolves at all.
    assert.deepEqual(waits, [ONE_PER_MINUTE_WAIT_MS]);
  });

  test('releases the real timer instead of leaving it to elapse', async () => {
    // The default sleep, deliberately not injected: this is the timer half.
    const limiter = new RateLimiter({
      now: () => 0,
      limits: { 'site-manager:v1': { requestsPerMinute: 12, maxWaitMs: 30_000 } },
    });
    const timers = privateCollection(limiter, 'pendingTimers');

    await Promise.all(Array.from({ length: 12 }, () => limiter.acquire('site-manager:v1')));
    assert.equal(timers.size, 0, 'the burst must not create timers');

    const waiting = outcomeOf(limiter.acquire('site-manager:v1'));
    await tick();
    assert.equal(timers.size, 1, 'the waiter must hold a real timer');

    const startedAt = Date.now();
    limiter.close();
    const normalized = shutdownErrorOf(await waiting);
    const elapsedMs = Date.now() - startedAt;

    // The wait was 5 000 ms. Anything near that means the timer elapsed.
    assert.ok(elapsedMs < 1_000, `rejection took ${elapsedMs}ms; the timer was not released`);
    assert.equal(normalized.retryAfterSeconds, 5);
    assert.equal(timers.size, 0, 'close() must clear the handle, not merely stop awaiting it');
  });

  test('the quietest shutdown raises no unhandled rejection', async () => {
    const observed: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      observed.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const limiter = new RateLimiter({ now: () => 0, sleep: async () => {} });
      // Zero acquisitions: the case where a rejected-promise signal would have
      // no handler attached at the moment of rejection.
      limiter.close();
      await tick();
      await tick();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    assert.deepEqual(observed, []);
  });

  test('a shutdown after every acquisition completed raises no unhandled rejection', async () => {
    const observed: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      observed.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const limiter = new RateLimiter({
        now: () => 0,
        sleep: async () => {},
        defaultLimit: { requestsPerMinute: 5 },
      });
      for (let i = 0; i < 5; i += 1) await limiter.acquire('site-manager:ea');
      limiter.close();
      await tick();
      await tick();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    assert.deepEqual(observed, []);
  });
});

describe('RateLimiter — unchanged behaviour when never closed (US-08 regression)', () => {
  test('still throws the saturation-ceiling error verbatim', async () => {
    const limiter = new RateLimiter({
      now: () => 0,
      sleep: async () => assert.fail('a saturated bucket must refuse rather than wait'),
      limits: { 'site-manager:v1': { requestsPerMinute: 1 } },
    });

    await limiter.acquire('site-manager:v1');
    const normalized = structuredRateLimitError(await outcomeOf(limiter.acquire('site-manager:v1')));

    assert.equal(normalized.service, 'site-manager');
    assert.equal(normalized.httpStatus, null);
    assert.equal(normalized.upstreamCode, null);
    assert.equal(normalized.correlationId, null);
    assert.equal(normalized.origin, null);
    assert.equal(normalized.retryAfterSeconds, 60);
    assert.equal(
      normalized.message,
      'Client-side rate limit for `site-manager:v1` is saturated: the next slot is 60s away, ' +
        'beyond the 30s queue ceiling. The request was not sent — refusing here is cheaper than ' +
        'an upstream 429.',
    );
    assert.equal(
      normalized.recoveryHint,
      'Retry in 60s, or reduce concurrency. The bucket allows 1 requests/minute; raise it with ' +
        'the matching UNIFI_RATE_LIMIT_* environment variable only if the upstream limit ' +
        'genuinely permits it.',
    );
    assert.equal(limiter.isClosed, false);
  });

  test('still spends the burst before waiting, and waits one slot when it is gone', async () => {
    const waits: number[] = [];
    const limiter = new RateLimiter({
      now: () => 0,
      sleep: async (ms: number) => {
        waits.push(ms);
      },
      defaultLimit: { requestsPerMinute: 5 },
    });

    for (let i = 0; i < 5; i += 1) await limiter.acquire('mobility:cloud');
    assert.deepEqual(waits, [], 'a cold bucket allows one minute of burst');

    await limiter.acquire('mobility:cloud');
    assert.deepEqual(waits, [12_000], '5 req/min is one slot every 12s');
  });

  test('still serves the queue FIFO, one slot apart', async () => {
    let clock = 0;
    const completions: number[] = [];
    // Slot boundaries, sampled where they are unambiguous: the clock each
    // waiter saw when it began its own wait.
    const slotStarts: number[] = [];
    const waits: number[] = [];
    const limiter = new RateLimiter({
      now: () => clock,
      sleep: async (ms: number) => {
        slotStarts.push(clock);
        waits.push(ms);
        clock += ms;
      },
      defaultLimit: { requestsPerMinute: 1, maxWaitMs: 600_000 },
    });

    await Promise.all(
      [0, 1, 2].map(async (index) => {
        await limiter.acquire('network:cloud');
        completions.push(index);
      }),
    );

    assert.deepEqual(completions, [0, 1, 2], 'the tail chain must preserve arrival order');
    // Each waiter sees the state its predecessor left, so they spread across
    // three slots instead of all computing the same short delay.
    assert.deepEqual(slotStarts, [0, ONE_PER_MINUTE_WAIT_MS]);
    assert.deepEqual(waits, [ONE_PER_MINUTE_WAIT_MS, ONE_PER_MINUTE_WAIT_MS]);
    assert.equal(clock, 2 * ONE_PER_MINUTE_WAIT_MS);
  });
});
