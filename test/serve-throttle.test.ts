/**
 * US-27 — the rejection throttle: its single emission site, its rolling window
 * and its memory bound.
 *
 * Suite C's C30, and Suite B's B25/B26 taken up one level to the pipeline.
 *
 * ## The three questions this file asks that a primitive test cannot
 *
 * US-10 proves `createRejectionThrottle` in isolation: the boundary is N/N+1,
 * the window moves on an injected clock, the table evicts least-recent-use. All
 * true, and all of it survives a pipeline that wires the primitive wrongly.
 *
 *   1. **Is the counter at ONE place?** FR-81's whole value turns on this. If
 *      the increment sits inside the authentication routine instead of at the
 *      uniform-401 emission site, the throttle becomes a path-enumeration
 *      oracle: N+1 garbage-token requests to a candidate path answer 429 when
 *      the path is real and 401 when it is not — one bit per minute per source,
 *      parallelisable across a /64, recovering exactly the fact the uniform
 *      rejection exists to hide. A test that only checks "the counter reads N
 *      after N mixed rejections" does NOT settle this: a scattered
 *      implementation incrementing twice in one place and never in another sums
 *      to the same N. §1 therefore asks per class, from a fresh listener, and
 *      reads the CALL STACK at the increment.
 *
 *   2. **Does the pipeline's own throttle carry the memory bound?** §4 drives
 *      ten times the table's capacity of distinct sources through the exact
 *      object the request path holds, obtained through the pipeline's own
 *      factory seam — not through a fresh one built with test-chosen options.
 *      And it does the same for the OTHER two per-source maps in the request
 *      path, because bounding one of three is not a memory bound.
 *
 *   3. **Does the window move without anyone waiting?** No test in this suite
 *      waits on real multi-second time. The rolling minute is driven by the
 *      clock injected at `ServingDeps.now`, over a real socket.
 *
 * The socket helper is a local copy for the reason named in
 * `test/serve-normalizer.test.ts`'s header: `test/harness/` is another story's
 * file scope this round.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer as createNodeHttpServer } from 'node:http';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  createRejectionThrottle,
  THROTTLE_DEFAULT_CAPACITY,
  THROTTLE_WINDOW_MS,
  type RejectionThrottle,
  type RejectionThrottleOptions,
} from '../src/serve/guard.js';
import { startHttp, type HttpServing, type HttpServingDeps } from '../src/serve/http.js';
import { createDiagnosticLogger, MAX_TRACKED_THROTTLED_CLIENTS } from '../src/serve/log.js';
import { buildRuntimeCore } from '../src/serve/runtime.js';

import { createInstruments, type Instruments } from './harness/counters.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HTTP_SOURCE = join(REPO_ROOT, 'src', 'serve', 'http.ts');

const SECRET = `s${'u'.repeat(39)}`;
const WRONG_SECRET = `w${'x'.repeat(39)}`;
const ALLOWED_HOST = 'allowed.example';
const REJECTED_HOST = 'not-allowed.example';
const KUBELET_HOST = '10.42.0.7:8787';

/** The loopback source key every request in this file is attributed to. */
const LOOPBACK_KEY = '127.0.0.1';

const UNIFORM_401_WIRE =
  'HTTP/1.1 401 Unauthorized\r\n' +
  'Content-Type: application/json\r\n' +
  'Content-Length: 24\r\n' +
  'WWW-Authenticate: Bearer\r\n' +
  'Cache-Control: no-store\r\n' +
  'X-Content-Type-Options: nosniff\r\n' +
  'Connection: close\r\n' +
  '\r\n' +
  '{"error":"unauthorized"}';

/** Contract §5.10.1. No `Retry-After`, no `WWW-Authenticate`. */
const THROTTLED_429_WIRE =
  'HTTP/1.1 429 Too Many Requests\r\n' +
  'Content-Type: application/json\r\n' +
  'Content-Length: 22\r\n' +
  'Cache-Control: no-store\r\n' +
  'X-Content-Type-Options: nosniff\r\n' +
  'Connection: close\r\n' +
  '\r\n' +
  '{"error":"rate_limit"}';

function httpEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST,
    UNIFI_HTTP_MAX_BODY_BYTES: '4096',
    UNIFI_HTTP_MAX_CONNECTIONS: '512',
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** One `record` call, as the pipeline made it. */
interface RecordCall {
  readonly key: string;
  /** The stack, so the CALL SITE can be asserted rather than only the count. */
  readonly stack: string;
}

interface Bound {
  readonly serving: HttpServing;
  readonly port: number;
  readonly instruments: Instruments;
  /** Every `record` the pipeline made, in order. */
  readonly records: RecordCall[];
  /** The throttle instance the request path is actually holding. */
  throttle(): RejectionThrottle;
  /** The options the pipeline handed the factory. */
  options(): RejectionThrottleOptions;
}

async function boundServer(
  t: TestContext,
  env: Record<string, string> = httpEnv(),
  deps: HttpServingDeps = {},
): Promise<Bound> {
  const instruments = createInstruments({ env: { ...env }, keychain: null });
  const core = buildRuntimeCore(instruments.deps);
  const records: RecordCall[] = [];
  let inner: RejectionThrottle | null = null;
  let seenOptions: RejectionThrottleOptions | null = null;

  const serving = await startHttp(core, instruments.observer, {
    warn: () => {},
    createHttpServer: (options, handler) => createNodeHttpServer(options, handler),
    createThrottle: (options) => {
      seenOptions = options;
      // The PRODUCTION throttle behind the counter, so what the pipeline uses
      // is the real object — the memory-bound assertions in §4 read it back out
      // rather than building a second one with test-chosen options.
      const real = createRejectionThrottle(options);
      inner = real;
      return {
        isThrottled: (key) => real.isThrottled(key),
        record: (key) => {
          records.push({ key, stack: new Error('record').stack ?? '' });
          real.record(key);
        },
        size: () => real.size(),
      };
    },
    ...deps,
  });

  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  await core.ready;
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  return {
    serving,
    port: serving.address.port,
    instruments,
    records,
    throttle: () => {
      assert.ok(inner !== null, 'the throttle factory seam was never used');
      return inner as unknown as RejectionThrottle;
    },
    options: () => {
      assert.ok(seenOptions !== null, 'the throttle factory seam was never used');
      return seenOptions as unknown as RejectionThrottleOptions;
    },
  };
}

interface Captured {
  readonly text: string;
  readonly closedByServer: boolean;
}

function exchange(port: number, request: string, idleMs = 250): Promise<Captured> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let closedByServer = false;
    let settled = false;
    let idle: NodeJS.Timeout | null = null;
    const socket = connect({ host: '127.0.0.1', port });

    const settle = (): void => {
      if (settled) return;
      settled = true;
      if (idle !== null) clearTimeout(idle);
      socket.destroy();
      resolve({ text: Buffer.concat(chunks).toString('latin1'), closedByServer });
    };
    const bump = (): void => {
      if (idle !== null) clearTimeout(idle);
      idle = setTimeout(settle, idleMs);
    };

    socket.on('connect', () => {
      socket.write(Buffer.from(request, 'latin1'));
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
      closedByServer = closedByServer || error.code === 'ECONNRESET';
    });
    socket.on('close', settle);
  });
}

function raw(startLine: string, headers: readonly string[], body = ''): string {
  return `${[startLine, ...headers, 'Connection: close'].join('\r\n')}\r\n\r\n${body}`;
}

function statusLine(captured: Captured): string {
  return captured.text.split('\r\n')[0] ?? '';
}

/**
 * The five rejection KINDS the criterion names, each reachable by an
 * unauthenticated caller and each answered by the same uniform 401.
 *
 * Only one of them is an authentication failure. That is the whole point: an
 * implementation counting authentication failures reads 1 where this reads 5.
 */
const MIXED_CLASSES: ReadonlyArray<readonly [string, string]> = [
  [
    'wrong secret',
    raw('POST /mcp HTTP/1.1', [
      `Host: ${ALLOWED_HOST}`,
      `Authorization: Bearer ${WRONG_SECRET}`,
      'Content-Length: 0',
    ]),
  ],
  ['disallowed Host', raw('POST /mcp HTTP/1.1', [`Host: ${REJECTED_HOST}`, 'Content-Length: 0'])],
  [
    'any Origin',
    raw('POST /mcp HTTP/1.1', [
      `Host: ${ALLOWED_HOST}`,
      'Origin: https://evil.example',
      'Content-Length: 0',
    ]),
  ],
  ['unknown path', raw('POST /no-such-path HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0'])],
  [
    'over-cap body',
    raw(
      'POST /mcp HTTP/1.1',
      [`Host: ${ALLOWED_HOST}`, 'Content-Type: application/json', 'Content-Length: 8192'],
      'A'.repeat(8192),
    ),
  ],
];

const PROBE_REQUEST = raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]);

// ---------------------------------------------------------------------------
// 1. One emission site (AC 7)
// ---------------------------------------------------------------------------

describe('US-27 §1: the counter sits at the single uniform-401 emission site', () => {
  test('AC 7: the source holds exactly one record and one isThrottled call, both inside rejectUnauthenticated', () => {
    const source = readFileSync(HTTP_SOURCE, 'utf8');

    const records = source.match(/\bthrottle\.record\s*\(/g) ?? [];
    const lookups = source.match(/\bthrottle\.isThrottled\s*\(/g) ?? [];
    assert.equal(
      records.length,
      1,
      `the throttle is incremented at ${records.length} places; a scattered counter sums to the ` +
        `same N as a correct one and is what makes the throttle a path-enumeration oracle`,
    );
    assert.equal(lookups.length, 1, `the throttle is consulted at ${lookups.length} places`);

    // …and that one place is the uniform-401 emitter, not the authentication
    // routine. Bounded by the next function declaration at the same nesting.
    const start = source.indexOf('function rejectUnauthenticated(');
    assert.notEqual(start, -1, 'the single emission site is no longer named rejectUnauthenticated');
    // Bounded by the next declaration at the same nesting. If this function is
    // the last one, the slice runs to the end of the file — which would weaken
    // the containment claim, so that case is refused rather than tolerated.
    const end = source.indexOf('\n  function ', start + 1);
    assert.notEqual(
      end,
      -1,
      'rejectUnauthenticated is now the last function in the module, so this scan can no longer ' +
        'bound its body; re-establish the boundary rather than widening the slice',
    );
    const body = source.slice(start, end);

    assert.match(body, /\bthrottle\.record\s*\(/);
    assert.match(body, /\bthrottle\.isThrottled\s*\(/);
    // Order matters: `record` THEN `isThrottled`, so the request that crosses
    // the threshold is itself throttled rather than the one after it.
    assert.ok(
      body.indexOf('throttle.record(') < body.indexOf('throttle.isThrottled('),
      'the throttle is consulted before the rejection is counted',
    );
  });

  test('AC 7: every rejection KIND increments exactly once, measured one kind at a time', async (t) => {
    // The disambiguating experiment. A sum of five over a mixed run is
    // satisfied by an implementation that counts a wrong secret twice and a
    // disallowed Host not at all — which is exactly the shape that makes the
    // throttle leak whether a path exists.
    for (const [label, request] of MIXED_CLASSES) {
      const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: '1000' }));
      const result = await exchange(bound.port, request);

      assert.equal(result.text, UNIFORM_401_WIRE, `${label} was not the uniform 401`);
      assert.equal(bound.records.length, 1, `${label} incremented ${bound.records.length} times`);
      // Keyed on the real peer address, never on a header.
      assert.equal(bound.records[0]?.key, LOOPBACK_KEY, `${label} was attributed to the wrong key`);
    }
  });

  test('AC 7: the increment is reached from rejectUnauthenticated, read off the call stack', async (t) => {
    // A source scan proves the text; this proves the RUNTIME path, and survives
    // reformatting, renaming of the local `throttle` binding, and a helper
    // introduced between the emitter and the call.
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: '1000' }));

    for (const [, request] of MIXED_CLASSES) await exchange(bound.port, request);

    assert.equal(bound.records.length, MIXED_CLASSES.length);
    for (const call of bound.records) {
      // Frame 0 is the counting wrapper in THIS file; the first frame outside
      // it is the production call site.
      const frames = call.stack
        .split('\n')
        .slice(1)
        .filter((frame) => !frame.includes('serve-throttle.test.ts'));
      const callSite = frames[0] ?? '';
      assert.match(
        callSite,
        /at rejectUnauthenticated \(/,
        `the throttle was incremented from ${callSite.trim()}, not from the uniform-401 emitter`,
      );
      assert.match(callSite, /src[\\/]serve[\\/]http\.ts/, 'the increment left the transport module');
    }
  });

  test('AC 7: N mixed rejections read N — one of the five is an authentication failure', async (t) => {
    const limit = MIXED_CLASSES.length;
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: String(limit) }));

    for (const [label, request] of MIXED_CLASSES) {
      const result = await exchange(bound.port, request);
      assert.equal(result.text, UNIFORM_401_WIRE, label);
    }
    assert.equal(bound.records.length, limit, 'the counter did not increment once per uniform 401');
    assert.equal(new Set(bound.records.map((call) => call.key)).size, 1, 'one source, one key');
  });
});

// ---------------------------------------------------------------------------
// 2. N+1, the probe exemption and the credential holder (AC 5)
// ---------------------------------------------------------------------------

describe('US-27 §2: crossing the threshold', () => {
  const limit = MIXED_CLASSES.length;
  const env = httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: String(limit) });

  test('AC 5: the N+1th unauthenticated request is 429, byte for byte', async (t) => {
    const bound = await boundServer(t, env);

    for (const [, request] of MIXED_CLASSES) {
      assert.equal((await exchange(bound.port, request)).text, UNIFORM_401_WIRE);
    }

    const throttled = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    // NO `Retry-After`: its only well-behaved beneficiary is a client that
    // trips the throttle, and a client holding the correct secret never does.
    // NO `WWW-Authenticate`: a 429 is not an invitation to retry with a
    // credential. Pinned as whole bytes so neither can be added quietly.
    assert.equal(throttled.text, THROTTLED_429_WIRE);
    assert.equal(throttled.closedByServer, true);

    // The 429 is the same response whichever class provoked it, so the throttle
    // does not reintroduce the differential the 401 removed.
    for (const [label, request] of MIXED_CLASSES) {
      const again = await exchange(bound.port, request);
      assert.equal(again.text, THROTTLED_429_WIRE, `the 429 after ${label} differed`);
    }
  });

  test('AC 5: a probe from the throttled key is still served, and is never counted', async (t) => {
    const bound = await boundServer(t, env);

    for (const [, request] of MIXED_CLASSES) await exchange(bound.port, request);
    const recordsAtThreshold = bound.records.length;
    assert.match(
      statusLine(
        await exchange(bound.port, raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0'])),
      ),
      /^HTTP\/1\.1 429 /,
      'the key is not actually throttled, so the probe assertion below would be vacuous',
    );

    // A 429 IS a probe failure, and `failureThreshold` consecutive failures
    // restart the container — the rate limiter would restart the service it
    // protects. In Kubernetes the kubelet probes from the NODE address, so
    // anything NAT'd to that node tripping the throttle is enough.
    for (let index = 0; index < 10; index += 1) {
      const probe = await exchange(bound.port, PROBE_REQUEST);
      assert.match(statusLine(probe), /^HTTP\/1\.1 200 /, 'a probe was throttled');
    }
    assert.equal(
      bound.records.length,
      recordsAtThreshold + 1,
      'a probe incremented the rejection counter',
    );
    // Neither counted NOR looked up: an unauthenticated lookup that allocated
    // would make the memory bound depend on the caller's choice of key.
    const fresh = await boundServer(t, env);
    for (let index = 0; index < 20; index += 1) await exchange(fresh.port, PROBE_REQUEST);
    assert.equal(fresh.records.length, 0);
    assert.equal(fresh.throttle().size(), 0, 'a probe allocated an entry in the throttle table');
  });

  test('AC 5: a valid secret from the throttled key is served — and does NOT clear the window', async (t) => {
    const bound = await boundServer(t, env);

    for (const [, request] of MIXED_CLASSES) await exchange(bound.port, request);

    // The throttle gates the RESPONSE, not the work, and it is consulted only
    // inside the uniform-401 emitter — so a caller presenting a valid secret
    // never reaches it. Under the other ordering one stranger behind a shared
    // reverse proxy locks out the only legitimate client for the rest of every
    // rolling minute, because `remoteAddress` is the proxy's address for the
    // whole caller population.
    const holder = await exchange(
      bound.port,
      raw('POST /nope HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(holder), /^HTTP\/1\.1 404 /, 'a credential holder was throttled');
    assert.equal(bound.records.length, MIXED_CLASSES.length, 'a served request was counted');

    // PINNED DELIBERATELY, because the natural reading of the criterion is that
    // presenting a good credential CLEARS the key. It does not, and it should
    // not: clearing on success would let an attacker who has learned any valid
    // credential — or who shares a source key with someone who has — reset the
    // window at will and brute-force the OTHER slot without limit. The window
    // expires on time alone (§3).
    const stillThrottled = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    assert.equal(stillThrottled.text, THROTTLED_429_WIRE);
  });
});

// ---------------------------------------------------------------------------
// 3. The rolling minute, on an injected clock (AC 5)
// ---------------------------------------------------------------------------

describe('US-27 §3: the window moves on the injected clock and on nothing else', () => {
  test('59 999 ms is still throttled; 60 001 ms is a fresh window — no test waits a minute', async (t) => {
    const limit = 3;
    // Started well away from zero so a naive `now - start` cannot pass by
    // accident on an uninitialised window.
    let clock = 1_700_000_000_000;
    const bound = await boundServer(
      t,
      httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: String(limit) }),
      { now: () => clock },
    );

    const anonymous = raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']);

    for (let index = 0; index < limit; index += 1) {
      assert.equal((await exchange(bound.port, anonymous)).text, UNIFORM_401_WIRE, `request ${index}`);
    }
    assert.equal((await exchange(bound.port, anonymous)).text, THROTTLED_429_WIRE, 'the N+1th');

    // One millisecond short of the window. Wall-clock time has advanced by a
    // few milliseconds in real terms and changes nothing, which is the property
    // being asserted: the window is the injected clock's, not the runner's.
    clock += THROTTLE_WINDOW_MS - 1;
    assert.equal((await exchange(bound.port, anonymous)).text, THROTTLED_429_WIRE, 'at 59 999 ms');

    clock += 2;
    assert.equal((await exchange(bound.port, anonymous)).text, UNIFORM_401_WIRE, 'at 60 001 ms');

    // …and the fresh window counts from one again rather than resuming.
    for (let index = 1; index < limit; index += 1) {
      assert.equal((await exchange(bound.port, anonymous)).text, UNIFORM_401_WIRE, `fresh ${index}`);
    }
    assert.equal((await exchange(bound.port, anonymous)).text, THROTTLED_429_WIRE, 'fresh N+1th');
  });

  test('one throttled source emits ONE log line, not one per throttled request', async (t) => {
    // The log is an output channel with the same flooding problem the throttle
    // exists to bound: an attacker at 10 000 req/s still produces 10 000
    // lines/s if every 429 is logged, and the throttle contributes nothing.
    const limit = 2;
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: String(limit) }));
    const anonymous = raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']);

    for (let index = 0; index < limit; index += 1) await exchange(bound.port, anonymous);
    const before = bound.instruments.counts.requestLogs.length;

    for (let index = 0; index < 12; index += 1) {
      assert.equal((await exchange(bound.port, anonymous)).text, THROTTLED_429_WIRE);
    }
    const emitted = bound.instruments.counts.requestLogs.slice(before);
    assert.equal(emitted.length, 1, `twelve throttled requests emitted ${emitted.length} lines`);
    assert.match(emitted[0] as string, /\bstatus=429\b/);
    assert.match(emitted[0] as string, /\breject_reason=rate_limit\b/);
  });
});

// ---------------------------------------------------------------------------
// 4. The memory bound (AC 6)
// ---------------------------------------------------------------------------

describe('US-27 §4: no per-source table an unauthenticated caller can grow is unbounded', () => {
  test('AC 6: the pipeline takes the default capacity — it does not pass one of its own', async (t) => {
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: '7' }));

    const options = bound.options();
    assert.equal(options.maxPerMinute, 7, 'the configured threshold did not reach the factory');
    // Left undefined ON PURPOSE, so `THROTTLE_DEFAULT_CAPACITY` is the value in
    // force and there is exactly one number to review. A pipeline that passed
    // its own capacity would put the memory bound somewhere no requirement
    // names.
    assert.equal(options.capacity, undefined);
    assert.equal(THROTTLE_DEFAULT_CAPACITY, 4096);
    // The clock is the pipeline's, so the window cannot silently be wall time
    // in production and injected only in tests.
    assert.equal(typeof options.now, 'function');
  });

  test('AC 6: ten times capacity of distinct sources leaves the table exactly at capacity', async (t) => {
    // Driven through the object the REQUEST PATH holds, obtained from the
    // pipeline's own factory seam — not a second throttle built here with
    // test-chosen options, which would prove the primitive again rather than
    // the wiring.
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_AUTH_FAIL_PER_MIN: '1' }));
    const throttle = bound.throttle();
    const capacity = THROTTLE_DEFAULT_CAPACITY;

    // `maxPerMinute: 1` makes membership directly observable: two records put a
    // key over the threshold, so `isThrottled` is a present/absent test.
    const key = (index: number): string => `198.51.100.${index}`;
    const remember = (index: number): void => {
      throttle.record(key(index));
      throttle.record(key(index));
    };

    for (let index = 0; index < capacity; index += 1) remember(index);
    assert.equal(throttle.size(), capacity);
    assert.equal(throttle.isThrottled(key(0)), true);
    assert.equal(throttle.isThrottled(key(capacity - 1)), true);

    // Eviction is LEAST-RECENTLY-USED: the next distinct source takes the
    // oldest slot.
    remember(capacity);
    assert.equal(throttle.size(), capacity, 'the table grew past its capacity');
    assert.equal(throttle.isThrottled(key(0)), false, 'eviction did not take the oldest key');
    assert.equal(throttle.isThrottled(key(1)), true);

    // …and recording a key REFRESHES its position, so an active offender is not
    // evicted by a flood of one-shot sources arriving behind them.
    throttle.record(key(1));
    remember(capacity + 1);
    remember(capacity + 2);
    assert.equal(throttle.isThrottled(key(1)), true, 'a refreshed key was still evicted');
    assert.equal(throttle.isThrottled(key(2)), false);
    assert.equal(throttle.isThrottled(key(3)), false);

    // The flood proper: ten times capacity of distinct sources, which is what
    // an attacker with a delegated /64 or a botnet actually has. The table must
    // not grow by one entry.
    const flood = capacity * 10;
    for (let index = 0; index < flood; index += 1) {
      throttle.record(`203.0.113.${index % 256}.${Math.floor(index / 256)}`);
      if (index % capacity === 0) {
        assert.ok(
          throttle.size() <= capacity,
          `the table reached ${throttle.size()} entries at flood step ${index}`,
        );
      }
    }
    assert.equal(throttle.size(), capacity, 'the table did not settle back at exactly capacity');

    // The listener is still serving after all of that.
    const result = await exchange(
      bound.port,
      raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]),
    );
    assert.match(statusLine(result), /^HTTP\/1\.1 200 /);
  });

  test('AC 6: the log suppression tracker is bounded too, and evicts oldest-first', () => {
    // THE SECOND per-source map in the request path. Bounding the throttle and
    // leaving this one unbounded would move the memory-exhaustion vector rather
    // than close it: it is keyed on the same attacker-chosen source address and
    // is written on exactly the requests the throttle is counting.
    //
    // Nothing in `test/serve-log.test.ts` exercises this bound today, so this
    // is its only coverage.
    const lines: string[] = [];
    const logger = createDiagnosticLogger({ write: (line) => lines.push(line) });
    const throttledLine = (client: string): boolean =>
      logger.logRequest({
        method: 'POST',
        route: 'mcp',
        status: 429,
        durationMs: 0,
        auth: 'rejected',
        rejectReason: 'rate_limit',
        writes: [],
        client,
      });

    const first = '192.0.2.1';
    assert.equal(throttledLine(first), true, 'the state entry was not logged');
    assert.equal(throttledLine(first), false, 'a second throttled request from one source logged again');

    // Fill past the ceiling with distinct sources.
    for (let index = 0; index < MAX_TRACKED_THROTTLED_CLIENTS; index += 1) {
      throttledLine(`198.18.${Math.floor(index / 256)}.${index % 256}`);
    }

    // The first source has been evicted, which is the observable form of "the
    // map did not grow". The cost of the bound is stated rather than hidden: a
    // long-lived offender behind a flood of fresh sources gets a second state
    // line, which is a duplicate log entry — not a duplicate 429.
    assert.equal(
      throttledLine(first),
      true,
      'the tracker never evicted, so it grows with the number of distinct sources',
    );
  });

  test('AC 6: the probe connection headroom is per-source and fixed, so it cannot be grown either', async (t) => {
    // THE THIRD per-source map: `headroomBySource` in the connection ledger.
    // Bounded by construction at `PROBE_CONNECTION_HEADROOM` entries, because a
    // key is inserted only when a connection is admitted INTO the headroom and
    // deleted on that socket's close.
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_MAX_CONNECTIONS: '2' }));
    const open: Array<ReturnType<typeof connect>> = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    const hold = (): Promise<void> =>
      new Promise((resolve, reject) => {
        const socket = connect({ host: '127.0.0.1', port: bound.port });
        open.push(socket);
        socket.once('connect', () => resolve());
        socket.once('error', reject);
      });

    for (let index = 0; index < 12; index += 1) await hold();
    await new Promise((resolve) => setTimeout(resolve, 100));

    const counts = bound.serving.connectionCounts();
    assert.ok(counts.headroom <= 1, `one source key claimed ${counts.headroom} headroom slots`);
    assert.ok(counts.total <= 3, `the ledger admitted ${counts.total} connections against a cap of 2 + 8`);
  });
});
