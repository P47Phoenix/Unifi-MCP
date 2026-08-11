/**
 * Request-guard tests (QA cases B1-B8, B11-B15, B17, B18, B20-B22, B24-B27).
 *
 * Every predicate under test is pure, so no test in this file opens a socket,
 * sleeps, or reads the wall clock. The throttle takes an injected clock for
 * exactly that reason.
 */
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { IncomingHttpHeaders } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import {
  bearerMatches,
  createRejectionThrottle,
  createRouteNormalizer,
  hasOrigin,
  hostAllowed,
  isLoopbackBind,
  sourceKey,
  THROTTLE_DEFAULT_CAPACITY,
  THROTTLE_WINDOW_MS,
  type NonEmptySlots,
  type Route,
} from '../src/serve/guard.js';
import { isLoopbackBind as isLoopbackBindFromLeaf } from '../src/netliteral.js';
import { bearerMatches as bearerMatchesFromAuth } from '../src/serve/auth.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Long enough to be a real secret under the configured 32-character minimum. */
const CORRECT_SECRET = 'correct-horse-battery-staple-0123456789';

const ALL_ROUTES: readonly Route[] = ['mcp', 'healthz', 'readyz', 'other'];

function digestOf(secret: string): Buffer {
  return createHash('sha256').update(secret, 'utf8').digest();
}

function slotsFor(...secrets: readonly string[]): NonEmptySlots {
  const [first, ...rest] = secrets.map(digestOf);
  if (first === undefined) throw new Error('slotsFor needs at least one secret');
  return [first, ...rest];
}

interface CompareCall {
  readonly presentedLength: number;
  readonly slotLength: number;
}

interface CompareSpy {
  readonly calls: CompareCall[];
  readonly fn: (a: Buffer, b: Buffer) => boolean;
}

/**
 * The injected comparator exists because Node 20 has no `mock.module`, so a
 * default parameter is the only way to observe how the real function is called.
 */
function createCompareSpy(): CompareSpy {
  const calls: CompareCall[] = [];
  return {
    calls,
    fn(a: Buffer, b: Buffer): boolean {
      calls.push({ presentedLength: a.length, slotLength: b.length });
      return a.equals(b);
    },
  };
}

describe('bearer comparison', () => {
  test('B1: a wrong secret does not match', () => {
    const slots = slotsFor(CORRECT_SECRET);
    assert.equal(bearerMatches(`Bearer ${CORRECT_SECRET}`, slots), true);
    assert.equal(bearerMatches('Bearer wrong-secret-that-is-also-long-enough-x', slots), false);
  });

  test('B2: a missing header is rejected before any hashing happens', () => {
    const slots = slotsFor(CORRECT_SECRET);
    const spy = createCompareSpy();
    assert.equal(bearerMatches(undefined, slots, spy.fn), false);
    assert.equal(spy.calls.length, 0);
  });

  test('B2: a non-string header value is rejected before any hashing happens', () => {
    const slots = slotsFor(CORRECT_SECRET);
    const spy = createCompareSpy();
    // Cast confined to this boundary: Node's header bag is typed, a hostile
    // caller in the same process is not.
    const nonString = 42 as unknown as string;
    assert.equal(bearerMatches(nonString, slots, spy.fn), false);
    assert.equal(spy.calls.length, 0);
  });

  test('B3: a strict prefix of the correct secret does not match', () => {
    const slots = slotsFor(CORRECT_SECRET);
    assert.equal(bearerMatches(`Bearer ${CORRECT_SECRET.slice(0, -1)}`, slots), false);
    assert.equal(bearerMatches(`Bearer ${CORRECT_SECRET.slice(0, 8)}`, slots), false);
  });

  test('B4: a superstring of the correct secret does not match', () => {
    const slots = slotsFor(CORRECT_SECRET);
    assert.equal(bearerMatches(`Bearer ${CORRECT_SECRET}x`, slots), false);
  });

  test('B5: every presented length answers false rather than throwing', () => {
    // This is the known throw source. `crypto.timingSafeEqual` throws
    // ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH on unequal-length buffers, so an
    // implementation that compares raw operands instead of hashing first turns
    // the very first hostile request from a 401 into a 500 — and a 500 to an
    // unauthenticated caller is itself a class-detection oracle.
    const slots = slotsFor(CORRECT_SECRET);
    for (const length of [0, 1, 31, 32, 33, 512, 16_384]) {
      const presented = `Bearer ${'a'.repeat(length)}`;
      assert.doesNotThrow(() => bearerMatches(presented, slots));
      assert.equal(bearerMatches(presented, slots), false);
    }
  });

  test('B6: both operands reach the comparator at exactly 32 bytes, once per slot', () => {
    const slots = slotsFor(CORRECT_SECRET, 'rotation-secret-also-long-enough-0123456');
    const spy = createCompareSpy();
    bearerMatches('Bearer anything-at-all', slots, spy.fn);

    assert.equal(spy.calls.length, slots.length);
    for (const call of spy.calls) {
      assert.equal(call.presentedLength, 32);
      assert.equal(call.slotLength, 32);
    }
  });

  test('B7: a match in the first slot still compares every slot', () => {
    // A short-circuit would make the number of configured slots observable in
    // the response time, disclosing whether a rotation secret is currently
    // configured — a fact an attacker uses to time a rotation window.
    const slots = slotsFor(CORRECT_SECRET, 'second-slot-secret-long-enough-0123456789');
    const spy = createCompareSpy();

    const matched = bearerMatches(`Bearer ${CORRECT_SECRET}`, slots, spy.fn);

    assert.equal(matched, true);
    assert.equal(spy.calls.length, 2);
  });

  test('B7: a match in the second slot is found', () => {
    const rotation = 'second-slot-secret-long-enough-0123456789';
    const slots = slotsFor(CORRECT_SECRET, rotation);
    assert.equal(bearerMatches(`Bearer ${rotation}`, slots), true);
  });

  test('B8: scheme parsing', () => {
    const slots = slotsFor(CORRECT_SECRET);
    const cases: ReadonlyArray<readonly [string, boolean]> = [
      [`Bearer ${CORRECT_SECRET}`, true],
      [`bearer ${CORRECT_SECRET}`, true],
      [`BEARER ${CORRECT_SECRET}`, true],
      [`BeArEr ${CORRECT_SECRET}`, true],
      // Two spaces: the credential begins with a space and is not trimmed.
      [`Bearer  ${CORRECT_SECRET}`, false],
      [`Bearer ${CORRECT_SECRET} `, false],
      [`Basic ${CORRECT_SECRET}`, false],
      [CORRECT_SECRET, false],
      ['', false],
      ['Bearer', false],
      ['Bearer ', false],
    ];

    for (const [presented, expected] of cases) {
      assert.equal(bearerMatches(presented, slots), expected, JSON.stringify(presented));
    }
  });
});

describe('Host validation', () => {
  test('B11: one allow-list entry matches with and without a port', () => {
    // The SDK's own check exact-matches the FULL Host header, port included, so
    // an operator who lists `example.com` gets a 403 on every real request —
    // every real request arrives as `example.com:8787`. Hence our own check.
    assert.equal(hostAllowed('example.com', ['example.com']), true);
    assert.equal(hostAllowed('example.com:8787', ['example.com']), true);
    assert.equal(hostAllowed('evil.example', ['example.com']), false);
  });

  test('B11: a port written into the allow-list is stripped too', () => {
    assert.equal(hostAllowed('example.com', ['example.com:8787']), true);
    assert.equal(hostAllowed('example.com:9000', ['example.com:8787']), true);
  });

  test('B12: a bracketed IPv6 entry matches with and without a port', () => {
    // Splitting on the first colon yields `[` and fails in exactly the default
    // IPv6-loopback bind case — the first case any developer hits.
    assert.equal(hostAllowed('[::1]', ['[::1]']), true);
    assert.equal(hostAllowed('[::1]:8787', ['[::1]']), true);
    assert.equal(hostAllowed('[::2]:8787', ['[::1]']), false);
  });

  test('B12: a bare unbracketed IPv6 literal keeps all of its colons', () => {
    assert.equal(hostAllowed('::1', ['::1']), true);
    assert.equal(hostAllowed('2001:db8::1', ['2001:db8::1']), true);
    assert.equal(hostAllowed('2001:db8::1', ['2001']), false);
  });

  test('B13: comparison is ASCII-case-insensitive', () => {
    assert.equal(hostAllowed('EXAMPLE.COM', ['example.com']), true);
    assert.equal(hostAllowed('example.com', ['EXAMPLE.COM']), true);
  });

  test('B13: one trailing dot is stripped', () => {
    assert.equal(hostAllowed('example.com.', ['example.com']), true);
    assert.equal(hostAllowed('example.com', ['example.com.']), true);
    assert.equal(hostAllowed('example.com.:8787', ['example.com']), true);
  });

  test('B13: IDN entries compare in punycode, in both directions', () => {
    assert.equal(hostAllowed('xn--bcher-kva.example', ['bücher.example']), true);
    assert.equal(hostAllowed('bücher.example', ['xn--bcher-kva.example']), true);
    assert.equal(hostAllowed('bücher.example', ['bücher.example']), true);
  });

  test('B13: near-miss names are rejected', () => {
    assert.equal(hostAllowed('example.com.evil', ['example.com']), false);
    assert.equal(hostAllowed('evil.com', ['example.com']), false);
    assert.equal(hostAllowed('xample.com', ['example.com']), false);
    assert.equal(hostAllowed('example.com', ['example.com.evil']), false);
  });

  test('B14: an absent or empty Host header is rejected', () => {
    assert.equal(hostAllowed(undefined, ['example.com']), false);
    assert.equal(hostAllowed('', ['example.com']), false);
  });

  test('an empty allow-list rejects everything', () => {
    // Recorded deliberately: this predicate does not implement "empty means
    // allow everything". Whether an unset UNIFI_HTTP_ALLOWED_HOSTS means "skip
    // Host validation" belongs to the pipeline and configuration layer.
    assert.equal(hostAllowed('example.com', []), false);
  });

  test('B15: no X-Forwarded-* header can reach either predicate', () => {
    // Both signatures make this structural rather than a convention:
    // `hostAllowed` takes one header VALUE and `sourceKey` takes one address,
    // so neither function can read a forwarded header even by accident.
    const headers: IncomingHttpHeaders = {
      host: 'evil.example',
      'x-forwarded-host': 'example.com',
      'x-forwarded-for': '10.42.0.7',
    };

    assert.equal(hostAllowed(headers.host, ['example.com']), false);
    assert.equal(sourceKey('203.0.113.9'), '203.0.113.9');
  });
});

describe('Origin', () => {
  // ─── DO NOT "FIX" THIS TEST. IT INVERTS THE SDK's DEFAULT ON PURPOSE. ───
  // FR-66: inverts SDK default.
  //
  // The MCP SDK's StreamableHTTPServerTransport ALLOWS a request carrying an
  // Origin header when `allowedOrigins` is left unconfigured. This server does
  // the OPPOSITE: it REJECTS any request carrying an Origin header, at every
  // value, and there is no Origin allow-list to configure.
  //
  // Why the inversion is correct, and why an allow-list would be a trap:
  //   1. A conforming MCP client is not a browser and sends no Origin. Its
  //      presence is therefore the DNS-rebinding / CSRF case by construction.
  //   2. The server emits no CORS headers at all, so a browser whose request
  //      the server accepted still could not read the response. An allow-list
  //      would be inert — a knob that looks like a control and is not one.
  //
  // If you are here because this test failed after you configured
  // `allowedOrigins` on the transport, the fix is to remove that option, not to
  // relax this assertion. src/serve/guard.ts carries the same marker string at
  // the enforcement site, and test/source-scans.test.ts asserts that the string
  // is still there (B19). Both must move together, and neither may move without
  // amending FR-66.
  // ────────────────────────────────────────────────────────────────────────
  test('B17: any Origin value at all is present', () => {
    const originValues: readonly string[] = [
      'https://evil.example',
      'http://localhost',
      'null',
      '',
      // Node joins duplicate headers with a comma.
      'a, b',
    ];

    for (const origin of originValues) {
      assert.equal(hasOrigin({ origin }), true, JSON.stringify(origin));
    }

    // The array shape a non-Node header bag might present.
    const duplicated = { origin: ['a', 'b'] as unknown as string };
    assert.equal(hasOrigin(duplicated), true);
  });

  test('B17: absence of Origin is the only way to be without one', () => {
    assert.equal(hasOrigin({}), false);
    assert.equal(
      hasOrigin({
        host: 'example.com',
        authorization: 'Bearer x',
        'x-forwarded-host': 'evil.example',
      }),
      false,
    );
  });

  test('B18: the probe exemption does not cover Origin', () => {
    // FR-67 exempts the probes from authentication and Host validation only.
    // The two predicates are independent and the caller must conjoin them.
    const normalizeRoute = createRouteNormalizer('/mcp');
    assert.equal(normalizeRoute('/healthz'), 'healthz');
    assert.equal(hasOrigin({ origin: 'https://evil.example' }), true);
    assert.equal(hasOrigin({ origin: '' }), true);
  });
});

describe('route normalisation', () => {
  const normalizeRoute = createRouteNormalizer('/mcp');

  const ROUTE_TABLE: ReadonlyArray<readonly [string, Route]> = [
    ['/healthz', 'healthz'],
    ['/healthz/', 'healthz'],
    ['//healthz', 'healthz'],
    ['/healthz?x=1', 'healthz'],
    ['/%68ealthz', 'healthz'],
    ['/readyz', 'readyz'],
    ['/mcp', 'mcp'],
    ['/mcp/', 'mcp'],
    ['/healthz/../mcp', 'mcp'],
    ['/healthz%2f..%2fmcp', 'mcp'],
    ['/healthz;x/../mcp', 'mcp'],
    ['/HEALTHZ', 'other'],
    ['/healthz/x', 'other'],
    ['/', 'other'],
    ['', 'other'],
    ['/%c0%af', 'other'],
    ['/%zz', 'other'],
    ['http://evil.example/mcp', 'other'],
    // Collapses to `/evil.example/mcp`, which is nobody's route.
    ['//evil.example/mcp', 'other'],
    ['/%252568ealthz', 'other'],
    ['/healthz%00', 'other'],
    ['/mcp%00', 'other'],
  ];

  for (const [target, expected] of ROUTE_TABLE) {
    test(`B20: ${JSON.stringify(target)} normalises to ${expected}`, () => {
      assert.equal(normalizeRoute(target), expected);
    });
  }

  test('B20: decoding runs first, comparison is case-SENSITIVE', () => {
    // The counter-intuitive half, asserted explicitly so nobody "fixes" it into
    // a case-insensitive comparison: `/%68ealthz` DOES reach the probe, because
    // percent-decoding happens before the comparison, while `/HEALTHZ` does NOT,
    // because the comparison is byte-exact.
    assert.equal(normalizeRoute('/%68ealthz'), 'healthz');
    assert.notEqual(normalizeRoute('/HEALTHZ'), 'healthz');
    assert.equal(normalizeRoute('/HEALTHZ'), 'other');
    assert.notEqual(normalizeRoute('/Mcp'), 'mcp');
  });

  test('B20: a doubly-encoded target is not decoded twice', () => {
    assert.notEqual(normalizeRoute('/%252568ealthz'), 'healthz');
    assert.equal(normalizeRoute('/%25'), 'other');
  });

  test('B21: the split detectors resolve to the authenticated route', () => {
    // The highest-risk line in the feature. An implementation that normalises
    // correctly for routing but tests the FR-67 probe exemption against the RAW
    // target with startsWith('/healthz') sends `/healthz%2f..%2fmcp` down the
    // exempt branch and serves the entire tool surface unauthenticated and
    // un-Host-validated. Both of these must be 'mcp' and neither may be a probe.
    assert.equal(normalizeRoute('/healthz%2f..%2fmcp'), 'mcp');
    assert.equal(normalizeRoute('/healthz;x/../mcp'), 'mcp');
    assert.notEqual(normalizeRoute('/healthz%2f..%2fmcp'), 'healthz');
    assert.notEqual(normalizeRoute('/healthz;x/../mcp'), 'healthz');
  });

  test('B21: popping past the root is a no-op, not an escape', () => {
    assert.equal(normalizeRoute('/../../mcp'), 'mcp');
    assert.equal(normalizeRoute('/a/b/../../healthz'), 'healthz');
  });

  test('B22: every hostile target yields a Route and never throws', () => {
    const hostile: readonly string[] = [
      '/%c0%af',
      '/%zz',
      '/%',
      '%2e%2e/',
      'http://evil/mcp',
      '//evil/mcp',
      '/mcp%00',
      '/%252568ealthz',
      '',
      `/${'a'.repeat(10_000)}`,
      `/${'../'.repeat(500)}mcp`,
      '/mcp?',
      '/?/mcp',
      '/./././mcp',
      '/mcp/./',
    ];

    for (const target of hostile) {
      assert.doesNotThrow(() => normalizeRoute(target));
      const route = normalizeRoute(target);
      assert.ok(ALL_ROUTES.includes(route), `${target} yielded ${String(route)}`);
    }
  });

  test('B20: the configured MCP path is canonicalised at factory time', () => {
    const withTrailingSlash = createRouteNormalizer('/deep/path/');
    assert.equal(withTrailingSlash('/deep/path'), 'mcp');
    assert.equal(withTrailingSlash('/deep//path/'), 'mcp');
    assert.equal(withTrailingSlash('/mcp'), 'other');
  });

  test('a colliding MCP path resolves to mcp, not to the probe', () => {
    // FR-73(d) refuses to start on this collision, so it cannot arise in a
    // running server. If it ever did, MCP-first is the fail-closed tiebreak: the
    // request takes the authenticated branch, not the unauthenticated one.
    const colliding = createRouteNormalizer('/healthz');
    assert.equal(colliding('/healthz'), 'mcp');
  });
});

describe('source key', () => {
  const SOURCE_TABLE: ReadonlyArray<readonly [string | undefined, string]> = [
    ['10.42.0.7', '10.42.0.7'],
    ['::ffff:10.42.0.7', '10.42.0.7'],
    ['::ffff:0a2a:0007', '10.42.0.7'],
    ['2001:db8::1', '2001:db8:0:0::/64'],
    ['2001:db8::2', '2001:db8:0:0::/64'],
    ['2001:db8:0:1::1', '2001:db8:0:1::/64'],
    ['fe80::1%eth0', 'fe80:0:0:0::/64'],
    [undefined, '-'],
    ['', '-'],
    ['not-an-address', '-'],
    ['10.42.0.7:1234', '-'],
    ['0177.0.0.1', '-'],
  ];

  for (const [address, expected] of SOURCE_TABLE) {
    test(`B24: ${String(address)} keys as ${expected}`, () => {
      assert.equal(sourceKey(address), expected);
    });
  }

  test('B24: two addresses in one /64 share a key, a different /64 does not', () => {
    assert.equal(sourceKey('2001:db8::1'), sourceKey('2001:db8::2'));
    assert.notEqual(sourceKey('2001:db8::1'), sourceKey('2001:db8:0:1::1'));
  });

  test('B15: the key follows the real remote address, not any forwarded header', () => {
    // `sourceKey` takes only an address, so a header an attacker controls cannot
    // forge attribution into the operator's forensic record.
    assert.equal(sourceKey('203.0.113.9'), '203.0.113.9');
    assert.equal(sourceKey('::ffff:203.0.113.9'), '203.0.113.9');
  });
});

describe('rejection throttle', () => {
  test('B26b: the boundary is N not throttled, N+1 throttled', () => {
    const throttle = createRejectionThrottle({ maxPerMinute: 20, now: () => 0 });

    for (let count = 0; count < 20; count += 1) {
      throttle.record('k');
      assert.equal(throttle.isThrottled('k'), false, `after ${count + 1} records`);
    }

    throttle.record('k');
    assert.equal(throttle.isThrottled('k'), true);
  });

  test('B26b: a lookup on an unknown key is false and allocates nothing', () => {
    const throttle = createRejectionThrottle({ maxPerMinute: 20, now: () => 0 });
    assert.equal(throttle.size(), 0);
    assert.equal(throttle.isThrottled('never-seen'), false);
    assert.equal(throttle.size(), 0);
  });

  test('B26: the window expires on the injected clock alone', () => {
    // No setTimeout, no sleep, no wall-clock read anywhere in this test.
    let nowMs = 0;
    const throttle = createRejectionThrottle({ maxPerMinute: 20, now: () => nowMs });

    for (let count = 0; count < 21; count += 1) throttle.record('k');
    assert.equal(throttle.isThrottled('k'), true);

    nowMs = THROTTLE_WINDOW_MS - 1;
    assert.equal(nowMs, 59_999);
    assert.equal(throttle.isThrottled('k'), true);

    nowMs = THROTTLE_WINDOW_MS;
    assert.equal(nowMs, 60_000);
    assert.equal(throttle.isThrottled('k'), false);
  });

  test('B26: a record after the window opens a fresh one', () => {
    let nowMs = 0;
    const throttle = createRejectionThrottle({ maxPerMinute: 1, now: () => nowMs });

    throttle.record('k');
    throttle.record('k');
    assert.equal(throttle.isThrottled('k'), true);

    nowMs = THROTTLE_WINDOW_MS;
    throttle.record('k');
    assert.equal(throttle.isThrottled('k'), false);
  });

  test('B25: the table never exceeds its capacity', () => {
    const capacity = THROTTLE_DEFAULT_CAPACITY;
    const throttle = createRejectionThrottle({ maxPerMinute: 20, capacity, now: () => 0 });

    const totalKeys = capacity * 10;
    for (let index = 0; index < totalKeys; index += 1) {
      throttle.record(`source-${index}`);
      assert.ok(throttle.size() <= capacity, `size ${throttle.size()} at ${index}`);
      if (index >= capacity) assert.equal(throttle.size(), capacity);
    }

    assert.equal(throttle.size(), capacity);
  });

  test('B25: capacity defaults to 4096', () => {
    assert.equal(THROTTLE_DEFAULT_CAPACITY, 4096);
    const throttle = createRejectionThrottle({ maxPerMinute: 20, now: () => 0 });
    for (let index = 0; index < THROTTLE_DEFAULT_CAPACITY + 500; index += 1) {
      throttle.record(`source-${index}`);
    }
    assert.equal(throttle.size(), THROTTLE_DEFAULT_CAPACITY);
  });

  test('B25b: eviction takes the least recently recorded key', () => {
    // maxPerMinute 0 makes "recorded at all" observable through isThrottled.
    const throttle = createRejectionThrottle({ maxPerMinute: 0, capacity: 3, now: () => 0 });

    throttle.record('a');
    throttle.record('b');
    throttle.record('c');
    assert.equal(throttle.size(), 3);
    assert.equal(throttle.isThrottled('a'), true);

    throttle.record('d');
    assert.equal(throttle.size(), 3);
    assert.equal(throttle.isThrottled('a'), false);
    assert.equal(throttle.isThrottled('b'), true);
    assert.equal(throttle.isThrottled('c'), true);
    assert.equal(throttle.isThrottled('d'), true);
  });

  test('B25b: re-recording a key refreshes its LRU position', () => {
    const throttle = createRejectionThrottle({ maxPerMinute: 0, capacity: 3, now: () => 0 });

    throttle.record('a');
    throttle.record('b');
    throttle.record('c');
    throttle.record('a');
    throttle.record('d');

    assert.equal(throttle.isThrottled('b'), false, 'b was least recently recorded');
    assert.equal(throttle.isThrottled('a'), true);
    assert.equal(throttle.isThrottled('c'), true);
    assert.equal(throttle.isThrottled('d'), true);
  });
});

describe('module boundaries', () => {
  test('B27: the guard imports nothing but node:http and the two leaves', () => {
    // The outbound limiter cannot serve this purpose, three times over:
    //   1. it is an outbound, QUEUEING limiter — acquire() chains onto a FIFO
    //      tail and consume() sleeps before admitting, whereas an inbound
    //      throttle must answer 429 immediately;
    //   2. forcing maxWaitMs: 0 makes it throw with outbound text naming the
    //      matching UNIFI_RATE_LIMIT_* variable and a service defaulting to
    //      site-manager — outbound diagnostics on an inbound rejection path;
    //   3. its bucket map is unbounded and never evicts, keyed by client
    //      address, which is an unauthenticated memory-exhaustion vector and
    //      fails FR-81's memory bound outright.
    //
    // `./auth.js` is on the list because the bearer comparator is re-exported
    // from the auth leaf rather than reimplemented here, which is why guard.ts
    // needs no `node:crypto` at all any more — and this assertion is what stops
    // a second `createHash` / `timingSafeEqual` import from creeping back in
    // unnoticed and growing a rival comparator behind it.
    const source = readFileSync(join(REPO_ROOT, 'src', 'serve', 'guard.ts'), 'utf8');

    assert.ok(!source.includes('http/ratelimit'), 'guard.ts must not reach for the outbound limiter');

    const specifiers = new Set<string>();
    for (const match of source.matchAll(/\bfrom\s+'([^']+)'/g)) {
      const specifier = match[1];
      if (specifier !== undefined) specifiers.add(specifier);
    }

    assert.deepEqual(
      [...specifiers].sort(),
      ['../netliteral.js', './auth.js', 'node:http'],
    );
  });

  test('B27: the FR-66 marker string is present at the enforcement site', () => {
    const source = readFileSync(join(REPO_ROOT, 'src', 'serve', 'guard.ts'), 'utf8');
    assert.ok(source.includes('FR-66: inverts SDK default'));
  });

  test('the loopback predicate has exactly one implementation (D-15)', () => {
    assert.equal(isLoopbackBind, isLoopbackBindFromLeaf);
  });

  test('the bearer comparator has exactly one implementation (D-15)', () => {
    // One predicate, one answer in the process. Both stories that touched this
    // wrote their own constant-time comparison and shipped them side by side;
    // identity — not behavioural equivalence — is what makes a reappearing
    // second copy fail the build rather than pass it by accident.
    assert.equal(bearerMatches, bearerMatchesFromAuth);
  });
});
