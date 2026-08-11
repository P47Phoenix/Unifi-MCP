/**
 * US-27 — the route normaliser, asserted where it is actually CONSUMED.
 *
 * Suite B's B21 and B22, in their routed form, plus the FR-67 counter proof.
 *
 * ## Why this file exists beside `test/serve-guard.test.ts`
 *
 * US-10 already proves `createRouteNormalizer` as a pure function: a table of
 * targets in, a `Route` out, never a throw. That is necessary and it is not
 * sufficient, because the vulnerability FR-67 is about does not live in the
 * normaliser at all. It lives in the SPLIT between two readings of one request:
 * an implementation that normalises correctly for ROUTING and then tests the
 * probe exemption against the RAW target with `startsWith('/healthz')` passes
 * every unit case in US-10's table and still serves the whole tool surface
 * unauthenticated. A pure-function test cannot see that split, because the
 * second reading never calls the function under test.
 *
 * So everything below drives a real listener over a raw `net.Socket` and reads
 * the two things that can only be observed from outside: the response the
 * pipeline chose, and the MCP-request-handler counter.
 *
 * ## The counter differential, which is the load-bearing idea
 *
 * "The counter reads 0" is a weak assertion on its own — it also reads 0 when
 * the request was routed to nowhere, when the listener was wedged, and when the
 * observer was never wired. Every counter assertion here is therefore a PAIR:
 * the same target, sent twice, differing in ONE bit — whether a valid secret was
 * presented. The unauthenticated send must read 0 and the authenticated send
 * must read 1. That is what distinguishes "the exemption held" from "nothing
 * happened", and it is what would fail loudly if the exemption were ever tested
 * against the raw target.
 *
 * ## `fetch` and `http.request` appear nowhere
 *
 * Both normalise the request target before it reaches the wire — `fetch` will
 * not send `/healthz%2f..%2fmcp` at all, it sends `/mcp`. A suite built on them
 * cannot express the inputs this file is about.
 *
 * The socket helper below is deliberately a local copy rather than a shared
 * harness export: `test/harness/` is US-25's file scope, and this story may not
 * add to it. The duplication is named here so it is a known pinned copy rather
 * than an accident, and `test/harness/README.md`'s owner may collapse the three
 * copies (this file, `serve-uniformity`, `serve-throttle`) later.
 */
import assert from 'node:assert/strict';
import { createServer as createNodeHttpServer } from 'node:http';
import { connect } from 'node:net';
import { describe, test, type TestContext } from 'node:test';

import { createRouteNormalizer } from '../src/serve/guard.js';
import { startHttp, type HttpServing, type HttpServingDeps } from '../src/serve/http.js';
import { buildRuntimeCore, type RuntimeCore } from '../src/serve/runtime.js';

import { createInstruments, type Instruments } from './harness/counters.js';

/** 40 characters, comfortably over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;
const ALLOWED_HOST = 'allowed.example';
/** What a kubelet sends: the pod IP, which no operator allow-list contains. */
const KUBELET_HOST = '10.42.0.7:8787';

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

/** The SDK's own answer for a non-initialisation request carrying no session id. */
const SESSION_REQUIRED = 'Mcp-Session-Id header is required';

function httpEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST,
    // Raised so the throttle never fires inside a corpus sweep. The throttle is
    // `test/serve-throttle.test.ts`'s subject; a 429 landing in the middle of a
    // routing table would be a confounder, not a finding.
    UNIFI_HTTP_AUTH_FAIL_PER_MIN: '1000000',
    // Raised for the same reason: a corpus of a hundred sequential connections
    // must not run into the connection cap and be refused with no response.
    UNIFI_HTTP_MAX_CONNECTIONS: '512',
    ...extra,
  };
}

interface Bound {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly instruments: Instruments;
}

/**
 * Start one listener and register its teardown on the TEST CONTEXT.
 *
 * Not in a shared `after()`: a file-level failure would otherwise leave a
 * listening handle behind and hang the runner.
 */
async function boundServer(
  t: TestContext,
  env: Record<string, string> = httpEnv(),
  deps: HttpServingDeps = {},
): Promise<Bound> {
  const instruments = createInstruments({ env: { ...env }, keychain: null });
  const core = buildRuntimeCore(instruments.deps);
  const serving = await startHttp(core, instruments.observer, {
    warn: () => {},
    createHttpServer: (options, handler) => createNodeHttpServer(options, handler),
    ...deps,
  });

  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  await core.ready;
  // `resolveRegistry`'s continuation flips the readiness phase one microtask
  // after `ready` settles; two macrotask ticks is comfortably past it.
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  return { serving, core, port: serving.address.port, instruments };
}

interface Captured {
  readonly text: string;
  readonly closedByServer: boolean;
  readonly errorCode: string | null;
}

/** One request over a raw socket, returning the server's bytes verbatim. */
function exchange(port: number, request: string, idleMs = 250): Promise<Captured> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let closedByServer = false;
    let errorCode: string | null = null;
    let settled = false;
    let idle: NodeJS.Timeout | null = null;

    const socket = connect({ host: '127.0.0.1', port });

    const settle = (): void => {
      if (settled) return;
      settled = true;
      if (idle !== null) clearTimeout(idle);
      socket.destroy();
      resolve({ text: Buffer.concat(chunks).toString('latin1'), closedByServer, errorCode });
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
      errorCode = error.code ?? 'UNKNOWN';
      closedByServer = closedByServer || errorCode === 'ECONNRESET';
    });
    socket.on('close', settle);
  });
}

/**
 * Build a request block, header order verbatim.
 *
 * `Connection: close` is on EVERY request in this file. It does not change any
 * response the pipeline composes — the uniform 401 already carries it and the
 * §1 assertion below proves the equality directly — and it makes a keep-alive
 * answer (the 404, the probes) settle on the socket's own close rather than on
 * an idle timer, which is the difference between a corpus of ninety targets
 * taking three seconds and taking half a minute.
 */
function raw(target: string, headers: readonly string[], method = 'GET'): string {
  return `${[`${method} ${target} HTTP/1.1`, ...headers, 'Connection: close'].join('\r\n')}\r\n\r\n`;
}

function anonymous(target: string, host = KUBELET_HOST, method = 'GET'): string {
  return raw(target, [`Host: ${host}`], method);
}

function authenticated(target: string, host = ALLOWED_HOST, method = 'GET'): string {
  return raw(target, [`Host: ${host}`, `Authorization: Bearer ${SECRET}`], method);
}

function statusLine(captured: Captured): string {
  return captured.text.split('\r\n')[0] ?? '';
}

function bodyOf(captured: Captured): string {
  const split = captured.text.indexOf('\r\n\r\n');
  return split === -1 ? '' : captured.text.slice(split + 4);
}

// ---------------------------------------------------------------------------
// 1. The split detectors, with the counter differential (US-27 AC 3, B21)
// ---------------------------------------------------------------------------

/**
 * The two targets FR-67 names, plus three more of the same family.
 *
 * Every one of them normalises to `mcp`. An implementation testing the
 * exemption against the raw target sends all five down the unauthenticated
 * probe branch.
 */
const SPLIT_DETECTORS: readonly string[] = [
  '/healthz%2f..%2fmcp',
  '/healthz;x/../mcp',
  // Uppercase escapes: percent-decoding is hex-case-insensitive, so an
  // implementation matching the literal `%2f` misses this one.
  '/healthz%2F..%2Fmcp',
  // Every separator encoded, so no `/` or `.` appears in the raw target at all.
  '/healthz%2f%2e%2e%2fmcp',
  // The readiness probe's name, for the same reason.
  '/readyz/../mcp',
];

describe('US-27 §1: the probe exemption is decided on the normalised route, not the raw target', () => {
  test('AC 3: every split detector reads 0 on the MCP-request-handler counter', async (t) => {
    const bound = await boundServer(t);

    for (const target of SPLIT_DETECTORS) {
      const before = bound.instruments.counts.mcpRequest;
      const result = await exchange(bound.port, anonymous(target));

      // Byte-identical to the uniform 401 — the same answer as a plain
      // unauthenticated `POST /mcp`, so the traversal attempt is not even
      // distinguishable from an ordinary refusal.
      assert.equal(result.text, UNIFORM_401_WIRE, `${target} did not get the uniform 401`);
      assert.equal(
        bound.instruments.counts.mcpRequest,
        before,
        `${target} reached the MCP request handler unauthenticated`,
      );
      // The probe bodies, stated explicitly: a raw-target exemption would
      // answer one of these with 200.
      assert.equal(bodyOf(result).includes('ok\n'), false, `${target} was served as /healthz`);
      assert.equal(bodyOf(result).includes('ready\n'), false, `${target} was served as /readyz`);
    }

    assert.equal(
      bound.instruments.counts.mcpRequest,
      0,
      'the counter is 0 for the whole detector set, not merely per row',
    );
  });

  test('AC 3: the SAME targets DO reach the handler with a valid secret — so 0 meant "refused"', async (t) => {
    const bound = await boundServer(t);

    // The differential. Without this half, a counter reading 0 above is
    // consistent with the request having been routed to nowhere, with the
    // listener being wedged, and with the observer never having been wired.
    // One bit differs between the two sends: the credential.
    for (const target of SPLIT_DETECTORS) {
      const before = bound.instruments.counts.mcpRequest;
      const result = await exchange(bound.port, authenticated(target));

      assert.equal(
        bound.instruments.counts.mcpRequest,
        before + 1,
        `${target} did not route to the MCP endpoint for a credential holder`,
      );
      // Dispatch was reached and the SDK's own session requirement answered it,
      // which is only expressible if the route resolved to `mcp`.
      assert.match(statusLine(result), /^HTTP\/1\.1 400 /);
      assert.ok(bodyOf(result).includes(SESSION_REQUIRED), `${target} did not reach dispatch`);
    }

    assert.equal(bound.instruments.counts.mcpRequest, SPLIT_DETECTORS.length);
  });

  test('a transport is never CONSTRUCTED for a split detector either', async (t) => {
    // The stronger of the two counters: a handler counter can read 0 while a
    // transport was still constructed and torn down.
    let transports = 0;
    const bound = await boundServer(t, httpEnv(), {
      createTransport: () => {
        transports += 1;
        throw new Error('no transport may be constructed for a rejected request');
      },
    });

    for (const target of SPLIT_DETECTORS) {
      const result = await exchange(bound.port, anonymous(target));
      assert.equal(result.text, UNIFORM_401_WIRE);
    }
    assert.equal(transports, 0);
    assert.equal(bound.instruments.counts.mcpRequest, 0);
  });
});

// ---------------------------------------------------------------------------
// 2. Scheme confusion and encoding probes (US-27 AC 4, B22)
// ---------------------------------------------------------------------------

/**
 * Targets that must resolve to `other` — never to a probe, never to `mcp` —
 * and must do so without the normaliser throwing.
 *
 * The "without throwing" half is not pedantry. `decodeURIComponent('/%c0%af')`
 * raises `URIError`, and step 2 runs BEFORE authentication: an uncaught one is a
 * remotely triggered, unauthenticated denial of service out of one malformed
 * byte, and a 500 handed to a stranger is a class-detection oracle by another
 * route.
 */
const RESOLVE_TO_OTHER: readonly string[] = [
  // Overlong UTF-8 encoding of `/`. The classic path-traversal smuggle, and the
  // input that makes `decodeURIComponent` throw.
  '/%c0%af',
  // Absolute-form request line. Legal on the wire for a proxy, and
  // `new URL(raw, base)` would discard the authority and hand back `/mcp` — a
  // request aimed at another host, routed to ours.
  'http://evil/mcp',
  // The same trick aimed at the UNAUTHENTICATED half of the surface, which is
  // the version that would actually be worth an attacker's time.
  'http://evil/healthz',
  'https://evil.example:443/readyz',
  // Protocol-relative form: collapses to `/evil.example/healthz`, nobody's route.
  '//evil.example/healthz',
  // A truncation attempt aimed at some later consumer's string.
  '/healthz%00',
  '/mcp%00',
  // Malformed and partial escapes.
  '/%zz',
  '/%',
  '/%25',
  // Double encoding: NOT unwrapped twice, so it fails closed rather than
  // resolving to a probe after enough rounds.
  '/%252568ealthz',
  // Backslash is not a path separator in a request target.
  '/healthz%5c..%5cmcp',
  // A fragment marker is NOT stripped — only the query is — so `healthz#x` is
  // one opaque segment and matches no route.
  '/healthz#x',
  // Trailing whitespace, decoded.
  '/healthz%20',
  '/healthz%09',
  // Case: the comparison is byte-exact after decoding.
  '/HEALTHZ',
  '/Mcp',
  '/healthz/x',
  '/mcp;',
];

describe('US-27 §2: hostile targets resolve to the `other` route without throwing', () => {
  test('AC 4: each resolves to `other` for a credential holder — a 404, never a 500', async (t) => {
    const bound = await boundServer(t);

    for (const target of RESOLVE_TO_OTHER) {
      const before = bound.instruments.counts.mcpRequest;
      const result = await exchange(bound.port, authenticated(target));

      // `other` is only observable to an AUTHENTICATED caller: to a stranger
      // every route below the probe branch answers the same 401, which is the
      // point of the uniform rejection and the reason the route cannot be read
      // off an unauthenticated response.
      assert.match(statusLine(result), /^HTTP\/1\.1 404 Not Found/, `${target} was not routed to other`);
      assert.equal(bodyOf(result), '{"error":"not_found"}', `${target} produced an unexpected body`);
      // A thrown normaliser surfaces here as a 500 to the holder. That is the
      // finding this case exists to make impossible to miss.
      assert.equal(
        result.text.includes('server_error'),
        false,
        `${target} threw inside the pipeline and produced a 500`,
      );
      assert.equal(bound.instruments.counts.mcpRequest, before, `${target} reached dispatch`);
    }
  });

  test('AC 4: the same targets are the uniform 401 to a stranger, and never a probe', async (t) => {
    const bound = await boundServer(t);

    for (const target of RESOLVE_TO_OTHER) {
      const result = await exchange(bound.port, anonymous(target));
      assert.equal(result.text, UNIFORM_401_WIRE, `${target} diverged from the uniform 401`);
    }
    assert.equal(bound.instruments.counts.mcpRequest, 0);
  });

  test('an absolute-form target naming a probe path is NOT exempt', async (t) => {
    // Called out on its own because it is the only member of the set above with
    // an unauthenticated reward: `GET http://evil/healthz` reaching the probe
    // branch would not itself leak much, but it would prove the exemption is
    // decided before the origin-form check, and `GET http://evil/mcp` is the
    // same bug with the whole tool surface behind it.
    const bound = await boundServer(t);

    for (const target of ['http://evil/healthz', 'https://evil.example:443/readyz']) {
      const result = await exchange(bound.port, anonymous(target));
      assert.equal(result.text, UNIFORM_401_WIRE);
      assert.equal(bodyOf(result).includes('ok\n'), false);
      assert.equal(bodyOf(result).includes('ready\n'), false);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. The routed normalisation table, end to end
// ---------------------------------------------------------------------------

type ExpectedRoute = 'mcp' | 'healthz' | 'readyz' | 'other';

/**
 * The whole corpus, with the route each target must resolve to.
 *
 * US-10 asserts this table against the pure function. This asserts it against
 * the RUNNING PIPELINE, which is a different claim: it says the value the
 * function returned is the value every subsequent decision was taken on.
 */
const ROUTED_CORPUS: ReadonlyArray<readonly [string, ExpectedRoute]> = [
  ['/healthz', 'healthz'],
  ['/healthz/', 'healthz'],
  ['//healthz', 'healthz'],
  ['/healthz?x=1', 'healthz'],
  ['/healthz?x=/mcp', 'healthz'],
  ['/%68ealthz', 'healthz'],
  ['/%2fhealthz', 'healthz'],
  ['/./././healthz', 'healthz'],
  ['/mcp/../healthz', 'healthz'],
  ['/a/b/../../healthz', 'healthz'],
  ['/readyz', 'readyz'],
  ['/readyz/', 'readyz'],
  ['/mcp', 'mcp'],
  ['/mcp/', 'mcp'],
  ['/mcp/./', 'mcp'],
  ['/mcp?x=1&y=/healthz', 'mcp'],
  ['/healthz/../mcp', 'mcp'],
  ['/healthz%2f..%2fmcp', 'mcp'],
  ['/healthz;x/../mcp', 'mcp'],
  ['/../../mcp', 'mcp'],
  [`/${'../'.repeat(200)}mcp`, 'mcp'],
  ['/%6dcp', 'mcp'],
  ['/HEALTHZ', 'other'],
  ['/HEALTHZ/../healthz', 'healthz'],
  ['/healthz/x', 'other'],
  ['/%c0%af', 'other'],
  ['/%zz', 'other'],
  ['http://evil/mcp', 'other'],
  ['http://evil/healthz', 'other'],
  ['//evil.example/mcp', 'other'],
  ['/%252568ealthz', 'other'],
  ['/healthz%00', 'other'],
  ['/mcp%00', 'other'],
  [`/${'a'.repeat(2000)}`, 'other'],
  ['/healthz#x', 'other'],
  // The counter-intuitive neighbour of the row above, pinned deliberately: a
  // fragment marker does NOT make the rest of the target opaque, because `/`
  // still splits after it. `/healthz#/../mcp` is therefore the AUTHENTICATED
  // route, which is the fail-closed direction — but anyone "fixing" the
  // normaliser to strip at `#` would flip this to `healthz`, which is the
  // dangerous direction, and would turn this row red.
  ['/healthz#/../mcp', 'mcp'],
  ['/mcp;', 'other'],
];

/** Read the route back out of the response an AUTHENTICATED caller received. */
function routeFromResponse(captured: Captured): ExpectedRoute | 'unknown' {
  const body = bodyOf(captured);
  if (body === 'ok\n') return 'healthz';
  if (body === 'ready\n' || body === 'starting\n' || body === 'draining\n') return 'readyz';
  if (body === '{"error":"not_found"}') return 'other';
  if (body.includes(SESSION_REQUIRED)) return 'mcp';
  return 'unknown';
}

describe('US-27 §3: the pipeline routes on the normalised value, for the whole corpus', () => {
  test('every target resolves to its declared route, observed from the wire', async (t) => {
    const bound = await boundServer(t);

    const wrong: string[] = [];
    let expectedMcp = 0;

    for (const [target, expected] of ROUTED_CORPUS) {
      if (expected === 'mcp') expectedMcp += 1;
      const result = await exchange(bound.port, authenticated(target));
      const observed = routeFromResponse(result);
      if (observed !== expected) {
        wrong.push(`${JSON.stringify(target)}: expected ${expected}, observed ${observed} — ${statusLine(result)}`);
      }
      // No target, however hostile, may produce a 500. A 500 here is a thrown
      // normaliser, and step 2 runs before authentication.
      assert.equal(
        result.text.includes('server_error'),
        false,
        `${target} produced a 500 from the routing layer`,
      );
    }

    assert.deepEqual(wrong, [], `targets routed to the wrong place:\n${wrong.join('\n')}`);
    // Cross-check against the independent instrument: exactly the rows declared
    // `mcp` reached dispatch. A response-shape reader that had drifted would
    // have to have drifted in exactly the same direction as the counter.
    assert.equal(bound.instruments.counts.mcpRequest, expectedMcp);
  });

  test('the raw target never reaches the response bytes or the log line', async (t) => {
    const bound = await boundServer(t);

    for (const [target] of ROUTED_CORPUS) {
      const result = await exchange(bound.port, authenticated(target));
      // Skip targets short enough to occur incidentally in a status line.
      if (target.length >= 6) {
        assert.equal(
          result.text.includes(target),
          false,
          `${target} was echoed back to the caller`,
        );
      }
    }

    // `RouteLabel` has four members, so there is no expressible way to put a
    // request target on the line. Asserted rather than assumed, because the
    // raw target is attacker-controlled and the log is the operator's record.
    const labels = new Set<string>();
    for (const line of bound.instruments.counts.requestLogs) {
      const match = /\bpath=(\S+)/.exec(line);
      assert.ok(match !== null, `a request line carried no path field: ${line}`);
      labels.add(match[1] as string);
    }
    assert.ok(labels.size > 0, 'no request lines were captured');
    for (const label of labels) {
      assert.ok(
        ['mcp', 'healthz', 'readyz', 'other'].includes(label),
        `path= rendered ${JSON.stringify(label)}, which is not one of the four routes`,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// 4. The normaliser is consulted exactly once per request
// ---------------------------------------------------------------------------

describe('US-27 §4: one normalisation per request, and the raw target is then gone', () => {
  test('the normaliser is called exactly once, whatever the outcome', async (t) => {
    // A second call is the observable signature of the split this whole file
    // exists to rule out: an implementation that normalises for routing and
    // then normalises (or inspects) the raw target again for the exemption.
    const seen: string[] = [];
    const bound = await boundServer(t, httpEnv(), {
      createRouteNormalizer: (mcpPath) => {
        // The PRODUCTION normaliser behind the counter, so what runs is the
        // real thing rather than a stand-in that agrees with itself.
        const inner = createRouteNormalizer(mcpPath);
        return (rawTarget: string) => {
          seen.push(rawTarget);
          return inner(rawTarget);
        };
      },
    });

    const targets = ['/mcp', '/healthz', '/healthz%2f..%2fmcp', '/%c0%af', 'http://evil/mcp'];
    for (const target of targets) {
      seen.length = 0;
      await exchange(bound.port, anonymous(target));
      assert.equal(seen.length, 1, `${target} was normalised ${seen.length} times`);
      assert.equal(seen[0], target, 'the normaliser did not receive the raw target verbatim');
    }
  });
});
