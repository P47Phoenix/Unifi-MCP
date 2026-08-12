/**
 * US-27 — the uniform unauthenticated rejection, and the closure of its
 * exception set.
 *
 * Suite C's C27, C28 and C35, taken from the other side. US-22 wrote the
 * pipeline and proved it correct with a seven-row list of the classes it knows
 * it produces. That is the implementer's proof and it is worth having. This is
 * the reviewer's: it does not ask "do the seven classes agree", it asks "is
 * there ANY well-formed request an unauthenticated caller can send whose bytes
 * differ" — and it answers by generating the population rather than listing it.
 *
 * ## Why the enumeration is generated, not curated
 *
 * A list of seven examples that happen to agree proves those seven agree. The
 * value of the word CLOSED is that a divergence introduced later fails the test
 * rather than being absent from a list nobody thought to extend. So §1 builds
 * its population from the seven request DIMENSIONS an unauthenticated caller
 * controls — method, target, credential, `Host`, `Origin`, body size, header
 * size — as a set of systematic design blocks over those dimensions: a
 * one-factor-at-a-time sweep from a baseline, the full method × target product,
 * the full credential × target product, the full origin × target product, and
 * the full host × body × header-size product. Around two hundred requests, none
 * of them chosen for its outcome.
 *
 * Each response is then CLASSIFIED BY ITS BYTES — uniform, probe, or divergent
 * — and the divergent set is required to be exactly the complete preimage of
 * one dimension value: `headers = overflow`. Adding a new branch anywhere in
 * the pipeline that an unauthenticated caller can reach puts a row in the
 * divergent set that is not a header-overflow row, and three assertions fail at
 * once.
 *
 * ## The scope of the claim, stated rather than assumed
 *
 * The population is every **well-formed HTTP/1.1 request**. A request that is
 * not well-formed HTTP — no `Host` on an HTTP/1.1 request line, an unparseable
 * method token, a bad version, a `Transfer-Encoding`/`Content-Length` conflict
 * — is answered by Node's PARSER before this application has a handler frame on
 * the stack, and no application code can be responsible for its bytes. Those
 * are not silently excluded: §6 sends them, records what the parser does, and
 * asserts the weaker property that actually holds for them — that they disclose
 * nothing about this product or its configuration.
 *
 * The `431` is inside the claim precisely because it is not that kind of case:
 * the header cap is one of THIS server's configured bounds, so a caller who can
 * move it by moving `UNIFI_HTTP_MAX_HEADER_BYTES` is observing our
 * configuration, and it has to be accounted for rather than dismissed.
 *
 * ## Raw sockets only
 *
 * `fetch` and `http.request` are used nowhere. Both normalise header case,
 * reorder headers and hide the status line, so a suite built on them passes
 * while the wire differs — which is the exact failure a byte comparison exists
 * to catch. The socket helper is a local copy for the reason named in
 * `test/serve-normalizer.test.ts`'s header: `test/harness/` is another story's
 * file scope this round.
 */
import assert from 'node:assert/strict';
import { createServer as createNodeHttpServer } from 'node:http';
import { connect } from 'node:net';
import { after, describe, test, type TestContext } from 'node:test';

import { startHttp, type HttpServing, type HttpServingDeps } from '../src/serve/http.js';
import { buildRuntimeCore } from '../src/serve/runtime.js';

import { createInstruments, type Instruments } from './harness/counters.js';

const SECRET = `s${'u'.repeat(39)}`;
/** Not the secret, and the same length as it. */
const WRONG_SECRET = `w${'x'.repeat(39)}`;

const ALLOWED_HOST = 'allowed.example';
const REJECTED_HOST = 'not-allowed.example';
const KUBELET_HOST = '10.42.0.7:8787';

const BODY_CAP = 4096;
const HEADER_CAP = 2048;

/** Operator contract §5.1, transcribed. */
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

/** The same response with the body omitted, which is what a `HEAD` receives. */
const UNIFORM_401_HEAD_WIRE = UNIFORM_401_WIRE.slice(
  0,
  UNIFORM_401_WIRE.indexOf('\r\n\r\n') + 4,
);

function httpEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST,
    UNIFI_HTTP_MAX_BODY_BYTES: String(BODY_CAP),
    UNIFI_HTTP_MAX_HEADER_BYTES: String(HEADER_CAP),
    // Raised out of the way. The throttle IS a divergence an unauthenticated
    // caller can reach, and it is not curated away: it is conditional on a
    // configured threshold rather than on the rejection CLASS, which is a
    // different fact and is `test/serve-throttle.test.ts`'s subject. §1 asserts
    // directly that zero 429s were observed, so this exclusion is verified
    // rather than assumed.
    UNIFI_HTTP_AUTH_FAIL_PER_MIN: '1000000',
    // A two-hundred-connection sweep must not run into the connection cap and
    // be refused at admission, which produces no response at all and would look
    // like a divergence.
    UNIFI_HTTP_MAX_CONNECTIONS: '512',
    ...extra,
  };
}

interface Bound {
  readonly serving: HttpServing;
  readonly port: number;
  readonly instruments: Instruments;
}

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
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  return { serving, port: serving.address.port, instruments };
}

// ---------------------------------------------------------------------------
// The raw socket client
// ---------------------------------------------------------------------------

interface Captured {
  readonly bytes: Buffer;
  readonly text: string;
  readonly closedByServer: boolean;
  readonly errorCode: string | null;
}

/** Every response this file captured, for the whole-suite header sweep. */
const allResponses: Captured[] = [];

const CORS_HEADER = /^access-control-|^timing-allow-origin:/im;
const FINGERPRINT_HEADER = /^server:|^x-powered-by:/im;

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
      const bytes = Buffer.concat(chunks);
      const captured: Captured = {
        bytes,
        text: bytes.toString('latin1'),
        closedByServer,
        errorCode,
      };
      allResponses.push(captured);
      resolve(captured);
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

function statusLine(captured: Captured): string {
  return captured.text.split('\r\n')[0] ?? '';
}

function bodyOf(captured: Captured): string {
  const split = captured.text.indexOf('\r\n\r\n');
  return split === -1 ? '' : captured.text.slice(split + 4);
}

// ---------------------------------------------------------------------------
// The seven dimensions
// ---------------------------------------------------------------------------

/**
 * Only methods `llhttp` will parse appear here.
 *
 * `FROB` and `FR@B` are answered `400 Bad Request` by the parser without any
 * application frame on the stack, which puts them in §6's population rather
 * than this one. Recorded because "we only sent methods that work" would
 * otherwise look like curation.
 */
const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE'] as const;

const TARGETS = [
  '/mcp',
  '/mcp/',
  '/unknown',
  '/healthz',
  '/readyz',
  '/healthz%2f..%2fmcp',
  '/healthz;x/../mcp',
  '/%c0%af',
  '/HEALTHZ',
  'http://evil/mcp',
] as const;

const PROBE_TARGETS: ReadonlySet<string> = new Set(['/healthz', '/readyz']);

const CREDENTIALS = {
  absent: null,
  wrong: `Bearer ${WRONG_SECRET}`,
  'basic-scheme': `Basic ${SECRET}`,
  'no-scheme': SECRET,
  'empty-bearer': 'Bearer',
} as const;

const HOSTS = {
  allowed: ALLOWED_HOST,
  disallowed: REJECTED_HOST,
  'kubelet-ip': KUBELET_HOST,
} as const;

const ORIGINS = {
  absent: null,
  hostile: 'https://evil.example',
  null: 'null',
  empty: '',
} as const;

const BODIES = { none: 0, 'under-cap': 64, 'over-cap': BODY_CAP * 2 } as const;

const HEADER_SIZES = { normal: 0, overflow: HEADER_CAP * 2 } as const;

interface Row {
  readonly method: (typeof METHODS)[number];
  readonly target: (typeof TARGETS)[number];
  readonly credential: keyof typeof CREDENTIALS;
  readonly host: keyof typeof HOSTS;
  readonly origin: keyof typeof ORIGINS;
  readonly body: keyof typeof BODIES;
  readonly headers: keyof typeof HEADER_SIZES;
}

const BASELINE: Row = {
  method: 'POST',
  target: '/mcp',
  credential: 'absent',
  host: 'allowed',
  origin: 'absent',
  body: 'none',
  headers: 'normal',
};

function render(row: Row): string {
  const lines = [`${row.method} ${row.target} HTTP/1.1`, `Host: ${HOSTS[row.host]}`];
  const credential = CREDENTIALS[row.credential];
  if (credential !== null) lines.push(`Authorization: ${credential}`);
  const origin = ORIGINS[row.origin];
  if (origin !== null) lines.push(`Origin: ${origin}`);
  const pad = HEADER_SIZES[row.headers];
  if (pad > 0) lines.push(`X-Pad: ${'F'.repeat(pad)}`);
  const size = BODIES[row.body];
  lines.push('Content-Type: application/json');
  lines.push(`Content-Length: ${size}`);
  // On EVERY row. It does not change any response this pipeline composes — §5
  // proves that directly against a row sent three ways — and it makes a
  // keep-alive answer settle on the socket's own close rather than on an idle
  // timer, which is what keeps two hundred requests inside two seconds.
  lines.push('Connection: close');
  return `${lines.join('\r\n')}\r\n\r\n${'A'.repeat(size)}`;
}

function describeRow(row: Row): string {
  return `${row.method} ${row.target} [cred=${row.credential} host=${row.host} origin=${row.origin} body=${row.body} headers=${row.headers}]`;
}

/**
 * The design blocks. Nothing here is chosen for its expected outcome.
 */
function enumerate(): readonly Row[] {
  const rows: Row[] = [BASELINE];

  // Block 1 — one factor at a time, every value of every dimension.
  for (const method of METHODS) rows.push({ ...BASELINE, method });
  for (const target of TARGETS) rows.push({ ...BASELINE, target });
  for (const credential of Object.keys(CREDENTIALS) as Array<keyof typeof CREDENTIALS>) {
    rows.push({ ...BASELINE, credential });
  }
  for (const host of Object.keys(HOSTS) as Array<keyof typeof HOSTS>) rows.push({ ...BASELINE, host });
  for (const origin of Object.keys(ORIGINS) as Array<keyof typeof ORIGINS>) {
    rows.push({ ...BASELINE, origin });
  }
  for (const body of Object.keys(BODIES) as Array<keyof typeof BODIES>) rows.push({ ...BASELINE, body });
  for (const headers of Object.keys(HEADER_SIZES) as Array<keyof typeof HEADER_SIZES>) {
    rows.push({ ...BASELINE, headers });
  }

  // Block 2 — method × target, the two dimensions the route/method ordering
  // couples.
  for (const method of METHODS) for (const target of TARGETS) rows.push({ ...BASELINE, method, target });

  // Block 3 — credential × target. Includes every probe target against every
  // way of getting authentication wrong, which is how "the probe branch runs
  // before authentication" becomes observable rather than asserted.
  for (const credential of Object.keys(CREDENTIALS) as Array<keyof typeof CREDENTIALS>) {
    for (const target of TARGETS) rows.push({ ...BASELINE, method: 'GET', credential, target });
  }

  // Block 4 — origin × target. FR-66 applies to the probes too, so this block
  // is where the probe rows that must NOT be served live.
  for (const origin of Object.keys(ORIGINS) as Array<keyof typeof ORIGINS>) {
    for (const target of TARGETS) rows.push({ ...BASELINE, method: 'GET', origin, target });
  }

  // Block 5 — host × body × header size, on the MCP endpoint. The body and
  // header dimensions are held to a non-probe target deliberately: an over-cap
  // body against a probe is answered before the body is read, and the RST that
  // follows can lose the response on the wire — a transport artefact, not a
  // uniformity fact.
  for (const host of Object.keys(HOSTS) as Array<keyof typeof HOSTS>) {
    for (const body of Object.keys(BODIES) as Array<keyof typeof BODIES>) {
      for (const headers of Object.keys(HEADER_SIZES) as Array<keyof typeof HEADER_SIZES>) {
        rows.push({ ...BASELINE, host, body, headers });
      }
    }
  }

  // Deduplicate on the RENDERED BYTES, so two blocks that happen to describe
  // the same request are one request on the wire.
  const seen = new Set<string>();
  return rows.filter((row) => {
    const key = render(row);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

type Outcome = 'uniform' | 'probe' | 'divergent';

/** What the pipeline's stated design says this row must produce. */
function expected(row: Row): Outcome {
  if (row.headers === 'overflow') return 'divergent';
  if (
    PROBE_TARGETS.has(row.target) &&
    (row.method === 'GET' || row.method === 'HEAD') &&
    row.origin === 'absent'
  ) {
    return 'probe';
  }
  return 'uniform';
}

/** What the BYTES say it produced. No row's expectation is consulted here. */
function classify(captured: Captured, reference: Captured): Outcome {
  if (Buffer.compare(captured.bytes, reference.bytes) === 0) return 'uniform';
  const body = bodyOf(captured);
  const probeBody = body === 'ok\n' || body === 'ready\n' || body === 'starting\n' || body === '';
  if (/^HTTP\/1\.1 (?:200|503) /.test(statusLine(captured)) && probeBody) return 'probe';
  return 'divergent';
}

// ---------------------------------------------------------------------------
// 1. The generated enumeration, and the closed exception set (AC 1, AC 2)
// ---------------------------------------------------------------------------

describe('US-27 §1: every well-formed unauthenticated request, enumerated', () => {
  test('AC 1 + AC 2: the divergent set is exactly the header-overflow preimage', async (t) => {
    const bound = await boundServer(t);
    const rows = enumerate();

    // The population is meaningful, and it covers every value of every
    // dimension. A future edit that quietly shrinks a dimension to one value
    // fails here rather than passing with less evidence.
    assert.ok(rows.length > 150, `the enumeration only produced ${rows.length} requests`);
    for (const [name, values] of [
      ['method', METHODS],
      ['target', TARGETS],
      ['credential', Object.keys(CREDENTIALS)],
      ['host', Object.keys(HOSTS)],
      ['origin', Object.keys(ORIGINS)],
      ['body', Object.keys(BODIES)],
      ['headers', Object.keys(HEADER_SIZES)],
    ] as ReadonlyArray<readonly [keyof Row, readonly string[]]>) {
      for (const value of values) {
        assert.ok(
          rows.some((row) => String(row[name]) === value),
          `the enumeration never exercised ${name}=${value}`,
        );
      }
    }

    // The reference, and its literal wire form. No `realm=`, no
    // `error="invalid_token"`, no CORS, no `Server`, no `Keep-Alive`, no `Vary`,
    // no `Transfer-Encoding`, and no `Date` — the last because Node adds it by
    // default and it changes every second, so without suppression this whole
    // comparison fails spuriously against a correct implementation.
    const reference = await exchange(bound.port, render(BASELINE));
    assert.equal(reference.text, UNIFORM_401_WIRE);
    assert.equal(bodyOf(reference).length, 24);

    const misclassified: string[] = [];
    const divergent: Array<readonly [Row, Captured]> = [];
    let throttled = 0;

    for (const row of rows) {
      const captured = await exchange(bound.port, render(row));
      assert.notEqual(captured.text, '', `${describeRow(row)} produced no response at all`);
      if (statusLine(captured).startsWith('HTTP/1.1 429')) throttled += 1;

      const observed = classify(captured, reference);
      if (observed !== expected(row)) {
        misclassified.push(
          `${describeRow(row)} — expected ${expected(row)}, observed ${observed}: ${statusLine(captured)}`,
        );
      }
      if (observed === 'divergent') divergent.push([row, captured] as const);
    }

    assert.deepEqual(
      misclassified,
      [],
      `rows did not behave as the pipeline's stated design requires:\n${misclassified.join('\n')}`,
    );

    // The exclusion of the throttle, verified rather than assumed.
    assert.equal(throttled, 0, 'the throttle fired inside the enumeration and confounded it');

    // THE CLOSURE STATEMENT, in three parts. Each is necessary:
    //   (a) every divergent row is a header-overflow row — nothing else diverges;
    //   (b) every header-overflow row is divergent — the preimage is complete,
    //       so the set cannot be trivially satisfied by a pipeline that stopped
    //       emitting 431s;
    //   (c) the divergent rows all carry ONE status line — a second divergence
    //       sharing the overflow dimension would still fail.
    const notOverflow = divergent
      .filter(([row]) => row.headers !== 'overflow')
      .map(([row, captured]) => `${describeRow(row)}: ${statusLine(captured)}`);
    assert.deepEqual(
      notOverflow,
      [],
      `the exception set is NOT closed — these diverge from the uniform 401 and are not header overflows:\n${notOverflow.join('\n')}`,
    );

    const overflowRows = rows.filter((row) => row.headers === 'overflow');
    assert.equal(
      divergent.length,
      overflowRows.length,
      'a header-overflow row did not diverge; the exception set is satisfied vacuously',
    );

    const statuses = [...new Set(divergent.map(([, captured]) => statusLine(captured)))].sort();
    assert.deepEqual(statuses, ['HTTP/1.1 431 Request Header Fields Too Large']);

    // The 431 is Node's parser answering before any application code runs, so
    // it must carry nothing of ours: not the product name, not the configured
    // cap, not one of the contract's eight error tokens.
    for (const [, captured] of divergent) {
      assert.equal(/unifi/i.test(captured.text), false, 'the 431 named this product');
      assert.equal(
        captured.text.includes(String(HEADER_CAP)),
        false,
        'the 431 disclosed the configured header cap',
      );
      assert.equal(/"error":/.test(captured.text), false, 'the 431 carried our error vocabulary');
    }
  });

  test('AC 2: the pre-application 431 produces no request log line', async (t) => {
    const bound = await boundServer(t);

    const before = bound.instruments.counts.requestLogs.length;
    for (let index = 0; index < 5; index += 1) {
      const overflow = await exchange(
        bound.port,
        render({ ...BASELINE, headers: 'overflow' }),
      );
      assert.match(statusLine(overflow), /^HTTP\/1\.1 431 /);
    }
    // Read immediately, before anything else is sent: the whole claim is that
    // the parser answered without application code running, so a later
    // request's line would mask it.
    assert.equal(
      bound.instruments.counts.requestLogs.length,
      before,
      'the pre-application 431 reached the request logger',
    );

    // …and the listener is still fully functional afterwards, so "no line"
    // is not "the server fell over".
    const after = await exchange(bound.port, render(BASELINE));
    assert.equal(after.text, UNIFORM_401_WIRE);
    assert.equal(bound.instruments.counts.requestLogs.length, before + 1);
  });
});

// ---------------------------------------------------------------------------
// 2. `HEAD` — the second divergence, and why it is not an oracle (AC 1)
// ---------------------------------------------------------------------------

describe('US-27 §2: a HEAD rejection is the uniform 401 with the body omitted', () => {
  test('every HEAD row is header-identical to the uniform 401 and carries no body', async (t) => {
    // FINDING, recorded here as a live assertion rather than in prose.
    //
    // Read literally, the criterion "the set whose bytes differ from the
    // uniform 401 is exactly {431 header-overflow}" is FALSE: `HEAD /mcp` from
    // a stranger differs too, because RFC 9110 forbids a body on a HEAD
    // response and `sendFixed` correctly omits it. US-22's own suite never sent
    // a HEAD to a non-probe path unauthenticated, so it never surfaced.
    //
    // It is not an oracle and the implementation is right: the caller CHOSE the
    // method, the status line and every header including `Content-Length: 24`
    // are byte-identical, and nothing about the server's internal shape is
    // recoverable from the absence of bytes the caller asked not to receive.
    // §1 therefore scopes its population to body-carrying methods and this
    // section pins the HEAD form EXACTLY, so the divergence cannot silently
    // widen into a second header set.
    const bound = await boundServer(t);

    for (const target of TARGETS) {
      const request = render({ ...BASELINE, method: 'GET', target })
        .replace('GET ', 'HEAD ');
      const captured = await exchange(bound.port, request);

      if (PROBE_TARGETS.has(target)) {
        assert.match(statusLine(captured), /^HTTP\/1\.1 (?:200|503) /, `HEAD ${target}`);
        assert.equal(bodyOf(captured), '', `HEAD ${target} returned a body`);
        continue;
      }
      assert.equal(captured.text, UNIFORM_401_HEAD_WIRE, `HEAD ${target} was not the uniform 401`);
      assert.equal(bodyOf(captured), '', `HEAD ${target} returned a body`);
      // The header block, byte for byte, is the one a GET would have received.
      assert.ok(UNIFORM_401_WIRE.startsWith(captured.text));
      assert.match(captured.text, /\r\nContent-Length: 24\r\n/);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Fail-closed at every seam, against every rejection class (AC 8)
// ---------------------------------------------------------------------------

/**
 * The seven unauthenticated classes, as raw requests.
 *
 * Re-derived from the dimensions rather than hand-written, so a fault sweep is
 * a sweep over the same population §1 enumerates.
 */
function rejectionClasses(): ReadonlyArray<readonly [string, string]> {
  const rows: ReadonlyArray<readonly [string, Row]> = [
    ['missing Authorization', BASELINE],
    ['wrong secret', { ...BASELINE, credential: 'wrong' }],
    ['malformed credential', { ...BASELINE, credential: 'basic-scheme' }],
    ['disallowed Host', { ...BASELINE, host: 'disallowed' }],
    ['any Origin', { ...BASELINE, origin: 'hostile' }],
    ['unknown path', { ...BASELINE, target: '/unknown' }],
    ['disallowed method', { ...BASELINE, method: 'PUT' }],
    ['over-cap body', { ...BASELINE, body: 'over-cap' }],
  ];
  return rows.map(([label, row]) => [label, render(row)] as const);
}

describe('US-27 §3: an injected fault at any pre-authentication seam is still the uniform 401', () => {
  /** Three flavours, because `catch {}` binds nothing and a non-Error must not escape it. */
  const FAULTS: ReadonlyArray<readonly [string, () => never]> = [
    ['Error', () => { throw new Error('injected fault'); }],
    ['bare string', () => { throw 'injected fault'; }],
    // The one that actually matters: `catch {}` binds nothing, so a thrown
    // `null` is indistinguishable from a thrown `Error` to the boundary — and
    // an implementation that "improved" the handler into
    // `catch (error) { if (error instanceof Error) … }` would fail open here.
    ['null', () => { throw null; }],
  ];

  const SEAMS = ['createRouteNormalizer', 'bearerMatches', 'hostAllowed', 'createTransport'] as const;

  function depsFor(seam: (typeof SEAMS)[number], boom: () => never): HttpServingDeps {
    switch (seam) {
      case 'createRouteNormalizer':
        return { createRouteNormalizer: () => boom };
      case 'bearerMatches':
        return { bearerMatches: boom };
      case 'hostAllowed':
        return { hostAllowed: boom };
      default:
        return { createTransport: boom };
    }
  }

  for (const seam of SEAMS) {
    test(`AC 8: a fault at ${seam} yields the byte-identical uniform 401 for every class`, async (t) => {
      for (const [flavour, boom] of FAULTS) {
        const bound = await boundServer(t, httpEnv(), depsFor(seam, boom));

        for (const [label, request] of rejectionClasses()) {
          const captured = await exchange(bound.port, request);
          // A 500 to an unauthenticated caller is instantly distinguishable
          // from the uniform 401 and is a class-detection oracle by another
          // route — which is the whole reason the boundary exists.
          assert.equal(
            captured.text,
            UNIFORM_401_WIRE,
            `${seam} / ${flavour} / ${label} did not fail closed`,
          );
          assert.equal(captured.closedByServer, true, `${seam} / ${label} left the socket open`);
          assert.equal(captured.text.includes('injected fault'), false);
          assert.equal(/Error|\.ts:|at \w+ \(/.test(bodyOf(captured)), false);
        }
      }
    });
  }

  test('AC 8: the log line for a faulted request is well formed and names no exception', async (t) => {
    // US-22 asserts the RESPONSE under fault injection. The operator's record
    // is the other output channel, and a caught exception reaching it would put
    // a stack trace — with source paths — into the same stream the per-request
    // lines go to.
    const bound = await boundServer(t, httpEnv(), {
      createRouteNormalizer: () => () => {
        throw new Error('injected fault carrying /secret/path.ts:42');
      },
    });

    await exchange(bound.port, render(BASELINE));

    const logs = bound.instruments.counts.requestLogs;
    assert.equal(logs.length, 1, `expected exactly one line, saw ${logs.length}`);
    assert.match(
      logs[0] as string,
      /^unifi-mcp: req method=\S+ path=\S+ status=401 dur_ms=\d+ auth=rejected reject_reason=auth writes=\S+ client=\S+$/,
    );
    assert.equal((logs[0] as string).includes('injected fault'), false);
    assert.equal((logs[0] as string).includes('.ts:'), false);
  });

  test('a fault raised by the diagnostic writer cannot corrupt the wire', async (t) => {
    // The emitter is the last thing in the rejection path, and in production it
    // is a write to `process.stderr` — a stream that can fail in a container
    // whose log collector went away. The response has already been flushed by
    // then, so the boundary's `res.headersSent` arm is what has to hold.
    //
    // The related gap this story reported as a finding — a throw raised BEFORE
    // the response is flushed, from inside `rejectUnauthenticated` itself,
    // escaping the fail-closed boundary because the catch handler called the
    // same emitter it was recovering with — is D-06, and it is FIXED. It is
    // asserted in §3b below rather than here, because it needs a fifth seam
    // (`createThrottle`, which is inside the catch handler's own emission) and
    // its observable is the absence of an unhandled rejection rather than the
    // bytes on the wire.
    let armed = false;
    const bound = await boundServer(t, httpEnv(), {
      warn: () => {
        if (armed) throw new Error('stderr went away');
      },
    });
    armed = true;

    for (const [label, request] of rejectionClasses()) {
      const captured = await exchange(bound.port, request);
      assert.equal(captured.text, UNIFORM_401_WIRE, `${label} was corrupted by the writer fault`);
      assert.equal(captured.closedByServer, true);
    }
    armed = false;
  });
});

// ---------------------------------------------------------------------------
// 3b. D-06 — the boundary's own emission is inside the boundary
// ---------------------------------------------------------------------------

/**
 * The fifth seam, and the one the four above could not reach.
 *
 * All four inject inside `runPipeline`, so the boundary catches the fault and
 * emits the uniform 401 from a healthy emitter. `createThrottle` is different:
 * `rejectUnauthenticated` calls `throttle.record` and `throttle.isThrottled`
 * BEFORE a byte is flushed, and the boundary's catch calls
 * `rejectUnauthenticated`. A throttle that throws therefore faults the pipeline
 * AND the recovery, which is the compound fault D-06 describes — and before the
 * fix the second throw escaped the `catch` into the fire-and-forget
 * `void (async …)()` wrapping it, becoming an unhandled rejection that Node
 * 20's default `--unhandled-rejections=throw` turns into process death, with
 * the caller's socket left open and zero bytes written.
 *
 * The observable is therefore not the wire — no response can be composed once
 * the emitter itself is broken — but the process surviving. Finding F-7 is why
 * this test exists at all: no test in the suite could reach `http.ts:1286-1288`.
 */
describe('US-27 §3b (D-06): the fail-closed boundary’s own emission cannot escape it', () => {
  test('a throttle that throws kills no process and leaves no socket hanging', async (t) => {
    const observed: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      observed.push(reason);
    };

    process.on('unhandledRejection', onUnhandled);
    try {
      const bound = await boundServer(t, httpEnv(), {
        createThrottle: () => ({
          record: () => {
            throw new Error('injected throttle fault');
          },
          isThrottled: () => {
            throw new Error('injected throttle fault');
          },
          size: () => 0,
        }),
      });

      for (const [label, request] of rejectionClasses()) {
        const captured = await exchange(bound.port, request);
        // Nothing is composed — the composer is what faulted — but the socket
        // is closed rather than held open forever on a response that can never
        // arrive, and no fragment of a response is emitted.
        assert.equal(captured.bytes.byteLength, 0, `${label} emitted bytes from a broken emitter`);
        assert.equal(captured.closedByServer, true, `${label} left the socket open`);
      }

      // Two turns of the microtask queue: an unhandled rejection is reported on
      // the tick AFTER the promise settles with no handler attached.
      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }

    assert.deepEqual(
      observed.map((reason) => (reason instanceof Error ? reason.message : String(reason))),
      [],
      'the boundary let its own fault escape into the fire-and-forget wrapper',
    );
  });
});

// ---------------------------------------------------------------------------
// 4. Post-response socket disposition (AC 1)
// ---------------------------------------------------------------------------

describe('US-27 §4: the socket disposition is part of the guarantee', () => {
  test('every uniform 401 closes the connection, and sends nothing after the body', async (t) => {
    const bound = await boundServer(t);

    for (const [label, request] of rejectionClasses()) {
      const captured = await exchange(bound.port, request, 400);
      assert.equal(captured.text, UNIFORM_401_WIRE, `${label}`);
      // Resetting for a large body and keeping alive for a small one would
      // reopen the leak one layer down, where TCP behaviour distinguishes the
      // two classes. The over-cap row is the one that would differ.
      assert.equal(captured.closedByServer, true, `${label} left the socket open`);
      // Exactly the response and nothing else: no trailing keep-alive probe, no
      // second frame, no stray bytes after the 24-byte body.
      assert.equal(
        captured.bytes.byteLength,
        Buffer.byteLength(UNIFORM_401_WIRE, 'latin1'),
        `${label} sent trailing bytes after the response`,
      );
    }
  });

  test('the caller’s connection preference is not a differential channel', async (t) => {
    const bound = await boundServer(t);

    // Three spellings of the same request. If the response varied with the
    // caller's `Connection` preference or protocol version, a stranger would
    // have a free bit — and every byte comparison in this file that adds
    // `Connection: close` for speed would be measuring something else.
    const withClose = await exchange(
      bound.port,
      `POST /mcp HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
    );
    const withKeepAlive = await exchange(
      bound.port,
      `POST /mcp HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n`,
    );
    const withNeither = await exchange(
      bound.port,
      `POST /mcp HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\nContent-Length: 0\r\n\r\n`,
    );
    const asHttp10 = await exchange(
      bound.port,
      `POST /mcp HTTP/1.0\r\nHost: ${ALLOWED_HOST}\r\nContent-Length: 0\r\n\r\n`,
    );

    for (const [label, captured] of [
      ['keep-alive', withKeepAlive],
      ['no Connection header', withNeither],
      ['HTTP/1.0', asHttp10],
    ] as ReadonlyArray<readonly [string, Captured]>) {
      assert.equal(
        Buffer.compare(captured.bytes, withClose.bytes),
        0,
        `the ${label} spelling produced different bytes`,
      );
      assert.equal(captured.closedByServer, withClose.closedByServer);
    }
    assert.equal(withClose.text, UNIFORM_401_WIRE);
  });
});

// ---------------------------------------------------------------------------
// 5. The parser's own population — outside the claim, and stated so (AC 2)
// ---------------------------------------------------------------------------

describe('US-27 §5: malformed HTTP is answered by the parser, and discloses nothing', () => {
  test('framing errors never name this product, its configuration or its vocabulary', async (t) => {
    const bound = await boundServer(t);
    const before = bound.instruments.counts.requestLogs.length;

    // Every one of these is answered before this application has a handler
    // frame on the stack, exactly as the 431 is. They are named and sent rather
    // than quietly excluded from §1: what CAN be claimed for them is weaker
    // than byte identity, and the weaker claim is worth asserting.
    const malformed: ReadonlyArray<readonly [string, string]> = [
      ['no Host on HTTP/1.1', 'GET /mcp HTTP/1.1\r\n\r\n'],
      ['unparseable version', `GET /mcp HTTP/9.9\r\nHost: ${ALLOWED_HOST}\r\n\r\n`],
      ['unparseable method token', `FR@B /mcp HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\n\r\n`],
      ['unregistered method', `FROB /mcp HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\n\r\n`],
      [
        'Transfer-Encoding and Content-Length together',
        `POST /mcp HTTP/1.1\r\nHost: ${ALLOWED_HOST}\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n`,
      ],
    ];

    for (const [label, request] of malformed) {
      const captured = await exchange(bound.port, request);
      assert.match(statusLine(captured), /^HTTP\/1\.1 4\d\d /, label);
      assert.equal(/unifi/i.test(captured.text), false, `${label} named this product`);
      assert.equal(captured.text.includes(SECRET), false, `${label} echoed the secret`);
      assert.equal(captured.text.includes(ALLOWED_HOST), false, `${label} echoed the allow-list`);
      assert.equal(captured.text.includes(String(BODY_CAP)), false, `${label} echoed a bound`);
      assert.equal(/"error":/.test(captured.text), false, `${label} used our error vocabulary`);
      assert.equal(captured.closedByServer, true, `${label} left the socket open`);
    }

    // And none of them reached the application at all, which is the fact that
    // puts them outside §1's population in the first place.
    assert.equal(
      bound.instruments.counts.requestLogs.length,
      before,
      'a framing error produced a request log line, so it DID reach the pipeline',
    );
  });
});

// ---------------------------------------------------------------------------
// 6. The whole-suite header sweep (C36)
// ---------------------------------------------------------------------------

after(() => {
  // Applied to every response this file captured — around five hundred of them
  // — rather than spot-checked. A spot check passes while some other branch
  // emits one.
  assert.ok(allResponses.length > 250, `the sweep only saw ${allResponses.length} responses`);
  for (const captured of allResponses) {
    assert.equal(CORS_HEADER.test(captured.text), false, `a response carried a CORS header:\n${captured.text}`);
    assert.equal(
      FINGERPRINT_HEADER.test(captured.text),
      false,
      `a response carried a product fingerprint header:\n${captured.text}`,
    );
  }
  // `Date` is suppressed by the pipeline at `res.sendDate = false`, and without
  // it no two responses captured a second apart are byte-identical. Node's own
  // parser-level errors are exempt: they are not composed by this pipeline, and
  // §5 covers what CAN be claimed for them.
  const ours = allResponses.filter((captured) => /"error":|^HTTP\/1\.1 (?:200|503) /m.test(captured.text));
  assert.ok(ours.length > 200, `only ${ours.length} responses came from the pipeline`);
  for (const captured of ours) {
    assert.equal(/\r\nDate:/i.test(captured.text), false, `a pipeline response carried a Date header`);
  }
});
