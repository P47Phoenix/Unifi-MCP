/**
 * The sanitised stderr emitter and the request-log composer (US-13).
 *
 * These are the US-13 acceptance criteria written as executable checks against
 * REAL emitted output — never against a claim about it. The suite proves the
 * eight-field grammar of NFR-24 (including AR-7's `draining` reason), that the
 * grammar regex is able to fail before it is trusted, that `path` is a route
 * label and never the attacker-controlled request target, the single
 * client-address normalisation, FR-63 probe suppression and throttled-source
 * suppression driven by an injected clock, that no interpolated value can forge
 * a request line, that no planted sentinel reaches the request-log channel, that
 * every byte lands on stderr and none on stdout, and that `src/serve/log.ts` is
 * the only module under `src/serve/` holding a stderr write.
 *
 * Output is read through the injected `write` sink. `process.stderr.write` is
 * never patched: that is a process-global mutation and a cross-test leak.
 */
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test, describe } from 'node:test';

import {
  LOG_PREFIX,
  MAX_TRACKED_THROTTLED_CLIENTS,
  PROBE_LOG_INTERVAL_MS,
  REQUEST_MARKER,
  composeRequestLine,
  createDiagnosticLogger,
  describeError,
  methodLabel,
  normalizeClientAddress,
  renderWriteSet,
  type DiagnosticLoggerDeps,
  type HttpMethodLabel,
  type RequestLogFields,
  type RouteLabel,
} from '../src/serve/log.js';
import type { ServiceId } from '../src/types.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The US-13 acceptance regex, verbatim. Anchored at both ends so an added field
 * fails. It is written for a SINGLE line: every use below splits the capture on
 * `\n` and matches per line, because copied onto a multi-line string it passes
 * or fails by accident.
 */
const REQUEST_LINE_RE =
  /^unifi-mcp: req method=(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|OTHER) path=(mcp|healthz|readyz|other) status=[0-9]{3} dur_ms=[0-9]+ auth=(ok|rejected) reject_reason=(-|auth|host|origin|path|method|body_size|rate_limit|session_limit|draining) writes=(none|(mobility|network|protect|site-manager)(,(mobility|network|protect|site-manager))*) client=(-|[^\s]+)$/;

const REQUEST_LINE_MARKER = `${LOG_PREFIX}${REQUEST_MARKER} `;

interface Recorder {
  /** Everything the emitter wrote, in order. */
  readonly lines: readonly string[];
  /** Only what reached the `ServingObserver.onRequestLog` seam. */
  readonly requestLines: readonly string[];
  /** The whole capture as one blob, exactly as an operator would see it. */
  capture(): string;
  /** The capture split per line — how the anchored regex must be applied. */
  splitLines(): readonly string[];
  advance(ms: number): void;
  readonly deps: DiagnosticLoggerDeps;
}

function createRecorder(): Recorder {
  const lines: string[] = [];
  const requestLines: string[] = [];
  let clockMs = 0;
  const capture = (): string => lines.join('\n');
  return {
    lines,
    requestLines,
    capture,
    splitLines: () => capture().split('\n').filter((line) => line.length > 0),
    advance: (ms) => {
      clockMs += ms;
    },
    deps: {
      write: (line) => {
        lines.push(line);
      },
      now: () => clockMs,
      onRequestLog: (line) => {
        requestLines.push(line);
      },
    },
  };
}

function fields(overrides: Partial<RequestLogFields> = {}): RequestLogFields {
  return {
    method: 'POST',
    route: 'mcp',
    status: 200,
    durationMs: 0,
    auth: 'ok',
    rejectReason: '-',
    writes: [],
    client: '10.42.0.7',
    ...overrides,
  };
}

function assertEveryLineMatchesGrammar(recorder: Recorder): void {
  for (const line of recorder.splitLines()) {
    if (!line.startsWith(REQUEST_LINE_MARKER)) continue;
    assert.match(line, REQUEST_LINE_RE, `line failed the US-13 grammar: ${line}`);
  }
}

describe('the eight-field request line (NFR-24, contract §4.2, §4.5)', () => {
  /** The contract's §4.5 worked examples, reproduced byte-for-byte. */
  const WORKED_EXAMPLES: ReadonlyArray<readonly [RequestLogFields, string]> = [
    [
      fields({ durationMs: 143 }),
      'unifi-mcp: req method=POST path=mcp status=200 dur_ms=143 auth=ok reject_reason=- writes=none client=10.42.0.7',
    ],
    [
      fields({ status: 403, durationMs: 1, rejectReason: 'host' }),
      'unifi-mcp: req method=POST path=mcp status=403 dur_ms=1 auth=ok reject_reason=host writes=none client=10.42.0.7',
    ],
    [
      fields({ status: 401, auth: 'rejected', rejectReason: 'host', client: '203.0.113.9' }),
      'unifi-mcp: req method=POST path=mcp status=401 dur_ms=0 auth=rejected reject_reason=host writes=none client=203.0.113.9',
    ],
    [
      fields({ method: 'GET', route: 'healthz', client: '10.42.0.1' }),
      'unifi-mcp: req method=GET path=healthz status=200 dur_ms=0 auth=ok reject_reason=- writes=none client=10.42.0.1',
    ],
    [
      fields({ durationMs: 891, writes: ['mobility', 'protect'] }),
      'unifi-mcp: req method=POST path=mcp status=200 dur_ms=891 auth=ok reject_reason=- writes=mobility,protect client=10.42.0.7',
    ],
    [
      fields({ status: 503, durationMs: 2, rejectReason: 'session_limit' }),
      'unifi-mcp: req method=POST path=mcp status=503 dur_ms=2 auth=ok reject_reason=session_limit writes=none client=10.42.0.7',
    ],
    [
      fields({ status: 429, auth: 'rejected', rejectReason: 'rate_limit', client: '203.0.113.9' }),
      'unifi-mcp: req method=POST path=mcp status=429 dur_ms=0 auth=rejected reject_reason=rate_limit writes=none client=203.0.113.9',
    ],
    [
      fields({ status: 401, auth: 'rejected', rejectReason: 'auth', client: '-' }),
      'unifi-mcp: req method=POST path=mcp status=401 dur_ms=0 auth=rejected reject_reason=auth writes=none client=-',
    ],
  ];

  test('reproduces every worked example byte-for-byte', () => {
    for (const [input, expected] of WORKED_EXAMPLES) {
      assert.equal(composeRequestLine(input), expected);
    }
  });

  test('every worked example passes the US-13 grammar, matched per line', () => {
    // The capture is multi-line; the regex is anchored for one line. Split
    // first, or the assertion passes or fails by accident.
    const capture = WORKED_EXAMPLES.map(([input]) => composeRequestLine(input)).join('\n');
    const lines = capture.split('\n');
    assert.equal(lines.length, WORKED_EXAMPLES.length);
    for (const line of lines) assert.match(line, REQUEST_LINE_RE);
  });

  test('the grammar regex is able to fail: a ninth field is rejected', () => {
    const [first] = WORKED_EXAMPLES;
    assert.ok(first !== undefined);
    const nineFields = `${composeRequestLine(first[0])} session=abc`;
    assert.equal(REQUEST_LINE_RE.test(nineFields), false);
  });

  test('the grammar regex is able to fail: a dropped writes= field is rejected', () => {
    // The named implementer mistake: omitting `writes=` on a rejection path and
    // shipping a seven-field line.
    const rejection = composeRequestLine(
      fields({ status: 403, auth: 'rejected', rejectReason: 'host' }),
    );
    const sevenFields = rejection.replace(' writes=none', '');
    assert.equal(sevenFields.split(' ').length, rejection.split(' ').length - 1);
    assert.equal(REQUEST_LINE_RE.test(sevenFields), false);
  });

  test('an emitted rejection line still carries all eight fields', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    for (const reason of ['auth', 'host', 'origin', 'path', 'method', 'body_size', 'draining'] as const) {
      logger.logRequest(
        fields({ status: 403, auth: 'rejected', rejectReason: reason, client: '203.0.113.9' }),
      );
    }
    assert.equal(recorder.lines.length, 7);
    for (const line of recorder.splitLines()) {
      const body = line.slice(REQUEST_LINE_MARKER.length);
      // The `unifi-mcp: req ` marker is not a field.
      assert.equal(body.split(' ').length, 8, `not eight fields: ${line}`);
    }
    assertEveryLineMatchesGrammar(recorder);
  });

  test('draining renders and passes the grammar (AR-7)', () => {
    // Distinguishes a rolling deploy from a capacity incident. AR-7 amended the
    // reason set after the contract's §4.2 regex copy was written.
    const line = composeRequestLine(fields({ status: 503, rejectReason: 'draining' }));
    assert.equal(
      line,
      'unifi-mcp: req method=POST path=mcp status=503 dur_ms=0 auth=ok reject_reason=draining writes=none client=10.42.0.7',
    );
    assert.match(line, REQUEST_LINE_RE);
  });

  test('coerces a programmer-error status and duration into the grammar', () => {
    const line = composeRequestLine(fields({ status: 12, durationMs: -5 }));
    assert.match(line, REQUEST_LINE_RE);
    assert.match(line, / status=500 dur_ms=0 /);
    assert.match(composeRequestLine(fields({ durationMs: 1.9 })), / dur_ms=1 /);
    assert.match(composeRequestLine(fields({ durationMs: Number.NaN })), / dur_ms=0 /);
  });
});

describe('method is a closed vocabulary (contract §4.2)', () => {
  test('renders each of the seven known verbs unchanged', () => {
    const known: readonly HttpMethodLabel[] = [
      'GET',
      'HEAD',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS',
    ];
    for (const verb of known) {
      assert.equal(methodLabel(verb), verb);
      assert.match(composeRequestLine(fields({ method: verb })), REQUEST_LINE_RE);
    }
  });

  test('every hostile or unknown method renders OTHER', () => {
    // A caller must not be able to inject a token of their choosing by choosing
    // the verb they send.
    const hostile = [
      'FOO',
      'post',
      'GET\nunifi-mcp: req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=1.2.3.4',
      '',
      'GET ',
      undefined,
    ];
    for (const raw of hostile) {
      assert.equal(methodLabel(raw), 'OTHER', `expected OTHER for ${JSON.stringify(raw)}`);
    }
  });

  test('an injected method cannot forge a second line', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    const injected =
      'GET\nunifi-mcp: req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=1.2.3.4';
    logger.logRequest(fields({ method: methodLabel(injected) }));
    assert.equal(recorder.splitLines().length, 1);
    assert.match(recorder.capture(), / method=OTHER /);
    assert.equal(recorder.capture().includes('client=1.2.3.4'), false);
  });
});

describe('path is a route label and never the request target (contract §4.3)', () => {
  test('the label domain is exactly four values', () => {
    const routes: readonly RouteLabel[] = ['mcp', 'healthz', 'readyz', 'other'];
    for (const route of routes) {
      assert.match(composeRequestLine(fields({ route })), new RegExp(` path=${route} `));
    }
  });

  test('the API has no parameter that accepts a request target', () => {
    // Structural: `RouteLabel` is a four-member union, so a request target is
    // not an expressible argument. The runtime guard below is the backstop for
    // untyped callers at the transport boundary.
    const hostileTarget =
      '/mcp?x=1\nunifi-mcp: req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=9.9.9.9';
    const line = composeRequestLine(fields({ route: hostileTarget as RouteLabel }));
    assert.match(line, / path=other /);
    assert.match(line, REQUEST_LINE_RE);
    assert.equal(line.includes('\n'), false);
    assert.equal(line.includes('9.9.9.9'), false);
  });

  test('a crafted target containing a newline appears in no emitted line', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.logRequest(fields({ route: '/../../etc/passwd\nforged' as RouteLabel }));
    assert.equal(recorder.capture().includes('passwd'), false);
    assert.equal(recorder.splitLines().length, 1);
    assertEveryLineMatchesGrammar(recorder);
  });
});

describe('the writes field (contract §0.1.3)', () => {
  test('an empty effective set renders none', () => {
    assert.equal(renderWriteSet([]), 'none');
  });

  test('renders alphabetically ascending, never declaration order', () => {
    assert.equal(renderWriteSet(['protect', 'mobility']), 'mobility,protect');
    assert.equal(renderWriteSet(['site-manager', 'network']), 'network,site-manager');
  });

  test('renders the full four-service set', () => {
    assert.equal(
      renderWriteSet(['protect', 'site-manager', 'mobility', 'network']),
      'mobility,network,protect,site-manager',
    );
    assert.match(
      composeRequestLine(fields({ writes: ['protect', 'site-manager', 'mobility', 'network'] })),
      REQUEST_LINE_RE,
    );
  });

  test('collapses duplicates', () => {
    assert.equal(renderWriteSet(['protect', 'protect', 'mobility', 'protect']), 'mobility,protect');
  });

  test('never renders the literal all, even when handed it', () => {
    // `all` is accepted INPUT syntax elsewhere; every output renders the
    // resolved set explicitly, or `none` when it is empty.
    assert.equal(renderWriteSet(['all' as ServiceId]), 'none');
    assert.equal(renderWriteSet(['all' as ServiceId, 'network']), 'network');
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.logRequest(fields({ writes: ['all' as ServiceId, 'protect', 'mobility'] }));
    assert.equal(/writes=all\b/.test(recorder.capture()), false);
    assert.match(recorder.capture(), / writes=mobility,protect /);
    assertEveryLineMatchesGrammar(recorder);
  });

  test('the separator is a comma with no space, because a space is the field separator', () => {
    const line = composeRequestLine(fields({ writes: ['mobility', 'protect'] }));
    assert.equal(line.slice(REQUEST_LINE_MARKER.length).split(' ').length, 8);
  });
});

describe('client-address normalisation (contract §0.1.2)', () => {
  test('renders an IPv4-mapped IPv6 address in its IPv4 form', () => {
    assert.equal(normalizeClientAddress('::ffff:10.42.0.7'), '10.42.0.7');
  });

  test('handles the hex spelling of the same mapped address', () => {
    assert.equal(normalizeClientAddress('::ffff:0a2a:0007'), '10.42.0.7');
    assert.equal(normalizeClientAddress('::FFFF:0A2A:0007'), '10.42.0.7');
  });

  test('lower-cases an IPv6 address and leaves it otherwise verbatim', () => {
    assert.equal(normalizeClientAddress('2001:DB8::1'), '2001:db8::1');
    assert.equal(normalizeClientAddress('::1'), '::1');
  });

  test('preserves the zone suffix of a link-local address', () => {
    // The zone names the interface the traffic arrived on — operationally
    // load-bearing when several interfaces carry the same link-local prefix.
    assert.equal(normalizeClientAddress('fe80::1%eth0'), 'fe80::1%eth0');
  });

  test('strips brackets and a port', () => {
    assert.equal(normalizeClientAddress('[2001:db8::1]'), '2001:db8::1');
    assert.equal(normalizeClientAddress('[2001:db8::1]:443'), '2001:db8::1');
    assert.equal(normalizeClientAddress('10.42.0.7:54321'), '10.42.0.7');
  });

  test('renders - when the address is unavailable', () => {
    // Attacker-inducible: send a request and reset the socket before the
    // handler reads remoteAddress. `-` is a member of the field's domain.
    assert.equal(normalizeClientAddress(undefined), '-');
    assert.equal(normalizeClientAddress(null), '-');
    assert.equal(normalizeClientAddress(''), '-');
  });

  test('renders - for anything that would break the grammar', () => {
    const hostile = [
      '10.0.0.1 extra',
      '10.0.0.1\nunifi-mcp: req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=1.2.3.4',
      '10.0.0.1\tx',
      '10.0.0.1 ',
      '   ',
    ];
    for (const raw of hostile) {
      assert.equal(normalizeClientAddress(raw), '-', `expected - for ${JSON.stringify(raw)}`);
    }
  });

  test('a hostile client value cannot split one emitted line into two', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.logRequest(
      fields({
        client: normalizeClientAddress(
          '10.0.0.1\nunifi-mcp: req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=1.2.3.4',
        ),
      }),
    );
    assert.equal(recorder.splitLines().length, 1);
    assert.match(recorder.capture(), / client=-$/);
    assertEveryLineMatchesGrammar(recorder);
  });
});

describe('probe-log suppression (FR-63, contract §4.8)', () => {
  test('logs the first request on each probe route after startup', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    assert.equal(logger.logRequest(fields({ method: 'GET', route: 'healthz' })), true);
    assert.equal(logger.logRequest(fields({ method: 'GET', route: 'readyz' })), true);
    assert.equal(recorder.lines.length, 2);
    assertEveryLineMatchesGrammar(recorder);
  });

  test('suppresses a second probe within the interval and logs one after it', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    const probe = fields({ method: 'GET', route: 'healthz', client: '10.42.0.1' });

    assert.equal(logger.logRequest(probe), true);
    recorder.advance(PROBE_LOG_INTERVAL_MS - 1);
    assert.equal(logger.logRequest(probe), false);
    recorder.advance(1);
    assert.equal(logger.logRequest(probe), true);
    assert.equal(recorder.lines.length, 2);
  });

  test('the two probe routes suppress independently', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    const healthz = fields({ method: 'GET', route: 'healthz' });
    const readyz = fields({ method: 'GET', route: 'readyz' });

    assert.equal(logger.logRequest(healthz), true);
    assert.equal(logger.logRequest(readyz), true);
    recorder.advance(1);
    // Liveness traffic must not be able to hide a readiness line.
    assert.equal(logger.logRequest(healthz), false);
    assert.equal(logger.logRequest(readyz), false);
    assert.equal(recorder.lines.length, 2);
  });

  test('a probe that changes the response state is always logged', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    const readyz = fields({ method: 'GET', route: 'readyz' });

    assert.equal(logger.logRequest(readyz), true); // starting
    recorder.advance(5);
    assert.equal(logger.logRequest(readyz), false); // suppressed inside the interval
    // starting -> ready, inside the same interval.
    assert.equal(logger.logRequest(readyz, { probeStateChanged: true }), true);
    recorder.advance(5);
    // ready -> draining, still inside an interval.
    assert.equal(
      logger.logRequest(fields({ method: 'GET', route: 'readyz', status: 503, rejectReason: 'draining' }), {
        probeStateChanged: true,
      }),
      true,
    );
    assert.equal(recorder.lines.length, 3);
    assertEveryLineMatchesGrammar(recorder);
  });

  test('suppression floods only the probe routes: 1000 mcp requests emit 1000 lines', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    for (let index = 0; index < 1000; index += 1) {
      assert.equal(logger.logRequest(fields({ durationMs: index })), true);
    }
    assert.equal(recorder.lines.length, 1000);
    assert.equal(recorder.requestLines.length, 1000);
  });
});

describe('throttled-source suppression (contract §4.5)', () => {
  const throttled = (client: string): RequestLogFields =>
    fields({ status: 429, auth: 'rejected', rejectReason: 'rate_limit', client });

  test('emits one line at the moment a source enters the throttled state', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);

    assert.equal(logger.logRequest(throttled('203.0.113.9')), true);
    for (let index = 0; index < 10_000; index += 1) {
      assert.equal(logger.logRequest(throttled('203.0.113.9')), false);
    }
    assert.equal(recorder.lines.length, 1);
    assertEveryLineMatchesGrammar(recorder);
  });

  test('a different source gets its own state-entry line', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    assert.equal(logger.logRequest(throttled('203.0.113.9')), true);
    assert.equal(logger.logRequest(throttled('203.0.113.10')), true);
    assert.equal(logger.logRequest(throttled('203.0.113.9')), false);
    assert.equal(recorder.lines.length, 2);
  });

  test('a non-throttled line from that source clears the state, so re-entry logs again', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    assert.equal(logger.logRequest(throttled('203.0.113.9')), true);
    assert.equal(logger.logRequest(throttled('203.0.113.9')), false);
    assert.equal(logger.logRequest(fields({ client: '203.0.113.9' })), true);
    assert.equal(logger.logRequest(throttled('203.0.113.9')), true);
    assert.equal(recorder.lines.length, 3);
  });

  test('client=- is never suppressed, because it is not an identity', () => {
    // Collapsing every address-unavailable source into one state would let a
    // single attacker's entry silence the first throttle line of every other
    // anonymous source.
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    for (let index = 0; index < 5; index += 1) {
      assert.equal(logger.logRequest(throttled('-')), true);
    }
    assert.equal(recorder.lines.length, 5);
    assertEveryLineMatchesGrammar(recorder);
  });

  test('the tracker is bounded and evicts oldest-first', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    const source = (index: number): string => `10.0.${Math.floor(index / 256)}.${index % 256}`;

    for (let index = 0; index < MAX_TRACKED_THROTTLED_CLIENTS; index += 1) {
      assert.equal(logger.logRequest(throttled(source(index))), true);
    }
    // The tracker is full; the newest source is still tracked.
    assert.equal(logger.logRequest(throttled(source(MAX_TRACKED_THROTTLED_CLIENTS - 1))), false);

    // One more source evicts the oldest, which therefore logs again — the
    // documented cost of bounding the tracker.
    assert.equal(logger.logRequest(throttled(source(MAX_TRACKED_THROTTLED_CLIENTS))), true);
    assert.equal(logger.logRequest(throttled(source(0))), true);
    assertEveryLineMatchesGrammar(recorder);
  });
});

describe('the single sanitised emitter (contract §2.2, architecture §1.2, §5.8)', () => {
  const FORGERY =
    '\n unifi-mcp: req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=1.2.3.4';

  function forgedRequestLines(recorder: Recorder): readonly string[] {
    return recorder.splitLines().filter((line) => line.startsWith(REQUEST_LINE_MARKER));
  }

  test('emitDiagnostic writes exactly one line and forges no request line', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.emitDiagnostic(`listener bound${FORGERY}`);
    assert.equal(recorder.lines.length, 1);
    assert.equal(recorder.splitLines().length, 1);
    assert.equal(forgedRequestLines(recorder).length, 0);
    assert.equal(recorder.capture().includes('client=1.2.3.4'), true, 'the text is echoed…');
    assert.equal(recorder.capture().includes('\n'), false, '…but on one line');
  });

  test('a diagnostic body that begins with the reserved marker cannot pose as a request line', () => {
    // The newline injection arrived at from the other side: a fully
    // caller-controlled message starting `req method=…` would otherwise render
    // as a syntactically perfect request line with no request behind it.
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.emitDiagnostic(
      'req method=POST path=mcp status=200 dur_ms=1 auth=ok reject_reason=- writes=none client=1.2.3.4',
    );
    assert.equal(recorder.lines.length, 1);
    assert.equal(forgedRequestLines(recorder).length, 0);
    assert.match(recorder.capture(), /^unifi-mcp: «reserved» req /);
  });

  test('emitError sanitises an exception message carrying an injection', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.emitError('request boundary', new Error(`upstream refused${FORGERY}`));
    assert.equal(recorder.lines.length, 1);
    assert.equal(recorder.splitLines().length, 1);
    assert.equal(forgedRequestLines(recorder).length, 0);
    assert.match(recorder.capture(), /^unifi-mcp: request boundary — upstream refused/);
  });

  test('emitError handles a thrown string and a thrown object', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.emitError('fatal', `boom${FORGERY}`);
    logger.emitError('fatal', { detail: 'an object nobody should stringify' });
    logger.emitError('fatal', null);
    assert.equal(recorder.lines.length, 3);
    assert.equal(recorder.splitLines().length, 3);
    assert.equal(forgedRequestLines(recorder).length, 0);
    // A thrown object is described by shape, never by content: stringifying it
    // is how a body or a header ends up in the log stream.
    assert.equal(recorder.capture().includes('nobody should stringify'), false);
    assert.match(recorder.capture(), /non-error thrown \(object\)/);
    assert.match(recorder.capture(), /unspecified error/);
  });

  test('no stack frame, exception class, or source path reaches the output', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    class UpstreamTimeoutError extends Error {}
    logger.emitError('request boundary', new UpstreamTimeoutError('deadline exceeded'));
    const capture = recorder.capture();
    assert.equal(/\bat /.test(capture), false, 'a stack frame reached the log');
    assert.equal(capture.includes('.ts:'), false, 'a source path reached the log');
    assert.equal(capture.includes('UpstreamTimeoutError'), false, 'the class name reached the log');
    assert.equal(capture, 'unifi-mcp: request boundary — deadline exceeded');
  });

  test('describeError never returns a multi-line string', () => {
    for (const thrown of [new Error(FORGERY), FORGERY, 42, false, undefined, {}]) {
      assert.equal(describeError(thrown).includes('\n'), false);
      assert.equal(describeError(thrown).length > 0, true);
    }
  });
});

describe('nothing that must never be logged can reach the line (US-13, contract §4.5)', () => {
  const SENTINEL_SCAN = /SENTINEL-[A-Z-]+-[0-9a-f]{16}/g;
  const INBOUND_TOKEN = 'SENTINEL-INBOUND-TOKEN-0123456789abcdef';
  const SESSION_ID = 'SENTINEL-SESSION-ID-fedcba9876543210';
  const REQUEST_BODY = 'SENTINEL-REQUEST-BODY-00112233445566aa';
  const TOOL_RESULT = 'SENTINEL-TOOL-RESULT-99887766554433bb';

  function assertNoSentinel(capture: string): void {
    const found = capture.match(SENTINEL_SCAN);
    assert.equal(found, null, `sentinel reached the log: ${found?.join(', ') ?? ''}`);
  }

  test('the sentinel scan is able to fail (H-SS-5)', () => {
    // Prove the detector before trusting a clean result from it.
    assert.throws(
      () => assertNoSentinel(`unifi-mcp: req … client=${INBOUND_TOKEN}`),
      /sentinel reached the log/,
    );
    assertNoSentinel('unifi-mcp: req method=GET path=mcp status=200 dur_ms=0');
  });

  test('no public parameter of the request log can carry a token, header, session id, body, or tool result', () => {
    // This is the structural property under test: the eight fields are
    // `auth` (a two-valued enum, not a credential), `body_size` (a reason, never
    // a length), `status` (the HTTP status, never the tool outcome), and five
    // closed vocabularies. `client` is a socket peer address supplied by the
    // kernel. There is no parameter through which a secret could arrive.
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);

    const smuggled = {
      ...fields({ status: 413, auth: 'rejected', rejectReason: 'body_size' }),
      authorization: `Bearer ${INBOUND_TOKEN}`,
      sessionId: SESSION_ID,
      body: REQUEST_BODY,
      toolResult: TOOL_RESULT,
    } as RequestLogFields;

    logger.logRequest(smuggled);

    assert.equal(recorder.lines.length, 1);
    assertNoSentinel(recorder.capture());
    for (const planted of [INBOUND_TOKEN, SESSION_ID, REQUEST_BODY, TOOL_RESULT]) {
      assert.equal(recorder.capture().includes(planted), false, `${planted} was echoed`);
    }
    assertEveryLineMatchesGrammar(recorder);
  });

  test('sentinels pushed through every string entry point never reach the request-log channel', () => {
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);

    // Every entry point on the request path that accepts a string.
    const method = methodLabel(`GET ${INBOUND_TOKEN}`);
    const client = normalizeClientAddress(`10.0.0.1 ${SESSION_ID}`);
    assert.equal(method, 'OTHER');
    assert.equal(client, '-');

    logger.logRequest(fields({ method, client }));
    logger.logRequest(fields({ route: SESSION_ID as RouteLabel }));
    logger.logRequest(fields({ writes: [TOOL_RESULT as ServiceId] }));

    // emitDiagnostic legitimately echoes its argument — its contract is that the
    // caller passes no secret, and it defangs whatever it is given. The property
    // asserted here is the honest one: the request-log channel stays clean.
    logger.emitError('request boundary', new Error(`upstream said ${REQUEST_BODY}`));

    assertNoSentinel(recorder.requestLines.join('\n'));
    assert.equal(recorder.requestLines.length, 3);
    for (const line of recorder.requestLines) assert.match(line, REQUEST_LINE_RE);
  });

  test('emitDiagnostic defangs but does not redact — that is the caller contract', () => {
    // Stated as a test so the boundary is not mistaken for a filter: the module
    // guarantees single-line, control-character-free output, not secret
    // detection. Nothing on the request path passes a credential to it.
    const recorder = createRecorder();
    const logger = createDiagnosticLogger(recorder.deps);
    logger.emitDiagnostic(`config loaded ${INBOUND_TOKEN}`);
    assert.equal(recorder.capture().includes(INBOUND_TOKEN), true);
    assert.equal(recorder.requestLines.length, 0);
    assertNoSentinel(recorder.requestLines.join('\n'));
  });
});

describe('every byte goes to stderr (contract §4.7, NFR-19 as replaced by E-21)', () => {
  test('a child process writes the lines to stderr and nothing to stdout', () => {
    // Proven end-to-end in a child rather than by patching process.stderr.write,
    // which is a process-global mutation and a cross-test leak. On HTTP stdout
    // is technically free, and diagnostics still go to stderr, so that no code
    // path can acquire a stray stdout write that would corrupt a stdio session
    // when the transport is switched back.
    const moduleUrl = pathToFileURL(join(REPO_ROOT, 'src', 'serve', 'log.ts')).href;
    const script = [
      `import { emitDiagnostic, createDiagnosticLogger } from ${JSON.stringify(moduleUrl)};`,
      "emitDiagnostic('child diagnostic line');",
      'const logger = createDiagnosticLogger();',
      "logger.logRequest({ method: 'POST', route: 'mcp', status: 200, durationMs: 143,",
      "  auth: 'ok', rejectReason: '-', writes: [], client: '10.42.0.7' });",
    ].join('\n');

    const child = spawnSync(
      process.execPath,
      ['--import', 'tsx', '--input-type=module', '-e', script],
      { cwd: REPO_ROOT, encoding: 'utf8', shell: false },
    );

    assert.equal(child.error, undefined);
    assert.equal(child.status, 0, `child failed: ${child.stderr}`);
    assert.equal(child.stdout, '', `stdout was not empty: ${JSON.stringify(child.stdout)}`);

    // Tolerate CRLF: the child's stream is not opened in binary mode on Windows.
    const stderrLines = child.stderr.split(/\r?\n/).filter((line) => line.length > 0);
    assert.ok(stderrLines.includes('unifi-mcp: child diagnostic line'), child.stderr);
    const requestLine = stderrLines.find((line) => line.startsWith(REQUEST_LINE_MARKER));
    assert.ok(requestLine !== undefined, child.stderr);
    assert.match(requestLine, REQUEST_LINE_RE);
  });
});

describe('log.ts is the only stderr writer under src/serve (architecture §1.2)', () => {
  function listTypeScriptFiles(directory: string): readonly string[] {
    const found: string[] = [];
    for (const entry of readdirSync(directory)) {
      const full = join(directory, entry);
      if (statSync(full).isDirectory()) found.push(...listTypeScriptFiles(full));
      else if (entry.endsWith('.ts')) found.push(full);
    }
    return found;
  }

  test('exactly one file under src/serve writes to a standard stream', () => {
    // Scoped to src/serve deliberately. `src/index.ts` still holds its own
    // process.stderr.write; migrating it onto emitDiagnostic is US-18's
    // obligation, and asserting on it here would red the suite for work another
    // story owns.
    const serveDir = join(REPO_ROOT, 'src', 'serve');
    const files = listTypeScriptFiles(serveDir);
    assert.ok(files.length > 0, 'no sources found under src/serve');

    const writers = files.filter((file) => {
      const source = readFileSync(file, 'utf8');
      return source.includes('process.stderr.write') || /\bconsole\s*\./.test(source);
    });

    assert.deepEqual(
      writers.map((file) => file.slice(serveDir.length + 1)),
      ['log.ts'],
    );
  });

  test('log.ts holds a single stderr write', () => {
    const source = readFileSync(join(REPO_ROOT, 'src', 'serve', 'log.ts'), 'utf8');
    const occurrences = source.split('process.stderr.write').length - 1;
    assert.equal(occurrences, 1);
  });
});
