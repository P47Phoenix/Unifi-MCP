/**
 * Liveness and readiness probe tests (FR-67, FR-68, FR-69, NFR-25, NFR-17).
 *
 * No server is started and no socket is opened: the probe handlers write to a
 * recording stand-in for ServerResponse, which is the whole point of keeping
 * them in a leaf module. The final suite is the structural one — it reads
 * src/serve/health.ts off disk and asserts its import list is closed, because
 * "readiness never touches credentials or the vendor API" is enforced by the
 * module graph rather than by review.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import type { OutgoingHttpHeaders, ServerResponse } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import {
  createReadinessState,
  handleHealthz,
  handleProbe,
  handleReadyz,
  type Phase,
  type ProbeKind,
  type ProbeMethod,
} from '../src/serve/health.js';

const PHASES: readonly Phase[] = ['starting', 'ready', 'draining'];
const METHODS: readonly ProbeMethod[] = ['GET', 'HEAD'];
const PROBES: readonly ProbeKind[] = ['healthz', 'readyz'];

const REQUIRED_HEADERS = ['cache-control', 'content-length', 'content-type', 'x-content-type-options'];

/** The complete set of bytes either probe is ever allowed to emit. */
const ALLOWED_BODIES = ['ok\n', 'starting\n', 'ready\n', 'draining\n'];

interface Recorder {
  readonly res: ServerResponse;
  status(): number | undefined;
  headers(): Record<string, string>;
  body(): Buffer;
  ended(): boolean;
}

/**
 * A ServerResponse stand-in recording exactly what a handler wrote. Header
 * names are lower-cased on the way in so assertions do not depend on the
 * casing the handler happens to use.
 */
function recorder(): Recorder {
  let status: number | undefined;
  let sent = false;
  let done = false;
  const seen: Record<string, string> = {};
  const chunks: Buffer[] = [];

  const fake = {
    get headersSent() {
      return sent;
    },
    writeHead(code: number, headers?: OutgoingHttpHeaders) {
      status = code;
      sent = true;
      for (const [name, value] of Object.entries(headers ?? {})) {
        seen[name.toLowerCase()] = String(value);
      }
      return fake;
    },
    end(chunk?: Buffer) {
      if (chunk !== undefined) chunks.push(chunk);
      done = true;
      return fake;
    },
  };

  return {
    res: fake as unknown as ServerResponse,
    status: () => status,
    headers: () => ({ ...seen }),
    body: () => Buffer.concat(chunks),
    ended: () => done,
  };
}

function probe(kind: ProbeKind, method: ProbeMethod, phase: Phase): Recorder {
  const rec = recorder();
  handleProbe(kind, method, rec.res, { phase });
  return rec;
}

describe('liveness (FR-68)', () => {
  test('answers 200 with the bytes "ok\\n" in every phase', () => {
    for (const phase of PHASES) {
      const rec = probe('healthz', 'GET', phase);
      assert.equal(rec.status(), 200, `status flipped in ${phase}`);
      assert.deepEqual(rec.body(), Buffer.from('ok\n', 'utf8'), `body changed in ${phase}`);
      assert.ok(rec.ended());
    }
  });

  test('emits byte-identical responses across the three phases', () => {
    const [starting, ready, draining] = PHASES.map((phase) => probe('healthz', 'GET', phase));
    assert.ok(starting && ready && draining);
    assert.equal(starting.body().equals(ready.body()), true);
    assert.equal(ready.body().equals(draining.body()), true);
    assert.deepEqual(starting.headers(), draining.headers());
    assert.equal(starting.status(), draining.status());
  });

  test('takes no occupancy input and is byte-identical over 100 probes', () => {
    // Asserting "0, 1 and 32 sessions all return ok" is unexpressible here by
    // construction: the handler has no parameter to put a session count in.
    // That absence is the assertion — arity 2 is (res, method) and nothing else.
    assert.equal(handleHealthz.length, 2);
    assert.equal(handleReadyz.length, 3);

    const expected = probe('healthz', 'GET', 'ready');
    for (let i = 0; i < 100; i += 1) {
      const rec = probe('healthz', 'GET', 'ready');
      assert.equal(rec.body().equals(expected.body()), true, `probe ${i} differed`);
      assert.equal(rec.status(), expected.status());
      assert.deepEqual(rec.headers(), expected.headers());
    }
  });
});

describe('readiness (FR-69, NFR-25)', () => {
  test('starting returns 503 "starting\\n"', () => {
    const rec = probe('readyz', 'GET', 'starting');
    assert.equal(rec.status(), 503);
    assert.deepEqual(rec.body(), Buffer.from('starting\n', 'utf8'));
  });

  test('ready returns 200 "ready\\n"', () => {
    const rec = probe('readyz', 'GET', 'ready');
    assert.equal(rec.status(), 200);
    assert.deepEqual(rec.body(), Buffer.from('ready\n', 'utf8'));
  });

  test('draining returns 503 "draining\\n"', () => {
    const rec = probe('readyz', 'GET', 'draining');
    assert.equal(rec.status(), 503);
    assert.deepEqual(rec.body(), Buffer.from('draining\n', 'utf8'));
  });

  test('a fresh state starts in "starting"', () => {
    assert.equal(createReadinessState().phase, 'starting');
  });

  test('answers from the state object it is handed, not a module global', () => {
    // Two transports in one process must not share a phase, so the phase cell
    // is created per transport and passed in.
    const first = createReadinessState();
    const second = createReadinessState();
    first.phase = 'ready';
    assert.equal(second.phase, 'starting');

    const firstRec = recorder();
    const secondRec = recorder();
    handleReadyz(firstRec.res, 'GET', first);
    handleReadyz(secondRec.res, 'GET', second);
    assert.equal(firstRec.status(), 200);
    assert.equal(secondRec.status(), 503);
    assert.deepEqual(secondRec.body(), Buffer.from('starting\n', 'utf8'));
  });

  test('100 sequential probes are byte-identical and mutate nothing', () => {
    const state = createReadinessState();
    state.phase = 'ready';
    const expected = { status: 200, body: Buffer.from('ready\n', 'utf8') };
    for (let i = 0; i < 100; i += 1) {
      const rec = recorder();
      handleReadyz(rec.res, 'GET', state);
      assert.equal(rec.status(), expected.status, `probe ${i} changed status`);
      assert.equal(rec.body().equals(expected.body), true, `probe ${i} changed body`);
      assert.equal(state.phase, 'ready', `probe ${i} mutated the phase`);
    }
  });
});

describe('graceful shutdown depends on liveness holding', () => {
  test('one state driven starting -> ready -> draining flips readiness only', () => {
    const state = createReadinessState();
    const observed: Array<[number | undefined, string]> = [];

    for (const phase of PHASES) {
      state.phase = phase;

      const live = recorder();
      handleHealthz(live.res, 'GET');
      assert.equal(live.status(), 200, `liveness failed while ${phase}`);
      assert.deepEqual(live.body(), Buffer.from('ok\n', 'utf8'));

      const ready = recorder();
      handleReadyz(ready.res, 'GET', state);
      observed.push([ready.status(), ready.body().toString('utf8')]);
    }

    // Readiness is the endpoint that moves; liveness never did.
    assert.deepEqual(observed, [
      [503, 'starting\n'],
      [200, 'ready\n'],
      [503, 'draining\n'],
    ]);
  });
});

describe('response headers (FR-67)', () => {
  test('carries exactly the three required headers plus Content-Length', () => {
    for (const kind of PROBES) {
      for (const method of METHODS) {
        for (const phase of PHASES) {
          const rec = probe(kind, method, phase);
          const headers = rec.headers();
          const where = `${method} /${kind} while ${phase}`;

          assert.deepEqual(Object.keys(headers).sort(), REQUIRED_HEADERS, where);
          assert.equal(headers['content-type'], 'text/plain; charset=utf-8', where);
          assert.equal(headers['cache-control'], 'no-store', where);
          assert.equal(headers['x-content-type-options'], 'nosniff', where);
        }
      }
    }
  });

  test('Content-Length states the GET body length even on HEAD', () => {
    for (const kind of PROBES) {
      for (const phase of PHASES) {
        const get = probe(kind, 'GET', phase);
        const head = probe(kind, 'HEAD', phase);
        assert.equal(get.headers()['content-length'], String(get.body().byteLength));
        assert.equal(head.headers()['content-length'], String(get.body().byteLength));
      }
    }
  });

  test('leaks no CORS, Server or X-Powered-By header', () => {
    for (const kind of PROBES) {
      for (const phase of PHASES) {
        for (const name of Object.keys(probe(kind, 'GET', phase).headers())) {
          assert.equal(name.startsWith('access-control-'), false, `${name} on /${kind}`);
          assert.equal(name === 'server', false, `${name} on /${kind}`);
          assert.equal(name === 'x-powered-by', false, `${name} on /${kind}`);
        }
      }
    }
  });
});

describe('HEAD mirrors GET', () => {
  test('identical status and headers with an empty body, both probes, every phase', () => {
    for (const kind of PROBES) {
      for (const phase of PHASES) {
        const get = probe(kind, 'GET', phase);
        const head = probe(kind, 'HEAD', phase);
        const where = `/${kind} while ${phase}`;

        assert.equal(head.status(), get.status(), where);
        assert.deepEqual(head.headers(), get.headers(), where);
        assert.equal(head.body().byteLength, 0, where);
        assert.ok(get.body().byteLength > 0, where);
        assert.equal(head.ended(), true, where);
      }
    }
  });
});

describe('disclosure scan (FR-67)', () => {
  const FORBIDDEN = [
    'version',
    'build',
    'commit',
    'uptime',
    'session',
    'connection',
    'count',
    'queue',
    'port',
    'host',
    'addr',
    'path',
    'token',
    'key',
    'secret',
    'credential',
    'unifi',
    'ubiquiti',
    'site',
    'protect',
    'mobility',
    'network',
    'spec',
    'write',
    'user',
    'pid',
  ];

  test('every body is one of the four allowed status words and nothing more', () => {
    for (const kind of PROBES) {
      for (const phase of PHASES) {
        const body = probe(kind, 'GET', phase).body().toString('utf8');
        assert.ok(ALLOWED_BODIES.includes(body), `/${kind} while ${phase} emitted ${JSON.stringify(body)}`);
      }
    }
  });

  test('no body contains any deployment detail', () => {
    for (const kind of PROBES) {
      for (const phase of PHASES) {
        const body = probe(kind, 'GET', phase).body().toString('utf8').toLowerCase();
        for (const term of FORBIDDEN) {
          assert.equal(body.includes(term), false, `/${kind} while ${phase} leaked "${term}"`);
        }
        assert.ok(body.length <= 'starting\n'.length);
      }
    }
  });
});

describe('import allow-list (QA C11 — FR-67, NFR-25)', () => {
  // URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
  const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
  const SOURCE = readFileSync(join(REPO_ROOT, 'src', 'serve', 'health.ts'), 'utf8');
  const ALLOW_LIST = ['node:http'];

  function specifiers(source: string): string[] {
    const found: string[] = [];
    for (const match of source.matchAll(/(?:^|\n)\s*(?:import|export)[^\n;]*?from\s*['"]([^'"]+)['"]/g)) {
      if (match[1]) found.push(match[1]);
    }
    // Side-effect imports carry no `from` clause.
    for (const match of source.matchAll(/(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g)) {
      if (match[1]) found.push(match[1]);
    }
    return found;
  }

  test('the module imports node:http and nothing else', () => {
    const found = specifiers(SOURCE);
    assert.deepEqual(found, ALLOW_LIST);
    for (const specifier of found) {
      assert.ok(ALLOW_LIST.includes(specifier), `${specifier} is outside the allow-list`);
    }
  });

  test('node:http is imported for types only, so nothing loads at runtime', () => {
    assert.match(SOURCE, /import type \{[^}]+\} from 'node:http';/);
  });

  test('no runtime escape hatch reintroduces a dependency', () => {
    assert.equal(/\brequire\s*\(/.test(SOURCE), false, 'require( found');
    assert.equal(/\bimport\s*\(/.test(SOURCE), false, 'dynamic import found');
  });

  test('the forbidden specifier fragments appear nowhere in the file', () => {
    for (const fragment of [
      '../config',
      '../credentials',
      '../registry',
      '../http/',
      '../tools',
      'redactedSummary',
    ]) {
      assert.equal(SOURCE.includes(fragment), false, `${fragment} must not appear`);
    }
  });

  test('the module graph is this one file — zero project imports', () => {
    // Offline answerability, mechanised: with every specifier a node: builtin
    // and that builtin type-only, loading this module executes no project code,
    // so /readyz cannot reach the credential store, the registry or the vendor
    // API. The runtime halves of MECH-NET (blocked outbound sockets, and
    // credential-store / registry / artifact-check counters staying at zero
    // across 100 probes) are asserted at the transport level in US-28's suite:
    // they need RuntimeDeps, which does not exist yet.
    for (const specifier of specifiers(SOURCE)) {
      assert.ok(specifier.startsWith('node:'), `${specifier} is a project import`);
    }
    const rec = recorder();
    handleReadyz(rec.res, 'GET', createReadinessState());
    assert.equal(rec.status(), 503);
    assert.deepEqual(rec.body(), Buffer.from('starting\n', 'utf8'));
  });
});
