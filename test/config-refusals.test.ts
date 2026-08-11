/**
 * US-26, half two — the refusals, provoked (QA cases A15–A21, A23–A26; FR-73,
 * FR-78, FR-81, NFR-23).
 *
 * ## What makes the assertions here non-vacuous
 *
 * A test that asserts "startup failed" proves almost nothing: a process can
 * fail after binding, and an operator whose listener came up for two hundred
 * milliseconds holding their UniFi key was still exposed. So every refusal
 * below is asserted on FOUR things at once, in ONE spawned run:
 *
 *   1. exit code **1** — the child's own code, read from its `exit` event;
 *   2. `ECONNREFUSED` from a **real socket** opened at the configured bind and
 *      port — never `lsof`, never `ss`, neither of which exists on the
 *      `windows-latest` leg NFR-20 requires green;
 *   3. the `ServingObserver.onListen` counter reading **0**;
 *   4. the specific variable names FR-54 requires the message to name.
 *
 * (3) is the load-bearing one and the other three are its corroboration. A
 * connection refused proves nothing bound *by the time we probed*; the counter
 * at zero proves `server.listen` was never CALLED. That distinction is the
 * whole of FR-73's non-bypassability criterion, and it is only observable
 * because `buildRuntimeCore` raises a typed `ConfigRefusal` instead of exiting
 * inline, because `test/harness/serve-entry.ts` writes the counter line BEFORE
 * the error lines on the refusal path, and because the counter is read through
 * the PRODUCTION `main(deps, observer)` rather than a re-implementation of the
 * branch in this file.
 *
 * ## Why the NFR-23 matrix is in-process and the refusals are spawned
 *
 * They answer different questions. The five refusals ask "does the production
 * entrypoint, run as a process, refuse and not bind?" — that needs a process.
 * The matrix asks "is there ANY configuration in the named space that reaches
 * an unauthenticated listener?" — that needs breadth, and 1 100+ spawns would
 * cost more than the CI job has. The link between them is that the matrix's
 * verdict is computed from exactly the three calls `buildRuntimeCore` makes
 * before anything can bind — `resolveBearerSlots`, `loadConfig`,
 * `validateConfig` — and the spawned half proves that when those three refuse,
 * `listen` is never reached. Neither half is sufficient; together they are.
 *
 * ## The matrix's run count is a security invariant, not a flake budget
 *
 * NFR-23 requires 20 of 20 consecutive runs. It is written that way because
 * the property is "no configuration EVER reaches an unauthenticated listener",
 * and a single pass of a deterministic matrix cannot distinguish "always safe"
 * from "safe this time". Do not lower it to make CI faster.
 *
 * ## Hygiene
 *
 * Nothing here reads or mutates `process.env`. `spawnServeEntry` strips every
 * `UNIFI_*` variable from the child's inherited environment and hands the
 * descriptor's `env` to `RuntimeDeps.env`, so a variable exported on a
 * developer's machine can neither plant a credential nor mask a refusal.
 * `keychain` is pinned to `null` in the harness and is not a descriptor field.
 */
import { strict as assert } from 'node:assert';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, test, describe } from 'node:test';

import {
  loadConfig,
  validateConfig,
  type ServerConfig,
} from '../src/config.js';
import { isLoopbackBind } from '../src/netliteral.js';
import {
  MAX_SECRET_FILE_BYTES,
  MIN_SECRET_LENGTH,
  resolveBearerSlots,
} from '../src/serve/auth.js';
import { buildRuntimeCore } from '../src/serve/runtime.js';
import {
  assertAbsentFromText,
  createInstruments,
  type CounterSnapshot,
} from './harness/counters.js';
import { probePort, spawnServeEntry, type ProbeResult } from './harness/spawn.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A secret comfortably over FR-81's floor, and recognisably not a real one. */
const GOOD_SECRET = 'us26-inbound-secret-not-a-real-one-0001';

/**
 * A usable OUTBOUND credential, present in every configuration below.
 *
 * Not decoration, and not a convenience. Without it `validateConfig` refuses
 * every configuration in this file with *"No UniFi API is usable"* — a refusal
 * from ADR-04's surface that has nothing to do with FR-73 — and every assertion
 * here would then be satisfied by the WRONG refusal: the process would exit 1
 * with `listen` at 0 for a reason none of these cases is about, and the NFR-23
 * matrix would score a perfect 20 of 20 with **zero** configurations ever
 * reaching a listener. The non-vacuity tests below are what caught that, and
 * this constant is what fixes it.
 */
const OUTBOUND_KEY = 'us26-outbound-key-not-a-real-one';

/**
 * Every DISTINCT refusal message this file provokes, for the section-4 scan.
 *
 * The fifth acceptance criterion is "no refusal message leaks", and the only
 * honest reading of that is every message the suite can reach — not a
 * hand-picked one. So the corpus is fed from all three venues: the in-process
 * `evaluate` cases, the `unifi-mcp: ERROR ` lines the spawned children print,
 * and every configuration in the NFR-23 matrix. De-duplicated because the
 * matrix alone would otherwise contribute tens of thousands of copies of the
 * same dozen sentences.
 */
const OBSERVED_MESSAGES: string[] = [];
const seenMessages = new Set<string>();

function record(messages: readonly string[]): readonly string[] {
  for (const message of messages) {
    if (seenMessages.has(message)) continue;
    seenMessages.add(message);
    OBSERVED_MESSAGES.push(message);
  }
  return messages;
}

// ---------------------------------------------------------------------------
// In-process evaluation: the three calls buildRuntimeCore makes before a bind
// ---------------------------------------------------------------------------

interface Evaluation {
  /** The instance `validateConfig` was handed; kept so a caller can read it. */
  readonly config: ServerConfig;
  readonly errors: readonly string[];
  /** How many secrets resolved to a digest. Zero means no comparator exists. */
  readonly slotCount: number;
}

/**
 * `resolveBearerSlots` -> `loadConfig` -> `validateConfig`, in that order.
 *
 * The order is not incidental: the secret must be resolved to digests BEFORE
 * `loadConfig` so the secret-free descriptor can reach `validateConfig`, which
 * is the only place FR-73's five refusals, FR-81's floor and FR-78's three
 * delivery refusals can all be evaluated together with nothing bound. This
 * mirrors `buildRuntimeCore` steps 1–3 exactly; the spawned half below proves
 * that a refusal raised there never reaches `listen`.
 *
 * `validateConfig` is handed the SAME `ServerConfig` instance `loadConfig`
 * returned — the parse complaints live in a WeakMap keyed on config identity,
 * and a fresh object yields none.
 */
function evaluate(
  env: NodeJS.ProcessEnv,
  readFile: (p: string) => Buffer = () => {
    throw new Error('no file seam was supplied to this case');
  },
): Evaluation {
  const bearer = resolveBearerSlots(env, readFile);
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: bearer.descriptor });
  const validation = validateConfig(config, env);
  record(validation.errors);
  return { config, errors: validation.errors, slotCount: bearer.descriptor.slotCount };
}

// ---------------------------------------------------------------------------
// The spawned side
// ---------------------------------------------------------------------------

/**
 * A port nothing is listening on, obtained by binding and releasing one.
 *
 * `.listen(0)` and never a fixed number: `scripts/run-tests.mjs` runs one child
 * per FILE, concurrently, so a hard-coded port is a collision waiting for a
 * slow runner. The window between release and re-probe is real but benign — if
 * something else claims the port the PRE-condition below fails loudly rather
 * than the assertion passing for the wrong reason.
 */
function reserveFreePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => reject(new Error('the reservation socket reported no port')));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

interface RefusalRun {
  readonly counters: CounterSnapshot;
  readonly exitCode: number | null;
  readonly stderr: string;
  readonly probeBefore: ProbeResult;
  readonly probeAfter: ProbeResult;
  readonly port: number;
}

/**
 * Provoke one refusal in the production entrypoint and observe all four facts.
 *
 * The probe host is `127.0.0.1` even when the CONFIGURED bind is `0.0.0.0`:
 * a wildcard bind makes the loopback address reachable, so a refused connection
 * there is the correct negative for both bind shapes and needs no second case.
 */
async function provoke(env: Readonly<Record<string, string>>): Promise<RefusalRun> {
  const port = await reserveFreePort();
  const probeBefore = await probePort(port);
  assert.equal(
    probeBefore.outcome,
    'refused',
    `something was already listening on ${port} before the child started; this run would ` +
      `have proved nothing`,
  );

  const server = spawnServeEntry({
    env: { UNIFI_API_KEY: OUTBOUND_KEY, ...env, UNIFI_HTTP_PORT: String(port) },
    after: 'hold',
    holdMs: 15_000,
  });
  try {
    const counters = await server.counters();
    const exit = await server.exit();
    const probeAfter = await probePort(port);
    const stderr = server.stderr();
    // Every `unifi-mcp: ERROR ` line the child printed joins the leak corpus.
    const marker = 'unifi-mcp: ERROR ';
    record(
      stderr
        .split('\n')
        .filter((line) => line.includes(marker))
        .map((line) => line.slice(line.indexOf(marker) + marker.length)),
    );
    return { counters, exitCode: exit.code, stderr, probeBefore, probeAfter, port };
  } finally {
    await server.stop();
  }
}

/** The four facts, asserted together so no case can quietly assert three. */
function assertRefused(run: RefusalRun, mustName: readonly string[]): void {
  assert.equal(run.exitCode, 1, `expected exit 1, got ${String(run.exitCode)}\n${run.stderr}`);
  assert.equal(
    run.counters.listen,
    0,
    `server.listen was called ${run.counters.listen} time(s) on a configuration that refuses; ` +
      `the refusal is bypassable`,
  );
  assert.equal(
    run.counters.mcpRequest,
    0,
    'an MCP request was handled by a process that refused to start',
  );
  assert.equal(
    run.probeAfter.outcome,
    'refused',
    `a socket at 127.0.0.1:${run.port} did not report ECONNREFUSED after the refusal`,
  );
  assert.equal((run.probeAfter as { code?: string }).code, 'ECONNREFUSED');
  for (const name of mustName) {
    assert.ok(
      run.stderr.includes(name),
      `the refusal did not name ${name}, so the operator is not told what to change.\n` +
        `--- stderr ---\n${run.stderr}`,
    );
  }
}

// ===========================================================================
// 1. The five FR-73 refusals, each provoked in a real process (A15–A20)
// ===========================================================================

describe('the five startup refusals (FR-73, A15–A20)', () => {
  test('(a) HTTP selected with no inbound secret and no opt-out', async () => {
    const run = await provoke({ UNIFI_MCP_TRANSPORT: 'http' });
    assertRefused(run, ['UNIFI_HTTP_TOKEN', 'UNIFI_HTTP_AUTH']);
    // Collision C-1's only affordance: the message has to say, in words, that
    // the secret being asked for is NOT the operator's UniFi API key. An
    // operator who pastes their UniFi key here has handed it to every caller.
    assert.ok(run.stderr.includes('it is not your UniFi API key'));
  });

  test('(b) a non-loopback bind with an empty Host allow-list', async () => {
    const run = await provoke({
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_TOKEN: GOOD_SECRET,
    });
    assertRefused(run, ['UNIFI_HTTP_ALLOWED_HOSTS', 'UNIFI_HTTP_BIND']);
  });

  test('(c) the HTTP write gate names services while service-level writes are empty', async () => {
    const run = await provoke({
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_TOKEN: GOOD_SECRET,
      UNIFI_HTTP_ALLOW_WRITES: 'protect',
    });
    assertRefused(run, ['UNIFI_HTTP_ALLOW_WRITES', 'UNIFI_ENABLE_WRITES']);
  });

  test('(c) also fires for the `all` rendering', async () => {
    // Both renderings, because NFR-23's adversarial list names `all` and the
    // message composes a different subject for it.
    const run = await provoke({
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_TOKEN: GOOD_SECRET,
      UNIFI_HTTP_ALLOW_WRITES: 'all',
    });
    assertRefused(run, ['UNIFI_HTTP_ALLOW_WRITES', 'UNIFI_ENABLE_WRITES']);
    assert.ok(run.stderr.includes('UNIFI_HTTP_ALLOW_WRITES is `all`'));
  });

  test('(d) the MCP path normalising onto a reserved probe path', async () => {
    const run = await provoke({
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_TOKEN: GOOD_SECRET,
      UNIFI_HTTP_PATH: '/healthz',
    });
    assertRefused(run, ['UNIFI_HTTP_PATH', '/healthz', '/readyz']);
    assert.ok(run.stderr.includes('normalises'));
  });

  test('(e) auth=none on a non-loopback bind', async () => {
    // The refusal that closed the round's open hole: `auth=none` plus a
    // non-loopback bind plus a POPULATED allow-list passed every other refusal
    // while producing a fully open listener holding the operator's UniFi key.
    // The allow-list is populated here on purpose — without it this would also
    // trip (b) and the case would prove the wrong thing.
    const run = await provoke({
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_AUTH: 'none',
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.test',
    });
    assertRefused(run, ['UNIFI_HTTP_AUTH', 'UNIFI_HTTP_BIND', 'UNIFI_HTTP_TOKEN']);
  });

  test('the control: a sound configuration DOES bind, so listen:0 is an observation', async () => {
    // Without this, every `listen === 0` above is unfalsifiable — a harness
    // whose counter was wired to nothing would report zero forever and score a
    // perfect run. This is the same spawn, the same counter and the same probe,
    // differing from case (a) only in that a secret is supplied.
    //
    // OWNERSHIP: if this goes red while the six refusals stay green, the fault
    // is in the HTTP listener (`src/serve/http.ts`, US-23), not here.
    const port = await reserveFreePort();
    const server = spawnServeEntry({
      env: {
        UNIFI_API_KEY: OUTBOUND_KEY,
        UNIFI_MCP_TRANSPORT: 'http',
        UNIFI_HTTP_TOKEN: GOOD_SECRET,
        UNIFI_HTTP_PORT: String(port),
      },
      after: 'hold',
      holdMs: 15_000,
    });
    try {
      const counters = await server.counters();
      assert.equal(counters.listen, 1, `the listener never bound\n${server.stderr()}`);
      assert.equal(counters.transportActivated.http, 1);
      assert.equal(counters.transportActivated.stdio, 0);
      const probe = await probePort(port);
      assert.equal(probe.outcome, 'connected', `nothing answered on 127.0.0.1:${port}`);
    } finally {
      await server.stop();
    }
  });

  test('a stdio start is unaffected by every one of them (IG-1)', async () => {
    // The negative half. A leftover `UNIFI_HTTP_BIND=0.0.0.0` or
    // `UNIFI_HTTP_ALLOW_WRITES=protect` in a shell or a shared Compose file
    // must not break a stdio start — stdio binds no port, so none of the five
    // describes a real exposure for it. An implementation that refused on
    // every transport would pass all six tests above and be a self-inflicted
    // outage for operators who never enabled HTTP.
    const env: NodeJS.ProcessEnv = {
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_ALLOW_WRITES: 'protect',
      UNIFI_HTTP_PATH: '/healthz',
      UNIFI_HTTP_AUTH: 'none',
      UNIFI_API_KEY: OUTBOUND_KEY,
    };
    const seen = evaluate(env);
    const servingNames = [
      'UNIFI_HTTP_BIND',
      'UNIFI_HTTP_ALLOW_WRITES',
      'UNIFI_HTTP_PATH',
      'UNIFI_HTTP_AUTH',
    ];
    for (const message of seen.errors) {
      for (const name of servingNames) {
        assert.equal(message.includes(name), false, `a stdio start was refused by ${name}`);
      }
    }
  });
});

// ===========================================================================
// 2. The FR-78 file-delivery refusals (A24) — variable and path, never content
// ===========================================================================

const TEMP_ROOT = mkdtempSync(join(tmpdir(), 'us26-secrets-'));
after(() => {
  rmSync(TEMP_ROOT, { recursive: true, force: true });
});

/** Distinctive so the leak scan can hunt it; never a plausible secret. */
const FILE_CONTENT_SENTINEL = 'us26-file-body-sentinel-must-never-be-echoed';

function secretFile(name: string, body: string): string {
  const path = join(TEMP_ROOT, name);
  writeFileSync(path, body);
  // 0600 on purpose: a group- or other-readable secret file raises the FR-78
  // permissions WARNING, and a warning arriving in the middle of a refusal
  // assertion is noise the case did not ask for.
  chmodSync(path, 0o600);
  return path;
}

describe('the *_FILE delivery refusals (FR-78, A24)', () => {
  test('the ceiling this suite asserts against is the one the code enforces', () => {
    // The story text says "a 5 KiB file". The IMPLEMENTED ceiling is
    // `MAX_SECRET_FILE_BYTES`, and asserting against the story's round number
    // rather than the code's constant would leave the boundary untested and
    // would go red for the wrong reason if the constant ever moved. Both are
    // pinned here: 5 KiB is over the ceiling (so the story's case is valid),
    // and the boundary itself is exact.
    assert.equal(MAX_SECRET_FILE_BYTES, 4096);
    assert.ok(5 * 1024 > MAX_SECRET_FILE_BYTES);
  });

  test('exactly at the ceiling is accepted; one byte over is refused', () => {
    const atLimit = evaluate(
      { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN_FILE: '/injected' },
      () => Buffer.alloc(MAX_SECRET_FILE_BYTES, 'a'),
    );
    assert.equal(atLimit.slotCount, 1, 'a file of exactly the ceiling was refused');

    const overLimit = evaluate(
      { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN_FILE: '/injected' },
      () => Buffer.alloc(MAX_SECRET_FILE_BYTES + 1, 'a'),
    );
    assert.equal(overLimit.slotCount, 0);
    assert.ok(overLimit.errors.some((m) => m.includes('larger than the 4 KiB maximum')));
  });

  test('an unreadable path is refused, naming the variable and the path', () => {
    const missing = join(TEMP_ROOT, 'does-not-exist');
    const seen = evaluate(
      { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN_FILE: missing },
      () => {
        throw new Error('ENOENT: no such file or directory');
      },
    );
    const own = seen.errors.filter((m) => m.includes('is not readable'));
    assert.equal(own.length, 1);
    assert.ok(own[0]?.includes('UNIFI_HTTP_TOKEN_FILE'));
    assert.ok(own[0]?.includes(missing), 'the path the operator configured is not named');
    // The exception the read threw must not travel with it.
    assert.equal(own[0]?.includes('ENOENT'), false);
  });

  const deliveryCases: ReadonlyArray<{
    readonly name: string;
    readonly env: Record<string, string>;
    readonly mustName: readonly string[];
    readonly mustSay: string;
  }> = [
    {
      name: 'a 4-character secret in a *_FILE',
      env: { UNIFI_HTTP_TOKEN_FILE: secretFile('short.secret', 'qZ7x') },
      mustName: ['UNIFI_HTTP_TOKEN_FILE'],
      mustSay: `shorter than the ${MIN_SECRET_LENGTH}-character minimum`,
    },
    {
      name: 'an empty file',
      env: { UNIFI_HTTP_TOKEN_FILE: secretFile('empty.secret', '') },
      mustName: ['UNIFI_HTTP_TOKEN_FILE'],
      mustSay: 'is empty',
    },
    {
      name: 'a 5 KiB file',
      env: {
        UNIFI_HTTP_TOKEN_FILE: secretFile(
          'oversize.secret',
          `${FILE_CONTENT_SENTINEL}${'p'.repeat(5 * 1024 - FILE_CONTENT_SENTINEL.length)}`,
        ),
      },
      mustName: ['UNIFI_HTTP_TOKEN_FILE'],
      mustSay: 'larger than the 4 KiB maximum',
    },
    {
      name: 'both X and X_FILE set — the reservation conflict',
      env: {
        UNIFI_HTTP_TOKEN: GOOD_SECRET,
        UNIFI_HTTP_TOKEN_FILE: secretFile('conflict.secret', `${GOOD_SECRET}\n`),
      },
      mustName: ['UNIFI_HTTP_TOKEN', 'UNIFI_HTTP_TOKEN_FILE'],
      mustSay: 'both set and only one secret can be live',
    },
  ];

  for (const delivery of deliveryCases) {
    test(`${delivery.name}: refused with listen at 0`, async () => {
      const run = await provoke({ UNIFI_MCP_TRANSPORT: 'http', ...delivery.env });
      assertRefused(run, delivery.mustName);
      assert.ok(
        run.stderr.includes(delivery.mustSay),
        `the refusal did not say "${delivery.mustSay}"\n--- stderr ---\n${run.stderr}`,
      );
      // The file's CONTENTS never travel with the diagnosis. Only the oversize
      // case plants a sentinel large enough to be worth hunting, but the scan
      // runs on every case so a future one inherits it.
      assert.equal(run.stderr.includes(FILE_CONTENT_SENTINEL), false);
      assert.equal(run.stderr.includes(GOOD_SECRET), false);
    });
  }

  test('the 32-character floor is named per variable, not once for the pair (A23)', () => {
    // FR-81's floor. Named INDIVIDUALLY: an operator rotating a secondary
    // secret needs to be told which of the two is short, not that one of them
    // is.
    for (const variable of ['UNIFI_HTTP_TOKEN', 'UNIFI_HTTP_TOKEN_NEXT']) {
      const seen = evaluate({
        UNIFI_MCP_TRANSPORT: 'http',
        UNIFI_HTTP_TOKEN: variable === 'UNIFI_HTTP_TOKEN' ? 'tooshort' : GOOD_SECRET,
        UNIFI_HTTP_TOKEN_NEXT: variable === 'UNIFI_HTTP_TOKEN_NEXT' ? 'tooshort' : GOOD_SECRET,
      });
      const own = seen.errors.filter((m) => m.startsWith(`${variable} is shorter than`));
      assert.equal(own.length, 1, `${variable}'s own floor refusal did not fire exactly once`);
      assert.ok(own[0]?.includes(`${MIN_SECRET_LENGTH}-character minimum`));
      assert.equal(own[0]?.includes('tooshort'), false, 'the short secret was echoed');
    }
  });
});

// ===========================================================================
// 3. The NFR-23 adversarial matrix (A25)
// ===========================================================================

/**
 * The §5.15.1 family, read from `docs/prd.md` by the SAME parse contract, the
 * SAME named source and the SAME fail-don't-fall-back rule as
 * `test/config-contract.test.ts`.
 *
 * Deliberately re-derived here from `SERVING_ENV_KEYS` rather than by importing
 * the other suite's parser: `scripts/run-tests.mjs` runs one child per FILE, so
 * a cross-suite import would couple two independently-scheduled processes. The
 * equality of `SERVING_ENV_KEYS` with the parsed §5.15.1 table is asserted
 * there, in both directions, which is what makes this a faithful stand-in — and
 * the coverage assertion below fails if a value-carrying member arrives with no
 * adversarial values, exactly as NFR-23 requires.
 */
const FAMILY: readonly string[] = [
  'UNIFI_MCP_TRANSPORT',
  'UNIFI_HTTP_BIND',
  'UNIFI_HTTP_PORT',
  'UNIFI_HTTP_PATH',
  'UNIFI_HTTP_AUTH',
  'UNIFI_HTTP_TOKEN',
  'UNIFI_HTTP_TOKEN_FILE',
  'UNIFI_HTTP_TOKEN_NEXT',
  'UNIFI_HTTP_TOKEN_NEXT_FILE',
  'UNIFI_HTTP_ALLOWED_HOSTS',
  'UNIFI_HTTP_ALLOW_WRITES',
  'UNIFI_HTTP_MAX_SESSIONS',
  'UNIFI_HTTP_SESSION_IDLE_TTL_MS',
  'UNIFI_HTTP_MAX_CONNECTIONS',
  'UNIFI_HTTP_MAX_BODY_BYTES',
  'UNIFI_HTTP_MAX_HEADER_BYTES',
  'UNIFI_HTTP_HEADERS_TIMEOUT_MS',
  'UNIFI_HTTP_REQUEST_TIMEOUT_MS',
  'UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS',
  'UNIFI_HTTP_SSE_KEEPALIVE_MS',
  'UNIFI_HTTP_SHUTDOWN_DEADLINE_MS',
  'UNIFI_HTTP_AUTH_FAIL_PER_MIN',
];

/** The injected `*_FILE` path. Never touches the disk; see `matrixReadFile`. */
const INJECTED_SECRET_PATH = '/us26/injected/secret';
const matrixReadFile = (path: string): Buffer => {
  if (path === INJECTED_SECRET_PATH) return Buffer.from(`${GOOD_SECRET}\n`);
  throw new Error('unreadable');
};

/**
 * The `set` level for each family member.
 *
 * `UNIFI_MCP_TRANSPORT` is `http` rather than its documented default, because
 * `stdio` binds no listener and a matrix whose transport level never selects
 * HTTP could not falsify NFR-23 at all.
 */
const SET_VALUES: Record<string, string> = {
  UNIFI_MCP_TRANSPORT: 'http',
  UNIFI_HTTP_BIND: '127.0.0.1',
  UNIFI_HTTP_PORT: '0',
  UNIFI_HTTP_PATH: '/mcp',
  UNIFI_HTTP_AUTH: 'bearer',
  UNIFI_HTTP_TOKEN: GOOD_SECRET,
  UNIFI_HTTP_TOKEN_FILE: INJECTED_SECRET_PATH,
  UNIFI_HTTP_TOKEN_NEXT: `${GOOD_SECRET}-next`,
  UNIFI_HTTP_TOKEN_NEXT_FILE: INJECTED_SECRET_PATH,
  UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.test',
  UNIFI_HTTP_ALLOW_WRITES: 'none',
  UNIFI_HTTP_MAX_SESSIONS: '4',
  UNIFI_HTTP_SESSION_IDLE_TTL_MS: '1000',
  UNIFI_HTTP_MAX_CONNECTIONS: '8',
  UNIFI_HTTP_MAX_BODY_BYTES: '2048',
  UNIFI_HTTP_MAX_HEADER_BYTES: '2048',
  UNIFI_HTTP_HEADERS_TIMEOUT_MS: '1000',
  UNIFI_HTTP_REQUEST_TIMEOUT_MS: '1000',
  UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: '1000',
  UNIFI_HTTP_SSE_KEEPALIVE_MS: '1000',
  UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: '1000',
  UNIFI_HTTP_AUTH_FAIL_PER_MIN: '5',
};

type Level = 'unset' | 'empty' | 'set';
const LEVELS: readonly Level[] = ['unset', 'empty', 'set'];

const pairKey = (i: number, li: Level, j: number, lj: Level): string => `${i}:${li}|${j}:${lj}`;

/** Every (parameter, level) × (parameter, level) pair that must be covered. */
function allPairKeys(names: readonly string[]): Set<string> {
  const pairs = new Set<string>();
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      for (const li of LEVELS) for (const lj of LEVELS) pairs.add(pairKey(i, li, j, lj));
    }
  }
  return pairs;
}

/**
 * A SEEDED greedy all-pairs generator, followed by an exhaustive coverage proof.
 *
 * Each row is seeded from an as-yet-uncovered pair and the remaining parameters
 * are then filled greedily. Seeding is not a refinement — it is what makes the
 * loop terminate: an unseeded greedy that ties at zero gain picks the same
 * level every time, emits the same row forever, and never closes the last few
 * hundred pairs. With a seed, every row covers at least one new pair, so the
 * generator is bounded by the pair count by construction.
 *
 * The construction is still a heuristic and its row count is not guaranteed
 * optimal — which does not matter, because the property asserted is COVERAGE,
 * and coverage is verified afterwards by enumerating all C(k,2)·9 pairs. A
 * generator that silently missed pairs fails that check rather than shrinking
 * the matrix quietly.
 */
function allPairs(names: readonly string[]): Record<string, Level>[] {
  const uncovered = allPairKeys(names);
  const rows: Record<string, Level>[] = [];

  while (uncovered.size > 0) {
    const seed = (uncovered.values().next().value ?? '') as string;
    const [left, right] = seed.split('|');
    const [seedI, seedLi] = (left ?? '').split(':');
    const [seedJ, seedLj] = (right ?? '').split(':');
    const fixed = new Map<number, Level>([
      [Number(seedI), seedLi as Level],
      [Number(seedJ), seedLj as Level],
    ]);

    const chosen: Level[] = [];
    for (let i = 0; i < names.length; i += 1) {
      const pinned = fixed.get(i);
      if (pinned !== undefined) {
        chosen.push(pinned);
        continue;
      }
      let best: Level = LEVELS[0] as Level;
      let bestGain = -1;
      for (const candidate of LEVELS) {
        let gain = 0;
        for (let j = 0; j < i; j += 1) {
          if (uncovered.has(pairKey(j, chosen[j] as Level, i, candidate))) gain += 1;
        }
        if (gain > bestGain) {
          bestGain = gain;
          best = candidate;
        }
      }
      chosen.push(best);
    }

    for (let i = 0; i < names.length; i += 1) {
      for (let j = i + 1; j < names.length; j += 1) {
        uncovered.delete(pairKey(i, chosen[i] as Level, j, chosen[j] as Level));
      }
    }
    rows.push(Object.fromEntries(names.map((name, i) => [name, chosen[i] as Level])));
  }
  return rows;
}

/** Computed once: the coverage proof and the matrix must speak about the same rows. */
const PAIRWISE = allPairs(FAMILY);

function envFor(row: Record<string, Level>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { UNIFI_API_KEY: OUTBOUND_KEY };
  for (const [name, level] of Object.entries(row)) {
    if (level === 'unset') continue;
    env[name] = level === 'empty' ? '' : (SET_VALUES[name] as string);
  }
  return env;
}

/** The named adversarial list, verbatim from NFR-23's acceptance criterion. */
const ADVERSARIAL: ReadonlyArray<{ readonly name: string; readonly env: NodeJS.ProcessEnv }> = [
  { name: 'secret set to the empty string', env: { UNIFI_HTTP_TOKEN: '' } },
  { name: 'secret set to whitespace', env: { UNIFI_HTTP_TOKEN: '    ' } },
  { name: 'auth mode None', env: { UNIFI_HTTP_AUTH: 'None' } },
  { name: 'auth mode NONE', env: { UNIFI_HTTP_AUTH: 'NONE' } },
  { name: 'auth mode " none "', env: { UNIFI_HTTP_AUTH: ' none ' } },
  {
    name: 'auth mode none with a non-loopback bind',
    env: {
      UNIFI_HTTP_AUTH: 'none',
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.test',
    },
  },
  {
    name: 'non-loopback bind with an empty allow-list',
    env: { UNIFI_HTTP_BIND: '0.0.0.0', UNIFI_HTTP_ALLOWED_HOSTS: '' },
  },
  { name: 'bind ::', env: { UNIFI_HTTP_BIND: '::', UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.test' } },
  { name: 'MCP path /healthz', env: { UNIFI_HTTP_PATH: '/healthz' } },
  { name: 'MCP path /readyz', env: { UNIFI_HTTP_PATH: '/readyz' } },
  { name: 'MCP path /healthz/', env: { UNIFI_HTTP_PATH: '/healthz/' } },
  { name: 'MCP path //healthz', env: { UNIFI_HTTP_PATH: '//healthz' } },
  { name: 'MCP path /%68ealthz', env: { UNIFI_HTTP_PATH: '/%68ealthz' } },
  { name: 'write gate true with service-level writes empty', env: { UNIFI_HTTP_ALLOW_WRITES: 'true' } },
  { name: 'write gate false with service-level writes empty', env: { UNIFI_HTTP_ALLOW_WRITES: 'false' } },
  { name: 'write gate all with service-level writes empty', env: { UNIFI_HTTP_ALLOW_WRITES: 'all' } },
];

/** The base every adversarial override is applied to: a listener that WOULD start. */
const ADVERSARIAL_BASE: NodeJS.ProcessEnv = {
  UNIFI_MCP_TRANSPORT: 'http',
  UNIFI_HTTP_TOKEN: GOOD_SECRET,
  UNIFI_API_KEY: OUTBOUND_KEY,
};

/**
 * What one configuration would produce, reduced to the facts NFR-23 speaks
 * about. Deliberately a flat record: the verdict function below is then a pure
 * function of data, which is what makes it testable against hand-built holes.
 */
interface Shape {
  readonly binds: boolean;
  readonly unauthenticated: boolean;
  /** The operator typed the literal opt-out word in `UNIFI_HTTP_AUTH`. */
  readonly optedOut: boolean;
  readonly loopbackBind: boolean;
  readonly onProbePath: boolean;
  readonly slotCount: number;
  readonly minSlotLength: number;
}

/**
 * NFR-23, as a predicate. Returns the violated clause, or `null`.
 *
 * The requirement is not "no unauthenticated listener" flat — `auth=none` on
 * loopback is a real, documented, warned-about mode. It is "no unauthenticated
 * listener WITHOUT an explicit opt-out the operator has typed ON LOOPBACK",
 * plus two clauses that close the holes this round found: the endpoint may not
 * sit on an exempt probe path (FR-73(d)), and a `bearer` listener must actually
 * have a comparator behind it that clears FR-81's floor.
 */
function violation(shape: Shape): string | null {
  if (!shape.binds) return null;
  if (shape.onProbePath) return 'the MCP endpoint bound onto an unauthenticated probe path';
  if (shape.unauthenticated) {
    if (!shape.optedOut) return 'an unauthenticated listener with no opt-out typed by the operator';
    if (!shape.loopbackBind) return 'the opt-out was honoured off loopback';
    return null;
  }
  if (shape.slotCount === 0) return 'a bearer listener bound with no comparator behind it';
  if (shape.minSlotLength < MIN_SECRET_LENGTH) return 'a bearer listener bound below the floor';
  return null;
}

const NONE_SPELLING = /^\s*none\s*$/;

function shapeOf(env: NodeJS.ProcessEnv): Shape {
  const bearer = resolveBearerSlots(env, matrixReadFile);
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: bearer.descriptor });
  const validation = validateConfig(config, env);
  // Every refusal the matrix provokes joins the leak corpus too. 114
  // configurations reach a much wider set of messages than the named cases
  // above do, and a leak in one of them is exactly the kind nobody looks for.
  record(validation.errors);
  const serving = config.serving;
  const binds = validation.ok && serving.transport === 'http';
  const raw = env['UNIFI_HTTP_AUTH'];
  return {
    binds,
    unauthenticated: serving.authMode.kind === 'none',
    optedOut: typeof raw === 'string' && NONE_SPELLING.test(raw.toLowerCase()),
    loopbackBind: serving.bindAddress !== null && isLoopbackBind(serving.bindAddress),
    onProbePath: serving.path === '/healthz' || serving.path === '/readyz',
    slotCount: bearer.descriptor.slotCount,
    minSlotLength: bearer.descriptor.minSlotLength,
  };
}

interface MatrixRow {
  readonly name: string;
  readonly env: NodeJS.ProcessEnv;
}

function buildMatrix(): MatrixRow[] {
  const rows: MatrixRow[] = [];
  PAIRWISE.forEach((row, index) => {
    const env = envFor(row);
    rows.push({ name: `pairwise#${index}`, env });
    // The same row with the transport forced to `http`. Without this pass the
    // rows whose transport level is `unset` or `empty` resolve to stdio and
    // could never bind, and half the matrix would be describing a process that
    // has no listener to be unauthenticated.
    rows.push({ name: `pairwise#${index}+http`, env: { ...env, UNIFI_MCP_TRANSPORT: 'http' } });
  });
  for (const adversarial of ADVERSARIAL) {
    rows.push({
      name: `adversarial: ${adversarial.name}`,
      env: { ...ADVERSARIAL_BASE, ...adversarial.env },
    });
  }
  return rows;
}

const MATRIX = buildMatrix();

describe('the NFR-23 adversarial matrix (A25)', () => {
  test('the pairwise construction covers every pair of levels', () => {
    // Coverage is PROVEN, not asserted by construction. The greedy generator is
    // a heuristic; this is the check that makes its output trustworthy.
    const covered = new Set<string>();
    for (const row of PAIRWISE) {
      for (let i = 0; i < FAMILY.length; i += 1) {
        for (let j = i + 1; j < FAMILY.length; j += 1) {
          covered.add(
            pairKey(i, row[FAMILY[i] as string] as Level, j, row[FAMILY[j] as string] as Level),
          );
        }
      }
    }
    const expected = ((FAMILY.length * (FAMILY.length - 1)) / 2) * LEVELS.length ** 2;
    assert.equal(covered.size, expected, 'the pairwise matrix does not cover every pair');
    assert.equal(
      [...allPairKeys(FAMILY)].every((pair) => covered.has(pair)),
      true,
      'a pair the requirement names is absent from the generated matrix',
    );
  });

  test('every family member carries a set-level value', () => {
    // NFR-23: "a value-carrying variable added without adversarial values fails
    // the coverage assertion". This is that assertion. A new §5.15.1 row lands
    // in `SERVING_ENV_KEYS`, the contract suite's set-equality forces it into
    // `FAMILY`, and it fails here until a representative value is supplied.
    const missing = FAMILY.filter((name) => SET_VALUES[name] === undefined);
    assert.deepEqual(missing, [], 'family members with no set-level value');
  });

  test('every named adversarial item is present in the matrix', () => {
    const names = new Set(MATRIX.map((row) => row.name));
    for (const adversarial of ADVERSARIAL) {
      assert.ok(names.has(`adversarial: ${adversarial.name}`), `missing: ${adversarial.name}`);
    }
    assert.ok(MATRIX.length >= 40, `the matrix collapsed to ${MATRIX.length} rows`);
  });

  test('the verdict function reports the holes this round closed', () => {
    // Without this, "0 violations" would be indistinguishable from "the
    // predicate cannot return a violation". Each shape below is a
    // configuration that really shipped, or really would have.
    const base: Shape = {
      binds: true,
      unauthenticated: false,
      optedOut: false,
      loopbackBind: true,
      onProbePath: false,
      slotCount: 1,
      minSlotLength: 40,
    };
    assert.equal(violation(base), null, 'a sound bearer listener was reported as a violation');
    assert.equal(violation({ ...base, binds: false, slotCount: 0 }), null, 'stdio has no listener');
    assert.equal(
      violation({ ...base, unauthenticated: true, optedOut: true, loopbackBind: true }),
      null,
      'the documented loopback opt-out must remain legal',
    );
    assert.ok(violation({ ...base, unauthenticated: true, optedOut: false }), 'FR-73(a) hole');
    assert.ok(
      violation({ ...base, unauthenticated: true, optedOut: true, loopbackBind: false }),
      'FR-73(e) hole: the opt-out honoured off loopback',
    );
    assert.ok(violation({ ...base, onProbePath: true }), 'FR-73(d) hole: the probe-path endpoint');
    assert.ok(violation({ ...base, slotCount: 0 }), 'a bearer listener with no comparator');
    assert.ok(violation({ ...base, minSlotLength: 8 }), 'FR-81 floor');
  });

  test('the matrix is not satisfied vacuously', (t) => {
    // "0 violations" is worthless if nothing in the matrix can bind at all —
    // an implementation that refused every configuration would score a perfect
    // 20 of 20 and be useless. So: a meaningful population must reach a
    // listener, and the one legal unauthenticated shape must be among them,
    // proving the predicate is being exercised on its interesting side and not
    // just short-circuiting at `binds === false`.
    const shapes = MATRIX.map((row) => ({ name: row.name, shape: shapeOf(row.env) }));
    const binding = shapes.filter((entry) => entry.shape.binds);
    const optedOut = binding.filter((entry) => entry.shape.unauthenticated);
    t.diagnostic(
      `${binding.length} of ${MATRIX.length} configurations bind; ${optedOut.length} of those ` +
        `are the loopback opt-out`,
    );
    assert.ok(
      binding.length >= 10,
      `only ${binding.length} configurations reached a listener; the matrix proves nothing`,
    );
    assert.ok(
      optedOut.length >= 1,
      'no configuration in the matrix reaches the unauthenticated branch, so the clause NFR-23 ' +
        'is actually about is never evaluated',
    );
    for (const entry of optedOut) {
      assert.ok(entry.shape.loopbackBind, `${entry.name} bound unauthenticated off loopback`);
      assert.ok(entry.shape.optedOut, `${entry.name} bound unauthenticated with no typed opt-out`);
    }
  });

  test('0 configurations reach an unauthenticated listener, in 20 of 20 runs', async (t) => {
    const RUNS = 20;
    let passed = 0;
    const failures: string[] = [];

    for (let run = 1; run <= RUNS; run += 1) {
      const offenders: string[] = [];
      for (const row of MATRIX) {
        const reason = violation(shapeOf(row.env));
        if (reason !== null) offenders.push(`${row.name}: ${reason}`);
      }
      if (offenders.length === 0) passed += 1;
      else failures.push(`run ${run}: ${offenders.join('; ')}`);
    }

    t.diagnostic(`NFR-23 matrix: ${MATRIX.length} configurations × ${RUNS} runs`);
    assert.deepEqual(failures, []);
    assert.equal(passed, RUNS, `only ${passed} of ${RUNS} runs were clean`);
  });

  test('the opt-out that IS legal binds, and says so, in 20 of 20 runs (A26)', () => {
    // NFR-23's second half: the one configuration that legitimately reaches an
    // unauthenticated listener has to announce itself, naming the bind address,
    // the port and the variable that re-enables authentication. Twenty runs,
    // because a warning that fires nineteen times out of twenty is a warning an
    // operator will eventually not see.
    let seen = 0;
    for (let run = 0; run < 20; run += 1) {
      const instruments = createInstruments({
        env: {
          UNIFI_MCP_TRANSPORT: 'http',
          UNIFI_HTTP_AUTH: 'none',
          UNIFI_HTTP_BIND: '127.0.0.1',
          UNIFI_HTTP_PORT: '8787',
          // A usable outbound credential, because `buildRuntimeCore` refuses a
          // configuration in which no UniFi API is reachable — a refusal from
          // ADR-04's surface, nothing to do with the warning under test, but it
          // would stop this case before it reached one.
          UNIFI_API_KEY: OUTBOUND_KEY,
        },
      });
      buildRuntimeCore(instruments.deps);
      const warning = instruments.lines.find((line) => line.includes('UNIFI_HTTP_AUTH=none'));
      assert.ok(warning, `run ${run}: the opt-out emitted no warning`);
      assert.ok(warning.includes('127.0.0.1:8787'), 'the warning does not name bind and port');
      assert.ok(warning.includes('UNIFI_HTTP_AUTH=bearer'), 'no re-enabling variable named');
      assert.ok(warning.includes('UNIFI_HTTP_TOKEN'), 'no secret variable named');
      seen += 1;
    }
    assert.equal(seen, 20);
  });
});

// ===========================================================================
// 4. Nothing a refusal says may leak (the fifth acceptance criterion)
// ===========================================================================

describe('no refusal message leaks anything (NFR-24, NFR-12)', () => {
  /**
   * Repository-source shapes. Deliberately NOT a blanket ban on `/`: three
   * delivery refusals name the operator's own configured PATH, which A24
   * requires them to do — the rule is "the variable and the path, never the
   * content", and never this process's own source.
   */
  const SOURCE_SHAPES: ReadonlyArray<[string, RegExp]> = [
    ['a stack frame', /\n\s+at\s+\S+/],
    ['a TypeScript source location', /\.(?:ts|js|mts|cts):\d+:\d+/],
    ['a node_modules path', /node_modules/],
    ['a file: URL', /file:\/\//],
    ['a repository source path', /\bsrc\/(?:serve\/)?[a-z]+\.(?:ts|js)\b/],
    ['an exception class', /\b(?:TypeError|RangeError|SyntaxError|ConfigRefusal|AssertionError)\b/],
    ['an errno code', /\b(?:ENOENT|EACCES|EPERM|EISDIR|ELOOP|ENAMETOOLONG)\b/],
    ['an Error prefix', /\bError:\s/],
  ];

  test('the corpus is populated by all three venues above', (t) => {
    // Ordering dependency, stated. `node:test` runs the describes in this file
    // in declaration order, so by the time this runs every refusal above has
    // contributed. An empty or one-venue corpus would make every scan below
    // vacuous, so both are the first things asserted.
    t.diagnostic(`${OBSERVED_MESSAGES.length} distinct refusal messages scanned`);
    assert.ok(
      OBSERVED_MESSAGES.length >= 15,
      `only ${OBSERVED_MESSAGES.length} distinct refusal messages were collected`,
    );
    // One marker from each venue, so a venue that silently stopped contributing
    // is caught rather than absorbed by the total.
    const has = (needle: string): boolean =>
      OBSERVED_MESSAGES.some((message) => message.includes(needle));
    assert.ok(has('requires an inbound shared secret'), 'the five-refusal venue contributed none');
    assert.ok(has('is larger than the 4 KiB maximum'), 'the delivery venue contributed none');
    assert.ok(has('must be `bearer` or `none`'), 'the matrix venue contributed none');
  });

  test('no message carries a source path, a stack, an exception class or an errno', () => {
    const offenders: string[] = [];
    for (const message of OBSERVED_MESSAGES) {
      for (const [what, pattern] of SOURCE_SHAPES) {
        if (pattern.test(message)) offenders.push(`${what}: ${message}`);
      }
    }
    assert.deepEqual(offenders, []);
  });

  test('no message carries secret material, at any length', () => {
    // `assertAbsentFromText` refuses an empty needle and never echoes the value
    // it hunts — a failure message is an output channel too, and printing the
    // leaked secret to prove it leaked merely moves the leak into the CI log.
    const needles: ReadonlyArray<[string, string]> = [
      ['the primary secret', GOOD_SECRET],
      ['the secondary secret', `${GOOD_SECRET}-next`],
      ['a 4-character file-delivered secret', 'qZ7x'],
      ['a short plaintext secret', 'tooshort'],
      ['the planted file body', FILE_CONTENT_SENTINEL],
    ];
    for (const [label, needle] of needles) {
      assertAbsentFromText({ 'refusal messages': OBSERVED_MESSAGES }, needle, label);
    }
  });

  test('no message carries the contents of a file it read', () => {
    // The oversize case's file is 5 KiB of a repeating byte. A message quoting
    // any of it would carry a long run of that byte; a message quoting the
    // whole file would be longer than any refusal has any business being.
    for (const message of OBSERVED_MESSAGES) {
      assert.equal(message.includes('p'.repeat(64)), false, 'a refusal echoed file contents');
      assert.ok(
        message.length < 1024,
        `a refusal message is ${message.length} characters long; the only way a refusal gets ` +
          `that long is by quoting something it read`,
      );
    }
  });

  test('every message is a sentence an operator can act on', () => {
    // Not decoration. A refusal that names no variable is a refusal the
    // operator has to read the source to resolve, which is exactly what FR-54
    // exists to prevent.
    for (const message of OBSERVED_MESSAGES) {
      assert.ok(message.trim().length > 0, 'an empty refusal message reached the corpus');
      assert.ok(
        /\bUNIFI_[A-Z0-9_]+\b/.test(message),
        `a refusal names no variable at all: ${message}`,
      );
    }
  });
});
