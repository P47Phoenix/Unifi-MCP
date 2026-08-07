/**
 * US-19 — signals, the stdio drain, and the exit-code vocabulary.
 *
 * Five sections, in the order the story's acceptance criteria run:
 *
 *  1. Installation order — the handlers are `main()`'s first statement, before
 *     any asynchronous work. Source scan, portable, runs on every CI leg.
 *  2. The exit-code vocabulary is CLOSED, and its one mirrored constant cannot
 *     drift from `src/config.ts`.
 *  3. The stdio drain state machine, through the directly-invoked `drain()`:
 *     the ordered steps, idempotence, the dispatch stop, the in-flight wait,
 *     the deadline and the hard stop.
 *  4. The installed handlers themselves, driven directly through an injected
 *     registrar: first signal, second-signal escalation, a signal that lands
 *     during startup, and the two crash handlers.
 *  5. Real signal DELIVERY, in a spawned child.
 *
 * ## MECH-SIGNAL scoping, and why only section 5 carries it
 *
 * `process.on('SIGTERM')` registers silently on Windows and is undeliverable:
 * the handler never runs and termination is unconditional. A test that sends a
 * signal there is not flaky, it is unsatisfiable by any correct implementation.
 * NFR-20 requires the three-OS matrix green, so section 5 — and ONLY section 5,
 * which is the delivery half — carries a declared, reported skip.
 *
 * Sections 1 to 4 run UNSCOPED, including on `windows-latest`. That is the
 * point of the two seams this story leans on: `Serving.drain()` is idempotent
 * and directly callable, and `StdioServingDeps.on` lets the four handlers be
 * installed into a recorder and invoked as ordinary functions. Between them the
 * whole state machine, the whole vocabulary and the whole escalation path are
 * asserted with no signal at all. A green Windows leg therefore asserts the
 * drain state machine — never the shutdown guarantee (owner decision, OQ-18:
 * Windows is a supported development and stdio platform and is NOT a supported
 * HTTP deployment target).
 *
 * ## The spawned-child helper is deliberately file-local
 *
 * `test/harness/serve-entry.ts` is US-25's, being built in this same wave. Two
 * agents independently creating the same infrastructure is the failure mode
 * that already cost this round once, so `spawnServer` below is scoped to this
 * file and a later story migrates it onto the canonical harness.
 *
 * `src/index.ts` is never imported here (test strategy S-09): importing the
 * entrypoint would install signal handlers over the runner's own. Section 1
 * scans it and section 5 spawns it.
 */
import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { CredentialStore, type CredentialStoreOptions } from '../src/credentials.js';
import { UnifiClient } from '../src/http/client.js';
import { buildRegistry, type SpecManifest } from '../src/registry/build.js';
import {
  buildRuntimeCore,
  resolveRegistry,
  type DrainReason,
  type RuntimeCore,
  type RuntimeDeps,
  type Serving,
  type ServingObserver,
  type ToolHandler,
} from '../src/serve/runtime.js';
import {
  DEFAULT_SHUTDOWN_DEADLINE_MS,
  DRAIN_REFUSAL_MESSAGE,
  EXIT_CODES,
  installShutdown,
  startStdio,
  STDIO_DRAIN_STEPS,
  STDIO_HARD_STOP_STEP,
  type ProcessEventRegistrar,
} from '../src/serve/stdio.js';
import type { ServerConfig } from '../src/config.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC_ROOT = join(REPO_ROOT, 'src');
const SENTINEL = `SENTINEL-${'k'.repeat(32)}`;

/**
 * The one tool whose whole input schema is optional, so a `tools/call` with no
 * arguments reaches the handler instead of failing schema validation. Asserted
 * below rather than assumed.
 */
const OPEN_TOOL = 'unifi_list_consoles';

/** MECH-SIGNAL. The reason string is mandatory and must name the portable cover. */
const MECH_SIGNAL_SKIP =
  process.platform === 'win32'
    ? 'MECH-SIGNAL: process.kill() terminates unconditionally on Windows; no handler runs. ' +
      'Sections 3 and 4 of this file assert the same drain state machine, exit-code vocabulary ' +
      'and second-signal escalation on this leg through the directly-invoked drain() and an ' +
      'injected process-event registrar.'
    : false;

// ===========================================================================
// Shared runtime harness
// ===========================================================================

function baseEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { UNIFI_API_KEY: SENTINEL, ...extra };
}

/**
 * `keychain: null` on every store is not optional (S-09): `npm ci` installs
 * `keytar` on the macOS and Windows legs, so a store built without it would
 * query the runner's — or a developer's — real login keychain.
 */
function runtimeDeps(env: NodeJS.ProcessEnv): RuntimeDeps {
  return {
    env,
    warn: () => undefined,
    createCredentialStore: (config: ServerConfig, options: CredentialStoreOptions) =>
      new CredentialStore(config, { ...options, keychain: null }),
    createClient: (config, credentials, options) => new UnifiClient(config, credentials, options),
    readManifest: () =>
      JSON.parse(readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8')) as SpecManifest,
    buildRegistry,
  };
}

interface Rig {
  readonly core: RuntimeCore;
  readonly serving: Serving;
  readonly client: Client;
  readonly steps: string[];
  readonly exits: number[];
  readonly codes: number[];
  /** Settles the tool call the rig's handler is holding open. */
  release(): void;
  /** How many times the injected handler was entered. */
  entered(): number;
  stop(): Promise<void>;
}

/**
 * One live stdio session over an in-memory transport pair, with a handler whose
 * completion the test controls.
 *
 * The transport is injected because `new StdioServerTransport()` binds the REAL
 * `process.stdin`/`process.stdout`: an in-process test that took the default
 * would read the runner's stdin and write MCP frames into its TAP stream.
 */
async function startRig(options: { deadlineMs?: number; stall?: boolean } = {}): Promise<Rig> {
  const env = baseEnv(
    options.deadlineMs === undefined
      ? {}
      : { UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: String(options.deadlineMs) },
  );
  const core = buildRuntimeCore(runtimeDeps(env));
  await resolveRegistry(core);
  assert.equal(core.readyError, null, 'the rig failed to build its registry');

  assert.ok(
    core.advertisedToolsFor('stdio').some((tool) => tool.name === OPEN_TOOL),
    `${OPEN_TOOL} is not advertised on stdio, so this file's dispatch fixture is invalid`,
  );

  let entered = 0;
  let release = (): void => undefined;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const handler: ToolHandler = async () => {
    entered += 1;
    if (options.stall === true) await new Promise<never>(() => undefined);
    else await held;
    return { content: [{ type: 'text' as const, text: 'ok' }] };
  };
  core.handlers[OPEN_TOOL] = handler;

  const steps: string[] = [];
  const exits: number[] = [];
  const codes: number[] = [];
  const observer: ServingObserver = { onDrainStep: (step) => steps.push(step) };

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const serving = await startStdio(core, observer, {
    createTransport: () => serverTransport,
    exit: (code) => exits.push(code),
    setExitCode: (code) => codes.push(code),
  });

  const client = new Client({ name: 'us-19', version: '0.0.0' });
  await client.connect(clientTransport);

  return {
    core,
    serving,
    client,
    steps,
    exits,
    codes,
    release,
    entered: () => entered,
    async stop(): Promise<void> {
      release();
      await client.close().catch(() => undefined);
      await serving.dispose();
    },
  };
}

// ===========================================================================
// 1. FR-80 — the handlers are installed before any asynchronous work
// ===========================================================================

describe('installation order (FR-80, portable half — runs on every leg)', () => {
  const index = readFileSync(join(SRC_ROOT, 'index.ts'), 'utf8');
  const stdio = readFileSync(join(SRC_ROOT, 'serve', 'stdio.ts'), 'utf8');

  /** `main()`'s body, from its opening brace to the matching close. */
  function mainBody(source: string): string {
    const start = source.indexOf('): Promise<Serving> {');
    assert.notEqual(start, -1, "main()'s signature was not found");
    const body = source.slice(start);
    const end = body.indexOf('\n}');
    assert.notEqual(end, -1, "main()'s body was not delimited");
    return body.slice(0, end);
  }

  test('the handler installation is the first statement of main()', () => {
    const body = mainBody(index);
    const statements = body
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('//') && !line.startsWith('*'))
      .slice(1);
    assert.match(
      statements[0] ?? '',
      /installShutdown\(/,
      "main()'s first statement must install the shutdown handlers",
    );
  });

  test('no await precedes the installation', () => {
    const body = mainBody(index);
    const install = body.indexOf('installShutdown(');
    const firstAwait = body.indexOf('await ');
    assert.notEqual(install, -1);
    assert.ok(
      firstAwait === -1 || firstAwait > install,
      'an await runs before the handlers are installed, so a signal in that window is lost',
    );
  });

  test('all four handlers are registered, and by one call', () => {
    // SIGTERM and SIGINT are the operator's; uncaughtException and
    // unhandledRejection are what turn a crash into the SAME ordered drain
    // rather than a process that skips the terminal frames and the agent
    // destruction on its way out.
    for (const event of ['SIGTERM', 'SIGINT', 'uncaughtException', 'unhandledRejection']) {
      assert.ok(
        stdio.includes(`on('${event}'`),
        `${event} has no handler, so that termination path is unhandled`,
      );
    }
    assert.equal(
      (index.match(/installShutdown\(/g) ?? []).length,
      1,
      'installation must happen exactly once, at one place',
    );
  });

  test('the abort check precedes the transport activation and the transport start', () => {
    // FR-80's "SIGTERM before the listener has bound binds nothing". On stdio
    // there is no listener to refuse a connection against, so the assertable
    // form is structural plus behavioural: the abort gate sits BEFORE both the
    // activation counter and `startStdio`, and section 4 drives the handler
    // that sets it. The `net.connect` -> ECONNREFUSED half belongs to the HTTP
    // surface and is A2's, in US-25's spawned harness.
    const body = mainBody(index);
    const abort = body.indexOf('shutdown.aborting');
    const activated = body.indexOf('onTransportActivated');
    const started = body.indexOf('startStdio(');
    assert.ok(abort > -1 && activated > abort, 'a transport is counted before the abort gate');
    assert.ok(started > abort, 'a transport is started before the abort gate');
  });

  test('the transport module never ends the process itself', () => {
    // The auto-run guard in `src/index.ts` is the only place in `src/` allowed
    // to do that, which is why the hard stop calls an INJECTED hook. Without
    // the injection an un-ref'd deadline timer arming a real exit inside a test
    // runner would kill the suite mid-file.
    assert.equal(stdio.includes('process.exit('), false);
  });
});

// ===========================================================================
// 2. The exit-code vocabulary is closed
// ===========================================================================

describe('the exit-code vocabulary (portable — runs on every leg)', () => {
  test('it is exactly six members with exactly these values', () => {
    assert.deepEqual(
      { ...EXIT_CODES },
      {
        clean: 0,
        refusal: 1,
        crash: 70,
        deadline: 75,
        forcedInterrupt: 130,
        forcedTermination: 143,
      },
    );
  });

  test('75 means drain-deadline expiry and nothing else', () => {
    // The reason the forced-stop codes exist at all. A human pressing Ctrl-C
    // twice is the most common human action in the system; emitting 75 for it
    // would fire ADR-05's reopen trigger — "the 35-second derivation was
    // wrong" — on pure noise, forever.
    const distinct = new Set(Object.values(EXIT_CODES));
    assert.equal(distinct.size, Object.keys(EXIT_CODES).length, 'two outcomes share a code');
    assert.notEqual(EXIT_CODES.deadline, EXIT_CODES.crash);
    assert.notEqual(EXIT_CODES.deadline, EXIT_CODES.forcedTermination);
    assert.notEqual(EXIT_CODES.deadline, EXIT_CODES.forcedInterrupt);
  });

  test('no source file exits with a bare numeric literal', () => {
    const offenders: string[] = [];
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
        entry.isDirectory()
          ? walk(join(dir, entry.name))
          : entry.name.endsWith('.ts')
            ? [join(dir, entry.name)]
            : [],
      );
    for (const file of walk(SRC_ROOT)) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(/\bexit\((\d+)\)/g)) {
        offenders.push(`${file}: exit(${match[1] ?? ''})`);
      }
    }
    assert.deepEqual(offenders, [], 'every exit must name a member of the closed vocabulary');
  });

  test('the startup-window default mirrors UNIFI_HTTP_SHUTDOWN_DEADLINE_MS', () => {
    // A signal can arrive before configuration has been read, so the backstop
    // has to be armed against a literal. This is the drift detector for it.
    const core = buildRuntimeCore(runtimeDeps(baseEnv()));
    assert.equal(core.config.serving.shutdownDeadlineMs, DEFAULT_SHUTDOWN_DEADLINE_MS);
  });
});

// ===========================================================================
// 3. The drain state machine, directly invoked (MECH-SIGNAL portable half)
// ===========================================================================

describe('the stdio drain (portable — runs on every leg, no signal delivered)', () => {
  test('the ordered steps fire, it returns clean, and it sets exit code 0', async () => {
    const rig = await startRig();
    try {
      rig.release();
      assert.equal(await rig.serving.drain('signal'), 'clean');
      assert.deepEqual(rig.steps, [...STDIO_DRAIN_STEPS]);
      assert.deepEqual(rig.codes, [EXIT_CODES.clean]);
      assert.deepEqual(rig.exits, [], 'a clean drain exits by natural event-loop drain');
    } finally {
      await rig.stop();
    }
  });

  test('it is idempotent — a second call re-runs nothing', async () => {
    const rig = await startRig();
    try {
      rig.release();
      const first = await rig.serving.drain('signal');
      const second = await rig.serving.drain('signal');
      assert.equal(first, 'clean');
      assert.equal(second, 'clean');
      assert.deepEqual(rig.steps, [...STDIO_DRAIN_STEPS], 'the steps ran twice');
      assert.deepEqual(rig.codes, [EXIT_CODES.clean]);
    } finally {
      await rig.stop();
    }
  });

  test('dispatch closes: a call arriving after the drain began is refused', async () => {
    // Architecture step 2b. Without it an ordinary `tools/call` arriving after
    // the drain started passes the whole pipeline, reaches a handler whose
    // outbound client already rejects, and returns a tool error that blames the
    // rate limiter — while its promise joins the in-flight set AFTER step 6 has
    // already snapshotted it.
    const rig = await startRig();
    try {
      const held = rig.client.callTool({ name: OPEN_TOOL, arguments: {} });
      while (rig.entered() === 0) await new Promise((resolve) => setImmediate(resolve));
      const drained = rig.serving.drain('signal');
      while (!rig.steps.includes('await-in-flight')) {
        await new Promise((resolve) => setImmediate(resolve));
      }

      const refused = JSON.stringify(await rig.client.callTool({ name: OPEN_TOOL, arguments: {} }));
      assert.match(refused, /shutting down/, 'a request during drain must be refused');
      assert.equal(rig.entered(), 1, 'the refused call must never reach the handler');
      assert.match(DRAIN_REFUSAL_MESSAGE, /Retry against a new instance\./);

      rig.release();
      assert.equal(await drained, 'clean');
      await held;
    } finally {
      await rig.stop();
    }
  });

  test('the drain awaits the in-flight handler, not the transport', async () => {
    // FR-70 step 4. Never `handleRequest()`: in JSON response mode that promise
    // is settled only by `resolveJson`, which the JSON-mode cleanup never
    // calls, so a drain written against it deadlocks the instant
    // `enableJsonResponse` is ever turned on.
    const rig = await startRig();
    try {
      const call = rig.client.callTool({ name: OPEN_TOOL, arguments: {} });
      while (rig.entered() === 0) await new Promise((resolve) => setImmediate(resolve));

      let settled = false;
      const drained = rig.serving.drain('signal').then((outcome) => {
        settled = true;
        return outcome;
      });
      await new Promise((resolve) => setTimeout(resolve, 25));
      assert.equal(settled, false, 'the drain resolved while a handler was still running');
      assert.deepEqual(rig.steps.slice(0, 3), ['not-ready', 'begin-drain', 'await-in-flight']);

      rig.release();
      assert.equal(await drained, 'clean');
      await call;
      assert.deepEqual(rig.codes, [EXIT_CODES.clean]);
    } finally {
      await rig.stop();
    }
  });

  test('the deadline expires to the hard stop and exit 75, not to a hang', async () => {
    // 150 ms, not 35 000: the runner has a 60 s per-test ceiling and a suite
    // that sleeps through a real shutdown deadline is a defect, not a test.
    const rig = await startRig({ deadlineMs: 150, stall: true });
    try {
      void rig.client.callTool({ name: OPEN_TOOL, arguments: {} }).catch(() => undefined);
      while (rig.entered() === 0) await new Promise((resolve) => setImmediate(resolve));

      assert.equal(await rig.serving.drain('signal'), 'deadline');
      assert.ok(rig.steps.includes(STDIO_HARD_STOP_STEP), 'the hard stop never ran');
      assert.equal(rig.steps.includes('exit-code'), false, 'a timed-out drain is not clean');
      assert.deepEqual(rig.codes, [EXIT_CODES.deadline]);
      assert.deepEqual(rig.exits, [EXIT_CODES.deadline]);
    } finally {
      await rig.stop();
    }
  });

  test('a crash-initiated drain exits 70, distinct from the deadline', async () => {
    const rig = await startRig();
    try {
      rig.release();
      assert.equal(await rig.serving.drain('crash'), 'clean');
      assert.deepEqual(rig.codes, [EXIT_CODES.crash]);
      assert.deepEqual(rig.exits, []);
    } finally {
      await rig.stop();
    }
  });

  test('dispose() is teardown only — it sets no exit code and exits nothing', async () => {
    const rig = await startRig();
    try {
      rig.release();
      await rig.serving.dispose();
      assert.deepEqual(rig.steps, [...STDIO_DRAIN_STEPS.filter((step) => step !== 'exit-code')]);
      assert.deepEqual(rig.codes, []);
      assert.deepEqual(rig.exits, []);
    } finally {
      await rig.stop();
    }
  });
});

// ===========================================================================
// 4. The installed handlers, driven directly (MECH-SIGNAL portable half)
// ===========================================================================

interface Installed {
  readonly fire: (event: string, ...args: unknown[]) => void;
  readonly exits: number[];
  readonly codes: number[];
  readonly drains: DrainReason[];
  readonly disposals: number;
  readonly shutdown: ReturnType<typeof installShutdown>;
  readonly serving: Serving;
}

/**
 * `installShutdown` over a recorder rather than `process.on`.
 *
 * This is what makes the second-signal escalation and both crash paths
 * assertable on `windows-latest`: the handlers are ordinary functions, and
 * invoking one is indistinguishable from the kernel invoking it — except that
 * it never touches the test runner's own signal disposition.
 */
function install(): Installed {
  const listeners = new Map<string, Array<(...args: unknown[]) => void>>();
  const on: ProcessEventRegistrar = (event, listener) => {
    listeners.set(event, [...(listeners.get(event) ?? []), listener]);
  };
  const exits: number[] = [];
  const codes: number[] = [];
  const drains: DrainReason[] = [];
  const state = { disposals: 0 };

  const serving: Serving = {
    kind: 'stdio',
    address: null,
    drain: (reason) => {
      drains.push(reason);
      return Promise.resolve('clean');
    },
    dispose: () => {
      state.disposals += 1;
      return Promise.resolve();
    },
  };

  const shutdown = installShutdown({
    on,
    exit: (code) => exits.push(code),
    setExitCode: (code) => codes.push(code),
  });

  return {
    fire: (event, ...args) => {
      const found = listeners.get(event);
      assert.ok(found !== undefined && found.length > 0, `no listener registered for ${event}`);
      for (const listener of found) listener(...args);
    },
    exits,
    codes,
    drains,
    get disposals(): number {
      return state.disposals;
    },
    shutdown,
    serving,
  };
}

describe('the installed handlers (portable — runs on every leg)', () => {
  test('SIGTERM on a running server starts one drain and nothing else', () => {
    const rig = install();
    rig.shutdown.publish(rig.serving, 1_000);
    rig.fire('SIGTERM');
    assert.deepEqual(rig.drains, ['signal']);
    assert.deepEqual(rig.exits, []);
    assert.equal(rig.shutdown.aborting, true);
  });

  test('SIGINT does the same', () => {
    const rig = install();
    rig.shutdown.publish(rig.serving, 1_000);
    rig.fire('SIGINT');
    assert.deepEqual(rig.drains, ['signal']);
    assert.deepEqual(rig.exits, []);
  });

  test('a second SIGTERM escalates to 143 rather than restarting the drain', () => {
    const rig = install();
    rig.shutdown.publish(rig.serving, 1_000);
    rig.fire('SIGTERM');
    rig.fire('SIGTERM');
    assert.deepEqual(rig.drains, ['signal'], 'the drain was restarted');
    assert.deepEqual(rig.exits, [EXIT_CODES.forcedTermination]);
    assert.equal(rig.disposals, 1, 'the forced stop must still release resources');
  });

  test('a second SIGINT escalates to 130', () => {
    const rig = install();
    rig.shutdown.publish(rig.serving, 1_000);
    rig.fire('SIGINT');
    rig.fire('SIGINT');
    assert.deepEqual(rig.exits, [EXIT_CODES.forcedInterrupt]);
  });

  test('the two signals need not match — the code follows the SECOND', () => {
    const rig = install();
    rig.shutdown.publish(rig.serving, 1_000);
    rig.fire('SIGTERM');
    rig.fire('SIGINT');
    assert.deepEqual(rig.exits, [EXIT_CODES.forcedInterrupt]);
  });

  test('a signal during startup aborts before anything is served', async () => {
    // Architecture §1.6. The failure this closes is a process that opened a
    // port on the network IN RESPONSE to being told to terminate — a pod that
    // binds, answers /healthz, joins the endpoints, and immediately drains.
    const rig = install();
    rig.fire('SIGTERM');
    assert.equal(rig.shutdown.aborting, true, 'main() must observe the abort at step 4');
    assert.deepEqual(rig.drains, [], 'there was nothing to drain yet');
    assert.deepEqual(rig.codes, [EXIT_CODES.clean]);

    const core = buildRuntimeCore(runtimeDeps(baseEnv()));
    const inert = rig.shutdown.abort(core);
    assert.equal(inert.address, null, 'the aborted startup must bind nothing');
    assert.equal(await inert.drain('signal'), 'clean');
    await inert.dispose();
    await core.close();
  });

  test('a signal during startup is replayed once the handle exists', () => {
    // The window between the handler firing and `startStdio` returning is real
    // on a slow container: the drain has to run when the handle finally lands.
    const rig = install();
    rig.fire('SIGTERM');
    assert.deepEqual(rig.drains, []);
    rig.shutdown.publish(rig.serving, 1_000);
    assert.deepEqual(rig.drains, ['signal']);
  });

  test('an uncaught exception drains with reason crash', () => {
    const rig = install();
    rig.shutdown.publish(rig.serving, 1_000);
    rig.fire('uncaughtException', new Error('boom'));
    assert.deepEqual(rig.drains, ['crash']);
    assert.equal(rig.shutdown.aborting, false, 'a crash is not an operator signal');
  });

  test('an unhandled rejection does the same, and exits 70 before serving exists', () => {
    const rig = install();
    rig.fire('unhandledRejection', new Error('boom'));
    assert.deepEqual(rig.drains, []);
    assert.deepEqual(rig.codes, [EXIT_CODES.crash]);
    assert.deepEqual(rig.exits, [EXIT_CODES.crash]);
  });
});

// ===========================================================================
// 5. Real signal delivery, in a spawned child — MECH-SIGNAL scoped
// ===========================================================================

const children = new Set<ChildProcessWithoutNullStreams>();
after(() => {
  for (const child of children) if (child.exitCode === null) child.kill('SIGKILL');
});

interface Child {
  readonly proc: ChildProcessWithoutNullStreams;
  /** Resolves when the server has answered an MCP `initialize` over real stdio. */
  ready(): Promise<void>;
  exited(): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/**
 * Spawn the PRODUCTION entrypoint and speak enough MCP to know it is serving.
 *
 * Readiness is proven by a protocol round trip rather than by matching a stderr
 * line: US-20 owns the startup diagnostics and is rewriting them in this same
 * wave, so a stderr matcher here would be a cross-story coupling with no
 * requirement behind it.
 */
function spawnServer(extra: NodeJS.ProcessEnv = {}): Child {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key, value]) => !key.startsWith('UNIFI_') && value !== undefined,
    ),
  ) as Record<string, string>;

  const proc = spawn(
    process.execPath,
    ['--import', 'tsx', join(REPO_ROOT, 'src', 'index.ts')],
    {
      cwd: REPO_ROOT,
      env: { ...inherited, UNIFI_API_KEY: SENTINEL, ...extra },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  ) as ChildProcessWithoutNullStreams;
  children.add(proc);
  proc.stderr.resume();

  return {
    proc,
    async ready(): Promise<void> {
      let buffered = '';
      const answered = new Promise<void>((resolve, reject) => {
        proc.stdout.setEncoding('utf8');
        proc.stdout.on('data', (chunk: string) => {
          buffered += chunk;
          if (buffered.includes('\n')) resolve();
        });
        proc.once('exit', (code) => reject(new Error(`the child exited (${String(code)})`)));
      });
      proc.stdin.write(
        `${JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'us-19-signals', version: '0.0.0' },
          },
        })}\n`,
      );
      await answered;
    },
    exited(): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
      return new Promise((resolve) => {
        proc.once('exit', (code, signal) => resolve({ code, signal }));
      });
    },
  };
}

describe('real signal delivery (MECH-SIGNAL — POSIX legs only)', () => {
  test(
    'SIGTERM to a running stdio process exits 0 within the deadline',
    { skip: MECH_SIGNAL_SKIP },
    async () => {
      // The requirement this closes: the container ENTRYPOINT is exec-form with
      // no init process, so the server is PID 1 and owns its own signal
      // disposition. An unhandled SIGTERM to PID 1 on Linux is IGNORED, which is
      // why `docker stop` against the pre-US-19 image waited the full timeout
      // and then SIGKILLed. FR-62 pins the ENTRYPOINT, so no init shim is
      // permitted as the fix.
      const child = spawnServer({ UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: '5000' });
      await child.ready();
      const exit = child.exited();
      child.proc.kill('SIGTERM');
      assert.deepEqual(await exit, { code: EXIT_CODES.clean, signal: null });
    },
  );

  test('SIGINT does the same', { skip: MECH_SIGNAL_SKIP }, async () => {
    const child = spawnServer({ UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: '5000' });
    await child.ready();
    const exit = child.exited();
    child.proc.kill('SIGINT');
    assert.deepEqual(await exit, { code: EXIT_CODES.clean, signal: null });
  });

  test(
    'SIGTERM delivered at spawn terminates rather than hanging',
    { skip: MECH_SIGNAL_SKIP },
    async () => {
      // The observable half of "handlers are installed before any await". A
      // spawned child cannot distinguish "before main() ran" from "before the
      // first await" — at t+1 ms the module graph is usually still loading, so
      // the kernel's default disposition may legitimately win, which is a
      // terminating outcome too. The ORDERING half is asserted by section 1's
      // source scan and by section 4, which drives the handler directly.
      const child = spawnServer({ UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: '5000' });
      const exit = child.exited();
      child.proc.kill('SIGTERM');
      const result = await exit;
      assert.ok(
        result.code === EXIT_CODES.clean || result.signal === 'SIGTERM',
        `startup neither drained nor terminated: ${JSON.stringify(result)}`,
      );
    },
  );
});
