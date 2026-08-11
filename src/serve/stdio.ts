/**
 * The stdio serving transport, its ordered drain, and the process-level
 * shutdown vocabulary (architecture §1.2, §1.6, §3.2).
 *
 * This is the shipped product's transport and this module must not change what
 * it does: the MCP frame path is byte-for-byte the behaviour of the single
 * `server.connect(new StdioServerTransport())` that stood at `src/index.ts:162`
 * before the split. NFR-19 holds because nothing here writes to stdout — every
 * diagnostic goes through `log.ts` to stderr, and stdout carries protocol
 * frames and nothing else.
 *
 * Unlike HTTP, stdio binds no listener and serves exactly one session, so there
 * is no probe surface on which a `starting` window could be observed and no
 * reason to hand a client a half-built registry: the registry resolves before
 * the transport connects.
 *
 * ## Why the signal handlers live here and not in `src/index.ts`
 *
 * Architecture §1.6 puts the three shutdown rules "all in `index.ts`", and
 * FR-80 requires the handlers to be `main()`'s first statements. Both still
 * hold observably — `installShutdown()` IS that first statement. What moved is
 * the *body*: `src/index.ts` is held under 90 lines by an assertion US-18
 * landed (`test/runtime.test.ts`, AC 9), and the second-signal escalation, the
 * startup backstop and the crash handlers do not fit in the six lines that
 * budget leaves. US-19's file scope is `src/index.ts` and this file, so a
 * dedicated `src/serve/signals.ts` was not available to it. **Carry-forward for
 * US-24:** when `src/serve/http.ts` lands and needs the same handlers, lift
 * `installShutdown` and `EXIT_CODES` into `src/serve/signals.ts` and have both
 * transports import them — an HTTP transport importing the stdio module for its
 * signal handling is the wrong shape to keep.
 *
 * NOT owned here: the HTTP drain (US-24). The vocabulary below is written so
 * that drain can be expressed in it without extension — `EXIT_CODES` is closed,
 * and `STDIO_DRAIN_STEPS` is the stdio subset of architecture §3.2's ordered
 * sequence with the listener-shaped steps (2a's pre-drain hold, 3's
 * `httpServer.close()`, 8's `closeAllConnections()`) absent because stdio binds
 * nothing and serves exactly one session over a pipe it does not own.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';

import { emitDiagnostic, emitError } from './log.js';
import { createMcpServer } from './mcpServer.js';
import {
  resolveRegistry,
  type DrainReason,
  type Runtime,
  type RuntimeCore,
  type Serving,
  type ServingDeps,
  type ServingObserver,
  type ToolHandler,
} from './runtime.js';

/**
 * The CLOSED exit-code vocabulary (architecture §8.3 as ratified at
 * `architecture.md:1153`; US-19's acceptance criterion). Six members, and
 * nothing else may be exited with.
 *
 * `deadline` means the drain budget expired and NOTHING ELSE. That is the whole
 * reason `forcedInterrupt` and `forcedTermination` exist: an operator pressing
 * Ctrl-C twice is the most common human action in the system, and reusing `75`
 * for it would fire ADR-05's reopen trigger — "the 35-second derivation was
 * wrong" — on pure noise, forever.
 *
 * `crash` is distinct from `deadline` so that a shutdown initiated by an
 * uncaught exception or an unhandled rejection is never read as a slow drain.
 */
export const EXIT_CODES = {
  /** Clean shutdown by natural event-loop drain. */
  clean: 0,
  /** Configuration refusal or listen failure. */
  refusal: 1,
  /** Drain initiated by an uncaught exception or an unhandled rejection. */
  crash: 70,
  /** Drain-deadline expiry, and nothing else. */
  deadline: 75,
  /** Operator-forced second SIGINT. */
  forcedInterrupt: 130,
  /** Operator-forced second SIGTERM. */
  forcedTermination: 143,
} as const;

/**
 * The stdio drain, in order, as reported through `ServingObserver.onDrainStep`.
 *
 * This is the observable form of the state machine on every CI leg, including
 * `windows-latest` where no signal can be delivered: `drain()` is idempotent and
 * directly callable, so the sequence is asserted without a signal (MECH-SIGNAL,
 * test strategy §12).
 */
export const STDIO_DRAIN_STEPS = [
  'not-ready',
  'begin-drain',
  'await-in-flight',
  'close-server',
  'close-runtime',
  'exit-code',
] as const;

/** Emitted instead of `exit-code` when the deadline expired first. */
export const STDIO_HARD_STOP_STEP = 'hard-stop';

/**
 * The shutdown budget used before configuration has been read.
 *
 * A signal can arrive before `buildRuntimeCore` has returned, so the startup
 * backstop of architecture §1.6 has to be armed against something. Mirrors
 * `UNIFI_HTTP_SHUTDOWN_DEADLINE_MS`'s default at `src/config.ts:616`; a test
 * asserts the two agree so the mirror cannot drift.
 */
export const DEFAULT_SHUTDOWN_DEADLINE_MS = 35_000;

/**
 * What a caller arriving after the drain began is told.
 *
 * The same sentence the HTTP transport's terminal JSON-RPC error frame carries
 * (test strategy C17), so an operator reading two transports' logs reads one
 * message.
 */
export const DRAIN_REFUSAL_MESSAGE =
  'The server is shutting down and is not accepting new requests. Retry against a new instance.';

/** Registers a process-level listener. Injected so a test never installs one. */
export type ProcessEventRegistrar = (event: string, listener: (...args: unknown[]) => void) => void;

/**
 * Transport-side injection for stdio.
 *
 * Extends `ServingDeps` here rather than widening it in `runtime.ts`, which is
 * the shape the carry-forward register fixes for `HttpServingDeps` in US-22:
 * the SDK transport types belong to the transport module, not to the runtime's
 * import list (§9.4).
 */
export interface StdioServingDeps extends ServingDeps {
  /**
   * The MCP transport. Defaults to `new StdioServerTransport()`, which binds
   * the REAL `process.stdin`/`process.stdout` — so an in-process test that did
   * not override this would read the runner's stdin and write MCP frames into
   * the runner's TAP stream.
   */
  createTransport?: () => Transport;
  /**
   * Where `installShutdown` registers its four listeners. Defaults to
   * `process.on`. A test injects a recorder and drives the handlers directly,
   * which is how the second-signal escalation and the crash path are asserted
   * on all three CI legs without delivering a signal (MECH-SIGNAL).
   */
  on?: ProcessEventRegistrar;
}

/** The handle `main()` holds over the installed handlers. */
export interface Shutdown {
  /**
   * True once a termination signal has been observed. `main()` reads it at
   * architecture §1.3 step 4 — a signal delivered during the synchronous
   * startup stops there, so nothing is served in response to being told to stop.
   */
  readonly aborting: boolean;
  /** Step 4's early return: release the half-built core and hand back an inert handle. */
  abort(core: RuntimeCore): Serving;
  /** Step 6: publish the live handle, and replay a signal that arrived during startup. */
  publish(serving: Serving, deadlineMs: number): void;
}

/**
 * Install the four process-level handlers FR-80 requires.
 *
 * Called as `main()`'s first statement, before any asynchronous work, on both
 * serving transports. The container `ENTRYPOINT` is exec-form with no init
 * process, so the server is PID 1 and owns its own signal disposition: an
 * unhandled SIGTERM to PID 1 on Linux is *ignored*, which is why `docker stop`
 * against the pre-US-19 image waits the full timeout and then SIGKILLs. FR-62
 * pins the `ENTRYPOINT`, so in-process handling is mandatory and no init shim
 * is permitted as the fix.
 */
export function installShutdown(deps: StdioServingDeps = {}): Shutdown {
  const on =
    deps.on ??
    ((event: string, listener: (...args: unknown[]) => void): void => {
      process.on(event, listener);
    });
  const setExitCode = deps.setExitCode ?? ((code: number): void => void (process.exitCode = code));
  // Without an injected hook there is no way to terminate from here — only
  // `src/index.ts` may call the process's own exit — so the best available
  // action is to record the code and let the loop drain. The auto-run guard
  // supplies the real hook, so production always has one.
  const exit = deps.exit ?? setExitCode;

  let serving: Serving | null = null;
  let signalled: 'SIGTERM' | 'SIGINT' | null = null;
  let deadlineMs = DEFAULT_SHUTDOWN_DEADLINE_MS;

  const startDrain = (reason: DrainReason, code: number): void => {
    if (serving === null) {
      // §1.6 rule 2: the deadline timer is armed in the HANDLER, not at drain
      // step 1, so the startup window carries the same bound as the serving
      // window. Without it a signal arriving before the transport connected was
      // never honoured and the orchestrator's grace period ran out to a SIGKILL.
      const backstop = setTimeout(() => exit(EXIT_CODES.deadline), deadlineMs);
      backstop.unref?.();
      setExitCode(code);
      if (reason === 'crash') exit(code);
      return;
    }
    void serving.drain(reason).catch((error: unknown) => {
      // A rejection here was previously unhandled, which killed the process
      // mid-drain with code 1 — the one failure the design has no diagnostic
      // for, neither clean nor deadline (architecture §3.2).
      emitError('drain', error);
      exit(EXIT_CODES.deadline);
    });
  };

  const onSignal = (signal: 'SIGTERM' | 'SIGINT'): void => {
    if (signalled !== null) {
      // Step 0. A second signal means "now": an immediate forced stop rather
      // than a restarted drain. The two signals need not match — a SIGINT
      // during a SIGTERM drain counts as the second, and the code follows the
      // SECOND signal.
      void serving?.dispose().catch(() => undefined);
      exit(signal === 'SIGINT' ? EXIT_CODES.forcedInterrupt : EXIT_CODES.forcedTermination);
      return;
    }
    signalled = signal;
    emitDiagnostic(`${signal} received — draining`);
    startDrain('signal', EXIT_CODES.clean);
  };

  const onCrash = (context: string, error: unknown): void => {
    emitError(context, error);
    startDrain('crash', EXIT_CODES.crash);
  };

  on('SIGTERM', () => onSignal('SIGTERM'));
  on('SIGINT', () => onSignal('SIGINT'));
  on('uncaughtException', (...args: unknown[]) => onCrash('uncaughtException', args[0]));
  on('unhandledRejection', (...args: unknown[]) => onCrash('unhandledRejection', args[0]));

  return {
    get aborting(): boolean {
      return signalled !== null;
    },
    abort(core: RuntimeCore): Serving {
      void core.close().catch((error: unknown) => emitError('abort', error));
      return {
        kind: core.activeSurface,
        address: null,
        drain: (): Promise<'clean' | 'deadline'> => Promise.resolve('clean'),
        dispose: (): Promise<void> => Promise.resolve(),
      };
    },
    publish(live: Serving, ms: number): void {
      serving = live;
      deadlineMs = ms;
      if (signalled !== null) startDrain('signal', EXIT_CODES.clean);
    },
  };
}

/**
 * Start serving MCP over stdin/stdout.
 *
 * The returned `drain()` is idempotent and directly callable, which is what
 * lets the whole state machine be asserted on `windows-latest` with no signal
 * at all (test strategy §12).
 */
export async function startStdio(
  core: RuntimeCore,
  observer?: ServingObserver,
  deps: StdioServingDeps = {},
): Promise<Serving> {
  await resolveRegistry(core);
  if (core.readyError) throw core.readyError;
  observer?.onReady?.();

  const setExitCode = deps.setExitCode ?? ((code: number): void => void (process.exitCode = code));
  const exit = deps.exit ?? setExitCode;
  const step = (name: string): void => observer?.onDrainStep?.(name);

  // The not-ready mark. stdio answers no probe, so this cell is not read by a
  // `/readyz` handler — it is what closes DISPATCH (architecture step 2b): from
  // the moment it flips, every tool call is refused rather than admitted into a
  // handler set step 6 has already snapshotted.
  let draining = false;

  // The in-flight set the drain awaits. Deliberately the HANDLERS' own
  // promises, never the transport's `handleRequest()` — in JSON response mode
  // that promise is settled only by `resolveJson`, which the JSON-mode cleanup
  // never calls, so a drain written against it deadlocks the instant
  // `enableJsonResponse` is ever turned on (FR-70 step 4).
  const inflight = new Set<Promise<unknown>>();
  const handlers: Record<string, ToolHandler> = {};
  for (const [name, handler] of Object.entries(core.handlers)) {
    handlers[name] = async (args: Record<string, unknown>) => {
      if (draining) throw new Error(DRAIN_REFUSAL_MESSAGE);
      const call = handler(args);
      inflight.add(call);
      try {
        return await call;
      } finally {
        inflight.delete(call);
      }
    };
  }

  // The session sees `Runtime`, never the process-scoped lifecycle type, so no
  // per-session path can reach `beginDrain()` or `close()` and take the whole
  // process down. The only field that differs from `core` is the tracked
  // handler map above.
  const session: Runtime = {
    config: core.config,
    credentials: core.credentials,
    client: core.client,
    handlers,
    auth: core.auth,
    activeSurface: core.activeSurface,
    ready: core.ready,
    get readyError() {
      return core.readyError;
    },
    get registry() {
      return core.registry;
    },
    advertisedToolsFor: (surface) => core.advertisedToolsFor(surface),
  };

  const server = createMcpServer(session, 'stdio');
  await server.connect(deps.createTransport?.() ?? new StdioServerTransport());

  // Normative (architecture §3.2): every awaited step is individually caught,
  // logs one line, and the drain continues to the next step. A drain invoked
  // from a signal handler is a promise nobody awaits, so a rejection escaping
  // one step used to skip every step after it.
  const guarded = async (label: string, run: () => unknown): Promise<void> => {
    try {
      await run();
    } catch (error) {
      emitError(`drain ${label}`, error);
    }
  };

  const teardown = async (): Promise<void> => {
    step('not-ready');
    draining = true;
    step('begin-drain');
    await guarded('begin-drain', () => core.beginDrain());
    step('await-in-flight');
    await Promise.allSettled([...inflight]);
    // The SDK sends a tool result AFTER its callback resolves, so closing the
    // server on the same tick would truncate the very response the step above
    // waited for — and FR-70 step 4 exists so that "a client with an
    // outstanding request receives a complete response". One macrotask is
    // enough: the send is initiated from the microtask chain the handler ended.
    await new Promise((resolve) => setImmediate(resolve));
    step('close-server');
    await guarded('close-server', () => server.close());
    step('close-runtime');
    await guarded('close-runtime', () => core.close());
  };

  let outcome: Promise<'clean' | 'deadline'> | null = null;
  let deadlineTimer: NodeJS.Timeout | null = null;

  const drain = (reason: DrainReason): Promise<'clean' | 'deadline'> => {
    outcome ??= (async () => {
      let expire = (): void => undefined;
      const expired = new Promise<'deadline'>((resolve) => {
        expire = (): void => resolve('deadline');
      });
      deadlineTimer = setTimeout(expire, core.config.serving.shutdownDeadlineMs);

      const finished = teardown().then((): 'clean' => 'clean');
      const result = await Promise.race([finished, expired]);

      if (result === 'deadline') {
        // Step H. NFR-27's "never SIGKILLed" is otherwise a hope: something is
        // still holding the loop and only the process's own exit ends it.
        step(STDIO_HARD_STOP_STEP);
        void Promise.resolve(core.close()).catch(() => undefined);
        if (reason !== 'disposal') {
          setExitCode(EXIT_CODES.deadline);
          exit(EXIT_CODES.deadline);
        }
        return 'deadline';
      }

      // Step 10. `dispose()` is teardown only and never touches the exit code,
      // so it never reaches this step at all.
      if (reason !== 'disposal') {
        setExitCode(reason === 'crash' ? EXIT_CODES.crash : EXIT_CODES.clean);
        step('exit-code');
      }
      // Un-ref'd rather than cleared: if everything was released the loop drains
      // and the process exits 0 BY NATURAL DRAIN, which is what proves the
      // agents were destroyed; if something leaked, the timer still fires and
      // reports it as `deadline` instead of a silent hang. `dispose()` clears
      // it, which is what keeps an un-ref'd timer out of a test runner whose
      // loop is always alive.
      deadlineTimer.unref?.();
      return 'clean';
    })();
    return outcome;
  };

  return {
    kind: 'stdio',
    address: null,
    drain,
    async dispose(): Promise<void> {
      await drain('disposal');
      if (deadlineTimer !== null) clearTimeout(deadlineTimer);
    },
  };
}
