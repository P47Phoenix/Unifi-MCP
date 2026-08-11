/**
 * The parent side of the spawned harness: launch `serve-entry.ts`, read its
 * counters, observe its exit, and probe a port without `lsof` or `ss`.
 *
 * Separate from `serve-entry.ts` on purpose. That file has a top-level auto-run
 * guard, and a test that imported it to reach a spawn helper would be one
 * `argv[1]` accident away from starting a server inside the test runner. The
 * parent-side API therefore lives here and shares only the JSON wire format
 * declared in `counters.ts`.
 *
 * This is a test HELPER, not a test file.
 *
 * ## Ownership note
 *
 * This is the round's ONE spawn helper. US-19 was scoped to keep any spawn
 * shape file-local to `test/signals.test.ts` rather than create a harness,
 * specifically so two concurrent stories did not independently build the same
 * infrastructure — the failure that produced two `bearerMatches` earlier in
 * this round. Later stories that need a spawned child (US-24's ordered drain,
 * US-26's five startup refusals, US-27's raw-socket captures, US-28's probe
 * counters, US-29's assembly) consume this module rather than re-rolling it.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { connect, type Socket } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  parseCounterLine,
  type CounterSnapshot,
  type ServeEntryDescriptor,
} from './counters.js';

const HARNESS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HARNESS_DIR, '..', '..');

/** `fileURLToPath`, never `URL.pathname`: the latter yields `/D:/a/...` on Windows. */
export const SERVE_ENTRY_PATH = join(HARNESS_DIR, 'serve-entry.ts');

/** How long to wait for a child's counter line before calling it a failure. */
const DEFAULT_WAIT_MS = 30_000;

/** How long `stop()` lets a handled signal work before escalating to SIGKILL. */
const DEFAULT_STOP_GRACE_MS = 1_000;

export interface ExitResult {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
}

export interface SpawnOptions {
  /** Extra process environment for the child. Never the config source. */
  readonly env?: Readonly<Record<string, string>>;
}

export interface SpawnedServer {
  readonly child: ChildProcess;
  /** Everything the child has written to stderr so far. */
  stderr(): string;
  /** Everything the child has written to stdout so far — MCP frames, on stdio. */
  stdout(): string;
  /** Resolves once the counter line appears; rejects if the child exits first. */
  counters(timeoutMs?: number): Promise<CounterSnapshot>;
  /** Resolves when stderr satisfies `predicate`; rejects on exit or timeout. */
  waitForStderr(predicate: (text: string) => boolean, timeoutMs?: number): Promise<string>;
  /** Resolves when the child exits. Safe to await more than once. */
  exit(): Promise<ExitResult>;
  /**
   * TEARDOWN, and only teardown. Never assert against what this returns.
   *
   * It sends `signal`, waits `graceMs`, and then escalates to `SIGKILL`. The
   * escalation is deliberate and it is not a workaround for flakiness: a child
   * whose drain is half-built — which is the state of the shutdown path for
   * most of this round — holds the event loop open after a handled `SIGTERM`,
   * and a `finally` block that waited on it would hang every suite that spawns
   * one until the 60 s per-test timeout, hiding the real assertion behind a
   * timeout in an unrelated test.
   *
   * A story asserting graceful shutdown must therefore drive the signal itself
   * — `server.child.kill('SIGTERM')` then `await server.exit()` — so that the
   * exit code it reads is the child's own and not this escalation's. Those
   * assertions are MECH-SIGNAL-scoped; this teardown is not, because on Windows
   * an unconditional termination is exactly what a cleanup path wants.
   */
  stop(signal?: NodeJS.Signals, graceMs?: number): Promise<ExitResult>;
}

/**
 * Spawn the production entrypoint through the harness.
 *
 * `--import tsx` matches `scripts/run-tests.mjs`'s own invocation, so the child
 * loads TypeScript exactly as the suite does and no build step is implied.
 *
 * The child's `process.env` is stripped of every `UNIFI_*` variable. The
 * descriptor's `env` is the configuration source, so a variable exported on a
 * developer's machine must not be able to enable a service, plant a credential
 * or mask a refusal.
 */
export function spawnServeEntry(
  descriptor: ServeEntryDescriptor = {},
  options: SpawnOptions = {},
): SpawnedServer {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key, value]) => !key.startsWith('UNIFI_') && value !== undefined,
    ),
  ) as Record<string, string>;

  const child = spawn(
    process.execPath,
    ['--import', 'tsx', SERVE_ENTRY_PATH, JSON.stringify(descriptor)],
    {
      cwd: REPO_ROOT,
      env: { ...inherited, ...(options.env ?? {}) },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );

  let errText = '';
  let outText = '';
  child.stderr?.setEncoding('utf8');
  child.stdout?.setEncoding('utf8');
  child.stderr?.on('data', (chunk: string) => {
    errText += chunk;
  });
  child.stdout?.on('data', (chunk: string) => {
    outText += chunk;
  });

  let exited: ExitResult | null = null;
  const exitPromise = new Promise<ExitResult>((resolve) => {
    child.once('exit', (code, signal) => {
      exited = { code, signal };
      resolve(exited);
    });
  });

  const waitForStderr = (
    predicate: (text: string) => boolean,
    timeoutMs = DEFAULT_WAIT_MS,
  ): Promise<string> =>
    new Promise<string>((resolve, reject) => {
      let settled = false;
      const finish = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stderr?.removeListener('data', onData);
        child.removeListener('exit', onExit);
        fn();
      };

      const check = (): boolean => {
        if (!predicate(errText)) return false;
        finish(() => resolve(errText));
        return true;
      };

      const onData = (): void => {
        check();
      };
      const onExit = (): void => {
        // Checked once more first: a child that emits the line and exits in the
        // same tick would otherwise lose the race against its own exit event.
        if (check()) return;
        finish(() =>
          reject(
            new Error(
              `the spawned child exited before stderr satisfied the predicate.\n--- stderr ---\n${errText}`,
            ),
          ),
        );
      };
      const timer = setTimeout(() => {
        finish(() =>
          reject(
            new Error(
              `timed out after ${timeoutMs} ms waiting on the spawned child's stderr.\n` +
                `--- stderr ---\n${errText}`,
            ),
          ),
        );
      }, timeoutMs);

      if (check()) return;
      if (exited !== null) {
        onExit();
        return;
      }
      child.stderr?.on('data', onData);
      child.once('exit', onExit);
    });

  return {
    child,
    stderr: () => errText,
    stdout: () => outText,
    waitForStderr,
    async counters(timeoutMs = DEFAULT_WAIT_MS): Promise<CounterSnapshot> {
      const text = await waitForStderr((seen) => parseCounterLine(seen) !== null, timeoutMs);
      const parsed = parseCounterLine(text);
      if (parsed === null) throw new Error('the counter line vanished between match and parse');
      return parsed;
    },
    exit: () => exitPromise,
    async stop(
      signal: NodeJS.Signals = 'SIGTERM',
      graceMs = DEFAULT_STOP_GRACE_MS,
    ): Promise<ExitResult> {
      if (exited !== null) return exitPromise;
      child.kill(signal);

      // Unref'd: on the ordinary path the child is already gone and this timer
      // must not be the thing that keeps the TEST process alive.
      const escalation = setTimeout(() => child.kill('SIGKILL'), graceMs);
      escalation.unref();
      try {
        return await exitPromise;
      } finally {
        clearTimeout(escalation);
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Port probing, without lsof and without ss
// ---------------------------------------------------------------------------

export type ProbeResult =
  | { readonly outcome: 'refused'; readonly code: string }
  | { readonly outcome: 'connected' }
  | { readonly outcome: 'error'; readonly code: string; readonly message: string }
  | { readonly outcome: 'timeout' };

/**
 * Ask whether anything is listening, portably.
 *
 * `lsof` and `ss` are used NOWHERE in this repository: neither exists on
 * `windows-latest`, and NFR-20 requires that leg green. A connection attempt is
 * the portable negative — it answers the same question with the standard
 * library on all three platforms.
 *
 * The result is returned rather than asserted so the caller owns the failure
 * message, and so that `connected` is a first-class outcome instead of a
 * timeout that reads like flakiness.
 */
export function probePort(
  port: number,
  host = '127.0.0.1',
  timeoutMs = 2_000,
): Promise<ProbeResult> {
  return new Promise<ProbeResult>((resolve) => {
    let settled = false;
    const finish = (result: ProbeResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const socket: Socket = connect({ host, port });
    const timer = setTimeout(() => finish({ outcome: 'timeout' }), timeoutMs);

    socket.once('connect', () => finish({ outcome: 'connected' }));
    socket.once('error', (error: NodeJS.ErrnoException) => {
      const code = error.code ?? 'UNKNOWN';
      finish(
        code === 'ECONNREFUSED'
          ? { outcome: 'refused', code }
          : { outcome: 'error', code, message: error.message },
      );
    });
  });
}

/** The serving transport's default port (`UNIFI_HTTP_PORT`, `src/config.ts`). */
export const DEFAULT_SERVING_PORT = 8787;
