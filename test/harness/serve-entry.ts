#!/usr/bin/env node
/**
 * The spawned entrypoint harness (FR-75).
 *
 * NOT a test file, and deliberately not named like one: `scripts/run-tests.mjs`
 * discovers suites with `readdirSync('test').filter(n => n.endsWith('.test.ts'))`,
 * non-recursively. This file sits under `test/harness/` and does not end in
 * `.test.ts`, so the runner never executes it — which is precisely what makes
 * it spawnable.
 *
 * ## Why a spawned child exists at all
 *
 * Six criteria in this round need three things AT ONCE, and no in-process shape
 * provides all three:
 *
 *   1. INJECTION — a `RuntimeDeps` the test controls, so counters read the real
 *      call sites rather than a re-implementation of the branch.
 *   2. A DELIVERED SIGNAL — a real `SIGTERM`, which cannot be sent to the test
 *      runner's own process without taking the suite down with it.
 *   3. AN OBSERVED EXIT CODE — likewise.
 *
 * On top of that, S-09 forbids any `*.test.ts` file from importing
 * `src/index.ts` in-process: the entrypoint installs signal handlers and,
 * once US-19 lands, would install them over the runner's. This file is the one
 * place in the repository permitted to import it, and it is not a test file.
 *
 * ## The contract
 *
 * `argv[2]` is a JSON `ServeEntryDescriptor` (see `counters.ts`). The child:
 *
 *   - builds a counting `RuntimeDeps` + `ServingObserver` over the descriptor's
 *     `env` — never over its own `process.env`, so the parent controls the
 *     configuration exactly;
 *   - calls the PRODUCTION `main(deps, observer)`;
 *   - writes the counters to stderr as ONE prefixed line, on both the success
 *     and the refusal path;
 *   - reproduces `src/index.ts`'s auto-run error rendering, because that guard
 *     does not fire here: this file is the main module, not the entrypoint.
 *
 * The counter line is written on the refusal path FIRST, before the error
 * lines, so a startup-refusal criterion can read `listen: 0` from a process
 * that then exits 1. That ordering is the whole reason FR-73's
 * non-bypassability assertion is not vacuous.
 *
 * A watchdog exits the child after `holdMs`, so a spawn the parent failed to
 * reap cannot outlive the suite and hold a CI runner open.
 */
import { pathToFileURL } from 'node:url';

import { emitDiagnostic, emitError } from '../../src/serve/log.js';
import { ConfigRefusal } from '../../src/serve/runtime.js';
import { main } from '../../src/index.js';

import {
  createInstruments,
  formatCounterLine,
  type ServeEntryDescriptor,
} from './counters.js';

const DEFAULT_HOLD_MS = 20_000;

function readDescriptor(): ServeEntryDescriptor {
  const raw = process.argv[2];
  if (raw === undefined || raw === '') return {};
  return JSON.parse(raw) as ServeEntryDescriptor;
}

async function run(): Promise<void> {
  const descriptor = readDescriptor();
  const wantObserver = descriptor.observer !== false;
  const wantCounters = wantObserver && descriptor.counters !== false;

  // `keychain` is not a descriptor field and cannot be made one: `npm ci`
  // installs keytar on the macOS and Windows legs, so any spawned child that
  // omitted it would query the runner's real login keychain. It is pinned to
  // null here rather than defaulted, so no caller can turn it back on.
  const instruments = createInstruments({ env: { ...(descriptor.env ?? {}) }, keychain: null });

  const emitCounters = (): void => {
    if (wantCounters) process.stderr.write(formatCounterLine(instruments.snapshot()));
  };

  // Ref'd on purpose: in `hold` mode the stdio transport keeps the loop alive
  // anyway, and an unref'd watchdog would let the process exit out from under a
  // parent that is still probing it.
  const watchdog = setTimeout(() => {
    process.stderr.write('unifi-mcp-harness: watchdog fired; the parent did not reap this child\n');
    process.exit(0);
  }, descriptor.holdMs ?? DEFAULT_HOLD_MS);

  try {
    const serving = wantObserver
      ? await main(instruments.deps, instruments.observer)
      : await main(instruments.deps);

    emitCounters();

    if (descriptor.after === 'exit') {
      clearTimeout(watchdog);
      await serving.dispose();
      process.exit(0);
    }
    // `hold`: fall through. The transport holds the event loop open until the
    // parent kills the child or the watchdog fires.
  } catch (error: unknown) {
    // Counters BEFORE the diagnosis: a refusal criterion reads `listen: 0` and
    // the message text from the same run, and a process that has already gone
    // reports neither.
    emitCounters();
    clearTimeout(watchdog);

    // The same rendering `src/index.ts`'s auto-run guard performs. Reproduced
    // rather than reached, because that guard tests `import.meta.url` against
    // `process.argv[1]` and this file is the main module here.
    if (error instanceof ConfigRefusal) {
      for (const message of error.errors) emitDiagnostic(`ERROR ${message}`);
    } else {
      emitError('fatal', error);
    }
    process.exit(1);
  }
}

// The same auto-run guard shape the entrypoint uses. This file is only ever
// spawned, but the guard means an accidental import cannot start a server.
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  void run();
}
