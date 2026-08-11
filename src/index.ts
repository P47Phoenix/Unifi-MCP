#!/usr/bin/env node
/**
 * UniFi MCP — entrypoint, and nothing else.
 *
 * Local deployment is not a fallback here: Network and Protect in local-direct
 * mode sit at private LAN addresses no hosted server can route to, and UniFi's
 * user-supplied API key has no OAuth and no hosted collection path (ADR-01).
 *
 * NFR-19: on stdio, stdout carries protocol frames and nothing else. Every
 * diagnostic goes to stderr through `serve/log.ts` — the one module permitted
 * to write to that stream. A text scan over this file and `src/serve/` enforces
 * it, so the forbidden call is named in prose rather than spelled out: a scan
 * cannot tell a mention from a use.
 *
 * The object graph is `serve/runtime.ts`, the session server
 * `serve/mcpServer.ts`, the two transports `serve/stdio.ts` and `serve/http.ts`,
 * and the shutdown vocabulary `serve/stdio.ts`. What is left is the branch, the
 * handler installation and the auto-run guard — the ONLY place in `src/` that
 * ends the process (FR-62, FR-80).
 */
import { pathToFileURL } from 'node:url';

import { healthcheck } from './healthcheck.js';
import { selfTest } from './selftest.js';
import { startHttp } from './serve/http.js';
import { emitDiagnostic, emitError } from './serve/log.js';
import {
  buildRuntimeCore,
  ConfigRefusal,
  type RuntimeDeps,
  type Serving,
  type ServingDeps,
  type ServingObserver,
} from './serve/runtime.js';
import { EXIT_CODES, installShutdown, startStdio } from './serve/stdio.js';

/**
 * `deps`, `observer` and `servingDeps` exist because FR-62's
 * transport-activation counter and FR-73's `listen` counter are assertions
 * about the PRODUCTION entrypoint: a test re-implementing this branch would
 * assert its own harness. Auto-running only as the process's own main module
 * also means importing this file installs no handlers over the runner's.
 */
export async function main(
  deps: RuntimeDeps = {},
  observer?: ServingObserver,
  servingDeps: ServingDeps = {},
): Promise<Serving> {
  // FR-80: SIGTERM, SIGINT, uncaughtException and unhandledRejection are
  // installed by this call, main()'s first statement, before any await.
  const shutdown = installShutdown(servingDeps);
  const core = buildRuntimeCore(deps);
  // Architecture §1.6: a signal delivered during the synchronous startup above
  // stops here. Nothing is activated and nothing binds, so the process never
  // joins a load balancer's endpoints after being told to terminate.
  if (shutdown.aborting) return shutdown.abort(core);

  // Counted at the branch, not inside either transport module: one counter
  // increments for the surface taken and the other never does (FR-62).
  const surface = core.config.activeSurface;
  observer?.onTransportActivated?.(surface);
  // A two-arm selection, never a fall-back: an unrecognised value was already
  // refused by `buildRuntimeCore`, so these arms are the whole surface set. A
  // fall-back to stdio would serve the stdio write set on a surface the
  // operator narrowed with UNIFI_HTTP_ALLOW_WRITES.
  const serving =
    surface === 'http'
      ? await startHttp(core, observer, servingDeps)
      : await startStdio(core, observer, servingDeps);
  shutdown.publish(serving, core.config.serving.shutdownDeadlineMs);
  return serving;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv.includes('--selftest')) process.exit(selfTest());
  if (process.argv.includes('--healthcheck')) process.exit(await healthcheck()); // FR-68, NFR-25
  // The production exit hook is supplied HERE because this guard is the only
  // place in `src/` permitted to end the process; the drain's hard stop calls it.
  main({}, undefined, { exit: (code) => process.exit(code) }).catch((error: unknown) => {
    // FR-54: name the offending setting so the fix is obvious without reading
    // the source. Everything else goes through the sanitising emitter: this
    // process holds a live credential and an unsanitised message leaks it.
    if (error instanceof ConfigRefusal) {
      for (const message of error.errors) emitDiagnostic(`ERROR ${message}`);
    } else emitError('fatal', error);
    process.exit(EXIT_CODES.refusal);
  });
}
