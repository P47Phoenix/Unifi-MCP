#!/usr/bin/env node
/**
 * UniFi MCP — entrypoint, and nothing else.
 *
 * Local deployment is not a fallback here: Network and Protect in local-direct
 * mode sit at private LAN addresses that no hosted server can route to, and
 * UniFi's long-lived user-supplied API key has no OAuth and no supported
 * collection path for a hosted remote server (ADR-01).
 *
 * NFR-19: on stdio, stdout carries protocol frames and nothing else. Every
 * diagnostic in this process goes to stderr, through `serve/log.ts` — the one
 * module permitted to write to that stream directly. The rule is enforced by a
 * text scan over this file and `src/serve/`, so the forbidden call is named in
 * prose here rather than spelled out: a scan cannot tell a mention from a use.
 *
 * The once-per-process object graph is `serve/runtime.ts`; the per-session
 * server is `serve/mcpServer.ts`; the transport is `serve/stdio.ts`. What is
 * left here is the branch and the auto-run guard, which is the ONLY place in
 * `src/` that calls `process.exit` (FR-62, FR-80).
 */
import { pathToFileURL } from 'node:url';

import { selfTest } from './selftest.js';
import { emitDiagnostic, emitError } from './serve/log.js';
import {
  buildRuntimeCore,
  ConfigRefusal,
  type RuntimeDeps,
  type Serving,
  type ServingDeps,
  type ServingObserver,
} from './serve/runtime.js';
import { startStdio } from './serve/stdio.js';

/**
 * `deps`, `observer` and `servingDeps` exist because FR-62's
 * transport-activation counter and FR-73's `listen` counter are assertions
 * about the PRODUCTION entrypoint: a test that re-implemented this branch would
 * be asserting its own harness. Exporting `main` and auto-running only as the
 * process's own main module also means importing this file no longer starts a
 * server and hijacks the runner's signal handlers.
 */
export async function main(
  deps: RuntimeDeps = {},
  observer?: ServingObserver,
  servingDeps: ServingDeps = {},
): Promise<Serving> {
  // US-19 installs the SIGTERM, SIGINT, uncaughtException and unhandledRejection
  // handlers here, as main()'s first statements, before any asynchronous work.
  const core = buildRuntimeCore(deps);

  // Counted at the branch, not inside either transport module: one counter
  // increments for the surface taken and the other never does, which is exactly
  // what FR-62's "exactly one serving transport" criterion asserts.
  const surface = core.config.activeSurface;
  observer?.onTransportActivated?.(surface);
  if (surface === 'http') {
    // US-22 owns `startHttp`. Until it lands, selecting http is refused rather
    // than served over stdio: a silent fall-back would serve the stdio write
    // set on a surface the operator narrowed with UNIFI_HTTP_ALLOW_WRITES.
    throw new ConfigRefusal([
      'UNIFI_MCP_TRANSPORT=http is not available in this build. The HTTP serving ' +
        'transport is still being assembled; unset the variable to serve over stdio.',
    ]);
  }
  return startStdio(core, observer, servingDeps);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv.includes('--selftest')) process.exit(selfTest());
  main().catch((error: unknown) => {
    // FR-54: name the offending setting so the fix is obvious without reading
    // the source. Everything else goes through the sanitising emitter — this
    // process holds a live credential and an unsanitised `error.message` on a
    // long-lived server is how one leaves it.
    if (error instanceof ConfigRefusal) {
      for (const message of error.errors) emitDiagnostic(`ERROR ${message}`);
    } else {
      emitError('fatal', error);
    }
    process.exit(1);
  });
}
