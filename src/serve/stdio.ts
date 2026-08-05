/**
 * The stdio serving transport (architecture §1.2).
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
 * NOT owned here, deliberately: signal handling and the exit-code vocabulary
 * (US-19), and the ordered drain with its deadline and hard stop (US-19 for
 * stdio, US-24 for HTTP). `drain()` below is the teardown those steps wrap.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createMcpServer } from './mcpServer.js';
import {
  resolveRegistry,
  type DrainReason,
  type RuntimeCore,
  type Serving,
  type ServingDeps,
  type ServingObserver,
} from './runtime.js';

/**
 * Start serving MCP over stdin/stdout.
 *
 * `deps` is accepted and threaded now so that US-19 has the `exit` and
 * `setExitCode` seams in place when it implements the drain; nothing in this
 * story reads them, and both are inert in production.
 */
export async function startStdio(
  core: RuntimeCore,
  observer?: ServingObserver,
  _deps: ServingDeps = {},
): Promise<Serving> {
  await resolveRegistry(core);
  if (core.readyError) throw core.readyError;
  observer?.onReady?.();

  const server = createMcpServer(core, 'stdio');
  await server.connect(new StdioServerTransport());

  let torndown: Promise<void> | null = null;
  const teardown = (): Promise<void> => {
    torndown ??= (async () => {
      core.beginDrain();
      await server.close();
      await core.close();
    })();
    return torndown;
  };

  return {
    kind: 'stdio',
    address: null,
    async drain(_reason: DrainReason): Promise<'clean' | 'deadline'> {
      await teardown();
      return 'clean';
    },
    dispose: teardown,
  };
}
