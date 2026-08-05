/**
 * The per-session MCP server factory (architecture §1.2).
 *
 * ONE `McpServer` per session, and that is forced rather than chosen:
 * `Protocol.connect` throws "Already connected to a transport. Call close()
 * before connecting to a new transport, or use a separate Protocol instance per
 * connection" (`shared/protocol.js:217`), with no queue and no replace
 * semantics. There is no option, configuration or ordering that lets one
 * `McpServer` serve two concurrent sessions.
 *
 * What is NOT per session is everything expensive or shared: the registry, the
 * handlers, the credential store and the outbound client all live on the
 * `Runtime` this factory reads. The factory receives `Runtime` and not
 * the process-scoped lifecycle type, so no per-session path can reach
 * `beginDrain()` or `close()` and take the whole process down while evicting
 * one idle session. The name of that type is deliberately not written here: a
 * source scan asserts which modules may hold it, and a scan cannot tell a
 * mention from a use.
 *
 * Pure factory: it connects nothing. Connection is the transport module's.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { Runtime, Surface } from './runtime.js';

const SERVER_NAME = 'unifi-mcp';
const SERVER_VERSION = '0.1.0';

const INSTRUCTIONS =
  'Exposes the four published Ubiquiti UniFi developer APIs — Site Manager, Network, ' +
  'Protect, and Mobility. Five common reads have dedicated tools; the remaining ' +
  'operations are discoverable through unifi_search_actions and run through the ' +
  'read or write execution tool.';

/**
 * Build one session's server over the shared runtime.
 *
 * `advertisedToolsFor(surface)` throws `RuntimeNotReady` before the registry has
 * resolved, so a session opened during the `starting` window fails loudly here
 * rather than quietly advertising an empty tool set.
 */
export function createMcpServer(runtime: Runtime, surface: Surface): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} }, instructions: INSTRUCTIONS },
  );

  for (const tool of runtime.advertisedToolsFor(surface)) {
    const handler = runtime.handlers[tool.name];
    if (!handler) continue;
    server.registerTool(
      tool.name,
      {
        title: tool.annotations.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
      },
      // The SDK's arg type is derived from the raw shape; handlers take a plain
      // record because they all funnel through one action runner.
      (async (args: Record<string, unknown>) => handler(args)) as never,
    );
  }

  return server;
}
