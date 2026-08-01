#!/usr/bin/env node
/**
 * UniFi MCP — entrypoint.
 *
 * Local stdio server (ADR-01). Local deployment is not a fallback here: Network
 * and Protect in local-direct mode sit at private LAN addresses that no hosted
 * server can route to, and UniFi's long-lived user-supplied API key has no
 * OAuth and no supported collection path for a hosted remote server.
 *
 * NFR-19: on stdio, stdout carries protocol frames and nothing else. Every
 * diagnostic in this process goes to stderr.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { loadConfig, validateConfig, redactedSummary } from './config.js';
import { CredentialStore } from './credentials.js';
import { UnifiClient } from './http/client.js';
import { buildRegistry, type SpecManifest } from './registry/build.js';
import { advertisedTools, createHandlers, PROMOTED_ACTION_IDS } from './tools/index.js';
import { SERVICE_IDS } from './types.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function warn(message: string): void {
  process.stderr.write(`${message}\n`);
}

/**
 * Credential-free image/install integrity check (`--selftest`).
 *
 * Exists because a container image of a stdio server has no port to probe: a
 * platform team otherwise has no way to tell a working image from one whose
 * `specs/` layer was dropped by a bad COPY. Deliberately independent of
 * credentials and of `UNIFI_*` configuration, so it answers "is this artifact
 * intact" and not "is this deployment configured" — a health check that fails
 * on a missing API key would report the wrong problem.
 *
 * This path never connects a transport, so writing to stdout here does not
 * violate NFR-19.
 */
function selfTest(): number {
  const problems: string[] = [];
  let manifest: SpecManifest;
  try {
    manifest = JSON.parse(
      readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'),
    ) as SpecManifest;
  } catch (e) {
    process.stdout.write(
      `${JSON.stringify({ ok: false, error: `specs/manifest.json unreadable at ${REPO_ROOT}: ${String(e)}` })}\n`,
    );
    return 1;
  }

  // Every service, regardless of configuration: this checks the artifact.
  const registry = buildRegistry(REPO_ROOT, manifest, new Set(SERVICE_IDS));
  const tools = advertisedTools(new Set(SERVICE_IDS), new Set(SERVICE_IDS));

  for (const [toolName, actionId] of Object.entries(PROMOTED_ACTION_IDS)) {
    if (!registry.byId.has(actionId)) {
      problems.push(`${toolName} has no backing action \`${actionId}\``);
    }
  }
  if (registry.actions.length === 0) problems.push('action registry is empty');

  const report = {
    ok: problems.length === 0,
    version: '0.1.0',
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
    actions: registry.actions.length,
    tools: tools.length,
    specs: Object.fromEntries(
      Object.entries(registry.stats).map(([service, s]) => [service, s.version]),
    ),
    problems,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return problems.length === 0 ? 0 : 1;
}

async function main(): Promise<void> {
  if (process.argv.includes('--selftest')) {
    process.exit(selfTest());
  }

  const manifest = JSON.parse(
    readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'),
  ) as SpecManifest;

  const config = loadConfig(process.env, { repoRoot: REPO_ROOT });
  const validation = validateConfig(config, process.env);

  for (const message of validation.warnings) warn(`unifi-mcp: ${message}`);
  if (!validation.ok) {
    // FR-54: fail rather than serve a half-configured surface, and name the
    // offending setting so the fix is obvious without reading the source.
    for (const error of validation.errors) warn(`unifi-mcp: ERROR ${error}`);
    process.exit(1);
  }

  // NFR-17: the registry is built from files on disk. No network call happens
  // before `tools/list` can be answered — the server starts fully offline.
  const registry = buildRegistry(REPO_ROOT, manifest, config.enabledServices);
  for (const message of registry.warnings) warn(`unifi-mcp: ${message}`);

  const credentials = new CredentialStore(config, { warn });
  const client = new UnifiClient(config, credentials, { warn });
  const handlers = createHandlers({
    config,
    client,
    actions: registry.actions,
    byId: registry.byId,
  });

  const server = new McpServer(
    { name: 'unifi-mcp', version: '0.1.0' },
    {
      capabilities: { tools: {} },
      instructions:
        'Exposes the four published Ubiquiti UniFi developer APIs — Site Manager, Network, ' +
        'Protect, and Mobility. Five common reads have dedicated tools; the remaining ' +
        'operations are discoverable through unifi_search_actions and run through the ' +
        'read or write execution tool.',
    },
  );

  const tools = advertisedTools(config.enabledServices, config.writesEnabled);
  for (const tool of tools) {
    const handler = handlers[tool.name];
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

  const summary = redactedSummary(config);
  warn(
    `unifi-mcp: ready — ${tools.length} tools, ${registry.actions.length} actions across ` +
      `${config.enabledServices.size} API(s). ${JSON.stringify(summary)}`,
  );
  if (config.writesEnabled.size === 0) {
    warn('unifi-mcp: read-only (writes are off; set UNIFI_ENABLE_WRITES to change that).');
  } else {
    warn(`unifi-mcp: WRITES ENABLED for ${[...config.writesEnabled].join(', ')}.`);
  }

  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  warn(`unifi-mcp: fatal — ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
