#!/usr/bin/env tsx
/**
 * Measure the context cost of the advertised tool surface (G-3, NFR-18).
 *
 * G-3 is "context economy — the tool surface does not crowd out the
 * conversation". Every byte of every schema returned from `tools/list` is
 * injected into the model's context on every single turn, whether or not any
 * tool is used. A naive one-tool-per-operation server over these four specs
 * would exceed 25,000 tokens; the hybrid search+execute design (ADR-02) exists
 * to keep it under 3,000.
 *
 * Budget:
 *   - ≤ 3,000 tokens with all four APIs enabled
 *   - ≤ 1,500 tokens with a single API enabled
 *
 * The single-API budget is the one that catches regressions: it is where a
 * per-service schema that fails to shrink when services are switched off shows
 * up. FR-17 / US-16 — "not pay context cost for APIs I do not own" — is only
 * real if the measurement is taken per service, so every one of the four is
 * measured individually.
 *
 * ## Why this drives a real MCP server rather than stringifying the definitions
 *
 * `ToolDefinition.inputSchema` is a `z.ZodRawShape`, not JSON Schema. What
 * actually lands on the wire is whatever the MCP SDK converts that shape into,
 * plus the fields the SDK adds on its own (`execution`, `_meta`). Measuring the
 * Zod objects would measure something no host ever sees.
 *
 * So this script registers the advertised tools on a real `McpServer` exactly
 * as `src/index.ts` does, connects a client over an in-memory transport, and
 * issues a genuine `tools/list` request. The bytes it counts are the bytes a
 * host receives. No socket, no credential, no subprocess.
 *
 * ## Which configuration the budget is enforced against
 *
 * G-3 measures "the default configuration", and the default is read-only
 * (FR-44) — the write execution tool is absent from `tools/list` until writes
 * are explicitly enabled, not merely refusing when called. The gate therefore
 * runs against writes-off. The writes-enabled figures are printed alongside as
 * context, clearly marked non-gating, because a maintainer sizing a change
 * wants to see the ceiling as well as the default.
 *
 * ## The estimate is a heuristic, deliberately
 *
 * This script does NOT run a tokenizer. It uses the documented characters ÷ 4
 * approximation over the exact JSON that lands in `tools/list`. Reasons:
 *
 *  - The real tokenizer is the host's, not ours, and differs per model. A number
 *    from the wrong tokenizer is not more accurate than a heuristic, it is just
 *    more confidently wrong.
 *  - A build gate needs to be dependency-free and offline (NFR-17). Adding a
 *    tokenizer package to make a budget check work is a poor trade.
 *  - chars÷4 runs slightly HIGH for JSON with lots of punctuation and short
 *    keys, which is the safe direction for a ceiling.
 *
 * Every line of output says so. Treat the number as a tripwire, not a
 * measurement — if it lands within ~10% of the budget, measure properly before
 * concluding anything.
 *
 * ## Degradation before the tool layer exists
 *
 * If `src/tools/index.ts` is absent this exits 0 with a clear message and
 * becomes a live gate automatically when the module appears. A module that
 * exists but throws on import is NOT degraded gracefully — that is a real
 * failure and it propagates.
 *
 * Exit codes: 0 within budget (or tool layer absent), 1 over budget or unusable.
 */
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServiceId } from '../src/types.js';
import { SERVICE_IDS } from '../src/types.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TOOL_MODULE_SOURCE = join(REPO_ROOT, 'src', 'tools', 'index.ts');

const BUDGET_ALL_SERVICES = 3_000;
const BUDGET_SINGLE_SERVICE = 1_500;
const CHARS_PER_TOKEN = 4;
/** FR-18 caps the advertised surface independently of the token budget. */
const MAX_TOOLS = 12;

/**
 * Ask a real MCP server what it advertises.
 *
 * Deliberately duplicated in scripts/lint-tools.ts rather than shared: both are
 * standalone build gates that live outside the tsconfig `include`, and a shared
 * helper between two scripts that must keep working when `src/tools` does not
 * exist is more coupling than it saves.
 */
async function wireToolsList(
  enabledServices: ReadonlySet<ServiceId>,
  writesEnabled: ReadonlySet<ServiceId>,
): Promise<Array<Record<string, unknown>>> {
  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
  const { advertisedTools } = (await import('../src/tools/index.js')) as {
    advertisedTools: (
      enabled: ReadonlySet<ServiceId>,
      writes: ReadonlySet<ServiceId>,
    ) => Array<{ name: string; description: string; inputSchema: unknown; annotations: { title: string } }>;
  };

  const server = new McpServer(
    { name: 'unifi-mcp', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  // Registration mirrors src/index.ts exactly. If that drifts, this measures the
  // wrong thing — which is why it is a short, literal copy rather than a clever
  // abstraction.
  for (const tool of advertisedTools(enabledServices, writesEnabled)) {
    server.registerTool(
      tool.name,
      {
        title: tool.annotations.title,
        description: tool.description,
        inputSchema: tool.inputSchema as never,
        annotations: tool.annotations as never,
      },
      (async () => ({ content: [] })) as never,
    );
  }

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'token-budget', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = await client.listTools();
  await client.close();
  return result.tools as unknown as Array<Record<string, unknown>>;
}

interface Measurement {
  label: string;
  tools: number;
  characters: number;
  tokens: number;
}

async function measure(
  label: string,
  enabled: ReadonlySet<ServiceId>,
  writes: ReadonlySet<ServiceId>,
): Promise<Measurement> {
  const tools = await wireToolsList(enabled, writes);
  const characters = JSON.stringify(tools).length;
  return { label, tools: tools.length, characters, tokens: Math.ceil(characters / CHARS_PER_TOKEN) };
}

function row(measurement: Measurement, budget: number | null): string {
  const verdict = budget === null ? 'info' : measurement.tokens <= budget ? 'PASS' : 'OVER';
  return (
    `  ${measurement.label.padEnd(26)}  ${String(measurement.tools).padStart(5)}  ` +
    `${String(measurement.characters).padStart(6)}  ${String(measurement.tokens).padStart(11)}  ` +
    `${(budget === null ? '—' : String(budget)).padStart(6)}   ${verdict}`
  );
}

async function main(): Promise<void> {
  if (!existsSync(TOOL_MODULE_SOURCE)) {
    console.log('token-budget: tool layer not built yet.');
    console.log(`  ${TOOL_MODULE_SOURCE} does not exist, so there is no tools/list surface to measure.`);
    console.log('  This gate goes live automatically once the tool layer lands (G-3, NFR-18).');
    console.log('  Budgets when it does: <=3000 tokens all four APIs, <=1500 tokens single API.');
    return;
  }

  console.log('token-budget: measuring the real tools/list payload (G-3, NFR-18)');
  console.log('  Measured by driving an in-process MCP server over an in-memory transport,');
  console.log('  so these are the exact bytes a host receives — Zod shapes converted by the SDK.');
  console.log('  ESTIMATE ONLY: characters / 4. A documented heuristic, NOT a tokenizer.');
  console.log('  The authoritative tokenizer belongs to the host model and is not run here.\n');

  const all = new Set<ServiceId>(SERVICE_IDS);
  const noWrites = new Set<ServiceId>();
  const failures: string[] = [];

  console.log('  configuration                tools   chars   est. tokens   budget   verdict');
  console.log('  ' + '-'.repeat(78));

  // ---- Gated: the default (read-only) configuration, per G-3 ---------------
  const allDefault = await measure('all four APIs', all, noWrites);
  console.log(row(allDefault, BUDGET_ALL_SERVICES));
  if (allDefault.tokens > BUDGET_ALL_SERVICES) {
    failures.push(
      `all four APIs enabled: ~${allDefault.tokens} estimated tokens exceeds the ` +
        `${BUDGET_ALL_SERVICES}-token budget (G-3, NFR-18).`,
    );
  }
  if (allDefault.tools > MAX_TOOLS) {
    failures.push(`tools/list advertises ${allDefault.tools} tools; FR-18 caps it at ${MAX_TOOLS}.`);
  }

  // FR-17 / US-16: a user who owns one API must not pay context for the other
  // three. Measured per service so a surface that ignores the enabled-set shows up.
  for (const service of SERVICE_IDS) {
    const single = await measure(`only ${service}`, new Set([service]), noWrites);
    console.log(row(single, BUDGET_SINGLE_SERVICE));
    if (single.tokens > BUDGET_SINGLE_SERVICE) {
      failures.push(
        `only ${service} enabled: ~${single.tokens} estimated tokens exceeds the ` +
          `${BUDGET_SINGLE_SERVICE}-token single-API budget (G-3, NFR-18, FR-17).`,
      );
    }
  }

  // ---- Informational: the ceiling with writes on --------------------------
  // Not gated. FR-44 makes read-only the default, and G-3 measures the default
  // configuration; a maintainer still wants the ceiling in front of them.
  console.log('  ' + '-'.repeat(78));
  console.log('  writes enabled (not gated — FR-44 makes read-only the default):');
  console.log(row(await measure('all four + writes', all, all), null));
  for (const service of SERVICE_IDS) {
    console.log(row(await measure(`only ${service} + writes`, new Set([service]), new Set([service])), null));
  }

  console.log('');

  if (failures.length > 0) {
    console.error(`token-budget: FAILED — ${failures.length} budget violation(s):\n`);
    for (const failure of failures) console.error(`  - ${failure}`);
    console.error(
      '\nThe estimate is chars/4 and runs slightly high for JSON, so a marginal\n' +
        'overage may be a false alarm — but it is the number this gate is defined\n' +
        'against (G-3, NFR-18). Shrink tool descriptions or move detail out of\n' +
        'tools/list and into what the tools return.\n',
    );
    process.exit(1);
  }

  console.log(
    `token-budget: OK — ~${allDefault.tokens} estimated tokens for ${allDefault.tools} tools ` +
      `(budget ${BUDGET_ALL_SERVICES}). Estimate only; see the header of this script.`,
  );
}

main().catch((error) => {
  console.error(`\ntoken-budget: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
