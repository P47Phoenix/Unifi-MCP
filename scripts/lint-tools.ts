#!/usr/bin/env tsx
/**
 * Lint the built tool manifest against the non-negotiable directory-review
 * constraints (NFR-01, NFR-02, NFR-03, NFR-04, NFR-10, FR-58).
 *
 * G-9 targets zero failures here. These are not style preferences: NFR-01 …
 * NFR-10 are carried directly from the `build-mcp-server` constraints and
 * directory review checks them mechanically. A violation is an auto-rejection,
 * so this fails the build rather than warning.
 *
 * Rules, and what each is actually protecting against:
 *
 *  - **NFR-02 — `title` and `readOnlyHint` on every tool; `destructiveHint` on
 *    every non-read-only tool.** A host decides whether to prompt the user before
 *    a call using these annotations. A missing `destructiveHint` on a write tool
 *    is not cosmetic; it is a mutation that runs without confirmation (R-4).
 *  - **NFR-01 — no tool accepts both read and write action classes.** The single
 *    hardest auto-reject. Documenting "safe versus unsafe" inside one tool's
 *    description explicitly does NOT satisfy it; the split has to be structural,
 *    which is why `unifi_execute_action` and `unifi_execute_write_action` are two
 *    tools (ADR-02).
 *  - **NFR-10 — `^[a-z][a-z0-9_]{0,63}$` names, and a non-empty description on
 *    every parameter.** An undescribed parameter is guessed at by the model.
 *  - **NFR-04 / FR-58 — no behavioural imperative in any description.** Text that
 *    directs the model ("always call this first", "you must…") is treated as
 *    prompt injection at directory review, because that is what it is:
 *    instructions reaching the model through a data channel. A tool description
 *    states what the tool does, what it returns, and what it does not do — the
 *    orchestration decision is the host's.
 *
 * ## Why this drives a real MCP server
 *
 * `ToolDefinition.inputSchema` is a `z.ZodRawShape`, not JSON Schema. Linting
 * the Zod objects would lint something no host ever sees — and "every parameter
 * has a description" is a statement about the JSON Schema on the wire, after the
 * SDK's conversion. So the advertised tools are registered on a real `McpServer`
 * exactly as `src/index.ts` does and fetched over an in-memory transport with a
 * genuine `tools/list` request. No socket, no credential, no subprocess.
 *
 * The lint runs against the MAXIMAL surface — all four services enabled and
 * writes on — because a violation on a tool that only appears in some
 * configurations is still an auto-reject. This is the opposite of the token
 * budget, which measures the default configuration (G-3).
 *
 * ## Degradation before the tool layer exists
 *
 * If `src/tools/index.ts` is absent this exits 0 with a clear message and
 * becomes a live gate automatically when the module appears. A module that
 * exists but throws on import is a real failure and propagates.
 *
 * Exit codes: 0 clean (or tool layer absent), 1 at least one violation.
 */
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServiceId } from '../src/types.js';
import { SERVICE_IDS } from '../src/types.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TOOL_MODULE_SOURCE = join(REPO_ROOT, 'src', 'tools', 'index.ts');

/** NFR-10: ≤ 64 characters, snake_case, leading letter. */
const TOOL_NAME_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * Behavioural imperatives (NFR-04, FR-58).
 *
 * Matched case-insensitively against tool and parameter descriptions. The list
 * is deliberately literal rather than clever: a regex broad enough to catch
 * every phrasing would also flag legitimate prose like "the call returns…", and
 * a lint nobody trusts gets disabled. These are the patterns FR-58's acceptance
 * criterion names, plus the near-synonyms that mean the same thing.
 *
 * Note what is NOT here: "not", "cannot", "does not return". NFR-03 positively
 * requires a tool to say what it does NOT do, so negation about the tool's own
 * behaviour is required prose, not an imperative directed at the model.
 */
const BEHAVIOURAL_IMPERATIVES: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\balways\s+(call|use|invoke|run|prefer|check)\b/i, label: 'always call' },
  { pattern: /\bfirst\s+call\b/i, label: 'first call' },
  { pattern: /\bcall\s+this\s+(tool\s+)?first\b/i, label: 'call this first' },
  { pattern: /\byou\s+must\b/i, label: 'you must' },
  { pattern: /\byou\s+should\s+(call|use|invoke|run)\b/i, label: 'you should call' },
  { pattern: /\bnever\s+(respond|reply|answer|call|use)\b/i, label: 'never respond' },
  { pattern: /\bbe\s+sure\s+to\b/i, label: 'be sure to' },
  { pattern: /\bmake\s+sure\s+(you|to)\b/i, label: 'make sure you' },
  { pattern: /\bdo\s+not\s+(call|use|invoke|respond|reply)\b/i, label: 'do not call' },
  { pattern: /\bbefore\s+(calling|using|invoking)\s+(any\s+)?other\b/i, label: 'before calling any other' },
  { pattern: /\bprefer\s+this\s+tool\b/i, label: 'prefer this tool' },
  { pattern: /\bignore\s+(previous|prior|all)\b/i, label: 'ignore previous' },
];

interface WireTool {
  name?: unknown;
  title?: unknown;
  description?: unknown;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: Record<string, unknown>;
  /**
   * Optional metadata a tool layer may advertise so NFR-01 can be checked
   * declaratively. Absent today; the schema fallback below covers it.
   */
  actionClasses?: unknown;
}

// ---------------------------------------------------------------------------
// The wire payload
// ---------------------------------------------------------------------------

/**
 * Ask a real MCP server what it advertises.
 *
 * Deliberately duplicated in scripts/token-budget.ts rather than shared: both
 * are standalone build gates living outside the tsconfig `include`, and a shared
 * helper between two scripts that must keep working when `src/tools` does not
 * exist is more coupling than it saves.
 */
async function wireToolsList(
  enabledServices: ReadonlySet<ServiceId>,
  writesEnabled: ReadonlySet<ServiceId>,
): Promise<WireTool[]> {
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

  // Registration mirrors src/index.ts exactly. If that drifts, this lints the
  // wrong thing — which is why it is a short, literal copy.
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
  const client = new Client({ name: 'lint-tools', version: '0.1.0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = await client.listTools();
  await client.close();
  return result.tools as unknown as WireTool[];
}

// ---------------------------------------------------------------------------
// Schema walking
// ---------------------------------------------------------------------------

interface ParameterNode {
  path: string;
  schema: Record<string, any>;
}

/**
 * Every named parameter in an input schema, including nested object properties.
 *
 * Nested properties count because NFR-10 says "every parameter carries a
 * description", and a model filling in `filter.field` is guessing just as hard
 * as one filling in a top-level argument. Depth is capped so a self-referential
 * schema cannot hang the linter.
 */
function collectParameters(schema: unknown, prefix = '', depth = 0, out: ParameterNode[] = []): ParameterNode[] {
  if (depth > 6 || !schema || typeof schema !== 'object') return out;
  const node = schema as Record<string, any>;

  const properties = node.properties;
  if (properties && typeof properties === 'object') {
    for (const [name, raw] of Object.entries<any>(properties)) {
      const path = prefix ? `${prefix}.${name}` : name;
      out.push({ path, schema: raw ?? {} });
      collectParameters(raw, path, depth + 1, out);
    }
  }
  if (node.items) collectParameters(node.items, `${prefix}[]`, depth + 1, out);
  for (const branch of ['allOf', 'oneOf', 'anyOf'] as const) {
    for (const sub of node[branch] ?? []) collectParameters(sub, prefix, depth + 1, out);
  }
  return out;
}

/** Every `description` string anywhere under a schema node, for imperative scanning. */
function collectDescriptions(
  schema: unknown,
  prefix = '',
  depth = 0,
  out: Array<[string, string]> = [],
): Array<[string, string]> {
  if (depth > 8 || !schema || typeof schema !== 'object') return out;
  for (const [key, value] of Object.entries<any>(schema as Record<string, any>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (key === 'description' && typeof value === 'string') out.push([path, value]);
    else if (value && typeof value === 'object') collectDescriptions(value, path, depth + 1, out);
  }
  return out;
}

/**
 * The action classes a tool accepts (NFR-01).
 *
 * Preferred source is an explicit `actionClasses` field on the advertised tool.
 * Failing that, the input schema is inspected for an action-class-shaped
 * property whose enum admits both `read` and `write` — exactly the shape a
 * combined execute tool would take, and the shape directory review rejects.
 *
 * Honest limitation: a manifest lint can only see the declared surface. That a
 * read execution tool actually *refuses* a write action at call time is a
 * runtime property and belongs in the test suite (FR-44's outbound-request
 * interceptor), not here. What this catches is the design mistake — one tool
 * whose schema openly admits both classes.
 *
 * The caller applies this only to tools that can act (see `readOnlyHint`
 * below). A read-only DISCOVERY tool that takes an action-class *filter* — as
 * `unifi_search_actions` does, to narrow what it lists — performs neither a read
 * nor a write against UniFi and is not what NFR-01 prohibits. Flagging it would
 * be the textbook false positive that gets a lint switched off.
 */
function actionClassesOf(tool: WireTool): string[] {
  if (Array.isArray(tool.actionClasses)) {
    return tool.actionClasses.filter((c): c is string => typeof c === 'string');
  }

  const found = new Set<string>();
  for (const parameter of collectParameters(tool.inputSchema)) {
    const leaf = parameter.path.split('.').pop() ?? '';
    if (!/^(action_?class|actionclass|mode|access|kind)$/i.test(leaf)) continue;
    const declared = parameter.schema.enum ?? parameter.schema.const;
    for (const value of Array.isArray(declared) ? declared : [declared]) {
      if (value === 'read' || value === 'write') found.add(value);
    }
  }
  return [...found];
}

function scanForImperatives(text: string): string | null {
  for (const { pattern, label } of BEHAVIOURAL_IMPERATIVES) {
    const match = text.match(pattern);
    if (match) return `"${label}" → matched "${match[0].trim()}"`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface Violation {
  tool: string;
  rule: string;
  detail: string;
}

async function main(): Promise<void> {
  if (!existsSync(TOOL_MODULE_SOURCE)) {
    console.log('lint-tools: tool layer not built yet.');
    console.log(`  ${TOOL_MODULE_SOURCE} does not exist, so there is no tool manifest to lint.`);
    console.log('  This gate goes live automatically once the tool layer lands');
    console.log('  (NFR-01, NFR-02, NFR-03, NFR-04, NFR-10, FR-58; G-9 targets zero failures).');
    return;
  }

  // Maximal surface: everything enabled, writes on. A violation on a tool that
  // only appears in some configurations is still an auto-reject.
  const all = new Set<ServiceId>(SERVICE_IDS);
  const tools = await wireToolsList(all, all);

  const violations: Violation[] = [];
  const seenNames = new Set<string>();

  console.log(
    `lint-tools: linting the ${tools.length}-tool manifest as advertised at tools/list\n` +
      '  (all four services enabled, writes on — the maximal surface)\n',
  );

  for (const tool of tools) {
    const name = typeof tool.name === 'string' ? tool.name : '<unnamed>';
    const annotations = tool.annotations ?? {};

    // ---- NFR-10: name shape ------------------------------------------------
    if (typeof tool.name !== 'string' || !TOOL_NAME_PATTERN.test(tool.name)) {
      violations.push({
        tool: name,
        rule: 'NFR-10',
        detail:
          'tool name does not match ^[a-z][a-z0-9_]{0,63}$ ' +
          '(<=64 characters, snake_case, leading lowercase letter).',
      });
    }
    if (seenNames.has(name)) {
      violations.push({ tool: name, rule: 'NFR-10', detail: 'duplicate tool name in tools/list.' });
    }
    seenNames.add(name);

    // ---- NFR-02: title -----------------------------------------------------
    // Accepted at the top level or inside `annotations`; the MCP spec has carried
    // it in both places and a host may read either.
    const title = typeof tool.title === 'string' ? tool.title : annotations['title'];
    if (typeof title !== 'string' || title.trim().length === 0) {
      violations.push({
        tool: name,
        rule: 'NFR-02',
        detail: 'no non-empty `title` (checked on the tool and in `annotations`).',
      });
    }

    // ---- NFR-02: readOnlyHint / destructiveHint ----------------------------
    const readOnlyHint = annotations['readOnlyHint'];
    if (typeof readOnlyHint !== 'boolean') {
      violations.push({
        tool: name,
        rule: 'NFR-02',
        detail: '`annotations.readOnlyHint` is missing or not a boolean. Hosts gate confirmation on it.',
      });
    } else if (readOnlyHint === false && typeof annotations['destructiveHint'] !== 'boolean') {
      violations.push({
        tool: name,
        rule: 'NFR-02',
        detail:
          'tool is not read-only but carries no `annotations.destructiveHint`. ' +
          'Without it a mutation can run with no confirmation prompt (FR-47, R-4).',
      });
    }

    // ---- NFR-01: never both action classes ---------------------------------
    // Scoped to tools that can act. `readOnlyHint === true` means the tool
    // performs no state change, so an action-class argument on it is a filter
    // over the catalog, not a dispatch switch — see `actionClassesOf`.
    const classes = readOnlyHint === true ? [] : actionClassesOf(tool);
    if (classes.includes('read') && classes.includes('write')) {
      violations.push({
        tool: name,
        rule: 'NFR-01',
        detail:
          'accepts both `read` and `write` action classes. This is an auto-reject at ' +
          'directory review, and documenting the distinction in the description does not ' +
          'satisfy it — the split must be two tools.',
      });
    }
    // A tool cannot be simultaneously read-only and destructive; if it claims
    // both, one of the two annotations is lying to the host.
    if (readOnlyHint === true && annotations['destructiveHint'] === true) {
      violations.push({
        tool: name,
        rule: 'NFR-01/NFR-02',
        detail: 'declares `readOnlyHint: true` and `destructiveHint: true` — contradictory annotations.',
      });
    }

    // ---- NFR-03: a description at all --------------------------------------
    const description = typeof tool.description === 'string' ? tool.description : '';
    if (description.trim().length === 0) {
      violations.push({
        tool: name,
        rule: 'NFR-03',
        detail: 'no description. It must state what the tool does, what it returns, and what it does not do.',
      });
    }

    // ---- NFR-04 / FR-58: no behavioural imperatives ------------------------
    const toolImperative = scanForImperatives(description);
    if (toolImperative) {
      violations.push({
        tool: name,
        rule: 'NFR-04/FR-58',
        detail: `tool description contains a behavioural imperative: ${toolImperative}`,
      });
    }
    for (const [path, text] of collectDescriptions(tool.inputSchema, 'inputSchema')) {
      const imperative = scanForImperatives(text);
      if (imperative) {
        violations.push({
          tool: name,
          rule: 'NFR-04/FR-58',
          detail: `\`${path}\` contains a behavioural imperative: ${imperative}`,
        });
      }
    }

    // ---- NFR-10: every parameter described ---------------------------------
    const parameters = collectParameters(tool.inputSchema);
    for (const parameter of parameters) {
      // Array item schemas are constraints on the parent parameter, not
      // separately-named parameters, so they inherit the parent's description.
      if (parameter.path.includes('[]')) continue;
      const text = parameter.schema?.description;
      if (typeof text !== 'string' || text.trim().length === 0) {
        violations.push({
          tool: name,
          rule: 'NFR-10',
          detail: `parameter \`${parameter.path}\` has no non-empty description — the model guesses it.`,
        });
      }
    }

    const classLabel = typeof readOnlyHint === 'boolean' ? (readOnlyHint ? 'read' : 'write') : '?';
    console.log(
      `  ${name.padEnd(28)} ${classLabel.padEnd(5)} ` +
        `${String(parameters.filter((p) => !p.path.includes('[]')).length).padStart(2)} params  ` +
        `${String(description.length).padStart(4)} chars`,
    );
  }

  console.log('');

  if (violations.length > 0) {
    console.error(`lint-tools: FAILED — ${violations.length} violation(s):\n`);
    for (const violation of violations) {
      console.error(`  [${violation.rule}] ${violation.tool}: ${violation.detail}`);
    }
    console.error(
      '\nNFR-01 … NFR-10 are the non-negotiable directory-review constraints; a\n' +
        'violation is an auto-rejection, not a style note (G-9 targets zero).\n',
    );
    process.exit(1);
  }

  console.log(`lint-tools: OK — ${tools.length} tools, zero violations (G-9).`);
}

main().catch((error) => {
  console.error(`\nlint-tools: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
