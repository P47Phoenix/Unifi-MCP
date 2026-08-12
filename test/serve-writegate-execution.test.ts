/**
 * US-29 — FR-71's EXECUTION gate, asserted in a single-transport run.
 *
 * Suite D of the test strategy: D10 and D11.
 *
 * ## Why this is a separate file from `test/serve-parity.test.ts`
 *
 * The parity suite runs both surfaces over ONE `Runtime`, which is exactly what
 * FR-74 needs and exactly what FR-71's execution criterion cannot use. FR-72
 * fixes one outbound `UnifiClient` per process, and the execution-time write
 * gate in `src/http/client.ts` reads the `writesEnabled` set BAKED INTO that
 * client at construction — `config.writesEnabled`, which is
 * `writesEnabledBySurface[the transport this process selected]`.
 *
 * So the parity harness structurally CANNOT diverge refusal; it can only
 * diverge advertisement. A developer reading this should not conclude that the
 * fix is a third enforcement point somewhere in the transport layer. It is not.
 * The narrowing happens ONCE, at configuration load, and this file asserts that
 * the one client the process built honours it — with the HTTP transport
 * selected, so the narrowed set is the one that applies to the only client
 * there is.
 *
 * ## Why listing tools is not enough
 *
 * D10 and D11 both actually CALL the tool. An MCP client is free to issue
 * `tools/call` for a name it never saw in `tools/list` — the protocol has no
 * rule against it and `tools/list` is not an access-control boundary. A test
 * that observed only the tool's absence from the advertised set would leave the
 * interesting half — what happens when someone calls it anyway — unasserted.
 *
 *   D10  gate SHUT   (`UNIFI_HTTP_ALLOW_WRITES=none`): the tool is unadvertised
 *                    AND an explicit call is refused by the SDK's own
 *                    dispatcher, which never reads `writesEnabled` at all. Plus
 *                    the A31 narrowing warning on stderr in the SAME run — a
 *                    refusal without the warning fails.
 *
 *                    DEVIATION, RECORDED: the criterion names JSON-RPC
 *                    `-32601`. `@modelcontextprotocol/sdk@~1.30` does not emit
 *                    it for an unregistered tool — it throws `-32602`
 *                    (`InvalidParams`) and then converts its own throw into an
 *                    `isError` tool result, so no JSON-RPC error frame reaches
 *                    the wire at all. §1(b) below pins what actually happens
 *                    and explains why that is an SDK behaviour rather than a
 *                    fault in `src/`.
 *   D11  gate NARROW (`UNIFI_HTTP_ALLOW_WRITES=protect`): the tool IS advertised,
 *                    and a call naming a NETWORK write action comes back 200
 *                    `text/event-stream` carrying the contract's three-line
 *                    structured tool error, with nothing mutating on the wire.
 *
 * Both runs prove the outbound ledger is live before they assert it is empty:
 * each drives one real read through the loopback origin first. "No mutating
 * request was recorded" is worthless from a recorder that records nothing.
 *
 * ## Computed, never enumerated (D9)
 *
 * No tool name and no action id appears here as a string literal, and no tool
 * count is compared to an integer. `test/serve-parity.test.ts` §10 asserts that
 * property over this file.
 */
import assert from 'node:assert/strict';
import { describe, test, type TestContext } from 'node:test';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ErrorCode } from '@modelcontextprotocol/sdk/types.js';

import { blockedDiscriminators, blocksEntireOperation } from '../src/registry/blocklist.js';
import { startHttp, type HttpServing } from '../src/serve/http.js';
import { buildRuntimeCore, type RuntimeCore } from '../src/serve/runtime.js';
import { EXECUTE_ACTION, EXECUTE_WRITE_ACTION } from '../src/tools/definitions.js';
import type { Action, ServiceId } from '../src/types.js';

import { createInstruments } from './harness/counters.js';
import {
  loopbackEnv,
  startLoopbackOrigin,
  type LoopbackOrigin,
} from './harness/interceptor.js';

/** A legal inbound secret. FR-81's floor is 32 characters. */
const SECRET = `us29-writegate-execution-secret-${'z'.repeat(32)}`;

const WRITE_TOOL = EXECUTE_WRITE_ACTION.name;

/** Both fixtures enable the same base set; only the HTTP gate differs. */
const BASE_WRITE_SERVICES = 'network,protect';

/**
 * Operator interface contract §5.9.2, rendered by `toolError`.
 *
 * `{service}` is bound from the `action_id` argument BEFORE the gate is
 * consulted, which is why a NETWORK action produces `network request failed`
 * even though network is outside the effective HTTP write set.
 *
 * D-15 amended the message: this refusal is reachable ONLY when the effective
 * set is non-empty — the tool is unadvertised otherwise — so the old sentence
 * claiming the intersection "is empty" was false on every firing. It now names
 * the service that is missing from the set, which is what the operator has to
 * add to `UNIFI_HTTP_ALLOW_WRITES`.
 */
const HTTP_REFUSAL = [
  'network request failed (config).',
  'Message: Write actions for network are disabled on the HTTP serving transport. Writes over ' +
    'HTTP require both UNIFI_ENABLE_WRITES and UNIFI_HTTP_ALLOW_WRITES, and network is not in ' +
    'the effective set — the intersection of the two.',
  'Next step: Set UNIFI_HTTP_ALLOW_WRITES to include this service on the server, then restart it.',
].join('\n');

/** §3.3's narrowing line, identified by its opening clause. US-20 owns its full text. */
const NARROWING_WARNING = 'WARNING WRITES ARE DISABLED ON THIS TRANSPORT.';
/** §3.3's other line. The two must never co-occur. */
const ENABLED_WARNING = 'WARNING WRITES ENABLED OVER HTTP';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ToolCallResult {
  readonly isError?: boolean;
  readonly content?: ReadonlyArray<{ readonly type: string; readonly text?: string }>;
}

function textOf(result: ToolCallResult): string {
  return result.content?.[0]?.text ?? '';
}

function isFullyExposed(action: Action): boolean {
  return (
    blocksEntireOperation(action.service, action.method, action.path) === undefined &&
    blockedDiscriminators(action.service, action.method, action.path).length === 0
  );
}

/** Chosen from the live registry, never written out — see the module doc on D9. */
function pickAction(core: RuntimeCore, service: ServiceId, actionClass: 'read' | 'write'): Action {
  const chosen = (core.registry?.actions ?? []).find(
    (action) =>
      action.service === service &&
      action.actionClass === actionClass &&
      isFullyExposed(action) &&
      !action.path.includes('*'),
  );
  if (!chosen) {
    throw new Error(`the registry offers no exposed ${service} ${actionClass} action to drive`);
  }
  return chosen;
}

function pathParamsFor(action: Action): Record<string, string> {
  const params: Record<string, string> = {};
  for (const parameter of action.parameters) {
    if (parameter.location === 'path') params[parameter.name] = `synthetic-${parameter.name}`;
  }
  return params;
}

interface RecordedResponse {
  readonly status: number;
  readonly contentType: string | null;
}

interface Rig {
  readonly core: RuntimeCore;
  readonly serving: HttpServing;
  readonly origin: LoopbackOrigin;
  readonly client: Client;
  readonly lines: readonly string[];
  /** Every HTTP response the MCP client transport received, in order. */
  readonly responses: readonly RecordedResponse[];
  /** Names as the single live client saw them. */
  readonly advertised: readonly string[];
}

/**
 * ONE transport, the HTTP one, over one real listener and one loopback console.
 *
 * `src/index.ts` is not imported: this builds the core and starts the transport
 * directly, which is the same shape every other in-process serving suite uses.
 * What matters for FR-71 is that exactly ONE serving transport exists in this
 * process, so the narrowed set is the one the single outbound client carries.
 */
async function startRig(t: TestContext, httpAllowWrites: string): Promise<Rig> {
  const lines: string[] = [];
  const responses: RecordedResponse[] = [];
  const origin = await startLoopbackOrigin();

  const instruments = createInstruments({
    env: loopbackEnv(origin, {
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_BIND: '127.0.0.1',
      UNIFI_HTTP_PORT: '0',
      UNIFI_HTTP_TOKEN: SECRET,
      UNIFI_ENABLE_WRITES: BASE_WRITE_SERVICES,
      UNIFI_HTTP_ALLOW_WRITES: httpAllowWrites,
    }),
    keychain: null,
    onLine: (line) => lines.push(line),
  });

  const core = buildRuntimeCore(instruments.deps);
  const serving = await startHttp(core, instruments.observer, {
    warn: (line) => lines.push(line),
  });
  await core.ready;
  assert.equal(core.readyError, null, 'the runtime failed to resolve its registry');
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  const address = serving.address;
  assert.ok(address !== null, 'the HTTP listener reported no address');

  const client = new Client({ name: 'us-29-writegate', version: '0.0.0' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${SECRET}` } },
      // The wire evidence D11 needs: the status line and the media type, which
      // the SDK client otherwise consumes and never surfaces.
      fetch: (async (input: string | URL | Request, init?: RequestInit) => {
        const response = await fetch(input as never, init as never);
        responses.push({
          status: response.status,
          contentType: response.headers.get('content-type'),
        });
        return response;
      }) as never,
    }),
  );

  t.after(async () => {
    await client.close().catch(() => undefined);
    await serving.dispose();
    await origin.close();
  });

  const advertised = (await client.listTools()).tools.map((tool) => tool.name).sort();

  // The recorder is live BEFORE anything asserts it is empty: one real read,
  // over the same single transport, against the loopback console.
  const readAction = pickAction(core, 'network', 'read');
  const read = (await client.callTool({
    name: EXECUTE_ACTION.name,
    arguments: { action_id: readAction.id, path_params: pathParamsFor(readAction) },
  })) as ToolCallResult;
  assert.equal(read.isError ?? false, false, `the anti-vacuity read failed — ${textOf(read)}`);
  assert.equal(
    origin.requests.length,
    1,
    'the loopback origin recorded no read, so every "nothing mutating happened" assertion below ' +
      'would pass on a recorder that records nothing',
  );

  return { core, serving, origin, client, lines, responses, advertised };
}

function narrowingWarnings(lines: readonly string[]): readonly string[] {
  return lines.filter((line) => line.includes(NARROWING_WARNING));
}

// ===========================================================================
// 1. D10 — the gate SHUT: unadvertised, and refused when called anyway
// ===========================================================================

describe('US-29 §1 (D10): UNIFI_HTTP_ALLOW_WRITES=none over the HTTP transport', () => {
  test('the write tool is absent, an explicit call is refused by the dispatcher, nothing mutating, and the warning fired', async (t) => {
    const rig = await startRig(t, 'none');

    // The configuration under test was actually constructed.
    assert.ok(
      rig.core.config.writesEnabledBySurface.stdio.size > 0,
      'the base write set is empty, so there is nothing for the HTTP gate to narrow',
    );
    assert.equal(rig.core.config.writesEnabled.size, 0, 'the effective HTTP write set is not empty');

    // (a) Absent from tools/list.
    assert.equal(
      rig.advertised.includes(WRITE_TOOL),
      false,
      'the write tool is advertised over HTTP despite the gate being shut',
    );

    // (b) Called anyway — because an MCP client may. `tools/list` is not an
    // access-control boundary, and nothing in the protocol stops a client
    // issuing `tools/call` for a name it never saw.
    //
    // WHAT THE CRITERION SAYS AND WHAT THE SDK ACTUALLY DOES — read this before
    // changing the assertion below.
    //
    // FR-71 AC 1b and test-strategy D10 both name JSON-RPC `-32601`
    // (`MethodNotFound`). `@modelcontextprotocol/sdk@~1.30` does not produce it
    // for an unregistered TOOL. `McpServer`'s `CallToolRequest` handler throws
    // `McpError(ErrorCode.InvalidParams, 'Tool <name> not found')` — `-32602` —
    // and then CATCHES its own throw and converts it into a `CallToolResult`
    // with `isError: true` (`server/mcp.js`, `createToolError`). No JSON-RPC
    // error frame ever reaches the wire.
    //
    // That is an SDK behaviour, NOT a fault in `src/`: the narrowing did its
    // job, the tool is genuinely not registered on this session, and no code in
    // this repository chooses the refusal shape. The assertion therefore pins
    // what actually happens, says so, and keeps every property the criterion
    // was reaching for — the call is refused, the refusal comes from the
    // dispatcher rather than from the execution gate, and nothing ran. An SDK
    // upgrade that changes any of this turns these lines red rather than
    // letting the divergence drift on unnoticed.
    const writeAction = pickAction(rig.core, 'network', 'write');
    const outcome = await rig.client
      .callTool({
        name: WRITE_TOOL,
        arguments: { action_id: writeAction.id, path_params: pathParamsFor(writeAction) },
      })
      .then(
        (result) => result as ToolCallResult,
        (error: unknown) => error,
      );

    assert.ok(
      !(outcome instanceof Error),
      `the SDK raised a transport-level error instead of a tool error: ${String(outcome)}`,
    );
    const refusal = outcome as ToolCallResult;
    assert.equal(refusal.isError, true, 'the unadvertised write tool was not refused');

    const code = /MCP error (-?\d+):/.exec(textOf(refusal))?.[1];
    assert.equal(
      code,
      String(ErrorCode.InvalidParams),
      `the JSON-RPC code the SDK embeds in the tool-not-found refusal changed. The criterion ` +
        `names ${-32601} (MethodNotFound); the SDK emits ${ErrorCode.InvalidParams} ` +
        `(InvalidParams). Refusal text was: ${textOf(refusal)}`,
    );
    assert.ok(
      textOf(refusal).includes(WRITE_TOOL),
      'the refusal must name the tool that was called',
    );

    // The substance of the criterion, and the part that is entirely ours: the
    // refusal came from the SDK dispatcher, which reads `writesEnabled`
    // NOWHERE, and NOT from the execution gate in `src/http/client.ts`. With
    // the HTTP gate shut, the write tool is indistinguishable from a tool that
    // does not exist — which is what "the narrowing happens once, at
    // configuration load" looks like from a client.
    const ghost = (await rig.client
      .callTool({ name: `${WRITE_TOOL}_does_not_exist`, arguments: {} })
      .catch((error: unknown) => ({
        isError: true,
        content: [{ type: 'text', text: String(error) }],
      }))) as ToolCallResult;
    assert.equal(
      textOf(refusal).replace(WRITE_TOOL, ''),
      textOf(ghost).replace(`${WRITE_TOOL}_does_not_exist`, ''),
      'the narrowed write tool is refused differently from a tool that never existed, which ' +
        'means something other than the dispatcher answered it',
    );

    // (c) Nothing state-changing crossed the socket, on a ledger already proven
    // live by the read `startRig` performed.
    assert.deepEqual(
      rig.origin.mutating().map((entry) => `${entry.method} ${entry.path}`),
      [],
      'a state-changing request reached the console from a refused write',
    );

    // (d) The A31 narrowing warning, in the SAME run. A run producing the
    // -32601 without this line FAILS: an operator who enabled writes and is not
    // getting them has to be told why, and which variable to change.
    const warnings = narrowingWarnings(rig.lines);
    assert.equal(
      warnings.length,
      1,
      `expected exactly one narrowing warning on stderr, saw ${warnings.length}:\n` +
        rig.lines.join('\n'),
    );
    const warning = warnings[0]!;
    assert.ok(warning.includes('UNIFI_ENABLE_WRITES'), 'the warning must name the base gate');
    assert.ok(warning.includes('UNIFI_HTTP_ALLOW_WRITES'), 'the warning must name the HTTP gate');
    assert.ok(
      warning.includes(WRITE_TOOL),
      'the warning must name the tool that disappeared from tools/list',
    );

    // §3.3 allows at most one of the two write-gate lines.
    assert.deepEqual(
      rig.lines.filter((line) => line.includes(ENABLED_WARNING)),
      [],
      'the narrowing warning and the writes-enabled warning must never co-occur',
    );
  });
});

// ===========================================================================
// 2. D11 — the gate NARROWED but not shut: advertised, and refused on call
// ===========================================================================

describe('US-29 §2 (D11): UNIFI_HTTP_ALLOW_WRITES names one of two enabled services', () => {
  test('the write tool is advertised, and a call outside the effective set is refused on the wire', async (t) => {
    const rig = await startRig(t, 'protect');

    // Exactly the narrowed-but-non-empty configuration: `protect` is inside the
    // effective HTTP set, `network` is not.
    assert.deepEqual([...rig.core.config.writesEnabled].sort(), ['protect']);
    assert.deepEqual([...rig.core.config.writesEnabledBySurface.stdio].sort(), [
      'network',
      'protect',
    ]);

    // (a) Advertised — so a caller can and will reach the execution gate. This
    // is what makes the criterion different from D10: absence is not the
    // control here, the refusal is.
    assert.equal(
      rig.advertised.includes(WRITE_TOOL),
      true,
      'the write tool must be advertised when the effective HTTP write set is non-empty',
    );

    // (b) Call it, naming an action of the service OUTSIDE the effective set.
    const writeAction = pickAction(rig.core, 'network', 'write');
    const before = rig.responses.length;
    const result = (await rig.client.callTool({
      name: WRITE_TOOL,
      arguments: { action_id: writeAction.id, path_params: pathParamsFor(writeAction) },
    })) as ToolCallResult;

    // The three lines of operator contract §5.9.2, exactly.
    assert.equal(result.isError, true, 'the refusal must be a structured tool error');
    assert.equal(textOf(result), HTTP_REFUSAL);

    // (c) On the wire: 200 with an SSE body, not a transport-level error. The
    // refusal is a TOOL result, so a client that only inspects HTTP status sees
    // a perfectly ordinary success — which is the correct MCP shape and the
    // reason the body has to be asserted rather than the status alone.
    const during = rig.responses.slice(before);
    assert.notDeepEqual(during, [], 'the tools/call made no HTTP request');
    assert.equal(during[0]!.status, 200, 'the tools/call status line');
    assert.ok(
      (during[0]!.contentType ?? '').includes('text/event-stream'),
      `expected an SSE response, saw ${String(during[0]!.contentType)}`,
    );

    // (d) Refused BEFORE the socket: the gate is in the outbound client, ahead
    // of target resolution and URL construction.
    assert.deepEqual(
      rig.origin.mutating().map((entry) => `${entry.method} ${entry.path}`),
      [],
      'a state-changing request reached the console despite the HTTP gate excluding its service',
    );
    assert.equal(
      rig.origin.requests.length,
      1,
      'the refused write added a request to the ledger; only the anti-vacuity read should be there',
    );

    // (e) The other §3.3 line fires here, and the narrowing one does not.
    assert.deepEqual(narrowingWarnings(rig.lines), []);
    assert.equal(
      rig.lines.filter((line) => line.includes(ENABLED_WARNING)).length,
      1,
      `expected exactly one writes-enabled-over-HTTP warning:\n${rig.lines.join('\n')}`,
    );
  });
});
