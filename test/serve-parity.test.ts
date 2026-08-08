/**
 * US-29 — the two serving surfaces, asserted EQUAL at equal effective write
 * set, and their one legitimate divergence asserted as a REQUIRED difference.
 *
 * Suite D of the test strategy: D1-D9. FR-74, FR-79, NFR-22, IG-7.
 *
 * ## Why this file exists at all, stated plainly
 *
 * The cheapest way to make "the two surfaces behave the same" pass is to delete
 * the HTTP write gate. US-15 built that gate precisely so writes can be
 * narrowed on the HTTP surface independently of the stdio one, and a no-op gate
 * satisfies every naive parity assertion while silently undoing the whole of
 * FR-71. So this suite does NOT assert that the surfaces are equal. It asserts
 * that they are equal EXCEPT in exactly the one configuration where they must
 * differ — and in that configuration it treats equality as a FAILURE.
 *
 * §4's `assert.deepEqual(symmetricDifference(...), [WRITE_TOOL])` is the load-
 * bearing line of the file. A gate that stopped narrowing makes that symmetric
 * difference empty and the assertion goes red. It is written as a positive
 * assertion of an exact expected set rather than as `assert.notDeepEqual`,
 * because an inequality passes for the wrong reason the moment any unrelated
 * tool changes on one surface.
 *
 * ## One process, one Runtime, two McpServer instances — literally, not simulated
 *
 * Every fixture below calls `buildRuntimeCore()` ONCE and then starts BOTH
 * production serving transports over that one core:
 *
 *   - `startHttp(core, ...)`  — a real `StreamableHTTPServerTransport` behind a
 *                               real `node:http` listener on 127.0.0.1:0,
 *                               driven by the SDK's own `Client`.
 *   - `startStdio(core, ..., { createTransport: () => serverSide })` — the real
 *                               stdio serving path with `InMemoryTransport`
 *                               .createLinkedPair() substituted for the process
 *                               pipes, which is the ONLY substitution made.
 *
 * `src/index.ts` is never imported. Its one-transport-per-process rule is
 * untouched and stays asserted where it lives; §1 proves this harness did not
 * go through it by reading the transport-activation counter — which only the
 * entrypoint ever increments — at zero on both surfaces.
 *
 * §1 also pins "the SAME runtime" positively: one registry build, one outbound
 * client, one credential store, for two sessions. A harness that quietly built
 * two runtimes would compare two configurations rather than two surfaces, and
 * every divergence assertion below would be measuring the wrong thing.
 *
 * ## THE LIMITATION OF THIS HARNESS, RECORDED AS SCOPE AND NOT AS A CAVEAT
 *
 * This suite proves SURFACE parity. It does NOT prove stdio FRAMING.
 *
 * The stdio half runs over `InMemoryTransport.createLinkedPair()`, not over
 * `StdioServerTransport`. Everything above the transport is the shipped code —
 * the same `createMcpServer`, the same `Runtime`, the same handler table, the
 * same drain wrapper — but the newline framing, the stdout discipline and the
 * real pipe buffering are NOT exercised here. That is architecture risk AR-13,
 * and it is accepted rather than hidden.
 *
 * THE COMPENSATING CONTROL IS `.github/workflows/container.yml`'s real-stdio
 * `tools/list` smoke step: it pipes hand-written JSON-RPC frames into
 * `docker run -i` against the published image and parses what comes back off
 * real stdout. §11 asserts that step still exists, so this limitation cannot be
 * closed by deleting the thing that covers it.
 *
 * ## Computed, never enumerated (D9)
 *
 * Not one assertion here names a tool by string literal or compares a tool
 * count to an integer. Every expected set is computed from the production tool
 * definitions in the same run; the write tool is referenced through
 * `EXECUTE_WRITE_ACTION.name`. §10 asserts this property over the two US-29
 * files themselves, so the rule is enforced on the file that states it.
 *
 * ## The fixtures use `network,protect`, not the strategy's `mobility,protect`
 *
 * DELIBERATE DEVIATION. D8 requires each surface to complete a real read
 * against a reachable endpoint in the SAME run, and `test/harness/`'s loopback
 * origin can carry only Network and Protect local-direct traffic — Site Manager
 * and Mobility resolve to a hardcoded cloud origin no configuration can
 * redirect. A `mobility` fixture would be routable-in-name-only, which is the
 * exact failure D8 exists to prevent. The write-gate arithmetic under test is
 * identical for any two services.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { blockedDiscriminators, blocksEntireOperation } from '../src/registry/blocklist.js';
import { startHttp, type HttpServing } from '../src/serve/http.js';
import {
  buildRuntimeCore,
  type RuntimeCore,
  type Serving,
  type Surface,
} from '../src/serve/runtime.js';
import { startStdio } from '../src/serve/stdio.js';
import {
  EXECUTE_ACTION,
  EXECUTE_WRITE_ACTION,
  SEARCH_ACTIONS,
  advertisedTools,
} from '../src/tools/definitions.js';
import type { Action, ServiceId } from '../src/types.js';

import { createInstruments, type CounterSnapshot } from './harness/counters.js';
import {
  MUTATING_METHODS,
  loopbackEnv,
  startLoopbackOrigin,
  type InterceptedRequest,
  type LoopbackOrigin,
} from './harness/interceptor.js';

/** `fileURLToPath`, never `URL.pathname`: the latter yields `/D:/a/...` on Windows. */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A legal inbound secret. FR-81's floor is 32 characters. */
const SECRET = `us29-inbound-parity-secret-${'z'.repeat(32)}`;

/**
 * The one tool whose presence is the subject of this file.
 *
 * Read off the production definition rather than written out, so a rename moves
 * this suite with it instead of leaving it asserting a name nothing exports.
 */
const WRITE_TOOL = EXECUTE_WRITE_ACTION.name;

/** The two services the loopback origin can actually carry. See the module doc. */
const FIXTURE_WRITE_SERVICES = 'network,protect';

/**
 * The query corpus for D5/D6/D7.
 *
 * Written the way an operator would say it, never quoting spec paths — the same
 * discipline `test/search-blocklist.test.ts` holds itself to. The last entry is
 * chosen because it matches a never-ship blocklist entry, which is what makes
 * D7 non-vacuous.
 */
const QUERY_CORPUS: readonly string[] = [
  'list the access points on this site',
  'wireless clients connected right now',
  'camera recording settings',
  'firewall rule',
  'reboot an access point',
];

/** The corpus entry D7 is about. Kept as one value so the two uses cannot drift. */
const BLOCKLISTED_QUERY = 'reboot an access point';

/** The literal FR-46 explanation lead-in, from `explainWithheld`. */
const EXPLANATION_LEAD = 'Not everything matching this query is exposed:';

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** A value per serving surface. Never a bare tuple: an ordering mistake is silent. */
interface BySurface<T> {
  readonly stdio: T;
  readonly http: T;
}

const SURFACES: readonly Surface[] = ['stdio', 'http'];

/**
 * Key-sorted serialisation, recursive.
 *
 * A local function rather than a dependency: FR-75 forbids adding one, and the
 * whole requirement is "same bytes for the same shape regardless of key order".
 */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, inner]) => `${JSON.stringify(key)}:${canonicalJson(inner)}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

interface ListedTool {
  readonly name: string;
  readonly inputSchema?: unknown;
}

function namesOf(tools: readonly ListedTool[]): string[] {
  return tools.map((tool) => tool.name).sort();
}

/**
 * `name -> sha256(canonicalJson(inputSchema))`, sorted.
 *
 * The name-set comparison alone misses a divergence in SHAPE: a `page_size`
 * maximum that differed per surface would pass every name assertion in this
 * file while handing the two surfaces different contracts.
 */
function schemaHashesOf(tools: readonly ListedTool[]): string[] {
  return tools
    .map(
      (tool) =>
        `${tool.name} ${createHash('sha256').update(canonicalJson(tool.inputSchema ?? null)).digest('hex')}`,
    )
    .sort();
}

function symmetricDifference(left: readonly string[], right: readonly string[]): string[] {
  const inLeft = new Set(left);
  const inRight = new Set(right);
  return [
    ...left.filter((name) => !inRight.has(name)),
    ...right.filter((name) => !inLeft.has(name)),
  ].sort();
}

function onlyIn(left: readonly string[], right: readonly string[]): string[] {
  const inRight = new Set(right);
  return left.filter((name) => !inRight.has(name)).sort();
}

/** True when neither the whole operation nor any variant of it is withheld. */
function isFullyExposed(action: Action): boolean {
  return (
    blocksEntireOperation(action.service, action.method, action.path) === undefined &&
    blockedDiscriminators(action.service, action.method, action.path).length === 0
  );
}

/**
 * Pick a real registry action of a given service and class.
 *
 * Chosen at run time rather than written out, so a spec refresh that renames an
 * operation cannot leave this file driving nothing — and so that no action id
 * is enumerated as a literal (FR-74, D9).
 */
function pickAction(core: RuntimeCore, service: ServiceId, actionClass: 'read' | 'write'): Action {
  const chosen = (core.registry?.actions ?? []).find(
    (action) =>
      action.service === service &&
      action.actionClass === actionClass &&
      isFullyExposed(action) &&
      !action.path.includes('*'),
  );
  if (!chosen) {
    throw new Error(
      `the registry offers no exposed ${service} ${actionClass} action with a concrete path, so ` +
        `the parity run has nothing routable to drive`,
    );
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

interface ToolCallResult {
  readonly isError?: boolean;
  readonly content?: ReadonlyArray<{ readonly type: string; readonly text?: string }>;
  readonly structuredContent?: Record<string, unknown>;
}

function textOf(result: ToolCallResult): string {
  return result.content?.[0]?.text ?? '';
}

interface SearchMatch {
  readonly action_id: string;
  readonly action_class: 'read' | 'write';
}

function matchesOf(result: ToolCallResult): readonly SearchMatch[] {
  const structured = result.structuredContent;
  assert.ok(structured !== undefined, `${SEARCH_ACTIONS.name} returned no structuredContent`);
  return (structured.matches ?? []) as readonly SearchMatch[];
}

function withheldOf(result: ToolCallResult): readonly Record<string, unknown>[] {
  const structured = result.structuredContent;
  assert.ok(structured !== undefined, `${SEARCH_ACTIONS.name} returned no structuredContent`);
  return (structured.withheld ?? []) as readonly Record<string, unknown>[];
}

/**
 * The FR-46 explanation paragraph, isolated from the rest of the answer.
 *
 * Extracted rather than compared as part of the whole text, so D7 can assert
 * the explanation is PRESENT as well as identical — two surfaces that both
 * dropped it would otherwise satisfy an identity check perfectly.
 */
function explanationOf(text: string): string {
  return text.split('\n\n').find((block) => block.startsWith(EXPLANATION_LEAD)) ?? '';
}

// ---------------------------------------------------------------------------
// The rig: one Runtime, two production transports, one loopback console
// ---------------------------------------------------------------------------

interface ReadProof {
  readonly surface: Surface;
  readonly request: InterceptedRequest;
}

interface ParityRig {
  readonly label: string;
  readonly core: RuntimeCore;
  readonly origin: LoopbackOrigin;
  readonly clients: BySurface<Client>;
  readonly serving: BySurface<Serving>;
  readonly httpServing: HttpServing;
  /** `tools/list` as each surface answered it, obtained in this same run. */
  readonly names: BySurface<string[]>;
  readonly hashes: BySurface<string[]>;
  /** The same sets recomputed from the production tool builder, for anchoring. */
  readonly expected: BySurface<string[]>;
  readonly readProof: readonly ReadProof[];
  readonly counts: CounterSnapshot;
  readonly lines: readonly string[];
  close(): Promise<void>;
}

async function buildRig(
  label: string,
  overrides: Readonly<Record<string, string>>,
): Promise<ParityRig> {
  const lines: string[] = [];
  const origin = await startLoopbackOrigin();
  const instruments = createInstruments({
    env: loopbackEnv(origin, {
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_BIND: '127.0.0.1',
      UNIFI_HTTP_PORT: '0',
      UNIFI_HTTP_TOKEN: SECRET,
      ...overrides,
    }),
    keychain: null,
    onLine: (line) => lines.push(line),
  });

  // ONE core. Both transports below receive this object and nothing else.
  const core = buildRuntimeCore(instruments.deps);

  const httpServing = await startHttp(core, instruments.observer, {
    warn: (line) => lines.push(line),
  });
  await core.ready;
  assert.equal(core.readyError, null, `${label}: the runtime failed to resolve its registry`);
  // `resolveRegistry`'s continuation flips the readiness phase one microtask
  // after `ready` settles; two macrotask ticks is comfortably past it.
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  // The stdio surface, over the REAL `startStdio`. `createTransport` is the one
  // substitution: the default binds `process.stdin`/`process.stdout` and would
  // write MCP frames into the test runner's own TAP stream.
  const [stdioClientSide, stdioServerSide] = InMemoryTransport.createLinkedPair();
  const stdioServing = await startStdio(core, undefined, {
    createTransport: () => stdioServerSide,
    exit: () => undefined,
    setExitCode: () => undefined,
  });

  const stdioClient = new Client({ name: `us-29-${label}-stdio`, version: '0.0.0' });
  await stdioClient.connect(stdioClientSide);

  const address = httpServing.address;
  assert.ok(address !== null, `${label}: the HTTP listener reported no address`);
  const httpClient = new Client({ name: `us-29-${label}-http`, version: '0.0.0' });
  await httpClient.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${address.port}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${SECRET}` } },
    }),
  );

  const clients: BySurface<Client> = { stdio: stdioClient, http: httpClient };

  // --- tools/list, both surfaces, this run ---------------------------------
  const listedStdio = (await stdioClient.listTools()).tools as readonly ListedTool[];
  const listedHttp = (await httpClient.listTools()).tools as readonly ListedTool[];

  // --- D8: one real read per surface, against a reachable console -----------
  //
  // Sequenced so each intercepted request is attributable to the surface that
  // caused it: the origin cannot tell two MCP surfaces apart, but a ledger that
  // grew by exactly one across a single surface's call can.
  const readAction = pickAction(core, 'network', 'read');
  const readProof: ReadProof[] = [];
  for (const surface of SURFACES) {
    const before = origin.requests.length;
    const result = (await clients[surface].callTool({
      name: EXECUTE_ACTION.name,
      arguments: { action_id: readAction.id, path_params: pathParamsFor(readAction) },
    })) as ToolCallResult;
    assert.equal(
      result.isError ?? false,
      false,
      `${label}/${surface}: the routability read failed — ${textOf(result)}`,
    );
    const added = origin.requests.slice(before);
    assert.equal(
      added.length,
      1,
      `${label}/${surface}: expected exactly one request to cross the loopback socket for one ` +
        `read action, saw ${added.length}`,
    );
    readProof.push({ surface, request: added[0]! });
  }

  return {
    label,
    core,
    origin,
    clients,
    serving: { stdio: stdioServing, http: httpServing },
    httpServing,
    names: { stdio: namesOf(listedStdio), http: namesOf(listedHttp) },
    hashes: { stdio: schemaHashesOf(listedStdio), http: schemaHashesOf(listedHttp) },
    expected: {
      stdio: advertisedTools(core.config.enabledServices, core.config.writesEnabledBySurface.stdio)
        .map((tool) => tool.name)
        .sort(),
      http: advertisedTools(core.config.enabledServices, core.config.writesEnabledBySurface.http)
        .map((tool) => tool.name)
        .sort(),
    },
    readProof,
    counts: instruments.counts,
    lines,
    async close(): Promise<void> {
      await stdioClient.close().catch(() => undefined);
      await httpClient.close().catch(() => undefined);
      await httpServing.dispose();
      await stdioServing.dispose();
      await origin.close();
    },
  };
}

/** Run one search query on one surface and hand back the whole tool result. */
async function search(rig: ParityRig, surface: Surface, query: string): Promise<ToolCallResult> {
  return (await rig.clients[surface].callTool({
    name: SEARCH_ACTIONS.name,
    arguments: { query, limit: 25 },
  })) as ToolCallResult;
}

// ---------------------------------------------------------------------------
// The three fixtures, built once, at module load
// ---------------------------------------------------------------------------

/** D1: the shipped default. Neither gate configured. */
const defaultRig = await buildRig('default', {});

/** D2: writes enabled and the HTTP gate naming the SAME services. */
const alignedRig = await buildRig('aligned', {
  UNIFI_ENABLE_WRITES: FIXTURE_WRITE_SERVICES,
  UNIFI_HTTP_ALLOW_WRITES: FIXTURE_WRITE_SERVICES,
});

/** D3: writes enabled and the HTTP gate shut. THE configuration under test. */
const divergentRig = await buildRig('divergent', {
  UNIFI_ENABLE_WRITES: FIXTURE_WRITE_SERVICES,
  UNIFI_HTTP_ALLOW_WRITES: 'none',
});

const ALL_RIGS: readonly ParityRig[] = [defaultRig, alignedRig, divergentRig];

after(async () => {
  for (const rig of ALL_RIGS) await rig.close();
});

// ===========================================================================
// 1. The harness itself — "the same runtime in the same run", proven
// ===========================================================================

describe('US-29 §1: one process, one Runtime, two McpServer instances', () => {
  test('each fixture built exactly one runtime and serves two sessions from it', () => {
    for (const rig of ALL_RIGS) {
      // One registry, one outbound client, one credential store — for two
      // sessions. Two runtimes would make every comparison below meaningless.
      assert.equal(rig.counts.registryBuild, 1, `${rig.label}: registry builds`);
      assert.equal(rig.counts.clientBuild, 1, `${rig.label}: outbound clients`);
      assert.equal(rig.counts.credentialStore, 1, `${rig.label}: credential stores`);

      assert.equal(rig.serving.stdio.kind, 'stdio', `${rig.label}: stdio handle`);
      assert.equal(rig.serving.http.kind, 'http', `${rig.label}: http handle`);
      assert.equal(rig.httpServing.sessionCount(), 1, `${rig.label}: live HTTP sessions`);
      assert.notEqual(rig.serving.http.address, null, `${rig.label}: the HTTP handle bound nothing`);
    }
  });

  test('the production entrypoint was not used — its one-transport rule is untouched', () => {
    // `onTransportActivated` is incremented at exactly one place in the tree:
    // `src/index.ts`, where the single-transport selection happens. Reading it
    // at zero on both surfaces is the observable form of "this harness did not
    // go through the entrypoint", and it is why running two transports here
    // does not relax the rule the entrypoint enforces.
    for (const rig of ALL_RIGS) {
      assert.deepEqual(
        rig.counts.transportActivated,
        { stdio: 0, http: 0 },
        `${rig.label}: the entrypoint's transport selector was entered`,
      );
    }
  });

  test('both surfaces answered tools/list with the set the production builder computes', () => {
    // The anchor for every comparison below. Without it, two surfaces that both
    // returned nothing would satisfy every equality assertion in this file.
    for (const rig of ALL_RIGS) {
      for (const surface of SURFACES) {
        assert.deepEqual(
          rig.names[surface],
          rig.expected[surface],
          `${rig.label}/${surface}: the wire disagrees with advertisedTools()`,
        );
      }
    }
  });
});

// ===========================================================================
// 2. D1 — the default configuration
// ===========================================================================

describe('US-29 §2 (D1): default configuration — the surfaces are identical', () => {
  test('the name sets are equal', () => {
    assert.deepEqual(defaultRig.names.stdio, defaultRig.names.http);
  });

  test('the input-schema hashes are equal — shape parity, not just name parity', () => {
    assert.deepEqual(defaultRig.hashes.stdio, defaultRig.hashes.http);
  });

  test('neither surface advertises the write tool, asserted positively', () => {
    assert.equal(defaultRig.names.stdio.includes(WRITE_TOOL), false, 'stdio');
    assert.equal(defaultRig.names.http.includes(WRITE_TOOL), false, 'http');
  });
});

// ===========================================================================
// 3. D2 — writes enabled, the HTTP gate naming the same services
// ===========================================================================

describe('US-29 §3 (D2): aligned gates — the surfaces are identical AND both carry the write tool', () => {
  test('the name sets are equal', () => {
    assert.deepEqual(alignedRig.names.stdio, alignedRig.names.http);
  });

  test('the input-schema hashes are equal', () => {
    assert.deepEqual(alignedRig.hashes.stdio, alignedRig.hashes.http);
  });

  test('BOTH surfaces advertise the write tool, asserted positively', () => {
    assert.equal(alignedRig.names.stdio.includes(WRITE_TOOL), true, 'stdio');
    assert.equal(alignedRig.names.http.includes(WRITE_TOOL), true, 'http');
  });
});

// ===========================================================================
// 4. D3 — THE REQUIRED DIVERGENCE
// ===========================================================================

describe('US-29 §4 (D3): UNIFI_HTTP_ALLOW_WRITES=none — the surfaces MUST differ', () => {
  test('the divergent configuration was actually constructed', () => {
    // Anti-vacuity. If the configuration collapsed to "writes off everywhere",
    // the divergence assertions below would be asserting nothing at all.
    const config = divergentRig.core.config;
    assert.ok(
      config.writesEnabledBySurface.stdio.size > 0,
      'the base write set is empty, so there is nothing for the HTTP gate to narrow',
    );
    assert.equal(config.writesEnabledBySurface.http.size, 0, 'the HTTP gate did not shut');
  });

  test('the write tool is advertised over stdio and absent over HTTP', () => {
    assert.equal(divergentRig.names.stdio.includes(WRITE_TOOL), true, 'stdio must keep it');
    assert.equal(divergentRig.names.http.includes(WRITE_TOOL), false, 'http must drop it');
  });

  test('EQUAL SETS HERE ARE A FAILURE: the symmetric difference is exactly the write tool', () => {
    // THE LOAD-BEARING ASSERTION OF THIS SUITE. Do not weaken it, do not turn it
    // into `notDeepEqual`, do not skip it.
    //
    // If someone deletes the HTTP write gate, makes it a no-op, or stops
    // `precomputeAdvertisedTools` from reading the per-surface write set, the
    // two name sets become equal, the symmetric difference becomes `[]`, and
    // this line goes red. That is the entire point of the story: the cheapest
    // way to make parity pass must not be to remove the security control that
    // parity is allowed to have one exception for.
    assert.deepEqual(
      symmetricDifference(divergentRig.names.stdio, divergentRig.names.http),
      [WRITE_TOOL],
      'the two surfaces did not diverge where FR-71 requires them to. Either the HTTP write ' +
        'gate has stopped narrowing the advertised set — which silently undoes US-15 — or a ' +
        'tool other than the write tool differs between the surfaces.',
    );
  });

  test('both directions, as explicit expected arrays', () => {
    assert.deepEqual(
      onlyIn(divergentRig.names.stdio, divergentRig.names.http),
      [WRITE_TOOL],
      'stdio-only tools',
    );
    assert.deepEqual(
      onlyIn(divergentRig.names.http, divergentRig.names.stdio),
      [],
      'HTTP must never advertise something stdio does not',
    );
  });

  test('the schema hashes of every SHARED tool are still identical', () => {
    // The divergence is in membership only. A tool present on both surfaces
    // whose schema differed would be a second, unauthorised divergence.
    const shared = new Set(
      divergentRig.names.stdio.filter((name) => divergentRig.names.http.includes(name)),
    );
    const keep = (entry: string): boolean => shared.has(entry.slice(0, entry.indexOf(' ')));
    assert.deepEqual(
      divergentRig.hashes.stdio.filter(keep),
      divergentRig.hashes.http.filter(keep),
    );
  });
});

// ===========================================================================
// 5. D4 — bounded divergence, in EVERY configuration
// ===========================================================================

describe('US-29 §5 (D4): no tool other than the write tool ever differs', () => {
  test('across all three fixtures, in both directions', () => {
    for (const rig of ALL_RIGS) {
      for (const [from, to] of [
        ['stdio', 'http'],
        ['http', 'stdio'],
      ] as const) {
        const extra = onlyIn(rig.names[from], rig.names[to]).filter(
          (name) => name !== WRITE_TOOL,
        );
        assert.deepEqual(
          extra,
          [],
          `${rig.label}: ${from} advertises tool(s) ${to} does not, and they are not the write ` +
            `tool. A regression that hid a READ tool over HTTP lands here.`,
        );
      }
    }
  });

  test('the shared schema hashes match in every fixture', () => {
    for (const rig of ALL_RIGS) {
      const shared = new Set(rig.names.stdio.filter((name) => rig.names.http.includes(name)));
      const keep = (entry: string): boolean => shared.has(entry.slice(0, entry.indexOf(' ')));
      assert.deepEqual(rig.hashes.stdio.filter(keep), rig.hashes.http.filter(keep), rig.label);
    }
  });
});

// ===========================================================================
// 6. D5 — search parity at equal write set, and determinism WITHIN a transport
// ===========================================================================

describe(`US-29 §6 (D5): ${SEARCH_ACTIONS.name} returns the same action-ID SET on both surfaces`, () => {
  for (const rig of [defaultRig, alignedRig]) {
    test(`${rig.label}: the ID sets are equal for every query in the corpus`, async () => {
      for (const query of QUERY_CORPUS) {
        const stdio = matchesOf(await search(rig, 'stdio', query)).map((m) => m.action_id);
        const http = matchesOf(await search(rig, 'http', query)).map((m) => m.action_id);
        assert.deepEqual(
          [...stdio].sort(),
          [...http].sort(),
          `${rig.label}: "${query}" returned different action IDs per surface`,
        );
      }
    });
  }

  test('the corpus is not vacuous — at least one query returns matches on both surfaces', async () => {
    // Without this, "the sets are equal" is satisfied by two empty answers.
    const productive: string[] = [];
    for (const query of QUERY_CORPUS) {
      const stdio = matchesOf(await search(defaultRig, 'stdio', query));
      const http = matchesOf(await search(defaultRig, 'http', query));
      if (stdio.length > 0 && http.length > 0) productive.push(query);
    }
    assert.notDeepEqual(productive, [], 'no query in the corpus matched anything on either surface');
  });

  test('ordering is deterministic WITHIN a transport — never compared across them', async () => {
    // NFR-22. Order equality ACROSS transports is deliberately not asserted
    // anywhere in this file: nothing in the contract promises it, and asserting
    // it would break on any future relevance-scoring change for a reason that
    // has nothing to do with the transport.
    for (const surface of SURFACES) {
      for (const query of QUERY_CORPUS) {
        const first = matchesOf(await search(defaultRig, surface, query)).map((m) => m.action_id);
        const second = matchesOf(await search(defaultRig, surface, query)).map((m) => m.action_id);
        assert.deepEqual(second, first, `${surface}: "${query}" is not order-stable`);
      }
    }
  });
});

// ===========================================================================
// 7. D6 — bounded search divergence in the divergent configuration
// ===========================================================================

describe('US-29 §7 (D6): in the divergent configuration search diverges by at most the write actions', () => {
  test('the symmetric difference is a subset of the enabled services\u2019 write actions', async () => {
    const permitted = new Set(
      (divergentRig.core.registry?.actions ?? [])
        .filter(
          (action) =>
            action.actionClass === 'write' &&
            divergentRig.core.config.writesEnabledBySurface.stdio.has(action.service),
        )
        .map((action) => action.id),
    );
    assert.ok(permitted.size > 0, 'the permitted-difference set is empty, so this test is vacuous');

    for (const query of QUERY_CORPUS) {
      const stdio = matchesOf(await search(divergentRig, 'stdio', query)).map((m) => m.action_id);
      const http = matchesOf(await search(divergentRig, 'http', query)).map((m) => m.action_id);
      const unexpected = symmetricDifference(stdio, http).filter((id) => !permitted.has(id));
      assert.deepEqual(
        unexpected,
        [],
        `"${query}" diverged on action(s) that are not write actions of an enabled service`,
      );
    }
  });

  test('the READ-action results are identical, query for query', async () => {
    // The one configuration where the surfaces legitimately differ is the one
    // in which a search regression would otherwise be invisible.
    for (const query of QUERY_CORPUS) {
      const reads = async (surface: Surface): Promise<string[]> =>
        matchesOf(await search(divergentRig, surface, query))
          .filter((match) => match.action_class === 'read')
          .map((match) => match.action_id);
      assert.deepEqual(await reads('stdio'), await reads('http'), `"${query}"`);
    }
  });
});

// ===========================================================================
// 8. D7 — FR-46 blocklist-explanation parity (gated on US-06, which shipped)
// ===========================================================================

describe('US-29 §8 (D7): the FR-46 explanation is IDENTICAL on both surfaces', () => {
  test('a query matching a withheld operation is explained the same way on stdio and HTTP', async () => {
    for (const rig of ALL_RIGS) {
      const stdio = await search(rig, 'stdio', BLOCKLISTED_QUERY);
      const http = await search(rig, 'http', BLOCKLISTED_QUERY);

      const stdioExplanation = explanationOf(textOf(stdio));
      const httpExplanation = explanationOf(textOf(http));

      // Non-vacuity FIRST: two surfaces that both dropped the explanation would
      // satisfy an identity check perfectly. US-06 shipped this text; if it
      // stops appearing, this fails before the comparison does.
      assert.notEqual(
        stdioExplanation,
        '',
        `${rig.label}: no FR-46 explanation over stdio for "${BLOCKLISTED_QUERY}" — the full ` +
          `answer was:\n${textOf(stdio)}`,
      );
      assert.equal(stdioExplanation, httpExplanation, `${rig.label}: explanations differ`);

      // The structured half, too: a caller rendering `withheld` must see the
      // same withheld set whichever surface it connected over.
      assert.notDeepEqual(withheldOf(stdio), [], `${rig.label}: the withheld set is empty`);
      assert.deepEqual(withheldOf(stdio), withheldOf(http), `${rig.label}: withheld sets differ`);

      // And the whole answer, not just the explanation paragraph.
      assert.equal(textOf(stdio), textOf(http), `${rig.label}: the full answers differ`);
    }
  });
});

// ===========================================================================
// 9. D8 — routability of the parity run (FR-79)
// ===========================================================================

describe('US-29 §9 (D8): each surface completed a real read against a reachable console', () => {
  test('exactly two requests crossed the loopback socket, one attributable to each surface', () => {
    for (const rig of ALL_RIGS) {
      assert.deepEqual(
        rig.readProof.map((proof) => proof.surface),
        [...SURFACES],
        `${rig.label}: one surface produced no outbound request`,
      );
      assert.equal(
        rig.origin.requests.length,
        rig.readProof.length,
        `${rig.label}: the origin saw traffic this suite did not account for`,
      );
    }
  });

  test('each recorded request was a real read, carrying the resolved credential', () => {
    for (const rig of ALL_RIGS) {
      for (const { surface, request } of rig.readProof) {
        assert.equal(
          MUTATING_METHODS.has(request.method),
          false,
          `${rig.label}/${surface}: a state-changing verb reached the console`,
        );
        assert.equal(request.service, 'network', `${rig.label}/${surface}: service attribution`);
        assert.notEqual(
          request.apiKey,
          undefined,
          `${rig.label}/${surface}: no X-API-Key reached the console, so the credential path was ` +
            `never entered and "reachable" would be an overstatement`,
        );
      }
    }
  });

  test('no state-changing request was made from any fixture', () => {
    for (const rig of ALL_RIGS) {
      assert.deepEqual(
        rig.origin.mutating().map((entry) => `${entry.method} ${entry.path}`),
        [],
        `${rig.label}: a state-changing request reached the outbound interceptor`,
      );
    }
  });
});

// ===========================================================================
// 10. D9 — computed, never enumerated: applied to this suite itself
// ===========================================================================

describe('US-29 §10 (D9): this suite names no tool as a literal and counts none', () => {
  test('neither US-29 file contains a quoted tool-name literal', () => {
    // The rule the story sets is "no test asserts a tool count or a literal
    // name list". The repository-wide detector is S-01 and belongs to US-30;
    // this is the narrow, self-applied form, so the file that states the rule
    // is also held to it. Every tool reference here goes through the production
    // definition objects instead.
    const quoted = /['"`]unifi_[a-z0-9_]+/g;
    for (const name of ['serve-parity.test.ts', 'serve-writegate-execution.test.ts']) {
      const source = readFileSync(join(REPO_ROOT, 'test', name), 'utf8');
      assert.deepEqual(
        source.match(quoted) ?? [],
        [],
        `${name} names a tool as a string literal; derive it from src/tools/definitions.ts`,
      );
    }
  });
});

// ===========================================================================
// 11. AR-13 — the limitation of this harness, and its compensating control
// ===========================================================================

describe('US-29 §11 (AR-13): surface parity is proven here; stdio FRAMING is not', () => {
  test('the compensating control still exists: container.yml drives real stdio', () => {
    // This suite runs the stdio half over an in-memory linked pair, so newline
    // framing, stdout discipline and real pipe buffering are NOT exercised. The
    // control that does exercise them is the container workflow's smoke step,
    // which pipes hand-written JSON-RPC frames into `docker run -i` and reads
    // the answer off real stdout. Asserting it here means the limitation cannot
    // be closed by deleting the thing that covers it.
    //
    // NOTE for US-30: that same step currently asserts a LITERAL tool-name list
    // in its Python block, which is exactly the D9/S-01 violation US-30 removes.
    // It is deliberately not asserted on here.
    const workflow = readFileSync(
      join(REPO_ROOT, '.github', 'workflows', 'container.yml'),
      'utf8',
    );
    assert.ok(
      workflow.includes('"method":"tools/list"'),
      'container.yml no longer drives a tools/list frame; AR-13 has lost its compensating control',
    );
    assert.ok(
      workflow.includes('docker run -i'),
      'container.yml no longer pipes into an interactive container, so nothing exercises real ' +
        'stdio framing anywhere in the tree',
    );
  });
});
