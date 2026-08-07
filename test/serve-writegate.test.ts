/**
 * US-15 — the HTTP write second gate (FR-71, FR-45, FR-73(c), G-6, R-4).
 *
 * The gate itself is ONE narrowing, in `loadConfig`: `writesEnabledBySurface`
 * intersects `UNIFI_ENABLE_WRITES` with `UNIFI_HTTP_ALLOW_WRITES` and hands the
 * selected surface's set to `ServerConfig.writesEnabled`. This file asserts the
 * consequences of that narrowing at the boundaries where an operator or a model
 * actually meets it, and asserts that meeting it did not create a third place
 * the policy can be decided.
 *
 * ## What each section proves, and why the weaker version would not
 *
 * 1. THE OUTBOUND REFUSAL IS SURFACE-AWARE (AC 1a). The narrowed-but-non-empty
 *    configuration is driven through the REAL `UnifiClient` — not a recorder —
 *    because the whole claim is that `src/http/client.ts`'s existing gate is
 *    what refuses, with an amended message. The refusal is asserted as the
 *    rendered three-line `toolError` text, byte for byte against the operator
 *    interface contract §5.9.2, because "names both variables" is satisfied by
 *    a message that also tells the operator to set the one they already set.
 *
 *    The zero-outbound-requests half is asserted AT A SOCKET: a `node:net`
 *    listener counts connections, and the refused write leaves it at 0. That
 *    number would also be 0 if the client were broken, if the action never ran,
 *    or if some earlier throw fired — so the same listener is driven with a
 *    write that IS inside the effective set, and the count goes to 1. Without
 *    that positive control the zero proves nothing at all.
 *
 * 2. THE STDIO REFUSAL IS UNCHANGED. The same gate over stdio still produces
 *    the pre-existing FR-44 text and never names `UNIFI_HTTP_ALLOW_WRITES`.
 *    FR-73(c) is scoped to the HTTP transport; a message change that leaked
 *    onto stdio would tell every existing MCPB user to set a variable that has
 *    no effect on their process.
 *
 * 3. TOOL-LIST VISIBILITY INHERITS THE NARROWING with no edit to
 *    `src/tools/definitions.ts`, asserted through the production
 *    `advertisedTools` — the same function `tools/list` is built from.
 *
 * 4. BOTH MANDATED WARNINGS FIRE, AND ONLY ONE AT A TIME, including the
 *    DANGEROUS one. Warning only when the gate closes leaves "writes are live
 *    over the network" silent on every surface.
 *
 * 5. NO NEW ENFORCEMENT DECISION APPEARED (AC 3). A `node:fs` walk of `src/`
 *    collects every site that reads the resolved write-enablement set and
 *    compares it against the inventory below, keyed on FILE PLUS MATCHED
 *    EXPRESSION and never on line number — `src/http/client.ts` is a permitted-
 *    change file and FR-70's drain affordances move its line numbers.
 *
 * ## Honest limits of this file
 *
 * - The `-32601` half of AC 1b needs a live `tools/list`/`tools/call` over the
 *   HTTP transport, which is US-22; and "the FR-75 interceptor records zero
 *   mutating requests" needs the interceptor, which is US-25. Both are asserted
 *   here at the nearest boundary that exists — advertisement, and a real
 *   socket — and the remainder is carried forward to US-29 (test-strategy D10,
 *   D11).
 * - The startup EMISSION of the two warnings, their `unifi-mcp: ` prefix, and
 *   the suppression of the read-only banner belong to US-20 (sequencing D-12).
 *   What is asserted here is that `validateConfig` composes the exact lines.
 * - The identifier scan in section 5 is what FR-71 specifies; it cannot see a
 *   branch taken on a local alias several lines below its declaration. The
 *   declaration itself IS a site and is classified, and the mislabelling case
 *   is caught behaviourally by sections 1 and 3, as FR-71 itself records.
 *
 * Nothing here reads or mutates `process.env`; every case builds its own env.
 */
import { strict as assert } from 'node:assert';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createServer, type Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import { loadConfig, validateConfig, type ServerConfig } from '../src/config.js';
import type { CredentialStore } from '../src/credentials.js';
import { UnifiClient, type UnifiResponse } from '../src/http/client.js';
import { toolError } from '../src/http/errors.js';
import { EXECUTE_WRITE_ACTION, advertisedTools } from '../src/tools/definitions.js';
import { SERVICE_IDS, UnifiError, type Action, type ServiceId } from '../src/types.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC_ROOT = join(REPO_ROOT, 'src');

/** Long enough to clear FR-81's 32-character floor. */
const HTTP_SECRET = 'inbound-shared-secret-for-tests-0123456789';
const LOCAL_API_KEY = 'test-local-key';

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

/**
 * A credentialed environment in which `network` and `protect` both resolve to
 * one local console, so a single counting listener stands in for both.
 */
function baseEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return {
    UNIFI_NETWORK_TRANSPORT: 'local',
    UNIFI_PROTECT_TRANSPORT: 'local',
    UNIFI_LOCAL_HOST: '127.0.0.1:9',
    UNIFI_LOCAL_API_KEY: LOCAL_API_KEY,
    ...overrides,
  };
}

function httpEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return baseEnv({
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_TOKEN: HTTP_SECRET,
    ...overrides,
  });
}

/** The same environment with the transport unset — i.e. a stdio start. */
function stdioEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  const env = httpEnv(overrides);
  delete env['UNIFI_MCP_TRANSPORT'];
  return env;
}

function load(env: NodeJS.ProcessEnv): ServerConfig {
  return loadConfig(env, { repoRoot: REPO_ROOT });
}

// ---------------------------------------------------------------------------
// A console that is real at the socket level, so "zero requests" is measured
// where a request would actually leave this process.
// ---------------------------------------------------------------------------

interface CountingConsole {
  readonly port: number;
  readonly connections: number;
  close(): Promise<void>;
}

async function startCountingConsole(): Promise<CountingConsole> {
  const live = new Set<Socket>();
  let connections = 0;

  const server = createServer((socket) => {
    connections += 1;
    live.add(socket);
    socket.on('close', () => live.delete(socket));
    socket.on('error', () => undefined);
    // Reset immediately: the client is dialling https:// and this listener
    // speaks no TLS, so the only useful thing it can do is fail the attempt
    // fast. What is under test is whether the attempt happened at all.
    socket.destroy();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('listener did not bind to a TCP port');
  }

  return {
    port: address.port,
    get connections(): number {
      return connections;
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of live) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

// ---------------------------------------------------------------------------
// Client scaffolding
// ---------------------------------------------------------------------------

/** The only member of `CredentialStore` that `UnifiClient` ever calls. */
interface CredentialSource {
  resolveFor(service: ServiceId, mode: string, host?: string): Promise<string>;
}

function asCredentialStore(source: CredentialSource): CredentialStore {
  return source as unknown as CredentialStore;
}

/** Counts resolutions, because the gate must refuse BEFORE a key is fetched. */
class CountingCredentials implements CredentialSource {
  calls = 0;

  resolveFor(): Promise<string> {
    this.calls += 1;
    return Promise.resolve(LOCAL_API_KEY);
  }
}

function writeActionFor(service: ServiceId): Action {
  return {
    id: `${service}.test.write`,
    service,
    method: 'POST',
    actionClass: 'write',
    path: '/v1/sites',
    summary: 'A state-changing operation',
    description: '',
    tags: [],
    parameters: [],
    earlyAccess: false,
    requiredScopes: [],
    searchText: '',
  };
}

function outcomeOf(promise: Promise<UnifiResponse>): Promise<unknown> {
  return promise.then(
    () => null,
    (error: unknown) => error,
  );
}

function unifiErrorOf(reason: unknown): UnifiError {
  if (!(reason instanceof UnifiError)) {
    return assert.fail(`expected a UnifiError, got ${String(reason)}`);
  }
  return reason;
}

/** The text an MCP client actually reads — `toolError`'s rendering (NFR-05). */
function renderedToolError(reason: unknown): string {
  const result = toolError(unifiErrorOf(reason).normalized);
  return result.content[0]?.text ?? '';
}

// ===========================================================================
// 1. AC 1a — the outbound refusal names both variables, over HTTP only
// ===========================================================================

/** Operator interface contract §5.9.2, verbatim. `{service}` is bound. */
const HTTP_REFUSAL = [
  'network request failed (config).',
  'Message: Write actions are disabled on the HTTP serving transport. Writes over HTTP ' +
    'require both UNIFI_ENABLE_WRITES and UNIFI_HTTP_ALLOW_WRITES, and the effective set — ' +
    'the intersection of the two — is empty.',
  'Next step: Set UNIFI_HTTP_ALLOW_WRITES to include this service on the server, then restart it.',
].join('\n');

/** The pre-existing FR-44 text, which the stdio surface must keep. */
const STDIO_REFUSAL = [
  'network request failed (config).',
  'Message: Action `network.test.write` is a POST (state-changing) operation and writes are not ' +
    'enabled for network.',
  'Next step: Writes are off by default. To enable them, set UNIFI_ENABLE_WRITES=network (or a ' +
    'comma-separated list) in the server environment and restart. This cannot be enabled from a ' +
    'tool call.',
].join('\n');

describe('AC 1a — a write outside the effective HTTP set is refused, naming both gates', () => {
  test('the refusal is the contract message, and nothing left this process', async () => {
    const console_ = await startCountingConsole();
    const credentials = new CountingCredentials();
    try {
      // The narrowed-but-NON-EMPTY configuration: `protect` is inside the HTTP
      // set, `network` is not. The write tool IS advertised here, so a caller
      // can and will reach this gate.
      const config = load(
        httpEnv({
          UNIFI_LOCAL_HOST: `127.0.0.1:${console_.port}`,
          UNIFI_ENABLE_WRITES: 'network,protect',
          UNIFI_HTTP_ALLOW_WRITES: 'protect',
        }),
      );
      assert.deepEqual([...config.writesEnabled].sort(), ['protect']);

      const client = new UnifiClient(config, asCredentialStore(credentials), { warn: () => {} });
      const reason = await outcomeOf(client.request(writeActionFor('network')));

      assert.equal(unifiErrorOf(reason).normalized.category, 'config');
      assert.equal(renderedToolError(reason), HTTP_REFUSAL);
      assert.ok(renderedToolError(reason).includes('UNIFI_HTTP_ALLOW_WRITES'));
      assert.ok(renderedToolError(reason).includes('UNIFI_ENABLE_WRITES'));

      // Refused before a key was resolved and before a socket was opened.
      assert.equal(credentials.calls, 0);
      assert.equal(console_.connections, 0);
    } finally {
      await console_.close();
    }
  });

  test('the positive control: a write INSIDE the set reaches the socket', async () => {
    // Without this, the `connections === 0` above is satisfied by a client that
    // never dials anything, by a broken action, or by any earlier throw.
    const console_ = await startCountingConsole();
    const credentials = new CountingCredentials();
    try {
      const config = load(
        httpEnv({
          UNIFI_LOCAL_HOST: `127.0.0.1:${console_.port}`,
          UNIFI_ENABLE_WRITES: 'network,protect',
          UNIFI_HTTP_ALLOW_WRITES: 'protect',
        }),
      );

      const client = new UnifiClient(config, asCredentialStore(credentials), { warn: () => {} });
      const reason = await outcomeOf(client.request(writeActionFor('protect')));

      // It failed — the listener speaks no TLS — but it failed at the network,
      // not at the gate, which is the distinction being drawn.
      assert.notEqual(unifiErrorOf(reason).normalized.category, 'config');
      assert.equal(credentials.calls, 1);
      assert.ok(console_.connections >= 1, 'the permitted write never reached the socket');
    } finally {
      await console_.close();
    }
  });

  test('the empty HTTP set produces the same refusal — only {service} differs', async () => {
    const credentials = new CountingCredentials();
    const config = load(
      httpEnv({ UNIFI_ENABLE_WRITES: 'network', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );
    assert.deepEqual([...config.writesEnabled], []);

    const client = new UnifiClient(config, asCredentialStore(credentials), { warn: () => {} });
    const reason = await outcomeOf(client.request(writeActionFor('network')));

    assert.equal(renderedToolError(reason), HTTP_REFUSAL);
    assert.equal(credentials.calls, 0);
  });
});

describe('the stdio refusal is untouched — FR-73(c) is scoped to the HTTP transport', () => {
  test('a gated stdio write keeps the pre-existing FR-44 text', async () => {
    const credentials = new CountingCredentials();
    // `protect` writes are on, `network` writes are not, so the SAME gate fires
    // over stdio with the HTTP variable set to something that cannot matter.
    const config = load(
      stdioEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'network' }),
    );
    assert.equal(config.activeSurface, 'stdio');

    const client = new UnifiClient(config, asCredentialStore(credentials), { warn: () => {} });
    const rendered = renderedToolError(await outcomeOf(client.request(writeActionFor('network'))));

    assert.equal(rendered, STDIO_REFUSAL);
    assert.equal(
      rendered.includes('UNIFI_HTTP_ALLOW_WRITES'),
      false,
      'a stdio caller is being told to set a variable their process never reads',
    );
    assert.equal(credentials.calls, 0);
  });
});

// ===========================================================================
// 2. AC 1b at the nearest existing boundary — tool-list visibility
// ===========================================================================

const toolNames = (config: ServerConfig): string[] =>
  advertisedTools(config.enabledServices, config.writesEnabled).map((tool) => tool.name);

describe('AC 1b — with the gate at `none` the write tool is never advertised', () => {
  test('absent over HTTP, present over stdio, from one narrowing', () => {
    const overHttp = load(
      httpEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );
    const overStdio = load(
      stdioEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );

    assert.equal(toolNames(overHttp).includes(EXECUTE_WRITE_ACTION.name), false);
    assert.equal(toolNames(overStdio).includes(EXECUTE_WRITE_ACTION.name), true);

    // The `-32601` follows from the tool never being registered, which is the
    // EXISTING tool-list-visibility enforcement site. Asserting it over a live
    // JSON-RPC session needs the HTTP listener (US-22) and the FR-75
    // interceptor (US-25); test-strategy D10 carries it in US-29.
  });

  test('a proper non-empty subset still advertises the write tool', () => {
    const narrowed = load(
      httpEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
    );
    assert.equal(toolNames(narrowed).includes(EXECUTE_WRITE_ACTION.name), true);
  });
});

describe('over stdio the HTTP gate has no effect in either position (FR-73(c))', () => {
  const positions = ['none', 'all', 'protect', 'network,protect'];

  test('the advertised tool set is identical across every value', () => {
    const unset = toolNames(load(stdioEnv({ UNIFI_ENABLE_WRITES: 'network,protect' })));
    for (const value of positions) {
      const set = toolNames(
        load(stdioEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: value })),
      );
      assert.deepEqual(set, unset, `UNIFI_HTTP_ALLOW_WRITES=${value} changed the stdio surface`);
    }
  });

  test('no value of it can prevent a stdio process from starting', () => {
    for (const value of [...positions, 'true', 'false', 'bogus', '']) {
      const env = stdioEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: value });
      const config = load(env);
      const validation = validateConfig(config, env);
      assert.equal(validation.ok, true, `UNIFI_HTTP_ALLOW_WRITES=${value} refused a stdio start`);
      assert.deepEqual(validation.errors, []);
      assert.deepEqual(
        validation.warnings.filter((line) => line.startsWith('WARNING WRITES')),
        [],
        `UNIFI_HTTP_ALLOW_WRITES=${value} warned on a transport that never reads it`,
      );
    }
  });
});

// ===========================================================================
// 3. The grammar — deliberately not a boolean
// ===========================================================================

describe('the second gate uses the UNIFI_ENABLE_WRITES grammar, not a boolean', () => {
  for (const raw of ['true', 'false']) {
    test(`UNIFI_HTTP_ALLOW_WRITES=${raw} is refused, naming the variable and the values`, () => {
      const env = httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: raw });
      const validation = validateConfig(load(env), env);

      assert.equal(validation.ok, false);
      assert.ok(
        validation.errors.includes(
          `UNIFI_HTTP_ALLOW_WRITES lists unknown service "${raw}"; valid values are ` +
            `${SERVICE_IDS.join(', ')}, \`all\`, or \`none\`.`,
        ),
        `no unknown-token refusal for ${raw}: ${JSON.stringify(validation.errors)}`,
      );
    });
  }

  test('the variable is a known key — an unregistered UNIFI_* is fatal', () => {
    const env = httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' });
    const validation = validateConfig(load(env), env);
    assert.deepEqual(validation.unknownEnvKeys, []);
  });

  test('the intersection is computed once, and the surfaces do not alias', () => {
    const config = load(
      httpEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
    );
    assert.deepEqual([...config.writesEnabledBySurface.http].sort(), ['protect']);
    assert.deepEqual([...config.writesEnabledBySurface.stdio].sort(), ['network', 'protect']);
    assert.equal(config.writesEnabled, config.writesEnabledBySurface[config.activeSurface]);
    assert.notEqual(config.writesEnabledBySurface.stdio, config.writesEnabledBySurface.http);
  });
});

// ===========================================================================
// 4. Both mandated warnings — including the dangerous one
// ===========================================================================

const NARROWING_WARNING =
  'WARNING WRITES ARE DISABLED ON THIS TRANSPORT. UNIFI_ENABLE_WRITES permits network, protect, ' +
  'but UNIFI_HTTP_ALLOW_WRITES is `none`, so the effective HTTP write set is empty: ' +
  'unifi_execute_write_action is absent from tools/list and every write action will be refused. ' +
  'If that is intended, this line is your confirmation. If it is not, widen ' +
  'UNIFI_HTTP_ALLOW_WRITES and restart.';

const EFFECTIVE_WARNING =
  'WARNING WRITES ENABLED OVER HTTP for protect on 127.0.0.1:8787 — any caller presenting the ' +
  'shared secret can change your UniFi estate. Set UNIFI_HTTP_ALLOW_WRITES=none to disable ' +
  'writes on this transport.';

describe('the write gate is never silent — both warnings, and only one at a time', () => {
  test('the narrowing case names both variables and the missing tool', () => {
    const env = httpEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: 'none' });
    const validation = validateConfig(load(env), env);

    assert.ok(validation.warnings.includes(NARROWING_WARNING), validation.warnings.join(' | '));
    assert.equal(
      validation.warnings.some((line) => line.startsWith('WARNING WRITES ENABLED OVER HTTP')),
      false,
      'both write-gate warnings printed; they are mutually exclusive states',
    );
  });

  test('the narrowing warning never names the value that grants everything', () => {
    const env = httpEnv({ UNIFI_ENABLE_WRITES: 'network,protect', UNIFI_HTTP_ALLOW_WRITES: 'none' });
    const [line] = validateConfig(load(env), env).warnings;

    // S-08: the line is printed in upper case at every start, into a log stream
    // several teams read. It must not be a standing recipe for removing the
    // control a security reviewer deliberately set.
    assert.ok(line !== undefined);
    assert.equal(/\ball\b/.test(line), false, `the narrowing warning enumerates \`all\`: ${line}`);
  });

  test('the DANGEROUS case warns too, naming services, bind and port', () => {
    const env = httpEnv({
      UNIFI_ENABLE_WRITES: 'network,protect',
      UNIFI_HTTP_ALLOW_WRITES: 'protect',
    });
    const validation = validateConfig(load(env), env);

    assert.ok(validation.warnings.includes(EFFECTIVE_WARNING), validation.warnings.join(' | '));
    assert.equal(
      validation.warnings.some((line) => line.startsWith('WARNING WRITES ARE DISABLED')),
      false,
    );
  });

  test('writes off entirely produces neither line', () => {
    const env = httpEnv();
    const validation = validateConfig(load(env), env);
    assert.deepEqual(
      validation.warnings.filter((line) => line.startsWith('WARNING WRITES')),
      [],
    );
  });

  test('refusal (c) still fires when the gate is open and the base gate is shut', () => {
    const env = httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'protect' });
    const validation = validateConfig(load(env), env);

    assert.equal(validation.ok, false);
    assert.ok(
      validation.errors.some(
        (line) =>
          line.includes('UNIFI_HTTP_ALLOW_WRITES names protect') &&
          line.includes('UNIFI_ENABLE_WRITES is empty'),
      ),
      validation.errors.join(' | '),
    );
  });
});

// ===========================================================================
// 5. AC 3 — the classified read-site inventory
// ===========================================================================

/**
 * FR-71's closed vocabulary. `enforcement` means the read decides whether a
 * tool is advertised or whether an outbound request proceeds — and nothing
 * else. Every other read is an `observation` carrying one of five reasons.
 */
type Classification =
  | 'enforcement'
  | 'type-declaration'
  | 'parse'
  | 'pass-through'
  | 'diagnostic'
  | 'redaction';

interface InventoryEntry {
  readonly file: string;
  /** The verbatim source expression the scan matched. NEVER a line number. */
  readonly expression: string;
  readonly classification: Classification;
}

/**
 * The inventory, taken BEFORE this story (at 77a3abc) and unchanged by it in
 * every entry that decides anything.
 *
 * This story added no row. It amended the MESSAGE inside the `src/http/client.ts`
 * enforcement site; the matched expression — the `if` condition — is byte-identical
 * to its form at HEAD, which is exactly why an inventory keyed on file plus
 * expression can tell "the message changed" from "a gate moved".
 */
const INVENTORY: readonly InventoryEntry[] = [
  // The two enforcement sites, and only these two.
  {
    file: 'src/tools/definitions.ts',
    expression: 'if (tool.requiresWrites && writesEnabled.size === 0) return false;',
    classification: 'enforcement',
  },
  {
    file: 'src/http/client.ts',
    expression:
      "if (action.actionClass === 'write' && !this.config.writesEnabled.has(action.service)) {",
    classification: 'enforcement',
  },

  // Type declarations.
  {
    file: 'src/config.ts',
    expression: 'writesEnabled: Set<ServiceId>;',
    classification: 'type-declaration',
  },
  {
    file: 'src/config.ts',
    expression:
      'writesEnabledBySurface: { readonly stdio: Set<ServiceId>; readonly http: Set<ServiceId> };',
    classification: 'type-declaration',
  },
  {
    file: 'src/tools/definitions.ts',
    expression: 'writesEnabled: ReadonlySet<ServiceId>,',
    classification: 'type-declaration',
  },

  // Resolution and the ONE narrowing, all inside `loadConfig`.
  {
    file: 'src/config.ts',
    expression: 'const writesEnabled = new Set<ServiceId>();',
    classification: 'parse',
  },
  {
    file: 'src/config.ts',
    expression: 'for (const s of enabledServices) writesEnabled.add(s);',
    classification: 'parse',
  },
  { file: 'src/config.ts', expression: 'writesEnabled.clear();', classification: 'parse' },
  {
    file: 'src/config.ts',
    expression: 'writesEnabled.add(token as ServiceId);',
    classification: 'parse',
  },
  {
    file: 'src/config.ts',
    expression: 'const writesEnabledBySurface = {',
    classification: 'parse',
  },
  { file: 'src/config.ts', expression: 'stdio: writesEnabled,', classification: 'parse' },
  {
    file: 'src/config.ts',
    expression: 'http: intersect(writesEnabled, httpAllowSet),',
    classification: 'parse',
  },
  {
    file: 'src/config.ts',
    expression: 'writesEnabled: writesEnabledBySurface[serving.transport],',
    classification: 'parse',
  },
  { file: 'src/config.ts', expression: 'writesEnabledBySurface,', classification: 'parse' },

  // Diagnostics: refusal (c)'s input, and the two startup warnings' input.
  // These decide what is REPORTED, never what is advertised or sent.
  {
    file: 'src/config.ts',
    expression: 'const baseWrites = config.writesEnabledBySurface.stdio;',
    classification: 'diagnostic',
  },
  {
    file: 'src/config.ts',
    expression: 'const base = config.writesEnabledBySurface.stdio;',
    classification: 'diagnostic',
  },
  {
    file: 'src/config.ts',
    expression: 'const overHttp = config.writesEnabledBySurface.http;',
    classification: 'diagnostic',
  },

  // Redaction — the introspection echo (FR-55).
  {
    file: 'src/config.ts',
    expression: 'writesEnabled: [...config.writesEnabled].sort(),',
    classification: 'redaction',
  },
  {
    file: 'src/config.ts',
    expression: 'writesEnabledCount: config.writesEnabled.size,',
    classification: 'redaction',
  },
  {
    file: 'src/config.ts',
    expression: 'writesEnabledBySurface: {',
    classification: 'redaction',
  },
  {
    file: 'src/config.ts',
    expression: 'stdio: [...config.writesEnabledBySurface.stdio].sort(),',
    classification: 'redaction',
  },
  {
    file: 'src/config.ts',
    expression: 'http: [...config.writesEnabledBySurface.http].sort(),',
    classification: 'redaction',
  },

  // The runtime: two pass-throughs into the enforcement site, two banners.
  //
  // MOVED FROM `src/index.ts` BY US-18, and the move is why this assertion is
  // keyed on file plus expression rather than on a line number: the three
  // entries that stood in the entrypoint went red the moment the split landed,
  // which is the guard working. All four remain `observation` — FR-71 permits
  // the Runtime to READ the set and forbids it to BRANCH on it to permit or
  // deny, so `src/serve/` still carries zero `enforcement` sites.
  //
  // The single `advertisedTools(…, config.writesEnabled)` call became two,
  // one per surface, because the runtime precomputes both advertised sets and
  // the session selects between them (architecture §1.2). Reading a set and
  // passing it as an argument is `pass-through`, not a second gate: the one
  // advertisement decision stays at `src/tools/definitions.ts`.
  {
    file: 'src/serve/runtime.ts',
    expression:
      'stdio: advertisedTools(config.enabledServices, config.writesEnabledBySurface.stdio),',
    classification: 'pass-through',
  },
  {
    file: 'src/serve/runtime.ts',
    expression:
      'http: advertisedTools(config.enabledServices, config.writesEnabledBySurface.http),',
    classification: 'pass-through',
  },
  //
  // AMENDED BY US-20, and amended rather than relaxed. The two banner reads
  // that stood inline in `announceStartup` moved into two named predicates when
  // D-12's read-only-banner suppression landed: `writeStateBanner` still reads
  // the EFFECTIVE set to choose between the two banners, and `narrowedToEmpty`
  // reads the PER-SURFACE sets to decide whether the HTTP narrowing is what
  // emptied it — which is the whole suppression decision. Both remain
  // `diagnostic`: they choose which line is printed and touch neither
  // advertisement nor dispatch, so `src/serve/` still carries zero
  // `enforcement` sites and the shrink-or-stay list below is untouched.
  {
    file: 'src/serve/runtime.ts',
    expression: 'const surfaces = config.writesEnabledBySurface;',
    classification: 'diagnostic',
  },
  {
    file: 'src/serve/runtime.ts',
    expression: 'const effective = config.writesEnabled;',
    classification: 'diagnostic',
  },
];

/** `file :: expression` — the key FR-71 mandates. Line numbers are not used. */
function keyOf(entry: { file: string; expression: string }): string {
  return `${entry.file} :: ${entry.expression}`;
}

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) found.push(...sourceFiles(path));
    else if (path.endsWith('.ts')) found.push(path);
  }
  return found;
}

/**
 * Every site under `src/` that reads the resolved write-enablement set.
 *
 * Comment-only lines are excluded: prose naming the identifier is not a read,
 * and including it would make the inventory go red every time someone improved
 * a comment — the rot that makes a checked-in inventory get deleted.
 */
function scanReadSites(): { file: string; expression: string; line: number }[] {
  const sites: { file: string; expression: string; line: number }[] = [];
  for (const path of sourceFiles(SRC_ROOT)) {
    const file = relative(REPO_ROOT, path).split('\\').join('/');
    readFileSync(path, 'utf8')
      .split(/\r?\n/)
      .forEach((raw, index) => {
        const expression = raw.trim();
        if (expression.startsWith('*') || expression.startsWith('//')) return;
        if (expression.startsWith('/*')) return;
        if (!expression.includes('writesEnabled')) return;
        sites.push({ file, expression, line: index + 1 });
      });
  }
  return sites;
}

describe('AC 3 — no new enforcement decision appeared (FR-71 assertions 1-4)', () => {
  const sites = scanReadSites();

  test('(1) site-set equality: every read under src/ is classified', () => {
    const scanned = new Set(sites.map(keyOf));
    const inventoried = new Set(INVENTORY.map(keyOf));

    const unclassified = [...scanned].filter((key) => !inventoried.has(key)).sort();
    const stale = [...inventoried].filter((key) => !scanned.has(key)).sort();

    assert.deepEqual(
      unclassified,
      [],
      'a new read of the write set is not in the inventory; classify it (see FR-71)',
    );
    assert.deepEqual(stale, [], 'the inventory names a site that no longer exists');
  });

  test('(2) exactly 2 sites are classified `enforcement`', () => {
    const enforcement = INVENTORY.filter((e) => e.classification === 'enforcement');
    assert.equal(enforcement.length, 2, enforcement.map(keyOf).join(' | '));
  });

  test('(3) shrink-or-stay: the enforcement list is a subset of its previous contents', () => {
    // The enforcement inventory as it stood BEFORE this story, at 77a3abc.
    // Keyed on expression, so `client.ts`'s gate moving down the file — which
    // FR-70's drain affordances already did — is not a change to this list.
    const previous = new Set([
      'src/tools/definitions.ts :: if (tool.requiresWrites && writesEnabled.size === 0) return false;',
      "src/http/client.ts :: if (action.actionClass === 'write' && " +
        '!this.config.writesEnabled.has(action.service)) {',
    ]);
    for (const entry of INVENTORY.filter((e) => e.classification === 'enforcement')) {
      assert.ok(
        previous.has(keyOf(entry)),
        `a third write gate was added and inventoried in the same change: ${keyOf(entry)}`,
      );
    }
  });

  test('(4) src/serve/ carries no `enforcement` site', () => {
    const offenders = INVENTORY.filter(
      (e) => e.classification === 'enforcement' && e.file.startsWith('src/serve/'),
    );
    assert.deepEqual(offenders.map(keyOf), []);
  });

  test('both enforcement expressions are present in the tree exactly once', () => {
    // The inventory is a claim about source; this is the claim checked against
    // it, so a gate that was deleted or duplicated cannot pass by leaving the
    // inventory untouched.
    for (const entry of INVENTORY.filter((e) => e.classification === 'enforcement')) {
      const matches = sites.filter((site) => keyOf(site) === keyOf(entry));
      assert.equal(matches.length, 1, `${keyOf(entry)} appears ${matches.length} times`);
    }
  });
});
