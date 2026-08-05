/**
 * US-18 — the runtime split.
 *
 * Six sections, in the order the story's acceptance criteria run:
 *
 *  1. `buildRuntimeCore` — the ordered startup sequence, and the FR-78/NFR-31
 *     credential capture-then-scrub that US-16 built and had no call site for.
 *  2. The startup refusals, raised rather than exited.
 *  3. `resolveRegistry` — once per process, after the bind, never rejecting.
 *  4. `createMcpServer` — one server per session over one shared runtime.
 *  5. The structural criteria: the shrunken entrypoint and the source scans.
 *  6. The stdio path, end to end, in a spawned process.
 *
 * `src/index.ts` is deliberately never imported here (test strategy S-09):
 * importing the entrypoint would, once US-19 lands, install signal handlers
 * over the test runner's own. Section 6 spawns it instead, which is also the
 * only honest way to prove the stdio transport still works — a no-regression
 * story that is asserted rather than tested proves nothing.
 *
 * Every `CredentialStore` this file constructs passes `keychain: null` (S-09).
 * `npm ci` installs `keytar` on the macOS and Windows legs, so a store built
 * without it would query the runner's — or a developer's — real login keychain.
 */
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { redactedSummary, type ServerConfig } from '../src/config.js';
import { CredentialStore, type CredentialStoreOptions } from '../src/credentials.js';
import { UnifiClient } from '../src/http/client.js';
import { buildRegistry, type SpecManifest } from '../src/registry/build.js';
import { createMcpServer } from '../src/serve/mcpServer.js';
import {
  buildRuntimeCore,
  ConfigRefusal,
  resolveRegistry,
  RuntimeNotReady,
  type RuntimeCore,
  type RuntimeDeps,
  type Surface,
} from '../src/serve/runtime.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC_ROOT = join(REPO_ROOT, 'src');

/** A recognisable value, so "did the key survive the scrub" is not a guess. */
const SENTINEL = `SENTINEL-${'k'.repeat(32)}`;

function baseEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return { UNIFI_API_KEY: SENTINEL, ...extra };
}

interface Counters {
  readonly lines: string[];
  /** `CredentialStoreOptions.env` as the store actually received it. */
  storeEnv: NodeJS.ProcessEnv | null;
  storeBuilds: number;
  clientBuilds: number;
  registryBuilds: number;
  manifestReads: number;
}

interface Harness {
  readonly deps: RuntimeDeps;
  readonly seen: Counters;
}

function readManifestFromDisk(): SpecManifest {
  return JSON.parse(readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8')) as SpecManifest;
}

/**
 * One `RuntimeDeps` carrying every counter this story asserts.
 *
 * The registry-build and client-construction counts are observed HERE, at the
 * `Runtime` call site, and never inside `src/registry/build.ts`, which has no
 * injection seam and which the diff-scope invariant forbids this round from
 * touching. Count the call, not the callee.
 */
function harness(env: NodeJS.ProcessEnv, overrides: RuntimeDeps = {}): Harness {
  const seen: Counters = {
    lines: [],
    storeEnv: null,
    storeBuilds: 0,
    clientBuilds: 0,
    registryBuilds: 0,
    manifestReads: 0,
  };

  const deps: RuntimeDeps = {
    env,
    warn: (line) => seen.lines.push(line),
    createCredentialStore: (config: ServerConfig, options: CredentialStoreOptions) => {
      seen.storeBuilds += 1;
      seen.storeEnv = options.env ?? null;
      return new CredentialStore(config, { ...options, keychain: null });
    },
    createClient: (config, credentials, options) => {
      seen.clientBuilds += 1;
      return new UnifiClient(config, credentials, options);
    },
    readManifest: () => {
      seen.manifestReads += 1;
      return (overrides.readManifest ?? readManifestFromDisk)();
    },
    buildRegistry: (root, manifest, services) => {
      seen.registryBuilds += 1;
      return (overrides.buildRegistry ?? buildRegistry)(root, manifest, services);
    },
  };

  for (const [key, value] of Object.entries(overrides)) {
    if (key === 'readManifest' || key === 'buildRegistry') continue;
    (deps as Record<string, unknown>)[key] = value;
  }

  return { deps, seen };
}

async function readyCore(extra: NodeJS.ProcessEnv = {}): Promise<RuntimeCore> {
  const core = buildRuntimeCore(harness(baseEnv(extra)).deps);
  await resolveRegistry(core);
  return core;
}

// ===========================================================================
// 1. buildRuntimeCore — the ordered startup sequence (AC 1)
// ===========================================================================

describe('buildRuntimeCore — the ordered startup sequence (FR-62, FR-78, NFR-31)', () => {
  test('capture, construct, scrub — and the first credential resolution still works', async () => {
    const env = baseEnv();
    const { deps, seen } = harness(env);
    const core = buildRuntimeCore(deps);

    try {
      // CAPTURE happened before the scrub: the store holds the plaintext.
      assert.equal(seen.storeEnv?.UNIFI_API_KEY, SENTINEL);
      // SCRUB happened after: the environment the runtime was handed is clean.
      assert.equal(env.UNIFI_API_KEY, undefined);
      assert.equal(JSON.stringify(env).includes(SENTINEL), false);

      // The seam is asserted, not assumed: an implementation that scrubbed a
      // snapshot it never wired up passes both assertions above and still
      // throws on the first call.
      assert.notEqual(seen.storeEnv, process.env);

      // THE SCRUB DOES NOT BREAK THE FIRST CREDENTIAL RESOLUTION. This is the
      // failure mode FR-78 exists to pin: a server that starts clean, reports
      // ready, and throws `No cloud API key is configured` at the operator's
      // first tool call, behind a green startup log.
      assert.equal(await core.credentials.resolveFor('site-manager', 'cloud'), SENTINEL);
    } finally {
      await core.close();
    }
  });

  test('the negative control — a missing key really does produce that message', async () => {
    // Proves the assertion above is not vacuous, and pins the exact substring
    // FR-78 names as the symptom of the wrong scrub ordering.
    // A local-only deployment: Network and Protect are usable, Site Manager is
    // not, and asking for the cloud key is the shape FR-78 names.
    const { deps } = harness({
      UNIFI_LOCAL_HOST: '192.0.2.10',
      UNIFI_LOCAL_API_KEY: `${'n'.repeat(40)}`,
    });
    const core = buildRuntimeCore(deps);
    try {
      await assert.rejects(
        () => core.credentials.resolveFor('site-manager', 'cloud'),
        /No cloud API key is configured/,
      );
    } finally {
      await core.close();
    }
  });

  test('the scrub covers the inbound secret class as well as the UniFi keys', async () => {
    const env = baseEnv({
      UNIFI_HTTP_TOKEN: 'i'.repeat(40),
      UNIFI_HTTP_TOKEN_NEXT: 'j'.repeat(40),
    });
    const core = buildRuntimeCore(harness(env).deps);
    try {
      for (const key of [
        'UNIFI_API_KEY',
        'UNIFI_API_KEY_FILE',
        'UNIFI_HTTP_TOKEN',
        'UNIFI_HTTP_TOKEN_FILE',
        'UNIFI_HTTP_TOKEN_NEXT',
        'UNIFI_HTTP_TOKEN_NEXT_FILE',
      ]) {
        assert.equal(env[key], undefined, `${key} survived the scrub`);
      }
    } finally {
      await core.close();
    }
  });

  test('an injected env leaves process.env untouched', async () => {
    // Without this, fixture 1 of a write-gate parity suite scrubs the keys and
    // fixture 2 in the same file hits a startup refusal it never configured.
    const marker = 'process-level-value';
    const had = Object.prototype.hasOwnProperty.call(process.env, 'UNIFI_API_KEY');
    const previous = process.env.UNIFI_API_KEY;
    process.env.UNIFI_API_KEY = marker;
    try {
      const core = buildRuntimeCore(harness(baseEnv()).deps);
      assert.equal(process.env.UNIFI_API_KEY, marker);
      await core.close();
    } finally {
      if (had) process.env.UNIFI_API_KEY = previous;
      else delete process.env.UNIFI_API_KEY;
    }
  });

  test('no sentinel reaches the redacted summary the startup line serialises', async () => {
    const core = buildRuntimeCore(harness(baseEnv()).deps);
    try {
      assert.equal(JSON.stringify(redactedSummary(core.config)).includes(SENTINEL), false);
    } finally {
      await core.close();
    }
  });

  test('a credential file that cannot be read is a FATAL startup refusal', () => {
    // US-16 shipped the three delivery refusals with no call site, so until
    // this story they surfaced as stderr diagnostics on the lazy path — an
    // hour later, as a failed tool call. They stop startup now.
    const missing = join(REPO_ROOT, 'test', 'fixtures', 'no-such-credential-file');
    assert.throws(
      () => buildRuntimeCore(harness({ UNIFI_API_KEY_FILE: missing }).deps),
      (error: unknown) => {
        assert.ok(error instanceof ConfigRefusal);
        const text = error.errors.join(' ');
        assert.match(text, /UNIFI_API_KEY_FILE/);
        assert.ok(text.includes(missing), 'the refusal names the path');
        return true;
      },
    );
  });

  test(
    'a group-readable credential file warns and still starts',
    { skip: process.platform === 'win32' ? 'mode bits are meaningless on Windows' : false },
    async () => {
      const path = join(mkdtempSync(join(tmpdir(), 'unifi-mcp-cred-')), 'api-key');
      writeFileSync(path, `${SENTINEL}\n`);
      chmodSync(path, 0o644);

      const { deps, seen } = harness({ UNIFI_API_KEY_FILE: path });
      const core = buildRuntimeCore(deps);
      try {
        assert.match(
          seen.lines.join('\n'),
          /readable by group or other/,
          'capture.warnings must reach stderr',
        );
        assert.equal(await core.credentials.resolveFor('site-manager', 'cloud'), SENTINEL);
      } finally {
        await core.close();
      }
    },
  );

  test('every diagnostic carries exactly one unifi-mcp prefix, composed by log.ts', async () => {
    const { deps, seen } = harness(
      baseEnv({ UNIFI_LOCAL_HOST: '192.0.2.10', UNIFI_LOCAL_TLS_INSECURE: '1' }),
    );
    const core = buildRuntimeCore(deps);
    try {
      // The collaborators predate `log.ts` and compose their own prefix; the
      // runtime hands their lines over with it removed rather than doubled.
      await core.credentials.resolveFor('site-manager', 'cloud');
      assert.ok(seen.lines.length > 0, 'nothing was emitted at all');
      for (const line of seen.lines) {
        assert.match(line, /^unifi-mcp: /);
        assert.equal(line.startsWith('unifi-mcp: unifi-mcp: '), false, `double prefix: ${line}`);
      }
    } finally {
      await core.close();
    }
  });
});

// ===========================================================================
// 2. The refusals, raised rather than exited (AC 8)
// ===========================================================================

describe('startup refusals are raised, and nothing is built behind them', () => {
  test('an unrecognised UNIFI_MCP_TRANSPORT names the variable and the accepted values', () => {
    const { deps, seen } = harness(baseEnv({ UNIFI_MCP_TRANSPORT: 'tcp' }));
    assert.throws(
      () => buildRuntimeCore(deps),
      (error: unknown) => {
        assert.ok(error instanceof ConfigRefusal);
        const text = error.errors.join(' ');
        assert.match(text, /UNIFI_MCP_TRANSPORT/);
        assert.match(text, /`stdio`/);
        assert.match(text, /`http`/);
        // Distinguished from the OUTBOUND transport variables, whose values are
        // `local` and `connector` and which control something else entirely.
        assert.match(text, /UNIFI_NETWORK_TRANSPORT/);
        assert.match(text, /UNIFI_PROTECT_TRANSPORT/);
        return true;
      },
    );
    // FR-62's fixed order: refuse first, bind second, registry third. The
    // registry counter is the observable half of "nothing happened yet".
    assert.equal(seen.registryBuilds, 0);
    assert.equal(seen.manifestReads, 0);
  });

  test('a ConfigRefusal carries its errors for the entrypoint to render', () => {
    const error = new ConfigRefusal(['first', 'second']);
    assert.equal(error.name, 'ConfigRefusal');
    assert.deepEqual([...error.errors], ['first', 'second']);
    assert.match(error.message, /first/);
  });
});

// ===========================================================================
// 3. resolveRegistry — once per process, after the bind (AC 2, 3, 4)
// ===========================================================================

describe('resolveRegistry — once per process regardless of session count', () => {
  test('the registry, the store and the client are constructed exactly once for N sessions', async () => {
    const { deps, seen } = harness(baseEnv());
    const core = buildRuntimeCore(deps);
    try {
      assert.equal(seen.registryBuilds, 0, 'the registry must not be built before the bind');

      await resolveRegistry(core);
      // Three sessions, as three concurrent HTTP clients would produce.
      const servers = [
        createMcpServer(core, 'stdio'),
        createMcpServer(core, 'stdio'),
        createMcpServer(core, 'stdio'),
      ];
      assert.equal(new Set(servers).size, 3, 'sessions must not share an McpServer');

      assert.equal(seen.registryBuilds, 1);
      assert.equal(seen.manifestReads, 1);
      assert.equal(seen.storeBuilds, 1);
      assert.equal(seen.clientBuilds, 1);
    } finally {
      await core.close();
    }
  });

  test('a second resolveRegistry is the first one, not a second build', async () => {
    const { deps, seen } = harness(baseEnv());
    const core = buildRuntimeCore(deps);
    try {
      await Promise.all([resolveRegistry(core), resolveRegistry(core)]);
      await resolveRegistry(core);
      assert.equal(seen.registryBuilds, 1);
    } finally {
      await core.close();
    }
  });

  test('every session draws on ONE outbound client — the shared token bucket', async () => {
    // NFR-15/NFR-26 and FR-72: the rate-limit buckets model a limit the UniFi
    // console enforces per console. N sessions with N clients would present
    // N x the permitted rate and manufacture exactly the self-inflicted 429s
    // the limiter exists to prevent. The identity half is asserted here; the
    // frozen-clock contention proof is US-28's C25.
    const { deps, seen } = harness(baseEnv());
    const core = buildRuntimeCore(deps);
    try {
      await resolveRegistry(core);
      createMcpServer(core, 'stdio');
      createMcpServer(core, 'http');
      assert.equal(seen.clientBuilds, 1);
      assert.equal(seen.storeBuilds, 1);
    } finally {
      await core.close();
    }
  });

  test('advertisedToolsFor throws RuntimeNotReady before the registry resolves', async () => {
    const core = buildRuntimeCore(harness(baseEnv()).deps);
    try {
      assert.throws(() => core.advertisedToolsFor('stdio'), RuntimeNotReady);
      assert.equal(core.registry, null);
      await resolveRegistry(core);
      assert.ok(core.advertisedToolsFor('stdio').length > 0);
      assert.notEqual(core.registry, null);
    } finally {
      await core.close();
    }
  });

  test('the advertised set is precomputed PER SURFACE', async () => {
    // `UNIFI_HTTP_ALLOW_WRITES` unset narrows the HTTP surface to no writes
    // while stdio keeps them, so the two sets must differ.
    const core = await readyCore({ UNIFI_ENABLE_WRITES: 'site-manager' });
    try {
      const stdio = core.advertisedToolsFor('stdio').map((t) => t.name);
      const http = core.advertisedToolsFor('http').map((t) => t.name);
      assert.ok(stdio.includes('unifi_execute_write_action'));
      assert.equal(http.includes('unifi_execute_write_action'), false);
      // The same array each time: precomputed at load, not narrowed per session.
      assert.equal(core.advertisedToolsFor('stdio'), core.advertisedToolsFor('stdio'));
    } finally {
      await core.close();
    }
  });

  test('a registry failure settles ready and lands on readyError — it never rejects', async () => {
    const { deps, seen } = harness(baseEnv(), {
      buildRegistry: () => {
        throw new Error('spec layer missing');
      },
    });
    const core = buildRuntimeCore(deps);
    try {
      await resolveRegistry(core);
      await core.ready;
      assert.match(String(core.readyError), /spec layer missing/);
      assert.throws(() => core.advertisedToolsFor('stdio'), RuntimeNotReady);
      assert.match(seen.lines.join('\n'), /the action registry failed to resolve/);
    } finally {
      await core.close();
    }
  });

  test('the startup announcement moved here from the entrypoint', async () => {
    const { deps, seen } = harness(baseEnv());
    const core = buildRuntimeCore(deps);
    try {
      await resolveRegistry(core);
      const text = seen.lines.join('\n');
      assert.match(text, /^unifi-mcp: ready — \d+ tools, \d+ actions across \d+ API\(s\)\./m);
      assert.match(text, /unifi-mcp: read-only \(writes are off; set UNIFI_ENABLE_WRITES/);
    } finally {
      await core.close();
    }
  });

  test('the write-enabled banner is the other arm of the same read', async () => {
    const { deps, seen } = harness(baseEnv({ UNIFI_ENABLE_WRITES: 'site-manager' }));
    const core = buildRuntimeCore(deps);
    try {
      await resolveRegistry(core);
      const text = seen.lines.join('\n');
      assert.match(text, /unifi-mcp: WRITES ENABLED for site-manager\./);
      assert.equal(text.includes('read-only (writes are off'), false);
    } finally {
      await core.close();
    }
  });
});

// ===========================================================================
// 4. createMcpServer — one server per session (AC 5, A1)
// ===========================================================================

describe('createMcpServer — per session, connecting nothing', () => {
  test('the factory connects nothing', async () => {
    const core = await readyCore();
    try {
      assert.equal(createMcpServer(core, 'stdio').isConnected(), false);
    } finally {
      await core.close();
    }
  });

  test('A1 — an initialize + tools/list round trip completes over an in-memory pair', async () => {
    const core = await readyCore();
    const server = createMcpServer(core, 'stdio');
    const client = new Client({ name: 'us-18', version: '0.0.0' });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    try {
      await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
      const listed = await client.listTools();
      assert.deepEqual(
        listed.tools.map((t) => t.name).sort(),
        core
          .advertisedToolsFor('stdio')
          .map((t) => t.name)
          .sort(),
      );
    } finally {
      await client.close();
      await server.close();
      await core.close();
    }
  });

  test('two sessions run concurrently on ONE runtime', async () => {
    const core = await readyCore();
    const surfaces: Surface[] = ['stdio', 'http'];
    const sessions = await Promise.all(
      surfaces.map(async (surface) => {
        const server = createMcpServer(core, surface);
        const client = new Client({ name: `us-18-${surface}`, version: '0.0.0' });
        const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
        await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
        return { server, client };
      }),
    );
    try {
      const results = await Promise.all(sessions.map(({ client }) => client.listTools()));
      assert.equal(results.length, 2);
      for (const result of results) assert.ok(result.tools.length > 0);
    } finally {
      for (const { client, server } of sessions) {
        await client.close();
        await server.close();
      }
      await core.close();
    }
  });

  test('one McpServer REFUSES a second transport — the constraint behind the split', async () => {
    // `shared/protocol.js:217`: "Already connected to a transport. Call close()
    // before connecting to a new transport, or use a separate Protocol instance
    // per connection." No queue, no replace semantics. The per-session server
    // is forced, not chosen.
    const core = await readyCore();
    const server = createMcpServer(core, 'stdio');
    const [, first] = InMemoryTransport.createLinkedPair();
    const [, second] = InMemoryTransport.createLinkedPair();
    try {
      await server.connect(first);
      await assert.rejects(() => server.connect(second), /Already connected/);
    } finally {
      await server.close();
      await core.close();
    }
  });
});

// ===========================================================================
// 5. The structural criteria (AC 9, 10, 11)
// ===========================================================================

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) found.push(...sourceFiles(path));
    else if (path.endsWith('.ts')) found.push(path);
  }
  return found;
}

function relPath(path: string): string {
  return relative(REPO_ROOT, path).split('\\').join('/');
}

/** Every `from '…'` specifier in a source file. */
function importSpecifiers(source: string): string[] {
  return [...source.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1] as string);
}

describe('the shrunken entrypoint (AC 9)', () => {
  const index = readFileSync(join(SRC_ROOT, 'index.ts'), 'utf8');

  test('src/index.ts is under 90 lines including comments', () => {
    const lines = index.split(/\r?\n/).length;
    assert.ok(lines < 90, `src/index.ts is ${lines} lines`);
  });

  test('it exports main(deps, observer, servingDeps)', () => {
    assert.match(index, /export async function main\(\s*deps[\s\S]*?observer[\s\S]*?servingDeps/);
  });

  test('it holds the ONLY process.exit in src/, inside the auto-run guard', () => {
    const holders = sourceFiles(SRC_ROOT).filter((file) =>
      readFileSync(file, 'utf8').includes('process.exit('),
    );
    assert.deepEqual(holders.map(relPath), ['src/index.ts']);
    assert.match(index, /import\.meta\.url === pathToFileURL\(process\.argv\[1\] \?\? ''\)\.href/);
  });

  test('no write-state banner is left emitting from the entrypoint (US-20 depends on this)', () => {
    // US-20 owns the read-only-banner suppression at the banner's NEW home in
    // `src/serve/runtime.ts`, and is instructed to stop and escalate if any
    // write-state banner is still emitting from here.
    assert.equal(index.includes('writesEnabled'), false);
    assert.equal(index.includes('WRITES ENABLED'), false);
    assert.equal(index.includes('read-only (writes are off'), false);
    assert.equal(index.includes('ready —'), false);
  });
});

describe('the source scans (AC 10)', () => {
  test('the literal `serve/` appears in no import outside src/serve/ and src/index.ts', () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(SRC_ROOT)) {
      const rel = relPath(file);
      if (rel.startsWith('src/serve/') || rel === 'src/index.ts') continue;
      for (const specifier of importSpecifiers(readFileSync(file, 'utf8'))) {
        if (specifier.includes('serve/')) offenders.push(`${rel} -> ${specifier}`);
      }
    }
    assert.deepEqual(offenders, []);
  });

  test('RuntimeLifecycle is named only where process-scoped teardown belongs', () => {
    // `runtime.ts` declares it; `index.ts`, `stdio.ts` and — once US-22 lands —
    // `http.ts` hold it. Every other module under `src/serve/` sees `Runtime`,
    // so no per-session path can reach `beginDrain()` or `close()`.
    const permitted = new Set([
      'src/serve/runtime.ts',
      'src/serve/stdio.ts',
      'src/serve/http.ts',
      'src/index.ts',
    ]);
    const namers = sourceFiles(SRC_ROOT)
      .filter((file) => readFileSync(file, 'utf8').includes('RuntimeLifecycle'))
      .map(relPath);
    assert.deepEqual(
      namers.filter((file) => !permitted.has(file)),
      [],
    );
    assert.ok(namers.includes('src/serve/runtime.ts'), 'the scan matched nothing, so it proves nothing');
  });

  test('the src/serve/ module graph is acyclic and one-directional', () => {
    const edges = new Map<string, string[]>();
    for (const file of sourceFiles(join(SRC_ROOT, 'serve'))) {
      const name = relPath(file).slice('src/serve/'.length);
      edges.set(
        name,
        importSpecifiers(readFileSync(file, 'utf8'))
          .filter((specifier) => specifier.startsWith('./'))
          .map((specifier) => specifier.slice(2).replace(/\.js$/, '.ts')),
      );
    }

    // Direction: the runtime sits BELOW the session factory and the transports.
    for (const above of ['stdio.ts', 'http.ts', 'mcpServer.ts']) {
      assert.equal(
        (edges.get('runtime.ts') ?? []).includes(above),
        false,
        `runtime.ts must not import ${above}`,
      );
    }
    assert.deepEqual(edges.get('mcpServer.ts'), ['runtime.ts']);

    // Acyclicity, by depth-first search over the whole intra-serve graph.
    const state = new Map<string, 'open' | 'done'>();
    const walk = (node: string, trail: readonly string[]): void => {
      if (state.get(node) === 'done') return;
      assert.notEqual(state.get(node), 'open', `import cycle: ${[...trail, node].join(' -> ')}`);
      state.set(node, 'open');
      for (const next of edges.get(node) ?? []) walk(next, [...trail, node]);
      state.set(node, 'done');
    };
    for (const node of edges.keys()) walk(node, []);
  });

  test('D-14 — only log.ts writes to a standard stream, across src/serve/ AND src/index.ts', () => {
    // The scan that was blocked behind the US-13 <-> US-18 cycle. `src/index.ts`
    // is in scope here for the first time: its `warn()` helper and its direct
    // stream writes are gone, routed onto `emitDiagnostic` / `emitError`.
    const scanned = [...sourceFiles(join(SRC_ROOT, 'serve')), join(SRC_ROOT, 'index.ts')];
    const writers = scanned.filter((file) => {
      const source = readFileSync(file, 'utf8');
      return source.includes('process.stderr.write') || /\bconsole\s*\./.test(source);
    });
    assert.deepEqual(writers.map(relPath), ['src/serve/log.ts']);
  });
});

describe('the declared SDK range (AC 11, NFR-28)', () => {
  test('package.json pins @modelcontextprotocol/sdk to exactly ~1.30.0', () => {
    const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    // A caret range permits 1.99.0, which is the drift the requirement exists
    // to prevent. Narrowed in the same change that introduces `src/serve/`.
    assert.equal(manifest.dependencies['@modelcontextprotocol/sdk'], '~1.30.0');
  });
});

// ===========================================================================
// 6. The stdio path, end to end (AC 7)
// ===========================================================================

describe('the stdio transport still serves, end to end', () => {
  test('a real client spawns the entrypoint and lists tools over stdin/stdout', async () => {
    // The production entrypoint, no arguments, driven by the SDK's own client
    // over real stdio framing. `lsof` and `ss` are deliberately used nowhere in
    // this file: neither exists on windows-latest and NFR-20 requires that leg
    // green.
    const inherited = Object.fromEntries(
      Object.entries(process.env).filter(
        ([key, value]) => !key.startsWith('UNIFI_') && value !== undefined,
      ),
    ) as Record<string, string>;

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['--import', 'tsx', join(REPO_ROOT, 'src', 'index.ts')],
      env: { ...inherited, UNIFI_API_KEY: SENTINEL },
      cwd: REPO_ROOT,
      stderr: 'ignore',
    });
    const client = new Client({ name: 'us-18-stdio', version: '0.0.0' });

    try {
      await client.connect(transport);
      const listed = await client.listTools();
      assert.ok(listed.tools.length > 0, 'the spawned stdio server advertised no tools');
      assert.ok(listed.tools.some((tool) => tool.name === 'unifi_search_actions'));
    } finally {
      await client.close();
    }
  });
});
