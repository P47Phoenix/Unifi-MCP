/**
 * The FR-75 invocation counters, and the wire format the spawned child uses.
 *
 * This is a test HELPER, not a test file: `scripts/run-tests.mjs` discovers
 * suites with a NON-recursive `readdirSync('test')`.
 *
 * ## The counting rule, which is the whole design
 *
 * Every counter is observed at the `Runtime` CALL SITE and never inside the
 * collaborator it counts. `src/registry/build.ts` exports a pure function with
 * no options object and no injection seam, and it is inside the diff-scope
 * invariant this round may not touch — so the only honest place to count a
 * registry build is where the runtime calls it. The same reasoning applies to
 * the manifest read and the credential-store construction, and the same
 * reasoning is why the three transport-side counters are `ServingObserver`
 * callbacks rather than probes inside the transports.
 *
 * Count the call, not the callee.
 *
 * ## Inertness
 *
 * Nothing here is reachable from production. `RuntimeDeps` fields each default
 * to the real collaborator and `ServingObserver` is `undefined` in production
 * with every call site optional-chained, so a process that constructs neither
 * behaves exactly as it does today. `test/instruments.test.ts` asserts that
 * behaviourally in both directions rather than by reading the source, because
 * the two files that hold those call sites are being rewritten by other
 * stories in this same wave and a text scan over them would be asserting their
 * formatting rather than this property.
 *
 * ## The keychain rule
 *
 * `createCredentialStore` below ALWAYS passes `keychain`, defaulting to `null`.
 * `npm ci` installs `keytar` on the macOS and Windows legs, so a store built
 * without the field queries the runner's — or a developer's — real login
 * keychain, and on a workstation that is a live credential prompt. S-09 asserts
 * this structurally over the whole of `test/`; this module makes it the only
 * thing a caller can do.
 */
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServerConfig } from '../../src/config.js';
import {
  CredentialStore,
  type CredentialStoreOptions,
  type KeytarLike,
} from '../../src/credentials.js';
import { UnifiClient, type UnifiClientOptions } from '../../src/http/client.js';
import { buildRegistry, type SpecManifest } from '../../src/registry/build.js';
import type { RuntimeDeps, ServingObserver, Surface } from '../../src/serve/runtime.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * The six named counters, plus the observer traffic four later stories read.
 *
 * JSON-serialisable by construction: the spawned child writes this object to
 * stderr as one line and the parent parses it back, so no `Map`, no `Set` and
 * no `undefined` may appear here.
 */
export interface CounterSnapshot {
  /** `RuntimeDeps.createCredentialStore` — the credential-store counter. */
  readonly credentialStore: number;
  /** `RuntimeDeps.buildRegistry` — the action-registry build counter. */
  readonly registryBuild: number;
  /** `RuntimeDeps.readManifest` — the startup artifact check counter. */
  readonly manifestRead: number;
  /** `RuntimeDeps.createClient`. Not one of the six; useful beside them. */
  readonly clientBuild: number;
  /** `ServingObserver.onMcpRequest` — the MCP request-handler counter. */
  readonly mcpRequest: number;
  /** `ServingObserver.onListen` — the `server.listen` counter. */
  readonly listen: number;
  /** `ServingObserver.onTransportActivated`, per surface. */
  readonly transportActivated: Readonly<Record<Surface, number>>;
  readonly ready: number;
  /** `ServingObserver.onListen`'s addresses, so a child can report its port. */
  readonly listenAddresses: readonly AddressInfo[];
  /** `ServingObserver.onDrainStep`, in order. */
  readonly drainSteps: readonly string[];
  /** `ServingObserver.onDisposal`, in order. */
  readonly disposals: readonly string[];
  /** `ServingObserver.onRequestLog` lines, for the NFR-24 sentinel scan. */
  readonly requestLogs: readonly string[];
}

interface MutableSnapshot {
  credentialStore: number;
  registryBuild: number;
  manifestRead: number;
  clientBuild: number;
  mcpRequest: number;
  listen: number;
  transportActivated: Record<Surface, number>;
  ready: number;
  listenAddresses: AddressInfo[];
  drainSteps: string[];
  disposals: string[];
  requestLogs: string[];
}

function emptySnapshot(): MutableSnapshot {
  return {
    credentialStore: 0,
    registryBuild: 0,
    manifestRead: 0,
    clientBuild: 0,
    mcpRequest: 0,
    listen: 0,
    transportActivated: { stdio: 0, http: 0 },
    ready: 0,
    listenAddresses: [],
    drainSteps: [],
    disposals: [],
    requestLogs: [],
  };
}

export interface InstrumentOptions {
  /**
   * The configuration source, handed to `RuntimeDeps.env`.
   *
   * Explicit and never `process.env`: FR-78's capture-then-delete scrub deletes
   * from THIS object, so an injected env leaves the runner's own environment
   * untouched and lets several differently-configured runtimes live in one
   * test file without the first poisoning the second.
   */
  readonly env: NodeJS.ProcessEnv;
  /**
   * `null` (the default) means the keychain path is never entered. Pass an
   * explicit stub to exercise it. There is no way to pass `undefined`.
   */
  readonly keychain?: KeytarLike | null;
  /** Extra `RuntimeDeps` fields, applied after the counting wrappers. */
  readonly deps?: RuntimeDeps;
  /** Called with each composed diagnostic line, in addition to capturing it. */
  readonly onLine?: (line: string) => void;
}

export interface Instruments {
  /** Pass to `buildRuntimeCore` / `main`. Every field counts, then delegates. */
  readonly deps: RuntimeDeps;
  /** Pass to `main` / `startStdio` / `startHttp` as the second argument. */
  readonly observer: ServingObserver;
  /** Live counters. Read directly, or `snapshot()` for a stable copy. */
  readonly counts: CounterSnapshot;
  /** Every diagnostic line, prefix applied and sanitised, as it would reach stderr. */
  readonly lines: readonly string[];
  snapshot(): CounterSnapshot;
}

/** The startup artifact check, when the caller does not override it. */
export function readManifestFromDisk(): SpecManifest {
  return JSON.parse(
    readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'),
  ) as SpecManifest;
}

/**
 * Build one counting `RuntimeDeps` and its matching `ServingObserver`.
 *
 * Each wrapper increments and then calls the PRODUCTION collaborator, so what
 * runs behind the counter is the real thing. A wrapper that substituted a
 * stand-in would turn "the runtime built the registry once" into "the harness
 * called itself once".
 */
export function createInstruments(options: InstrumentOptions): Instruments {
  const counts = emptySnapshot();
  const lines: string[] = [];
  const keychain = options.keychain ?? null;
  const extra = options.deps ?? {};

  const deps: RuntimeDeps = {
    env: options.env,
    warn: (line) => {
      lines.push(line);
      options.onLine?.(line);
    },
    createCredentialStore: (config: ServerConfig, storeOptions: CredentialStoreOptions) => {
      counts.credentialStore += 1;
      // `keychain` is spread LAST so a caller cannot accidentally drop it by
      // supplying their own options object upstream (S-09).
      return new CredentialStore(config, { ...storeOptions, keychain });
    },
    createClient: (
      config: ServerConfig,
      credentials: CredentialStore,
      clientOptions: UnifiClientOptions,
    ) => {
      counts.clientBuild += 1;
      return new UnifiClient(config, credentials, clientOptions);
    },
    readManifest: () => {
      counts.manifestRead += 1;
      return (extra.readManifest ?? readManifestFromDisk)();
    },
    buildRegistry: (root, manifest, services) => {
      counts.registryBuild += 1;
      return (extra.buildRegistry ?? buildRegistry)(root, manifest, services);
    },
    ...omit(extra, ['readManifest', 'buildRegistry']),
  };

  const observer: ServingObserver = {
    onTransportActivated: (kind: Surface) => {
      counts.transportActivated[kind] += 1;
    },
    onListen: (address: AddressInfo) => {
      counts.listen += 1;
      counts.listenAddresses.push(address);
    },
    onReady: () => {
      counts.ready += 1;
    },
    onMcpRequest: () => {
      counts.mcpRequest += 1;
    },
    onRequestLog: (line: string) => {
      counts.requestLogs.push(line);
    },
    onDrainStep: (step: string) => {
      counts.drainSteps.push(step);
    },
    onDisposal: (what: string) => {
      counts.disposals.push(what);
    },
  };

  return {
    deps,
    observer,
    counts,
    lines,
    snapshot: () => JSON.parse(JSON.stringify(counts)) as CounterSnapshot,
  };
}

/**
 * Copy `source` without the wrapped fields.
 *
 * `readManifest` and `buildRegistry` are consumed by the wrappers above; if
 * they were spread over the top they would silently REPLACE the counter rather
 * than being called behind it, and every registry-build assertion would read
 * zero while the build still happened.
 */
function omit(source: RuntimeDeps, keys: readonly string[]): RuntimeDeps {
  const copy: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(source)) {
    if (keys.includes(key)) continue;
    copy[key] = value;
  }
  return copy as RuntimeDeps;
}

// ---------------------------------------------------------------------------
// The spawned child's wire format
// ---------------------------------------------------------------------------

/**
 * What `test/harness/serve-entry.ts` reads from `argv[2]`, as JSON.
 *
 * One JSON argument rather than an environment block, because the point of the
 * spawned harness is to inject `RuntimeDeps` — and the child's own
 * `process.env` is deliberately NOT the configuration source. A criterion that
 * needs a real signal AND injection AND an observed exit code in one run has no
 * other shape available on Node 20.
 */
export interface ServeEntryDescriptor {
  /** Becomes `RuntimeDeps.env`. Absent means an empty environment. */
  readonly env?: Readonly<Record<string, string>>;
  /**
   * Pass an observer to `main`. Default `true`.
   *
   * `false` is the inertness case: production passes no observer, and every
   * call site is optional-chained, so a child started this way must reach the
   * same state and emit no counter line.
   */
  readonly observer?: boolean;
  /** Emit the counter line. Default `true`; forced off when `observer` is false. */
  readonly counters?: boolean;
  /**
   * `hold` stays alive until killed or the watchdog fires — what a signal or a
   * connection-refused probe needs. `exit` drains and exits 0 once ready.
   */
  readonly after?: 'hold' | 'exit';
  /** Watchdog, so a leaked child cannot outlive the suite. Default 20 000 ms. */
  readonly holdMs?: number;
}

/**
 * The counter line's prefix.
 *
 * Deliberately NOT `unifi-mcp: `. That prefix belongs to the product's own
 * diagnostics, and a suite scanning the child's stderr for a startup warning
 * must not match the harness's bookkeeping instead.
 */
export const COUNTER_LINE_PREFIX = 'unifi-mcp-harness: counters ';

export function formatCounterLine(counts: CounterSnapshot): string {
  return `${COUNTER_LINE_PREFIX}${JSON.stringify(counts)}\n`;
}

/**
 * Parse the counter line out of a child's captured stderr.
 *
 * Returns `null` when no line is present — which is a meaningful answer, not a
 * failure: it is exactly what the inertness case asserts.
 */
export function parseCounterLine(stderr: string): CounterSnapshot | null {
  for (const line of stderr.split('\n')) {
    if (!line.startsWith(COUNTER_LINE_PREFIX)) continue;
    return JSON.parse(line.slice(COUNTER_LINE_PREFIX.length)) as CounterSnapshot;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Text-channel scanning, for a value that cannot be planted
// ---------------------------------------------------------------------------

/**
 * Assert that a CAPTURED value does not appear in any captured TEXT channel.
 *
 * This is deliberately NOT a second copy of the object-graph walker in
 * `test/fixtures/sentinel.ts`. That walker exists because `JSON.stringify`
 * drops `Map`, `Set`, non-enumerable properties and `Buffer` bytes, and it
 * hunts values that were PLANTED — so it can key on a fixed table of sentinels
 * and on their shared shape.
 *
 * Some values cannot be planted. FR-77 requires the session identifier to come
 * from this server's own CSPRNG, so a test can only CAPTURE the emitted
 * `Mcp-Session-Id` and then look for that captured value. And the channels it
 * has to be absent from — stderr lines, per-request log lines, raw response
 * bytes read off a socket — are already text. An object walk over a string is
 * a string search, so this is the smaller instrument, not a competing one. Use
 * the walker for tool results, errors and the live `ServerConfig`; use this for
 * anything already flattened to text.
 *
 * The failure message NEVER echoes the value. A CI log is a text channel too,
 * and a leak assertion that prints the leaked secret to prove it leaked has
 * merely moved the leak somewhere more durable.
 */
export function assertAbsentFromText(
  channels: Readonly<Record<string, string | readonly string[]>>,
  value: string,
  label: string,
): void {
  if (value === '') {
    throw new Error(
      `assertAbsentFromText was asked to hunt an empty ${label}, which every channel trivially ` +
        `contains and no channel meaningfully leaks. Capture the value first.`,
    );
  }

  const hits: string[] = [];
  for (const [channel, content] of Object.entries(channels)) {
    const parts = typeof content === 'string' ? [content] : content;
    parts.forEach((part, index) => {
      if (!part.includes(value)) return;
      hits.push(typeof content === 'string' ? channel : `${channel}[${index}]`);
    });
  }

  if (hits.length > 0) {
    throw new Error(
      `the captured ${label} reached ${hits.length} output location(s): ${hits.join(', ')}. ` +
        `Its value is deliberately not reproduced here — a failure message is an output channel ` +
        `too, and printing it would move the leak into the CI log.`,
    );
  }
}
