/**
 * The once-per-process object graph (architecture §1.1, §1.2).
 *
 * Everything that used to live inline in `main()` between `src/index.ts:92` and
 * `:160` lives here now, split into two lifetimes:
 *
 *   `buildRuntimeCore()`  — SYNCHRONOUS, and everything in it must precede the
 *                           bind: bearer slots, configuration, all of FR-73's
 *                           refusals, FR-81's floor, FR-78's delivery refusals,
 *                           the credential capture, the outbound client and the
 *                           environment scrub.
 *   `resolveRegistry()`   — ASYNCHRONOUS, and it runs AFTER the bind: manifest,
 *                           registry, the per-surface advertised tool sets,
 *                           then `ready` settles.
 *
 * The split at the registry boundary is forced by FR-62's fixed order —
 * "validation and the startup refusals run first; the listener binds second;
 * the action registry and promoted tools resolve third" — and by operator
 * contract §5.15, which answers a request arriving before the registry resolves
 * with `503 unavailable` rather than a connection refusal. Building the
 * registry before the bind would give the `starting` readiness phase zero
 * duration and hand an orchestrator `ECONNREFUSED` for the whole startup
 * window.
 *
 * ## Why the client and the credential store are shared, and the McpServer is not
 *
 * `Protocol.connect` throws on a second transport — "use a separate Protocol
 * instance per connection" (`shared/protocol.js:217`) — so ONE `McpServer` per
 * session is forced, not chosen. The outbound `UnifiClient` is shared for the
 * opposite reason, and it is correctness rather than convenience: the rate-limit
 * buckets model a limit the UniFi console enforces per console, so N sessions
 * with N clients would present N x the permitted rate to the operator's console
 * and manufacture exactly the self-inflicted 429s the limiter exists to prevent
 * (FR-72, NFR-15, NFR-26).
 *
 * ## Diagnostics
 *
 * Nothing in this module writes to a stream. Every line goes through
 * `log.ts`'s emitter, which owns the `unifi-mcp: ` prefix and the sanitisation,
 * and which is the only module under `src/serve/` permitted to hold a direct
 * write to the standard error stream (architecture §9.4). That rule is a text
 * scan, so this comment states the name of the forbidden call in prose rather
 * than spelling it — the scan cannot tell a mention from a use, and neither
 * should it have to.
 */
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  loadConfig,
  redactedSummary,
  validateConfig,
  type ConfigValidation,
  type LocalConsole,
  type ServerConfig,
  type ServingTransport,
} from '../config.js';
import {
  captureCredentialEnv,
  scrubCredentialEnv,
  CredentialStore,
  type CredentialStoreOptions,
} from '../credentials.js';
import { UnifiClient, type UnifiClientOptions } from '../http/client.js';
// The §0.1.1 loopback predicate, taken from the shared leaf `src/config.ts` and
// `src/serve/guard.ts` both already use rather than re-implemented here. It
// widens §9.4's declared import list for this module by one dependency-free
// leaf and introduces no edge inside `src/serve/`; the alternative — a third
// copy of an address predicate — is the drift hazard this round already paid
// for once with `bearerMatches`.
import { isLoopbackBind } from '../netliteral.js';
import {
  buildRegistry,
  type RegistryBuildResult,
  type SpecManifest,
} from '../registry/build.js';
import {
  advertisedTools,
  createHandlers,
  type HandlerContext,
  type ToolDefinition,
  type ToolResult,
} from '../tools/index.js';
import type { Action, ServiceId } from '../types.js';

import { resolveBearerSlots, INBOUND_SECRET_ENV_KEYS, type AuthMode } from './auth.js';
import { createDiagnosticLogger, LOG_PREFIX, renderBindAddress } from './log.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * Architecture §3.2 step 2a: the pre-drain hold, a fixed constant rather than a
 * variable because FR-63 closes the family.
 *
 * US-24 owns the hold itself. US-20 needs only the NUMBER, for the cross-field
 * budget warning below, and it is exported so the drain reads this one rather
 * than declaring a second copy of the same constant.
 */
export const PREDRAIN_HOLD_MS = 5_000;

/** Architecture §3.4's stated margin in `predrain + connector + 1 000 > deadline`. */
const SHUTDOWN_BUDGET_MARGIN_MS = 1_000;

/** Inbound serving surface. Distinct from `TransportMode`, which is outbound. */
export type Surface = ServingTransport;

/** Why a drain was started. Widened by US-19 and US-24 as they land. */
export type DrainReason = 'signal' | 'startup-failure' | 'crash' | 'disposal';

/** One tool handler, as `createHandlers` produces them. */
export type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;

/**
 * A startup refusal, raised rather than exited.
 *
 * `validateConfig` is a pure validator, and exiting the process inline from the
 * startup path would make FR-73's non-bypassability criterion vacuous: a test
 * cannot read the `listen` invocation counter at `0` in a process that has
 * already gone. Raising a typed error lets the refusal be asserted in-process
 * AND lets `src/index.ts`'s auto-run guard remain the only `process.exit` in
 * `src/` (architecture §10.2).
 */
export class ConfigRefusal extends Error {
  readonly errors: readonly string[];

  constructor(errors: readonly string[]) {
    super(errors.join(' | ') || 'configuration refused');
    this.name = 'ConfigRefusal';
    this.errors = errors;
  }
}

/**
 * Thrown by `advertisedToolsFor` before the registry has resolved.
 *
 * This is what makes the `starting` window a real state rather than a race: a
 * request arriving in it is answered `503 unavailable` rather than by touching
 * a half-built registry.
 */
export class RuntimeNotReady extends Error {
  constructor() {
    super('the action registry has not resolved yet');
    this.name = 'RuntimeNotReady';
  }
}

/**
 * One injection point for everything the runtime constructs (architecture
 * §10.1).
 *
 * Node 20 has no `mock.module` — it landed in 22.3 and CI pins 20 on all three
 * platforms — so every seam in this round is either an injected dependency or a
 * default parameter. Each field below defaults to the real implementation and
 * every one of them is inert in production.
 */
export interface RuntimeDeps {
  /**
   * Configuration source. Defaults to `process.env`.
   *
   * NORMATIVE (architecture §1.4, §10.1): FR-78's capture-then-delete scrub
   * deletes from THIS object, never unconditionally from `process.env`. A
   * runtime built with an injected env leaves `process.env` untouched, which is
   * what lets three write-gate parity fixtures live in one file without the
   * first one poisoning the second.
   */
  env?: NodeJS.ProcessEnv;
  /** FR-68/FR-69/NFR-25's "startup artifact check" counter. */
  readManifest?: () => SpecManifest;
  /**
   * The registry-build counter, and the `starting`-window barrier.
   *
   * Typed to permit a promise so a test can inject a build that awaits a
   * barrier it controls and observe `/healthz` 200 alongside `/readyz` 503
   * `starting` in one run. Production `buildRegistry` stays synchronous.
   * `src/registry/build.ts` has no options object and is inside the
   * diff-scope invariant: count the call, not the callee.
   */
  buildRegistry?: (
    repoRoot: string,
    manifest: SpecManifest,
    enabledServices: ReadonlySet<ServiceId>,
  ) => RegistryBuildResult | Promise<RegistryBuildResult>;
  createCredentialStore?: (config: ServerConfig, options: CredentialStoreOptions) => CredentialStore;
  createClient?: (
    config: ServerConfig,
    credentials: CredentialStore,
    options: UnifiClientOptions,
  ) => UnifiClient;
  /** The `*_FILE` read seam, shared by the bearer resolver and the capture. */
  readSecretFile?: (path: string) => Buffer;
  /**
   * Receives each composed diagnostic line — prefix applied, sanitised, exactly
   * as it would reach stderr. Substitutes for the stream, never for the
   * composer, so an in-process test reads the real line rather than patching
   * the process-global stream.
   */
  warn?: (line: string) => void;
  now?: () => number;
  /**
   * FR-80's platform scope, read once for the Windows startup warning.
   *
   * A default parameter rather than a patch of `process.platform`, so the
   * assertion is portable: the `windows-latest` leg exercises the production
   * default and the other two legs still assert the text and its absence. Node
   * 20 has no `mock.module`, so this is the only seam shape available.
   */
  platform?: NodeJS.Platform;
  /**
   * The bound listener's address, read AFTER the bind and used only for the
   * serving line.
   *
   * FR-63 requires `UNIFI_HTTP_PORT=0` to report the OS-assigned port, and that
   * number exists only once `listen` has resolved. `resolveRegistry` runs after
   * the bind (FR-62's third step), so US-22 supplies this there —
   * `resolveRegistry(core, { listenAddress: () => httpServer.address() })` —
   * and nothing here imports or constructs a server. Absent, the serving line
   * falls back to the CONFIGURED bind and port, which is exact for every fixed
   * port and is what the in-process tests assert against.
   */
  listenAddress?: () => AddressInfo | null;
}

/** What `createMcpServer` and every per-session path receives. */
export interface Runtime {
  readonly config: ServerConfig;
  readonly credentials: CredentialStore;
  readonly client: UnifiClient;
  readonly handlers: Record<string, ToolHandler>;
  /** The bearer digests. NEVER on `ServerConfig` (FR-64). */
  readonly auth: AuthMode;
  readonly activeSurface: Surface;
  /** Settles when the registry resolved. NEVER rejects; faults land on `readyError`. */
  readonly ready: Promise<void>;
  readonly readyError: Error | null;
  /** `null` until `ready` settles. */
  readonly registry: RegistryBuildResult | null;
  /** Throws `RuntimeNotReady` before `ready` settles. */
  advertisedToolsFor(surface: Surface): readonly ToolDefinition[];
}

/**
 * Process-scoped teardown. Held ONLY by `index.ts` and the `Serving` handle.
 *
 * The two types are one object and the split is not decoration: `terminateSession`
 * is *about* closing things, so a per-session cleanup path calling
 * `runtime.close()` is a natural mistake — and it would destroy the shared
 * agents, close the limiter and take down every other session. `createMcpServer`
 * receives `Runtime` and cannot reach either method.
 */
export interface RuntimeLifecycle extends Runtime {
  beginDrain(): void;
  close(): Promise<void>;
}

export type RuntimeCore = RuntimeLifecycle;

/**
 * The transport counters (architecture §10.2). `undefined` in production; every
 * call site is `observer?.onX?.()`.
 */
export interface ServingObserver {
  onTransportActivated?(kind: Surface): void;
  onListen?(address: AddressInfo): void;
  onReady?(): void;
  onMcpRequest?(): void;
  onRequestLog?(line: string): void;
  onDrainStep?(step: string): void;
  onDisposal?(what: 'limiter' | 'client' | 'agents'): void;
}

/**
 * Transport-side injection.
 *
 * `exit` and `setExitCode` are declared here and used by US-19 and US-24: drain
 * step 10 calls them and never touches `process.*` directly, because an
 * un-ref'd deadline timer arming a real exit-75 call inside a test runner
 * kills the suite mid-file.
 *
 * US-22 needs two more fields — `createTransport` and `createHttpServer` — whose
 * types come from the SDK's Streamable HTTP transport. They are deliberately
 * NOT declared here: importing those types would put the HTTP transport into
 * `runtime.ts`'s import list, which §9.4 fixes as
 * `{ auth, config, credentials, http/client, registry, tools, log }`. US-22
 * declares `interface HttpServingDeps extends ServingDeps` in `src/serve/http.ts`.
 */
export interface ServingDeps {
  exit?: (code: number) => never | void;
  setExitCode?: (code: number) => void;
  now?: () => number;
}

/** The handle both serving transports return. */
export interface Serving {
  readonly kind: Surface;
  /** `null` for stdio, which binds nothing. */
  readonly address: AddressInfo | null;
  /**
   * Idempotent. US-19 (stdio) and US-24 (HTTP) own the ordered drain — the
   * not-ready mark, the in-flight wait, the deadline and the exit-code
   * vocabulary. What exists today is the teardown those steps wrap.
   */
  drain(reason: DrainReason): Promise<'clean' | 'deadline'>;
  /** Teardown only. Never touches `process.exitCode` and never calls `process.exit`. */
  dispose(): Promise<void>;
}

/**
 * Per-core state that is NOT reachable from a `Runtime` reference.
 *
 * A `WeakMap` rather than fields on the object, for the same reason
 * `RuntimeLifecycle` is a separate type: what per-session code cannot name, it
 * cannot call.
 */
interface RuntimeInternals {
  readonly deps: RuntimeDeps;
  /** Untrusted: relayed collaborator lines, registry warnings, caught errors. */
  readonly warn: (message: string) => void;
  /** Trusted: lines this process composed from values it resolved itself. */
  readonly announce: (message: string) => void;
  readonly handlerContext: HandlerContext;
  registry: RegistryBuildResult | null;
  toolsBySurface: { readonly stdio: readonly ToolDefinition[]; readonly http: readonly ToolDefinition[] } | null;
  readyError: Error | null;
  settle: () => void;
  resolving: Promise<void> | null;
  closed: boolean;
}

const internals = new WeakMap<Runtime, RuntimeInternals>();

function internalsOf(core: Runtime): RuntimeInternals {
  const found = internals.get(core);
  if (!found) throw new Error('runtime internals are unavailable for this object');
  return found;
}

/**
 * The ordered startup sequence, synchronous, before anything binds.
 *
 * The order below is normative and every step of it closes a specific failure:
 *
 *  1. `resolveBearerSlots` runs BEFORE `loadConfig` so that the digests exist
 *     and the secret-free descriptor can be validated by `validateConfig` — the
 *     only way FR-73's five refusals, FR-81's floor and FR-78's three delivery
 *     refusals can all be evaluated in one place with the `listen` counter at 0,
 *     whether the secret came from the environment or from a file.
 *  2-3. Load, then validate. A refusal raises `ConfigRefusal` here.
 *  4. CAPTURE the credential-bearing variables into a private object.
 *  5. Construct the store over `capture.env` — NOT `process.env`.
 *  6. SCRUB both credential classes from the environment we were handed.
 *  7. Render the capture's problems as fatal and its warnings to stderr.
 *
 * Steps 4-7 are the wiring US-16 built and could not call: it shipped
 * `captureCredentialEnv` and `scrubCredentialEnv` fully tested with no call
 * site, because the call site is this function and this function did not exist
 * until now. The ORDER is the whole requirement. `CredentialStore` holds a LIVE
 * reference to the env object it was given and resolves lazily on first use, so
 * scrubbing before the store is constructed — or constructing the store over
 * the scrubbed environment — produces a server that starts clean, reports
 * ready, and throws `No cloud API key is configured` on the operator's first
 * tool call behind a green startup log (FR-78, NFR-31).
 */
export function buildRuntimeCore(deps: RuntimeDeps = {}): RuntimeCore {
  const env = deps.env ?? process.env;
  const readSecretFile = deps.readSecretFile ?? readFileSync;
  const logger = createDiagnosticLogger(deps.warn ? { write: deps.warn } : {});
  const warn = (message: string): void => logger.emitDiagnostic(message);
  // The startup announcement and the ordered warnings are TRUSTED text: this
  // process composed every one of them from configuration it resolved itself,
  // so the injection defences apply and `sanitizeUntrusted`'s 512-character
  // ceiling — which exists for device-supplied names — does not. Before this,
  // the `ready` line's ~1.2 kB `redactedSummary` was cut off mid-JSON.
  const announce = (message: string): void => logger.emitTrusted(message);
  // `CredentialStore` and `UnifiClient` predate `log.ts` and compose their own
  // `unifi-mcp: ` prefix. `emitDiagnostic` owns the prefix now, so their lines
  // are handed over with it removed rather than emitted twice over.
  //
  // US-18 asked whether US-20 should collapse this. KEPT, deliberately.
  // Collapsing it means deleting the prefix from the two collaborators, and
  // both `src/credentials.ts` and `src/http/client.ts` are outside this story's
  // file scope — `src/credentials.ts` additionally sits under the FR-78 argv
  // and sentinel scans. Removing the strip without removing the composers
  // double-prefixes every relayed line; removing both is a two-file change in
  // files this wave does not own, and it buys one branch. It stays here, where
  // it is three lines and where `emitDiagnostic` remains the single owner of
  // the prefix in fact as well as in principle. Note also that this path is
  // UNTRUSTED on purpose: a relayed line can interpolate an API error message
  // or a device-supplied name, so the 512-character ceiling belongs on it.
  const relay = (line: string): void =>
    warn(line.startsWith(LOG_PREFIX) ? line.slice(LOG_PREFIX.length) : line);

  // 1. The inbound secret's whole lifecycle, before anything else reads config.
  const bearer = resolveBearerSlots(env, readSecretFile);

  // 2. The descriptor carries no secret material, so it is safe on ServerConfig.
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: bearer.descriptor });

  // 3. FR-54: fail rather than serve a half-configured surface, and name the
  // offending setting so the fix is obvious without reading the source.
  // NOTHING IS EMITTED HERE. A refused start prints its refusals and no
  // warnings at all, matching the pre-split behaviour the story cites at
  // `src/index.ts:99-105`: advice about a configuration that is not going to
  // run buries the refusal that has to be acted on. Every warning this
  // validation produced is held and emitted at the foot of this function, once
  // both refusal points below have been passed.
  const validation = validateConfig(config, env);
  if (!validation.ok) throw new ConfigRefusal(validation.errors);
  // `resolveBearerSlots` returns `auth: null` exactly when the descriptor
  // carries problems — including the ordinary case of a stdio deployment with
  // no inbound secret configured at all, where `UNIFI_HTTP_AUTH` defaults to
  // `bearer` fail-closed and resolves nothing. On stdio that is not a fault:
  // IG-1 requires that a leftover or absent inbound secret never stop a stdio
  // server, which binds no port and admits no inbound caller. On HTTP the same
  // problems are already fatal — `validateConfig` pushes every one of
  // `serving.auth.problems` onto its errors — so the refusal above has thrown
  // and this branch is unreachable there. It is written as a refusal anyway so
  // that if that coupling is ever broken the runtime fails CLOSED rather than
  // serving an HTTP listener with no comparator behind it.
  const auth: AuthMode = bearer.auth ?? resolveAbsentAuth(config, bearer.descriptor.problems);

  // 4. CAPTURE — before anything is deleted.
  const capture = captureCredentialEnv(config, env, readSecretFile);

  // 5. The store reads `capture.env`, which the scrub below never touches.
  const createStore = deps.createCredentialStore ?? defaultCreateCredentialStore;
  const credentials = createStore(config, { env: capture.env, warn: relay });
  const createClient = deps.createClient ?? defaultCreateClient;
  const client = createClient(config, credentials, { warn: relay });

  // 6. SCRUB. Both credential classes: the UniFi accounts and their `*_FILE`
  // siblings, and the four inbound-secret variables, whose digests were taken
  // at step 1. The environment is not a private channel — `/proc/self/environ`
  // is readable by any process of the same uid and `docker inspect` prints `-e`
  // values in cleartext (NFR-31).
  scrubCredentialEnv(env, [...capture.variables, ...INBOUND_SECRET_ENV_KEYS]);

  // 7. The capture's problems are FATAL rather than lazy-path diagnostics: an
  // unreadable, empty or over-4-KiB credential file must stop startup before
  // the bind, not surface as a failed tool call an hour later (FR-78). They are
  // raised HERE, in the capture's own step, so the scrub above has still run.
  //
  // Its WARNINGS are no longer emitted here. The `*_FILE` mode warning is the
  // fourth member of §3.5's ordered sequence, so it is emitted with the rest of
  // that sequence at step 8 — and after this refusal, because a refused start
  // emits no warnings at all. Only the EMISSION moved; the
  // capture-then-construct-then-scrub order this step belongs to is untouched,
  // which is the part that is load-bearing.
  if (capture.problems.length > 0) throw new ConfigRefusal(capture.problems);

  // 8. The ordered startup warnings (contract §3.5), before the bind and after
  // every refusal. FR-79's routability warning in particular describes OUTBOUND
  // reachability and is worth more to an operator before the listener exists
  // than after the registry resolves.
  for (const line of collectStartupWarnings(config, validation, capture.warnings, deps)) {
    announce(line);
  }

  // The registry is not built yet, so the handler context starts empty and
  // `resolveRegistry` fills it. Every handler reads `ctx.actions` and
  // `ctx.byId` at CALL time, never at construction time, so this is a
  // deferred read and not a stale capture.
  const handlerContext: HandlerContext = {
    config,
    client,
    actions: [] as Action[],
    byId: new Map<string, Action>(),
  };
  const handlers = createHandlers(handlerContext) as Record<string, ToolHandler>;

  let settle = (): void => {};
  const ready = new Promise<void>((resolve) => {
    settle = resolve;
  });

  const core: RuntimeCore = {
    config,
    credentials,
    client,
    handlers,
    auth,
    activeSurface: config.activeSurface,
    ready,
    get readyError(): Error | null {
      return internalsOf(core).readyError;
    },
    get registry(): RegistryBuildResult | null {
      return internalsOf(core).registry;
    },
    advertisedToolsFor(surface: Surface): readonly ToolDefinition[] {
      const sets = internalsOf(core).toolsBySurface;
      if (sets === null) throw new RuntimeNotReady();
      return sets[surface];
    },
    beginDrain(): void {
      client.beginDrain();
    },
    async close(): Promise<void> {
      const state = internalsOf(core);
      if (state.closed) return;
      state.closed = true;
      await client.close();
    },
  };

  internals.set(core, {
    deps,
    warn,
    announce,
    handlerContext,
    registry: null,
    toolsBySurface: null,
    readyError: null,
    settle,
    resolving: null,
    closed: false,
  });

  return core;
}

/**
 * The rest, asynchronous, AFTER the listener has bound (FR-62's third step).
 *
 * Idempotent: the second call returns the first call's promise, so the registry
 * is built exactly once per process regardless of how many sessions are served.
 * That count is asserted at this call site rather than inside
 * `src/registry/build.ts`, which has no injection seam and which the diff-scope
 * invariant forbids this round from touching.
 *
 * NEVER rejects. A fault lands on `readyError` and settles `ready`, so a
 * registry failure becomes a drain the transport can act on rather than a
 * floating rejection and a process that answers `503 starting` forever.
 */
export function resolveRegistry(core: RuntimeCore, deps: RuntimeDeps = {}): Promise<void> {
  const state = internalsOf(core);
  if (state.resolving !== null) return state.resolving;

  const merged: RuntimeDeps = { ...state.deps, ...deps };
  state.resolving = (async () => {
    try {
      const readManifest = merged.readManifest ?? defaultReadManifest;
      const build = merged.buildRegistry ?? buildRegistry;
      const registry = await build(REPO_ROOT, readManifest(), core.config.enabledServices);

      // NFR-17: the registry is built from files on disk. No network call
      // happens before `tools/list` can be answered.
      for (const message of registry.warnings) state.warn(message);

      state.handlerContext.actions = registry.actions;
      state.handlerContext.byId = registry.byId;
      state.registry = registry;
      state.toolsBySurface = precomputeAdvertisedTools(core.config);
      // Read AFTER the registry resolved, which is after the bind, so the
      // OS-assigned port of `UNIFI_HTTP_PORT=0` is available (FR-63).
      announceStartup(core, state, merged.listenAddress?.() ?? null);
    } catch (error) {
      state.readyError = error instanceof Error ? error : new Error(String(error));
      state.warn(`ERROR the action registry failed to resolve — ${state.readyError.message}`);
    } finally {
      state.settle();
    }
  })();

  return state.resolving;
}

/**
 * The advertised tool set for each surface, computed once.
 *
 * FR-71 classification `pass-through`: this READS the resolved write set and
 * hands it to the tool builder, and the tool builder owns the one advertisement
 * decision. Nothing here branches on the set to permit or deny, which is why
 * `src/serve/` carries no `enforcement` site in the FR-71 inventory.
 */
function precomputeAdvertisedTools(config: ServerConfig): {
  readonly stdio: readonly ToolDefinition[];
  readonly http: readonly ToolDefinition[];
} {
  return {
    stdio: advertisedTools(config.enabledServices, config.writesEnabledBySurface.stdio),
    http: advertisedTools(config.enabledServices, config.writesEnabledBySurface.http),
  };
}

// ---------------------------------------------------------------------------
// The startup announcement (US-20; operator contract §3.1-§3.7)
//
// Every string below is the contract's, not this module's invention, and every
// one of them is emitted through `log.ts` — the single emitter. Nothing here
// writes to a stream, and the whole block is TRUSTED text: it is composed from
// configuration this process resolved itself, so it carries the injection
// defences and not the device-name length ceiling (see `sanitizeTrusted`).
// ---------------------------------------------------------------------------

/**
 * §3.5's severity word.
 *
 * The pre-existing warnings (`src/config.ts`'s insecure-TLS and
 * enabled-without-credentials lines) carry none, and keep none; the six added
 * by the serving transport all do, because they now compete with a per-request
 * log stream the stdio shape never had.
 */
const WARNING_PREFIX = 'WARNING ';

/** §3.1, verbatim. The banner as it stood at `src/index.ts:156-157` pre-split. */
const READ_ONLY_BANNER = 'read-only (writes are off; set UNIFI_ENABLE_WRITES to change that).';

/**
 * The opening clause §3.3.1 and §3.3.2 share, and the key this module uses to
 * lift the write pair out of `validateConfig`'s flat warning list.
 *
 * `src/config.ts` composes both lines and is not this story's file, so the pair
 * arrives already interleaved with the other validation warnings and has to be
 * recognised to be ordered last. Keying on the upper-case opening is keying on
 * the interface: the contract fixes those words, states that the upper case is
 * the point, and `test/serve-config.test.ts:1228` already classifies them the
 * same way.
 */
const WRITE_GATE_WARNING_PREFIX = 'WARNING WRITES';

/** The two probe routes, spelled as §3.1 spells them in the line itself. */
const HEALTHZ_PROBE_PATH = '/healthz';
const READYZ_PROBE_PATH = '/readyz';

/**
 * §3.6, the plaintext-transport warning. Names NO variable, deliberately: the
 * remedy is architectural rather than configuration, so FR-73's
 * name-the-variable obligation does not apply and there is no opt-out to copy.
 */
function plaintextWarning(address: string): string {
  return (
    `${WARNING_PREFIX}this listener speaks plaintext HTTP on ${address}. The shared secret and ` +
    `every MCP request and response cross the network unencrypted, and anyone on the path can ` +
    `read them. Terminate TLS in front of this process — an ingress, a service mesh, or a ` +
    `reverse proxy — and do not expose this port directly.`
  );
}

/** §3.2, the `auth=none` warning: bind, port, and the re-enabling variables. */
function authNoneWarning(address: string): string {
  return (
    `${WARNING_PREFIX}UNIFI_HTTP_AUTH=none — this listener at ${address} accepts unauthenticated ` +
    `MCP requests and will drive your UniFi estate for anyone who can reach it. Set ` +
    `UNIFI_HTTP_AUTH=bearer and UNIFI_HTTP_TOKEN to require a secret.`
  );
}

/**
 * §3.4, the routability warning. The last sentence is not decoration: FR-79's
 * second criterion forbids making readiness depend on routability, so naming
 * the non-dependency here is cheaper than an operator suspecting the probe.
 */
function routabilityWarning(consoles: readonly LocalConsole[]): string {
  // Named `entry` and not `console`: `.` after that identifier is exactly what
  // the D-14 single-emitter scan looks for, and a local variable would trip it.
  const hosts = [...new Set(consoles.map((entry) => entry.host))].join(', ');
  return (
    `${WARNING_PREFIX}local-direct consoles ${hosts} must be routable from this process's ` +
    `network namespace. A container in a cluster with no route to them will advertise the full ` +
    `Network and Protect surface and fail every call at connect time. Readiness does not check ` +
    `this — ${READYZ_PROBE_PATH} returns 200 regardless (NFR-25).`
  );
}

/**
 * FR-80 / NFR-27's platform scope, said to the operator rather than only to the
 * reader of ADR-05. Permanent operator-facing text, not a placeholder: OQ-18 is
 * resolved and no alternative Windows shutdown trigger is being built.
 */
function windowsPlatformWarning(): string {
  return (
    `${WARNING_PREFIX}graceful shutdown is unavailable on this platform. SIGTERM and SIGINT ` +
    `handlers register but never fire, so an HTTP deployment here has no drain, no terminal ` +
    `frame and no bounded exit. Windows is a supported development and stdio platform and is ` +
    `not a supported HTTP deployment target (ADR-05).`
  );
}

/**
 * Architecture §3.4's cross-field check, and a WARNING rather than a sixth
 * refusal: FR-73 fixes the refusal set at five and its criteria count them.
 *
 * `UNIFI_CONNECTOR_TIMEOUT_MS` has no ceiling, so raising it for a slow local
 * console — an entirely reasonable act — silently guarantees that every drain
 * with one in-flight request hard-stops at exit 75, for a reason FR-70's own
 * budget derivation says contributes zero.
 */
function shutdownBudgetWarning(config: ServerConfig): string | null {
  const connector = config.connectorTimeoutMs;
  const deadline = config.serving.shutdownDeadlineMs;
  const needed = PREDRAIN_HOLD_MS + connector + SHUTDOWN_BUDGET_MARGIN_MS;
  if (needed <= deadline) return null;
  return (
    `${WARNING_PREFIX}UNIFI_CONNECTOR_TIMEOUT_MS=${connector} leaves no room in the shutdown ` +
    `budget: the ${PREDRAIN_HOLD_MS} ms pre-drain hold plus the connector timeout plus ` +
    `${SHUTDOWN_BUDGET_MARGIN_MS} ms is ${needed} ms, and ` +
    `UNIFI_HTTP_SHUTDOWN_DEADLINE_MS=${deadline}. Every drain with a request still in flight ` +
    `will run out of budget and hard-stop. Lower UNIFI_CONNECTOR_TIMEOUT_MS or raise ` +
    `UNIFI_HTTP_SHUTDOWN_DEADLINE_MS.`
  );
}

/**
 * The whole startup warning stream, in emission order.
 *
 * §3.5 fixes the order of the five and states why: the two that describe HOW
 * EXPOSED this listener is come before the two that describe WHAT IT CAN DO,
 * because an operator who reads only the first line should read the most
 * consequential one. It is a decision rather than a requirement, and it is
 * asserted, which is what makes it an interface rather than an accident.
 *
 *   0. the pre-existing `src/config.ts` warnings, unchanged and unprefixed
 *   0. the two platform/lifecycle scopes: Windows, then the shutdown budget
 *   1. §3.6  plaintext transport
 *   2. §3.2  auth=none
 *   3. §3.4  routability
 *   4. §3.7  `*_FILE` mode
 *   5. §3.3  the write pair
 *
 * The Windows warning is deliberately OUTSIDE the ordered five — the test
 * strategy's A-W asserts it "separately" — and leads, because it says the whole
 * deployment shape is unsupported, which dominates anything the five report.
 */
function collectStartupWarnings(
  config: ServerConfig,
  validation: ConfigValidation,
  captureWarnings: readonly string[],
  deps: RuntimeDeps,
): string[] {
  const serving = config.serving;
  const http = config.activeSurface === 'http';
  const address = renderBindAddress(serving.bindAddress ?? serving.bind, serving.port);
  const routableBind = http && serving.bindAddress !== null && !isLoopbackBind(serving.bindAddress);

  // `validateConfig` returns one flat list holding three different populations.
  // The inbound `*_FILE` mode warnings are identified by identity against the
  // descriptor that produced them rather than by their text; the write pair by
  // its fixed opening; everything else is pre-existing and keeps its position.
  const inboundFileWarnings = new Set<string>(serving.auth.warnings);
  const general: string[] = [];
  const fileMode: string[] = [];
  const writePair: string[] = [];
  for (const message of validation.warnings) {
    if (message.startsWith(WRITE_GATE_WARNING_PREFIX)) writePair.push(message);
    else if (inboundFileWarnings.has(message)) fileMode.push(message);
    else general.push(message);
  }
  // The outbound half of §3.7. `captureCredentialEnv` produces only permissions
  // warnings, so this needs no partition of its own.
  fileMode.push(...captureWarnings);

  const lines = [...general];

  if (http && (deps.platform ?? process.platform) === 'win32') lines.push(windowsPlatformWarning());
  if (http) {
    const budget = shutdownBudgetWarning(config);
    if (budget !== null) lines.push(budget);
  }

  if (routableBind) lines.push(plaintextWarning(address));
  if (http && serving.authMode.kind === 'none') lines.push(authNoneWarning(address));
  if (routableBind && config.localConsoles.length > 0) {
    lines.push(routabilityWarning(config.localConsoles));
  }
  // §3.5's severity word, applied here because `src/serve/auth.ts` and
  // `src/credentials.ts` compose the §3.7 text and predate that decision; both
  // are outside this story's file scope, and prefixing at the one emission
  // point keeps the two composers identical to each other.
  for (const message of fileMode) lines.push(`${WARNING_PREFIX}${message}`);
  lines.push(...writePair);

  return lines;
}

/**
 * §3.1's serving line — one line, after the readiness flag flips, added AFTER
 * the `ready` line because the tool count and the redacted summary are what an
 * operator checks first and they are transport-independent.
 *
 * `{bind}` and `{port}` render per §0.1.4, so an IPv6 bind is bracketed and
 * `UNIFI_HTTP_BIND=::` produces `at [::]:8787/mcp` rather than `at :::8787/mcp`.
 * `{path}` is the NORMALISED path — what the router actually matches, not what
 * the operator typed. `{auth}` is the mode and never the secret, its length or
 * a prefix of it.
 */
function servingLine(config: ServerConfig, bound: AddressInfo | null): string {
  const serving = config.serving;
  const bind = bound?.address ?? serving.bindAddress ?? serving.bind;
  const port = bound?.port ?? serving.port;
  return (
    `serving MCP over ${serving.transport} at ${renderBindAddress(bind, port)}${serving.path} — ` +
    `auth ${serving.authMode.kind}, probes GET ${HEALTHZ_PROBE_PATH} and GET ` +
    `${READYZ_PROBE_PATH} (unauthenticated).`
  );
}

/**
 * True when FR-71's HTTP narrowing is what emptied the effective write set.
 *
 * An `observation` read: it decides what is REPORTED and never what is
 * advertised or sent, which is why `src/serve/` still carries no `enforcement`
 * site in the FR-71 inventory.
 */
function narrowedToEmpty(config: ServerConfig): boolean {
  if (config.activeSurface !== 'http') return false;
  const surfaces = config.writesEnabledBySurface;
  return surfaces.stdio.size > 0 && surfaces.http.size === 0;
}

/**
 * The write-state banner, and D-12's suppression at the banner's new home.
 *
 * After FR-71's intersection narrowing, `writesEnabled.size === 0` is true in
 * exactly §3.3.1's scenario as well as the ordinary read-only one — and in that
 * scenario the banner tells the operator the OPPOSITE of the truth, that
 * `UNIFI_ENABLE_WRITES` is the fix, when they have already set it and the other
 * gate is what is closed. So the banner is suppressed there and §3.3.1's
 * narrowing warning stands in its place: the two never appear together.
 *
 * On stdio, and on HTTP where `UNIFI_ENABLE_WRITES` is genuinely empty, the
 * banner is unchanged.
 */
function writeStateBanner(config: ServerConfig): string | null {
  const effective = config.writesEnabled;
  if (effective.size > 0) return `WRITES ENABLED for ${[...effective].join(', ')}.`;
  if (narrowedToEmpty(config)) return null;
  return READ_ONLY_BANNER;
}

/**
 * The startup announcement, relocated wholesale from `src/index.ts:151-160` by
 * US-18 and completed here.
 *
 * Emitted after the readiness flag flips, which is the observable FR-62 fixes —
 * `/readyz` cannot return anything until a request arrives and none may ever
 * come, so the flag is the event and the probe response is a consequence of it.
 * An operator seeing `ready` alongside a failing readiness probe therefore
 * knows the probe is not reaching the process.
 */
function announceStartup(
  core: RuntimeCore,
  state: RuntimeInternals,
  bound: AddressInfo | null,
): void {
  const config = core.config;
  const registry = state.registry;
  const tools = core.advertisedToolsFor(config.activeSurface);
  const summary = redactedSummary(config);

  state.announce(
    `ready — ${tools.length} tools, ${registry ? registry.actions.length : 0} actions across ` +
      `${config.enabledServices.size} API(s). ${JSON.stringify(summary)}`,
  );

  // stdio binds nothing and has no address, no auth mode and no probes, so it
  // gets no serving line. §3.1 is scoped to a successful HTTP start.
  if (config.activeSurface === 'http') state.announce(servingLine(config, bound));

  const banner = writeStateBanner(config);
  if (banner !== null) state.announce(banner);
}

/**
 * The inbound authentication mode for a process whose bearer slots did not
 * resolve. Reachable only off the HTTP transport; see the call site.
 */
function resolveAbsentAuth(config: ServerConfig, problems: readonly string[]): AuthMode {
  if (config.serving.transport === 'http') {
    throw new ConfigRefusal(
      problems.length > 0 ? problems : ['the inbound authentication mode could not be resolved'],
    );
  }
  return { kind: 'none' };
}

function defaultReadManifest(): SpecManifest {
  return JSON.parse(
    readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'),
  ) as SpecManifest;
}

function defaultCreateCredentialStore(
  config: ServerConfig,
  options: CredentialStoreOptions,
): CredentialStore {
  return new CredentialStore(config, options);
}

function defaultCreateClient(
  config: ServerConfig,
  credentials: CredentialStore,
  options: UnifiClientOptions,
): UnifiClient {
  return new UnifiClient(config, credentials, options);
}
