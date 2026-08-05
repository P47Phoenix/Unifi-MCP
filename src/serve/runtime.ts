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
import { createDiagnosticLogger, LOG_PREFIX } from './log.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

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
  readonly warn: (message: string) => void;
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
  // `CredentialStore` and `UnifiClient` predate `log.ts` and compose their own
  // `unifi-mcp: ` prefix. `emitDiagnostic` owns the prefix now, so their lines
  // are handed over with it removed rather than emitted twice over.
  const relay = (line: string): void =>
    warn(line.startsWith(LOG_PREFIX) ? line.slice(LOG_PREFIX.length) : line);

  // 1. The inbound secret's whole lifecycle, before anything else reads config.
  const bearer = resolveBearerSlots(env, readSecretFile);

  // 2. The descriptor carries no secret material, so it is safe on ServerConfig.
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: bearer.descriptor });

  // 3. FR-54: fail rather than serve a half-configured surface, and name the
  // offending setting so the fix is obvious without reading the source.
  const validation = validateConfig(config, env);
  for (const message of validation.warnings) warn(message);
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

  // 7. Only now are the capture's findings rendered, and the problems are FATAL
  // rather than lazy-path diagnostics: an unreadable, empty or over-4-KiB
  // credential file must stop startup before the bind, not surface as a failed
  // tool call an hour later (FR-78).
  for (const message of capture.warnings) warn(message);
  if (capture.problems.length > 0) throw new ConfigRefusal(capture.problems);

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
      announceStartup(core, state);
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

/**
 * The startup announcement, relocated wholesale from `src/index.ts:151-160`.
 *
 * It travels with the runtime so that US-20 can own the serving line, the five
 * warnings and the read-only-banner suppression at the banner's new home,
 * without opening `src/index.ts` — which US-19 rewrites in the same wave. Both
 * banners below are `observation` reads of the write set: they decide what is
 * REPORTED, never what is advertised or sent.
 *
 * KNOWN, AND IT BELONGS TO US-20. `emitDiagnostic` passes every message through
 * `sanitizeUntrusted`, whose 512-character ceiling exists for device-supplied
 * names — SSIDs, camera names, client hostnames — and not for a line the
 * process composed from its own resolved configuration. `redactedSummary` is
 * about 1.2 kB, so the ready line's tail is truncated where it previously was
 * not. The composition is unchanged here on purpose: the fix is a trusted-text
 * path in `src/serve/log.ts`, which this story does not own and US-20 does.
 */
function announceStartup(core: RuntimeCore, state: RuntimeInternals): void {
  const config = core.config;
  const registry = state.registry;
  const tools = core.advertisedToolsFor(config.activeSurface);
  const summary = redactedSummary(config);

  state.warn(
    `ready — ${tools.length} tools, ${registry ? registry.actions.length : 0} actions across ` +
      `${config.enabledServices.size} API(s). ${JSON.stringify(summary)}`,
  );
  if (config.writesEnabled.size === 0) {
    state.warn('read-only (writes are off; set UNIFI_ENABLE_WRITES to change that).');
  } else {
    state.warn(`WRITES ENABLED for ${[...config.writesEnabled].join(', ')}.`);
  }
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
