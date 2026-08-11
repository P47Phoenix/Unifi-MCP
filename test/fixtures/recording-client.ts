/**
 * A recording stand-in for `UnifiClient`, plus a driver that walks the whole
 * advertised tool surface through it.
 *
 * This is a test HELPER, not a test file. It lives under `test/fixtures/` on
 * purpose: `scripts/run-tests.mjs` discovers tests with a NON-recursive
 * `readdirSync('test')`, so nothing here is ever executed as a test suite.
 *
 * ## Why a recorder rather than a mock server
 *
 * FR-44's acceptance criterion is "no POST/PUT/PATCH/DELETE reaches any UniFi
 * API, asserted by an outbound-request interceptor". The only honest place to
 * intercept is the one seam every handler funnels through —
 * `ctx.client.request(action, args)` — because that is where the production
 * code commits to an HTTP verb. The verb is `action.method`, passed straight
 * through by `src/http/client.ts`; the client never chooses one. So recording
 * `action.method` here records exactly what would have gone on the wire.
 *
 * Nothing in this file opens a socket, builds a URL, or imports
 * `src/http/transport.js`. The service and path come off the `Action`.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ServerConfig } from '../../src/config.js';
import type { UnifiClient, UnifiResponse } from '../../src/http/client.js';
import { normalizeError } from '../../src/http/errors.js';
import { blockedDiscriminators, blocksEntireOperation } from '../../src/registry/blocklist.js';
import { buildRegistry, type SpecManifest } from '../../src/registry/build.js';
import { advertisedTools, type ToolDefinition } from '../../src/tools/definitions.js';
import { createHandlers, type ToolResult } from '../../src/tools/handlers.js';
import type { Action, ActionClass, HttpMethod, ServiceId } from '../../src/types.js';
import { UnifiError } from '../../src/types.js';

// ---------------------------------------------------------------------------
// The ledger
// ---------------------------------------------------------------------------

/** One attempted outbound request, attributed to the tool that caused it. */
export interface LedgerEntry {
  readonly tool: string;
  readonly method: HttpMethod;
  readonly service: ServiceId;
  readonly path: string;
  readonly actionId: string;
}

/** Human-readable form, so an assertion failure names the offending request. */
export function describeEntry(entry: LedgerEntry): string {
  return `${entry.tool} -> ${entry.method} ${entry.path} (${entry.service}, ${entry.actionId})`;
}

// ---------------------------------------------------------------------------
// Synthetic upstream bodies
// ---------------------------------------------------------------------------

/**
 * Each service's success envelope, shaped exactly as `normalizePage` expects.
 *
 * A body of the wrong shape would make every handler degrade to an empty page,
 * which would still pass a naive "no writes happened" assertion while proving
 * nothing about the read path. Realistic items also give the sentinel scan real
 * content to walk.
 */
function syntheticBody(service: ServiceId): unknown {
  switch (service) {
    case 'site-manager':
      return {
        data: [
          {
            id: 'host-7f3a91c4',
            type: 'console',
            ipAddress: '192.0.2.10',
            isBlocked: false,
            owner: true,
            name: 'Studio Gateway',
            hostId: 'host-7f3a91c4',
            permission: 'admin',
          },
          {
            id: 'host-2b8d40ff',
            type: 'console',
            ipAddress: '192.0.2.11',
            isBlocked: false,
            owner: false,
            name: 'Workshop Gateway',
            hostId: 'host-2b8d40ff',
            permission: 'readonly',
          },
        ],
        httpStatusCode: 200,
        traceId: 'trace-6d1f0a72',
      };

    case 'network':
      return {
        count: 3,
        data: [
          {
            id: 'dev-11a2',
            name: 'ap-studio-ceiling',
            model: 'U6-Pro',
            macAddress: '00:00:5e:00:53:01',
            ipAddress: '192.0.2.31',
            state: 'ONLINE',
            firmwareVersion: '6.6.65',
            type: 'WIRED',
            connectedAt: '2026-07-30T09:12:04Z',
          },
          {
            id: 'dev-11a3',
            name: 'sw-rack-24',
            model: 'USW-24-PoE',
            macAddress: '00:00:5e:00:53:02',
            ipAddress: '192.0.2.32',
            state: 'ONLINE',
            firmwareVersion: '6.6.65',
            type: 'WIRED',
            connectedAt: '2026-07-28T17:44:51Z',
          },
          {
            id: 'dev-11a4',
            name: 'laptop-arden',
            model: null,
            macAddress: '00:00:5e:00:53:03',
            ipAddress: '192.0.2.94',
            state: 'ONLINE',
            firmwareVersion: null,
            type: 'WIRELESS',
            connectedAt: '2026-08-01T07:02:19Z',
          },
        ],
        limit: 25,
        offset: 0,
        totalCount: 3,
      };

    case 'mobility':
      return {
        data: [
          { id: 'mob-8801', name: 'Field Tablet 01', state: 'ACTIVE' },
          { id: 'mob-8802', name: 'Field Tablet 02', state: 'SUSPENDED' },
        ],
        total: 2,
        offset: 0,
        limit: 200,
        httpStatusCode: 200,
        traceId: 'trace-c07b39e5',
      };

    // Protect answers with a bare top-level array and no paging of its own.
    case 'protect':
      return [
        {
          id: 'cam-4410',
          name: 'Front Door',
          type: 'UVC-G4-Doorbell',
          state: 'CONNECTED',
          isConnected: true,
          isRecording: true,
        },
        {
          id: 'cam-4411',
          name: 'Loading Bay',
          type: 'UVC-G5-Bullet',
          state: 'CONNECTED',
          isConnected: true,
          isRecording: false,
        },
      ];
  }
}

/**
 * Each service's failure envelope, in its own upstream dialect.
 *
 * Deliberately free of anything key-shaped: the point of the error-path sentinel
 * scan is that nothing the SERVER adds leaks a credential, so the upstream body
 * must not be the thing that plants one.
 */
const UPSTREAM_ERROR_BODIES: Readonly<Record<ServiceId, Record<string, unknown>>> = {
  'site-manager': {
    code: 'BAD_GATEWAY',
    message: 'The upstream console did not answer in time.',
    httpStatusCode: 503,
    traceId: 'trace-9f2c41d0',
  },
  network: {
    code: 'api.gateway.unavailable',
    message: 'The controller is restarting.',
    statusCode: 503,
    statusName: 'Service Unavailable',
    requestId: 'req-4a1b77e2',
  },
  protect: {
    name: 'ServiceUnavailable',
    error: 'The Protect application is not ready.',
  },
  mobility: {
    code: 'SERVICE_UNAVAILABLE',
    message: 'The Mobility gateway is unavailable.',
    httpStatusCode: 503,
    traceId: 'trace-77c0aa31',
  },
};

/**
 * Build the rejection through the production normalizer rather than hand-rolling
 * a `NormalizedError`, so the error path under test is the real one.
 */
function rejectionFor(action: Action): UnifiError {
  const headers = new Headers({ 'retry-after': '7' });
  return new UnifiError(
    normalizeError(action.service, 503, UPSTREAM_ERROR_BODIES[action.service], headers),
  );
}

// ---------------------------------------------------------------------------
// The recording client
// ---------------------------------------------------------------------------

export interface RecordingClientOptions {
  /** Reject the requests this selects, instead of answering them. */
  readonly shouldFail?: (entry: LedgerEntry) => boolean;
}

export interface RecordingClient {
  /** Passed to `createHandlers` in place of a real `UnifiClient`. */
  readonly client: UnifiClient;
  /** Every request attempted, in order. */
  readonly ledger: readonly LedgerEntry[];
  /** Called by the driver immediately before invoking a handler. */
  setCurrentTool(tool: string): void;
}

export function createRecordingClient(options: RecordingClientOptions = {}): RecordingClient {
  const ledger: LedgerEntry[] = [];
  let currentTool = '(no tool set)';

  const request = async (action: Action): Promise<UnifiResponse> => {
    const entry: LedgerEntry = {
      tool: currentTool,
      method: action.method,
      service: action.service,
      path: action.path,
      actionId: action.id,
    };
    ledger.push(entry);

    if (options.shouldFail?.(entry) === true) throw rejectionFor(action);

    return { status: 200, body: syntheticBody(action.service), headers: new Headers() };
  };

  // `UnifiClient` is a class with private fields, so a structurally identical
  // object is not assignable to it and no amount of interface extraction makes
  // it so. The cast is confined to this one line, and it is honest: `request`
  // is the only public method the class exposes and it is fully implemented
  // above with the same signature.
  const client = { request } as unknown as UnifiClient;

  return {
    client,
    ledger,
    setCurrentTool(tool: string): void {
      currentTool = tool;
    },
  };
}

// ---------------------------------------------------------------------------
// Choosing real actions to execute
// ---------------------------------------------------------------------------

/** True when neither the whole operation nor any variant of it is withheld. */
function isFullyExposed(action: Action): boolean {
  return (
    blocksEntireOperation(action.service, action.method, action.path) === undefined &&
    blockedDiscriminators(action.service, action.method, action.path).length === 0
  );
}

/** Wildcard proxy paths take a caller-supplied sub-path; a synthetic one is meaningless. */
function hasConcretePath(action: Action): boolean {
  return !action.path.includes('*');
}

/**
 * The first registry action of a given class that this server is willing to
 * expose. Chosen at run time rather than hard-coded, so a spec refresh that
 * renames an operation cannot leave the driver pointing at nothing.
 */
function pickAction(actions: readonly Action[], actionClass: ActionClass): Action {
  const chosen = actions.find(
    (action) =>
      action.actionClass === actionClass && isFullyExposed(action) && hasConcretePath(action),
  );
  if (!chosen) {
    throw new Error(
      `The registry offers no exposed ${actionClass} action, so the surface driver has nothing ` +
        `to execute. Either every ${actionClass} action is on the never-ship blocklist or the ` +
        `registry failed to build.`,
    );
  }
  return chosen;
}

/** Placeholder values for an action's required path placeholders. */
function pathParamsFor(action: Action): Record<string, string> {
  const params: Record<string, string> = {};
  for (const parameter of action.parameters) {
    if (parameter.location === 'path') params[parameter.name] = `synthetic-${parameter.name}`;
  }
  return params;
}

const SYNTHETIC_SITE_ID = 'site-4f2a9c10';

/**
 * Minimal valid arguments per tool.
 *
 * Written as an object literal with UNQUOTED identifier keys: a tool-name lookup
 * is legitimate, an array of tool-name string literals is not — it would be a
 * second, drifting copy of the surface that `advertisedTools` already defines.
 * Every advertised tool is checked against this map below, so a newly added tool
 * fails loudly rather than being silently skipped.
 */
function toolArguments(actions: readonly Action[]): Record<string, Record<string, unknown>> {
  const readAction = pickAction(actions, 'read');
  const writeAction = pickAction(actions, 'write');

  return {
    unifi_list_consoles: {},
    unifi_list_sites: {},
    unifi_list_devices: { site_id: SYNTHETIC_SITE_ID },
    unifi_list_clients: { site_id: SYNTHETIC_SITE_ID },
    unifi_list_cameras: {},
    unifi_search_actions: { query: 'which cameras are recording' },
    unifi_execute_action: {
      action_id: readAction.id,
      path_params: pathParamsFor(readAction),
    },
    unifi_execute_write_action: {
      action_id: writeAction.id,
      path_params: pathParamsFor(writeAction),
      body: { note: 'synthetic write payload' },
    },
  };
}

function assertEveryToolHasArguments(
  tools: readonly ToolDefinition[],
  args: Readonly<Record<string, Record<string, unknown>>>,
): void {
  const missing = tools
    .map((tool) => tool.name)
    .filter((name) => !Object.prototype.hasOwnProperty.call(args, name));

  if (missing.length > 0) {
    throw new Error(
      `The advertised tool surface contains ${missing.join(', ')}, for which the surface driver ` +
        `has no arguments. Add an entry to toolArguments() in ` +
        `test/fixtures/recording-client.ts — skipping the tool would make every assertion over ` +
        `the surface silently weaker.`,
    );
  }
}

// ---------------------------------------------------------------------------
// The surface driver
// ---------------------------------------------------------------------------

export interface SurfaceRunOptions {
  readonly config: ServerConfig;
  readonly repoRoot: string;
  /** Reject the requests this selects, to exercise the error rendering path. */
  readonly shouldFail?: (entry: LedgerEntry) => boolean;
}

export interface SurfaceRun {
  /** Tool names `advertisedTools` produced for this configuration. */
  readonly surface: readonly string[];
  /** Tool names recorded on entry, before the handler was called. */
  readonly invoked: readonly string[];
  readonly ledger: readonly LedgerEntry[];
  readonly results: ReadonlyMap<string, ToolResult>;
  /** Anything a handler threw rather than rendering. Normally empty. */
  readonly failures: ReadonlyMap<string, unknown>;
}

/**
 * Invoke every advertised tool exactly once against the recording client.
 *
 * The surface comes from `advertisedTools(config.enabledServices,
 * config.writesEnabled)` — the same function `tools/list` uses — so the driver
 * cannot drift from what the server would actually publish.
 */
export async function runAdvertisedSurface(options: SurfaceRunOptions): Promise<SurfaceRun> {
  const manifest = JSON.parse(
    readFileSync(join(options.repoRoot, 'specs', 'manifest.json'), 'utf8'),
  ) as SpecManifest;
  const { actions, byId } = buildRegistry(
    options.repoRoot,
    manifest,
    options.config.enabledServices,
  );

  const recorder = createRecordingClient({ shouldFail: options.shouldFail });
  const handlers = createHandlers({
    config: options.config,
    client: recorder.client,
    actions,
    byId,
  });

  const tools = advertisedTools(options.config.enabledServices, options.config.writesEnabled);
  const args = toolArguments(actions);
  assertEveryToolHasArguments(tools, args);

  const invoked: string[] = [];
  const results = new Map<string, ToolResult>();
  const failures = new Map<string, unknown>();

  for (const tool of tools) {
    const handler = handlers[tool.name];
    if (!handler) {
      throw new Error(
        `${tool.name} is advertised but createHandlers supplies no handler for it — the tool ` +
          `surface and the handler table have drifted apart.`,
      );
    }
    // Recorded on ENTRY, before the call: a handler that throws before reaching
    // the client must still count as invoked, or a broken handler would look
    // like a tool that was never in the surface.
    recorder.setCurrentTool(tool.name);
    invoked.push(tool.name);
    try {
      results.set(tool.name, await handler(args[tool.name] ?? {}));
    } catch (e: unknown) {
      failures.set(tool.name, e);
    }
  }

  return {
    surface: tools.map((tool) => tool.name),
    invoked,
    ledger: recorder.ledger,
    results,
    failures,
  };
}
