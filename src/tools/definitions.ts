/**
 * Tool definitions — names, descriptions, schemas, annotations.
 *
 * Kept free of handler logic and of any import that opens a socket, so that
 * `scripts/lint-tools.ts` and `scripts/token-budget.ts` can measure the exact
 * surface that lands in `tools/list` without booting a server.
 *
 * ## Descriptions are the contract
 *
 * A description states what the tool does, what it returns, and what it does
 * NOT do, and names its near-siblings so the model can tell them apart
 * (NFR-03). What a description must never do is instruct the model how to
 * behave — "always call X first", "be sure to" — which is treated as prompt
 * injection at directory review (NFR-04, FR-58). `npm run lint:tools` fails the
 * build on that pattern, so this file is written to pass its own linter.
 *
 * The two execute tools accept caller-constructed parameters, which the review
 * criteria class as freeform; their descriptions therefore name the upstream
 * API and link its documentation.
 */
import { z } from 'zod';

import type { ServiceId } from '../types.js';

/** Annotations drive auto-approval and confirmation in the host (NFR-02). */
export interface ToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ToolDefinition {
  name: string;
  description: string;
  annotations: ToolAnnotations;
  inputSchema: z.ZodRawShape;
  /** Service whose configuration gates this tool's presence (FR-22). */
  requiresService?: ServiceId;
  /** True for the write execution tool, absent unless writes are on (FR-44). */
  requiresWrites?: boolean;
}

// ---------------------------------------------------------------------------
// Shared argument shapes
// ---------------------------------------------------------------------------

/**
 * The one normalized pagination interface (FR-23).
 *
 * Callers see a cursor regardless of whether the upstream API uses an opaque
 * token (Site Manager), offset/limit (Network, Mobility), or has no pagination
 * whatsoever (Protect, where the server slices and emits a synthetic cursor).
 */
function paginationArgs(maxPageSize: number, defaultPageSize: number): z.ZodRawShape {
  return {
    cursor: z
      .string()
      .optional()
      .describe(
        'Opaque cursor from a previous response\'s next_cursor. Omit for the first page.',
      ),
    page_size: z
      .number()
      .int()
      .min(1)
      .max(maxPageSize)
      .default(defaultPageSize)
      .describe(
        `Maximum items to return. Hard cap ${maxPageSize}; responses state when they are truncated.`,
      ),
  };
}

const siteIdArg = {
  site_id: z
    .string()
    .min(1)
    .describe('Site identifier, as returned in the `id` field by unifi_list_sites.'),
};

const fieldsArg = {
  fields: z
    .array(z.string().min(1))
    .max(40)
    .optional()
    .describe(
      'Field names to return. Defaults to a compact projection per resource type. The resource identifier is always included.',
    ),
};

// ---------------------------------------------------------------------------
// Promoted read tools (FR-21)
// ---------------------------------------------------------------------------

export const LIST_CONSOLES: ToolDefinition = {
  name: 'unifi_list_consoles',
  description:
    'Lists UniFi consoles (hosts) visible to the cloud API key, with the console identifier in ' +
    'the exact form Cloud Connector paths require and the firmware version that determines ' +
    'Connector eligibility (5.0.3 or later). A non-organization key sees only its owner\'s ' +
    'consoles. Returns consoles, not the sites they host (unifi_list_sites) or the devices ' +
    'adopted on them (unifi_list_devices).',
  annotations: {
    title: 'List UniFi consoles',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  inputSchema: { ...paginationArgs(500, 50), ...fieldsArg },
  requiresService: 'site-manager',
};

export const LIST_SITES: ToolDefinition = {
  name: 'unifi_list_sites',
  description:
    'Lists UniFi sites visible to the cloud API key, with the site identifier most Network ' +
    'operations require and the console hosting each. Returns sites, not the consoles hosting ' +
    'them (unifi_list_consoles) or the devices and clients within them (unifi_list_devices, ' +
    'unifi_list_clients).',
  annotations: {
    title: 'List UniFi sites',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  inputSchema: { ...paginationArgs(500, 50), ...fieldsArg },
  requiresService: 'site-manager',
};

export const LIST_DEVICES: ToolDefinition = {
  name: 'unifi_list_devices',
  description:
    'Lists UniFi infrastructure devices adopted by a site — access points, switches, gateways ' +
    '— with model, state, and firmware. These serve the network; for the client machines using ' +
    'it see unifi_list_clients. One site per call; site identifiers come from unifi_list_sites.',
  annotations: {
    title: 'List UniFi network devices',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  inputSchema: {
    ...siteIdArg,
    ...paginationArgs(200, 25),
    ...fieldsArg,
    filter: z
      .string()
      .optional()
      .describe(
        "Network filter DSL expression, for example name.like('ap-*'). Validated before the request is sent.",
      ),
  },
  requiresService: 'network',
};

export const LIST_CLIENTS: ToolDefinition = {
  name: 'unifi_list_clients',
  description:
    'Lists client machines connected to a UniFi site — laptops, phones, IoT devices — with ' +
    'hostname, IP, and connection details. These use the network; for the UniFi hardware ' +
    'serving it see unifi_list_devices. One site per call.',
  annotations: {
    title: 'List UniFi clients',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  inputSchema: {
    ...siteIdArg,
    ...paginationArgs(200, 25),
    ...fieldsArg,
    filter: z
      .string()
      .optional()
      .describe(
        "Network filter DSL expression, for example name.like('guest*'). Validated before the request is sent.",
      ),
  },
  requiresService: 'network',
};

export const LIST_CAMERAS: ToolDefinition = {
  name: 'unifi_list_cameras',
  description:
    'Lists UniFi Protect cameras with model, state, and recording configuration. Protect ' +
    'returns every camera in one unpaginated array, so this slices and projects server-side ' +
    'and reports the true total. Cameras only — sensors, lights, chimes and viewers are ' +
    'reachable through unifi_search_actions.',
  annotations: {
    title: 'List UniFi Protect cameras',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  inputSchema: { ...paginationArgs(200, 25), ...fieldsArg },
  requiresService: 'protect',
};

// ---------------------------------------------------------------------------
// Search and execute (FR-19, FR-20)
// ---------------------------------------------------------------------------

export const SEARCH_ACTIONS: ToolDefinition = {
  name: 'unifi_search_actions',
  description:
    'Searches UniFi API operations by natural-language intent. Returns matching action ' +
    'identifiers with their input schemas, HTTP method, service, and read-or-write class, for ' +
    'use verbatim with unifi_execute_action or unifi_execute_write_action. Searches the ' +
    'catalog only — it performs no UniFi API request. Operations this server deliberately ' +
    'withholds are reported as such rather than silently omitted.',
  annotations: {
    title: 'Search UniFi API actions',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  inputSchema: {
    query: z
      .string()
      .min(1)
      .describe(
        'Natural-language description of the intent, for example "which access points are offline".',
      ),
    service: z
      .enum(['site-manager', 'network', 'protect', 'mobility'])
      .optional()
      .describe('Restrict results to one API. Omit to search all enabled APIs.'),
    action_class: z
      .enum(['read', 'write'])
      .optional()
      .describe('Restrict results to read-only or state-changing operations.'),
    limit: z
      .number()
      .int()
      .min(1)
      .max(25)
      .default(10)
      .describe('Maximum matches to return. Hard cap 25.'),
  },
};

/** Shared by both execute tools; the classification check is what differs. */
const executeArgs: z.ZodRawShape = {
  action_id: z
    .string()
    .min(1)
    .describe('Action identifier exactly as returned by unifi_search_actions.'),
  path_params: z
    .record(z.string())
    .optional()
    .describe('Values for path placeholders such as siteId or deviceId.'),
  query: z
    .record(z.union([z.string(), z.number(), z.boolean()]))
    .optional()
    .describe('Query-string parameters defined by the action schema.'),
};

export const EXECUTE_ACTION: ToolDefinition = {
  name: 'unifi_execute_action',
  description:
    'Executes one read-only UniFi action by identifier, returning a normalized envelope with ' +
    'consistent pagination and error fields across all four APIs. A state-changing identifier ' +
    'is rejected and names unifi_execute_write_action. Identifiers come from ' +
    'unifi_search_actions. Wraps the Ubiquiti UniFi developer APIs at https://developer.ui.com.',
  annotations: {
    title: 'Execute a read-only UniFi action',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  inputSchema: { ...executeArgs, ...paginationArgs(500, 25), ...fieldsArg },
};

export const EXECUTE_WRITE_ACTION: ToolDefinition = {
  name: 'unifi_execute_write_action',
  description:
    'Executes one state-changing UniFi action by identifier — create, update, or delete. A ' +
    'read-only identifier is rejected and names unifi_execute_action. Present only when write ' +
    'support is enabled in server configuration; operations judged irreversible from a chat ' +
    'context are withheld in every configuration. Identifiers come from unifi_search_actions. ' +
    'Wraps the Ubiquiti UniFi developer APIs at https://developer.ui.com.',
  annotations: {
    title: 'Execute a state-changing UniFi action',
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
  inputSchema: {
    ...executeArgs,
    body: z
      .record(z.unknown())
      .optional()
      .describe('Request body for the action, matching the schema unifi_search_actions returned.'),
  },
  requiresWrites: true,
};

export const ALL_TOOLS: readonly ToolDefinition[] = [
  LIST_CONSOLES,
  LIST_SITES,
  LIST_DEVICES,
  LIST_CLIENTS,
  LIST_CAMERAS,
  SEARCH_ACTIONS,
  EXECUTE_ACTION,
  EXECUTE_WRITE_ACTION,
] as const;

/**
 * The tools a given configuration advertises.
 *
 * FR-22: a promoted tool is absent when its owning API is disabled, so a user
 * with no Protect gear pays no Protect schema tokens. FR-44: the write tool is
 * absent unless writes are explicitly enabled — absent from `tools/list`, not
 * merely refusing when called.
 */
export function advertisedTools(
  enabledServices: ReadonlySet<ServiceId>,
  writesEnabled: ReadonlySet<ServiceId>,
): ToolDefinition[] {
  return ALL_TOOLS.filter((tool) => {
    if (tool.requiresService && !enabledServices.has(tool.requiresService)) return false;
    if (tool.requiresWrites && writesEnabled.size === 0) return false;
    return true;
  });
}
