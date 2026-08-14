/**
 * Tool handlers.
 *
 * Every handler funnels into `runAction`, so the guarantees that matter —
 * read/write separation, pagination normalization, untrusted-string fencing,
 * payload ceilings — hold in one place rather than being re-implemented per
 * tool and drifting.
 */
import type { Action, PaginatedResult, ServiceId } from '../types.js';
import { UnifiError } from '../types.js';
import type { ServerConfig } from '../config.js';
import type { UnifiClient } from '../http/client.js';
import { toolError, localError } from '../http/errors.js';
import { normalizePage, clampPageSize, pageQueryParams } from '../http/pagination.js';
import { renderUntrustedBlock } from '../safety/sanitize.js';
import { applyPayloadCeiling, projectFields, projectionFor } from '../safety/truncate.js';
import { NEVER_SHIP } from '../registry/blocklist.js';
import {
  CLOUD_API_KEY_ARG,
  CONSOLE_API_KEY_ARG,
  CONSOLE_HOST_ARG,
  CONSOLE_ID_ARG,
} from '../http/client.js';
import type { WithheldMatch } from './search.js';
import { searchActions, searchBlocklist } from './search.js';

export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export interface HandlerContext {
  config: ServerConfig;
  client: UnifiClient;
  actions: Action[];
  byId: Map<string, Action>;
}

/**
 * Actions backing the five promoted tools (FR-21).
 *
 * Promotion is a presentation choice, not a second code path: each promoted
 * tool is a named, pre-bound call into the same registry the execute tools use,
 * so a bug fixed in `runAction` is fixed for both surfaces at once.
 */
export const PROMOTED_ACTION_IDS = {
  unifi_list_consoles: 'site_manager.list_hosts',
  unifi_list_sites: 'site_manager.list_sites',
  unifi_list_devices: 'network.get_adopted_device_overview_page',
  unifi_list_clients: 'network.get_connected_client_overview_page',
  unifi_list_cameras: 'protect.get_cameras',
} as const;

/** Resource type each promoted tool returns, for default field projection. */
const PROMOTED_RESOURCE: Record<string, string> = {
  unifi_list_consoles: 'host',
  unifi_list_sites: 'site',
  unifi_list_devices: 'device',
  unifi_list_clients: 'client',
  unifi_list_cameras: 'camera',
};

function errorResult(e: unknown): ToolResult {
  if (e instanceof UnifiError) return toolError(e.normalized);
  // An unexpected throw still leaves as a structured tool error rather than
  // propagating and killing the stdio transport (NFR-05).
  return toolError(
    localError(
      'site-manager',
      'server_error',
      e instanceof Error ? e.message : String(e),
      'This is an internal error in the UniFi MCP server rather than an API failure. Retrying the same call is unlikely to help.',
    ),
  );
}

// ---------------------------------------------------------------------------
// Explaining what is withheld (FR-46)
// ---------------------------------------------------------------------------

/**
 * The one sentence this server says about a withheld operation.
 *
 * Every surface that mentions the blocklist routes through here — the
 * empty-result branch of search, the results-present branch, and the
 * unknown-action-id error. One composer is the only way the same fact stops
 * being told two different ways depending on whether other results happened to
 * match, and it is also what makes the explanation identical over stdio and
 * over HTTP (FR-74): there is no second string to drift.
 *
 * The wording differs by disposition because the facts differ. A whole-operation
 * block is absent from the registry in every configuration; a variant
 * withholding leaves the operation reachable and refuses one named
 * discriminator. Describing the second as "not exposed" would be false, and
 * would send a caller looking for a workaround to an endpoint they can already
 * reach.
 *
 * What it deliberately does not say: any action ID, any execute-tool name, any
 * parameter schema, any alternative route. Naming the operation and the reason
 * is the whole of what FR-46 promises.
 */
function describeWithheldOperation(match: WithheldMatch): string {
  const operation = `${match.method} ${match.path} (${match.service})`;
  const reason = match.reasons.join(' ');
  if (match.disposition === 'variant-withheld') {
    const variants = match.variants.join(' and ');
    const verb = match.variants.length === 1 ? 'variant is' : 'variants are';
    return `${operation} remains reachable, but its ${variants} ${verb} deliberately withheld — ${reason}`;
  }
  return `${operation} is deliberately not exposed by this server, in any configuration — ${reason}`;
}

/** The withheld footnote for a search result, or '' when nothing was withheld. */
export function explainWithheld(matches: readonly WithheldMatch[]): string {
  if (matches.length === 0) return '';
  return [
    'Not everything matching this query is exposed:',
    ...matches.map((match) => `- ${describeWithheldOperation(match)}`),
  ].join('\n');
}

/**
 * Structured form of the withheld set.
 *
 * Kept under its own key rather than merged into `matches`: that array is the
 * invocable set, and a withheld operation appearing in it would read as
 * something to call.
 */
function withheldContent(matches: readonly WithheldMatch[]): Array<Record<string, unknown>> {
  return matches.map((match) => ({
    service: match.service,
    method: match.method,
    path: match.path,
    disposition: match.disposition,
    variants: match.variants,
    reason: match.reasons.join(' '),
  }));
}

/** Render a normalized page as text + structured content. */
function renderPage(
  label: string,
  page: PaginatedResult,
  resource: string | null,
  explicitFields: string[] | undefined,
): ToolResult {
  const projection = explicitFields ?? (resource ? projectionFor(resource) : null);
  const items =
    projection && page.items.every((i) => typeof i === 'object' && i !== null)
      ? projectFields(page.items as object[], projection)
      : page.items;

  const lines: string[] = [];
  if (page.truncation) {
    lines.push(page.truncation.message);
  } else {
    lines.push(
      `Returned ${page.returnedCount}${
        page.totalCount !== null && page.totalCount !== page.returnedCount
          ? ` of ${page.totalCount}`
          : ''
      } result${page.returnedCount === 1 ? '' : 's'}.`,
    );
  }
  // FR-23: emulated paging is disclosed even when nothing was withheld, so a
  // caller never mistakes a server-side slice for native upstream paging.
  if (page.paginationEmulated) {
    lines.push(
      'Pagination is emulated server-side: this API returns its full collection and provides no paging of its own.',
    );
  }
  if (page.nextCursor) {
    lines.push(`More results available. Pass cursor="${page.nextCursor}" to continue.`);
  }
  if (projection && !explicitFields) {
    lines.push(`Fields are a default projection. Pass fields=[...] to choose others.`);
  }

  // FR-56: names, hostnames, SSIDs and camera names are attacker-influenceable
  // and are fenced in the TEXT rendering. structuredContent below carries the
  // original bytes so nothing downstream loses fidelity.
  lines.push(renderUntrustedBlock(label, items));

  const { text, notice } = applyPayloadCeiling(lines.join('\n\n'));

  return {
    content: [{ type: 'text', text }],
    structuredContent: {
      items: page.items,
      next_cursor: page.nextCursor,
      total_count: page.totalCount,
      returned_count: page.returnedCount,
      pagination_emulated: page.paginationEmulated,
      truncated: page.truncation !== null || notice !== null,
    },
  };
}

/** The four runtime console-selection argument names, in pass-through order. */
const CONSOLE_SELECTION_ARG_NAMES: readonly string[] = [
  CONSOLE_HOST_ARG,
  CONSOLE_API_KEY_ARG,
  CONSOLE_ID_ARG,
  CLOUD_API_KEY_ARG,
];

/** The single path from an action to a rendered result. */
async function runAction(
  ctx: HandlerContext,
  action: Action,
  args: Record<string, unknown>,
  label: string,
  resource: string | null,
): Promise<ToolResult> {
  const pageSize = clampPageSize(action.service, args.page_size as number | undefined);
  // The cursor stays opaque here: `pageQueryParams` and `normalizePage` decode
  // it, so this layer never has to know which of the four paging schemes the
  // service actually uses.
  const cursor = (args.cursor as string | undefined) ?? null;
  const requestArgs: Record<string, unknown> = {
    ...(args.path_params && typeof args.path_params === 'object' ? args.path_params : {}),
    ...(args.query && typeof args.query === 'object' ? args.query : {}),
    ...pageQueryParams(action.service, { pageSize, cursor }),
  };
  if (args.site_id) requestArgs.siteId = args.site_id;
  if (args.filter) requestArgs.filter = args.filter;
  if (args.body !== undefined) requestArgs.body = args.body;
  // Runtime console selection: passed straight through to `UnifiClient.request`,
  // which reads these four reserved names itself (`CONSOLE_HOST_ARG` and
  // siblings in src/http/client.ts) and never forwards them into a request
  // body or query string.
  for (const key of CONSOLE_SELECTION_ARG_NAMES) {
    if (args[key] !== undefined) requestArgs[key] = args[key];
  }

  const response = await ctx.client.request(action, requestArgs);

  // FR-41: Mobility PUTs answer 204 with an empty body. An empty content array
  // reads as "nothing happened"; say what changed and to what.
  if (response.status === 204 || response.body === undefined || response.body === null) {
    const target =
      (requestArgs.deviceId as string) ??
      (requestArgs.id as string) ??
      (requestArgs.siteId as string) ??
      '(unspecified target)';
    return {
      content: [
        {
          type: 'text',
          text: `${action.id} succeeded (HTTP ${response.status}, empty body). Target: ${target}.`,
        },
      ],
      structuredContent: { success: true, action_id: action.id, target, http_status: response.status },
    };
  }

  const page = normalizePage(action.service, response.body, { pageSize, cursor });
  return renderPage(label, page, resource, args.fields as string[] | undefined);
}

export function createHandlers(ctx: HandlerContext) {
  const handlers: Record<string, (args: Record<string, unknown>) => Promise<ToolResult>> = {};

  for (const [toolName, actionId] of Object.entries(PROMOTED_ACTION_IDS)) {
    handlers[toolName] = async (args) => {
      try {
        const action = ctx.byId.get(actionId);
        if (!action) {
          return errorResult(
            new UnifiError(
              localError(
                'site-manager',
                'config',
                `${toolName} is advertised but its backing action \`${actionId}\` is absent from the registry.`,
                'This means the vendored spec changed shape. Run `npm run coverage:check` to see what moved.',
              ),
            ),
          );
        }
        return await runAction(
          ctx,
          action,
          args,
          toolName.replace('unifi_list_', ''),
          PROMOTED_RESOURCE[toolName] ?? null,
        );
      } catch (e) {
        return errorResult(e);
      }
    };
  }

  handlers.unifi_search_actions = async (args) => {
    const query = String(args.query ?? '').toLowerCase();
    const limit = Math.min(Number(args.limit ?? 10), 25);
    const service = args.service as ServiceId | undefined;
    const actionClass = args.action_class as 'read' | 'write' | undefined;

    const scored = searchActions(ctx.actions, query, { service, actionClass, limit });

    // FR-46: a query that matches something deliberately withheld gets told so.
    // Silence would read as "this API cannot do that", which is false. The
    // withheld set is ranked by the same expansion and weighting as `scored`,
    // so ordinary phrasing that finds an action also finds what was withheld.
    const withheld = searchBlocklist(NEVER_SHIP, query, { service });
    const explanation = explainWithheld(withheld);

    if (scored.length === 0) {
      const enabled = [...ctx.config.enabledServices].join(', ') || 'none';
      const lines = [`No actions matched "${args.query}". Enabled services: ${enabled}.`];
      if (explanation) lines.push(explanation);
      return {
        content: [{ type: 'text', text: lines.join('\n\n') }],
        structuredContent: {
          matches: [],
          withheld: withheldContent(withheld),
          enabled_services: [...ctx.config.enabledServices],
        },
      };
    }

    const matches = scored.map(({ action }) => ({
      action_id: action.id,
      service: action.service,
      method: action.method,
      path: action.path,
      action_class: action.actionClass,
      summary: action.summary || action.description.slice(0, 160),
      required_scopes: action.requiredScopes,
      early_access: action.earlyAccess,
      parameters: action.parameters.map((p) => ({
        name: p.name,
        in: p.location,
        required: p.required,
        description: p.description,
      })),
      execute_with:
        action.actionClass === 'read' ? 'unifi_execute_action' : 'unifi_execute_write_action',
    }));

    const lines = [`${matches.length} matching action${matches.length === 1 ? '' : 's'}:`];
    if (explanation) lines.push(explanation);
    lines.push(JSON.stringify(matches, null, 2));
    const { text } = applyPayloadCeiling(lines.join('\n\n'));

    return {
      content: [{ type: 'text', text }],
      structuredContent: { matches, withheld: withheldContent(withheld) },
    };
  };

  const makeExecutor = (expected: 'read' | 'write', siblingTool: string) =>
    async (args: Record<string, unknown>): Promise<ToolResult> => {
      try {
        const actionId = String(args.action_id ?? '');
        const action = ctx.byId.get(actionId);
        if (!action) {
          // The same ranked matcher search uses, fed the action id as the
          // query: `expandConcepts` already splits on the dots and underscores
          // an id is built from, so `network.restart_device` expands exactly
          // as "restart device" would.
          const [nearest] = searchBlocklist(NEVER_SHIP, actionId, { limit: 1 });
          return errorResult(
            new UnifiError(
              localError(
                'site-manager',
                'not_found',
                `No action with id \`${actionId}\`.${
                  nearest
                    ? ` A similar operation is covered by this server's never-ship blocklist: ${describeWithheldOperation(nearest)}`
                    : ''
                }`,
                'Use unifi_search_actions to get a valid action id.',
              ),
            ),
          );
        }
        // NFR-01: the class check is the whole point of having two tools. It
        // happens before any request is built, so a misrouted call never
        // reaches the network.
        if (action.actionClass !== expected) {
          return errorResult(
            new UnifiError(
              localError(
                action.service,
                'bad_request',
                `\`${action.id}\` is a ${action.actionClass === 'write' ? 'state-changing' : 'read-only'} action (${action.method}).`,
                `Call it with ${siblingTool} instead.`,
              ),
            ),
          );
        }
        return await runAction(ctx, action, args, action.id, null);
      } catch (e) {
        return errorResult(e);
      }
    };

  handlers.unifi_execute_action = makeExecutor('read', 'unifi_execute_write_action');
  handlers.unifi_execute_write_action = makeExecutor('write', 'unifi_execute_action');

  return handlers;
}
