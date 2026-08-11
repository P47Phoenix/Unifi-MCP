/**
 * Tool surface assembly.
 *
 * `scripts/lint-tools.ts` and `scripts/token-budget.ts` import from here to
 * measure exactly what `tools/list` advertises, so this module must stay
 * importable without opening a socket or reading a credential.
 */
export {
  ALL_TOOLS,
  advertisedTools,
  LIST_CONSOLES,
  LIST_SITES,
  LIST_DEVICES,
  LIST_CLIENTS,
  LIST_CAMERAS,
  SEARCH_ACTIONS,
  EXECUTE_ACTION,
  EXECUTE_WRITE_ACTION,
  type ToolDefinition,
  type ToolAnnotations,
} from './definitions.js';

export { createHandlers, PROMOTED_ACTION_IDS, type ToolResult, type HandlerContext } from './handlers.js';
