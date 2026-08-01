/**
 * Shared contracts for the UniFi MCP server.
 *
 * Traceability: identifiers like FR-23 refer to requirements in docs/prd.md.
 */

/** The four published Ubiquiti developer APIs. */
export type ServiceId = 'site-manager' | 'network' | 'protect' | 'mobility';

export const SERVICE_IDS: readonly ServiceId[] = [
  'site-manager',
  'network',
  'protect',
  'mobility',
] as const;

/**
 * How a request reaches a service (FR-07, FR-08, FR-10).
 *
 * Transport is chosen by configuration, never by tool name (FR-11): the same
 * action ID resolves to a different base URL depending on this value alone.
 */
export type TransportMode =
  /** Site Manager and Mobility on api.ui.com. Public TLS, no host config. */
  | 'cloud'
  /** Network and Protect on the user's LAN. Self-signed certs (FR-09). */
  | 'local'
  /** Network and Protect proxied through api.ui.com by console ID (FR-12). */
  | 'connector';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Safe methods per the directory review criteria; everything else is a write. */
export const READ_METHODS: readonly HttpMethod[] = ['GET'] as const;

export type ActionClass = 'read' | 'write';

/**
 * One callable UniFi operation, derived from a vendored OpenAPI spec.
 *
 * The registry of these is the central data structure (ADR-02): search ranks
 * over it, the execute tools dispatch through it, and the coverage check
 * (FR-59) asserts every spec operation is either present here or blocklisted.
 */
export interface Action {
  /** Stable, user-facing ID. Directly usable as execute-tool input (FR-19). */
  id: string;
  service: ServiceId;
  method: HttpMethod;
  /** OpenAPI path template, e.g. `/v1/sites/{siteId}/devices`. */
  path: string;
  /** `read` maps to unifi_execute_action, `write` to the write tool (FR-20). */
  actionClass: ActionClass;
  summary: string;
  description: string;
  tags: string[];
  parameters: ActionParameter[];
  /** Present for operations that take a body. */
  requestBody?: { required: boolean; schema: unknown; contentType: string };
  /** True for Site Manager `/ea/` paths — 100 req/min, not 10,000 (FR-30). */
  earlyAccess: boolean;
  /** Scopes the key must carry. Mobility only, today (FR-39). */
  requiredScopes: string[];
  /** Free-text search haystack, precomputed at build time. */
  searchText: string;
}

export interface ActionParameter {
  name: string;
  location: 'path' | 'query' | 'header';
  required: boolean;
  description: string;
  schema: unknown;
}

/** An operation deliberately not exposed in any configuration (FR-46). */
export interface BlocklistEntry {
  service: ServiceId;
  method: HttpMethod;
  /** Exact OpenAPI path template, matched literally. */
  path: string;
  /**
   * Request-body discriminator value to withhold, for Network's generic
   * `.../actions` endpoints where the dangerous verb is a body field rather
   * than its own path. Absent means the whole operation is withheld.
   */
  discriminator?: string;
  /** One-line justification. FR-46 requires every entry to carry one. */
  reason: string;
}

/**
 * The single normalized error shape spanning all four APIs (FR-24).
 *
 * The four upstream envelopes disagree on every field name; `upstreamCode` is
 * preserved verbatim and is never rewritten or dropped.
 */
export interface NormalizedError {
  /** Stable category, mapped from status and upstream code. */
  category: ErrorCategory;
  service: ServiceId;
  httpStatus: number | null;
  /** Upstream code verbatim: `NOT_FOUND`, `api.authentication.missing-credentials`, … */
  upstreamCode: string | null;
  message: string;
  /** traceId / requestId. Null for Protect, which carries none — never fabricated. */
  correlationId: string | null;
  /** Mobility distinguishes gateway from upstream failures (FR-25). */
  origin: 'gateway' | 'upstream' | null;
  /** Actionable next step. NFR-05 requires this to be non-empty. */
  recoveryHint: string;
  /** Seconds, from a `Retry-After` header where present (FR-26). */
  retryAfterSeconds: number | null;
}

export type ErrorCategory =
  | 'bad_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'rate_limit'
  | 'timeout'
  | 'payload_too_large'
  | 'tls'
  | 'network'
  | 'server_error'
  | 'config';

/**
 * The single normalized pagination envelope (FR-23).
 *
 * Upstream uses three different schemes — Site Manager's opaque cursor,
 * offset/limit for Network and Mobility, and nothing at all for Protect.
 * Callers see only this.
 */
export interface PaginatedResult<T = unknown> {
  items: T[];
  /** Opaque. Round-trips to the next page; null when the page is last. */
  nextCursor: string | null;
  /** Upstream total where the API reports one; null where it does not. */
  totalCount: number | null;
  returnedCount: number;
  /** True when the server sliced client-side because Protect has no paging. */
  paginationEmulated: boolean;
  truncation: TruncationNotice | null;
}

/** Truncation is always stated, never silent (FR-49, NFR-07). */
export interface TruncationNotice {
  returned: number;
  total: number | null;
  reason: 'page_size' | 'payload_ceiling' | 'field_projection';
  /** Rendered into the text content, e.g. "Showing 10 of 847 results. …". */
  message: string;
}

/** Thrown by the HTTP layer; converted to a structured tool error at the boundary. */
export class UnifiError extends Error {
  constructor(readonly normalized: NormalizedError) {
    super(normalized.message);
    this.name = 'UnifiError';
  }
}
