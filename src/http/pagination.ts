/**
 * One cursor-shaped pagination contract over four schemes (FR-23).
 *
 * Upstream offers an opaque token (Site Manager), two different offset/limit
 * dialects with different defaults (Network, Mobility), and nothing at all
 * (Protect). Callers see only `cursor` in / `nextCursor` out.
 *
 * The cursor is base64-encoded JSON precisely so that one opaque string can
 * carry either an offset or a vendor token without the caller — or the model —
 * needing to know which scheme is underneath.
 */
import type { PaginatedResult, ServiceId, TruncationNotice } from '../types.js';

/** Per-service page sizing, from the vendored specs (FR-23). */
export const PAGE_LIMITS: Record<ServiceId, { default: number; max: number }> = {
  'site-manager': { default: 100, max: 500 },
  network: { default: 25, max: 200 },
  mobility: { default: 200, max: 200 },
  // Protect returns whole arrays; these are the slice sizes this server
  // imposes, not anything upstream enforces.
  protect: { default: 100, max: 500 },
};

/** Decoded cursor state. Short keys keep the encoded string small. */
export interface CursorState {
  /** Service the cursor was minted for; a cross-service cursor is rejected. */
  s: ServiceId;
  /** Offset-based schemes (Network, Mobility, emulated Protect). */
  o?: number;
  /** Token-based scheme (Site Manager `nextToken`). */
  t?: string;
  /** Page size the cursor was minted with, so pagination stays stable. */
  l?: number;
}

export function encodeCursor(state: CursorState): string {
  return Buffer.from(JSON.stringify(state), 'utf8').toString('base64url');
}

export function decodeCursor(cursor: string | null | undefined): CursorState | null {
  if (!cursor) return null;
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as CursorState;
    return typeof parsed?.s === 'string' ? parsed : null;
  } catch {
    return null;
  }
}

export interface PageRequest {
  /** Opaque cursor from a previous `nextCursor`. */
  cursor?: string | null;
  /** Caller-requested page size; clamped to the service maximum. */
  pageSize?: number | null;
}

export function clampPageSize(service: ServiceId, requested: number | null | undefined): number {
  const limits = PAGE_LIMITS[service];
  if (requested === null || requested === undefined || !Number.isFinite(requested)) {
    return limits.default;
  }
  return Math.min(limits.max, Math.max(1, Math.floor(requested)));
}

/**
 * The native query parameters for a page request.
 *
 * Protect gets none: it has no pagination parameters to send, and adding
 * speculative ones would be a silent no-op the caller could not detect.
 */
export function pageQueryParams(
  service: ServiceId,
  requested: PageRequest = {},
): Record<string, string | number> {
  const state = decodeCursor(requested.cursor);
  const pageSize = clampPageSize(service, requested.pageSize ?? state?.l ?? null);

  switch (service) {
    case 'site-manager': {
      // `pageSize` is declared as a string in the spec; sending a number would
      // still serialise correctly but the string keeps the wire form exact.
      const params: Record<string, string | number> = { pageSize: String(pageSize) };
      if (state?.t) params.nextToken = state.t;
      return params;
    }
    case 'network':
    case 'mobility':
      return { offset: state?.o ?? 0, limit: pageSize };
    case 'protect':
      return {};
  }
}

function arrayFrom(value: unknown): unknown[] | null {
  if (Array.isArray(value)) return value;
  return null;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function truncationFor(
  returned: number,
  total: number | null,
  hasMore: boolean,
  extra = '',
): TruncationNotice | null {
  if (!hasMore) return null;
  const of = total === null ? 'more available' : `of ${total}`;
  return {
    returned,
    total,
    reason: 'page_size',
    message:
      `Showing ${returned} ${of}. Pass the returned cursor as \`cursor\` to fetch the next ` +
      `page.${extra}`,
  };
}

/**
 * Normalize one raw upstream response body into the shared envelope.
 *
 * `requested` matters because the cursor this returns must round-trip the page
 * size — otherwise page 2 could silently change size relative to page 1.
 */
export function normalizePage(
  service: ServiceId,
  rawBody: unknown,
  requested: PageRequest = {},
): PaginatedResult {
  const body = (rawBody !== null && typeof rawBody === 'object' ? rawBody : {}) as Record<
    string,
    unknown
  >;
  const state = decodeCursor(requested.cursor);
  const pageSize = clampPageSize(service, requested.pageSize ?? state?.l ?? null);

  switch (service) {
    case 'site-manager': {
      const items = arrayFrom(body.data) ?? arrayFrom(rawBody) ?? [];
      const nextToken = typeof body.nextToken === 'string' && body.nextToken !== ''
        ? body.nextToken
        : null;
      const totalCount = num(body.totalCount);
      return {
        items,
        nextCursor: nextToken ? encodeCursor({ s: service, t: nextToken, l: pageSize }) : null,
        totalCount,
        returnedCount: items.length,
        paginationEmulated: false,
        truncation: truncationFor(items.length, totalCount, nextToken !== null),
      };
    }

    case 'network': {
      // Envelope: {count, data[], limit, offset, totalCount}.
      const items = arrayFrom(body.data) ?? arrayFrom(rawBody) ?? [];
      const offset = num(body.offset) ?? state?.o ?? 0;
      const limit = num(body.limit) ?? pageSize;
      const totalCount = num(body.totalCount);
      const nextOffset = offset + items.length;
      const hasMore =
        totalCount !== null ? nextOffset < totalCount : items.length >= limit && items.length > 0;
      return {
        items,
        nextCursor: hasMore ? encodeCursor({ s: service, o: nextOffset, l: pageSize }) : null,
        totalCount,
        returnedCount: items.length,
        paginationEmulated: false,
        truncation: truncationFor(items.length, totalCount, hasMore),
      };
    }

    case 'mobility': {
      // Envelope: {data[], total, offset, limit, httpStatusCode, traceId}.
      const items = arrayFrom(body.data) ?? arrayFrom(rawBody) ?? [];
      const offset = num(body.offset) ?? state?.o ?? 0;
      const total = num(body.total);
      const nextOffset = offset + items.length;
      // FR-23: terminate at `offset >= total`. An empty page also terminates —
      // without that guard a total that never advances loops forever.
      const hasMore =
        items.length > 0 && (total === null ? items.length >= pageSize : nextOffset < total);
      return {
        items,
        nextCursor: hasMore ? encodeCursor({ s: service, o: nextOffset, l: pageSize }) : null,
        totalCount: total,
        returnedCount: items.length,
        paginationEmulated: false,
        truncation: truncationFor(items.length, total, hasMore),
      };
    }

    case 'protect': {
      // FR-23: Protect's list endpoints take no pagination parameters and
      // return the entire collection. Slicing here is the only way to keep the
      // contract, and the result says so rather than passing emulation off as
      // native paging.
      const all = arrayFrom(rawBody) ?? arrayFrom(body.data) ?? [];
      const offset = state?.o ?? 0;
      const items = all.slice(offset, offset + pageSize);
      const nextOffset = offset + items.length;
      const hasMore = nextOffset < all.length;
      const notice = truncationFor(
        items.length,
        all.length,
        hasMore,
        ' Pagination is emulated: Protect returns the full array and provides no paging of its own.',
      );
      return {
        items,
        nextCursor: hasMore ? encodeCursor({ s: service, o: nextOffset, l: pageSize }) : null,
        totalCount: all.length,
        returnedCount: items.length,
        paginationEmulated: true,
        // FR-49 is explicit that an untruncated response carries NO truncation
        // statement, so a full final page gets `null` here even though the
        // slicing was emulated. The emulation is still disclosed — the tools
        // layer renders it from `paginationEmulated`, which is a real text
        // channel; `TruncationNotice` is not one.
        truncation: notice,
      };
    }
  }
}
