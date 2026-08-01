/**
 * One normalized error contract over four incompatible upstream envelopes (FR-24).
 *
 * The four APIs agree on nothing: field names, code vocabularies, and whether a
 * correlation id exists at all differ per service. Normalizing is therefore
 * per-service parsing into a shared shape — not a generic "find the message"
 * heuristic, which would silently mislabel the cases that matter.
 *
 * `upstreamCode` is copied verbatim and never rewritten (FR-24): it is the only
 * field a user can take to Ubiquiti support.
 */
import type { ErrorCategory, NormalizedError, ServiceId } from '../types.js';

/** Headers as `fetch` gives them, or as node:http gives them. */
export type HeaderLike =
  | Headers
  | Record<string, string | string[] | undefined>
  | null
  | undefined;

function header(headers: HeaderLike, name: string): string | null {
  if (!headers) return null;
  if (typeof (headers as Headers).get === 'function') {
    return (headers as Headers).get(name);
  }
  const record = headers as Record<string, string | string[] | undefined>;
  const key = Object.keys(record).find((k) => k.toLowerCase() === name.toLowerCase());
  const value = key === undefined ? undefined : record[key];
  if (value === undefined) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

/**
 * `Retry-After` is either delta-seconds or an HTTP date (RFC 9110). Both are
 * seen in the wild; a date parsed as a number would silently become NaN.
 */
function parseRetryAfter(headers: HeaderLike): number | null {
  const raw = header(headers, 'retry-after');
  if (raw === null) return null;
  const seconds = Number(raw.trim());
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
  const at = Date.parse(raw);
  if (Number.isNaN(at)) return null;
  return Math.max(0, Math.ceil((at - Date.now()) / 1000));
}

function asRecord(body: unknown): Record<string, unknown> {
  return body !== null && typeof body === 'object' && !Array.isArray(body)
    ? (body as Record<string, unknown>)
    : {};
}

function str(value: unknown): string | null {
  if (typeof value === 'string' && value.trim() !== '') return value.trim();
  if (typeof value === 'number') return String(value);
  return null;
}

function categoryFromStatus(status: number | null): ErrorCategory {
  switch (status) {
    case 400:
    case 422:
      return 'bad_request';
    case 401:
      return 'unauthorized';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 408:
      return 'timeout';
    case 413:
      return 'payload_too_large';
    case 429:
      return 'rate_limit';
    default:
      if (status !== null && status >= 500) return 'server_error';
      if (status !== null && status >= 400) return 'bad_request';
      return 'network';
  }
}

/** Site Manager's fixed code vocabulary (FR-24). */
const SITE_MANAGER_CATEGORIES: Record<string, ErrorCategory> = {
  BAD_REQUEST: 'bad_request',
  UNAUTHORIZED: 'unauthorized',
  FORBIDDEN: 'forbidden',
  NOT_FOUND: 'not_found',
  RATE_LIMIT: 'rate_limit',
  SERVER_ERROR: 'server_error',
  BAD_GATEWAY: 'server_error',
};

interface ParsedEnvelope {
  upstreamCode: string | null;
  message: string | null;
  correlationId: string | null;
  /** Some envelopes carry their own status, which can differ from the transport's. */
  bodyStatus: number | null;
  origin: 'gateway' | 'upstream' | null;
  category: ErrorCategory | null;
}

function parseSiteManager(body: Record<string, unknown>): ParsedEnvelope {
  const code = str(body.code);
  return {
    upstreamCode: code,
    message: str(body.message),
    correlationId: str(body.traceId),
    bodyStatus: typeof body.httpStatusCode === 'number' ? body.httpStatusCode : null,
    origin: null,
    category: code ? (SITE_MANAGER_CATEGORIES[code] ?? null) : null,
  };
}

function parseNetwork(body: Record<string, unknown>): ParsedEnvelope {
  const code = str(body.code);
  // Dotted codes (`api.authentication.missing-credentials`) are an open-ended
  // namespace, so only the leading segment is interpreted; the code itself is
  // still handed through verbatim.
  let category: ErrorCategory | null = null;
  if (code?.startsWith('api.authentication.')) category = 'unauthorized';
  else if (code?.startsWith('api.authorization.')) category = 'forbidden';
  else if (code?.startsWith('api.rate-limit')) category = 'rate_limit';

  return {
    upstreamCode: code,
    message: str(body.message) ?? str(body.statusName),
    correlationId: str(body.requestId),
    bodyStatus: typeof body.statusCode === 'number' ? body.statusCode : null,
    origin: null,
    category,
  };
}

function parseMobility(body: Record<string, unknown>): ParsedEnvelope {
  const code = str(body.code);
  return {
    upstreamCode: code,
    message: str(body.message),
    correlationId: str(body.traceId),
    bodyStatus: typeof body.httpStatusCode === 'number' ? body.httpStatusCode : null,
    // FR-25: the presence of `code` is itself the signal. A body that came from
    // the gateway carries one; a passed-through upstream failure does not.
    origin: code ? 'gateway' : 'upstream',
    category: null,
  };
}

function parseProtect(body: Record<string, unknown>): ParsedEnvelope {
  return {
    upstreamCode: str(body.name),
    message: str(body.error) ?? str(body.message),
    // FR-24: Protect carries no correlation id. Inventing one would make an
    // unsupportable error look supportable.
    correlationId: null,
    bodyStatus: null,
    origin: null,
    category: null,
  };
}

/**
 * FR-40: a Mobility 403 has three distinct causes with three distinct fixes,
 * and the upstream body usually does not say which. Guessing one would send the
 * user to the wrong console, so all three are enumerated unless the message
 * itself disambiguates.
 */
function mobilityForbiddenHint(message: string | null, upstreamCode: string | null): string {
  const haystack = `${message ?? ''} ${upstreamCode ?? ''}`.toLowerCase();
  const regenerate =
    'Regenerate the key at https://unifi.ui.com with the `mobility` app scope enabled ' +
    '(plus `read:mobility` for reads and `write:mobility` for writes).';

  if (/scope|permission denied for app|app scope/.test(haystack)) {
    return `The API key is missing the \`mobility\` app scope. ${regenerate}`;
  }
  if (/admin|role|not authorized for workspace|workspace member/.test(haystack)) {
    return (
      'The caller is not a workspace Admin. Mobility requires workspace Admin role on the ' +
      `target workspace. If the role is correct, the key may instead lack the \`mobility\` ` +
      `app scope — ${regenerate}`
    );
  }
  if (/subscription|not subscribed|plan|license/.test(haystack)) {
    return (
      'The target device has no active UniFi cloud subscription; Mobility writes require one. ' +
      'Activate the subscription at https://unifi.ui.com for the device in question.'
    );
  }
  return (
    'Mobility returned 403 without stating which of three causes applies. Check all three: ' +
    `(1) the API key lacks the \`mobility\` app scope — ${regenerate} ` +
    '(2) the caller is not a workspace Admin on the target workspace — Mobility requires that role. ' +
    '(3) the target device has no active UniFi cloud subscription — writes require one.'
  );
}

function recoveryHintFor(
  service: ServiceId,
  category: ErrorCategory,
  message: string | null,
  upstreamCode: string | null,
  retryAfterSeconds: number | null,
): string {
  if (service === 'mobility' && category === 'forbidden') {
    return mobilityForbiddenHint(message, upstreamCode);
  }

  switch (category) {
    case 'bad_request':
      return (
        'The request was rejected as malformed. Re-check the action arguments against the ' +
        'action schema from unifi_search_actions — particularly required path parameters and ' +
        'enum-valued fields — then retry.'
      );
    case 'unauthorized':
      return (
        `The API key was rejected by ${service}. Confirm the key is current and belongs to the ` +
        'account that owns this console, then re-run with the corrected key. Keys are read from ' +
        'the OS keychain first and from the environment second.'
      );
    case 'forbidden':
      return (
        `The key authenticated but is not permitted this ${service} operation. Verify the key's ` +
        'scopes and that the account has the required role on the target site or workspace.'
      );
    case 'not_found':
      return (
        'No such resource. Confirm the identifier by listing the parent collection first — ' +
        'UniFi identifiers are console-scoped, so an id from one console will not resolve on another.'
      );
    case 'rate_limit':
      return retryAfterSeconds !== null
        ? `Rate limited. Wait ${retryAfterSeconds}s before retrying, or reduce the request rate.`
        : 'Rate limited with no Retry-After header. Back off before retrying and reduce concurrency.';
    case 'timeout':
      return (
        'The request exceeded its deadline. Narrow the query (fewer items, a shorter time range) ' +
        'and retry; if it persists the console or the Cloud Connector path may be unreachable.'
      );
    case 'payload_too_large':
      return (
        'The response exceeded the size ceiling. Narrow the query with a smaller page_size or a ' +
        'more specific filter.'
      );
    case 'tls':
      return (
        'Certificate verification failed. Either supply a CA bundle via UNIFI_LOCAL_CA_BUNDLE, or ' +
        'set UNIFI_LOCAL_TLS_INSECURE=true to accept the console self-signed certificate.'
      );
    case 'network':
      return (
        `Could not reach ${service}. Verify the host is reachable from this machine and that no ` +
        'firewall or VPN split-tunnel blocks it, then retry.'
      );
    case 'config':
      return 'Fix the named configuration setting and restart the server.';
    case 'server_error':
      return (
        `${service} failed server-side. This is upstream, not a request defect: retry once after a ` +
        'short delay, and quote the correlation id to Ubiquiti support if it persists.'
      );
  }
}

export function normalizeError(
  service: ServiceId,
  httpStatus: number | null,
  body: unknown,
  headers?: HeaderLike,
): NormalizedError {
  const record = asRecord(body);

  let parsed: ParsedEnvelope;
  switch (service) {
    case 'site-manager':
      parsed = parseSiteManager(record);
      break;
    case 'network':
      parsed = parseNetwork(record);
      break;
    case 'mobility':
      parsed = parseMobility(record);
      break;
    case 'protect':
      parsed = parseProtect(record);
      break;
  }

  const status = httpStatus ?? parsed.bodyStatus;
  const category = parsed.category ?? categoryFromStatus(status);
  const retryAfterSeconds = parseRetryAfter(headers);

  // A body we could not parse is still an error the caller must act on. Fall
  // back to a status-derived sentence rather than an empty message — but never
  // forward a raw HTML body (NFR-05).
  const message =
    parsed.message ??
    (typeof body === 'string' && body.trim() !== '' && !/^\s*</.test(body)
      ? body.trim().slice(0, 500)
      : `${service} returned HTTP ${status ?? 'no status'} with no parseable error body.`);

  return {
    category,
    service,
    httpStatus: status,
    upstreamCode: parsed.upstreamCode,
    message,
    correlationId: parsed.correlationId,
    origin: parsed.origin,
    recoveryHint: recoveryHintFor(service, category, message, parsed.upstreamCode, retryAfterSeconds),
    retryAfterSeconds,
  };
}

/** Build a NormalizedError for a failure that never reached an upstream envelope. */
export function localError(
  service: ServiceId,
  category: ErrorCategory,
  message: string,
  recoveryHint?: string,
): NormalizedError {
  return {
    category,
    service,
    httpStatus: null,
    upstreamCode: null,
    message,
    correlationId: null,
    origin: null,
    recoveryHint: recoveryHint ?? recoveryHintFor(service, category, message, null, null),
    retryAfterSeconds: null,
  };
}

export interface ToolErrorResult {
  isError: true;
  content: Array<{ type: 'text'; text: string }>;
}

/**
 * Render a normalized error as an MCP tool error (NFR-05).
 *
 * Every line is one the model can act on: the hint comes last because that is
 * what a reader continues from, and the correlation id is stated only when one
 * genuinely exists.
 */
export function toolError(e: NormalizedError): ToolErrorResult {
  const lines = [`${e.service} request failed (${e.category}${e.httpStatus ? ` — HTTP ${e.httpStatus}` : ''}).`];
  lines.push(`Message: ${e.message}`);
  if (e.upstreamCode) lines.push(`Upstream code: ${e.upstreamCode}`);
  if (e.origin) lines.push(`Origin: ${e.origin}`);
  if (e.correlationId) lines.push(`Correlation id: ${e.correlationId}`);
  if (e.retryAfterSeconds !== null) lines.push(`Retry-After: ${e.retryAfterSeconds}s`);
  lines.push(`Next step: ${e.recoveryHint}`);

  return { isError: true, content: [{ type: 'text', text: lines.join('\n') }] };
}
