/**
 * Response size control (FR-48..FR-51, NFR-07, NFR-08).
 *
 * The ceilings here are the client's, not the API's, and they are not the same
 * unit: claude.ai and Claude Desktop cut a tool result at roughly 150,000
 * CHARACTERS, while Claude Code cuts at roughly 25,000 TOKENS. Whichever binds
 * first is the one that matters, so both are expressed in characters and the
 * tighter wins.
 *
 * The upstream side supplies the pressure. Protect paginates nothing — a NVR
 * with a long event history returns the whole array — and the Cloud Connector
 * will hand back bodies up to 10 MB. Truncating is therefore routine, and
 * NFR-07 requires it to be stated every time: a silently shortened list is
 * indistinguishable from a complete one, and the model will reason from it as
 * though it were complete.
 */
import type { TruncationNotice } from '../types.js';

/** claude.ai / Claude Desktop tool-result ceiling. */
export const PAYLOAD_CEILING_CHARS = 150_000;

/** Claude Code tool-result ceiling, in tokens. */
export const TOKEN_CEILING = 25_000;

/**
 * Heuristic. Real tokenisation is BPE and content-dependent; four characters
 * per token is the usual English-prose approximation and runs a little
 * pessimistic on JSON, which is the direction to err in for a ceiling.
 */
export const CHARS_PER_TOKEN = 4;

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

/**
 * The binding ceiling: 100,000 characters, from Claude Code's token budget.
 * One constant for all clients, because the server cannot detect which client
 * is calling and the tighter bound is safe everywhere.
 */
export const EFFECTIVE_CEILING_CHARS = Math.min(
  PAYLOAD_CEILING_CHARS,
  TOKEN_CEILING * CHARS_PER_TOKEN,
);

function plural(unit: string, n: number): string {
  return n === 1 ? unit : `${unit}s`;
}

/** Unit and advice differ per reason; the sentence shape does not (FR-49). */
const REASON_COPY: Record<TruncationNotice['reason'], { unit: string; advice: string }> = {
  page_size: { unit: 'result', advice: 'Refine the query to narrow down.' },
  payload_ceiling: {
    unit: 'character',
    advice: 'Refine the query or request fewer fields to narrow down.',
  },
  field_projection: {
    unit: 'field',
    advice: 'Request specific fields to see more.',
  },
};

/**
 * `Showing 10 of 847 results. Refine the query to narrow down.`
 *
 * Returns the empty string when nothing was withheld: a complete response must
 * carry no truncation statement at all (FR-49), because a "showing 10 of 10"
 * line trains the reader to skip the sentence that matters.
 */
export function truncationMessage(
  returned: number,
  total: number | null,
  reason: TruncationNotice['reason'],
): string {
  if (total !== null && returned >= total) return '';

  const copy = REASON_COPY[reason];
  const scope =
    total === null
      ? `${returned} ${plural(copy.unit, returned)} (total unknown)`
      : `${returned} of ${total} ${plural(copy.unit, total)}`;

  return `Showing ${scope}. ${copy.advice}`;
}

/** Build a notice, or null when the response was complete. */
export function truncationNotice(
  returned: number,
  total: number | null,
  reason: TruncationNotice['reason'],
): TruncationNotice | null {
  const message = truncationMessage(returned, total, reason);
  if (message === '') return null;
  return { returned, total, reason, message };
}

export interface CeilingResult {
  /** Truncated text with the notice already appended — it cannot be dropped. */
  text: string;
  notice: TruncationNotice | null;
}

/**
 * Cut `text` to the binding ceiling and state that it was cut.
 *
 * The notice is appended to the returned text as well as returned separately,
 * so a caller that forwards only `text` still ships the disclosure. Under the
 * ceiling, the text is returned untouched and `notice` is null.
 */
export function applyPayloadCeiling(text: string): CeilingResult {
  if (text.length <= EFFECTIVE_CEILING_CHARS) return { text, notice: null };

  const message = truncationMessage(EFFECTIVE_CEILING_CHARS, text.length, 'payload_ceiling');
  const suffix = `\n\n${message}`;

  let kept = text.slice(0, EFFECTIVE_CEILING_CHARS - suffix.length);
  // Slicing by UTF-16 code unit can strand a lone high surrogate, which no
  // longer round-trips through JSON. Drop the orphan.
  const last = kept.charCodeAt(kept.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) kept = kept.slice(0, -1);

  return {
    text: kept + suffix,
    notice: { returned: kept.length, total: text.length, reason: 'payload_ceiling', message },
  };
}

/**
 * Identifier fields, always kept.
 *
 * A projected record without its ID is a dead end: the model can see the item
 * but cannot fetch, filter, or act on it, which turns one call into two. The
 * four APIs disagree on the spelling, so all the spellings in use are kept.
 */
export const IDENTIFIER_FIELDS: readonly string[] = ['id', '_id'];

/**
 * Default field sets per resource (FR-50).
 *
 * Deliberately small: identifier, the human-readable name, the one state field
 * a user asks about first, and at most a couple of high-signal extras. Full
 * records from these APIs run to dozens of fields — Protect cameras alone carry
 * a nested settings tree — and returning them all is what breaches the ceiling
 * above. Callers wanting more pass an explicit field list.
 */
export const DEFAULT_PROJECTIONS: Record<string, readonly string[]> = {
  /** Protect. `state` is the connection state; `isRecording` is the usual question. */
  camera: ['id', 'name', 'type', 'state', 'isConnected', 'isRecording'],
  /** Network / Site Manager. Model and IP are what identifies a box on a LAN. */
  device: ['id', 'name', 'model', 'macAddress', 'ipAddress', 'state', 'firmwareVersion'],
  /** Network. `type` distinguishes wired from wireless, the first thing asked. */
  client: ['id', 'name', 'type', 'macAddress', 'ipAddress', 'connectedAt'],
  /** Site Manager. `hostId` links the site back to its console. */
  site: ['id', 'name', 'hostId', 'permission'],
  /** Site Manager consoles. `isBlocked` explains an otherwise silent failure. */
  host: ['id', 'type', 'ipAddress', 'isBlocked', 'owner'],
};

/** The default set for a resource, or null when the resource has no default. */
export function projectionFor(resource: string): readonly string[] | null {
  return DEFAULT_PROJECTIONS[resource] ?? null;
}

/**
 * Keep only `projection` (plus the identifier) on each item.
 *
 * Absent keys are omitted rather than set to undefined, so a projected record
 * never claims a field exists with no value.
 */
export function projectFields<T extends object>(
  items: T[],
  projection: readonly string[],
  identifiers: readonly string[] = IDENTIFIER_FIELDS,
): Partial<T>[] {
  const keep = new Set<string>([...identifiers, ...projection]);

  return items.map((item) => {
    const out: Partial<T> = {};
    for (const key of Object.keys(item) as Array<keyof T & string>) {
      if (keep.has(key)) out[key] = item[key];
    }
    return out;
  });
}
