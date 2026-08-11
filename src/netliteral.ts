/**
 * The single loopback predicate, and the single IPv6 literal parser (D-15).
 *
 * Two modules need to decide "is this bind address loopback?": the
 * configuration layer, which refuses to start an unauthenticated listener on a
 * non-loopback address (FR-73(b)) and which relaxes that refusal only for a
 * genuine loopback bind (FR-73(e)); and the request guard, which reports the
 * same fact at runtime. The architecture forbids the configuration layer from
 * importing anything under `src/serve/`, so without this leaf the two would
 * each grow their own predicate — and two implementations of a *closed* rule
 * are the exact defect the requirement exists to prevent. One of them
 * eventually accepts something the other rejects, and the one that is wrong in
 * the accepting direction is the open listener NFR-23 promises is unreachable.
 * So the predicate lives here, imports nothing from this project, and both
 * consumers import it rather than reimplement it.
 *
 * The dangerous direction is one-sided: a *non*-loopback value classified as
 * loopback is, combined with `UNIFI_HTTP_AUTH=none`, an open listener holding a
 * live UniFi credential. A loopback value classified as non-loopback is merely
 * a startup refusal an operator can read. Every unrecognised, malformed or
 * unparseable input therefore returns `false` — this module fails closed by
 * construction, not by convention.
 */
import { isIP } from 'node:net';

/** `isIP` return codes, named so no bare `4`/`6` appears at a call site. */
const IPV4_FAMILY = 4;
const IPV6_FAMILY = 6;

const IPV6_GROUP_COUNT = 8;
const IPV4_OCTET_COUNT = 4;
const OCTET_BITS = 8;
const OCTET_MASK = 0xff;

/** RFC 1122 reserves the whole 127.0.0.0/8, not just 127.0.0.1. */
const IPV4_LOOPBACK_FIRST_OCTET = 127;

/** Index of the `ffff` marker group in an IPv4-mapped IPv6 address. */
const MAPPED_MARKER_INDEX = 5;
const MAPPED_MARKER = 0xffff;
/** The two groups that carry the embedded 32-bit IPv4 address. */
const MAPPED_HIGH_INDEX = 6;
const MAPPED_LOW_INDEX = 7;

/** Index of the group holding `::1`'s single set bit. */
const IPV6_LOOPBACK_LOW_INDEX = 7;

const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;
const DECIMAL_OCTET = /^\d{1,3}$/;

/**
 * Parse one dotted quad into the two 16-bit groups it occupies at the tail of
 * an IPv6 address. `null` on anything that is not four decimal octets.
 */
function parseDottedQuad(text: string): readonly [number, number] | null {
  const parts = text.split('.');
  if (parts.length !== IPV4_OCTET_COUNT) return null;

  const octets: number[] = [];
  for (const part of parts) {
    if (!DECIMAL_OCTET.test(part)) return null;
    const octet = Number(part);
    if (octet > OCTET_MASK) return null;
    octets.push(octet);
  }

  const [first, second, third, fourth] = octets;
  if (
    first === undefined ||
    second === undefined ||
    third === undefined ||
    fourth === undefined
  ) {
    return null;
  }
  return [(first << OCTET_BITS) | second, (third << OCTET_BITS) | fourth];
}

/**
 * Parse a colon-separated run of hex groups, expanding a trailing dotted quad
 * into the two groups it stands for. An empty run yields no groups, which is
 * what each side of a `::` contributes when it is absent.
 */
function parseGroupRun(text: string): number[] | null {
  if (text === '') return [];

  const parts = text.split(':');
  const groups: number[] = [];
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === undefined) return null;

    const isFinalPart = index === parts.length - 1;
    if (isFinalPart && part.includes('.')) {
      const quad = parseDottedQuad(part);
      if (quad === null) return null;
      groups.push(quad[0], quad[1]);
      continue;
    }

    if (!HEX_GROUP.test(part)) return null;
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

/**
 * Expand an IPv6 literal to its eight 16-bit groups, or `null` if it is not one.
 *
 * Exported so the request guard's `sourceKey` derives its /64 prefix from THIS
 * parser rather than growing a second one: a divergent expansion of `::` there
 * would silently mis-key throttle buckets, and a second parser is a second
 * place for the loopback rule to drift.
 *
 * Validation is delegated to `isIP` first — a value carrying whitespace,
 * brackets, a port or a zone id is rejected there, and that rejection is the
 * fail-closed behaviour, not an oversight.
 */
export function ipv6Groups(value: string): readonly number[] | null {
  if (isIP(value) !== IPV6_FAMILY) return null;

  const halves = value.split('::');
  if (halves.length > 2) return null;

  if (halves.length === 1) {
    const groups = parseGroupRun(value);
    return groups !== null && groups.length === IPV6_GROUP_COUNT ? groups : null;
  }

  const head = parseGroupRun(halves[0] ?? '');
  const tail = parseGroupRun(halves[1] ?? '');
  if (head === null || tail === null) return null;

  const elided = IPV6_GROUP_COUNT - head.length - tail.length;
  if (elided < 0) return null;
  return [...head, ...new Array<number>(elided).fill(0), ...tail];
}

/** True when the groups carry the `::ffff:0:0/96` IPv4-mapped prefix. */
function hasMappedPrefix(groups: readonly number[]): boolean {
  for (let index = 0; index < MAPPED_MARKER_INDEX; index += 1) {
    if (groups[index] !== 0) return false;
  }
  return groups[MAPPED_MARKER_INDEX] === MAPPED_MARKER;
}

/**
 * Render the IPv4 address embedded in an IPv4-mapped IPv6 literal, or `null`
 * when `value` is not one — including for every IPv4 literal, which is already
 * in the form this function produces.
 *
 * Exported for the same reason as `ipv6Groups`: the request guard folds
 * `::ffff:10.42.0.7` onto `10.42.0.7` before keying a throttle bucket, and it
 * must do so with this parser so that a dual-stack bind and a v4-only bind
 * produce the same key for the same caller.
 */
export function unmapIpv4Mapped(value: string): string | null {
  const groups = ipv6Groups(value);
  if (groups === null || !hasMappedPrefix(groups)) return null;

  const high = groups[MAPPED_HIGH_INDEX];
  const low = groups[MAPPED_LOW_INDEX];
  if (high === undefined || low === undefined) return null;

  return [
    high >>> OCTET_BITS,
    high & OCTET_MASK,
    low >>> OCTET_BITS,
    low & OCTET_MASK,
  ].join('.');
}

function isIpv4Loopback(value: string): boolean {
  const firstOctet = value.slice(0, value.indexOf('.'));
  return Number(firstOctet) === IPV4_LOOPBACK_FIRST_OCTET;
}

function isIpv6Loopback(groups: readonly number[]): boolean {
  for (let index = 0; index < IPV6_LOOPBACK_LOW_INDEX; index += 1) {
    if (groups[index] !== 0) return false;
  }
  return groups[IPV6_LOOPBACK_LOW_INDEX] === 1;
}

/** `::ffff:127.0.0.0/104` — the mapped form of the IPv4 loopback /8. */
function isMappedIpv4Loopback(groups: readonly number[]): boolean {
  if (!hasMappedPrefix(groups)) return false;
  const high = groups[MAPPED_HIGH_INDEX];
  return high !== undefined && high >>> OCTET_BITS === IPV4_LOOPBACK_FIRST_OCTET;
}

/**
 * Closed predicate: `true` for exactly the loopback bind addresses, `false` for
 * everything else including every input that cannot be parsed.
 *
 * True for: any IPv4 literal in `127.0.0.0/8`; the IPv6 literal `::1` in any
 * legal spelling; and IPv4-mapped loopback `::ffff:127.0.0.0/104` in both the
 * dotted (`::ffff:127.0.0.1`) and hex (`::ffff:7f00:1`) spellings, because a
 * dual-stack listener reports the mapped form and an operator may configure
 * either.
 *
 * False for `0.0.0.0`, `::`, `localhost` and every other host NAME — a name is
 * not an address and its resolution is not this server's to trust — and for a
 * value carrying whitespace, brackets, a port or a zone id.
 */
export function isLoopbackBind(value: string): boolean {
  const family = isIP(value);
  if (family === IPV4_FAMILY) return isIpv4Loopback(value);
  if (family !== IPV6_FAMILY) return false;

  const groups = ipv6Groups(value);
  if (groups === null || groups.length !== IPV6_GROUP_COUNT) return false;
  return isIpv6Loopback(groups) || isMappedIpv4Loopback(groups);
}
