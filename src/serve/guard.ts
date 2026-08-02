/**
 * Request-guard primitives for the HTTP transport (FR-64, FR-65, FR-66, FR-67,
 * FR-81, R-16).
 *
 * These controls are ours rather than the SDK's, and that is a decision worth
 * recording because the SDK appears to offer all three of them:
 *
 *   - Its `allowedHosts` check exact-matches the FULL `Host` header, port and
 *     all. An operator who lists `example.com` therefore gets a 403 on every
 *     real request, because every real request arrives as `example.com:8787`.
 *     Host validation that rejects the correct configuration is not a control,
 *     it is an outage (FR-64, FR-65).
 *   - All three of its DNS-rebinding options are marked `@deprecated`.
 *   - The non-deprecated replacement it points at is Express-only, and this
 *     server does not mount Express (R-16).
 *
 * So the predicates live here: pure, total, unit-testable without opening a
 * socket, and each one shaped so the dangerous variant is hard to write. The
 * one stateful thing in the module is a closure, not a class, and it takes an
 * injected clock so its tests are deterministic.
 *
 * This module never emits, composes or names a CORS header. There is no
 * response surface here at all, which is what makes the `Origin` rule below
 * safe to state as absolutely as it is stated.
 */
import type { IncomingHttpHeaders } from 'node:http';

import { ipv6Groups, unmapIpv4Mapped } from '../netliteral.js';

/**
 * The four request classes the rest of the server may distinguish. A `Route`
 * rather than a string is itself the control — see `createRouteNormalizer`.
 */
export type Route = 'mcp' | 'healthz' | 'readyz' | 'other';

export const HEALTHZ_ROUTE_PATH = '/healthz';
export const READYZ_ROUTE_PATH = '/readyz';

export const THROTTLE_WINDOW_MS = 60_000;
export const THROTTLE_DEFAULT_CAPACITY = 4096;

/** Source key for a caller whose address is absent or unparseable. */
const UNKNOWN_SOURCE_KEY = '-';
/** Number of leading IPv6 groups that make up a /64. */
const IPV6_PREFIX_GROUPS = 4;
/** Prefix that turns a bare IPv4 literal into its IPv4-mapped IPv6 spelling. */
const IPV4_MAPPED_PREFIX = '::ffff:';

const ASCII_UPPERCASE = /[A-Z]/g;
const MAX_ASCII_CODE_POINT = 0x7f;
const ASCII_CASE_OFFSET = 32;

/** True when every code unit is ASCII; written without a regex escape. */
function isAsciiOnly(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > MAX_ASCII_CODE_POINT) return false;
  }
  return true;
}

/**
 * Lower-case only `A`–`Z`.
 *
 * `toLowerCase`/`toLocaleLowerCase` are locale- and Unicode-aware: in a Turkish
 * locale `I` folds to a dotless `ı`, and Unicode folds `İ` and the Kelvin sign
 * onto ASCII letters. Either behaviour makes a host or a scheme compare equal
 * to something an operator did not write. Protocol tokens are ASCII by
 * definition, so fold ASCII and leave every other code point alone; IDN labels
 * are handled separately, by punycode conversion.
 */
function toAsciiLowerCase(value: string): string {
  return value.replace(ASCII_UPPERCASE, (character) =>
    String.fromCharCode(character.charCodeAt(0) + ASCII_CASE_OFFSET),
  );
}

/**
 * Remove the port from a `Host`-header-shaped value, bracket-aware.
 *
 * A naive `host.split(':')[0]` yields `[` and fails in exactly the default
 * IPv6-loopback bind case — the case every developer hits first.
 *
 * Rule: if the value starts with `[`, the host part ends at the matching `]`
 * inclusive and any port follows it. Otherwise, more than one `:` means a bare
 * unbracketed IPv6 literal, which has no port to strip; a single `:` is a port
 * separator.
 */
function stripPort(value: string): string {
  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    return close === -1 ? value : value.slice(0, close + 1);
  }

  const firstColon = value.indexOf(':');
  if (firstColon === -1) return value;
  if (value.indexOf(':', firstColon + 1) !== -1) return value;
  return value.slice(0, firstColon);
}

/** Drop the one trailing dot a fully-qualified name is allowed to carry. */
function stripRootDot(value: string): string {
  return value.endsWith('.') ? value.slice(0, -1) : value;
}

/**
 * Convert an internationalised name to its punycode (IDNA) form so that a
 * header and an allow-list entry written in different scripts still compare
 * equal. WHATWG `URL` performs the conversion; it throws on inputs it cannot
 * parse, and the fallback is the un-converted value because `hostAllowed` is
 * total and must never throw.
 *
 * Attempted only for non-bracketed, non-ASCII values, so an IPv6 literal or an
 * ordinary ASCII name is never rewritten by the URL parser.
 */
function toPunycode(host: string): string {
  if (host.startsWith('[') || isAsciiOnly(host)) return host;
  try {
    const converted = new URL(`http://${host}`).hostname;
    return converted === '' ? host : converted;
  } catch {
    return host;
  }
}

/** One normalisation, applied identically to the header and to every entry. */
function normalizeHost(value: string): string {
  return toPunycode(stripRootDot(stripPort(toAsciiLowerCase(value))));
}

/**
 * Is this request's `Host` one the operator listed?
 *
 * Port-agnostic on both sides: the header's port is stripped, and so is a port
 * an operator wrote into the allow-list, so `example.com` and
 * `example.com:8787` are the same entry. That is the whole point of not using
 * the SDK's check, which compares the header verbatim including the port.
 *
 * The signature takes a single header value, never a header bag. That is how
 * "no `X-Forwarded-Host`, and no other `X-Forwarded-*` header, is ever
 * consulted" is enforced — structurally, so it cannot lapse by someone reaching
 * for a more convenient field. A forwarded header is attacker-controlled; the
 * `Host` the client actually sent is the only thing worth validating.
 *
 * Decision, recorded deliberately: an empty allow-list returns `false`. This
 * predicate does NOT implement "empty means allow everything". Whether an unset
 * `UNIFI_HTTP_ALLOWED_HOSTS` means "do not perform Host validation at all" is a
 * decision for the request pipeline and the configuration layer, not for this
 * predicate — because folding "empty ⇒ allow all" in here turns an accidentally
 * empty allow-list on a non-loopback bind into an open door, which is precisely
 * what the startup refusal in FR-73(b) exists to prevent.
 */
export function hostAllowed(hostHeader: string | undefined, allow: readonly string[]): boolean {
  if (typeof hostHeader !== 'string' || hostHeader === '') return false;
  if (allow.length === 0) return false;

  const host = normalizeHost(hostHeader);
  if (host === '') return false;

  for (const entry of allow) {
    if (typeof entry !== 'string' || entry === '') continue;
    if (normalizeHost(entry) === host) return true;
  }
  return false;
}

/**
 * Is an `Origin` header present at any value at all?
 *
 * The caller rejects when this is `true`. Reads `headers.origin` only, which is
 * the single joined value Node exposes however many `Origin` headers arrived.
 */
export function hasOrigin(headers: IncomingHttpHeaders): boolean {
  // FR-66: inverts SDK default.
  //
  // The MCP SDK's `StreamableHTTPServerTransport` ALLOWS a request carrying an
  // `Origin` header when `allowedOrigins` is left unconfigured. This server does
  // the OPPOSITE: it REJECTS any request carrying an `Origin` header, at every
  // value — including the empty string and the literal `null` — and there is no
  // Origin allow-list anywhere in this product, nor may one be added.
  //
  // A conforming MCP client is not a browser and sends no `Origin`; its presence
  // is therefore the DNS-rebinding / CSRF case by construction. And this server
  // emits no CORS headers at all, so a browser whose request was accepted still
  // could not read the response — an `Origin` allow-list would be inert, a knob
  // that looks like a control and is not one.
  //
  // Do not "fix" this into an allow-list. Changing it requires amending FR-66.
  //
  // Optional chaining keeps the predicate total even if a caller hands over a
  // header bag that never came from Node.
  return headers?.origin !== undefined;
}

/**
 * Collapse duplicate slashes, resolve `.` and `..`, and drop a trailing slash.
 *
 * Resolution is done by hand rather than by `new URL`, which would accept an
 * absolute-form target and silently discard its authority.
 */
function canonicalizePath(path: string): string {
  const segments = path.split('/');
  const resolved: string[] = [];

  for (const segment of segments) {
    // Empty segments come from duplicate and trailing slashes alike.
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      // Popping past the root is a no-op, not an escape.
      resolved.pop();
      continue;
    }
    resolved.push(segment);
  }
  return `/${resolved.join('/')}`;
}

/**
 * Build the one function that turns a raw request target into a `Route`.
 *
 * The return type is the control. Because the raw target is discarded here and
 * a `Route` — not a string — comes back, no downstream consumer *can* pattern-
 * match on a path, including for logging. That matters because the dangerous
 * implementation of this feature is not one that normalises wrongly; it is one
 * that normalises correctly for routing and then tests the FR-67 probe
 * exemption against the RAW target with `startsWith('/healthz')`. Under that
 * implementation `GET /healthz%2f..%2fmcp` takes the exempt branch and serves
 * the entire tool surface unauthenticated and un-Host-validated. This is the
 * highest-risk line in the feature; normalise once, here, and hand out a
 * closed union.
 *
 * The function is total: every input, including a malformed percent-escape,
 * yields a `Route` and never throws.
 */
export function createRouteNormalizer(mcpPath: string): (rawTarget: string) => Route {
  // Canonicalised once, at factory time, by the same rules the request target
  // gets, so a configured `/mcp/` and a requested `/mcp` are the same route.
  const canonicalMcpPath = canonicalizePath(typeof mcpPath === 'string' ? mcpPath : '');

  return function normalizeRoute(rawTarget: string): Route {
    // An absolute-form target (`GET http://evil.example/healthz`) is legal on
    // the wire, and `new URL(raw, base)` would discard the authority and hand
    // back `/healthz` — the probe route, for a request aimed at another host.
    // Anything that is not an origin-form path is simply not routed.
    if (typeof rawTarget !== 'string' || !rawTarget.startsWith('/')) return 'other';

    const queryIndex = rawTarget.indexOf('?');
    const withoutQuery = queryIndex === -1 ? rawTarget : rawTarget.slice(0, queryIndex);

    let decoded: string;
    try {
      // Exactly once. An uncaught `URIError` from `GET /%c0%af` would throw
      // BEFORE authentication: a remotely triggered, unauthenticated denial of
      // service out of one malformed byte.
      decoded = decodeURIComponent(withoutQuery);
    } catch {
      return 'other';
    }

    // Note what does NOT happen here: a decoded target still containing `%` is
    // not decoded again. That is what makes `/%252568ealthz` fail closed rather
    // than resolve to a probe path after enough rounds of unwrapping.

    // A NUL byte is not a path character. It reaches this point only as an
    // attempt to truncate some later consumer's string, so the request is not
    // routed at all.
    if (decoded.includes('\0')) return 'other';

    const canonical = canonicalizePath(decoded);

    // MCP first, then the probes. FR-73(d) refuses to start when the configured
    // MCP path collides with a probe path, so this tie cannot arise in a
    // running server — but if it ever did, matching MCP first sends the request
    // to the AUTHENTICATED branch rather than the unauthenticated probe branch.
    // That ordering is the fail-closed tiebreak.
    if (canonical === canonicalMcpPath) return 'mcp';
    if (canonical === HEALTHZ_ROUTE_PATH) return 'healthz';
    if (canonical === READYZ_ROUTE_PATH) return 'readyz';
    return 'other';
  };
}

/** Render the /64 prefix of an expanded IPv6 address, deterministically. */
function ipv6Prefix64(groups: readonly number[]): string {
  const prefix: string[] = [];
  for (let index = 0; index < IPV6_PREFIX_GROUPS; index += 1) {
    const group = groups[index];
    if (group === undefined) return UNKNOWN_SOURCE_KEY;
    prefix.push(group.toString(16));
  }
  return `${prefix.join(':')}::/64`;
}

/**
 * The throttle key for a connection's peer address.
 *
 * Takes only `remoteAddress` — never a header bag — because that signature is
 * how "no `X-Forwarded-*` header is consulted" is enforced structurally. A
 * header an attacker controls would let them forge attribution into the
 * operator's forensic record, blaming a chosen third party for their own
 * traffic while evading the throttle themselves.
 *
 * Rules, all of them erring towards over-grouping, which throttles more rather
 * than less:
 *   - absent, non-string or empty → `-`. An attacker can induce an absent
 *     address by sending a request and immediately resetting the socket, so `-`
 *     is a legitimate member of the domain and not an error case.
 *   - a zone id (`%eth0`) is stripped before parsing.
 *   - IPv4-mapped IPv6 folds onto its IPv4 form, so a dual-stack bind and a
 *     v4-only bind produce the same key for the same caller. Without this,
 *     every worked example in the operator contract fails to reproduce.
 *   - IPv6 collapses to its /64, because a single delegated /64 otherwise hands
 *     an attacker 2^64 free source addresses.
 *   - anything unparseable → `-`.
 */
export function sourceKey(remoteAddress: string | undefined): string {
  if (typeof remoteAddress !== 'string') return UNKNOWN_SOURCE_KEY;

  const zoneIndex = remoteAddress.indexOf('%');
  const address = zoneIndex === -1 ? remoteAddress : remoteAddress.slice(0, zoneIndex);
  if (address === '') return UNKNOWN_SOURCE_KEY;

  const groups = ipv6Groups(address);
  if (groups !== null) {
    const mapped = unmapIpv4Mapped(address);
    return mapped ?? ipv6Prefix64(groups);
  }

  // Not IPv6. An IPv4 literal is recognised by asking the shared parser to read
  // its IPv4-mapped spelling, so this module needs no second address validator
  // and cannot disagree with the one the loopback predicate uses.
  return unmapIpv4Mapped(`${IPV4_MAPPED_PREFIX}${address}`) ?? UNKNOWN_SOURCE_KEY;
}

interface ThrottleWindow {
  count: number;
  windowStartMs: number;
}

export interface RejectionThrottle {
  isThrottled(key: string): boolean;
  record(key: string): void;
  size(): number;
}

export interface RejectionThrottleOptions {
  maxPerMinute: number;
  /** Maximum tracked keys; defaults to `THROTTLE_DEFAULT_CAPACITY`. */
  capacity?: number;
  /** Injected clock. Defaults to `Date.now`. */
  now?: () => number;
}

/**
 * A fixed-capacity, fixed-window, LRU-evicting counter of rejected requests.
 *
 * Why this is not the existing outbound limiter — the default assumption on
 * reading "rate limit" in this repository, and wrong three times over:
 *   1. That limiter is an OUTBOUND, QUEUEING limiter: `acquire()` chains onto a
 *      FIFO tail and `consume()` sleeps before admitting. An inbound throttle
 *      must answer 429 immediately; making the attacker wait is making the
 *      server hold their socket open for them.
 *   2. Forcing `maxWaitMs: 0` to stop it queueing makes it throw with outbound
 *      text naming the matching `UNIFI_RATE_LIMIT_*` environment variable and a
 *      `service` that defaults to `site-manager` — outbound diagnostics on an
 *      inbound rejection path.
 *   3. Its bucket map is unbounded and never evicts. Keyed by client address
 *      that is an unauthenticated memory-exhaustion vector, and fails FR-81's
 *      memory bound outright.
 *
 * Usage contract, because the wiring can get this wrong invisibly: the caller
 * increments at THE SINGLE POINT WHERE THE UNIFORM 401 IS EMITTED, whatever the
 * rejection reason — never inside the authentication routine. If only
 * authentication failures increment, then N+1 garbage-token requests to a
 * candidate path yield 429 when the path is the real MCP path and 401 when it
 * is not: one bit per minute per source, parallelisable across a /64, which
 * recovers exactly the fact the uniform rejection exists to hide.
 * Probe-resolving requests are neither counted nor looked up.
 *
 * Honest limits, so nobody mistakes this for the control that protects the
 * secret. Behind a reverse proxy — the recommended deployment shape, because it
 * is the only way to get TLS — `remoteAddress` is the proxy's address for every
 * request and `sourceKey` collapses the entire caller population onto one key,
 * so per-source counting has nothing to count. A distributed or IPv6-mobile
 * attacker is not source-bounded to begin with. And LRU eviction turns that
 * bypass into an eviction attack: someone else's flood evicts a genuine
 * single-source brute-forcer and un-throttles them as a side effect. This is a
 * cost-raiser against a single source with its own address. The controls that
 * protect the secret are its 32-character minimum and its restricted network
 * reach.
 */
export function createRejectionThrottle(options: RejectionThrottleOptions): RejectionThrottle {
  const { maxPerMinute } = options;
  const capacity = options.capacity ?? THROTTLE_DEFAULT_CAPACITY;
  const now = options.now ?? Date.now;

  // Map insertion order IS the LRU order: `record` deletes then re-sets a key to
  // move it to the most-recent end, and eviction takes from the front.
  const windows = new Map<string, ThrottleWindow>();

  function hasExpired(window: ThrottleWindow, atMs: number): boolean {
    return atMs - window.windowStartMs >= THROTTLE_WINDOW_MS;
  }

  function evictOverflow(): void {
    while (windows.size > capacity) {
      const oldest = windows.keys().next();
      if (oldest.done === true) return;
      windows.delete(oldest.value);
    }
  }

  return {
    /**
     * A pure read. It never creates an entry, so an unauthenticated lookup
     * cannot allocate — otherwise the memory bound would depend on the caller's
     * choice of key rather than on `capacity`.
     */
    isThrottled(key: string): boolean {
      const window = windows.get(key);
      if (window === undefined) return false;
      if (hasExpired(window, now())) return false;
      return window.count > maxPerMinute;
    },

    record(key: string): void {
      const atMs = now();
      const existing = windows.get(key);
      const next: ThrottleWindow =
        existing === undefined || hasExpired(existing, atMs)
          ? { count: 1, windowStartMs: atMs }
          : { count: existing.count + 1, windowStartMs: existing.windowStartMs };

      windows.delete(key);
      windows.set(key, next);
      evictOverflow();
    },

    size(): number {
      return windows.size;
    },
  };
}

/**
 * Re-exported, not reimplemented (D-15). The configuration layer imports the
 * predicate from the leaf and the request pipeline imports it from here; both
 * paths resolve to one function, so there is exactly one answer to "is this
 * bind loopback?" in the process.
 */
export { isLoopbackBind } from '../netliteral.js';

/**
 * Re-exported, not reimplemented (D-15) — and for a comparator the rule is
 * sharper than housekeeping: two comparators are two chances to get the
 * constant-time property wrong, and one silently missed fix when only one of
 * them is corrected. `auth.ts` owns the inbound secret's whole lifecycle —
 * resolution, digesting, scrubbing — so it owns the comparison against those
 * digests too; a second copy here would be a security primitive maintained at
 * arm's length from the only module that knows how its operands were made.
 *
 * The request pipeline may keep importing `bearerMatches` from this module:
 * this is where the guard's predicates live, and the specifier resolves to the
 * one function object in the process either way.
 */
export { bearerMatches } from './auth.js';
export type { NonEmptySlots } from './auth.js';
