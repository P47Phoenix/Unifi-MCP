/**
 * Planted credential sentinels and the recursive scanner that hunts for them.
 *
 * This is a test HELPER, not a test file — `scripts/run-tests.mjs` discovers
 * tests with a non-recursive `readdirSync('test')`, so nothing under
 * `test/fixtures/` is ever executed as a suite.
 *
 * ## Why the walk is hand-written
 *
 * The obvious implementation — `JSON.stringify(value).includes(SENTINEL)` — is
 * not sufficient, and its insufficiency is exactly the shape of a real leak:
 *
 *  - `Map`, `Set`, symbol keys, non-enumerable properties and `undefined` are
 *    silently dropped by `JSON.stringify`, so a credential in any of them is
 *    invisible to it.
 *  - A `Buffer` serialises as `{"type":"Buffer","data":[83,69,78,...]}` — the
 *    bytes are there, the string is not, and a naive search misses it.
 *  - An `Error` serialises to `{}`. Its `message`, `stack` and `cause` — the
 *    three places an echoed key most plausibly lands — vanish entirely.
 *  - A getter that throws would abort the whole stringify.
 *
 * So the walker below handles each of those explicitly, and fails loudly rather
 * than skipping anything it cannot read: a property that cannot be inspected
 * cannot be proven free of credentials.
 */

// ---------------------------------------------------------------------------
// The planted values
// ---------------------------------------------------------------------------

/**
 * Each value is >= 32 characters, none is a substring of another, and all match
 * ANY_SENTINEL. The length matters: a short marker collides with ordinary text
 * and turns a real assertion into a flaky one.
 */
export const CLOUD_API_KEY_SENTINEL = 'SENTINEL-CLOUD-KEY-c3d4e5f60718293a';
export const LOCAL_API_KEY_SENTINEL = 'SENTINEL-LOCAL-KEY-d4e5f60718293a4b';
export const LABELLED_LOCAL_API_KEY_SENTINEL = 'SENTINEL-LOCAL-EDGE-e5f60718293a4b5c';

/** Shape of every sentinel, for catching a mangled or re-encoded echo. */
export const ANY_SENTINEL = /SENTINEL-[A-Z-]+-[0-9a-f]{16}/;

/** Value keyed by the credential channel it stands in for. */
export const SENTINEL_VALUES: ReadonlyMap<string, string> = new Map([
  ['UNIFI_API_KEY', CLOUD_API_KEY_SENTINEL],
  ['UNIFI_LOCAL_API_KEY', LOCAL_API_KEY_SENTINEL],
  ['UNIFI_LOCAL_API_KEY_EDGE', LABELLED_LOCAL_API_KEY_SENTINEL],
]);

/** RFC 5737 documentation addresses — never routable, never a real console. */
const LOCAL_CONSOLE_HOST = '192.0.2.10';
const LABELLED_LOCAL_CONSOLE_HOST = '192.0.2.11';

/**
 * An environment with every sentinel planted and all four services enabled.
 *
 * Explicitly built rather than derived from `process.env`, so a key that happens
 * to be exported on the developer's machine can neither enable a service nor
 * mask a leak.
 */
export function plantedEnv(
  overrides: Readonly<Record<string, string>> = {},
): NodeJS.ProcessEnv {
  return {
    UNIFI_API_KEY: CLOUD_API_KEY_SENTINEL,
    UNIFI_LOCAL_HOST: LOCAL_CONSOLE_HOST,
    UNIFI_LOCAL_API_KEY: LOCAL_API_KEY_SENTINEL,
    UNIFI_LOCAL_HOST_EDGE: LABELLED_LOCAL_CONSOLE_HOST,
    UNIFI_LOCAL_API_KEY_EDGE: LABELLED_LOCAL_API_KEY_SENTINEL,
    UNIFI_ENABLE_SITE_MANAGER: 'true',
    UNIFI_ENABLE_NETWORK: 'true',
    UNIFI_ENABLE_PROTECT: 'true',
    UNIFI_ENABLE_MOBILITY: 'true',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// The scanner
// ---------------------------------------------------------------------------

/**
 * Depth cap. Reaching it THROWS rather than returning quietly: silently
 * stopping would report "no sentinels found" about a structure the scan never
 * finished reading.
 */
export const MAX_SCAN_DEPTH = 32;

/** Throws when any sentinel is reachable anywhere inside `value`. */
export function scanForSentinels(value: unknown, label = '$'): void {
  walk(value, label, 0, new WeakSet<object>());
}

function walk(value: unknown, path: string, depth: number, seen: WeakSet<object>): void {
  if (depth > MAX_SCAN_DEPTH) {
    throw new Error(
      `Sentinel scan exceeded its depth cap of ${MAX_SCAN_DEPTH} at ${path}. A structure this ` +
        `deep cannot be proven free of credentials, so the scan fails rather than stopping quietly.`,
    );
  }
  if (value === null || value === undefined) return;

  switch (typeof value) {
    case 'string':
      searchText(value, path);
      return;
    case 'number':
    case 'boolean':
    case 'bigint':
    case 'symbol':
    case 'function':
      // The catch-all: anything not structurally handled is searched as text.
      searchText(String(value), path);
      return;
    default:
      break;
  }

  const object = value as object;
  if (seen.has(object)) return;
  seen.add(object);

  if (ArrayBuffer.isView(object)) {
    searchBytes(object, path);
    return;
  }
  if (object instanceof Date || object instanceof RegExp) {
    searchText(String(object), path);
    return;
  }
  if (object instanceof Map) {
    walkMap(object, path, depth, seen);
    return;
  }
  if (object instanceof Set) {
    walkSet(object, path, depth, seen);
    return;
  }
  if (object instanceof Error) {
    walkError(object, path, depth, seen);
    return;
  }
  if (Array.isArray(object)) {
    object.forEach((element, index) => walk(element, `${path}[${index}]`, depth + 1, seen));
    return;
  }

  walkEnumerable(object, path, depth, seen);
}

function walkMap(map: ReadonlyMap<unknown, unknown>, path: string, depth: number, seen: WeakSet<object>): void {
  let index = 0;
  for (const [key, value] of map) {
    walk(key, `${path}.<mapKey ${index}>`, depth + 1, seen);
    walk(value, `${path}.<mapValue ${index}>`, depth + 1, seen);
    index += 1;
  }
}

function walkSet(set: ReadonlySet<unknown>, path: string, depth: number, seen: WeakSet<object>): void {
  let index = 0;
  for (const member of set) {
    walk(member, `${path}.<setMember ${index}>`, depth + 1, seen);
    index += 1;
  }
}

/**
 * `message`, `stack` and `cause` are own NON-enumerable properties, so a
 * for-in walk alone would miss all three — and they are the likeliest place an
 * echoed credential ends up.
 */
function walkError(error: Error, path: string, depth: number, seen: WeakSet<object>): void {
  searchText(error.name, `${path}.name`);
  searchText(error.message, `${path}.message`);
  if (typeof error.stack === 'string') searchText(error.stack, `${path}.stack`);
  walk((error as { cause?: unknown }).cause, `${path}.cause`, depth + 1, seen);

  for (const key of Object.getOwnPropertyNames(error)) {
    if (key === 'name' || key === 'message' || key === 'stack' || key === 'cause') continue;
    walk(readProperty(error, key, path), `${path}.${key}`, depth + 1, seen);
  }
  walkEnumerable(error, path, depth, seen);
}

/** Own AND inherited enumerable string keys — `for..in` is exactly that set. */
function walkEnumerable(object: object, path: string, depth: number, seen: WeakSet<object>): void {
  for (const key in object) {
    // A key name is a channel too: `{ 'SENTINEL-…': true }` leaks just as well.
    searchText(key, `${path}.<key ${key}>`);
    walk(readProperty(object, key, path), `${path}.${key}`, depth + 1, seen);
  }
}

/**
 * Read one property, invoking any getter behind it.
 *
 * A getter that throws FAILS the walk. Swallowing it would leave a property the
 * scan never read while reporting the object clean, which is the precise
 * failure this whole file exists to prevent.
 */
function readProperty(object: object, key: string, path: string): unknown {
  try {
    return (object as Record<string, unknown>)[key];
  } catch (e: unknown) {
    throw new Error(
      `Sentinel scan could not read ${path}.${key}: ${e instanceof Error ? e.message : String(e)}. ` +
        `A property that throws on access cannot be proven free of credentials.`,
    );
  }
}

/** Decode binary as both UTF-8 and Latin-1; a key survives either encoding. */
function searchBytes(view: ArrayBufferView, path: string): void {
  const buffer = Buffer.from(view.buffer, view.byteOffset, view.byteLength);
  searchDecoded(buffer.toString('utf8'), `${path} (bytes decoded as utf8)`);
  searchDecoded(buffer.toString('latin1'), `${path} (bytes decoded as latin1)`);
}

/**
 * Search a string directly and in its Latin-1 re-encoding, which is what a
 * credential looks like after a byte-mangling round trip through a layer that
 * guessed the wrong charset.
 */
function searchText(text: string, path: string): void {
  searchDecoded(text, path);
  const reencoded = Buffer.from(text, 'utf8').toString('latin1');
  if (reencoded !== text) searchDecoded(reencoded, `${path} (latin1 re-encoding)`);
}

function searchDecoded(text: string, path: string): void {
  for (const [channel, value] of SENTINEL_VALUES) {
    if (text.includes(value)) {
      throw new Error(
        `Credential sentinel for ${channel} reached the output at ${path}. NFR-12 requires that ` +
          `no configured key value appear in any tool result, error message, or diagnostic.`,
      );
    }
  }

  const shaped = ANY_SENTINEL.exec(text);
  if (shaped) {
    throw new Error(
      `A sentinel-shaped value (${shaped[0]}) reached the output at ${path}. It is not one of the ` +
        `planted values verbatim, which means a credential was transformed rather than withheld.`,
    );
  }
}
