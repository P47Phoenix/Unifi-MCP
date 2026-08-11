/**
 * The inbound bearer secret and its whole lifecycle (US-12; FR-64, FR-73,
 * FR-78, FR-81, NFR-19).
 *
 * This module is a LEAF on purpose: it imports `node:crypto` and `node:fs` and
 * nothing else, from this project or from `node_modules`. That is not tidiness
 * — it is what lets a unit test exercise the whole secret lifecycle with no
 * filesystem, no config layer and no transport, and it is what makes "the
 * plaintext never escapes this module" a property of the module graph rather
 * than of review.
 *
 * ## The ordering that makes this safe (architecture §1.2 / §1.4)
 *
 * `buildRuntimeCore` is synchronous and runs, in this order:
 *
 *  1. `resolveBearerSlots(env, deps)` — file first, environment second.
 *     Produces the slot digests and a secret-free descriptor.
 *  2. `loadConfig(env, { repoRoot, auth: descriptor })` — the DESCRIPTOR lands
 *     on `config.serving.auth` and carries no secret material.
 *  3. `validateConfig(config, env)` — all five FR-73 refusals, FR-81's floor and
 *     FR-78's three delivery refusals, in one place, before anything binds.
 *  4-5. Capture the UniFi credential variables into a private object; construct
 *     `CredentialStore` / `UnifiClient`.
 *  6. Scrub: delete both credential classes' keys from the environment object
 *     the core was handed — including all four inbound-secret variables, which
 *     is why `INBOUND_SECRET_ENV_KEYS` is exported from here. The plaintext is
 *     dropped; only the 32-byte digests survive.
 *
 * ## Residency
 *
 * `RuntimeCore.auth` holds the digests. `startHttp(core)` closes over
 * `core.auth` and the comparator receives it as an argument. A digest is never
 * on `ServerConfig`, never in a log line, never in a response, never in
 * `redactedSummary()`'s output. The DESCRIPTOR is safe on `ServerConfig`
 * because it is an enum, two integers and two lists of strings that name
 * variables and paths — never content.
 *
 * ## Why `auth` can be null
 *
 * `AuthMode` has exactly two arms and neither of them can express "mode is
 * bearer but resolution failed". Inventing a zero-slot arm would BE the
 * fail-open branch this design exists to forbid, so instead `auth` is `null`
 * whenever `descriptor.problems` is non-empty, and only then. `bearerMatches`
 * takes a `NonEmptySlots`, so "no slots configured" cannot reach the comparison
 * at all.
 *
 * ## Echoed values
 *
 * A local `echoValue` implements the contract §2.2 ceiling because importing
 * `sanitizeUntrusted` from `src/safety/sanitize.ts` would break the leaf rule.
 * `validateConfig` may re-render these strings through the real
 * `sanitizeUntrusted`; that is idempotent over what `echoValue` already
 * produced. Only `UNIFI_HTTP_AUTH` is ever echoed. A token value is never
 * echoed at any length — not its content, not its length, not a prefix, not its
 * digest. A path IS echoed in full, which FR-78 permits.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';

/** FR-81's floor, in characters of the resolved plaintext. */
export const MIN_SECRET_LENGTH = 32;

/**
 * The 4 KiB cap on a `*_FILE` payload, compared against the RAW bytes read.
 * Exactly 4096 bytes is accepted; 4097 is refused. A file bigger than this is
 * almost always a certificate or a key bundle pointed at the wrong variable.
 */
export const MAX_SECRET_FILE_BYTES = 4096;

/**
 * The four variables this module owns. Step 6 of `buildRuntimeCore` deletes
 * these from the environment object it was handed; the list lives here because
 * this module is the only reader of them.
 */
export const INBOUND_SECRET_ENV_KEYS: readonly string[] = [
  'UNIFI_HTTP_TOKEN',
  'UNIFI_HTTP_TOKEN_NEXT',
  'UNIFI_HTTP_TOKEN_FILE',
  'UNIFI_HTTP_TOKEN_NEXT_FILE',
];

/** Contract §2.2: a scalar value is echoed only at 16 characters or fewer. */
const MAX_ECHOED_VALUE_LENGTH = 16;

/** A tuple that cannot be empty, so the fail-open branch is unrepresentable. */
export type NonEmptySlots = readonly [Buffer, ...Buffer[]];

/** Exactly two arms. There is deliberately no "bearer with zero slots". */
export type AuthMode =
  | { readonly kind: 'bearer'; readonly slots: NonEmptySlots }
  | { readonly kind: 'none' };

/** Where a slot's plaintext came from, in resolution order. */
export type SecretSource = 'env' | 'file';

/**
 * Everything the configuration layer is allowed to know about the inbound
 * secret. Carries no digest and no plaintext, which is what makes it safe to
 * place on `ServerConfig` and to serialise.
 */
export interface BearerDescriptor {
  readonly mode: 'bearer' | 'none';
  /** 0, 1 or 2. */
  readonly slotCount: number;
  readonly sources: readonly SecretSource[];
  /** 0 when no slot resolved. Never rendered into a message. */
  readonly minSlotLength: number;
  /** Fatal. Names variables and paths only — never content. */
  readonly problems: readonly string[];
  /**
   * Non-fatal. Added to the pinned architecture shape because the descriptor is
   * the only channel back to `validateConfig`, which keeps separate `errors`
   * and `warnings` arrays, and the §3.7 permissions finding is a warning.
   */
  readonly warnings: readonly string[];
}

export interface BearerResolution {
  /** `null` exactly when `descriptor.problems` is non-empty. */
  readonly auth: AuthMode | null;
  readonly descriptor: BearerDescriptor;
}

/** A `{ plain, file }` variable pair that supports both delivery mechanisms. */
export interface SecretEnvPair {
  readonly plain: string;
  readonly file: string;
}

/**
 * The outcome of resolving one `{ plain, file }` pair.
 *
 * `value` is the PLAINTEXT. The caller digests it immediately and lets it go
 * out of scope; nothing here is retained, and no caller may store it on a
 * longer-lived object.
 */
export interface FileBackedSecret {
  readonly value: string | null;
  readonly source: SecretSource | null;
  readonly problems: string[];
  readonly warnings: string[];
}

const PRIMARY_PAIR: SecretEnvPair = { plain: 'UNIFI_HTTP_TOKEN', file: 'UNIFI_HTTP_TOKEN_FILE' };
const SECONDARY_PAIR: SecretEnvPair = {
  plain: 'UNIFI_HTTP_TOKEN_NEXT',
  file: 'UNIFI_HTTP_TOKEN_NEXT_FILE',
};

const AUTH_MODE_ENV_KEY = 'UNIFI_HTTP_AUTH';

/** C0, DEL, C1, and the bidi overrides/embeddings and isolates. */
const UNPRINTABLE = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

/** ASCII whitespace only: space, tab, CR, LF. */
const ASCII_SPACE_EDGES = /^[ \t\r\n]+|[ \t\r\n]+$/g;

/** RFC 7235 makes the scheme token case-insensitive; some clients send `bearer`. */
const BEARER_SCHEME = 'bearer';

/** SHA-256 of `plaintext`, always 32 bytes. Exported so tests can build slots. */
export function digestSecret(plaintext: string): Buffer {
  return createHash('sha256').update(plaintext, 'utf8').digest();
}

/**
 * Compare an `Authorization` header value against every configured slot.
 *
 * @remarks
 * Architecture §5.2 lists this function under `src/serve/guard.ts`, which is
 * story US-10's. It lives here because US-12's own acceptance criterion names
 * it, because `auth.ts` must stay a leaf so `test/serve-auth.test.ts` can reach
 * an implementation at all, and because this module owns the whole lifecycle of
 * the digests being compared. `guard.ts` accordingly re-exports this symbol
 * rather than defining a second copy — two comparators is two chances to get
 * the constant-time property wrong, and one of them silently missed when the
 * other is fixed. `test/serve-guard.test.ts` asserts the two specifiers resolve
 * to the same function object, so a second copy cannot reappear unnoticed.
 *
 * The caller reads `headers.authorization` only, never `rawHeaders`: this
 * function takes the single header value as a string, and duplicate
 * `Authorization` headers are a transport-level refusal, not something to
 * reconcile here.
 *
 * @param compare - Injected only so FR-64's spy criterion is expressible; Node
 * 20 has no `mock.module`. Inert in production and adds no branch.
 */
export function bearerMatches(
  presented: string | undefined,
  slots: NonEmptySlots,
  compare: (a: Buffer, b: Buffer) => boolean = timingSafeEqual,
): boolean {
  // Before any hashing: `createHash().update(undefined)` throws, and a 500 to an
  // unauthenticated caller is a class-detection oracle.
  if (typeof presented !== 'string') return false;

  const credential = credentialFromAuthorization(presented);
  if (credential === null) return false;

  // Hashing equalises both operands to 32 bytes unconditionally. Comparing raw
  // operands would make the presented length an oracle AND would make a
  // wrong-length guess throw ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH.
  const candidate = digestSecret(credential);

  let matched = false;
  // `|| matched`, never `matched ||`: the latter short-circuits and makes the
  // number of configured slots observable — a rotation-window side channel.
  for (const slot of slots) matched = compare(candidate, slot) || matched;
  return matched;
}

/**
 * Resolve both inbound secret slots, file first and environment second.
 *
 * Pure over `env`: this function never reads and never mutates `process.env`.
 * Each resolved plaintext is digested immediately and dropped; only the 32-byte
 * digests and a secret-free descriptor survive the call.
 */
export function resolveBearerSlots(
  env: NodeJS.ProcessEnv,
  readFile: (p: string) => Buffer = readFileSync,
): BearerResolution {
  const mode = parseAuthMode(env[AUTH_MODE_ENV_KEY]);
  if (mode.kind === 'invalid') return refusedResolution([mode.problem]);
  if (mode.kind === 'none') return noneResolution();

  return resolveBearerMode(env, readFile);
}

/**
 * Resolve one `{ plain, file }` pair: file delivery first, environment second.
 *
 * Generic by design — architecture §5.15.1b applies this same helper to the
 * credential pairs (`UNIFI_API_KEY` / `UNIFI_API_KEY_FILE` and the local
 * console keys) in story US-16, so every rule below — the 4 KiB cap, the single
 * trailing newline, the both-set refusal, the permissions warning — is
 * implemented once.
 *
 * The returned `value` is PLAINTEXT: digest it at the call site and let it go.
 */
export function resolveFileBackedSecret(
  env: NodeJS.ProcessEnv,
  pair: SecretEnvPair,
  readFile: (p: string) => Buffer = readFileSync,
): FileBackedSecret {
  const plain = env[pair.plain];
  const path = env[pair.file];
  const hasPlain = isSet(plain);
  const hasFile = isSet(path);

  if (hasPlain && hasFile) {
    return absent([bothSetProblem(pair)]);
  }
  if (hasFile && path !== undefined) {
    return readSecretFile(pair, path, readFile);
  }
  if (hasPlain && plain !== undefined) {
    return { value: plain, source: 'env', problems: [], warnings: [] };
  }
  return absent([]);
}

/** The `_FILE` suffix reserved across the `UNIFI_LOCAL_API_KEY_` family. */
export const RESERVED_FILE_SUFFIX = '_FILE';

/**
 * True for a local console label the `_FILE` reservation makes unaddressable.
 *
 * PRD §5.15.1b, Disambiguation rule, normative: "Within the
 * `UNIFI_LOCAL_API_KEY_` family the trailing `_FILE` suffix is reserved. A key
 * of the form `UNIFI_LOCAL_API_KEY_<LABEL>_FILE` is file delivery for console
 * `<LABEL>` and is never a key for a console named `<LABEL>_FILE`;
 * `UNIFI_LOCAL_API_KEY_FILE` is file delivery for the default console and is
 * never a key for a console named `FILE`. Consequently a local console whose
 * label is `FILE`, or whose label ends in `_FILE`, is unaddressable and is
 * refused at startup with an error naming `UNIFI_LOCAL_HOST_<LABEL>` and the
 * reservation — a refusal, not a warning, because the alternative is a console
 * whose key can be set but never read."
 *
 * `FILENAME` and `MYFILE` are unaffected: the reservation is the suffix
 * `_FILE`, plus the bare label `FILE`.
 *
 * Enforcing this inside `src/config.ts` is story US-16's work. This module owns
 * only the leaf predicate and the message, unit-tested here and ready to be
 * consumed — nothing in `config.ts` is changed by this story.
 */
export function isReservedConsoleLabel(label: string): boolean {
  return label === 'FILE' || label.endsWith(RESERVED_FILE_SUFFIX);
}

/** The refusal for a console label the `_FILE` reservation makes unaddressable. */
export function reservedConsoleLabelProblem(label: string): string {
  return (
    `UNIFI_LOCAL_HOST_${label} names a console whose label is unaddressable: the trailing ` +
    `${RESERVED_FILE_SUFFIX} suffix is reserved for file delivery, so UNIFI_LOCAL_API_KEY_${label} ` +
    `would be read as a file path for another console and this console's key could be set but ` +
    `never read. Rename the console to a label that is not FILE and does not end in ` +
    `${RESERVED_FILE_SUFFIX}.`
  );
}

// --- internals ---------------------------------------------------------------

type ParsedAuthMode =
  | { readonly kind: 'bearer' }
  | { readonly kind: 'none' }
  | { readonly kind: 'invalid'; readonly problem: string };

/**
 * Contract §2.5.1, fail-closed. Trim ASCII whitespace, fold ASCII case, then
 * compare against exactly two constants. Every other value — including the
 * empty string after trimming — is a refusal, because a parser that falls back
 * on an unrecognised token turns a typo into an open listener. Unset resolves
 * to the default, `bearer`.
 *
 * Note for US-14: contract §2.5's example refusal echoes `"None "`, which reads
 * as though that value were unrecognised. It is not, under the normalisation
 * the same contract pins in §2.5.1 — step (1) strips the trailing space and
 * step (2) folds the case, so `"None "` is the constant `none`, exactly as
 * `" none "` and `"NONE"` are. The numbered algorithm is implemented here; if
 * `"None "` really must be refused, step (1) has to go, and `" bearer "` goes
 * with it.
 */
function parseAuthMode(raw: string | undefined): ParsedAuthMode {
  if (raw === undefined) return { kind: 'bearer' };

  const normalized = asciiLowerCase(raw.replace(ASCII_SPACE_EDGES, ''));
  if (normalized === 'bearer') return { kind: 'bearer' };
  if (normalized === 'none') return { kind: 'none' };

  return {
    kind: 'invalid',
    problem:
      `${AUTH_MODE_ENV_KEY}="${echoValue(raw)}" must be \`bearer\` or \`none\`. \`bearer\` requires ` +
      `callers to present ${PRIMARY_PAIR.plain}; \`none\` disables inbound authentication entirely ` +
      `and is accepted only on a loopback UNIFI_HTTP_BIND.`,
  };
}

/**
 * `auth=none`, architecture §5.7: no token variable is read even if one is set,
 * so a stale secret alongside `none` cannot masquerade as a configured slot.
 */
function noneResolution(): BearerResolution {
  return {
    auth: { kind: 'none' },
    descriptor: {
      mode: 'none',
      slotCount: 0,
      sources: [],
      minSlotLength: 0,
      problems: [],
      warnings: [],
    },
  };
}

/** A refusal that never reached slot resolution. `auth` is null by definition. */
function refusedResolution(problems: readonly string[]): BearerResolution {
  return {
    auth: null,
    descriptor: {
      mode: 'bearer',
      slotCount: 0,
      sources: [],
      minSlotLength: 0,
      problems,
      warnings: [],
    },
  };
}

function resolveBearerMode(
  env: NodeJS.ProcessEnv,
  readFile: (p: string) => Buffer,
): BearerResolution {
  const problems: string[] = [];
  const warnings: string[] = [];
  const sources: SecretSource[] = [];
  const slots: Buffer[] = [];
  let minSlotLength = 0;

  for (const pair of [PRIMARY_PAIR, SECONDARY_PAIR]) {
    const resolved = resolveFileBackedSecret(env, pair, readFile);
    problems.push(...resolved.problems);
    warnings.push(...resolved.warnings);
    if (resolved.value === null || resolved.source === null) continue;

    const variable = resolved.source === 'file' ? pair.file : pair.plain;
    if (resolved.value.length < MIN_SECRET_LENGTH) problems.push(shortSecretProblem(variable));

    minSlotLength =
      slots.length === 0 ? resolved.value.length : Math.min(minSlotLength, resolved.value.length);
    sources.push(resolved.source);
    slots.push(digestSecret(resolved.value));
  }

  if (slots.length === 0 && problems.length === 0) problems.push(noSecretProblem());

  const nonEmpty = toNonEmptySlots(slots);
  const auth: AuthMode | null =
    problems.length > 0 || nonEmpty === null ? null : { kind: 'bearer', slots: nonEmpty };

  return {
    auth,
    descriptor: {
      mode: 'bearer',
      slotCount: slots.length,
      sources,
      minSlotLength,
      problems,
      warnings,
    },
  };
}

/**
 * The only place a zero-slot tuple can be rejected, so `{ kind: 'bearer' }` can
 * never be constructed without at least one digest.
 */
function toNonEmptySlots(slots: readonly Buffer[]): NonEmptySlots | null {
  const [first, ...rest] = slots;
  return first === undefined ? null : [first, ...rest];
}

function readSecretFile(
  pair: SecretEnvPair,
  path: string,
  readFile: (p: string) => Buffer,
): FileBackedSecret {
  let bytes: Buffer;
  try {
    bytes = readFile(path);
  } catch {
    return absent([unreadableProblem(pair, path)]);
  }

  const warnings = exposedFilePermissionWarnings(pair, path);
  if (bytes.byteLength > MAX_SECRET_FILE_BYTES) {
    return { value: null, source: null, problems: [oversizeProblem(pair, path)], warnings };
  }

  const value = stripOneTrailingNewline(bytes.toString('utf8'));
  if (value === '') {
    return { value: null, source: null, problems: [emptyProblem(pair, path)], warnings };
  }

  return { value, source: 'file', problems: [], warnings };
}

/** Exactly one trailing newline, and no other transformation whatsoever. */
function stripOneTrailingNewline(text: string): string {
  return text.endsWith('\n') ? text.slice(0, -1) : text;
}

/**
 * Contract §3.7. Best effort by construction: the pinned two-parameter
 * signature offers no stat seam, mode bits are meaningless on Windows, and a
 * stat failure must never become a refusal.
 */
function exposedFilePermissionWarnings(pair: SecretEnvPair, path: string): string[] {
  if (process.platform === 'win32') return [];
  try {
    if ((statSync(path).mode & 0o077) !== 0) return [permissionsWarning(pair, path)];
  } catch {
    // Unreadable metadata is not evidence of exposure; stay silent.
  }
  return [];
}

function absent(problems: string[]): FileBackedSecret {
  return { value: null, source: null, problems, warnings: [] };
}

function isSet(raw: string | undefined): boolean {
  return raw !== undefined && raw !== '';
}

/** ASCII case folding only — no locale, no Unicode special casing. */
function asciiLowerCase(value: string): string {
  return value.replace(/[A-Z]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 32));
}

/**
 * The scheme prefix, matched ASCII-case-insensitively, followed by EXACTLY one
 * space. The remainder is taken verbatim and is NOT trimmed — trimming would be
 * a second normalisation, so `Bearer  S` presents ` S` and does not match `S`.
 */
function credentialFromAuthorization(header: string): string | null {
  if (header.length <= BEARER_SCHEME.length) return null;
  if (header[BEARER_SCHEME.length] !== ' ') return null;
  if (asciiLowerCase(header.slice(0, BEARER_SCHEME.length)) !== BEARER_SCHEME) return null;
  return header.slice(BEARER_SCHEME.length + 1);
}

/**
 * Contract §2.2's echoed-value ceiling, implemented locally because importing
 * `sanitizeUntrusted` would break the leaf rule. Used for `UNIFI_HTTP_AUTH`
 * only: no refusal echoes a value whose role is `secret` or `path`.
 */
function echoValue(raw: string): string {
  const cleaned = raw.replace(UNPRINTABLE, '');
  return cleaned.length <= MAX_ECHOED_VALUE_LENGTH ? cleaned : `(${raw.length} characters)`;
}

function bothSetProblem(pair: SecretEnvPair): string {
  return `${pair.plain} and ${pair.file} are both set and only one secret can be live. Set exactly one.`;
}

function unreadableProblem(pair: SecretEnvPair, path: string): string {
  return (
    `${pair.file}=${path} is not readable. Set it to a path this process can read, or set ` +
    `${pair.plain} instead.`
  );
}

function emptyProblem(pair: SecretEnvPair, path: string): string {
  return (
    `${pair.file}=${path} is empty. Write the shared secret into that file, or set ${pair.plain} ` +
    `instead.`
  );
}

function oversizeProblem(pair: SecretEnvPair, path: string): string {
  return (
    `${pair.file}=${path} is larger than the 4 KiB maximum. It should contain the shared secret ` +
    `and nothing else; check you have not pointed it at a certificate or a key bundle.`
  );
}

function permissionsWarning(pair: SecretEnvPair, path: string): string {
  return (
    `${pair.file}=${path} is readable by group or other. Restrict it to the process user; a ` +
    `secret file on a shared volume is the exposure the *_FILE mechanism exists to avoid.`
  );
}

/** Names the delivering variable, which is the one the operator has to change. */
function shortSecretProblem(variable: string): string {
  return (
    `${variable} is shorter than the ${MIN_SECRET_LENGTH}-character minimum. Generate one with ` +
    '`openssl rand -base64 32` or an equivalent CSPRNG; a guessable secret on a reachable port is ' +
    'the same as no secret.'
  );
}

function noSecretProblem(): string {
  return (
    `${PRIMARY_PAIR.plain} is not set and ${AUTH_MODE_ENV_KEY}=bearer requires a secret. Set ` +
    `${PRIMARY_PAIR.plain} or ${PRIMARY_PAIR.file}, or set ${AUTH_MODE_ENV_KEY}=none on a ` +
    `loopback UNIFI_HTTP_BIND.`
  );
}
