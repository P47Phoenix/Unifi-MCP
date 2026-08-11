/**
 * The fixture corpus loader and the assertions shared across all four contract
 * suites (US-07).
 *
 * This file is a helper, not a test: it declares no node:test suite or case,
 * and the runner only discovers `*.test.ts` sitting directly in `test/`, so
 * nothing here executes on its own.
 *
 * Two properties are worth stating because they are what the corpus is for.
 * First, fixtures are read by *directory listing*: adding a case is one JSON
 * file and never a test edit, so the cost of covering a newly observed upstream
 * body is a file, not a diff across four suites. Second, every fixture must
 * declare where it came from — `loadFixtureFile` refuses a file with incomplete
 * `$provenance` rather than letting it join the corpus silently, because a
 * fixture nobody can trace back to a spec pointer is a fixture nobody can
 * re-derive when the spec moves.
 */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ServiceId } from '../../src/types.js';

/**
 * The six keys `normalizePage` promises on every result, sorted.
 *
 * This is the single declaration of the page contract. Nothing else — here or
 * in the suites that import it — may re-list these names: the drift-fuzz suite
 * derives its "no promised field disappeared" check from this constant, and a
 * second hand-written copy is exactly the thing that would drift out of step
 * with the first.
 */
export const PAGE_ENVELOPE_KEYS = [
  'items',
  'nextCursor',
  'paginationEmulated',
  'returnedCount',
  'totalCount',
  'truncation',
] as const;

/** The nine keys `normalizeError` promises on every result, sorted. */
export const ERROR_FIELD_KEYS = [
  'category',
  'correlationId',
  'httpStatus',
  'message',
  'origin',
  'recoveryHint',
  'retryAfterSeconds',
  'service',
  'upstreamCode',
] as const;

/** Where a fixture body came from, so a spec bump names what to re-derive. */
export interface FixtureProvenance {
  /** Repo-relative path of the vendored spec, e.g. `specs/network/v10.4.57/openapi.json`. */
  spec: string;
  /** OpenAPI operation the body answers, e.g. `listSites` or `GET /v1/cameras`. */
  operation: string;
  /** JSON pointer to the schema the body was authored against. */
  pointer: string;
  /** What this particular case exercises, in one sentence. */
  note: string;
}

export interface FixtureFile {
  /** Bare file name, e.g. `sites-page1.json`. Stable; suites may switch on it. */
  name: string;
  /** Absolute path, for assertion messages that must name the offending file. */
  path: string;
  provenance: FixtureProvenance;
  /** The response body alone — the `$provenance` wrapper is stripped. */
  body: unknown;
}

/** Page fixtures for `service`, sorted by name. */
export function loadPageFixtures(service: ServiceId): FixtureFile[] {
  return loadDirectory(join(fixturesRoot(), service, 'pages'));
}

/** Error-body fixtures for `service`, sorted by name. */
export function loadErrorFixtures(service: ServiceId): FixtureFile[] {
  return loadDirectory(join(fixturesRoot(), service, 'errors'));
}

/** Read and validate one fixture file. Throws naming the file on any defect. */
export function loadFixtureFile(path: string): FixtureFile {
  const parsed = parseJsonFile(path);
  const name = path.split(/[\\/]/).at(-1) ?? path;
  return {
    name,
    path,
    provenance: readProvenance(parsed, path),
    body: readBody(parsed, path),
  };
}

/**
 * Assert a `normalizePage` result carries exactly the promised envelope.
 *
 * Exactly, not at least: an extra key is drift too — it is a field the tools
 * layer never learned to render, so it reaches nobody.
 */
export function assertPageEnvelope(result: unknown, label: string): void {
  const record = assertPlainObject(result, label);
  assert.deepEqual(
    Object.keys(record).sort(),
    [...PAGE_ENVELOPE_KEYS],
    `${label}: page envelope keys drifted from the promised set`,
  );
  assert.ok(Array.isArray(record.items), `${label}: items must be an array`);
  assert.equal(
    record.returnedCount,
    (record.items as unknown[]).length,
    `${label}: returnedCount must equal items.length`,
  );
  assertNullableType(record.nextCursor, 'string', `${label}: nextCursor`);
  assertNullableType(record.totalCount, 'number', `${label}: totalCount`);
  assert.equal(
    typeof record.paginationEmulated,
    'boolean',
    `${label}: paginationEmulated must be a boolean`,
  );
  assert.ok(
    record.truncation === null || isPlainObject(record.truncation),
    `${label}: truncation must be an object or null`,
  );
}

/**
 * Assert a `normalizeError` result carries exactly the promised nine fields.
 *
 * `message` and `recoveryHint` are checked non-empty because NFR-05 promises a
 * caller always gets something to act on; an empty hint satisfies the shape and
 * fails the requirement.
 */
export function assertErrorEnvelope(normalized: unknown, label: string): void {
  const record = assertPlainObject(normalized, label);
  assert.deepEqual(
    Object.keys(record).sort(),
    [...ERROR_FIELD_KEYS],
    `${label}: error field keys drifted from the promised set`,
  );
  assert.equal(typeof record.category, 'string', `${label}: category must be a string`);
  assert.equal(typeof record.service, 'string', `${label}: service must be a string`);
  assertNonEmptyString(record.message, `${label}: message`);
  assertNonEmptyString(record.recoveryHint, `${label}: recoveryHint`);
  assertNullableType(record.httpStatus, 'number', `${label}: httpStatus`);
  assertNullableType(record.upstreamCode, 'string', `${label}: upstreamCode`);
  assertNullableType(record.correlationId, 'string', `${label}: correlationId`);
  assertNullableType(record.retryAfterSeconds, 'number', `${label}: retryAfterSeconds`);
  assert.ok(
    record.origin === null || record.origin === 'gateway' || record.origin === 'upstream',
    `${label}: origin must be 'gateway', 'upstream' or null`,
  );
}

/**
 * Expand the committed Protect camera template into `count` distinct cameras.
 *
 * The pagination-emulation case needs an array larger than Protect's 500-item
 * page maximum. Committing 500 near-identical cameras would add well over the
 * corpus's entire byte budget in content no reviewer would read, so the shape
 * is committed once and the volume is synthesised from it.
 */
export function syntheticProtectCameras(count: number): Array<Record<string, unknown>> {
  if (!Number.isInteger(count) || count < 0) {
    throw new Error(`syntheticProtectCameras: count must be a non-negative integer, got ${count}`);
  }
  const template = protectCameraTemplate();
  return Array.from({ length: count }, (_, index) => ({
    ...structuredClone(template),
    id: `${SYNTHETIC_ID_PREFIX}${String(index).padStart(6, '0')}`,
    name: `Synthetic Camera ${String(index).padStart(3, '0')}`,
    mac: syntheticMac(index),
  }));
}

/**
 * Restrict `value` to `keys`, keeping only keys that are actually present.
 *
 * Absent keys are omitted rather than set to undefined so that a
 * `deepEqual`-style "no promised field changed" comparison distinguishes a
 * field that vanished from one that was always absent.
 */
export function pickPromisedFields(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  const record = isPlainObject(value) ? value : {};
  const picked: Record<string, unknown> = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(record, key)) picked[key] = record[key];
  }
  return picked;
}

// --- helpers -----------------------------------------------------------------

const PROVENANCE_KEY = '$provenance';
const BODY_KEY = 'body';
const PROVENANCE_FIELDS = ['spec', 'operation', 'pointer', 'note'] as const;
const SYNTHETIC_ID_PREFIX = 'synthetic-camera-';
const PROTECT_TEMPLATE_FIXTURE = 'cameras-page1.json';
const MAC_OCTET_RADIX = 16;
const MAC_OCTET_MODULUS = 256;

/**
 * Fixture root, resolved from this module's own URL.
 *
 * Not `process.cwd()`: the runner spawns from the repo root today, but a suite
 * run from anywhere else would then load nothing and pass vacuously.
 */
function fixturesRoot(): string {
  return fileURLToPath(new URL('.', import.meta.url));
}

function loadDirectory(dir: string): FixtureFile[] {
  return readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => loadFixtureFile(join(dir, name)));
}

function parseJsonFile(path: string): unknown {
  const text = readFileSync(path, 'utf8');
  try {
    return JSON.parse(text) as unknown;
  } catch (e: unknown) {
    const detail = e instanceof Error ? e.message : String(e);
    throw new Error(`Fixture ${path} is not valid JSON: ${detail}`);
  }
}

function readProvenance(parsed: unknown, path: string): FixtureProvenance {
  if (!isPlainObject(parsed)) {
    throw new Error(`Fixture ${path} must be a JSON object wrapping "${PROVENANCE_KEY}".`);
  }
  const raw = parsed[PROVENANCE_KEY];
  if (!isPlainObject(raw)) {
    throw new Error(`Fixture ${path} is missing its "${PROVENANCE_KEY}" block.`);
  }
  for (const field of PROVENANCE_FIELDS) {
    const value = raw[field];
    if (typeof value !== 'string' || value.trim() === '') {
      throw new Error(
        `Fixture ${path} has no "${PROVENANCE_KEY}.${field}". Every fixture must name the spec, ` +
          'operation and pointer it was derived from.',
      );
    }
  }
  return {
    spec: raw.spec as string,
    operation: raw.operation as string,
    pointer: raw.pointer as string,
    note: raw.note as string,
  };
}

function readBody(parsed: unknown, path: string): unknown {
  const record = parsed as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(record, BODY_KEY)) {
    throw new Error(`Fixture ${path} has no "${BODY_KEY}" key.`);
  }
  return record[BODY_KEY];
}

/**
 * The first camera of the committed Protect page, used as the expansion seed.
 *
 * Named explicitly rather than taken as `[0]` of the directory listing: the
 * corpus is read by listing precisely so a new file can be dropped in, and a
 * new file sorting ahead of this one must not silently change what every
 * synthetic camera is a copy of.
 */
function protectCameraTemplate(): Record<string, unknown> {
  const fixture = loadPageFixtures('protect').find((f) => f.name === PROTECT_TEMPLATE_FIXTURE);
  if (fixture === undefined) {
    throw new Error(`Protect page fixtures must include ${PROTECT_TEMPLATE_FIXTURE}.`);
  }
  const [first] = Array.isArray(fixture.body) ? (fixture.body as unknown[]) : [];
  if (!isPlainObject(first)) {
    throw new Error(`${fixture.path} must be a non-empty bare array of camera objects.`);
  }
  return first;
}

function syntheticMac(index: number): string {
  const octets = ['02'];
  for (let shift = 32; shift >= 0; shift -= 8) {
    const octet = Math.floor(index / 2 ** shift) % MAC_OCTET_MODULUS;
    octets.push(octet.toString(MAC_OCTET_RADIX).padStart(2, '0').toUpperCase());
  }
  return octets.join(':');
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertPlainObject(value: unknown, label: string): Record<string, unknown> {
  assert.ok(isPlainObject(value), `${label}: expected a plain object, got ${typeName(value)}`);
  return value;
}

function assertNullableType(value: unknown, expected: string, label: string): void {
  assert.ok(
    value === null || typeof value === expected,
    `${label} must be ${expected} or null, got ${typeName(value)}`,
  );
}

function assertNonEmptyString(value: unknown, label: string): void {
  assert.ok(
    typeof value === 'string' && value.trim() !== '',
    `${label} must be a non-empty string, got ${typeName(value)}`,
  );
}

function typeName(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}
