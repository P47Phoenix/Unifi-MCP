/**
 * Mobility contract tests, driven entirely by the fixture corpus (US-07).
 *
 * Every case below iterates `test/fixtures/mobility/**`, which the loader reads
 * by directory listing, so covering a newly observed upstream body is one JSON
 * file and never an edit here.
 *
 * ## Properties carried here
 *
 * Mobility's own: H-P-1 (FR-23), H-P-4 (FR-23), H-E-1 (FR-24), H-E-4 (FR-25)
 * and H-E-8 (FR-40).
 *
 * Two shared properties live in this file, so a reader looking for them knows
 * where to come:
 *   - **H-P-6** (FR-23, FR-61) — `decodeCursor` is total: it answers null and
 *     never throws for every malformed cursor a caller can hand it. It sits
 *     beside H-P-4 because both are about a cursor a caller controls.
 *   - **H-E-5** (FR-24, NFR-05) — the status-to-category map is exhaustive and
 *     correct, and a body-less error still yields a usable message.
 */
import { strict as assert } from 'node:assert';
import { test, describe } from 'node:test';

import { normalizeError } from '../src/http/errors.js';
import { decodeCursor, encodeCursor, normalizePage, pageQueryParams } from '../src/http/pagination.js';
import type { ServiceId } from '../src/types.js';
import {
  assertErrorEnvelope,
  assertPageEnvelope,
  loadErrorFixtures,
  loadPageFixtures,
  type FixtureFile,
} from './fixtures/load.js';

const SERVICE: ServiceId = 'mobility';

const pages = loadPageFixtures(SERVICE);
const errors = loadErrorFixtures(SERVICE);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fixtureNamed(files: readonly FixtureFile[], name: string): FixtureFile {
  const found = files.find((file) => file.name === name);
  assert.ok(found, `the corpus must contain ${name}`);
  return found;
}

/** The transport status a fixture stands for, read from its file name. */
function statusFromName(name: string): number | null {
  const match = /-(\d{3})(?=[-.])/.exec(name);
  return match === null ? null : Number(match[1]);
}

interface MobilityPageBody {
  total: number;
  offset: number;
  data: unknown[];
}

function pageBody(fixture: FixtureFile): MobilityPageBody {
  const body = fixture.body as MobilityPageBody;
  assert.equal(typeof body.total, 'number', `${fixture.name} must declare a total`);
  assert.equal(typeof body.offset, 'number', `${fixture.name} must declare an offset`);
  assert.ok(Array.isArray(body.data), `${fixture.name} must carry a data array`);
  return body;
}

function hintFor(fixture: FixtureFile): string {
  return normalizeError(SERVICE, statusFromName(fixture.name), fixture.body).recoveryHint;
}

// ---------------------------------------------------------------------------
// H-P-1 (FR-23)
// ---------------------------------------------------------------------------

describe('H-P-1: every Mobility page normalizes to the one envelope (FR-23)', () => {
  for (const fixture of pages) {
    test(`${fixture.name} carries exactly the promised envelope fields`, () => {
      assertPageEnvelope(normalizePage(SERVICE, fixture.body), fixture.name);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(pages.length > 0, 'mobility has no page fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-P-4 (FR-23)
// ---------------------------------------------------------------------------

/** The page size the committed chain was recorded at. */
const CHAIN_PAGE_SIZE = 3;

describe('H-P-4: iteration terminates at offset >= total (FR-23)', () => {
  test('the committed chain is walked once, in order, and then stops', () => {
    // The cap is what makes this a test rather than a hang: a `hasMore` that
    // never goes false would otherwise spin until the runner's timeout and
    // report a timeout instead of naming the defect.
    const iterationCap = pages.length + 1;
    const visited: string[] = [];
    let cursor: string | null = null;
    let iterations = 0;

    for (;;) {
      iterations += 1;
      assert.ok(
        iterations <= iterationCap,
        `paging did not terminate within ${iterationCap} iterations`,
      );

      const fixture = pages[visited.length];
      assert.ok(fixture, 'the cursor asked for a page beyond the committed chain');
      const body = pageBody(fixture);

      // The cursor minted by the previous page must address exactly this one.
      assert.equal(
        decodeCursor(cursor)?.o ?? 0,
        body.offset,
        `${fixture.name} is not the page the previous cursor pointed at`,
      );

      const page = normalizePage(SERVICE, fixture.body, { cursor, pageSize: CHAIN_PAGE_SIZE });
      visited.push(fixture.name);
      assert.equal(page.totalCount, body.total);

      if (page.nextCursor === null) {
        assert.ok(
          body.offset + body.data.length >= body.total,
          `${fixture.name} ended the chain before reaching the declared total`,
        );
        assert.equal(page.truncation, null, 'a complete chain states no truncation');
        break;
      }

      assert.ok(
        body.offset + body.data.length < body.total,
        `${fixture.name} continued the chain after reaching the declared total`,
      );
      cursor = page.nextCursor;
    }

    assert.equal(visited.length, pages.length, 'the walk did not visit every committed page');
    assert.equal(new Set(visited).size, visited.length, 'a page was visited twice');
  });

  test('an empty page terminates even when the total says otherwise', () => {
    // Without this guard a total that never advances loops forever, which is
    // the failure mode the iteration cap above exists to catch.
    const body = { total: 99, offset: 0, limit: CHAIN_PAGE_SIZE, data: [] };
    const page = normalizePage(SERVICE, body, { pageSize: CHAIN_PAGE_SIZE });

    assert.equal(page.returnedCount, 0);
    assert.equal(page.nextCursor, null);
  });
});

// ---------------------------------------------------------------------------
// H-P-6 (FR-23, FR-61) — shared property, hosted here
// ---------------------------------------------------------------------------

/**
 * Every malformed cursor a caller can produce. The cursor is opaque and
 * caller-supplied, which makes it an input surface: `decodeCursor` answering
 * null is a rejected page request, while `decodeCursor` throwing is a crashed
 * tool call.
 */
const MALFORMED_CURSORS: ReadonlyArray<readonly [string, string | null | undefined]> = [
  ['a truncated base64url string', 'eyJzIjoibW9iaW'],
  ['valid base64url of non-JSON', Buffer.from('not json at all', 'utf8').toString('base64url')],
  ['valid JSON with no `s` field', Buffer.from(JSON.stringify({ o: 3 }), 'utf8').toString('base64url')],
  ['valid JSON whose `s` is not a string', Buffer.from(JSON.stringify({ s: 7 }), 'utf8').toString('base64url')],
  ['an empty string', ''],
  ['null', null],
  ['undefined', undefined],
];

const FOREIGN_OFFSET = 42;

describe('H-P-6: an opaque cursor is never a crash vector (FR-23, FR-61)', () => {
  for (const [label, cursor] of MALFORMED_CURSORS) {
    test(`${label} decodes to null without throwing`, () => {
      assert.doesNotThrow(() => decodeCursor(cursor));
      assert.strictEqual(decodeCursor(cursor), null);
    });

    test(`${label} still produces usable query parameters`, () => {
      assert.doesNotThrow(() => pageQueryParams(SERVICE, { cursor }));
      assert.deepEqual(pageQueryParams(SERVICE, { cursor }), { offset: 0, limit: 200 });
    });
  }

  test('a cursor minted for another service names that service, so a caller can tell', () => {
    // `decodeCursor` reports which service the cursor was minted for; it does
    // not itself reject a foreign one, because it has no idea which call it is
    // being decoded for. What it must not do is throw.
    const foreign = encodeCursor({ s: 'protect', o: FOREIGN_OFFSET });
    const state = decodeCursor(foreign);

    assert.ok(state);
    assert.equal(state.s, 'protect');
    assert.notEqual(state.s, SERVICE);
    assert.doesNotThrow(() => pageQueryParams(SERVICE, { cursor: foreign }));
  });
});

// ---------------------------------------------------------------------------
// H-E-1 (FR-24)
// ---------------------------------------------------------------------------

describe('H-E-1: every Mobility error normalizes to the nine promised fields (FR-24)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} carries exactly the promised error fields`, () => {
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assertErrorEnvelope(normalized, fixture.name);
      assert.equal(normalized.service, SERVICE);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(errors.length > 0, 'mobility has no error fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-E-4 (FR-25)
// ---------------------------------------------------------------------------

describe('H-E-4: the presence of a code is what distinguishes gateway from upstream (FR-25)', () => {
  test('a body carrying a code is attributed to the gateway', () => {
    const fixture = fixtureNamed(errors, 'server-error-500.json');
    assert.ok(
      (fixture.body as Record<string, unknown>).code,
      `${fixture.name} no longer carries the code this case is about`,
    );
    assert.equal(normalizeError(SERVICE, 500, fixture.body).origin, 'gateway');
  });

  test('a body carrying no code is attributed to the upstream it passed through', () => {
    const fixture = fixtureNamed(errors, 'upstream-passthrough-502-no-code.json');
    assert.equal(
      Object.prototype.hasOwnProperty.call(fixture.body as object, 'code'),
      false,
      `${fixture.name} no longer omits the code this case is about`,
    );
    assert.equal(normalizeError(SERVICE, 502, fixture.body).origin, 'upstream');
  });

  for (const fixture of errors) {
    test(`${fixture.name} attributes an origin by that same rule`, () => {
      const code = (fixture.body as Record<string, unknown>).code;
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assert.equal(normalized.origin, code ? 'gateway' : 'upstream');
    });
  }
});

// ---------------------------------------------------------------------------
// H-E-8 (FR-40)
// ---------------------------------------------------------------------------

describe('H-E-8: a 403 caused by a missing app scope says so, and says how (FR-40)', () => {
  test('the scope-triggered hint names the scope and how to regenerate the key', () => {
    const hint = hintFor(fixtureNamed(errors, 'forbidden-403-app-scope.json'));

    assert.match(hint, /scope/i, 'the hint must name what is missing');
    assert.match(hint, /mobility/, 'the hint must name which scope is missing');
    assert.match(hint, /regenerate/i, 'naming the gap without the remedy is half an answer');
  });

  test('a generic 403 enumerates all three causes rather than guessing one', () => {
    const hint = hintFor(fixtureNamed(errors, 'forbidden-403-generic.json'));

    // Guessing would send the user to the wrong console, so when the body does
    // not disambiguate, all three fixes are named.
    assert.match(hint, /\(1\)/);
    assert.match(hint, /\(2\)/);
    assert.match(hint, /\(3\)/);
    assert.match(hint, /scope/i);
    assert.match(hint, /admin/i);
    assert.match(hint, /subscription/i);
  });

  test('the two hints are distinct, so the specific one is not the generic one', () => {
    const scoped = hintFor(fixtureNamed(errors, 'forbidden-403-app-scope.json'));
    const generic = hintFor(fixtureNamed(errors, 'forbidden-403-generic.json'));

    assert.notEqual(scoped, generic);
    assert.equal(/\(3\)/.test(scoped), false, 'a diagnosed 403 must not fall back to the list');
  });

  test('each committed 403 cause yields its own hint', () => {
    // Read by listing, so a newly observed 403 phrasing joins this case by
    // being committed rather than by being named here.
    const forbidden = errors.filter((fixture) => fixture.name.startsWith('forbidden-403'));
    assert.ok(forbidden.length > 1, 'the corpus must carry more than one 403 phrasing');

    const hints = forbidden.map(hintFor);
    assert.equal(
      new Set(hints).size,
      hints.length,
      'two distinct 403 causes produced the same remediation',
    );
  });
});

// ---------------------------------------------------------------------------
// H-E-5 (FR-24, NFR-05) — shared property, hosted here
// ---------------------------------------------------------------------------

/**
 * The whole status-to-category map, including a status it does not name.
 *
 * 418 is in the table on purpose: an unmapped 4xx must still land somewhere a
 * caller can act on, and "somewhere" is a decision worth pinning rather than
 * discovering in production.
 */
const STATUS_CATEGORIES: ReadonlyArray<readonly [number, string]> = [
  [400, 'bad_request'],
  [401, 'unauthorized'],
  [403, 'forbidden'],
  [404, 'not_found'],
  [408, 'timeout'],
  [413, 'payload_too_large'],
  [418, 'bad_request'],
  [422, 'bad_request'],
  [429, 'rate_limit'],
  [500, 'server_error'],
  [502, 'server_error'],
  [503, 'server_error'],
  [504, 'server_error'],
];

const NO_STATUS_CATEGORY = 'network';

describe('H-E-5: the status-to-category map is exhaustive and correct (FR-24, NFR-05)', () => {
  for (const [status, category] of STATUS_CATEGORIES) {
    test(`HTTP ${status} is categorised as ${category}`, () => {
      // An empty body leaves the status as the only signal, which is the point:
      // any per-service code table would otherwise mask the map under test.
      const normalized = normalizeError(SERVICE, status, {});
      assert.equal(normalized.category, category);
      assert.equal(normalized.httpStatus, status);
    });
  }

  test('no status at all is a network failure, not a server failure', () => {
    assert.equal(normalizeError(SERVICE, null, null).category, NO_STATUS_CATEGORY);
  });

  for (const [label, status] of [
    ['a status', 503],
    ['no status', null],
  ] as ReadonlyArray<readonly [string, number | null]>) {
    test(`a body-less error with ${label} still yields the fallback sentence`, () => {
      const normalized = normalizeError(SERVICE, status, undefined);
      assert.equal(
        normalized.message,
        `${SERVICE} returned HTTP ${status ?? 'no status'} with no parseable error body.`,
      );
      assert.notEqual(normalized.recoveryHint.trim(), '');
    });
  }
});
