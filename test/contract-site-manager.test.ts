/**
 * Site Manager contract tests, driven entirely by the fixture corpus (US-07).
 *
 * Every case below iterates `test/fixtures/site-manager/**`, which the loader
 * reads by directory listing. Covering a newly observed upstream body is one
 * JSON file dropped into the corpus and never an edit here — which is the only
 * arrangement under which "we cover what upstream actually sends" can stay true
 * as upstream moves.
 *
 * ## Properties carried here
 *
 * Site Manager's own: H-P-1, H-P-2 (FR-23), H-E-1, H-E-2 (FR-24) and the Site
 * Manager half of H-E-4 (FR-25).
 *
 * Three shared properties live in this file, so a reader looking for them knows
 * where to come:
 *   - **H-P-7** (FR-49, NFR-07) — truncation is stated with counts and a
 *     narrowing suggestion, and an untruncated response says nothing at all.
 *   - **H-E-6** (NFR-05) — an HTML error body is never forwarded, and an
 *     oversized raw string body is sliced.
 *   - **H-E-7** (FR-26, NFR-05) — `Retry-After` rendering, and `toolError`'s
 *     exact line shape over every error fixture of every service. It sits here
 *     because Site Manager is the service whose fixtures carry a `Retry-After`
 *     worked example, and because the rendering is shared, not per-service.
 */
import { strict as assert } from 'node:assert';
import { test, describe } from 'node:test';

import { z } from 'zod';

import { normalizeError, toolError, type ToolErrorResult } from '../src/http/errors.js';
import {
  clampPageSize,
  decodeCursor,
  normalizePage,
  pageQueryParams,
} from '../src/http/pagination.js';
import { truncationMessage, truncationNotice } from '../src/safety/truncate.js';
import { LIST_SITES } from '../src/tools/definitions.js';
import { SERVICE_IDS, type NormalizedError, type ServiceId, type TruncationNotice } from '../src/types.js';
import {
  assertErrorEnvelope,
  assertPageEnvelope,
  loadErrorFixtures,
  loadPageFixtures,
  type FixtureFile,
} from './fixtures/load.js';

const SERVICE: ServiceId = 'site-manager';

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

/**
 * The transport status a fixture stands for, read from its file name.
 *
 * Taking it from the name rather than a table keeps the corpus additive: a new
 * `forbidden-403-something.json` is exercised at 403 with no edit here. A
 * degenerate fixture that names no status is normalized with a null status,
 * which is itself a case worth covering — the body then has to supply
 * everything, or the fallback does.
 */
function statusFromName(name: string): number | null {
  const match = /-(\d{3})(?=[-.])/.exec(name);
  return match === null ? null : Number(match[1]);
}

function stringField(body: unknown, key: string): string {
  const value = (body as Record<string, unknown>)[key];
  assert.equal(typeof value, 'string', `fixture body must carry a string \`${key}\``);
  return value as string;
}

function textOf(result: ToolErrorResult): string {
  const [block] = result.content;
  assert.ok(block, 'a tool error must carry one text block');
  return block.text;
}

/**
 * The lines `toolError` promises, in order, with the prefixes it promises.
 *
 * Restated here rather than derived from the renderer: an expectation built by
 * calling the code under test would accept whatever that code did. The dash in
 * the first line is U+2014 EM DASH with a space either side.
 */
function expectedToolErrorLines(e: NormalizedError): string[] {
  const status = e.httpStatus ? ` — HTTP ${e.httpStatus}` : '';
  const lines = [`${e.service} request failed (${e.category}${status}).`, `Message: ${e.message}`];
  if (e.upstreamCode) lines.push(`Upstream code: ${e.upstreamCode}`);
  if (e.origin) lines.push(`Origin: ${e.origin}`);
  if (e.correlationId) lines.push(`Correlation id: ${e.correlationId}`);
  if (e.retryAfterSeconds !== null) lines.push(`Retry-After: ${e.retryAfterSeconds}s`);
  lines.push(`Next step: ${e.recoveryHint}`);
  return lines;
}

// ---------------------------------------------------------------------------
// H-P-1 (FR-23)
// ---------------------------------------------------------------------------

describe('H-P-1: every Site Manager page normalizes to the one envelope (FR-23)', () => {
  for (const fixture of pages) {
    test(`${fixture.name} carries exactly the promised envelope fields`, () => {
      assertPageEnvelope(normalizePage(SERVICE, fixture.body), fixture.name);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(pages.length > 0, 'site-manager has no page fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-P-2 (FR-23)
// ---------------------------------------------------------------------------

/** Deliberately not the schema default, so a lost page size shows up as drift. */
const REQUESTED_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 500;
const OVER_MAX_PAGE_SIZE = 501;

describe('H-P-2: the nextToken chain round-trips through the opaque cursor (FR-23)', () => {
  const firstPage = fixtureNamed(pages, 'sites-page1.json');
  const terminalPage = fixtureNamed(pages, 'sites-page2.json');

  test('page 1 carries its nextToken into the cursor', () => {
    const token = stringField(firstPage.body, 'nextToken');
    const page = normalizePage(SERVICE, firstPage.body, { pageSize: REQUESTED_PAGE_SIZE });

    assert.notEqual(page.nextCursor, null, 'a non-empty nextToken must mint a cursor');
    assert.equal(decodeCursor(page.nextCursor)?.s, SERVICE);
    assert.equal(decodeCursor(page.nextCursor)?.t, token);
  });

  test('feeding that cursor back yields the same token and the same page size', () => {
    const token = stringField(firstPage.body, 'nextToken');
    const page = normalizePage(SERVICE, firstPage.body, { pageSize: REQUESTED_PAGE_SIZE });

    // `pageSize` is a STRING on this API's wire format; a number would still
    // serialise but would not be the shape the spec declares.
    assert.deepEqual(pageQueryParams(SERVICE, { cursor: page.nextCursor }), {
      pageSize: String(REQUESTED_PAGE_SIZE),
      nextToken: token,
    });
  });

  test('the terminal page ends the chain', () => {
    const page = normalizePage(SERVICE, terminalPage.body, { pageSize: REQUESTED_PAGE_SIZE });
    assert.equal(page.nextCursor, null, 'an absent nextToken must end the chain');
    assert.equal(page.truncation, null, 'a complete page states no truncation');
  });

  test('an over-large page_size is rejected in-schema, before any URL is built', () => {
    // `inputSchema` is a raw shape, so exercising it means wrapping it — which
    // is exactly what the MCP layer does before a handler ever runs.
    const schema = z.object(LIST_SITES.inputSchema);
    assert.equal(schema.safeParse({ page_size: OVER_MAX_PAGE_SIZE }).success, false);
    assert.equal(schema.safeParse({ page_size: MAX_PAGE_SIZE }).success, true);
  });

  test('a page size that reaches the transport layer is clamped rather than sent on', () => {
    assert.equal(clampPageSize(SERVICE, OVER_MAX_PAGE_SIZE), MAX_PAGE_SIZE);
  });
});

// ---------------------------------------------------------------------------
// H-E-1 (FR-24)
// ---------------------------------------------------------------------------

describe('H-E-1: every Site Manager error normalizes to the nine promised fields (FR-24)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} carries exactly the promised error fields`, () => {
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assertErrorEnvelope(normalized, fixture.name);
      assert.equal(normalized.service, SERVICE);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(errors.length > 0, 'site-manager has no error fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-E-2 (FR-24)
// ---------------------------------------------------------------------------

/**
 * A mirror of the private `SITE_MANAGER_CATEGORIES` table in
 * `src/http/errors.ts`.
 *
 * That table is module-private on purpose — it is how the mapper decides, not
 * something callers may depend on — so it cannot be imported and is restated
 * here. Restating it is the point: if the production table gains, loses or
 * remaps a key, the category assertions below stop agreeing with it.
 */
const UPPERCASE_TABLE: ReadonlyArray<readonly [string, string]> = [
  ['BAD_REQUEST', 'bad_request'],
  ['UNAUTHORIZED', 'unauthorized'],
  ['FORBIDDEN', 'forbidden'],
  ['NOT_FOUND', 'not_found'],
  ['RATE_LIMIT', 'rate_limit'],
  ['SERVER_ERROR', 'server_error'],
  ['BAD_GATEWAY', 'server_error'],
];

/**
 * A status the status map sends to `bad_request` and nothing else.
 *
 * Pairing it with each table code means a mapper that ignored the table would
 * answer `bad_request` for all seven, so six of the seven rows below fail on a
 * table miss. `BAD_REQUEST` is the one row where table and status agree; it is
 * still listed because the assertion that matters for every row is that the
 * code survives verbatim.
 */
const UNMAPPED_STATUS = 418;

/**
 * The lowercase, PascalCase and mixed codes the vendored spec's own examples
 * emit. None of them is a key of the uppercase table, so each falls through to
 * the status map — the resulting category is asserted rather than assumed, so
 * that the fall-through is pinned behaviour and not an accident nobody noticed.
 */
const SPEC_CODES: ReadonlyArray<readonly [string, number, string]> = [
  ['unauthorized', 401, 'unauthorized'],
  ['parameter_invalid', 400, 'bad_request'],
  ['forbidden', 403, 'forbidden'],
  ['not_found', 404, 'not_found'],
  // The one authentic code that DOES hit the uppercase table.
  ['NOT_FOUND', 404, 'not_found'],
  ['rate_limit', 429, 'rate_limit'],
  ['server_error', 500, 'server_error'],
  ['bad_gateway', 502, 'server_error'],
  ['DeviceTimeout', 408, 'timeout'],
];

function siteManagerBody(code: string): Record<string, unknown> {
  return { code, message: `synthetic body for ${code}`, traceId: 'trace-0d1f2a3b' };
}

describe('H-E-2: the upstream code survives verbatim (FR-24)', () => {
  for (const [code, category] of UPPERCASE_TABLE) {
    test(`${code} is categorised from the code table and handed back unchanged`, () => {
      const normalized = normalizeError(SERVICE, UNMAPPED_STATUS, siteManagerBody(code));
      assert.equal(normalized.category, category);
      // Byte-identical: a mapper that categorised correctly while rewriting or
      // dropping the code has destroyed the only string a user can quote to
      // Ubiquiti support.
      assert.strictEqual(normalized.upstreamCode, code);
    });
  }

  for (const [code, status, category] of SPEC_CODES) {
    test(`${code} misses the table, falls through to HTTP ${status}, and is still handed back unchanged`, () => {
      const normalized = normalizeError(SERVICE, status, siteManagerBody(code));
      assert.equal(normalized.category, category);
      assert.strictEqual(normalized.upstreamCode, code);
    });
  }

  for (const fixture of errors) {
    test(`${fixture.name} preserves whatever code it actually carries`, () => {
      const code = (fixture.body as Record<string, unknown>).code;
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assert.strictEqual(normalized.upstreamCode, typeof code === 'string' ? code : null);
    });
  }
});

// ---------------------------------------------------------------------------
// H-E-4, Site Manager half (FR-25)
// ---------------------------------------------------------------------------

describe('H-E-4: Site Manager states no origin (FR-25)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} yields origin null`, () => {
      // Only Mobility distinguishes a gateway failure from a passed-through
      // one. Inventing an origin here would be a claim the envelope cannot
      // support.
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assert.strictEqual(normalized.origin, null);
    });
  }
});

// ---------------------------------------------------------------------------
// H-P-7 (FR-49, NFR-07) — shared property, hosted here
// ---------------------------------------------------------------------------

const TRUNCATION_REASONS: ReadonlyArray<TruncationNotice['reason']> = [
  'page_size',
  'payload_ceiling',
  'field_projection',
];

const RETURNED_COUNT = 10;
const TOTAL_COUNT = 847;

describe('H-P-7: truncation is stated with counts and a suggestion, or not at all (FR-49, NFR-07)', () => {
  for (const reason of TRUNCATION_REASONS) {
    test(`${reason} states both counts and what to do about them`, () => {
      const notice = truncationNotice(RETURNED_COUNT, TOTAL_COUNT, reason);
      assert.ok(notice, `${reason} withheld data and must say so`);
      assert.equal(notice.returned, RETURNED_COUNT);
      assert.equal(notice.total, TOTAL_COUNT);
      assert.equal(notice.reason, reason);
      assert.match(notice.message, new RegExp(`\\b${RETURNED_COUNT}\\b`));
      assert.match(notice.message, new RegExp(`\\b${TOTAL_COUNT}\\b`));
      // A count with no advice leaves the reader knowing they are missing
      // something and not how to stop missing it.
      assert.match(notice.message, /\b(refine|request|narrow)\b/i);
    });

    test(`${reason} says nothing when the response was complete`, () => {
      assert.equal(truncationNotice(TOTAL_COUNT, TOTAL_COUNT, reason), null);
      assert.equal(truncationMessage(TOTAL_COUNT, TOTAL_COUNT, reason), '');
    });

    test(`${reason} still states the returned count when the total is unknown`, () => {
      const notice = truncationNotice(RETURNED_COUNT, null, reason);
      assert.ok(notice, 'an unknown total is not a reason to stay silent');
      assert.equal(notice.total, null);
      assert.match(notice.message, new RegExp(`\\b${RETURNED_COUNT}\\b`));
    });
  }
});

// ---------------------------------------------------------------------------
// H-E-6 (NFR-05) — shared property, hosted here
// ---------------------------------------------------------------------------

/** A CDN refusal page: the classic body an API client never asked for. */
const CLOUDFLARE_HTML = [
  '<!DOCTYPE html>',
  '<html><head><title>Attention Required! | Cloudflare</title></head>',
  '<body><h1>Sorry, you have been blocked</h1>',
  '<p>You are unable to access this site. Ray ID: 8f2c1d4e5a6b7c8d</p>',
  '</body></html>',
].join('\n');

const HTML_STATUS = 403;
const RAW_BODY_LIMIT = 500;
const RAW_BODY_STATUS = 502;

describe('H-E-6: an HTML body is never forwarded, and a raw body is bounded (NFR-05)', () => {
  for (const [label, body] of [
    ['a bare HTML document', CLOUDFLARE_HTML],
    ['HTML behind leading whitespace', `\n\n   ${CLOUDFLARE_HTML}`],
  ] as ReadonlyArray<readonly [string, string]>) {
    test(`${label} is replaced by the fallback sentence`, () => {
      const normalized = normalizeError(SERVICE, HTML_STATUS, body);
      assert.equal(
        normalized.message,
        `${SERVICE} returned HTTP ${HTML_STATUS} with no parseable error body.`,
      );
      // Belt and braces: markup reaching a model's context is a prompt surface,
      // not merely noise.
      assert.equal(normalized.message.includes('<'), false);
      assert.equal(normalized.message.includes('Cloudflare'), false);
      assert.equal(normalized.message.includes('Ray ID'), false);
    });
  }

  test('a multi-kilobyte plain-text body is sliced to the documented bound', () => {
    const body = 'the upstream proxy could not reach the target device; retrying. '.repeat(50);
    assert.ok(body.length > 2000, 'the source body must be big enough to be worth slicing');

    const normalized = normalizeError(SERVICE, RAW_BODY_STATUS, body);
    assert.equal(normalized.message.length, RAW_BODY_LIMIT);
    assert.equal(normalized.message, body.trim().slice(0, RAW_BODY_LIMIT));
  });
});

// ---------------------------------------------------------------------------
// H-E-7 (FR-26, NFR-05) — shared property, hosted here
// ---------------------------------------------------------------------------

const RETRY_AFTER_SECONDS = 5;

describe('H-E-7: every error renders an actionable, exactly-shaped tool error (FR-26, NFR-05)', () => {
  test('Retry-After becomes a number and a rendered line', () => {
    const fixture = fixtureNamed(errors, 'rate-limit-429.json');
    const normalized = normalizeError(SERVICE, 429, fixture.body, {
      'retry-after': String(RETRY_AFTER_SECONDS),
    });

    assert.equal(normalized.retryAfterSeconds, RETRY_AFTER_SECONDS);
    assert.ok(
      textOf(toolError(normalized)).split('\n').includes(`Retry-After: ${RETRY_AFTER_SECONDS}s`),
      'the wait a caller must observe has to appear in the text, not only in the struct',
    );
  });

  // Deliberately every service, not only this one: the renderer is shared, and
  // a per-service copy of this loop would be four chances to check three.
  for (const service of SERVICE_IDS) {
    for (const fixture of loadErrorFixtures(service)) {
      test(`${service}/${fixture.name} renders exactly the promised lines`, () => {
        const normalized = normalizeError(service, statusFromName(fixture.name), fixture.body);
        assert.notEqual(normalized.recoveryHint.trim(), '', 'every error owes the caller a next step');

        const lines = textOf(toolError(normalized)).split('\n');
        assert.deepEqual(lines, expectedToolErrorLines(normalized));
        assert.ok(
          lines.some((line) => line.startsWith('Next step: ')),
          'the next step is the line a reader continues from',
        );
      });
    }
  }
});
