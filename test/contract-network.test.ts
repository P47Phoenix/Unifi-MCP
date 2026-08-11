/**
 * Network contract tests, driven by the fixture corpus and the large estate
 * (US-07).
 *
 * The page and error cases iterate `test/fixtures/network/**`, read by
 * directory listing, so a newly observed upstream body is one JSON file and
 * never an edit here.
 *
 * ## Properties carried here
 *
 * Network's own: H-P-1, H-P-3 (FR-23), H-E-1, H-E-2 (FR-24) and the Network
 * half of H-E-4 (FR-25).
 *
 * The Network half of the large-estate properties H-LE-1 … H-LE-5 (FR-51,
 * FR-50, NFR-07, NFR-08). The Protect half lives in `contract-protect.test.ts`.
 *
 * ## H-LE-5 is structural, not a timeout override
 *
 * The estate is generated ONCE at module load, below, and every case reuses it.
 * Six thousand clients take a few hundred milliseconds to build; regenerating
 * per case would multiply that by the number of cases and would eventually meet
 * the runner's 60 000 ms per-test timeout. Meeting the deadline by raising it
 * would prove nothing, so there is deliberately no per-test `{ timeout }` here.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test, describe } from 'node:test';
import { fileURLToPath } from 'node:url';

import { z } from 'zod';

import { loadConfig } from '../src/config.js';
import type { UnifiClient, UnifiResponse } from '../src/http/client.js';
import { normalizeError } from '../src/http/errors.js';
import {
  PAGE_LIMITS,
  clampPageSize,
  decodeCursor,
  normalizePage,
  pageQueryParams,
} from '../src/http/pagination.js';
import { buildRegistry, type SpecManifest } from '../src/registry/build.js';
import {
  DEFAULT_PROJECTIONS,
  EFFECTIVE_CEILING_CHARS,
  PAYLOAD_CEILING_CHARS,
  TOKEN_CEILING,
  estimateTokens,
  projectFields,
  projectionFor,
} from '../src/safety/truncate.js';
import { LIST_CLIENTS, advertisedTools, type ToolDefinition } from '../src/tools/definitions.js';
import { createHandlers, type ToolResult } from '../src/tools/handlers.js';
import type { Action, ServiceId } from '../src/types.js';
import {
  assertErrorEnvelope,
  assertPageEnvelope,
  loadErrorFixtures,
  loadPageFixtures,
  type FixtureFile,
} from './fixtures/load.js';
import { largeEstate } from './fixtures/large-estate/generate.mjs';

const SERVICE: ServiceId = 'network';

/** The resource whose default projection the promoted client tool applies. */
const RESOURCE = 'client';

const pages = loadPageFixtures(SERVICE);
const errors = loadErrorFixtures(SERVICE);

/** H-LE-5: generated once, at module load, and reused by every case below. */
const { clients } = largeEstate();

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

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

function textOf(result: ToolResult): string {
  const [block] = result.content;
  assert.ok(block, 'a tool result must carry one text block');
  return block.text;
}

/** The `{count, data, limit, offset, totalCount}` envelope this API returns. */
function clientPage(offset: number, limit: number): Record<string, unknown> {
  const data = clients.slice(offset, offset + limit);
  return { count: data.length, data, limit, offset, totalCount: clients.length };
}

// ---------------------------------------------------------------------------
// H-P-1 (FR-23)
// ---------------------------------------------------------------------------

describe('H-P-1: every Network page normalizes to the one envelope (FR-23)', () => {
  for (const fixture of pages) {
    test(`${fixture.name} carries exactly the promised envelope fields`, () => {
      assertPageEnvelope(normalizePage(SERVICE, fixture.body), fixture.name);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(pages.length > 0, 'network has no page fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-P-3 (FR-23)
// ---------------------------------------------------------------------------

const CHAIN_PAGE_SIZE = 3;
const MAX_PAGE_SIZE = 200;
const OVER_MAX_PAGE_SIZE = 201;
const SITE_ID = 'site-4f2a9c10';

describe('H-P-3: offset, limit and total round-trip through the opaque cursor (FR-23)', () => {
  const firstPage = fixtureNamed(pages, 'clients-page1.json');
  const secondPage = fixtureNamed(pages, 'clients-page2.json');

  test('the envelope total becomes totalCount', () => {
    const page = normalizePage(SERVICE, firstPage.body, { pageSize: CHAIN_PAGE_SIZE });
    const body = firstPage.body as { totalCount: number; count: number };
    assert.equal(page.totalCount, body.totalCount);
    assert.equal(page.returnedCount, body.count);
    assert.equal(page.paginationEmulated, false, 'this API pages natively');
  });

  test('count, limit and offset survive the cursor round trip', () => {
    const body = firstPage.body as { offset: number; count: number };
    const page = normalizePage(SERVICE, firstPage.body, { pageSize: CHAIN_PAGE_SIZE });
    const state = decodeCursor(page.nextCursor);

    assert.ok(state, 'an incomplete chain must mint a cursor');
    assert.equal(state.s, SERVICE);
    assert.equal(state.o, body.offset + body.count);
    assert.equal(state.l, CHAIN_PAGE_SIZE);
  });

  test('the cursor becomes offset/limit query parameters and never a pageSize', () => {
    const page = normalizePage(SERVICE, firstPage.body, { pageSize: CHAIN_PAGE_SIZE });
    const params = pageQueryParams(SERVICE, { cursor: page.nextCursor });

    assert.deepEqual(params, { offset: CHAIN_PAGE_SIZE, limit: CHAIN_PAGE_SIZE });
    // `pageSize` is Site Manager's spelling. Sending it here would be a silent
    // no-op the caller could not detect.
    assert.equal(Object.prototype.hasOwnProperty.call(params, 'pageSize'), false);
  });

  test('the chain terminates when offset plus count reaches the total', () => {
    const first = normalizePage(SERVICE, firstPage.body, { pageSize: CHAIN_PAGE_SIZE });
    const second = normalizePage(SERVICE, secondPage.body, { cursor: first.nextCursor });

    assert.equal(second.nextCursor, null);
    assert.equal(second.truncation, null);
    assert.equal(first.returnedCount + second.returnedCount, second.totalCount);
  });

  test('an over-large page_size is rejected in-schema, before any URL is built', () => {
    const schema = z.object(LIST_CLIENTS.inputSchema);
    // `site_id` is required, so it is supplied on both sides: without it both
    // parses would fail and the assertion would pass for the wrong reason.
    assert.equal(
      schema.safeParse({ site_id: SITE_ID, page_size: OVER_MAX_PAGE_SIZE }).success,
      false,
    );
    assert.equal(schema.safeParse({ site_id: SITE_ID, page_size: MAX_PAGE_SIZE }).success, true);
  });

  test('a page size that reaches the transport layer is clamped rather than sent on', () => {
    assert.equal(clampPageSize(SERVICE, OVER_MAX_PAGE_SIZE), MAX_PAGE_SIZE);
  });
});

// ---------------------------------------------------------------------------
// H-E-1 (FR-24)
// ---------------------------------------------------------------------------

describe('H-E-1: every Network error normalizes to the nine promised fields (FR-24)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} carries exactly the promised error fields`, () => {
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assertErrorEnvelope(normalized, fixture.name);
      assert.equal(normalized.service, SERVICE);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(errors.length > 0, 'network has no error fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-E-2 (FR-24)
// ---------------------------------------------------------------------------

/**
 * Dotted codes are an open-ended namespace, so only the leading segment is
 * interpreted. Each row names the fixture that carries it, so the expectation
 * is checked against a body the spec actually documents rather than one written
 * to match the implementation.
 */
const DOTTED_PREFIXES: ReadonlyArray<readonly [string, string, string]> = [
  ['unauthorized-401-missing-credentials.json', 'api.authentication.missing-credentials', 'unauthorized'],
  ['forbidden-403.json', 'api.authorization.insufficient-permissions', 'forbidden'],
  ['rate-limit-429.json', 'api.rate-limit.exceeded', 'rate_limit'],
];

describe('H-E-2: dotted codes map by prefix and survive verbatim (FR-24)', () => {
  for (const [name, code, category] of DOTTED_PREFIXES) {
    test(`${code} maps to ${category} and is handed back unchanged`, () => {
      const fixture = fixtureNamed(errors, name);
      assert.equal(
        (fixture.body as Record<string, unknown>).code,
        code,
        `${name} no longer carries the code this case is about`,
      );

      const normalized = normalizeError(SERVICE, statusFromName(name), fixture.body);
      assert.equal(normalized.category, category);
      // The whole dotted string, not the prefix that was matched: the trailing
      // segment is the part a user quotes to support.
      assert.strictEqual(normalized.upstreamCode, code);
    });
  }

  test('a code outside the prefix table does not over-match and is still preserved', () => {
    const fixture = fixtureNamed(errors, 'not-found-404.json');
    const code = (fixture.body as Record<string, unknown>).code;
    const normalized = normalizeError(SERVICE, 404, fixture.body);

    assert.equal(normalized.category, 'not_found', 'the status supplies what the prefix cannot');
    assert.strictEqual(normalized.upstreamCode, code);
  });

  for (const fixture of errors) {
    test(`${fixture.name} preserves whatever code it actually carries`, () => {
      const code = (fixture.body as Record<string, unknown>).code;
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assert.strictEqual(normalized.upstreamCode, typeof code === 'string' ? code : null);
    });
  }
});

// ---------------------------------------------------------------------------
// H-E-4, Network half (FR-25)
// ---------------------------------------------------------------------------

describe('H-E-4: Network states no origin (FR-25)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} yields origin null`, () => {
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assert.strictEqual(normalized.origin, null);
    });
  }
});

// ---------------------------------------------------------------------------
// The large estate (FR-51, FR-50, NFR-07, NFR-08)
// ---------------------------------------------------------------------------

describe('H-LE-1: the Network estate is genuinely large (FR-51)', () => {
  test('the generated client list is the size the requirement describes', () => {
    // Asserted on the FIXTURE, not on a response: an estate that silently shrank
    // would leave every ceiling assertion below passing while proving nothing.
    assert.ok(clients.length > 5000, `only ${clients.length} clients generated`);
    assert.ok(
      Buffer.byteLength(JSON.stringify(clients)) > 4 * 1024 * 1024,
      'the client estate no longer serialises to megabytes',
    );
  });
});

/**
 * A `UnifiClient` stand-in that answers with the large estate.
 *
 * It honours the `offset`/`limit` the production layer put in the request
 * arguments, because this API pages natively: a stub that returned all six
 * thousand clients regardless would be testing a server the upstream is not.
 */
function largeEstateClient(): UnifiClient {
  const request = async (_action: Action, args: Record<string, unknown> = {}): Promise<UnifiResponse> => {
    const offset = Number(args.offset ?? 0);
    const limit = Number(args.limit ?? PAGE_LIMITS[SERVICE].default);
    return { status: 200, body: clientPage(offset, limit), headers: new Headers() };
  };

  // `UnifiClient` is a class with private fields, so a structurally identical
  // object is not assignable to it. The cast is confined to this one line and
  // it is honest: `request` is the only method the handlers call, implemented
  // here with the same signature.
  return { request } as unknown as UnifiClient;
}

const enabledServices = new Set<ServiceId>([SERVICE]);
const manifest = JSON.parse(
  readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'),
) as SpecManifest;
const registry = buildRegistry(REPO_ROOT, manifest, enabledServices);
const handlers = createHandlers({
  config: loadConfig({}, { repoRoot: REPO_ROOT }),
  client: largeEstateClient(),
  actions: registry.actions,
  byId: registry.byId,
});

/**
 * The read tools this service actually contributes to the advertised surface.
 *
 * Computed from `advertisedTools` — the same function `tools/list` uses — so a
 * tool added to the surface is exercised here automatically. A hand-listed set
 * would be a second copy of the surface, and the copy is what goes stale.
 */
const readSurface = advertisedTools(enabledServices, new Set<ServiceId>()).filter(
  (tool) => tool.requiresService === SERVICE,
);

/**
 * The largest `page_size` a tool's own schema accepts — the worst case for the
 * ceiling. Probed rather than restated, so a definition that raised its cap is
 * exercised at the new cap without an edit here.
 */
function largestAcceptedPageSize(tool: ToolDefinition, baseArgs: Record<string, unknown>): number {
  const schema = z.object(tool.inputSchema);
  const accepts = (size: number): boolean =>
    schema.safeParse({ ...baseArgs, page_size: size }).success;

  assert.ok(accepts(1), `${tool.name} rejects even the smallest page size`);
  let low = 1;
  let high = PAGE_LIMITS[SERVICE].max;
  if (accepts(high)) return high;
  while (high - low > 1) {
    const mid = Math.floor((low + high) / 2);
    if (accepts(mid)) low = mid;
    else high = mid;
  }
  return low;
}

describe('H-LE-2: every Network read tool stays under the ceilings (FR-51, NFR-08)', () => {
  test('the computed surface is not empty, so the cases below are not vacuous', () => {
    assert.ok(readSurface.length > 0, `${SERVICE} contributes no tools to the surface`);
    for (const tool of readSurface) {
      assert.equal(tool.annotations.readOnlyHint, true, `${tool.name} is not a read tool`);
    }
  });

  for (const tool of readSurface) {
    test(`${tool.name} answers under the ceilings against six thousand clients`, async () => {
      const handler = handlers[tool.name];
      assert.ok(handler, `${tool.name} is advertised but createHandlers supplies no handler`);

      const baseArgs = { site_id: SITE_ID };
      const result = await handler({
        ...baseArgs,
        page_size: largestAcceptedPageSize(tool, baseArgs),
      });

      // A handler that errored would also be "under the ceiling"; requiring a
      // real answer is what keeps the ceiling assertions meaningful.
      assert.notEqual(result.isError, true, `${tool.name} failed instead of answering`);
      const text = textOf(result);

      assert.ok(
        text.length <= EFFECTIVE_CEILING_CHARS,
        `${tool.name} returned ${text.length} characters, over the ${EFFECTIVE_CEILING_CHARS} ceiling`,
      );
      assert.ok(
        text.length < PAYLOAD_CEILING_CHARS,
        `${tool.name} returned ${text.length} characters, over the ${PAYLOAD_CEILING_CHARS} client ceiling`,
      );
      assert.ok(
        estimateTokens(text) <= TOKEN_CEILING,
        `${tool.name} returned about ${estimateTokens(text)} tokens, over the ${TOKEN_CEILING} ceiling`,
      );
    });
  }
});

const PROJECTION_PAGE_SIZE = 200;

describe('H-LE-3: projection is what keeps a Network page under the ceiling (FR-50)', () => {
  test('the same page is over the ceiling unprojected and under it projected', () => {
    const page = normalizePage(SERVICE, clientPage(0, PROJECTION_PAGE_SIZE), {
      pageSize: PROJECTION_PAGE_SIZE,
    });
    assert.equal(page.returnedCount, PROJECTION_PAGE_SIZE);

    const projection = projectionFor(RESOURCE);
    assert.ok(projection, `${RESOURCE} must have a default projection`);

    const unprojected = JSON.stringify(page.items);
    const projected = JSON.stringify(projectFields(page.items as object[], projection));

    assert.ok(
      unprojected.length > EFFECTIVE_CEILING_CHARS,
      `unprojected page is only ${unprojected.length} characters, so projection proves nothing`,
    );
    assert.ok(
      projected.length < EFFECTIVE_CEILING_CHARS,
      `projected page is ${projected.length} characters, still over the ceiling`,
    );
  });

  test('the projected field set is the documented default for the resource', () => {
    const projection = projectionFor(RESOURCE);
    assert.ok(projection);
    assert.deepEqual([...projection], [...(DEFAULT_PROJECTIONS[RESOURCE] ?? [])]);

    const page = normalizePage(SERVICE, clientPage(0, PROJECTION_PAGE_SIZE), {
      pageSize: PROJECTION_PAGE_SIZE,
    });
    for (const item of projectFields(page.items as object[], projection)) {
      assert.deepEqual(Object.keys(item).sort(), [...projection].sort());
    }
  });
});

describe('H-LE-4: a truncated Network response states what was withheld (FR-49, NFR-07)', () => {
  test('both the item counts and a narrowing suggestion survive the cut', async () => {
    const handler = handlers[LIST_CLIENTS.name];
    assert.ok(handler);

    const [sample] = clients;
    assert.ok(sample, 'the estate must carry at least one client');

    // Projection forced off by asking for every field the item has: this is the
    // response that genuinely exceeds the character ceiling.
    const result = await handler({
      site_id: SITE_ID,
      page_size: PROJECTION_PAGE_SIZE,
      fields: Object.keys(sample),
    });
    const text = textOf(result);

    assert.ok(text.length <= EFFECTIVE_CEILING_CHARS, `returned ${text.length} characters`);
    // Counts of what came back and of what exists, in the first line.
    assert.match(
      text,
      new RegExp(`Showing ${PROJECTION_PAGE_SIZE} of ${clients.length}\\b`),
      'the response must state how much of the collection it is',
    );
    // Counts of the characters withheld, plus what to do about it.
    assert.match(text, /Showing \d+ of \d+ characters\./);
    assert.match(text, /narrow/i);
  });
});

describe('H-LE-5: the Network estate case fits the runner budget (NFR-08)', () => {
  test('a second use of the estate costs nothing, because it is memoized', () => {
    // The property is structural: `largeEstate()` is called once at module load
    // and returns the same arrays thereafter, so no case pays to rebuild it.
    assert.strictEqual(largeEstate().clients, clients);
  });
});
