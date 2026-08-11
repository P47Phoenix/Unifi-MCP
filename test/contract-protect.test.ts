/**
 * Protect contract tests, driven by the fixture corpus and the large estate
 * (US-07).
 *
 * The page and error cases iterate `test/fixtures/protect/**`, read by
 * directory listing, so a newly observed upstream body is one JSON file and
 * never an edit here.
 *
 * ## Properties carried here
 *
 * Protect's own: H-P-1, H-P-5 (FR-23, FR-36, FR-37), H-E-1, H-E-3 (FR-24) and
 * the Protect half of H-E-4 (FR-25).
 *
 * The Protect half of the large-estate properties H-LE-1 … H-LE-5 (FR-51,
 * FR-50, NFR-07, NFR-08). The Network half lives in `contract-network.test.ts`.
 *
 * ## H-LE-5 is structural, not a timeout override
 *
 * The estate is generated ONCE at module load, below, and every case reuses it.
 * Six thousand cameras serialise to over 10 MB; regenerating them per case
 * would multiply a few hundred milliseconds by the number of cases and would
 * eventually meet the runner's 60 000 ms per-test timeout. Meeting the deadline
 * by raising it would prove nothing, so there is deliberately no per-test
 * `{ timeout }` here.
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
import { PAGE_LIMITS, decodeCursor, normalizePage } from '../src/http/pagination.js';
import { buildRegistry, type SpecManifest } from '../src/registry/build.js';
import {
  DEFAULT_PROJECTIONS,
  EFFECTIVE_CEILING_CHARS,
  PAYLOAD_CEILING_CHARS,
  TOKEN_CEILING,
  applyPayloadCeiling,
  estimateTokens,
  projectFields,
  projectionFor,
  truncationMessage,
} from '../src/safety/truncate.js';
import { LIST_CAMERAS, advertisedTools, type ToolDefinition } from '../src/tools/definitions.js';
import { createHandlers, type ToolResult } from '../src/tools/handlers.js';
import type { Action, ServiceId } from '../src/types.js';
import {
  assertErrorEnvelope,
  assertPageEnvelope,
  loadErrorFixtures,
  loadPageFixtures,
  syntheticProtectCameras,
} from './fixtures/load.js';
import { largeEstate } from './fixtures/large-estate/generate.mjs';

const SERVICE: ServiceId = 'protect';

/** The resource whose default projection the promoted camera tool applies. */
const RESOURCE = 'camera';

const pages = loadPageFixtures(SERVICE);
const errors = loadErrorFixtures(SERVICE);

/** H-LE-5: generated once, at module load, and reused by every case below. */
const { cameras } = largeEstate();

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function idOf(item: unknown): string {
  const id = (item as Record<string, unknown>).id;
  assert.equal(typeof id, 'string', 'every camera must carry a string id');
  return id as string;
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

// ---------------------------------------------------------------------------
// H-P-1 (FR-23)
// ---------------------------------------------------------------------------

describe('H-P-1: every Protect page normalizes to the one envelope (FR-23)', () => {
  for (const fixture of pages) {
    test(`${fixture.name} carries exactly the promised envelope fields`, () => {
      assertPageEnvelope(normalizePage(SERVICE, fixture.body), fixture.name);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(pages.length > 0, 'protect has no page fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-P-5 (FR-23, FR-36, FR-37)
// ---------------------------------------------------------------------------

/** Larger than one page, so the emulation has something to emulate over. */
const SYNTHETIC_CAMERA_COUNT = 500;
const EMULATED_PAGE_SIZE = 100;

/**
 * The sentence the emulated truncation notice must carry verbatim.
 *
 * It leads with a space because it is appended to the page-size sentence, and
 * the whole point of the assertion is that emulation is never passed off as
 * native paging — so the wording is compared, not paraphrased.
 */
const EMULATION_SENTENCE =
  ' Pagination is emulated: Protect returns the full array and provides no paging of its own.';

describe('H-P-5: a parameterless full array is paged server-side (FR-23, FR-36, FR-37)', () => {
  const all = syntheticProtectCameras(SYNTHETIC_CAMERA_COUNT);

  test('page 1 returns exactly page_size items and says the paging is emulated', () => {
    const page = normalizePage(SERVICE, all, { pageSize: EMULATED_PAGE_SIZE });

    assert.equal(page.returnedCount, EMULATED_PAGE_SIZE);
    assert.equal(page.items.length, EMULATED_PAGE_SIZE);
    assert.equal(page.totalCount, SYNTHETIC_CAMERA_COUNT, 'the true total is reported, not the slice');
    assert.equal(page.paginationEmulated, true);
    assert.ok(page.truncation, 'a sliced page withheld items and must say so');
    assert.ok(
      page.truncation.message.endsWith(EMULATION_SENTENCE),
      `truncation message did not carry the emulation sentence: ${page.truncation.message}`,
    );
  });

  test('the cursor carries this service and the next offset', () => {
    const page = normalizePage(SERVICE, all, { pageSize: EMULATED_PAGE_SIZE });
    const state = decodeCursor(page.nextCursor);

    assert.ok(state, 'an incomplete slice must mint a cursor');
    assert.equal(state.s, SERVICE);
    assert.equal(state.o, EMULATED_PAGE_SIZE);
  });

  test('page 2 continues from that offset', () => {
    const first = normalizePage(SERVICE, all, { pageSize: EMULATED_PAGE_SIZE });
    const second = normalizePage(SERVICE, all, { cursor: first.nextCursor });

    assert.equal(second.returnedCount, EMULATED_PAGE_SIZE);
    assert.equal(idOf(second.items[0]), idOf(all[EMULATED_PAGE_SIZE]));
    assert.equal(second.paginationEmulated, true);
  });

  test('walking the emulated chain terminates and visits every camera once', () => {
    // Capped so a non-terminating implementation FAILS rather than hanging the
    // runner until its timeout.
    const iterationCap = SYNTHETIC_CAMERA_COUNT / EMULATED_PAGE_SIZE + 1;
    const seen: string[] = [];
    let cursor: string | null = null;
    let iterations = 0;

    for (;;) {
      iterations += 1;
      assert.ok(
        iterations <= iterationCap,
        `emulated paging did not terminate within ${iterationCap} pages`,
      );

      const page = normalizePage(SERVICE, all, { cursor, pageSize: EMULATED_PAGE_SIZE });
      for (const item of page.items) seen.push(idOf(item));
      if (page.nextCursor === null) {
        assert.equal(page.truncation, null, 'the final page withheld nothing and must say nothing');
        break;
      }
      cursor = page.nextCursor;
    }

    assert.equal(seen.length, SYNTHETIC_CAMERA_COUNT);
    assert.equal(new Set(seen).size, SYNTHETIC_CAMERA_COUNT, 'a camera was returned twice');
  });
});

// ---------------------------------------------------------------------------
// H-E-1 (FR-24)
// ---------------------------------------------------------------------------

describe('H-E-1: every Protect error normalizes to the nine promised fields (FR-24)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} carries exactly the promised error fields`, () => {
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      assertErrorEnvelope(normalized, fixture.name);
      assert.equal(normalized.service, SERVICE);
    });
  }

  test('the corpus is not empty, so the loop above is not vacuous', () => {
    assert.ok(errors.length > 0, 'protect has no error fixtures');
  });
});

// ---------------------------------------------------------------------------
// H-E-3 (FR-24)
// ---------------------------------------------------------------------------

describe('H-E-3: Protect never fabricates a correlation id (FR-24)', () => {
  for (const fixture of errors) {
    test(`${fixture.name} yields correlationId strictly null`, () => {
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);
      // strictEqual, not a falsiness check: '' and undefined would both satisfy
      // "no correlation id" while being different lies about the envelope. This
      // API's `{error, name}` shape carries no such identifier anywhere, and
      // inventing one would make an unsupportable error look supportable.
      assert.strictEqual(normalized.correlationId, null);
    });
  }

  for (const fixture of errors) {
    test(`${fixture.name} sources upstreamCode from name and message from error`, () => {
      const body = fixture.body as { name?: unknown; error?: unknown };
      const normalized = normalizeError(SERVICE, statusFromName(fixture.name), fixture.body);

      // The opposite convention to the other three APIs, which is exactly why
      // it is asserted per fixture rather than assumed once.
      assert.strictEqual(
        normalized.upstreamCode,
        typeof body.name === 'string' ? body.name : null,
      );
      if (typeof body.error === 'string') assert.equal(normalized.message, body.error);
    });
  }
});

// ---------------------------------------------------------------------------
// H-E-4, Protect half (FR-25)
// ---------------------------------------------------------------------------

describe('H-E-4: Protect states no origin (FR-25)', () => {
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

const TEN_MEGABYTES = 10 * 1024 * 1024;

describe('H-LE-1: the Protect estate is genuinely large (FR-51)', () => {
  test('the generated camera array is the size the requirement describes', () => {
    // Asserted on the FIXTURE, not on a response: an estate that silently shrank
    // would leave every ceiling assertion below passing while proving nothing.
    assert.ok(
      Buffer.byteLength(JSON.stringify(cameras)) > TEN_MEGABYTES,
      `the camera estate serialises to under ${TEN_MEGABYTES} bytes`,
    );
  });
});

/**
 * A `UnifiClient` stand-in that answers with the large estate.
 *
 * It ignores the request arguments entirely, which is not laziness: this API
 * takes no pagination parameters and answers every list call with its whole
 * collection. Slicing here would hide the very behaviour the ceiling exists for.
 */
function largeEstateClient(): UnifiClient {
  const request = async (_action: Action, _args: Record<string, unknown> = {}): Promise<UnifiResponse> => ({
    status: 200,
    body: cameras,
    headers: new Headers(),
  });

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

describe('H-LE-2: every Protect read tool stays under the ceilings (FR-51, NFR-08)', () => {
  test('the computed surface is not empty, so the cases below are not vacuous', () => {
    assert.ok(readSurface.length > 0, `${SERVICE} contributes no tools to the surface`);
    for (const tool of readSurface) {
      assert.equal(tool.annotations.readOnlyHint, true, `${tool.name} is not a read tool`);
    }
  });

  for (const tool of readSurface) {
    test(`${tool.name} answers under the ceilings against six thousand cameras`, async () => {
      const handler = handlers[tool.name];
      assert.ok(handler, `${tool.name} is advertised but createHandlers supplies no handler`);

      const result = await handler({ page_size: largestAcceptedPageSize(tool, {}) });

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

const PROJECTION_PAGE_SIZE = 100;

describe('H-LE-3: projection is what keeps a Protect page under the ceiling (FR-50)', () => {
  test('the same page is over the ceiling unprojected and under it projected', () => {
    const page = normalizePage(SERVICE, cameras, { pageSize: PROJECTION_PAGE_SIZE });
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

    const page = normalizePage(SERVICE, cameras, { pageSize: PROJECTION_PAGE_SIZE });
    for (const item of projectFields(page.items as object[], projection)) {
      assert.deepEqual(Object.keys(item).sort(), [...projection].sort());
    }
  });
});

/** A single astral character, so every code unit pair is a surrogate pair. */
const SURROGATE_PAIR = '\u{1F600}';
const SURROGATE_PAIR_COUNT = 75_000;

describe('H-LE-4: a truncated Protect response states what was withheld (FR-49, NFR-07)', () => {
  test('the response names how much came back, of how much, and how to continue', async () => {
    const handler = handlers[LIST_CAMERAS.name];
    assert.ok(handler);

    const pageSize = largestAcceptedPageSize(LIST_CAMERAS, {});
    const text = textOf(await handler({ page_size: pageSize }));

    assert.match(
      text,
      new RegExp(`Showing ${pageSize} of ${cameras.length}\\b`),
      'the response must state how much of the collection it is',
    );
    assert.match(text, /cursor/, 'the response must name a concrete way to get the rest');
    assert.ok(
      text.includes(EMULATION_SENTENCE.trim()),
      'the response must say the paging was emulated rather than upstream',
    );
  });

  test('the payload ceiling never strands half of a surrogate pair', () => {
    // The cut index depends on the length of the notice that gets appended, so
    // it is computed rather than guessed, and the source is padded so the cut
    // lands EXACTLY between the two halves of a pair. Without that, the case
    // would pass on a build with no surrogate handling at all.
    const nominalTotal = SURROGATE_PAIR_COUNT * 2;
    const suffixLength =
      '\n\n'.length +
      truncationMessage(EFFECTIVE_CEILING_CHARS, nominalTotal, 'payload_ceiling').length;
    const cutIndex = EFFECTIVE_CEILING_CHARS - suffixLength;
    const source =
      'a'.repeat((cutIndex - 1) % 2) + SURROGATE_PAIR.repeat(SURROGATE_PAIR_COUNT);

    assert.ok(
      isHighSurrogate(source.charCodeAt(cutIndex - 1)),
      'the cut must land mid-pair for this case to prove anything',
    );

    const { text } = applyPayloadCeiling(source);
    const kept = text.slice(0, text.length - suffixLength);

    assert.equal(kept.length, cutIndex - 1, 'the stranded high surrogate must be dropped');
    assert.equal(
      isHighSurrogate(kept.charCodeAt(kept.length - 1)),
      false,
      'the kept text ends on a lone high surrogate, which no longer round-trips through JSON',
    );
    assert.equal(JSON.parse(JSON.stringify(text)), text);
  });
});

describe('H-LE-5: the Protect estate case fits the runner budget (NFR-08)', () => {
  test('a second use of the estate costs nothing, because it is memoized', () => {
    // The property is structural: `largeEstate()` is called once at module load
    // and returns the same arrays thereafter, so no case pays to rebuild it.
    assert.strictEqual(largeEstate().cameras, cameras);
  });
});
