#!/usr/bin/env tsx
/**
 * Verify the vendored OpenAPI specs against `specs/manifest.json`.
 *
 * This is the cheap CI gate. It needs no network (NFR-17), reads four files and
 * finishes in well under a second, so it runs before the coverage check and
 * before the build — a corrupted or hand-edited spec should surface here with a
 * one-line message rather than three steps later as a confusing registry error.
 *
 * What it asserts, and why each one earns its place:
 *
 *  - **SHA-256 matches the manifest.** FR-01 records a digest per spec precisely
 *    so that "someone edited the vendored JSON in place" is distinguishable from
 *    "someone landed a reviewed refresh PR". `src/registry/build.ts` only warns
 *    on a digest mismatch, because the server must still start; CI must not be
 *    that forgiving, so here it is fatal (FR-05).
 *  - **Operation counts match.** The manifest records a per-service count and a
 *    total. A spec that silently loses operations would quietly shrink the tool
 *    surface, and the coverage check (FR-59) would still pass because every
 *    remaining operation is accounted for. Only a recorded count catches it.
 *  - **The document is still shaped like OpenAPI** (FR-03) — an `openapi` version
 *    string and a non-empty `paths` object.
 *  - **No URL contains `latest`.** FR-01's acceptance criterion is literally a
 *    grep for that string in any spec-fetching code path; asserting it on the
 *    recorded URLs closes the loop from the other end.
 *  - **The recorded path matches `specs/{service}/v{version}/openapi.json`**, so
 *    a version bump cannot leave the manifest pointing at the old file.
 *
 * Exit codes: 0 all good, 1 at least one mismatch.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServiceId } from '../src/types.js';
import { SERVICE_IDS } from '../src/types.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Mirrors the method list in `src/registry/build.ts`; head/options/trace are not operations here. */
const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

interface VendoredEntry {
  version: string;
  url: string;
  path: string;
  sha256: string;
  openapi: string;
  infoVersion: string;
  operations: number;
  declaresSecuritySchemes: boolean;
  authInjectionRequired: boolean;
}

interface VendoredManifest {
  services: Record<ServiceId, VendoredEntry>;
  totalOperations: number;
}

const failures: string[] = [];

function check(condition: boolean, message: string): void {
  if (!condition) failures.push(message);
}

function countOperations(doc: Record<string, any>): number {
  let count = 0;
  for (const rawPathItem of Object.values<any>(doc.paths ?? {})) {
    if (!rawPathItem) continue;
    for (const method of METHODS) if (rawPathItem[method]) count += 1;
  }
  return count;
}

const manifestPath = join(REPO_ROOT, 'specs', 'manifest.json');
let manifest: VendoredManifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as VendoredManifest;
} catch (error) {
  console.error(`verify-specs: cannot read ${manifestPath}: ${(error as Error).message}`);
  process.exit(1);
}

console.log('verify-specs: checking vendored specs against specs/manifest.json\n');

let observedTotal = 0;

for (const service of SERVICE_IDS) {
  const entry = manifest.services[service];
  if (!entry) {
    failures.push(`${service}: no entry in specs/manifest.json`);
    continue;
  }

  // FR-01: the acceptance criterion is that no spec-fetching code path contains
  // `/latest/openapi.json`. The recorded URL is the other half of that path.
  check(
    !/\/latest\//i.test(entry.url),
    `${service}: manifest URL \`${entry.url}\` contains an unpinned \`latest\` segment (FR-01). ` +
      `That URL returns the docs SPA HTML shell with HTTP 200.`,
  );

  const expectedPath = `specs/${service}/v${entry.version}/openapi.json`;
  check(
    entry.path === expectedPath,
    `${service}: manifest path \`${entry.path}\` does not match the versioned layout ` +
      `\`${expectedPath}\` required by FR-01. A bump probably updated the version but not the path.`,
  );

  let raw: string;
  try {
    raw = readFileSync(join(REPO_ROOT, entry.path), 'utf8');
  } catch {
    failures.push(
      `${service}: vendored spec missing at ${entry.path}. Run \`npm run specs:refresh\`; ` +
        `the server does not fall back to a different version (FR-04).`,
    );
    continue;
  }

  const digest = createHash('sha256').update(raw).digest('hex');
  check(
    digest === entry.sha256,
    `${service}: SHA-256 mismatch for ${entry.path}\n` +
      `      manifest: ${entry.sha256}\n` +
      `      on disk:  ${digest}\n` +
      `      The spec was edited in place rather than refreshed through a reviewed PR (FR-05).`,
  );

  let doc: Record<string, any>;
  try {
    doc = JSON.parse(raw) as Record<string, any>;
  } catch (error) {
    failures.push(`${service}: ${entry.path} does not parse as JSON (${(error as Error).message}).`);
    continue;
  }

  // FR-03, restated on disk: an HTML shell that slipped past the refresh gate
  // would parse-fail above, but a truncated or half-written file can still be
  // valid JSON with no `paths`.
  check(
    typeof doc.openapi === 'string' && doc.openapi.trim().length > 0,
    `${service}: ${entry.path} has no \`openapi\` version string — it is not an OpenAPI document (FR-03).`,
  );
  check(
    Boolean(doc.paths) && typeof doc.paths === 'object' && Object.keys(doc.paths).length > 0,
    `${service}: ${entry.path} has no non-empty \`paths\` object (FR-03).`,
  );
  check(
    doc.openapi === entry.openapi,
    `${service}: OpenAPI version on disk (${doc.openapi}) does not match the manifest (${entry.openapi}).`,
  );

  const observed = countOperations(doc);
  observedTotal += observed;
  check(
    observed === entry.operations,
    `${service}: operation count mismatch — manifest records ${entry.operations}, ` +
      `${entry.path} contains ${observed}. A spec that silently gains or loses operations ` +
      `changes the tool surface without review (FR-05, FR-59).`,
  );

  const declares = Object.keys(doc.components?.securitySchemes ?? {}).length > 0;
  check(
    declares === entry.declaresSecuritySchemes,
    `${service}: manifest records declaresSecuritySchemes=${entry.declaresSecuritySchemes} ` +
      `but the spec ${declares ? 'does' : 'does not'} declare any. The auth-injection ` +
      `precondition (FR-06, R-8) is stated against the wrong fact.`,
  );

  console.log(
    `  ${service.padEnd(13)} v${entry.version.padEnd(9)} ` +
      `${String(observed).padStart(3)} ops  ${digest.slice(0, 12)}…`,
  );
}

check(
  observedTotal === manifest.totalOperations,
  `totalOperations mismatch — manifest records ${manifest.totalOperations}, ` +
    `the vendored specs contain ${observedTotal}.`,
);

console.log('');

if (failures.length > 0) {
  console.error(`verify-specs: FAILED with ${failures.length} problem(s):\n`);
  for (const failure of failures) console.error(`  - ${failure}`);
  console.error('');
  process.exit(1);
}

console.log(
  `verify-specs: OK — ${SERVICE_IDS.length} specs, ${observedTotal} operations, all digests match.`,
);
