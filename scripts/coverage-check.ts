#!/usr/bin/env tsx
/**
 * Coverage check: every spec operation is reachable or deliberately withheld
 * (FR-59, G-1).
 *
 * G-1 is written as a percentage against a build-time-computed denominator
 * rather than against a guessed absolute (OQ-12), so this script computes both
 * halves itself: it enumerates every `paths.*.{get,post,put,patch,delete}` entry
 * in the four vendored specs, then asserts each one is either present in the
 * action registry or present in the Never-Ship blocklist with a stated reason.
 *
 * ## Why "uncovered" is a build failure and not a warning
 *
 * The failure this guards against is silent. A spec bump adds an operation, the
 * registry builder skips it for some structural reason (no `operationId`, an
 * unusual `$ref`, a path shape the ID builder chokes on), and nobody notices
 * because nothing errored — the tool surface is simply smaller than the specs
 * say it should be. There is no user-visible symptom until someone asks for a
 * capability that ought to exist. So: any uncovered operation exits non-zero.
 *
 * ## Why the report is committed
 *
 * FR-59 requires the counts in a committed file a reviewer can diff across spec
 * bumps. The file therefore has no timestamp and no run metadata in it — those
 * would produce a diff on every run and train reviewers to ignore the diff. Every
 * collection is sorted deterministically for the same reason: a meaningful diff
 * is one where a changed line means a changed fact.
 *
 * Exit codes: 0 fully covered, 1 at least one uncovered operation or a build error.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Action, BlocklistEntry, HttpMethod, ServiceId } from '../src/types.js';
import { SERVICE_IDS } from '../src/types.js';
import { blockedDiscriminators, blocksEntireOperation, NEVER_SHIP } from '../src/registry/blocklist.js';
import type { SpecManifest } from '../src/registry/build.js';
import { buildRegistry } from '../src/registry/build.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPORT_PATH = join(REPO_ROOT, 'coverage-report.json');

/** Mirrors the method list in `src/registry/build.ts` so the denominators agree. */
const METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

type OperationStatus = 'registered' | 'blocked';

interface OperationRow {
  method: HttpMethod;
  path: string;
  status: OperationStatus;
  /** The registry ID for a registered operation; null for a blocked one. */
  actionId: string | null;
  /** FR-46 requires a stated reason on every blocklist entry; echoed here. */
  reason?: string;
  /** Discriminator values withheld from an otherwise-registered operation. */
  withheldVariants?: Array<{ discriminator: string; reason: string }>;
}

interface ServiceReport {
  version: string;
  specOperations: number;
  registered: number;
  blocked: number;
  blockedDiscriminators: number;
  uncovered: number;
  operations: OperationRow[];
}

function loadSpec(entry: { path: string }): Record<string, any> {
  return JSON.parse(readFileSync(join(REPO_ROOT, entry.path), 'utf8')) as Record<string, any>;
}

/** Deterministic ordering: by path, then by the canonical method order. */
function sortRows(rows: OperationRow[]): OperationRow[] {
  return rows.sort((a, b) => {
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    return METHODS.indexOf(a.method) - METHODS.indexOf(b.method);
  });
}

const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8')) as SpecManifest;

// FR-59 measures the whole published surface, so the check runs with all four
// services enabled regardless of what any local configuration would enable. An
// operation withheld only because its service is switched off is not "covered".
const enabled = new Set<ServiceId>(SERVICE_IDS);

let registry;
try {
  registry = buildRegistry(REPO_ROOT, manifest, enabled);
} catch (error) {
  console.error(`coverage-check: registry build failed — ${(error as Error).message}`);
  process.exit(1);
}

// `service METHOD path` → action, so an operation can be matched back to the
// registry entry that makes it reachable.
const registered = new Map<string, Action>();
for (const action of registry.actions) {
  registered.set(`${action.service} ${action.method} ${action.path}`, action);
}

const services: Record<string, ServiceReport> = {};
const uncovered: Array<{ service: ServiceId; method: HttpMethod; path: string }> = [];

for (const service of SERVICE_IDS) {
  const entry = manifest.services[service];
  const spec = loadSpec(entry);
  const rows: OperationRow[] = [];
  let blocked = 0;
  let discriminatorsWithheld = 0;

  for (const [path, rawPathItem] of Object.entries<any>(spec.paths ?? {})) {
    const pathItem = rawPathItem ?? {};
    for (const method of METHODS) {
      if (!pathItem[method.toLowerCase()]) continue;

      const action = registered.get(`${service} ${method} ${path}`);
      const fullyBlocked: BlocklistEntry | undefined = blocksEntireOperation(service, method, path);
      const withheld = blockedDiscriminators(service, method, path);
      discriminatorsWithheld += withheld.length;

      if (action) {
        const row: OperationRow = {
          method,
          path,
          status: 'registered',
          actionId: action.id,
        };
        if (withheld.length > 0) {
          row.withheldVariants = withheld
            .map((w) => ({ discriminator: w.discriminator as string, reason: w.reason }))
            .sort((a, b) => (a.discriminator < b.discriminator ? -1 : 1));
        }
        rows.push(row);
        continue;
      }

      if (fullyBlocked) {
        blocked += 1;
        // FR-46 requires a one-line reason on every entry; FR-59 requires the
        // report to show that blocklisted operations are accounted for, not gaps.
        rows.push({ method, path, status: 'blocked', actionId: null, reason: fullyBlocked.reason });
        continue;
      }

      uncovered.push({ service, method, path });
    }
  }

  const stats = registry.stats[service];
  services[service] = {
    version: stats.version,
    specOperations: stats.specOperations,
    registered: rows.filter((r) => r.status === 'registered').length,
    blocked,
    blockedDiscriminators: discriminatorsWithheld,
    uncovered: uncovered.filter((u) => u.service === service).length,
    operations: sortRows(rows),
  };
}

const totals = SERVICE_IDS.reduce(
  (accumulator, service) => {
    const report = services[service]!;
    accumulator.specOperations += report.specOperations;
    accumulator.registered += report.registered;
    accumulator.blocked += report.blocked;
    accumulator.blockedDiscriminators += report.blockedDiscriminators;
    accumulator.uncovered += report.uncovered;
    return accumulator;
  },
  { specOperations: 0, registered: 0, blocked: 0, blockedDiscriminators: 0, uncovered: 0 },
);

const report = {
  $comment:
    'Generated by scripts/coverage-check.ts (FR-59, G-1). Committed so a reviewer can diff ' +
    'coverage across spec bumps. Deliberately carries no timestamp and no run metadata: a ' +
    'file that changes on every run is a file nobody reads the diff of. Regenerate with ' +
    '`npm run coverage:check`.',
  generator: 'scripts/coverage-check.ts',
  totals: {
    ...totals,
    // G-1's target: 100% of GETs, 100% of mutating operations minus the published
    // blocklist, zero unaccounted-for operations.
    coveragePercent:
      totals.specOperations === 0
        ? 100
        : Number(
            (((totals.registered + totals.blocked) / totals.specOperations) * 100).toFixed(2),
          ),
  },
  blocklist: [...NEVER_SHIP]
    .map((e) => ({
      service: e.service,
      method: e.method,
      path: e.path,
      discriminator: e.discriminator ?? null,
      reason: e.reason,
    }))
    .sort((a, b) => {
      const left = `${a.service} ${a.path} ${a.method} ${a.discriminator ?? ''}`;
      const right = `${b.service} ${b.path} ${b.method} ${b.discriminator ?? ''}`;
      return left < right ? -1 : left > right ? 1 : 0;
    }),
  // Object keys are emitted in SERVICE_IDS order, not insertion-by-accident order.
  services: Object.fromEntries(SERVICE_IDS.map((service) => [service, services[service]!])),
};

writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

// ---------------------------------------------------------------------------
// Console summary
// ---------------------------------------------------------------------------

console.log('coverage-check: every spec operation must be registered or blocklisted (FR-59, G-1)\n');
console.log('  service        version     spec  registered  blocked  withheld  uncovered');
console.log('  ' + '-'.repeat(74));
for (const service of SERVICE_IDS) {
  const report_ = services[service]!;
  console.log(
    `  ${service.padEnd(13)}  ${report_.version.padEnd(9)}  ` +
      `${String(report_.specOperations).padStart(4)}  ` +
      `${String(report_.registered).padStart(10)}  ` +
      `${String(report_.blocked).padStart(7)}  ` +
      `${String(report_.blockedDiscriminators).padStart(8)}  ` +
      `${String(report_.uncovered).padStart(9)}`,
  );
}
console.log('  ' + '-'.repeat(74));
console.log(
  `  ${'TOTAL'.padEnd(13)}  ${''.padEnd(9)}  ` +
    `${String(totals.specOperations).padStart(4)}  ` +
    `${String(totals.registered).padStart(10)}  ` +
    `${String(totals.blocked).padStart(7)}  ` +
    `${String(totals.blockedDiscriminators).padStart(8)}  ` +
    `${String(totals.uncovered).padStart(9)}`,
);
console.log(`\n  coverage: ${report.totals.coveragePercent}%  (G-1 target: 100%)`);
console.log(`  report:   ${REPORT_PATH}`);

for (const warning of registry.warnings) console.log(`  note:     ${warning}`);

if (uncovered.length > 0) {
  console.error(
    `\ncoverage-check: FAILED — ${uncovered.length} operation(s) are neither registered ` +
      `nor blocklisted:\n`,
  );
  for (const operation of uncovered) {
    console.error(`  - ${operation.service} ${operation.method} ${operation.path}`);
  }
  console.error(
    '\nEvery spec operation must be reachable through the tool surface, or listed in\n' +
      'src/registry/blocklist.ts with a one-line reason (FR-46). An operation that is\n' +
      'neither is a silent gap: nothing errors, the surface is just smaller than the\n' +
      'specs say it is.\n',
  );
  process.exit(1);
}

console.log('\ncoverage-check: OK — zero unaccounted-for operations.');
