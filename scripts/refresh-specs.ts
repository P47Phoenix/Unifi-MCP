#!/usr/bin/env tsx
/**
 * Refresh the vendored OpenAPI specs from the Ubiquiti developer portal.
 *
 * Implements FR-02 (bootstrap from the `llms.txt` index), FR-03 (validate every
 * fetched body as an OpenAPI document *before* writing it) and FR-05 (emit a
 * machine-generated operation-level diff so a version bump lands as a reviewable
 * pull request rather than being absorbed silently).
 *
 * ## Why this is a maintainer command and not a runtime path
 *
 * NFR-17 requires the server to start and advertise its full tool surface with
 * all outbound traffic blocked. Nothing in `src/` fetches anything. This script
 * is the only place in the repository that talks to `developer.ui.com`, it runs
 * on a maintainer's machine or a scheduled CI job, and its entire output is a
 * branch plus a PR body for a human to read.
 *
 * ## Why `latest` never appears in a URL
 *
 * `https://developer.ui.com/{service}/latest/openapi.json` returns HTTP 200 with
 * the docs single-page-app HTML shell, not a spec. A refresh that trusted the
 * status code would vendor an HTML file and the registry build would fail at the
 * next startup with a confusing parse error. FR-01 therefore bans the string
 * outright and `assertPinnedUrl` enforces it on every URL this script touches,
 * including URLs read out of the vendor's own index.
 *
 * ## Exit codes
 *
 *   0  Success. Either no drift, or a branch and PR body were prepared.
 *   1  Operational failure — index unreachable, a fetched body failed FR-03
 *      validation, or git refused. NOTHING was changed on disk in this case.
 *   2  `--check` found drift. Nothing was changed; this is the CI drift gate.
 *
 * ## Usage
 *
 *   tsx scripts/refresh-specs.ts                 # refresh, branch, PR body
 *   tsx scripts/refresh-specs.ts --dry-run       # report only, touch nothing
 *   tsx scripts/refresh-specs.ts --check         # exit 2 on drift (CI gate)
 *   tsx scripts/refresh-specs.ts --allow-mirror  # opt in to community mirrors
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServiceId } from '../src/types.js';
import { SERVICE_IDS } from '../src/types.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX_URL = 'https://developer.ui.com/llms.txt';
const FETCH_TIMEOUT_MS = 30_000;

/** The HTTP methods that count as operations. Mirrors `src/registry/build.ts`. */
const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Where a candidate spec came from.
 *
 * OQ-14 leaves mirror vendoring as an unratified policy question with a proposed
 * resolution: mirrors are fine for diffing and early warning, and a mirror-sourced
 * spec may be vendored ONLY when the PR labels its provenance explicitly and a
 * human approves. So provenance is carried on every candidate and printed
 * everywhere a candidate is — branch name, commit message and PR body.
 */
type Provenance =
  | { kind: 'portal'; label: string; indexUrl: string }
  | { kind: 'mirror'; label: string; repo: string; indexUrl: string };

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
  $comment?: string;
}

interface VendoredManifest {
  $comment?: string;
  fetchedAt: string;
  indexUrl: string;
  services: Record<ServiceId, VendoredEntry>;
  totalOperations: number;
}

type OpenApiDoc = Record<string, any>;

interface IndexedService {
  service: ServiceId;
  version: string;
  specUrl: string;
}

interface Candidate {
  service: ServiceId;
  version: string;
  specUrl: string;
  body: string;
  doc: OpenApiDoc;
  sha256: string;
  operations: number;
  declaresSecuritySchemes: boolean;
  infoVersion: string;
  openapi: string;
  /** True when either the version or the byte content differs from the vendored copy. */
  drifted: boolean;
  driftReasons: string[];
  diff: OperationDiff;
}

interface OperationDiff {
  added: string[];
  removed: string[];
  parameterChanges: Array<{ operation: string; added: string[]; removed: string[] }>;
  responseChanges: Array<{ operation: string; added: string[]; removed: string[] }>;
}

/** Raised for FR-03 validation failures so the message can name URL and reason. */
class SpecValidationError extends Error {
  constructor(readonly url: string, reason: string) {
    super(`${url} is not a valid OpenAPI document: ${reason}`);
    this.name = 'SpecValidationError';
  }
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

interface Options {
  dryRun: boolean;
  check: boolean;
  allowMirror: boolean;
}

function parseArgs(argv: string[]): Options {
  const options: Options = { dryRun: false, check: false, allowMirror: false };
  for (const arg of argv) {
    switch (arg) {
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--check':
        // `--check` is a reporting gate by definition: it must never change a
        // byte, so it implies --dry-run rather than merely coexisting with it.
        options.check = true;
        options.dryRun = true;
        break;
      case '--allow-mirror':
        options.allowMirror = true;
        break;
      case '--help':
      case '-h':
        printUsage();
        process.exit(0);
        break;
      default:
        fail(`Unknown argument: ${arg}\nRun with --help for usage.`);
    }
  }
  return options;
}

function printUsage(): void {
  console.log(
    [
      'Usage: tsx scripts/refresh-specs.ts [options]',
      '',
      'Options:',
      '  --dry-run        Report drift and print the PR body; write nothing.',
      '  --check          Exit 2 if any vendored spec has drifted. Implies --dry-run.',
      '  --allow-mirror   Fall back to the community mirrors when the portal index',
      '                   is unreachable. Mirror-sourced specs are labelled as such',
      '                   in the branch name, commit message and PR body (OQ-14).',
      '  -h, --help       Show this message.',
      '',
      'Exit codes: 0 success/no drift, 1 operational failure (nothing changed),',
      '            2 --check found drift (nothing changed).',
    ].join('\n'),
  );
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/**
 * FR-01: refuse any URL carrying an unpinned version segment.
 *
 * Applied to URLs this script constructs AND to URLs parsed out of the vendor's
 * index, because the index is vendor-controlled input and could start
 * advertising `latest` without notice (R-1).
 */
function assertPinnedUrl(url: string): void {
  if (/\/latest\//i.test(url) || /\/latest$/i.test(url)) {
    throw new Error(
      `Refusing to fetch ${url}: the URL contains an unpinned \`latest\` segment. ` +
        `That URL returns HTTP 200 with the docs SPA HTML shell, not a spec (FR-01).`,
    );
  }
}

async function fetchText(url: string): Promise<{ body: string; contentType: string }> {
  assertPinnedUrl(url);
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { accept: 'application/json, text/plain, */*' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`GET ${url} returned HTTP ${response.status} ${response.statusText}`);
  }
  return {
    body: await response.text(),
    contentType: response.headers.get('content-type') ?? '',
  };
}

// ---------------------------------------------------------------------------
// FR-03 — validation before any write
// ---------------------------------------------------------------------------

/**
 * Validate a fetched body as an OpenAPI document (FR-03).
 *
 * Three checks, in the order that produces the most useful message:
 *
 *  1. HTML sniff. The exact failure mode an unpinned `latest` URL produces is a
 *     200 whose body is the docs SPA shell. Naming that explicitly saves the
 *     maintainer from debugging a generic "Unexpected token <" JSON error.
 *  2. JSON parse.
 *  3. Shape: an `openapi` version string and a NON-EMPTY `paths` object. A spec
 *     with zero paths would build an empty registry and silently shrink the
 *     tool surface, which is exactly the drift FR-05 exists to catch.
 *
 * The caller must not write anything until this returns.
 */
function validateOpenApiDocument(url: string, body: string, contentType: string): OpenApiDoc {
  const head = body.slice(0, 512).trimStart();
  if (head.startsWith('<') || /^text\/html/i.test(contentType)) {
    throw new SpecValidationError(
      url,
      `the response body is HTML, not JSON (content-type: ${contentType || 'unset'}). ` +
        `This is what the docs single-page-app shell looks like; the URL is probably ` +
        `unpinned or the service path is wrong.`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new SpecValidationError(
      url,
      `the response body does not parse as JSON (${(error as Error).message}).`,
    );
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SpecValidationError(url, 'the response body is not a JSON object.');
  }

  const doc = parsed as OpenApiDoc;
  if (typeof doc.openapi !== 'string' || !doc.openapi.trim()) {
    throw new SpecValidationError(url, 'it has no `openapi` version string.');
  }
  if (!doc.paths || typeof doc.paths !== 'object' || Array.isArray(doc.paths)) {
    throw new SpecValidationError(url, 'it has no `paths` object.');
  }
  if (Object.keys(doc.paths).length === 0) {
    throw new SpecValidationError(url, 'its `paths` object is empty.');
  }
  return doc;
}

// ---------------------------------------------------------------------------
// The vendor index (FR-02)
// ---------------------------------------------------------------------------

/**
 * Parse `https://developer.ui.com/llms.txt` into the current pinned spec URL per
 * service.
 *
 * The index is Markdown, not a machine format, so parsing it by section heading
 * would be brittle. Instead every `…/{service}/v{version}/openapi.json` URL
 * anywhere in the document is matched, which survives the vendor reordering or
 * renaming sections (R-1). Duplicate mentions of the same service are reconciled
 * by taking the highest version rather than the first seen.
 */
function parseIndex(text: string): Map<ServiceId, IndexedService> {
  const pattern =
    /https:\/\/developer\.ui\.com\/(site-manager|network|protect|mobility)\/v([0-9][0-9A-Za-z.\-+]*)\/openapi\.json/g;

  const found = new Map<ServiceId, IndexedService>();
  for (const match of text.matchAll(pattern)) {
    const service = match[1] as ServiceId;
    const version = match[2] as string;
    const specUrl = match[0];
    assertPinnedUrl(specUrl);
    const existing = found.get(service);
    if (!existing || compareVersions(version, existing.version) > 0) {
      found.set(service, { service, version, specUrl });
    }
  }
  return found;
}

/** Numeric-segment-aware version comparison. `10.4.57` sorts above `9.5.21`. */
function compareVersions(a: string, b: string): number {
  const partsA = a.split(/[.\-+]/);
  const partsB = b.split(/[.\-+]/);
  for (let i = 0; i < Math.max(partsA.length, partsB.length); i += 1) {
    const rawA = partsA[i] ?? '';
    const rawB = partsB[i] ?? '';
    const numA = Number.parseInt(rawA, 10);
    const numB = Number.parseInt(rawB, 10);
    if (Number.isFinite(numA) && Number.isFinite(numB)) {
      if (numA !== numB) return numA < numB ? -1 : 1;
      continue;
    }
    if (rawA !== rawB) return rawA < rawB ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Community mirrors (D-1, OQ-14) — opt-in only
// ---------------------------------------------------------------------------

/**
 * The two documented fallbacks, used only behind `--allow-mirror`.
 *
 * D-1 names both; OQ-14 governs what may be done with them. The rule enforced
 * here: a mirror is never consulted unless a human passed the flag, and anything
 * sourced from one is labelled `provenance: community-mirror` in the branch
 * name, the commit message and the PR body, with a DO-NOT-MERGE-BLIND banner.
 * There is no code path that reaches a mirror automatically.
 *
 * `opastorello/unifi-api-docs` is preferred because it publishes a machine-readable
 * `catalog.json` covering all four services. `beezly/unifi-apis` is
 * controller-extracted and carries only Network and Protect, so it can never
 * satisfy a full refresh on its own — it is a partial early-warning source.
 */
const MIRRORS = [
  {
    repo: 'opastorello/unifi-api-docs',
    indexUrl: 'https://raw.githubusercontent.com/opastorello/unifi-api-docs/main/catalog.json',
    resolve: resolveOpastorelloCatalog,
  },
  {
    repo: 'beezly/unifi-apis',
    indexUrl: 'https://api.github.com/repos/beezly/unifi-apis/git/trees/HEAD?recursive=1',
    resolve: resolveBeezlyTree,
  },
] as const;

/** `catalog.json` → `{apps: {network: {latest: "v10.4.57", versions: [{openapi: "network/v10.4.57/openapi.json"}]}}}`. */
function resolveOpastorelloCatalog(body: string): Map<ServiceId, IndexedService> {
  const base = 'https://raw.githubusercontent.com/opastorello/unifi-api-docs/main/';
  const catalog = JSON.parse(body) as {
    apps?: Record<string, { latest?: string; versions?: Array<{ version?: string; openapi?: string }> }>;
  };
  const found = new Map<ServiceId, IndexedService>();
  for (const service of SERVICE_IDS) {
    const app = catalog.apps?.[service];
    if (!app?.latest) continue;
    const entry = app.versions?.find((v) => v.version === app.latest);
    if (!entry?.openapi) continue;
    const specUrl = base + entry.openapi;
    assertPinnedUrl(specUrl);
    found.set(service, { service, version: app.latest.replace(/^v/, ''), specUrl });
  }
  return found;
}

/** GitHub trees listing → `unifi-network/10.4.57.json`, `unifi-protect/7.1.87.json`. */
function resolveBeezlyTree(body: string): Map<ServiceId, IndexedService> {
  const base = 'https://raw.githubusercontent.com/beezly/unifi-apis/main/';
  const tree = JSON.parse(body) as { tree?: Array<{ path?: string }> };
  const directories: Partial<Record<ServiceId, string>> = {
    network: 'unifi-network',
    protect: 'unifi-protect',
  };
  const found = new Map<ServiceId, IndexedService>();
  for (const [service, directory] of Object.entries(directories) as Array<[ServiceId, string]>) {
    let best: IndexedService | undefined;
    for (const node of tree.tree ?? []) {
      const match = node.path?.match(new RegExp(`^${directory}/([0-9][0-9A-Za-z.\\-+]*)\\.json$`));
      if (!match?.[1]) continue;
      const version = match[1];
      if (best && compareVersions(version, best.version) <= 0) continue;
      const specUrl = base + node.path;
      assertPinnedUrl(specUrl);
      best = { service, version, specUrl };
    }
    if (best) found.set(service, best);
  }
  return found;
}

// ---------------------------------------------------------------------------
// FR-05 — operation-level diff
// ---------------------------------------------------------------------------

/** Resolve a chain of local `#/…` `$ref`s, breaking cycles. Remote refs are unused. */
function follow(spec: OpenApiDoc, node: any, seen: Set<string>): any {
  let current = node;
  while (current && typeof current === 'object' && typeof current.$ref === 'string') {
    const ref: string = current.$ref;
    if (seen.has(ref) || !ref.startsWith('#/')) return {};
    seen.add(ref);
    let target: any = spec;
    for (const segment of ref.slice(2).split('/')) {
      target = target?.[segment.replace(/~1/g, '/').replace(/~0/g, '~')];
      if (target === undefined) return {};
    }
    current = target;
  }
  return current;
}

/** `in:name` for every parameter on an operation, path-item parameters merged in. */
function parameterKeys(spec: OpenApiDoc, pathItem: any, operation: any): Set<string> {
  const keys = new Set<string>();
  for (const raw of [...(pathItem?.parameters ?? []), ...(operation?.parameters ?? [])]) {
    const parameter = follow(spec, raw, new Set());
    if (parameter?.name && parameter?.in) keys.add(`${parameter.in}:${parameter.name}`);
  }
  return keys;
}

/**
 * Flatten a response schema into dotted property paths.
 *
 * A vendor can widen or narrow a response without touching an operation or a
 * parameter, and FR-05 requires that to be visible in the PR. Depth is capped at
 * 6 and `$ref` cycles are broken per-branch — these specs nest deeply enough
 * (Network device schemas especially) that an uncapped walk is not worth the
 * review noise.
 */
function flattenSchema(
  spec: OpenApiDoc,
  rawSchema: any,
  prefix: string,
  depth: number,
  out: Set<string>,
  seen: Set<string>,
): void {
  if (depth > 6) return;
  const schema = follow(spec, rawSchema, new Set(seen));
  if (!schema || typeof schema !== 'object') return;

  for (const branch of ['allOf', 'oneOf', 'anyOf'] as const) {
    for (const sub of schema[branch] ?? []) {
      flattenSchema(spec, sub, prefix, depth + 1, out, seen);
    }
  }

  if (schema.items) {
    flattenSchema(spec, schema.items, `${prefix}[]`, depth + 1, out, seen);
  }

  const properties = schema.properties;
  if (properties && typeof properties === 'object') {
    for (const [name, sub] of Object.entries(properties)) {
      const path = prefix ? `${prefix}.${name}` : name;
      out.add(path);
      flattenSchema(spec, sub, path, depth + 1, out, seen);
    }
  }
}

/**
 * `"<status> <dotted.property.path>"` for every JSON response body of an operation.
 *
 * The status code is part of the key so that a property moving from the 200
 * body to the 400 body reads as one removal and one addition rather than as no
 * change at all.
 */
function responseKeys(spec: OpenApiDoc, operation: any): Set<string> {
  const out = new Set<string>();
  for (const [status, rawResponse] of Object.entries(operation?.responses ?? {})) {
    const response = follow(spec, rawResponse, new Set());
    const local = new Set<string>();
    for (const [contentType, media] of Object.entries<any>(response?.content ?? {})) {
      if (!contentType.includes('json')) continue;
      flattenSchema(spec, media?.schema, '', 0, local, new Set());
    }
    for (const path of local) out.add(`${status} ${path}`);
  }
  return out;
}

interface OperationIndex {
  keys: string[];
  byKey: Map<string, { pathItem: any; operation: any }>;
}

function indexOperations(spec: OpenApiDoc): OperationIndex {
  const byKey = new Map<string, { pathItem: any; operation: any }>();
  for (const [path, rawPathItem] of Object.entries<any>(spec.paths ?? {})) {
    const pathItem = rawPathItem ?? {};
    for (const method of METHODS) {
      const operation = pathItem[method];
      if (!operation) continue;
      byKey.set(`${method.toUpperCase()} ${path}`, { pathItem, operation });
    }
  }
  return { keys: [...byKey.keys()].sort(), byKey };
}

function difference(a: Set<string>, b: Set<string>): string[] {
  return [...a].filter((value) => !b.has(value)).sort();
}

/** The FR-05 diff: operations, parameters and response properties, added and removed. */
function diffSpecs(before: OpenApiDoc | null, after: OpenApiDoc): OperationDiff {
  const diff: OperationDiff = { added: [], removed: [], parameterChanges: [], responseChanges: [] };
  const next = indexOperations(after);

  if (!before) {
    // First-ever vendoring of this service: every operation is an addition.
    diff.added = next.keys;
    return diff;
  }

  const previous = indexOperations(before);
  const previousKeys = new Set(previous.keys);
  const nextKeys = new Set(next.keys);

  diff.added = difference(nextKeys, previousKeys);
  diff.removed = difference(previousKeys, nextKeys);

  for (const key of next.keys) {
    if (!previousKeys.has(key)) continue;
    const oldEntry = previous.byKey.get(key)!;
    const newEntry = next.byKey.get(key)!;

    const oldParameters = parameterKeys(before, oldEntry.pathItem, oldEntry.operation);
    const newParameters = parameterKeys(after, newEntry.pathItem, newEntry.operation);
    const parametersAdded = difference(newParameters, oldParameters);
    const parametersRemoved = difference(oldParameters, newParameters);
    if (parametersAdded.length || parametersRemoved.length) {
      diff.parameterChanges.push({ operation: key, added: parametersAdded, removed: parametersRemoved });
    }

    const oldResponses = responseKeys(before, oldEntry.operation);
    const newResponses = responseKeys(after, newEntry.operation);
    const responsesAdded = difference(newResponses, oldResponses);
    const responsesRemoved = difference(oldResponses, newResponses);
    if (responsesAdded.length || responsesRemoved.length) {
      diff.responseChanges.push({ operation: key, added: responsesAdded, removed: responsesRemoved });
    }
  }

  return diff;
}

function diffIsEmpty(diff: OperationDiff): boolean {
  return (
    diff.added.length === 0 &&
    diff.removed.length === 0 &&
    diff.parameterChanges.length === 0 &&
    diff.responseChanges.length === 0
  );
}

// ---------------------------------------------------------------------------
// Manifest and disk
// ---------------------------------------------------------------------------

function readManifest(): VendoredManifest {
  const path = join(REPO_ROOT, 'specs', 'manifest.json');
  return JSON.parse(readFileSync(path, 'utf8')) as VendoredManifest;
}

function sha256(body: string): string {
  return createHash('sha256').update(body).digest('hex');
}

function countOperations(doc: OpenApiDoc): number {
  let count = 0;
  for (const rawPathItem of Object.values<any>(doc.paths ?? {})) {
    if (!rawPathItem) continue;
    for (const method of METHODS) if (rawPathItem[method]) count += 1;
  }
  return count;
}

function readVendoredSpec(entry: VendoredEntry | undefined): { body: string; doc: OpenApiDoc } | null {
  if (!entry) return null;
  const absolute = join(REPO_ROOT, entry.path);
  if (!existsSync(absolute)) return null;
  const body = readFileSync(absolute, 'utf8');
  try {
    return { body, doc: JSON.parse(body) as OpenApiDoc };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// git (FR-02: never commit to the default branch)
// ---------------------------------------------------------------------------

function git(...args: string[]): string {
  return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
}

function currentBranch(): string {
  return git('rev-parse', '--abbrev-ref', 'HEAD');
}

/**
 * Best-effort default-branch detection.
 *
 * Used as a guard, not as a target: this script never checks the default branch
 * out. It only needs to know its name so it can refuse to commit while HEAD is
 * on it (FR-02: "The refresh command never commits directly to the default
 * branch"). When detection fails, both `main` and `master` are treated as
 * default — refusing too often is the safe direction.
 */
function defaultBranches(): Set<string> {
  const names = new Set(['main', 'master']);
  try {
    const ref = git('symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD');
    const name = ref.split('/').pop();
    if (name) names.add(name);
  } catch {
    // No origin, or no origin/HEAD. The main/master fallback stands.
  }
  return names;
}

function workingTreeIsDirty(): boolean {
  return git('status', '--porcelain', '--', 'specs', 'coverage-report.json').length > 0;
}

// ---------------------------------------------------------------------------
// PR body (FR-05)
// ---------------------------------------------------------------------------

function renderPrBody(
  candidates: Candidate[],
  manifest: VendoredManifest,
  provenance: Provenance,
  drifted: Candidate[],
): string {
  const lines: string[] = [];
  const services = drifted.map((c) => c.service).join(', ');

  lines.push(`# Spec refresh: ${services || 'no changes'}`);
  lines.push('');
  lines.push(`**Provenance:** ${provenance.label}`);
  lines.push(`**Index:** \`${provenance.indexUrl}\``);
  lines.push('');

  if (provenance.kind === 'mirror') {
    // OQ-14: a mirror-sourced spec may be vendored only when the PR labels its
    // provenance explicitly and a human approves. This banner is that label.
    lines.push('> [!WARNING]');
    lines.push(`> **MIRROR-SOURCED — DO NOT MERGE WITHOUT VERIFICATION (OQ-14, D-1).**`);
    lines.push(`> The Ubiquiti developer portal was unreachable and these specs were`);
    lines.push(`> fetched from the community mirror \`${provenance.repo}\`, not from`);
    lines.push(`> Ubiquiti. Mirrors are sanctioned for diffing and early warning.`);
    lines.push(`> Vendoring one requires a maintainer to confirm the content against the`);
    lines.push(`> portal once it is reachable again. Nothing here was auto-vendored:`);
    lines.push(`> \`--allow-mirror\` was passed explicitly.`);
    lines.push('');
  }

  lines.push('## Versions');
  lines.push('');
  lines.push('| Service | Vendored | Candidate | Ops (was → now) | SHA-256 (new) |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const candidate of candidates) {
    const entry = manifest.services[candidate.service];
    const status = candidate.drifted ? '' : ' _(unchanged)_';
    lines.push(
      `| \`${candidate.service}\`${status} | ${entry?.version ?? '—'} | **${candidate.version}** | ` +
        `${entry?.operations ?? '—'} → ${candidate.operations} | \`${candidate.sha256}\` |`,
    );
  }
  lines.push('');

  if (drifted.length === 0) {
    lines.push('No drift. Every vendored spec matches the version and bytes the index advertises.');
    return `${lines.join('\n')}\n`;
  }

  lines.push('## Operation-level diff (FR-05)');
  lines.push('');

  for (const candidate of drifted) {
    const entry = manifest.services[candidate.service];
    lines.push(`### \`${candidate.service}\` ${entry?.version ?? 'unvendored'} → ${candidate.version}`);
    lines.push('');
    lines.push(`Reason: ${candidate.driftReasons.join('; ')}.`);
    lines.push('');

    if (diffIsEmpty(candidate.diff)) {
      // FR-05: "A refresh producing zero operation-level differences still
      // records the version change and the new SHA-256."
      lines.push(
        '**Zero operation-level differences.** The version and SHA-256 above change anyway ' +
          'and are recorded in `specs/manifest.json`; this is still a reviewed bump (FR-05).',
      );
      lines.push('');
      continue;
    }

    lines.push(`**Operations added (${candidate.diff.added.length}):**`);
    lines.push('');
    if (candidate.diff.added.length === 0) lines.push('_none_');
    for (const operation of candidate.diff.added) lines.push(`- \`${operation}\``);
    lines.push('');

    lines.push(`**Operations removed (${candidate.diff.removed.length}):**`);
    lines.push('');
    if (candidate.diff.removed.length === 0) lines.push('_none_');
    for (const operation of candidate.diff.removed) {
      lines.push(`- \`${operation}\` — check \`src/registry/blocklist.ts\` for a now-stale entry (R-1).`);
    }
    lines.push('');

    lines.push(`**Parameter changes (${candidate.diff.parameterChanges.length} operations):**`);
    lines.push('');
    if (candidate.diff.parameterChanges.length === 0) lines.push('_none_');
    for (const change of candidate.diff.parameterChanges) {
      const added = change.added.map((p) => `+\`${p}\``).join(' ');
      const removed = change.removed.map((p) => `-\`${p}\``).join(' ');
      lines.push(`- \`${change.operation}\`: ${[added, removed].filter(Boolean).join(' ')}`);
    }
    lines.push('');

    lines.push(`**Response property changes (${candidate.diff.responseChanges.length} operations):**`);
    lines.push('');
    if (candidate.diff.responseChanges.length === 0) lines.push('_none_');
    for (const change of candidate.diff.responseChanges) {
      const added = change.added.map((p) => `+\`${p}\``).join(' ');
      const removed = change.removed.map((p) => `-\`${p}\``).join(' ');
      lines.push(`- \`${change.operation}\`: ${[added, removed].filter(Boolean).join(' ')}`);
    }
    lines.push('');
  }

  lines.push('## Reviewer checklist');
  lines.push('');
  lines.push('- [ ] `npm run specs:verify` passes (digests and operation counts match).');
  lines.push('- [ ] `npm run coverage:check` passes — every new operation is registered or blocklisted (FR-59).');
  lines.push('- [ ] Removed operations do not leave a stale Never-Ship blocklist entry (FR-46, R-1).');
  lines.push('- [ ] Every added mutating operation was read and classified against FR-46.');
  lines.push('- [ ] `coverage-report.json` diff reviewed.');
  if (provenance.kind === 'mirror') {
    lines.push('- [ ] **Mirror provenance accepted, or re-fetched from the portal before merge (OQ-14).**');
  }

  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function fail(message: string): never {
  console.error(`\nrefresh-specs: ${message}\n`);
  console.error('Nothing was changed.');
  process.exit(1);
}

async function resolveIndex(options: Options): Promise<{
  services: Map<ServiceId, IndexedService>;
  provenance: Provenance;
}> {
  try {
    const { body } = await fetchText(INDEX_URL);
    const services = parseIndex(body);
    if (services.size === 0) {
      throw new Error(
        `the index at ${INDEX_URL} advertised no \`…/v{version}/openapi.json\` URLs. ` +
          `Its format changed (R-1) and the parser in this script needs updating.`,
      );
    }
    return {
      services,
      provenance: { kind: 'portal', label: 'Ubiquiti developer portal', indexUrl: INDEX_URL },
    };
  } catch (error) {
    const reason = (error as Error).message;
    console.error(`refresh-specs: could not retrieve the index — ${reason}`);

    if (!options.allowMirror) {
      // FR-02: "exits non-zero and changes nothing when the index cannot be
      // retrieved". Mirrors exist but are never reached automatically (OQ-14).
      fail(
        `the vendor index could not be retrieved and \`--allow-mirror\` was not passed.\n` +
          `  Community mirrors are documented fallbacks (D-1) but are never used\n` +
          `  automatically: OQ-14 requires a human to opt in and the PR to label the\n` +
          `  provenance. Re-run with --allow-mirror to use them.`,
      );
    }

    for (const mirror of MIRRORS) {
      console.error(`refresh-specs: trying community mirror ${mirror.repo} …`);
      try {
        const { body } = await fetchText(mirror.indexUrl);
        const services = mirror.resolve(body);
        if (services.size === 0) continue;
        const missing = SERVICE_IDS.filter((s) => !services.has(s));
        if (missing.length) {
          console.error(
            `refresh-specs: ${mirror.repo} carries no spec for ${missing.join(', ')}; ` +
              `those services will be left at their vendored version.`,
          );
        }
        return {
          services,
          provenance: {
            kind: 'mirror',
            label: `COMMUNITY MIRROR \`${mirror.repo}\` (portal unreachable) — provenance requires explicit review (OQ-14)`,
            repo: mirror.repo,
            indexUrl: mirror.indexUrl,
          },
        };
      } catch (mirrorError) {
        console.error(`refresh-specs: ${mirror.repo} failed — ${(mirrorError as Error).message}`);
      }
    }

    fail('neither the vendor index nor any community mirror could be retrieved.');
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const manifest = readManifest();

  console.log(`refresh-specs: index ${INDEX_URL}`);
  const { services: indexed, provenance } = await resolveIndex(options);
  console.log(`refresh-specs: provenance ${provenance.kind === 'portal' ? 'portal' : `MIRROR ${provenance.repo}`}`);

  const candidates: Candidate[] = [];
  for (const service of SERVICE_IDS) {
    const entry = manifest.services[service];
    const advertised = indexed.get(service);
    if (!advertised) {
      console.log(`  ${service.padEnd(13)} not advertised by the index — leaving at v${entry?.version}`);
      continue;
    }

    // FR-03: fetch, then validate, then — and only then — consider writing.
    let doc: OpenApiDoc;
    let body: string;
    try {
      const response = await fetchText(advertised.specUrl);
      body = response.body;
      doc = validateOpenApiDocument(advertised.specUrl, response.body, response.contentType);
    } catch (error) {
      fail((error as Error).message);
    }

    const digest = sha256(body);
    const vendored = readVendoredSpec(entry);
    const driftReasons: string[] = [];
    if (!entry) driftReasons.push('no manifest entry — first vendoring');
    else {
      if (entry.version !== advertised.version) {
        driftReasons.push(`version ${entry.version} → ${advertised.version}`);
      }
      if (entry.sha256 !== digest) {
        driftReasons.push(`sha256 ${entry.sha256.slice(0, 12)}… → ${digest.slice(0, 12)}…`);
      }
      if (!vendored) driftReasons.push(`vendored file missing or unparseable at ${entry.path}`);
    }

    candidates.push({
      service,
      version: advertised.version,
      specUrl: advertised.specUrl,
      body,
      doc,
      sha256: digest,
      operations: countOperations(doc),
      declaresSecuritySchemes: Object.keys(doc.components?.securitySchemes ?? {}).length > 0,
      infoVersion: typeof doc.info?.version === 'string' ? doc.info.version : '',
      openapi: doc.openapi as string,
      drifted: driftReasons.length > 0,
      driftReasons,
      diff: diffSpecs(vendored?.doc ?? null, doc),
    });

    const marker = driftReasons.length ? 'DRIFT' : 'ok   ';
    console.log(
      `  ${marker} ${service.padEnd(13)} v${advertised.version.padEnd(9)} ` +
        `${String(countOperations(doc)).padStart(3)} ops  ${digest.slice(0, 12)}…`,
    );
  }

  const drifted = candidates.filter((c) => c.drifted);
  const prBody = renderPrBody(candidates, manifest, provenance, drifted);

  if (drifted.length === 0) {
    console.log('\nrefresh-specs: no drift. Vendored specs match the index.');
    return;
  }

  console.log(`\nrefresh-specs: ${drifted.length} service(s) drifted: ${drifted.map((c) => c.service).join(', ')}`);
  for (const candidate of drifted) {
    console.log(
      `  ${candidate.service}: +${candidate.diff.added.length} operations, ` +
        `-${candidate.diff.removed.length} operations, ` +
        `${candidate.diff.parameterChanges.length} parameter change(s), ` +
        `${candidate.diff.responseChanges.length} response change(s)`,
    );
  }

  if (options.check) {
    console.error('\nrefresh-specs: --check found drift. Run `npm run specs:refresh` to prepare a PR.');
    process.exit(2);
  }

  if (options.dryRun) {
    console.log('\n--- PR body (dry run, not written) ---\n');
    console.log(prBody);
    return;
  }

  // ---- Writing starts here. Everything above is read-only. ----------------

  if (workingTreeIsDirty()) {
    fail(
      'the working tree has uncommitted changes under specs/ or coverage-report.json.\n' +
        '  Refusing to mix them into a spec-refresh commit. Commit or stash first.',
    );
  }

  const stamp = new Date().toISOString().slice(0, 10);
  const suffix = provenance.kind === 'mirror' ? '-mirror' : '';
  const branch = `spec-refresh/${stamp}-${drifted.map((c) => c.service).join('-')}${suffix}`;
  const defaults = defaultBranches();

  try {
    git('checkout', '-b', branch);
  } catch (error) {
    fail(`could not create branch ${branch}: ${(error as Error).message}`);
  }

  // FR-02: never commit directly to the default branch. The checkout above
  // should have moved HEAD off it; this asserts it actually did rather than
  // trusting the exit code of a command that can succeed in surprising ways.
  const head = currentBranch();
  if (defaults.has(head) || head === 'HEAD') {
    fail(
      `after creating ${branch}, HEAD is on \`${head}\`, which is a default branch ` +
        `(or detached). Refusing to commit (FR-02).`,
    );
  }

  for (const candidate of drifted) {
    const relative = `specs/${candidate.service}/v${candidate.version}/openapi.json`;
    const absolute = join(REPO_ROOT, relative);
    mkdirSync(dirname(absolute), { recursive: true });
    writeFileSync(absolute, candidate.body, 'utf8');

    // FR-04: older versions stay vendored alongside the new one, so a user on
    // older firmware can still pin. The previous file is deliberately not deleted.
    manifest.services[candidate.service] = {
      ...(manifest.services[candidate.service] ?? ({} as VendoredEntry)),
      version: candidate.version,
      url: candidate.specUrl,
      path: relative,
      sha256: candidate.sha256,
      openapi: candidate.openapi,
      infoVersion: candidate.infoVersion,
      operations: candidate.operations,
      declaresSecuritySchemes: candidate.declaresSecuritySchemes,
      // FR-06 / R-8: injection is required exactly when the spec declares nothing.
      authInjectionRequired: !candidate.declaresSecuritySchemes,
    };
    console.log(`  wrote ${relative}`);
  }

  manifest.fetchedAt = stamp;
  manifest.indexUrl = provenance.indexUrl;
  manifest.totalOperations = SERVICE_IDS.reduce(
    (total, service) => total + (manifest.services[service]?.operations ?? 0),
    0,
  );
  writeFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  console.log('  wrote specs/manifest.json');

  const prBodyPath = join(REPO_ROOT, '.probe', 'spec-refresh', 'pr-body.md');
  mkdirSync(dirname(prBodyPath), { recursive: true });
  writeFileSync(prBodyPath, prBody, 'utf8');
  console.log(`  wrote ${prBodyPath} (gitignored scratch — feed it to \`gh pr create --body-file\`)`);

  git('add', '--', 'specs');
  const provenanceLine =
    provenance.kind === 'mirror'
      ? `\n\nProvenance: COMMUNITY MIRROR ${provenance.repo} — requires maintainer verification (OQ-14).`
      : '\n\nProvenance: Ubiquiti developer portal.';
  git(
    'commit',
    '-m',
    `chore(specs): refresh ${drifted.map((c) => `${c.service}@${c.version}`).join(', ')}${provenanceLine}`,
  );

  console.log(`\nrefresh-specs: committed on branch \`${branch}\`.`);
  console.log('Open the PR with:');
  console.log(`  git push -u origin ${branch}`);
  console.log(
    `  gh pr create --title "chore(specs): refresh ${drifted.map((c) => c.service).join(', ')}" ` +
      `--body-file ${prBodyPath}` +
      (provenance.kind === 'mirror' ? ' --label spec-provenance:community-mirror' : ''),
  );
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error));
});
