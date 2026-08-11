/**
 * Build the action registry from the vendored OpenAPI specs (FR-01, FR-06).
 *
 * This runs at startup against files on disk. There is no network access here
 * and none anywhere in the serving path — NFR-17 requires the server to start
 * and advertise its full tool surface with all outbound traffic blocked.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import type {
  Action,
  ActionParameter,
  HttpMethod,
  ServiceId,
} from '../types.js';
import { SERVICE_IDS } from '../types.js';
import { buildActionId, deduplicate } from './actionId.js';
import { blockedDiscriminators, blocksEntireOperation, staleEntries } from './blocklist.js';

const METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

export interface SpecManifestEntry {
  version: string;
  url: string;
  path: string;
  sha256: string;
  declaresSecuritySchemes: boolean;
  authInjectionRequired: boolean;
}

export interface SpecManifest {
  services: Record<ServiceId, SpecManifestEntry>;
}

export interface RegistryBuildResult {
  actions: Action[];
  byId: Map<string, Action>;
  /** Per-service accounting, consumed by the coverage check (FR-59). */
  stats: Record<ServiceId, ServiceStats>;
  /** Non-fatal notices surfaced on stderr at startup (never stdout — NFR-19). */
  warnings: string[];
}

export interface ServiceStats {
  version: string;
  specOperations: number;
  registered: number;
  blocked: number;
  blockedDiscriminators: number;
  authInjected: boolean;
}

/** Read and parse a vendored spec, verifying its recorded digest (FR-01). */
function loadSpec(
  repoRoot: string,
  entry: SpecManifestEntry,
  service: ServiceId,
  warnings: string[],
): Record<string, any> {
  const absolute = join(repoRoot, entry.path);
  let raw: string;
  try {
    raw = readFileSync(absolute, 'utf8');
  } catch {
    throw new Error(
      `Vendored spec missing for ${service} v${entry.version} at ${entry.path}. ` +
        `Run \`npm run specs:refresh\` to vendor it. The server does not fall back to ` +
        `a different version (FR-04).`,
    );
  }

  const digest = createHash('sha256').update(raw).digest('hex');
  if (digest !== entry.sha256) {
    warnings.push(
      `${service}: vendored spec digest does not match specs/manifest.json ` +
        `(expected ${entry.sha256.slice(0, 12)}…, got ${digest.slice(0, 12)}…). ` +
        `The spec was edited in place rather than refreshed through a reviewed PR (FR-05).`,
    );
  }

  const parsed = JSON.parse(raw);
  // FR-03: the failure mode an unpinned `latest` URL produces is a 200 whose
  // body is the docs SPA shell. Validate shape, not just parseability.
  if (typeof parsed.openapi !== 'string' || !parsed.paths || typeof parsed.paths !== 'object') {
    throw new Error(
      `${entry.path} is not an OpenAPI document (no \`openapi\` version string or no \`paths\`). ` +
        `This is what an unpinned \`latest\` URL returns — check specs/manifest.json.`,
    );
  }
  return parsed;
}

/** Resolve a local `#/components/...` $ref. Remote refs are not used by these specs. */
function resolveRef(spec: Record<string, any>, ref: string): any {
  if (!ref.startsWith('#/')) return {};
  let node: any = spec;
  for (const segment of ref.slice(2).split('/')) {
    node = node?.[segment.replace(/~1/g, '/').replace(/~0/g, '~')];
    if (node === undefined) return {};
  }
  return node;
}

function deref(spec: Record<string, any>, node: any, depth = 0): any {
  if (depth > 12 || node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map((n) => deref(spec, n, depth + 1));
  if (typeof node.$ref === 'string') return deref(spec, resolveRef(spec, node.$ref), depth + 1);
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(node)) out[k] = deref(spec, v, depth + 1);
  return out;
}

function collectParameters(
  spec: Record<string, any>,
  pathItem: Record<string, any>,
  operation: Record<string, any>,
): ActionParameter[] {
  const merged = [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])];
  const seen = new Set<string>();
  const out: ActionParameter[] = [];

  for (const candidate of merged) {
    const p = deref(spec, candidate);
    if (!p?.name || !p.in) continue;
    const dedupeKey = `${p.in}:${p.name}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    if (p.in !== 'path' && p.in !== 'query' && p.in !== 'header') continue;
    out.push({
      name: p.name,
      location: p.in,
      required: p.in === 'path' ? true : Boolean(p.required),
      description: typeof p.description === 'string' ? p.description : '',
      schema: p.schema ?? {},
    });
  }
  return out;
}

/**
 * Scopes an operation requires.
 *
 * Mobility is the only API that scopes today: it needs the `mobility` app
 * scope on the key plus `read:mobility` for GETs and `write:mobility` for PUTs
 * (FR-39). Carried as action metadata so the 403 path can name what is missing
 * (FR-40) rather than emitting a bare permission denial.
 */
function requiredScopes(service: ServiceId, method: HttpMethod): string[] {
  if (service !== 'mobility') return [];
  return ['mobility', method === 'GET' ? 'read:mobility' : 'write:mobility'];
}

export function buildRegistry(
  repoRoot: string,
  manifest: SpecManifest,
  enabledServices: ReadonlySet<ServiceId>,
): RegistryBuildResult {
  const warnings: string[] = [];
  const actions: Action[] = [];
  const stats = {} as Record<ServiceId, ServiceStats>;
  const knownOperations = new Set<string>();

  for (const service of SERVICE_IDS) {
    const entry = manifest.services[service];
    if (!entry) throw new Error(`specs/manifest.json has no entry for ${service}`);

    // Always parse every spec, even for disabled services: the blocklist
    // staleness check (FR-46) and the coverage check (FR-59) must account for
    // operations the current configuration happens not to expose.
    const spec = loadSpec(repoRoot, entry, service, warnings);

    // FR-06 / R-8: Network and Protect declare no securitySchemes and no
    // security block. A client generated straight from the spec would send
    // unauthenticated requests. Auth injection is unconditional in the HTTP
    // layer; this asserts the precondition rather than assuming it.
    const declares = Object.keys(spec.components?.securitySchemes ?? {}).length > 0;
    if (entry.authInjectionRequired) {
      if (declares) {
        warnings.push(
          `${service}: spec now DOES declare securitySchemes. The unconditional ` +
            `auth-header injection may be redundant — review before it double-applies (FR-06).`,
        );
      } else {
        warnings.push(
          `${service}: spec declares no securitySchemes; injecting the X-API-Key ` +
            `header requirement for all ${service} operations (FR-06).`,
        );
      }
    }

    let specOperations = 0;
    let registered = 0;
    let blocked = 0;
    let discriminatorsBlocked = 0;
    const rawIds: Array<{ id: string; action: Omit<Action, 'id'> }> = [];

    for (const [path, pathItemRaw] of Object.entries(spec.paths as Record<string, any>)) {
      const pathItem = pathItemRaw ?? {};
      for (const method of METHODS) {
        const operation = pathItem[method.toLowerCase()];
        if (!operation) continue;
        specOperations += 1;
        knownOperations.add(`${service} ${method} ${path}`);

        const fullyBlocked = blocksEntireOperation(service, method, path);
        if (fullyBlocked) {
          blocked += 1;
          continue;
        }

        const withheld = blockedDiscriminators(service, method, path);
        discriminatorsBlocked += withheld.length;

        if (!enabledServices.has(service)) continue;

        const actionClass = method === 'GET' ? 'read' : 'write';
        const summary: string = operation.summary ?? '';
        const description: string = operation.description ?? '';
        const tags: string[] = Array.isArray(operation.tags) ? operation.tags : [];

        let requestBody: Action['requestBody'];
        const bodySpec = deref(spec, operation.requestBody);
        if (bodySpec?.content) {
          const contentType =
            Object.keys(bodySpec.content).find((c) => c.includes('json')) ??
            Object.keys(bodySpec.content)[0];
          if (contentType) {
            requestBody = {
              required: Boolean(bodySpec.required),
              contentType,
              schema: bodySpec.content[contentType]?.schema ?? {},
            };
          }
        }

        const withheldNote = withheld.length
          ? ` Withheld variants (FR-46): ${withheld
              .map((w) => `${w.discriminator} — ${w.reason}`)
              .join(' ')}`
          : '';

        rawIds.push({
          id: buildActionId(service, method, path, operation.operationId),
          action: {
            service,
            method,
            path,
            actionClass,
            summary,
            description: description + withheldNote,
            tags,
            parameters: collectParameters(spec, pathItem, operation),
            requestBody,
            // FR-30: Site Manager Early Access paths carry the 100 req/min
            // bucket, not the 10,000 req/min stable one.
            earlyAccess: service === 'site-manager' && path.startsWith('/ea/'),
            requiredScopes: requiredScopes(service, method),
            searchText: [path, summary, description, tags.join(' '), operation.operationId ?? '']
              .join(' ')
              .toLowerCase(),
          },
        });
        registered += 1;
      }
    }

    const finalIds = deduplicate(rawIds.map((r) => r.id));
    finalIds.forEach((id, i) => {
      const entry = rawIds[i];
      if (entry) actions.push({ id, ...entry.action });
    });

    stats[service] = {
      version: entry.version,
      specOperations,
      registered,
      blocked,
      blockedDiscriminators: discriminatorsBlocked,
      authInjected: entry.authInjectionRequired,
    };
  }

  // A blocklist entry that no longer matches any operation is worse than no
  // entry: it reads as protection that is not there. Hard failure, not warning.
  const stale = staleEntries(knownOperations);
  if (stale.length > 0) {
    throw new Error(
      `Never-Ship blocklist has ${stale.length} entr${stale.length === 1 ? 'y' : 'ies'} ` +
        `matching no operation in the vendored specs. Ubiquiti renames paths without ` +
        `notice (R-1), so these no longer block anything:\n` +
        stale.map((e) => `  - ${e.service} ${e.method} ${e.path}`).join('\n') +
        `\nUpdate src/registry/blocklist.ts to match the current specs (FR-46, OQ-11).`,
    );
  }

  const byId = new Map(actions.map((a) => [a.id, a]));
  return { actions, byId, stats, warnings };
}
