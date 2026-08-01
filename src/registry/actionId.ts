/**
 * Stable action identifiers.
 *
 * Action IDs are user-facing: `unifi_search_actions` returns them and the
 * execute tools accept them verbatim (FR-19). They must therefore be stable
 * across spec refreshes — an ID that changes shape between firmware versions
 * silently breaks any saved workflow that referenced it.
 *
 * Site Manager, Network and Mobility supply an `operationId` for every
 * operation. Protect v7.1.87 supplies NONE — all 73 operations lack one — so
 * IDs there are synthesised deterministically from method and path.
 */
import type { HttpMethod, ServiceId } from '../types.js';

/** camelCase / PascalCase / kebab-case → snake_case. */
export function toSnakeCase(input: string): string {
  return input
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .toLowerCase();
}

/**
 * Turn a path template into an ID fragment.
 *
 * The leading API version segment is dropped — it is already pinned by the
 * vendored spec version and repeating it in every ID adds noise without
 * distinguishing anything. Path parameters become `by_<name>` so that
 * `/cameras` and `/cameras/{id}` do not collide.
 *
 *   /v1/cameras                     → cameras
 *   /v1/cameras/{id}                → cameras_by_id
 *   /v1/cameras/{id}/snapshot       → cameras_by_id_snapshot
 *   /v1/sites/{siteId}/devices      → sites_by_site_id_devices
 */
export function pathToSlug(path: string): string {
  const segments = path.split('/').filter(Boolean);
  if (segments[0] && /^v\d+$/i.test(segments[0])) segments.shift();

  return segments
    .map((segment) => {
      const param = segment.match(/^\{(.+)\}$/);
      if (param?.[1]) return `by_${toSnakeCase(param[1])}`;
      // Site Manager's ConnectorGet uses a `*path` wildcard segment.
      if (segment.startsWith('*')) return toSnakeCase(segment.slice(1));
      return toSnakeCase(segment);
    })
    .filter(Boolean)
    .join('_');
}

/**
 * Build an action ID.
 *
 * `service.operation_id` where the spec provides one, else a synthesised
 * `service.method_path_slug`. The service prefix keeps IDs unambiguous when
 * search returns results spanning several APIs.
 */
export function buildActionId(
  service: ServiceId,
  method: HttpMethod,
  path: string,
  operationId: string | undefined,
): string {
  const prefix = toSnakeCase(service);
  if (operationId && operationId.trim()) {
    return `${prefix}.${toSnakeCase(operationId)}`;
  }
  return `${prefix}.${method.toLowerCase()}_${pathToSlug(path)}`;
}

/**
 * Disambiguate IDs that collide.
 *
 * Nothing in the current four specs collides, but Ubiquiti adds operations
 * without notice (R-1) and a silent collision would make one action
 * unreachable. Suffixing is deterministic so IDs stay stable given the same
 * spec input (NFR-22).
 */
export function deduplicate(ids: string[]): string[] {
  const seen = new Map<string, number>();
  return ids.map((id) => {
    const count = seen.get(id) ?? 0;
    seen.set(id, count + 1);
    return count === 0 ? id : `${id}_${count + 1}`;
  });
}
