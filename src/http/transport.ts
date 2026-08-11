/**
 * Base-URL resolution for the three transports (FR-07, FR-08, FR-10, FR-11).
 *
 * The only thing that varies between local-direct and Cloud Connector mode is
 * the string produced here. FR-11 depends on that being literally true: the
 * action registry, the tool schemas, and the argument shapes are identical in
 * both modes, so a transport switch can never change tool-facing behaviour.
 */
import type { ServerConfig } from '../config.js';
import type { Action, ServiceId, TransportMode } from '../types.js';
import { UnifiError } from '../types.js';
import { localError } from './errors.js';

export const CLOUD_BASE_URL = 'https://api.ui.com';

/** The one host the insecure TLS opt-in must never apply to (FR-09, NFR-14). */
export const CLOUD_HOST = 'api.ui.com';

/**
 * Local-console and Connector paths share this per-service segment.
 *
 * OQ-06: the Cloud Connector's own prose shows example paths WITHOUT `/proxy`,
 * while three other sources include it — the `servers[]` entries in both the
 * Network and Protect specs (verified in specs/network/v10.4.57/openapi.json
 * and specs/protect/v7.1.87/openapi.json), the path-parameter example, and
 * `ai-gettingstarted.md`. FR-10 resolves the inconsistency in favour of
 * `/proxy/...` on the weight of three sources against one. If empirical testing
 * ever shows the vendor changed position, this constant is the single edit.
 */
const PROXY_SEGMENT: Record<'network' | 'protect', string> = {
  network: '/proxy/network/integration',
  protect: '/proxy/protect/integration',
};

export interface ResolvedTarget {
  baseUrl: string;
  mode: TransportMode;
  /** Hostname the request will actually contact. Drives the TLS decision. */
  host: string;
  /** Set for connector mode only; named in timeout errors (NFR-16). */
  consoleId: string | null;
}

function configError(service: ServiceId, message: string, hint: string): UnifiError {
  return new UnifiError(localError(service, 'config', message, hint));
}

/**
 * Resolve where a service's requests go, and how.
 *
 * Mobility is deliberately NOT reachable through the Connector (FR-38): it is a
 * cloud-native API and proxying it through a console makes no sense.
 */
export function resolveTarget(
  config: ServerConfig,
  service: ServiceId,
  host?: string,
): ResolvedTarget {
  if (service === 'site-manager' || service === 'mobility') {
    // FR-07 describes Mobility's base as `https://api.ui.com/v1/mobility`, but
    // every Mobility path in the vendored spec already begins `/v1/mobility/…`
    // and the spec's own `servers[]` entry is bare `https://api.ui.com`.
    // Prefixing here would produce `/v1/mobility/v1/mobility/…`, so the base is
    // the bare origin and the effective base URL emerges from the join.
    return { baseUrl: CLOUD_BASE_URL, mode: 'cloud', host: CLOUD_HOST, consoleId: null };
  }

  const mode = config.transport[service];

  if (mode === 'connector') {
    const consoleId = config.consoleId;
    if (!consoleId) {
      throw configError(
        service,
        `${service} is configured for Cloud Connector transport but UNIFI_CONSOLE_ID is not set.`,
        `Set UNIFI_CONSOLE_ID to the console you want to proxy through, or set ` +
          `UNIFI_${service.toUpperCase()}_TRANSPORT=local and configure UNIFI_LOCAL_HOST.`,
      );
    }
    return {
      baseUrl:
        `${CLOUD_BASE_URL}/v1/connector/consoles/${encodeURIComponent(consoleId)}` +
        PROXY_SEGMENT[service],
      mode,
      host: CLOUD_HOST,
      consoleId,
    };
  }

  const target = host ?? config.defaultLocalHost;
  if (!target) {
    throw configError(
      service,
      `${service} is configured for local-direct transport but no console host is configured.`,
      `Set UNIFI_LOCAL_HOST to the console address (for example 192.168.1.1) and ` +
        `UNIFI_LOCAL_API_KEY to a key created on that console.`,
    );
  }
  return {
    baseUrl: `https://${target}${PROXY_SEGMENT[service]}`,
    mode: 'local',
    host: target,
    consoleId: null,
  };
}

export function resolveBaseUrl(
  config: ServerConfig,
  service: ServiceId,
  host?: string,
): { baseUrl: string; mode: TransportMode } {
  const { baseUrl, mode } = resolveTarget(config, service, host);
  return { baseUrl, mode };
}

/** Values a path or query parameter may take once coerced from tool arguments. */
export type ParamValue = string | number | boolean | Array<string | number | boolean>;

function renderPath(action: Action, pathParams: Record<string, unknown>): string {
  return action.path.replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const value = pathParams[name];
    if (value === undefined || value === null || value === '') {
      throw configError(
        action.service,
        `Action \`${action.id}\` requires the path parameter \`${name}\`, which was not supplied.`,
        `Call unifi_search_actions for \`${action.id}\` to see its required parameters, then ` +
          `retry with \`${name}\` set.`,
      );
    }
    // Path segments carry console-generated ids that may contain `:` and `/`;
    // encoding is what keeps `a/b` one segment rather than two.
    return encodeURIComponent(String(value));
  });
}

export function buildUrl(
  config: ServerConfig,
  action: Action,
  pathParams: Record<string, unknown> = {},
  query: Record<string, unknown> = {},
  host?: string,
): string {
  const { baseUrl } = resolveTarget(config, action.service, host);
  const url = new URL(baseUrl + renderPath(action, pathParams));

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) url.searchParams.append(key, String(item));
      }
    } else {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}
