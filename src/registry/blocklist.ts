/**
 * The Never-Ship blocklist (FR-46).
 *
 * These operations are absent from the action registry in EVERY configuration,
 * including one booted with all writes enabled. They are not gated, not
 * confirmed, not behind a flag — they are not built.
 *
 * The line, per FR-46: an operation is blocked when it is not undoable from a
 * chat window AND its blast radius exceeds any conversational benefit.
 * Reversible mutations are gated instead, via the read-only default (FR-44)
 * plus `destructiveHint` (FR-47).
 *
 * ## Why entries carry an optional discriminator
 *
 * The Network API does not give each dangerous verb its own path. It exposes
 * generic `.../actions` endpoints whose request body carries an OpenAPI
 * discriminator naming the verb:
 *
 *   POST /v1/sites/{siteId}/devices/{deviceId}/actions   {"action": "RESTART"}
 *   POST /v1/sites/{siteId}/clients/{clientId}/actions   {"action": "AUTHORIZE_GUEST_ACCESS"}
 *   POST .../interfaces/ports/{portIdx}/actions          {"action": "POWER_CYCLE"}
 *
 * Blocking by path alone would be wrong in both directions: it would block
 * guest-access authorisation (reversible, useful, explicitly gated-not-blocked
 * by FR-46) while pretending to be precise. So an entry may name a
 * discriminator value, and only that variant is withheld.
 *
 * ## Deltas from the FR-46 text — for OQ-11 ratification
 *
 * FR-46 was written before the vendored specs were enumerated. Measured against
 * the real mutating surface (32 Network + 35 Protect operations):
 *
 *  - "firmware upgrade initiation" — NO SUCH OPERATION exists in the Network
 *    v10.4.57 spec. Nothing to block.
 *  - "factory reset" — likewise absent.
 *  - "site deletion" — likewise absent; there is no DELETE /v1/sites/{siteId}.
 *  - "WLAN deletion" — exists, but is spelled `wifi/broadcasts`. Blocked below.
 *  - ADDED: Protect `disable-mic-permanently`. Not in FR-46's list because its
 *    existence was unknown when FR-46 was written. "Permanently" is
 *    definitionally irreversible, so it meets FR-46's stated principle.
 *
 * OQ-11's resolution path calls for exactly this review "against the actual
 * mutating operations enumerated from the vendored specs at M2". These deltas
 * are the output of that step and need maintainer sign-off before the write
 * path ships at M4.
 */
import type { BlocklistEntry } from '../types.js';

export const NEVER_SHIP: readonly BlocklistEntry[] = [
  // ---- Reboot and power (FR-46: "console or device reboot and power-cycle") --
  {
    service: 'network',
    method: 'POST',
    path: '/v1/sites/{siteId}/devices/{deviceId}/actions',
    discriminator: 'RESTART',
    reason:
      'Rebooting a device drops every client on it, and the operator may be reaching the controller through the very device being restarted. No software path back.',
  },
  {
    service: 'network',
    method: 'POST',
    path: '/v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions',
    discriminator: 'POWER_CYCLE',
    reason:
      'PoE power-cycle drops whatever is plugged into that port, including uplinks and cameras, with no software path back.',
  },

  // ---- Adoption lifecycle (FR-46: "device adoption and un-adoption") ---------
  {
    service: 'network',
    method: 'POST',
    path: '/v1/sites/{siteId}/devices',
    reason:
      'Adoption rewrites device ownership and credentials. Recovering a wrongly-adopted device generally requires physical access to a reset button.',
  },
  {
    service: 'network',
    method: 'DELETE',
    path: '/v1/sites/{siteId}/devices/{deviceId}',
    reason:
      'Un-adoption ("forget") removes the device from the site and resets it. Not reversible from chat.',
  },

  // ---- Destructive topology deletion (FR-46: "site, network, or WLAN") -------
  // No DELETE /v1/sites/{siteId} exists in Network v10.4.57 — nothing to block.
  {
    service: 'network',
    method: 'DELETE',
    path: '/v1/sites/{siteId}/networks/{networkId}',
    reason:
      'Deleting a network severs every client on it and destroys its configuration. No undo.',
  },
  {
    service: 'network',
    method: 'DELETE',
    path: '/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}',
    reason:
      'The WLAN equivalent in this spec. Deleting it disconnects every wireless client and loses the PSK.',
  },

  // ---- Irreversible by construction (Protect) --------------------------------
  {
    service: 'protect',
    method: 'POST',
    path: '/v1/cameras/{id}/disable-mic-permanently',
    reason:
      'The upstream operation is named "permanently" and is documented as irreversible; the microphone cannot be re-enabled through the API. Added beyond the FR-46 list — see OQ-11.',
  },
] as const;

function key(service: string, method: string, path: string): string {
  return `${service} ${method} ${path}`;
}

/**
 * Whether an operation is blocked outright — i.e. every variant of it.
 *
 * An entry carrying a discriminator does NOT block the whole path; the
 * operation stays in the registry with that one variant withheld.
 */
export function blocksEntireOperation(
  service: string,
  method: string,
  path: string,
): BlocklistEntry | undefined {
  return NEVER_SHIP.find(
    (e) => !e.discriminator && key(e.service, e.method, e.path) === key(service, method, path),
  );
}

/** Discriminator values withheld from an otherwise-exposed operation. */
export function blockedDiscriminators(
  service: string,
  method: string,
  path: string,
): BlocklistEntry[] {
  return NEVER_SHIP.filter(
    (e) => e.discriminator && key(e.service, e.method, e.path) === key(service, method, path),
  );
}

/**
 * Blocklist entries whose path is absent from the vendored specs.
 *
 * Ubiquiti renames paths without advance notice (R-1), so an entry can quietly
 * stop matching and silently re-expose what it was written to withhold. The
 * registry build treats a stale entry as a hard error rather than a warning:
 * a blocklist that no longer matches is worse than no blocklist, because it
 * reads as protection that is not there.
 */
export function staleEntries(knownOperations: ReadonlySet<string>): BlocklistEntry[] {
  return NEVER_SHIP.filter((e) => !knownOperations.has(key(e.service, e.method, e.path)));
}
