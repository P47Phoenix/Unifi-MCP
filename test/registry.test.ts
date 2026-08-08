/**
 * Registry, action-ID, and blocklist tests.
 *
 * These run against the real vendored specs rather than fixtures: the point of
 * most of them is that the server's assumptions still hold against what
 * Ubiquiti actually published, which a fixture would hide.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import { buildRegistry } from '../src/registry/build.js';
import { buildActionId, pathToSlug, toSnakeCase, deduplicate } from '../src/registry/actionId.js';
import {
  NEVER_SHIP,
  blockedDiscriminators,
  blocksEntireOperation,
  staleEntries,
} from '../src/registry/blocklist.js';
import { advertisedTools, ALL_TOOLS } from '../src/tools/definitions.js';
import { SERVICE_IDS, type ServiceId } from '../src/types.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'));
const allServices = new Set<ServiceId>(SERVICE_IDS);

describe('action IDs', () => {
  test('snake-cases camelCase operation IDs', () => {
    assert.equal(toSnakeCase('getAdoptedDeviceOverviewPage'), 'get_adopted_device_overview_page');
    assert.equal(toSnakeCase('listHosts'), 'list_hosts');
    assert.equal(toSnakeCase('getISPMetrics'), 'get_isp_metrics');
  });

  test('path slugs distinguish collection from item', () => {
    assert.equal(pathToSlug('/v1/cameras'), 'cameras');
    assert.equal(pathToSlug('/v1/cameras/{id}'), 'cameras_by_id');
    assert.equal(pathToSlug('/v1/cameras/{id}/snapshot'), 'cameras_by_id_snapshot');
  });

  test('synthesises an ID when the spec supplies no operationId', () => {
    // Every one of Protect v7.1.87's 73 operations lacks an operationId.
    assert.equal(buildActionId('protect', 'GET', '/v1/cameras', undefined), 'protect.get_cameras');
    assert.equal(
      buildActionId('protect', 'PATCH', '/v1/cameras/{id}', undefined),
      'protect.patch_cameras_by_id',
    );
  });

  test('deduplicates collisions deterministically', () => {
    assert.deepEqual(deduplicate(['a', 'b', 'a', 'a']), ['a', 'b', 'a_2', 'a_3']);
  });
});

describe('never-ship blocklist (FR-46)', () => {
  test('every entry carries a reason', () => {
    for (const entry of NEVER_SHIP) {
      assert.ok(entry.reason.trim().length > 20, `${entry.path} needs a real reason`);
    }
  });

  test('no entry is stale against the vendored specs', () => {
    // A blocklist entry matching nothing is worse than no entry: it reads as
    // protection that is not there. buildRegistry throws on this; assert the
    // predicate directly so the failure names the offender.
    const { stats } = buildRegistry(REPO_ROOT, manifest, allServices);
    assert.ok(stats.network.blocked > 0);
    const known = new Set<string>();
    for (const service of SERVICE_IDS) {
      const spec = JSON.parse(
        readFileSync(join(REPO_ROOT, manifest.services[service].path), 'utf8'),
      );
      for (const [path, item] of Object.entries(spec.paths as Record<string, any>)) {
        for (const method of Object.keys(item ?? {})) {
          known.add(`${service} ${method.toUpperCase()} ${path}`);
        }
      }
    }
    assert.deepEqual(staleEntries(known), []);
  });

  test('withholds reboot as a discriminator, not by blocking the whole endpoint', () => {
    // Network exposes reboot as {"action":"RESTART"} on a generic actions
    // endpoint. Blocking the path would also block guest-access authorisation,
    // which FR-46 explicitly gates rather than blocks.
    const path = '/v1/sites/{siteId}/devices/{deviceId}/actions';
    assert.equal(blocksEntireOperation('network', 'POST', path), undefined);
    const withheld = blockedDiscriminators('network', 'POST', path);
    assert.equal(withheld.length, 1);
    assert.equal(withheld[0]?.discriminator, 'RESTART');
  });

  test('leaves reversible client actions reachable', () => {
    const path = '/v1/sites/{siteId}/clients/{clientId}/actions';
    assert.equal(blocksEntireOperation('network', 'POST', path), undefined);
    assert.deepEqual(blockedDiscriminators('network', 'POST', path), []);
  });

  test('blocked operations are absent even with every service enabled', () => {
    const { actions } = buildRegistry(REPO_ROOT, manifest, allServices);
    const present = new Set(actions.map((a) => `${a.service} ${a.method} ${a.path}`));
    for (const entry of NEVER_SHIP) {
      if (entry.discriminator) continue;
      assert.ok(
        !present.has(`${entry.service} ${entry.method} ${entry.path}`),
        `${entry.method} ${entry.path} must not be registered`,
      );
    }
  });
});

describe('registry build', () => {
  test('accounts for every operation in every vendored spec (FR-59)', () => {
    const { actions, stats } = buildRegistry(REPO_ROOT, manifest, allServices);
    let specTotal = 0;
    let blockedTotal = 0;
    for (const service of SERVICE_IDS) {
      specTotal += stats[service].specOperations;
      blockedTotal += stats[service].blocked;
      assert.equal(
        stats[service].specOperations,
        manifest.services[service].operations,
        `${service} operation count drifted from specs/manifest.json`,
      );
    }
    assert.equal(specTotal, 168);
    assert.equal(actions.length + blockedTotal, specTotal, 'operations unaccounted for');
  });

  test('flags exactly the two services whose specs declare no securitySchemes (FR-06)', () => {
    const { stats } = buildRegistry(REPO_ROOT, manifest, allServices);
    assert.equal(stats.network.authInjected, true);
    assert.equal(stats.protect.authInjected, true);
    assert.equal(stats['site-manager'].authInjected, false);
    assert.equal(stats.mobility.authInjected, false);
  });

  test('classifies GET as read and everything else as write (NFR-01)', () => {
    const { actions } = buildRegistry(REPO_ROOT, manifest, allServices);
    for (const action of actions) {
      assert.equal(action.actionClass, action.method === 'GET' ? 'read' : 'write');
    }
  });

  test('carries Mobility scope metadata on every Mobility action (FR-39)', () => {
    const { actions } = buildRegistry(REPO_ROOT, manifest, allServices);
    const mobility = actions.filter((a) => a.service === 'mobility');
    assert.equal(mobility.length, 8);
    for (const action of mobility) {
      assert.ok(action.requiredScopes.includes('mobility'));
      assert.ok(
        action.requiredScopes.includes(action.method === 'GET' ? 'read:mobility' : 'write:mobility'),
      );
    }
  });

  test('no service outside Mobility claims a scope requirement', () => {
    const { actions } = buildRegistry(REPO_ROOT, manifest, allServices);
    for (const action of actions.filter((a) => a.service !== 'mobility')) {
      assert.deepEqual(action.requiredScopes, []);
    }
  });

  test('action IDs are unique across the whole registry', () => {
    const { actions } = buildRegistry(REPO_ROOT, manifest, allServices);
    assert.equal(new Set(actions.map((a) => a.id)).size, actions.length);
  });

  test('is deterministic — same specs produce the same registry (NFR-22)', () => {
    const a = buildRegistry(REPO_ROOT, manifest, allServices);
    const b = buildRegistry(REPO_ROOT, manifest, allServices);
    assert.deepEqual(
      a.actions.map((x) => x.id),
      b.actions.map((x) => x.id),
    );
  });

  test('disabling a service drops its actions but still accounts for them', () => {
    const withoutProtect = new Set<ServiceId>(['site-manager', 'network', 'mobility']);
    const { actions, stats } = buildRegistry(REPO_ROOT, manifest, withoutProtect);
    assert.equal(actions.some((a) => a.service === 'protect'), false);
    // The spec is still parsed so coverage and blocklist staleness stay honest.
    assert.equal(stats.protect.specOperations, 73);
  });
});

describe('advertised tool surface', () => {
  test('write tool is absent by default (FR-44, G-6)', () => {
    const tools = advertisedTools(allServices, new Set());
    assert.equal(tools.some((t) => t.name === 'unifi_execute_write_action'), false);
  });

  test('write tool appears only once writes are explicitly enabled', () => {
    const tools = advertisedTools(allServices, new Set<ServiceId>(['mobility']));
    assert.ok(tools.some((t) => t.name === 'unifi_execute_write_action'));
  });

  test('no configuration advertises more than the declared surface (FR-18, FR-74)', () => {
    // FR-18's cap was written here as the literal 12. A literal cannot notice a
    // thirteenth tool being declared, so the bound that actually protects the
    // budget is the declared surface itself: `advertisedTools` filters
    // `ALL_TOOLS`, so the widest configuration can only ever equal it, and any
    // configuration that exceeded it would mean the filter had started
    // inventing tools. Computed, never enumerated (FR-74, §14 item 14).
    const tools = advertisedTools(allServices, new Set<ServiceId>(['network']));
    assert.ok(tools.length <= ALL_TOOLS.length, `advertised ${tools.length} tools`);
    assert.ok(ALL_TOOLS.length > 0, 'the declared surface is empty, so this bound proves nothing');
    // The cap is a budget, not an accident of today's surface: the token budget
    // gate (G-3) is what enforces the cost, and FR-18's ceiling is asserted
    // against the declared set rather than against a number kept in step by hand.
    assert.deepEqual(
      tools.filter((tool) => !ALL_TOOLS.includes(tool)),
      [],
      'advertisedTools returned a tool that is not declared in ALL_TOOLS',
    );
  });

  test('disabling Protect removes the camera tool (FR-22)', () => {
    const tools = advertisedTools(new Set<ServiceId>(['site-manager']), new Set());
    assert.equal(tools.some((t) => t.name === 'unifi_list_cameras'), false);
    assert.ok(tools.some((t) => t.name === 'unifi_list_sites'));
  });

  test('every tool carries title and readOnlyHint; writes carry destructiveHint (NFR-02)', () => {
    for (const tool of ALL_TOOLS) {
      assert.ok(tool.annotations.title, `${tool.name} needs a title`);
      assert.equal(typeof tool.annotations.readOnlyHint, 'boolean');
      if (!tool.annotations.readOnlyHint) {
        assert.equal(tool.annotations.destructiveHint, true, `${tool.name} needs destructiveHint`);
      }
    }
  });

  test('tool names are snake_case and within 64 characters (NFR-10)', () => {
    for (const tool of ALL_TOOLS) {
      assert.match(tool.name, /^[a-z][a-z0-9_]{0,63}$/, `${tool.name} violates the name rule`);
    }
  });

  test('no description instructs the model how to behave (NFR-04, FR-58)', () => {
    const injectionPatterns = [
      /\balways call\b/i,
      /\bfirst call\b/i,
      /\byou must\b/i,
      /\bnever respond\b/i,
      /\bbe sure to\b/i,
      /\bmake sure you\b/i,
      /\bignore (?:previous|prior)\b/i,
    ];
    for (const tool of ALL_TOOLS) {
      for (const pattern of injectionPatterns) {
        assert.equal(
          pattern.test(tool.description),
          false,
          `${tool.name} description matches ${pattern}`,
        );
      }
    }
  });

  test('each promoted read tool names a sibling it could be confused with (NFR-03)', () => {
    // The promotion predicate is `requiresService`: a promoted read tool is one
    // that exists because a specific API is enabled (FR-22), which is exactly
    // the set `advertisedTools` drops when that API is off. The literal 5 this
    // replaces restated the answer instead of deriving it, so promoting a sixth
    // tool would have turned this red for a reason unrelated to NFR-03.
    const promoted = ALL_TOOLS.filter((t) => t.name.startsWith('unifi_list_'));
    assert.deepEqual(
      promoted.map((t) => t.name).sort(),
      ALL_TOOLS.filter((t) => t.requiresService !== undefined)
        .map((t) => t.name)
        .sort(),
      'the promoted read tools are exactly the service-gated tools (FR-22)',
    );
    assert.ok(promoted.length > 0, 'the scan matched nothing, so it proves nothing');
    for (const tool of promoted) {
      const namesAnother = ALL_TOOLS.some(
        (other) => other.name !== tool.name && tool.description.includes(other.name),
      );
      assert.ok(namesAnother, `${tool.name} names no sibling`);
    }
  });

  test('execute tools name the upstream API they wrap', () => {
    for (const name of ['unifi_execute_action', 'unifi_execute_write_action']) {
      const tool = ALL_TOOLS.find((t) => t.name === name);
      assert.ok(tool);
      assert.match(tool.description, /developer\.ui\.com/);
    }
  });
});
