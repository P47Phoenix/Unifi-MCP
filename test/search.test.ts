/**
 * Search ranking tests (FR-19).
 *
 * These run against the real registry, because ranking quality is a property of
 * this scorer meeting Ubiquiti's actual vocabulary. A fixture would let the
 * scorer pass while the shipped search stayed broken.
 *
 * Assertions are stated as "the intended action appears within the top N"
 * rather than pinning exact scores: scores are a tuning detail, position is the
 * contract, and pinning scores would make every future tuning change a test
 * rewrite.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { test, describe } from 'node:test';

import { buildRegistry } from '../src/registry/build.js';
import { expandConcepts, resourceOf, searchActions } from '../src/tools/search.js';
import { SERVICE_IDS, type ServiceId } from '../src/types.js';

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(`${REPO_ROOT}specs/manifest.json`, 'utf8'));
const { actions } = buildRegistry(REPO_ROOT, manifest, new Set<ServiceId>(SERVICE_IDS));

const rankOf = (query: string, actionId: string, limit = 10): number =>
  searchActions(actions, query, { limit }).findIndex((r) => r.action.id === actionId);

describe('query expansion', () => {
  test('maps operator vocabulary onto spec vocabulary', () => {
    const variants = expandConcepts('access points').flatMap((c) => c.variants);
    assert.ok(variants.includes('device'));
  });

  test('drops the literal word once it has a domain mapping', () => {
    // Keeping "access" would match "Access Control List" across the ACL
    // endpoints, which is how this query used to return firewall rules.
    const variants = expandConcepts('access points').flatMap((c) => c.variants);
    assert.equal(variants.includes('access'), false);
  });

  test('drops stopwords', () => {
    const originals = expandConcepts('which devices are on my network').map((c) => c.original);
    assert.deepEqual(originals, ['devices', 'network']);
  });

  test('groups synonyms under one concept so breadth does not inflate score', () => {
    const concepts = expandConcepts('wifi');
    assert.equal(concepts.length, 1);
    assert.ok(concepts[0]!.variants.length > 1);
  });
});

describe('resource extraction', () => {
  test('takes the terminal non-parameter segment', () => {
    assert.equal(resourceOf('/v1/sites/{siteId}/devices'), 'devices');
    assert.equal(resourceOf('/v1/cameras/{id}/snapshot'), 'snapshot');
    assert.equal(resourceOf('/v1/hosts'), 'hosts');
  });

  test('ignores path parameters and wildcards', () => {
    assert.equal(resourceOf('/v1/cameras/{id}'), 'cameras');
    assert.equal(resourceOf('/v1/connector/consoles/{id}/*path'), 'consoles');
  });
});

describe('ranking (FR-19)', () => {
  test('"which access points are offline" surfaces the Network device list', () => {
    // The literal FR-19 acceptance criterion: at least one Network
    // device-listing action, with its schema, must come back.
    const results = searchActions(actions, 'which access points are offline', { limit: 10 });
    const networkDeviceList = results.find(
      (r) => r.action.id === 'network.get_adopted_device_overview_page',
    );
    assert.ok(networkDeviceList, 'Network device list absent from results');
    assert.ok(networkDeviceList.action.parameters.length > 0, 'action carries no schema');
  });

  test('common intents put the right action in the top three', () => {
    const cases: Array<[string, string]> = [
      ['what devices are on my network', 'network.get_adopted_device_overview_page'],
      ['who is connected to my wifi', 'network.get_connected_client_overview_page'],
      ['list my cameras', 'protect.get_cameras'],
      ['show me my sites', 'site_manager.list_sites'],
      ['what consoles do I have', 'site_manager.list_hosts'],
      ['guest wifi vouchers', 'network.get_vouchers'],
      ['camera snapshot', 'protect.get_cameras_by_id_snapshot'],
    ];
    for (const [query, expected] of cases) {
      const rank = rankOf(query, expected);
      assert.ok(rank >= 0 && rank < 3, `"${query}" ranked ${expected} at ${rank}`);
    }
  });

  test('prefers the collection endpoint over the by-id lookup', () => {
    const results = searchActions(actions, 'cameras', { limit: 5 });
    assert.equal(results[0]?.action.id, 'protect.get_cameras');
  });

  test('does not let the ubiquitous /sites/{siteId} prefix dominate', () => {
    // Almost every Network path contains `/sites/{siteId}/`, so a naive path
    // match on "site" ranks the whole API by coincidence.
    const top = searchActions(actions, 'sites', { limit: 3 }).map((r) => resourceOf(r.action.path));
    assert.ok(top.every((r) => r.includes('site')), `got resources ${top.join(', ')}`);
  });

  test('ranks reads above writes for an ambiguous intent', () => {
    const results = searchActions(actions, 'firewall policies', { limit: 5 });
    assert.equal(results[0]?.action.actionClass, 'read');
  });

  test('honours the service filter', () => {
    const results = searchActions(actions, 'devices', { service: 'mobility', limit: 10 });
    assert.ok(results.length > 0);
    assert.ok(results.every((r) => r.action.service === 'mobility'));
  });

  test('honours the action-class filter', () => {
    const results = searchActions(actions, 'firewall', { actionClass: 'write', limit: 10 });
    assert.ok(results.length > 0);
    assert.ok(results.every((r) => r.action.actionClass === 'write'));
  });

  test('returns an empty set rather than noise for an unrelated query', () => {
    assert.deepEqual(searchActions(actions, 'quarterly revenue forecast', { limit: 10 }), []);
  });

  test('respects the hard limit', () => {
    assert.ok(searchActions(actions, 'device', { limit: 100 }).length <= 25);
  });

  test('is stable across identical calls (NFR-22)', () => {
    const a = searchActions(actions, 'devices', { limit: 10 }).map((r) => r.action.id);
    const b = searchActions(actions, 'devices', { limit: 10 }).map((r) => r.action.id);
    assert.deepEqual(a, b);
  });

  test('every returned id resolves in the registry — usable without transformation', () => {
    const byId = new Map(actions.map((a) => [a.id, a]));
    for (const query of ['devices', 'cameras', 'sites', 'firewall', 'vouchers']) {
      for (const { action } of searchActions(actions, query, { limit: 10 })) {
        assert.ok(byId.has(action.id), `${action.id} does not resolve`);
      }
    }
  });
});
