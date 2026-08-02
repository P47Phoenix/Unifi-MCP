/**
 * Blocklist explanation tests (FR-46, US-06).
 *
 * The requirement these cover is not "the blocklist is enforced" — that is
 * `registry.test.ts` — but that a caller who asks for a withheld operation is
 * *told* so. Silence reads as "this API cannot do that", which is false, and
 * the previous substring matcher produced exactly that silence for any phrasing
 * that did not happen to quote a path fragment.
 *
 * So every query below is written the way an operator would say it, and none of
 * them contains the path or the discriminator it is expected to find. A test
 * that quoted `RESTART` would pass against the matcher this story replaced.
 *
 * These run against the real registry and the real blocklist, for the same
 * reason `search.test.ts` does: recall is a property of this ranker meeting
 * Ubiquiti's actual vocabulary, and a fixture would let it pass while the
 * shipped tool stayed silent.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import { loadConfig } from '../src/config.js';
import { CredentialStore } from '../src/credentials.js';
import { UnifiClient } from '../src/http/client.js';
import { NEVER_SHIP } from '../src/registry/blocklist.js';
import { buildRegistry } from '../src/registry/build.js';
import { createHandlers, type HandlerContext, type ToolResult } from '../src/tools/handlers.js';
import { searchBlocklist } from '../src/tools/search.js';
import { SERVICE_IDS, type ServiceId } from '../src/types.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'));
const { actions } = buildRegistry(REPO_ROOT, manifest, new Set<ServiceId>(SERVICE_IDS));

type Handler = (args: Record<string, unknown>) => Promise<ToolResult>;

/**
 * A context whose HTTP client is real but unreachable.
 *
 * Search resolves entirely out of the registry, so nothing here can touch a
 * console, `api.ui.com`, an API key or the OS keychain: the config is loaded
 * from an empty environment, which leaves every service without credentials.
 */
function contextFor(registry: typeof actions): HandlerContext {
  const config = loadConfig({}, { repoRoot: REPO_ROOT });
  const credentials = new CredentialStore(config, { env: {}, warn: () => {} });
  return {
    config,
    client: new UnifiClient(config, credentials, { warn: () => {} }),
    actions: registry,
    byId: new Map(registry.map((a) => [a.id, a])),
  };
}

function handlerFor(ctx: HandlerContext, name: string): Handler {
  const handler = createHandlers(ctx)[name];
  assert.ok(handler, `${name} is not registered`);
  return handler;
}

const searchTool = handlerFor(contextFor(actions), 'unifi_search_actions');
const writeTool = handlerFor(contextFor(actions), 'unifi_execute_write_action');

/**
 * The same tool over a registry with no services enabled (FR-22 allows exactly
 * this: enablement is opt-in by evidence, and an environment with no
 * credentials enables nothing). Every query returns no results, which is the
 * only way to reach the empty branch of the handler — no phrasing produces zero
 * actions and a non-empty withheld set, because withheld operations are always
 * *about* resources the registry also covers.
 */
const searchToolWithEmptyRegistry = handlerFor(
  contextFor(buildRegistry(REPO_ROOT, manifest, new Set<ServiceId>()).actions),
  'unifi_search_actions',
);

const textOf = (result: ToolResult): string => result.content.map((c) => c.text).join('\n');

const structured = (result: ToolResult, key: string): unknown =>
  (result.structuredContent ?? {})[key];

const withheldOf = (result: ToolResult): Array<Record<string, unknown>> =>
  structured(result, 'withheld') as Array<Record<string, unknown>>;

/**
 * One plain-language query per blocklist entry.
 *
 * Every entry needs one: an entry no phrasing can surface is an entry whose
 * explanation can never be shown, which is the defect this story fixes wearing
 * a different hat.
 */
const PLAIN_LANGUAGE: ReadonlyArray<readonly [string, string]> = [
  ['reboot an access point', '/v1/sites/{siteId}/devices/{deviceId}/actions'],
  [
    'power cycle a switch port',
    '/v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions',
  ],
  ['adopt a new access point', '/v1/sites/{siteId}/devices'],
  ['remove a device from the site', '/v1/sites/{siteId}/devices/{deviceId}'],
  ['delete a wifi network', '/v1/sites/{siteId}/networks/{networkId}'],
  ['delete an ssid', '/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}'],
  ['permanently disable a camera mic', '/v1/cameras/{id}/disable-mic-permanently'],
];

const RESTART_PATH = '/v1/sites/{siteId}/devices/{deviceId}/actions';

describe('withheld matching goes through the search ranker (FR-46)', () => {
  test('the queries name neither the path nor the discriminator', () => {
    // Guards the guard: if a query starts quoting spec text, these tests stop
    // proving that ordinary phrasing works.
    for (const [query] of PLAIN_LANGUAGE) {
      for (const entry of NEVER_SHIP) {
        assert.equal(query.includes(entry.path), false, `"${query}" quotes ${entry.path}`);
        const discriminator = entry.discriminator?.toLowerCase();
        if (discriminator) {
          assert.equal(query.includes(discriminator), false, `"${query}" quotes ${discriminator}`);
        }
      }
    }
  });

  test('ordinary phrasing surfaces the operation it describes', () => {
    for (const [query, path] of PLAIN_LANGUAGE) {
      const paths = searchBlocklist(NEVER_SHIP, query).map((m) => m.path);
      assert.ok(paths.includes(path), `"${query}" did not surface ${path} (got ${paths.join(', ')})`);
    }
  });

  test('every blocklist entry is reachable by at least one plain-language query', () => {
    const reachable = new Set(PLAIN_LANGUAGE.map(([, path]) => path));
    for (const entry of NEVER_SHIP) {
      assert.ok(reachable.has(entry.path), `no plain-language query reaches ${entry.path}`);
    }
  });

  test('the operation a query is about outranks its neighbours', () => {
    // The withheld set is ranked, not filtered: "reboot an access point" also
    // matches the adoption blocks, and the restart variant must still lead.
    const top = searchBlocklist(NEVER_SHIP, 'reboot an access point')[0];
    assert.equal(top?.path, RESTART_PATH);
    assert.deepEqual(top?.variants, ['RESTART']);
  });

  test('an unrelated query withholds nothing', () => {
    assert.deepEqual(searchBlocklist(NEVER_SHIP, 'quarterly revenue forecast'), []);
  });

  test('the service filter applies to the withheld set as it does to results', () => {
    const matches = searchBlocklist(NEVER_SHIP, 'permanently disable a camera mic', {
      service: 'network',
    });
    assert.deepEqual(matches, []);
  });

  test('the withheld set is capped so it cannot swamp the answer', () => {
    for (const [query] of PLAIN_LANGUAGE) {
      assert.ok(searchBlocklist(NEVER_SHIP, query).length <= 3);
    }
  });
});

describe('three-way disposition (FR-46, G-1)', () => {
  test('a discriminator classifies as variant-withheld, its absence as whole-operation', () => {
    for (const [query, path] of PLAIN_LANGUAGE) {
      const match = searchBlocklist(NEVER_SHIP, query).find((m) => m.path === path);
      assert.ok(match, `${path} absent for "${query}"`);
      const entry = NEVER_SHIP.find((e) => e.path === path);
      assert.ok(entry);
      const expected = entry.discriminator ? 'variant-withheld' : 'whole-operation';
      assert.equal(match.disposition, expected, `${path} classified ${match.disposition}`);
      assert.deepEqual(match.variants, entry.discriminator ? [entry.discriminator] : []);
    }
  });

  test('a variant withholding is reported as reachable, never as unavailable', async () => {
    const result = await searchTool({ query: 'reboot an access point' });
    const text = textOf(result);
    assert.match(text, /remains reachable, but its RESTART variant is deliberately withheld/);
    // The operation IS reachable — only the RESTART body value is refused — so
    // no sentence about it may claim otherwise.
    const sentence = sentenceFor(text, RESTART_PATH);
    assert.doesNotMatch(sentence, /not exposed|unavailable|cannot be reached|does not exist/i);
  });

  test('a whole-operation block says it is absent in every configuration', async () => {
    const result = await searchTool({ query: 'adopt a new access point' });
    const sentence = sentenceFor(textOf(result), '/v1/sites/{siteId}/devices ');
    assert.match(sentence, /is deliberately not exposed by this server, in any configuration/);
  });
});

/** The one explanation line mentioning `path`. */
function sentenceFor(text: string, path: string): string {
  const line = text.split('\n').find((l) => l.startsWith('- ') && l.includes(path));
  assert.ok(line, `no explanation line for ${path} in:\n${text}`);
  return line;
}

describe('the search tool explains rather than omits (FR-46)', () => {
  test('a query that also returns results still names the operation and its reason', async () => {
    const result = await searchTool({ query: 'reboot an access point' });
    const matches = structured(result, 'matches') as unknown[];
    assert.ok(matches.length > 0, 'expected ordinary results alongside the explanation');

    const restart = NEVER_SHIP.find((e) => e.discriminator === 'RESTART');
    assert.ok(restart);
    const sentence = sentenceFor(textOf(result), RESTART_PATH);
    assert.ok(sentence.includes('POST'), 'method missing');
    assert.ok(sentence.includes('(network)'), 'service missing');
    assert.ok(sentence.includes(restart.reason), 'recorded reason missing');
  });

  test('a query that returns nothing is not an empty answer', async () => {
    const result = await searchToolWithEmptyRegistry({ query: 'reboot an access point' });
    assert.deepEqual(structured(result, 'matches'), []);

    const restart = NEVER_SHIP.find((e) => e.discriminator === 'RESTART');
    assert.ok(restart);
    const sentence = sentenceFor(textOf(result), RESTART_PATH);
    assert.ok(sentence.includes(restart.reason), 'recorded reason missing');
    assert.ok(withheldOf(result).length > 0, 'withheld set empty');
  });

  test('both branches tell it the same way — one composer, one wording', async () => {
    // The defect this replaces: the results-present branch dropped the reason
    // while the empty branch kept it, so the same fact read differently
    // depending on whether other results happened to match. Structurally this
    // is also what makes the explanation identical over stdio and over HTTP:
    // there is no second string to drift.
    const withResults = sentenceFor(textOf(await searchTool({ query: 'reboot an access point' })), RESTART_PATH);
    const withoutResults = sentenceFor(
      textOf(await searchToolWithEmptyRegistry({ query: 'reboot an access point' })),
      RESTART_PATH,
    );
    assert.equal(withResults, withoutResults);
  });

  test('an unrelated query explains nothing', async () => {
    const result = await searchTool({ query: 'quarterly revenue forecast' });
    assert.deepEqual(withheldOf(result), []);
    assert.doesNotMatch(textOf(result), /withheld|not exposed/i);
  });
});

describe('the explanation offers no route to the withheld thing (FR-46)', () => {
  const INVOCABLE_KEYS = ['action_id', 'execute_with', 'parameters', 'action_class'];

  test('withheld operations never appear in the invocable set', async () => {
    for (const [query] of PLAIN_LANGUAGE) {
      const result = await searchTool({ query });
      const matches = structured(result, 'matches') as Array<{ path: string; method: string }>;
      for (const match of matches) {
        const blocked = NEVER_SHIP.some(
          (e) => !e.discriminator && e.path === match.path && e.method === match.method,
        );
        assert.equal(blocked, false, `${match.method} ${match.path} is invocable in matches`);
      }
    }
  });

  test('the withheld payload carries nothing that could be called', async () => {
    const result = await searchTool({ query: 'reboot an access point' });
    const withheld = withheldOf(result);
    assert.ok(withheld.length > 0);
    for (const entry of withheld) {
      assert.deepEqual(
        Object.keys(entry).sort(),
        ['disposition', 'method', 'path', 'reason', 'service', 'variants'],
      );
      for (const key of INVOCABLE_KEYS) {
        assert.equal(key in entry, false, `withheld entry carries ${key}`);
      }
    }
  });

  test('no explanation line names an execute tool', async () => {
    for (const [query] of PLAIN_LANGUAGE) {
      const text = textOf(await searchTool({ query }));
      for (const line of text.split('\n').filter((l) => l.startsWith('- '))) {
        assert.doesNotMatch(line, /unifi_execute|execute_with|action_id/);
      }
    }
  });
});

describe('the unknown-action-id error is shape-correct (FR-46)', () => {
  test('a variant-withheld neighbour is not described as unexposed', async () => {
    const result = await writeTool({ action_id: 'network.restart_device' });
    const text = textOf(result);
    assert.equal(result.isError, true);
    assert.match(text, /remains reachable, but its RESTART variant is deliberately withheld/);
    assert.doesNotMatch(text, /not exposed by this server/);
  });

  test('a whole-operation neighbour is described as unexposed', async () => {
    const result = await writeTool({ action_id: 'protect.disable_mic_permanently' });
    assert.match(textOf(result), /is deliberately not exposed by this server, in any configuration/);
  });

  test('an id resembling nothing withheld gets no blocklist sentence', async () => {
    const text = textOf(await writeTool({ action_id: 'billing.quarterly_revenue_forecast' }));
    assert.doesNotMatch(text, /blocklist/);
  });
});

describe('determinism (NFR-22)', () => {
  test('identical calls to the matcher give identical output', () => {
    const first = searchBlocklist(NEVER_SHIP, 'reboot an access point');
    const second = searchBlocklist(NEVER_SHIP, 'reboot an access point');
    assert.deepEqual(first, second);
  });

  test('identical calls to the tool give identical output', async () => {
    const first = await searchTool({ query: 'delete a wifi network' });
    const second = await searchTool({ query: 'delete a wifi network' });
    assert.deepEqual(first, second);
  });
});
