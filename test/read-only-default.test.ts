/**
 * The read-only default, ASSERTED rather than assumed (FR-44, G-6, NFR-01).
 *
 * What this file proves: with no `UNIFI_ENABLE_WRITES` in the environment, the
 * server advertises no write tool, and invoking every single tool it DOES
 * advertise produces not one POST, PUT, PATCH or DELETE at the only seam where
 * an HTTP verb is ever chosen — `UnifiClient.request`, whose verb is
 * `action.method` passed straight through.
 *
 * ## The anti-vacuity design — do not weaken any of this
 *
 * A previous review found that the naive reading of FR-44's criterion ("no
 * mutating request reaches any UniFi API, asserted by an outbound-request
 * interceptor") is satisfied by a test that stands up a recorder, invokes
 * NOTHING, and asserts `mutating.length === 0`. That test passes. It also
 * passes if every read tool is deleted, if the client is broken, and if every
 * handler throws on entry. It proves nothing at all.
 *
 * Three of the five assertions below exist specifically to fail for that
 * degenerate shape:
 *
 *  - H-RO-1 puts a strictly positive lower bound on the ledger, computed from
 *    the production tool definitions rather than typed in.
 *  - H-RO-2 asserts the set of tools actually invoked equals the advertised
 *    surface, so deleting a tool or skipping one is a failure.
 *  - H-RO-5 proves the recorder can fail, by enabling writes and watching the
 *    same assertion go red.
 *
 * H-RO-3 asserts the empty ARRAY rather than a zero count, so its failure
 * message names the offending method and path. H-RO-4 pins the configuration
 * under test to the default one, so a future edit cannot quietly turn writes on
 * and leave the mutating assertion green because nothing ever called a write.
 *
 * The two surface runs are built ONCE at module load and asserted over by
 * several cases each; they are deliberately module-scoped, and nothing mutates
 * them.
 */
import { strict as assert } from 'node:assert';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import { loadConfig } from '../src/config.js';
import { EXECUTE_WRITE_ACTION, SEARCH_ACTIONS, advertisedTools } from '../src/tools/definitions.js';
import { SERVICE_IDS, type HttpMethod, type ServiceId } from '../src/types.js';
import { describeEntry, runAdvertisedSurface } from './fixtures/recording-client.js';
import { plantedEnv } from './fixtures/sentinel.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

const allServices = new Set<ServiceId>(SERVICE_IDS);
const MUTATING_METHODS = new Set<HttpMethod>(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Tools that answer from memory and make no outbound call.
 *
 * Derived from the exported tool definition, NOT from the ledger. Deriving it
 * from the ledger would define "local-only" as "made no request", which is what
 * the partition assertion is trying to test — the whole thing would collapse
 * into a tautology.
 */
const LOCAL_ONLY_TOOLS: readonly string[] = [SEARCH_ACTIONS.name];

// --- the default posture: everything enabled, writes untouched ---------------
const defaultConfig = loadConfig(plantedEnv(), { repoRoot: REPO_ROOT });
const defaultRun = await runAdvertisedSurface({ config: defaultConfig, repoRoot: REPO_ROOT });

const expectedSurface = advertisedTools(allServices, new Set()).map((tool) => tool.name).sort();
const outboundToolCount = expectedSurface.filter(
  (name) => !LOCAL_ONLY_TOOLS.includes(name),
).length;

const mutatingRequests = defaultRun.ledger.filter((entry) => MUTATING_METHODS.has(entry.method));

// --- the proof that the recorder can fail ------------------------------------
const writesConfig = loadConfig(plantedEnv({ UNIFI_ENABLE_WRITES: 'all' }), {
  repoRoot: REPO_ROOT,
});
const writesRun = await runAdvertisedSurface({ config: writesConfig, repoRoot: REPO_ROOT });
const writesMutatingRequests = writesRun.ledger.filter((entry) =>
  MUTATING_METHODS.has(entry.method),
);

describe('read-only default — the interceptor is not vacuous (FR-44)', () => {
  test('H-RO-1: the interceptor recorded a strictly positive number of requests', () => {
    assert.ok(
      defaultRun.ledger.length > 0,
      'interceptor recorded zero requests — this assertion is vacuous. A ledger that is never ' +
        'populated satisfies every "no mutating request" check while proving nothing.',
    );
  });

  test('H-RO-1: every outbound tool in the surface produced at least one request', () => {
    assert.ok(
      defaultRun.ledger.length >= outboundToolCount,
      `only ${defaultRun.ledger.length} request(s) recorded for ${outboundToolCount} outbound ` +
        `tool(s). At least one advertised tool reached no client call, so the mutating-method ` +
        `assertion covers less of the surface than it appears to. Ledger: ` +
        `${defaultRun.ledger.map(describeEntry).join('; ') || '(empty)'}`,
    );
  });

  test('H-RO-2: exactly the advertised surface was invoked, nothing skipped', () => {
    assert.deepEqual([...defaultRun.invoked].sort(), expectedSurface);
  });

  test('H-RO-2: the surface partitions cleanly into outbound and local-only tools', () => {
    const requested = new Set(defaultRun.ledger.map((entry) => entry.tool));
    const outbound = defaultRun.invoked.filter((name) => requested.has(name));
    const localOnly = defaultRun.invoked.filter((name) => !requested.has(name));

    // A mis-partition must fail rather than quietly hide a tool in neither half.
    assert.deepEqual([...outbound, ...localOnly].sort(), expectedSurface);
    assert.deepEqual(localOnly.sort(), [...LOCAL_ONLY_TOOLS].sort());
  });

  test('H-RO-3: not one mutating request reached the client (FR-44, NFR-01)', () => {
    // The empty ARRAY, not a zero count: on failure the message names the
    // offending method and path instead of saying `1 !== 0`.
    assert.deepEqual(
      mutatingRequests,
      [],
      `mutating requests escaped the read-only default: ` +
        `${mutatingRequests.map(describeEntry).join('; ')}`,
    );
  });

  test('H-RO-4: the configuration under test is the default one', () => {
    assert.equal(
      defaultConfig.writesEnabled.size,
      0,
      'the fixture environment enabled writes, so the read-only assertions above were made ' +
        'against a configuration that is not the default posture FR-44 describes',
    );
    assert.equal(defaultRun.surface.includes(EXECUTE_WRITE_ACTION.name), false);
    assert.deepEqual([...defaultConfig.enabledServices].sort(), [...SERVICE_IDS].sort());
  });
});

describe('read-only default — the recorder is proven able to fail (FR-44)', () => {
  test('H-RO-5: enabling writes advertises the write tool', () => {
    assert.ok(writesConfig.writesEnabled.size > 0);
    assert.ok(writesRun.surface.includes(EXECUTE_WRITE_ACTION.name));
  });

  test('H-RO-5: with writes enabled the ledger genuinely records a mutating request', () => {
    assert.ok(
      writesMutatingRequests.length > 0,
      'writes were enabled and the write tool was invoked, yet the interceptor recorded no ' +
        'mutating request. The recorder cannot see writes at all, which makes H-RO-3 green for ' +
        'the wrong reason.',
    );
    assert.ok(
      writesMutatingRequests.every((entry) => entry.tool === EXECUTE_WRITE_ACTION.name),
      `a tool other than the write tool issued a mutating request: ` +
        `${writesMutatingRequests.map(describeEntry).join('; ')}`,
    );
  });

  test('H-RO-5: the H-RO-3 assertion fails when a mutating request is present', () => {
    // Run the exact assertion from H-RO-3 over a ledger that DOES contain
    // writes. If this does not throw, H-RO-3 is incapable of ever failing.
    assert.throws(() => assert.deepEqual(writesMutatingRequests, []));
  });
});
