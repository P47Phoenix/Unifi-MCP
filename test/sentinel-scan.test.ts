/**
 * Credentials never surface in output (NFR-12).
 *
 * Sentinel key values are planted as the configured cloud key, local console
 * key and labelled local console key. Every tool in the advertised surface is
 * then invoked — once on a healthy client and once on a client that rejects
 * every request — and every byte the server produces is walked for those
 * values: tool result text, `structuredContent`, rendered error results, and
 * anything a handler threw. The redacted startup summary and the live
 * `ServerConfig` object graph are walked too.
 *
 * ## Deferred channels — named, not silently skipped
 *
 * NFR-12 has six sentinel channels. Three are NOT reachable at this point in
 * the plan because the seams they need do not exist yet, and pretending
 * otherwise would leave a gap nobody could see:
 *
 *  - H-SS-2, captured stderr: needs the `RuntimeDeps` seam. Patching
 *    `process.stderr.write` is not an acceptable substitute — it is the module
 *    mocking Node 20 cannot do safely, and it would test the patch rather than
 *    the server.
 *  - H-SS-4, HTTP response bodies and headers: needs the serving transport and
 *    a `ServingObserver` to observe them.
 *  - H-SS-6, container `/proc/self/environ` and `docker logs`: needs a built
 *    image and a running container, neither of which belongs in the unit suite.
 *
 * H-SS-3 is therefore covered here only in its in-repo half — `redactedSummary`
 * and the config object — with the served-over-HTTP half deferred alongside
 * H-SS-4.
 *
 * The two surface runs are built ONCE at module load and asserted over by
 * several cases each. Nothing mutates them.
 */
import { strict as assert } from 'node:assert';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import { loadConfig, redactedSummary } from '../src/config.js';
import { runAdvertisedSurface } from './fixtures/recording-client.js';
import {
  CLOUD_API_KEY_SENTINEL,
  LABELLED_LOCAL_API_KEY_SENTINEL,
  LOCAL_API_KEY_SENTINEL,
  MAX_SCAN_DEPTH,
  SENTINEL_VALUES,
  plantedEnv,
  scanForSentinels,
} from './fixtures/sentinel.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

const config = loadConfig(plantedEnv(), { repoRoot: REPO_ROOT });

const healthyRun = await runAdvertisedSurface({ config, repoRoot: REPO_ROOT });
const rejectingRun = await runAdvertisedSurface({
  config,
  repoRoot: REPO_ROOT,
  shouldFail: () => true,
});

describe('planted sentinels (NFR-12)', () => {
  test('every sentinel is long, distinct, and none contains another', () => {
    const values = [...SENTINEL_VALUES.values()];
    for (const value of values) {
      assert.ok(value.length >= 32, `${value} is too short to be collision-proof`);
      assert.match(value, /^SENTINEL-[A-Z-]+-[0-9a-f]{16}$/);
      const containers = values.filter((other) => other !== value && other.includes(value));
      assert.deepEqual(containers, [], `${value} is a substring of another sentinel`);
    }
    assert.equal(new Set(values).size, values.length);
  });

  test('the fixture really did configure the planted keys', () => {
    // Without this, a typo in the environment would leave nothing to find and
    // every scan below would pass by having nothing to search for.
    assert.equal(config.hasCloudApiKey, true);
    assert.deepEqual(
      config.localConsoles.filter((console_) => console_.hasApiKey).map((c) => c.label).sort(),
      ['EDGE', 'default'],
    );
  });
});

describe('H-SS-1: no sentinel reaches a tool result or an error (NFR-12)', () => {
  test('healthy run: every tool result is sentinel-free', () => {
    for (const [tool, result] of healthyRun.results) {
      scanForSentinels(result, `healthy.${tool}`);
    }
  });

  test('healthy run: no handler threw, so no thrown error escaped unscanned', () => {
    for (const [tool, failure] of healthyRun.failures) {
      scanForSentinels(failure, `healthy.${tool}.thrown`);
    }
    assert.deepEqual([...healthyRun.failures.keys()], []);
  });

  test('rejecting run: the error rendering path was actually taken', () => {
    // Anti-vacuity: scanning error output proves nothing unless errors happened.
    const errored = [...rejectingRun.results.entries()]
      .filter(([, result]) => result.isError === true)
      .map(([tool]) => tool);
    assert.ok(
      errored.length > 0,
      'no tool rendered an error result even though the client rejected every request; the ' +
        'error-path scan below would have had nothing to search',
    );

    const requested = new Set(rejectingRun.ledger.map((entry) => entry.tool));
    assert.deepEqual(
      errored.sort(),
      [...requested].sort(),
      'a tool that made a request did not surface the rejection as an error result',
    );
  });

  test('rejecting run: every rendered error and thrown error is sentinel-free', () => {
    for (const [tool, result] of rejectingRun.results) {
      scanForSentinels(result, `rejecting.${tool}`);
    }
    for (const [tool, failure] of rejectingRun.failures) {
      // A UnifiError carries `normalized` as an own enumerable property, so the
      // walker reaches the recovery hint and correlation id through it.
      scanForSentinels(failure, `rejecting.${tool}.thrown`);
    }
  });
});

describe('H-SS-3: no sentinel reaches the startup summary or the config (NFR-12, FR-55)', () => {
  test('redactedSummary carries zero key material', () => {
    scanForSentinels(redactedSummary(config), 'redactedSummary');
  });

  test('the live ServerConfig object graph carries zero key material', () => {
    scanForSentinels(config, 'config');
  });

  test('the summary still names the env vars, which is the actionable half', () => {
    const summary = redactedSummary(config) as {
      credentials: {
        cloudKey: { envVar: string; present: boolean };
        localConsoles: Array<{ keyEnvVar: string; keyPresent: boolean }>;
      };
    };
    assert.equal(summary.credentials.cloudKey.envVar, 'UNIFI_API_KEY');
    assert.equal(summary.credentials.cloudKey.present, true);
    assert.ok(summary.credentials.localConsoles.every((c) => c.keyPresent));
  });
});

describe('H-SS-5: the scanner is proven able to fail before it is trusted to pass', () => {
  test('a tool result that echoes a sentinel fails the scan', () => {
    const pollutedResult = {
      content: [{ type: 'text', text: `Authenticated with ${CLOUD_API_KEY_SENTINEL}.` }],
      structuredContent: { items: [] },
    };
    assert.throws(() => scanForSentinels(pollutedResult), /UNIFI_API_KEY/);
  });

  test('a sentinel hidden in a Buffer fails the scan', () => {
    // JSON.stringify renders this as {"type":"Buffer","data":[…]}, in which a
    // naive substring search finds nothing.
    const buffered = { payload: Buffer.from(LOCAL_API_KEY_SENTINEL, 'utf8') };
    assert.throws(() => scanForSentinels(buffered), /UNIFI_LOCAL_API_KEY/);
  });

  test('a sentinel hidden in a Uint8Array fails the scan', () => {
    const bytes = new Uint8Array(Buffer.from(LABELLED_LOCAL_API_KEY_SENTINEL, 'latin1'));
    assert.throws(() => scanForSentinels({ bytes }), /UNIFI_LOCAL_API_KEY_EDGE/);
  });

  test('a sentinel hidden in a Map value fails the scan', () => {
    const map = new Map<string, unknown>([['headers', { 'x-api-key': CLOUD_API_KEY_SENTINEL }]]);
    assert.throws(() => scanForSentinels({ map }), /UNIFI_API_KEY/);
  });

  test('a sentinel hidden in a Map key fails the scan', () => {
    const map = new Map<string, number>([[LOCAL_API_KEY_SENTINEL, 1]]);
    assert.throws(() => scanForSentinels({ map }), /UNIFI_LOCAL_API_KEY/);
  });

  test("a sentinel hidden in an Error's cause fails the scan", () => {
    // JSON.stringify renders an Error as {} — message, stack and cause all gone.
    const error = new Error('request failed', {
      cause: new Error(`upstream rejected key ${LOCAL_API_KEY_SENTINEL}`),
    });
    assert.throws(() => scanForSentinels(error), /UNIFI_LOCAL_API_KEY/);
  });

  test('a sentinel hidden in a Set member fails the scan', () => {
    assert.throws(
      () => scanForSentinels({ seen: new Set([CLOUD_API_KEY_SENTINEL]) }),
      /UNIFI_API_KEY/,
    );
  });

  test('a sentinel used as an object key fails the scan', () => {
    assert.throws(
      () => scanForSentinels({ [LABELLED_LOCAL_API_KEY_SENTINEL]: true }),
      /UNIFI_LOCAL_API_KEY_EDGE/,
    );
  });

  test('a sentinel reachable only through a getter fails the scan', () => {
    const lazy = {
      get token(): string {
        return CLOUD_API_KEY_SENTINEL;
      },
    };
    assert.throws(() => scanForSentinels(lazy), /UNIFI_API_KEY/);
  });

  test('a getter that throws fails the walk rather than being skipped', () => {
    const hostile = {
      get token(): string {
        throw new Error('access denied');
      },
    };
    assert.throws(() => scanForSentinels(hostile), /cannot be proven free of credentials/);
  });

  test('an over-deep structure fails the walk rather than stopping quietly', () => {
    let deep: unknown = { leaf: 'nothing here' };
    for (let level = 0; level < MAX_SCAN_DEPTH + 8; level += 1) deep = { nested: deep };
    assert.throws(() => scanForSentinels(deep), /depth cap/);
  });

  test('a cyclic structure terminates instead of hanging', () => {
    const cyclic: Record<string, unknown> = { name: 'safe' };
    cyclic.self = cyclic;
    scanForSentinels(cyclic);
  });
});
