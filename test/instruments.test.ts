/**
 * US-25 — the FR-75 instruments, treated as deliverables under test.
 *
 * FR-75 is a requirement in its own right, not scaffolding: ten Must-Have
 * acceptance criteria across nine requirements name an instrument, and an
 * instrument nobody has proven able to FAIL is a green test that means nothing.
 * So every instrument below is exercised in both directions — it records the
 * thing when the thing happens, and it records nothing when it does not.
 *
 * Five sections:
 *
 *   1. The committed certificate pair — the offline blocker, resolved.
 *   2. The outbound interceptor, against the PRODUCTION client, over a real
 *      socket, through the real credential path.
 *   3. The invocation counters, observed at the `Runtime` call site.
 *   4. The spawned harness — A2 (`ECONNREFUSED`) and A3 (the
 *      transport-activation counter in both configurations).
 *   5. The operating envelope, pinned as an assertion rather than as prose.
 *
 * `src/index.ts` is never imported here (S-09). Section 4 spawns
 * `test/harness/serve-entry.ts`, which is the one module permitted to import
 * it and which is not a test file.
 *
 * Every `CredentialStore` reached from this file is constructed by
 * `createInstruments`, which always passes `keychain: null` (S-09): `npm ci`
 * installs `keytar` on the macOS and Windows legs, so a store built without it
 * would query the runner's — or a developer's — real login keychain.
 */
import assert from 'node:assert/strict';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { CLOUD_HOST, resolveTarget } from '../src/http/transport.js';
import { blockedDiscriminators, blocksEntireOperation } from '../src/registry/blocklist.js';
import {
  buildRuntimeCore,
  resolveRegistry,
  type RuntimeCore,
} from '../src/serve/runtime.js';
import type { Action, ServiceId } from '../src/types.js';

import {
  assertAbsentFromText,
  createInstruments,
  parseCounterLine,
  type CounterSnapshot,
  type Instruments,
} from './harness/counters.js';
import {
  LOOPBACK_CERT_PATH,
  LOOPBACK_KEY_PATH,
  MUTATING_METHODS,
  describeAttempt,
  loopbackEnv,
  mergeLedgers,
  startLoopbackOrigin,
  type InterceptedRequest,
  type LoopbackOrigin,
  type OutboundAttempt,
} from './harness/interceptor.js';
import {
  DEFAULT_SERVING_PORT,
  probePort,
  spawnServeEntry,
} from './harness/spawn.js';
import type { LedgerEntry } from './fixtures/recording-client.js';
import { LOCAL_API_KEY_SENTINEL, scanForSentinels } from './fixtures/sentinel.js';

/** `fileURLToPath`, never `URL.pathname`: the latter yields `/D:/a/...` on Windows. */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A legal inbound secret: FR-81's floor is 32 characters. */
const INBOUND_TOKEN = `harness-inbound-secret-${'z'.repeat(32)}`;

interface Rig {
  readonly origin: LoopbackOrigin;
  readonly core: RuntimeCore;
  readonly instruments: Instruments;
  close(): Promise<void>;
}

/**
 * A production runtime wired to a live loopback origin.
 *
 * `buildRuntimeCore` and `resolveRegistry` are the real ones; the only
 * substitution is the counting `RuntimeDeps`, and each of its fields calls the
 * production collaborator behind the counter.
 */
async function rig(overrides: Readonly<Record<string, string>> = {}): Promise<Rig> {
  const origin = await startLoopbackOrigin();
  const instruments = createInstruments({ env: loopbackEnv(origin, overrides) });
  const core = buildRuntimeCore(instruments.deps);
  await resolveRegistry(core);
  assert.equal(core.readyError, null, 'the runtime failed to resolve its registry');

  return {
    origin,
    core,
    instruments,
    async close(): Promise<void> {
      await core.close();
      await origin.close();
    },
  };
}

/** True when neither the whole operation nor any variant of it is withheld. */
function isFullyExposed(action: Action): boolean {
  return (
    blocksEntireOperation(action.service, action.method, action.path) === undefined &&
    blockedDiscriminators(action.service, action.method, action.path).length === 0
  );
}

/**
 * Pick a real registry action of a given service and class.
 *
 * Chosen at run time rather than hard-coded, so a spec refresh that renames an
 * operation cannot leave this file pointing at nothing — and so that no tool
 * name or action id is enumerated as a literal list (FR-74, S-01).
 */
function pickAction(core: RuntimeCore, service: ServiceId, actionClass: 'read' | 'write'): Action {
  const actions = core.registry?.actions ?? [];
  const chosen = actions.find(
    (action) =>
      action.service === service &&
      action.actionClass === actionClass &&
      isFullyExposed(action) &&
      !action.path.includes('*'),
  );
  if (!chosen) {
    throw new Error(
      `the registry offers no exposed ${service} ${actionClass} action with a concrete path, so ` +
        `the interceptor has nothing to drive`,
    );
  }
  return chosen;
}

function pathParamsFor(action: Action): Record<string, string> {
  const params: Record<string, string> = {};
  for (const parameter of action.parameters) {
    if (parameter.location === 'path') params[parameter.name] = `synthetic-${parameter.name}`;
  }
  return params;
}

/** The FR-44 claim, as a reusable assertion so its failure names the request. */
function assertNoMutatingRequests(requests: readonly InterceptedRequest[]): void {
  const mutating = requests.filter((entry) => MUTATING_METHODS.has(entry.method));
  assert.deepEqual(
    mutating.map((entry) => `${entry.method} ${entry.path}`),
    [],
    'a state-changing request reached the outbound interceptor',
  );
}

// ===========================================================================
// 1. The committed certificate pair (AC 3)
// ===========================================================================

describe('the loopback certificate fixture — the offline blocker, resolved', () => {
  test('the certificate is self-signed for the loopback address with a far-future expiry', () => {
    const certificate = new X509Certificate(readFileSync(LOOPBACK_CERT_PATH));

    assert.equal(certificate.subject, 'CN=127.0.0.1');
    assert.equal(certificate.issuer, certificate.subject, 'the fixture must be self-signed');
    assert.equal(certificate.subjectAltName, 'IP Address:127.0.0.1');
    assert.ok(certificate.ca === false, 'the fixture must not be a certificate authority');

    // Far future, checked as a property rather than against a literal date, so
    // the assertion does not itself become the thing that expires.
    const expiresIn = new Date(certificate.validTo).getTime() - Date.now();
    const seventyYearsMs = 70 * 365 * 24 * 60 * 60 * 1000;
    assert.ok(
      expiresIn > seventyYearsMs,
      `the fixture expires in ${Math.round(expiresIn / 86_400_000)} days; it is meant to outlive ` +
        `this project so that nothing schedules a breakage`,
    );
  });

  test('the private key belongs to the certificate', () => {
    const certificate = new X509Certificate(readFileSync(LOOPBACK_CERT_PATH));
    // `checkPrivateKey` is the honest form of "the pair matches": a mismatched
    // pair otherwise surfaces only as a TLS handshake failure inside whichever
    // suite happened to use it next.
    assert.ok(certificate.checkPrivateKey(createPrivateKey(readFileSync(LOOPBACK_KEY_PATH))));
  });

  test('both files are labelled as test material before their PEM block', () => {
    // PEM parsers skip every byte before the first BEGIN marker, which is what
    // makes the banner possible. It is not decoration: a committed private key
    // with no explanation is indistinguishable from a leaked one, and a scanner
    // finding that nobody can adjudicate is a scanner finding people learn to
    // ignore.
    for (const path of [LOOPBACK_CERT_PATH, LOOPBACK_KEY_PATH]) {
      const text = readFileSync(path, 'utf8');
      assert.ok(text.startsWith('TEST MATERIAL ONLY'), `${path} lost its banner`);
      assert.ok(text.includes('127.0.0.1'), `${path} should name the only host it certifies`);
    }
  });

  test('the origin actually serves with the committed pair', async () => {
    const origin = await startLoopbackOrigin();
    try {
      assert.ok(origin.port > 0, 'the origin bound no port');
      assert.equal(origin.host, `127.0.0.1:${origin.port}`);
      assert.deepEqual(origin.requests, []);
    } finally {
      await origin.close();
    }
  });
});

// ===========================================================================
// 2. The outbound interceptor, against the production client (AC 1, AC 2)
// ===========================================================================

describe('the outbound interceptor records the production client (FR-44, FR-75, FR-78)', () => {
  test('one read action produces exactly one attempt, with its method and URL', async () => {
    const harness = await rig();
    try {
      const action = pickAction(harness.core, 'network', 'read');
      const handler = harness.core.handlers['unifi_execute_action'];
      assert.ok(handler, 'the read execution tool has no handler');

      const result = await handler({
        action_id: action.id,
        path_params: pathParamsFor(action),
      });
      assert.equal(result.isError ?? false, false, JSON.stringify(result));

      assert.equal(
        harness.origin.requests.length,
        1,
        'the interceptor did not record exactly one attempt for one read action',
      );
      const recorded = harness.origin.requests[0];
      assert.ok(recorded);
      assert.equal(recorded.method, action.method);
      assert.equal(recorded.service, 'network');
      assert.ok(
        recorded.url.startsWith(`https://${harness.origin.host}/proxy/network/integration`),
        `the recorded URL was ${recorded.url}`,
      );
    } finally {
      await harness.close();
    }
  });

  /**
   * The half every prior harness was missing.
   *
   * The credential is resolved by the PRODUCTION `CredentialStore`, from the
   * environment `buildRuntimeCore` captured before it scrubbed, and carried by
   * the production client onto a real socket. Nothing here reaches past the
   * `X-API-Key` header to read it from the store: the value asserted is the one
   * the wire carried.
   */
  test('the attempt carries the planted sentinel on X-API-Key', async () => {
    const harness = await rig();
    try {
      const handler = harness.core.handlers['unifi_list_cameras'];
      assert.ok(handler, 'the promoted Protect read tool has no handler');
      await handler({});

      assert.equal(harness.origin.requests.length, 1);
      const recorded = harness.origin.requests[0];
      assert.ok(recorded);
      assert.equal(
        recorded.apiKey,
        LOCAL_API_KEY_SENTINEL,
        'the credential the interceptor observed is not the one that was planted',
      );
      assert.equal(recorded.service, 'protect');
    } finally {
      await harness.close();
    }
  });

  test('the environment was scrubbed and the key still resolved on the first call', async () => {
    // FR-78 / NFR-31 in one run: a server that scrubs before constructing the
    // store starts clean, reports ready, and then fails the operator's first
    // tool call. The interceptor is the only instrument that can tell those two
    // outcomes apart, because the difference is visible on the wire and nowhere
    // else.
    const origin = await startLoopbackOrigin();
    const env = loopbackEnv(origin);
    const instruments = createInstruments({ env });
    const core = buildRuntimeCore(instruments.deps);
    try {
      await resolveRegistry(core);
      assert.equal(env['UNIFI_LOCAL_API_KEY'], undefined, 'the credential survived the scrub');

      const handler = core.handlers['unifi_list_cameras'];
      assert.ok(handler);
      const result = await handler({});

      const rendered = JSON.stringify(result);
      assert.ok(
        !rendered.includes('No cloud API key is configured'),
        'the first call after the scrub could not resolve a credential',
      );
      assert.equal(origin.requests.length, 1);
      assert.equal(origin.requests[0]?.apiKey, LOCAL_API_KEY_SENTINEL);
    } finally {
      await core.close();
      await origin.close();
    }
  });

  test('a run that issues no outbound action records zero attempts', async () => {
    const harness = await rig();
    try {
      const handler = harness.core.handlers['unifi_search_actions'];
      assert.ok(handler, 'the local-only search tool has no handler');
      const result = await handler({ query: 'which cameras are recording' });

      assert.equal(result.isError ?? false, false);
      assert.deepEqual(
        harness.origin.requests,
        [],
        'a purely local tool reached the network',
      );
    } finally {
      await harness.close();
    }
  });

  test('the default configuration is read-only, and no mutating request reaches the wire', async () => {
    const harness = await rig();
    try {
      assert.equal(
        harness.core.config.writesEnabled.size,
        0,
        'the fixture quietly enabled writes, which would make the next assertion vacuous',
      );
      const write = pickAction(harness.core, 'network', 'write');
      const handler = harness.core.handlers['unifi_execute_action'];
      assert.ok(handler);

      // Driven through the READ execution tool on purpose: it is the tool a
      // caller has when writes are off, and the refusal must come from the
      // server rather than from the tool being absent.
      await handler({ action_id: write.id, path_params: pathParamsFor(write) });

      assertNoMutatingRequests(harness.origin.requests);
    } finally {
      await harness.close();
    }
  });

  test('the interceptor is proven able to fail: a real write does reach the wire', async () => {
    // H-RO-5 over a real socket. Without this the read-only assertion above
    // could be green because the interceptor never records anything at all.
    const harness = await rig({ UNIFI_ENABLE_WRITES: 'network' });
    try {
      assert.ok(harness.core.config.writesEnabled.has('network'));
      const write = pickAction(harness.core, 'network', 'write');
      const handler = harness.core.handlers['unifi_execute_write_action'];
      assert.ok(handler, 'the write execution tool is not advertised with writes enabled');

      await handler({
        action_id: write.id,
        path_params: pathParamsFor(write),
        body: { note: 'synthetic write payload' },
      });

      const mutating = harness.origin.mutating();
      assert.ok(
        mutating.length > 0,
        'writes were enabled and a write action was driven, yet the interceptor recorded no ' +
          'state-changing request — the recorder is not observing the wire',
      );
      assert.throws(
        () => assertNoMutatingRequests(harness.origin.requests),
        'the FR-44 assertion passed against a ledger that contains a mutating request',
      );
    } finally {
      await harness.close();
    }
  });

  test('the key went out on the wire and reached no tool result (NFR-12)', async () => {
    // The two halves have to hold in the SAME run, and until now nothing could
    // put them there: the credential-boundary tests proved the key resolved,
    // and the sentinel suite proved nothing echoed it, but neither had a wire.
    // Here the wire is real, the interceptor proves the key crossed it, and the
    // scan proves the rendered result carries no trace of it.
    const harness = await rig();
    try {
      const handler = harness.core.handlers['unifi_list_cameras'];
      assert.ok(handler);
      const result = await handler({});

      assert.equal(harness.origin.requests[0]?.apiKey, LOCAL_API_KEY_SENTINEL);
      scanForSentinels(result, 'toolResult');
      scanForSentinels(harness.instruments.lines, 'diagnostics');

      // Proven able to fail, in this configuration, before it is trusted: a
      // scan that cannot fail is a green light wired to nothing.
      assert.throws(
        () => scanForSentinels({ echoed: LOCAL_API_KEY_SENTINEL }, 'polluted'),
        /reached the output/,
      );
    } finally {
      await harness.close();
    }
  });

  test('the text-channel scanner finds a captured value, and says so without echoing it', () => {
    // The instrument US-27 and US-29 need for the session identifier, which
    // FR-77 makes impossible to plant: it is generated by this server's own
    // CSPRNG, so it can only be captured and then hunted.
    const captured = 'e3b0c44298fc1c149afbf4c8996fb924';

    assertAbsentFromText({ stderr: 'nothing to see', logs: ['req ok'] }, captured, 'session id');

    assert.throws(
      () => assertAbsentFromText({ stderr: `Mcp-Session-Id: ${captured}` }, captured, 'session id'),
      (error: Error) => {
        assert.match(error.message, /reached 1 output location/);
        assert.ok(
          !error.message.includes(captured),
          'the failure message reproduced the value it was complaining about',
        );
        return true;
      },
    );
    assert.throws(
      () => assertAbsentFromText({ stderr: '' }, '', 'session id'),
      /empty session id/,
    );
  });

  test('the interceptor sees the retry loop, not just the first attempt', async () => {
    // The property a hook on `UnifiClient.request` structurally cannot observe:
    // retries happen below that seam. Two retryable failures then a 200 must
    // appear as three recorded attempts for one tool call. 503 rather than 500
    // because `RETRYABLE_STATUSES` is {408, 429, 502, 503, 504} — a 500 is
    // terminal, and using one here would have made this assertion about the
    // retry policy rather than about what the interceptor can see.
    const origin = await startLoopbackOrigin();
    let served = 0;
    origin.respondWith(() => {
      served += 1;
      return served <= 2
        ? { status: 503, body: { name: 'ServiceUnavailable', error: 'transient' } }
        : { status: 200, body: [] };
    });

    const instruments = createInstruments({
      env: loopbackEnv(origin, {
        UNIFI_RETRY_MAX_ATTEMPTS: '3',
        UNIFI_RETRY_BASE_DELAY_MS: '1',
        UNIFI_RETRY_MAX_DELAY_MS: '2',
      }),
    });
    const core = buildRuntimeCore(instruments.deps);
    try {
      await resolveRegistry(core);
      const handler = core.handlers['unifi_list_cameras'];
      assert.ok(handler);
      await handler({});

      assert.equal(
        origin.requests.length,
        3,
        'the interceptor recorded a different number of attempts than the retry loop made',
      );
      assertNoMutatingRequests(origin.requests);
    } finally {
      await core.close();
      await origin.close();
    }
  });
});

// ===========================================================================
// 3. The invocation counters (AC 6, AC 7)
// ===========================================================================

describe('the invocation counters, observed at the Runtime call site (FR-75)', () => {
  test('a full startup increments each once, and the transport counters not at all', async () => {
    const harness = await rig();
    try {
      const counts = harness.instruments.snapshot();
      assert.equal(counts.credentialStore, 1);
      assert.equal(counts.clientBuild, 1);
      assert.equal(counts.manifestRead, 1);
      assert.equal(counts.registryBuild, 1);

      // Nothing served, nothing bound: the counters that belong to the serving
      // transports must not move merely because a runtime was constructed.
      assert.equal(counts.listen, 0);
      assert.equal(counts.mcpRequest, 0);
      assert.deepEqual(counts.transportActivated, { stdio: 0, http: 0 });
      assert.equal(counts.ready, 0);
    } finally {
      await harness.close();
    }
  });

  test('a run that never resolves the registry does not increment its counters', async () => {
    const origin = await startLoopbackOrigin();
    const instruments = createInstruments({ env: loopbackEnv(origin) });
    const core = buildRuntimeCore(instruments.deps);
    try {
      const counts = instruments.snapshot();
      assert.equal(counts.credentialStore, 1, 'the store is built synchronously, before the bind');
      assert.equal(counts.registryBuild, 0, 'the registry must not be built before the bind');
      assert.equal(counts.manifestRead, 0, 'the startup artifact check runs with the registry');
    } finally {
      await core.close();
      await origin.close();
    }
  });

  test('the registry is built once per process however many times it is asked for', async () => {
    const harness = await rig();
    try {
      await resolveRegistry(harness.core);
      await resolveRegistry(harness.core);
      assert.equal(harness.instruments.counts.registryBuild, 1);
      assert.equal(harness.instruments.counts.manifestRead, 1);
    } finally {
      await harness.close();
    }
  });

  test('the counter is at the call site, and the production collaborator runs behind it', async () => {
    const harness = await rig();
    try {
      // If the wrapper had SUBSTITUTED the registry build rather than counting
      // it, this would be empty — which is the failure mode "count the call,
      // not the callee" is guarding against.
      assert.ok((harness.core.registry?.actions.length ?? 0) > 0);
      assert.equal(harness.instruments.counts.registryBuild, 1);
    } finally {
      await harness.close();
    }
  });

  test('the observer carries every counted event through the JSON wire format', () => {
    // An instrument self-proof, and labelled as one: it asserts that the
    // counter object records and round-trips what it is handed. The PRODUCTION
    // call sites for `onListen` and `onMcpRequest` arrive with the HTTP
    // listener in US-22; until then those two read 0 in every configuration,
    // which section 4 asserts.
    const instruments = createInstruments({ env: {} });
    instruments.observer.onTransportActivated?.('http');
    instruments.observer.onListen?.({ address: '127.0.0.1', family: 'IPv4', port: 1 });
    instruments.observer.onReady?.();
    instruments.observer.onMcpRequest?.();
    instruments.observer.onRequestLog?.('req line');
    instruments.observer.onDrainStep?.('not-ready');
    instruments.observer.onDisposal?.('limiter');

    const roundTripped = parseCounterLine(
      `unifi-mcp-harness: counters ${JSON.stringify(instruments.snapshot())}`,
    ) as CounterSnapshot;

    assert.deepEqual(roundTripped.transportActivated, { stdio: 0, http: 1 });
    assert.equal(roundTripped.listen, 1);
    assert.equal(roundTripped.listenAddresses[0]?.port, 1);
    assert.equal(roundTripped.mcpRequest, 1);
    assert.equal(roundTripped.ready, 1);
    assert.deepEqual(roundTripped.requestLogs, ['req line']);
    assert.deepEqual(roundTripped.drainSteps, ['not-ready']);
    assert.deepEqual(roundTripped.disposals, ['limiter']);
  });
});

// ===========================================================================
// 4. The spawned harness — A2 and A3 (AC 8)
// ===========================================================================

describe('the spawned harness — the entrypoint under observation (FR-62, FR-75)', () => {
  test('A2: with no serving-transport variable set, nothing listens on the default port', async () => {
    // The baseline first. Without it, a green result could mean "the server
    // bound nothing" or "someone else already owns 8787 and refused us for an
    // unrelated reason"; asserting the port is free BEFORE the spawn tells the
    // two apart and names the collision when it happens.
    const before = await probePort(DEFAULT_SERVING_PORT);
    assert.equal(
      before.outcome,
      'refused',
      `port ${DEFAULT_SERVING_PORT} was not free before the child started (${before.outcome}); ` +
        `this assertion cannot distinguish our listener from a pre-existing one`,
    );

    const server = spawnServeEntry({
      env: { UNIFI_API_KEY: `SENTINEL-CLOUD-KEY-${'0'.repeat(16)}` },
      after: 'hold',
    });
    try {
      const counts = await server.counters();
      assert.deepEqual(counts.transportActivated, { stdio: 1, http: 0 });

      // `lsof` and `ss` appear nowhere in this repository: neither exists on
      // windows-latest and NFR-20 requires that leg green. A connection attempt
      // is the portable negative.
      const after = await probePort(DEFAULT_SERVING_PORT, '127.0.0.1', 2_000);
      assert.equal(
        after.outcome,
        'refused',
        `a stdio server opened a listening socket on ${DEFAULT_SERVING_PORT}`,
      );
      assert.equal(counts.listen, 0, 'the listen counter moved on a transport that binds nothing');
    } finally {
      await server.stop();
    }
  });

  test('A3 (stdio): the entrypoint activates exactly one serving transport', async () => {
    const server = spawnServeEntry({
      env: { UNIFI_API_KEY: `SENTINEL-CLOUD-KEY-${'1'.repeat(16)}` },
      after: 'exit',
    });
    try {
      const counts = await server.counters();
      assert.equal(counts.transportActivated.stdio, 1);
      assert.equal(counts.transportActivated.http, 0);
      assert.equal(counts.ready, 1, 'the stdio transport did not report ready');
      assert.equal(counts.registryBuild, 1);
      assert.equal(counts.manifestRead, 1);
      assert.equal(counts.credentialStore, 1);

      const exit = await server.exit();
      assert.equal(exit.code, 0, server.stderr());
    } finally {
      await server.stop();
    }
  });

  test('A3 (http): the other surface is counted, and stdio is not', async () => {
    // The counter is read at `main`'s branch, which fires BEFORE the surface is
    // served — so this assertion is available now and is unchanged when US-22
    // replaces the temporary refusal with a real listener. What changes then is
    // the exit code and the message, not the counter.
    const server = spawnServeEntry({
      env: {
        UNIFI_API_KEY: `SENTINEL-CLOUD-KEY-${'2'.repeat(16)}`,
        UNIFI_MCP_TRANSPORT: 'http',
        UNIFI_HTTP_TOKEN: INBOUND_TOKEN,
      },
    });
    try {
      const counts = await server.counters();
      assert.equal(counts.transportActivated.http, 1);
      assert.equal(counts.transportActivated.stdio, 0);
      assert.equal(counts.listen, 0, 'nothing may bind while the HTTP transport is unbuilt');

      const exit = await server.exit();
      assert.equal(exit.code, 1);
      assert.match(server.stderr(), /unifi-mcp: ERROR /);
    } finally {
      await server.stop();
    }
  });

  test('the descriptor on argv[2] is the configuration source, not the child environment', async () => {
    const server = spawnServeEntry({ env: { UNIFI_MCP_TRANSPORT: 'local' } });
    try {
      const exit = await server.exit();
      assert.equal(exit.code, 1);
      // Reaching this refusal at all proves the descriptor's env was what
      // `loadConfig` read: the child's own environment is stripped of every
      // UNIFI_* variable before the spawn.
      assert.match(server.stderr(), /UNIFI_MCP_TRANSPORT/);
    } finally {
      await server.stop();
    }
  });

  test('the observation seams are inert: the entrypoint runs with no observer at all', async () => {
    // AC 10, asserted behaviourally rather than by scanning the two files that
    // hold the call sites — both are being rewritten by other stories in this
    // same wave, and a text scan over them would assert their formatting.
    // If any call site were `observer.onX()` rather than `observer?.onX?.()`,
    // this child would throw instead of exiting 0.
    const server = spawnServeEntry({
      env: { UNIFI_API_KEY: `SENTINEL-CLOUD-KEY-${'3'.repeat(16)}` },
      observer: false,
      after: 'exit',
    });
    try {
      const exit = await server.exit();
      assert.equal(exit.code, 0, server.stderr());
      assert.equal(
        parseCounterLine(server.stderr()),
        null,
        'a child started with no observer still emitted counters',
      );
    } finally {
      await server.stop();
    }
  });

  test('a startup refusal reports its counters before it exits', async () => {
    // The ordering FR-73's non-bypassability criterion rests on: a refusal that
    // exits before reporting leaves `listen: 0` unreadable, and "no listener
    // was opened" becomes an assertion about a process nobody observed.
    // FR-73(a)'s shape, chosen because it refuses at `validateConfig` — step 3
    // of the ordered startup sequence, before the credential store is
    // constructed at step 5. US-26 owns the five refusals' message text; what
    // is asserted here is that the harness makes the counters readable from a
    // process that then exits 1.
    const server = spawnServeEntry({
      env: {
        UNIFI_API_KEY: `SENTINEL-CLOUD-KEY-${'5'.repeat(16)}`,
        UNIFI_MCP_TRANSPORT: 'http',
      },
    });
    try {
      const counts = await server.counters();
      assert.equal(counts.listen, 0, 'a refused configuration must not bind');
      assert.equal(counts.credentialStore, 0, 'a refused configuration must build nothing');
      assert.equal(counts.registryBuild, 0);

      const exit = await server.exit();
      assert.equal(exit.code, 1);
      assert.match(server.stderr(), /unifi-mcp: ERROR .*UNIFI_HTTP_TOKEN/);
    } finally {
      await server.stop();
    }
  });
});

// ===========================================================================
// 5. The instruments as deliverables: discovery and dependencies (AC 8, AC 9)
// ===========================================================================

describe('the instruments themselves (FR-75)', () => {
  test('the runner discovers this suite and never executes the harness', () => {
    // `scripts/run-tests.mjs` filters `readdirSync('test')` for `.test.ts`,
    // NON-recursively. Both halves matter: the suite is picked up with no
    // package.json edit, and `serve-entry.ts` — which imports the entrypoint
    // and would start a server — can never be run as a test. Renaming a harness
    // module to end in `.test.ts` would break the second half silently.
    const discovered = readdirSync(join(REPO_ROOT, 'test')).filter((name) =>
      name.endsWith('.test.ts'),
    );
    assert.ok(discovered.includes('instruments.test.ts'));

    const harnessFiles = readdirSync(join(REPO_ROOT, 'test', 'harness'));
    assert.ok(harnessFiles.includes('serve-entry.ts'), 'the spawned harness is missing');
    assert.deepEqual(
      harnessFiles.filter((name) => name.endsWith('.test.ts')),
      [],
      'a harness module was named like a suite; the runner would execute it',
    );
  });

  test('the merged ledger keeps each recorder distinguishable', () => {
    // US-29 assembles assertions over both recorders. The provenance tag is the
    // whole point: a `loopback` entry means a socket carried these bytes, a
    // `synthetic` entry means the client committed to the request and a
    // stand-in answered it. An assembly that lost the distinction would let
    // cloud-mode evidence be read as wire evidence, which is exactly the
    // conflation the envelope exists to prevent.
    const intercepted: InterceptedRequest = {
      method: 'GET',
      path: '/proxy/network/integration/v1/sites',
      url: 'https://127.0.0.1:1/proxy/network/integration/v1/sites',
      headers: {},
      apiKey: undefined,
      body: '',
      service: 'network',
    };
    const synthetic: LedgerEntry = {
      tool: 'unifi_list_sites',
      method: 'GET',
      service: 'site-manager',
      path: '/v1/sites',
      actionId: 'site_manager.list_sites',
    };

    const merged = mergeLedgers([intercepted], [synthetic]);
    assert.deepEqual(
      merged.map((entry) => entry.source),
      ['loopback', 'synthetic'],
    );
    assert.equal(merged[0]?.tool, null, 'the wire cannot attribute a request to a tool');
    assert.equal(merged[1]?.tool, 'unifi_list_sites');
    assert.match(describeAttempt(merged[1] as OutboundAttempt), /\[synthetic\]$/);
    assert.match(describeAttempt(merged[0] as OutboundAttempt), /\[loopback\]$/);
  });

  test('every instrument runs on the Node standard library alone', () => {
    // FR-75 forbids a new runtime dependency and a new dev dependency outright.
    // A bare import specifier in a harness module is the shape that violation
    // takes, so it is asserted rather than reviewed. `node:` builtins, relative
    // paths into `src/` and sibling harness modules are the closed allow-list.
    const dir = join(REPO_ROOT, 'test', 'harness');
    for (const name of readdirSync(dir).filter((file) => file.endsWith('.ts'))) {
      const source = readFileSync(join(dir, name), 'utf8');
      for (const match of source.matchAll(/^\s*(?:import|export)[^'"]*from\s+'([^']+)'/gm)) {
        const specifier = match[1] ?? '';
        assert.ok(
          specifier.startsWith('node:') || specifier.startsWith('.'),
          `${name} imports \`${specifier}\`, which is neither a Node builtin nor a relative path`,
        );
      }
    }
  });
});

// ===========================================================================
// 6. The operating envelope, pinned as an assertion (AC 2)
// ===========================================================================

describe('the interceptor envelope — what it can and cannot carry', () => {
  test('local-direct Network and Protect resolve to the loopback origin', async () => {
    const harness = await rig();
    try {
      for (const service of ['network', 'protect'] as const) {
        const target = resolveTarget(harness.core.config, service);
        assert.equal(target.mode, 'local');
        assert.equal(target.host, harness.origin.host);
        assert.ok(target.baseUrl.startsWith(`https://${harness.origin.host}/`));
      }
    } finally {
      await harness.close();
    }
  });

  test('Site Manager and Mobility cannot be pointed at it, and that is a hardcoded fact', async () => {
    // The literal vendor hostname is deliberately not written here: S-09 scans
    // `test/` for it outside a comment, because a test that names it is a test
    // that might one day contact it. The constant is imported instead.
    const harness = await rig();
    try {
      for (const service of ['site-manager', 'mobility'] as const) {
        const target = resolveTarget(harness.core.config, service);
        assert.equal(target.mode, 'cloud');
        assert.equal(target.host, CLOUD_HOST);
        assert.notEqual(
          target.host,
          harness.origin.host,
          'the envelope this harness documents no longer holds',
        );
      }
    } finally {
      await harness.close();
    }
  });

  test('connector mode is outside the envelope too, for the same reason', async () => {
    const origin = await startLoopbackOrigin();
    const instruments = createInstruments({
      env: loopbackEnv(origin, {
        UNIFI_API_KEY: `SENTINEL-CLOUD-KEY-${'4'.repeat(16)}`,
        UNIFI_NETWORK_TRANSPORT: 'connector',
        UNIFI_CONSOLE_ID: 'console-loopback',
      }),
    });
    const core = buildRuntimeCore(instruments.deps);
    try {
      const target = resolveTarget(core.config, 'network');
      assert.equal(target.mode, 'connector');
      assert.equal(target.host, CLOUD_HOST);
      assert.notEqual(target.host, origin.host);
    } finally {
      await core.close();
      await origin.close();
    }
  });
});
