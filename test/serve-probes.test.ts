/**
 * US-28c — the probes, asserted at the live HTTP transport (QA C9, C10, C14).
 *
 * `test/serve-health.test.ts` (US-11, Wave A) already asserts the handlers as a
 * leaf module: the four frozen bodies, the header set, HEAD mirroring GET, the
 * disclosure scan and the closed import allow-list. None of that is restated
 * here. What this file adds is the half US-11 could not reach, because the
 * instruments it needs — `RuntimeDeps`' invocation counters and the FR-75
 * outbound interceptor — are US-25's deliverable and landed four waves later:
 *
 *   1. **US-11's relocated criterion, verbatim.** 100 probes against a REAL
 *      bound listener leave the credential-store, registry-build and
 *      artifact-check counters unchanged, and the outbound interceptor records
 *      zero requests attributable to a probe. Relocated to this slot by
 *      sequencing decision §6; see the strikethrough under US-11's criteria.
 *   2. **MECH-NET.** `/readyz` returns 200 with all outbound dispatch replaced
 *      by a collaborator that throws a synthetic `ENETUNREACH` and records
 *      every attempt, and that collaborator records 0.
 *   3. **The barrier.** With the registry build held open behind a barrier the
 *      test controls, `/healthz` answers 200 while `/readyz` answers 503
 *      `starting\n` — in the same run, on the same connection.
 *
 * ## Every "zero" here is paired with a control that moves
 *
 * A count that never moves for any reason proves nothing by staying at zero.
 * So each of the three sections asserts its instrument is live in the same run:
 *
 *   - the three counters are observed at 1 apiece after the real startup
 *     sequence (a real `CredentialStore` construction, a real manifest read, a
 *     real `buildRegistry`) and only THEN frozen across the 100 probes;
 *   - the interceptor is driven to record a real outbound request, over a real
 *     socket, after the probe window closes;
 *   - the MECH-NET collaborator is driven to record an attempt, and the
 *     barrier is released so `/readyz` is seen to flip to 200 — proving the 503
 *     was the barrier and not a listener that never worked.
 *
 * ## Why a raw socket and one keep-alive connection
 *
 * `fetch` and `http.request` normalise header case, reorder headers and hide
 * the status line, so a probe suite built on them passes while the wire
 * differs. All 100 probes share ONE keep-alive connection: the connection
 * ledger's probe headroom is capped at one per source key, and a hundred
 * sequential connect/close cycles would race the ledger's `close` release for
 * no gain in coverage — the connection cap is US-28a's criterion, not this
 * file's.
 *
 * Every listener binds `127.0.0.1` port `0`; nothing here imports
 * `src/index.ts`; no assertion waits on wall-clock time.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { dirname, join } from 'node:path';
import { describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import type { ServerConfig } from '../src/config.js';
import type { CredentialStore } from '../src/credentials.js';
import { UnifiClient, type UnifiClientOptions, type UnifiResponse } from '../src/http/client.js';
import { buildRegistry } from '../src/registry/build.js';
import { startHttp, type HttpServing, type HttpServingDeps } from '../src/serve/http.js';
import { buildRuntimeCore, type RuntimeCore, type RuntimeDeps } from '../src/serve/runtime.js';
import type { Action } from '../src/types.js';

import { createInstruments, type Instruments } from './harness/counters.js';
import { loopbackEnv, startLoopbackOrigin, type LoopbackOrigin } from './harness/interceptor.js';

/** `fileURLToPath`, never `URL.pathname`: the latter yields `/D:/a/...` on Windows. */
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A legal inbound secret. FR-81's floor is 32 characters. */
const INBOUND_SECRET = `probe-suite-inbound-${'q'.repeat(32)}`;

/** The relocated criterion's number, stated once so the loop cannot drift from it. */
const PROBE_COUNT = 100;

const OK_BODY = 'ok\n';
const STARTING_BODY = 'starting\n';
const READY_BODY = 'ready\n';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * The HTTP transport pointed at a live loopback origin.
 *
 * `loopbackEnv` is what makes the interceptor half of the relocated criterion
 * non-vacuous: without it every outbound request resolves to the hardcoded
 * cloud origin, no socket this process controls could ever carry one, and
 * "the interceptor recorded zero" would be true of a server that made a
 * thousand calls.
 */
function probeEnv(
  origin: Pick<LoopbackOrigin, 'host'>,
  extra: Readonly<Record<string, string>> = {},
): Record<string, string> {
  return {
    ...(loopbackEnv(origin) as Record<string, string>),
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: INBOUND_SECRET,
    ...extra,
  };
}

interface Bound {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly instruments: Instruments;
  /** Every composed diagnostic line, as it would reach stderr. */
  readonly lines: readonly string[];
}

interface Prepared {
  readonly instruments: Instruments;
  readonly lines: string[];
}

/**
 * The counting `RuntimeDeps`, built BEFORE the runtime that consumes them.
 *
 * Separated from `boundServer` so a caller can read the counters while they are
 * still at zero. That reading is what turns "unchanged across 100 probes" into
 * evidence: the same objects are seen at 0, then at 1 after real work, then
 * frozen through the probe window.
 */
function prepareInstruments(env: Record<string, string>, runtimeDeps: RuntimeDeps = {}): Prepared {
  const lines: string[] = [];
  const instruments = createInstruments({
    env: { ...env },
    keychain: null,
    deps: runtimeDeps,
    onLine: (line) => lines.push(line),
  });
  return { instruments, lines };
}

/**
 * Start one listener and register the §10.5 teardown contract for it.
 *
 * Registered on the test context rather than in a shared `after()` so a
 * failure cannot leave a listening handle — or the drain's deadline timer,
 * whose callback is a hard stop — alive for the rest of the file.
 */
async function boundServer(
  t: TestContext,
  env: Record<string, string>,
  runtimeDeps: RuntimeDeps = {},
  prepared?: Prepared,
): Promise<Bound> {
  const { instruments, lines } = prepared ?? prepareInstruments(env, runtimeDeps);
  const core = buildRuntimeCore(instruments.deps);
  const deps: HttpServingDeps = { warn: (line) => lines.push(line) };
  const serving = await startHttp(core, instruments.observer, deps);

  t.after(async () => {
    // The teardown contract, verbatim: one call releases the http server, the
    // per-session servers and transports, the keep-alive interval, live
    // sockets, the sweep interval, the deadline timer and the cached agents.
    await serving.dispose();
    await core.close();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  assert.equal(serving.address.address, '127.0.0.1');
  return { serving, core, port: serving.address.port, instruments, lines };
}

/** Wait until the registry resolved AND the readiness phase flipped. */
async function waitReady(bound: Bound): Promise<void> {
  await bound.core.ready;
  // `resolveRegistry`'s continuation flips the phase one microtask after
  // `ready` settles; two macrotask ticks is comfortably past it.
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

// ---------------------------------------------------------------------------
// The raw probe connection
// ---------------------------------------------------------------------------

type ProbeRoute = 'healthz' | 'readyz';
type ProbeMethod = 'GET' | 'HEAD';

interface ProbeReply {
  readonly status: number;
  readonly reason: string;
  /** Lower-cased names. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** `Content-Length` as the server declared it, even on a HEAD. */
  readonly declaredLength: number;
  /** Every byte of this response, in order, unmodified. */
  readonly raw: string;
}

interface ProbeConnection {
  send(route: ProbeRoute, method?: ProbeMethod): Promise<ProbeReply>;
  close(): Promise<void>;
}

interface ParsedReply {
  readonly reply: ProbeReply;
  readonly consumed: number;
}

/** Parse one complete response, or `null` when more bytes are needed. */
function parseReply(buffer: Buffer, head: boolean): ParsedReply | null {
  const headerEnd = buffer.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;

  const [statusLine = '', ...headerLines] = buffer.subarray(0, headerEnd).toString('latin1').split('\r\n');
  const match = /^HTTP\/1\.1 (\d{3}) ?(.*)$/.exec(statusLine);
  if (!match) throw new Error(`unparseable status line ${JSON.stringify(statusLine)}`);

  const headers: Record<string, string> = {};
  for (const line of headerLines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }

  const declaredLength = Number(headers['content-length'] ?? '0');
  // A HEAD reply declares the GET body length and carries none of it. Reading
  // `Content-Length` bytes here would consume the NEXT response off the wire.
  const bodyLength = head ? 0 : declaredLength;
  const total = headerEnd + 4 + bodyLength;
  if (buffer.byteLength < total) return null;

  return {
    consumed: total,
    reply: {
      status: Number(match[1]),
      reason: match[2] ?? '',
      headers,
      body: buffer.subarray(headerEnd + 4, total).toString('utf8'),
      declaredLength,
      raw: buffer.subarray(0, total).toString('latin1'),
    },
  };
}

/**
 * One keep-alive connection carrying an ordered series of probes.
 *
 * Requests are written one at a time and each reply is matched to the request
 * that is at the head of the queue, so a server that answered out of order, or
 * that framed a HEAD reply as though it carried a body, desynchronises the
 * stream and fails rather than passing quietly.
 */
function openProbeConnection(port: number): Promise<ProbeConnection> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1');
    socket.setNoDelay(true);

    let buffer = Buffer.alloc(0);
    let failure: Error | null = null;
    const waiting: Array<{
      readonly head: boolean;
      readonly settle: (reply: ProbeReply) => void;
      readonly fail: (error: Error) => void;
    }> = [];

    function pump(): void {
      while (waiting.length > 0) {
        const next = waiting[0];
        if (!next) return;
        let parsed: ParsedReply | null;
        try {
          parsed = parseReply(buffer, next.head);
        } catch (error) {
          abandon(error instanceof Error ? error : new Error(String(error)));
          return;
        }
        if (parsed === null) return;
        buffer = buffer.subarray(parsed.consumed);
        waiting.shift();
        next.settle(parsed.reply);
      }
    }

    function abandon(error: Error): void {
      failure ??= error;
      for (const pending of waiting.splice(0)) pending.fail(error);
    }

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      pump();
    });
    socket.on('error', (error: Error) => abandon(error));
    socket.on('close', () =>
      abandon(new Error('the server closed the probe connection with a reply outstanding')),
    );
    socket.once('error', reject);

    socket.once('connect', () => {
      socket.removeListener('error', reject);
      resolve({
        send(route: ProbeRoute, method: ProbeMethod = 'GET'): Promise<ProbeReply> {
          return new Promise<ProbeReply>((settle, fail) => {
            if (failure !== null) {
              fail(failure);
              return;
            }
            waiting.push({ head: method === 'HEAD', settle, fail });
            // `Host` is the bound authority: the probes' Host exemption is
            // US-22's criterion, and borrowing it here would couple this
            // file's three claims to a fourth story's behaviour.
            socket.write(`${method} /${route} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`);
          });
        },
        close(): Promise<void> {
          return new Promise<void>((done) => {
            if (socket.destroyed) {
              done();
              return;
            }
            socket.once('close', () => done());
            socket.end();
          });
        },
      });
    });
  });
}

/**
 * The frozen answer each route owes in each phase.
 *
 * `body` is always the GET body. A HEAD reply carries none of it and still
 * declares its length, so the two are asserted separately rather than the
 * caller passing `''` and losing the `Content-Length` check with it.
 */
function assertProbeShape(
  reply: ProbeReply,
  status: number,
  body: string,
  where: string,
  head = false,
): void {
  assert.equal(reply.status, status, `${where}: status\n${reply.raw}`);
  assert.equal(reply.body, head ? '' : body, `${where}: body\n${reply.raw}`);
  assert.equal(reply.headers['content-type'], 'text/plain; charset=utf-8', where);
  assert.equal(reply.headers['cache-control'], 'no-store', where);
  assert.equal(reply.headers['x-content-type-options'], 'nosniff', where);
  assert.equal(reply.declaredLength, Buffer.byteLength(body, 'utf8'), `${where}: content-length`);
}

// ---------------------------------------------------------------------------
// MECH-NET: the injected dispatch collaborator
// ---------------------------------------------------------------------------

interface BlockedOutbound {
  /** Every attempt the collaborator intercepted, in order. Live; read after. */
  readonly attempts: readonly string[];
  readonly createClient: NonNullable<RuntimeDeps['createClient']>;
}

/**
 * A synthetic `ENETUNREACH`, in the shape `node:https` raises one.
 *
 * `203.0.113.0/24` is TEST-NET-3: a documentation range that is unroutable by
 * definition, so the message names an address no deployment could ever hold.
 */
function syntheticEnetunreach(): NodeJS.ErrnoException {
  const error = new Error('connect ENETUNREACH 203.0.113.7:443') as NodeJS.ErrnoException;
  error.code = 'ENETUNREACH';
  error.syscall = 'connect';
  return error;
}

/**
 * MECH-NET, at the only seam that exists.
 *
 * `src/http/client.ts` statically imports `request` from `node:https` and Node
 * 20 has no `mock.module`, so there is no seam BELOW the client — which is why
 * the test strategy places this at `RuntimeDeps.createClient`. No firewall, no
 * `--network=none`, no host-level manipulation: none of those is available
 * inside `node --test`.
 *
 * The PRODUCTION `UnifiClient` is still constructed, so the runtime holds a
 * real object with a real limiter, real agents and a real `close()`; only the
 * dispatch is replaced. A stand-in would turn "the server made no outbound
 * request" into "the harness was not asked to make one".
 */
function blockOutbound(): BlockedOutbound {
  const attempts: string[] = [];
  return {
    attempts,
    createClient: (
      config: ServerConfig,
      credentials: CredentialStore,
      options: UnifiClientOptions,
    ): UnifiClient => {
      const client = new UnifiClient(config, credentials, options);
      const seam = client as unknown as {
        request: (action: Action, args?: Record<string, unknown>) => Promise<UnifiResponse>;
      };
      seam.request = async (action: Action): Promise<UnifiResponse> => {
        attempts.push(`${action.method} ${action.service} ${action.path}`);
        throw syntheticEnetunreach();
      };
      return client;
    },
  };
}

// ===========================================================================
// 1. The relocated US-11 criterion (QA C9 — FR-68, FR-69, NFR-25, FR-75)
// ===========================================================================

describe('100 probes move nothing (C9 — US-11 criterion, relocated to US-28c)', () => {
  test('the three counters are unchanged and the interceptor records zero', async (t) => {
    const origin = await startLoopbackOrigin();
    t.after(() => origin.close());

    // ---- The positive control, taken FIRST and in the same run -------------
    //
    // The same three counter objects the probe window is measured against,
    // read at zero before anything has run. Startup then puts a real
    // `CredentialStore` construction, a real manifest read and a real
    // `buildRegistry` behind them, and each is observed to move. "Unchanged
    // across 100 probes" is therefore a statement about the probes, not about
    // counters that never move for anything.
    const env = probeEnv(origin);
    const prepared = prepareInstruments(env);
    const atRest = prepared.instruments.snapshot();
    assert.deepEqual(
      [atRest.credentialStore, atRest.registryBuild, atRest.manifestRead, atRest.clientBuild],
      [0, 0, 0, 0],
      'the counters were not at zero before the runtime was built',
    );

    const bound = await boundServer(t, env, {}, prepared);
    await waitReady(bound);
    assert.equal(bound.core.readyError, null, 'the runtime failed to resolve its registry');

    const started = bound.instruments.snapshot();
    assert.deepEqual(
      [started.credentialStore, started.registryBuild, started.manifestRead, started.clientBuild],
      [1, 1, 1, 1],
      'a real credential-store construction, artifact check and registry build did NOT move ' +
        'these counters, so the probe assertion below would be vacuous',
    );
    assert.equal(started.listen, 1, 'the listener counter never moved');

    // Startup itself reaches no third party: the registry is built from files
    // on disk and the credential store resolves lazily, so nothing has crossed
    // a socket yet even though the origin is live and reachable.
    assert.equal(origin.requests.length, 0, 'startup made an outbound request');

    // ---- The probe window --------------------------------------------------
    const probes = await openProbeConnection(bound.port);
    t.after(() => probes.close());

    const observed: string[] = [];
    for (let index = 0; index < PROBE_COUNT; index += 1) {
      const route: ProbeRoute = index % 2 === 0 ? 'healthz' : 'readyz';
      const method: ProbeMethod = index % 10 === 0 ? 'HEAD' : 'GET';
      const reply = await probes.send(route, method);
      const where = `probe ${index} (${method} /${route})`;

      const body = route === 'healthz' ? OK_BODY : READY_BODY;
      assertProbeShape(reply, 200, body, where, method === 'HEAD');
      observed.push(`${method} /${route} ${reply.status}`);
    }
    assert.equal(observed.length, PROBE_COUNT, 'the probe loop did not run to completion');

    // ---- The criterion, verbatim -------------------------------------------
    const after = bound.instruments.snapshot();
    assert.equal(
      after.credentialStore,
      started.credentialStore,
      `${PROBE_COUNT} probes changed the credential-store invocation counter`,
    );
    assert.equal(
      after.registryBuild,
      started.registryBuild,
      `${PROBE_COUNT} probes changed the registry-build invocation counter`,
    );
    assert.equal(
      after.manifestRead,
      started.manifestRead,
      `${PROBE_COUNT} probes changed the startup artifact-check invocation counter`,
    );
    assert.equal(
      after.clientBuild,
      started.clientBuild,
      `${PROBE_COUNT} probes constructed an outbound client`,
    );
    assert.deepEqual(
      origin.requests.map((entry) => `${entry.method} ${entry.path}`),
      [],
      `the outbound interceptor recorded a request attributable to one of ${PROBE_COUNT} probes`,
    );
    // A probe is not an MCP request and must never be counted as one: the
    // handler counter is what a rate limit or a quota would be built on.
    assert.equal(after.mcpRequest, 0, 'a probe was counted as an MCP request');

    // ---- The interceptor's own control, after the window closes ------------
    //
    // The ledger stayed empty for 100 probes. Here it is driven to move, on
    // the same origin, in the same run — so the empty ledger above is a
    // property of the probes and not of an interceptor nothing can reach.
    const handler = bound.core.handlers['unifi_list_cameras'];
    assert.ok(handler, 'the promoted Protect read tool has no handler');
    const result = await handler({});
    assert.equal(result.isError ?? false, false, JSON.stringify(result));
    assert.equal(
      origin.requests.length,
      1,
      'the interceptor recorded nothing for a real read action, so its zero above proves nothing',
    );
    const recorded = origin.requests[0];
    assert.ok(recorded);
    assert.equal(recorded.service, 'protect');

    // And the counters are still where the probes left them: a real outbound
    // call does not rebuild the registry or the store either, so the three
    // counters distinguish "a probe" from "everything else" correctly.
    const final = bound.instruments.snapshot();
    assert.equal(final.registryBuild, started.registryBuild);
    assert.equal(final.credentialStore, started.credentialStore);
    assert.equal(final.manifestRead, started.manifestRead);
  });
});

// ===========================================================================
// 2. MECH-NET (QA C10 — NFR-17, NFR-25)
// ===========================================================================

describe('MECH-NET: /readyz answers with all outbound dispatch blocked (C10)', () => {
  test('200 ready with 0 probe-attributable dispatch invocations', async (t) => {
    const origin = await startLoopbackOrigin();
    t.after(() => origin.close());

    const blocked = blockOutbound();
    const bound = await boundServer(t, probeEnv(origin), { createClient: blocked.createClient });
    await waitReady(bound);
    assert.equal(bound.core.readyError, null, 'the runtime failed to resolve its registry');

    const probes = await openProbeConnection(bound.port);
    t.after(() => probes.close());

    // Both halves of the criterion, and the second is what makes the first
    // mean something: if `/readyz` tried to reach a UniFi console or
    // `api.ui.com`, the collaborator would have caught the attempt and this
    // count would be non-zero.
    for (let index = 0; index < PROBE_COUNT; index += 1) {
      const reply = await probes.send('readyz');
      assertProbeShape(reply, 200, READY_BODY, `blocked-network probe ${index}`);
    }
    const live = await probes.send('healthz');
    assertProbeShape(live, 200, OK_BODY, 'blocked-network liveness');

    assert.deepEqual(
      blocked.attempts,
      [],
      'a probe reached the outbound dispatch collaborator, so /readyz is not independent of a ' +
        'third party',
    );
    assert.deepEqual(
      origin.requests.map((entry) => `${entry.method} ${entry.path}`),
      [],
      'a probe reached a real socket',
    );

    // ---- The collaborator's control ---------------------------------------
    //
    // Drive one real action. The collaborator records the attempt and throws
    // the synthetic ENETUNREACH, and the origin STILL records nothing —
    // proving the collaborator sits above the socket and genuinely blocks it,
    // rather than being an inert wrapper that counts nothing.
    const handler = bound.core.handlers['unifi_list_cameras'];
    assert.ok(handler, 'the promoted Protect read tool has no handler');
    const result = await handler({});
    assert.equal(
      blocked.attempts.length,
      1,
      'the dispatch collaborator recorded nothing for a real action, so its zero above is vacuous',
    );
    assert.equal(result.isError ?? false, true, 'a blocked network produced a successful result');
    assert.equal(origin.requests.length, 0, 'the blocked dispatch still reached a real socket');

    // Readiness is unmoved by the failure: an outbound fault is not a
    // readiness fault, which is the whole of NFR-25.
    const stillReady = await probes.send('readyz');
    assertProbeShape(stillReady, 200, READY_BODY, 'readiness after a blocked outbound call');
  });
});

// ===========================================================================
// 3. The registry-build barrier (QA C14 — FR-62, FR-69)
// ===========================================================================

describe('the starting window is real and observable (C14)', () => {
  test('/healthz 200 while /readyz 503 starting, in the same run', async (t) => {
    const origin = await startLoopbackOrigin();
    t.after(() => origin.close());

    // Definite-assignment: the executor runs synchronously inside the `new
    // Promise` call, so `release` is a function by the next statement. Without
    // the `!` TypeScript's control flow narrows it to `never` at every use,
    // because it does not track assignments made inside a callback.
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    let buildsStarted = 0;

    // The barrier goes on `RuntimeDeps.buildRegistry`, which `createInstruments`
    // calls BEHIND its counter, so the injected build is counted exactly as the
    // production one would be. This works only because the architecture binds
    // the listener BEFORE resolving the registry: under the other ordering the
    // barrier would suspend startup before anything could be probed.
    const bound = await boundServer(t, probeEnv(origin), {
      buildRegistry: async (root, manifest, services) => {
        buildsStarted += 1;
        await barrier;
        return buildRegistry(root, manifest, services);
      },
    });

    try {
      assert.equal(buildsStarted, 1, 'the registry build never started');
      assert.equal(bound.core.registry, null, 'the registry resolved despite the barrier');
      assert.equal(
        bound.instruments.counts.listen,
        1,
        'the listener had not bound, so the two probes below would be meaningless',
      );

      // Both probes, one connection, one run — which is what makes them the
      // same instant rather than two readings either side of a transition.
      const probes = await openProbeConnection(bound.port);
      t.after(() => probes.close());

      const held = {
        healthz: await probes.send('healthz'),
        readyz: await probes.send('readyz'),
        headHealthz: await probes.send('healthz', 'HEAD'),
        headReadyz: await probes.send('readyz', 'HEAD'),
      };

      assertProbeShape(held.healthz, 200, OK_BODY, 'liveness while the registry build is held');
      assertProbeShape(
        held.readyz,
        503,
        STARTING_BODY,
        'readiness while the registry build is held',
      );
      assertProbeShape(held.headHealthz, 200, OK_BODY, 'HEAD liveness while held', true);
      assertProbeShape(held.headReadyz, 503, STARTING_BODY, 'HEAD readiness while held', true);

      // The two signals are independent, not the same boolean read twice.
      assert.notEqual(
        held.healthz.status,
        held.readyz.status,
        'both probes reported the same status while starting, so they are one signal',
      );
      assert.equal(bound.instruments.counts.ready, 0, 'readiness was announced before the build');

      // ---- Release, and watch the 503 become a 200 --------------------------
      //
      // Without this the 503 could equally be a listener that never worked.
      assert.equal(typeof release, 'function', 'the barrier was never armed');
      release();
      await waitReady(bound);
      assert.equal(bound.core.readyError, null, 'the released build failed');

      assertProbeShape(
        await probes.send('readyz'),
        200,
        READY_BODY,
        'readiness after the barrier released',
      );
      assertProbeShape(
        await probes.send('healthz'),
        200,
        OK_BODY,
        'liveness after the barrier released',
      );

      assert.equal(buildsStarted, 1, 'the registry was built more than once');
      assert.equal(bound.instruments.counts.registryBuild, 1);
      assert.equal(bound.instruments.counts.ready, 1);
      assert.ok(bound.core.registry !== null, 'the registry is still unresolved');
    } finally {
      // Unconditional: `dispose()` awaits the registry resolution, so a
      // failure before the release above would hang teardown rather than
      // reporting the failure. Resolving an already-resolved promise is a
      // no-op, so calling it twice on the success path is safe.
      release();
    }
  });
});

// ===========================================================================
// 4. The mechanism behind section 1, restated where it is load-bearing
// ===========================================================================

describe('the counter claim rests on a closed module graph', () => {
  /**
   * US-11's suite owns the full allow-list scan. This is the one-line
   * restatement, kept here because sections 1 and 2 above are DYNAMIC evidence
   * ("no counter moved during this run") and dynamic evidence is only as good
   * as the coverage of the run. The static half is what makes it general: a
   * handler that cannot NAME the credential store cannot consult it on any
   * input, probed or not. If this fails, the runtime assertions above are no
   * longer sufficient and the criterion needs re-deriving.
   */
  test('src/serve/health.ts still imports node:http, for types only, and nothing else', () => {
    const source = readFileSync(join(REPO_ROOT, 'src', 'serve', 'health.ts'), 'utf8');
    const found: string[] = [];
    for (const match of source.matchAll(
      /(?:^|\n)\s*(?:import|export)[^\n;]*?from\s*['"]([^'"]+)['"]/g,
    )) {
      if (match[1]) found.push(match[1]);
    }
    for (const match of source.matchAll(/(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g)) {
      if (match[1]) found.push(match[1]);
    }

    assert.deepEqual(found, ['node:http'], 'the probe module grew an import');
    assert.match(source, /import type \{[^}]+\} from 'node:http';/);
    assert.equal(/\brequire\s*\(/.test(source), false, 'a require() escape hatch appeared');
    assert.equal(/\bimport\s*\(/.test(source), false, 'a dynamic import appeared');
  });
});
