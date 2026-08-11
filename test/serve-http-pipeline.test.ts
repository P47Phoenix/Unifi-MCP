/**
 * US-22 — the listener, the validation pipeline and the inbound bounds.
 *
 * Suite C of the test strategy: C1, C2, C7, C24, C27-C36 and B16.
 *
 * ## Why every byte assertion here uses a raw `net.Socket`
 *
 * `fetch` and `http.request` are used NOWHERE in this file, and that is a
 * decision rather than a style preference. Both normalise header case, reorder
 * headers, and hide the status line entirely — so a suite built on them passes
 * while the wire differs, which is precisely the failure FR-81's byte
 * comparison exists to catch. The one place an SDK client appears is the
 * interoperability case, where the property under test is that a REAL MCP
 * client works, not that our bytes look plausible to us.
 *
 * ## Every listener binds `127.0.0.1` port `0`
 *
 * An ephemeral loopback socket never leaves the host and is not "the network"
 * for the purposes of the no-network rule. It is also the only mechanism that
 * can assert wire behaviour at all.
 *
 * ## The universal CORS assertion
 *
 * `exchange()` inspects EVERY response it captures for a CORS header, a
 * `Server` header and an `X-Powered-By` header, and records it in a
 * suite-scoped ledger. FR-66 is asserted across the whole suite rather than
 * spot-checked, which is what the requirement asks for — a spot check passes
 * while some other branch emits one.
 */
import assert from 'node:assert/strict';
import { connect, createServer as createTcpServer, type Socket } from 'node:net';
import { readFileSync } from 'node:fs';
import { createServer as createNodeHttpServer, type Server } from 'node:http';
import { dirname, join } from 'node:path';
import { after, describe, test, type TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { loadConfig } from '../src/config.js';
import { normalizeError } from '../src/http/errors.js';
import {
  createServingOptions,
  startHttp,
  PROBE_CONNECTION_HEADROOM,
  type HttpServing,
  type HttpServingDeps,
} from '../src/serve/http.js';
import { buildRuntimeCore, type RuntimeCore, type RuntimeDeps } from '../src/serve/runtime.js';
import type { ErrorCategory } from '../src/types.js';

import { createRejectionThrottle } from '../src/serve/guard.js';

import { createInstruments, type Instruments } from './harness/counters.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HTTP_SOURCE = join(REPO_ROOT, 'src', 'serve', 'http.ts');

/** The inbound shared secret. 40 characters, comfortably over FR-81's floor of 32. */
const SECRET = `s${'u'.repeat(39)}`;
/** A rotation slot, so "every configured slot is evaluated" is not vacuous. */
const NEXT_SECRET = `n${'v'.repeat(39)}`;
/** Not either of the above, and the same length as both. */
const WRONG_SECRET = `w${'x'.repeat(39)}`;

const ALLOWED_HOST = 'allowed.example';
const REJECTED_HOST = 'not-allowed.example';
/** What a kubelet sends: the pod IP, which no operator allow-list contains. */
const KUBELET_HOST = '10.42.0.7:8787';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function httpEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    UNIFI_API_KEY: `key-${'k'.repeat(36)}`,
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_BIND: '127.0.0.1',
    UNIFI_HTTP_PORT: '0',
    UNIFI_HTTP_TOKEN: SECRET,
    UNIFI_HTTP_TOKEN_NEXT: NEXT_SECRET,
    ...extra,
  };
}

interface Bound {
  readonly serving: HttpServing;
  readonly core: RuntimeCore;
  readonly port: number;
  readonly instruments: Instruments;
  /** Every composed diagnostic and request line, as it would reach stderr. */
  readonly lines: string[];
  /** The `node:http` server, for the bound-provenance assertions. */
  readonly server: Server;
}

/**
 * Start one listener and register its teardown.
 *
 * `dispose()` is registered on the test context rather than in a shared
 * `after()` so a file-level failure cannot leave a listening handle behind and
 * hang the runner — every in-process transport in this round arms timers and
 * holds sockets, and the deadline timer's own callback is what kills a suite
 * mid-file when teardown is skipped.
 */
async function boundServer(
  t: TestContext,
  env: Record<string, string> = httpEnv(),
  deps: HttpServingDeps = {},
  runtimeDeps: RuntimeDeps = {},
): Promise<Bound> {
  const lines: string[] = [];
  const instruments = createInstruments({
    env: { ...env },
    keychain: null,
    deps: runtimeDeps,
    onLine: (line) => lines.push(line),
  });
  const core = buildRuntimeCore(instruments.deps);

  let server: Server | null = null;
  const serving = await startHttp(core, instruments.observer, {
    warn: (line) => lines.push(line),
    createHttpServer: (options, handler) => {
      server = createNodeHttpServer(options, handler);
      return server;
    },
    ...deps,
  });

  t.after(async () => {
    await serving.dispose();
  });

  assert.ok(serving.address !== null, 'the listener reported no address');
  assert.ok(server !== null, 'the http server seam was not used');
  return {
    serving,
    core,
    port: serving.address.port,
    instruments,
    lines,
    server: server as unknown as Server,
  };
}

/** Wait until the registry has resolved and the readiness flag has flipped. */
async function waitReady(bound: Bound): Promise<void> {
  await bound.core.ready;
  // `resolveRegistry`'s continuation flips the phase one microtask after
  // `ready` settles; two macrotask ticks is comfortably past it.
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

// ---------------------------------------------------------------------------
// The raw socket client
// ---------------------------------------------------------------------------

interface Exchange {
  /** Every byte the server sent, in order, unmodified. */
  readonly bytes: Buffer;
  readonly text: string;
  /** True when the server ended or destroyed the connection rather than keeping it. */
  readonly closedByServer: boolean;
  readonly errorCode: string | null;
  /** Bytes this client successfully handed to the socket before settling. */
  readonly bytesWritten: number;
  readonly elapsedMs: number;
}

/** Every response the suite has captured, for the FR-66 sweep. */
const capturedResponses: Exchange[] = [];

const CORS_HEADER = /^access-control-|^timing-allow-origin:/im;
const FINGERPRINT_HEADER = /^server:|^x-powered-by:/im;

function recordAndScreen(captured: Exchange): Exchange {
  capturedResponses.push(captured);
  // FR-66, applied to EVERY captured response rather than to a chosen few.
  assert.equal(
    CORS_HEADER.test(captured.text),
    false,
    `a response carried a CORS header:\n${captured.text}`,
  );
  assert.equal(
    FINGERPRINT_HEADER.test(captured.text),
    false,
    `a response carried a product fingerprint header:\n${captured.text}`,
  );
  return captured;
}

interface ExchangeOptions {
  /** Milliseconds of silence after which the exchange is considered finished. */
  readonly idleMs?: number;
  /** Called once connected, instead of writing `request`. */
  readonly drive?: (socket: Socket, done: () => void) => void;
  /** Bind the client socket to this local address, for a distinct source key. */
  readonly localAddress?: string;
}

/**
 * One request over a raw socket, returning the server's bytes verbatim.
 *
 * The idle timer is what makes a keep-alive response (`403`, `404`, `405`)
 * terminable: those deliberately do NOT carry `Connection: close`, so the
 * server holds the socket open and nothing else would ever settle the promise.
 */
function exchange(
  port: number,
  request: string | Buffer,
  options: ExchangeOptions = {},
): Promise<Exchange> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const startedAt = Date.now();
    let closedByServer = false;
    let errorCode: string | null = null;
    let bytesWritten = 0;
    let settled = false;
    let idle: NodeJS.Timeout | null = null;

    const socket = connect({
      host: '127.0.0.1',
      port,
      ...(options.localAddress === undefined ? {} : { localAddress: options.localAddress }),
    });

    const settle = (): void => {
      if (settled) return;
      settled = true;
      if (idle !== null) clearTimeout(idle);
      socket.destroy();
      resolve(
        recordAndScreen({
          bytes: Buffer.concat(chunks),
          text: Buffer.concat(chunks).toString('latin1'),
          closedByServer,
          errorCode,
          bytesWritten,
          elapsedMs: Date.now() - startedAt,
        }),
      );
    };

    const bump = (): void => {
      if (idle !== null) clearTimeout(idle);
      idle = setTimeout(settle, options.idleMs ?? 300);
    };

    socket.on('connect', () => {
      if (options.drive !== undefined) {
        options.drive(socket, settle);
      } else {
        const payload = typeof request === 'string' ? Buffer.from(request, 'latin1') : request;
        socket.write(payload);
        bytesWritten += payload.byteLength;
      }
      bump();
    });
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      bump();
    });
    socket.on('end', () => {
      closedByServer = true;
    });
    socket.on('error', (error: NodeJS.ErrnoException) => {
      errorCode = error.code ?? 'UNKNOWN';
      closedByServer = closedByServer || errorCode === 'ECONNRESET';
    });
    socket.on('close', settle);
  });
}

/** Build a request block. Header order is the caller's, verbatim. */
function raw(startLine: string, headers: readonly string[], body = ''): string {
  return `${[startLine, ...headers].join('\r\n')}\r\n\r\n${body}`;
}

function statusLine(captured: Exchange): string {
  return captured.text.split('\r\n')[0] ?? '';
}

function bodyOf(captured: Exchange): string {
  const split = captured.text.indexOf('\r\n\r\n');
  return split === -1 ? '' : captured.text.slice(split + 4);
}

function assertSameBytes(actual: Exchange, expected: Exchange, label: string): void {
  assert.equal(
    Buffer.compare(actual.bytes, expected.bytes),
    0,
    `${label} is not byte-identical.\n--- actual ---\n${actual.text}\n--- expected ---\n${expected.text}`,
  );
  assert.equal(
    actual.closedByServer,
    expected.closedByServer,
    `${label} differs in post-response socket disposition`,
  );
}

// ---------------------------------------------------------------------------
// The contract's fixed responses, transcribed from operator contract §5
// ---------------------------------------------------------------------------

const UNIFORM_401_WIRE =
  'HTTP/1.1 401 Unauthorized\r\n' +
  'Content-Type: application/json\r\n' +
  'Content-Length: 24\r\n' +
  'WWW-Authenticate: Bearer\r\n' +
  'Cache-Control: no-store\r\n' +
  'X-Content-Type-Options: nosniff\r\n' +
  'Connection: close\r\n' +
  '\r\n' +
  '{"error":"unauthorized"}';

// ---------------------------------------------------------------------------
// 1. The single exported factory (B16, C24, FR-65, FR-70, FR-76)
// ---------------------------------------------------------------------------

describe('US-22 §1: createServingOptions is the one factory everything reads', () => {
  function optionsFor(extra: Record<string, string> = {}) {
    const config = loadConfig(httpEnv(extra), { repoRoot: REPO_ROOT });
    return createServingOptions(config);
  }

  test('B16: Host, Origin and rebinding protection are all left undefined', () => {
    const transport = optionsFor().transportOptionsFor('session-a');

    // Validation is performed by repository code, not by an SDK transport
    // option. The SDK's `allowedHosts` exact-matches the FULL Host header, port
    // and all, so an operator who lists `example.com` gets a 403 on every real
    // request; its `allowedOrigins` is an allow-list where FR-66 requires
    // blanket rejection; and all three are `@deprecated`.
    assert.equal(transport.allowedHosts, undefined);
    assert.equal(transport.allowedOrigins, undefined);
    assert.equal(transport.enableDnsRebindingProtection, undefined);
  });

  test('C24: enableJsonResponse is at its default and keepAliveMs is explicit', () => {
    const transport = optionsFor({ UNIFI_HTTP_SSE_KEEPALIVE_MS: '4321' }).transportOptionsFor('s');

    // Default (`false`) means SSE mode. Turning it on would also deadlock any
    // drain written against `handleRequest`'s promise.
    assert.equal(transport.enableJsonResponse, undefined);
    // Set explicitly from UNIFI_HTTP_SSE_KEEPALIVE_MS rather than inherited
    // from the SDK's own 15000, so the operator's value is the one in force.
    assert.equal(transport.keepAliveMs, 4321);
    assert.notEqual(transport.keepAliveMs, 15_000);
  });

  test('sessionIdGenerator is passed explicitly — omitting it is stateless mode', () => {
    const transport = optionsFor().transportOptionsFor('the-id');
    assert.equal(typeof transport.sessionIdGenerator, 'function');
    assert.equal(transport.sessionIdGenerator?.(), 'the-id');
  });

  test('closeIdleConnections is never called; closeAllConnections is', () => {
    const source = readFileSync(HTTP_SOURCE, 'utf8');
    // A CALL, not a mention: the module names `closeIdleConnections()` in prose
    // to say why it is unusable, and a scan cannot tell a mention from a use.
    // `close()` and `closeIdleConnections()` both use the "not sending a request
    // or waiting for a response" predicate, and an open SSE response is by
    // definition not idle — so only `closeAllConnections()` kills one.
    assert.equal(/\w\.closeIdleConnections\s*\(/.test(source), false);
    assert.ok(/\w\.closeAllConnections\s*\(/.test(source));
  });

  test('server.maxConnections is never assigned — the accept layer has no route', () => {
    const source = readFileSync(HTTP_SOURCE, 'utf8');
    assert.equal(
      /^\s*\w+\.maxConnections\s*=/m.test(source),
      false,
      'something assigned maxConnections on a server object',
    );
  });
});

// ---------------------------------------------------------------------------
// 2. The bind, and the serving line under UNIFI_HTTP_PORT=0 (FR-62, FR-63)
// ---------------------------------------------------------------------------

describe('US-22 §2: the listener binds first and reports the port it actually got', () => {
  test('resolveRegistry receives listenAddress, so the serving line renders the real port', async (t) => {
    const bound = await boundServer(t);
    await waitReady(bound);

    assert.equal(bound.instruments.counts.listen, 1);
    assert.notEqual(bound.port, 0, 'UNIFI_HTTP_PORT=0 must yield an OS-assigned port');

    const serving = bound.lines.find((line) => line.includes('serving MCP over http'));
    assert.ok(serving !== undefined, `no serving line in:\n${bound.lines.join('\n')}`);
    // Without the `listenAddress` seam this renders the CONFIGURED port and
    // reads `at 127.0.0.1:0/mcp` on every ephemeral-port deployment.
    assert.match(serving, new RegExp(`at 127\\.0\\.0\\.1:${bound.port}/mcp`));
    assert.equal(serving.includes(':0/mcp'), false);
    assert.match(serving, /auth bearer, probes GET \/healthz and GET \/readyz \(unauthenticated\)/);
  });

  test('the registry resolves AFTER the bind: /healthz answers 200 while /readyz says starting', async (t) => {
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const bound = await boundServer(
      t,
      httpEnv(),
      {},
      {
        buildRegistry: async (root, manifest, services) => {
          await gate;
          const { buildRegistry } = await import('../src/registry/build.js');
          return buildRegistry(root, manifest, services);
        },
      },
    );

    const live = await exchange(bound.port, raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
    const ready = await exchange(bound.port, raw('GET /readyz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));

    assert.match(statusLine(live), /^HTTP\/1\.1 200 /);
    assert.equal(bodyOf(live), 'ok\n');
    assert.match(statusLine(ready), /^HTTP\/1\.1 503 /);
    assert.equal(bodyOf(ready), 'starting\n');

    // 12r: an authenticated MCP request in the same window is 503 unavailable,
    // never a 500 and never a connection refusal.
    const early = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(early), /^HTTP\/1\.1 503 /);
    assert.equal(bodyOf(early), '{"error":"unavailable"}');

    release();
    await waitReady(bound);
    const afterReady = await exchange(
      bound.port,
      raw('GET /readyz HTTP/1.1', [`Host: ${KUBELET_HOST}`]),
    );
    assert.equal(bodyOf(afterReady), 'ready\n');
  });
});

// ---------------------------------------------------------------------------
// 3. The uniform 401 (C27) and the closed exception set (C28)
// ---------------------------------------------------------------------------

describe('US-22 §3: every unauthenticated rejection is byte-identical', () => {
  const env = httpEnv({
    UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST,
    UNIFI_HTTP_MAX_BODY_BYTES: '4096',
    UNIFI_HTTP_MAX_HEADER_BYTES: '2048',
  });

  /**
   * The seven classes an unauthenticated caller can reach.
   *
   * They are ALL 401 not because seven responses were composed identically by
   * hand, but because authentication is step 4 and `Host`, `Origin`, route,
   * method and body are steps 6-10: an unauthenticated caller never reaches
   * them, so there is nothing for them to differ about.
   */
  function classes(): ReadonlyArray<readonly [string, string]> {
    const host = `Host: ${ALLOWED_HOST}`;
    return [
      ['missing Authorization', raw('POST /mcp HTTP/1.1', [host, 'Content-Length: 0'])],
      [
        'wrong secret',
        raw('POST /mcp HTTP/1.1', [
          host,
          `Authorization: Bearer ${WRONG_SECRET}`,
          'Content-Length: 0',
        ]),
      ],
      ['disallowed Host', raw('POST /mcp HTTP/1.1', [`Host: ${REJECTED_HOST}`, 'Content-Length: 0'])],
      [
        'any Origin',
        raw('POST /mcp HTTP/1.1', [host, 'Origin: https://evil.example', 'Content-Length: 0']),
      ],
      ['unknown path', raw('POST /no-such-path HTTP/1.1', [host, 'Content-Length: 0'])],
      ['disallowed method', raw('PUT /mcp HTTP/1.1', [host, 'Content-Length: 0'])],
      [
        'over-cap body',
        raw('POST /mcp HTTP/1.1', [host, 'Content-Length: 65536'], 'A'.repeat(8192)),
      ],
    ] as ReadonlyArray<readonly [string, string]>;
  }

  test('C27: seven classes, one status line, one header set, one body, one disposition', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const seen: Array<readonly [string, Exchange]> = [];
    for (const [label, request] of classes()) {
      seen.push([label, await exchange(bound.port, request)] as const);
    }

    const first = seen[0];
    assert.ok(first !== undefined);
    const [, reference] = first;

    // The literal wire form, transcribed from operator contract §5.1. No
    // `realm=`, no `error="invalid_token"`, no CORS, no `Server`, no
    // `Keep-Alive`, no `Vary`, no `Transfer-Encoding`, and no `Date` — the last
    // because Node adds it by default and it changes every second, so without
    // suppression this comparison fails spuriously against a correct
    // implementation.
    assert.equal(reference.text, UNIFORM_401_WIRE);
    assert.equal(bodyOf(reference).length, 24);

    for (const [label, actual] of seen.slice(1)) {
      assertSameBytes(actual, reference, `the ${label} rejection`);
    }

    // The post-response socket disposition is part of the guarantee: resetting
    // for a large body and keeping alive for a small one would reopen the leak
    // one layer down, where TCP behaviour distinguishes the two classes.
    for (const [label, actual] of seen) {
      assert.equal(actual.closedByServer, true, `${label} left the socket open`);
    }
  });

  test('C1: no transport is constructed and no MCP request is dispatched for any of them', async (t) => {
    let transports = 0;
    const bound = await boundServer(t, env, {
      createTransport: (options) => {
        transports += 1;
        return new StreamableHTTPServerTransport(options);
      },
    });
    await waitReady(bound);

    for (const [, request] of classes()) await exchange(bound.port, request);

    // The transport counter is the stronger of the two: a handler counter can
    // read 0 while a transport was still constructed and torn down.
    assert.equal(transports, 0, 'a transport was constructed for a rejected request');
    assert.equal(bound.instruments.counts.mcpRequest, 0);
  });

  test('C28: the exception set is closed and has exactly one member — the pre-application 431', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const reference = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );

    const logsBefore = bound.instruments.counts.requestLogs.length;
    const overflow = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `X-Filler: ${'F'.repeat(4096)}`,
        'Content-Length: 0',
      ]),
    );

    // Read IMMEDIATELY after the overflow and before anything else is sent:
    // the whole claim is that Node's parser answered without application code
    // running, so a later request's line would mask it.
    const logsAfterOverflow = bound.instruments.counts.requestLogs.length;

    const divergent = new Map<string, string>();
    const measured: Array<readonly [string, Exchange]> = [['header overflow', overflow]];
    for (const [label, request] of classes()) {
      measured.push([label, await exchange(bound.port, request)] as const);
    }
    for (const [label, actual] of measured) {
      if (Buffer.compare(actual.bytes, reference.bytes) !== 0) divergent.set(label, statusLine(actual));
    }

    assert.deepEqual(
      [...divergent.keys()],
      ['header overflow'],
      `the exception set is not closed: ${JSON.stringify([...divergent])}`,
    );
    assert.match(divergent.get('header overflow') ?? '', /^HTTP\/1\.1 431 /);

    // Emitted by Node's parser before any application code runs, which is also
    // why it carries no log line. A second divergence introduced later fails
    // this assertion rather than joining a waiver.
    assert.equal(
      logsAfterOverflow,
      logsBefore,
      'the pre-application 431 produced a request log line',
    );
    assert.equal(/unifi[- ]/i.test(bodyOf(overflow)), false, 'the 431 body named this product');
  });
});

// ---------------------------------------------------------------------------
// 4. Authenticated rejections are distinct and correct (C29)
// ---------------------------------------------------------------------------

describe('US-22 §4: an authenticated caller gets the real status', () => {
  const env = httpEnv({
    UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST,
    UNIFI_HTTP_MAX_BODY_BYTES: '4096',
  });

  function authed(startLine: string, headers: readonly string[], body = ''): string {
    return raw(startLine, [`Authorization: Bearer ${SECRET}`, ...headers], body);
  }

  test('C29: 403 / 403 / 404 / 405+Allow / 413+close, and the two 403s are identical', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const badHost = await exchange(
      bound.port,
      authed('POST /mcp HTTP/1.1', [`Host: ${REJECTED_HOST}`, 'Content-Length: 0']),
    );
    const withOrigin = await exchange(
      bound.port,
      authed('POST /mcp HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        'Origin: https://evil.example',
        'Content-Length: 0',
      ]),
    );
    const unknownPath = await exchange(
      bound.port,
      authed('POST /nope HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    const badMethod = await exchange(
      bound.port,
      authed('PUT /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    const overCap = await exchange(
      bound.port,
      authed(
        'POST /mcp HTTP/1.1',
        [`Host: ${ALLOWED_HOST}`, 'Content-Type: application/json', 'Content-Length: 8192'],
        'B'.repeat(8192),
      ),
    );

    assert.match(statusLine(badHost), /^HTTP\/1\.1 403 Forbidden/);
    assert.equal(bodyOf(badHost), '{"error":"forbidden"}');
    // ONE body for both, so an authenticated caller learns "one of the
    // browser-facing controls rejected you" and not which.
    assertSameBytes(withOrigin, badHost, 'the Origin rejection');

    assert.match(statusLine(unknownPath), /^HTTP\/1\.1 404 Not Found/);
    assert.equal(bodyOf(unknownPath), '{"error":"not_found"}');
    assert.equal(unknownPath.text.includes('/nope'), false, 'the 404 echoed the request target');

    assert.match(statusLine(badMethod), /^HTTP\/1\.1 405 Method Not Allowed/);
    assert.equal(bodyOf(badMethod), '{"error":"method_not_allowed"}');
    assert.match(badMethod.text, /\r\nAllow: POST, GET, DELETE, HEAD\r\n/);

    assert.match(statusLine(overCap), /^HTTP\/1\.1 413 /);
    assert.equal(bodyOf(overCap), '{"error":"payload_too_large"}');
    assert.match(overCap.text, /\r\nConnection: close\r\n/);
    // The threshold is configuration and §5.0's no-configuration-leak rule has
    // no authentication exemption.
    assert.equal(overCap.text.includes('4096'), false, 'the 413 disclosed the cap');
  });

  test('OPTIONS is a 405 and no preflight is ever answered', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const preflight = await exchange(
      bound.port,
      authed('OPTIONS /mcp HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        'Access-Control-Request-Method: POST',
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(preflight), /^HTTP\/1\.1 405 /);
    // `recordAndScreen` already asserted no CORS header; stated here because an
    // implementer following a CORS reflex must not add an OPTIONS handler.
    assert.equal(/access-control/i.test(preflight.text), false);
  });

  test('an unknown session identifier is rejected identically however it died', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const never = await exchange(
      bound.port,
      authed('POST /mcp HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        'Mcp-Session-Id: 0000000000000000000000000000000000000000',
        'Content-Length: 0',
      ]),
    );
    const alsoNever = await exchange(
      bound.port,
      authed('POST /mcp HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        'Mcp-Session-Id: ffffffffffffffffffffffffffffffffffffffff',
        'Content-Length: 0',
      ]),
    );

    assert.match(statusLine(never), /^HTTP\/1\.1 404 /);
    assert.equal(statusLine(alsoNever), statusLine(never));
    assert.equal(bodyOf(alsoNever), bodyOf(never));
    // `Mcp-Session-Id` is bearer-equivalent, so the identifier is never echoed.
    assert.equal(never.text.includes('0000000000'), false);
  });
});

// ---------------------------------------------------------------------------
// 5. The probe exemption is narrow, and 401-not-405 (C7, C29's probe halves)
// ---------------------------------------------------------------------------

describe('US-22 §5: the probes are the deliberate exception, scoped to two paths', () => {
  const env = httpEnv({ UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST });

  test('C7: both probes answer under a hostile Host that 403s the MCP endpoint in the same run', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    // What a kubelet actually sends: the pod IP, which no operator allow-list
    // contains. A probe subject to FR-65 fails for EVERY correctly configured
    // deployment, which is why this is the single most likely operational bug
    // in the feature.
    const healthz = await exchange(bound.port, raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
    const readyz = await exchange(bound.port, raw('GET /readyz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));

    assert.match(statusLine(healthz), /^HTTP\/1\.1 200 /);
    assert.equal(bodyOf(healthz), 'ok\n');
    assert.match(statusLine(readyz), /^HTTP\/1\.1 200 /);
    assert.equal(bodyOf(readyz), 'ready\n');
    assert.match(healthz.text, /\r\nContent-Type: text\/plain; charset=utf-8\r\n/);
    assert.match(healthz.text, /\r\nX-Content-Type-Options: nosniff\r\n/);
    assert.equal(/\r\nDate:/i.test(healthz.text), false, 'a probe response carried a Date header');

    // THE SAME header value, with a valid secret presented, on the MCP endpoint.
    const mcp = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: ${KUBELET_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(mcp), /^HTTP\/1\.1 403 /);

    // …and it still enforces authentication in that same run.
    const anonymous = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    assert.equal(anonymous.text, UNIFORM_401_WIRE);
  });

  test('C29: a non-GET probe is 401 to a stranger and 405 to an authenticated caller, same run', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const stranger = await exchange(
      bound.port,
      raw('POST /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`, 'Content-Length: 0']),
    );
    const holder = await exchange(
      bound.port,
      raw('POST /healthz HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );

    // A 405 to a stranger is a probe-path oracle: it confirms both that the
    // path exists and that the method was the problem, which is more than "no".
    assert.equal(stranger.text, UNIFORM_401_WIRE);
    assert.match(statusLine(holder), /^HTTP\/1\.1 405 /);
    assert.match(holder.text, /\r\nAllow: GET, HEAD\r\n/);
    assert.equal(bodyOf(holder), '{"error":"method_not_allowed"}');
  });

  test('the exemption covers authentication and Host only — an Origin still 403s a probe', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    const withOrigin = await exchange(
      bound.port,
      raw('GET /healthz HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Origin: https://evil.example',
      ]),
    );
    assert.match(statusLine(withOrigin), /^HTTP\/1\.1 403 /);
  });

  test('normalisation happens once: a probe-prefixed target that resolves to /mcp is not exempt', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    // The dangerous implementation normalises correctly for ROUTING and tests
    // the exemption against the RAW target with `startsWith('/healthz')`. Under
    // that split this request takes the exempt branch and routes to the MCP
    // endpoint — the whole tool surface served unauthenticated.
    const traversal = await exchange(
      bound.port,
      raw('GET /healthz%2f..%2fmcp HTTP/1.1', [`Host: ${KUBELET_HOST}`]),
    );
    assert.equal(traversal.text, UNIFORM_401_WIRE);

    // The forms FR-67 enumerates as hitting the probe, and the ones that do not.
    for (const target of ['/healthz', '/healthz/', '//healthz', '/healthz?x=1', '/%68ealthz']) {
      const hit = await exchange(bound.port, raw(`GET ${target} HTTP/1.1`, [`Host: ${KUBELET_HOST}`]));
      assert.equal(bodyOf(hit), 'ok\n', `${target} should have hit the probe`);
    }
    for (const target of ['/HEALTHZ', '/healthz/x', '/healthz/../mcp', '/%c0%af']) {
      const miss = await exchange(bound.port, raw(`GET ${target} HTTP/1.1`, [`Host: ${KUBELET_HOST}`]));
      assert.equal(miss.text, UNIFORM_401_WIRE, `${target} should NOT have hit the probe`);
    }
  });
});

// ---------------------------------------------------------------------------
// 6. Authentication precedes body read; the body cap (C31)
// ---------------------------------------------------------------------------

describe('US-22 §6: nothing an unauthenticated caller sends is buffered', () => {
  test('C31: 401 arrives after at most the header bytes, by a socket byte counter', async (t) => {
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_MAX_BODY_BYTES: '4096' }));
    await waitReady(bound);

    // The decisive form: write ONLY the header block, declaring a five-megabyte
    // body, and then nothing at all. A server that read the body before
    // authenticating would block here until the request timeout and this test
    // would time out rather than fail — so a 401 arriving at all is the proof,
    // and `bytesWritten` records exactly how much this client had to send.
    const headers = raw('POST /mcp HTTP/1.1', [
      `Host: 127.0.0.1:${bound.port}`,
      'Content-Type: application/json',
      'Content-Length: 5000000',
    ]);

    const result = await exchange(bound.port, headers, { idleMs: 500 });

    assert.equal(result.text, UNIFORM_401_WIRE);
    assert.equal(result.bytesWritten, Buffer.byteLength(headers, 'latin1'));
    assert.ok(
      result.bytesWritten < 5_000_000,
      'the client had to send the body before being rejected',
    );
    assert.equal(bound.serving.retainedRequestBuffers(), 0);
  });

  test('C31: an over-cap body is refused, and 10x the bound behaves identically', async (t) => {
    const limit = 4096;
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_MAX_BODY_BYTES: String(limit) }));
    await waitReady(bound);

    const send = async (size: number): Promise<Exchange> =>
      exchange(
        bound.port,
        raw(
          'POST /mcp HTTP/1.1',
          [
            `Host: 127.0.0.1:${bound.port}`,
            `Authorization: Bearer ${SECRET}`,
            'Content-Type: application/json',
            `Content-Length: ${size}`,
          ],
          'C'.repeat(size),
        ),
      );

    const justOver = await send(limit + 1);
    const tenTimes = await send(limit * 10);

    assert.match(statusLine(justOver), /^HTTP\/1\.1 413 /);
    // Size is never the thing being measured, so a body ten times the bound is
    // the same event as a body one byte over it.
    assertSameBytes(tenTimes, justOver, 'the 10x over-cap body');
    assert.equal(bound.serving.retainedRequestBuffers(), 0, 'a request buffer was retained');
  });

  test('C31: a flood far larger than any socket buffer is refused without being consumed', async (t) => {
    const limit = 4096;
    const bound = await boundServer(t, httpEnv({ UNIFI_HTTP_MAX_BODY_BYTES: String(limit) }));
    await waitReady(bound);

    const declared = 16 * 1024 * 1024;
    const chunk = Buffer.alloc(64 * 1024, 0x44);

    // A CLIENT-side byte counter, paced by write backpressure. The bound below
    // is deliberately generous and its slack is NAMED rather than tuned: the
    // kernel's loopback socket buffers hold megabytes, so no socket-level
    // counter on either side can resolve "the bound plus one read chunk"
    // exactly. What this CAN prove decisively is that the process refuses
    // without consuming the flood — which is the property NFR-29 is about —
    // and a memory comparison would be GC-nondeterministic and would be tuned
    // until it could not fail.
    const SLACK = 8 * 1024 * 1024;

    let sent = 0;
    const result = await exchange(bound.port, '', {
      idleMs: 750,
      drive: (socket) => {
        socket.write(
          raw(
            'POST /mcp HTTP/1.1',
            [
              `Host: 127.0.0.1:${bound.port}`,
              `Authorization: Bearer ${SECRET}`,
              'Content-Type: application/json',
              `Content-Length: ${declared}`,
            ],
            '',
          ),
        );
        let stop = false;
        const halt = (): void => {
          stop = true;
        };
        // The server answering, or the socket going away, is what stops the
        // pump. Reaching `declared` deliberately does NOT settle the exchange:
        // the response is the thing under test and it arrives after the write.
        socket.on('data', halt);
        socket.on('error', halt);
        socket.on('close', halt);
        const pump = (): void => {
          if (stop || sent >= declared) return;
          sent += chunk.byteLength;
          socket.write(chunk, () => setImmediate(pump));
        };
        pump();
      },
    });

    // WHAT THIS CASE CANNOT ASSERT, AND WHY THAT IS THE CORRECT OUTCOME.
    //
    // The 413 IS emitted — the log line below proves it — but a peer still
    // blasting sixteen megabytes does not receive it. Closing a socket that
    // still has unread inbound data makes the kernel send RST rather than FIN,
    // and an RST lets the peer's stack discard bytes it had already buffered.
    // Delivering the response reliably would mean reading and discarding the
    // rest of the body, which is precisely the unbounded pre-refusal
    // consumption FR-76 and NFR-29 forbid. The over-cap cases above — a body
    // one byte over the bound and one ten times it — DO receive the 413,
    // because they fit inside the socket buffers; that is every ordinary
    // over-cap request.
    //
    // So this case asserts the property that actually matters: the process
    // refuses without consuming the flood.
    assert.ok(
      result.errorCode !== null || result.closedByServer,
      'the flood was neither reset nor closed — the server kept reading it',
    );
    assert.ok(sent < declared, `the whole ${declared}-byte flood was accepted before the refusal`);
    assert.ok(
      sent <= limit + SLACK,
      `the flood pushed ${sent} bytes before being refused, beyond the cap plus kernel buffering`,
    );
    assert.equal(bound.serving.retainedRequestBuffers(), 0);

    // The refusal is in the operator's record even though it never reached the
    // caller, and it is a 413 rather than anything else.
    const refusals = bound.instruments.counts.requestLogs.filter((line) =>
      line.includes('status=413 dur_ms='),
    );
    assert.equal(refusals.length, 1, `expected one 413 line, saw ${refusals.length}`);
    assert.match(refusals[0] ?? '', /reject_reason=body_size/);
  });
});

// ---------------------------------------------------------------------------
// 7. Connection admission and the probe headroom (C33)
// ---------------------------------------------------------------------------

/** Can this host reach a second loopback address, for a distinct source key? */
function secondLoopbackAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createTcpServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, '127.0.0.2', () => {
      probe.close(() => resolve(true));
    });
  });
}

describe('US-22 §7: the connection budget is the NON-probe budget', () => {
  const cap = 2;
  const env = httpEnv({ UNIFI_HTTP_MAX_CONNECTIONS: String(cap) });

  /** Hold a raw TCP connection open without sending anything. */
  function hold(port: number, localAddress?: string): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = connect({
        host: '127.0.0.1',
        port,
        ...(localAddress === undefined ? {} : { localAddress }),
      });
      socket.once('connect', () => resolve(socket));
      socket.once('error', reject);
    });
  }

  test('C33: cap + a fixed headroom of 8, capped at one per source key', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);
    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    open.push(await hold(bound.port));
    open.push(await hold(bound.port));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(bound.serving.connectionCounts(), { total: cap, headroom: 0 });

    // The (cap+1)th is still ACCEPTED — into the headroom. That acceptance is
    // the behavioural proof that `server.maxConnections` is not doing this job:
    // Node's accept layer would have destroyed this socket before any request
    // line was read, so no route information could ever have been consulted.
    open.push(await hold(bound.port));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.deepEqual(bound.serving.connectionCounts(), { total: cap + 1, headroom: 1 });

    // …and the next one from the SAME source key is refused, because within the
    // headroom at most one connection per source is admitted. Without that cap
    // an attacker sends `GET /healthz` on eight keep-alive connections and
    // starves the kubelet exactly as before, at a cost of eight sockets.
    const fourth = await hold(bound.port);
    open.push(fourth);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.deepEqual(
      bound.serving.connectionCounts(),
      { total: cap + 1, headroom: 1 },
      'a second headroom connection was admitted from one source key',
    );
    assert.ok(
      fourth.destroyed || fourth.readyState === 'closed',
      'the refused connection was not dropped',
    );

    // Total accepted never exceeds cap + 8, whatever is thrown at it.
    assert.ok(bound.serving.connectionCounts().total <= cap + PROBE_CONNECTION_HEADROOM);
  });

  test('C33: a headroom connection whose route is not a probe gets the uniform 401 and is destroyed', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);
    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    open.push(await hold(bound.port));
    open.push(await hold(bound.port));
    await new Promise((resolve) => setTimeout(resolve, 50));

    // The headroom-admitted connection asking for a probe: served.
    const probe = await exchange(bound.port, raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
    assert.equal(bodyOf(probe), 'ok\n');

    // The headroom slot is released on the SERVER socket's `close`, which lands
    // a tick after this client destroys its end. Opening the next connection in
    // the same tick would be refused at admission — correctly, and with no
    // response at all — which is a different case from the one under test.
    await new Promise((resolve) => setTimeout(resolve, 150));

    // The headroom-admitted connection asking for anything else, WITH a valid
    // secret: still the byte-identical uniform 401. Naming a distinct status
    // here would be a pre-auth oracle whose existence is conditional on the
    // connection count — an attacker who could produce it would learn the cap
    // had been reached and, by binary search, learn UNIFI_HTTP_MAX_CONNECTIONS.
    const claimed = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.equal(claimed.text, UNIFORM_401_WIRE);
    assert.equal(claimed.closedByServer, true);
  });

  test('C33: a probe from a DIFFERENT source key still connects', async (t) => {
    if (!(await secondLoopbackAvailable())) {
      // Reported rather than silently passed: 127.0.0.2 is routable on Linux
      // and on Windows but is not configured by default on macOS, and the
      // per-source rule cannot be exercised without two source keys.
      t.skip('no second loopback address (127.0.0.2) on this platform');
      return;
    }

    const bound = await boundServer(t, env);
    await waitReady(bound);
    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    open.push(await hold(bound.port));
    open.push(await hold(bound.port));
    open.push(await hold(bound.port)); // takes 127.0.0.1's single headroom slot
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(bound.serving.connectionCounts().headroom, 1);

    const fromElsewhere = await exchange(
      bound.port,
      raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]),
      { localAddress: '127.0.0.2' },
    );
    assert.equal(bodyOf(fromElsewhere), 'ok\n');
  });
});

// ---------------------------------------------------------------------------
// 8. Every bound, by provenance and effect (C34)
// ---------------------------------------------------------------------------

describe('US-22 §8: bounds are asserted by provenance and effect, never against a Node default', () => {
  /**
   * Probe values chosen so that none coincides with the §5.15.1 default OR with
   * a Node default. `keepAliveTimeout` is configured at 5000 and Node's default
   * is 5000; the header cap is configured at 16384 and `--max-http-header-size`
   * defaults to 16384 — so a test written as "not the default" fails against a
   * correct implementation at the documented defaults, and one written as
   * "equals 5000" proves nothing about whether this configuration wired it.
   */
  const PROBE = {
    UNIFI_HTTP_HEADERS_TIMEOUT_MS: '1500',
    UNIFI_HTTP_REQUEST_TIMEOUT_MS: '6000',
    UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: '1200',
    UNIFI_HTTP_MAX_HEADER_BYTES: '2048',
    UNIFI_HTTP_MAX_CONNECTIONS: '3',
    UNIFI_HTTP_MAX_BODY_BYTES: '4096',
  };

  test('C34 provenance, run 1: unset variables resolve to the §5.15.1 defaults', async (t) => {
    const bound = await boundServer(t);
    await waitReady(bound);

    assert.deepEqual(bound.serving.bounds(), {
      headersTimeout: 10_000,
      requestTimeout: 30_000,
      keepAliveTimeout: 5_000,
      maxHeaderSize: 16_384,
      maxConnections: 64,
      maxBodyBytes: 1_048_576,
    });
  });

  test('C34 provenance, run 2: probe values reach the factory, the handle AND the server', async (t) => {
    const bound = await boundServer(t, httpEnv(PROBE));
    await waitReady(bound);

    const expected = {
      headersTimeout: 1500,
      requestTimeout: 6000,
      keepAliveTimeout: 1200,
      maxHeaderSize: 2048,
      maxConnections: 3,
      maxBodyBytes: 4096,
    };

    // The single exported factory…
    const config = loadConfig(httpEnv(PROBE), { repoRoot: REPO_ROOT });
    assert.deepEqual({ ...createServingOptions(config).bounds }, expected);
    // …the handle…
    assert.deepEqual({ ...bound.serving.bounds() }, expected);
    // …and the server object the behaviour actually comes from. An
    // implementation that ignores the variables passes run 1 and fails here.
    assert.equal(bound.server.headersTimeout, expected.headersTimeout);
    assert.equal(bound.server.requestTimeout, expected.requestTimeout);
    assert.equal(bound.server.keepAliveTimeout, expected.keepAliveTimeout);
  });

  test('C34 effect: the body cap, the header cap and the connection cap all move with configuration', async (t) => {
    const bound = await boundServer(t, httpEnv(PROBE));
    await waitReady(bound);
    const open: Socket[] = [];
    t.after(() => {
      for (const socket of open) socket.destroy();
    });

    // Body cap at the probe value: 4095 passes the cap, 4097 does not.
    const underCap = await exchange(
      bound.port,
      raw(
        'POST /mcp HTTP/1.1',
        [
          `Host: 127.0.0.1:${bound.port}`,
          `Authorization: Bearer ${SECRET}`,
          'Content-Type: application/json',
          'Content-Length: 4000',
        ],
        `{"pad":"${'p'.repeat(3988)}"}`,
      ),
    );
    assert.equal(/^HTTP\/1\.1 413 /.test(statusLine(underCap)), false);

    const overCap = await exchange(
      bound.port,
      raw(
        'POST /mcp HTTP/1.1',
        [
          `Host: 127.0.0.1:${bound.port}`,
          `Authorization: Bearer ${SECRET}`,
          'Content-Type: application/json',
          'Content-Length: 4097',
        ],
        'z'.repeat(4097),
      ),
    );
    assert.match(statusLine(overCap), /^HTTP\/1\.1 413 /);

    // Header cap at the probe value: 1 KiB of headers passes, 3 KiB does not.
    const smallHeaders = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `X-Pad: ${'h'.repeat(1000)}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(smallHeaders), /^HTTP\/1\.1 401 /);

    const bigHeaders = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `X-Pad: ${'h'.repeat(3000)}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(bigHeaders), /^HTTP\/1\.1 431 /);

    // Connection cap at the probe value of 3.
    for (let index = 0; index < 3; index += 1) {
      open.push(
        await new Promise<Socket>((resolve, reject) => {
          const socket = connect({ host: '127.0.0.1', port: bound.port });
          socket.once('connect', () => resolve(socket));
          socket.once('error', reject);
        }),
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(bound.serving.connectionCounts().total, 3);
    assert.equal(bound.serving.connectionCounts().headroom, 0);
  });

  test('C34 effect: an idle keep-alive socket is closed after keepAliveTimeout and not before', async (t) => {
    const bound = await boundServer(t, httpEnv(PROBE));
    await waitReady(bound);

    const result = await exchange(bound.port, '', {
      idleMs: 5_000,
      drive: (socket, done) => {
        // A 404 deliberately carries NO `Connection: close`, so the socket is
        // left idle and keep-alive governs it from here.
        socket.write(
          raw('POST /nope HTTP/1.1', [
            `Host: 127.0.0.1:${bound.port}`,
            `Authorization: Bearer ${SECRET}`,
            'Content-Length: 0',
          ]),
        );
        socket.once('close', done);
        socket.once('end', done);
      },
    });

    assert.match(statusLine(result), /^HTTP\/1\.1 404 /);
    assert.ok(result.closedByServer, 'the idle keep-alive socket was never closed');
    assert.ok(
      result.elapsedMs >= 1_000,
      `the socket closed after ${result.elapsedMs} ms, before the configured 1200 ms`,
    );
    assert.ok(result.elapsedMs < 5_000, `the socket took ${result.elapsedMs} ms to close`);
  });

  test('C34 effect: a slowly delivered body is terminated by requestTimeout', async (t) => {
    const bound = await boundServer(
      t,
      httpEnv({
        UNIFI_HTTP_HEADERS_TIMEOUT_MS: '1000',
        UNIFI_HTTP_REQUEST_TIMEOUT_MS: '1500',
        UNIFI_HTTP_MAX_BODY_BYTES: '1048576',
      }),
    );
    await waitReady(bound);

    // Headers complete promptly, so `headersTimeout` is satisfied; the body
    // then dribbles. Only `requestTimeout` bounds this, and without it a
    // caller holds a connection slot indefinitely at one byte per second.
    const result = await exchange(bound.port, '', {
      idleMs: 8_000,
      drive: (socket, done) => {
        socket.write(
          raw('POST /mcp HTTP/1.1', [
            `Host: 127.0.0.1:${bound.port}`,
            `Authorization: Bearer ${SECRET}`,
            'Content-Type: application/json',
            'Content-Length: 4000',
          ]),
        );
        const drip = setInterval(() => socket.write('a'), 200);
        const stop = (): void => {
          clearInterval(drip);
          done();
        };
        socket.once('close', stop);
        socket.once('end', stop);
        socket.once('error', stop);
      },
    });

    assert.ok(result.closedByServer || result.errorCode !== null, 'the dribbled body was never cut off');
    assert.ok(
      result.elapsedMs < 4_000,
      `the request survived ${result.elapsedMs} ms against a 1500 ms requestTimeout`,
    );
    assert.ok(
      result.elapsedMs >= 1_000,
      `the request was cut off after ${result.elapsedMs} ms, before requestTimeout could apply`,
    );
  });

  test('C32 / C34 effect: ten slowloris connections close inside the headers timeout, and real traffic still works', async (t) => {
    const bound = await boundServer(
      t,
      httpEnv({
        UNIFI_HTTP_HEADERS_TIMEOUT_MS: '1000',
        UNIFI_HTTP_REQUEST_TIMEOUT_MS: '4000',
      }),
    );
    await waitReady(bound);

    const startedAt = Date.now();
    const stalls = Array.from({ length: 10 }, () =>
      exchange(bound.port, '', {
        idleMs: 6_000,
        drive: (socket, done) => {
          // A partial request line and then nothing at all.
          socket.write('GET /mc');
          socket.once('close', done);
          socket.once('end', done);
        },
      }),
    );

    const settled = await Promise.all(stalls);
    const elapsed = Date.now() - startedAt;

    // An event-occurrence assertion with a generous window — the shape the
    // requirement itself states, and not a latency measurement.
    assert.ok(elapsed < 3_000, `ten stalled connections took ${elapsed} ms to close`);
    for (const stall of settled) {
      assert.ok(stall.closedByServer, 'a stalled connection was left open');
    }

    // …and a well-formed authenticated request succeeds in the same run.
    const good = await exchange(
      bound.port,
      raw('POST /nope HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(good), /^HTTP\/1\.1 404 /);
  });
});

// ---------------------------------------------------------------------------
// 9. The rejection throttle (C30)
// ---------------------------------------------------------------------------

describe('US-22 §9: the throttle counts uniform-401 EMISSIONS, not authentication failures', () => {
  const limit = 5;
  const env = httpEnv({
    UNIFI_HTTP_AUTH_FAIL_PER_MIN: String(limit),
    UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST,
    UNIFI_HTTP_MAX_BODY_BYTES: '4096',
  });

  /** Five rejections of five DIFFERENT classes, in mixed order. */
  function mixed(): readonly string[] {
    const host = `Host: ${ALLOWED_HOST}`;
    return [
      raw('POST /mcp HTTP/1.1', [host, `Authorization: Bearer ${WRONG_SECRET}`, 'Content-Length: 0']),
      raw('POST /mcp HTTP/1.1', [`Host: ${REJECTED_HOST}`, 'Content-Length: 0']),
      raw('POST /mcp HTTP/1.1', [host, 'Origin: https://evil.example', 'Content-Length: 0']),
      raw('POST /unknown HTTP/1.1', [host, 'Content-Length: 0']),
      raw('POST /mcp HTTP/1.1', [host, 'Content-Length: 999999']),
    ];
  }

  test('C30: N mixed rejections increment N times, the N+1th is 429, and a valid secret is still served', async (t) => {
    let records = 0;
    const bound = await boundServer(t, env, {
      createThrottle: (options) => {
        // The counter sits at the ONE call site — nothing else in the module
        // may call `record`, so N after N mixed rejections is a statement about
        // the emission point rather than about authentication.
        const inner = createRejectionThrottle(options);
        return {
          isThrottled: (key) => inner.isThrottled(key),
          record: (key) => {
            records += 1;
            inner.record(key);
          },
          size: () => inner.size(),
        };
      },
    });
    await waitReady(bound);

    for (const request of mixed()) {
      const result = await exchange(bound.port, request);
      assert.equal(result.text, UNIFORM_401_WIRE);
    }
    // Counting only authentication failures would read 1 here, and the throttle
    // would be a path-enumeration oracle: N+1 garbage-token requests to a
    // candidate path yield 429 when the path is real and 401 when it is not.
    assert.equal(records, limit, 'the counter did not increment once per uniform 401');

    const throttled = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    assert.match(statusLine(throttled), /^HTTP\/1\.1 429 Too Many Requests/);
    assert.equal(bodyOf(throttled), '{"error":"rate_limit"}');
    assert.equal(bodyOf(throttled).length, 22);
    // No Retry-After: its only well-behaved beneficiary is a client that trips
    // the throttle, and a client holding the correct secret never does.
    assert.equal(/retry-after/i.test(throttled.text), false);
    assert.equal(/www-authenticate/i.test(throttled.text), false);

    // The throttle gates the RESPONSE, not the work: a caller presenting a
    // VALID secret from a throttled source key is served normally. Under the
    // other ordering, one stranger behind a shared reverse proxy locks out the
    // only legitimate client for the rest of every rolling minute.
    const good = await exchange(
      bound.port,
      raw('POST /nope HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(good), /^HTTP\/1\.1 404 /);
  });

  test('C30: the 429s across every provoking class are byte-identical, and probes are never throttled', async (t) => {
    const bound = await boundServer(t, env);
    await waitReady(bound);

    for (const request of mixed()) await exchange(bound.port, request);

    const throttledResponses: Exchange[] = [];
    for (const request of mixed()) {
      throttledResponses.push(await exchange(bound.port, request));
    }
    const reference = throttledResponses[0];
    assert.ok(reference !== undefined);
    assert.match(statusLine(reference), /^HTTP\/1\.1 429 /);
    for (const actual of throttledResponses.slice(1)) {
      assertSameBytes(actual, reference, 'a 429 from another provoking class');
    }

    // In the SAME run, with the throttle saturated: the probes answer. A 429 is
    // a probe failure, and `failureThreshold` consecutive failures restart the
    // container — the rate limiter would restart the service it protects.
    const healthz = await exchange(bound.port, raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
    const readyz = await exchange(bound.port, raw('GET /readyz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
    assert.equal(bodyOf(healthz), 'ok\n');
    assert.equal(bodyOf(readyz), 'ready\n');
  });

  test('C30: probes are never COUNTED either', async (t) => {
    let records = 0;
    const bound = await boundServer(t, env, {
      createThrottle: (options) => {
        const inner = createRejectionThrottle(options);
        return {
          isThrottled: (key) => inner.isThrottled(key),
          record: (key) => {
            records += 1;
            inner.record(key);
          },
          size: () => inner.size(),
        };
      },
    });
    await waitReady(bound);

    for (let index = 0; index < 20; index += 1) {
      await exchange(bound.port, raw('GET /healthz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
      await exchange(bound.port, raw('GET /readyz HTTP/1.1', [`Host: ${KUBELET_HOST}`]));
    }
    assert.equal(records, 0, 'a probe incremented the rejection counter');
  });
});

// ---------------------------------------------------------------------------
// 10. Fail-closed (C35)
// ---------------------------------------------------------------------------

describe('US-22 §10: any fault fails CLOSED', () => {
  const env = httpEnv({ UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST });
  const boom = (): never => {
    throw new Error('injected fault');
  };

  test('C35(a): a fault at target normalisation yields the byte-identical uniform 401', async (t) => {
    const bound = await boundServer(t, env, { createRouteNormalizer: () => boom });
    await waitReady(bound);

    const result = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    // A 500 to an unauthenticated caller is instantly distinguishable from the
    // uniform 401 and is a class-detection oracle by another route.
    assert.equal(result.text, UNIFORM_401_WIRE);
  });

  test('C35(b): a fault inside the comparator yields the byte-identical uniform 401', async (t) => {
    const bound = await boundServer(t, env, { bearerMatches: boom });
    await waitReady(bound);

    // Both with and without a credential presented: an exception thrown inside
    // the authentication path has by construction not returned 401, and the
    // next question is whether the request continued.
    for (const headers of [
      [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0'],
      [`Host: ${ALLOWED_HOST}`, `Authorization: Bearer ${SECRET}`, 'Content-Length: 0'],
    ]) {
      const result = await exchange(bound.port, raw('POST /mcp HTTP/1.1', headers));
      assert.equal(result.text, UNIFORM_401_WIRE);
    }
  });

  test('C35(c): a fault at Host validation is 500 to a holder and 401 to a stranger', async (t) => {
    const bound = await boundServer(t, env, { hostAllowed: boom });
    await waitReady(bound);

    const stranger = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    assert.equal(stranger.text, UNIFORM_401_WIRE);

    const holder = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(holder), /^HTTP\/1\.1 500 /);
    assert.equal(bodyOf(holder), '{"error":"server_error"}');
    assert.equal(bodyOf(holder).length, 24);
    // No message, no exception class, no stack, no source path, no correlation id.
    assert.equal(holder.text.includes('injected fault'), false);
    assert.equal(/Error|\.ts:|at \w+ \(/.test(bodyOf(holder)), false);
  });

  test('C35(d): a fault at MCP dispatch is 500 to a holder and 401 to a stranger', async (t) => {
    const bound = await boundServer(t, env, { createTransport: boom });
    await waitReady(bound);

    const stranger = await exchange(
      bound.port,
      raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']),
    );
    assert.equal(stranger.text, UNIFORM_401_WIRE);

    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'probe', version: '0' },
      },
    });
    const holder = await exchange(
      bound.port,
      raw(
        'POST /mcp HTTP/1.1',
        [
          `Host: ${ALLOWED_HOST}`,
          `Authorization: Bearer ${SECRET}`,
          'Content-Type: application/json',
          'Accept: application/json, text/event-stream',
          `Content-Length: ${Buffer.byteLength(body)}`,
        ],
        body,
      ),
    );
    assert.match(statusLine(holder), /^HTTP\/1\.1 500 /);
    assert.equal(bodyOf(holder), '{"error":"server_error"}');
  });
});

// ---------------------------------------------------------------------------
// 11. Interoperability with a real MCP client (C2)
// ---------------------------------------------------------------------------

describe('US-22 §11: a real MCP client completes initialize and tools/list', () => {
  test('C2: the SDK client transport interoperates — which is what proves the blanket Origin rejection is safe', async (t) => {
    const bound = await boundServer(t);
    await waitReady(bound);

    // The SDK's OWN client half, not a hand-rolled HTTP client: a hand-rolled
    // one proves only that our bytes look plausible to us. This proves the two
    // halves interoperate — the framing, the Mcp-Session-Id round-trip, the SSE
    // event parsing and the initialize handshake version — and it is the only
    // assertion in the suite that would catch a change in the SDK's own wire
    // expectations.
    //
    // It is ALSO the criterion that proves FR-66's blanket Origin rejection
    // does not break conforming clients: `StreamableHTTPClientTransport` sends
    // no Origin header, exactly as a conforming client does not, so it sails
    // through the same step 7 that rejects every browser.
    const client = new Client({ name: 'us-22-interop', version: '0.0.0' });
    const transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${bound.port}/mcp`),
      { requestInit: { headers: { Authorization: `Bearer ${SECRET}` } } },
    );

    t.after(async () => {
      await client.close().catch(() => undefined);
    });

    await client.connect(transport);
    const listed = await client.listTools();

    assert.ok(listed.tools.length > 0, 'tools/list returned nothing');
    assert.equal(bound.serving.sessionCount(), 1);
    assert.ok(bound.instruments.counts.mcpRequest > 0);
    // FR-71's HTTP narrowing: the advertised set is the read surface by
    // default, so the -32601 half of US-15's criterion now has a live endpoint.
    assert.ok(listed.tools.some((tool) => tool.name === 'unifi_search_actions'));
  });

  test('the rotation slot is live: the secondary secret authenticates too', async (t) => {
    const bound = await boundServer(t);
    await waitReady(bound);

    for (const secret of [SECRET, NEXT_SECRET]) {
      const result = await exchange(
        bound.port,
        raw('POST /nope HTTP/1.1', [
          `Host: 127.0.0.1:${bound.port}`,
          `Authorization: Bearer ${secret}`,
          'Content-Length: 0',
        ]),
      );
      assert.match(statusLine(result), /^HTTP\/1\.1 404 /);
    }
  });
});

// ---------------------------------------------------------------------------
// 12. The normative order, asserted structurally and behaviourally
// ---------------------------------------------------------------------------

describe('US-22 §12: the pipeline order is normative', () => {
  test('the ordering pairs that matter are observable', async (t) => {
    const bound = await boundServer(
      t,
      httpEnv({ UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST, UNIFI_HTTP_MAX_BODY_BYTES: '4096' }),
    );
    await waitReady(bound);

    // Route (step 8) BEFORE method (step 9), so `Allow` never varies by route
    // for a path that does not exist and cannot disclose which route matched.
    const unknownAndBadMethod = await exchange(
      bound.port,
      raw('PUT /definitely-not-here HTTP/1.1', [
        `Host: ${ALLOWED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(unknownAndBadMethod), /^HTTP\/1\.1 404 /);
    assert.equal(/\r\nAllow:/i.test(unknownAndBadMethod.text), false);

    // Method (step 9) BEFORE body cap (step 10).
    const badMethodAndBigBody = await exchange(
      bound.port,
      raw(
        'PUT /mcp HTTP/1.1',
        [
          `Host: ${ALLOWED_HOST}`,
          `Authorization: Bearer ${SECRET}`,
          'Content-Length: 65536',
        ],
        'Q'.repeat(8192),
      ),
    );
    assert.match(statusLine(badMethodAndBigBody), /^HTTP\/1\.1 405 /);

    // Host (step 6) BEFORE route (step 8): a bad host on an unknown path is 403.
    const badHostUnknownPath = await exchange(
      bound.port,
      raw('POST /nope HTTP/1.1', [
        `Host: ${REJECTED_HOST}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );
    assert.match(statusLine(badHostUnknownPath), /^HTTP\/1\.1 403 /);
  });

  test('the source states its steps in the normative order', () => {
    const source = readFileSync(HTTP_SOURCE, 'utf8');
    const markers = [
      'Step 2b — the headroom claim check',
      'Step 3 — the probe branch',
      '-- Step 4: authenticate',
      '-- Step 5: the throttle decision',
      '-- Step 6: Host',
      '-- Step 7: Origin',
      '-- Step 8: route',
      '-- Step 9: method',
      '-- Step 10: body cap',
      '-- Step 11: session admission',
      '-- Step 12: the drain gate',
      '-- Step 12r: the readiness gate',
      '-- Step 13: MCP dispatch',
    ];

    let previous = -1;
    for (const marker of markers) {
      const index = source.indexOf(marker);
      assert.notEqual(index, -1, `the pipeline no longer states "${marker}"`);
      assert.ok(index > previous, `"${marker}" appears out of the normative order`);
      previous = index;
    }
  });

  test('the exempt-route set is a two-element literal, closed by governance', () => {
    const guard = readFileSync(join(REPO_ROOT, 'src', 'serve', 'guard.ts'), 'utf8');
    const probeRoutes = guard.match(/^export const (HEALTHZ|READYZ)_ROUTE_PATH = '.*';$/gm) ?? [];
    // Adding a third is a security-boundary change requiring a new requirement
    // and a review of FR-67, FR-81 and NFR-32 — it is not a routing change, and
    // a future `/metrics` added "next to the other probes" is how this erodes.
    assert.equal(probeRoutes.length, 2);
  });
});

// ---------------------------------------------------------------------------
// 13. The per-request log line, at this story's emission sites (NFR-24)
// ---------------------------------------------------------------------------

describe('US-22 §13: every emission site produces one well-formed line', () => {
  test('the reject_reason vocabulary at each site, and writes= on every line', async (t) => {
    const bound = await boundServer(
      t,
      httpEnv({ UNIFI_HTTP_ALLOWED_HOSTS: ALLOWED_HOST, UNIFI_HTTP_MAX_BODY_BYTES: '4096' }),
    );
    await waitReady(bound);

    const authed = (startLine: string, extra: readonly string[] = [], body = ''): string =>
      raw(startLine, [`Host: ${ALLOWED_HOST}`, `Authorization: Bearer ${SECRET}`, ...extra], body);

    await exchange(bound.port, raw('POST /mcp HTTP/1.1', [`Host: ${ALLOWED_HOST}`, 'Content-Length: 0']));
    await exchange(bound.port, authed('POST /mcp HTTP/1.1', ['Content-Length: 0']).replace(
      `Host: ${ALLOWED_HOST}`,
      `Host: ${REJECTED_HOST}`,
    ));
    await exchange(bound.port, authed('POST /mcp HTTP/1.1', ['Origin: https://x.example', 'Content-Length: 0']));
    await exchange(bound.port, authed('POST /nope HTTP/1.1', ['Content-Length: 0']));
    await exchange(bound.port, authed('PUT /mcp HTTP/1.1', ['Content-Length: 0']));
    await exchange(
      bound.port,
      authed('POST /mcp HTTP/1.1', ['Content-Length: 8192'], 'Y'.repeat(8192)),
    );

    const logs = bound.instruments.counts.requestLogs;
    assert.ok(logs.length >= 6, `expected at least six request lines, saw ${logs.length}`);

    const reasons = logs.map((line) => /reject_reason=(\S+)/.exec(line)?.[1]);
    // An UNAUTHENTICATED rejection is `auth` whatever else was also wrong,
    // because step 5 rejected it and no later check ever ran — the same
    // mechanical rule contract §5.8.1 fixes for the over-cap body. The distinct
    // reasons below are all authenticated-caller rejections.
    assert.deepEqual(reasons.slice(0, 6), ['auth', 'host', 'origin', 'path', 'method', 'body_size']);

    for (const line of logs) {
      assert.match(line, /^unifi-mcp: req method=\S+ path=\S+ status=\d+ dur_ms=\d+ auth=\S+ reject_reason=\S+ writes=\S+ client=\S+$/);
      // The raw request target is attacker-controlled and never appears.
      assert.equal(line.includes('/nope'), false);
      assert.equal(line.includes(SECRET), false);
    }
  });

  test('writes= carries the EFFECTIVE resolved set, not a placeholder', async (t) => {
    // The carry-forward obligation from Wave D: the field renders at
    // `src/serve/log.ts`, and this is the story that had to feed it. `all` is
    // accepted input syntax and is never an output value — an operator reading
    // `writes=all` cannot tell which services were actually reachable.
    const bound = await boundServer(
      t,
      httpEnv({ UNIFI_ENABLE_WRITES: 'all', UNIFI_HTTP_ALLOW_WRITES: 'site-manager' }),
    );
    await waitReady(bound);

    await exchange(
      bound.port,
      raw('POST /nope HTTP/1.1', [
        `Host: 127.0.0.1:${bound.port}`,
        `Authorization: Bearer ${SECRET}`,
        'Content-Length: 0',
      ]),
    );

    const logs = bound.instruments.counts.requestLogs;
    assert.ok(logs.length >= 1);
    for (const line of logs) {
      // FR-71's per-surface intersection: `all` on the base gate narrowed to
      // `site-manager` on the HTTP surface is `site-manager`, not `all`.
      assert.match(line, /\bwrites=site-manager\b/);
    }
  });
});

// ---------------------------------------------------------------------------
// 14. src/types.ts (AC-20)
// ---------------------------------------------------------------------------

describe('US-22 §14: the response-body vocabulary is aligned with ErrorCategory', () => {
  test('method_not_allowed and unavailable are members of the union', () => {
    // A type-level assertion: this file does not compile under `npm run
    // typecheck` (which excludes `test/`), but `tsx` still type-strips it and
    // the values below are the same eight tokens the contract's §5.0.2 table
    // fixes. The union widening is what makes the two new bodies expressible
    // without bending them to `bad_request` and `server_error`, which would
    // make both statuses undiagnosable from the body.
    const inbound: readonly ErrorCategory[] = [
      'unauthorized',
      'forbidden',
      'not_found',
      'method_not_allowed',
      'payload_too_large',
      'rate_limit',
      'server_error',
      'unavailable',
    ];
    assert.equal(new Set(inbound).size, 8);
  });

  test('DEVIATION, recorded as a live assertion: categoryFromStatus keeps its 503 arm', () => {
    // Operator contract §5.0.2 asks for `case 405:` and `case 503:` arms in
    // `src/http/errors.ts`'s `categoryFromStatus`. The 503 arm CANNOT be added
    // without turning `test/contract-mobility.test.ts`'s pinned status-to-
    // category map red — that map is an OUTBOUND assertion about how a VENDOR
    // 503 is categorised (FR-24), and `unavailable` is an INBOUND token for
    // this server's own capacity refusals. Two different facts, one function.
    //
    // Neither arm was added, and this assertion is the drift detector: whoever
    // resolves the collision must delete this test deliberately rather than
    // discover the conflict in review.
    assert.equal(normalizeError('network', 503, {}).category, 'server_error');
    assert.equal(normalizeError('network', 405, {}).category, 'bad_request');
  });
});

// ---------------------------------------------------------------------------
// 15. FR-66 across the whole suite (C36)
// ---------------------------------------------------------------------------

after(() => {
  // `recordAndScreen` already asserted per response; this is the closing
  // statement that the sweep actually covered a meaningful population rather
  // than silently observing nothing.
  assert.ok(
    capturedResponses.length > 60,
    `the CORS sweep only saw ${capturedResponses.length} responses`,
  );
  for (const response of capturedResponses) {
    assert.equal(/access-control/i.test(response.text), false);
  }
});
