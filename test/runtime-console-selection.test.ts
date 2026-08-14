/**
 * Runtime, per-call console selection (FR-52a).
 *
 * A single server process may reach N consoles chosen per tool call rather
 * than pinned once at startup. This file asserts the four pieces that make
 * that true:
 *
 *   1. the server starts with ZERO consoles configured via environment
 *      variables — no fatal "no console is usable" refusal remains;
 *   2. a call supplying `consoleHost` + `consoleApiKey` reaches a LOCAL
 *      console that was never registered via UNIFI_LOCAL_HOST[_LABEL];
 *   3. a call supplying `consoleId` + `cloudApiKey` reaches CONNECTOR mode
 *      with no UNIFI_CONSOLE_ID configured on the process at all;
 *   4. neither inline key is logged anywhere, and omitting all four fields
 *      reproduces the pre-existing environment-variable-only resolution.
 *
 * The socket-level technique — a `node:net` listener that resets the
 * connection rather than speaking TLS — is the same one `client-lifecycle.
 * test.ts` uses (see its module comment): this repo has no PEM fixtures, so
 * a real TLS handshake cannot be completed in-process. What is observable
 * without one is exactly what matters here: whether the client attempted the
 * connection at all, and reached it with the right host — proving the
 * request got PAST credential/target resolution to the socket, rather than
 * being refused by a "no credential bound to this host" config error before
 * ever dialing out.
 */
import { strict as assert } from 'node:assert';
import { createServer, type Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import { loadConfig, validateConfig } from '../src/config.js';
import type { CredentialStore } from '../src/credentials.js';
import {
  CLOUD_API_KEY_ARG,
  CONSOLE_API_KEY_ARG,
  CONSOLE_HOST_ARG,
  CONSOLE_ID_ARG,
  UnifiClient,
} from '../src/http/client.js';
import { resolveTarget } from '../src/http/transport.js';
import { UnifiError, type Action, type ServiceId } from '../src/types.js';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

// ---------------------------------------------------------------------------
// 1. The server starts with zero consoles configured
// ---------------------------------------------------------------------------

describe('a server with no console configured via environment variables', () => {
  test('startup is no longer fatally refused for that reason alone', () => {
    const config = loadConfig({}, { repoRoot: REPO_ROOT });
    const validation = validateConfig(config, {});
    assert.equal(
      validation.errors.some((m) => m.includes('No UniFi API is usable')),
      false,
      'the removed "no console configured" refusal must be gone',
    );
    assert.equal(config.localConsoles.length, 0);
    assert.equal(config.consoleId, null);
    assert.equal(config.hasCloudApiKey, false);
  });

  test('an informational note explains that consoles may be supplied per call', () => {
    const config = loadConfig({}, { repoRoot: REPO_ROOT });
    const validation = validateConfig(config, {});
    assert.ok(
      validation.warnings.some((m) => m.includes('No console is pre-configured')),
      'no informational note was emitted for a zero-console startup',
    );
    // Non-fatal: it must not appear among the errors.
    assert.equal(
      validation.errors.some((m) => m.includes('No console is pre-configured')),
      false,
    );
  });

  test('other startup validation is unaffected — an unknown key still refuses', () => {
    const env = { UNIFI_TYPO_VARIABLE: 'x' };
    const config = loadConfig(env, { repoRoot: REPO_ROOT });
    const validation = validateConfig(config, env);
    assert.equal(validation.ok, false);
    assert.ok(validation.errors.some((m) => m.includes('UNIFI_TYPO_VARIABLE')));
  });
});

// ---------------------------------------------------------------------------
// 2 & 3. resolveTarget honours the per-call overrides, with no pre-registration
// ---------------------------------------------------------------------------

describe('resolveTarget with per-call overrides (src/http/transport.ts)', () => {
  test('a local host not in config.localConsoles resolves when passed as an override', () => {
    const config = loadConfig({ UNIFI_NETWORK_TRANSPORT: 'local' }, { repoRoot: REPO_ROOT });
    assert.equal(config.localConsoles.length, 0);
    const target = resolveTarget(config, 'network', '10.20.30.40');
    assert.equal(target.mode, 'local');
    assert.equal(target.host, '10.20.30.40');
    assert.ok(target.baseUrl.startsWith('https://10.20.30.40/'));
  });

  test('a connector consoleId override reaches connector mode with no UNIFI_CONSOLE_ID set', () => {
    const config = loadConfig(
      { UNIFI_NETWORK_TRANSPORT: 'connector' },
      { repoRoot: REPO_ROOT },
    );
    assert.equal(config.consoleId, null);
    const target = resolveTarget(config, 'network', undefined, 'console-xyz');
    assert.equal(target.mode, 'connector');
    assert.equal(target.consoleId, 'console-xyz');
    assert.ok(target.baseUrl.includes('/v1/connector/consoles/console-xyz/'));
  });

  test('the override takes precedence over a configured default', () => {
    const config = loadConfig(
      {
        UNIFI_NETWORK_TRANSPORT: 'connector',
        UNIFI_CONSOLE_ID: 'configured-console',
        UNIFI_API_KEY: 'k',
      },
      { repoRoot: REPO_ROOT },
    );
    const target = resolveTarget(config, 'network', undefined, 'override-console');
    assert.equal(target.consoleId, 'override-console');
  });
});

// ---------------------------------------------------------------------------
// 4. UnifiClient.request: inline keys reach the socket, bypass CredentialStore,
//    and are never logged
// ---------------------------------------------------------------------------

interface FakeConsole {
  readonly port: number;
  connections: number;
  close(): Promise<void>;
}

/** Accepts, then resets — the client sees a network error, never a TLS answer. */
async function startResettingConsole(): Promise<FakeConsole> {
  const live = new Set<Socket>();
  let connections = 0;
  const server = createServer((socket) => {
    connections += 1;
    live.add(socket);
    socket.on('close', () => live.delete(socket));
    socket.on('error', () => undefined);
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') {
    return assert.fail('expected the listener to report an AddressInfo');
  }
  return {
    port: address.port,
    get connections(): number {
      return connections;
    },
    close(): Promise<void> {
      for (const socket of live) socket.destroy();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/**
 * A `CredentialStore` stand-in that FAILS the test if it is ever consulted.
 * Inline keys must be used directly and must never reach the store.
 */
function neverCalledCredentials(): CredentialStore {
  return {
    resolveFor(): Promise<string> {
      assert.fail(
        'CredentialStore.resolveFor was called even though an inline key was supplied',
      );
    },
  } as unknown as CredentialStore;
}

function writeAction(service: ServiceId = 'network'): Action {
  return {
    id: `${service}.test.write`,
    service,
    method: 'POST',
    actionClass: 'write',
    path: '/v1/sites',
    summary: '',
    description: '',
    tags: [],
    parameters: [],
    earlyAccess: false,
    requiredScopes: [],
    searchText: '',
  };
}

describe('UnifiClient.request honours inline console-selection arguments', () => {
  test('consoleHost + consoleApiKey reach a local console absent from config.localConsoles', async () => {
    const console_ = await startResettingConsole();
    try {
      const config = loadConfig(
        { UNIFI_NETWORK_TRANSPORT: 'local', UNIFI_ENABLE_WRITES: 'network' },
        { repoRoot: REPO_ROOT },
      );
      assert.equal(config.localConsoles.length, 0, 'precondition: no console pre-registered');

      const client = new UnifiClient(config, neverCalledCredentials(), { warn: () => {} });
      try {
        const outcome = await client
          .request(writeAction(), {
            [CONSOLE_HOST_ARG]: `127.0.0.1:${console_.port}`,
            [CONSOLE_API_KEY_ARG]: 'inline-local-secret',
          })
          .then(
            () => null,
            (e: unknown) => e,
          );
        // The connection attempt happened — proof the request got past target
        // and credential resolution to the socket, unblocked by the missing
        // pre-registration. A config-category refusal here would mean the
        // override never worked; anything else (network reset) is expected.
        assert.ok(console_.connections >= 1, 'no connection attempt reached the fake console');
        if (outcome instanceof UnifiError) {
          assert.notEqual(
            outcome.normalized.category,
            'config',
            `unexpected config refusal: ${outcome.normalized.message}`,
          );
        }
      } finally {
        await client.close();
      }
    } finally {
      await console_.close();
    }
  });

  test('consoleId + cloudApiKey reach connector mode with no UNIFI_CONSOLE_ID configured', async () => {
    // Connector mode always dials api.ui.com, which this test cannot reach or
    // fake a TLS handshake for — so what is asserted here is the part that is
    // reachable in-process: resolution succeeds (no `config` refusal for a
    // missing console id) all the way up to the point a real socket would be
    // opened, and the inline cloud key is what let it get there.
    const config = loadConfig(
      { UNIFI_NETWORK_TRANSPORT: 'connector', UNIFI_ENABLE_WRITES: 'network' },
      { repoRoot: REPO_ROOT },
    );
    assert.equal(config.consoleId, null, 'precondition: no console id configured');
    assert.equal(config.hasCloudApiKey, false, 'precondition: no cloud key configured');

    const client = new UnifiClient(config, neverCalledCredentials(), { warn: () => {} });
    try {
      const outcome = await client
        .request(writeAction(), {
          [CONSOLE_ID_ARG]: 'inline-console-id',
          [CLOUD_API_KEY_ARG]: 'inline-cloud-secret',
        })
        .then(
          () => null,
          (e: unknown) => e,
        );
      // api.ui.com is unreachable/unmockable here, so the outcome is a network
      // or timeout error — never the `config` refusal a missing console id or
      // missing cloud key would have produced.
      if (outcome instanceof UnifiError) {
        assert.notEqual(
          outcome.normalized.category,
          'config',
          `unexpected config refusal: ${outcome.normalized.message}`,
        );
      }
    } finally {
      await client.close();
    }
  }, { timeout: 30_000 });

  test('inline keys never reach a warn()/log line', async () => {
    const console_ = await startResettingConsole();
    try {
      const config = loadConfig(
        { UNIFI_NETWORK_TRANSPORT: 'local', UNIFI_ENABLE_WRITES: 'network' },
        { repoRoot: REPO_ROOT },
      );
      const lines: string[] = [];
      const secret = 'must-never-be-logged-sentinel';
      const client = new UnifiClient(config, neverCalledCredentials(), {
        warn: (line) => lines.push(line),
      });
      try {
        await client
          .request(writeAction(), {
            [CONSOLE_HOST_ARG]: `127.0.0.1:${console_.port}`,
            [CONSOLE_API_KEY_ARG]: secret,
          })
          .catch(() => undefined);
      } finally {
        await client.close();
      }
      assert.equal(
        lines.some((line) => line.includes(secret)),
        false,
        'an inline console API key leaked into a warn() line',
      );
    } finally {
      await console_.close();
    }
  });

  test('omitting all four fields falls back to CredentialStore exactly as before', async () => {
    const console_ = await startResettingConsole();
    try {
      const config = loadConfig(
        {
          UNIFI_NETWORK_TRANSPORT: 'local',
          UNIFI_LOCAL_HOST: `127.0.0.1:${console_.port}`,
          UNIFI_LOCAL_API_KEY: 'env-key',
          UNIFI_ENABLE_WRITES: 'network',
        },
        { repoRoot: REPO_ROOT },
      );
      let resolveForCalls = 0;
      const store = {
        resolveFor(): Promise<string> {
          resolveForCalls += 1;
          return Promise.resolve('env-key');
        },
      } as unknown as CredentialStore;

      const client = new UnifiClient(config, store, { warn: () => {} });
      try {
        await client.request(writeAction(), {}).catch(() => undefined);
      } finally {
        await client.close();
      }
      assert.equal(
        resolveForCalls,
        1,
        'existing env-var-based credential resolution must still run when no inline key is given',
      );
    } finally {
      await console_.close();
    }
  });
});
