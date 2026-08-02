/**
 * The serving configuration: defaults, grammars, the five startup refusals, the
 * suppression ladder and the write second gate (US-14, US-15; FR-67, FR-73,
 * FR-81, NFR-23, IG-1).
 *
 * ## WHAT THIS FILE PROVES, and why each half cannot pass vacuously
 *
 * 1. THE STDIO DEFAULT SURVIVES. The first suite asserts it directly, against
 *    an empty environment and against a fully credentialed one, because every
 *    other assertion here is written against a config object that a regression
 *    in transport selection would silently reshape. An implementation that made
 *    `http` the default would pass most of the refusal tests below — they set
 *    the transport explicitly — and break every deployment in existence.
 *
 * 2. THE REFUSALS FIRE, AND ARE SCOPED. Every refusal is asserted twice: once
 *    as a full, byte-for-byte string equality under `UNIFI_MCP_TRANSPORT=http`,
 *    and once as an ABSENCE with the transport unset. The second half is IG-1:
 *    a leftover `UNIFI_HTTP_BIND=0.0.0.0` in a shell or a shared Compose file
 *    must not break a stdio start. A test that only asserted the positive
 *    direction would pass an implementation that refuses on every transport,
 *    which is a self-inflicted outage for operators who never enabled HTTP.
 *
 * 3. THE SUPPRESSION LADDER IS ASSERTED BY ABSENCE. Each cascade case asserts
 *    that the T1/T2 message IS present and the T3 message is NOT. The negative
 *    half is the only thing that fails an implementation which reports
 *    everything unconditionally — and each cascade is paired with a control
 *    environment showing the suppressed refusal DOES fire when the value
 *    parses, so the absence is never absence-by-impossibility.
 *
 * 4. THE TWO DUPLICATED ALGORITHMS ARE PINNED TO THEIR SIBLINGS. `src/config.ts`
 *    may not import from `src/serve/`, so it carries its own copy of FR-67's
 *    path canonicalisation and of §2.5.1's auth-mode grammar. This file imports
 *    BOTH sides and compares them: every path that passes validation is fed
 *    back through `createRouteNormalizer` and must resolve to the `mcp` route
 *    while `/healthz` and `/readyz` still resolve to their own, and every
 *    refused auth token must produce a refusal byte-identical to the one
 *    `resolveBearerSlots` composes. A divergence in either fails the build.
 *
 * 5. THE WRITE SECOND GATE REACHES BOTH ENFORCEMENT POINTS WITH NO THIRD CHECK.
 *    `config.writesEnabled` is narrowed once, in `loadConfig`. This file proves
 *    the narrowing by calling the production `advertisedTools` — the same
 *    function `tools/list` is built from — and by asserting on the resolved set
 *    that `src/http/client.ts` reads. Neither file is imported for mutation and
 *    neither was edited.
 *
 * Every case builds its own env object literal. Nothing here reads or mutates
 * `process.env`, so a variable exported on a developer's machine can neither
 * enable a service nor mask a failure. `validateConfig` is always handed the
 * SAME `ServerConfig` instance `loadConfig` returned — the diagnostics are held
 * in WeakMaps keyed on config identity, and a fresh object yields nothing.
 *
 * The order of reported messages is not fixed by any requirement, so nothing
 * here asserts by line index; every assertion is containment or set equality.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import {
  SCALAR_ENV_KEYS,
  SERVING_ENV_KEYS,
  loadConfig,
  redactedSummary,
  validateConfig,
  type ConfigValidation,
  type ServerConfig,
  type ServingConfig,
} from '../src/config.js';
import { resolveBearerSlots } from '../src/serve/auth.js';
import { createRouteNormalizer } from '../src/serve/guard.js';
import { EXECUTE_WRITE_ACTION, advertisedTools } from '../src/tools/definitions.js';
import { SERVICE_IDS } from '../src/types.js';
import { ANY_SENTINEL, plantedEnv, scanForSentinels } from './fixtures/sentinel.js';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Long enough to clear FR-81's 32-character floor; not sentinel-shaped. */
const HTTP_SECRET = 'inbound-shared-secret-for-tests-0123456789';

interface Outcome {
  readonly config: ServerConfig;
  readonly validation: ConfigValidation;
}

function load(env: NodeJS.ProcessEnv): ServerConfig {
  return loadConfig(env, { repoRoot: REPO_ROOT });
}

/** The pairing `validateConfig` requires: the very instance `loadConfig` made. */
function outcome(env: NodeJS.ProcessEnv): Outcome {
  const config = load(env);
  return { config, validation: validateConfig(config, env) };
}

/**
 * The production wiring: `resolveBearerSlots` first, its secret-free descriptor
 * into `loadConfig` second. Used wherever a case depends on a *_FILE or
 * short-secret refusal, which only `src/serve/auth.ts` can compose.
 */
function outcomeWithResolvedAuth(env: NodeJS.ProcessEnv): Outcome {
  const config = loadConfig(env, {
    repoRoot: REPO_ROOT,
    auth: resolveBearerSlots(env).descriptor,
  });
  return { config, validation: validateConfig(config, env) };
}

/** A credentialed HTTP environment that is otherwise valid. */
function httpEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return plantedEnv({
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_TOKEN: HTTP_SECRET,
    ...overrides,
  });
}

/** The same environment with the transport unset — i.e. a stdio start. */
function stdioEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  const env = httpEnv(overrides);
  delete env['UNIFI_MCP_TRANSPORT'];
  return env;
}

function includesMessage(validation: ConfigValidation, needle: string): boolean {
  return validation.errors.some((message) => message.includes(needle));
}

// ---------------------------------------------------------------------------
// The exact strings. Asserted whole, at least once each.
// ---------------------------------------------------------------------------

const REFUSAL_A =
  'UNIFI_MCP_TRANSPORT=http requires an inbound shared secret: set UNIFI_HTTP_TOKEN (or ' +
  'UNIFI_HTTP_TOKEN_FILE) to a string of at least 32 characters. This is a secret you invent ' +
  'for MCP clients to present — it is not your UniFi API key. UNIFI_HTTP_AUTH=none disables ' +
  'inbound authentication entirely and is accepted only when UNIFI_HTTP_BIND is a loopback ' +
  'address.';

const REFUSAL_B =
  'UNIFI_HTTP_BIND=0.0.0.0 is not a loopback address and UNIFI_HTTP_ALLOWED_HOSTS is empty: ' +
  'set UNIFI_HTTP_ALLOWED_HOSTS to the comma-separated host names clients will use, or set ' +
  'UNIFI_HTTP_BIND=127.0.0.1. Host allow-listing is a DNS-rebinding control that protects ' +
  'browsers, not an access control — also restrict who can reach this port with a firewall or ' +
  'a NetworkPolicy.';

const REFUSAL_C_TAIL =
  ' but UNIFI_ENABLE_WRITES is empty, so the effective HTTP write set would be empty and no ' +
  'write action could ever run. Set UNIFI_ENABLE_WRITES to the same services, or set ' +
  'UNIFI_HTTP_ALLOW_WRITES=none. Writes over HTTP need both gates; the effective set is the ' +
  'intersection.';
const REFUSAL_C_LIST = `UNIFI_HTTP_ALLOW_WRITES names protect${REFUSAL_C_TAIL}`;
const REFUSAL_C_ALL = `UNIFI_HTTP_ALLOW_WRITES is \`all\`${REFUSAL_C_TAIL}`;

const REFUSAL_D =
  'UNIFI_HTTP_PATH=/healthz normalises onto a reserved probe path. `/healthz` and `/readyz` ' +
  'are unauthenticated and exempt from Host validation, so serving MCP on either would expose ' +
  'the whole tool surface to anyone who can reach this port. Set UNIFI_HTTP_PATH to any other ' +
  'absolute path; the default is /mcp.';

const REFUSAL_E =
  'UNIFI_HTTP_AUTH=none is permitted only on a loopback bind, and UNIFI_HTTP_BIND=0.0.0.0 is ' +
  'not one: this configuration would serve your UniFi estate to anyone who can reach this ' +
  'port. Set UNIFI_HTTP_BIND=127.0.0.1, or set UNIFI_HTTP_AUTH=bearer and supply ' +
  'UNIFI_HTTP_TOKEN.';

/** One distinctive clause per refusal, for the absence assertions. */
const MARK_A = 'it is not your UniFi API key';
const MARK_B = 'is not a loopback address and UNIFI_HTTP_ALLOWED_HOSTS is empty';
const MARK_C = 'the effective set is the intersection';
const MARK_D = 'normalises onto a reserved probe path';
const MARK_E = 'is permitted only on a loopback bind';

const BAD_PORT_MESSAGE =
  'UNIFI_HTTP_PORT="70000" is not a port. Set it to an integer in 0 … 65535; 0 binds an ' +
  'OS-assigned port.';
const BAD_BIND_MESSAGE =
  'UNIFI_HTTP_BIND="localhost:8787" is not an IP address. Set it to an IPv4 or IPv6 literal, ' +
  'for example 127.0.0.1, 0.0.0.0 or ::.';
const BAD_PATH_MESSAGE =
  'UNIFI_HTTP_PATH="mcp" is not an absolute path. Set it to a path beginning with `/`; the ' +
  'default is /mcp.';
const BAD_AUTH_MESSAGE =
  'UNIFI_HTTP_AUTH="basic" must be `bearer` or `none`. `bearer` requires callers to present ' +
  'UNIFI_HTTP_TOKEN; `none` disables inbound authentication entirely and is accepted only on ' +
  'a loopback UNIFI_HTTP_BIND.';
const BAD_TRANSPORT_MESSAGE =
  'UNIFI_MCP_TRANSPORT="local" must be `stdio` or `http`. (`local` and `connector` are values ' +
  'for UNIFI_NETWORK_TRANSPORT and UNIFI_PROTECT_TRANSPORT, which control how this server ' +
  'reaches your console — a different setting.)';
const BAD_ALLOW_WRITES_MESSAGE =
  'UNIFI_HTTP_ALLOW_WRITES lists unknown service "true"; valid values are site-manager, ' +
  'network, protect, mobility, `all`, or `none`.';

const NARROWING_WARNING =
  'WARNING WRITES ARE DISABLED ON THIS TRANSPORT. UNIFI_ENABLE_WRITES permits protect, but ' +
  'UNIFI_HTTP_ALLOW_WRITES is `none`, so the effective HTTP write set is empty: ' +
  'unifi_execute_write_action is absent from tools/list and every write action will be ' +
  'refused. If that is intended, this line is your confirmation. If it is not, widen ' +
  'UNIFI_HTTP_ALLOW_WRITES and restart.';
const EFFECTIVE_WARNING =
  'WARNING WRITES ENABLED OVER HTTP for protect on 127.0.0.1:8787 — any caller presenting the ' +
  'shared secret can change your UniFi estate. Set UNIFI_HTTP_ALLOW_WRITES=none to disable ' +
  'writes on this transport.';

// ===========================================================================
// 1. THE STDIO DEFAULT REGRESSION — first in the file, on purpose
// ===========================================================================

describe('THE STDIO DEFAULT REGRESSION — UNIFI_MCP_TRANSPORT unset means stdio', () => {
  test('H-SC-1: an empty environment serves over stdio and binds no listener', () => {
    const config = load({});
    assert.equal(
      config.serving.transport,
      'stdio',
      'the default transport changed. Every existing deployment starts with no ' +
        'UNIFI_MCP_TRANSPORT set; an http default would open a port on all of them.',
    );
    assert.equal(config.activeSurface, 'stdio');
  });

  test('H-SC-1: a fully credentialed environment still serves over stdio', () => {
    const config = load(plantedEnv());
    assert.equal(config.serving.transport, 'stdio');
    assert.equal(config.activeSurface, 'stdio');
    assert.equal(config.writesEnabled, config.writesEnabledBySurface.stdio);
  });

  test('H-SC-1: an explicit UNIFI_MCP_TRANSPORT=http is the only way to http', () => {
    assert.equal(load(httpEnv()).serving.transport, 'http');
    assert.equal(load(httpEnv()).activeSurface, 'http');
  });

  test('H-SC-1: an unrecognised transport token resolves to stdio and refuses', () => {
    const { config, validation } = outcome(plantedEnv({ UNIFI_MCP_TRANSPORT: 'local' }));
    assert.equal(config.serving.transport, 'stdio');
    assert.deepEqual([...config.serving.unresolved], ['transport']);
    assert.ok(validation.errors.includes(BAD_TRANSPORT_MESSAGE));
    assert.equal(validation.ok, false);
  });
});

// ===========================================================================
// 2. Every §5.15.1 default
// ===========================================================================

const DEFAULTS: readonly (readonly [string, keyof ServingConfig, unknown])[] = [
  ['UNIFI_MCP_TRANSPORT', 'transport', 'stdio'],
  ['UNIFI_HTTP_BIND', 'bind', '127.0.0.1'],
  ['UNIFI_HTTP_BIND', 'bindAddress', '127.0.0.1'],
  ['UNIFI_HTTP_PORT', 'port', 8787],
  ['UNIFI_HTTP_PATH', 'path', '/mcp'],
  ['UNIFI_HTTP_MAX_SESSIONS', 'maxSessions', 32],
  ['UNIFI_HTTP_SESSION_IDLE_TTL_MS', 'sessionIdleTtlMs', 300_000],
  ['UNIFI_HTTP_MAX_CONNECTIONS', 'maxConnections', 64],
  ['UNIFI_HTTP_MAX_BODY_BYTES', 'maxBodyBytes', 1_048_576],
  ['UNIFI_HTTP_MAX_HEADER_BYTES', 'maxHeaderBytes', 16_384],
  ['UNIFI_HTTP_HEADERS_TIMEOUT_MS', 'headersTimeoutMs', 10_000],
  ['UNIFI_HTTP_REQUEST_TIMEOUT_MS', 'requestTimeoutMs', 30_000],
  ['UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS', 'keepAliveTimeoutMs', 5_000],
  ['UNIFI_HTTP_SSE_KEEPALIVE_MS', 'sseKeepaliveMs', 15_000],
  ['UNIFI_HTTP_SHUTDOWN_DEADLINE_MS', 'shutdownDeadlineMs', 35_000],
  ['UNIFI_HTTP_AUTH_FAIL_PER_MIN', 'authFailPerMin', 20],
];

describe('§5.15.1 defaults resolve with the variable unset', () => {
  const config = load({});

  for (const [envKey, field, expected] of DEFAULTS) {
    test(`H-SC-2: ${envKey} unset ⇒ serving.${String(field)} === ${String(expected)}`, () => {
      assert.deepEqual(config.serving[field], expected);
    });
  }

  test('H-SC-2: the non-scalar defaults', () => {
    assert.deepEqual(config.serving.allowedHosts, []);
    assert.deepEqual(config.serving.authMode, { kind: 'bearer' });
    assert.deepEqual([...config.serving.unresolved], []);
    assert.equal(config.serving.auth.mode, 'bearer');
    assert.equal(config.serving.auth.slotCount, 0);
    assert.deepEqual([...config.writesEnabled], []);
    assert.deepEqual([...config.writesEnabledBySurface.stdio], []);
    assert.deepEqual([...config.writesEnabledBySurface.http], []);
  });

  test('H-SC-2: the table covers every scalar §5.15.1 knob it claims to', () => {
    // Anti-vacuity: if a field is dropped from the table, this notices.
    assert.equal(DEFAULTS.length, 16);
  });
});

// ===========================================================================
// 3. The environment allow-list, in both directions
// ===========================================================================

/** A value for each serving variable that is valid on its own. */
const SAMPLE_VALUES: Readonly<Record<string, string>> = {
  UNIFI_MCP_TRANSPORT: 'stdio',
  UNIFI_HTTP_BIND: '127.0.0.1',
  UNIFI_HTTP_PORT: '8787',
  UNIFI_HTTP_PATH: '/mcp',
  UNIFI_HTTP_AUTH: 'bearer',
  UNIFI_HTTP_TOKEN: HTTP_SECRET,
  UNIFI_HTTP_TOKEN_FILE: '/run/secrets/unifi-http-token',
  UNIFI_HTTP_TOKEN_NEXT: HTTP_SECRET,
  UNIFI_HTTP_TOKEN_NEXT_FILE: '/run/secrets/unifi-http-token-next',
  UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.com',
  UNIFI_HTTP_ALLOW_WRITES: 'none',
  UNIFI_HTTP_MAX_SESSIONS: '8',
  UNIFI_HTTP_SESSION_IDLE_TTL_MS: '60000',
  UNIFI_HTTP_MAX_CONNECTIONS: '16',
  UNIFI_HTTP_MAX_BODY_BYTES: '65536',
  UNIFI_HTTP_MAX_HEADER_BYTES: '8192',
  UNIFI_HTTP_HEADERS_TIMEOUT_MS: '5000',
  UNIFI_HTTP_REQUEST_TIMEOUT_MS: '15000',
  UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: '2500',
  UNIFI_HTTP_SSE_KEEPALIVE_MS: '10000',
  UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: '20000',
  UNIFI_HTTP_AUTH_FAIL_PER_MIN: '10',
};

const CONFIG_SOURCE = readFileSync(new URL('../src/config.ts', import.meta.url), 'utf8');
const SERVING_NAME_PATTERN = /UNIFI_(?:HTTP|MCP)_[A-Z0-9_]+/g;

/** Names referenced by the source that a candidate registry does not cover. */
function unregistered(names: Iterable<string>, registry: readonly string[]): string[] {
  return [...new Set(names)].filter((name) => !registry.includes(name)).sort();
}

describe('the environment allow-list is registered in the same change as the reader', () => {
  for (const key of SERVING_ENV_KEYS) {
    test(`H-SC-3: ${key} set alone is a recognised key`, () => {
      const value = SAMPLE_VALUES[key];
      assert.ok(value !== undefined, `SAMPLE_VALUES is missing a value for ${key}`);
      const { validation } = outcome(plantedEnv({ [key]: value }));

      assert.deepEqual(
        validation.unknownEnvKeys,
        [],
        `${key} is documented in §5.15.1 but not registered, so validateConfig fatals on it — ` +
          `the server refuses to start for exactly the operators who followed the docs.`,
      );
      assert.equal(includesMessage(validation, key), false);
      assert.equal(validation.ok, true);
    });
  }

  test('H-SC-3: every serving variable the source names is registered', () => {
    const referenced = CONFIG_SOURCE.match(SERVING_NAME_PATTERN) ?? [];
    assert.ok(
      referenced.length > 0,
      'the source scan matched nothing, so this assertion proves nothing about the registry',
    );
    assert.deepEqual(
      unregistered(referenced, SERVING_ENV_KEYS),
      [],
      'src/config.ts names a UNIFI_HTTP_*/UNIFI_MCP_* variable that SERVING_ENV_KEYS does not ' +
        'register. Setting it would trip the unknown-key fatal.',
    );
  });

  test('H-SC-3: the same comparison reports a discrepancy against a doctored list', () => {
    // Proves the check above can fail. Without this, an empty `referenced` or a
    // broken comparison would read as a clean bill of health.
    const referenced = CONFIG_SOURCE.match(SERVING_NAME_PATTERN) ?? [];
    const doctored = SERVING_ENV_KEYS.filter((key) => key !== 'UNIFI_HTTP_BIND');
    assert.deepEqual(unregistered(referenced, doctored), ['UNIFI_HTTP_BIND']);
  });

  test('H-SC-3: SERVING_ENV_KEYS is spread into the recognised scalar set', () => {
    assert.deepEqual(unregistered(SERVING_ENV_KEYS, SCALAR_ENV_KEYS), []);
    assert.equal(SERVING_ENV_KEYS.length, 22);
  });
});

// ===========================================================================
// 4. readPort — a separate helper, because readInt cannot express port 0
// ===========================================================================

describe('UNIFI_HTTP_PORT accepts 0 … 65535 (readPort, not readInt)', () => {
  test('H-SC-4: port 0 resolves to 0 and is not an error', () => {
    const { config, validation } = outcome(httpEnv({ UNIFI_HTTP_PORT: '0' }));
    assert.equal(config.serving.port, 0);
    assert.deepEqual([...config.serving.unresolved], []);
    assert.equal(validation.ok, true);
    assert.equal(includesMessage(validation, 'UNIFI_HTTP_PORT'), false);
  });

  test("H-SC-4: readInt's `n <= 0` guard is NOT the one in play for the port", () => {
    // The same literal `0` through the shared integer reader still refuses, so
    // the acceptance above is specific to readPort and not a widened readInt.
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '0' }));
    assert.ok(
      validation.errors.includes('UNIFI_HTTP_MAX_SESSIONS="0" is not a positive integer.'),
      'readInt was widened to accept zero, which turns a mistyped timeout or pool size into a ' +
        'silently disabled limit',
    );
  });

  test('H-SC-4: 65535 is the ceiling and resolves', () => {
    assert.equal(load(httpEnv({ UNIFI_HTTP_PORT: '65535' })).serving.port, 65535);
  });

  for (const raw of ['65536', '-1', '70000', 'abc', '1.5']) {
    test(`H-SC-4: UNIFI_HTTP_PORT=${raw} is refused and falls back to 8787`, () => {
      const { config, validation } = outcome(httpEnv({ UNIFI_HTTP_PORT: raw }));
      assert.equal(config.serving.port, 8787);
      assert.ok(config.serving.unresolved.includes('port'));
      assert.equal(validation.ok, false);
      const expected =
        `UNIFI_HTTP_PORT="${raw}" is not a port. Set it to an integer in 0 … 65535; 0 binds an ` +
        `OS-assigned port.`;
      assert.ok(
        validation.errors.includes(expected),
        `expected the exact port refusal; got ${JSON.stringify(validation.errors)}`,
      );
    });
  }

  test('H-SC-4: the port refusal is exact for the documented example', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_PORT: '70000' }));
    assert.ok(validation.errors.includes(BAD_PORT_MESSAGE));
  });
});

// ===========================================================================
// 5. UNIFI_HTTP_BIND — IP literals only, and isLoopbackBind is the predicate
// ===========================================================================

describe('UNIFI_HTTP_BIND parses IP literals and refuses names', () => {
  for (const literal of ['127.0.0.1', '0.0.0.0', '::', '::1', '127.0.0.5']) {
    test(`H-SC-5: ${literal} parses`, () => {
      const config = load(httpEnv({ UNIFI_HTTP_BIND: literal }));
      assert.equal(config.serving.bind, literal);
      assert.equal(config.serving.bindAddress, literal);
      assert.equal(config.serving.unresolved.includes('bind'), false);
    });
  }

  for (const bad of ['localhost', 'localhost:8787', '1.2.3']) {
    test(`H-SC-5: ${bad} is refused — a name is not an address`, () => {
      const { config, validation } = outcome(httpEnv({ UNIFI_HTTP_BIND: bad }));
      assert.equal(config.serving.bindAddress, null);
      assert.equal(config.serving.bind, bad);
      assert.ok(config.serving.unresolved.includes('bind'));
      assert.equal(validation.ok, false);
      assert.ok(
        validation.errors.some((m) => m.startsWith(`UNIFI_HTTP_BIND="${bad}"`)),
        `expected a bind refusal naming ${bad}`,
      );
    });
  }

  test('H-SC-5: the bind refusal is exact for the documented example', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_BIND: 'localhost:8787' }));
    assert.ok(validation.errors.includes(BAD_BIND_MESSAGE));
  });

  test('H-SC-5: an explicitly empty bind falls back to the loopback default', () => {
    const config = load(httpEnv({ UNIFI_HTTP_BIND: '' }));
    assert.equal(config.serving.bind, '127.0.0.1');
    assert.equal(config.serving.bindAddress, '127.0.0.1');
    assert.equal(config.serving.unresolved.includes('bind'), false);
  });

  test('H-SC-5: isLoopbackBind is the predicate — 127.0.0.5 does not trip (b)', () => {
    // A naive `bind === '127.0.0.1'` check would refuse this, and RFC 1122
    // reserves the whole 127.0.0.0/8.
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_BIND: '127.0.0.5' }));
    assert.equal(includesMessage(validation, MARK_B), false);
    assert.equal(validation.ok, true);
  });

  test('H-SC-5: a routable bind with no allow-list DOES trip (b)', () => {
    // The control for the assertion above: the check is capable of firing.
    assert.ok(includesMessage(outcome(httpEnv({ UNIFI_HTTP_BIND: '0.0.0.0' })).validation, MARK_B));
  });
});

// ===========================================================================
// 6. UNIFI_HTTP_AUTH — the §2.5.1 table, and no fail-open arm
// ===========================================================================

const AUTH_RESOLVING: readonly (readonly [string, 'bearer' | 'none'])[] = [
  ['bearer', 'bearer'],
  ['Bearer', 'bearer'],
  [' bearer ', 'bearer'],
  ['BEARER', 'bearer'],
  ['none', 'none'],
  ['None', 'none'],
  ['NONE', 'none'],
  ['NoNe', 'none'],
  [' none ', 'none'],
  ['None ', 'none'],
];

const AUTH_REFUSED: readonly string[] = ['', 'basic', 'token', 'off', 'false', '0', 'bearer '.trim() + 'x'];

describe('UNIFI_HTTP_AUTH is fail-closed and has no arm reachable from a typo', () => {
  test('H-SC-6: unset resolves to bearer', () => {
    assert.deepEqual(load({}).serving.authMode, { kind: 'bearer' });
  });

  for (const [raw, expected] of AUTH_RESOLVING) {
    test(`H-SC-6: UNIFI_HTTP_AUTH=${JSON.stringify(raw)} resolves to ${expected}`, () => {
      const config = load(httpEnv({ UNIFI_HTTP_AUTH: raw }));
      assert.equal(config.serving.authMode.kind, expected);
      assert.equal(config.serving.unresolved.includes('auth'), false);

      // The sibling grammar in src/serve/auth.ts must classify it identically.
      assert.equal(
        resolveBearerSlots({ UNIFI_HTTP_AUTH: raw, UNIFI_HTTP_TOKEN: HTTP_SECRET }).descriptor.mode,
        expected,
        'src/config.ts and src/serve/auth.ts disagree about this value. They carry separate ' +
          'implementations of §2.5.1 because config.ts may not import from src/serve/, and a ' +
          'divergence here is one module opening a listener the other believes is authenticated.',
      );
    });
  }

  for (const raw of AUTH_REFUSED) {
    test(`H-SC-6: UNIFI_HTTP_AUTH=${JSON.stringify(raw)} is refused, never a fallback`, () => {
      const { config, validation } = outcome(httpEnv({ UNIFI_HTTP_AUTH: raw }));
      assert.equal(
        config.serving.authMode.kind,
        'bearer',
        'an unrecognised auth token resolved to `none`. That is the fail-open arm this union ' +
          'exists to make unrepresentable.',
      );
      assert.ok(config.serving.unresolved.includes('auth'));
      assert.equal(validation.ok, false);

      const composed = validation.errors.find((m) => m.startsWith('UNIFI_HTTP_AUTH='));
      assert.ok(composed !== undefined, 'no auth refusal was reported');

      // Byte-for-byte agreement with the sibling implementation.
      const sibling = resolveBearerSlots({ UNIFI_HTTP_AUTH: raw }).descriptor.problems;
      assert.deepEqual([composed], [...sibling]);
    });
  }

  test('H-SC-6: the auth refusal is exact for the documented shape', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_AUTH: 'basic' }));
    assert.ok(validation.errors.includes(BAD_AUTH_MESSAGE));
  });
});

// ===========================================================================
// 7 & 8. UNIFI_HTTP_PATH — absoluteness first, then normalisation, then (d)
// ===========================================================================

describe('UNIFI_HTTP_PATH: absoluteness is checked before normalisation', () => {
  for (const bad of ['mcp', './mcp', 'http://host/mcp', '']) {
    test(`H-SC-7: ${JSON.stringify(bad)} is refused with no silent promotion`, () => {
      const { config, validation } = outcome(httpEnv({ UNIFI_HTTP_PATH: bad }));
      assert.ok(config.serving.unresolved.includes('path'));
      assert.equal(config.serving.path, '/mcp');
      assert.equal(validation.ok, false);
      assert.ok(validation.errors.some((m) => m.startsWith('UNIFI_HTTP_PATH=')));
    });
  }

  test('H-SC-7: the path refusal is exact for the documented example', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_PATH: 'mcp' }));
    assert.ok(validation.errors.includes(BAD_PATH_MESSAGE));
  });

  const NORMALISATIONS: readonly (readonly [string, string])[] = [
    ['/mcp', '/mcp'],
    ['/mcp/', '/mcp'],
    ['//a//b', '/a/b'],
    ['/a/../b', '/b'],
    ['/../../b', '/b'],
    ['/mcp?x=1', '/mcp'],
    ['/%6dcp', '/mcp'],
    ['/x/./y', '/x/y'],
    ['/HEALTHZ', '/HEALTHZ'],
  ];

  for (const [raw, expected] of NORMALISATIONS) {
    test(`H-SC-7: ${raw} stores ${expected}`, () => {
      const config = load(httpEnv({ UNIFI_HTTP_PATH: raw }));
      assert.equal(config.serving.path, expected);
      assert.equal(config.serving.unresolved.includes('path'), false);
    });
  }

  test('H-SC-7: /HEALTHZ is legal — the probe comparison is case-SENSITIVE', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_PATH: '/HEALTHZ' }));
    assert.equal(includesMessage(validation, MARK_D), false);
    assert.equal(validation.ok, true);
  });
});

describe('refusal (d): the MCP path may not normalise onto a probe path (NFR-23)', () => {
  for (const raw of ['/healthz', '/readyz', '/healthz/', '//healthz', '/%68ealthz']) {
    test(`H-SC-8: UNIFI_HTTP_PATH=${raw} is refused`, () => {
      const { validation } = outcome(httpEnv({ UNIFI_HTTP_PATH: raw }));
      assert.equal(validation.ok, false);
      const message = validation.errors.find((m) => m.includes(MARK_D));
      assert.ok(
        message !== undefined,
        `${raw} normalises onto a probe path but was accepted. The probe routes are ` +
          `unauthenticated AND exempt from Host validation, so this serves the whole tool ` +
          `surface to anyone who can reach the port.`,
      );
      for (const needle of ['UNIFI_HTTP_PATH', '/healthz', '/readyz', 'normalises']) {
        assert.ok(message.includes(needle), `refusal (d) lost the substring ${needle}`);
      }
    });
  }

  test('H-SC-8: refusal (d) is exact for /healthz', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_PATH: '/healthz' }));
    assert.ok(validation.errors.includes(REFUSAL_D));
  });
});

// ===========================================================================
// 9. Agreement with src/serve/guard.ts — the build gate for the duplicate
// ===========================================================================

const ROUTE_CANDIDATES: readonly string[] = [
  '/mcp',
  '/mcp/',
  '//a//b',
  '/a/../b',
  '/mcp?x=1',
  '/%6dcp',
  '/x/./y',
  '/HEALTHZ',
  '/v1/mcp',
  '/deep/nested/endpoint',
  '/unifi-mcp',
  '/a/b/c/',
];

describe('the stored path agrees with createRouteNormalizer (FR-67, D-15)', () => {
  for (const raw of ROUTE_CANDIDATES) {
    test(`H-SC-9: ${raw} routes to mcp and steals no probe route`, () => {
      const { config, validation } = outcome(httpEnv({ UNIFI_HTTP_PATH: raw }));
      assert.equal(validation.ok, true, `${raw} did not pass validation: ${validation.errors}`);

      const route = createRouteNormalizer(config.serving.path);
      assert.equal(
        route(config.serving.path),
        'mcp',
        'the value config.ts stored does not route to the MCP endpoint under guard.ts. The two ' +
          'canonicalisers have diverged, and the server would advertise a path it never serves.',
      );
      assert.equal(route('/healthz'), 'healthz');
      assert.equal(route('/readyz'), 'readyz');
    });
  }

  test('H-SC-9: the agreement check is capable of failing', () => {
    // A path config would have refused resolves to a probe route under guard.ts,
    // which is exactly the collision refusal (d) exists to prevent.
    assert.equal(createRouteNormalizer('/healthz')('/healthz'), 'mcp');
  });
});

// ===========================================================================
// 10, 11, 12. The five refusals: exact, scoped, and jointly reportable
// ===========================================================================

const REFUSAL_CASES: readonly (readonly [string, NodeJS.ProcessEnv, string, string])[] = [
  [
    '(a) bearer with no secret',
    plantedEnv({ UNIFI_MCP_TRANSPORT: 'http' }),
    REFUSAL_A,
    MARK_A,
  ],
  [
    '(b) routable bind with an empty allow-list',
    httpEnv({ UNIFI_HTTP_BIND: '0.0.0.0' }),
    REFUSAL_B,
    MARK_B,
  ],
  [
    '(c) HTTP write gate named while the base gate is shut',
    httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
    REFUSAL_C_LIST,
    MARK_C,
  ],
  [
    '(c) the same with `all`',
    httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'all' }),
    REFUSAL_C_ALL,
    MARK_C,
  ],
  ['(d) MCP path on a probe path', httpEnv({ UNIFI_HTTP_PATH: '/healthz' }), REFUSAL_D, MARK_D],
  [
    '(e) auth=none off loopback',
    httpEnv({
      UNIFI_HTTP_AUTH: 'none',
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.com',
    }),
    REFUSAL_E,
    MARK_E,
  ],
];

describe('the five §2.3 startup refusals, verbatim', () => {
  for (const [label, env, expected] of REFUSAL_CASES) {
    test(`H-SC-10: ${label}`, () => {
      const { validation } = outcome(env);
      assert.equal(validation.ok, false);
      assert.ok(
        validation.errors.includes(expected),
        `the refusal text drifted.\nexpected: ${expected}\ngot: ${JSON.stringify(validation.errors, null, 2)}`,
      );
    });
  }

  test('H-SC-10: (a) names both remedies and disclaims the UniFi key', () => {
    for (const needle of ['UNIFI_HTTP_TOKEN', 'UNIFI_HTTP_AUTH', 'it is not your UniFi API key']) {
      assert.ok(REFUSAL_A.includes(needle));
    }
  });

  test('H-SC-10: (b) names both remedies', () => {
    assert.ok(REFUSAL_B.includes('UNIFI_HTTP_ALLOWED_HOSTS'));
    assert.ok(REFUSAL_B.includes('UNIFI_HTTP_BIND'));
  });

  test('H-SC-10: (c) names both gates in both renderings', () => {
    for (const message of [REFUSAL_C_LIST, REFUSAL_C_ALL]) {
      assert.ok(message.includes('UNIFI_HTTP_ALLOW_WRITES'));
      assert.ok(message.includes('UNIFI_ENABLE_WRITES'));
    }
  });

  test('H-SC-10: (d) names the variable and both probe paths', () => {
    for (const needle of ['UNIFI_HTTP_PATH', '/healthz', '/readyz']) {
      assert.ok(REFUSAL_D.includes(needle));
    }
  });

  test('H-SC-10: (e) names all three remedy variables', () => {
    for (const needle of ['UNIFI_HTTP_AUTH', 'UNIFI_HTTP_BIND', 'UNIFI_HTTP_TOKEN']) {
      assert.ok(REFUSAL_E.includes(needle));
    }
  });
});

describe('every serving refusal is scoped to an http start (IG-1)', () => {
  for (const [label, env, , mark] of REFUSAL_CASES) {
    test(`H-SC-11: ${label} is silent with UNIFI_MCP_TRANSPORT unset`, () => {
      const stdio: NodeJS.ProcessEnv = { ...env };
      delete stdio['UNIFI_MCP_TRANSPORT'];
      const { config, validation } = outcome(stdio);

      assert.equal(config.serving.transport, 'stdio');
      assert.equal(
        includesMessage(validation, mark),
        false,
        `a stdio start reported an HTTP-only refusal. A leftover UNIFI_HTTP_* variable in a ` +
          `shell or a shared Compose file would then break every stdio deployment.`,
      );
      assert.equal(
        validation.ok,
        true,
        `a stdio start failed validation: ${JSON.stringify(validation.errors)}`,
      );
    });
  }

  test('H-SC-11: none of the five marks appears on a plain stdio start', () => {
    const { validation } = outcome(
      stdioEnv({
        UNIFI_HTTP_BIND: '0.0.0.0',
        UNIFI_HTTP_AUTH: 'none',
        UNIFI_HTTP_PATH: '/healthz',
        UNIFI_HTTP_ALLOW_WRITES: 'protect',
      }),
    );
    for (const mark of [MARK_A, MARK_B, MARK_C, MARK_D, MARK_E]) {
      assert.equal(includesMessage(validation, mark), false);
    }
    assert.equal(validation.ok, true);
  });
});

describe('refusals that are deliberately NOT suppressed report together', () => {
  test('H-SC-12: (b) and (e) both fire — two true facts, two different remedies', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_AUTH: 'none', UNIFI_HTTP_BIND: '0.0.0.0' }));
    assert.ok(includesMessage(validation, MARK_B));
    assert.ok(includesMessage(validation, MARK_E));
  });

  test('H-SC-12: an unparseable port and refusal (d) both fire', () => {
    const { validation } = outcome(
      httpEnv({ UNIFI_HTTP_PORT: 'abc', UNIFI_HTTP_PATH: '/healthz' }),
    );
    assert.ok(includesMessage(validation, 'UNIFI_HTTP_PORT="abc"'));
    assert.ok(includesMessage(validation, MARK_D));
  });
});

// ===========================================================================
// 13. The suppression ladder, asserted BY ABSENCE
// ===========================================================================

interface Cascade {
  readonly label: string;
  /** The env whose T1/T2 failure should suppress a T3 refusal. */
  readonly env: NodeJS.ProcessEnv;
  /** A distinctive substring of the message that MUST be reported. */
  readonly reported: string;
  /** A distinctive substring of the refusal that MUST NOT be reported. */
  readonly suppressed: string;
  /** The same configuration with the T1/T2 failure repaired. */
  readonly control: NodeJS.ProcessEnv;
}

const CASCADES: readonly Cascade[] = [
  {
    label: 'cascade 1: an unparseable bind suppresses (b)',
    env: httpEnv({ UNIFI_HTTP_BIND: 'localhost' }),
    reported: 'UNIFI_HTTP_BIND="localhost"',
    suppressed: MARK_B,
    control: httpEnv({ UNIFI_HTTP_BIND: '0.0.0.0' }),
  },
  {
    label: 'cascade 2: an unparseable bind suppresses (e)',
    env: httpEnv({ UNIFI_HTTP_BIND: 'localhost', UNIFI_HTTP_AUTH: 'none' }),
    reported: 'UNIFI_HTTP_BIND="localhost"',
    suppressed: MARK_E,
    control: httpEnv({ UNIFI_HTTP_BIND: '0.0.0.0', UNIFI_HTTP_AUTH: 'none' }),
  },
  {
    label: 'an unresolved auth mode suppresses (a)',
    env: plantedEnv({ UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_AUTH: 'basic' }),
    reported: 'UNIFI_HTTP_AUTH="basic"',
    suppressed: MARK_A,
    control: plantedEnv({ UNIFI_MCP_TRANSPORT: 'http' }),
  },
  {
    label: 'an unresolved auth mode suppresses (e)',
    env: httpEnv({
      UNIFI_HTTP_AUTH: 'basic',
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.com',
    }),
    reported: 'UNIFI_HTTP_AUTH="basic"',
    suppressed: MARK_E,
    control: httpEnv({
      UNIFI_HTTP_AUTH: 'none',
      UNIFI_HTTP_BIND: '0.0.0.0',
      UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.com',
    }),
  },
  {
    label: 'an unresolved path suppresses (d)',
    env: httpEnv({ UNIFI_HTTP_PATH: 'healthz' }),
    reported: 'UNIFI_HTTP_PATH="healthz"',
    suppressed: MARK_D,
    control: httpEnv({ UNIFI_HTTP_PATH: '/healthz' }),
  },
  {
    label: 'cascade 6: an unknown write-gate token suppresses (c)',
    env: httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'protect,bogus' }),
    reported: 'UNIFI_HTTP_ALLOW_WRITES lists unknown service "bogus"',
    suppressed: MARK_C,
    control: httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
  },
];

describe('the §2.7 suppression ladder — no refusal derived from a meaningless value', () => {
  for (const cascade of CASCADES) {
    test(`H-SC-13: ${cascade.label}`, () => {
      const { validation } = outcome(cascade.env);
      assert.ok(
        includesMessage(validation, cascade.reported),
        `the higher-tier failure was not reported at all: ${JSON.stringify(validation.errors)}`,
      );
      assert.equal(
        includesMessage(validation, cascade.suppressed),
        false,
        'a lower-tier refusal was derived from a value that did not parse. The operator is ' +
          'handed advice about a configuration they never wrote, and the parse failure that ' +
          'actually needs fixing is buried under it.',
      );
    });

    test(`H-SC-13: ${cascade.label} — the control shows it can fire`, () => {
      const { validation } = outcome(cascade.control);
      assert.ok(
        includesMessage(validation, cascade.suppressed),
        'the suppressed refusal never fires even with the value repaired, so the absence ' +
          'assertion above proves nothing',
      );
    });
  }
});

describe('cascades 3-5: a configured-but-invalid secret is not "no secret"', () => {
  const SHORT_SECRET_CASES: readonly (readonly [string, NodeJS.ProcessEnv, string])[] = [
    [
      'a secret below the 32-character floor',
      plantedEnv({ UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: 'short' }),
      'shorter than the 32-character minimum',
    ],
    [
      'both UNIFI_HTTP_TOKEN and UNIFI_HTTP_TOKEN_FILE set',
      plantedEnv({
        UNIFI_MCP_TRANSPORT: 'http',
        UNIFI_HTTP_TOKEN: HTTP_SECRET,
        UNIFI_HTTP_TOKEN_FILE: '/definitely/not/a/real/path/unifi-token',
      }),
      'are both set and only one secret can be live',
    ],
    [
      'an unreadable *_FILE',
      plantedEnv({
        UNIFI_MCP_TRANSPORT: 'http',
        UNIFI_HTTP_TOKEN_FILE: '/definitely/not/a/real/path/unifi-token',
      }),
      'is not readable',
    ],
  ];

  for (const [label, env, reported] of SHORT_SECRET_CASES) {
    test(`H-SC-13: ${label} reports its own refusal and silences (a)`, () => {
      const { validation } = outcomeWithResolvedAuth(env);
      assert.ok(
        includesMessage(validation, reported),
        `expected the auth-layer refusal; got ${JSON.stringify(validation.errors)}`,
      );
      assert.equal(
        includesMessage(validation, MARK_A),
        false,
        'refusal (a) is an ABSENCE refusal. Reporting "no secret is set" alongside "the secret ' +
          'you set is too short" tells the operator to do something they already did.',
      );
      assert.equal(validation.ok, false);
    });
  }

  test('H-SC-13: with no secret at all, (a) IS the reported refusal', () => {
    const { validation } = outcomeWithResolvedAuth(plantedEnv({ UNIFI_MCP_TRANSPORT: 'http' }));
    assert.ok(includesMessage(validation, MARK_A));
  });

  test('H-SC-13: an invalid auth mode drops auth.problems, so it is reported once', () => {
    const { validation } = outcomeWithResolvedAuth(
      plantedEnv({ UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_AUTH: 'basic' }),
    );
    const occurrences = validation.errors.filter((m) => m === BAD_AUTH_MESSAGE);
    assert.equal(
      occurrences.length,
      1,
      'the auth-mode refusal was printed twice — once by config.ts and once forwarded from ' +
        'auth.ts, whose only problem when the mode is invalid IS the mode problem',
    );
  });

  test('H-SC-13: auth.warnings are forwarded on http and withheld on stdio', () => {
    // No permissions warning is reachable without a real file, so this asserts
    // the plumbing on the empty case: warnings never leak the mode problem.
    const httpOutcome = outcomeWithResolvedAuth(httpEnv());
    assert.equal(httpOutcome.validation.warnings.some((w) => w.includes('UNIFI_HTTP_TOKEN')), false);
    assert.equal(httpOutcome.validation.ok, true);
  });
});

// ===========================================================================
// 14 & 19. Corpus-wide invariants
// ===========================================================================

/**
 * Broken configurations, every one of them free of typo'd variable names so the
 * unknown-key fatal (which by construction names an UNRECOGNISED variable)
 * cannot enter the corpus and invert the invariant below.
 */
const BROKEN_CORPUS: readonly NodeJS.ProcessEnv[] = [
  plantedEnv({ UNIFI_MCP_TRANSPORT: 'http' }),
  plantedEnv({ UNIFI_MCP_TRANSPORT: 'local' }),
  httpEnv({ UNIFI_HTTP_BIND: '0.0.0.0' }),
  httpEnv({ UNIFI_HTTP_BIND: 'localhost' }),
  httpEnv({ UNIFI_HTTP_BIND: '1.2.3' }),
  httpEnv({ UNIFI_HTTP_PORT: '70000' }),
  httpEnv({ UNIFI_HTTP_PORT: '-1' }),
  httpEnv({ UNIFI_HTTP_PORT: 'abc' }),
  httpEnv({ UNIFI_HTTP_PATH: 'mcp' }),
  httpEnv({ UNIFI_HTTP_PATH: '/healthz' }),
  httpEnv({ UNIFI_HTTP_PATH: '/readyz' }),
  httpEnv({ UNIFI_HTTP_AUTH: 'basic' }),
  httpEnv({ UNIFI_HTTP_AUTH: '' }),
  httpEnv({ UNIFI_HTTP_AUTH: 'none', UNIFI_HTTP_BIND: '0.0.0.0' }),
  httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'all' }),
  httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
  httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'true' }),
  httpEnv({ UNIFI_HTTP_MAX_SESSIONS: '0' }),
  httpEnv({ UNIFI_HTTP_SSE_KEEPALIVE_MS: 'soon' }),
  plantedEnv({ UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: 'short' }),
  plantedEnv({ UNIFI_LOCAL_CA_BUNDLE: '/tmp/ca.pem', UNIFI_LOCAL_TLS_INSECURE: 'true' }),
  { UNIFI_MCP_TRANSPORT: 'http' },
];

const ENV_NAME_PATTERN = /\bUNIFI_[A-Z0-9_]+\b/g;

function isRecognisedEnvKey(key: string): boolean {
  return (
    SCALAR_ENV_KEYS.includes(key) ||
    (key.startsWith('UNIFI_LOCAL_API_KEY_') && key.length > 'UNIFI_LOCAL_API_KEY_'.length) ||
    (key.startsWith('UNIFI_LOCAL_HOST_') && key.length > 'UNIFI_LOCAL_HOST_'.length)
  );
}

describe('every reported error names a variable the operator can actually set', () => {
  test('H-SC-14: the corpus really is broken', () => {
    const broken = BROKEN_CORPUS.filter((env) => !outcomeWithResolvedAuth(env).validation.ok);
    assert.equal(
      broken.length,
      BROKEN_CORPUS.length,
      'a corpus entry validated cleanly, so it contributes no messages to the invariant below',
    );
    assert.ok(BROKEN_CORPUS.length >= 20);
  });

  test('H-SC-14: every message carries at least one recognised remedy variable', () => {
    // Honest limit: this proves each message names SOME variable this build
    // recognises. It cannot prove the named variable is the RIGHT one — that is
    // what the per-refusal exact-string assertions above are for. What it does
    // catch, cheaply and for every future message, is the two failure modes
    // that make an error unactionable: naming nothing at all, and naming a
    // variable that was renamed or never registered.
    const offenders: string[] = [];
    for (const env of BROKEN_CORPUS) {
      for (const message of outcomeWithResolvedAuth(env).validation.errors) {
        const names = message.match(ENV_NAME_PATTERN) ?? [];
        if (!names.some(isRecognisedEnvKey)) offenders.push(message);
      }
    }
    assert.deepEqual(offenders, []);
  });

  test('H-SC-14: the invariant is capable of failing', () => {
    assert.equal((''.match(ENV_NAME_PATTERN) ?? []).some(isRecognisedEnvKey), false);
    assert.equal(isRecognisedEnvKey('UNIFI_HTTP_TYPO'), false);
  });
});

describe('validateConfig is total: it never throws and never exits', () => {
  test('H-SC-19: the whole broken corpus validates without throwing or exiting', () => {
    type ExitFn = typeof process.exit;
    const originalExit: ExitFn = process.exit;
    const trap = ((code?: number): never => {
      throw new Error(`validateConfig called process.exit(${String(code)})`);
    }) as ExitFn;

    process.exit = trap;
    try {
      for (const env of BROKEN_CORPUS) {
        assert.doesNotThrow(() => {
          const config = load(env);
          validateConfig(config, env);
        }, `validateConfig threw or exited for ${JSON.stringify(env['UNIFI_MCP_TRANSPORT'])}`);
      }
      // A config that never came from loadConfig has no WeakMap entry at all.
      assert.doesNotThrow(() => validateConfig(load(httpEnv()), httpEnv()));
    } finally {
      process.exit = originalExit;
    }
  });
});

// ===========================================================================
// 15. The write second gate — one narrowing, two enforcement points
// ===========================================================================

function writeSets(env: NodeJS.ProcessEnv): {
  effective: string[];
  stdio: string[];
  http: string[];
  config: ServerConfig;
} {
  const config = load(env);
  return {
    effective: [...config.writesEnabled].sort(),
    stdio: [...config.writesEnabledBySurface.stdio].sort(),
    http: [...config.writesEnabledBySurface.http].sort(),
    config,
  };
}

describe('the write second gate narrows once, and both gates must agree', () => {
  test('H-SC-15: the HTTP set is the intersection of the two gates', () => {
    const sets = writeSets(
      httpEnv({
        UNIFI_ENABLE_WRITES: 'mobility,protect',
        UNIFI_HTTP_ALLOW_WRITES: 'protect',
      }),
    );
    assert.deepEqual(sets.http, ['protect']);
    assert.deepEqual(sets.effective, ['protect']);
    assert.deepEqual(sets.stdio, ['mobility', 'protect']);
  });

  test('H-SC-15: `none` empties the HTTP set and leaves the base set intact', () => {
    const sets = writeSets(
      httpEnv({ UNIFI_ENABLE_WRITES: 'mobility,protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );
    assert.deepEqual(sets.http, []);
    assert.deepEqual(sets.effective, []);
    assert.deepEqual(sets.stdio, ['mobility', 'protect']);
  });

  test('H-SC-15: over stdio the HTTP gate has no effect, in either position', () => {
    for (const allow of ['none', 'protect', 'all']) {
      const sets = writeSets(
        stdioEnv({ UNIFI_ENABLE_WRITES: 'mobility,protect', UNIFI_HTTP_ALLOW_WRITES: allow }),
      );
      assert.deepEqual(sets.effective, ['mobility', 'protect'], `allow=${allow}`);
      assert.deepEqual(sets.stdio, ['mobility', 'protect'], `allow=${allow}`);
    }
  });

  test('H-SC-15: the two surface sets are DISTINCT Set instances', () => {
    const { config } = writeSets(httpEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    assert.notEqual(
      config.writesEnabledBySurface.stdio,
      config.writesEnabledBySurface.http,
      'the two surfaces alias one Set, so mutating one silently widens the other',
    );
  });

  test('H-SC-15: writesEnabled IS writesEnabledBySurface[activeSurface]', () => {
    // This identity is the whole second gate: src/http/client.ts reads
    // `config.writesEnabled.has(action.service)` and src/tools/definitions.ts
    // reads `writesEnabled.size === 0`, so both inherit the narrowing with no
    // third check and neither file was edited.
    for (const env of [
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
      stdioEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    ]) {
      const config = load(env);
      assert.equal(config.writesEnabled, config.writesEnabledBySurface[config.activeSurface]);
      assert.equal(config.activeSurface, config.serving.transport);
    }
  });

  test('H-SC-15: the narrowing reaches tools/list with no third check', () => {
    const narrowed = load(
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );
    const overStdio = load(
      stdioEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );

    const names = (config: ServerConfig): string[] =>
      advertisedTools(config.enabledServices, config.writesEnabled).map((t) => t.name);

    assert.equal(
      names(narrowed).includes(EXECUTE_WRITE_ACTION.name),
      false,
      'the write tool is still advertised over HTTP despite the HTTP gate being shut',
    );
    assert.equal(names(overStdio).includes(EXECUTE_WRITE_ACTION.name), true);
  });

  test('H-SC-15: the outbound gate reads the same narrowed set', () => {
    // src/http/client.ts refuses when `!config.writesEnabled.has(action.service)`.
    // Asserted on the resolved set rather than by importing the client, which
    // this story must not touch.
    const narrowed = load(
      httpEnv({ UNIFI_ENABLE_WRITES: 'mobility,protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
    );
    assert.equal(narrowed.writesEnabled.has('protect'), true);
    assert.equal(narrowed.writesEnabled.has('mobility'), false);
  });

  const GRAMMAR: readonly (readonly [string, string[]])[] = [
    ['protect', ['protect']],
    ['protect,mobility', ['mobility', 'protect']],
    ['PROTECT', ['protect']],
    [' protect , mobility ', ['mobility', 'protect']],
    ['all', ['mobility', 'protect']],
    ['none', []],
    ['protect,none', []],
    ['none,protect', ['protect']],
  ];

  for (const [raw, expected] of GRAMMAR) {
    test(`H-SC-15: UNIFI_HTTP_ALLOW_WRITES=${JSON.stringify(raw)} ⇒ ${JSON.stringify(expected)}`, () => {
      const sets = writeSets(
        httpEnv({ UNIFI_ENABLE_WRITES: 'mobility,protect', UNIFI_HTTP_ALLOW_WRITES: raw }),
      );
      assert.deepEqual(sets.http, expected);
    });
  }

  for (const raw of ['true', 'false']) {
    test(`H-SC-15: UNIFI_HTTP_ALLOW_WRITES=${raw} is an unknown token, not a boolean`, () => {
      const { config, validation } = outcome(
        httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: raw }),
      );
      assert.deepEqual([...config.writesEnabledBySurface.http], []);
      assert.ok(config.serving.unresolved.includes('allowWrites'));
      assert.ok(
        validation.errors.includes(
          `UNIFI_HTTP_ALLOW_WRITES lists unknown service "${raw}"; valid values are ` +
            `${SERVICE_IDS.join(', ')}, \`all\`, or \`none\`.`,
        ),
        `\`${raw}\` was accepted by the boolean path, which would make it mean \`all\` — the ` +
          `broadest authority in the product, granted by a word an operator plausibly typed ` +
          `meaning "yes, HTTP is on"`,
      );
    });
  }

  test('H-SC-15: the unknown-token refusal is exact', () => {
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'true' }));
    assert.ok(validation.errors.includes(BAD_ALLOW_WRITES_MESSAGE));
  });
});

// ===========================================================================
// 16. The two §3.3 warnings
// ===========================================================================

function writeWarnings(env: NodeJS.ProcessEnv): string[] {
  return outcome(env).validation.warnings.filter((w) => w.startsWith('WARNING WRITES'));
}

describe('the §3.3 write-gate warnings: exactly one, never both', () => {
  test('H-SC-16: the narrowing warning is exact', () => {
    const warnings = writeWarnings(
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'none' }),
    );
    assert.deepEqual(warnings, [NARROWING_WARNING]);
  });

  test('H-SC-16: the narrowing warning never names the broadest-authority value', () => {
    assert.equal(
      /\ball\b/.test(NARROWING_WARNING),
      false,
      'the narrowing warning names `all`, which invites an operator to paste the value that ' +
        'grants every service rather than the one they actually need',
    );
  });

  test('H-SC-16: the effective warning is exact', () => {
    const warnings = writeWarnings(
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
    );
    assert.deepEqual(warnings, [EFFECTIVE_WARNING]);
  });

  test('H-SC-16: the effective warning renders an IPv6 bind in brackets, never :::', () => {
    const warnings = writeWarnings(
      httpEnv({
        UNIFI_ENABLE_WRITES: 'protect',
        UNIFI_HTTP_ALLOW_WRITES: 'protect',
        UNIFI_HTTP_BIND: '::1',
      }),
    );
    assert.equal(warnings.length, 1);
    assert.ok(warnings[0]?.includes('on [::1]:8787 —'));
    assert.equal(warnings[0]?.includes(':::8787'), false);
  });

  test('H-SC-16: the effective warning never renders the literal `all`', () => {
    const warnings = writeWarnings(
      httpEnv({ UNIFI_ENABLE_WRITES: 'all', UNIFI_HTTP_ALLOW_WRITES: 'all' }),
    );
    assert.equal(warnings.length, 1);
    assert.equal(/\ball\b/.test(warnings[0] ?? ''), false);
    assert.ok(warnings[0]?.includes('mobility, network, protect, site-manager'));
  });

  test('H-SC-16: exactly one of the two fires, in every write configuration', () => {
    for (const allow of ['none', 'protect', 'all']) {
      assert.equal(
        writeWarnings(httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: allow }))
          .length,
        1,
        `allow=${allow}`,
      );
    }
  });

  test('H-SC-16: neither fires when no write is enabled anywhere', () => {
    assert.deepEqual(writeWarnings(httpEnv()), []);
  });

  test('H-SC-16: neither fires on a stdio start', () => {
    for (const allow of ['none', 'protect', 'all']) {
      assert.deepEqual(
        writeWarnings(stdioEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: allow })),
        [],
        `allow=${allow}`,
      );
    }
  });
});

// ===========================================================================
// 17. The sentinel scan over the redacted summary
// ===========================================================================

const INBOUND_TOKEN_SENTINEL = 'SENTINEL-INBOUND-TOKEN-0123456789abcdef';
const INBOUND_NEXT_SENTINEL = 'SENTINEL-INBOUND-NEXT-fedcba9876543210';

describe('no inbound secret reaches the config object or the start line (NFR-12)', () => {
  const env = plantedEnv({
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_TOKEN: INBOUND_TOKEN_SENTINEL,
    UNIFI_HTTP_TOKEN_NEXT: INBOUND_NEXT_SENTINEL,
  });
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: resolveBearerSlots(env).descriptor });
  const summary = redactedSummary(config);
  const serialised = JSON.stringify(summary);

  test('H-SC-17: the planted values are sentinel-shaped, so the scanner can see them', () => {
    assert.ok(ANY_SENTINEL.test(INBOUND_TOKEN_SENTINEL));
    assert.ok(ANY_SENTINEL.test(INBOUND_NEXT_SENTINEL));
    assert.ok(INBOUND_TOKEN_SENTINEL.length >= 32 && INBOUND_NEXT_SENTINEL.length >= 32);
  });

  test('H-SC-17: the redacted summary carries no sentinel', () => {
    scanForSentinels(summary, 'redactedSummary(config)');
  });

  test('H-SC-17: the config object itself carries no sentinel', () => {
    scanForSentinels(config, 'config');
  });

  test('H-SC-17: neither planted value survives serialisation', () => {
    assert.equal(serialised.includes(INBOUND_TOKEN_SENTINEL), false);
    assert.equal(serialised.includes(INBOUND_NEXT_SENTINEL), false);
  });

  test('H-SC-17: minSlotLength is never serialised — no length oracle', () => {
    assert.equal(
      serialised.includes('minSlotLength'),
      false,
      'the start line would report the length of the shortest configured secret, which narrows ' +
        'a brute-force search for anyone who can read a log',
    );
  });

  test('H-SC-17: serving.auth carries exactly mode, slotCount and sources', () => {
    const serving = summary['serving'] as Record<string, unknown>;
    const auth = serving['auth'] as Record<string, unknown>;
    assert.deepEqual(Object.keys(auth).sort(), ['mode', 'slotCount', 'sources']);
    assert.equal('problems' in auth, false);
    assert.equal('warnings' in auth, false);
    assert.equal(auth['slotCount'], 2);
  });

  test('H-SC-17: the serving block reports the surface and both write sets', () => {
    const serving = summary['serving'] as Record<string, unknown>;
    assert.equal(serving['transport'], 'http');
    assert.equal(serving['activeSurface'], 'http');
    assert.equal(serving['bind'], '127.0.0.1');
    assert.equal(serving['path'], '/mcp');
    assert.deepEqual(serving['writesEnabledBySurface'], { stdio: [], http: [] });
  });
});

// ===========================================================================
// 18. The 16-character echo ceiling
// ===========================================================================

/** 64 characters, sentinel-shaped, comma- and whitespace-free. */
const LONG_VALUE = `SENTINEL-ECHO-CEILING-0123456789abcdef${'x'.repeat(26)}`;

describe('the contract §2.2 echo ceiling: long values are counted, not echoed', () => {
  test('H-SC-18: the fixture really is 64 characters', () => {
    assert.equal(LONG_VALUE.length, 64);
    assert.ok(ANY_SENTINEL.test(LONG_VALUE));
  });

  const CEILING_CASES: readonly (readonly [string, string])[] = [
    ['UNIFI_HTTP_PORT', 'UNIFI_HTTP_PORT="(64 characters)" is not a port.'],
    ['UNIFI_HTTP_BIND', 'UNIFI_HTTP_BIND="(64 characters)" is not an IP address.'],
    ['UNIFI_HTTP_PATH', 'UNIFI_HTTP_PATH="(64 characters)" is not an absolute path.'],
    [
      'UNIFI_HTTP_ALLOW_WRITES',
      'UNIFI_HTTP_ALLOW_WRITES lists unknown service "(64 characters)";',
    ],
  ];

  for (const [key, expectedPrefix] of CEILING_CASES) {
    test(`H-SC-18: ${key} renders as a character count, not as the value`, () => {
      const { validation } = outcome(httpEnv({ [key]: LONG_VALUE }));
      assert.ok(
        validation.errors.some((m) => m.includes(expectedPrefix)),
        `expected the ceiling rendering; got ${JSON.stringify(validation.errors)}`,
      );
      for (const message of validation.errors) {
        assert.equal(
          message.includes(LONG_VALUE) || message.includes(LONG_VALUE.toLowerCase()),
          false,
          'a 64-character operator-supplied value was echoed in full',
        );
      }
    });
  }

  test('H-SC-18: a value at the 16-character ceiling is still echoed verbatim', () => {
    // The control: without this, an implementation that echoes nothing at all
    // passes every assertion above while making refusals unactionable.
    const sixteen = '1234567890.1.2.3';
    assert.equal(sixteen.length, 16);
    const { validation } = outcome(httpEnv({ UNIFI_HTTP_BIND: sixteen }));
    assert.ok(validation.errors.some((m) => m.includes(`UNIFI_HTTP_BIND="${sixteen}"`)));
  });
});
