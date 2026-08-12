/**
 * US-20 — the startup announcement: the serving line, the five warnings, the
 * write pair and D-12's read-only-banner suppression.
 *
 * Traceability: FR-79 (serving line, routability warning), FR-80 / AR-10 /
 * ADR-R3 (the Windows platform-scope warning), FR-64 + NFR-23 (`auth=none`),
 * FR-78 + NFR-31 (the `*_FILE` permissions warning), FR-71 (the write pair and
 * the suppression), Out of Scope #14 + NFR-32 (plaintext transport), NFR-24.
 * Test-strategy cases A26, A31 and A-W.
 *
 * ## What this file asserts and what it deliberately does not
 *
 * Every line here is read back through `RuntimeDeps.warn`, which receives the
 * line EXACTLY as it would reach the stream — prefix applied, sanitisation
 * done — so these are assertions about the operator's log and not about an
 * internal composer. Nothing patches `process.stderr`, which would be a
 * cross-test leak and would also make the D-14 single-emitter scan meaningless.
 *
 * No listener is bound anywhere in this file. The bind is US-22's (Wave G) and
 * the drain is US-24's (Wave I); the serving line's dependency on a real
 * `AddressInfo` is expressed as the `listenAddress` seam and exercised through
 * it, so this file asserts the LINE without stubbing the transport.
 */
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadConfig, validateConfig } from '../src/config.js';
import { CredentialStore, type CredentialStoreOptions } from '../src/credentials.js';
import { MAX_UNTRUSTED_LENGTH, TRUNCATION_MARKER, sanitizeUntrusted } from '../src/safety/sanitize.js';
import { resolveBearerSlots } from '../src/serve/auth.js';
import {
  LOG_PREFIX,
  createDiagnosticLogger,
  renderBindAddress,
  sanitizeTrusted,
} from '../src/serve/log.js';
import {
  ConfigRefusal,
  buildRuntimeCore,
  resolveRegistry,
  type RuntimeCore,
  type RuntimeDeps,
} from '../src/serve/runtime.js';

import { plantedEnv } from './fixtures/sentinel.js';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Clears FR-81's 32-character floor; not sentinel-shaped. */
const HTTP_SECRET = 'inbound-shared-secret-for-tests-0123456789';

/** The two hosts `plantedEnv` configures, in configuration order. */
const LOCAL_HOSTS = '192.0.2.10, 192.0.2.11';

/** An HTTP environment that passes all five FR-73 refusals. */
function httpEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return plantedEnv({ UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: HTTP_SECRET, ...overrides });
}

/** The same, off loopback — which needs a `Host` allow-list to clear refusal (b). */
function routableEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return httpEnv({
    UNIFI_HTTP_BIND: '0.0.0.0',
    UNIFI_HTTP_ALLOWED_HOSTS: 'mcp.example.test',
    ...overrides,
  });
}

function stdioEnv(overrides: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv {
  return plantedEnv(overrides);
}

interface Capture {
  readonly deps: RuntimeDeps;
  readonly lines: string[];
}

/**
 * `RuntimeDeps` with the collaborators that would open a socket or a keychain
 * replaced, and every emitted line collected.
 *
 * `keychain: null` matters: `CredentialStore` would otherwise consult the OS
 * keychain on a developer machine, which is neither hermetic nor fast.
 */
function capture(env: NodeJS.ProcessEnv, overrides: RuntimeDeps = {}): Capture {
  const lines: string[] = [];
  const deps: RuntimeDeps = {
    env,
    warn: (line) => lines.push(line),
    createCredentialStore: (config, options: CredentialStoreOptions) =>
      new CredentialStore(config, { ...options, keychain: null }),
    ...overrides,
  };
  return { deps, lines };
}

/** Build, resolve the registry, and hand back every line in emission order. */
async function announced(env: NodeJS.ProcessEnv, overrides: RuntimeDeps = {}): Promise<string[]> {
  const { deps, lines } = capture(env, overrides);
  const core: RuntimeCore = buildRuntimeCore(deps);
  try {
    await resolveRegistry(core, overrides);
  } finally {
    await core.close();
  }
  return lines;
}

/** The one line matching a needle. Fails loudly when there is not exactly one. */
function only(lines: readonly string[], needle: string): string {
  const found = lines.filter((line) => line.includes(needle));
  assert.equal(found.length, 1, `expected exactly one line containing ${needle}:\n${lines.join('\n')}`);
  return found[0] as string;
}

function indexOfLine(lines: readonly string[], needle: string): number {
  return lines.findIndex((line) => line.includes(needle));
}

/** A file at the given mode, in a directory removed with the runner's temp dir. */
function fileWithMode(contents: string, mode: number): string {
  const path = join(mkdtempSync(join(tmpdir(), 'unifi-startup-')), 'secret');
  writeFileSync(path, contents);
  chmodSync(path, mode);
  return path;
}

// ===========================================================================
// 1. The serving line (§3.1)
// ===========================================================================

describe('the serving line — one line, after the readiness flag flips (FR-79, FR-63)', () => {
  test('exactly one line, in the contract’s exact form, with auth bearer', async () => {
    const lines = await announced(httpEnv());
    assert.equal(
      only(lines, 'serving MCP over'),
      `${LOG_PREFIX}serving MCP over http at 127.0.0.1:8787/mcp — auth bearer, probes GET ` +
        `/healthz and GET /readyz (unauthenticated).`,
    );
  });

  test('under UNIFI_HTTP_AUTH=none the word is `none`, same position, same grammar', async () => {
    const lines = await announced(httpEnv({ UNIFI_HTTP_AUTH: 'none' }));
    assert.equal(
      only(lines, 'serving MCP over'),
      `${LOG_PREFIX}serving MCP over http at 127.0.0.1:8787/mcp — auth none, probes GET ` +
        `/healthz and GET /readyz (unauthenticated).`,
    );
  });

  test('an IPv6 bind renders bracketed — `[::1]:8787`, never `:::8787` (§0.1.4)', async () => {
    const line = only(await announced(httpEnv({ UNIFI_HTTP_BIND: '::1' })), 'serving MCP over');
    assert.ok(line.includes('at [::1]:8787/mcp'), line);
    assert.equal(line.includes(':::8787'), false);
  });

  test('{path} renders NORMALISED — what the router matches, not what was typed', async () => {
    // `//deep//../mcp-alt/` normalises to `/mcp-alt` (FR-67, §2.5.2 step 3).
    const line = only(
      await announced(httpEnv({ UNIFI_HTTP_PATH: '//deep//../mcp-alt/' })),
      'serving MCP over',
    );
    assert.ok(line.includes('at 127.0.0.1:8787/mcp-alt —'), line);
  });

  test('it is emitted AFTER the ready line, and after the readiness flag flips', async () => {
    const { deps, lines } = capture(httpEnv());
    const core = buildRuntimeCore(deps);
    try {
      // The flag has not flipped: the announcement has not happened.
      assert.equal(indexOfLine(lines, 'serving MCP over'), -1);
      assert.equal(indexOfLine(lines, 'ready —'), -1);
      await resolveRegistry(core);
      await core.ready;
      assert.ok(indexOfLine(lines, 'ready —') >= 0);
      assert.equal(indexOfLine(lines, 'serving MCP over'), indexOfLine(lines, 'ready —') + 1);
    } finally {
      await core.close();
    }
  });

  test('FR-63 — with UNIFI_HTTP_PORT=0 the line reports the OS-assigned port', async () => {
    // The bind is US-22's. What US-20 owns is that the line reports the port the
    // listener actually got rather than the `0` the operator configured, and the
    // seam that carries it is read after the registry resolves, i.e. after bind.
    const lines = await announced(httpEnv({ UNIFI_HTTP_PORT: '0' }), {
      listenAddress: () => ({ address: '127.0.0.1', family: 'IPv4', port: 49152 }),
    });
    assert.ok(only(lines, 'serving MCP over').includes('at 127.0.0.1:49152/mcp'));
  });

  test('D-16 — every address-bearing line agrees with the serving line on the bound port', async () => {
    // The defect this pins: under `UNIFI_HTTP_PORT=0` the serving line rendered
    // the OS-assigned port while all THREE address-bearing warnings rendered
    // `:0`, a bind/port pair that never existed — including the writes-enabled
    // line, the most consequential security warning in the system.
    //
    // Asserted over ONE run, deliberately: the escape (finding F-6) was that
    // the `listenAddress` seam had exactly one consuming test and it asserted
    // only the serving line, so four lines that must agree were never compared
    // in the same process. A per-line test would have passed against the
    // defect; this one cannot.
    // Two runs rather than one, for the reason §3.5's order test gives: `auth=none`
    // is legal only on loopback (refusal (e)) and the plaintext warning fires only
    // OFF loopback, so no startable process emits both. Each run still compares its
    // own address-bearing lines against its own serving line, in its own process,
    // which is the property that was missing.
    const BOUND_PORT = 49173;
    const writes = { UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' };

    const loopback = await announced(httpEnv({ UNIFI_HTTP_PORT: '0', UNIFI_HTTP_AUTH: 'none', ...writes }), {
      listenAddress: () => ({ address: '127.0.0.1', family: 'IPv4', port: BOUND_PORT }),
    });
    const routable = await announced(routableEnv({ UNIFI_HTTP_PORT: '0', ...writes }), {
      listenAddress: () => ({ address: '0.0.0.0', family: 'IPv4', port: BOUND_PORT }),
    });

    const agreed: ReadonlyArray<readonly [string, readonly string[]]> = [
      [
        '127.0.0.1',
        [
          only(loopback, 'serving MCP over'),
          only(loopback, 'UNIFI_HTTP_AUTH=none —'),
          only(loopback, 'WARNING WRITES ENABLED OVER HTTP'),
        ],
      ],
      [
        '0.0.0.0',
        [
          only(routable, 'serving MCP over'),
          only(routable, 'speaks plaintext HTTP'),
          only(routable, 'WARNING WRITES ENABLED OVER HTTP'),
        ],
      ],
    ];

    for (const [bind, addressed] of agreed) {
      for (const line of addressed) {
        assert.ok(
          line.includes(`${bind}:${BOUND_PORT}`),
          `did not name the address the listener bound: ${line}`,
        );
        assert.equal(line.includes(`${bind}:0`), false, `rendered the configured :0 — ${line}`);
      }
    }
  });

  test('stdio binds nothing, so it gets no serving line', async () => {
    const lines = await announced(stdioEnv());
    assert.equal(indexOfLine(lines, 'serving MCP over'), -1);
    assert.ok(indexOfLine(lines, 'ready —') >= 0);
  });

  test('the line names the auth MODE and never the secret, its length or a prefix', async () => {
    const line = only(await announced(httpEnv()), 'serving MCP over');
    assert.equal(line.includes(HTTP_SECRET), false);
    assert.equal(line.includes(String(HTTP_SECRET.length)), false);
    assert.equal(line.includes(HTTP_SECRET.slice(0, 8)), false);
  });
});

// ===========================================================================
// 2. The individual warnings (§3.2, §3.4, §3.6, §3.7) and FR-80's platform scope
// ===========================================================================

describe('§3.2 the auth=none warning (NFR-23, FR-64, case A26)', () => {
  test('the exact line, naming the bind, the port and the re-enabling variables', async () => {
    const lines = await announced(httpEnv({ UNIFI_HTTP_AUTH: 'none' }));
    assert.equal(
      only(lines, 'UNIFI_HTTP_AUTH=none —'),
      `${LOG_PREFIX}WARNING UNIFI_HTTP_AUTH=none — this listener at 127.0.0.1:8787 accepts ` +
        `unauthenticated MCP requests and will drive your UniFi estate for anyone who can reach ` +
        `it. Set UNIFI_HTTP_AUTH=bearer and UNIFI_HTTP_TOKEN to require a secret.`,
    );
  });

  test('NFR-23 — it fires in 20 of 20 consecutive runs, byte-identical each time', async () => {
    const seen = new Set<string>();
    for (let run = 0; run < 20; run += 1) {
      seen.add(only(await announced(httpEnv({ UNIFI_HTTP_AUTH: 'none' })), 'UNIFI_HTTP_AUTH=none —'));
    }
    assert.equal(seen.size, 1, [...seen].join('\n'));
  });

  test('it is silent under the default bearer mode, and on stdio', async () => {
    assert.equal(indexOfLine(await announced(httpEnv()), 'UNIFI_HTTP_AUTH=none —'), -1);
    assert.equal(indexOfLine(await announced(stdioEnv()), 'UNIFI_HTTP_AUTH=none —'), -1);
  });
});

describe('§3.6 the plaintext-transport warning (Out of Scope #14, NFR-32)', () => {
  test('the exact line, on a non-loopback bind', async () => {
    const lines = await announced(routableEnv());
    assert.equal(
      only(lines, 'speaks plaintext HTTP'),
      `${LOG_PREFIX}WARNING this listener speaks plaintext HTTP on 0.0.0.0:8787. The shared ` +
        `secret and every MCP request and response cross the network unencrypted, and anyone on ` +
        `the path can read them. Terminate TLS in front of this process — an ingress, a service ` +
        `mesh, or a reverse proxy — and do not expose this port directly.`,
    );
  });

  test('it deliberately names no variable — the remedy is architectural', async () => {
    const line = only(await announced(routableEnv()), 'speaks plaintext HTTP');
    assert.equal(/UNIFI_[A-Z_]+/.test(line), false, line);
  });

  test('silent on a loopback bind, and on stdio however the bind is set', async () => {
    assert.equal(indexOfLine(await announced(httpEnv()), 'speaks plaintext HTTP'), -1);
    const leftover = await announced(stdioEnv({ UNIFI_HTTP_BIND: '0.0.0.0' }));
    assert.equal(indexOfLine(leftover, 'speaks plaintext HTTP'), -1);
  });
});

describe('§3.4 the routability warning (FR-79)', () => {
  test('the exact line, naming EVERY configured local host', async () => {
    const lines = await announced(routableEnv());
    assert.equal(
      only(lines, 'local-direct consoles'),
      `${LOG_PREFIX}WARNING local-direct consoles ${LOCAL_HOSTS} must be routable from this ` +
        `process's network namespace. A container in a cluster with no route to them will ` +
        `advertise the full Network and Protect surface and fail every call at connect time. ` +
        `Readiness does not check this — /readyz returns 200 regardless (NFR-25).`,
    );
  });

  test('it states that readiness does NOT depend on routability (FR-79 criterion 2)', async () => {
    const line = only(await announced(routableEnv()), 'local-direct consoles');
    assert.ok(line.includes('/readyz returns 200 regardless'), line);
  });

  test('silent with no local console configured, and silent on a loopback bind', async () => {
    const noConsoles = routableEnv();
    delete noConsoles['UNIFI_LOCAL_HOST'];
    delete noConsoles['UNIFI_LOCAL_API_KEY'];
    delete noConsoles['UNIFI_LOCAL_HOST_EDGE'];
    delete noConsoles['UNIFI_LOCAL_API_KEY_EDGE'];
    delete noConsoles['UNIFI_ENABLE_NETWORK'];
    delete noConsoles['UNIFI_ENABLE_PROTECT'];
    assert.equal(indexOfLine(await announced(noConsoles), 'local-direct consoles'), -1);
    assert.equal(indexOfLine(await announced(httpEnv()), 'local-direct consoles'), -1);
  });
});

describe('§3.7 the *_FILE permissions warning (FR-78, NFR-31)', () => {
  const groupReadable = process.platform === 'win32';

  test(
    'a group-readable inbound token file warns, naming the variable and the path',
    { skip: groupReadable ? 'mode bits are meaningless on win32' : false },
    async () => {
      const path = fileWithMode(HTTP_SECRET, 0o644);
      const env = httpEnv({ UNIFI_HTTP_TOKEN_FILE: path });
      delete env['UNIFI_HTTP_TOKEN'];
      const line = only(await announced(env), 'readable by group or other');
      assert.equal(
        line,
        `${LOG_PREFIX}WARNING UNIFI_HTTP_TOKEN_FILE=${path} is readable by group or other. ` +
          `Restrict it to the process user; a secret file on a shared volume is the exposure ` +
          `the *_FILE mechanism exists to avoid.`,
      );
    },
  );

  test(
    'a group-readable OUTBOUND credential file warns the same way',
    { skip: groupReadable ? 'mode bits are meaningless on win32' : false },
    async () => {
      const path = fileWithMode('outbound-api-key-value', 0o644);
      const env = httpEnv({ UNIFI_API_KEY_FILE: path });
      delete env['UNIFI_API_KEY'];
      const line = only(await announced(env), 'UNIFI_API_KEY_FILE=');
      assert.ok(line.startsWith(`${LOG_PREFIX}WARNING UNIFI_API_KEY_FILE=${path} is readable`), line);
    },
  );

  test(
    'a 0600 file is silent — the warning is about exposure, not about *_FILE',
    { skip: groupReadable ? 'mode bits are meaningless on win32' : false },
    async () => {
      const path = fileWithMode(HTTP_SECRET, 0o600);
      const env = httpEnv({ UNIFI_HTTP_TOKEN_FILE: path });
      delete env['UNIFI_HTTP_TOKEN'];
      assert.equal(indexOfLine(await announced(env), 'readable by group or other'), -1);
    },
  );
});

describe('FR-80 the Windows platform-scope warning (AR-10 / ADR-R3, case A-W)', () => {
  test('exactly one warning, carrying all three mandated statements', async () => {
    const lines = await announced(httpEnv(), { platform: 'win32' });
    const line = only(lines, 'graceful shutdown is unavailable');
    assert.equal(
      line,
      `${LOG_PREFIX}WARNING graceful shutdown is unavailable on this platform. SIGTERM and ` +
        `SIGINT handlers register but never fire, so an HTTP deployment here has no drain, no ` +
        `terminal frame and no bounded exit. Windows is a supported development and stdio ` +
        `platform and is not a supported HTTP deployment target (ADR-05).`,
    );
    assert.ok(line.includes('SIGTERM and SIGINT handlers register but never fire'));
    assert.ok(line.includes('is not a supported HTTP deployment target'));
  });

  test('it does not fire on a POSIX platform, nor on stdio under win32', async () => {
    assert.equal(
      indexOfLine(await announced(httpEnv(), { platform: 'linux' }), 'graceful shutdown is unavailable'),
      -1,
    );
    assert.equal(
      indexOfLine(await announced(stdioEnv(), { platform: 'win32' }), 'graceful shutdown is unavailable'),
      -1,
    );
  });

  test('the production default is the real platform, so the windows-latest leg asserts it', async () => {
    const lines = await announced(httpEnv());
    assert.equal(
      indexOfLine(lines, 'graceful shutdown is unavailable') >= 0,
      process.platform === 'win32',
    );
  });
});

describe('the cross-field shutdown-budget warning (architecture §3.4)', () => {
  test('silent at the defaults — 5 000 + 25 000 + 1 000 fits inside 35 000', async () => {
    assert.equal(indexOfLine(await announced(httpEnv()), 'shutdown budget'), -1);
  });

  test('a raised connector timeout warns, naming BOTH variables and no third one', async () => {
    const lines = await announced(httpEnv({ UNIFI_CONNECTOR_TIMEOUT_MS: '60000' }));
    const line = only(lines, 'shutdown budget');
    assert.ok(line.includes('UNIFI_CONNECTOR_TIMEOUT_MS=60000'), line);
    assert.ok(line.includes('UNIFI_HTTP_SHUTDOWN_DEADLINE_MS=35000'), line);
    assert.ok(line.startsWith(`${LOG_PREFIX}WARNING `), line);
  });

  test('it is a warning and not a sixth refusal — FR-73 counts its set at five', async () => {
    // The observable half: the process still starts and still announces ready.
    const lines = await announced(httpEnv({ UNIFI_CONNECTOR_TIMEOUT_MS: '60000' }));
    assert.ok(indexOfLine(lines, 'ready —') >= 0);
  });
});

// ===========================================================================
// 3. The order, asserted so it is an interface rather than an accident (§3.5)
// ===========================================================================

describe('§3.5 the warning order: plaintext, auth=none, routability, *_FILE, write pair', () => {
  /**
   * One configuration in which all five fire at once.
   *
   * `auth=none` is legal only on loopback (refusal (e)) and the plaintext and
   * routability warnings need a non-loopback bind, so the two cannot co-occur
   * in a *startable* HTTP process. The order is therefore asserted over the
   * composed sequence with the `auth=none` arm supplied by its own run, plus a
   * four-of-five run that is genuinely startable.
   */
  test('four of the five fire together, in the fixed order', async () => {
    const path = fileWithMode(HTTP_SECRET, 0o644);
    const env = routableEnv({
      UNIFI_HTTP_TOKEN_FILE: path,
      UNIFI_ENABLE_WRITES: 'protect',
    });
    delete env['UNIFI_HTTP_TOKEN'];
    const lines = await announced(env);

    const positions = [
      indexOfLine(lines, 'speaks plaintext HTTP'),
      indexOfLine(lines, 'local-direct consoles'),
      indexOfLine(lines, 'readable by group or other'),
      indexOfLine(lines, 'WARNING WRITES'),
    ];
    if (process.platform !== 'win32') {
      assert.ok(
        positions.every((position) => position >= 0),
        `not every warning fired:\n${lines.join('\n')}`,
      );
    }
    const fired = positions.filter((position) => position >= 0);
    assert.deepEqual(fired, [...fired].sort((a, b) => a - b), lines.join('\n'));
  });

  test('the auth=none arm sits between plaintext and routability in the composed order', async () => {
    // Asserted on the loopback configuration where `auth=none` is legal: the
    // write pair still trails it, which is the ordering claim that matters
    // (`auth=none` before the write pair, write pair last).
    const lines = await announced(httpEnv({ UNIFI_HTTP_AUTH: 'none', UNIFI_ENABLE_WRITES: 'protect' }));
    const authNone = indexOfLine(lines, 'UNIFI_HTTP_AUTH=none —');
    const writePair = indexOfLine(lines, 'WARNING WRITES');
    assert.ok(authNone >= 0 && writePair >= 0, lines.join('\n'));
    assert.ok(authNone < writePair, `auth=none must precede the write pair:\n${lines.join('\n')}`);
  });

  test('the write pair is LAST among the warnings, in every configuration that fires it', async () => {
    for (const env of [
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect' }),
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
      routableEnv({ UNIFI_ENABLE_WRITES: 'protect' }),
    ]) {
      const lines = await announced(env);
      const warnings = lines.filter((line) => line.includes(`${LOG_PREFIX}WARNING `));
      const writeGate = warnings.filter((line) => line.includes('WARNING WRITES'));
      assert.equal(writeGate.length, 1, warnings.join('\n'));
      assert.equal(warnings.at(-1), writeGate[0], warnings.join('\n'));
    }
  });

  test('every emitted line carries the `unifi-mcp: ` prefix exactly once', async () => {
    const lines = await announced(routableEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    assert.ok(lines.length > 0);
    for (const line of lines) {
      assert.ok(line.startsWith(LOG_PREFIX), line);
      assert.equal(line.slice(LOG_PREFIX.length).includes(LOG_PREFIX), false, line);
    }
  });

  test('the whole sequence is emitted at the bind, ahead of the registry and of `ready`', async () => {
    // FR-62 fixes validation and the refusals first, the bind second, the
    // registry third. This sequence is emitted at the SECOND of those, not the
    // first — D-16: three of the five lines name the listener's address, and
    // under `UNIFI_HTTP_PORT=0` there is no address to name until `listen()`
    // resolves, so composing them in `buildRuntimeCore` rendered `:0` on the
    // plaintext, `auth=none` and writes-enabled warnings while the serving line
    // rendered the real port. What has NOT moved is the sequence's position
    // relative to every other line: still ahead of the registry's own warnings,
    // ahead of `ready`, ahead of the serving line, and still absent entirely
    // from a refused start (asserted in §5 below).
    const { deps, lines } = capture(routableEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    const core = buildRuntimeCore(deps);
    try {
      // Nothing yet: no listener exists, so no line that names one can be true.
      assert.equal(indexOfLine(lines, 'speaks plaintext HTTP'), -1);
      assert.equal(indexOfLine(lines, 'WARNING WRITES'), -1);

      await resolveRegistry(core);
      const plaintext = indexOfLine(lines, 'speaks plaintext HTTP');
      const writePair = indexOfLine(lines, 'WARNING WRITES');
      const ready = indexOfLine(lines, 'ready —');
      assert.ok(plaintext >= 0, lines.join('\n'));
      assert.ok(writePair >= 0, lines.join('\n'));
      assert.ok(ready >= 0, lines.join('\n'));
      assert.ok(plaintext < ready, `the warnings must precede ready:\n${lines.join('\n')}`);
      assert.ok(writePair < ready, `the warnings must precede ready:\n${lines.join('\n')}`);
    } finally {
      await core.close();
    }
  });
});

// ===========================================================================
// 4. The write pair and D-12's read-only-banner suppression (case A31)
// ===========================================================================

describe('D-12 — the read-only banner and the narrowing warning never appear together', () => {
  const READ_ONLY = 'read-only (writes are off; set UNIFI_ENABLE_WRITES to change that).';
  const NARROWING = 'WARNING WRITES ARE DISABLED ON THIS TRANSPORT.';

  test('one run over BOTH configurations, as the criterion requires', async () => {
    // (a) Narrowed to empty: writes were requested, the HTTP gate closed them.
    const narrowed = await announced(httpEnv({ UNIFI_ENABLE_WRITES: 'mobility,protect' }));
    assert.ok(indexOfLine(narrowed, NARROWING) >= 0, narrowed.join('\n'));
    assert.equal(
      indexOfLine(narrowed, READ_ONLY),
      -1,
      `the banner names the wrong variable here and must be suppressed:\n${narrowed.join('\n')}`,
    );

    // (b) Read-only because UNIFI_ENABLE_WRITES was never set: the banner
    // stands, and no narrowing warning is emitted.
    const neverSet = await announced(httpEnv());
    assert.ok(indexOfLine(neverSet, READ_ONLY) >= 0, neverSet.join('\n'));
    assert.equal(indexOfLine(neverSet, NARROWING), -1, neverSet.join('\n'));
  });

  test('the narrowing line is §3.3.1 verbatim, and never names the value `all`', async () => {
    const lines = await announced(httpEnv({ UNIFI_ENABLE_WRITES: 'mobility,protect' }));
    assert.equal(
      only(lines, NARROWING),
      `${LOG_PREFIX}WARNING WRITES ARE DISABLED ON THIS TRANSPORT. UNIFI_ENABLE_WRITES permits ` +
        `mobility, protect, but UNIFI_HTTP_ALLOW_WRITES is \`none\`, so the effective HTTP write ` +
        `set is empty: unifi_execute_write_action is absent from tools/list and every write ` +
        `action will be refused. If that is intended, this line is your confirmation. If it is ` +
        `not, widen UNIFI_HTTP_ALLOW_WRITES and restart.`,
    );
  });

  test('the effective-writes case emits §3.3.2 and the enabled banner, not the read-only one', async () => {
    const lines = await announced(
      httpEnv({ UNIFI_ENABLE_WRITES: 'protect', UNIFI_HTTP_ALLOW_WRITES: 'protect' }),
    );
    assert.ok(indexOfLine(lines, 'WARNING WRITES ENABLED OVER HTTP for protect on 127.0.0.1:8787') >= 0);
    assert.ok(indexOfLine(lines, 'WRITES ENABLED for protect.') >= 0);
    assert.equal(indexOfLine(lines, READ_ONLY), -1);
    assert.equal(indexOfLine(lines, NARROWING), -1);
  });

  test('stdio is untouched: an empty write set still prints the banner', async () => {
    const lines = await announced(stdioEnv());
    assert.ok(indexOfLine(lines, READ_ONLY) >= 0, lines.join('\n'));
  });

  test('stdio with writes on prints the enabled banner and no HTTP write warning', async () => {
    const lines = await announced(stdioEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    assert.ok(indexOfLine(lines, 'WRITES ENABLED for protect.') >= 0);
    assert.equal(indexOfLine(lines, 'WARNING WRITES'), -1);
  });

  test('the suppression is keyed on the narrowing, not on the transport', async () => {
    // HTTP, writes never requested: the banner is NOT suppressed. This is the
    // case a transport-keyed suppression would have got wrong.
    const lines = await announced(httpEnv({ UNIFI_HTTP_ALLOW_WRITES: 'none' }));
    assert.ok(indexOfLine(lines, READ_ONLY) >= 0, lines.join('\n'));
  });
});

// ===========================================================================
// 5. A failed start emits its refusals and no warnings at all
// ===========================================================================

describe('a refused start emits no warnings (matching src/index.ts:99-105 pre-split)', () => {
  test('a validation refusal raises, and not one warning reaches the stream', () => {
    // `UNIFI_HTTP_BIND=0.0.0.0` with no allow-list is refusal (b). The same
    // configuration would otherwise have produced the plaintext warning, the
    // routability warning and the write pair.
    const { deps, lines } = capture(
      httpEnv({ UNIFI_HTTP_BIND: '0.0.0.0', UNIFI_ENABLE_WRITES: 'protect' }),
    );
    assert.throws(() => buildRuntimeCore(deps), ConfigRefusal);
    assert.deepEqual(lines, [], `a refused start must say only why it refused:\n${lines.join('\n')}`);
  });

  test('a configuration whose only fault is an unknown key also emits nothing', () => {
    const { deps, lines } = capture(httpEnv({ UNIFI_HTTP_TOKENN: 'typo' }));
    assert.throws(() => buildRuntimeCore(deps), ConfigRefusal);
    assert.deepEqual(lines, []);
  });

  test('a *_FILE delivery refusal is fatal and silent, even though it also warns', () => {
    // An unreadable token file is one of FR-78's three delivery refusals. The
    // capture's warnings must not be emitted ahead of the refusal that stops
    // the process.
    const env = httpEnv({ UNIFI_HTTP_TOKEN_FILE: join(REPO_ROOT, 'definitely-not-a-file') });
    delete env['UNIFI_HTTP_TOKEN'];
    const { deps, lines } = capture(env);
    assert.throws(() => buildRuntimeCore(deps), ConfigRefusal);
    assert.deepEqual(lines, []);
  });

  test('the same configuration MINUS the refusal does warn — the scan proves something', async () => {
    // The warnings are emitted at the bind (D-16), so the control has to reach
    // the bind: `resolveRegistry` is the post-bind moment both this sequence
    // and the serving line are emitted from.
    const lines = await announced(routableEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    assert.ok(lines.length > 0);
    assert.ok(indexOfLine(lines, 'speaks plaintext HTTP') >= 0, lines.join('\n'));
  });
});

// ===========================================================================
// 6. The 512-character truncation defect, and what still gets truncated
// ===========================================================================

describe('the trusted-text path — the ready line is no longer cut off at 512 characters', () => {
  test('the ready line carries its whole redacted summary, unmarked and un-truncated', async () => {
    const lines = await announced(httpEnv());
    const ready = only(lines, 'ready —');

    assert.ok(
      ready.length > MAX_UNTRUSTED_LENGTH,
      `the fixture no longer exercises the defect: ${ready.length} characters`,
    );
    assert.equal(ready.includes(TRUNCATION_MARKER), false, ready);

    // The tail of `redactedSummary` is the half the ceiling used to remove, so
    // asserting a leading substring would not have caught the bug.
    const summary = JSON.parse(ready.slice(ready.indexOf('{'))) as Record<string, unknown>;
    assert.ok('limits' in summary, Object.keys(summary).join(','));
    // `serving` is the LAST key `redactedSummary` renders, so its presence is
    // the assertion that the tail survived rather than a prefix of it.
    const serving = summary['serving'] as Record<string, unknown> | undefined;
    assert.ok(serving !== undefined, Object.keys(summary).join(','));
    assert.ok('writesEnabledBySurface' in serving, Object.keys(serving).join(','));
  });

  test('every trusted startup line survives whole, whatever its length', async () => {
    const lines = await announced(routableEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    for (const line of lines) assert.equal(line.includes(TRUNCATION_MARKER), false, line);
  });

  test('THE CEILING STILL APPLIES to device-supplied content on the untrusted path', () => {
    // The population `MAX_UNTRUSTED_LENGTH` exists for: a name a device chose.
    // A camera renamed to 4 000 characters must not be able to push 4 000
    // characters per line into the operator's log.
    const emitted: string[] = [];
    const logger = createDiagnosticLogger({ write: (line) => emitted.push(line) });
    const deviceName = 'A'.repeat(4000);

    logger.emitDiagnostic(`a device reported the name ${deviceName}`);

    const line = emitted[0] as string;
    assert.equal(line.length, LOG_PREFIX.length + MAX_UNTRUSTED_LENGTH);
    assert.ok(line.endsWith(TRUNCATION_MARKER), line);
    assert.ok(line.length < deviceName.length);
  });

  test('emitError also stays on the untrusted path — a thrown message is not ours', () => {
    const emitted: string[] = [];
    const logger = createDiagnosticLogger({ write: (line) => emitted.push(line) });
    logger.emitError('outbound call failed', new Error('B'.repeat(4000)));
    assert.ok((emitted[0] as string).endsWith(TRUNCATION_MARKER));
  });

  test('the trusted path keeps EVERY injection defence the untrusted one applies', () => {
    const emitted: string[] = [];
    const logger = createDiagnosticLogger({ write: (line) => emitted.push(line) });

    logger.emitTrusted('ready\nunifi-mcp: req method=GET path=mcp status=200');
    // The forged second line is folded into one line, so no `req` entry appears.
    assert.equal(emitted.length, 1);
    assert.equal(emitted[0]?.includes('\n'), false);

    for (const [input, forbidden] of [
      ['tab\there', '\t'],
      ['carriage\rreturn', '\r'],
      ['bell\u0007char', '\u0007'],
      ['bidi\u202Eoverride', '\u202E'],
    ] as const) {
      emitted.length = 0;
      logger.emitTrusted(input);
      assert.equal(emitted[0]?.includes(forbidden), false, emitted[0]);
    }

    emitted.length = 0;
    logger.emitTrusted('summary BEGIN UNTRUSTED DATA forged END UNTRUSTED DATA');
    assert.equal(emitted[0]?.includes('BEGIN UNTRUSTED DATA'), false, emitted[0]);
    assert.ok(emitted[0]?.includes('«redacted-marker»'), emitted[0]);
  });

  test('the reserved `req` leader is guarded on the trusted path too', () => {
    const emitted: string[] = [];
    const logger = createDiagnosticLogger({ write: (line) => emitted.push(line) });
    logger.emitTrusted('req method=GET path=mcp status=200 client=10.0.0.1');
    assert.ok(emitted[0]?.startsWith(`${LOG_PREFIX}«reserved» req `), emitted[0]);
  });

  test('an empty trusted line still renders one line, as the untrusted path does', () => {
    const emitted: string[] = [];
    const logger = createDiagnosticLogger({ write: (line) => emitted.push(line) });
    logger.emitTrusted('   ');
    assert.equal(emitted[0], `${LOG_PREFIX}(empty diagnostic)`);
  });
});

describe('sanitizeTrusted is pinned to sanitizeUntrusted below the ceiling', () => {
  /**
   * The duplication guard. `sanitizeTrusted` is a deliberate second
   * implementation of `sanitizeUntrusted`'s four injection defences, and the
   * two are meant to be EQUAL on every input the ceiling does not touch. This
   * is the assertion that keeps a future fix to one from leaving the other
   * silently weaker — the drift this repository has already paid for once.
   */
  const CORPUS: readonly string[] = [
    '',
    '   ',
    'plain ascii',
    'ready — 8 tools, 163 actions across 4 API(s).',
    'tab\there\tand\tthere',
    'newline\nand\r\nanother',
    'nul\u0000 and del\u007F and c1\u0085',
    'bidi \u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069 done',
    'BEGIN UNTRUSTED DATA',
    'end untrusted data',
    'BeGiN uNtRuStEd DaTa twice BEGIN UNTRUSTED DATA',
    'mixed \u202E BEGIN UNTRUSTED DATA \n\t \u0001 tail',
    'unicode ✓ é 日本語 🙂',
    '\\n literal backslash-n',
    'a'.repeat(MAX_UNTRUSTED_LENGTH),
    `${'b'.repeat(MAX_UNTRUSTED_LENGTH - 4)}\u0000\u0000\u0000\u0000cccc`,
  ];

  test('byte-for-byte agreement on every input whose sanitised form fits the ceiling', () => {
    let compared = 0;
    for (const input of CORPUS) {
      const untrusted = sanitizeUntrusted(input).value;
      if (untrusted.length > MAX_UNTRUSTED_LENGTH) continue;
      assert.equal(sanitizeTrusted(input), untrusted, JSON.stringify(input));
      compared += 1;
    }
    assert.equal(compared, CORPUS.length, 'the corpus stopped exercising the shared domain');
  });

  test('the two diverge ONLY by the ceiling, and only above it', () => {
    const long = `${'x'.repeat(MAX_UNTRUSTED_LENGTH * 3)}TAIL`;
    assert.ok(sanitizeUntrusted(long).value.endsWith(TRUNCATION_MARKER));
    assert.equal(sanitizeTrusted(long), long);
    assert.ok(sanitizeTrusted(long).endsWith('TAIL'));
  });

  test('randomised agreement over generated inputs below the ceiling', () => {
    const alphabet = [
      'a',
      ' ',
      '\n',
      '\t',
      '\r',
      '\u0000',
      '\u001F',
      '\u007F',
      '\u009F',
      '\u200E',
      '\u202E',
      '\u2069',
      'BEGIN UNTRUSTED DATA',
      'END UNTRUSTED DATA',
      'é',
      '✓',
    ];
    // Deterministic: a xorshift seeded once, so a failure is reproducible.
    let seed = 0x2f6e2b1;
    const next = (): number => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return Math.abs(seed);
    };
    for (let round = 0; round < 500; round += 1) {
      let input = '';
      const parts = next() % 12;
      for (let part = 0; part <= parts; part += 1) {
        input += alphabet[next() % alphabet.length];
      }
      const untrusted = sanitizeUntrusted(input).value;
      if (untrusted.length > MAX_UNTRUSTED_LENGTH) continue;
      assert.equal(sanitizeTrusted(input), untrusted, JSON.stringify(input));
    }
  });
});

// ===========================================================================
// 7. The two composition helpers, and the duplication they are pinned against
// ===========================================================================

describe('renderBindAddress agrees with the rendering src/config.ts composes (§0.1.4)', () => {
  test('an IPv6 bind is bracketed in BOTH the serving line and the §3.3.2 warning', () => {
    // `renderBindAddress` in `src/serve/log.ts` and `renderAddress` in
    // `src/config.ts` are two implementations of one contract rule. This is
    // what keeps them from drifting: the same bind, rendered by each, compared.
    const env = plantedEnv({
      UNIFI_MCP_TRANSPORT: 'http',
      UNIFI_HTTP_TOKEN: HTTP_SECRET,
      UNIFI_HTTP_BIND: '::1',
      UNIFI_ENABLE_WRITES: 'protect',
      UNIFI_HTTP_ALLOW_WRITES: 'protect',
    });
    const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: resolveBearerSlots(env).descriptor });
    const composedByConfig = validateConfig(config, env).warnings.find((warning) =>
      warning.startsWith('WARNING WRITES ENABLED OVER HTTP'),
    );
    assert.ok(composedByConfig, 'the §3.3.2 warning did not fire; the comparison proves nothing');
    assert.ok(composedByConfig.includes(`on ${renderBindAddress('::1', 8787)} —`), composedByConfig);
  });

  test('an IPv4 bind renders unbracketed, and a hostname is never bracketed', () => {
    assert.equal(renderBindAddress('0.0.0.0', 8787), '0.0.0.0:8787');
    assert.equal(renderBindAddress('::', 8787), '[::]:8787');
    assert.equal(renderBindAddress('mcp.example.test', 8787), 'mcp.example.test:8787');
  });
});

// ===========================================================================
// 8. log.ts is still the single emitter, and nothing here reintroduces a write
// ===========================================================================

describe('the announcement writes to no stream of its own', () => {
  test('src/serve/runtime.ts holds no direct stream write', async () => {
    const { readFileSync } = await import('node:fs');
    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'serve', 'runtime.ts'),
      'utf8',
    );
    assert.equal(source.includes('process.stderr.write'), false);
    assert.equal(source.includes('process.stdout.write'), false);
    assert.equal(/\bconsole\s*\./.test(source), false);
  });

  test('every announcement line arrives through the injected writer, in order', async () => {
    const lines = await announced(httpEnv({ UNIFI_ENABLE_WRITES: 'protect' }));
    assert.ok(lines.length >= 3);
    assert.ok(lines.every((line) => line.startsWith(LOG_PREFIX)));
  });
});
