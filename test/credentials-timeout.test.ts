/**
 * US-17 — the keychain lookup is bounded (FR-82, FR-80's AR-1 criterion, FR-70's
 * credential-resolution state, NFR-13, NFR-24, NFR-27, RES-3).
 *
 * Four things shape this suite.
 *
 * FIRST, NOTHING HERE WAITS. The bound is 10 000 ms and one case exercises ten
 * consecutive expiries, which at real time is 100 s against a 60 s per-test
 * ceiling. So the clock and the timer are injected through `KeychainTimers` —
 * the store's third constructor parameter, a DEFAULT parameter because Node 20
 * has no `mock.module` and because `CredentialStoreOptions` is closed to this
 * story. `RecordingTimers` below also records what was asked for, which is how
 * "the bound is 10 000 ms" is asserted as a fact about the call rather than as
 * a fact about how long the test took.
 *
 * SECOND, ABANDONMENT IS NOT REJECTION, and the difference is asserted rather
 * than assumed. A design that raced a rejecting timeout promise was tried
 * earlier in this round and killed the process on an unhandled rejection when
 * the keychain settled late. `G3` plants exactly that shape — a keychain that
 * rejects AFTER the bound expired — and fails if any unhandled rejection
 * reaches the process.
 *
 * THIRD, EVERY COUNTER IS PROVED NON-VACUOUS. A keychain-invocation counter
 * reading `0` for the container shape means nothing unless the same harness
 * reads a positive number elsewhere, and "the second call re-consults the
 * keychain" means nothing unless a successful answer is shown to be cached. The
 * negative and the positive of each property are asserted side by side.
 *
 * FOURTH, no test here reaches a real keychain (S-09): every construction below
 * goes through the single `store()` helper, which requires a `keychain` value.
 *
 * DEFERRED, NAMED: FR-82's last criterion — SIGTERM delivered while an action
 * is inside `resolveFor()` and the process exiting 0 within
 * `UNIFI_HTTP_SHUTDOWN_DEADLINE_MS` — needs a drain, and the drain is US-24.
 * This story is that criterion's MECHANISM, so what is asserted here is the
 * mechanism (`G4`): an in-flight resolution over a never-settling keychain is
 * abandoned at the bound and settles, and the timer that abandons it does not
 * hold the event loop open. The end-to-end signal-and-exit-code assertion is
 * recorded as a carry-forward obligation on US-24.
 */
import { strict as assert } from 'node:assert';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { CLOUD_API_KEY_ENV, loadConfig, validateConfig, type ServerConfig } from '../src/config.js';
import {
  CredentialStore,
  KEYCHAIN_TIMEOUT_MS,
  KEYCHAIN_WARNING_WINDOW_MS,
  credentialFileVar,
  realKeychainTimers,
  type KeychainTimers,
  type KeytarLike,
} from '../src/credentials.js';
import { toolError } from '../src/http/errors.js';
import { UnifiError } from '../src/types.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CREDENTIALS_SOURCE = readFileSync(join(REPO_ROOT, 'src', 'credentials.ts'), 'utf8');
const PRD = readFileSync(join(REPO_ROOT, 'docs', 'prd.md'), 'utf8');

/** 44 characters, distinctive enough that a substring search cannot false-positive. */
const ENV_SENTINEL = 'sentinel-us17-env-api-key-value-000000000001';
const FILE_SENTINEL = 'sentinel-us17-file-api-key-value-00000000002';
const KEYCHAIN_SENTINEL = 'sentinel-us17-keychain-api-key-val-00000003';

/** The text that must NOT appear when the keychain merely failed to answer. */
const CONFIGURED_TEXT = 'No cloud API key is configured';

// ===========================================================================
// Harness
// ===========================================================================

/**
 * The injected clock and timer.
 *
 * `expire` fires the bound on the next macrotask, which models "the 10 000 ms
 * elapsed" without any of it elapsing. `hold` never fires it, so a test can
 * observe that a resolution is genuinely still pending and then release it.
 * Either way `requested` records the milliseconds the production code asked
 * for, and `outstanding` reports timers that were neither fired nor cleared —
 * a stray one of those is what hangs a test runner.
 */
class RecordingTimers implements KeychainTimers {
  readonly requested: number[] = [];
  cleared = 0;
  private clock = 0;
  private seq = 0;
  private readonly pending = new Map<number, { fn: () => void; immediate: NodeJS.Immediate | null }>();

  constructor(private readonly mode: 'expire' | 'hold' = 'expire') {}

  setTimeout(fn: () => void, ms: number): unknown {
    this.requested.push(ms);
    const id = ++this.seq;
    const immediate =
      this.mode === 'expire'
        ? setImmediate(() => {
            this.pending.delete(id);
            fn();
          })
        : null;
    this.pending.set(id, { fn, immediate });
    return id;
  }

  clearTimeout(handle: unknown): void {
    const id = handle as number;
    const entry = this.pending.get(id);
    if (entry === undefined) return;
    this.pending.delete(id);
    this.cleared++;
    if (entry.immediate) clearImmediate(entry.immediate);
  }

  now(): number {
    return this.clock;
  }

  /** Moves the warning window's clock only. The bound never reads this. */
  advance(ms: number): void {
    this.clock += ms;
  }

  /** Fires every timer still pending — the `hold` mode's release. */
  fire(): void {
    for (const [id, entry] of [...this.pending]) {
      this.pending.delete(id);
      entry.fn();
    }
  }

  get outstanding(): number {
    return this.pending.size;
  }
}

/** A keychain double that counts its invocations. Never a real keychain. */
class CountingKeychain implements KeytarLike {
  readonly accounts: string[] = [];

  constructor(private readonly answers: Array<() => Promise<string | null>>) {}

  get calls(): number {
    return this.accounts.length;
  }

  getPassword(_service: string, account: string): Promise<string | null> {
    this.accounts.push(account);
    const answer = this.answers[Math.min(this.accounts.length - 1, this.answers.length - 1)];
    assert.ok(answer !== undefined, 'CountingKeychain was constructed with no answers');
    return answer();
  }
}

/** A promise that never settles — the wedged-keychain shape (RES-3). */
const never = (): Promise<string | null> => new Promise<string | null>(() => {});

function config(env: NodeJS.ProcessEnv = {}): ServerConfig {
  return loadConfig(env, { repoRoot: REPO_ROOT });
}

/**
 * The ONE construction site in this file, so `keychain` cannot be omitted by
 * accident anywhere below (S-09) and so the timer seam is never the default.
 */
function store(options: {
  config?: ServerConfig;
  env?: NodeJS.ProcessEnv;
  keychain: KeytarLike | null;
  timers?: RecordingTimers;
}): { store: CredentialStore; warnings: string[]; timers: RecordingTimers } {
  const warnings: string[] = [];
  const timers = options.timers ?? new RecordingTimers();
  const built = new CredentialStore(
    options.config ?? config(),
    { env: options.env ?? {}, warn: (m) => warnings.push(m), keychain: options.keychain },
    timers,
  );
  return { store: built, warnings, timers };
}

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-us17-'));
  after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** The rendered three-line tool error for a rejected resolution. */
async function refusalText(resolution: Promise<unknown>): Promise<string> {
  try {
    await resolution;
  } catch (e) {
    assert.ok(e instanceof UnifiError, `expected a UnifiError, got ${String(e)}`);
    const rendered = toolError(e.normalized).content[0];
    assert.ok(rendered !== undefined);
    return rendered.text;
  }
  assert.fail('the resolution succeeded where a structured refusal was expected');
}

// ===========================================================================
// A. The bound exists, is 10 000 ms, and the fallback answers inside it
// ===========================================================================

describe('FR-82: a slow keychain resolves from the fallback, inside the bound', () => {
  test('A1: a never-settling keychain does not stop the environment key resolving', async () => {
    const keychain = new CountingKeychain([never]);
    const { store: credentials, timers } = store({
      env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
      keychain,
    });

    const started = Date.now();
    const key = await credentials.resolveFor('site-manager', 'cloud');
    const elapsed = Date.now() - started;

    assert.equal(key, ENV_SENTINEL);
    assert.equal(keychain.calls, 1, 'the keychain was consulted first (FR-15 ordering survives)');
    assert.deepEqual(keychain.accounts, [CLOUD_API_KEY_ENV]);
    assert.deepEqual(
      timers.requested,
      [KEYCHAIN_TIMEOUT_MS],
      'exactly one bound, on the keychain call, for exactly the constant',
    );
    assert.ok(
      elapsed < 2000,
      `resolution took ${elapsed} ms of real time — the bound is not being modelled, it is ` +
        `being waited out`,
    );
    assert.equal(timers.outstanding, 0, 'a timer was left pending after the call settled');
  });

  test('A1b: the bound is the constant FR-82 names, and it is 10 000 ms', () => {
    assert.equal(KEYCHAIN_TIMEOUT_MS, 10_000);
    assert.equal(KEYCHAIN_WARNING_WINDOW_MS, 60_000);
    // The messages render it as `10000 ms`, which is what the operator sees and
    // what the acceptance criteria quote.
    assert.equal(`${KEYCHAIN_TIMEOUT_MS}`, '10000');
  });

  test('A2: the same holds for `*_FILE` delivery (§5.15.1b)', async () => {
    const path = join(tempDir(), 'api-key');
    writeFileSync(path, `${FILE_SENTINEL}\n`);
    if (process.platform !== 'win32') chmodSync(path, 0o600);

    const keychain = new CountingKeychain([never]);
    const { store: credentials, timers } = store({
      env: { [credentialFileVar(CLOUD_API_KEY_ENV)]: path },
      keychain,
    });

    assert.equal(await credentials.resolveFor('site-manager', 'cloud'), FILE_SENTINEL);
    assert.equal(keychain.calls, 1);
    assert.deepEqual(timers.requested, [KEYCHAIN_TIMEOUT_MS]);
    assert.equal(timers.outstanding, 0);
  });

  test('A3: the bound applies to the keychain call and to nothing else', async () => {
    // File and environment resolution perform no IPC and are not raced: with
    // the keychain absent, no timer is created at all even though both
    // fallbacks are exercised.
    const path = join(tempDir(), 'api-key-2');
    writeFileSync(path, FILE_SENTINEL);
    if (process.platform !== 'win32') chmodSync(path, 0o600);

    const { store: credentials, timers } = store({
      env: { [credentialFileVar(CLOUD_API_KEY_ENV)]: path },
      keychain: null,
    });

    assert.equal(await credentials.resolveFor('site-manager', 'cloud'), FILE_SENTINEL);
    assert.deepEqual(timers.requested, []);
  });

  test('A4: a second resolution is served from the in-memory cache, unbounded', async () => {
    const keychain = new CountingKeychain([never]);
    const { store: credentials, timers } = store({
      env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
      keychain,
    });

    await credentials.resolveFor('site-manager', 'cloud');
    await credentials.resolveFor('mobility', 'cloud');

    // FR-82 handles expiry exactly as keychain unavailability already is: the
    // fallback value that answered IS cached, as it is on the keychain-error
    // path, so only the first call pays the bound. What is never cached is the
    // timeout itself — see D1.
    assert.equal(keychain.calls, 1);
    assert.deepEqual(timers.requested, [KEYCHAIN_TIMEOUT_MS]);
  });
});

// ===========================================================================
// B. The warning, its exact text, and its cadence
// ===========================================================================

const EXPECTED_WARNING =
  `unifi-mcp: WARNING the OS keychain did not answer within 10000 ms for ${CLOUD_API_KEY_ENV}. ` +
  `The lookup was abandoned; if the keychain is locked, unlock it and retry — or set ` +
  `${CLOUD_API_KEY_ENV}_FILE to bypass the keychain entirely.`;

describe('FR-82 / NFR-24: one warning per account per 60-second window', () => {
  test('B1: the warning is the exact line the contract specifies', async () => {
    const { store: credentials, warnings } = store({
      env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
      keychain: new CountingKeychain([never]),
    });

    await credentials.resolveFor('site-manager', 'cloud');

    assert.deepEqual(warnings, [EXPECTED_WARNING]);
    assert.ok(!warnings[0]?.includes(ENV_SENTINEL), 'the warning carries key material');
  });

  test('B2: ten consecutive timed-out resolutions in one window produce exactly one line', async () => {
    // No fallback, so nothing is cached and every one of the ten resolutions
    // reaches the keychain and times out.
    const keychain = new CountingKeychain([never]);
    const { store: credentials, warnings, timers } = store({ keychain });

    for (let i = 0; i < 10; i++) {
      await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    }

    assert.equal(keychain.calls, 10, 'the ten resolutions did not all reach the keychain');
    assert.equal(
      warnings.filter((w) => w === EXPECTED_WARNING).length,
      1,
      `expected one warning, got ${warnings.length}: ${JSON.stringify(warnings)}`,
    );
    assert.equal(timers.requested.length, 10, 'each uncached resolution is bounded afresh');
    assert.equal(timers.outstanding, 0);
  });

  test('B3: the cadence is a window, not a one-shot — a later expiry warns again', async () => {
    const { store: credentials, warnings, timers } = store({
      keychain: new CountingKeychain([never]),
    });

    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    timers.advance(KEYCHAIN_WARNING_WINDOW_MS - 1);
    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    assert.equal(warnings.length, 1, 'a line was emitted inside the window');

    timers.advance(1);
    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    assert.deepEqual(warnings, [EXPECTED_WARNING, EXPECTED_WARNING]);
  });

  test('B4: the window is per account, so one wedged account cannot mute another', async () => {
    const cfg = config({ UNIFI_LOCAL_HOST: '192.168.1.1', UNIFI_LOCAL_API_KEY: 'placeholder' });
    const localAccount = cfg.localConsoles[0]?.apiKeyEnvVar;
    assert.ok(localAccount !== undefined && localAccount !== CLOUD_API_KEY_ENV);

    const { store: credentials, warnings } = store({
      config: cfg,
      keychain: new CountingKeychain([never]),
    });

    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    await assert.rejects(credentials.resolveFor('network', 'local'), UnifiError);

    assert.equal(warnings.length, 2);
    assert.ok(warnings[0]?.includes(CLOUD_API_KEY_ENV));
    assert.ok(warnings[1]?.includes(localAccount));
    assert.ok(warnings[1]?.includes(credentialFileVar(localAccount)));
  });
});

// ===========================================================================
// C. The structured refusal when there is no fallback
// ===========================================================================

describe('FR-82: no fallback fails as a `timeout`, never as "not configured"', () => {
  test('C1: the three-line shape is exactly what the contract specifies', async () => {
    const { store: credentials } = store({ keychain: new CountingKeychain([never]) });

    const text = await refusalText(credentials.resolveFor('site-manager', 'cloud'));

    assert.deepEqual(text.split('\n'), [
      'site-manager request failed (timeout).',
      `Message: The OS keychain did not answer within 10000 ms for ${CLOUD_API_KEY_ENV}, and no ` +
        `value was supplied by environment or file.`,
      `Next step: Unlock the keychain and try again, or set ${CLOUD_API_KEY_ENV}_FILE (or ` +
        `${CLOUD_API_KEY_ENV}) and restart the server.`,
    ]);
  });

  test('C2: the "no cloud API key is configured" text is absent, and so is key material', async () => {
    const { store: credentials } = store({ keychain: new CountingKeychain([never]) });

    const text = await refusalText(credentials.resolveFor('site-manager', 'cloud'));

    assert.ok(
      !text.includes(CONFIGURED_TEXT),
      `the timeout refusal claims the key is not configured, which is false — the key is ` +
        `configured and the keychain did not answer:\n${text}`,
    );
    for (const secret of [ENV_SENTINEL, FILE_SENTINEL, KEYCHAIN_SENTINEL]) {
      assert.ok(!text.includes(secret));
    }
  });

  test('C3: the same run still produces the config refusal when nothing IS configured', async () => {
    // Without this, C2 would pass against an implementation that had simply
    // deleted the message it asserts the absence of.
    const { store: credentials } = store({ keychain: null });

    const text = await refusalText(credentials.resolveFor('site-manager', 'cloud'));

    assert.ok(text.includes(CONFIGURED_TEXT), text);
    assert.ok(text.startsWith('site-manager request failed (config).'), text);
  });

  test('C4: the local-console path refuses the same way', async () => {
    const cfg = config({ UNIFI_LOCAL_HOST: '192.168.1.1', UNIFI_LOCAL_API_KEY: 'placeholder' });
    const account = cfg.localConsoles[0]?.apiKeyEnvVar;
    assert.ok(account !== undefined);
    const { store: credentials } = store({ config: cfg, keychain: new CountingKeychain([never]) });

    const text = await refusalText(credentials.resolveFor('network', 'local'));

    assert.deepEqual(text.split('\n'), [
      'network request failed (timeout).',
      `Message: The OS keychain did not answer within 10000 ms for ${account}, and no value was ` +
        `supplied by environment or file.`,
      `Next step: Unlock the keychain and try again, or set ${credentialFileVar(account)} (or ` +
        `${account}) and restart the server.`,
    ]);
    assert.ok(!text.includes('has no API key configured'));
  });
});

// ===========================================================================
// D. No negative caching — "unlock and retry" works without a restart
// ===========================================================================

describe('FR-82: a timed-out lookup is not cached in either direction', () => {
  test('D1: the second call re-consults the keychain and the counter reads exactly 2', async () => {
    const keychain = new CountingKeychain([never, () => Promise.resolve(KEYCHAIN_SENTINEL)]);
    const { store: credentials, timers } = store({ keychain });

    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    const key = await credentials.resolveFor('site-manager', 'cloud');

    assert.equal(key, KEYCHAIN_SENTINEL, 'the second call did not resolve FROM the keychain');
    assert.equal(keychain.calls, 2, 'the second call skipped the keychain — the cache is poisoned');
    assert.deepEqual(timers.requested, [KEYCHAIN_TIMEOUT_MS, KEYCHAIN_TIMEOUT_MS]);
    assert.equal(timers.cleared, 1, 'the answered call must clear its bound rather than let it fire');
    assert.equal(timers.outstanding, 0);
  });

  test('D2: a successful keychain answer IS cached, so D1 is not just "nothing caches"', async () => {
    const keychain = new CountingKeychain([() => Promise.resolve(KEYCHAIN_SENTINEL)]);
    const { store: credentials } = store({ keychain });

    assert.equal(await credentials.resolveFor('site-manager', 'cloud'), KEYCHAIN_SENTINEL);
    assert.equal(await credentials.resolveFor('mobility', 'cloud'), KEYCHAIN_SENTINEL);
    assert.equal(keychain.calls, 1);
  });

  test('D3: a keychain that stays wedged is re-consulted every time, never memoised as absent', async () => {
    const keychain = new CountingKeychain([never]);
    const { store: credentials } = store({ keychain });

    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);
    await assert.rejects(credentials.resolveFor('site-manager', 'cloud'), UnifiError);

    assert.equal(keychain.calls, 3);
  });
});

// ===========================================================================
// E. Inert where no keychain exists — unscoped, all three CI legs
// ===========================================================================

describe('FR-82 / NFR-13: `keychain: null` is the container shape and creates nothing', () => {
  // No signal, no platform-specific behaviour: this runs unscoped on
  // ubuntu-latest, macos-latest AND windows-latest.
  test('E1: no keychain call, no timer, no warning', async () => {
    const { store: credentials, warnings, timers } = store({
      env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
      keychain: null,
    });

    assert.equal(await credentials.resolveFor('site-manager', 'cloud'), ENV_SENTINEL);

    assert.deepEqual(timers.requested, [], 'a timer was created where no keychain path exists');
    assert.equal(timers.outstanding, 0);
    assert.equal(
      warnings.filter((w) => w.includes('did not answer')).length,
      0,
      `a timeout warning was emitted on the container shape: ${JSON.stringify(warnings)}`,
    );
  });

  test('E2: the counter that reads 0 above is the counter that reads 1 with a keychain', async () => {
    const keychain = new CountingKeychain([() => Promise.resolve(null)]);
    const { store: credentials, timers } = store({
      env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
      keychain,
    });

    assert.equal(await credentials.resolveFor('site-manager', 'cloud'), ENV_SENTINEL);
    assert.equal(keychain.calls, 1);
    assert.deepEqual(timers.requested, [KEYCHAIN_TIMEOUT_MS]);
  });
});

// ===========================================================================
// F. The bound is a constant and cannot become a variable by accident
// ===========================================================================

/** Every plausible spelling an operator or a future edit might reach for. */
const PROPOSED_NAMES = [
  'UNIFI_KEYCHAIN_TIMEOUT_MS',
  'UNIFI_KEYCHAIN_TIMEOUT',
  'UNIFI_MCP_KEYCHAIN_TIMEOUT_MS',
  'UNIFI_HTTP_KEYCHAIN_TIMEOUT_MS',
  'UNIFI_CREDENTIAL_TIMEOUT_MS',
];

/** The rows of one normative §5.15 table, as variable names. */
function tableVariables(heading: string): string[] {
  const start = PRD.indexOf(heading);
  assert.ok(start > 0, `${heading} is not in docs/prd.md`);
  const rest = PRD.slice(start + heading.length);
  const end = rest.indexOf('\n#### ');
  const section = end === -1 ? rest : rest.slice(0, end);
  return [...section.matchAll(/^\|\s*`(UNIFI_[A-Z0-9_<>]+)`/gm)].map((m) => m[1] as string);
}

describe('FR-82: the bound is a fixed constant, not configuration', () => {
  for (const name of PROPOSED_NAMES) {
    test(`F1: ${name} produces the existing unknown-key startup refusal`, () => {
      const env = { [name]: '5000' };
      const cfg = config(env);
      const validation = validateConfig(cfg, env);

      assert.deepEqual(validation.unknownEnvKeys, [name]);
      assert.equal(validation.ok, false, `${name} was accepted as configuration`);
    });
  }

  test('F2: no row of §5.15.1 or §5.15.1b names the bound', () => {
    const serving = tableVariables('#### 5.15.1 Serving-transport configuration surface');
    const delivery = tableVariables('#### 5.15.1b Credential file-delivery variables');
    assert.ok(serving.length > 10, 'the §5.15.1 scan matched nothing and proves nothing');
    assert.ok(delivery.length > 0, 'the §5.15.1b scan matched nothing and proves nothing');

    for (const name of [...serving, ...delivery]) {
      assert.ok(
        !/KEYCHAIN/.test(name),
        `${name} documents the keychain bound as configuration; FR-82 makes it a constant`,
      );
      assert.ok(!PROPOSED_NAMES.includes(name), `${name} is documented as configuration`);
    }
  });

  test('F3: the source reads no environment variable for the bound', () => {
    assert.ok(
      /const KEYCHAIN_TIMEOUT_MS = 10_000;/.test(CREDENTIALS_SOURCE),
      'the bound is no longer a literal constant in src/credentials.ts',
    );
    const names = [...CREDENTIALS_SOURCE.matchAll(/UNIFI_[A-Z0-9_]+/g)].map((m) => m[0]);
    for (const name of names) {
      assert.ok(!/KEYCHAIN|TIMEOUT/.test(name), `src/credentials.ts names ${name}`);
    }
  });
});

// ===========================================================================
// G. Abandonment, not rejection — and the timer holds nothing open (AR-1)
// ===========================================================================

describe('FR-80 AR-1 / RES-3: the mechanism a drain needs', () => {
  test('G1: the production timer does not hold the event loop open', () => {
    const handle = realKeychainTimers.setTimeout(() => {
      assert.fail('the production bound fired inside a test that never waited for it');
    }, KEYCHAIN_TIMEOUT_MS) as NodeJS.Timeout;

    assert.equal(
      typeof handle.hasRef === 'function' ? handle.hasRef() : false,
      false,
      'the bound is a `ref`\'d timer: a process with a pending lookup cannot exit by natural ' +
        'drain, which is the defect FR-82 exists to remove',
    );
    realKeychainTimers.clearTimeout(handle);
  });

  test('G2: an in-flight resolution is pending until the bound expires, then settles', async () => {
    const held = new RecordingTimers('hold');
    const { store: credentials } = store({ keychain: new CountingKeychain([never]), timers: held });

    let settled = false;
    const resolution = credentials
      .resolveFor('site-manager', 'cloud')
      .then(
        () => {
          settled = true;
        },
        () => {
          settled = true;
        },
      );

    // Several turns of the loop: a resolution that was going to settle on its
    // own would have done so by now.
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    assert.equal(settled, false, 'the resolution settled without the bound expiring');
    assert.equal(held.requested.length, 1);

    held.fire();
    await resolution;
    assert.equal(settled, true, 'the bound expired and the resolution did NOT settle');
    assert.equal(held.outstanding, 0);
  });

  test('G3: a keychain that rejects after abandonment causes no unhandled rejection', async () => {
    const unhandled: unknown[] = [];
    const capture = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', capture);

    try {
      let reject: (e: Error) => void = () => {};
      const late = new Promise<string | null>((_, r) => {
        reject = r;
      });
      const keychain = new CountingKeychain([() => late]);
      const { store: credentials, warnings } = store({
        env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
        keychain,
      });

      // The bound expires first; the keychain then fails, long after this
      // process stopped caring about the answer.
      assert.equal(await credentials.resolveFor('site-manager', 'cloud'), ENV_SENTINEL);
      reject(new Error('keychain daemon went away'));
      for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

      assert.deepEqual(
        unhandled,
        [],
        'the late keychain rejection reached the process as an unhandled rejection — this is ' +
          'the crash a rejected-promise timeout design produced, and it would kill the drain ' +
          'the bound exists to unblock',
      );
      // The late failure must not be reported as a second, contradictory line.
      assert.deepEqual(warnings, [EXPECTED_WARNING]);
    } finally {
      process.off('unhandledRejection', capture);
    }
  });

  test('G4: a keychain that throws synchronously is a failure, not a crash', async () => {
    const keychain = new CountingKeychain([
      () => {
        throw new Error('keytar exploded');
      },
    ]);
    const { store: credentials, warnings, timers } = store({
      env: { [CLOUD_API_KEY_ENV]: ENV_SENTINEL },
      keychain,
    });

    assert.equal(await credentials.resolveFor('site-manager', 'cloud'), ENV_SENTINEL);
    assert.equal(warnings.length, 1);
    assert.ok(warnings[0]?.includes('keytar exploded'), warnings[0]);
    assert.ok(!warnings[0]?.includes('did not answer'), 'a failure was reported as a timeout');
    assert.equal(timers.cleared, 1, 'a failed call must clear its bound');
    assert.equal(timers.outstanding, 0);
  });

  test('G5: abandonment is signalled by AbortController, never by a rejected timer promise', () => {
    assert.ok(
      /new AbortController\(\)/.test(CREDENTIALS_SOURCE),
      'the bound no longer uses an AbortController-style abandonment',
    );
    assert.ok(
      !/reject\(new (?:Unifi)?Error/.test(CREDENTIALS_SOURCE),
      'the bound rejects a promise to signal expiry: whichever promise loses that race still ' +
        'settles, and a late rejection with no handler terminates the process',
    );
  });
});
