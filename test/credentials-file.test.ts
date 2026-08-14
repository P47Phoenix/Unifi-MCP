/**
 * US-16 — secrets by file, and the environment scrub (FR-78, NFR-31, §5.15.1b,
 * AR-9, OQ-15, Out of Scope #22, NFR-12). QA cases A24, A34, C39, S-09.
 *
 * Four things shape this suite.
 *
 * FIRST, the ordering trap is the point of the whole story, so it is asserted
 * from BOTH sides. `CredentialStore` holds a live reference to whatever
 * environment it was handed and resolves LAZILY, on the first tool call. A
 * scrub that only deletes therefore passes every startup check, binds, prints a
 * green ready line and then throws on the operator's first call. So there are
 * two tests: capture-then-delete resolves after the scrub, and delete-only
 * fails after it with the exact message an operator would see. If the second
 * ever stops failing, the first has stopped proving anything.
 *
 * SECOND, every refusal is checked against a planted sentinel. It is not enough
 * that a message names the variable and the path: `assert.ok(!msg.includes(KEY))`
 * is what makes a future edit that helpfully echoes the file's contents fail the
 * build. FR-78 permits the path and forbids the content.
 *
 * THIRD, three modules now spell the same `_FILE` rules — `src/serve/auth.ts`
 * for the inbound secret, `src/credentials.ts` for the UniFi keys, and
 * `src/config.ts` for the reservation inside the local-key family. They cannot
 * share one implementation: nothing outside `src/serve/` may import
 * `src/serve/*`, and `src/config.ts` may import neither of the others. So the
 * copies are pinned to each other here, case for case, exactly as
 * `test/serve-config.test.ts` already pins the duplicated path canonicaliser
 * and auth-mode grammar. A divergence fails the build rather than shipping.
 *
 * FOURTH, no test here may reach a real OS keychain. `keytar` is an
 * `optionalDependency` that `npm ci` installs on the macOS and Windows legs, so
 * every construction below passes `keychain: null` or an explicit stub through
 * the one new seam. Passing `undefined` would be a defect (S-09), and the
 * production path is asserted structurally instead, by reading the source.
 */
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CLOUD_API_KEY_ENV,
  SCALAR_ENV_KEYS,
  loadConfig,
  validateConfig,
  type ServerConfig,
} from '../src/config.js';
import {
  CREDENTIAL_FILE_SUFFIX,
  CredentialStore,
  MAX_CREDENTIAL_FILE_BYTES,
  captureCredentialEnv,
  credentialEnvKeys,
  credentialFileVar,
  readCredentialFile,
  resolveCredentialDelivery,
  scrubCredentialEnv,
  type CredentialStoreOptions,
  type KeytarLike,
} from '../src/credentials.js';
import {
  INBOUND_SECRET_ENV_KEYS,
  MAX_SECRET_FILE_BYTES,
  RESERVED_FILE_SUFFIX,
  isReservedConsoleLabel,
  reservedConsoleLabelProblem,
  resolveFileBackedSecret,
} from '../src/serve/auth.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** 44 characters, distinctive enough that a substring search cannot false-positive. */
const CLOUD_SENTINEL = 'sentinel-us16-cloud-api-key-value-0000000001';
const LOCAL_SENTINEL = 'sentinel-us16-local-api-key-value-0000000002';
const EDGE_SENTINEL = 'sentinel-us16-edge-api-key-value-00000000003';
const TOKEN_SENTINEL = 'sentinel-us16-inbound-shared-secret-00000004';

const CLOUD_FILE_ENV = credentialFileVar(CLOUD_API_KEY_ENV);
const LOCAL_KEY_ENV = 'UNIFI_LOCAL_API_KEY';
const LOCAL_FILE_ENV = credentialFileVar(LOCAL_KEY_ENV);
const EDGE_KEY_ENV = 'UNIFI_LOCAL_API_KEY_EDGE';
const EDGE_FILE_ENV = credentialFileVar(EDGE_KEY_ENV);

const CLOUD_PATH = '/run/secrets/unifi-api-key';
const LOCAL_PATH = '/run/secrets/unifi-local-api-key';
const EDGE_PATH = '/run/secrets/unifi-edge-api-key';

const LOCAL_HOST = '10.0.0.5';
const EDGE_HOST = '10.0.0.9';

/**
 * A `readFile` seam over an in-memory filesystem. Node 20 has no `mock.module`,
 * so a default parameter is the only seam available — and it is the better one
 * here, because the resolver then runs with no filesystem at all.
 */
function fakeReadFile(files: Record<string, string | Buffer>): (p: string) => Buffer {
  return (p: string): Buffer => {
    const found = files[p];
    if (found === undefined) throw new Error(`ENOENT: no such file or directory, open '${p}'`);
    return Buffer.isBuffer(found) ? found : Buffer.from(found, 'utf8');
  };
}

function config(env: NodeJS.ProcessEnv): ServerConfig {
  return loadConfig(env, { repoRoot: REPO_ROOT });
}

/**
 * The ONE construction site in this file, so the `keychain` field cannot be
 * omitted by accident anywhere below (S-09). `null` is the container shape:
 * no keychain path exists at all.
 */
function store(
  cfg: ServerConfig,
  env: NodeJS.ProcessEnv,
  options: Partial<CredentialStoreOptions> = {},
): { store: CredentialStore; warnings: string[] } {
  const warnings: string[] = [];
  const built = new CredentialStore(cfg, {
    env,
    warn: (m) => warnings.push(m),
    keychain: options.keychain ?? null,
  });
  return { store: built, warnings };
}

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'unifi-mcp-us16-'));
  after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// ===========================================================================
// 1. The keys arrive from the file, and the value that arrives is exact
// ===========================================================================

describe('§5.15.1b: every UniFi API key can be delivered by file', () => {
  test('A24: UNIFI_API_KEY_FILE delivers the cloud key to the credential store', async () => {
    const env = { [CLOUD_FILE_ENV]: CLOUD_PATH };
    const capture = captureCredentialEnv(
      config(env),
      env,
      fakeReadFile({ [CLOUD_PATH]: `${CLOUD_SENTINEL}\n` }),
    );

    assert.deepEqual(capture.problems, []);
    const resolved = await store(config(env), capture.env).store.resolveFor('site-manager', 'cloud');
    assert.equal(resolved, CLOUD_SENTINEL);
  });

  test('A24: UNIFI_LOCAL_API_KEY_FILE delivers the DEFAULT console key', async () => {
    const env = { UNIFI_LOCAL_HOST: LOCAL_HOST, [LOCAL_FILE_ENV]: LOCAL_PATH };
    const cfg = config(env);
    const capture = captureCredentialEnv(cfg, env, fakeReadFile({ [LOCAL_PATH]: LOCAL_SENTINEL }));

    assert.deepEqual(capture.problems, []);
    const resolved = await store(cfg, capture.env).store.resolveFor('network', 'local', LOCAL_HOST);
    assert.equal(resolved, LOCAL_SENTINEL);
  });

  test('A24: UNIFI_LOCAL_API_KEY_<LABEL>_FILE delivers that console key', async () => {
    const env = { UNIFI_LOCAL_HOST_EDGE: EDGE_HOST, [EDGE_FILE_ENV]: EDGE_PATH };
    const cfg = config(env);
    const capture = captureCredentialEnv(cfg, env, fakeReadFile({ [EDGE_PATH]: EDGE_SENTINEL }));

    assert.deepEqual(capture.problems, []);
    const resolved = await store(cfg, capture.env).store.resolveFor('network', 'local', EDGE_HOST);
    assert.equal(resolved, EDGE_SENTINEL);
  });

  test('A24: three consoles and the cloud key resolve from four separate files', async () => {
    const env = {
      [CLOUD_FILE_ENV]: CLOUD_PATH,
      UNIFI_LOCAL_HOST: LOCAL_HOST,
      [LOCAL_FILE_ENV]: LOCAL_PATH,
      UNIFI_LOCAL_HOST_EDGE: EDGE_HOST,
      [EDGE_FILE_ENV]: EDGE_PATH,
    };
    const cfg = config(env);
    const capture = captureCredentialEnv(
      cfg,
      env,
      fakeReadFile({
        [CLOUD_PATH]: CLOUD_SENTINEL,
        [LOCAL_PATH]: LOCAL_SENTINEL,
        [EDGE_PATH]: EDGE_SENTINEL,
      }),
    );
    const built = store(cfg, capture.env).store;

    assert.equal(await built.resolveFor('site-manager', 'cloud'), CLOUD_SENTINEL);
    assert.equal(await built.resolveFor('network', 'local', LOCAL_HOST), LOCAL_SENTINEL);
    assert.equal(await built.resolveFor('protect', 'local', EDGE_HOST), EDGE_SENTINEL);
  });

  test('A24: the store reads a real mounted file with no capture step', async () => {
    // The lookup-path half. `captureCredentialEnv` is what the wired startup
    // path calls; a store handed an environment that still carries the PATH
    // must still resolve, or file delivery would be accepted and discarded on
    // every shape that has not been converted yet.
    const dir = tempDir();
    const path = join(dir, 'api-key');
    writeFileSync(path, `${CLOUD_SENTINEL}\n`);

    const env = { [CLOUD_FILE_ENV]: path };
    assert.equal(await store(config(env), env).store.resolveFor('mobility', 'cloud'), CLOUD_SENTINEL);
  });

  test('FR-78: exactly one trailing newline is stripped, and nothing else', () => {
    const cases: Array<[string, string]> = [
      [`${CLOUD_SENTINEL}\n`, CLOUD_SENTINEL],
      [`${CLOUD_SENTINEL}\n\n`, `${CLOUD_SENTINEL}\n`],
      [`${CLOUD_SENTINEL}\r\n`, `${CLOUD_SENTINEL}\r`],
      [CLOUD_SENTINEL, CLOUD_SENTINEL],
      [` ${CLOUD_SENTINEL} `, ` ${CLOUD_SENTINEL} `],
      [`\t${CLOUD_SENTINEL}\n`, `\t${CLOUD_SENTINEL}`],
    ];
    for (const [written, expected] of cases) {
      const read = readCredentialFile(
        CLOUD_API_KEY_ENV,
        CLOUD_PATH,
        fakeReadFile({ [CLOUD_PATH]: written }),
      );
      assert.equal(read.value, expected, `payload ${JSON.stringify(written)}`);
      assert.equal(read.source, 'file');
    }
  });

  test('FR-78: the 4 KiB cap is on the RAW bytes, and 4096 is accepted', () => {
    const exact = 'k'.repeat(MAX_CREDENTIAL_FILE_BYTES);
    const over = 'k'.repeat(MAX_CREDENTIAL_FILE_BYTES + 1);

    const accepted = readCredentialFile(
      CLOUD_API_KEY_ENV,
      CLOUD_PATH,
      fakeReadFile({ [CLOUD_PATH]: exact }),
    );
    assert.equal(accepted.value, exact);
    assert.deepEqual(accepted.problems, []);

    const refused = readCredentialFile(
      CLOUD_API_KEY_ENV,
      CLOUD_PATH,
      fakeReadFile({ [CLOUD_PATH]: over }),
    );
    assert.equal(refused.value, null);
    assert.equal(refused.problems.length, 1);
  });

  test('FR-78: file delivery beats the environment, and the keychain beats both', async () => {
    // Both-set is a startup refusal, so this is about ORDER inside `lookup`
    // rather than about a configuration an operator should ever reach.
    const env = { [CLOUD_FILE_ENV]: CLOUD_PATH };
    const dir = tempDir();
    const path = join(dir, 'ordered-key');
    writeFileSync(path, EDGE_SENTINEL);

    const fromFile = store(config(env), { [CLOUD_FILE_ENV]: path, [CLOUD_API_KEY_ENV]: LOCAL_SENTINEL });
    assert.equal(await fromFile.store.resolveFor('site-manager', 'cloud'), EDGE_SENTINEL);

    const keychain: KeytarLike = { getPassword: async () => CLOUD_SENTINEL };
    const fromKeychain = store(
      config(env),
      { [CLOUD_FILE_ENV]: path, [CLOUD_API_KEY_ENV]: LOCAL_SENTINEL },
      { keychain },
    );
    assert.equal(await fromKeychain.store.resolveFor('site-manager', 'cloud'), CLOUD_SENTINEL);
  });
});

// ===========================================================================
// 2. The delivery refusals name the variable and the path — never the content
// ===========================================================================

describe('A24: a *_FILE that cannot deliver is a refusal naming the variable and the path', () => {
  const unreadable = (): ReturnType<typeof resolveCredentialDelivery> =>
    resolveCredentialDelivery({ [CLOUD_FILE_ENV]: CLOUD_PATH }, CLOUD_API_KEY_ENV, fakeReadFile({}));

  test('unreadable', () => {
    const resolved = unreadable();
    assert.equal(resolved.value, null);
    assert.deepEqual(resolved.problems, [
      `${CLOUD_FILE_ENV}=${CLOUD_PATH} is not readable. Set it to a path this process can read, ` +
        `or set ${CLOUD_API_KEY_ENV} instead.`,
    ]);
  });

  test('empty, and empty after the trailing-newline strip', () => {
    for (const payload of ['', '\n']) {
      const resolved = resolveCredentialDelivery(
        { [LOCAL_FILE_ENV]: LOCAL_PATH },
        LOCAL_KEY_ENV,
        fakeReadFile({ [LOCAL_PATH]: payload }),
      );
      assert.equal(resolved.value, null);
      assert.deepEqual(resolved.problems, [
        `${LOCAL_FILE_ENV}=${LOCAL_PATH} is empty. Write the API key into that file, or set ` +
          `${LOCAL_KEY_ENV} instead.`,
      ]);
    }
  });

  test('larger than 4 KiB', () => {
    const resolved = resolveCredentialDelivery(
      { [EDGE_FILE_ENV]: EDGE_PATH },
      EDGE_KEY_ENV,
      fakeReadFile({ [EDGE_PATH]: `${EDGE_SENTINEL}${'x'.repeat(5120)}` }),
    );
    assert.equal(resolved.value, null);
    assert.deepEqual(resolved.problems, [
      `${EDGE_FILE_ENV}=${EDGE_PATH} is larger than the 4 KiB maximum. It should contain the ` +
        `API key and nothing else; check you have not pointed it at a certificate or a key bundle.`,
    ]);
  });

  test('both X and X_FILE set — the ambiguity is not resolved silently', () => {
    const resolved = resolveCredentialDelivery(
      { [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL, [CLOUD_FILE_ENV]: CLOUD_PATH },
      CLOUD_API_KEY_ENV,
      fakeReadFile({ [CLOUD_PATH]: EDGE_SENTINEL }),
    );
    assert.equal(resolved.value, null, 'neither delivery may win by accident');
    assert.deepEqual(resolved.problems, [
      `${CLOUD_API_KEY_ENV} and ${CLOUD_FILE_ENV} are both set and only one API key can be live. ` +
        `Set exactly one.`,
    ]);
  });

  test('FR-78: both X and X_FILE set is a FATAL startup refusal, before any file is opened', () => {
    const env = {
      [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL,
      [CLOUD_FILE_ENV]: CLOUD_PATH,
      UNIFI_LOCAL_HOST: LOCAL_HOST,
      [LOCAL_KEY_ENV]: LOCAL_SENTINEL,
      [LOCAL_FILE_ENV]: LOCAL_PATH,
    };
    const cfg = config(env);
    const validation = validateConfig(cfg, env);

    assert.equal(validation.ok, false);
    assert.deepEqual(validation.mutuallyExclusiveOptions, [
      `${CLOUD_API_KEY_ENV} and ${CLOUD_FILE_ENV} are both set and only one API key can be live. ` +
        `Set exactly one.`,
      `${LOCAL_KEY_ENV} and ${LOCAL_FILE_ENV} are both set and only one API key can be live. ` +
        `Set exactly one.`,
    ]);
    for (const message of validation.errors) {
      assert.ok(!message.includes(CLOUD_SENTINEL));
      assert.ok(!message.includes(LOCAL_SENTINEL));
    }
  });

  test('A24: no refusal or warning echoes a single byte of the file', () => {
    const oversize = `${CLOUD_SENTINEL}${'x'.repeat(5120)}`;
    const messages: string[] = [];
    for (const payload of [oversize, `${CLOUD_SENTINEL}\n`]) {
      const read = readCredentialFile(
        CLOUD_API_KEY_ENV,
        CLOUD_PATH,
        fakeReadFile({ [CLOUD_PATH]: payload }),
      );
      messages.push(...read.problems, ...read.warnings);
    }
    messages.push(...unreadable().problems);

    assert.ok(messages.length >= 2, 'the corpus is empty, so this assertion proves nothing');
    for (const message of messages) {
      assert.ok(!message.includes(CLOUD_SENTINEL), `message echoed the file content: ${message}`);
      assert.ok(message.includes(CLOUD_FILE_ENV), `message names no remedy variable: ${message}`);
      assert.ok(message.includes(CLOUD_PATH), `message names no path: ${message}`);
    }
  });

  test('FR-78 §3.7: a group-readable secret file WARNS and is still delivered', (t) => {
    if (process.platform === 'win32') {
      t.skip('POSIX mode bits are meaningless on Windows; the implementation returns early');
      return;
    }
    const dir = tempDir();
    const path = join(dir, 'group-readable-key');
    writeFileSync(path, CLOUD_SENTINEL);
    chmodSync(path, 0o644);

    const read = readCredentialFile(CLOUD_API_KEY_ENV, path);
    assert.equal(read.value, CLOUD_SENTINEL, 'a wide mode is a warning, never a refusal');
    assert.deepEqual(read.problems, []);
    assert.deepEqual(read.warnings, [
      `${CLOUD_FILE_ENV}=${path} is readable by group or other. Restrict it to the process user; ` +
        `a secret file on a shared volume is the exposure the *_FILE mechanism exists to avoid.`,
    ]);

    chmodSync(path, 0o600);
    assert.deepEqual(readCredentialFile(CLOUD_API_KEY_ENV, path).warnings, []);
  });

  test('the lazy path reports a delivery problem on stderr rather than failing silently', async () => {
    const env = { [CLOUD_FILE_ENV]: CLOUD_PATH };
    const built = store(config(env), env);

    await assert.rejects(
      () => built.store.resolveFor('site-manager', 'cloud'),
      (e: Error) => e.message.includes('No cloud API key is configured'),
    );
    assert.equal(built.warnings.length, 1);
    assert.ok(built.warnings[0]?.includes(CLOUD_FILE_ENV));
    assert.ok(built.warnings[0]?.includes(CLOUD_PATH));
    assert.ok(!built.warnings[0]?.includes(CLOUD_SENTINEL));
  });
});

// ===========================================================================
// 3. The `_FILE` reservation inside the local-key family
// ===========================================================================

describe('§5.15.1b: the _FILE suffix is reserved across UNIFI_LOCAL_API_KEY_*', () => {
  test('UNIFI_LOCAL_API_KEY_FILE alone is the DEFAULT console key, not a console named FILE', async () => {
    const env = { UNIFI_LOCAL_HOST: LOCAL_HOST, [LOCAL_FILE_ENV]: LOCAL_PATH };
    const cfg = config(env);
    const validation = validateConfig(cfg, env);

    // (i) it is accepted by the unknown-key check ...
    assert.deepEqual(validation.unknownEnvKeys, []);
    // (ii) ... it does NOT invent a console labelled FILE ...
    assert.deepEqual(
      cfg.localConsoles.map((c) => c.label),
      ['default'],
    );
    // (iii) ... the default console counts as credentialed, so the service is
    // enabled rather than refused with "no local console has a key" ...
    assert.equal(cfg.localConsoles[0]?.hasApiKey, true);
    assert.ok(cfg.enabledServices.has('network'));
    assert.equal(validation.ok, true);
    // (iv) ... and it is actually READ. This is the criterion today's code
    // fails: accepted by the unknown-key check and then never read.
    const capture = captureCredentialEnv(cfg, env, fakeReadFile({ [LOCAL_PATH]: LOCAL_SENTINEL }));
    assert.equal(
      await store(cfg, capture.env).store.resolveFor('network', 'local', LOCAL_HOST),
      LOCAL_SENTINEL,
    );
  });

  test('a console labelled FILE is REFUSED, naming UNIFI_LOCAL_HOST_<LABEL> and the reservation', () => {
    for (const label of ['FILE', 'EDGE_FILE', 'A_B_FILE']) {
      const env = { [`UNIFI_LOCAL_HOST_${label}`]: EDGE_HOST, [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL };
      const cfg = config(env);
      const validation = validateConfig(cfg, env);

      assert.equal(validation.ok, false, `${label} started cleanly`);
      assert.ok(
        validation.errors.includes(reservedConsoleLabelProblem(label)),
        `${label}: ${JSON.stringify(validation.errors)}`,
      );
      assert.deepEqual(
        cfg.localConsoles.map((c) => c.label),
        [],
        `${label}: an unaddressable console must not be created`,
      );
      // A refusal, not a warning — the alternative is a console whose key can
      // be set but never read.
      assert.ok(!validation.warnings.some((w) => w.includes(`UNIFI_LOCAL_HOST_${label}`)));
    }
  });

  test('the reservation is the SUFFIX: FILENAME and MYFILE are ordinary labels', () => {
    for (const label of ['FILENAME', 'MYFILE', 'FILES', 'PROFILE']) {
      const env = {
        [`UNIFI_LOCAL_HOST_${label}`]: EDGE_HOST,
        [`UNIFI_LOCAL_API_KEY_${label}`]: EDGE_SENTINEL,
      };
      const cfg = config(env);
      assert.deepEqual(
        cfg.localConsoles.map((c) => c.label),
        [label],
      );
      assert.equal(validateConfig(cfg, env).ok, true, label);
    }
  });

  test('AC-4: every §5.15.1b variable set alone is a recognised key, never a fatal', () => {
    const rows: Array<Record<string, string>> = [
      { [CLOUD_FILE_ENV]: CLOUD_PATH },
      { UNIFI_LOCAL_HOST: LOCAL_HOST, [LOCAL_FILE_ENV]: LOCAL_PATH },
      { UNIFI_LOCAL_HOST_EDGE: EDGE_HOST, [EDGE_FILE_ENV]: EDGE_PATH },
    ];
    for (const env of rows) {
      const validation = validateConfig(config(env), env);
      assert.deepEqual(
        validation.unknownEnvKeys,
        [],
        `${JSON.stringify(env)} — a §5.15.1b row that is read but not registered makes the ` +
          `server refuse to start for exactly the operators who followed the documentation`,
      );
      assert.equal(validation.ok, true, JSON.stringify(validation.errors));
    }
  });

  test('the two fixed §5.15.1b rows are registered in SCALAR_ENV_KEYS', () => {
    assert.ok(SCALAR_ENV_KEYS.includes(CLOUD_FILE_ENV));
    assert.ok(SCALAR_ENV_KEYS.includes(LOCAL_FILE_ENV));
  });
});

// ===========================================================================
// 4. The three copies of the `_FILE` rules agree
// ===========================================================================

describe('the duplicated _FILE rules are pinned to each other', () => {
  test('the suffix and the 4 KiB cap are the same in auth.ts and credentials.ts', () => {
    assert.equal(CREDENTIAL_FILE_SUFFIX, RESERVED_FILE_SUFFIX);
    assert.equal(MAX_CREDENTIAL_FILE_BYTES, MAX_SECRET_FILE_BYTES);
  });

  test("config.ts's reservation refusal is auth.ts's, character for character", () => {
    for (const label of ['FILE', 'EDGE_FILE', 'A_FILE']) {
      const env = { [`UNIFI_LOCAL_HOST_${label}`]: EDGE_HOST };
      const errors = validateConfig(config(env), env).errors;
      assert.ok(errors.includes(reservedConsoleLabelProblem(label)), label);
    }
  });

  test("config.ts's reserved-label predicate is auth.ts's, over the same table", () => {
    const labels = ['FILE', 'EDGE_FILE', 'A_B_FILE', 'FILENAME', 'MYFILE', 'EDGE', 'file', '_FILE'];
    for (const label of labels) {
      const env = { [`UNIFI_LOCAL_HOST_${label}`]: EDGE_HOST };
      const created = config(env).localConsoles.some((c) => c.label === label);
      assert.equal(
        created,
        !isReservedConsoleLabel(label),
        `${label}: config.ts and auth.ts disagree about the reservation`,
      );
    }
  });

  test('the credential resolver and the inbound resolver agree case for case', () => {
    const pair = { plain: CLOUD_API_KEY_ENV, file: CLOUD_FILE_ENV };
    const scenarios: Array<{ name: string; env: NodeJS.ProcessEnv; files: Record<string, string> }> =
      [
        { name: 'neither set', env: {}, files: {} },
        { name: 'env only', env: { [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL }, files: {} },
        { name: 'empty env value', env: { [CLOUD_API_KEY_ENV]: '' }, files: {} },
        {
          name: 'file only',
          env: { [CLOUD_FILE_ENV]: CLOUD_PATH },
          files: { [CLOUD_PATH]: `${CLOUD_SENTINEL}\n` },
        },
        { name: 'file unreadable', env: { [CLOUD_FILE_ENV]: CLOUD_PATH }, files: {} },
        {
          name: 'file empty',
          env: { [CLOUD_FILE_ENV]: CLOUD_PATH },
          files: { [CLOUD_PATH]: '\n' },
        },
        {
          name: 'file oversize',
          env: { [CLOUD_FILE_ENV]: CLOUD_PATH },
          files: { [CLOUD_PATH]: 'x'.repeat(MAX_SECRET_FILE_BYTES + 1) },
        },
        {
          name: 'file at the cap',
          env: { [CLOUD_FILE_ENV]: CLOUD_PATH },
          files: { [CLOUD_PATH]: 'x'.repeat(MAX_SECRET_FILE_BYTES) },
        },
        {
          name: 'both set',
          env: { [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL, [CLOUD_FILE_ENV]: CLOUD_PATH },
          files: { [CLOUD_PATH]: CLOUD_SENTINEL },
        },
        { name: 'empty file path', env: { [CLOUD_FILE_ENV]: '' }, files: {} },
      ];

    for (const { name, env, files } of scenarios) {
      const read = fakeReadFile(files);
      const mine = resolveCredentialDelivery(env, CLOUD_API_KEY_ENV, read);
      const theirs = resolveFileBackedSecret(env, pair, read);

      assert.equal(mine.value, theirs.value, `${name}: value`);
      assert.equal(mine.source, theirs.source, `${name}: source`);
      assert.equal(mine.problems.length, theirs.problems.length, `${name}: problem count`);
      assert.equal(mine.warnings.length, theirs.warnings.length, `${name}: warning count`);
      for (const message of mine.problems) {
        assert.ok(message.startsWith(CLOUD_FILE_ENV) || message.startsWith(CLOUD_API_KEY_ENV), name);
      }
    }
  });
});

// ===========================================================================
// 5. Capture-then-delete: the scrub, and the trap it exists to avoid
// ===========================================================================

describe('A34 / NFR-31: the environment is scrubbed once the keys are captured', () => {
  const planted = (): NodeJS.ProcessEnv => ({
    [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL,
    UNIFI_LOCAL_HOST: LOCAL_HOST,
    [LOCAL_KEY_ENV]: LOCAL_SENTINEL,
    UNIFI_LOCAL_HOST_EDGE: EDGE_HOST,
    [EDGE_FILE_ENV]: EDGE_PATH,
    UNIFI_HTTP_TOKEN: TOKEN_SENTINEL,
    UNIFI_CONSOLE_ID: 'console-1234',
  });

  const captureFrom = (env: NodeJS.ProcessEnv) =>
    captureCredentialEnv(config(env), env, fakeReadFile({ [EDGE_PATH]: EDGE_SENTINEL }));

  test('A34: after the scrub no credential variable and no sentinel survives', () => {
    const env = planted();
    const capture = captureFrom(env);
    scrubCredentialEnv(env, [...capture.variables, ...INBOUND_SECRET_ENV_KEYS]);

    for (const name of [...capture.variables, ...INBOUND_SECRET_ENV_KEYS]) {
      assert.equal(env[name], undefined, `${name} survived the scrub`);
    }
    for (const [name, value] of Object.entries(env)) {
      for (const sentinel of [CLOUD_SENTINEL, LOCAL_SENTINEL, EDGE_SENTINEL, TOKEN_SENTINEL]) {
        assert.ok(!value?.includes(sentinel), `${name} still carries a planted secret`);
      }
    }
    // Non-credential configuration is untouched: the scrub is targeted, not a
    // blanket wipe of `UNIFI_*`.
    assert.equal(env.UNIFI_LOCAL_HOST, LOCAL_HOST);
    assert.equal(env.UNIFI_CONSOLE_ID, 'console-1234');
  });

  test('A34: the FIRST tool call after the scrub still resolves every key', async () => {
    const env = planted();
    const cfg = config(env);
    const capture = captureFrom(env);
    const built = store(cfg, capture.env).store;

    // The store exists but has resolved NOTHING yet — `lookup` is lazy. The
    // scrub happens here, between construction and first use, exactly as
    // `buildRuntimeCore` orders it.
    scrubCredentialEnv(env, [...capture.variables, ...INBOUND_SECRET_ENV_KEYS]);

    assert.equal(await built.resolveFor('site-manager', 'cloud'), CLOUD_SENTINEL);
    assert.equal(await built.resolveFor('network', 'local', LOCAL_HOST), LOCAL_SENTINEL);
    assert.equal(await built.resolveFor('protect', 'local', EDGE_HOST), EDGE_SENTINEL);
  });

  test('A34: a DELETE-ONLY scrub starts clean and throws on that first call', async () => {
    // The naive ordering, asserted so the test above cannot pass for the wrong
    // reason. `CredentialStore` holds a LIVE reference to whatever it was
    // handed, so scrubbing the object it is reading empties it underneath.
    const env = planted();
    const built = store(config(env), env).store;
    scrubCredentialEnv(env, [...credentialEnvKeys(config(env)), ...INBOUND_SECRET_ENV_KEYS]);

    await assert.rejects(
      () => built.resolveFor('site-manager', 'cloud'),
      (e: Error) => e.message.includes('No cloud API key is configured'),
    );
  });

  test('A34: the capture object is not process.env, and carries only resolved keys', () => {
    const env = planted();
    const capture = captureFrom(env);

    assert.notEqual(capture.env as object, process.env as object);
    assert.notEqual(capture.env as object, env as object);
    assert.deepEqual(Object.keys(capture.env).sort(), [
      CLOUD_API_KEY_ENV,
      EDGE_KEY_ENV,
      LOCAL_KEY_ENV,
    ].sort());
    // The PATH variables do not travel into the store: they were resolved once
    // and are the scrub's business, not the store's.
    assert.equal(capture.env[EDGE_FILE_ENV], undefined);
  });

  test('credentialEnvKeys names both spellings of every account', () => {
    const env = planted();
    assert.deepEqual(credentialEnvKeys(config(env)), [
      CLOUD_API_KEY_ENV,
      CLOUD_FILE_ENV,
      LOCAL_KEY_ENV,
      LOCAL_FILE_ENV,
      EDGE_KEY_ENV,
      EDGE_FILE_ENV,
    ]);
  });

  test('scrubCredentialEnv reports what it removed and touches nothing else', () => {
    const env: NodeJS.ProcessEnv = { A: '1', B: '2' };
    assert.deepEqual(scrubCredentialEnv(env, ['A', 'MISSING']), ['A']);
    assert.deepEqual(env, { B: '2' });
    assert.deepEqual(scrubCredentialEnv(env, ['A']), [], 'a second scrub is a no-op');
  });

  test('C39: nothing here mutates process.env', () => {
    const before = JSON.stringify(process.env);
    const env = planted();
    const capture = captureFrom(env);
    scrubCredentialEnv(env, capture.variables);

    assert.equal(JSON.stringify(process.env), before);
    assert.equal(process.env[CLOUD_API_KEY_ENV], undefined);
  });
});

// ===========================================================================
// 6. The keychain seam — one optional field, one memoisation point
// ===========================================================================

describe('the keychain seam (architecture §10.3, the third bounded exception)', () => {
  test('an injected keychain is consulted once per account and its value wins', async () => {
    const calls: Array<[string, string]> = [];
    const keychain: KeytarLike = {
      getPassword: async (service, account) => {
        calls.push([service, account]);
        return CLOUD_SENTINEL;
      },
    };
    const env = { [CLOUD_API_KEY_ENV]: LOCAL_SENTINEL };
    const built = store(config(env), env, { keychain }).store;

    assert.equal(await built.resolveFor('site-manager', 'cloud'), CLOUD_SENTINEL);
    assert.equal(await built.resolveFor('mobility', 'cloud'), CLOUD_SENTINEL);
    assert.deepEqual(calls, [['unifi-mcp', CLOUD_API_KEY_ENV]], 'the per-account cache is intact');
  });

  test('keychain: null takes the environment path and warns exactly as an absent keytar does', async () => {
    const env = { [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL };
    const built = store(config(env), env);

    assert.equal(await built.store.resolveFor('site-manager', 'cloud'), CLOUD_SENTINEL);
    assert.equal(built.warnings.length, 1);
    assert.ok(built.warnings[0]?.includes('OS keychain storage is not in use'));
  });

  test('a throwing keychain falls back to the environment and says so', async () => {
    const keychain: KeytarLike = {
      getPassword: async () => {
        throw new Error('the login keychain is locked');
      },
    };
    const env = { [CLOUD_API_KEY_ENV]: CLOUD_SENTINEL };
    const built = store(config(env), env, { keychain });

    assert.equal(await built.store.resolveFor('site-manager', 'cloud'), CLOUD_SENTINEL);
    assert.ok(built.warnings.some((w) => w.includes('the login keychain is locked')));
  });

  test('the field is consumed at the ONE existing memoisation point', () => {
    // Structural, because `undefined` — the production value — must never be
    // exercised in a test: `npm ci` installs keytar on the macOS and Windows
    // legs, and a store built with `undefined` there queries a real login
    // keychain. This asserts the shape of the production path instead.
    const source = readFileSync(join(REPO_ROOT, 'src/credentials.ts'), 'utf8');
    assert.equal(
      (source.match(/if \(this\.keytar !== undefined\) return this\.keytar;/g) ?? []).length,
      1,
    );
    assert.equal((source.match(/this\.keytar = options\.keychain;/g) ?? []).length, 1);
    assert.equal(
      (source.match(/await import\(moduleName\)/g) ?? []).length,
      1,
      'the dynamic import must remain the only production keychain load',
    );
  });
});

// ===========================================================================
// 7. Out of Scope #22 — the credential path never reads argv
// ===========================================================================

describe('Out of Scope #22: no credential ever arrives on the command line', () => {
  const SRC = join(REPO_ROOT, 'src');

  function sourceFiles(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(full);
      return entry.name.endsWith('.ts') ? [full] : [];
    });
  }

  test('src/credentials.ts and the resolver seam of src/serve/auth.ts never read process.argv', () => {
    for (const file of ['src/credentials.ts', 'src/serve/auth.ts']) {
      const source = readFileSync(join(REPO_ROOT, file), 'utf8');
      assert.equal(source.includes('process.argv'), false, `${file} reads process.argv`);
    }
  });

  test('every process.argv read in src/ is a valueless mode flag', () => {
    // Two permitted forms, not one.
    //
    // The mode flags are the original pair and carry no value. `process.argv[1]`
    // was ADDED by US-18 and is the auto-run guard architecture §1.3 mandates:
    // `import.meta.url === pathToFileURL(process.argv[1] ?? '').href`, which is
    // what stops importing `src/index.ts` from starting a server and hijacking
    // the test runner's signal handlers.
    //
    // Permitting it does not widen what this scan protects. Out of Scope #22 is
    // about a SECRET arriving on the command line; `argv[1]` is the entry path
    // Node itself put there, is never operator-supplied content, and is compared
    // against a module URL rather than read as a value. The normative half of
    // the requirement — that `src/credentials.ts` and `src/serve/auth.ts`
    // contain no occurrence of `argv` at all — is asserted unchanged above.
    const permitted = /process\.argv\.includes\('--(?:selftest|healthcheck)'\)|process\.argv\[1\]/g;
    let reads = 0;
    for (const file of sourceFiles(SRC)) {
      const source = readFileSync(file, 'utf8');
      const total = (source.match(/process\.argv/g) ?? []).length;
      const allowed = (source.match(permitted) ?? []).length;
      assert.equal(
        total,
        allowed,
        `${file} reads process.argv in a form other than --selftest/--healthcheck: argv is ` +
          `visible in ps, /proc/<pid>/cmdline and docker inspect`,
      );
      reads += total;
    }
    assert.ok(reads > 0, 'the scan matched nothing, so it proves nothing');
  });

  test('a secret passed as an argument is neither accepted nor echoed', () => {
    const clean = {
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('UNIFI_'))),
      // A server with NO console configured now STARTS (runtime per-call
      // console selection), so it is no longer usable as this fixture's
      // deterministic refusal. `UNIFI_MCP_TRANSPORT=http` with no
      // UNIFI_HTTP_TOKEN still refuses fast, for a reason unrelated to
      // console configuration and to the argv/env behaviour under test here.
      UNIFI_MCP_TRANSPORT: 'http',
    } as NodeJS.ProcessEnv;
    const run = (args: string[]): { status: number | null; stderr: string; stdout: string } => {
      const child = spawnSync(
        process.execPath,
        ['--import', 'tsx', join(REPO_ROOT, 'src/index.ts'), ...args],
        { cwd: REPO_ROOT, env: clean, encoding: 'utf8', timeout: 45_000 },
      );
      return { status: child.status, stderr: child.stderr, stdout: child.stdout };
    };

    const without = run([]);
    const withArgs = run([CLOUD_SENTINEL, `--token=${CLOUD_SENTINEL}`]);

    assert.equal(withArgs.status, without.status, 'the argument changed the startup outcome');
    assert.equal(withArgs.stderr, without.stderr, 'the argument changed the startup output');
    assert.equal(without.status, 1, 'the fixture is meant to refuse; it did not');
    assert.ok(!withArgs.stderr.includes(CLOUD_SENTINEL), 'the argument was echoed on stderr');
    assert.ok(!withArgs.stdout.includes(CLOUD_SENTINEL), 'the argument was echoed on stdout');
  });
});

// ===========================================================================
// 8. The module doc says what the module now does
// ===========================================================================

test('the credentials module doc states that a mounted read is still a read', () => {
  const doc = readFileSync(join(REPO_ROOT, 'src/credentials.ts'), 'utf8').split('*/')[0] ?? '';
  assert.ok(doc.includes('The server NEVER writes a key to disk'), 'invariant 1 must survive');
  assert.ok(doc.includes('is a READ'), 'the doc must resolve the apparent contradiction');
  assert.ok(doc.includes('FR-16'), 'invariant 2 must survive');
});
