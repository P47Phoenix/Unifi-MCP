/**
 * The inbound bearer secret and its lifecycle (US-12; FR-64, FR-73, FR-78,
 * FR-81, NFR-19). QA cases A23, A24, B1-B10.
 *
 * Two things shape this suite.
 *
 * First, nothing here measures wall-clock time. "Constant-time comparison" is
 * asserted STRUCTURALLY — through an injected comparator spy that records what
 * the comparator was handed and how often — because a timing assertion on a
 * shared CI runner is a coin flip, and a flaky security test gets deleted.
 * `compare` is a default parameter rather than a mock because Node 20 has no
 * `mock.module`; it is the only seam FR-64's criterion can have.
 *
 * Second, every refusal is checked against a planted sentinel secret. It is not
 * enough that the message looks right: `assert.ok(!msg.includes(SENTINEL))` is
 * what makes a future edit that helpfully echoes the token fail the build.
 *
 * `readFile` is injected for every case except the one permissions test, so the
 * resolver runs with no filesystem at all.
 */
import { strict as assert } from 'node:assert';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, describe } from 'node:test';

import {
  INBOUND_SECRET_ENV_KEYS,
  MAX_SECRET_FILE_BYTES,
  MIN_SECRET_LENGTH,
  RESERVED_FILE_SUFFIX,
  bearerMatches,
  digestSecret,
  isReservedConsoleLabel,
  reservedConsoleLabelProblem,
  resolveBearerSlots,
  resolveFileBackedSecret,
  type BearerResolution,
  type NonEmptySlots,
} from '../src/serve/auth.js';

/** 41 characters, distinctive enough that a substring search cannot false-positive. */
const SENTINEL = 'sentinel-zzq7-primary-secret-value-000001';
const SENTINEL_NEXT = 'sentinel-zzq7-secondary-secret-value-0002';
const SECRET_PATH = '/run/secrets/mcp-token';
const NEXT_PATH = '/run/secrets/mcp-token-next';

const BOTH_SET_MESSAGE =
  'UNIFI_HTTP_TOKEN and UNIFI_HTTP_TOKEN_FILE are both set and only one secret can be live. Set exactly one.';
const UNREADABLE_MESSAGE =
  'UNIFI_HTTP_TOKEN_FILE=/run/secrets/mcp-token is not readable. Set it to a path this process can read, or set UNIFI_HTTP_TOKEN instead.';
const EMPTY_MESSAGE =
  'UNIFI_HTTP_TOKEN_FILE=/run/secrets/mcp-token is empty. Write the shared secret into that file, or set UNIFI_HTTP_TOKEN instead.';
const OVERSIZE_MESSAGE =
  'UNIFI_HTTP_TOKEN_FILE=/run/secrets/mcp-token is larger than the 4 KiB maximum. It should contain the shared secret and nothing else; check you have not pointed it at a certificate or a key bundle.';
const BAD_AUTH_MESSAGE =
  'UNIFI_HTTP_AUTH="Nope " must be `bearer` or `none`. `bearer` requires callers to present UNIFI_HTTP_TOKEN; `none` disables inbound authentication entirely and is accepted only on a loopback UNIFI_HTTP_BIND.';
const SHORT_PRIMARY_MESSAGE =
  'UNIFI_HTTP_TOKEN is shorter than the 32-character minimum. Generate one with `openssl rand -base64 32` or an equivalent CSPRNG; a guessable secret on a reachable port is the same as no secret.';
const SHORT_SECONDARY_MESSAGE =
  'UNIFI_HTTP_TOKEN_NEXT is shorter than the 32-character minimum. Generate one with `openssl rand -base64 32` or an equivalent CSPRNG; a guessable secret on a reachable port is the same as no secret.';

/** The header value a compliant client sends. */
function authorization(secret: string): string {
  return `Bearer ${secret}`;
}

interface ComparatorSpy {
  readonly calls: Array<readonly [number, number]>;
  readonly compare: (a: Buffer, b: Buffer) => boolean;
}

function comparatorSpy(): ComparatorSpy {
  const calls: Array<readonly [number, number]> = [];
  return {
    calls,
    compare: (a, b) => {
      calls.push([a.length, b.length]);
      return a.equals(b);
    },
  };
}

/** Asserts by exploding: no `*_FILE` variable is set, so nothing may be read. */
function forbiddenRead(path: string): Buffer {
  throw new Error(`readFile called unexpectedly for ${path}`);
}

function fakeFiles(files: Record<string, string | Buffer | Error>): (p: string) => Buffer {
  return (path) => {
    const entry = files[path];
    if (entry === undefined) throw new Error(`ENOENT: ${path}`);
    if (entry instanceof Error) throw entry;
    return Buffer.isBuffer(entry) ? entry : Buffer.from(entry, 'utf8');
  };
}

function slotsOf(resolution: BearerResolution): NonEmptySlots {
  assert.ok(resolution.auth, `expected a resolution, got ${JSON.stringify(resolution.descriptor)}`);
  assert.equal(resolution.auth.kind, 'bearer');
  assert.ok(resolution.auth.kind === 'bearer');
  return resolution.auth.slots;
}

/** Every message must name the variable and the path, and leak nothing. */
function assertNamesVariableAndPath(message: string, variable: string, path: string): void {
  assert.ok(message.includes(variable), `"${message}" does not name ${variable}`);
  assert.ok(message.includes(path), `"${message}" does not name ${path}`);
  assert.ok(!message.includes(SENTINEL), `"${message}" leaked the secret`);
}

describe('bearerMatches (FR-64)', () => {
  const slots: NonEmptySlots = [digestSecret(SENTINEL)];

  test('B1 a wrong secret returns false', () => {
    assert.equal(bearerMatches(authorization('not-the-secret-but-long-enough-000'), slots), false);
  });

  test('B1 the correct secret returns true', () => {
    assert.equal(bearerMatches(authorization(SENTINEL), slots), true);
  });

  test('B2 an absent credential returns false before any hashing', () => {
    const spy = comparatorSpy();
    assert.equal(bearerMatches(undefined, slots, spy.compare), false);
    assert.equal(spy.calls.length, 0, 'the comparator ran on an absent credential');
  });

  test('B2 a non-string credential returns false on the same path', () => {
    const spy = comparatorSpy();
    // `createHash().update(undefined)` throws, so the type check has to come
    // first; the cast reproduces a header object that is not what its type says.
    const notAString = 42 as unknown as string;
    assert.equal(bearerMatches(notAString, slots, spy.compare), false);
    assert.equal(spy.calls.length, 0);
  });

  test('B3 a strict prefix of the correct secret returns false', () => {
    assert.ok(SENTINEL.length >= MIN_SECRET_LENGTH);
    const prefix = SENTINEL.slice(0, SENTINEL.length - 1);
    assert.equal(bearerMatches(authorization(prefix), slots), false);
    // A short prefix too: hashing equalises the operands, so a near-miss and a
    // wild guess have to reach the same 32-byte comparison and the same answer.
    assert.equal(bearerMatches(authorization(SENTINEL.slice(0, 8)), slots), false);
  });

  test('B4 a superstring of the correct secret returns false', () => {
    assert.equal(bearerMatches(authorization(`${SENTINEL}x`), slots), false);
  });

  test('B5 differing lengths return false and do not throw', () => {
    // This is the known throw source: crypto.timingSafeEqual raises
    // ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH on unequal-length buffers. The design
    // avoids it by hashing BOTH operands to 32 bytes first. An implementation
    // that skips the hash throws on the first hostile request, turning a 401
    // into a 500 — and a 500 to an unauthenticated caller is a class-detection
    // oracle. The real timingSafeEqual is used here deliberately: no spy.
    for (const length of [0, 1, 31, 32, 33, 512, 16384]) {
      const guess = 'a'.repeat(length);
      assert.doesNotThrow(() => bearerMatches(authorization(guess), slots), `length ${length}`);
      assert.equal(bearerMatches(authorization(guess), slots), false, `length ${length}`);
    }
  });

  test('B6 the comparator sees two 32-byte operands, once per configured slot', () => {
    // Structural constant-time. No wall-clock timing is measured anywhere.
    const oneSlot = comparatorSpy();
    bearerMatches(authorization('short'), slots, oneSlot.compare);
    assert.deepEqual(oneSlot.calls, [[32, 32]]);

    const twoSlots: NonEmptySlots = [digestSecret(SENTINEL), digestSecret(SENTINEL_NEXT)];
    const both = comparatorSpy();
    bearerMatches(authorization('a'.repeat(4096)), twoSlots, both.compare);
    assert.deepEqual(both.calls, [
      [32, 32],
      [32, 32],
    ]);
  });

  test('B7 a match on the first slot still compares the second', () => {
    // `ok || compare(...)` would short-circuit and make the number of
    // configured slots observable — a rotation-window side channel.
    const twoSlots: NonEmptySlots = [digestSecret(SENTINEL), digestSecret(SENTINEL_NEXT)];
    const spy = comparatorSpy();
    assert.equal(bearerMatches(authorization(SENTINEL), twoSlots, spy.compare), true);
    assert.equal(spy.calls.length, 2, 'the comparison short-circuited');
  });

  test('B8 the scheme token is matched ASCII-case-insensitively and the remainder is not trimmed', () => {
    const cases: ReadonlyArray<readonly [string, boolean]> = [
      [`Bearer ${SENTINEL}`, true],
      [`bearer ${SENTINEL}`, true],
      [`BEARER ${SENTINEL}`, true],
      [`BeArEr ${SENTINEL}`, true],
      [`Bearer  ${SENTINEL}`, false],
      [`Bearer ${SENTINEL} `, false],
      [`Basic ${SENTINEL}`, false],
      [SENTINEL, false],
      ['Bearer', false],
      // A bare scheme plus its separator presents the empty credential.
      ['Bearer ', false],
      ['', false],
    ];
    for (const [header, expected] of cases) {
      assert.equal(bearerMatches(header, slots), expected, JSON.stringify(header));
    }
  });
});

describe('resolveBearerSlots rotation (FR-64, B9)', () => {
  test('B9 either secret is accepted in the same run', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN: SENTINEL, UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT },
      forbiddenRead,
    );
    assert.deepEqual(resolution.descriptor.problems, []);
    assert.equal(resolution.descriptor.slotCount, 2);
    assert.deepEqual(resolution.descriptor.sources, ['env', 'env']);

    const slots = slotsOf(resolution);
    assert.equal(bearerMatches(authorization(SENTINEL), slots), true);
    assert.equal(bearerMatches(authorization(SENTINEL_NEXT), slots), true);
  });

  test('B9 with the primary removed the secondary alone is accepted', () => {
    const resolution = resolveBearerSlots({ UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT }, forbiddenRead);
    assert.deepEqual(resolution.descriptor.problems, []);
    assert.equal(resolution.descriptor.slotCount, 1);

    const slots = slotsOf(resolution);
    assert.equal(bearerMatches(authorization(SENTINEL_NEXT), slots), true);
    assert.equal(bearerMatches(authorization(SENTINEL), slots), false);
  });
});

describe('the fail-open branch is unrepresentable (B10)', () => {
  test('B10 bearer with no secret refuses and produces no zero-slot AuthMode', () => {
    const resolution = resolveBearerSlots({ UNIFI_HTTP_AUTH: 'bearer' }, forbiddenRead);
    assert.equal(resolution.auth, null);
    assert.ok(resolution.descriptor.problems.length > 0);
    assert.equal(resolution.descriptor.slotCount, 0);
    assert.deepEqual(resolution.descriptor.sources, []);
    assert.equal(resolution.descriptor.minSlotLength, 0);
    // There is no arm of AuthMode that says "bearer, zero slots", so the
    // comparator can never be reached with an empty tuple.
    assert.equal(resolution.auth === null, true);
  });

  test('B10 every refusal path leaves auth null', () => {
    const refusals: BearerResolution[] = [
      resolveBearerSlots({ UNIFI_HTTP_AUTH: 'off' }, forbiddenRead),
      resolveBearerSlots(
        { UNIFI_HTTP_TOKEN: SENTINEL, UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
        forbiddenRead,
      ),
      resolveBearerSlots({ UNIFI_HTTP_TOKEN: 'too-short' }, forbiddenRead),
      resolveBearerSlots({ UNIFI_HTTP_TOKEN_FILE: SECRET_PATH }, fakeFiles({})),
    ];
    for (const resolution of refusals) {
      assert.ok(resolution.descriptor.problems.length > 0);
      assert.equal(resolution.auth, null);
    }
  });
});

describe('*_FILE delivery (FR-78, A24)', () => {
  test('A24 an unreadable file refuses, naming the variable and the path', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: new Error(`EACCES: ${SENTINEL}`) }),
    );
    const [problem] = resolution.descriptor.problems;
    assert.ok(problem);
    assert.equal(problem, UNREADABLE_MESSAGE);
    assertNamesVariableAndPath(problem, 'UNIFI_HTTP_TOKEN_FILE', SECRET_PATH);
    assert.equal(resolution.auth, null);
  });

  test('A24 an empty file refuses, naming the variable and the path', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: '' }),
    );
    assert.deepEqual(resolution.descriptor.problems, [EMPTY_MESSAGE]);
    assertNamesVariableAndPath(EMPTY_MESSAGE, 'UNIFI_HTTP_TOKEN_FILE', SECRET_PATH);
  });

  test('A24 a file that is empty after the newline strip refuses the same way', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: '\n' }),
    );
    assert.deepEqual(resolution.descriptor.problems, [EMPTY_MESSAGE]);
  });

  test('A24 a 5 KiB file refuses, naming the variable and the path', () => {
    const oversize = `${SENTINEL}${'x'.repeat(5 * 1024)}`;
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: oversize }),
    );
    const [problem] = resolution.descriptor.problems;
    assert.ok(problem);
    assert.equal(problem, OVERSIZE_MESSAGE);
    assertNamesVariableAndPath(problem, 'UNIFI_HTTP_TOKEN_FILE', SECRET_PATH);
  });

  test('A24 both X and X_FILE set refuses, naming both', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN: SENTINEL, UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      forbiddenRead,
    );
    assert.deepEqual(resolution.descriptor.problems, [BOTH_SET_MESSAGE]);
    assert.ok(BOTH_SET_MESSAGE.includes('UNIFI_HTTP_TOKEN '));
    assert.ok(BOTH_SET_MESSAGE.includes('UNIFI_HTTP_TOKEN_FILE'));
    assert.ok(!BOTH_SET_MESSAGE.includes(SENTINEL));
    assert.equal(resolution.auth, null);
  });

  test('A24 the secondary pair carries the identical both-set sentence', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT, UNIFI_HTTP_TOKEN_NEXT_FILE: NEXT_PATH },
      forbiddenRead,
    );
    assert.deepEqual(resolution.descriptor.problems, [
      'UNIFI_HTTP_TOKEN_NEXT and UNIFI_HTTP_TOKEN_NEXT_FILE are both set and only one secret can be live. Set exactly one.',
    ]);
  });

  test('A24 no refusal echoes the file content at any length', () => {
    const planted: ReadonlyArray<Record<string, string>> = [
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      { UNIFI_HTTP_TOKEN: SENTINEL, UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH, UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT },
    ];
    const contents = ['', SENTINEL, `${SENTINEL}${'x'.repeat(5 * 1024)}`];
    for (const env of planted) {
      for (const content of contents) {
        const resolution = resolveBearerSlots(env, fakeFiles({ [SECRET_PATH]: content }));
        for (const message of [...resolution.descriptor.problems, ...resolution.descriptor.warnings]) {
          assert.ok(!message.includes(SENTINEL), message);
          assert.ok(!message.includes(SENTINEL_NEXT), message);
        }
      }
    }
  });

  test('a secret delivered by UNIFI_HTTP_TOKEN_FILE is accepted end to end', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: SENTINEL }),
    );
    assert.deepEqual(resolution.descriptor.problems, []);
    assert.deepEqual(resolution.descriptor.sources, ['file']);
    assert.equal(bearerMatches(authorization(SENTINEL), slotsOf(resolution)), true);
  });

  test('sources record file first and environment second in resolution order', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH, UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT },
      fakeFiles({ [SECRET_PATH]: SENTINEL }),
    );
    assert.deepEqual(resolution.descriptor.sources, ['file', 'env']);
    assert.equal(resolution.descriptor.slotCount, 2);
  });
});

describe('trailing newline handling (FR-78)', () => {
  function fileValue(content: string): NonEmptySlots {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: content }),
    );
    assert.deepEqual(resolution.descriptor.problems, []);
    return slotsOf(resolution);
  }

  test('exactly one trailing newline is stripped', () => {
    assert.equal(bearerMatches(authorization(SENTINEL), fileValue(`${SENTINEL}\n`)), true);
  });

  test('a second trailing newline survives', () => {
    const slots = fileValue(`${SENTINEL}\n\n`);
    assert.equal(bearerMatches(authorization(`${SENTINEL}\n`), slots), true);
    assert.equal(bearerMatches(authorization(SENTINEL), slots), false);
  });

  test('surrounding spaces are not trimmed', () => {
    const padded = `  ${SENTINEL}  `;
    const slots = fileValue(padded);
    assert.equal(bearerMatches(authorization(padded), slots), true);
    assert.equal(bearerMatches(authorization(SENTINEL), slots), false);
  });

  test('a CRLF ending strips only the LF', () => {
    const slots = fileValue(`${SENTINEL}\r\n`);
    assert.equal(bearerMatches(authorization(`${SENTINEL}\r`), slots), true);
    assert.equal(bearerMatches(authorization(SENTINEL), slots), false);
  });
});

describe('the 4 KiB ceiling (FR-78)', () => {
  function resolveSized(byteLength: number): BearerResolution {
    return resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: Buffer.alloc(byteLength, 'a') }),
    );
  }

  test('exactly 4096 bytes is accepted', () => {
    assert.equal(MAX_SECRET_FILE_BYTES, 4096);
    const resolution = resolveSized(MAX_SECRET_FILE_BYTES);
    assert.deepEqual(resolution.descriptor.problems, []);
    assert.equal(resolution.descriptor.slotCount, 1);
  });

  test('4097 bytes is refused', () => {
    const resolution = resolveSized(MAX_SECRET_FILE_BYTES + 1);
    assert.deepEqual(resolution.descriptor.problems, [OVERSIZE_MESSAGE]);
    assert.equal(resolution.auth, null);
  });
});

describe('UNIFI_HTTP_AUTH parses fail-closed (FR-73)', () => {
  test('unset defaults to bearer', () => {
    const resolution = resolveBearerSlots({ UNIFI_HTTP_TOKEN: SENTINEL }, forbiddenRead);
    assert.equal(resolution.descriptor.mode, 'bearer');
    assert.deepEqual(resolution.descriptor.problems, []);
  });

  test('bearer is recognised after ASCII trimming and case folding', () => {
    for (const raw of ['bearer', ' bearer ', 'BEARER', '\tBearer\r\n']) {
      const resolution = resolveBearerSlots(
        { UNIFI_HTTP_AUTH: raw, UNIFI_HTTP_TOKEN: SENTINEL },
        forbiddenRead,
      );
      assert.equal(resolution.descriptor.mode, 'bearer', raw);
      assert.deepEqual(resolution.descriptor.problems, [], raw);
      assert.equal(resolution.descriptor.slotCount, 1, raw);
    }
  });

  test('none is recognised after ASCII trimming and case folding', () => {
    // "None " belongs here, not in the refusal table: §2.5.1 step (1) strips
    // trailing ASCII whitespace and step (2) folds ASCII case, so "None " and
    // " none " and "NONE" all normalise to the constant `none`. The contract's
    // §2.5 example refusal happens to echo "None ", which reads as though that
    // value were unrecognised — it is not, under the normalisation the same
    // contract pins. Flagged for US-14: if "None " really must be refused, the
    // trim in step (1) has to go, and " bearer " / " none " go with it.
    for (const raw of ['none', 'NONE', ' none ', 'None ', '\tNone\r\n']) {
      const resolution = resolveBearerSlots({ UNIFI_HTTP_AUTH: raw }, forbiddenRead);
      assert.equal(resolution.descriptor.mode, 'none', JSON.stringify(raw));
      assert.deepEqual(resolution.auth, { kind: 'none' }, JSON.stringify(raw));
      assert.deepEqual(resolution.descriptor.problems, [], JSON.stringify(raw));
    }
  });

  test('every other value is a refusal and never falls back to none', () => {
    for (const raw of ['', '  ', 'nonce', 'basic', 'token', 'off', 'false', '0', 'bearer none']) {
      const resolution = resolveBearerSlots(
        { UNIFI_HTTP_AUTH: raw, UNIFI_HTTP_TOKEN: SENTINEL },
        forbiddenRead,
      );
      assert.equal(resolution.auth, null, JSON.stringify(raw));
      assert.equal(resolution.descriptor.problems.length, 1, JSON.stringify(raw));
      // Fail-closed: an unrecognised token never resolves to `none`, which is
      // what turns a typo into an open listener.
      assert.equal(resolution.descriptor.mode, 'bearer', JSON.stringify(raw));
      assert.equal(resolution.descriptor.slotCount, 0, JSON.stringify(raw));
    }
  });

  test('the refusal echoes the raw value verbatim inside double quotes', () => {
    // Byte-for-byte the contract §2.5 sentence; only the echoed value differs,
    // because "None " is a recognised spelling of `none` (see above).
    const resolution = resolveBearerSlots({ UNIFI_HTTP_AUTH: 'Nope ' }, forbiddenRead);
    assert.deepEqual(resolution.descriptor.problems, [BAD_AUTH_MESSAGE]);
    assert.ok(BAD_AUTH_MESSAGE.startsWith('UNIFI_HTTP_AUTH="Nope " must be `bearer` or `none`.'));
  });

  test('a long value renders as a character count, never as content', () => {
    const raw = 'x'.repeat(64);
    const resolution = resolveBearerSlots({ UNIFI_HTTP_AUTH: raw }, forbiddenRead);
    const [problem] = resolution.descriptor.problems;
    assert.ok(problem);
    assert.match(problem, /UNIFI_HTTP_AUTH="\(64 characters\)"/);
    assert.ok(!problem.includes(raw));
  });
});

describe('auth=none (FR-73, architecture §5.7)', () => {
  test('resolves to the none arm with no slots and no problems', () => {
    const resolution = resolveBearerSlots({ UNIFI_HTTP_AUTH: 'none' }, forbiddenRead);
    assert.deepEqual(resolution.auth, { kind: 'none' });
    assert.equal(resolution.descriptor.mode, 'none');
    assert.equal(resolution.descriptor.slotCount, 0);
    assert.deepEqual(resolution.descriptor.sources, []);
    assert.deepEqual(resolution.descriptor.problems, []);
    assert.equal(resolution.descriptor.minSlotLength, 0);
  });

  test('token variables set alongside none are not read at all', () => {
    // forbiddenRead throwing would be the failure: no *_FILE is opened, and the
    // plaintext variable is never turned into a slot either.
    const resolution = resolveBearerSlots(
      {
        UNIFI_HTTP_AUTH: 'none',
        UNIFI_HTTP_TOKEN: SENTINEL,
        UNIFI_HTTP_TOKEN_NEXT_FILE: NEXT_PATH,
      },
      forbiddenRead,
    );
    assert.deepEqual(resolution.auth, { kind: 'none' });
    assert.equal(resolution.descriptor.slotCount, 0);
    assert.deepEqual(resolution.descriptor.sources, []);
    assert.equal(resolution.descriptor.minSlotLength, 0);
    assert.deepEqual(resolution.descriptor.problems, []);
  });
});

describe('the 32-character floor (FR-81, A23)', () => {
  const SHORT = 'a'.repeat(MIN_SECRET_LENGTH - 1);
  const EXACT = 'b'.repeat(MIN_SECRET_LENGTH);

  test('A23 a 31-character primary secret is refused', () => {
    const resolution = resolveBearerSlots({ UNIFI_HTTP_TOKEN: SHORT }, forbiddenRead);
    assert.deepEqual(resolution.descriptor.problems, [SHORT_PRIMARY_MESSAGE]);
    assert.equal(resolution.auth, null);
  });

  test('A23 a 31-character secondary secret is refused by name', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN: EXACT, UNIFI_HTTP_TOKEN_NEXT: SHORT },
      forbiddenRead,
    );
    assert.deepEqual(resolution.descriptor.problems, [SHORT_SECONDARY_MESSAGE]);
  });

  test('A23 both short yields both messages, named individually', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN: SHORT, UNIFI_HTTP_TOKEN_NEXT: SHORT },
      forbiddenRead,
    );
    assert.deepEqual(resolution.descriptor.problems, [
      SHORT_PRIMARY_MESSAGE,
      SHORT_SECONDARY_MESSAGE,
    ]);
  });

  test('A23 exactly 32 characters is accepted', () => {
    const resolution = resolveBearerSlots({ UNIFI_HTTP_TOKEN: EXACT }, forbiddenRead);
    assert.deepEqual(resolution.descriptor.problems, []);
    assert.equal(bearerMatches(authorization(EXACT), slotsOf(resolution)), true);
  });

  test('A23 a short secret delivered by *_FILE is refused too', () => {
    // validateConfig alone could never see this: it does no I/O, so the floor
    // has to be applied here, after the file has been read.
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH },
      fakeFiles({ [SECRET_PATH]: `${SHORT}\n` }),
    );
    assert.equal(resolution.auth, null);
    assert.equal(resolution.descriptor.problems.length, 1);
    const [problem] = resolution.descriptor.problems;
    assert.ok(problem);
    assert.ok(problem.includes('UNIFI_HTTP_TOKEN_FILE'));
    assert.ok(problem.includes('32-character minimum'));
    assert.ok(!problem.includes(SHORT));
  });
});

describe('the descriptor is secret-free (FR-73, NFR-19)', () => {
  test('no plaintext and no digest survives serialisation', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN_FILE: SECRET_PATH, UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT },
      fakeFiles({ [SECRET_PATH]: SENTINEL }),
    );
    const serialised = JSON.stringify(resolution.descriptor);
    const digest = digestSecret(SENTINEL);
    const nextDigest = digestSecret(SENTINEL_NEXT);

    assert.equal(serialised.includes(SENTINEL), false);
    assert.equal(serialised.includes(SENTINEL_NEXT), false);
    for (const encoded of [
      digest.toString('hex'),
      digest.toString('base64'),
      nextDigest.toString('hex'),
      nextDigest.toString('base64'),
    ]) {
      assert.equal(serialised.includes(encoded), false, encoded);
    }
    // The descriptor is an enum, two integers and two lists of strings.
    assert.deepEqual(Object.keys(resolution.descriptor).sort(), [
      'minSlotLength',
      'mode',
      'problems',
      'slotCount',
      'sources',
      'warnings',
    ]);
  });

  test('minSlotLength never leaks into a message', () => {
    const resolution = resolveBearerSlots(
      { UNIFI_HTTP_TOKEN: SENTINEL, UNIFI_HTTP_TOKEN_NEXT_FILE: NEXT_PATH },
      fakeFiles({ [NEXT_PATH]: '' }),
    );
    for (const message of [...resolution.descriptor.problems, ...resolution.descriptor.warnings]) {
      assert.equal(message.includes(String(SENTINEL.length)), false, message);
      assert.ok(!message.includes(SENTINEL), message);
    }
  });

  test('resolveBearerSlots does not mutate the environment it is handed', () => {
    const env = { UNIFI_HTTP_TOKEN: SENTINEL, UNIFI_HTTP_TOKEN_NEXT: SENTINEL_NEXT };
    const before = { ...env };
    resolveBearerSlots(env, forbiddenRead);
    assert.deepEqual(env, before);
  });
});

describe('INBOUND_SECRET_ENV_KEYS (architecture §1.4 step 6)', () => {
  test('lists exactly the four inbound-secret variables', () => {
    assert.deepEqual([...INBOUND_SECRET_ENV_KEYS].sort(), [
      'UNIFI_HTTP_TOKEN',
      'UNIFI_HTTP_TOKEN_FILE',
      'UNIFI_HTTP_TOKEN_NEXT',
      'UNIFI_HTTP_TOKEN_NEXT_FILE',
    ]);
    assert.equal(INBOUND_SECRET_ENV_KEYS.length, 4);
  });
});

describe('resolveFileBackedSecret is generic (architecture §5.15.1b)', () => {
  const CREDENTIAL_PAIR = { plain: 'UNIFI_API_KEY', file: 'UNIFI_API_KEY_FILE' } as const;

  test('applies every rule to a non-inbound pair so US-16 can reuse it', () => {
    const fromFile = resolveFileBackedSecret(
      { UNIFI_API_KEY_FILE: '/run/secrets/unifi-api-key' },
      CREDENTIAL_PAIR,
      fakeFiles({ '/run/secrets/unifi-api-key': `${SENTINEL}\n` }),
    );
    assert.equal(fromFile.value, SENTINEL);
    assert.equal(fromFile.source, 'file');
    assert.deepEqual(fromFile.problems, []);

    const fromEnv = resolveFileBackedSecret(
      { UNIFI_API_KEY: SENTINEL },
      CREDENTIAL_PAIR,
      forbiddenRead,
    );
    assert.equal(fromEnv.value, SENTINEL);
    assert.equal(fromEnv.source, 'env');

    const bothSet = resolveFileBackedSecret(
      { UNIFI_API_KEY: SENTINEL, UNIFI_API_KEY_FILE: '/run/secrets/unifi-api-key' },
      CREDENTIAL_PAIR,
      forbiddenRead,
    );
    assert.deepEqual(bothSet.problems, [
      'UNIFI_API_KEY and UNIFI_API_KEY_FILE are both set and only one secret can be live. Set exactly one.',
    ]);
    assert.equal(bothSet.value, null);

    const oversize = resolveFileBackedSecret(
      { UNIFI_API_KEY_FILE: '/run/secrets/unifi-api-key' },
      CREDENTIAL_PAIR,
      fakeFiles({ '/run/secrets/unifi-api-key': Buffer.alloc(MAX_SECRET_FILE_BYTES + 1, 'a') }),
    );
    assert.equal(oversize.value, null);
    assert.ok(oversize.problems[0]?.includes('UNIFI_API_KEY_FILE=/run/secrets/unifi-api-key'));
  });

  test('an unset pair is neither a value nor a problem', () => {
    const nothing = resolveFileBackedSecret({}, CREDENTIAL_PAIR, forbiddenRead);
    assert.equal(nothing.value, null);
    assert.equal(nothing.source, null);
    assert.deepEqual(nothing.problems, []);
    assert.deepEqual(nothing.warnings, []);
  });
});

describe('the _FILE reservation (PRD §5.15.1b)', () => {
  // The collision this predicate exists to close: `UNIFI_LOCAL_API_KEY_FILE`
  // matches LOCAL_KEY_PREFIX in src/config.ts, so it parses today as "the key
  // for a console labelled FILE", passes isKnownEnvKey, and is then silently
  // ignored by collectLocalConsoles — which derives its label set from the
  // UNIFI_LOCAL_HOST_ variables. An operator's secret is accepted and discarded.
  // Enforcement lives in config.ts and is story US-16's; this is the leaf
  // predicate and message it will consume.
  test('FILE and any label ending in _FILE are reserved', () => {
    assert.equal(isReservedConsoleLabel('FILE'), true);
    assert.equal(isReservedConsoleLabel('SITEA_FILE'), true);
    assert.equal(RESERVED_FILE_SUFFIX, '_FILE');
  });

  test('labels that merely contain FILE are unaffected', () => {
    assert.equal(isReservedConsoleLabel('FILENAME'), false);
    assert.equal(isReservedConsoleLabel('MYFILE'), false);
    assert.equal(isReservedConsoleLabel('SITEA'), false);
    assert.equal(isReservedConsoleLabel(''), false);
  });

  test('the refusal names UNIFI_LOCAL_HOST_<LABEL> and the reservation', () => {
    const message = reservedConsoleLabelProblem('FILE');
    assert.ok(message.startsWith('UNIFI_LOCAL_HOST_FILE'));
    assert.ok(message.includes('_FILE'));
    assert.ok(message.includes('UNIFI_LOCAL_API_KEY_FILE'));
    assert.match(message, /reserved/);

    const suffixed = reservedConsoleLabelProblem('SITEA_FILE');
    assert.ok(suffixed.startsWith('UNIFI_LOCAL_HOST_SITEA_FILE'));
  });
});

describe('*_FILE permissions warning (contract §3.7, A24)', () => {
  test('a group-readable secret file warns but still resolves', { skip: process.platform === 'win32' }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'unifi-auth-'));
    try {
      const path = join(dir, 'token');
      writeFileSync(path, SENTINEL, { mode: 0o644 });
      chmodSync(path, 0o644);

      // The real default readFile — this is the one case that touches disk.
      const resolution = resolveBearerSlots({ UNIFI_HTTP_TOKEN_FILE: path });

      assert.deepEqual(resolution.descriptor.problems, []);
      assert.equal(resolution.descriptor.warnings.length, 1);
      const [warning] = resolution.descriptor.warnings;
      assert.ok(warning);
      assert.ok(warning.startsWith(`UNIFI_HTTP_TOKEN_FILE=${path} is readable by group or other.`));
      assert.ok(warning.includes('Restrict it to the process user'));
      assert.ok(!warning.includes(SENTINEL));
      assert.equal(bearerMatches(authorization(SENTINEL), slotsOf(resolution)), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a 0600 secret file warns about nothing', { skip: process.platform === 'win32' }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'unifi-auth-'));
    try {
      const path = join(dir, 'token');
      writeFileSync(path, `${SENTINEL}\n`, { mode: 0o600 });
      chmodSync(path, 0o600);

      const resolution = resolveBearerSlots({ UNIFI_HTTP_TOKEN_FILE: path });
      assert.deepEqual(resolution.descriptor.warnings, []);
      assert.deepEqual(resolution.descriptor.problems, []);
      assert.equal(bearerMatches(authorization(SENTINEL), slotsOf(resolution)), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
