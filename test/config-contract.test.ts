/**
 * US-26, half one — the configuration CONTRACT, parsed from the normative
 * tables rather than copied out of them (QA cases A4–A8, A22, A33).
 *
 * ## The one property this file exists for
 *
 * "A variable added to the code without a row, or a row without a
 * registration, fails the build rather than the operator's server."
 *
 * That sentence is a DRIFT DETECTOR, and a drift detector is only real if both
 * of its inputs are live. `validateConfig` treats an unrecognised `UNIFI_*` key
 * as a FATAL error, not a warning (`isKnownEnvKey`), so a serving variable that
 * exists in the code but not in `SCALAR_ENV_KEYS` makes the server refuse to
 * start for exactly the operators who followed the documentation — they set the
 * documented variable and get a fatal error naming their own variable as
 * unrecognised. The failure is therefore a DOCUMENTATION-vs-CODE divergence,
 * and no test that hard-codes either side can see it.
 *
 * So: nothing below contains a hand-copied list of variable names. §5.15.1 and
 * §5.15.1b of `docs/prd.md` are PARSED, at test time, by the parse contract
 * FR-63 states, and cross-referenced against the live `SCALAR_ENV_KEYS` /
 * `SERVING_ENV_KEYS` exports. Add a row and forget the registration, or add a
 * registration and forget the row, and this file goes red.
 *
 * ## Why the source file is one constant
 *
 * `PARSE_SOURCE` below names `docs/prd.md`. FR-63 makes that the canonical
 * source *"once E-17 has landed"* — E-17 is US-04's PRD reconciliation, Wave A.
 * Before it, the tables lived in the reconciliation spec and the both-directions
 * check would have been asserted against the wrong document. The dependency is
 * satisfied; the constant records where the answer comes from so a future move
 * is one edit and not a search.
 *
 * ## Fail, don't fall back
 *
 * `parseVariableTable` THROWS when the heading is missing, when the table has no
 * body rows, or when any body row fails the field-1 pattern. It must not fall
 * back to a built-in list, must not skip the row and must not warn: a silent
 * fallback restores exactly the hand-copied array this file replaces, while
 * still printing green. `test/fixtures/env-matrix.json` proves all three
 * failures fire, and proves the cross-reference reports drift in BOTH
 * directions — which is what converts this from "a test that passes" into "a
 * test that can fail" (A6).
 *
 * ## Hygiene
 *
 * Every case builds its own `env` object literal. Nothing here reads or mutates
 * `process.env`, so a variable exported on a developer's machine can neither
 * mask a drift nor invent one. `validateConfig` is always handed the SAME
 * `ServerConfig` instance `loadConfig` returned — the parse complaints live in a
 * WeakMap keyed on config identity and a fresh object yields none.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, describe } from 'node:test';

import {
  loadConfig,
  redactedSummary,
  SCALAR_ENV_KEYS,
  SERVING_ENV_KEYS,
  validateConfig,
  type ServerConfig,
} from '../src/config.js';
import { resolveBearerSlots } from '../src/serve/auth.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * The canonical parse source, carried as ONE constant (A4's mechanism).
 *
 * FR-63 names `docs/prd.md` once E-17 has landed. It has (US-04, Wave A).
 */
const PARSE_SOURCE = join(REPO_ROOT, 'docs', 'prd.md');

/** §5.15.1 — the serving-transport family FR-63 closes. */
const SERVING_HEADING = /^#{2,4}\s+5\.15\.1\b/;

/**
 * §5.15.1b — the credential file-delivery table, a SEPARATE anchor.
 *
 * The two are disjoint by construction: `\b` between `1` and `b` is not a word
 * boundary, so `SERVING_HEADING` cannot match the `5.15.1b` heading. §5.15.1's
 * own scope note is explicit that "a test reading §5.15.1 as the
 * serving-transport family must not read §5.15.1b rows into it", and the
 * set-equality assertion below would fail loudly if it did.
 */
const CREDENTIAL_HEADING = /^#{2,4}\s+5\.15\.1b\b/;

// ---------------------------------------------------------------------------
// The parser — FR-63's stated contract, and nothing more
// ---------------------------------------------------------------------------

/** Field 1: a backticked, fully-spelled variable name. */
const LITERAL_NAME = /^`(UNIFI_[A-Z0-9_]+)`$/;

/**
 * Field 1, template form: `UNIFI_LOCAL_API_KEY_<LABEL>_FILE`.
 *
 * DEVIATION FROM A4'S LITERAL WORDING, stated rather than buried. A4 gives one
 * field-1 pattern and says any row failing it FAILS the test. §5.15.1b's third
 * row is a template — it names a FAMILY, and §5.15.1b itself says that row is
 * "matched by the local-key rule" rather than registered as a literal key. A
 * parser admitting only the literal pattern therefore cannot read the document
 * it is pointed at. The contract is widened by exactly one alternative, the
 * alternative is CLASSIFIED (`kind: 'template'`) rather than silently folded
 * into the literal set, and a row matching neither still fails. The template's
 * obligation is asserted separately, by substitution, in section 2.
 */
const TEMPLATE_NAME = /^`(UNIFI_[A-Z0-9_]*<[A-Z]+>[A-Z0-9_]*)`$/;

/** The literal field-2 spelling for "this variable has no default". */
const UNSET = '*(unset)*';
/** The literal field-2 spelling for "this variable defaults to nothing set". */
const EMPTY = '*(empty)*';

interface TableRow {
  /** Field 1: the variable name, or the template naming its family. */
  readonly name: string;
  readonly kind: 'literal' | 'template';
  /** Field 2, backticks stripped. `*(unset)*` / `*(empty)*` survive verbatim. */
  readonly default: string;
  /** For a message a human has to act on. */
  readonly line: number;
}

/**
 * Parse the first Markdown table under `heading` in `markdown`.
 *
 * The contract, verbatim from FR-63 by way of QA case A4: locate the first
 * table after the heading; end at the first blank line after the body; skip the
 * header row and the `|---|` delimiter; split each row on `|`; field 1 is the
 * variable name; field 2 stripped of backticks is the default.
 *
 * Throws — never returns partial, never returns empty, never warns.
 */
function parseVariableTable(markdown: string, heading: RegExp, where: string): TableRow[] {
  const lines = markdown.split(/\r?\n/);
  const headingIndex = lines.findIndex((line) => heading.test(line));
  if (headingIndex === -1) {
    throw new Error(
      `${where}: no heading matching ${String(heading)}. The normative table this suite is the ` +
        `drift detector for has moved or been renamed; fix the anchor, do not fall back to a list.`,
    );
  }

  let index = headingIndex + 1;
  while (index < lines.length && !(lines[index] ?? '').startsWith('|')) {
    if (heading !== CREDENTIAL_HEADING && CREDENTIAL_HEADING.test(lines[index] ?? '')) break;
    index += 1;
  }
  if (index >= lines.length || !(lines[index] ?? '').startsWith('|')) {
    throw new Error(`${where}: no table follows the heading.`);
  }

  const rows: TableRow[] = [];
  // Skip the header row and the `|---|` delimiter; stop at the first blank line.
  for (let cursor = index + 2; cursor < lines.length; cursor += 1) {
    const raw = lines[cursor] ?? '';
    if (raw.trim() === '') break;
    if (!raw.startsWith('|')) break;

    const fields = raw.split('|').slice(1, -1).map((field) => field.trim());
    const first = fields[0] ?? '';
    const second = fields[1] ?? '';

    const literal = LITERAL_NAME.exec(first);
    const template = TEMPLATE_NAME.exec(first);
    if (literal === null && template === null) {
      throw new Error(
        `${where}: line ${cursor + 1} field 1 is ${JSON.stringify(first)}, which is neither a ` +
          `backticked UNIFI_ name nor a template. The parse contract is field 1 = the variable ` +
          `name; a row that does not obey it is a defect in the document, not a row to skip.`,
      );
    }

    rows.push({
      name: (literal?.[1] ?? template?.[1]) as string,
      kind: literal === null ? 'template' : 'literal',
      default: second.replace(/`/g, ''),
      line: cursor + 1,
    });
  }

  if (rows.length === 0) throw new Error(`${where}: the table under the heading has no body rows.`);
  return rows;
}

/**
 * The cross-reference, in both directions, as ONE function.
 *
 * A6 requires the fixture canary to run through the same compare the real
 * assertion uses. Sharing the function is what makes that true rather than
 * claimed.
 */
function crossReference(
  tabled: readonly string[],
  registered: readonly string[],
): { missingFromCode: string[]; missingFromTable: string[] } {
  const inTable = new Set(tabled);
  const inCode = new Set(registered);
  return {
    missingFromCode: [...inTable].filter((name) => !inCode.has(name)).sort(),
    missingFromTable: [...inCode].filter((name) => !inTable.has(name)).sort(),
  };
}

const PRD = readFileSync(PARSE_SOURCE, 'utf8');
const SERVING_ROWS = parseVariableTable(PRD, SERVING_HEADING, 'docs/prd.md §5.15.1');
const CREDENTIAL_ROWS = parseVariableTable(PRD, CREDENTIAL_HEADING, 'docs/prd.md §5.15.1b');

const SERVING_NAMES = SERVING_ROWS.map((row) => row.name);
const CREDENTIAL_LITERALS = CREDENTIAL_ROWS.filter((r) => r.kind === 'literal').map((r) => r.name);
const CREDENTIAL_TEMPLATES = CREDENTIAL_ROWS.filter((r) => r.kind === 'template');

/**
 * `isKnownEnvKey` is not exported, and exporting it is a `src/` change this
 * verification story may not make. `validateConfig`'s `unknownEnvKeys` is the
 * same predicate observed through the public surface, which is also the surface
 * an operator meets, so it is the better probe anyway.
 */
function unknownKeysFor(env: NodeJS.ProcessEnv): string[] {
  const bearer = resolveBearerSlots(env, () => Buffer.from('x'.repeat(40)));
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: bearer.descriptor });
  return validateConfig(config, env).unknownEnvKeys;
}

/** Load + validate as one pair, keeping the WeakMap identity intact. */
function evaluate(env: NodeJS.ProcessEnv): {
  config: ServerConfig;
  errors: string[];
  warnings: string[];
} {
  const bearer = resolveBearerSlots(env, () => Buffer.from('x'.repeat(40)));
  const config = loadConfig(env, { repoRoot: REPO_ROOT, auth: bearer.descriptor });
  const validation = validateConfig(config, env);
  return { config, errors: validation.errors, warnings: validation.warnings };
}

// ===========================================================================
// 1. The parser is real, and it can fail (A6)
// ===========================================================================

interface CanaryCase {
  readonly name: string;
  readonly markdown: readonly string[];
  readonly registered: readonly string[];
  readonly expect: { readonly missingFromCode: string[]; readonly missingFromTable: string[] };
}
interface MalformedCase {
  readonly name: string;
  readonly because: string;
  readonly markdown: readonly string[];
}

const FIXTURE = JSON.parse(
  readFileSync(join(REPO_ROOT, 'test', 'fixtures', 'env-matrix.json'), 'utf8'),
) as { cases: CanaryCase[]; malformed: MalformedCase[] };

describe('the parser and the cross-reference can fail (A6)', () => {
  test('the fixture is loaded and non-trivial', () => {
    // A canary file that quietly became empty would make every case below
    // vacuous while still printing green.
    assert.ok(FIXTURE.cases.length >= 3, 'the both-directions fixture lost its cases');
    assert.ok(FIXTURE.malformed.length >= 3, 'the fail-dont-fall-back fixture lost its cases');
  });

  for (const canary of FIXTURE.cases) {
    test(`cross-reference: ${canary.name}`, () => {
      const rows = parseVariableTable(
        canary.markdown.join('\n'),
        SERVING_HEADING,
        `env-matrix.json/${canary.name}`,
      );
      const result = crossReference(
        rows.map((row) => row.name),
        canary.registered,
      );
      assert.deepEqual(result.missingFromCode, canary.expect.missingFromCode);
      assert.deepEqual(result.missingFromTable, canary.expect.missingFromTable);
    });
  }

  for (const bad of FIXTURE.malformed) {
    test(`the parser throws: ${bad.name}`, () => {
      // `because` is carried in the failure message so a reviewer who breaks
      // the parser is told what the case was protecting, not just that it went.
      assert.throws(
        () =>
          parseVariableTable(
            bad.markdown.join('\n'),
            SERVING_HEADING,
            `env-matrix.json/${bad.name}`,
          ),
        (error: unknown) => error instanceof Error,
        `the parser accepted a malformed table; ${bad.because}`,
      );
    });
  }

  test('the two headings are disjoint anchors', () => {
    // §5.15.1's own scope note forbids reading §5.15.1b rows into the
    // serving-transport family. This is that rule, asserted.
    assert.equal(SERVING_HEADING.test('#### 5.15.1b Credential file-delivery variables'), false);
    assert.equal(CREDENTIAL_HEADING.test('#### 5.15.1 Serving-transport configuration'), false);
    for (const name of CREDENTIAL_LITERALS) {
      assert.equal(
        SERVING_NAMES.includes(name),
        false,
        `${name} is a §5.15.1b row that leaked into the §5.15.1 family`,
      );
    }
  });
});

// ===========================================================================
// 2. Table -> code: every documented row is registered (A4, A5)
// ===========================================================================

describe('§5.15.1: every documented serving variable is registered (A4)', () => {
  test('the table was actually read', () => {
    // The forward assertions below are per-row `test()`s; zero rows would mean
    // zero tests and a green suite that proved nothing.
    assert.ok(SERVING_ROWS.length >= 20, `only ${SERVING_ROWS.length} rows parsed from §5.15.1`);
    assert.deepEqual(
      SERVING_ROWS.filter((row) => row.kind === 'template'),
      [],
      '§5.15.1 gained a templated row; the family is meant to be fully spelled',
    );
  });

  for (const row of SERVING_ROWS) {
    test(`${row.name} is recognised and startable`, () => {
      assert.ok(
        SCALAR_ENV_KEYS.includes(row.name),
        `docs/prd.md:${row.line} documents ${row.name} but SCALAR_ENV_KEYS does not register it. ` +
          `validateConfig fatals on an unrecognised UNIFI_* key, so every operator who follows ` +
          `the documentation gets a refusal naming their own variable.`,
      );

      // Set it ALONE against an otherwise default configuration. The value is
      // the documented default where there is one, so this asserts recognition
      // without also asserting the grammar (which A9–A14 own).
      const value = row.default === UNSET || row.default === EMPTY ? '' : row.default;
      const env: NodeJS.ProcessEnv = { [row.name]: value };
      assert.deepEqual(unknownKeysFor(env), [], `${row.name} set alone reads as an unknown key`);
      for (const message of evaluate(env).errors) {
        assert.equal(
          message.includes(`${row.name} is not recognised`),
          false,
          `${row.name} produced an unrecognised-key error: ${message}`,
        );
      }
    });
  }
});

describe('§5.15.1b: every credential file-delivery row is registered (A5)', () => {
  test('the table was actually read', () => {
    assert.ok(CREDENTIAL_ROWS.length >= 3, `only ${CREDENTIAL_ROWS.length} rows parsed`);
    assert.ok(CREDENTIAL_TEMPLATES.length >= 1, 'the templated local-key row vanished');
  });

  for (const row of CREDENTIAL_ROWS.filter((r) => r.kind === 'literal')) {
    test(`${row.name} is recognised`, () => {
      assert.ok(
        SCALAR_ENV_KEYS.includes(row.name),
        `docs/prd.md:${row.line} documents ${row.name} but SCALAR_ENV_KEYS does not register it.`,
      );
      assert.deepEqual(unknownKeysFor({ [row.name]: '/nonexistent/path' }), []);
    });
  }

  for (const row of CREDENTIAL_TEMPLATES) {
    test(`${row.name} is covered by the local-key rule, not by a literal entry`, () => {
      // §5.15.1b: "every row is registered in SCALAR_ENV_KEYS **or matched by
      // the local-key rule below**". A template cannot be registered literally
      // — the label set is open — so the obligation is discharged by
      // substitution: a concrete spelling of the family must be recognised.
      assert.equal(
        SCALAR_ENV_KEYS.includes(row.name),
        false,
        `${row.name} is a template and must not be registered verbatim`,
      );
      const concrete = row.name.replace(/<[A-Z]+>/, 'EDGE');
      assert.deepEqual(
        unknownKeysFor({ [concrete]: '/nonexistent/path' }),
        [],
        `${concrete}, a concrete spelling of ${row.name}, is not recognised`,
      );
    });
  }
});

// ===========================================================================
// 3. Code -> table: every registered serving key traces back to a row (A4, A8)
// ===========================================================================

describe('the reverse direction: no registration without a row (A4, A8)', () => {
  test('SERVING_ENV_KEYS set-equals the §5.15.1 family, in both directions', () => {
    // This is the sharpest form the reverse check takes. `SERVING_ENV_KEYS` is
    // the code's own statement of the family FR-63 closes, so equality — not
    // containment — is the right relation, and it fails in BOTH directions:
    // a row added without a registration, and a registration added without a
    // row.
    const drift = crossReference(SERVING_NAMES, SERVING_ENV_KEYS);
    assert.deepEqual(
      drift.missingFromCode,
      [],
      'documented in §5.15.1, absent from SERVING_ENV_KEYS',
    );
    assert.deepEqual(
      drift.missingFromTable,
      [],
      'registered in SERVING_ENV_KEYS, absent from §5.15.1',
    );
  });

  test('every UNIFI_HTTP_* registration is a §5.15.1 row', () => {
    // `SCALAR_ENV_KEYS` is wider than the serving family by design — it also
    // carries ADR-04's outbound credential surface, which §5.15.1's scope note
    // explicitly places outside FR-63's closure. What is NOT permitted is an
    // `UNIFI_HTTP_*` key sitting in the wider list with no row: that is the
    // exact shape of the Q-02 risk.
    const orphans = SCALAR_ENV_KEYS.filter(
      (key) => key.startsWith('UNIFI_HTTP_') && !SERVING_NAMES.includes(key),
    );
    assert.deepEqual(orphans, [], 'UNIFI_HTTP_* keys registered with no §5.15.1 row');
  });

  test('every *_FILE registration is a row in §5.15.1 or §5.15.1b', () => {
    // The file-delivery surface spans both tables — the two inbound halves live
    // in §5.15.1, the UniFi keys in §5.15.1b — so this one is asserted against
    // the union and nothing else.
    const documented = new Set([...SERVING_NAMES, ...CREDENTIAL_LITERALS]);
    const orphans = SCALAR_ENV_KEYS.filter(
      (key) => key.endsWith('_FILE') && !documented.has(key),
    );
    assert.deepEqual(orphans, [], '*_FILE keys registered with no normative row');
  });

  test('A8, stated as a named property so a reviewer can find it', () => {
    // "A variable added to the code without a row, or a row without a
    // registration, fails the build rather than the operator's server."
    //
    // The conjunction: §2 is table -> code, §3 is code -> table, and §1 proves
    // the machinery reports both directions on drifted input. Asserted here as
    // one statement over live data so the property has a home rather than being
    // an emergent consequence of three describes.
    const forward = crossReference(SERVING_NAMES, SCALAR_ENV_KEYS).missingFromCode;
    const reverse = crossReference(SERVING_NAMES, SERVING_ENV_KEYS).missingFromTable;
    const credentials = crossReference(CREDENTIAL_LITERALS, SCALAR_ENV_KEYS).missingFromCode;
    assert.deepEqual({ forward, reverse, credentials }, {
      forward: [],
      reverse: [],
      credentials: [],
    });
  });
});

// ===========================================================================
// 4. Field 2 is normative too: the documented defaults are the real ones (A7)
// ===========================================================================

/**
 * Field 2 -> the resolved value, per variable.
 *
 * Every §5.15.1 row must have an entry. A row added without one fails the
 * coverage test below rather than being silently skipped — the same
 * fail-don't-fall-back rule the parser obeys.
 */
const DEFAULT_READERS: Record<string, (config: ServerConfig) => unknown> = {
  UNIFI_MCP_TRANSPORT: (c) => c.serving.transport,
  UNIFI_HTTP_BIND: (c) => c.serving.bind,
  UNIFI_HTTP_PORT: (c) => String(c.serving.port),
  UNIFI_HTTP_PATH: (c) => c.serving.path,
  UNIFI_HTTP_AUTH: (c) => c.serving.authMode.kind,
  UNIFI_HTTP_ALLOWED_HOSTS: (c) => (c.serving.allowedHosts.length === 0 ? EMPTY : 'set'),
  UNIFI_HTTP_ALLOW_WRITES: (c) => (c.writesEnabledBySurface.http.size === 0 ? 'none' : 'some'),
  UNIFI_HTTP_MAX_SESSIONS: (c) => String(c.serving.maxSessions),
  UNIFI_HTTP_SESSION_IDLE_TTL_MS: (c) => String(c.serving.sessionIdleTtlMs),
  UNIFI_HTTP_MAX_CONNECTIONS: (c) => String(c.serving.maxConnections),
  UNIFI_HTTP_MAX_BODY_BYTES: (c) => String(c.serving.maxBodyBytes),
  UNIFI_HTTP_MAX_HEADER_BYTES: (c) => String(c.serving.maxHeaderBytes),
  UNIFI_HTTP_HEADERS_TIMEOUT_MS: (c) => String(c.serving.headersTimeoutMs),
  UNIFI_HTTP_REQUEST_TIMEOUT_MS: (c) => String(c.serving.requestTimeoutMs),
  UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS: (c) => String(c.serving.keepAliveTimeoutMs),
  UNIFI_HTTP_SSE_KEEPALIVE_MS: (c) => String(c.serving.sseKeepaliveMs),
  UNIFI_HTTP_SHUTDOWN_DEADLINE_MS: (c) => String(c.serving.shutdownDeadlineMs),
  UNIFI_HTTP_AUTH_FAIL_PER_MIN: (c) => String(c.serving.authFailPerMin),
  // The four inbound-secret variables have no default by design (NFR-23: there
  // is no default secret and no generated-and-printed secret). `*(unset)*` is
  // asserted as "the resolved descriptor holds no slot", which is the observable
  // form of "there is no default".
  UNIFI_HTTP_TOKEN: (c) => (c.serving.auth.slotCount === 0 ? UNSET : 'a slot'),
  UNIFI_HTTP_TOKEN_FILE: (c) => (c.serving.auth.sources.length === 0 ? UNSET : 'a source'),
  UNIFI_HTTP_TOKEN_NEXT: (c) => (c.serving.auth.slotCount === 0 ? UNSET : 'a slot'),
  UNIFI_HTTP_TOKEN_NEXT_FILE: (c) => (c.serving.auth.sources.length === 0 ? UNSET : 'a source'),
};

describe('§5.15.1 field 2: the documented default is the resolved default (A7)', () => {
  test('every parsed row has a reader; a new row without one fails here', () => {
    const uncovered = SERVING_NAMES.filter((name) => DEFAULT_READERS[name] === undefined);
    assert.deepEqual(
      uncovered,
      [],
      'a §5.15.1 row was added with no default reader in this file; add one rather than ' +
        'shrinking the table',
    );
  });

  // ONE config, resolved from an empty environment, read by every row. Building
  // it once is not an optimisation: it is the assertion. Each documented default
  // must hold in the SAME process the operator gets, not one per variable.
  const bare = evaluate({});

  test('the empty environment refuses nothing about the serving surface', () => {
    // NOT "no errors at all": an empty environment has no UniFi credential
    // either, and `validateConfig` says so. That refusal belongs to ADR-04's
    // outbound surface and is asserted elsewhere. What matters here is that the
    // defaults below describe a serving configuration nothing objects to — if
    // any §5.15.1 variable were named in a refusal, every default assertion
    // that follows would be describing a surface that cannot start.
    const servingComplaints = bare.errors.filter((message) =>
      SERVING_NAMES.some((name) => message.includes(name)),
    );
    assert.deepEqual(servingComplaints, []);
  });

  for (const row of SERVING_ROWS) {
    test(`${row.name} defaults to ${row.default}`, () => {
      const reader = DEFAULT_READERS[row.name];
      assert.ok(reader, `no reader for ${row.name}`);
      assert.equal(
        reader(bare.config),
        row.default,
        `docs/prd.md:${row.line} documents ${row.name} defaulting to ${row.default}`,
      );
    });
  }

  test('the resolved serving configuration carries no secret material (A7, FR-78)', () => {
    // A7's second half. `serving.auth` is the descriptor, and a descriptor that
    // grew a length or a plaintext would put secret material on ServerConfig.
    const summary = redactedSummary(bare.config) as Record<string, unknown>;
    const serving = summary['serving'] as Record<string, unknown>;
    const auth = serving['auth'] as Record<string, unknown>;
    assert.deepEqual(Object.keys(auth).sort(), ['mode', 'slotCount', 'sources']);
    assert.equal('minSlotLength' in auth, false, 'the summary rendered a secret length');
    assert.equal(JSON.stringify(summary).includes('minSlotLength'), false);
  });
});

// ===========================================================================
// 5. Every refusal names a registered variable (A22)
// ===========================================================================

/**
 * Configurations chosen to reach as many distinct refusal messages as one
 * corpus reasonably can: the five FR-73 refusals, the value errors of §2.6, and
 * the write-gate grammar.
 */
const REFUSAL_CORPUS: ReadonlyArray<NodeJS.ProcessEnv> = [
  { UNIFI_MCP_TRANSPORT: 'http' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_BIND: '0.0.0.0', UNIFI_HTTP_TOKEN: 'y'.repeat(40) },
  {
    UNIFI_MCP_TRANSPORT: 'http',
    UNIFI_HTTP_TOKEN: 'y'.repeat(40),
    UNIFI_HTTP_ALLOW_WRITES: 'protect',
  },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: 'y'.repeat(40), UNIFI_HTTP_ALLOW_WRITES: 'all' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: 'y'.repeat(40), UNIFI_HTTP_PATH: '/healthz' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_AUTH: 'none', UNIFI_HTTP_BIND: '0.0.0.0' },
  { UNIFI_MCP_TRANSPORT: 'local' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_PORT: '70000', UNIFI_HTTP_TOKEN: 'y'.repeat(40) },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_BIND: 'localhost:8787' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_PATH: 'mcp', UNIFI_HTTP_TOKEN: 'y'.repeat(40) },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_AUTH: 'basic' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: 'short' },
  { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_TOKEN: 'y'.repeat(40), UNIFI_HTTP_ALLOW_WRITES: 'true' },
  { UNIFI_ENABLE_WRITES: 'nonsense' },
  { UNIFI_LOCAL_HOST_FILE: '10.0.0.1' },
  { UNIFI_HTTP_GHOST_VARIABLE: '1' },
];

describe('every refusal names a registered variable (A22, FR-54)', () => {
  test('the corpus reaches a broad set of distinct messages', () => {
    const seen = new Set<string>();
    for (const env of REFUSAL_CORPUS) for (const message of evaluate(env).errors) seen.add(message);
    assert.ok(seen.size >= 14, `only ${seen.size} distinct refusals reached; the corpus decayed`);
  });

  test('each message names at least one recognised UNIFI_ variable', () => {
    // The honest limit, stated: this proves "the message names a REGISTERED
    // variable", not "the message names the REMEDY variable". A15–A19 in
    // test/config-refusals.test.ts own correctness; this owns coverage. Keep
    // both — neither subsumes the other.
    const recognised = new Set(SCALAR_ENV_KEYS);
    const offenders: string[] = [];
    for (const env of REFUSAL_CORPUS) {
      for (const message of evaluate(env).errors) {
        // The ONE exempt class, named rather than filtered out of the corpus.
        // The unknown-key refusal's entire job is to quote a variable that is
        // NOT registered — that is the fault it is reporting. Requiring it to
        // name a registered variable would require it to name something other
        // than the operator's typo, which is the opposite of FR-54.
        if (message.startsWith('Unrecognised UNIFI_* environment variable:')) continue;
        const named = [...message.matchAll(/\bUNIFI_[A-Z0-9_]+\b/g)].map((m) => m[0]);
        const anyRegistered = named.some(
          (name) =>
            recognised.has(name) ||
            name.startsWith('UNIFI_LOCAL_API_KEY_') ||
            name.startsWith('UNIFI_LOCAL_HOST_'),
        );
        if (!anyRegistered) offenders.push(message);
      }
    }
    assert.deepEqual(offenders, [], 'refusal messages naming no registered variable');
  });
});

// ===========================================================================
// 6. The echo ceiling holds for the variables a secret lands in BY MISTAKE (A33)
// ===========================================================================

describe('a secret in the wrong variable is not echoed either (A33, contract §2.2)', () => {
  // Lower-case on purpose. Three of the readers below ASCII-fold their input
  // before composing the message (`UNIFI_MCP_TRANSPORT`, `UNIFI_HTTP_AUTH`,
  // `UNIFI_HTTP_ALLOW_WRITES`), and a mixed-case sentinel would silently stop
  // matching after the fold — the leak check would pass because the needle
  // changed, not because the value was withheld.
  const SENTINEL = 'zq7w'.repeat(16);

  // FR-64's own criterion covers the variable DESIGNED to hold a secret. These
  // are the ones an operator will paste one into by accident — a shell history
  // mishap, a wrong line in a Compose file — which is collision C-1's real
  // shape. Each of these variables echoes its value in its refusal, so each is
  // a genuine leak path if the 16-character ceiling is not applied.
  const cases: ReadonlyArray<[string, NodeJS.ProcessEnv]> = [
    ['UNIFI_HTTP_PORT', { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_PORT: SENTINEL }],
    ['UNIFI_HTTP_BIND', { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_BIND: SENTINEL }],
    ['UNIFI_HTTP_PATH', { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_PATH: SENTINEL }],
    ['UNIFI_HTTP_ALLOW_WRITES', { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_ALLOW_WRITES: SENTINEL }],
    ['UNIFI_MCP_TRANSPORT', { UNIFI_MCP_TRANSPORT: SENTINEL }],
    ['UNIFI_HTTP_AUTH', { UNIFI_MCP_TRANSPORT: 'http', UNIFI_HTTP_AUTH: SENTINEL }],
  ];

  for (const [variable, env] of cases) {
    test(`${variable} renders (64 characters), never the value`, () => {
      const messages = evaluate(env).errors;
      const own = messages.filter((message) => message.includes(variable));
      assert.ok(own.length > 0, `${variable} produced no refusal to inspect`);
      for (const message of own) {
        assert.equal(
          message.includes(SENTINEL),
          false,
          `${variable}'s refusal echoed the whole value`,
        );
      }
      assert.ok(
        own.some((message) => message.includes('(64 characters)')),
        `${variable}'s refusal did not render the length substitution`,
      );
    });
  }

  test('no partial prefix of the sentinel survives either', () => {
    // The ceiling truncating rather than substituting would still leak 16
    // characters, and a 16-character prefix of a secret is a real disclosure.
    for (const [, env] of cases) {
      for (const message of evaluate(env).errors) {
        for (let length = 8; length <= SENTINEL.length; length += 1) {
          assert.equal(
            message.includes(SENTINEL.slice(0, length)),
            false,
            'a refusal echoed a prefix of the planted value',
          );
        }
      }
    }
  });
});
