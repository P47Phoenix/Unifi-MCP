/**
 * The canonical source-scan suite (US-30, the closing gate).
 *
 * Every assertion here is a claim about the SHAPE of the finished tree rather
 * than about its behaviour. They are gathered into one file because that is
 * what makes them maintainable: a structural rule scattered across the suite of
 * the story that happened to need it gets weakened by the next story that trips
 * over it, and nobody reviewing that change can see the rule it belongs to.
 *
 * Several of these scans were run in-test by earlier stories and are superseded
 * here rather than merely copied — S-04 (the FR-71 enforcement inventory) and
 * S-05 (the four structural scans) both say so. The in-test copies still stand
 * in `test/runtime.test.ts` §5, `test/serve-writegate.test.ts` §5,
 * `test/healthcheck.test.ts` §6 and `test/serve-throttle.test.ts` §1: those
 * files were outside this story's declared scope, so the duplicates are
 * reported as a carry-forward item rather than removed by an out-of-scope edit.
 * Two copies of the same true assertion cost a little duplication and hide
 * nothing — a divergence turns both red, not one.
 *
 * The governing principle, from the story: a rule that would go red on its
 * first CI run against code nobody was asked to change gets FIXED rather than
 * scoped down.
 */
import { strict as assert } from 'node:assert';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { test, describe } from 'node:test';
import { fileURLToPath } from 'node:url';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC_ROOT = join(REPO_ROOT, 'src');
const TEST_ROOT = join(REPO_ROOT, 'test');
const WORKFLOW_ROOT = join(REPO_ROOT, '.github', 'workflows');

const CI_WORKFLOW = '.github/workflows/ci.yml';
const CONTAINER_WORKFLOW = '.github/workflows/container.yml';

/** Repo-relative, forward-slashed, so a failure message reads the same everywhere. */
function relPath(path: string): string {
  return relative(REPO_ROOT, path).split('\\').join('/');
}

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf8');
}

/** Every `.ts` file under a directory, recursively, in a stable order. */
function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) found.push(...sourceFiles(path));
    else if (path.endsWith('.ts')) found.push(path);
  }
  return found;
}

// ===========================================================================
// 1. The anti-hardcoding detector (FR-74 "computed, never enumerated", §14
//    item 14)
// ===========================================================================

/**
 * FR-74's detector, implemented to its written definition rather than invented.
 *
 * The definition matters as much as the rule. A detector that flags every
 * numeric `.length` comparison in scope also flags `test/registry.test.ts`'s
 * blocked-discriminator count and its Mobility action count, neither of which
 * has anything to do with the tool surface — and each false positive would
 * force an allow-list entry, which turns a closed list into an open one. The
 * definition below is what makes the false-positive rate zero BY CONSTRUCTION
 * rather than by hand-exempting the two lines.
 *
 * SCOPE (FR-74, widened in its own Revision 3): every `*.test.ts` the harness
 * discovers directly under `test/` — the harness scans that directory
 * non-recursively — plus BOTH workflow files. Not just the serving-transport
 * steps of the container workflow, and not just `test/serve-*.test.ts`: the
 * earlier, narrower scope excluded both files its own allow-list named, which
 * made the allow-list inert.
 */
function scannedFiles(): string[] {
  const tests = readdirSync(TEST_ROOT)
    .filter((name) => name.endsWith('.test.ts'))
    .sort()
    .map((name) => join(TEST_ROOT, name));
  return [...tests, join(WORKFLOW_ROOT, 'ci.yml'), join(WORKFLOW_ROOT, 'container.yml')];
}

/**
 * THE LEXICAL RULE — what counts as "the exported tool set".
 *
 * An identifier is a tool-set identifier inside a scanned file if it is
 * `ALL_TOOLS`, or if that same file binds it — `const NAME =`, `let NAME =`,
 * `var NAME =`, or a bare `NAME =` inside a workflow's inline `node`/`python3`
 * block — to an initialiser whose text contains `advertisedTools(`,
 * `ALL_TOOLS`, or a `tools` member read of a `tools/list` payload.
 *
 * Resolution is SINGLE-FILE and TEXTUAL: no cross-file analysis, no dataflow,
 * no alias chasing. That bound is inherited from FR-74 rather than widened
 * here. An alias introduced through an intermediate binding is caught by
 * review, not by this scan — the same bound FR-71's inventory places on its own
 * detection half.
 */
const TOOL_SET_INITIALISER = /advertisedTools\(|ALL_TOOLS|\.tools\b|\['tools'\]|\["tools"\]/;

function toolSetIdentifiers(source: string): Set<string> {
  const identifiers = new Set<string>(['ALL_TOOLS']);
  for (const line of source.split(/\r?\n/)) {
    const bound = /(?:\b(?:const|let|var)\s+|^\s*)([A-Za-z_$][\w$]*)\s*=[^=]/.exec(line);
    if (!bound) continue;
    const initialiser = line.slice(bound.index + bound[0].length - 1);
    if (TOOL_SET_INITIALISER.test(initialiser)) identifiers.add(bound[1] as string);
  }
  return identifiers;
}

interface Finding {
  readonly file: string;
  readonly limb: 1 | 2;
  readonly line: number;
  readonly expression: string;
}

const COMPARISONS = '===|!==|==|!=|<=|>=|<|>';
/** The three count expressions FR-74 names: `X.length`, `X.size`, `len(X)`. */
const COUNT = '(?:([A-Za-z_$][\\w$]*)\\s*\\.\\s*(?:length|size)|len\\(\\s*([A-Za-z_$][\\w$]*)\\s*\\))';

/**
 * LIMB 1 — a tool-count comparison.
 *
 * Rejects a binary comparison in which one operand is a count expression whose
 * receiver is a tool-set identifier and the other is a decimal integer literal.
 * Covers `assert.equal(X, N)` / `assert.strictEqual(X, N)`, `assert.ok(X op N)`,
 * the bare Python `assert X op N`, and every plain comparison.
 *
 * The five ignore rules, each satisfied BY CONSTRUCTION rather than by an
 * exemption list:
 *
 *  (a) a count expression whose receiver is NOT a tool-set identifier, whatever
 *      the literal — we only ever report when the captured receiver is in the
 *      set above. This is what excludes `test/registry.test.ts`'s
 *      `assert.equal(withheld.length, 1)` and `assert.equal(mobility.length, 8)`.
 *  (b) a count expression that is not an operand of a comparison — we match
 *      only comparison forms, so an interpolated `${tools.length}` in a
 *      diagnostic string, or `{len(tools)}` in a Python f-string, is invisible.
 *  (c) a comparison in which neither operand is an integer literal — the
 *      literal is a required capture. This is what excludes
 *      `assert.equal(actions.length + blockedTotal, specTotal, …)`, and it is
 *      also what makes the REPLACEMENTS this story installs legal: a count
 *      compared against another computed count is exactly the fix.
 *  (d) a truthiness test, such as `if (missing.length)` or `if (!expected.length)`
 *      — and, by the same reasoning, a comparison whose integer literal is `0`.
 *      RECORDED INTERPRETATION, see the note below.
 *  (e) a `.length` on a string or any non-collection expression — the receiver
 *      must be a bare identifier AND a tool-set identifier, so
 *      `entry.reason.trim().length > 20` cannot match: nothing that is an
 *      identifier immediately precedes its `.length`.
 */
function limb1(file: string, source: string): Finding[] {
  const identifiers = toolSetIdentifiers(source);
  const found: Finding[] = [];
  const patterns = [
    new RegExp(`${COUNT}\\s*(?:${COMPARISONS})\\s*(\\d+)`, 'g'),
    new RegExp(`(\\d+)\\s*(?:${COMPARISONS})\\s*${COUNT}`, 'g'),
    new RegExp(`assert\\.(?:equal|strictEqual)\\(\\s*${COUNT}\\s*,\\s*(\\d+)\\s*[,)]`, 'g'),
  ];
  source.split(/\r?\n/).forEach((raw, index) => {
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      for (const match of raw.matchAll(pattern)) {
        const groups = match.slice(1).filter((g) => g !== undefined) as string[];
        const receiver = groups.find((g) => !/^\d+$/.test(g));
        const literal = groups.find((g) => /^\d+$/.test(g));
        if (receiver === undefined || !identifiers.has(receiver)) continue;
        // Ignore rule (d), second half — see the interpretation note.
        if (literal === '0') continue;
        found.push({ file, limb: 1, line: index + 1, expression: match[0].trim() });
      }
    }
  });
  return found;
}

/**
 * RECORDED INTERPRETATION of ignore rule (d), and a finding against FR-74.
 *
 * FR-74 states that under its definition the detector matches, in this
 * repository today, exactly the six sites (i)-(vi) "and no others". Run
 * literally, it does not: `test/contract-network.test.ts` and
 * `test/contract-protect.test.ts` each carry an anti-vacuity guard of the form
 * `assert.ok(readSurface.length > 0, …)`, where `readSurface` is bound to
 * `advertisedTools(…)` and `0` is a decimal integer literal. Both predate this
 * story and neither has anything to do with a hardcoded tool count.
 *
 * The resolution is NOT a sixth ignore rule and NOT two more allow-list
 * entries — FR-74 closes the list, and an allow-list that grows to accommodate
 * the detector is the detector admitting it is wrong. `X.length > 0` is the
 * truthiness test of ignore rule (d) written with an operator: it asserts the
 * set is NON-EMPTY, which is the opposite of asserting how big it is, and it
 * cannot encode a surface size. Flagging it would push authors to delete
 * anti-vacuity guards to satisfy an anti-hardcoding rule, which is a strictly
 * worse tree — the same trade limb 2's ignore rule already refuses when it
 * declines to forbid FR-44's own read-only-default assertion.
 *
 * So rule (d) reads: a truthiness test, whether spelled without an operator or
 * as a comparison against `0`. Five rules, unchanged in number. Reported for a
 * one-clause amendment to FR-74's rule (d) at UAT.
 */

/**
 * LIMB 2 — a tool-name enumeration literal.
 *
 * Rejects an array, list, set or tuple literal containing two or more string
 * literals each matching the tool-name shape: JavaScript `[ … ]` including the
 * argument of `new Set([ … ])`, and Python `[ … ]`, `{ … }` or `( … )`.
 *
 * The brace and parenthesis forms are PYTHON's, and are applied only to the
 * workflow files, which are where this repository's Python lives. Applying them
 * to TypeScript would make every block and every argument list a candidate
 * "literal" — `test/runtime.test.ts`'s write-tool test has two single-name
 * assertions inside one `{ … }` body, which is two properties of two named
 * tools and not an enumeration of anything.
 *
 * It IGNORES a tool-name string literal that is not an element of such a
 * literal. Naming ONE tool to assert a property OF THAT TOOL is not enumerating
 * the surface, and the surface is the only thing this rule protects. A rule
 * that forbade every literal tool name under `test/` would forbid FR-44's own
 * read-only-default regression test, which is a worse outcome than the drift it
 * prevents.
 */
const TOOL_NAME = /^unifi_[a-z0-9_]+$/;
const STRING_LITERAL = /'([^'\\\n]*)'|"([^"\\\n]*)"/g;
/** Innermost bracketed regions, so a nested literal is judged on its own contents. */
const JS_BRACKETED = /\[[^[\]]*\]/gs;
const PY_BRACKETED = /\[[^[\]]*\]|\{[^{}]*\}|\([^()]*\)/gs;

function limb2(file: string, source: string): Finding[] {
  const found: Finding[] = [];
  const bracketed = file.endsWith('.yml') || file.endsWith('.yaml') ? PY_BRACKETED : JS_BRACKETED;
  for (const region of source.matchAll(bracketed)) {
    const text = region[0];
    STRING_LITERAL.lastIndex = 0;
    const names = [...text.matchAll(STRING_LITERAL)]
      .map((m) => (m[1] ?? m[2]) as string)
      .filter((value) => TOOL_NAME.test(value));
    if (names.length < 2) continue;
    const line = source.slice(0, region.index).split(/\r?\n/).length;
    found.push({ file, limb: 2, line, expression: text.replace(/\s+/g, ' ').trim() });
  }
  return found;
}

function detect(): Finding[] {
  const found: Finding[] = [];
  for (const path of scannedFiles()) {
    const file = relPath(path);
    const source = readFileSync(path, 'utf8');
    found.push(...limb1(file, source), ...limb2(file, source));
  }
  return found.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

/**
 * THE ALLOW-LIST, ENUMERATED IN FULL.
 *
 * FR-74 fixed its initial contents at six entries, (i)–(vi), re-derived against
 * the repository at HEAD under the definition above. §14 item 14 — this story —
 * removes (i) through (v). (vi) is marked PERMANENT by the requirement and
 * stays, so after this change the list is a STRICT SUBSET of what it was, which
 * is what the shrink-only rule rewards rather than trips over.
 *
 * ONE entry remains, and this is it in full.
 */
interface AllowListEntry {
  readonly file: string;
  readonly limb: 1 | 2;
  /** What the detector matches, described rather than pasted — see the note below. */
  readonly shape: string;
  readonly reason: string;
}

/**
 * The matched text is DESCRIBED here and asserted structurally below, not
 * pasted in. Pasting it would create a second literal of the same shape inside
 * this file — which is in the scan's own scope — and the allow-list would then
 * have to grow an entry for itself. A rule that cannot be written down without
 * violating itself is a rule with a bug in it.
 */
const ALLOW_LIST: readonly AllowListEntry[] = [
  {
    file: 'test/registry.test.ts',
    limb: 2,
    shape: 'the two-element `for (const name of [ … ])` head of the execute-tool description test',
    reason:
      'FR-74 (vi), PERMANENT. It looks up two NAMED tools to assert a property of each ' +
      "description — that it names the upstream API it wraps — rather than enumerating the " +
      'surface. Deriving the pair would assert the derivation instead of the two tools the ' +
      'criterion is about.',
  },
];

function keyOf(entry: { file: string; limb: 1 | 2 }): string {
  return `${entry.file} :: limb ${entry.limb}`;
}

describe('US-30 §1: the anti-hardcoding detector (FR-74, §14 item 14)', () => {
  const findings = detect();

  test('the scan is green — every match is allow-listed, and every entry still matches', () => {
    const matched = findings.map(keyOf);
    const allowed = ALLOW_LIST.map(keyOf);

    const unallowed = findings.filter((f) => !allowed.includes(keyOf(f)));
    assert.deepEqual(
      unallowed.map((f) => `${f.file}:${f.line} (limb ${f.limb}) ${f.expression}`),
      [],
      'a tool count or a tool-name list was hardcoded; compute it from the registry instead',
    );

    const stale = ALLOW_LIST.filter((entry) => !matched.includes(keyOf(entry)));
    assert.deepEqual(
      stale.map(keyOf),
      [],
      'the allow-list names a site the detector no longer matches; delete the entry',
    );
  });

  test('the allow-list is closed and has SHRUNK — FR-74 (i)-(v) are gone, (vi) remains', () => {
    // FR-74's closure rule: (i)-(v) leave the list when §14 item 14 lands, (vi)
    // may leave but may never be joined, and no entry may be added without
    // amending the requirement. So the post-state must be a subset of the
    // pre-state, keyed the same way.
    const PREVIOUS = new Set([
      `${CI_WORKFLOW} :: limb 1`, // (i)   the FR-18 tool-count cap
      'test/registry.test.ts :: limb 1', // (ii) and (iii)
      `${CI_WORKFLOW} :: limb 2`, // (iv)  the eight-name `expected` array
      `${CONTAINER_WORKFLOW} :: limb 2`, // (v) the seven-name Python set
      'test/registry.test.ts :: limb 2', // (vi) PERMANENT
    ]);
    for (const entry of ALLOW_LIST) {
      assert.ok(PREVIOUS.has(keyOf(entry)), `${keyOf(entry)} was added, not inherited`);
    }
    assert.ok(ALLOW_LIST.length < PREVIOUS.size, 'the list did not shrink');
  });

  test('the one remaining entry is the shape FR-74 (vi) describes, and nothing wider', () => {
    const remaining = findings.filter((f) => f.file === 'test/registry.test.ts' && f.limb === 2);
    assert.equal(remaining.length, 1, remaining.map((f) => `${f.line}: ${f.expression}`).join(' | '));
    const only = remaining[0] as Finding;
    const hostLine = read('test/registry.test.ts').split(/\r?\n/)[only.line - 1] as string;
    assert.ok(
      hostLine.includes('for (const name of'),
      `FR-74 (vi) is the head of a for-of over two named tools; this is ${hostLine.trim()}`,
    );
    STRING_LITERAL.lastIndex = 0;
    const names = [...only.expression.matchAll(STRING_LITERAL)]
      .map((m) => (m[1] ?? m[2]) as string)
      .filter((value) => TOOL_NAME.test(value));
    assert.equal(names.length, 2, 'FR-74 (vi) names exactly two tools');
    assert.ok(
      names.every((name) => name.startsWith('unifi_execute')),
      `FR-74 (vi) is about the execute tools; this names ${names.join(', ')}`,
    );
  });

  test('the five removed sites are absent, each proven by its own signature', () => {
    // Keyed on a signature rather than a line number so an unrelated edit above
    // a site cannot invalidate the check, and written without any tool name so
    // this file does not become limb 2's next match.
    const REMOVED: ReadonlyArray<{ file: string; limb: 1 | 2; label: string; signature: RegExp }> = [
      {
        file: CI_WORKFLOW,
        limb: 1,
        label: 'FR-74 (i) — the FR-18 tool-count cap',
        signature: /\btools\.length\s*>\s*12\b/,
      },
      {
        file: 'test/registry.test.ts',
        limb: 1,
        label: 'FR-74 (ii) — the `<= 12` advertised bound',
        signature: /\btools\.length\s*<=\s*12\b/,
      },
      {
        file: 'test/registry.test.ts',
        limb: 1,
        label: 'FR-74 (iii) — the promoted-tool count',
        signature: /\bpromoted\.length\s*,\s*5\b/,
      },
      {
        file: CI_WORKFLOW,
        limb: 2,
        label: 'FR-74 (iv) — the eight-name `expected` array',
        signature: /const expected = \[\s*$/m,
      },
      {
        file: CONTAINER_WORKFLOW,
        limb: 2,
        label: 'FR-74 (v) — the seven-name Python set',
        signature: /^\s*expected = \{\s*$/m,
      },
    ];
    for (const site of REMOVED) {
      assert.equal(
        site.signature.test(read(site.file)),
        false,
        `${site.label} is still in ${site.file}`,
      );
    }
  });

  test('both workflows compare a real tools/list frame against the computed surface', () => {
    // FR-74: "in BOTH workflows the check compares `tools/list` against the same
    // source rather than against a literal list". Absence of the old literal is
    // half the claim; this is the other half, so the sites cannot be satisfied
    // by deleting the check instead of replacing it.
    for (const file of [CI_WORKFLOW, CONTAINER_WORKFLOW]) {
      const source = read(file);
      assert.match(source, /advertisedTools\(/, `${file} no longer derives the expected surface`);
      assert.match(source, /loadConfig\(/, `${file} no longer resolves the served configuration`);
      assert.match(source, /tools\/list|tools-list\.json|\['tools'\]/, `${file} reads no tools/list`);
    }
    // The container workflow's real `tools/list` frame piped into `docker run -i`
    // is AR-13's compensating control and US-29's parity suite depends on it
    // existing. Rewriting the check must not have deleted the frame.
    assert.match(read(CONTAINER_WORKFLOW), /"method":"tools\/list"/);
    assert.match(read(CONTAINER_WORKFLOW), /docker run -i/);
  });

  test('the detector is proven able to fail before it is trusted to pass', () => {
    // Anti-vacuity, both limbs, against synthetic sources. Without this, a
    // detector that matched nothing at all would report the same green.
    //
    // The fixtures are COMPOSED rather than written out, because this file is
    // itself in the scan's scope and a literal violation here would be a real
    // match, not a fixture. Same reason the allow-list describes its one entry
    // instead of pasting it.
    const ident = 'surface';
    const jsCount = `const ${ident} = advertisedTools(a, b);\nassert.ok(${ident}.length <= 12);\n`;
    assert.equal(limb1('synthetic.ts', jsCount).length, 1);

    const pyCount = `${ident} = msg['result']['tools']\nassert len(${ident}) == 7\n`;
    assert.equal(limb1('synthetic.yml', pyCount).length, 1);

    const listed = ['sites', 'devices'].map((suffix) => `'unifi_list_${suffix}'`).join(', ');
    assert.equal(limb2('synthetic.ts', `const promoted = [${listed}];\n`).length, 1);

    // …and it stays silent on the shapes ignore rules (a)-(e) name.
    assert.deepEqual(limb1('synthetic.ts', 'assert.equal(other.length, 3);\n'), []);
    assert.deepEqual(limb1('synthetic.ts', `const ${ident} = ALL_TOOLS;\nif (${ident}.length) x();\n`), []);
    assert.deepEqual(limb2('synthetic.ts', `const one = ['unifi_list_${'sites'}'];\n`), []);
  });

  test('the detector does NOT flag the two unrelated collection assertions', () => {
    // The named false positives from FR-74's own definition. Asserted against
    // the REAL file, at whatever lines they now sit at, because pinning them by
    // line number would make this test a maintenance tax rather than a control.
    const source = read('test/registry.test.ts');
    const lines = source.split(/\r?\n/);
    const flagged = new Set(limb1('test/registry.test.ts', source).map((f) => f.line));
    for (const signature of [/assert\.equal\(withheld\.length, 1\)/, /assert\.equal\(mobility\.length, 8\)/]) {
      const index = lines.findIndex((line) => signature.test(line));
      assert.notEqual(index, -1, `${signature} is no longer in test/registry.test.ts`);
      assert.equal(
        flagged.has(index + 1),
        false,
        `line ${index + 1} is an unrelated collection assertion and must not be flagged`,
      );
    }
    // …and the string-length rule, ignore rule (e).
    const reasonIndex = lines.findIndex((line) => /entry\.reason\.trim\(\)\.length > 20/.test(line));
    assert.notEqual(reasonIndex, -1);
    assert.equal(flagged.has(reasonIndex + 1), false);
  });
});

// ===========================================================================
// 2. The FR-66 marker
// ===========================================================================

describe('US-30 §2: the Origin enforcement site carries its marker (FR-66)', () => {
  test('the literal marker appears in src/, exactly once, at the Origin predicate', () => {
    const MARKER = 'FR-66: inverts SDK default';
    const carriers = sourceFiles(SRC_ROOT).filter((file) =>
      readFileSync(file, 'utf8').includes(MARKER),
    );
    assert.deepEqual(carriers.map(relPath), ['src/serve/guard.ts']);

    // …and it sits at the enforcement site rather than in a file header. The
    // marker exists so a reader who finds the predicate finds the reason it
    // inverts the SDK's default in the same screen.
    const guard = readFileSync(join(SRC_ROOT, 'serve', 'guard.ts'), 'utf8');
    const marker = guard.indexOf(MARKER);
    const predicate = guard.indexOf('export function hasOrigin(');
    assert.notEqual(predicate, -1, 'the Origin predicate is no longer named hasOrigin');
    assert.ok(marker > predicate, 'the marker is not inside the Origin predicate');
    assert.ok(
      guard.slice(predicate, marker).split(/\r?\n/).length < 5,
      'the marker has drifted away from the predicate it explains',
    );
  });
});

// ===========================================================================
// 3. The structural scans over `src/serve/` AND `src/index.ts`
// ===========================================================================

/** Every `from '…'` specifier in a source file. */
function importSpecifiers(source: string): string[] {
  return [...source.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1] as string);
}

describe('US-30 §3: the src/serve/ + src/index.ts structural scans', () => {
  test('the literal `serve/` appears in no import specifier outside src/serve/ and src/index.ts', () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(SRC_ROOT)) {
      const rel = relPath(file);
      if (rel.startsWith('src/serve/') || rel === 'src/index.ts') continue;
      for (const specifier of importSpecifiers(readFileSync(file, 'utf8'))) {
        if (specifier.includes('serve/')) offenders.push(`${rel} -> ${specifier}`);
      }
    }
    assert.deepEqual(offenders, []);
    // The rule is about SPECIFIERS, not about prose: `src/config.ts` and
    // `src/credentials.ts` both discuss `src/serve/` at length in comments
    // explaining why they may not import it. A scan that flagged those would be
    // deleted the first time somebody improved a comment.
    assert.ok(
      readFileSync(join(SRC_ROOT, 'config.ts'), 'utf8').includes('src/serve/'),
      'the prose case has disappeared, so this scan no longer distinguishes mention from use',
    );
  });

  test('the runtime lifecycle type is named only by index.ts, http.ts and stdio.ts', () => {
    // `Serving` is the handle both transports return and the entrypoint holds.
    // `runtime.ts` DECLARES it; the three modules below are the only ones
    // permitted to name it, because holding it is what confers the process-wide
    // `drain()`/`close()` authority a per-session path must not reach.
    const permitted = ['src/index.ts', 'src/serve/http.ts', 'src/serve/stdio.ts'];
    const namers = sourceFiles(SRC_ROOT)
      .filter((file) => /\bServing\b/.test(readFileSync(file, 'utf8')))
      .map(relPath);
    assert.deepEqual(namers.sort(), [...permitted, 'src/serve/runtime.ts'].sort());

    // The teardown half of the same claim, and the sharper one: `RuntimeCore` /
    // `RuntimeLifecycle` carry `beginDrain()` and `close()`, and
    // `createMcpServer` must receive the narrower `Runtime` so a per-session
    // cleanup path cannot reach either. Comment-only mentions are excluded —
    // `auth.ts` explains the type without holding it.
    const lifecycleHolders = sourceFiles(SRC_ROOT)
      .filter((file) => {
        const code = readFileSync(file, 'utf8')
          .split(/\r?\n/)
          .filter((line) => {
            const t = line.trim();
            return !t.startsWith('*') && !t.startsWith('//') && !t.startsWith('/*');
          })
          .join('\n');
        return /\bRuntimeCore\b|\bRuntimeLifecycle\b/.test(code);
      })
      .map(relPath);
    assert.deepEqual(
      lifecycleHolders.filter((file) => !['src/serve/runtime.ts', ...permitted].includes(file)),
      [],
    );
    assert.ok(
      !lifecycleHolders.includes('src/serve/mcpServer.ts'),
      'the per-session server can name the lifecycle type, so it can reach close()',
    );
    assert.ok(lifecycleHolders.includes('src/serve/runtime.ts'), 'the scan matched nothing');
  });

  test('D-14 — only log.ts writes to a standard stream, across src/serve/ AND src/index.ts', () => {
    // US-13's original AC 1, relocated here by D-14. Asserting it inside US-13
    // needed an edit to `src/index.ts`, which is US-18's and which depends on
    // US-13 — the round's only dependency cycle. US-30 is the closing gate and
    // owns a final tree, so it is the only story that can run it.
    //
    // `src/index.ts` IS IN SCOPE, and that is the whole point: a run that omits
    // it leaves the criterion undischarged in both stories.
    //
    // The scan is deliberately raw text, not comment-stripped. `src/index.ts`
    // names the forbidden call in PROSE rather than spelling it out, precisely
    // so a scan cannot mistake the mention for a use — which means the stricter
    // form is the one the tree was written to satisfy.
    const scanned = [...sourceFiles(join(SRC_ROOT, 'serve')), join(SRC_ROOT, 'index.ts')];
    const writers = scanned.filter((file) => {
      const source = readFileSync(file, 'utf8');
      return source.includes('process.stderr.write') || /\bconsole\s*\./.test(source);
    });
    assert.deepEqual(writers.map(relPath), ['src/serve/log.ts']);
    assert.ok(
      scanned.map(relPath).includes('src/index.ts'),
      'src/index.ts was not scanned, so D-14 is undischarged',
    );
  });

  test("src/serve/health.ts's imports match its closed allow-list", () => {
    // The probe module answers from a state object and a header bag and reaches
    // nothing else — no registry, no credential store, no clock. FR-68 makes
    // `/healthz` a BIND-liveness check, and every import added here is a new way
    // for it to fail for a reason that is not "the process is bound".
    const source = readFileSync(join(SRC_ROOT, 'serve', 'health.ts'), 'utf8');
    const specifiers = importSpecifiers(source).sort();
    assert.deepEqual(specifiers, ['node:http']);
    assert.match(source, /^import type \{[^}]*\} from 'node:http';$/m, 'the node:http import must be type-only');
    // Its own state type is declared in this module rather than imported, which
    // is what keeps the allow-list at one entry.
    assert.match(source, /\bReadinessState\b/, 'the readiness state type is no longer named here');
  });

  test('`transport.onclose =` appears nowhere (US-23)', () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(SRC_ROOT)) {
      if (/\btransport\s*\.\s*onclose\s*=/.test(readFileSync(file, 'utf8'))) {
        offenders.push(`${relPath(file)}: transport.onclose =`);
      }
    }
    assert.deepEqual(offenders, []);
    // Anti-vacuity: the identifier is genuinely present in the tree, on the
    // comment that explains why it is never assigned. If that ever goes away
    // this scan is watching for something nobody would write anyway.
    assert.ok(
      readFileSync(join(SRC_ROOT, 'serve', 'http.ts'), 'utf8').includes('transport.onclose'),
      'the reason this rule exists is no longer recorded at the site it protects',
    );
  });
});

// ===========================================================================
// 4. The FR-71 `writesEnabled` enforcement inventory — CANONICAL (S-04)
// ===========================================================================

/**
 * FR-71's closed classification vocabulary. `enforcement` means the read
 * decides whether a tool is advertised or whether an outbound request proceeds
 * — and nothing else. Every other read is an observation carrying one of five
 * reasons.
 */
type Classification =
  | 'enforcement'
  | 'type-declaration'
  | 'parse'
  | 'pass-through'
  | 'diagnostic'
  | 'redaction';

interface InventoryEntry {
  readonly file: string;
  /** The verbatim source expression the scan matched. NEVER a line number. */
  readonly expression: string;
  readonly classification: Classification;
}

/**
 * The canonical inventory. Keyed on file plus matched expression, so a gate
 * moving down its file is not a change to this list while a gate moving to a
 * different file is.
 */
const WRITE_GATE_INVENTORY: readonly InventoryEntry[] = [
  // The two enforcement sites, and only these two.
  {
    file: 'src/tools/definitions.ts',
    expression: 'if (tool.requiresWrites && writesEnabled.size === 0) return false;',
    classification: 'enforcement',
  },
  {
    file: 'src/http/client.ts',
    expression:
      "if (action.actionClass === 'write' && !this.config.writesEnabled.has(action.service)) {",
    classification: 'enforcement',
  },

  // Type declarations.
  {
    file: 'src/config.ts',
    expression: 'writesEnabled: Set<ServiceId>;',
    classification: 'type-declaration',
  },
  {
    file: 'src/config.ts',
    expression:
      'writesEnabledBySurface: { readonly stdio: Set<ServiceId>; readonly http: Set<ServiceId> };',
    classification: 'type-declaration',
  },
  {
    file: 'src/tools/definitions.ts',
    expression: 'writesEnabled: ReadonlySet<ServiceId>,',
    classification: 'type-declaration',
  },

  // Resolution and the ONE narrowing, all inside `loadConfig`.
  {
    file: 'src/config.ts',
    expression: 'const writesEnabled = new Set<ServiceId>();',
    classification: 'parse',
  },
  {
    file: 'src/config.ts',
    expression: 'for (const s of enabledServices) writesEnabled.add(s);',
    classification: 'parse',
  },
  { file: 'src/config.ts', expression: 'writesEnabled.clear();', classification: 'parse' },
  {
    file: 'src/config.ts',
    expression: 'writesEnabled.add(token as ServiceId);',
    classification: 'parse',
  },
  { file: 'src/config.ts', expression: 'const writesEnabledBySurface = {', classification: 'parse' },
  { file: 'src/config.ts', expression: 'stdio: writesEnabled,', classification: 'parse' },
  {
    file: 'src/config.ts',
    expression: 'http: intersect(writesEnabled, httpAllowSet),',
    classification: 'parse',
  },
  {
    file: 'src/config.ts',
    expression: 'writesEnabled: writesEnabledBySurface[serving.transport],',
    classification: 'parse',
  },
  { file: 'src/config.ts', expression: 'writesEnabledBySurface,', classification: 'parse' },

  // Diagnostics: refusal (c)'s input, and the two startup warnings' input.
  {
    file: 'src/config.ts',
    expression: 'const baseWrites = config.writesEnabledBySurface.stdio;',
    classification: 'diagnostic',
  },
  {
    file: 'src/config.ts',
    expression: 'const base = config.writesEnabledBySurface.stdio;',
    classification: 'diagnostic',
  },
  {
    file: 'src/config.ts',
    expression: 'const overHttp = config.writesEnabledBySurface.http;',
    classification: 'diagnostic',
  },

  // Redaction — the introspection echo (FR-55).
  {
    file: 'src/config.ts',
    expression: 'writesEnabled: [...config.writesEnabled].sort(),',
    classification: 'redaction',
  },
  {
    file: 'src/config.ts',
    expression: 'writesEnabledCount: config.writesEnabled.size,',
    classification: 'redaction',
  },
  { file: 'src/config.ts', expression: 'writesEnabledBySurface: {', classification: 'redaction' },
  {
    file: 'src/config.ts',
    expression: 'stdio: [...config.writesEnabledBySurface.stdio].sort(),',
    classification: 'redaction',
  },
  {
    file: 'src/config.ts',
    expression: 'http: [...config.writesEnabledBySurface.http].sort(),',
    classification: 'redaction',
  },

  // The runtime: two pass-throughs into the enforcement site, two banner reads,
  // and the HTTP request line's `writes=` field. All observation — FR-71
  // permits the runtime to READ the set and forbids it to BRANCH on it to
  // permit or deny, so `src/serve/` carries zero enforcement sites.
  {
    file: 'src/serve/runtime.ts',
    expression:
      'stdio: advertisedTools(config.enabledServices, config.writesEnabledBySurface.stdio),',
    classification: 'pass-through',
  },
  {
    file: 'src/serve/runtime.ts',
    expression: 'http: advertisedTools(config.enabledServices, config.writesEnabledBySurface.http),',
    classification: 'pass-through',
  },
  {
    file: 'src/serve/runtime.ts',
    expression: 'const surfaces = config.writesEnabledBySurface;',
    classification: 'diagnostic',
  },
  {
    file: 'src/serve/runtime.ts',
    expression: 'const effective = config.writesEnabled;',
    classification: 'diagnostic',
  },
  {
    file: 'src/serve/http.ts',
    expression: 'const writes = [...config.writesEnabled];',
    classification: 'diagnostic',
  },
];

function inventoryKey(entry: { file: string; expression: string }): string {
  return `${entry.file} :: ${entry.expression}`;
}

/**
 * Every site under `src/` that reads the resolved write-enablement set.
 *
 * Comment-only lines are excluded: prose naming the identifier is not a read,
 * and including it would make the inventory go red every time someone improved
 * a comment — the rot that makes a checked-in inventory get deleted.
 */
function writeGateReadSites(): Array<{ file: string; expression: string; line: number }> {
  const sites: Array<{ file: string; expression: string; line: number }> = [];
  for (const path of sourceFiles(SRC_ROOT)) {
    const file = relPath(path);
    readFileSync(path, 'utf8')
      .split(/\r?\n/)
      .forEach((raw, index) => {
        const expression = raw.trim();
        if (expression.startsWith('*') || expression.startsWith('//')) return;
        if (expression.startsWith('/*')) return;
        if (!expression.includes('writesEnabled')) return;
        sites.push({ file, expression, line: index + 1 });
      });
  }
  return sites;
}

describe('US-30 §4: the FR-71 writesEnabled enforcement inventory (canonical, S-04)', () => {
  const sites = writeGateReadSites();

  test('(1) site-set equality — every read under src/ is classified', () => {
    const scanned = new Set(sites.map(inventoryKey));
    const inventoried = new Set(WRITE_GATE_INVENTORY.map(inventoryKey));
    assert.deepEqual(
      [...scanned].filter((key) => !inventoried.has(key)).sort(),
      [],
      'a new read of the write set is not in the inventory; classify it (FR-71)',
    );
    assert.deepEqual(
      [...inventoried].filter((key) => !scanned.has(key)).sort(),
      [],
      'the inventory names a site that no longer exists',
    );
  });

  test('(2) exactly two sites are classified `enforcement`', () => {
    const enforcement = WRITE_GATE_INVENTORY.filter((e) => e.classification === 'enforcement');
    assert.equal(enforcement.length, 2, enforcement.map(inventoryKey).join(' | '));
  });

  test('(3) shrink-or-stay — the enforcement list never grows', () => {
    const PREVIOUS = new Set([
      'src/tools/definitions.ts :: if (tool.requiresWrites && writesEnabled.size === 0) return false;',
      "src/http/client.ts :: if (action.actionClass === 'write' && " +
        '!this.config.writesEnabled.has(action.service)) {',
    ]);
    for (const entry of WRITE_GATE_INVENTORY.filter((e) => e.classification === 'enforcement')) {
      assert.ok(PREVIOUS.has(inventoryKey(entry)), `a third write gate appeared: ${inventoryKey(entry)}`);
    }
  });

  test('(4) src/serve/ carries no `enforcement` site', () => {
    assert.deepEqual(
      WRITE_GATE_INVENTORY.filter(
        (e) => e.classification === 'enforcement' && e.file.startsWith('src/serve/'),
      ).map(inventoryKey),
      [],
    );
  });

  test('both enforcement expressions are present in the tree exactly once', () => {
    for (const entry of WRITE_GATE_INVENTORY.filter((e) => e.classification === 'enforcement')) {
      const matches = sites.filter((site) => inventoryKey(site) === inventoryKey(entry));
      assert.equal(matches.length, 1, `${inventoryKey(entry)} appears ${matches.length} times`);
    }
  });
});

// ===========================================================================
// 5. Single-site containment scans folded in from earlier stories
// ===========================================================================

describe('US-30 §5: the rejection throttle is incremented at one site (US-27)', () => {
  test('the source holds exactly one `throttle.record` and one `throttle.isThrottled`', () => {
    // A scattered counter sums to the same N as a correct one, which is what
    // makes the throttle a path-enumeration oracle rather than a control.
    const source = readFileSync(join(SRC_ROOT, 'serve', 'http.ts'), 'utf8');
    assert.equal((source.match(/\bthrottle\.record\s*\(/g) ?? []).length, 1);
    assert.equal((source.match(/\bthrottle\.isThrottled\s*\(/g) ?? []).length, 1);
    const start = source.indexOf('function rejectUnauthenticated(');
    assert.notEqual(start, -1, 'the single emission site is no longer named rejectUnauthenticated');
    const end = source.indexOf('\n  function ', start + 1);
    assert.notEqual(end, -1, 'the containment slice can no longer be bounded; re-establish it');
    const body = source.slice(start, end);
    assert.match(body, /\bthrottle\.record\s*\(/);
    assert.match(body, /\bthrottle\.isThrottled\s*\(/);
  });
});

// ===========================================================================
// 6. The README literal scans (FR-68, FR-70, NFR-27, FR-79, AR-6)
// ===========================================================================

describe('US-30 §6: README.md carries the operator-facing literals', () => {
  const readme = read('README.md');

  test('the bind-liveness framing and both grace-period numbers are present', () => {
    // FR-68 makes `/healthz` a BIND-liveness check and its limits are part of
    // the requirement. FR-70's 35-second default and NFR-27's 50-second
    // orchestrator minimum are written here four waves before the code that
    // implements them, so this scan is the drift detector for both.
    assert.match(readme, /bind-liveness/);
    assert.match(readme, /\b35\b/);
    assert.match(readme, /\b50\b/);
    assert.match(readme, /35 000 ms|35000/, 'the shutdown deadline default is no longer stated');
    assert.match(readme, /terminationGracePeriodSeconds: 50|at least 50 s/);
  });

  test('the FR-79 routability statement is present', () => {
    assert.match(
      readme,
      /routable from this process|must be routable|no route to/i,
      'the README no longer states that configured local hosts must be reachable (FR-79)',
    );
  });

  test("AR-6's four no-line rejection classes are all named (D-10)", () => {
    // D-10 moved this from US-13 to US-05 and said "let US-30's README scan
    // enforce it"; neither landed a matching criterion, so the correct text has
    // sat here with no drift detector. The orchestrator's recorded decision was
    // to extend this scan rather than retro-fit an AC onto a shipped story.
    assert.match(readme, /Four rejection classes emit no line at all/);
    assert.match(readme, /431/);
    assert.match(readme, /refused by the connection cap/);
    assert.match(readme, /too long to send its headers/);
    assert.match(readme, /refused during drain/);
  });
});

// ===========================================================================
// 7. docs/prd.md §5.15.3 — the trust boundary (NFR-32, ADR-R7)
// ===========================================================================

/** The bold lead-in that identifies a non-defence, which is what the two lists share. */
function nonDefenceBullets(lines: readonly string[], headingIndex: number): string[] {
  const members: string[] = [];
  for (let i = headingIndex + 1; i < lines.length; i += 1) {
    const line = lines[i] as string;
    // Both lists open with a lead-in paragraph between the heading and the
    // first bullet, so scanning skips forward until the list starts and stops
    // at the first line after it that is not one.
    if (!line.startsWith('- ')) {
      if (members.length > 0) break;
      // …but not past the end of the section it belongs to.
      if (/^#/.test(line) || /^---\s*$/.test(line)) break;
      continue;
    }
    assert.match(line, /^- \*\*(.+?)\*\*/, `a non-defence carries no bold lead-in to key on`);
    members.push(line);
  }
  return members;
}

/** The bold lead-in, which is the part the two lists share verbatim. */
function leadIn(bullet: string): string {
  return ((/^- \*\*(.+?)\*\*/.exec(bullet) as RegExpExecArray)[1] as string).trim();
}

describe('US-30 §7: docs/prd.md §5.15.3 exists and matches ADR-05 (NFR-32)', () => {
  const prd = read('docs/prd.md');
  const lines = prd.split(/\r?\n/);

  test('the subsection exists with all five named parts, so a stub cannot satisfy it', () => {
    assert.match(prd, /^#### 5\.15\.3 /m);
    for (const part of [
      /^\*\*Assets\.\*\*/m,
      /^\*\*Trust zones and the boundary between them\.\*\*/m,
      /^\*\*Entry points across the boundary\.\*\*/m,
      /^\*\*Controls at each entry point, and the requirement that owns each\.\*\*/m,
      /^\*\*What is deliberately not defended against\.\*\*/m,
    ]) {
      assert.match(prd, part, `§5.15.3 is missing a named part: ${part}`);
    }
  });

  test('every entry point resolves to a requirement ID present in §5.15', () => {
    const sectionStart = lines.findIndex((line) => /^### 5\.15 /.test(line));
    assert.notEqual(sectionStart, -1, '§5.15 is no longer a locatable heading');
    const sectionEnd = lines.findIndex(
      (line, index) => index > sectionStart && /^### 5\.16 |^## 6\. /.test(line),
    );
    const section = lines.slice(sectionStart, sectionEnd === -1 ? undefined : sectionEnd).join('\n');
    const present = new Set(section.match(/\b(?:FR|NFR)-\d+\b/g) ?? []);
    assert.ok(present.size > 0, 'the scan matched nothing, so it proves nothing');

    // The control table is where each entry point is bound to its owner.
    const controlRows = lines.filter((line) => /^\| (?:MCP endpoint|`GET \/|All three)/.test(line));
    assert.ok(controlRows.length >= 3, `the control table has ${controlRows.length} rows`);

    const entryPoints = new Map<string, Set<string>>();
    for (const row of controlRows) {
      const cells = row.split('|').map((cell) => cell.trim());
      const entry = cells[1] as string;
      const owners = (cells[3] ?? '').match(/\b(?:FR|NFR)-\d+\b/g) ?? [];
      const bucket = entryPoints.get(entry) ?? new Set<string>();
      for (const owner of owners) bucket.add(owner);
      entryPoints.set(entry, bucket);
    }
    for (const [entry, owners] of entryPoints) {
      assert.ok(owners.size > 0, `${entry} names no owning requirement`);
      for (const owner of owners) {
        assert.ok(present.has(owner), `${entry} cites ${owner}, which is absent from §5.15`);
      }
    }

    // NFR-32 names the ten that must each be cited by at least one control. A
    // control table that silently drops a requirement is the failure this
    // target exists to catch.
    const cited = new Set([...entryPoints.values()].flatMap((owners) => [...owners]));
    for (const required of [
      'FR-64',
      'FR-65',
      'FR-66',
      'FR-67',
      'FR-71',
      'FR-73',
      'FR-76',
      'FR-77',
      'FR-78',
      'FR-81',
    ]) {
      assert.ok(cited.has(required), `${required} is cited by no control in §5.15.3`);
    }
  });

  test("§5.15.3's non-defence list EQUALS ADR-05's, member for member (ADR-R7)", () => {
    // Both lists live in `docs/prd.md` — §5.15.3's here, ADR-05's in its §11
    // paste — so NFR-32's "single in-file scan" compares them directly.
    //
    // Keyed on the bold LEAD-IN rather than on the whole bullet, deliberately.
    // The bodies genuinely differ: the ADR copy carries "(Added in Revision 2)"
    // parentheticals and the PRD copy carries trailing requirement citations.
    // A byte-equality assertion would be red at HEAD for a reason that is not
    // drift, and the first thing anyone would do is delete it.
    // §5.15.3 opens its list with a bolded paragraph lead-in; ADR-05's §11
    // paste opens its own with a heading. Both are located by their own form so
    // that neither can be silently retitled into the other's.
    const prdIndex = lines.findIndex((line) =>
      /^\*\*What is deliberately not defended against\.\*\*/.test(line),
    );
    const adrIndex = lines.findIndex((line) =>
      /^#+ What is deliberately not defended against\s*$/.test(line),
    );
    assert.notEqual(prdIndex, -1, '§5.15.3 no longer carries a non-defence list');
    assert.notEqual(adrIndex, -1, "ADR-05's non-defence list is no longer in docs/prd.md");

    const prdBullets = nonDefenceBullets(lines, prdIndex);
    const adrBullets = nonDefenceBullets(lines, adrIndex);
    const first = prdBullets.map(leadIn);
    const second = adrBullets.map(leadIn);
    assert.ok(first.length > 0 && second.length > 0, 'a non-defence list is empty');

    const a = new Set(first);
    const b = new Set(second);
    assert.deepEqual(
      first.filter((member) => !b.has(member)),
      [],
      'a non-defence is present in one list and absent from the other',
    );
    assert.deepEqual(
      second.filter((member) => !a.has(member)),
      [],
      'a non-defence is present in one list and absent from the other',
    );
    assert.equal(first.length, second.length, 'the two lists differ in length');

    // The six NFR-32 requires present in BOTH by name, because each is the
    // recorded consequence of an adjudicated escalation or residual.
    for (const required of [
      /inert/i,
      /probe connection headroom/i,
      /occupy every session slot/i,
      /length floor, not an entropy floor/i,
      /`auth=none` mode on loopback/i,
      /reliable product fingerprint/i,
    ]) {
      assert.ok(prdBullets.some((m) => required.test(m)), `§5.15.3 drops ${required}`);
      assert.ok(adrBullets.some((m) => required.test(m)), `ADR-05 drops ${required}`);
    }
  });
});

// ===========================================================================
// 8. The container workflow gates a pull request (FR-75, ADR-R2)
// ===========================================================================

/**
 * A deliberately small workflow reader: top-level keys, and each job's own
 * block. Enough to answer "what does this job carry", and no more — the
 * repository has no YAML parser and adding one for a source scan would trade a
 * dependency for a convenience.
 */
function workflowJobs(source: string): Map<string, string> {
  const lines = source.split(/\r?\n/);
  const jobsStart = lines.findIndex((line) => /^jobs:\s*$/.test(line));
  assert.notEqual(jobsStart, -1, 'the workflow declares no jobs');
  const jobs = new Map<string, string>();
  let current: string | null = null;
  let body: string[] = [];
  for (const line of lines.slice(jobsStart + 1)) {
    const header = /^ {2}([A-Za-z_][\w-]*):\s*$/.exec(line);
    if (header) {
      if (current) jobs.set(current, body.join('\n'));
      current = header[1] as string;
      body = [];
      continue;
    }
    if (/^\S/.test(line) && line.trim() !== '') break;
    // YAML comments are not job content. Dropping them matters: a comment
    // explaining why a job does NOT carry `continue-on-error` would otherwise
    // read as the job carrying it, and the comment block introducing one job
    // is indented as part of the previous one.
    if (line.trim().startsWith('#')) continue;
    if (current) body.push(line);
  }
  if (current) jobs.set(current, body.join('\n'));
  return jobs;
}

/** A job-level key, at exactly four spaces of indentation. */
function jobKey(body: string, key: string): string | null {
  const match = new RegExp(`^ {4}${key}:(.*)$`, 'm').exec(body);
  return match ? (match[1] as string).trim() : null;
}

function triggers(source: string): string[] {
  const lines = source.split(/\r?\n/);
  const start = lines.findIndex((line) => /^on:\s*$/.test(line));
  assert.notEqual(start, -1, 'the workflow declares no `on:` block');
  const found: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line) && line.trim() !== '') break;
    const key = /^ {2}([a-z_]+):/.exec(line);
    if (key) found.push(key[1] as string);
  }
  return found;
}

describe('US-30 §8: container.yml carries a pull-request-gating job (FR-75, ADR-R2)', () => {
  const source = read(CONTAINER_WORKFLOW);

  test('the workflow is pull-request triggered', () => {
    assert.ok(triggers(source).includes('pull_request'), 'container.yml no longer runs on PRs');
  });

  test('at least one job carries no continue-on-error and no github.event_name condition', () => {
    // The mechanised form of ADR-05's "this decision is not merged until the
    // harness exists". A job that is skipped on pull requests, or that swallows
    // its own failure, is a check that does not gate — which is the defect
    // ADR-R2 records as unenforced.
    const jobs = workflowJobs(source);
    assert.ok(jobs.size > 0, 'the scan matched no jobs, so it proves nothing');
    const gating = [...jobs.entries()].filter(([, body]) => {
      if (jobKey(body, 'continue-on-error') !== null) return false;
      const condition = jobKey(body, 'if');
      return condition === null || !condition.includes('github.event_name');
    });
    assert.ok(
      gating.length > 0,
      `every job in ${CONTAINER_WORKFLOW} is either non-blocking or skipped on pull requests: ` +
        [...jobs.keys()].join(', '),
    );
  });
});

// ===========================================================================
// 9. The Dockerfile declares no top-level CMD (FR-62)
// ===========================================================================

describe('US-30 §9: the Dockerfile declares no top-level CMD (FR-62)', () => {
  const dockerfile = read('Dockerfile');

  /** FR-62's rule, verbatim: join backslash continuations, then take the first token. */
  function firstTokens(source: string): string[] {
    return source
      .replace(/\\\r?\n\s*/g, ' ')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== '' && !line.startsWith('#'))
      .map((line) => line.split(/\s+/)[0] as string);
  }

  test('no line whose first token is CMD, after joining continuations', () => {
    const tops = firstTokens(dockerfile);
    assert.deepEqual(
      tops.filter((token) => token === 'CMD'),
      [],
      'a top-level CMD would make the serving transport an argv default (FR-62)',
    );
    assert.ok(tops.includes('HEALTHCHECK'), 'the scan matched nothing, so it proves nothing');
    assert.ok(tops.includes('ENTRYPOINT'), 'the exec-form ENTRYPOINT must survive');
  });

  test('the parse rule is load-bearing — a naive search falsifies a correct Dockerfile', () => {
    // If this stops matching, the rule above has become decoration. Until then
    // it cannot: `CMD` is genuinely present, on a backslash continuation, as an
    // argument to HEALTHCHECK.
    assert.ok(dockerfile.includes('CMD'), 'the token must be present for the rule to matter');
    assert.ok(
      /\\\r?\n\s*CMD /.test(dockerfile),
      'the CMD sits on a continuation line, which is exactly what the join handles',
    );
  });
});
