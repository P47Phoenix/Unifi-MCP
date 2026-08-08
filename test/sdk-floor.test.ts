/**
 * The SDK floor, the canary, and the HTTP Inspector script (US-31, NFR-28).
 *
 * The defect NFR-28 exists against is narrow and easy to miss: `npm ci` installs
 * the LOCKFILE, and the lockfile is not what a consumer gets. A consumer running
 * `npm install unifi-mcp` gets whatever the DECLARED RANGE resolves to on the
 * day they run it, and the lowest member of that range is the one nobody ever
 * builds. A green CI run therefore says nothing about the floor.
 *
 * Everything here is a claim about `package.json` and `.github/workflows/ci.yml`
 * as text. That is deliberate: the jobs themselves cannot be executed locally,
 * so the properties that make them load-bearing — no `continue-on-error` on the
 * blocking one, `continue-on-error` on the reporting one, a schedule so drift
 * surfaces between pull requests — are asserted where they are written down.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test, describe } from 'node:test';
import { fileURLToPath } from 'node:url';

// URL.pathname yields `/D:/a/...` on Windows, which readFileSync cannot open.
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

function read(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf8');
}

const manifest = JSON.parse(read('package.json')) as {
  dependencies: Record<string, string>;
  scripts: Record<string, string>;
};
const ci = read('.github/workflows/ci.yml');

/**
 * A deliberately small workflow reader: each job's own block, keyed by name.
 * The repository has no YAML parser and adding one for a source scan would
 * trade a dependency for a convenience.
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

const jobs = workflowJobs(ci);

// ---------------------------------------------------------------------------
// 1. The declared floor
// ---------------------------------------------------------------------------

describe('US-31 §1: the declared SDK range (NFR-28, RC-1)', () => {
  test('the literal declared range is exactly `~1.30.0`', () => {
    // A caret range admits 1.99.0, which is the drift this requirement exists
    // to prevent — and the reason it is asserted as a LITERAL STRING rather
    // than by semver satisfaction is that `^1.30.0` and `~1.30.0` both satisfy
    // 1.30.x, so a satisfaction check would not notice the widening.
    assert.equal(manifest.dependencies['@modelcontextprotocol/sdk'], '~1.30.0');
  });

  test('the installed SDK actually satisfies the declared floor', () => {
    // Anti-vacuity of a different kind: the string above is a claim about what
    // the manifest says, not about what is on disk. Without this, the range
    // could be narrowed to a version nobody has ever run.
    const installed = JSON.parse(
      read('node_modules/@modelcontextprotocol/sdk/package.json'),
    ) as { version: string };
    const [major, minor] = installed.version.split('.');
    assert.equal(`${major}.${minor}`, '1.30', `installed ${installed.version}`);
  });
});

// ---------------------------------------------------------------------------
// 2. The `sdk-floor` job — blocking, by construction
// ---------------------------------------------------------------------------

describe('US-31 §2: the sdk-floor job gates a merge (NFR-28, §14 item 17)', () => {
  const body = jobs.get('sdk-floor');

  test('the job exists and is a single ubuntu-latest leg', () => {
    assert.ok(body, 'ci.yml declares no sdk-floor job');
    assert.equal(jobKey(body, 'runs-on'), 'ubuntu-latest');
    assert.equal(jobKey(body, 'strategy'), null, 'a matrix would make this more than one leg');
  });

  test('it carries NO continue-on-error, at the job level or on any step', () => {
    // This is the whole point. A non-blocking floor check is precisely the
    // defect NFR-28 was written against: it would observe the breakage and
    // ship it. Steps are checked too, because a `continue-on-error` on the
    // suite step makes the job green while the suite fails.
    assert.equal(jobKey(body as string, 'continue-on-error'), null);
    assert.doesNotMatch(body as string, /continue-on-error/);
  });

  test('it is not skipped on pull requests, and ci.yml runs on pull requests', () => {
    // "In the required-status set" is branch-protection configuration and lives
    // outside the repository, so it cannot be asserted here. What CAN be
    // asserted is every property that makes the job eligible to be required:
    // it runs on the pull-request event, and it does not opt itself out.
    const condition = jobKey(body as string, 'if');
    assert.equal(condition, null, `sdk-floor is conditioned on ${condition}`);
    assert.match(ci, /^ {2}pull_request:/m, 'ci.yml no longer runs on pull_request');
  });

  test('it installs the floor rather than the lockfile, and proves what it installed', () => {
    const source = body as string;
    assert.match(source, /npm ci/, 'the job skips the normal install');
    assert.match(source, /npm i --no-save "@modelcontextprotocol\/sdk@/, 'the lockfile is not overridden');
    // The version it installs is READ OUT of package.json rather than written
    // into the workflow, so the job and the manifest cannot drift apart — which
    // is the failure mode that would leave this job testing the wrong floor
    // while still reporting green.
    assert.match(source, /require\('\.\/package\.json'\)\.dependencies\['@modelcontextprotocol\/sdk'\]/);
    assert.match(source, /node_modules\/@modelcontextprotocol\/sdk\/package\.json/);
  });

  test('it builds and runs the serving-transport suite against that install', () => {
    const source = body as string;
    assert.match(source, /npm run build/);
    assert.match(source, /node --test .*--import tsx/s);
    assert.match(source, /test\/serve-\*\.test\.ts/, 'the serving-transport suite is not run');
  });
});

// ---------------------------------------------------------------------------
// 3. The `sdk-canary` job — reporting, by construction
// ---------------------------------------------------------------------------

describe('US-31 §3: the sdk-canary job reports drift without gating (NFR-28, R-16)', () => {
  const body = jobs.get('sdk-canary');

  test('the job exists and runs the same steps against @latest', () => {
    assert.ok(body, 'ci.yml declares no sdk-canary job');
    assert.equal(jobKey(body, 'runs-on'), 'ubuntu-latest');
    assert.match(body, /npm ci/);
    assert.match(body, /@modelcontextprotocol\/sdk@latest/);
    assert.match(body, /npm run build/);
    assert.match(body, /test\/serve-\*\.test\.ts/);
  });

  test('it carries continue-on-error: true at the JOB level', () => {
    // At the job level specifically: a step-level flag alone would still fail
    // the job on any step nobody thought to mark, so a vendor release could
    // still turn a commit red that changed nothing.
    assert.equal(jobKey(body as string, 'continue-on-error'), 'true');
  });

  test('it writes the resolved version and any failure to the job summary', () => {
    const source = body as string;
    assert.match(source, /GITHUB_STEP_SUMMARY/, 'the canary reports nowhere');
    assert.match(source, /steps\.latest\.outputs\.version/, 'the resolved version is not reported');
    assert.match(source, /steps\.build\.outcome/);
    assert.match(source, /steps\.suite\.outcome/);
    // The report is the deliverable, so it must survive the failure it reports.
    assert.match(source, /if: always\(\)/);
  });

  test('the workflow carries a weekly schedule so drift shows between pull requests', () => {
    const cron = /^ {4}- cron: '([^']+)'/m.exec(ci);
    assert.ok(cron, 'ci.yml declares no schedule');
    const fields = (cron[1] as string).trim().split(/\s+/);
    assert.equal(fields.length, 5, `a cron expression has five fields, not ${fields.length}`);
    // Weekly means: pinned to a day of week, and not narrowed by a day of month.
    assert.notEqual(fields[4], '*', 'the schedule is not weekly — no day of week is pinned');
    assert.equal(fields[2], '*', 'a day-of-month restriction makes this less than weekly');
    assert.match(ci, /^ {2}schedule:/m);
  });

  test('the two jobs are distinguishable — one blocks, one does not', () => {
    // Asserted as a pair, because the failure that matters is the two being
    // accidentally made alike: a canary that gates turns vendor releases into
    // red builds, and a floor check that does not gate is NFR-28's own defect.
    const floor = jobs.get('sdk-floor') as string;
    const canary = body as string;
    assert.equal(/continue-on-error/.test(floor), false);
    assert.equal(/continue-on-error/.test(canary), true);
  });
});

// ---------------------------------------------------------------------------
// 4. `inspect:cli:http` — the HTTP analogue of the stdio smoke test
// ---------------------------------------------------------------------------

describe('US-31 §4: the inspect:cli:http script', () => {
  const script = manifest.scripts['inspect:cli:http'];

  test('it exists as a sibling of the stdio script', () => {
    assert.ok(script, 'package.json declares no inspect:cli:http script');
    assert.ok(manifest.scripts['inspect:cli'], 'the stdio sibling it mirrors has gone');
  });

  test('it starts the server under the HTTP transport on an ephemeral port', () => {
    const source = script as string;
    assert.match(source, /UNIFI_MCP_TRANSPORT=http/);
    // FR-63: port 0 is the ephemeral request, and the bound port is read back
    // off the serving line rather than guessed — which is also what proves the
    // listener-address seam is wired, since a fallback to the configured value
    // would print `:0` and the script would drive nothing.
    assert.match(source, /UNIFI_HTTP_PORT=0/);
    assert.match(source, /serving MCP over http at/);
    assert.match(source, /node dist\/index\.js/);
  });

  test('the secret is generated per run, not written into the manifest', () => {
    const source = script as string;
    assert.match(source, /randomBytes\(/, 'the shared secret is not generated');
    assert.match(source, /UNIFI_HTTP_TOKEN="\$SECRET"/);
    // A literal secret in package.json would be a committed credential, and
    // FR-81's 32-character floor would make it a long and convincing one.
    assert.doesNotMatch(source, /UNIFI_HTTP_TOKEN=[A-Za-z0-9]{8}/);
  });

  test('it drives tools/list against the bound endpoint with an Authorization header', () => {
    const source = script as string;
    assert.match(source, /--method tools\/list/);
    assert.match(source, /--header "Authorization: Bearer \$SECRET"/);
    assert.match(source, /--transport http/);
    assert.match(source, /http:\/\/\$ENDPOINT/);
    assert.match(source, /@modelcontextprotocol\/inspector/);
  });

  test('it cleans up the server it spawned, on every exit path', () => {
    // Without the trap a failed Inspector run leaves a listener holding a live
    // credential on the developer's machine, and on a CI runner it leaves the
    // job hanging on an open handle.
    assert.match(script as string, /trap '[^']*kill \$SERVER/);
    assert.match(script as string, /EXIT INT TERM/);
  });
});

// ---------------------------------------------------------------------------
// 5. The Inspector job invokes it, on POSIX legs only
// ---------------------------------------------------------------------------

describe('US-31 §5: ci.yml runs the HTTP Inspector smoke test on POSIX legs', () => {
  const verify = jobs.get('verify') as string;

  test('the verify job invokes the new script', () => {
    assert.ok(verify, 'ci.yml declares no verify job');
    assert.match(verify, /npm run inspect:cli:http/);
    // …alongside, not instead of, the stdio smoke test it mirrors.
    assert.match(verify, /--method tools\/list/, 'the stdio Inspector step has gone');
  });

  test('the step is guarded to POSIX legs', () => {
    // It spawns a server process, reads its bound port off stderr and signals
    // it on the way out. Windows is a development and stdio platform for this
    // round (OQ-18) and NFR-27 scopes the shutdown guarantee to POSIX, so a
    // Windows leg here would assert a guarantee the product does not make.
    const step = /- name: MCP Inspector CLI smoke test over HTTP\n([\s\S]*?)\n\n/.exec(verify);
    assert.ok(step, 'the HTTP Inspector step is not where its guard can be read');
    assert.match(step[1] as string, /if: runner\.os != 'Windows'/);
  });

  test('the matrix still covers all three platforms, so the guard is a guard', () => {
    // If the matrix were POSIX-only the `if:` above would be decoration, and
    // nobody reading it would know the exclusion was ever real.
    assert.match(verify, /windows-latest/);
    assert.match(verify, /macos-latest/);
    assert.match(verify, /ubuntu-latest/);
  });
});
