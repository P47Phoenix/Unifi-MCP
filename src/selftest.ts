/**
 * Credential-free image/install integrity check (`--selftest`).
 *
 * Extracted verbatim from `src/index.ts:33-85` by US-18. The entrypoint has to
 * shrink to a shape where "the signal handlers are the first statements of
 * `main()`" is assertable by a source scan (FR-80), and a fifty-line self-test
 * body sitting above `main()` is the largest thing in the way.
 *
 * This module deliberately imports nothing from `src/serve/`. Architecture §9.4
 * permits the literal `serve/` in an import specifier only inside `src/serve/`
 * itself and in `src/index.ts`; a self-test that reached for the serving
 * transport's logger would break that scan for no gain, and it has no serving
 * transport to log through anyway.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildRegistry, type SpecManifest } from './registry/build.js';
import { advertisedTools, PROMOTED_ACTION_IDS } from './tools/index.js';
import { SERVICE_IDS } from './types.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Exists because a container image of a stdio server has no port to probe: a
 * platform team otherwise has no way to tell a working image from one whose
 * `specs/` layer was dropped by a bad COPY. Deliberately independent of
 * credentials and of `UNIFI_*` configuration, so it answers "is this artifact
 * intact" and not "is this deployment configured" — a health check that fails
 * on a missing API key would report the wrong problem.
 *
 * This path never connects a transport, so writing to stdout here does not
 * violate NFR-19. It is also why the D-14 stderr rule does not reach it: the
 * self-test's channel is stdout, by requirement, and `emitDiagnostic` writes to
 * stderr.
 */
export function selfTest(): number {
  const problems: string[] = [];
  let manifest: SpecManifest;
  try {
    manifest = JSON.parse(
      readFileSync(join(REPO_ROOT, 'specs', 'manifest.json'), 'utf8'),
    ) as SpecManifest;
  } catch (e) {
    process.stdout.write(
      `${JSON.stringify({ ok: false, error: `specs/manifest.json unreadable at ${REPO_ROOT}: ${String(e)}` })}\n`,
    );
    return 1;
  }

  // Every service, regardless of configuration: this checks the artifact.
  const registry = buildRegistry(REPO_ROOT, manifest, new Set(SERVICE_IDS));
  const tools = advertisedTools(new Set(SERVICE_IDS), new Set(SERVICE_IDS));

  for (const [toolName, actionId] of Object.entries(PROMOTED_ACTION_IDS)) {
    if (!registry.byId.has(actionId)) {
      problems.push(`${toolName} has no backing action \`${actionId}\``);
    }
  }
  if (registry.actions.length === 0) problems.push('action registry is empty');

  const report = {
    ok: problems.length === 0,
    version: '0.1.0',
    node: process.version,
    platform: `${process.platform}/${process.arch}`,
    actions: registry.actions.length,
    tools: tools.length,
    specs: Object.fromEntries(
      Object.entries(registry.stats).map(([service, s]) => [service, s.version]),
    ),
    problems,
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  return problems.length === 0 ? 0 : 1;
}
