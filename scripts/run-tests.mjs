#!/usr/bin/env node
/**
 * Cross-platform test discovery.
 *
 * `npm test` previously passed `test/*.test.ts` straight to node and relied on
 * the shell to expand it. POSIX shells do; cmd.exe and PowerShell do not, so
 * the Windows CI leg failed with `Could not find 'test\*.test.ts'` — a real
 * portability break against NFR-20, caught only because CI runs all three
 * platforms.
 *
 * Letting node discover them instead is not an option on Node 20: its test
 * runner only auto-discovers `.js`, and glob support for positional arguments
 * landed in Node 21. So discovery happens here, where it behaves identically
 * everywhere and a new test file is picked up without editing package.json.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const testDir = join(repoRoot, 'test');

const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.ts'))
  .sort()
  .map((name) => join(testDir, name));

if (files.length === 0) {
  console.error(`No *.test.ts files found in ${testDir}`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', '--import', 'tsx', ...files], {
  stdio: 'inherit',
  cwd: repoRoot,
});

process.exit(result.status ?? 1);
