/**
 * taintgate CLI: version resolution.
 *
 * Reads the version from the package's package.json at runtime so the built
 * binary and the dev (tsx) entry report the same value without a bundler
 * baking it in. Resolved relative to this module so it works both from
 * `src/cli/` (dev) and `dist/cli/` (published bin).
 */

import { readFileSync } from 'node:fs';

export function getVersion(): string {
  try {
    const url = new URL('../../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(url, 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
