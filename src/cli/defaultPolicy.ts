/**
 * taintgate CLI: starter policy for `init-config`.
 *
 * Shape mirrors examples/policy-example.json (consumed by PolicyManager). The
 * global block gives fail-closed-ish defaults (allow < 0.3, block >= 0.7) and a
 * couple of illustrative tool overrides so users have something to edit.
 */

import { writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

export const DEFAULT_POLICY = {
  version: '1.0.0',
  global: {
    riskThresholds: { allow: 0.3, block: 0.7 },
    weights: { sensitivity: 0.6, exposure: 0.4 },
    enabled: true,
  },
  tools: {
    'example:write_row': { actionOverride: 'BLOCK', enabled: true },
    'example:read_row': { actionOverride: 'REDACT', enabled: true },
  },
} as const;

export const DEFAULT_POLICY_FILENAME = 'taintgate.policy.json';

/**
 * Write the starter policy to `path` (or ./taintgate.policy.json). Refuses to
 * overwrite an existing file so a user cannot clobber a real policy by accident.
 *
 * @returns The absolute path the policy was written to.
 */
export function writeInitConfig(path?: string): string {
  const target = resolve(path ?? DEFAULT_POLICY_FILENAME);
  if (existsSync(target)) {
    throw new Error(`refusing to overwrite existing file: ${target}`);
  }
  writeFileSync(target, JSON.stringify(DEFAULT_POLICY, null, 2) + '\n', 'utf8');
  return target;
}
