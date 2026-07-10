/**
 * taintgate `scan` tests.
 *
 * Drives `runScan` / `performScan` against committed fixture configs under
 * test/fixtures/scan and asserts findings, severities and exit codes. Pure
 * static inspection — no MCP server is spawned or contacted.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { join } from 'node:path';

import { runScan, performScan, type ScanResult } from '../../cli/scan';

// Jest runs with cwd at the project root, so resolve fixtures from there.
const fixtureDir = join(process.cwd(), 'test/fixtures/scan');
const fixture = (name: string): string => join(fixtureDir, name);

/** Capture everything written to stdout while `fn` runs. */
async function captureStdout(fn: () => Promise<number>): Promise<{ out: string; code: number }> {
  const chunks: string[] = [];
  const spy = jest
    .spyOn(process.stdout, 'write')
    .mockImplementation((chunk: unknown): boolean => {
      chunks.push(typeof chunk === 'string' ? chunk : String(chunk));
      return true;
    });
  try {
    const code = await fn();
    return { out: chunks.join(''), code };
  } finally {
    spy.mockRestore();
  }
}

function findServer(result: ScanResult, name: string) {
  for (const cfg of result.configs) {
    const s = cfg.servers.find((sv) => sv.name === name);
    if (s) return s;
  }
  return undefined;
}

describe('taintgate scan', () => {
  describe('secret in env', () => {
    it('flags a plaintext token as HIGH and exits 1 in JSON mode', async () => {
      const { out, code } = await captureStdout(() => runScan(['--config', fixture('secret-env.json'), '--json']));
      const parsed = JSON.parse(out) as {
        executedServers: boolean;
        highOrAbove: number;
        severityCounts: Record<string, number>;
        configs: Array<{ servers: Array<{ name: string; findings: Array<{ rule: string; severity: string }> }> }>;
      };
      expect(code).toBe(1);
      expect(parsed.executedServers).toBe(false);
      expect(parsed.highOrAbove).toBeGreaterThanOrEqual(1);
      const server = parsed.configs[0]!.servers.find((s) => s.name === 'github')!;
      const secretFinding = server.findings.find((f) => f.rule === 'secret-in-env');
      expect(secretFinding).toBeDefined();
      expect(secretFinding!.severity).toBe('HIGH');
    });

    it('--no-fail downgrades the exit code to 0 while still reporting', async () => {
      const { code } = await captureStdout(() =>
        runScan(['--config', fixture('secret-env.json'), '--json', '--no-fail'])
      );
      expect(code).toBe(0);
    });
  });

  describe('filesystem broad scope', () => {
    it('flags a filesystem server rooted at "/" as HIGH', async () => {
      const result = performScan({ explicitConfig: fixture('filesystem-root.json'), cwd: process.cwd() });
      const server = findServer(result, 'filesystem');
      expect(server).toBeDefined();
      expect(server!.maxSeverity).toBe('HIGH');
      const broad = server!.findings.find((f) => f.rule === 'filesystem-broad-scope');
      expect(broad).toBeDefined();
      expect(broad!.severity).toBe('HIGH');
    });
  });

  describe('remote http url', () => {
    it('flags a non-local http endpoint as HIGH and reads the "servers" key', async () => {
      const result = performScan({ explicitConfig: fixture('remote-http.json'), cwd: process.cwd() });
      const server = findServer(result, 'weather-api');
      expect(server).toBeDefined();
      expect(server!.kind).toBe('remote');
      const insecure = server!.findings.find((f) => f.rule === 'remote-insecure');
      expect(insecure).toBeDefined();
      expect(insecure!.severity).toBe('HIGH');
      expect(result.severityCounts.HIGH).toBe(1);
    });
  });

  describe('clean config', () => {
    it('produces no HIGH+ findings and exits 0', async () => {
      const { code } = await captureStdout(() => runScan(['--config', fixture('clean.json')]));
      expect(code).toBe(0);
      const result = performScan({ explicitConfig: fixture('clean.json'), cwd: process.cwd() });
      expect(result.severityCounts.HIGH).toBe(0);
      expect(result.severityCounts.CRITICAL).toBe(0);
      // A specific-subdir filesystem grant is LOW, not HIGH.
      const fsServer = findServer(result, 'filesystem-docs');
      expect(fsServer!.maxSeverity).toBe('LOW');
      const scoped = fsServer!.findings.find((f) => f.rule === 'filesystem-scoped');
      expect(scoped).toBeDefined();
      // A pinned, scoped package must NOT raise a supply-chain finding.
      expect(fsServer!.findings.some((f) => f.rule === 'supply-chain-unpinned')).toBe(false);
    });
  });

  describe('no configs found', () => {
    it('exits 0 gracefully when the explicit config does not exist', async () => {
      const { out, code } = await captureStdout(() => runScan(['--config', fixture('does-not-exist.json')]));
      expect(code).toBe(0);
      expect(out).toContain('taintgate scan');
    });

    it('performScan records a parse error but reports zero servers', () => {
      const result = performScan({ explicitConfig: fixture('does-not-exist.json'), cwd: process.cwd() });
      expect(result.serverCount).toBe(0);
      expect(result.parseErrors.length).toBe(1);
    });

    it('handles a config with an empty server table', () => {
      const result = performScan({ explicitConfig: fixture('empty.json'), cwd: process.cwd() });
      expect(result.serverCount).toBe(0);
      expect(result.configs.length).toBe(1);
    });
  });

  describe('help and flag parsing', () => {
    it('prints help and exits 0', async () => {
      const { out, code } = await captureStdout(() => runScan(['--help']));
      expect(code).toBe(0);
      expect(out).toContain('taintgate scan');
      expect(out).toContain('--config');
    });

    it('returns exit code 2 on an unknown flag', async () => {
      const spy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
      try {
        const code = await runScan(['--bogus']);
        expect(code).toBe(2);
      } finally {
        spy.mockRestore();
      }
    });
  });
});
