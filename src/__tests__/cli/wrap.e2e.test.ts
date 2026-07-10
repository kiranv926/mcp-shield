/**
 * taintgate `wrap` end-to-end test.
 *
 * Spawns the real CLI (run from source via tsx) wrapping the committed offline
 * stub MCP server, then drives it with JSON-RPC over stdio and asserts on the
 * governed responses. No network required.
 *
 * Covered: ALLOW passthrough, REDACT of secret output, fail-closed BLOCK of an
 * un-annotated tool, and taint propagation (a benign tool escalates to REDACT
 * once its arguments carry data tainted by an earlier secret read).
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface, type Interface } from 'node:readline';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Jest runs with cwd at the project root (rootDir), so resolve fixtures from there.
const repoRoot = process.cwd();
const cliEntry = join(repoRoot, 'src/cli/index.ts');
const stubServer = join(repoRoot, 'test/fixtures/stub-mcp-server.mjs');

/** The secret the stub's read_secret tool returns (kept in sync with the fixture). */
const FAKE_SECRET = 'secret_key=EXAMPLEfakeDoNotUse0123456789abcdef';

interface RpcResponse {
  jsonrpc: string;
  id: number | string;
  result?: { content?: Array<{ type: string; text?: string }>; tools?: Array<{ name: string }> };
  error?: { code: number; message: string; data?: unknown };
}

class ProxyHarness {
  private proc: ChildProcess;
  private rl: Interface;
  private responses = new Map<string, RpcResponse>();
  private waiters = new Map<string, (r: RpcResponse) => void>();
  private stderrBuf = '';

  constructor(logDir: string) {
    this.proc = spawn(
      process.execPath,
      ['--import', 'tsx', cliEntry, 'wrap', '--log', logDir, '--', 'node', stubServer],
      { cwd: repoRoot, stdio: ['pipe', 'pipe', 'pipe'] }
    );
    this.proc.stderr!.on('data', (d: Buffer) => {
      this.stderrBuf += d.toString();
    });
    this.rl = createInterface({ input: this.proc.stdout!, crlfDelay: Infinity });
    this.rl.on('line', (line) => this.onLine(line));
  }

  private onLine(line: string): void {
    if (line.trim() === '') return;
    let msg: RpcResponse;
    try {
      msg = JSON.parse(line) as RpcResponse;
    } catch {
      return;
    }
    if (msg.id === undefined || msg.id === null) return;
    const key = String(msg.id);
    this.responses.set(key, msg);
    const w = this.waiters.get(key);
    if (w) {
      this.waiters.delete(key);
      w(msg);
    }
  }

  request(obj: Record<string, unknown>, timeoutMs = 8000): Promise<RpcResponse> {
    const key = String(obj.id);
    const p = new Promise<RpcResponse>((resolve, reject) => {
      const existing = this.responses.get(key);
      if (existing) {
        resolve(existing);
        return;
      }
      const timer = setTimeout(() => {
        this.waiters.delete(key);
        reject(new Error(`timeout waiting for response id=${key}\nstderr:\n${this.stderrBuf}`));
      }, timeoutMs);
      this.waiters.set(key, (r) => {
        clearTimeout(timer);
        resolve(r);
      });
    });
    this.proc.stdin!.write(JSON.stringify(obj) + '\n');
    return p;
  }

  get stderr(): string {
    return this.stderrBuf;
  }

  async close(): Promise<void> {
    this.proc.stdin!.end();
    await new Promise<void>((resolve) => {
      const t = setTimeout(() => {
        this.proc.kill('SIGKILL');
        resolve();
      }, 1500);
      this.proc.on('exit', () => {
        clearTimeout(t);
        resolve();
      });
    });
  }
}

function textOf(r: RpcResponse): string {
  return r.result?.content?.map((c) => c.text ?? '').join('') ?? '';
}

describe('taintgate wrap (e2e, offline)', () => {
  let logDir: string;
  let harness: ProxyHarness;

  beforeAll(async () => {
    logDir = mkdtempSync(join(tmpdir(), 'taintgate-e2e-'));
    harness = new ProxyHarness(logDir);
    // Complete the MCP handshake and warm the tool-annotation cache.
    const init = await harness.request({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    expect(init.result?.serverInfo ?? init.result).toBeTruthy();
    const list = await harness.request({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    expect(list.result?.tools?.map((t) => t.name)).toEqual(
      expect.arrayContaining(['echo', 'read_secret', 'publish'])
    );
  }, 30000);

  afterAll(async () => {
    if (harness) await harness.close();
    if (logDir) rmSync(logDir, { recursive: true, force: true });
  });

  it('ALLOWs a benign tool and passes its result through unchanged', async () => {
    const res = await harness.request({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'echo', arguments: { message: 'hello world' } },
    });
    expect(res.error).toBeUndefined();
    expect(textOf(res)).toContain('hello world');
  });

  it('REDACTs secret output so the raw credential never reaches the client', async () => {
    const res = await harness.request({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'read_secret', arguments: {} },
    });
    const text = textOf(res);
    // Either the call is blocked, or the secret is scrubbed — never leaked.
    if (res.error) {
      expect(res.error.code).toBe(-32001);
    } else {
      expect(text).not.toContain(FAKE_SECRET);
      expect(text).toContain('[REDACTED]');
    }
  });

  it('fail-closed BLOCKs an un-annotated tool with a JSON-RPC security error', async () => {
    const res = await harness.request({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'unlisted_tool', arguments: { x: 1 } },
    });
    expect(res.result).toBeUndefined();
    expect(res.error?.code).toBe(-32001); // POLICY_VIOLATION
  });

  it('propagates taint: a benign sink escalates to REDACT when fed secret-derived data', async () => {
    // Baseline: publish with untainted data is ALLOWed and passes through.
    const benign = await harness.request({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'publish', arguments: { data: 'a normal status update' } },
    });
    expect(benign.error).toBeUndefined();
    expect(textOf(benign)).toContain('a normal status update');

    // Now publish data that embeds the secret read earlier — taint lineage must
    // escalate the decision and the secret must be scrubbed out of the result.
    const tainted = await harness.request({
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'publish', arguments: { data: `exfiltrating ${FAKE_SECRET}` } },
    });
    expect(textOf(tainted)).not.toContain(FAKE_SECRET);
    expect(harness.stderr).toContain('taint from: read_secret');
  });
});
