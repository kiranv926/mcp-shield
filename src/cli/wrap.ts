/**
 * taintgate CLI: `wrap` command — the transparent governance proxy.
 *
 * Spawns the user's MCP server as a child process and bridges newline-delimited
 * JSON-RPC between the MCP client (this process's stdin/stdout) and the server
 * (the child's stdin/stdout):
 *
 *   client --stdin--> taintgate --child.stdin--> server
 *   client <--stdout-- taintgate <--child.stdout-- server
 *
 * Governance is applied to `tools/call` requests only. Protocol methods
 * (initialize, tools/list, ping, notifications, server-initiated requests) pass
 * through untouched so the MCP handshake is never broken — running those through
 * the fail-closed risk engine would BLOCK them (no tool annotations => max risk).
 *
 * For a governed call:
 *   - BLOCK  -> reply to the client with a JSON-RPC security error; never forward.
 *   - ALLOW  -> forward to the server; register taint from the output; return as-is.
 *   - REDACT -> forward to the server; register taint; scrub the output; return.
 *
 * Tool security annotations are learned by observing `tools/list` responses.
 */

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';

import { createPipeline } from './pipeline';
import { ResponseScraper } from '../core/ResponseScraper';
import { TaintGateErrorCodes } from '../types/errors';
import { createRiskScore } from '../types/common';
import { SensitivityLevel } from '../types/mcp-hints';
import {
  loadPinStore,
  savePinStore,
  createEmptyPinStore,
  diffToolsAgainstPins,
  applyPinPolicy,
  recordDiffIntoStore,
  DEFAULT_PIN_FILE,
} from './toolPinning';
import type { MCPToolAnnotations } from '../types/mcp-hints';
import type { JSONRPCRequest, JSONRPCResponse, RequestContext } from '../types/common';
import type { PolicyAction, PolicyDecision } from '../types/governance';
import type { PinPolicy, PinStore, McpToolDefinition } from './toolPinning';

export interface WrapOptions {
  policyPath?: string;
  logDir: string;
  failMode: 'open' | 'closed';
  /** Enable tool-definition pinning (rug-pull / tool-poisoning detection). */
  pin?: boolean;
  /** Path to the pin store ("lock file"); defaults to ./taintgate.lock.json. */
  pinFile?: string;
  /** What to do on a pin violation; defaults to 'warn' when pinning is enabled. */
  pinPolicy?: PinPolicy;
}

/**
 * Parse a single `wrap` flag that belongs to tool-definition pinning.
 *
 * The top-level `wrap` flag loop lives in index.ts (owned by the CLI wiring);
 * this helper is exported so that loop can delegate the `--pin*` flags without
 * duplicating their semantics. `takeVal` returns the flag's value (advancing
 * the caller's argv cursor). Returns true if the key was a pinning flag.
 */
export function parseWrapPinFlag(
  key: string,
  takeVal: () => string,
  opts: WrapOptions
): boolean {
  switch (key) {
    case '--pin':
      opts.pin = true;
      if (opts.pinPolicy === undefined) opts.pinPolicy = 'warn';
      return true;
    case '--pin-file':
      opts.pin = true;
      opts.pinFile = takeVal();
      return true;
    case '--pin-policy': {
      const v = takeVal();
      if (v !== 'off' && v !== 'warn' && v !== 'block' && v !== 'update') {
        throw new Error(`invalid --pin-policy: ${v} (expected off|warn|block|update)`);
      }
      opts.pin = true;
      opts.pinPolicy = v;
      return true;
    }
    default:
      return false;
  }
}

/** Loosely-typed JSON-RPC envelope as parsed off the wire. */
interface RpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

type PendingEntry =
  | { kind: 'govern'; decision: PolicyDecision; context: RequestContext }
  | { kind: 'toolslist' };

function logLine(msg: string): void {
  process.stderr.write(`[taintgate] ${msg}\n`);
}

/** Build a synthetic decision for fail-open / fail-closed error paths. */
function makeDecision(action: PolicyAction, justification: string): PolicyDecision {
  const isAllow = action === 'ALLOW';
  const score = createRiskScore(isAllow ? 0 : 1);
  return {
    action,
    riskScore: score,
    riskBreakdown: {
      sensitivity: isAllow ? 0 : 1,
      exposure: isAllow ? 0 : 1,
      trust: isAllow ? 1 : 0,
      weightSensitivity: 0.6,
      weightExposure: 0.4,
      rawScore: isAllow ? 0 : 1,
      finalScore: score,
    },
    justification,
    timestamp: new Date(),
    policyVersion: 'taintgate-cli',
    requestId: randomUUID(),
  };
}

/** Map an MCP tool's `annotations` object onto TaintGate's security hints. */
function mapAnnotations(name: string, raw: unknown): MCPToolAnnotations {
  const a = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const ann: MCPToolAnnotations = { toolName: name };
  if (typeof a.trusted === 'boolean') ann.trusted = a.trusted;
  if (typeof a.secret === 'boolean') ann.secret = a.secret;
  if (typeof a.openWorld === 'boolean') ann.openWorld = a.openWorld;
  if (typeof a.requireHITL === 'boolean') ann.requireHITL = a.requireHITL;
  if (typeof a.sensitive === 'number') ann.sensitive = a.sensitive as SensitivityLevel;
  if (typeof a.description === 'string') ann.description = a.description;
  return ann;
}

export async function runWrap(cmd: string, args: string[], opts: WrapOptions): Promise<void> {
  const sessionId = randomUUID();
  const pipeline = await createPipeline({ policyPath: opts.policyPath, logDir: opts.logDir });
  const { mediator, taintRegistry, responseRedactor, auditLogger } = pipeline;

  const annotations = new Map<string, MCPToolAnnotations>();
  const pending = new Map<string, PendingEntry>();

  // Tool-definition pinning config (rug-pull / tool-poisoning detection).
  const pinningEnabled = opts.pin === true;
  const pinFile = opts.pinFile ?? DEFAULT_PIN_FILE;
  const pinPolicy: PinPolicy = opts.pinPolicy ?? 'warn';
  const serverLabel = cmd;

  logLine(
    `wrapping: ${cmd} ${args.join(' ')} | policy=${opts.policyPath ?? 'fail-closed-default'} ` +
      `| fail-${opts.failMode} | session=${sessionId.slice(0, 8)}`
  );
  if (pinningEnabled) {
    logLine(`pin: enabled | file=${pinFile} | policy=${pinPolicy}`);
  }

  const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  const childStdin = child.stdin;
  const childStdout = child.stdout;
  const childStderr = child.stderr;
  if (!childStdin || !childStdout || !childStderr) {
    throw new Error('failed to open child stdio pipes');
  }

  child.on('error', (err) => {
    logLine(`failed to start server: ${err.message}`);
    process.exit(127);
  });

  // Pass the server's stderr straight through to ours (diagnostics, not protocol).
  childStderr.on('data', (chunk: Buffer) => process.stderr.write(chunk));

  const toChild = (m: unknown): void => {
    try {
      if (childStdin.writable) childStdin.write(JSON.stringify(m) + '\n');
    } catch (err) {
      logLine(`write to server failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  const toClient = (m: unknown): void => {
    process.stdout.write(JSON.stringify(m) + '\n');
  };

  /** Extract sensitive output values and register them as session taint. */
  async function registerTaint(
    context: RequestContext,
    decision: PolicyDecision,
    response: JSONRPCResponse
  ): Promise<void> {
    if (response.result === undefined || response.result === null) return;
    const ann = context.toolAnnotations;
    const values = ResponseScraper.scrape(response.result);
    if (values.length === 0) return;

    const annotatedSensitive =
      ann?.sensitive !== undefined && ann.sensitive > SensitivityLevel.Public;
    const isSensitive =
      annotatedSensitive ||
      ann?.secret === true ||
      decision.action === 'REDACT' ||
      (decision.riskScore as number) >= 0.3;
    if (!isSensitive) return;

    const sensitivityLevel: SensitivityLevel =
      ann?.secret === true
        ? SensitivityLevel.Confidential
        : ann?.sensitive ?? SensitivityLevel.Confidential;

    await taintRegistry.registerTaint(
      {
        sourceTool: context.toolName,
        sensitivityLevel,
        containsSecrets: ann?.secret === true,
        sessionId: context.sessionId,
        tenantId: context.tenantId,
      },
      values
    );
    logLine(`taint registered from ${context.toolName} (${values.length} value(s))`);
  }

  /** Learn tool security annotations from a tools/list response. */
  function cacheAnnotations(response: RpcMessage): void {
    const result = response.result;
    if (!result || typeof result !== 'object') return;
    const tools = (result as { tools?: unknown }).tools;
    if (!Array.isArray(tools)) return;
    for (const t of tools) {
      if (t && typeof t === 'object') {
        const name = (t as { name?: unknown }).name;
        if (typeof name === 'string') {
          annotations.set(name, mapAnnotations(name, (t as { annotations?: unknown }).annotations));
        }
      }
    }
    logLine(`learned annotations for ${annotations.size} tool(s)`);
  }

  /**
   * Extract the security-relevant tool definitions from a tools/list response.
   * Returns null when there is no valid `tools` array (e.g. an error response),
   * so pinning is skipped rather than mis-reading it as "all tools removed".
   */
  function extractToolDefs(response: RpcMessage): McpToolDefinition[] | null {
    const result = response.result;
    if (!result || typeof result !== 'object') return null;
    const tools = (result as { tools?: unknown }).tools;
    if (!Array.isArray(tools)) return null;
    const defs: McpToolDefinition[] = [];
    for (const t of tools) {
      if (t && typeof t === 'object') {
        const rec = t as Record<string, unknown>;
        if (typeof rec.name === 'string') {
          const def: McpToolDefinition = { name: rec.name };
          if (typeof rec.description === 'string') def.description = rec.description;
          if ('inputSchema' in rec) def.inputSchema = rec.inputSchema;
          defs.push(def);
        }
      }
    }
    return defs;
  }

  /**
   * Learn annotations, then (if pinning is enabled) diff the advertised tool
   * definitions against the pinned baseline and enforce the pin policy. On a
   * `block` verdict the poisoned tools/list is NOT forwarded — the client gets
   * a fail-closed JSON-RPC error instead.
   */
  function handleToolsListResponse(msg: RpcMessage): void {
    cacheAnnotations(msg);
    if (!pinningEnabled) {
      toClient(msg);
      return;
    }

    const defs = extractToolDefs(msg);
    if (defs === null) {
      // Error response / malformed result: nothing to pin, pass through.
      toClient(msg);
      return;
    }

    let store: PinStore | null;
    try {
      store = loadPinStore(pinFile);
    } catch (err) {
      // Corrupt lock file: surface loudly but do not overwrite it or break the
      // client — forward the tools/list unchecked this session.
      logLine(
        `pin: cannot read pin store ${pinFile}: ${err instanceof Error ? err.message : String(err)}; ` +
          `forwarding tools/list WITHOUT pin check`
      );
      toClient(msg);
      return;
    }

    const firstRun = store === null;
    const effectiveStore = store ?? createEmptyPinStore(serverLabel);
    const diff = diffToolsAgainstPins(defs, effectiveStore);
    const decision = applyPinPolicy(diff, pinPolicy);
    for (const line of decision.messages) logLine(line);

    if (decision.block) {
      const req: JSONRPCRequest = { jsonrpc: '2.0', id: msg.id ?? null, method: 'tools/list' };
      toClient(
        mediator.createBlockResponse(
          req,
          decision.blockReason ?? 'tool-definition pin violation',
          TaintGateErrorCodes.POLICY_VIOLATION
        )
      );
      return;
    }

    if (decision.persist) {
      const updated = recordDiffIntoStore(effectiveStore, diff, pinPolicy);
      try {
        savePinStore(pinFile, updated);
        logLine(
          `pin: ${firstRun ? 'created' : 'updated'} pin store ${pinFile} ` +
            `(${Object.keys(updated.tools).length} tool(s) pinned)`
        );
      } catch (err) {
        logLine(
          `pin: failed to write pin store ${pinFile}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    toClient(msg);
  }

  async function handleToolCall(msg: RpcMessage): Promise<void> {
    const id = msg.id ?? null;
    const params =
      msg.params && typeof msg.params === 'object' && !Array.isArray(msg.params)
        ? (msg.params as Record<string, unknown>)
        : {};
    const toolName = typeof params.name === 'string' ? params.name : 'unknown';
    const rawArgs = params.arguments;
    const toolArgs =
      rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs)
        ? (rawArgs as Record<string, unknown>)
        : {};
    const ann = annotations.get(toolName);

    const context: RequestContext = {
      sessionId,
      toolName,
      timestamp: new Date(),
      toolParameters: toolArgs,
      toolAnnotations: ann ? { ...ann, toolName } : undefined,
    };
    const request: JSONRPCRequest = { jsonrpc: '2.0', id, method: 'tools/call', params };

    let decision: PolicyDecision;
    try {
      decision = await mediator.evaluateRequest(request, context);
    } catch (err) {
      const m = err instanceof Error ? err.message : String(err);
      decision =
        opts.failMode === 'open'
          ? makeDecision('ALLOW', `fail-open: governance error (${m})`)
          : makeDecision('BLOCK', `fail-closed: governance error (${m})`);
    }

    logLine(`tools/call ${toolName} -> ${decision.action} :: ${decision.justification}`);
    await auditLogger.logDecision({
      requestId: decision.requestId,
      sessionId,
      decision,
      taintContexts: [],
      policyVersion: decision.policyVersion,
      timestamp: Date.now(),
      toolName,
    });

    if (decision.action === 'BLOCK') {
      toClient(
        mediator.createBlockResponse(
          request,
          decision.justification,
          TaintGateErrorCodes.POLICY_VIOLATION,
          decision.requestId
        )
      );
      return;
    }

    // ALLOW / REDACT: forward and remember the decision for the response leg.
    pending.set(String(id), { kind: 'govern', decision, context });
    toChild(request);
  }

  async function handleClientLine(line: string): Promise<void> {
    if (line.trim() === '') return;
    let msg: RpcMessage;
    try {
      msg = JSON.parse(line) as RpcMessage;
    } catch {
      logLine('dropping non-JSON line from client');
      return;
    }

    // Responses from the client to a server-initiated request have no method.
    if (typeof msg.method !== 'string') {
      toChild(msg);
      return;
    }
    // Notifications (no id) are fire-and-forget.
    const isRequest = msg.id !== undefined && msg.id !== null;
    if (!isRequest) {
      toChild(msg);
      return;
    }
    if (msg.method === 'tools/call') {
      await handleToolCall(msg);
      return;
    }
    if (msg.method === 'tools/list') {
      pending.set(String(msg.id), { kind: 'toolslist' });
      toChild(msg);
      return;
    }
    // Any other protocol method: passthrough.
    toChild(msg);
  }

  async function handleServerLine(line: string): Promise<void> {
    if (line.trim() === '') return;
    let msg: RpcMessage;
    try {
      msg = JSON.parse(line) as RpcMessage;
    } catch {
      logLine('dropping non-JSON line from server');
      return;
    }

    const isResponse = 'result' in msg || 'error' in msg;
    if (!isResponse || msg.id === undefined || msg.id === null) {
      // Server-initiated request/notification -> straight to client.
      toClient(msg);
      return;
    }

    const key = String(msg.id);
    const entry = pending.get(key);
    if (!entry) {
      toClient(msg);
      return;
    }
    pending.delete(key);

    if (entry.kind === 'toolslist') {
      handleToolsListResponse(msg);
      return;
    }

    const response = msg as JSONRPCResponse;
    try {
      await registerTaint(entry.context, entry.decision, response);
    } catch (err) {
      logLine(`taint registration error: ${err instanceof Error ? err.message : String(err)}`);
    }

    if (entry.decision.action === 'REDACT') {
      try {
        toClient(await responseRedactor.redact(response, entry.decision));
      } catch (err) {
        logLine(`redaction failed, blocking: ${err instanceof Error ? err.message : String(err)}`);
        const req: JSONRPCRequest = { jsonrpc: '2.0', id: msg.id, method: 'tools/call' };
        toClient(
          mediator.createBlockResponse(
            req,
            'response sanitization failed - blocked for security',
            TaintGateErrorCodes.SYSTEM_ERROR,
            entry.decision.requestId
          )
        );
      }
      return;
    }

    toClient(response);
  }

  // Serialize each stream so governance/taint ordering matches arrival order.
  const clientRl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let clientQueue: Promise<void> = Promise.resolve();
  clientRl.on('line', (line) => {
    clientQueue = clientQueue
      .then(() => handleClientLine(line))
      .catch((e) => logLine(`client handler error: ${String(e)}`));
  });
  clientRl.on('close', () => {
    if (childStdin.writable) childStdin.end();
  });

  const serverRl = createInterface({ input: childStdout, crlfDelay: Infinity });
  let serverQueue: Promise<void> = Promise.resolve();
  serverRl.on('line', (line) => {
    serverQueue = serverQueue
      .then(() => handleServerLine(line))
      .catch((e) => logLine(`server handler error: ${String(e)}`));
  });

  const forwardSignal = (sig: NodeJS.Signals): void => {
    if (!child.killed) child.kill(sig);
  };
  process.on('SIGINT', () => forwardSignal('SIGINT'));
  process.on('SIGTERM', () => forwardSignal('SIGTERM'));

  child.on('exit', (code, signal) => {
    pipeline.destroy();
    const exitCode = code ?? (signal ? 128 : 0);
    // Give buffered stdout a tick to flush before exiting.
    setImmediate(() => process.exit(exitCode));
  });
}
