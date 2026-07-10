/**
 * TaintGate: Stdio Integration Example
 *
 * Demonstrates how to assemble the full TaintGate governance proxy and run a
 * batch of tool calls through it — end to end, entirely offline.
 *
 * In production the `clientTransport` and `serverTransport` would be real
 * `StdioTransport` instances speaking line-delimited JSON-RPC over stdin/stdout
 * to an MCP client and an MCP server. To keep this example runnable with no
 * network and no child process, the downstream server is replaced by an
 * in-process `MockServerTransport` that echoes a canned result, and the client
 * transport is a real `StdioTransport` bound to an in-memory stream (purely to
 * show how it is wired — it is not read from here).
 *
 * Run it:
 *   npx tsx examples/stdio-integration.ts
 */

import { PassThrough } from 'stream';
import { TaintGate } from '../src/mediator/TaintGate';
import { StdioTransport } from '../src/transport/StdioTransport';
import { PolicyManager } from '../src/core/PolicyManager';
import { RiskEvaluator } from '../src/core/RiskEvaluator';
import { TaintRegistry } from '../src/core/TaintRegistry';
import { RateLimiter } from '../src/core/RateLimiter';
import { ResponseRedactor } from '../src/core/ResponseRedactor';
import { SecureAuditLogger } from '../src/core/audit/SecureAuditLogger';
import { SensitivityLevel } from '../src/types/mcp-hints';
import type { RequestContext } from '../src/types/common';
import type { MCPToolAnnotations } from '../src/types/mcp-hints';
import { MockServerTransport } from './mock-transport';
import { tmpdir } from 'os';
import { join } from 'path';

interface Scenario {
  label: string;
  toolName: string;
  args: Record<string, unknown>;
  annotations?: Partial<MCPToolAnnotations>;
}

async function main() {
  console.error('[TaintGate] Starting stdio integration demo...\n');

  // --- Transports ---------------------------------------------------------
  // Real StdioTransport for the client side, bound to an in-memory stream so
  // the demo never blocks on process.stdin. The mock server auto-responds.
  const clientTransport = new StdioTransport({
    inputStream: new PassThrough(),
    outputStream: new PassThrough(),
    debug: process.env.DEBUG === 'true',
  });
  const serverTransport = new MockServerTransport();

  // --- Governance components ----------------------------------------------
  const policyManager = new PolicyManager();
  await policyManager.loadPolicies('./policies/default.json');

  const taintRegistry = new TaintRegistry();
  // RiskEvaluator takes a config object (policyManager + taintRegistry), not a
  // bare PolicyManager.
  const riskEvaluator = new RiskEvaluator({ policyManager, taintRegistry });
  const rateLimiter = new RateLimiter();
  const responseRedactor = new ResponseRedactor();
  const auditLogger = new SecureAuditLogger({
    logDirectory: join(tmpdir(), 'taintgate-example-logs'),
  });

  // --- Mediator (Policy Enforcement Point) --------------------------------
  const mediator = new TaintGate({
    clientTransport,
    serverTransport,
    policyManager,
    riskEvaluator,
    taintRegistry,
    rateLimiter,
    responseRedactor,
    auditLogger,
    evaluationTimeout: 2000,
    taintTimeout: 1000,
  });

  // start() registers the server-transport listener that correlates responses.
  mediator.start();
  console.error('[TaintGate] Mediator started and ready\n');

  // --- Demo scenarios ------------------------------------------------------
  const scenarios: Scenario[] = [
    {
      label: 'Trusted, public, closed-world read -> ALLOW',
      toolName: 'filesystem:read_file',
      args: { path: '/etc/hostname' },
      annotations: {
        toolName: 'filesystem:read_file',
        trusted: true,
        sensitive: SensitivityLevel.Public,
        openWorld: false,
        secret: false,
      },
    },
    {
      label: 'Untrusted, internal-sensitivity fetch -> REDACT',
      toolName: 'api:fetch_url',
      args: { url: 'https://intranet.local/report' },
      annotations: {
        toolName: 'api:fetch_url',
        trusted: false,
        sensitive: SensitivityLevel.Internal,
        openWorld: false,
        secret: false,
      },
    },
    {
      label: 'Tool with BLOCK policy override -> BLOCK (escalated by policy)',
      toolName: 'database:write_row',
      args: { table: 'users', values: { name: 'alice' } },
      annotations: {
        toolName: 'database:write_row',
        trusted: true,
        sensitive: SensitivityLevel.Public,
        openWorld: false,
        secret: false,
      },
    },
    {
      label: 'No security hints at all -> BLOCK (fail-closed)',
      toolName: 'unknown:mystery_tool',
      args: { payload: 'exfiltrate-me' },
      // no annotations => sensitivity=1, exposure=1, trust=0, secret assumed
    },
  ];

  let requestId = 1;
  for (const scenario of scenarios) {
    const request = {
      jsonrpc: '2.0' as const,
      id: requestId++,
      method: 'tools/call',
      params: {
        name: scenario.toolName,
        arguments: scenario.args,
      },
    };

    const context: RequestContext = {
      sessionId: 'session-demo',
      tenantId: 'acme-corp',
      toolName: scenario.toolName,
      timestamp: new Date(),
      toolAnnotations: scenario.annotations as MCPToolAnnotations | undefined,
    };

    const response = await mediator.intercept(request, context);

    const outcome = response.error
      ? `BLOCKED (${response.error.message})`
      : `ALLOWED/REDACTED result=${JSON.stringify(response.result)}`;

    console.log(`- ${scenario.label}`);
    console.log(`    tool: ${scenario.toolName}`);
    console.log(`    outcome: ${outcome}\n`);
  }

  // --- Teardown ------------------------------------------------------------
  // There is no mediator.stop(). Tear down the transports and dispose of the
  // components that own background timers (RateLimiter's cleanup interval and
  // TaintRegistry's expiry sweep) so the Node event loop can drain and the
  // process exits cleanly.
  await clientTransport.close();
  await serverTransport.close();
  rateLimiter.destroy();
  taintRegistry.destroy();
  policyManager.destroy();

  console.error('[TaintGate] Demo complete.');
}

main().catch((error) => {
  console.error('[TaintGate] Fatal error:', error);
  process.exit(1);
});
