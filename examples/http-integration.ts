/**
 * TaintGate: HTTP Integration Example
 *
 * Demonstrates wiring TaintGate in front of an HTTP/JSON-RPC MCP server.
 *
 * To stay self-contained and offline, this example spins up a tiny local HTTP
 * server on 127.0.0.1 that plays the role of the downstream MCP server (it
 * echoes a canned JSON-RPC result). A real `HTTPTransport` points the mediator
 * at that local server, so the request actually travels over HTTP — no external
 * network and no separate process required.
 *
 * Run it:
 *   npx tsx examples/http-integration.ts
 */

import { createServer, type Server } from 'http';
import { AddressInfo } from 'net';
import { TaintGate } from '../src/mediator/TaintGate';
import { HTTPTransport } from '../src/transport/HTTPTransport';
import { PolicyManager } from '../src/core/PolicyManager';
import { RiskEvaluator } from '../src/core/RiskEvaluator';
import { TaintRegistry } from '../src/core/TaintRegistry';
import { RateLimiter } from '../src/core/RateLimiter';
import { ResponseRedactor } from '../src/core/ResponseRedactor';
import { SecureAuditLogger } from '../src/core/audit/SecureAuditLogger';
import { SensitivityLevel } from '../src/types/mcp-hints';
import type { RequestContext } from '../src/types/common';
import type { MCPToolAnnotations } from '../src/types/mcp-hints';
import { MockClientTransport } from './mock-transport';
import { tmpdir } from 'os';
import { join } from 'path';

/**
 * Start a fake MCP server that echoes a JSON-RPC result for any POST /messages.
 * Returns the running server and its base URL.
 */
function startFakeMcpServer(): Promise<{ server: Server; baseUrl: string }> {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      if (req.method !== 'POST') {
        res.writeHead(404).end();
        return;
      }
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        let id: string | number | null = null;
        let toolName = 'unknown';
        try {
          const parsed = JSON.parse(body);
          id = parsed.id ?? null;
          toolName = parsed?.params?.name ?? 'unknown';
        } catch {
          /* ignore malformed body */
        }
        const response = {
          jsonrpc: '2.0',
          id, // echo the wire id so the mediator can correlate the response
          result: {
            ok: true,
            tool: toolName,
            content: [{ type: 'text', text: `Simulated HTTP response for ${toolName}` }],
          },
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

async function main() {
  const { server, baseUrl } = await startFakeMcpServer();
  console.error(`[TaintGate] Fake MCP server listening at ${baseUrl}`);

  // --- Transports ---------------------------------------------------------
  const clientTransport = new MockClientTransport();
  const serverTransport = new HTTPTransport({
    baseUrl,
    timeout: 5000,
    debug: process.env.DEBUG === 'true',
  });

  // --- Governance components ----------------------------------------------
  const policyManager = new PolicyManager();
  await policyManager.loadPolicies('./policies/default.json');

  const taintRegistry = new TaintRegistry();
  // RiskEvaluator takes a config object (policyManager + taintRegistry).
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

  // Example 1: a trusted, low-risk tool call that is ALLOWED end to end.
  const allowRequest = {
    jsonrpc: '2.0' as const,
    id: 1,
    method: 'tools/call',
    params: {
      name: 'filesystem:read_file',
      arguments: { path: '/etc/hostname' },
    },
  };
  const allowContext: RequestContext = {
    sessionId: 'session-http',
    tenantId: 'acme-corp',
    toolName: 'filesystem:read_file',
    timestamp: new Date(),
    toolAnnotations: {
      toolName: 'filesystem:read_file',
      trusted: true,
      sensitive: SensitivityLevel.Public,
      openWorld: false,
      secret: false,
    } as MCPToolAnnotations,
  };
  const allowResponse = await mediator.intercept(allowRequest, allowContext);
  console.log('- Trusted read via HTTP -> expect ALLOW');
  console.log(`    outcome: ${allowResponse.error ? 'BLOCKED' : 'ALLOWED'}`);
  console.log(`    result: ${JSON.stringify(allowResponse.result ?? allowResponse.error)}\n`);

  // Example 2: a policy-blocked tool call (database:write_row -> BLOCK).
  const blockRequest = {
    jsonrpc: '2.0' as const,
    id: 2,
    method: 'tools/call',
    params: {
      name: 'database:write_row',
      arguments: { table: 'users', values: { name: 'alice' } },
    },
  };
  const blockContext: RequestContext = {
    sessionId: 'session-http',
    tenantId: 'acme-corp',
    toolName: 'database:write_row',
    timestamp: new Date(),
    toolAnnotations: {
      toolName: 'database:write_row',
      trusted: true,
      sensitive: SensitivityLevel.Public,
      openWorld: false,
      secret: false,
    } as MCPToolAnnotations,
  };
  const blockResponse = await mediator.intercept(blockRequest, blockContext);
  console.log('- Write via HTTP -> expect BLOCK (policy override)');
  console.log(`    outcome: ${blockResponse.error ? 'BLOCKED' : 'ALLOWED'}`);
  console.log(`    reason: ${JSON.stringify(blockResponse.error?.data ?? blockResponse.result)}\n`);

  // --- Teardown ------------------------------------------------------------
  // There is no mediator.stop(). Close the transports, dispose of the
  // components that own background timers (RateLimiter's cleanup interval and
  // TaintRegistry's expiry sweep), and shut the fake server down so the process
  // exits cleanly.
  await clientTransport.close();
  await serverTransport.close();
  rateLimiter.destroy();
  taintRegistry.destroy();
  policyManager.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));

  console.error('[TaintGate] Demo complete.');
}

main().catch((error) => {
  console.error('[TaintGate] Fatal error:', error);
  process.exit(1);
});
