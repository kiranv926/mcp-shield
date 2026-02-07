/**
 * MCP-Shield: HTTPTransport Integration Example
 * 
 * This example demonstrates how to integrate MCP-Shield with an MCP server
 * using HTTP/REST communication.
 */

import { ShieldMediator } from '../src/mediator/ShieldMediator';
import { HTTPTransport } from '../src/transport/HTTPTransport';
import { PolicyManager } from '../src/core/PolicyManager';
import { RiskEvaluator } from '../src/core/RiskEvaluator';
import { TaintRegistry } from '../src/core/TaintRegistry';
import { RateLimiter } from '../src/core/RateLimiter';
import { ResponseRedactor } from '../src/core/ResponseRedactor';
import { SecureAuditLogger } from '../src/core/audit/SecureAuditLogger';

async function main() {
  const mcpServerUrl = process.env.MCP_SERVER_URL || 'http://localhost:3000';
  const apiKey = process.env.MCP_API_KEY;

  console.error(`[MCP-Shield] Connecting to MCP server at ${mcpServerUrl}`);

  // Create transports
  const clientTransport = new HTTPTransport({
    baseUrl: mcpServerUrl,
    headers: apiKey ? {
      'Authorization': `Bearer ${apiKey}`,
    } : undefined,
    timeout: 30000,
    debug: process.env.DEBUG === 'true',
  });
  
  const serverTransport = new HTTPTransport({
    baseUrl: mcpServerUrl,
    headers: apiKey ? {
      'Authorization': `Bearer ${apiKey}`,
    } : undefined,
    timeout: 30000,
    debug: process.env.DEBUG === 'true',
  });

  // Create governance components
  const policyManager = new PolicyManager();
  await policyManager.loadPolicies('./policies/default.json');

  const riskEvaluator = new RiskEvaluator(policyManager);
  const taintRegistry = new TaintRegistry();
  const rateLimiter = new RateLimiter();
  const responseRedactor = new ResponseRedactor();
  const auditLogger = new SecureAuditLogger({
    logDirectory: './logs',
  });

  // Create ShieldMediator
  const mediator = new ShieldMediator({
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

  // Start the mediator
  await mediator.start();

  console.error('[MCP-Shield] Mediator started and ready');

  // Example: Intercept a tool call
  const exampleRequest = {
    jsonrpc: '2.0' as const,
    id: 1,
    method: 'tools/call',
    params: {
      name: 'database_query',
      arguments: {
        query: 'SELECT * FROM users',
      },
    },
  };

  const context = {
    tenantId: 'tenant-1',
    sessionId: 'session-1',
  };

  try {
    const decision = await mediator.intercept(exampleRequest, context);
    console.error('[MCP-Shield] Decision:', decision);
  } catch (error) {
    console.error('[MCP-Shield] Error:', error);
  }

  // Handle graceful shutdown
  process.on('SIGTERM', async () => {
    console.error('[MCP-Shield] Shutting down...');
    await mediator.stop();
    await clientTransport.close();
    await serverTransport.close();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.error('[MCP-Shield] Shutting down...');
    await mediator.stop();
    await clientTransport.close();
    await serverTransport.close();
    process.exit(0);
  });
}

main().catch((error) => {
  console.error('[MCP-Shield] Fatal error:', error);
  process.exit(1);
});

