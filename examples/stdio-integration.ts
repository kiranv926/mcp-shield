/**
 * MCP-Shield: StdioTransport Integration Example
 * 
 * This example demonstrates how to integrate MCP-Shield with an MCP server
 * using stdin/stdout communication.
 * 
 * Usage:
 *   node examples/stdio-integration.js < mcp-server-output.txt
 */

import { ShieldMediator } from '../src/mediator/ShieldMediator';
import { StdioTransport } from '../src/transport/StdioTransport';
import { PolicyManager } from '../src/core/PolicyManager';
import { RiskEvaluator } from '../src/core/RiskEvaluator';
import { TaintRegistry } from '../src/core/TaintRegistry';
import { RateLimiter } from '../src/core/RateLimiter';
import { ResponseRedactor } from '../src/core/ResponseRedactor';
import { SecureAuditLogger } from '../src/core/audit/SecureAuditLogger';

async function main() {
  console.error('[MCP-Shield] Starting stdio integration...');

  // Create transports
  const clientTransport = new StdioTransport({
    debug: process.env.DEBUG === 'true',
  });
  
  const serverTransport = new StdioTransport({
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

  // The mediator will now intercept all JSON-RPC messages
  // and enforce governance policies

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

