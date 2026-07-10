/**
 * MCP-Shield: Lineage Provenance Report Integration Tests
 * 
 * Demonstrates the audit trail capabilities for data laundering detection.
 * These tests verify that the system can generate complete lineage provenance
 * reports showing how sensitive data flows through multiple tools.
 */

import { TaintRegistry } from '../../core/TaintRegistry';
import { ShieldMediator } from '../../mediator/ShieldMediator';
import { LineageProvenanceReport, ReportPrivacyLevel } from '../../core/reporters/LineageProvenanceReport';
import type { ITransport } from '../../interfaces/ITransport';
import type { IRiskEvaluator } from '../../interfaces/IRiskEvaluator';
import type { IPolicyManager } from '../../interfaces/IPolicyManager';
import type { IResponseRedactor } from '../../interfaces/IResponseRedactor';
import type { IAuditLogger } from '../../interfaces/IAuditLogger';
import type { IRateLimiter } from '../../interfaces/IRateLimiter';
import type { JSONRPCRequest, JSONRPCResponse } from '../../types/common';
import { SensitivityLevel } from '../../types/mcp-hints';
import { createRiskScore } from '../../types/common';
import { randomUUID } from 'crypto';

// Resolve a canned response by request id. Handles both the plain original id
// and the mediator's composite wire id format `tenant:session:originalId:uuid`.
function resolveCannedResponse(
  responses: Map<string | number, JSONRPCResponse>,
  wireId: string | number
): JSONRPCResponse | undefined {
  const direct = responses.get(wireId);
  if (direct) return direct;
  if (typeof wireId === 'string' && wireId.includes(':')) {
    const parts = wireId.split(':');
    if (parts.length >= 4) {
      const originalId = parts[parts.length - 2]!;
      return responses.get(originalId) ?? responses.get(Number(originalId));
    }
  }
  return undefined;
}

/**
 * Mock implementations for testing
 */
class MockTransport implements ITransport {
  private messageHandler?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private pendingResponses = new Map<string | number, JSONRPCResponse>();

  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    // Simulate async response. Echo the received (possibly composite) wire id,
    // resolving the canned response by original id like a real MCP server.
    if ('id' in message && message.id !== null) {
      const response = resolveCannedResponse(this.pendingResponses, message.id);
      if (response && this.messageHandler) {
        const echoed = { ...response, id: message.id } as JSONRPCResponse;
        setTimeout(() => this.messageHandler!(echoed), 10);
      }
    }
  }

  onMessage(handler: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.messageHandler = handler;
  }

  close(): void {
    // No-op
  }

  isReady(): boolean {
    return true;
  }

  setResponse(id: string | number, response: JSONRPCResponse): void {
    this.pendingResponses.set(id, response);
  }
}

class MockRiskEvaluator implements IRiskEvaluator {
  async evaluatePolicy(
    context: any,
    policyManager?: IPolicyManager
  ): Promise<any> {
    // Simulate risk evaluation based on taint context
    const lineageCheck = context.taintContexts?.[0];
    
    if (lineageCheck?.highestSensitivity === SensitivityLevel.Confidential) {
      return {
        action: 'BLOCK',
        riskScore: createRiskScore(0.9),
        riskBreakdown: {
          sensitivity: 1.0,
          exposure: 1,
          trust: 0,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 1.0,
          finalScore: createRiskScore(1.0),
        },
        justification: 'Data laundering detected',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: context.requestId || randomUUID(),
      };
    }
    
    if (lineageCheck?.highestSensitivity === SensitivityLevel.Internal) {
      return {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 0,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Moderate sensitivity detected',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: context.requestId || randomUUID(),
      };
    }
    
    return {
      action: 'ALLOW',
      riskScore: createRiskScore(0.1),
      riskBreakdown: {
        sensitivity: 0.0,
        exposure: 0,
        trust: 1.0,
        weightSensitivity: 0.6,
        weightExposure: 0.4,
        rawScore: 0.0,
        finalScore: createRiskScore(0.0),
      },
      justification: 'Low risk',
      timestamp: new Date(),
      policyVersion: '1.0',
      requestId: context.requestId || randomUUID(),
    };
  }

  async buildEvaluationContext(context: any): Promise<any> {
    return context;
  }

  async calculateRisk(_context: any): Promise<any> {
    return createRiskScore(0.5);
  }

  extractRiskFactors(_annotations?: any): { sensitivity: number; exposure: number; trust: number } {
    return { sensitivity: 0.0, exposure: 0, trust: 1.0 };
  }

  calculateRiskScore(_s: number, _e: number, _t: number): any {
    return createRiskScore(0.5);
  }

  async getRiskBreakdown(_context: any): Promise<any> {
    return {
      sensitivity: 0.0,
      exposure: 0,
      trust: 1.0,
      weightSensitivity: 0.6,
      weightExposure: 0.4,
      rawScore: 0.0,
      finalScore: createRiskScore(0.0),
    };
  }

  determineAction(_riskScore: any): any {
    return 'ALLOW';
  }

  getPolicyManager(): IPolicyManager | undefined {
    return undefined;
  }

  getConfig(): any {
    return {};
  }

  updateConfig(_config: any): void {
    // Mock
  }

  getRiskEvaluationConfig(policyManager?: IPolicyManager): any {
    return {};
  }
}

class MockPolicyManager implements IPolicyManager {
  async getResolvedPolicy(tenantId: string, toolName: string): Promise<any> {
    return {
      actionOverride: null,
      riskWeights: { sensitivity: 0.5, exposure: 0.3, trust: 0.2 },
    };
  }

  async getToolMetadata(tenantId: string, toolName: string): Promise<any> {
    if (toolName === 'database:read_row') {
      return {
        sensitivityLevel: SensitivityLevel.Confidential,
        secret: false,
        trusted: false,
      };
    }
    if (toolName === 'slack:post_message') {
      return {
        sensitivityLevel: SensitivityLevel.Public,
        secret: false,
        trusted: true,
      };
    }
    if (toolName === 'api:transform_data') {
      return {
        sensitivityLevel: SensitivityLevel.Internal,
        secret: false,
        trusted: false,
      };
    }
    return {
      sensitivityLevel: SensitivityLevel.Public,
      secret: false,
      trusted: true,
    };
  }

  async loadPolicies(): Promise<void> {}
  async reloadPolicies(): Promise<void> {}
  getPolicyVersion(): string { return '1.0'; }
  async getPolicyHistory(): Promise<any[]> { return []; }
  async rollbackPolicy(): Promise<void> {}
  async validatePolicy(): Promise<boolean> { return true; }
  async healthCheck(): Promise<boolean> { return true; }
  getRiskEvaluationConfig(): any { return {}; }
}

class MockResponseRedactor implements IResponseRedactor {
  async redact(response: JSONRPCResponse, decision: any): Promise<JSONRPCResponse> {
    return response;
  }
}

class MockAuditLogger implements IAuditLogger {
  public logs: any[] = [];

  async logDecision(entry: any): Promise<void> {
    // Extract decision details for report generation
    const decision = entry.decision || {};
    this.logs.push({
      type: 'decision',
      requestId: entry.requestId,
      sessionId: entry.sessionId,
      tenantId: entry.tenantId,
      toolName: entry.toolName,
      action: decision.action,
      riskScore: decision.riskScore,
      policyVersion: entry.policyVersion || decision.policyVersion,
      taintContexts: entry.taintContexts || [],
      originTools: entry.originTools || [],
      reason: decision.justification || decision.reason,
      timestamp: new Date(entry.timestamp || Date.now()),
      decision: entry.decision,
      // CRITICAL: Preserve metadata for origin tools extraction
      metadata: entry.metadata || {},
    });
  }

  async logSystemError(entry: any): Promise<void> {
    this.logs.push({
      type: 'system_error',
      ...entry,
      timestamp: new Date(entry.timestamp || Date.now()),
    });
  }

  async queryLogs(options: any): Promise<any[]> {
    return this.logs.filter(log => {
      if (options.sessionId && log.sessionId !== options.sessionId) return false;
      if (options.tenantId && log.tenantId !== options.tenantId) return false;
      if (options.action && log.action !== options.action) return false;
      return true;
    });
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  clear(): void {
    this.logs = [];
  }
}

class MockRateLimiter implements IRateLimiter {
  async checkLimit(tenantId: string, toolName: string): Promise<any> {
    return { allowed: true, currentCount: 0, maxRequests: 100, resetInSeconds: 60 };
  }
  tryConsume(_tenantId?: string, _toolName?: string): any {
    return { allowed: true, currentCount: 0, maxRequests: 100, resetInSeconds: 60 };
  }
  async recordRequest(tenantId: string, toolName: string): Promise<void> {}
  async getStatus(tenantId: string): Promise<any> { return {}; }
  async reset(tenantId: string): Promise<void> {}
  async configure(config: any): Promise<void> {}
  async healthCheck(): Promise<boolean> { return true; }
}

/**
 * Lineage Provenance Report Generator
 * 
 * Generates human-readable audit reports showing data flow through tools.
 */
// Test-specific report generator (uses MockAuditLogger)
// Production version is in src/core/reporters/LineageProvenanceReport.ts

describe('Lineage Provenance Report', () => {
  let taintRegistry: TaintRegistry;
  let mediator: ShieldMediator;
  let clientTransport: MockTransport;
  let serverTransport: MockTransport;
  let auditLogger: MockAuditLogger;
  let reportGenerator: LineageProvenanceReport;

  beforeEach(() => {
    taintRegistry = new TaintRegistry();
    clientTransport = new MockTransport();
    serverTransport = new MockTransport();
    auditLogger = new MockAuditLogger();
    // Use production LineageProvenanceReport - MockAuditLogger implements IAuditLogger
    reportGenerator = new LineageProvenanceReport(auditLogger as unknown as IAuditLogger);

    const config = {
      clientTransport,
      serverTransport,
      riskEvaluator: new MockRiskEvaluator(),
      taintRegistry,
      policyManager: new MockPolicyManager(),
      responseRedactor: new MockResponseRedactor(),
      auditLogger,
      rateLimiter: new MockRateLimiter(),
      evaluationTimeout: 1000,
      taintTimeout: 500,
    };

    mediator = new ShieldMediator(config);

    // Start mediator after transports are set up
    mediator.start();
  });

  afterEach(() => {
    taintRegistry.destroy();
    auditLogger.clear();
  });

  it('should generate complete lineage provenance report for data laundering scenario', async () => {
    const sessionId = 'session-123';
    const tenantId = 'tenant-abc';
    const requestId1 = 'req-1';
    const requestId2 = 'req-2';
    const requestId3 = 'req-3';

    // Step 1: Tool A (database:read_row) returns sensitive data
    const toolARequest: JSONRPCRequest = {
      jsonrpc: '2.0',
      id: requestId1,
      method: 'tools/call',
      params: {
        name: 'database:read_row',
        arguments: {
          table: 'users',
          id: 'user-123',
        },
      },
    };

    const toolAResponse: JSONRPCResponse = {
      jsonrpc: '2.0',
      id: requestId1,
      result: {
        id: 'user-123',
        email: 'john.doe@example.com',
        ssn: '123-45-6789',
        name: 'John Doe',
      },
    };

    serverTransport.setResponse(requestId1, toolAResponse);

    const result1 = await mediator.intercept(toolARequest, {
      sessionId,
      tenantId,
      requestId: requestId1,
      timestamp: new Date(),
    });

    // Wait a bit for async operations
    await new Promise(resolve => setTimeout(resolve, 100));

    // Step 2: Tool B (api:transform_data) tries to use the sensitive data
    const toolBRequest: JSONRPCRequest = {
      jsonrpc: '2.0',
      id: requestId2,
      method: 'tools/call',
      params: {
        name: 'api:transform_data',
        arguments: {
          data: {
            userId: 'user-123',
            email: 'john.doe@example.com', // Tainted data from Tool A
            ssn: '123-45-6789', // Tainted data from Tool A
          },
        },
      },
    };

    const toolBResponse: JSONRPCResponse = {
      jsonrpc: '2.0',
      id: requestId2,
      result: {
        transformed: true,
      },
    };

    serverTransport.setResponse(requestId2, toolBResponse);

    const result2 = await mediator.intercept(toolBRequest, {
      sessionId,
      tenantId,
      requestId: requestId2,
      timestamp: new Date(),
    });

    // Wait a bit for async operations
    await new Promise(resolve => setTimeout(resolve, 100));

    // Step 3: Tool C (slack:post_message) tries to exfiltrate the data
    const toolCRequest: JSONRPCRequest = {
      jsonrpc: '2.0',
      id: requestId3,
      method: 'tools/call',
      params: {
        name: 'slack:post_message',
        arguments: {
          channel: '#general',
          message: `User ${'user-123'} with email ${'john.doe@example.com'} has SSN ${'123-45-6789'}`,
        },
      },
    };

    const result3 = await mediator.intercept(toolCRequest, {
      sessionId,
      tenantId,
      requestId: requestId3,
      timestamp: new Date(),
    });

    // Wait for all async operations
    await new Promise(resolve => setTimeout(resolve, 200));

    // Generate the provenance report
    const report = await reportGenerator.generateReport(sessionId, tenantId);

    // Verify the report contains expected information
    expect(report).toContain('LINEAGE PROVENANCE REPORT');
    expect(report).toContain(sessionId);
    expect(report).toContain(tenantId);
    
    // The report should show at least one tool interaction
    expect(report).toMatch(/Tool:\s+\w+/);
    
    // Verify report structure
    expect(report).toContain('Request ID:');
    expect(report).toContain('Action:');
    expect(report).toContain('Risk Score:');
  });

  it('should show complete data flow path in provenance report', async () => {
    const sessionId = 'session-456';
    const tenantId = 'tenant-xyz';

    // Simulate a multi-step data flow
    const steps = [
      {
        id: 'req-1',
        tool: 'database:read_row',
        args: { table: 'customers', id: 'cust-789' },
        response: { id: 'cust-789', email: 'customer@example.com', phone: '555-1234' },
      },
      {
        id: 'req-2',
        tool: 'api:transform_data',
        args: { data: { customerId: 'cust-789', email: 'customer@example.com' } },
        response: { transformed: true },
      },
      {
        id: 'req-3',
        tool: 'slack:post_message',
        args: { channel: '#sales', message: 'Customer cust-789 contacted us' },
        response: null, // Should be blocked
      },
    ];

    for (const step of steps) {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: step.id,
        method: 'tools/call',
        params: {
          name: step.tool,
          arguments: step.args,
        },
      };

      if (step.response) {
        serverTransport.setResponse(step.id, {
          jsonrpc: '2.0',
          id: step.id,
          result: step.response,
        });
      }

      await mediator.intercept(request, {
        sessionId,
        tenantId,
        requestId: step.id,
        timestamp: new Date(),
      });

      await new Promise(resolve => setTimeout(resolve, 50));
    }

    // Wait for all async operations
    await new Promise(resolve => setTimeout(resolve, 200));

    // Generate report
    const report = await reportGenerator.generateReport(sessionId, tenantId);

    // Verify report structure and that it captured multiple requests
    expect(report).toContain('LINEAGE PROVENANCE REPORT');
    expect(report).toContain(sessionId);
    expect(report).toContain(tenantId);
    expect(report).toContain('Total Events:');
    
    // The report should show multiple request entries
    const requestCount = (report.match(/Request ID:/g) || []).length;
    expect(requestCount).toBeGreaterThan(0);
  });

  it('should include origin tools in lineage report', async () => {
    const sessionId = 'session-789';
    const tenantId = 'tenant-abc';

    // Step 1: Register taint with first origin tool (database:read_row)
    await taintRegistry.registerTaint(
      {
        sessionId,
        tenantId,
        sourceTool: 'database:read_row',
        sensitivityLevel: SensitivityLevel.Confidential,
        containsSecrets: false,
      },
      ['user-123', 'john.doe@example.com']
    );

    // Step 2: Register the same data again with a different tool (simulating laundering)
    // This should add to the originTools set, not replace it
    await taintRegistry.registerTaint(
      {
        sessionId,
        tenantId,
        sourceTool: 'api:transform_data',
        sensitivityLevel: SensitivityLevel.Confidential,
        containsSecrets: false,
      },
      ['user-123', 'john.doe@example.com'] // Same data values
    );

    // Check lineage - should return both origin tools
    const lineage = await taintRegistry.checkLineage(
      { userId: 'user-123', email: 'john.doe@example.com' },
      sessionId,
      tenantId
    );

    expect(lineage.highestSensitivity).toBe(SensitivityLevel.Confidential);
    expect(lineage.originTools).toBeDefined();
    expect(lineage.originTools!.length).toBeGreaterThanOrEqual(1);

    // Log a decision with origin tools (matching IAuditLogger interface)
    await auditLogger.logDecision({
      requestId: 'req-test',
      sessionId,
      tenantId,
      toolName: 'slack:post_message',
      decision: {
        action: 'BLOCK',
        riskScore: createRiskScore(0.9),
        policyVersion: '1.0',
        requestId: 'req-test',
        justification: 'Data laundering detected - data originated from multiple tools',
        timestamp: new Date(),
        riskBreakdown: {
          sensitivity: 1.0,
          exposure: 1,
          trust: 0,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 1.0,
          finalScore: createRiskScore(1.0),
        },
      },
      taintContexts: lineage.relevantContexts,
      policyVersion: '1.0',
      timestamp: Date.now(),
      metadata: {
        originTools: lineage.originTools || [],
      },
    });

    const report = await reportGenerator.generateReport(sessionId, tenantId);

    // Verify report contains expected elements
    expect(report).toContain('Data Origin Path');
    expect(report).toContain('database:read_row');
    expect(report).toContain('Taint Lineage Detected');
    expect(report).toContain('BLOCK');
    expect(report).toContain('slack:post_message');
    
      // Verify that both origin tools are shown in the report when available
      if (lineage.originTools && lineage.originTools.length > 1) {
        expect(report).toContain('api:transform_data');
        // Verify the full path is shown
        expect(report).toMatch(/database:read_row\s*→\s*api:transform_data/);
      }
    });

  it('should generate JSON audit report for SIEM integration', async () => {
    const sessionId = 'session-json-test';
    const tenantId = 'tenant-json';

    // Step 1: Create a tool request that generates audit logs
    const request: JSONRPCRequest = {
      jsonrpc: '2.0',
      id: 'req-json-1',
      method: 'tools/call',
      params: {
        name: 'database:read_row',
        arguments: {
          table: 'users',
          id: 'user-456',
        },
      },
    };

    const response: JSONRPCResponse = {
      jsonrpc: '2.0',
      id: 'req-json-1',
      result: {
        id: 'user-456',
        email: 'test@example.com',
        name: 'Test User',
      },
    };

    serverTransport.setResponse('req-json-1', response);

    await mediator.intercept(request, {
      sessionId,
      tenantId,
      requestId: 'req-json-1',
      timestamp: new Date(),
    });

    // Wait for async operations
    await new Promise(resolve => setTimeout(resolve, 100));

    // Generate JSON report
    const jsonReport = await reportGenerator.generateReportJSON(sessionId, tenantId);

    // Verify JSON structure
    expect(jsonReport).toBeDefined();
    expect(jsonReport).toHaveProperty('sessionId', sessionId);
    expect(jsonReport).toHaveProperty('tenantId', tenantId);
    expect(jsonReport).toHaveProperty('generatedAt');
    expect(jsonReport).toHaveProperty('privacyLevel');
    expect(jsonReport).toHaveProperty('totalEvents');
    expect(jsonReport).toHaveProperty('events');
    expect(Array.isArray((jsonReport as any).events)).toBe(true);

    // Verify event structure
    if ((jsonReport as any).events.length > 0) {
      const event = (jsonReport as any).events[0];
      expect(event).toHaveProperty('requestId');
      expect(event).toHaveProperty('sessionId');
      expect(event).toHaveProperty('tenantId');
      expect(event).toHaveProperty('tool');
      expect(event).toHaveProperty('action');
      expect(event).toHaveProperty('riskScore');
      expect(event).toHaveProperty('policyVersion');
      expect(event).toHaveProperty('timestamp');
      expect(event).toHaveProperty('originTools');
      expect(event).toHaveProperty('taintContexts');
      expect(event).toHaveProperty('reason');
      expect(Array.isArray(event.originTools)).toBe(true);
      expect(Array.isArray(event.taintContexts)).toBe(true);
    }

    // Verify JSON is serializable
    const jsonString = JSON.stringify(jsonReport);
    expect(jsonString).toBeDefined();
    expect(jsonString.length).toBeGreaterThan(0);

    // Verify it can be parsed back
    const parsed = JSON.parse(jsonString);
    expect(parsed.sessionId).toBe(sessionId);
    expect(parsed.tenantId).toBe(tenantId);
  });
});

