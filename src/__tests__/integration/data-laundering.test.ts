/**
 * MCP-Shield: Data Laundering Prevention Integration Tests
 * 
 * Tests end-to-end data laundering prevention using hash-based taint tracking.
 * 
 * These tests verify that:
 * 1. Sensitive data from Tool A is tracked in TaintRegistry
 * 2. Subsequent tool calls using that data are detected via lineage checking
 * 3. The system prevents data exfiltration through untracked paths
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { randomUUID } from 'crypto';
import { ShieldMediator, ShieldMediatorConfig } from '../../mediator/ShieldMediator';
import { TaintRegistry } from '../../core/TaintRegistry';
import { SensitivityLevel } from '../../types/mcp-hints';
import { createRiskScore } from '../../types/common';
import type {
  JSONRPCRequest,
  JSONRPCResponse,
  RequestContext,
} from '../../types/common';
import type { PolicyDecision } from '../../types/governance';
import type { IRiskEvaluator } from '../../interfaces/IRiskEvaluator';
import type { IPolicyManager } from '../../interfaces/IPolicyManager';
import type { IRateLimiter } from '../../interfaces/IRateLimiter';
import type { IResponseRedactor } from '../../interfaces/IResponseRedactor';
import type { IAuditLogger } from '../../interfaces/IAuditLogger';
import type { ITransport } from '../../interfaces/ITransport';

// Mock implementations
class MockRiskEvaluator implements IRiskEvaluator {
  async evaluatePolicy(context: any): Promise<PolicyDecision> {
    // Check if taint contexts exist (simulating lineage detection)
    const hasTaint = context.taintContexts && context.taintContexts.length > 0;
    
    if (hasTaint) {
      // High risk if tainted data is present
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
        justification: 'Tainted data detected in request',
        timestamp: new Date(),
        policyVersion: 'test-v1',
        requestId: randomUUID(),
      };
    }

    // Low risk for untainted requests
    return {
      action: 'ALLOW',
      riskScore: createRiskScore(0.2),
      riskBreakdown: {
        sensitivity: 0.0,
        exposure: 0,
        trust: 1.0,
        weightSensitivity: 0.6,
        weightExposure: 0.4,
        rawScore: 0.0,
        finalScore: createRiskScore(0.0),
      },
      justification: 'Low risk - trusted tool',
      timestamp: new Date(),
      policyVersion: 'test-v1',
      requestId: randomUUID(),
    };
  }

  async buildEvaluationContext(context: RequestContext): Promise<any> {
    return {
      ...context,
      taintContexts: [],
    };
  }

  // Other required methods
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

  getPolicyManager(): IPolicyManager {
    return {} as IPolicyManager;
  }

  getConfig(): any {
    return {};
  }

  updateConfig(_config: any): void {
    // Mock
  }
}

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

  async getRiskEvaluationConfig(_tenantId?: string, _toolName?: string): Promise<any> {
    return {
      weightSensitivity: 0.6,
      weightExposure: 0.4,
      thresholdAllow: 0.3,
      thresholdBlock: 0.7,
      enableTaintEvaluation: true,
    };
  }

  // Other required methods
  async loadPolicies(_configPath: string): Promise<void> {}
  async reloadPolicies(): Promise<void> {}
  getPolicyVersion(): string { return 'test-v1'; }
  getPolicyHistory(): Array<{ version: string; loadedAt: Date; description?: string }> { return []; }
  async rollbackPolicy(_version: string): Promise<void> {}
  validatePolicy(_rule: any): { valid: boolean; errors: string[] } { return { valid: true, errors: [] }; }
  async healthCheck(): Promise<boolean> { return true; }
}

class MockRateLimiter implements IRateLimiter {
  async checkLimit(_tenantId?: string, _toolName?: string): Promise<any> {
    return {
      allowed: true,
      currentCount: 0,
      maxRequests: 100,
      resetInSeconds: 60,
    };
  }
  async recordRequest(_tenantId?: string, _toolName?: string): Promise<void> {}
  async getStatus(_tenantId?: string, _toolName?: string): Promise<any> {
    return {
      allowed: true,
      currentCount: 0,
      maxRequests: 100,
      resetInSeconds: 60,
    };
  }
  async reset(_tenantId?: string, _toolName?: string): Promise<void> {}
  async configure(_config: any, _tenantId?: string, _toolName?: string): Promise<void> {}
  async healthCheck(): Promise<boolean> { return true; }
}

class MockResponseRedactor implements IResponseRedactor {
  async redact(_response: JSONRPCResponse, _decision: PolicyDecision): Promise<JSONRPCResponse> {
    return {
      jsonrpc: '2.0',
      id: 1,
      result: { redacted: true },
    };
  }
}

class MockAuditLogger implements IAuditLogger {
  async logDecision(_entry: any): Promise<void> {}
  async logSystemError(_entry: any): Promise<void> {}
  async queryLogs(_criteria: any): Promise<any[]> { return []; }
  async healthCheck(): Promise<boolean> { return true; }
}

class MockTransport implements ITransport {
  private messageCallback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private ready = true;
  private pendingResponses = new Map<string | number, JSONRPCResponse>();

  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    // If this is a request with an ID, check if we have a pending response
    if ('id' in message && message.id !== null && 'method' in message) {
      const response = this.pendingResponses.get(message.id);
      if (response && this.messageCallback) {
        // Simulate async response (use setImmediate for better async handling)
        setImmediate(async () => {
          if (this.messageCallback) {
            await this.messageCallback(response);
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

  // Helper to set up expected responses
  setResponse(requestId: string | number, response: JSONRPCResponse): void {
    this.pendingResponses.set(requestId, response);
  }

  async simulateMessage(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    if (this.messageCallback) {
      await this.messageCallback(message);
    }
  }
}

describe('Data Laundering Prevention Integration', () => {
  let mediator: ShieldMediator;
  let taintRegistry: TaintRegistry;
  let mockRiskEvaluator: MockRiskEvaluator;
  let mockPolicyManager: MockPolicyManager;
  let mockRateLimiter: MockRateLimiter;
  let mockResponseRedactor: MockResponseRedactor;
  let mockAuditLogger: MockAuditLogger;
  let mockClientTransport: MockTransport;
  let mockServerTransport: MockTransport;

  const sessionId = 'test-session';
  const tenantId = 'test-tenant';

  beforeEach(() => {
    taintRegistry = new TaintRegistry();
    mockRiskEvaluator = new MockRiskEvaluator();
    mockPolicyManager = new MockPolicyManager();
    mockRateLimiter = new MockRateLimiter();
    mockResponseRedactor = new MockResponseRedactor();
    mockAuditLogger = new MockAuditLogger();
    mockClientTransport = new MockTransport();
    mockServerTransport = new MockTransport();

    const config: ShieldMediatorConfig = {
      riskEvaluator: mockRiskEvaluator,
      taintRegistry,
      policyManager: mockPolicyManager,
      rateLimiter: mockRateLimiter,
      responseRedactor: mockResponseRedactor,
      auditLogger: mockAuditLogger,
      clientTransport: mockClientTransport,
      serverTransport: mockServerTransport,
      evaluationTimeout: 1000,
      taintTimeout: 500,
    };

    mediator = new ShieldMediator(config);
    mediator.start();
  });

  describe('End-to-End Data Laundering Prevention', () => {
    it('should prevent data laundering: Tool A → Tool B with tainted data', async () => {
      // Simulate Tool A returning sensitive data
      // We manually register taint to verify the lineage checking works
      // In production, this would be done automatically by ShieldMediator
      const sensitiveValues = ['user@example.com', '12345', '67890', 'admin@example.com'];
      await taintRegistry.registerTaint(
        {
          sourceTool: 'databaseTool',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
          sessionId,
          tenantId,
        },
        sensitiveValues
      );

      // Step 2: Tool B tries to use tainted data from Tool A
      const toolBRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'callTool',
        params: {
          name: 'emailTool',
          args: {
            to: 'user@example.com', // Tainted value from Tool A
            subject: 'Test',
            body: 'User ID: 12345', // Another tainted value
          },
        },
      };

      const toolBContext: RequestContext = {
        sessionId,
        tenantId,
        toolName: 'emailTool',
        timestamp: new Date(),
        toolAnnotations: {
          openWorld: true, // Open-world tool (egress risk)
          toolName: 'emailTool',
        },
      };

      // Verify lineage check detects tainted values
      const lineageCheck = await taintRegistry.checkLineage(
        toolBRequest.params?.args as Record<string, unknown>,
        sessionId,
        tenantId
      );

      // Taint should be detected
      expect(lineageCheck.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(lineageCheck.relevantContexts.length).toBeGreaterThan(0);
      expect(lineageCheck.relevantContexts[0].sourceTool).toBe('databaseTool');

      // Mock RiskEvaluator to return BLOCK when taint contexts are present
      mockRiskEvaluator.buildEvaluationContext = jest.fn().mockImplementation(async (context) => {
        // ShieldMediator will call checkLineage internally and add taintContexts
        const lineageResult = await taintRegistry.checkLineage(
          toolBRequest.params?.args as Record<string, unknown>,
          context.sessionId,
          context.tenantId
        );

        return {
          ...context,
          taintContexts: lineageResult.relevantContexts,
        };
      });

      // Mock server response for Tool B
      const toolBResponse: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 2,
        result: { sent: true },
      };

      mockServerTransport.setResponse(2, toolBResponse);

      const toolBResult = await mediator.intercept(toolBRequest, toolBContext);

      // Tool B should be BLOCKED because it uses tainted data
      // The RiskEvaluator should detect taintContexts and return BLOCK
      expect(toolBResult.error).toBeDefined();
      expect(toolBResult.error?.code).toBeDefined();
    });

    it('should allow safe operations on untainted data', async () => {
      // Tool B uses different data (not tainted)
      const toolBRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'callTool',
        params: {
          name: 'otherTool',
          args: { value: 'different-data' },
        },
      };

      const toolBContext: RequestContext = {
        sessionId,
        tenantId,
        toolName: 'otherTool',
        timestamp: new Date(),
      };

      // Verify no taint is detected
      const lineageCheck = await taintRegistry.checkLineage(
        toolBRequest.params?.args as Record<string, unknown>,
        sessionId,
        tenantId
      );

      expect(lineageCheck.highestSensitivity).toBeNull();

      // Mock server response
      const toolBResponse: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 2,
        result: { success: true },
      };

      mockServerTransport.setResponse(2, toolBResponse);

      const toolBResult = await mediator.intercept(toolBRequest, toolBContext);

      // Should be allowed (no taint match)
      expect(toolBResult.error).toBeUndefined();
    });

    it('should track origin tool for audit trail', async () => {
      // Register taint manually to test origin tracking
      await taintRegistry.registerTaint(
        {
          sourceTool: 'databaseTool',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
          sessionId,
          tenantId,
        },
        ['user@example.com', '12345']
      );

      const lineageResult = await taintRegistry.checkLineage(
        { email: 'user@example.com' },
        sessionId,
        tenantId
      );

      expect(lineageResult.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(lineageResult.relevantContexts.length).toBeGreaterThan(0);
      expect(lineageResult.relevantContexts[0].sourceTool).toBe('databaseTool');
    });

    it('should handle multi-tenant isolation', async () => {
      // Tenant 1: Register taint
      await taintRegistry.registerTaint(
        {
          sourceTool: 'tool1',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
          sessionId: 'session-1',
          tenantId: 'tenant-1',
        },
        ['secret-value-1']
      );

      // Tenant 2: Register different taint
      await taintRegistry.registerTaint(
        {
          sourceTool: 'tool2',
          sensitivityLevel: SensitivityLevel.Confidential,
          containsSecrets: false,
          sessionId: 'session-1',
          tenantId: 'tenant-2',
        },
        ['secret-value-2']
      );

      // Tenant 1 should only see its own taint
      const result1 = await taintRegistry.checkLineage(
        { data: 'secret-value-1' },
        'session-1',
        'tenant-1'
      );
      expect(result1.highestSensitivity).toBe(SensitivityLevel.Confidential);

      // Tenant 1 should NOT see tenant-2's taint
      const result2 = await taintRegistry.checkLineage(
        { data: 'secret-value-2' },
        'session-1',
        'tenant-1'
      );
      expect(result2.highestSensitivity).toBeNull();

      // Tenant 2 should only see its own taint
      const result3 = await taintRegistry.checkLineage(
        { data: 'secret-value-2' },
        'session-1',
        'tenant-2'
      );
      expect(result3.highestSensitivity).toBe(SensitivityLevel.Confidential);
    });
  });
});

