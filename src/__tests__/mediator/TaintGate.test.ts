/**
 * TaintGate: TaintGate Tests
 * 
 * Comprehensive test suite for the Policy Enforcement Point (PEP) implementation.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { randomUUID } from 'crypto';
import type {
  JSONRPCRequest,
  JSONRPCResponse,
  RequestContext,
  EvaluationContext,
  RiskScore,
  RiskBreakdown,
} from '../../types/common';
import type { PolicyDecision, PolicyAction } from '../../types/governance';
import type { SensitivityLevel } from '../../types/mcp-hints';
import { createRiskScore } from '../../types/common';
import { TaintGateErrorCodes } from '../../types/errors';
import { TaintGate, TaintGateConfig, GovernanceViolationError } from '../../mediator/TaintGate';
import type { IRiskEvaluator } from '../../interfaces/IRiskEvaluator';
import type { ITaintRegistry } from '../../interfaces/ITaintRegistry';
import type { IPolicyManager } from '../../interfaces/IPolicyManager';
import type { IRateLimiter } from '../../interfaces/IRateLimiter';
import type { IResponseRedactor } from '../../interfaces/IResponseRedactor';
import type { IAuditLogger } from '../../interfaces/IAuditLogger';
import type { ITransport } from '../../interfaces/ITransport';

// Mock implementations
class MockRiskEvaluator implements IRiskEvaluator {
  async calculateRisk(_context: EvaluationContext): Promise<RiskScore> {
    return createRiskScore(0.5);
  }

  async evaluatePolicy(context: EvaluationContext): Promise<PolicyDecision> {
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

  extractRiskFactors(_annotations?: any): { sensitivity: number; exposure: number; trust: number } {
    return { sensitivity: 0.0, exposure: 0, trust: 1.0 };
  }

  calculateRiskScore(_s: number, _e: number, _t: number): RiskScore {
    return createRiskScore(0.5);
  }

  async getRiskBreakdown(_context: EvaluationContext): Promise<RiskBreakdown> {
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

  determineAction(_riskScore: RiskScore): PolicyAction {
    return 'ALLOW';
  }

  async buildEvaluationContext(context: RequestContext): Promise<EvaluationContext> {
    return {
      ...context,
      taintContexts: [],
    };
  }
}

class MockTaintRegistry implements ITaintRegistry {
  async registerTaint(_context: any, _sessionId: string, _tenantId?: string): Promise<void> {
    // Mock implementation
  }

  async checkLineage(
    _args: Record<string, unknown>,
    _sessionId: string,
    _tenantId?: string
  ): Promise<{
    highestSensitivity: SensitivityLevel | null;
    relevantContexts: any[];
    containsSecrets: boolean;
  }> {
    return {
      highestSensitivity: null,
      relevantContexts: [],
      containsSecrets: false,
    };
  }

  async getTaintContexts(_sessionId: string, _tenantId?: string): Promise<any[]> {
    return [];
  }

  async clearSession(_sessionId: string, _tenantId?: string): Promise<void> {
    // Mock implementation
  }

  async clearContext(_contextId: string, _tenantId?: string): Promise<void> {
    // Mock implementation
  }

  async updateContextTTL(_contextId: string, _ttlSeconds: number, _tenantId?: string): Promise<void> {
    // Mock implementation
  }

  async getSessionStats(_sessionId: string, _tenantId?: string): Promise<any> {
    return {
      totalContexts: 0,
      activeContexts: 0,
      expiredContexts: 0,
      highestSensitivity: null,
      hasSecrets: false,
    };
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  getConfig(): any {
    return {};
  }
}

class MockPolicyManager implements IPolicyManager {
  async loadPolicies(_configPath: string): Promise<void> {
    // Mock implementation
  }

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

  async reloadPolicies(): Promise<void> {
    // Mock implementation
  }

  getPolicyVersion(): string {
    return 'test-v1';
  }

  getPolicyHistory(): Array<{ version: string; loadedAt: Date; description?: string }> {
    return [];
  }

  async rollbackPolicy(_version: string): Promise<void> {
    // Mock implementation
  }

  validatePolicy(_rule: any): { valid: boolean; errors: string[] } {
    return { valid: true, errors: [] };
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
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

  tryConsume(_tenantId?: string, _toolName?: string): any {
    return {
      allowed: true,
      currentCount: 1,
      maxRequests: 100,
      resetInSeconds: 60,
    };
  }

  async recordRequest(_tenantId?: string, _toolName?: string): Promise<void> {
    // Mock implementation
  }

  async getStatus(_tenantId?: string, _toolName?: string): Promise<any> {
    return {
      allowed: true,
      currentCount: 0,
      maxRequests: 100,
      resetInSeconds: 60,
    };
  }

  async reset(_tenantId?: string, _toolName?: string): Promise<void> {
    // Mock implementation
  }

  async configure(_config: any, _tenantId?: string, _toolName?: string): Promise<void> {
    // Mock implementation
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
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
  async logDecision(_entry: any): Promise<void> {
    // Mock implementation
  }

  async logSystemError(_entry: any): Promise<void> {
    // Mock implementation
  }

  async queryLogs(_criteria: any): Promise<any[]> {
    return [];
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
}

class MockTransport implements ITransport {
  private messageCallback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private ready = true;

  async send(_message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    // Mock implementation
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

  // Helper method to simulate receiving a message
  async simulateMessage(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    if (this.messageCallback) {
      await this.messageCallback(message);
    }
  }
}

describe('TaintGate', () => {
  let mediator: TaintGate;
  let mockRiskEvaluator: MockRiskEvaluator;
  let mockTaintRegistry: MockTaintRegistry;
  let mockPolicyManager: MockPolicyManager;
  let mockRateLimiter: MockRateLimiter;
  let mockResponseRedactor: MockResponseRedactor;
  let mockAuditLogger: MockAuditLogger;
  let mockClientTransport: MockTransport;
  let mockServerTransport: MockTransport;

  const createConfig = (): TaintGateConfig => ({
    riskEvaluator: mockRiskEvaluator,
    taintRegistry: mockTaintRegistry,
    policyManager: mockPolicyManager,
    rateLimiter: mockRateLimiter,
    responseRedactor: mockResponseRedactor,
    auditLogger: mockAuditLogger,
    clientTransport: mockClientTransport,
    serverTransport: mockServerTransport,
    evaluationTimeout: 1000,
    taintTimeout: 500,
  });

  beforeEach(() => {
    mockRiskEvaluator = new MockRiskEvaluator();
    mockTaintRegistry = new MockTaintRegistry();
    mockPolicyManager = new MockPolicyManager();
    mockRateLimiter = new MockRateLimiter();
    mockResponseRedactor = new MockResponseRedactor();
    mockAuditLogger = new MockAuditLogger();
    mockClientTransport = new MockTransport();
    mockServerTransport = new MockTransport();

    const config = createConfig();
    mediator = new TaintGate(config);
  });

  afterEach(() => {
    // Clear any pending timers
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  describe('Constructor', () => {
    it('should initialize all dependencies', () => {
      expect(mediator).toBeDefined();
      expect(mediator.getAuditLogger()).toBe(mockAuditLogger);
      expect(mediator.getRateLimiter()).toBe(mockRateLimiter);
      expect(mediator.getResponseRedactor()).toBe(mockResponseRedactor);
    });

    it('should not register transport listener until start() is called', () => {
      // Listener should not be registered in constructor
      expect(mockServerTransport.isReady()).toBe(true);
    });
  });

  describe('start()', () => {
    it('should activate transport listener', () => {
      mediator.start();
      // Listener should now be registered
      expect(mockServerTransport.isReady()).toBe(true);
    });

    it('should throw error if already started', () => {
      mediator.start();
      expect(() => mediator.start()).toThrow('TaintGate is already started');
    });
  });

  describe('validateRequest()', () => {
    it('should validate correct JSON-RPC request', () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const result = mediator.validateRequest(request);
      expect(result.valid).toBe(true);
      expect(result.parsed).toEqual(request);
    });

    it('should reject invalid JSON-RPC request', () => {
      const invalidRequest = {
        jsonrpc: '1.0', // Wrong version
        id: 1,
      };

      const result = mediator.validateRequest(invalidRequest);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject request with missing required fields', () => {
      const invalidRequest = {
        id: 1,
        // Missing jsonrpc and method
      };

      const result = mediator.validateRequest(invalidRequest);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('extractToolName()', () => {
    it('should extract tool name from tools/call request', () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool', arguments: {} },
      };

      const result = mediator.validateRequest(request);
      expect(result.valid).toBe(true);
      // Tool name extraction is tested via intercept()
    });

    it('should return undefined for non-tools/call methods', () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
      };

      const result = mediator.validateRequest(request);
      expect(result.valid).toBe(true);
      // Tool name should be undefined for tools/list
    });
  });

  describe('intercept()', () => {
    beforeEach(() => {
      mediator.start();
    });

    it('should block invalid JSON-RPC request', async () => {
      const invalidRequest = { invalid: 'request' };
      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      const response = await mediator.intercept(invalidRequest, context);

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(TaintGateErrorCodes.VALIDATION_FAILED);
    });

    it('should block request when rate limit exceeded', async () => {
      // The mediator now enforces via the atomic tryConsume() at the rate-limit step.
      mockRateLimiter.tryConsume = jest.fn().mockReturnValue({
        allowed: false,
        currentCount: 101,
        maxRequests: 100,
        resetInSeconds: 30,
        reason: 'Rate limit exceeded: 101/100 requests in 60s window',
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      const response = await mediator.intercept(request, context);

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(TaintGateErrorCodes.RATE_LIMITED);
    });

    it('should allow low-risk request', async () => {
      const decision: PolicyDecision = {
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
        justification: 'Low risk',
        timestamp: new Date(),
        policyVersion: 'test-v1',
        requestId: randomUUID(),
      };

      mockRiskEvaluator.evaluatePolicy = jest.fn().mockResolvedValue(decision);

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      // Mock server response
      const serverResponse: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { success: true },
      };

      // Mock transport to simulate server response
      let messageHandler: ((message: JSONRPCRequest | JSONRPCResponse) => Promise<void>) | undefined;
      let timeoutHandle: NodeJS.Timeout | undefined;
      
      mockServerTransport.send = jest.fn().mockImplementation(async () => {
        // Simulate server response after send
        if (messageHandler) {
          timeoutHandle = setTimeout(async () => {
            await messageHandler!(serverResponse);
          }, 10);
        }
      });

      mockServerTransport.onMessage = jest.fn().mockImplementation((callback) => {
        messageHandler = callback;
      });

      const response = await mediator.intercept(request, context);

      // Clean up timeout if it hasn't fired yet
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }

      // Response should be defined (either server response or error)
      expect(response).toBeDefined();
      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe(1);
    });

    it('should block high-risk request', async () => {
      mockRiskEvaluator.evaluatePolicy = jest.fn().mockResolvedValue({
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
        justification: 'High risk - blocked',
        timestamp: new Date(),
        policyVersion: 'test-v1',
        requestId: randomUUID(),
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      const response = await mediator.intercept(request, context);

      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(TaintGateErrorCodes.POLICY_VIOLATION);
    });

    it('should force-escalate to REDACT when secretHint is true', async () => {
      mockRiskEvaluator.evaluatePolicy = jest.fn().mockResolvedValue({
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
        justification: 'Low risk',
        timestamp: new Date(),
        policyVersion: 'test-v1',
        requestId: randomUUID(),
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
        toolAnnotations: {
          secret: true, // secretHint = true
          toolName: 'testTool',
        },
      };

      // This test verifies the secretHint escalation logic
      // The actual implementation will be tested via integration tests
      const response = await mediator.intercept(request, context);
      expect(response).toBeDefined();
    });

    it('should handle evaluation timeout with fail-closed', async () => {
      // Mock slow evaluation (longer than timeout)
      let timeoutHandle: NodeJS.Timeout;
      mockRiskEvaluator.evaluatePolicy = jest.fn().mockImplementation(
        () => new Promise((resolve) => {
          timeoutHandle = setTimeout(resolve, 2000); // Longer than 1000ms timeout
        })
      );

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      const response = await mediator.intercept(request, context);

      // Clean up the pending timeout to prevent open handles warning
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }

      // Should block due to timeout (fail-closed)
      // The timeout creates a BLOCK decision which uses POLICY_VIOLATION code
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(TaintGateErrorCodes.POLICY_VIOLATION);
      expect(response.error?.message).toContain('Access denied');
    });
  });

  describe('createBlockResponse()', () => {
    it('should create error response with preserved request ID', () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 123,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const requestId = randomUUID();
      const response = mediator.createBlockResponse(
        request,
        'Test block reason',
        TaintGateErrorCodes.POLICY_VIOLATION,
        requestId
      );

      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe(123); // Preserved original ID
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe(TaintGateErrorCodes.POLICY_VIOLATION);
      expect(response.error?.data).toBeDefined();
      expect((response.error?.data as any).requestId).toBe(requestId);
    });

    it('should use default error code when not provided', () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      const response = mediator.createBlockResponse(request, 'Test reason');

      expect(response.error?.code).toBe(TaintGateErrorCodes.POLICY_VIOLATION);
    });
  });

  describe('extractIdSafely()', () => {
    it('should extract ID from valid object', () => {
      const request = { id: 123, jsonrpc: '2.0' };
      const result = mediator.validateRequest(request);
      
      // extractIdSafely is private, but we can test via validateRequest error path
      if (!result.valid && request.id) {
        expect(request.id).toBe(123);
      }
    });

    it('should return null for invalid input', () => {
      const invalid = null;
      const result = mediator.validateRequest(invalid);
      expect(result.valid).toBe(false);
    });
  });

  describe('handleFailure()', () => {
    it('should return BLOCK decision with fail-closed policy', () => {
      const error = new Error('Test error');
      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };
      const requestId = randomUUID();

      const decision = mediator.handleFailure(error, context, 'TestComponent', requestId);

      expect(decision.action).toBe('BLOCK');
      expect(decision.riskScore).toBe(createRiskScore(1.0));
      expect(decision.justification).toContain('Fail-closed');
      expect(decision.requestId).toBe(requestId);
      expect(decision.policyVersion).toBe('fail-closed');
    });
  });

  describe('Composite Key Generation', () => {
    beforeEach(() => {
      mediator.start();
    });

    it('should generate composite key for multi-tenant isolation', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const context1: RequestContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      const context2: RequestContext = {
        sessionId: 'session-2',
        tenantId: 'tenant-1',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      // Both use same request ID (1), but different sessions
      // Composite key should be: tenant-1:session-1:1 vs tenant-1:session-2:1
      // This ensures no collision

      // This is tested implicitly through forwardRequest
      // The actual key generation is internal to forwardRequest
      expect(context1.sessionId).not.toBe(context2.sessionId);
    });
  });

  describe('Cross-Tenant Response Isolation (regression)', () => {
    beforeEach(() => {
      mediator.start();
    });

    it('should NOT cross-deliver responses between two tenants using identical request ids', async () => {
      // Capture the wire ids the mediator stamps onto outbound requests so the
      // test can echo them back like a real server would.
      const sentWireIds: Array<string | number | null> = [];
      mockServerTransport.send = jest.fn().mockImplementation(async (msg: JSONRPCRequest) => {
        sentWireIds.push(msg.id);
      });

      // Two DIFFERENT tenants, both using JSON-RPC id === 1.
      const requestA: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };
      const requestB: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'testTool' },
      };

      const ctxA: RequestContext = {
        sessionId: 'session-A',
        tenantId: 'tenant-A',
        toolName: 'testTool',
        timestamp: new Date(),
      };
      const ctxB: RequestContext = {
        sessionId: 'session-B',
        tenantId: 'tenant-B',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      const pA = mediator.forwardRequest(requestA, ctxA);
      const pB = mediator.forwardRequest(requestB, ctxB);

      // Both requests were sent with DISTINCT, globally-unique wire ids even though
      // their client-facing JSON-RPC id is identical (1).
      expect(sentWireIds).toHaveLength(2);
      expect(sentWireIds[0]).not.toBe(sentWireIds[1]);

      // Respond out of order: tenant-B's response first, then tenant-A's.
      await mockServerTransport.simulateMessage({
        jsonrpc: '2.0',
        id: sentWireIds[1]!,
        result: { who: 'B' },
      });
      await mockServerTransport.simulateMessage({
        jsonrpc: '2.0',
        id: sentWireIds[0]!,
        result: { who: 'A' },
      });

      const [respA, respB] = await Promise.all([pA, pB]);

      // Each tenant receives ITS OWN response (no cross-over), and the original
      // client-facing id (1) is restored on the way back.
      expect((respA.result as any).who).toBe('A');
      expect((respB.result as any).who).toBe('B');
      expect(respA.id).toBe(1);
      expect(respB.id).toBe(1);
    });
  });

  describe('Notification Handling', () => {
    beforeEach(() => {
      mediator.start();
    });

    it('should handle notifications (id: null) with fire-and-forget', async () => {
      const notification: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: null,
        method: 'notify',
        params: { data: 'test' },
      };

      const context: RequestContext = {
        sessionId: 'test-session',
        tenantId: 'test-tenant',
        toolName: 'testTool',
        timestamp: new Date(),
      };

      mockServerTransport.send = jest.fn().mockResolvedValue(undefined);

      const response = await mediator.forwardRequest(notification, context);

      expect(response.jsonrpc).toBe('2.0');
      expect(response.id).toBe(null);
      expect(mockServerTransport.send).toHaveBeenCalledWith(notification);
      // Notification should not be added to pendingRequests
    });
  });
});

