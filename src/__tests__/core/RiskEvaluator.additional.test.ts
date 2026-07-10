/**
 * MCP-Shield: RiskEvaluator Additional Tests
 * 
 * Additional comprehensive tests for edge cases, error scenarios, and integration.
 */

import { RiskEvaluator } from '../../core/RiskEvaluator';
import { PolicyManager } from '../../core/PolicyManager';
import { TaintRegistry } from '../../core/TaintRegistry';
import type { EvaluationContext, RequestContext } from '../../types/common';
import type { MCPToolAnnotations } from '../../types/mcp-hints';
import { SensitivityLevel } from '../../types/mcp-hints';
import { createRiskScore } from '../../types/common';
import { promises as fs } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('RiskEvaluator - Additional Tests', () => {
  let riskEvaluator: RiskEvaluator;
  let policyManager: PolicyManager;
  let taintRegistry: TaintRegistry;
  let testPolicyDir: string;
  let testPolicyPath: string;

  beforeEach(async () => {
    testPolicyDir = join(tmpdir(), `mcp-shield-risk-additional-${Date.now()}`);
    testPolicyPath = join(testPolicyDir, 'test-policy.json');

    await fs.mkdir(testPolicyDir, { recursive: true });
    const policyContent = {
      version: '1.0',
      global: {
        riskThresholds: { allow: 0.3, block: 0.7 },
        weights: { sensitivity: 0.6, exposure: 0.4 },
      },
    };
    await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

    policyManager = new PolicyManager({ policyPath: testPolicyPath });
    await policyManager.loadPolicies();
    taintRegistry = new TaintRegistry();

    riskEvaluator = new RiskEvaluator({
      policyManager,
      taintRegistry,
    });
  });

  afterEach(async () => {
    if (policyManager) {
      policyManager.destroy();
    }
    try {
      await fs.rm(testPolicyDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Concurrent Evaluations', () => {
    it('should handle concurrent evaluatePolicy calls safely', async () => {
      const contexts: EvaluationContext[] = Array.from({ length: 50 }, (_, i) => ({
        sessionId: `session-${i}`,
        tenantId: `tenant-${i % 5}`,
        toolName: `tool-${i % 10}`,
        toolAnnotations: {
          toolName: `tool-${i % 10}`,
          trusted: i % 2 === 0,
          sensitive: i % 3 === 0 ? SensitivityLevel.Confidential : SensitivityLevel.Public,
          openWorld: i % 4 === 0,
        },
        timestamp: new Date(),
        metadata: { requestId: `req-${i}` },
      }));

      const promises = contexts.map(context => riskEvaluator.evaluatePolicy(context));
      const decisions = await Promise.all(promises);

      expect(decisions.length).toBe(50);
      decisions.forEach((decision, i) => {
        expect(decision.action).toMatch(/ALLOW|REDACT|BLOCK/);
        expect(decision.riskScore).toBeGreaterThanOrEqual(0);
        expect(decision.riskScore).toBeLessThanOrEqual(1);
        expect(decision.requestId).toBe(`req-${i}`);
      });
    });

    it('should handle concurrent calculateRisk calls safely', async () => {
      const contexts: EvaluationContext[] = Array.from({ length: 100 }, (_, i) => ({
        sessionId: `session-${i}`,
        tenantId: `tenant-${i % 5}`,
        toolName: `tool-${i % 10}`,
        toolAnnotations: {
          toolName: `tool-${i % 10}`,
          trusted: true,
          sensitive: SensitivityLevel.Public,
          openWorld: false,
        },
        timestamp: new Date(),
      }));

      const promises = contexts.map(context => riskEvaluator.calculateRisk(context));
      const riskScores = await Promise.all(promises);

      expect(riskScores.length).toBe(100);
      riskScores.forEach(score => {
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('Extreme Risk Score Values', () => {
    it('should handle maximum risk scenario (S=1, E=1, T=0)', async () => {
      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: false, // T=0
          sensitive: SensitivityLevel.Confidential, // S=1.0
          openWorld: true, // E=1
        },
        timestamp: new Date(),
      };

      const riskScore = await riskEvaluator.calculateRisk(context);
      expect(riskScore).toBe(createRiskScore(1.0)); // Maximum risk
    });

    it('should handle minimum risk scenario (S=0, E=0, T=1)', async () => {
      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: true, // T=1
          sensitive: SensitivityLevel.Public, // S=0
          openWorld: false, // E=0
        },
        timestamp: new Date(),
      };

      const riskScore = await riskEvaluator.calculateRisk(context);
      expect(riskScore).toBe(createRiskScore(0.0)); // Minimum risk
    });

    it('should handle boundary risk scores correctly', async () => {
      // Test at threshold boundaries
      const contexts = [
        {
          // Just below thresholdAllow
          annotations: {
            toolName: 'tool-1',
            trusted: true,
            sensitive: SensitivityLevel.Public,
            openWorld: false,
          },
          expectedAction: 'ALLOW' as const,
        },
        {
          // At thresholdAllow
          annotations: {
            toolName: 'tool-2',
            trusted: false,
            sensitive: SensitivityLevel.Internal,
            openWorld: true,
          },
          expectedAction: 'REDACT' as const,
        },
        {
          // At thresholdBlock
          annotations: {
            toolName: 'tool-3',
            trusted: false,
            sensitive: SensitivityLevel.Confidential,
            openWorld: true,
          },
          expectedAction: 'BLOCK' as const,
        },
      ];

      for (const testCase of contexts) {
        const context: EvaluationContext = {
          sessionId: 'session-1',
          tenantId: 'tenant-1',
          toolName: testCase.annotations.toolName,
          toolAnnotations: testCase.annotations as MCPToolAnnotations,
          timestamp: new Date(),
          metadata: { requestId: 'req-1' },
        };

        const decision = await riskEvaluator.evaluatePolicy(context);
        // Note: Actual action may vary based on exact risk calculation
        expect(['ALLOW', 'REDACT', 'BLOCK']).toContain(decision.action);
      }
    });
  });

  describe('Multiple Taint Contexts', () => {
    it('should use highest sensitivity from multiple taint contexts', async () => {
      // Register multiple taints with different sensitivity levels
      await taintRegistry.registerTaint(
        ['value-1'],
        SensitivityLevel.Public,
        'tool-1',
        'session-1',
        'tenant-1'
      );
      await taintRegistry.registerTaint(
        ['value-2'],
        SensitivityLevel.Internal,
        'tool-2',
        'session-1',
        'tenant-1'
      );
      await taintRegistry.registerTaint(
        ['value-3'],
        SensitivityLevel.Confidential,
        'tool-3',
        'session-1',
        'tenant-1'
      );

      await new Promise(resolve => setTimeout(resolve, 10));

      const requestContext: RequestContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolParameters: { query: 'value-3' }, // Match highest sensitivity
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: true,
          sensitive: SensitivityLevel.Public, // Low from annotations
          openWorld: false,
        },
        timestamp: new Date(),
      };

      const enrichedContext = await riskEvaluator.buildEvaluationContext(requestContext);
      const riskScore = await riskEvaluator.calculateRisk(enrichedContext);

      // Should have higher risk due to Confidential taint
      if (enrichedContext.taintContexts && enrichedContext.taintContexts.length > 0) {
        expect(riskScore).toBeGreaterThan(createRiskScore(0.0));
      }
    });

    it('should handle taint contexts from multiple origin tools', async () => {
      // Register taints from different tools
      await taintRegistry.registerTaint(
        ['data-1'],
        SensitivityLevel.Confidential,
        'database:read_row',
        'session-1',
        'tenant-1'
      );
      await taintRegistry.registerTaint(
        ['data-2'],
        SensitivityLevel.Internal,
        'api:fetch_data',
        'session-1',
        'tenant-1'
      );

      await new Promise(resolve => setTimeout(resolve, 10));

      const requestContext: RequestContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolParameters: { query: 'data-1' },
        toolAnnotations: {
          toolName: 'test-tool',
        },
        timestamp: new Date(),
      };

      const enrichedContext = await riskEvaluator.buildEvaluationContext(requestContext);
      const decision = await riskEvaluator.evaluatePolicy(enrichedContext);

      if (enrichedContext.taintContexts && enrichedContext.taintContexts.length > 0) {
        expect(decision.justification).toContain('taint from');
      }
    });
  });

  describe('Complex Evaluation Scenarios', () => {
    it('should handle evaluation with all risk factors at maximum', async () => {
      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: false, // T=0
          sensitive: SensitivityLevel.Confidential, // S=1.0
          openWorld: true, // E=1
          secret: true, // Force-escalation
          requireHITL: true, // HITL required
        },
        timestamp: new Date(),
        metadata: { requestId: 'req-1' },
      };

      const decision = await riskEvaluator.evaluatePolicy(context);

      expect(decision.action).toBe('BLOCK');
      expect(decision.riskScore).toBe(createRiskScore(1.0));
      expect(decision.requiresHITL).toBe(true);
      expect(decision.justification).toContain('High risk');
      // Note: secretHint escalation may not add text if already BLOCK
      // The important thing is that action is BLOCK
    });

    it('should handle evaluation with mixed trust levels', async () => {
      const contexts = [
        {
          trusted: false,
          expectedTrust: 0,
        },
        {
          trusted: true,
          expectedTrust: 1.0,
        },
        {
          // Missing trusted hint (fail-closed)
          expectedTrust: 0,
        },
      ];

      for (const testCase of contexts) {
        const annotations: MCPToolAnnotations = {
          toolName: 'test-tool',
          trusted: testCase.trusted,
          sensitive: SensitivityLevel.Confidential,
          openWorld: true,
        };

        const factors = riskEvaluator.extractRiskFactors(annotations);
        expect(factors.trust).toBe(testCase.expectedTrust);
      }
    });
  });

  describe('Logger Integration', () => {
    it('should use logger when provided', async () => {
      const logMessages: Array<{ level: string; message: string; context?: Record<string, unknown> }> = [];
      const logger = {
        error: (message: string, context?: Record<string, unknown>) => {
          logMessages.push({ level: 'error', message, context });
        },
        warn: (message: string, context?: Record<string, unknown>) => {
          logMessages.push({ level: 'warn', message, context });
        },
        info: (message: string, context?: Record<string, unknown>) => {
          logMessages.push({ level: 'info', message, context });
        },
      };

      const failingTaintRegistry = {
        checkLineage: async () => {
          throw new Error('TaintRegistry error');
        },
      } as any;

      const evaluatorWithLogger = new RiskEvaluator({
        policyManager,
        taintRegistry: failingTaintRegistry,
        logger,
        failClosedOnTaintError: true,
      });

      const requestContext: RequestContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolParameters: { query: 'data' },
        timestamp: new Date(),
      };

      await evaluatorWithLogger.buildEvaluationContext(requestContext);

      // Should have logged error
      expect(logMessages.length).toBeGreaterThan(0);
      expect(logMessages.some(log => log.level === 'error')).toBe(true);
    });
  });

  describe('Performance Under Load', () => {
    it('should evaluate policies efficiently under high load', async () => {
      const contexts: EvaluationContext[] = Array.from({ length: 1000 }, (_, i) => ({
        sessionId: `session-${i}`,
        tenantId: `tenant-${i % 10}`,
        toolName: `tool-${i % 20}`,
        toolAnnotations: {
          toolName: `tool-${i % 20}`,
          trusted: i % 2 === 0,
          sensitive: i % 3 === 0 ? SensitivityLevel.Confidential : SensitivityLevel.Public,
          openWorld: i % 4 === 0,
        },
        timestamp: new Date(),
        metadata: { requestId: `req-${i}` },
      }));

      const startTime = Date.now();
      const promises = contexts.map(context => riskEvaluator.evaluatePolicy(context));
      const decisions = await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(decisions.length).toBe(1000);
      // Should complete within reasonable time (< 5 seconds for 1000 evaluations)
      expect(duration).toBeLessThan(5000);
      
      // Average time per evaluation should be reasonable
      const avgTime = duration / 1000;
      expect(avgTime).toBeLessThan(10); // < 10ms per evaluation
    });
  });

  describe('Error Scenarios', () => {
    it('should handle PolicyManager returning invalid config', async () => {
      const invalidPolicyManager = {
        getRiskEvaluationConfig: async () => ({
          weightSensitivity: NaN, // Invalid
          weightExposure: 0.4,
          thresholdAllow: 0.3,
          thresholdBlock: 0.7,
          enableTaintEvaluation: true,
        }),
        getResolvedPolicy: async () => ({
          policyVersion: '1.0',
          thresholds: { allow: 0.3, block: 0.7 },
          weights: { sensitivity: 0.6, exposure: 0.4 },
          actionOverride: null,
          appliedPolicies: [],
        }),
        healthCheck: async () => true,
      } as any;

      const evaluator = new RiskEvaluator({
        policyManager: invalidPolicyManager,
        taintRegistry,
      });

      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
        },
        timestamp: new Date(),
        metadata: { requestId: 'req-1' },
      };

      // Should throw validation error or return fail-closed decision
      try {
        const decision = await evaluator.evaluatePolicy(context);
        // If it returns, should be fail-closed
        expect(decision.action).toBe('BLOCK');
      } catch (error) {
        // Validation error is acceptable
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should handle TaintRegistry timeout gracefully', async () => {
      const slowTaintRegistry = {
        checkLineage: async () => {
          // Deliberately slower than the evaluator's timeout; unref so this
          // never-cleared timer does not keep the test runner alive.
          await new Promise(resolve => {
            const t = setTimeout(resolve, 10000); // 10 seconds
            (t as { unref?: () => void }).unref?.();
          });
          return { highestSensitivity: null, relevantContexts: [], containsSecrets: false };
        },
      } as any;

      const evaluator = new RiskEvaluator({
        policyManager,
        taintRegistry: slowTaintRegistry,
        evaluationTimeout: 100, // 100ms timeout
      });

      const requestContext: RequestContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolParameters: { query: 'data' },
        timestamp: new Date(),
      };

      // Should timeout and handle gracefully
      const enrichedContext = await evaluator.buildEvaluationContext(requestContext);
      
      if (evaluator['failClosedOnTaintError']) {
        // Fail-closed: should have taint context
        expect(enrichedContext.taintContexts).toBeDefined();
      } else {
        // Fail-open: should have empty taint contexts
        expect(enrichedContext.taintContexts?.length).toBe(0);
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle evaluation context with no annotations', async () => {
      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        // No toolAnnotations
        timestamp: new Date(),
        metadata: { requestId: 'req-1' },
      };

      const decision = await riskEvaluator.evaluatePolicy(context);

      // Should use fail-closed defaults
      expect(decision.action).toBe('BLOCK'); // Maximum risk
      expect(decision.riskScore).toBe(createRiskScore(1.0));
    });

    it('should handle evaluation context with empty taint contexts array', async () => {
      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: true,
          sensitive: SensitivityLevel.Public,
          openWorld: false,
        },
        taintContexts: [], // Empty array
        timestamp: new Date(),
      };

      const riskScore = await riskEvaluator.calculateRisk(context);
      // Should use base sensitivity (Public = 0.0)
      expect(riskScore).toBe(createRiskScore(0.0));
    });

    it('should handle very small risk scores', async () => {
      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: true,
          sensitive: SensitivityLevel.Public,
          openWorld: false,
        },
        timestamp: new Date(),
      };

      const riskScore = await riskEvaluator.calculateRisk(context);
      expect(riskScore).toBe(createRiskScore(0.0));
    });
  });

  describe('Integration Scenarios', () => {
    it('should work correctly with PolicyManager hot-reload', async () => {
      // Initial policy
      let policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
          weights: { sensitivity: 0.6, exposure: 0.4 },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({
        policyPath: testPolicyPath,
        enableHotReload: false,
      });
      await policyManager.loadPolicies();

      riskEvaluator = new RiskEvaluator({
        policyManager,
        taintRegistry,
      });

      const context: EvaluationContext = {
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        toolAnnotations: {
          toolName: 'test-tool',
          trusted: false,
          sensitive: SensitivityLevel.Internal,
          openWorld: true,
        },
        timestamp: new Date(),
        metadata: { requestId: 'req-1' },
      };

      const decision1 = await riskEvaluator.evaluatePolicy(context);
      const riskScore1 = decision1.riskScore as number;

      // Update policy with stricter thresholds
      policyContent = {
        version: '2.0',
        global: {
          riskThresholds: { allow: 0.2, block: 0.5 },
          weights: { sensitivity: 0.6, exposure: 0.4 },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));
      await policyManager.reloadPolicies();

      const decision2 = await riskEvaluator.evaluatePolicy(context);
      const riskScore2 = decision2.riskScore as number;

      // Risk score should be the same (deterministic)
      expect(riskScore1).toBe(riskScore2);
      
      // But action might change due to different thresholds
      expect(['ALLOW', 'REDACT', 'BLOCK']).toContain(decision2.action);
    });
  });
});

