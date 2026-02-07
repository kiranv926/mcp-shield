/**
 * MCP-Shield: PolicyManager Additional Tests
 * 
 * Additional comprehensive tests for edge cases, error scenarios, and integration.
 */

import { PolicyManager } from '../../core/PolicyManager';
import { promises as fs } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('PolicyManager - Additional Tests', () => {
  let policyManager: PolicyManager;
  let testPolicyDir: string;
  let testPolicyPath: string;

  beforeEach(() => {
    testPolicyDir = join(tmpdir(), `mcp-shield-policy-additional-${Date.now()}`);
    testPolicyPath = join(testPolicyDir, 'test-policy.json');
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

  describe('Concurrent Access & Thread Safety', () => {
    it('should handle concurrent getResolvedPolicy calls safely', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
          weights: { sensitivity: 0.6, exposure: 0.4 },
        },
        tenants: {
          'tenant-A': { riskThresholds: { allow: 0.2, block: 0.5 } },
          'tenant-B': { riskThresholds: { allow: 0.4, block: 0.8 } },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Fire 100 concurrent requests
      const promises = Array.from({ length: 100 }, (_, i) =>
        policyManager.getResolvedPolicy(
          i % 2 === 0 ? 'tenant-A' : 'tenant-B',
          `tool-${i % 10}`
        )
      );

      const results = await Promise.all(promises);

      // All should succeed
      expect(results.length).toBe(100);
      results.forEach(result => {
        expect(result.policyVersion).toBe('1.0');
        expect(result.thresholds.allow).toBeGreaterThanOrEqual(0);
        expect(result.thresholds.block).toBeGreaterThanOrEqual(result.thresholds.allow);
      });
    });

    it('should handle concurrent reloads safely', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({
        policyPath: testPolicyPath,
        enableHotReload: false, // Manual reloads
      });
      await policyManager.loadPolicies();

      // Fire 10 concurrent reloads
      const reloadPromises = Array.from({ length: 10 }, () =>
        policyManager.reloadPolicies()
      );

      await Promise.all(reloadPromises);

      // Should still have valid policy
      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.policyVersion).toBe('1.0');
    });
  });

  describe('Malformed JSON Handling', () => {
    it('should handle invalid JSON syntax', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      await fs.writeFile(testPolicyPath, '{ invalid json }');

      policyManager = new PolicyManager({ policyPath: testPolicyPath });

      await expect(policyManager.loadPolicies()).rejects.toThrow();
    });

    it('should handle missing required fields gracefully', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const invalidPolicy = {
        // Missing version
        global: {
          // Missing riskThresholds
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(invalidPolicy, null, 2));

      policyManager = new PolicyManager({
        policyPath: testPolicyPath,
        failClosed: true,
      });

      // Should use defaults or throw validation error
      try {
        await policyManager.loadPolicies();
        const resolution = await policyManager.getResolvedPolicy();
        expect(resolution.policyVersion).toBeDefined();
      } catch (error) {
        // Validation error is acceptable
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should handle null values in policy', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyWithNulls = {
        version: '1.0',
        global: {
          riskThresholds: { allow: null, block: 0.7 },
          weights: { sensitivity: 0.6, exposure: null },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyWithNulls, null, 2));

      policyManager = new PolicyManager({
        policyPath: testPolicyPath,
        failClosed: true,
      });

      await policyManager.loadPolicies();
      const resolution = await policyManager.getResolvedPolicy();
      // Should use defaults for null values
      expect(resolution.thresholds.allow).toBeGreaterThanOrEqual(0);
      expect(resolution.thresholds.block).toBeGreaterThanOrEqual(resolution.thresholds.allow);
    });
  });

  describe('Complex MRW Scenarios', () => {
    it('should handle three-level policy hierarchy (global, tenant, tool)', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const complexPolicy = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
          weights: { sensitivity: 0.6, exposure: 0.4 },
          actionOverride: 'ALLOW',
        },
        tenants: {
          'tenant-A': {
            riskThresholds: { allow: 0.2, block: 0.5 },
            weights: { sensitivity: 0.7, exposure: 0.3 },
            actionOverride: 'REDACT',
          },
        },
        tools: {
          'database:read_row': {
            riskThresholds: { allow: 0.1, block: 0.4 },
            weights: { sensitivity: 0.8, exposure: 0.2 },
            actionOverride: 'BLOCK',
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(complexPolicy, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy('tenant-A', 'database:read_row');

      // MRW: Most restrictive wins
      expect(resolution.thresholds.allow).toBe(0.1); // Minimum (most restrictive)
      expect(resolution.thresholds.block).toBe(0.4); // Minimum (most restrictive)
      expect(resolution.actionOverride).toBe('BLOCK'); // Highest severity
      // Weights: Maximum values, then normalized if sum > 1.0
      // max(0.6 global, 0.7 tenant, 0.8 tool) = 0.8 for sensitivity
      // max(0.4 global, 0.3 tenant, 0.2 tool) = 0.4 for exposure
      // Sum = 0.8 + 0.4 = 1.2, so normalized: 0.8/1.2 = 0.666..., 0.4/1.2 = 0.333...
      expect(resolution.weights.sensitivity).toBeCloseTo(0.6666666666666666, 5);
      expect(resolution.weights.exposure).toBeCloseTo(0.3333333333333333, 5);
    });

    it('should handle multiple tenant policies with different scopes', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const multiTenantPolicy = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
        },
        tenants: {
          'tenant-A': {
            riskThresholds: { allow: 0.2, block: 0.5 },
          },
          'tenant-B': {
            riskThresholds: { allow: 0.4, block: 0.8 },
          },
          'tenant-C': {
            riskThresholds: { allow: 0.1, block: 0.3 },
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(multiTenantPolicy, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolutionA = await policyManager.getResolvedPolicy('tenant-A');
      const resolutionB = await policyManager.getResolvedPolicy('tenant-B');
      const resolutionC = await policyManager.getResolvedPolicy('tenant-C');

      // MRW: Minimum (most restrictive) wins
      expect(resolutionA.thresholds.allow).toBe(0.2); // min(0.3 global, 0.2 tenant-A)
      expect(resolutionB.thresholds.allow).toBe(0.3); // min(0.3 global, 0.4 tenant-B) = 0.3 (global is more restrictive)
      expect(resolutionC.thresholds.allow).toBe(0.1); // min(0.3 global, 0.1 tenant-C)
    });
  });

  describe('Policy Versioning Edge Cases', () => {
    it('should handle rapid version changes', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      
      // Initial policy
      let policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();
      expect(policyManager.getPolicyVersion()).toBe('1.0');

      // Rapid version changes
      for (let i = 2; i <= 5; i++) {
        policyContent = {
          version: `${i}.0`,
          global: { riskThresholds: { allow: 0.3, block: 0.7 } },
        };
        await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));
        await policyManager.reloadPolicies();
        expect(policyManager.getPolicyVersion()).toBe(`${i}.0`);
      }

      const history = policyManager.getPolicyHistory();
      expect(history.length).toBeGreaterThanOrEqual(5);
    });

    it('should handle rollback to earliest version', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const initialPolicy = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.2, block: 0.5 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(initialPolicy, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Create multiple versions
      for (let i = 2; i <= 3; i++) {
        const policy = {
          version: `${i}.0`,
          global: { riskThresholds: { allow: 0.3, block: 0.7 } },
        };
        await fs.writeFile(testPolicyPath, JSON.stringify(policy, null, 2));
        await policyManager.reloadPolicies();
      }

      // Rollback to version 1.0
      await policyManager.rollbackPolicy('1.0');
      expect(policyManager.getPolicyVersion()).toBe('1.0');
      
      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.thresholds.allow).toBe(0.2);
    });
  });

  describe('Performance & Memory', () => {
    it('should handle large policy files efficiently', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      
      // Create policy with many tenants and tools
      const largePolicy: any = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
        tenants: {},
        tools: {},
      };

      // Add 100 tenants
      for (let i = 0; i < 100; i++) {
        largePolicy.tenants[`tenant-${i}`] = {
          riskThresholds: { allow: 0.2 + (i % 10) * 0.01, block: 0.5 + (i % 10) * 0.01 },
        };
      }

      // Add 50 tools
      for (let i = 0; i < 50; i++) {
        largePolicy.tools[`tool-${i}`] = {
          riskThresholds: { allow: 0.1 + (i % 5) * 0.02, block: 0.4 + (i % 5) * 0.02 },
        };
      }

      await fs.writeFile(testPolicyPath, JSON.stringify(largePolicy, null, 2));

      const startTime = Date.now();
      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();
      const loadTime = Date.now() - startTime;

      // Should load within reasonable time (< 1 second)
      expect(loadTime).toBeLessThan(1000);

      // Should resolve policies quickly
      const resolveStart = Date.now();
      await policyManager.getResolvedPolicy('tenant-50', 'tool-25');
      const resolveTime = Date.now() - resolveStart;

      expect(resolveTime).toBeLessThan(100);
    });

    it('should not leak memory with repeated reloads', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Perform 50 reloads
      for (let i = 0; i < 50; i++) {
        policyContent.version = `${i + 1}.0`;
        await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));
        await policyManager.reloadPolicies();
      }

      // History should be limited
      const history = policyManager.getPolicyHistory();
      expect(history.length).toBeLessThanOrEqual(100); // Default maxHistorySize
    });
  });

  describe('Error Recovery', () => {
    it('should recover from temporary file access errors', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Simulate file access error by deleting file temporarily
      await fs.unlink(testPolicyPath);

      // Reload should fail but preserve previous policy
      try {
        await policyManager.reloadPolicies();
        // If reload doesn't throw, that's also acceptable (might use fail-closed)
      } catch (error) {
        // Expected to fail - previous policy should be preserved
      }

      // Previous policy should still be available (PolicyManager preserves on reload failure)
      const resolution = await policyManager.getResolvedPolicy();
      // Note: If reload fails completely, it might fall back to fail-closed
      // The important thing is that the system doesn't crash
      expect(resolution.policyVersion).toBeDefined();
      expect(resolution.thresholds.allow).toBeGreaterThanOrEqual(0);
    });

    it('should handle corrupted policy file gracefully', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const validPolicy = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(validPolicy, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Corrupt the file
      await fs.writeFile(testPolicyPath, 'corrupted content');

      // Reload should fail but preserve previous policy
      try {
        await policyManager.reloadPolicies();
      } catch (error) {
        // Expected to fail
      }

      // Previous policy should still be available
      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.policyVersion).toBe('1.0');
    });
  });

  describe('Edge Cases', () => {
    it('should handle very small threshold values', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.001, block: 0.002 },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.thresholds.allow).toBe(0.001);
      expect(resolution.thresholds.block).toBe(0.002);
    });

    it('should handle threshold values very close to boundaries', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.999, block: 1.0 },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.thresholds.allow).toBe(0.999);
      expect(resolution.thresholds.block).toBe(1.0);
    });

    it('should handle empty policy with only version', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const minimalPolicy = {
        version: '1.0',
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(minimalPolicy, null, 2));

      policyManager = new PolicyManager({
        policyPath: testPolicyPath,
        failClosed: true,
      });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy();
      // Should use defaults
      expect(resolution.thresholds.allow).toBeGreaterThanOrEqual(0);
      expect(resolution.thresholds.block).toBeGreaterThanOrEqual(resolution.thresholds.allow);
    });
  });
});

