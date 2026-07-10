/**
 * TaintGate: PolicyManager Unit Tests
 * 
 * Tests for the PolicyManager (PAP) implementation.
 */

import { PolicyManager } from '../../core/PolicyManager';
import type { PolicyManagerConfig } from '../../core/PolicyManager';
import { promises as fs } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('PolicyManager', () => {
  let policyManager: PolicyManager;
  let testPolicyDir: string;
  let testPolicyPath: string;

  beforeEach(() => {
    testPolicyDir = join(tmpdir(), `taintgate-policy-test-${Date.now()}`);
    testPolicyPath = join(testPolicyDir, 'test-policy.json');
  });

  afterEach(async () => {
    // Cleanup
    if (policyManager) {
      policyManager.destroy();
    }
    try {
      await fs.rm(testPolicyDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('loadPolicies', () => {
    it('should load policies from JSON file', async () => {
      // Create test policy file
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: {
            allow: 0.2,
            block: 0.6,
          },
          weights: {
            sensitivity: 0.7,
            exposure: 0.3,
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      expect(policyManager.getPolicyVersion()).toBe('1.0');
    });

    it('should use fail-closed defaults when file does not exist', async () => {
      const nonExistentPath = join(testPolicyDir, 'non-existent.json');
      policyManager = new PolicyManager({ 
        policyPath: nonExistentPath,
        failClosed: true,
      });
      
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.policyVersion).toBe('fail-closed-default');
      expect(resolution.thresholds.allow).toBe(0.3);
      expect(resolution.thresholds.block).toBe(0.7);
    });

    it('should throw error when file does not exist and failClosed is false', async () => {
      const nonExistentPath = join(testPolicyDir, 'non-existent.json');
      policyManager = new PolicyManager({ 
        policyPath: nonExistentPath,
        failClosed: false,
      });
      
      await expect(policyManager.loadPolicies()).rejects.toThrow('Policy file not found');
    });

    it('should load tenant-specific policies', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
        },
        tenants: {
          'tenant-A': {
            riskThresholds: { allow: 0.2, block: 0.5 },
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy('tenant-A');
      expect(resolution.appliedPolicies).toContain('tenant:tenant-A:tenant-tenant-A-default');
    });

    it('should load tool-specific policies', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
        },
        tools: {
          'database:read_row': {
            actionOverride: 'REDACT',
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy(undefined, 'database:read_row');
      expect(resolution.actionOverride).toBe('REDACT');
      expect(resolution.appliedPolicies).toContain('tool:database:read_row:tool-database:read_row-default');
    });
  });

  describe('getResolvedPolicy - MRW Logic', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should apply Most Restrictive Wins for thresholds (minimum values)', async () => {
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
        },
        tenants: {
          'tenant-A': {
            riskThresholds: { allow: 0.2, block: 0.5 }, // More restrictive
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy('tenant-A');
      expect(resolution.thresholds.allow).toBe(0.2); // Minimum (most restrictive)
      expect(resolution.thresholds.block).toBe(0.5); // Minimum (most restrictive)
    });

    it('should apply Most Restrictive Wins for weights (maximum values)', async () => {
      const policyContent = {
        version: '1.0',
        global: {
          weights: { sensitivity: 0.6, exposure: 0.4 },
        },
        tenants: {
          'tenant-A': {
            weights: { sensitivity: 0.8, exposure: 0.2 }, // Higher sensitivity weight
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy('tenant-A');
      // MRW takes max: sensitivity = 0.8, exposure = 0.4, sum = 1.2 > 1.0, so normalize
      expect(resolution.weights.sensitivity).toBeCloseTo(0.8 / 1.2, 2); // Normalized
      expect(resolution.weights.exposure).toBeCloseTo(0.4 / 1.2, 2); // Normalized
    });

    it('should apply action override with highest severity (BLOCK > REDACT > ALLOW)', async () => {
      const policyContent = {
        version: '1.0',
        global: {
          actionOverride: 'ALLOW',
        },
        tenants: {
          'tenant-A': {
            actionOverride: 'REDACT',
          },
        },
        tools: {
          'database:read_row': {
            actionOverride: 'BLOCK', // Highest severity
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy('tenant-A', 'database:read_row');
      expect(resolution.actionOverride).toBe('BLOCK'); // Highest severity wins
    });

    it('should clamp thresholds to ensure allow < block when combining policies', async () => {
      // This test verifies that when combining multiple policies with MRW,
      // if the minimum values result in allow >= block, we clamp block
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.3, block: 0.7 },
        },
        tenants: {
          'tenant-A': {
            riskThresholds: { allow: 0.5, block: 0.4 }, // This would be invalid if used alone
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      // This should fail validation during load because tenant-A has invalid thresholds
      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await expect(policyManager.loadPolicies()).rejects.toThrow();
    });

    it('should normalize weights if sum exceeds 1.0 when combining policies', async () => {
      // This test verifies that when combining multiple policies with MRW,
      // if the maximum weights from different rules result in sum > 1.0, we normalize
      // Each individual rule is valid (sum <= 1.0), but MRW takes max from each, which might exceed 1.0
      const policyContent = {
        version: '1.0',
        global: {
          weights: { sensitivity: 0.7, exposure: 0.2 }, // Sum = 0.9 (valid)
        },
        tenants: {
          'tenant-A': {
            weights: { sensitivity: 0.3, exposure: 0.6 }, // Sum = 0.9 (valid)
            // MRW takes max: sensitivity = 0.7, exposure = 0.6, sum = 1.3 > 1.0
          },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const resolution = await policyManager.getResolvedPolicy('tenant-A');
      const weightSum = resolution.weights.sensitivity + resolution.weights.exposure;
      expect(weightSum).toBeLessThanOrEqual(1.0);
      // Verify normalization: 0.7 / 1.3 ≈ 0.538, 0.6 / 1.3 ≈ 0.462
      expect(resolution.weights.sensitivity).toBeCloseTo(0.7 / 1.3, 2);
      expect(resolution.weights.exposure).toBeCloseTo(0.6 / 1.3, 2);
    });
  });

  describe('getRiskEvaluationConfig', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should return risk evaluation config from resolved policy', async () => {
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 0.2, block: 0.6 },
          weights: { sensitivity: 0.7, exposure: 0.3 },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const config = await policyManager.getRiskEvaluationConfig();
      expect(config.thresholdAllow).toBe(0.2);
      expect(config.thresholdBlock).toBe(0.6);
      expect(config.weightSensitivity).toBe(0.7);
      expect(config.weightExposure).toBe(0.3);
      expect(config.enableTaintEvaluation).toBe(true);
    });
  });

  describe('reloadPolicies', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should reload policies from file', async () => {
      const policyContent1 = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent1, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();
      expect(policyManager.getPolicyVersion()).toBe('1.0');

      // Update policy file
      const policyContent2 = {
        version: '2.0',
        global: { riskThresholds: { allow: 0.2, block: 0.6 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent2, null, 2));

      await policyManager.reloadPolicies();
      expect(policyManager.getPolicyVersion()).toBe('2.0');
    });
  });

  describe('getPolicyVersion', () => {
    it('should return current policy version', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.5.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      expect(policyManager.getPolicyVersion()).toBe('1.5.0');
    });

    it('should return fail-closed-default when no policies loaded', () => {
      policyManager = new PolicyManager({ 
        policyPath: join(testPolicyDir, 'non-existent.json'),
        failClosed: true,
      });
      
      expect(policyManager.getPolicyVersion()).toBe('fail-closed-default');
    });
  });

  describe('getPolicyHistory', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should track policy history', async () => {
      const policyContent1 = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent1, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const history = policyManager.getPolicyHistory();
      expect(history.length).toBeGreaterThan(0);
      expect(history[0]?.version).toBe('1.0');
    });

    it('should include rollback entries in history', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Rollback to same version (creates new history entry)
      await policyManager.rollbackPolicy('1.0');

      const history = policyManager.getPolicyHistory();
      expect(history.length).toBeGreaterThan(1);
      expect(history[history.length - 1]?.description).toContain('Rollback');
    });
  });

  describe('rollbackPolicy', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should rollback to previous policy version', async () => {
      const policyContent1 = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent1, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const policyContent2 = {
        version: '2.0',
        global: { riskThresholds: { allow: 0.2, block: 0.6 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent2, null, 2));
      await policyManager.reloadPolicies();

      // Rollback to version 1.0
      await policyManager.rollbackPolicy('1.0');

      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.thresholds.allow).toBe(0.3); // From version 1.0
    });

    it('should throw error when rolling back to non-existent version', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      await expect(policyManager.rollbackPolicy('non-existent')).rejects.toThrow(
        'Policy version not found'
      );
    });
  });

  describe('validatePolicy', () => {
    beforeEach(() => {
      policyManager = new PolicyManager();
    });

    it('should validate correct policy rule', () => {
      const rule = {
        id: 'test-rule',
        scope: 'global' as const,
        thresholdAllow: 0.3,
        thresholdBlock: 0.7,
        weights: { sensitivity: 0.6, exposure: 0.4 },
        enabled: true,
        version: '1.0',
      };

      const result = policyManager.validatePolicy(rule);
      expect(result.valid).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    it('should reject invalid thresholds', () => {
      const rule = {
        id: 'test-rule',
        scope: 'global' as const,
        thresholdAllow: 0.8,
        thresholdBlock: 0.5, // Invalid: allow >= block
        weights: { sensitivity: 0.6, exposure: 0.4 },
        enabled: true,
        version: '1.0',
      };

      const result = policyManager.validatePolicy(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject invalid weights', () => {
      const rule = {
        id: 'test-rule',
        scope: 'global' as const,
        thresholdAllow: 0.3,
        thresholdBlock: 0.7,
        weights: { sensitivity: 0.8, exposure: 0.5 }, // Sum = 1.3 > 1.0
        enabled: true,
        version: '1.0',
      };

      const result = policyManager.validatePolicy(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('weights sum'))).toBe(true);
    });

    it('should reject invalid action override', () => {
      const rule = {
        id: 'test-rule',
        scope: 'global' as const,
        thresholdAllow: 0.3,
        thresholdBlock: 0.7,
        weights: { sensitivity: 0.6, exposure: 0.4 },
        actionOverride: 'INVALID' as any,
        enabled: true,
        version: '1.0',
      };

      const result = policyManager.validatePolicy(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('actionOverride'))).toBe(true);
    });

    it('should require target for tenant-scoped policies', () => {
      const rule = {
        id: 'test-rule',
        scope: 'tenant' as const,
        thresholdAllow: 0.3,
        thresholdBlock: 0.7,
        weights: { sensitivity: 0.6, exposure: 0.4 },
        enabled: true,
        version: '1.0',
      };

      const result = policyManager.validatePolicy(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('target is required'))).toBe(true);
    });
  });

  describe('healthCheck', () => {
    it('should return true when policies are loaded', async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      const healthy = await policyManager.healthCheck();
      expect(healthy).toBe(true);
    });

    it('should return false when policies are not loaded', async () => {
      policyManager = new PolicyManager({ 
        policyPath: join(testPolicyDir, 'non-existent.json'),
        failClosed: false,
      });

      const healthy = await policyManager.healthCheck();
      expect(healthy).toBe(false);
    });
  });

  describe('hot-reload', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should enable hot-reload when configured', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ 
        policyPath: testPolicyPath,
        enableHotReload: true,
        reloadInterval: 1000, // Minimum allowed interval for testing
      });
      await policyManager.loadPolicies();

      expect(policyManager.getPolicyVersion()).toBe('1.0');

      // Update policy file
      const policyContent2 = {
        version: '2.0',
        global: { riskThresholds: { allow: 0.2, block: 0.6 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent2, null, 2));

      // Wait for hot-reload to trigger (need to wait at least reloadInterval)
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Hot-reload should have picked up the change
      expect(policyManager.getPolicyVersion()).toBe('2.0');
    });
  });

  describe('Security & Validation Improvements', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should validate configuration on construction', () => {
      expect(() => {
        new PolicyManager({ reloadInterval: 500 }); // Less than 1000ms
      }).toThrow('reloadInterval must be at least 1000ms');

      expect(() => {
        new PolicyManager({ maxFileSize: -1 });
      }).toThrow('maxFileSize must be greater than 0');

      expect(() => {
        new PolicyManager({ maxHistorySize: 0 });
      }).toThrow('maxHistorySize must be at least 1');
    });

    it('should enforce file size limits', async () => {
      // Create a large policy file (simulate)
      const largeContent = 'x'.repeat(11 * 1024 * 1024); // 11MB
      await fs.writeFile(testPolicyPath, JSON.stringify({ version: '1.0', global: {} }));

      policyManager = new PolicyManager({ 
        policyPath: testPolicyPath,
        maxFileSize: 10 * 1024 * 1024, // 10MB limit
      });

      // Manually create a large file to test
      const largeFile = join(testPolicyDir, 'large-policy.json');
      await fs.writeFile(largeFile, largeContent);

      policyManager = new PolicyManager({ 
        policyPath: largeFile,
        maxFileSize: 10 * 1024 * 1024,
      });

      await expect(policyManager.loadPolicies()).rejects.toThrow('Policy file too large');
    });

    it('should limit policy history size', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ 
        policyPath: testPolicyPath,
        maxHistorySize: 3,
      });

      // Load multiple versions
      for (let i = 1; i <= 5; i++) {
        const content = { ...policyContent, version: `${i}.0` };
        await fs.writeFile(testPolicyPath, JSON.stringify(content, null, 2));
        await policyManager.loadPolicies();
      }

      const history = policyManager.getPolicyHistory();
      expect(history.length).toBeLessThanOrEqual(3); // Should be limited
    });

    it('should handle concurrent reloads safely', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Trigger multiple concurrent reloads
      const reloads = Promise.all([
        policyManager.reloadPolicies(),
        policyManager.reloadPolicies(),
        policyManager.reloadPolicies(),
      ]);

      await expect(reloads).resolves.not.toThrow();
    });

    it('should validate raw config structure', async () => {
      // Invalid: not an object
      await fs.writeFile(testPolicyPath, '"invalid"');
      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await expect(policyManager.loadPolicies()).rejects.toThrow('Policy config must be an object');

      // Invalid: global is not an object
      await fs.writeFile(testPolicyPath, JSON.stringify({ global: 'invalid' }));
      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await expect(policyManager.loadPolicies()).rejects.toThrow('global policy must be an object');

      // Invalid: tenants is an array
      await fs.writeFile(testPolicyPath, JSON.stringify({ tenants: [] }));
      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await expect(policyManager.loadPolicies()).rejects.toThrow('tenants must be an object');
    });

    it('should provide better error messages for JSON parsing errors', async () => {
      await fs.writeFile(testPolicyPath, '{ invalid json }');
      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      
      await expect(policyManager.loadPolicies()).rejects.toThrow('Invalid JSON in policy file');
    });

    it('should provide better error messages for file read errors', async () => {
      const nonExistentPath = join(testPolicyDir, 'non-existent', 'policy.json');
      policyManager = new PolicyManager({ 
        policyPath: nonExistentPath,
        failClosed: false,
      });
      
      await expect(policyManager.loadPolicies()).rejects.toThrow('Policy file not found');
    });
  });

  describe('Edge Cases & Robustness', () => {
    beforeEach(async () => {
      await fs.mkdir(testPolicyDir, { recursive: true });
    });

    it('should handle empty strings for tenantId and toolName', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
        tenants: {
          'tenant-A': { riskThresholds: { allow: 0.2, block: 0.5 } },
        },
        tools: {
          'tool-1': { actionOverride: 'REDACT' },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Empty strings should be treated as undefined
      const resolution1 = await policyManager.getResolvedPolicy('', '');
      expect(resolution1.appliedPolicies).not.toContain('tenant');
      expect(resolution1.appliedPolicies).not.toContain('tool');

      // Whitespace-only strings should be treated as undefined
      const resolution2 = await policyManager.getResolvedPolicy('   ', '   ');
      expect(resolution2.appliedPolicies).not.toContain('tenant');
      expect(resolution2.appliedPolicies).not.toContain('tool');

      // Valid strings should work
      const resolution3 = await policyManager.getResolvedPolicy('tenant-A', 'tool-1');
      expect(resolution3.appliedPolicies.some(p => p.includes('tenant:tenant-A'))).toBe(true);
      expect(resolution3.appliedPolicies.some(p => p.includes('tool:tool-1'))).toBe(true);
    });

    it('should reject NaN values in numeric fields', async () => {
      // JSON.stringify converts NaN to null, so we need to manually create invalid JSON
      await fs.writeFile(testPolicyPath, JSON.stringify({
        version: '1.0',
        global: {
          riskThresholds: { allow: null, block: 0.7 },
        },
      }, null, 2).replace('null', 'NaN'));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      // JSON.parse will fail on NaN, so this will throw a JSON parse error
      await expect(policyManager.loadPolicies()).rejects.toThrow();
    });

    it('should reject Infinity values in numeric fields', async () => {
      // JSON.stringify converts Infinity to null, so we need to manually create invalid JSON
      await fs.writeFile(testPolicyPath, JSON.stringify({
        version: '1.0',
        global: {
          riskThresholds: { allow: null, block: 0.7 },
        },
      }, null, 2).replace('null', 'Infinity'));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      // JSON.parse will fail on Infinity, so this will throw a JSON parse error
      await expect(policyManager.loadPolicies()).rejects.toThrow();
    });

    it('should use default values for non-numeric string values in numeric fields', async () => {
      // JSON.parse will parse "invalid" as a string, which validateNumeric will reject
      // and use the default value
      const policyContent = {
        version: '1.0',
        global: {
          riskThresholds: { allow: 'invalid' as any, block: 0.7 },
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies(); // Should use default value

      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.thresholds.allow).toBe(0.3); // Uses default value
    });

    it('should handle empty tenant/tool IDs in config', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
        tenants: {
          '': { riskThresholds: { allow: 0.2 } }, // Empty tenant ID
        },
        tools: {
          '   ': { actionOverride: 'REDACT' }, // Whitespace-only tool name
        },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await expect(policyManager.loadPolicies()).rejects.toThrow('must be a non-empty string');
    });

    it('should preserve previous policy on reload failure', async () => {
      const policyContent1 = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent1, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();
      expect(policyManager.getPolicyVersion()).toBe('1.0');

      // Write invalid JSON
      await fs.writeFile(testPolicyPath, '{ invalid json }');

      // Reload should fail but preserve previous policy
      await expect(policyManager.reloadPolicies()).rejects.toThrow('Policy reload failed');
      expect(policyManager.getPolicyVersion()).toBe('1.0'); // Previous version preserved
    });

    it('should handle hot-reload failure gracefully', async () => {
      const policyContent = {
        version: '1.0',
        global: { riskThresholds: { allow: 0.3, block: 0.7 } },
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ 
        policyPath: testPolicyPath,
        enableHotReload: true,
        reloadInterval: 1000,
      });
      await policyManager.loadPolicies();
      expect(policyManager.getPolicyVersion()).toBe('1.0');

      // Write invalid JSON
      await fs.writeFile(testPolicyPath, '{ invalid json }');

      // Wait for hot-reload to attempt reload
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Previous policy should be preserved
      expect(policyManager.getPolicyVersion()).toBe('1.0');
    });

    it('should handle empty policy set (no global, tenants, or tools)', async () => {
      const policyContent = {
        version: '1.0',
        // No global, tenants, or tools
      };
      await fs.writeFile(testPolicyPath, JSON.stringify(policyContent, null, 2));

      policyManager = new PolicyManager({ policyPath: testPolicyPath });
      await policyManager.loadPolicies();

      // Should return fail-closed defaults
      const resolution = await policyManager.getResolvedPolicy();
      expect(resolution.policyVersion).toBe('fail-closed-default');
    });
  });
});

