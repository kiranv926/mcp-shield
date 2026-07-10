/**
 * TaintGate: TaintRegistry Tests
 * 
 * Comprehensive test suite for the State Manager implementation.
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { TaintRegistry } from '../../core/TaintRegistry';
import { ResponseScraper } from '../../core/ResponseScraper';
import { SensitivityLevel } from '../../types/mcp-hints';
import type { TaintContext } from '../../types/common';

describe('TaintRegistry', () => {
  let registry: TaintRegistry;

  const createTaintContext = (
    sourceTool: string,
    sensitivityLevel: SensitivityLevel,
    sessionId: string,
    tenantId?: string,
    containsSecrets = false
  ): Omit<TaintContext, 'contextId' | 'timestamp'> => ({
    sourceTool,
    sensitivityLevel,
    containsSecrets,
    sessionId,
    tenantId,
  });

  beforeEach(() => {
    registry = new TaintRegistry({
      sessionTTL: 3600,
      contextTTL: 1800,
      enableMultiTenant: true,
      cacheBackend: 'memory',
    });
  });

  describe('Constructor', () => {
    it('should initialize with default configuration', () => {
      const defaultRegistry = new TaintRegistry();
      const config = defaultRegistry.getConfig();
      
      expect(config.sessionTTL).toBe(3600);
      expect(config.contextTTL).toBe(1800);
      expect(config.enableMultiTenant).toBe(true);
      expect(config.cacheBackend).toBe('memory');
    });

    it('should initialize with custom configuration', () => {
      const customRegistry = new TaintRegistry({
        sessionTTL: 7200,
        contextTTL: 3600,
        enableMultiTenant: false,
        cacheBackend: 'redis',
        cacheUrl: 'redis://localhost:6379',
      });
      
      const config = customRegistry.getConfig();
      expect(config.sessionTTL).toBe(7200);
      expect(config.contextTTL).toBe(3600);
      expect(config.enableMultiTenant).toBe(false);
      expect(config.cacheBackend).toBe('redis');
      expect(config.cacheUrl).toBe('redis://localhost:6379');
    });
  });

  describe('registerTaint()', () => {
    it('should register a new taint context', async () => {
      const context = createTaintContext(
        'databaseTool',
        SensitivityLevel.Confidential,
        'session-1',
        'tenant-1'
      );

      const contextId = await registry.registerTaint(context);

      expect(contextId).toBeDefined();
      expect(typeof contextId).toBe('string');
      expect(contextId.length).toBeGreaterThan(0);
    });

    it('should register taint with actual data values (hash-based)', async () => {
      const context = createTaintContext(
        'databaseTool',
        SensitivityLevel.Confidential,
        'session-1',
        'tenant-1'
      );

      // CRITICAL: Pass actual data values for hash-based matching
      const dataValues = ['user@example.com', '12345', 'sensitive-data'];
      const contextId = await registry.registerTaint(context, dataValues);

      expect(contextId).toBeDefined();
      
      // Verify taint can be detected via lineage check
      const lineageResult = await registry.checkLineage(
        { email: 'user@example.com', id: '12345' },
        'session-1',
        'tenant-1'
      );

      expect(lineageResult.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(lineageResult.relevantContexts.length).toBeGreaterThan(0);
    });

    it('should hash values for privacy (not store raw data)', async () => {
      const context = createTaintContext(
        'secretTool',
        SensitivityLevel.Restricted,
        'session-1'
      );

      const sensitiveData = ['secret-password-123', 'api-key-xyz'];
      await registry.registerTaint(context, sensitiveData);

      // Verify values are hashed (we can't directly check storage, but lineage should work)
      const lineageResult = await registry.checkLineage(
        { password: 'secret-password-123' },
        'session-1'
      );

      // If hashing works, lineage should detect the match
      expect(lineageResult.highestSensitivity).toBe(SensitivityLevel.Restricted);
    });

    it('should register multiple taints for the same session', async () => {
      const context1 = createTaintContext(
        'tool1',
        SensitivityLevel.Internal,
        'session-1'
      );
      const context2 = createTaintContext(
        'tool2',
        SensitivityLevel.Confidential,
        'session-1'
      );

      const id1 = await registry.registerTaint(context1);
      const id2 = await registry.registerTaint(context2);

      expect(id1).not.toBe(id2);

      const isTainted = await registry.isSessionTainted('session-1');
      expect(isTainted).toBe(true);
    });

    it('should isolate taints by tenant', async () => {
      const context1 = createTaintContext(
        'tool1',
        SensitivityLevel.Confidential,
        'session-1',
        'tenant-1'
      );
      const context2 = createTaintContext(
        'tool2',
        SensitivityLevel.Confidential,
        'session-1',
        'tenant-2'
      );

      await registry.registerTaint(context1);
      await registry.registerTaint(context2);

      const taints1 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-1',
      });
      const taints2 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-2',
      });

      expect(taints1.length).toBe(1);
      expect(taints2.length).toBe(1);
      expect(taints1[0].sourceTool).toBe('tool1');
      expect(taints2[0].sourceTool).toBe('tool2');
    });

    it('should track origin tool for audit trail', async () => {
      const context = createTaintContext(
        'sensitiveDataTool',
        SensitivityLevel.Restricted,
        'session-1'
      );

      await registry.registerTaint(context);

      const taints = await registry.queryTaints({
        sessionId: 'session-1',
      });

      expect(taints.length).toBe(1);
      expect(taints[0].sourceTool).toBe('sensitiveDataTool');
    });
  });

  describe('queryTaints()', () => {
    beforeEach(async () => {
      // Set up test data
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Public, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Internal, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('tool3', SensitivityLevel.Confidential, 'session-1')
      );
    });

    it('should return all taints for a session', async () => {
      const taints = await registry.queryTaints({
        sessionId: 'session-1',
      });

      expect(taints.length).toBe(3);
    });

    it('should filter by minimum sensitivity', async () => {
      const taints = await registry.queryTaints({
        sessionId: 'session-1',
        minSensitivity: SensitivityLevel.Internal,
      });

      expect(taints.length).toBe(2); // Internal and Confidential
      expect(taints.every(t => 
        t.sensitivityLevel === SensitivityLevel.Internal ||
        t.sensitivityLevel === SensitivityLevel.Confidential
      )).toBe(true);
    });

    it('should exclude expired contexts by default', async () => {
      // Create a registry with very short TTL
      const shortTTLRegistry = new TaintRegistry({
        contextTTL: 0.001, // 1ms
      });

      await shortTTLRegistry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const taints = await shortTTLRegistry.queryTaints({
        sessionId: 'session-1',
        includeExpired: false,
      });

      expect(taints.length).toBe(0);
    });

    it('should include expired contexts when requested', async () => {
      const shortTTLRegistry = new TaintRegistry({
        contextTTL: 0.001, // 1ms
      });

      await shortTTLRegistry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const taints = await shortTTLRegistry.queryTaints({
        sessionId: 'session-1',
        includeExpired: true,
      });

      expect(taints.length).toBe(1);
    });
  });

  describe('isSessionTainted()', () => {
    it('should return false for untainted session', async () => {
      const isTainted = await registry.isSessionTainted('session-1');
      expect(isTainted).toBe(false);
    });

    it('should return true for tainted session', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );

      const isTainted = await registry.isSessionTainted('session-1');
      expect(isTainted).toBe(true);
    });

    it('should respect tenant isolation', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );

      const isTainted1 = await registry.isSessionTainted('session-1', 'tenant-1');
      const isTainted2 = await registry.isSessionTainted('session-1', 'tenant-2');

      expect(isTainted1).toBe(true);
      expect(isTainted2).toBe(false);
    });
  });

  describe('getRelevantTaints()', () => {
    beforeEach(async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Internal, 'session-1')
      );
    });

    it('should return relevant taints for a tool', async () => {
      const taints = await registry.getRelevantTaints('tool3', {
        sessionId: 'session-1',
      });

      // For now, returns all taints (production would analyze tool parameters)
      expect(taints.length).toBeGreaterThan(0);
    });
  });

  describe('checkLineage()', () => {
    beforeEach(async () => {
      // Register taints with known values
      await registry.registerTaint(
        createTaintContext('databaseTool', SensitivityLevel.Confidential, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('apiTool', SensitivityLevel.Restricted, 'session-1')
      );
    });

    it('should return null when no taint is found', async () => {
      const result = await registry.checkLineage(
        { param1: 'untainted-value', param2: 123 },
        'session-1'
      );

      expect(result.highestSensitivity).toBeNull();
      expect(result.relevantContexts).toEqual([]);
      expect(result.containsSecrets).toBe(false);
    });

    it('should detect taint in string parameters (hash-based matching)', async () => {
      // Register taint with actual data values
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1'),
        ['test-id', 'some-query']
      );

      // Now check lineage - should detect the tainted values
      const result = await registry.checkLineage(
        { query: 'some-query', id: 'test-id' },
        'session-1'
      );

      expect(result.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(result.relevantContexts.length).toBeGreaterThan(0);
      expect(result.relevantContexts[0].sourceTool).toBe('tool1');
    });

    it('should return highest sensitivity when multiple taints match', async () => {
      // Register taints with different sensitivity levels and actual data values
      await registry.registerTaint(
        createTaintContext('lowSensitivityTool', SensitivityLevel.Public, 'session-2'),
        ['test-value']
      );
      await registry.registerTaint(
        createTaintContext('highSensitivityTool', SensitivityLevel.Restricted, 'session-2'),
        ['test-value'] // Same value, different sensitivity
      );

      const result = await registry.checkLineage(
        { data: 'test-value' },
        'session-2'
      );

      // Should return the highest sensitivity found (Restricted)
      expect(result.highestSensitivity).toBe(SensitivityLevel.Restricted);
      expect(result.relevantContexts.length).toBeGreaterThan(0);
    });

    it('should track origin tool in relevant contexts', async () => {
      await registry.registerTaint(
        createTaintContext('originTool', SensitivityLevel.Confidential, 'session-3'),
        ['value']
      );

      const result = await registry.checkLineage(
        { param: 'value' },
        'session-3'
      );

      expect(result.relevantContexts.length).toBeGreaterThan(0);
      expect(result.relevantContexts[0].sourceTool).toBe('originTool');
    });

    it('should detect secrets in taint', async () => {
      await registry.registerTaint(
        createTaintContext('secretTool', SensitivityLevel.Confidential, 'session-4', undefined, true),
        ['secret-data']
      );

      const result = await registry.checkLineage(
        { data: 'secret-data' },
        'session-4'
      );

      // Taint should be detected and secrets should be flagged
      expect(result.relevantContexts.length).toBeGreaterThan(0);
      expect(result.containsSecrets).toBe(true);
    });

    it('should handle nested object parameters', async () => {
      // Register taint with values that appear in nested structure
      await registry.registerTaint(
        createTaintContext('nestedTool', SensitivityLevel.Internal, 'session-1'),
        ['test@example.com', '123', 'tag1']
      );

      const nestedParams = {
        user: {
          id: '123',
          profile: {
            email: 'test@example.com',
          },
        },
        metadata: {
          tags: ['tag1', 'tag2'],
        },
      };

      const result = await registry.checkLineage(nestedParams, 'session-1');

      // Should detect tainted values in nested structures
      expect(result.highestSensitivity).toBe(SensitivityLevel.Internal);
      expect(result.relevantContexts.length).toBeGreaterThan(0);
    });

    it('should handle array parameters', async () => {
      // Register taint with array values
      await registry.registerTaint(
        createTaintContext('arrayTool', SensitivityLevel.Confidential, 'session-1'),
        ['item2', 'item3']
      );

      const arrayParams = {
        items: ['item1', 'item2', 'item3'],
        numbers: [1, 2, 3],
      };

      const result = await registry.checkLineage(arrayParams, 'session-1');

      // Should detect tainted values in arrays
      expect(result.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(result.relevantContexts.length).toBeGreaterThan(0);
    });

    it('should respect tenant isolation in lineage check', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1'),
        ['test-value']
      );

      const result1 = await registry.checkLineage(
        { data: 'test-value' },
        'session-1',
        'tenant-1'
      );
      const result2 = await registry.checkLineage(
        { data: 'test-value' },
        'session-1',
        'tenant-2'
      );

      // Tenant-1 should see the taint, tenant-2 should not
      expect(result1.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(result2.highestSensitivity).toBeNull();
    });
  });

  describe('clearSession()', () => {
    it('should clear all taints for a session', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Internal, 'session-1')
      );

      await registry.clearSession('session-1');

      const isTainted = await registry.isSessionTainted('session-1');
      expect(isTainted).toBe(false);

      const taints = await registry.queryTaints({ sessionId: 'session-1' });
      expect(taints.length).toBe(0);
    });

    it('should only clear taints for specified tenant', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Confidential, 'session-1', 'tenant-2')
      );

      await registry.clearSession('session-1', 'tenant-1');

      const taints1 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-1',
      });
      const taints2 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-2',
      });

      expect(taints1.length).toBe(0);
      expect(taints2.length).toBe(1);
    });
  });

  describe('clearContext()', () => {
    it('should clear a specific taint context', async () => {
      const id1 = await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );
      const id2 = await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Internal, 'session-1')
      );

      await registry.clearContext(id1);

      const taints = await registry.queryTaints({ sessionId: 'session-1' });
      expect(taints.length).toBe(1);
      expect(taints[0].contextId).toBe(id2);
    });

    it('should respect tenant isolation when clearing context', async () => {
      const id1 = await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Confidential, 'session-1', 'tenant-2')
      );

      await registry.clearContext(id1, 'tenant-1');

      const taints1 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-1',
      });
      const taints2 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-2',
      });

      expect(taints1.length).toBe(0);
      expect(taints2.length).toBe(1);
    });
  });

  describe('updateContextTTL()', () => {
    it('should update context expiration time', async () => {
      const contextId = await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );

      // Update TTL to a longer duration
      await registry.updateContextTTL(contextId, 7200);

      // Context should still be active
      const taints = await registry.queryTaints({ sessionId: 'session-1' });
      expect(taints.length).toBe(1);
    });

    it('should respect tenant isolation when updating TTL', async () => {
      const id1 = await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );

      await registry.updateContextTTL(id1, 7200, 'tenant-1');

      const taints = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-1',
      });
      expect(taints.length).toBe(1);
    });
  });

  describe('getSessionStats()', () => {
    it('should return statistics for a session', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Public, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Internal, 'session-1')
      );
      await registry.registerTaint(
        createTaintContext('tool3', SensitivityLevel.Confidential, 'session-1')
      );

      const stats = await registry.getSessionStats('session-1');

      expect(stats.totalContexts).toBe(3);
      expect(stats.activeContexts).toBe(3);
      expect(stats.expiredContexts).toBe(0);
      expect(stats.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(stats.hasSecrets).toBe(false);
    });

    it('should track secrets in statistics', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', undefined, true)
      );

      const stats = await registry.getSessionStats('session-1');

      expect(stats.hasSecrets).toBe(true);
    });

    it('should count expired contexts', async () => {
      const shortTTLRegistry = new TaintRegistry({
        contextTTL: 0.001, // 1ms
      });

      await shortTTLRegistry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1')
      );

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      const stats = await shortTTLRegistry.getSessionStats('session-1');

      expect(stats.totalContexts).toBe(1);
      expect(stats.activeContexts).toBe(0);
      expect(stats.expiredContexts).toBe(1);
    });

    it('should respect tenant isolation in statistics', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Confidential, 'session-1', 'tenant-2')
      );

      const stats1 = await registry.getSessionStats('session-1', 'tenant-1');
      const stats2 = await registry.getSessionStats('session-1', 'tenant-2');

      expect(stats1.totalContexts).toBe(1);
      expect(stats2.totalContexts).toBe(1);
    });
  });

  describe('healthCheck()', () => {
    it('should return true for healthy registry', async () => {
      const isHealthy = await registry.healthCheck();
      expect(isHealthy).toBe(true);
    });
  });

  describe('Configuration Management', () => {
    it('should get current configuration', () => {
      const config = registry.getConfig();

      expect(config).toBeDefined();
      expect(config.sessionTTL).toBe(3600);
      expect(config.contextTTL).toBe(1800);
      expect(config.enableMultiTenant).toBe(true);
    });

    it('should update configuration', () => {
      registry.updateConfig({
        sessionTTL: 7200,
        contextTTL: 3600,
      });

      const config = registry.getConfig();
      expect(config.sessionTTL).toBe(7200);
      expect(config.contextTTL).toBe(3600);
      // Other values should remain unchanged
      expect(config.enableMultiTenant).toBe(true);
    });

    it('should support partial configuration updates', () => {
      const originalConfig = registry.getConfig();
      
      registry.updateConfig({
        sessionTTL: 7200,
      });

      const updatedConfig = registry.getConfig();
      expect(updatedConfig.sessionTTL).toBe(7200);
      expect(updatedConfig.contextTTL).toBe(originalConfig.contextTTL);
    });
  });

  describe('Composite Key Isolation', () => {
    it('should isolate sessions with same ID but different tenants', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );
      await registry.registerTaint(
        createTaintContext('tool2', SensitivityLevel.Confidential, 'session-1', 'tenant-2')
      );

      const taints1 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-1',
      });
      const taints2 = await registry.queryTaints({
        sessionId: 'session-1',
        tenantId: 'tenant-2',
      });

      expect(taints1.length).toBe(1);
      expect(taints2.length).toBe(1);
      expect(taints1[0].sourceTool).toBe('tool1');
      expect(taints2[0].sourceTool).toBe('tool2');
    });

    it('should isolate tenants with same session ID', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1', 'tenant-1')
      );

      const isTainted1 = await registry.isSessionTainted('session-1', 'tenant-1');
      const isTainted2 = await registry.isSessionTainted('session-1', 'tenant-2');

      expect(isTainted1).toBe(true);
      expect(isTainted2).toBe(false);
    });
  });

  describe('Origin Tool Tracking', () => {
    it('should preserve origin tool in taint context', async () => {
      const originTool = 'databaseQueryTool';
      await registry.registerTaint(
        createTaintContext(originTool, SensitivityLevel.Confidential, 'session-1'),
        ['data-value']
      );

      const taints = await registry.queryTaints({ sessionId: 'session-1' });

      expect(taints.length).toBeGreaterThan(0);
      expect(taints[0].sourceTool).toBe(originTool);
    });

    it('should track origin tool in lineage results', async () => {
      const originTool = 'sensitiveDataFetcher';
      await registry.registerTaint(
        createTaintContext(originTool, SensitivityLevel.Restricted, 'session-1'),
        ['test-data']
      );

      const result = await registry.checkLineage(
        { data: 'test-data' },
        'session-1'
      );

      // Taint should be detected and origin tool should be preserved
      expect(result.relevantContexts.length).toBeGreaterThan(0);
      expect(result.relevantContexts[0].sourceTool).toBe(originTool);
    });
  });

  describe('Hash-Based Storage', () => {
    it('should store hashes, not raw values', async () => {
      const sensitiveValue = 'secret-password-123';
      await registry.registerTaint(
        createTaintContext('secretTool', SensitivityLevel.Restricted, 'session-1'),
        [sensitiveValue]
      );

      // Verify we can match via hash (lineage check)
      const result = await registry.checkLineage(
        { password: sensitiveValue },
        'session-1'
      );

      expect(result.highestSensitivity).toBe(SensitivityLevel.Restricted);
    });

    it('should handle value length limits (DoS protection)', async () => {
      const longValue = 'a'.repeat(2000); // Exceeds MAX_VALUE_LENGTH (1024)
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1'),
        [longValue]
      );

      // Should truncate and hash (no error thrown)
      const result = await registry.checkLineage(
        { data: longValue.substring(0, 1024) },
        'session-1'
      );

      // Should still work with truncated value
      expect(result).toBeDefined();
    });

    it('should filter out noise (values too short)', async () => {
      await registry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1'),
        ['ab', 'x', ''] // Too short (min length is 3)
      );

      const result = await registry.checkLineage(
        { data: 'ab' },
        'session-1'
      );

      // Short values should not be stored (noise filtering)
      expect(result.highestSensitivity).toBeNull();
    });
  });

  describe('Security Fix: Numeric taint evasion (registration/check symmetry)', () => {
    it('should taint a secret returned as a JSON number and flag a later call consuming it', async () => {
      // Simulate a tool response where the secret is returned as a JSON *number*.
      const secretNumber = 9087654321; // e.g. an account/secret code as a number
      const toolResponse = { account: { code: secretNumber, label: 'primary' } };

      // Registration path: ResponseScraper must extract numeric leaves (symmetry fix).
      const scraped = ResponseScraper.scrape(toolResponse);
      expect(scraped).toContain(String(secretNumber));

      await registry.registerTaint(
        createTaintContext('numberTool', SensitivityLevel.Confidential, 'session-num'),
        scraped
      );

      // A later tool call consuming that same value (as a number) must be flagged.
      const result = await registry.checkLineage(
        { forwardTo: 'sink', payload: secretNumber },
        'session-num'
      );

      expect(result.highestSensitivity).toBe(SensitivityLevel.Confidential);
      expect(result.relevantContexts.length).toBeGreaterThan(0);
    });

    it('should match a numeric secret whether it arrives as a number or its string form', async () => {
      await registry.registerTaint(
        createTaintContext('numberTool', SensitivityLevel.Restricted, 'session-num2'),
        ResponseScraper.scrape({ token: 5551239876 })
      );

      const asNumber = await registry.checkLineage({ v: 5551239876 }, 'session-num2');
      const asString = await registry.checkLineage({ v: '5551239876' }, 'session-num2');

      expect(asNumber.highestSensitivity).toBe(SensitivityLevel.Restricted);
      expect(asString.highestSensitivity).toBe(SensitivityLevel.Restricted);
    });
  });

  describe('Security Fix: Sub-token false positives', () => {
    it('should NOT over-taint an unrelated later call from a common word like "User"', async () => {
      // A tool returns "User ID: 12345"; the meaningful id (12345) is tainted, but the
      // dictionary word "User" must not be registered as a taint on its own.
      const scraped = ResponseScraper.scrape({ note: 'User ID: 12345' });
      expect(scraped).not.toContain('User');
      expect(scraped).toContain('12345');

      await registry.registerTaint(
        createTaintContext('lookupTool', SensitivityLevel.Confidential, 'session-sub'),
        scraped
      );

      // Unrelated later call that merely mentions the word "User" (no real id) -> not tainted.
      const unrelated = await registry.checkLineage(
        { message: 'User logged in successfully' },
        'session-sub'
      );
      expect(unrelated.highestSensitivity).toBeNull();
      expect(unrelated.relevantContexts).toEqual([]);

      // But a call that actually reuses the tainted id IS still flagged.
      const reused = await registry.checkLineage({ id: '12345' }, 'session-sub');
      expect(reused.highestSensitivity).toBe(SensitivityLevel.Confidential);
    });

    it('should still track a real high-entropy secret token', async () => {
      const secret = 'aB3xK9mZ7qLw2Rt'; // high-entropy, mixed-case + digits
      const scraped = ResponseScraper.scrape({ credential: `Bearer ${secret}` });
      expect(scraped).toContain(secret);

      await registry.registerTaint(
        createTaintContext('authTool', SensitivityLevel.Restricted, 'session-sub2', undefined, true),
        scraped
      );

      const result = await registry.checkLineage(
        { authorization: secret },
        'session-sub2'
      );
      expect(result.highestSensitivity).toBe(SensitivityLevel.Restricted);
      expect(result.containsSecrets).toBe(true);
    });
  });

  describe('Security Fix: Depth cap evasion', () => {
    it('should still taint deeply-nested sensitive data at a reasonable depth', async () => {
      // Bury a sensitive value at depth 8 (previously beyond the depth-5 cap).
      let nested: any = { secretCode: 'X9f3Kq7Zt10' };
      for (let i = 0; i < 8; i++) {
        nested = { level: nested };
      }

      const scraped = ResponseScraper.scrape(nested);
      expect(scraped).toContain('X9f3Kq7Zt10');

      await registry.registerTaint(
        createTaintContext('deepTool', SensitivityLevel.Confidential, 'session-deep'),
        scraped
      );

      const result = await registry.checkLineage(
        { exfil: 'X9f3Kq7Zt10' },
        'session-deep'
      );
      expect(result.highestSensitivity).toBe(SensitivityLevel.Confidential);
    });

    it('should expose configurable tokenization limits', () => {
      expect(() => registry.setTokenizationLimits({ maxDepth: 20, maxTokens: 5000 })).not.toThrow();
      expect(() => registry.setTokenizationLimits({ maxDepth: 0 })).toThrow();
      expect(() => registry.setTokenizationLimits({ maxTokens: -1 })).toThrow();
    });
  });

  describe('Periodic Cleanup', () => {
    it('should purge expired sessions', async () => {
      const shortTTLRegistry = new TaintRegistry({
        contextTTL: 0.001, // 1ms
        sessionTTL: 0.001,
      });

      await shortTTLRegistry.registerTaint(
        createTaintContext('tool1', SensitivityLevel.Confidential, 'session-1'),
        ['value1']
      );

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 10));

      // Manually trigger cleanup
      shortTTLRegistry.purgeExpiredSessions(1);

      const isTainted = await shortTTLRegistry.isSessionTainted('session-1');
      expect(isTainted).toBe(false);
    });
  });
});

