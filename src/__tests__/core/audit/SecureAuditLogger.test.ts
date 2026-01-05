/**
 * MCP-Shield: SecureAuditLogger Unit Tests
 * 
 * Tests for the hardened SecureAuditLogger implementation with hash chain integrity.
 */

import { SecureAuditLogger } from '../../../core/audit/SecureAuditLogger';
import type { AuditLogEntry, SystemErrorAuditEntry } from '../../../interfaces/IAuditLogger';
import type { SecureAuditEntry } from '../../../types/audit';
import { createRiskScore } from '../../../types/common';
import { SensitivityLevel } from '../../../types/mcp-hints';
import { promises as fs } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('SecureAuditLogger', () => {
  let logger: SecureAuditLogger;
  let logDir: string;

  beforeEach(() => {
    logDir = join(tmpdir(), `mcp-shield-secure-test-${Date.now()}`);
    logger = new SecureAuditLogger({ logDirectory: logDir });
  });

  afterEach(async () => {
    // Cleanup: Remove test log files
    try {
      await fs.rm(logDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Hash Chain Implementation', () => {
    it('should initialize with genesis hash', () => {
      expect(logger.getLastHash()).toBe('MCP-SHIELD-GENESIS-001');
    });

    it('should create hash chain for sequential entries', async () => {
      const entry1: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        toolName: 'tool-1',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.1),
          justification: 'Test 1',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-1',
          riskBreakdown: {
            sensitivity: 0.0,
            exposure: 0,
            trust: 1.0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 0.0,
            finalScore: createRiskScore(0.0),
          },
        },
        taintContexts: [],
        policyVersion: '1.0',
        timestamp: Date.now(),
      };

      const entry2: AuditLogEntry = {
        ...entry1,
        requestId: 'req-2',
        decision: {
          ...entry1.decision,
          justification: 'Test 2',
          requestId: 'req-2',
        },
      };

      await logger.logDecision(entry1);
      const hash1 = logger.getLastHash();
      expect(hash1).not.toBe('MCP-SHIELD-GENESIS-001');

      await logger.logDecision(entry2);
      const hash2 = logger.getLastHash();
      expect(hash2).not.toBe(hash1);

      // Verify entries have prevSig
      const secureLogs = logger.getSecureLogs();
      expect(secureLogs).toHaveLength(2);
      expect(secureLogs[0]?.prevSig).toBeUndefined(); // First entry has no prevSig
      expect(secureLogs[1]?.prevSig).toBeDefined(); // Second entry references first
    });

    it('should include prevSig in secure entries', async () => {
      const entry: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        toolName: 'tool-1',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.1),
          justification: 'Test',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-1',
          riskBreakdown: {
            sensitivity: 0.0,
            exposure: 0,
            trust: 1.0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 0.0,
            finalScore: createRiskScore(0.0),
          },
        },
        taintContexts: [],
        policyVersion: '1.0',
        timestamp: Date.now(),
      };

      await logger.logDecision(entry);

      const secureLogs = logger.getSecureLogs();
      expect(secureLogs).toHaveLength(1);
      expect(secureLogs[0]?.v).toBe('1.1');
      expect(secureLogs[0]?.sig).toBeDefined();
      expect(secureLogs[0]?.prevSig).toBeUndefined(); // First entry
    });
  });

  describe('Fail-Closed Behavior', () => {
    it('should throw error on hash chain failure (fail-closed)', async () => {
      // Mock console.error to suppress expected error messages from constructor
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {
        // Suppress expected error output
      });

      try {
        // Create logger with invalid directory to force write failure
        const failingLogger = new SecureAuditLogger({ 
          logDirectory: '/invalid/path/that/does/not/exist' 
        });

        // Allow constructor's async error handling to complete
        await new Promise(resolve => setTimeout(resolve, 10));

        const entry: AuditLogEntry = {
          requestId: 'req-1',
          sessionId: 'session-1',
          toolName: 'tool-1',
          decision: {
            action: 'ALLOW',
            riskScore: createRiskScore(0.1),
            justification: 'Test',
            timestamp: new Date(),
            policyVersion: '1.0',
            requestId: 'req-1',
            riskBreakdown: {
              sensitivity: 0.0,
              exposure: 0,
              trust: 1.0,
              weightSensitivity: 0.6,
              weightExposure: 0.4,
              rawScore: 0.0,
              finalScore: createRiskScore(0.0),
            },
          },
          taintContexts: [],
          policyVersion: '1.0',
          timestamp: Date.now(),
        };

        // Should throw (fail-closed behavior)
        await expect(failingLogger.logDecision(entry)).rejects.toThrow(
          'Audit logging failed (hash chain)'
        );
      } finally {
        consoleErrorSpy.mockRestore();
      }
    });
  });

  describe('verifyIntegrity', () => {
    it('should verify valid hash chain', async () => {
      const entries: AuditLogEntry[] = [
        {
          requestId: 'req-1',
          sessionId: 'session-1',
          toolName: 'tool-1',
          decision: {
            action: 'ALLOW',
            riskScore: createRiskScore(0.1),
            justification: 'Test 1',
            timestamp: new Date(),
            policyVersion: '1.0',
            requestId: 'req-1',
            riskBreakdown: {
              sensitivity: 0.0,
              exposure: 0,
              trust: 1.0,
              weightSensitivity: 0.6,
              weightExposure: 0.4,
              rawScore: 0.0,
              finalScore: createRiskScore(0.0),
            },
          },
          taintContexts: [],
          policyVersion: '1.0',
          timestamp: Date.now(),
        },
        {
          requestId: 'req-2',
          sessionId: 'session-1',
          toolName: 'tool-2',
          decision: {
            action: 'BLOCK',
            riskScore: createRiskScore(0.9),
            justification: 'Test 2',
            timestamp: new Date(),
            policyVersion: '1.0',
            requestId: 'req-2',
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
          taintContexts: [],
          policyVersion: '1.0',
          timestamp: Date.now(),
        },
      ];

      for (const entry of entries) {
        await logger.logDecision(entry);
      }

      const secureLogs = logger.getSecureLogs();
      const isValid = await logger.verifyIntegrity(secureLogs);
      expect(isValid).toBe(true);
    });

    it('should detect tampering in hash chain', async () => {
      // Log first entry
      const entry1: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        toolName: 'tool-1',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.1),
          justification: 'Test',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-1',
          riskBreakdown: {
            sensitivity: 0.0,
            exposure: 0,
            trust: 1.0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 0.0,
            finalScore: createRiskScore(0.0),
          },
        },
        taintContexts: [],
        policyVersion: '1.0',
        timestamp: Date.now(),
      };

      // Log second entry (this will have prevSig pointing to first entry's hash)
      const entry2: AuditLogEntry = {
        requestId: 'req-2',
        sessionId: 'session-1',
        toolName: 'tool-2',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.2),
          justification: 'Test 2',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-2',
          riskBreakdown: {
            sensitivity: 0.0,
            exposure: 0,
            trust: 1.0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 0.0,
            finalScore: createRiskScore(0.0),
          },
        },
        taintContexts: [],
        policyVersion: '1.0',
        timestamp: Date.now(),
      };

      await logger.logDecision(entry1);
      await logger.logDecision(entry2);

      const secureLogs = logger.getSecureLogs();
      
      // Tamper with the first entry (change action from ALLOW to BLOCK)
      if (secureLogs[0]) {
        secureLogs[0].decision.act = 'BLOCK'; // Change action
      }

      // Now verifyIntegrity should detect that entry2's prevSig doesn't match
      // the recalculated hash of the tampered entry1
      const isValid = await logger.verifyIntegrity(secureLogs);
      expect(isValid).toBe(false);
    });

    it('should return true for empty chain', async () => {
      const isValid = await logger.verifyIntegrity([]);
      expect(isValid).toBe(true);
    });
  });

  describe('Taint Context Handling', () => {
    it('should include taint contexts in provenance', async () => {
      const entry: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'database:read_row',
        decision: {
          action: 'BLOCK',
          riskScore: createRiskScore(0.9),
          justification: 'Data laundering detected',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-1',
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
        taintContexts: [
          {
            contextId: 'ctx-1',
            sessionId: 'session-1',
            tenantId: 'tenant-1',
            sourceTool: 'database:read_row',
            sensitivityLevel: SensitivityLevel.Confidential,
            containsSecrets: false,
            timestamp: new Date(),
          },
        ],
        policyVersion: '1.0',
        timestamp: Date.now(),
        metadata: {
          originTools: ['database:read_row'],
        },
      };

      await logger.logDecision(entry);

      const secureLogs = logger.getSecureLogs();
      expect(secureLogs[0]?.prov).toBeDefined();
      expect(secureLogs[0]?.prov?.origin).toContain('database:read_row');
      expect(secureLogs[0]?.prov?.sensitivity).toBe(1.0);
    });
  });

  describe('queryLogs', () => {
    it('should convert secure entries back to standard format', async () => {
      const entry: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        toolName: 'tool-1',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.1),
          justification: 'Test',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-1',
          riskBreakdown: {
            sensitivity: 0.0,
            exposure: 0,
            trust: 1.0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 0.0,
            finalScore: createRiskScore(0.0),
          },
        },
        taintContexts: [],
        policyVersion: '1.0',
        timestamp: Date.now(),
      };

      await logger.logDecision(entry);

      const logs = await logger.queryLogs({ sessionId: 'session-1' });
      expect(logs).toHaveLength(1);
      expect(logs[0]?.requestId).toBe('req-1');
      expect(logs[0]?.toolName).toBe('tool-1');
    });
  });

  describe('resetChain', () => {
    it('should reset hash chain to genesis', async () => {
      const entry: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        toolName: 'tool-1',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.1),
          justification: 'Test',
          timestamp: new Date(),
          policyVersion: '1.0',
          requestId: 'req-1',
          riskBreakdown: {
            sensitivity: 0.0,
            exposure: 0,
            trust: 1.0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 0.0,
            finalScore: createRiskScore(0.0),
          },
        },
        taintContexts: [],
        policyVersion: '1.0',
        timestamp: Date.now(),
      };

      await logger.logDecision(entry);
      expect(logger.getLastHash()).not.toBe('MCP-SHIELD-GENESIS-001');

      logger.resetChain();
      expect(logger.getLastHash()).toBe('MCP-SHIELD-GENESIS-001');
      expect(logger.getSecureLogs()).toHaveLength(0);
    });
  });
});

