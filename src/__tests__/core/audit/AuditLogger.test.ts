/**
 * MCP-Shield: AuditLogger Unit Tests
 * 
 * Tests for the base AuditLogger implementation (simple logging without security features).
 */

import { AuditLogger } from '../../../core/audit/AuditLogger';
import type { AuditLogEntry, SystemErrorAuditEntry } from '../../../interfaces/IAuditLogger';
import { createRiskScore } from '../../../types/common';
import { promises as fs } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('AuditLogger', () => {
  let logger: AuditLogger;
  let logDir: string;

  beforeEach(() => {
    logDir = join(tmpdir(), `mcp-shield-test-${Date.now()}`);
    logger = new AuditLogger({ logDirectory: logDir });
  });

  afterEach(async () => {
    // Cleanup: Remove test log files
    try {
      await fs.rm(logDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('logDecision', () => {
    it('should log a decision entry to file', async () => {
      const entry: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        toolName: 'test-tool',
        decision: {
          action: 'ALLOW',
          riskScore: createRiskScore(0.1),
          justification: 'Low risk',
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

      // Verify log file exists
      const logFiles = await fs.readdir(logDir);
      expect(logFiles.length).toBeGreaterThan(0);

      // Verify log content
      const logFile = logFiles.find(f => f.startsWith('audit-'));
      expect(logFile).toBeDefined();
      
      const logContent = await fs.readFile(join(logDir, logFile!), 'utf-8');
      const logEntry = JSON.parse(logContent.trim());
      expect(logEntry.requestId).toBe('req-1');
      expect(logEntry.toolName).toBe('test-tool');
    });

    it('should handle logging errors gracefully (fail-open)', async () => {
      // Mock console.error to suppress expected error messages
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {
        // Suppress expected error output
      });

      try {
        // Create logger with invalid directory to force error
        const invalidLogger = new AuditLogger({ logDirectory: '/invalid/path/that/does/not/exist' });
        
        // Allow constructor's async error handling to complete
        await new Promise(resolve => setTimeout(resolve, 10));
        
        const entry: AuditLogEntry = {
          requestId: 'req-1',
          sessionId: 'session-1',
          toolName: 'test-tool',
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

        // Should not throw (fail-open behavior)
        await expect(invalidLogger.logDecision(entry)).resolves.not.toThrow();
      } finally {
        consoleErrorSpy.mockRestore();
      }
    });
  });

  describe('logSystemError', () => {
    it('should log system errors', async () => {
      const errorEntry: SystemErrorAuditEntry = {
        requestId: 'req-error-1',
        sessionId: 'session-1',
        tenantId: 'tenant-1',
        error: {
          type: 'TimeoutError',
          message: 'Request timeout',
        },
        failedComponent: 'TaintRegistry',
        action: 'BLOCK',
        timestamp: Date.now(),
      };

      await logger.logSystemError(errorEntry);

      // Verify log was written
      const logFiles = await fs.readdir(logDir);
      expect(logFiles.length).toBeGreaterThan(0);
    });
  });

  describe('queryLogs', () => {
    it('should query logs by sessionId', async () => {
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

      const entry2: AuditLogEntry = {
        ...entry1,
        requestId: 'req-2',
        sessionId: 'session-2',
      };

      await logger.logDecision(entry1);
      await logger.logDecision(entry2);

      const logs = await logger.queryLogs({ sessionId: 'session-1' });
      // The cache should have both entries, filtered by sessionId
      expect(logs.length).toBe(1);
      expect(logs[0]?.sessionId).toBe('session-1');
      expect(logs[0]?.requestId).toBe('req-1');
    });

    it('should query logs by tenantId', async () => {
      const entry1: AuditLogEntry = {
        requestId: 'req-1',
        sessionId: 'session-1',
        tenantId: 'tenant-A',
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

      const entry2: AuditLogEntry = {
        ...entry1,
        requestId: 'req-2',
        tenantId: 'tenant-B',
      };

      await logger.logDecision(entry1);
      await logger.logDecision(entry2);

      const logs = await logger.queryLogs({ tenantId: 'tenant-A' });
      expect(logs.length).toBe(1);
      expect(logs[0]?.tenantId).toBe('tenant-A');
      expect(logs[0]?.requestId).toBe('req-1');
    });

    it('should respect limit parameter', async () => {
      for (let i = 0; i < 5; i++) {
        const entry: AuditLogEntry = {
          requestId: `req-${i}`,
          sessionId: 'session-1',
          toolName: 'tool-1',
          decision: {
            action: 'ALLOW',
            riskScore: createRiskScore(0.1),
            justification: 'Test',
            timestamp: new Date(),
            policyVersion: '1.0',
            requestId: `req-${i}`,
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
      }

      const logs = await logger.queryLogs({ limit: 2 });
      expect(logs).toHaveLength(2);
    });
  });

  describe('healthCheck', () => {
    it('should return true when logger is healthy', async () => {
      const healthy = await logger.healthCheck();
      expect(healthy).toBe(true);
    });
  });
});

