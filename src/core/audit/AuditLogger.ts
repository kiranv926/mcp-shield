/**
 * MCP-Shield: Base AuditLogger Implementation
 * 
 * Simple audit logging implementation that handles basic log transport.
 * This is the "dumb" logger that doesn't care about log security itself.
 * 
 * For production-grade security with hash chaining and non-repudiation,
 * use SecureAuditLogger instead.
 * 
 * @see SecureAuditLogger - Hardened implementation with hash chain
 * @see ARCHITECTURE.md - Audit Logging
 */

import type { IAuditLogger, AuditLogEntry, SystemErrorAuditEntry } from '../../interfaces/IAuditLogger';
import { createRiskScore } from '../../types/common';
import { promises as fs } from 'fs';
import { join } from 'path';

/**
 * AuditLogger - Base Implementation
 * 
 * Simple file-based audit logger that writes JSON log entries.
 * This implementation:
 * - Writes logs to JSONL (JSON Lines) files
 * - Provides basic query functionality
 * - Does NOT include hash chaining or integrity verification
 * 
 * For production security requirements, use SecureAuditLogger.
 */
export class AuditLogger implements IAuditLogger {
  /**
   * Audit log file path
   */
  protected logFilePath: string;

  /**
   * In-memory log cache (for queryLogs)
   * 
   * In production, this would be backed by a database or distributed cache
   */
  protected logCache: AuditLogEntry[] = [];

  /**
   * Constructor
   * 
   * @param options - Configuration options
   */
  constructor(options: {
    logDirectory?: string;
  } = {}) {
    const logDir = options.logDirectory || './logs';
    this.logFilePath = join(logDir, `audit-${new Date().toISOString().split('T')[0]}.jsonl`);

    // Ensure log directory exists
    this.ensureLogDirectory(logDir).catch(err => {
      console.error('Failed to create log directory:', err);
    });
  }

  /**
   * Ensure log directory exists
   */
  protected async ensureLogDirectory(dir: string): Promise<void> {
    try {
      await fs.mkdir(dir, { recursive: true });
    } catch (error) {
      // Directory might already exist, ignore error
      if (error && typeof error === 'object' && 'code' in error && error.code !== 'EEXIST') {
        throw error;
      }
    }
  }

  /**
   * Log a governance decision
   * 
   * @param entry - Audit log entry to record
   */
  async logDecision(entry: AuditLogEntry): Promise<void> {
    try {
      // Ensure log directory exists before writing
      const logDir = this.logFilePath.substring(0, this.logFilePath.lastIndexOf('/'));
      await this.ensureLogDirectory(logDir);

      // Persist to file (append-only)
      const logLine = JSON.stringify(entry) + '\n';
      await fs.appendFile(this.logFilePath, logLine, 'utf-8');

      // Update in-memory cache
      this.logCache.push(entry);
    } catch (error) {
      // Base logger: Fail-open (log error but don't block)
      console.error('Audit logging failed:', error);
    }
  }

  /**
   * Log a system error
   * 
   * @param entry - System error audit entry
   */
  async logSystemError(entry: SystemErrorAuditEntry): Promise<void> {
    try {
      // Convert to standard audit entry format for consistency
      const auditEntry: AuditLogEntry = {
        requestId: entry.requestId,
        sessionId: entry.sessionId,
        tenantId: entry.tenantId,
        toolName: entry.context?.toolName as string || 'system',
        decision: {
          action: entry.action,
          riskScore: createRiskScore(1.0), // System errors are high risk
          justification: `System error: ${entry.error.message}`,
          timestamp: new Date(entry.timestamp),
          policyVersion: 'system-error',
          requestId: entry.requestId,
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
        policyVersion: 'system-error',
        timestamp: typeof entry.timestamp === 'number' ? entry.timestamp : new Date(entry.timestamp).getTime(),
        metadata: {
          failedComponent: entry.failedComponent,
          errorType: entry.error.type,
        },
      };

      await this.logDecision(auditEntry);
    } catch (error) {
      // Base logger: Fail-open (log error but don't block)
      console.error('System error logging failed:', error);
    }
  }

  /**
   * Query audit logs
   * 
   * @param query - Query parameters
   * @returns Array of audit log entries
   */
  async queryLogs(query: {
    sessionId?: string;
    tenantId?: string;
    limit?: number;
  }): Promise<AuditLogEntry[]> {
    // Filter in-memory cache
    let filtered = this.logCache.filter(log => {
      if (query.sessionId && log.sessionId !== query.sessionId) return false;
      if (query.tenantId && log.tenantId !== query.tenantId) return false;
      return true;
    });

    // Apply limit
    if (query.limit) {
      filtered = filtered.slice(0, query.limit);
    }

    return filtered;
  }

  /**
   * Health check
   * 
   * @returns true if logger is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Verify we can write to log file
      await fs.access(this.logFilePath);
      return true;
    } catch {
      // File doesn't exist yet, try to create directory
      try {
        const logDir = this.logFilePath.substring(0, this.logFilePath.lastIndexOf('/'));
        await this.ensureLogDirectory(logDir);
        return true;
      } catch {
        return false;
      }
    }
  }

  /**
   * Clear log cache (for testing only)
   * 
   * WARNING: This should never be called in production.
   */
  clearCache(): void {
    this.logCache = [];
  }
}
