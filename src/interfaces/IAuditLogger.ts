/**
 * TaintGate: IAuditLogger Interface
 * 
 * Audit logging interface for governance transparency and compliance.
 * 
 * All policy decisions, system errors, and governance violations are logged
 * through this interface to ensure full auditability and compliance.
 */

import type { TaintContext } from '../types/common';
import type { PolicyDecision } from '../types/governance';

/**
 * Audit Log Entry
 */
export interface AuditLogEntry {
  /**
   * Unique request identifier for correlation
   */
  requestId: string;
  
  /**
   * Session ID
   */
  sessionId: string;
  
  /**
   * Tenant ID (if multi-tenant)
   */
  tenantId?: string;
  
  /**
   * Policy decision that was made
   */
  decision: PolicyDecision;
  
  /**
   * Taint contexts that influenced the decision
   */
  taintContexts: TaintContext[];
  
  /**
   * Policy version ID that was active
   */
  policyVersion: string;
  
  /**
   * Timestamp of the log entry (ISO 8601)
   */
  timestamp: number;
  
  /**
   * Tool name that was evaluated
   */
  toolName: string;
  
  /**
   * Additional metadata for the log entry
   */
  metadata?: Record<string, unknown>;
}

/**
 * System Error Audit Entry
 * Used when system failures occur (fail-closed scenarios)
 */
export interface SystemErrorAuditEntry {
  /**
   * Unique request identifier
   */
  requestId: string;
  
  /**
   * Session ID
   */
  sessionId: string;
  
  /**
   * Tenant ID (if multi-tenant)
   */
  tenantId?: string;
  
  /**
   * Error that occurred
   */
  error: {
    type: string;
    message: string;
    stack?: string;
  };
  
  /**
   * Component that failed (PEP, PDP, TaintRegistry, etc.)
   */
  failedComponent: string;
  
  /**
   * Action taken (always BLOCK for fail-closed)
   */
  action: 'BLOCK';
  
  /**
   * Timestamp of the error (ISO 8601)
   */
  timestamp: number;
  
  /**
   * Additional context
   */
  context?: Record<string, unknown>;
}

/**
 * IAuditLogger - Audit Logging Interface
 * 
 * Responsibilities:
 * 1. Log all policy decisions for compliance
 * 2. Log system errors with fail-closed actions
 * 3. Support querying audit logs for forensics
 * 4. Ensure immutable, tamper-proof logging
 */
export interface IAuditLogger {
  /**
   * Log a policy decision.
   * 
   * This method logs all policy decisions with full context for
   * compliance, forensics, and auditability.
   * 
   * @param entry - Audit log entry with decision details
   * @returns Promise resolving when log is written
   */
  logDecision(entry: AuditLogEntry): Promise<void>;

  /**
   * Log a system error with fail-closed action.
   * 
   * When system failures occur (timeouts, exceptions, etc.),
   * this method logs the error and the resulting BLOCK decision.
   * 
   * @param entry - System error audit entry
   * @returns Promise resolving when log is written
   */
  logSystemError(entry: SystemErrorAuditEntry): Promise<void>;

  /**
   * Query audit logs by criteria.
   * 
   * @param criteria - Query criteria
   * @returns Promise resolving to matching audit log entries
   */
  queryLogs(criteria: {
    sessionId?: string;
    tenantId?: string;
    toolName?: string;
    startTime?: number;
    endTime?: number;
    action?: 'ALLOW' | 'BLOCK' | 'REDACT';
    limit?: number;
  }): Promise<AuditLogEntry[]>;

  /**
   * Health check for audit logging system.
   * 
   * @returns Promise resolving to true if audit system is healthy
   */
  healthCheck(): Promise<boolean>;
}

