/**
 * TaintGate: Structured Audit Entry Types
 * 
 * Phase 3: Enhanced audit logging for "Major Significance" compliance.
 * 
 * This module defines the structured audit entry schema with:
 * - Version field for schema evolution
 * - Explicit subject and lineage objects
 * - Signature support for immutability
 */

import type { PolicyAction } from './governance';
import type { SensitivityLevel } from './mcp-hints';

/**
 * Structured Audit Entry (v1.0 - Legacy)
 * 
 * @deprecated Use SecureAuditEntry (v1.1) for new implementations.
 * This interface is kept for backward compatibility.
 */
export interface AuditEntry {
  /**
   * Schema version for evolution and compatibility
   */
  version: '1.0';
  
  /**
   * ISO-8601 timestamp of the audit event
   */
  timestamp: string;
  
  /**
   * Unique request identifier for correlation
   */
  requestId: string;
  
  /**
   * Tenant ID for multi-tenant isolation
   */
  tenantId: string;
  
  /**
   * Session ID for session tracking
   */
  sessionId: string;
  
  /**
   * Subject of the audit event (what was evaluated)
   */
  subject: {
    /**
     * Tool name that was evaluated
     */
    toolName: string;
    
    /**
     * Action type that was performed
     */
    action: 'callTool' | 'listTools' | 'resourceRead' | 'unknown';
  };
  
  /**
   * Policy decision that was made
   */
  decision: {
    /**
     * Enforcement action taken
     */
    action: PolicyAction;
    
    /**
     * Human-readable reason for the decision
     */
    reason: string;
    
    /**
     * Calculated risk score [0, 1]
     */
    riskScore: number;
    
    /**
     * Policy version ID that was active
     */
    policyId: string;
  };
  
  /**
   * Lineage provenance data (what data caused this decision)
   * 
   * This is the "Provenance" part that links decisions to their data sources.
   * Only present if taint lineage was detected.
   */
  lineage?: {
    /**
     * Matched tokens/context IDs that triggered the taint
     * These are the context IDs or token hashes that matched during lineage check
     */
    matchedTokens: string[];
    
    /**
     * Origin tools where these tokens were first seen
     * Chronologically sorted by first appearance timestamp
     */
    originTools: string[];
    
    /**
     * Highest sensitivity level detected in the lineage
     */
    sensitivityLevel: SensitivityLevel | number;
    
    /**
     * Whether the lineage contains secrets
     */
    containsSecrets: boolean;
  };
  
  /**
   * HMAC-SHA256 signature for immutability
   * 
   * Computed over all fields except signature itself.
   * Prevents tampering and ensures audit trail integrity.
   * 
   * Format: `hmac-sha256:<hex-signature>`
   */
  signature?: string;
}

/**
 * Secure Audit Entry (v1.1 - Hardened)
 * 
 * Enhanced audit entry schema with production-grade security features:
 * - Deterministic canonicalization for signature consistency
 * - Hash + Type pattern for forensic replay (GDPR compliant)
 * - Hash chain support for sequential immutability
 * - Compact field names for performance
 * - Tenant ID in signature to prevent log swapping
 */
export interface SecureAuditEntry {
  /**
   * Schema version for evolution and compatibility
   */
  v: '1.1';
  
  /**
   * Unix epoch timestamp (milliseconds) for efficient sorting
   */
  ts: number;
  
  /**
   * Request ID for correlation
   */
  rid: string;
  
  /**
   * Tenant ID - included in signature to prevent cross-tenant log swapping
   */
  tid: string;
  
  /**
   * Session ID
   */
  sid: string;
  
  /**
   * Subject of the audit event (what was evaluated)
   */
  sub: {
    /**
     * Tool name that was evaluated
     */
    tool: string;
    
    /**
     * Action type that was performed
     */
    action: 'callTool' | 'listTools' | 'resourceRead' | 'unknown';
  };
  
  /**
   * Policy decision that was made
   */
  decision: {
    /**
     * Enforcement action taken
     */
    act: PolicyAction;
    
    /**
     * Calculated risk score [0, 1]
     */
    score: number;
    
    /**
     * Human-readable reason for the decision
     */
    reason: string;
    
    /**
     * Policy version ID that was active
     */
    policyId: string;
  };
  
  /**
   * Provenance data (what data caused this decision)
   * 
   * The "Life Story" of sensitive data - enables forensic replay.
   * Only present if taint lineage was detected.
   */
  prov?: {
    /**
     * SHA-256 hashes of sensitive data values (not raw data - GDPR compliant)
     * These are the actual data hashes that triggered the taint match
     */
    hashes: string[];
    
    /**
     * Data type hints for forensic analysis
     * Examples: "EMAIL_PATTERN", "SSN_PATTERN", "API_KEY", "CREDIT_CARD", "PHONE_NUMBER"
     * Allows auditors to understand what was detected without storing PII
     */
    types: string[];
    
    /**
     * Origin tools in chronological order (first seen → last seen)
     * Shows the complete data laundering path
     */
    origin: string[];
    
    /**
     * Context ID chain for full provenance path
     * Links all taint contexts that contributed to this decision
     */
    chain: string[];
    
    /**
     * Highest sensitivity level detected in the lineage
     */
    sensitivity: SensitivityLevel | number;
    
    /**
     * Whether the lineage contains secrets
     */
    secrets: boolean;
  };
  
  /**
   * HMAC-SHA256 signature for immutability
   * 
   * Computed over canonicalized entry (excluding this field and prevSig).
   * Format: `v2:hmac-sha256:<keyId>:<hex-signature>` (real HMAC, key-versioned)
   */
  sig?: string;
  
  /**
   * Previous entry signature for hash chain (Sequential Immutability)
   * 
   * This makes the log Sequentially Immutable - if entry #4 is deleted,
   * entry #5's signature will fail because the chain is broken.
   * 
   * This is the "Audit-the-Auditor" strategy for maximum integrity.
   */
  prevSig?: string;
}

/**
 * Structured System Error Audit Entry
 * 
 * Enhanced entry for system failures (fail-closed scenarios) with signature support.
 * This is the structured version of SystemErrorAuditEntry from IAuditLogger.
 */
export interface StructuredSystemErrorAuditEntry {
  /**
   * Schema version
   */
  version: '1.0';
  
  /**
   * ISO-8601 timestamp
   */
  timestamp: string;
  
  /**
   * Unique request identifier
   */
  requestId: string;
  
  /**
   * Tenant ID
   */
  tenantId: string;
  
  /**
   * Session ID
   */
  sessionId: string;
  
  /**
   * Error details
   */
  error: {
    type: string;
    message: string;
    stack?: string;
  };
  
  /**
   * Component that failed
   */
  failedComponent: string;
  
  /**
   * Action taken (always BLOCK for fail-closed)
   */
  action: 'BLOCK';
  
  /**
   * Additional context
   */
  context?: Record<string, unknown>;
  
  /**
   * HMAC-SHA256 signature for immutability
   */
  signature?: string;
}

/**
 * Audit Entry Conversion Helpers
 */
export interface AuditEntryConverter {
  /**
   * Convert AuditLogEntry to structured AuditEntry (v1.0 - legacy)
   */
  toStructuredEntry(entry: import('../interfaces/IAuditLogger').AuditLogEntry): AuditEntry;
  
  /**
   * Convert AuditLogEntry to SecureAuditEntry (v1.1 - hardened)
   * 
   * This is the preferred method for new implementations.
   * Includes hash + type pattern for forensic replay.
   */
  toSecureEntry(entry: import('../interfaces/IAuditLogger').AuditLogEntry): SecureAuditEntry;
  
  /**
   * Convert SystemErrorAuditEntry to structured SystemErrorAuditEntry
   */
  toStructuredErrorEntry(entry: import('../interfaces/IAuditLogger').SystemErrorAuditEntry): StructuredSystemErrorAuditEntry;
}

/**
 * Data Type Patterns for Forensic Analysis
 * 
 * These patterns allow auditors to understand what sensitive data was detected
 * without storing the actual PII/secrets (GDPR compliant).
 */
export enum DataTypePattern {
  EMAIL = 'EMAIL_PATTERN',
  SSN = 'SSN_PATTERN',
  PHONE = 'PHONE_NUMBER',
  CREDIT_CARD = 'CREDIT_CARD',
  API_KEY = 'API_KEY',
  SECRET = 'SECRET',
  PASSWORD = 'PASSWORD',
  IP_ADDRESS = 'IP_ADDRESS',
  UUID = 'UUID',
  CUSTOM = 'CUSTOM',
}

/**
 * Detects data type pattern from a value (without storing the value itself).
 * 
 * @param value - The value to analyze (will be hashed, not stored)
 * @returns Detected data type pattern or null if unknown
 */
export function detectDataTypePattern(value: string): DataTypePattern | null {
  // Email pattern
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    return DataTypePattern.EMAIL;
  }
  
  // SSN pattern (XXX-XX-XXXX)
  if (/^\d{3}-\d{2}-\d{4}$/.test(value)) {
    return DataTypePattern.SSN;
  }
  
  // Phone number (various formats)
  if (/^[\d\s\-()+]{10,}$/.test(value.replace(/\s/g, ''))) {
    return DataTypePattern.PHONE;
  }
  
  // Credit card (Luhn algorithm check would be ideal, but regex for now)
  if (/^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$/.test(value)) {
    return DataTypePattern.CREDIT_CARD;
  }
  
  // UUID
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    return DataTypePattern.UUID;
  }
  
  // IP address
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
    return DataTypePattern.IP_ADDRESS;
  }
  
  // API key pattern (long alphanumeric strings)
  if (/^[A-Za-z0-9]{32,}$/.test(value)) {
    return DataTypePattern.API_KEY;
  }
  
  return null;
}

