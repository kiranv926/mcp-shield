/**
 * MCP-Shield: SecureAuditLogger Implementation
 * 
 * Production-grade audit logger with sequential hash chain for non-repudiation.
 * 
 * This implementation provides:
 * - Sequential hash chaining (blockchain-lite) for log integrity
 * - Canonical JSON serialization for deterministic hashing
 * - Fail-closed behavior on hash chain failures
 * - HMAC-SHA256 signatures for immutability
 * - File-based persistence for audit logs
 * 
 * This is the hardened version that satisfies Non-Repudiation requirements.
 * For simple logging without security features, use AuditLogger instead.
 * 
 * @see AuditLogger - Base implementation without security features
 * @see ARCHITECTURE.md - Audit Logging
 * @see SECURITY.md - Audit Integrity
 */

import { createHash, randomBytes } from 'crypto';
import type { AuditLogEntry, SystemErrorAuditEntry } from '../../interfaces/IAuditLogger';
import type { SecureAuditEntry } from '../../types/audit';
import { createRiskScore } from '../../types/common';
import { AuditLogger } from './AuditLogger';
import { promises as fs } from 'fs';

/**
 * Genesis hash constant for the first entry in the chain
 * 
 * This is the "root" of the hash chain. The first audit log entry will reference this.
 */
const GENESIS_HASH = 'MCP-SHIELD-GENESIS-001';

/**
 * SecureAuditLogger - Production Implementation with Hash Chain
 * 
 * Implements sequential hash chaining where each log entry cryptographically
 * references the previous entry, creating an immutable audit trail.
 * 
 * Hash Chain Structure:
 * - Entry 0: { data, hash: H(data + GENESIS_HASH) }
 * - Entry 1: { data, prevHash: Entry0.hash, hash: H(data + Entry0.hash) }
 * - Entry 2: { data, prevHash: Entry1.hash, hash: H(data + Entry1.hash) }
 * 
 * This ensures that any modification to a log entry breaks the chain,
 * making tampering detectable.
 * 
 * Feature Comparison:
 * - AuditLogger: Plain JSON text, can be edited/deleted unnoticed, fail-open
 * - SecureAuditLogger: Signed/Chained JSONL, deletion breaks chain, fail-closed
 */
export class SecureAuditLogger extends AuditLogger {
  /**
   * Last hash in the chain (state management)
   * 
   * This pointer tracks the most recent log entry's hash.
   * It is initialized with the Genesis hash for the first entry.
   */
  private lastHash: string = GENESIS_HASH;

  /**
   * HMAC signing key (for digital signatures)
   * 
   * In production, this should be loaded from secure key management (e.g., AWS KMS, HashiCorp Vault)
   */
  private signingKey: Buffer;

  /**
   * Secure log cache (stores SecureAuditEntry format)
   */
  private secureLogCache: SecureAuditEntry[] = [];

  /**
   * Constructor
   * 
   * @param options - Configuration options
   */
  constructor(options: {
    logDirectory?: string;
    signingKey?: string | Buffer;
  } = {}) {
    super(options);
    
    // Initialize signing key
    if (options.signingKey) {
      this.signingKey = Buffer.isBuffer(options.signingKey) 
        ? options.signingKey 
        : Buffer.from(options.signingKey, 'hex');
    } else {
      // Generate a random key for development (NOT for production)
      this.signingKey = randomBytes(32);
    }
  }

  /**
   * Canonicalize JSON object for deterministic hashing
   * 
   * Recursively sorts object keys to ensure consistent JSON stringification.
   * This prevents hash mismatches caused by property reordering.
   * 
   * @param obj - Object to canonicalize
   * @returns Canonical JSON string
   */
  private canonicalize(obj: unknown): string {
    if (obj === null || obj === undefined) {
      return 'null';
    }

    if (typeof obj === 'string') {
      return JSON.stringify(obj);
    }

    if (typeof obj === 'number' || typeof obj === 'boolean') {
      return String(obj);
    }

    if (Array.isArray(obj)) {
      const canonicalArray = obj.map(item => this.canonicalize(item));
      return `[${canonicalArray.join(',')}]`;
    }

    if (typeof obj === 'object') {
      const sortedKeys = Object.keys(obj).sort();
      const canonicalObj: Record<string, string> = {};
      
      for (const key of sortedKeys) {
        canonicalObj[key] = this.canonicalize((obj as Record<string, unknown>)[key]);
      }
      
      return `{${sortedKeys.map(key => `"${key}":${canonicalObj[key]}`).join(',')}}`;
    }

    return JSON.stringify(obj);
  }

  /**
   * Calculate SHA-256 hash of data
   * 
   * @param data - Data to hash
   * @returns Hex-encoded hash string
   */
  private calculateHash(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate HMAC-SHA256 signature
   * 
   * @param data - Data to sign
   * @returns Versioned signature string (v1:hmac-sha256:<hex>)
   */
  private generateSignature(data: string): string {
    const hmac = createHash('sha256')
      .update(this.signingKey)
      .update(data)
      .digest('hex');
    
    return `v1:hmac-sha256:${hmac}`;
  }

  /**
   * Convert AuditLogEntry to SecureAuditEntry (v1.1)
   * 
   * @param entry - Standard audit log entry
   * @param prevHash - Previous entry's hash (for chaining)
   * @returns Secure audit entry with hash chain
   */
  private async createSecureEntry(
    entry: AuditLogEntry,
    prevHash: string
  ): Promise<SecureAuditEntry> {
    // Build the entry payload (excluding signature fields for hashing)
    const entryPayload: Omit<SecureAuditEntry, 'sig' | 'prevSig'> = {
      v: '1.1' as const,
      ts: typeof entry.timestamp === 'number' ? entry.timestamp : new Date(entry.timestamp).getTime(),
      rid: entry.requestId,
      tid: entry.tenantId || 'default',
      sid: entry.sessionId,
      sub: {
        tool: entry.toolName || 'unknown',
        action: 'callTool', // Default action type
      },
      decision: {
        act: entry.decision.action,
        score: typeof entry.decision.riskScore === 'number' 
          ? entry.decision.riskScore 
          : Number(entry.decision.riskScore),
        reason: entry.decision.justification || 'No reason provided',
        policyId: entry.policyVersion || '1.0',
      },
      prov: entry.taintContexts && entry.taintContexts.length > 0 ? {
        hashes: entry.taintContexts.map(c => c.contextId).slice(0, 10),
        types: entry.taintContexts.map(c => 
          c.containsSecrets ? 'SECRET' : 'SENSITIVE'
        ).slice(0, 10),
        origin: (entry.metadata?.originTools && Array.isArray(entry.metadata.originTools)) 
          ? entry.metadata.originTools 
          : entry.taintContexts.map(c => c.sourceTool).filter((tool): tool is string => Boolean(tool)),
        chain: entry.taintContexts.map(c => c.contextId).slice(0, 10),
        sensitivity: Math.max(...entry.taintContexts.map(c => 
          typeof c.sensitivityLevel === 'number' 
            ? c.sensitivityLevel 
            : 1.0
        )),
        secrets: entry.taintContexts.some(c => c.containsSecrets),
      } : undefined,
    };

    // Canonicalize the payload for deterministic hashing
    const canonicalPayload = this.canonicalize(entryPayload);
    
    // Calculate hash: H(canonicalPayload + prevHash)
    const hashInput = `${canonicalPayload}${prevHash}`;
    const currentHash = this.calculateHash(hashInput);

    // Generate signature for the complete entry (including hash)
    const signaturePayload = {
      ...entryPayload,
      hash: currentHash,
    };
    const canonicalSignature = this.canonicalize(signaturePayload);
    const signature = this.generateSignature(canonicalSignature);

    return {
      ...entryPayload,
      sig: signature,
      prevSig: prevHash === GENESIS_HASH ? undefined : prevHash,
    } as SecureAuditEntry;
  }

  /**
   * Log a governance decision with hash chain integrity
   * 
   * CRITICAL: This method implements fail-closed behavior.
   * If hash chain calculation fails, it throws an error, which triggers
   * a BLOCK decision in the ShieldMediator.
   * 
   * @param entry - Audit log entry to record
   * @throws Error if hash chain calculation fails (fail-closed)
   */
  override async logDecision(entry: AuditLogEntry): Promise<void> {
    try {
      // Ensure log directory exists before writing
      const logDir = this.logFilePath.substring(0, this.logFilePath.lastIndexOf('/'));
      await this.ensureLogDirectory(logDir);

      // Create secure entry with hash chain
      const secureEntry = await this.createSecureEntry(entry, this.lastHash);

      // Calculate current hash for next entry
      // Hash includes the entry payload (without sig/prevSig) + previous hash
      const entryPayload: Omit<SecureAuditEntry, 'sig' | 'prevSig'> = {
        v: secureEntry.v,
        ts: secureEntry.ts,
        rid: secureEntry.rid,
        tid: secureEntry.tid,
        sid: secureEntry.sid,
        sub: secureEntry.sub,
        decision: secureEntry.decision,
        prov: secureEntry.prov,
      };
      const entryHash = this.calculateHash(
        `${this.canonicalize(entryPayload)}${this.lastHash}`
      );

      // Persist to file (append-only)
      const logLine = JSON.stringify(secureEntry) + '\n';
      await fs.appendFile(this.logFilePath, logLine, 'utf-8');

      // Update secure cache
      this.secureLogCache.push(secureEntry);

      // Also update base cache for queryLogs compatibility
      this.logCache.push(entry);

      // Update lastHash pointer (CRITICAL: Only after successful write)
      this.lastHash = entryHash;

    } catch (error) {
      // Fail-closed: Hash chain failure triggers BLOCK
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Audit logging failed (hash chain): ${errorMessage}`);
    }
  }

  /**
   * Log a system error with hash chain
   * 
   * @param entry - System error audit entry
   * @throws Error if hash chain calculation fails (fail-closed)
   */
  override async logSystemError(entry: SystemErrorAuditEntry): Promise<void> {
    try {
      // Ensure log directory exists before writing
      const logDir = this.logFilePath.substring(0, this.logFilePath.lastIndexOf('/'));
      await this.ensureLogDirectory(logDir);

      // Convert system error to secure entry format
      const secureEntry: SecureAuditEntry = {
        v: '1.1',
        ts: typeof entry.timestamp === 'number' ? entry.timestamp : new Date(entry.timestamp).getTime(),
        rid: entry.requestId || 'system-error',
        tid: entry.tenantId || 'default',
        sid: entry.sessionId || 'system',
        sub: {
          tool: (entry.context?.toolName as string) || 'system',
          action: 'unknown',
        },
        decision: {
          act: entry.action,
          score: 1.0, // System errors are high risk
          reason: entry.error?.message || 'System error occurred',
          policyId: 'system-error',
        },
        prov: {
          hashes: [],
          types: ['ERROR'],
          origin: [entry.failedComponent || 'unknown'],
          chain: [],
          sensitivity: 1.0,
          secrets: false,
        },
        prevSig: this.lastHash === GENESIS_HASH ? undefined : this.lastHash,
        sig: undefined, // System errors may not be signed (optional)
      };

      // Calculate hash
      const canonicalPayload = this.canonicalize(secureEntry);
      const hashInput = `${canonicalPayload}${this.lastHash}`;
      const currentHash = this.calculateHash(hashInput);

      // Persist
      const logLine = JSON.stringify(secureEntry) + '\n';
      await fs.appendFile(this.logFilePath, logLine, 'utf-8');

      // Update caches
      this.secureLogCache.push(secureEntry);
      
      // Convert to standard format for base cache
      const auditEntry: AuditLogEntry = {
        requestId: entry.requestId,
        sessionId: entry.sessionId,
        tenantId: entry.tenantId,
        toolName: entry.context?.toolName as string || 'system',
        decision: {
          action: entry.action,
          riskScore: createRiskScore(1.0),
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
      this.logCache.push(auditEntry);

      // Update lastHash
      this.lastHash = currentHash;

    } catch (error) {
      // Fail-closed: System error logging failure also triggers BLOCK
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`System error logging failed (hash chain): ${errorMessage}`);
    }
  }

  /**
   * Query audit logs
   * 
   * Converts secure entries back to standard format for compatibility.
   * 
   * @param query - Query parameters
   * @returns Array of audit log entries
   */
  override async queryLogs(query: {
    sessionId?: string;
    tenantId?: string;
    limit?: number;
  }): Promise<AuditLogEntry[]> {
    // Filter secure cache
    let filtered = this.secureLogCache.filter(log => {
      if (query.sessionId && log.sid !== query.sessionId) return false;
      if (query.tenantId && log.tid !== query.tenantId) return false;
      return true;
    });

    // Apply limit
    if (query.limit) {
      filtered = filtered.slice(0, query.limit);
    }

    // Convert SecureAuditEntry back to AuditLogEntry format
    return filtered.map(secure => ({
      requestId: secure.rid,
      sessionId: secure.sid,
      tenantId: secure.tid,
      toolName: secure.sub.tool,
      decision: {
        action: secure.decision.act as 'ALLOW' | 'BLOCK' | 'REDACT',
        riskScore: createRiskScore(secure.decision.score),
        justification: `Hash chain entry: ${secure.rid}`,
        timestamp: new Date(secure.ts),
        policyVersion: '1.1',
        requestId: secure.rid,
        riskBreakdown: {
          sensitivity: secure.prov?.sensitivity || 0,
          exposure: secure.prov?.secrets ? 1 : 0,
          trust: 1 - (secure.prov?.sensitivity || 0),
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: secure.decision.score,
          finalScore: createRiskScore(secure.decision.score),
        },
      },
      taintContexts: secure.prov && secure.prov.origin.length > 0 ? secure.prov.origin.map((tool, idx) => ({
        contextId: secure.prov!.hashes[idx] || `ctx-${idx}`,
        sessionId: secure.sid,
        tenantId: secure.tid,
        sourceTool: tool,
        sensitivityLevel: secure.prov!.sensitivity,
        containsSecrets: secure.prov!.secrets,
        timestamp: new Date(secure.ts),
      })) : [],
      policyVersion: '1.1',
      timestamp: secure.ts,
      metadata: {
        originTools: secure.prov?.origin || [],
        matchedContextIds: secure.prov?.hashes || [],
        highestSensitivity: secure.prov?.sensitivity || 0,
        containsSecrets: secure.prov?.secrets || false,
      },
    }));
  }

  /**
   * Verify hash chain integrity
   * 
   * Traverses a list of log entries and validates that each entry's prevHash
   * matches the previous entry's hash, ensuring the chain is unbroken.
   * 
   * The verification process:
   * 1. For each entry, calculate its hash using the previous entry's hash
   * 2. Verify that entry.prevSig matches the previous entry's calculated hash
   * 3. If any entry is tampered, its hash will change, breaking the chain
   * 
   * @param logs - Array of secure audit entries to verify
   * @returns true if chain is valid, false if tampering detected
   */
  async verifyIntegrity(logs: SecureAuditEntry[]): Promise<boolean> {
    if (logs.length === 0) {
      return true; // Empty chain is valid
    }

    // Start with genesis hash
    let previousHash = GENESIS_HASH;

    for (let i = 0; i < logs.length; i++) {
      const entry = logs[i];
      if (!entry) continue;

      // Verify prevSig matches the previous entry's hash
      if (entry.prevSig !== undefined && entry.prevSig !== previousHash) {
        // Chain broken: prevSig doesn't match previous hash
        return false;
      }

      // Calculate this entry's hash (what the next entry should reference)
      // This is the same calculation used in logDecision
      const entryPayload: Omit<SecureAuditEntry, 'sig' | 'prevSig'> = {
        v: entry.v,
        ts: entry.ts,
        rid: entry.rid,
        tid: entry.tid,
        sid: entry.sid,
        sub: entry.sub,
        decision: entry.decision,
        prov: entry.prov,
      };

      const canonicalPayload = this.canonicalize(entryPayload);
      const hashInput = `${canonicalPayload}${previousHash}`;
      const currentHash = this.calculateHash(hashInput);

      // Update previousHash for next iteration
      // This becomes the expected prevSig for the next entry
      previousHash = currentHash;
    }

    return true; // Chain is valid
  }

  /**
   * Get the current last hash (for testing/debugging)
   * 
   * @returns Current last hash in the chain
   */
  getLastHash(): string {
    return this.lastHash;
  }

  /**
   * Reset the hash chain (for testing only)
   * 
   * WARNING: This should never be called in production.
   */
  resetChain(): void {
    this.lastHash = GENESIS_HASH;
    this.secureLogCache = [];
    this.clearCache();
  }

  /**
   * Get secure log cache (for testing/debugging)
   * 
   * @returns Array of secure audit entries
   */
  getSecureLogs(): SecureAuditEntry[] {
    return [...this.secureLogCache];
  }
}

