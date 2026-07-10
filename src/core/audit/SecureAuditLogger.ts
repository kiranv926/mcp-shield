/**
 * TaintGate: SecureAuditLogger Implementation
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

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import type { AuditLogEntry, SystemErrorAuditEntry } from '../../interfaces/IAuditLogger';
import type { SecureAuditEntry } from '../../types/audit';
import { createRiskScore } from '../../types/common';
import { AuditLogger } from './AuditLogger';
import { promises as fs } from 'fs';

/**
 * Signature construction version tag.
 *
 * `v2` denotes a real HMAC-SHA256 over the canonical payload (replacing the
 * earlier `v1` tag which mislabelled a plain SHA-256 of key‖data as an HMAC).
 * Format of a signature string: `v2:hmac-sha256:<keyId>:<hex-mac>`.
 */
const SIGNATURE_VERSION = 'v2';

/**
 * Reason codes explaining why integrity verification failed.
 */
export type IntegrityFailureReason =
  | 'CHAIN_BROKEN'
  | 'SIGNATURE_MISSING'
  | 'SIGNATURE_MISMATCH';

/**
 * Structured result of {@link SecureAuditLogger.verifyIntegrity}.
 *
 * Verification passes only when BOTH the HMAC signature of every entry is
 * valid AND the hash-chain linkage is intact. On failure, the offending
 * entry is identified.
 */
export interface IntegrityVerificationResult {
  /** True only if every entry passed both signature and chain checks. */
  valid: boolean;
  /** Number of entries that were verified (or attempted). */
  entryCount: number;
  /** Index of the first failing entry, if any. */
  failedIndex?: number;
  /** Request ID of the first failing entry, if any. */
  failedRequestId?: string;
  /** Machine-readable reason for the failure, if any. */
  reason?: IntegrityFailureReason;
  /** Human-readable description of the failure, if any. */
  message?: string;
}

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
   * Key identifier (fingerprint) embedded in each signature.
   *
   * A short, non-secret fingerprint of the signing key. It lets a verifier
   * detect that a signature was produced with a different key (key rotation /
   * wrong key) without revealing the key material itself.
   */
  private keyId: string;

  /**
   * Secure log cache (stores SecureAuditEntry format).
   *
   * Bounded via the inherited {@link maxCacheEntries} (ring-buffer behavior).
   * Trimming this cache never affects the persisted chain: the rolling
   * {@link lastHash} is retained independently of the cache contents.
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
    maxCacheEntries?: number;
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

    // Derive a stable, non-secret key fingerprint for signature attribution.
    this.keyId = createHash('sha256').update(this.signingKey).digest('hex').slice(0, 16);
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
   * Build the canonical, hash/signature-covered payload for an entry.
   *
   * This is the SINGLE canonical form used for BOTH chaining and verification.
   * It deliberately EXCLUDES the volatile `sig` and `prevSig` fields so that
   * the same bytes are produced when an entry is created, when the chain hash
   * is advanced, and when integrity is later verified. (Previously
   * logSystemError canonicalized the whole entry including prevSig/sig, which
   * broke verification of every subsequent entry.)
   *
   * @param entry - A secure entry (or entry payload) to canonicalize
   * @returns Canonical JSON string over the stable fields only
   */
  private canonicalPayload(
    entry: Omit<SecureAuditEntry, 'sig' | 'prevSig'> | SecureAuditEntry
  ): string {
    const payload: Omit<SecureAuditEntry, 'sig' | 'prevSig'> = {
      v: entry.v,
      ts: entry.ts,
      rid: entry.rid,
      tid: entry.tid,
      sid: entry.sid,
      sub: entry.sub,
      decision: entry.decision,
      prov: entry.prov,
    };
    return this.canonicalize(payload);
  }

  /**
   * Compute the chain hash for an entry: H(canonicalPayload ‖ prevHash).
   *
   * @param canonicalPayload - Canonical payload string (excludes sig/prevSig)
   * @param prevHash - Previous entry's chain hash
   * @returns Hex-encoded chain hash
   */
  private computeChainHash(canonicalPayload: string, prevHash: string): string {
    return this.calculateHash(`${canonicalPayload}${prevHash}`);
  }

  /**
   * Generate a REAL HMAC-SHA256 signature over the canonical payload and its
   * chain hash.
   *
   * Uses `crypto.createHmac('sha256', key)` — a proper keyed MAC that is NOT
   * length-extension vulnerable (unlike the previous `H(key‖data)`
   * construction that was mislabelled as an HMAC). The chain hash is bound
   * into the signed input so a signature also attests to the entry's position
   * in the chain.
   *
   * @param canonicalPayload - Canonical payload string (excludes sig/prevSig)
   * @param chainHash - The entry's chain hash
   * @returns Versioned signature string: `v2:hmac-sha256:<keyId>:<hex-mac>`
   */
  private generateSignature(canonicalPayload: string, chainHash: string): string {
    const mac = createHmac('sha256', this.signingKey)
      .update(canonicalPayload)
      .update('|')
      .update(chainHash)
      .digest('hex');

    return `${SIGNATURE_VERSION}:hmac-sha256:${this.keyId}:${mac}`;
  }

  /**
   * Constant-time comparison of two signature strings.
   *
   * Length is not secret, so an early length check is acceptable; the MAC
   * bytes themselves are compared with `timingSafeEqual` to avoid leaking
   * information via timing.
   *
   * @param a - First signature string
   * @param b - Second signature string
   * @returns true if the signatures are byte-for-byte equal
   */
  private signaturesEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) {
      return false;
    }
    return timingSafeEqual(bufA, bufB);
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

    // Canonicalize the payload for deterministic hashing (excludes sig/prevSig).
    const canonicalPayload = this.canonicalPayload(entryPayload);

    // Calculate chain hash: H(canonicalPayload + prevHash)
    const currentHash = this.computeChainHash(canonicalPayload, prevHash);

    // Generate a real HMAC signature bound to the payload and chain hash.
    const signature = this.generateSignature(canonicalPayload, currentHash);

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
   * a BLOCK decision in the TaintGate.
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

      // Advance the chain using the SAME canonical form used for signing and
      // verification (excludes sig/prevSig).
      const entryHash = this.computeChainHash(
        this.canonicalPayload(secureEntry),
        this.lastHash
      );

      // Persist to file (append-only)
      const logLine = JSON.stringify(secureEntry) + '\n';
      await fs.appendFile(this.logFilePath, logLine, 'utf-8');

      // Update caches (bounded ring-buffer; does not affect the chain state)
      this.secureLogCache.push(secureEntry);
      this.logCache.push(entry);
      this.enforceSecureCacheBound();
      this.enforceCacheBound();

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

      // Build the stable entry payload (excludes sig/prevSig).
      const entryPayload: Omit<SecureAuditEntry, 'sig' | 'prevSig'> = {
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
      };

      // Calculate chain hash using the SAME canonical form as logDecision and
      // verifyIntegrity (excludes sig/prevSig). Previously this canonicalized
      // the whole entry (including prevSig), which desynchronized the chain and
      // broke verification of every subsequent entry.
      const canonicalPayload = this.canonicalPayload(entryPayload);
      const currentHash = this.computeChainHash(canonicalPayload, this.lastHash);

      // Sign system-error entries too, so verifyIntegrity can check every entry
      // uniformly.
      const secureEntry: SecureAuditEntry = {
        ...entryPayload,
        sig: this.generateSignature(canonicalPayload, currentHash),
        prevSig: this.lastHash === GENESIS_HASH ? undefined : this.lastHash,
      };

      // Persist
      const logLine = JSON.stringify(secureEntry) + '\n';
      await fs.appendFile(this.logFilePath, logLine, 'utf-8');

      // Update caches (bounded)
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
      this.enforceSecureCacheBound();
      this.enforceCacheBound();

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
   * Verify audit-trail integrity (signatures AND hash chain).
   *
   * Verification fails if EITHER check fails for any entry:
   *
   * 1. HMAC signature: the stored `sig` is recomputed with the signing key and
   *    compared in constant time (`crypto.timingSafeEqual`). This is the check
   *    that makes forgery hard: previously the signature was never verified, so
   *    anyone able to rewrite the log could recompute the plaintext hash chain
   *    and forge a "valid" trail.
   * 2. Hash-chain linkage: each entry's `prevSig` must equal the previous
   *    entry's recomputed chain hash, so deleting or reordering entries is
   *    detected.
   *
   * The `logs` argument is verified independently of the in-memory cache, so a
   * bounded/trimmed cache does not affect verification of the persisted logs
   * (pass the full set read back from disk).
   *
   * @param logs - Array of secure audit entries to verify (chain order)
   * @returns Structured result indicating validity and, on failure, which
   *          entry failed and why
   */
  async verifyIntegrity(logs: SecureAuditEntry[]): Promise<IntegrityVerificationResult> {
    if (logs.length === 0) {
      return { valid: true, entryCount: 0 }; // Empty chain is valid
    }

    // Start with genesis hash
    let previousHash = GENESIS_HASH;

    for (let i = 0; i < logs.length; i++) {
      const entry = logs[i];
      if (!entry) continue;

      // (b) Verify chain linkage: prevSig must reference the previous hash.
      if (entry.prevSig !== undefined && entry.prevSig !== previousHash) {
        return {
          valid: false,
          entryCount: logs.length,
          failedIndex: i,
          failedRequestId: entry.rid,
          reason: 'CHAIN_BROKEN',
          message: `Entry ${i} (rid=${entry.rid}) prevSig does not match the previous entry's hash (broken/reordered/deleted chain).`,
        };
      }

      // Recompute this entry's canonical payload and chain hash.
      const canonicalPayload = this.canonicalPayload(entry);
      const currentHash = this.computeChainHash(canonicalPayload, previousHash);

      // (a) Verify the HMAC signature (constant-time compare).
      if (entry.sig === undefined) {
        return {
          valid: false,
          entryCount: logs.length,
          failedIndex: i,
          failedRequestId: entry.rid,
          reason: 'SIGNATURE_MISSING',
          message: `Entry ${i} (rid=${entry.rid}) has no signature.`,
        };
      }

      const expectedSig = this.generateSignature(canonicalPayload, currentHash);
      if (!this.signaturesEqual(entry.sig, expectedSig)) {
        return {
          valid: false,
          entryCount: logs.length,
          failedIndex: i,
          failedRequestId: entry.rid,
          reason: 'SIGNATURE_MISMATCH',
          message: `Entry ${i} (rid=${entry.rid}) signature is invalid (tampered payload or wrong key).`,
        };
      }

      // Advance chain: this hash becomes the expected prevSig of the next entry.
      previousHash = currentHash;
    }

    return { valid: true, entryCount: logs.length }; // Chain is valid
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

  /**
   * Enforce the bounded (ring-buffer) size of the secure in-memory cache.
   *
   * Drops the oldest secure entries once the cache exceeds
   * {@link maxCacheEntries}. This is purely an in-memory concern: the rolling
   * {@link lastHash} chain state and the persisted append-only log file are
   * unaffected, so trimming cannot corrupt chain verification of persisted
   * logs.
   */
  private enforceSecureCacheBound(): void {
    const overflow = this.secureLogCache.length - this.maxCacheEntries;
    if (overflow > 0) {
      this.secureLogCache.splice(0, overflow);
    }
  }
}

