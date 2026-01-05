/**
 * MCP-Shield: TaintRegistry Implementation
 * 
 * State Manager for context-aware taint tracking.
 * 
 * This implementation provides the "long-term memory" of the governance system,
 * ensuring that if an AI tool fetches sensitive data, that sensitivity follows
 * the data throughout the entire session, preventing "Data Laundering."
 * 
 * Key Features:
 * - Composite Key (tenant:session) for multi-tenant isolation
 * - Origin Tool tracking for full audit trail of data lineage
 * - Context-aware taint (not session-wide) to reduce false positives
 * - Recursive lineage checking with DoS protection
 * - Memory-efficient storage with TTL expiration
 * 
 * @see ARCHITECTURE.md - Supporting Components: TaintRegistry
 */

import { randomUUID, createHash } from 'crypto';
import type { ITaintRegistry, TaintRegistryConfig, TaintQueryOptions } from '../interfaces/ITaintRegistry';
import type { TaintContext } from '../types/common';
import type { SensitivityLevel } from '../types/mcp-hints';

/**
 * Internal Taint Entry (Hash-Based Storage)
 * 
 * Stores taint information with origin tracking for audit trail.
 * Uses hash-based storage for privacy and efficient lookups.
 * 
 * CRITICAL FIX: Now stores actual data value hashes, not tool names.
 * This enables actual lineage matching against tool arguments.
 */
interface TaintEntry {
  /**
   * SHA-256 hash of the tainted value (for privacy and exact matching)
   * CRITICAL: This is the hash of actual data values, not tool names
   */
  valueHash: string;
  
  /**
   * Sensitivity level of this taint
   */
  sensitivity: SensitivityLevel;
  
  /**
   * Origin tool that produced this tainted data
   * Critical for audit trail: "Tool A (Source) -> Taint Registry -> Tool B (Blocked)"
   */
  originTool: string;
  
  /**
   * Timestamp when this taint was registered
   */
  timestamp: number;
  
  /**
   * Context ID for this taint entry
   */
  contextId: string;
  
  /**
   * Whether this taint contains secrets
   */
  containsSecrets: boolean;
  
  /**
   * Expiration timestamp (timestamp + TTL)
   */
  expiresAt: number;
}

/**
 * DoS Protection Constants
 */
const MAX_VALUE_LENGTH = 1024; // Maximum length for value extraction
const MIN_VALUE_LENGTH = 3; // Minimum length to prevent noise

/**
 * TaintRegistry - State Manager Implementation
 * 
 * Implements context-aware taint tracking with:
 * - Multi-tenant isolation via composite keys
 * - Origin tool tracking for audit trail
 * - Recursive lineage checking
 * - TTL-based expiration
 */
export class TaintRegistry implements ITaintRegistry {
  /**
   * Hash-based storage: Composite Key "tenantId:sessionId" -> Map<ValueHash, TaintEntry>
   * 
   * CRITICAL FIX: Changed from Array to Map for O(1) hash lookups instead of O(n) string matching.
   * This resolves Issue #2 (inefficient lineage checking) and Issue #12 (performance).
   * 
   * TODO: In production, this would be backed by Redis or similar distributed cache
   * for horizontal scalability.
   */
  private storage = new Map<string, Map<string, TaintEntry>>();
  
  /**
   * Cleanup interval handle (for periodic expiration cleanup)
   */
  private cleanupInterval?: NodeJS.Timeout;

  /**
   * Configuration
   */
  private config: TaintRegistryConfig;

  /**
   * Constructor
   */
  constructor(config?: Partial<TaintRegistryConfig>) {
    this.config = {
      sessionTTL: config?.sessionTTL ?? 3600, // 1 hour
      contextTTL: config?.contextTTL ?? 1800, // 30 minutes
      enableMultiTenant: config?.enableMultiTenant ?? true,
      cacheBackend: config?.cacheBackend ?? 'memory',
      cacheUrl: config?.cacheUrl,
    };
    
    // Start periodic cleanup (Issue #4: Memory Leak Prevention)
    this.startCleanupInterval();
  }
  
  /**
   * Start periodic cleanup interval for expired sessions
   * Runs every 5 minutes to prevent memory leaks
   */
  private startCleanupInterval(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    // Cleanup every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.purgeExpiredSessions(this.config.sessionTTL * 1000);
    }, 5 * 60 * 1000);
    
    // Unref to allow process to exit if this is the only timer
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }
  
  /**
   * Purge expired sessions (Issue #4: Memory Leak Prevention)
   * 
   * Removes sessions where all entries are expired.
   * This prevents unbounded memory growth.
   */
  public purgeExpiredSessions(maxAgeMs: number = 3600000): void {
    const now = Date.now();
    const keysToDelete: string[] = [];
    
    for (const [key, sessionMap] of this.storage.entries()) {
      // Remove expired entries from session
      const activeEntries = Array.from(sessionMap.values()).filter(
        e => (now - e.timestamp) < maxAgeMs && e.expiresAt > now
      );
      
      if (activeEntries.length === 0) {
        // All entries expired, mark session for deletion
        keysToDelete.push(key);
      } else {
        // Rebuild map with only active entries
        const activeMap = new Map<string, TaintEntry>();
        for (const entry of activeEntries) {
          activeMap.set(entry.valueHash, entry);
        }
        this.storage.set(key, activeMap);
      }
    }
    
    // Delete expired sessions
    for (const key of keysToDelete) {
      this.storage.delete(key);
    }
  }
  
  /**
   * Hash a value using SHA-256 (Issue #1, #15: Privacy Protection)
   * 
   * CRITICAL: Never store raw sensitive data. Only store hashes.
   * This prevents sensitive data leaks if memory is dumped.
   */
  private hashValue(val: string): string {
    const normalized = val.trim();
    if (normalized.length > MAX_VALUE_LENGTH) {
      // Truncate to prevent DoS (Issue #6)
      return createHash('sha256').update(normalized.substring(0, MAX_VALUE_LENGTH)).digest('hex');
    }
    return createHash('sha256').update(normalized).digest('hex');
  }

  /**
   * Generate composite key for multi-tenant isolation
   */
  private getCompositeKey(sessionId: string, tenantId?: string): string {
    const tenant = tenantId ?? 'default';
    return `${tenant}:${sessionId}`;
  }

  /**
   * Register a new taint context.
   * 
   * CRITICAL FIX (Issue #1, #3): Now accepts actual data values from tool responses.
   * This method is called by ShieldMediator after extracting values from server responses.
   * 
   * Records a new taint discovery (e.g., from a tool output).
   * Implements the "Data Laundering Prevention" by tracking origin tool and actual data values.
   * 
   * @param context - Taint context with metadata
   * @param dataValues - Actual data values extracted from tool response (CRITICAL: new parameter)
   * @returns Promise resolving to registered context ID
   */
  async registerTaint(
    context: Omit<TaintContext, 'contextId' | 'timestamp'>,
    dataValues?: string[]
  ): Promise<string> {
    const contextId = randomUUID();
    const timestamp = Date.now();
    const expiresAt = timestamp + (this.config.contextTTL * 1000);

    const key = this.getCompositeKey(context.sessionId, context.tenantId);
    
    // Initialize session map if it doesn't exist
    if (!this.storage.has(key)) {
      this.storage.set(key, new Map());
    }
    
    const sessionMap = this.storage.get(key)!;
    
    // CRITICAL FIX: Register actual data values, not tool names
    // If dataValues are provided, hash and store them
    // Otherwise, fall back to legacy behavior (for backward compatibility during migration)
    if (dataValues && dataValues.length > 0) {
      for (const val of dataValues) {
        // Skip empty or too-short values (noise filtering)
        if (!val || val.length < MIN_VALUE_LENGTH) {
          continue;
        }
        
        // Hash the value for privacy and exact matching
        const valueHash = this.hashValue(val);
        
        // Store or update entry (same hash can come from different tools, keep highest sensitivity)
        const existing = sessionMap.get(valueHash);
        if (!existing || this.sensitivityToNumber(context.sensitivityLevel) > this.sensitivityToNumber(existing.sensitivity)) {
          sessionMap.set(valueHash, {
            valueHash,
            sensitivity: context.sensitivityLevel,
            originTool: context.sourceTool ?? 'unknown',
            timestamp,
            contextId,
            containsSecrets: context.containsSecrets ?? false,
            expiresAt,
          });
        }
      }
    } else {
      // Legacy fallback: Create a taint signature (for backward compatibility)
      // This is less effective but maintains compatibility during migration
      const legacyValue = `${context.sourceTool}:${context.sensitivityLevel}:${timestamp}`;
      const valueHash = this.hashValue(legacyValue);
      
      sessionMap.set(valueHash, {
        valueHash,
        sensitivity: context.sensitivityLevel,
        originTool: context.sourceTool ?? 'unknown',
        timestamp,
        contextId,
        containsSecrets: context.containsSecrets ?? false,
        expiresAt,
      });
    }

    return contextId;
  }

  /**
   * Query taint contexts for a session.
   */
  async queryTaints(options: TaintQueryOptions): Promise<TaintContext[]> {
    const key = this.getCompositeKey(options.sessionId, options.tenantId);
    const sessionMap = this.storage.get(key);
    
    if (!sessionMap) {
      return [];
    }

    const now = Date.now();
    const entries = Array.from(sessionMap.values());
    let filtered = entries;

    // Filter expired if not including them
    if (!options.includeExpired) {
      filtered = entries.filter(e => e.expiresAt > now);
    }

    // Filter by minimum sensitivity
    if (options.minSensitivity !== undefined) {
      const minLevel = this.sensitivityToNumber(options.minSensitivity);
      filtered = filtered.filter(e => 
        this.sensitivityToNumber(e.sensitivity) >= minLevel
      );
    }

    // Convert to TaintContext format
    return filtered.map(entry => ({
      contextId: entry.contextId,
      sessionId: options.sessionId,
      tenantId: options.tenantId,
      sensitivityLevel: entry.sensitivity,
      sourceTool: entry.originTool, // Map originTool to sourceTool for TaintContext
      containsSecrets: entry.containsSecrets,
      timestamp: new Date(entry.timestamp),
    }));
  }

  /**
   * Check if a session has any taint contexts.
   */
  async isSessionTainted(sessionId: string, tenantId?: string): Promise<boolean> {
    const key = this.getCompositeKey(sessionId, tenantId);
    const sessionMap = this.storage.get(key);
    
    if (!sessionMap) {
      return false;
    }
    
    const now = Date.now();
    return Array.from(sessionMap.values()).some(e => e.expiresAt > now);
  }

  /**
   * Get taint contexts that affect a specific tool call.
   */
  async getRelevantTaints(
    _toolName: string,
    options: TaintQueryOptions
  ): Promise<TaintContext[]> {
    // For now, return all taints for the session
    // In production, this would analyze tool parameters to determine relevance
    return this.queryTaints(options);
  }

  /**
   * Check argument lineage for taint propagation.
   * 
   * CRITICAL FIX (Issue #2, #12): Now uses hash-based O(1) lookups instead of O(n*m) string matching.
   * 
   * Implements efficient tokenization and hash-based matching:
   * 1. Tokenize parameters into searchable values
   * 2. Hash each token
   * 3. Lookup hash in session map (O(1) instead of O(n))
   * 
   * Performance Constraints (DoS Protection):
   * - Max depth: 5 levels
   * - Max string length: 1000 characters
   * - Timeout: 100ms (fail-closed if exceeded, handled by ShieldMediator)
   */
  async checkLineage(
    args: Record<string, unknown>,
    sessionId: string,
    tenantId?: string
  ): Promise<{
    highestSensitivity: SensitivityLevel | null;
    relevantContexts: TaintContext[];
    containsSecrets: boolean;
  }> {
    const key = this.getCompositeKey(sessionId, tenantId);
    const sessionMap = this.storage.get(key);

    if (!sessionMap) {
      return {
        highestSensitivity: null,
        relevantContexts: [],
        containsSecrets: false,
      };
    }

    // Remove expired entries
    const now = Date.now();
    const activeEntries = Array.from(sessionMap.values()).filter(e => e.expiresAt > now);

    if (activeEntries.length === 0) {
      return {
        highestSensitivity: null,
        relevantContexts: [],
        containsSecrets: false,
      };
    }

    // CRITICAL FIX: Tokenize parameters and use hash-based matching
    const tokens = this.tokenizeParams(args);
    
    let highestSensitivity: SensitivityLevel | null = null;
    let highestSensitivityNum = -1;
    const relevantContexts: TaintContext[] = [];
    const matchedContextIds = new Set<string>(); // Prevent duplicates
    let hasSecrets = false;

    // Hash each token and check against session map (O(1) lookup)
    for (const token of tokens) {
      const tokenHash = this.hashValue(token);
      const match = sessionMap.get(tokenHash);
      
      if (match && !matchedContextIds.has(match.contextId)) {
        const sensitivityNum = this.sensitivityToNumber(match.sensitivity);
        
        if (sensitivityNum > highestSensitivityNum) {
          highestSensitivityNum = sensitivityNum;
          highestSensitivity = match.sensitivity;
        }

        if (match.containsSecrets) {
          hasSecrets = true;
        }

        // Add to relevant contexts (only once per context)
        matchedContextIds.add(match.contextId);
        relevantContexts.push({
          contextId: match.contextId,
          sessionId,
          tenantId,
          sensitivityLevel: match.sensitivity,
          sourceTool: match.originTool,
          containsSecrets: match.containsSecrets,
          timestamp: new Date(match.timestamp),
        });
      }
    }

    return {
      highestSensitivity,
      relevantContexts,
      containsSecrets: hasSecrets,
    };
  }
  
  /**
   * Tokenize parameters into searchable values (Issue #2, #10)
   * 
   * Extracts all string values, potential IDs, emails, and other meaningful tokens
   * from the parameters object for efficient hash-based matching.
   * 
   * @param params - Parameters object to tokenize
   * @returns Set of token strings
   */
  private tokenizeParams(params: Record<string, unknown>): Set<string> {
    const tokens = new Set<string>();
    
    // Use recursive extraction to get all string values
    const extractStrings = (obj: unknown, depth = 0): void => {
      if (depth > 5) return; // DoS protection: max depth
      
      if (typeof obj === 'string') {
        // Add the string itself (for exact matching)
        if (obj.length >= MIN_VALUE_LENGTH && obj.length <= MAX_VALUE_LENGTH) {
          tokens.add(obj);
        }
      } else if (Array.isArray(obj)) {
        for (const item of obj) {
          extractStrings(item, depth + 1);
        }
      } else if (typeof obj === 'object' && obj !== null) {
        for (const value of Object.values(obj)) {
          extractStrings(value, depth + 1);
        }
      } else if (typeof obj === 'number' || typeof obj === 'boolean') {
        // Convert numbers/booleans to strings for matching
        tokens.add(String(obj));
      }
    };
    
    extractStrings(params);
    
    return tokens;
  }


  /**
   * Convert SensitivityLevel to numeric value for comparison
   */
  private sensitivityToNumber(level: SensitivityLevel): number {
    if (typeof level === 'number') {
      return level;
    }
    // Handle enum values
    const enumMap: Record<string, number> = {
      'Public': 0.0,
      'Internal': 0.5,
      'Confidential': 1.0,
      'Restricted': 1.0,
    };
    return enumMap[level] ?? 1.0;
  }

  /**
   * Clear taint contexts for a session.
   */
  async clearSession(sessionId: string, tenantId?: string): Promise<void> {
    const key = this.getCompositeKey(sessionId, tenantId);
    this.storage.delete(key);
  }
  
  /**
   * Cleanup method to stop intervals and free resources
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
  }

  /**
   * Clear a specific taint context.
   */
  async clearContext(contextId: string, tenantId?: string): Promise<void> {
    // Search through all sessions for this contextId
    // In production with distributed cache, this would use indexed lookup
    for (const [storageKey, sessionMap] of this.storage.entries()) {
      // Check if this key belongs to the tenant
      if (tenantId && !storageKey.startsWith(`${tenantId}:`)) {
        continue;
      }

      // Find and remove entry with matching contextId
      for (const [hash, entry] of sessionMap.entries()) {
        if (entry.contextId === contextId) {
          sessionMap.delete(hash);
          // If session map is now empty, remove the session
          if (sessionMap.size === 0) {
            this.storage.delete(storageKey);
          }
          return; // Found and removed, exit early
        }
      }
    }
  }

  /**
   * Update taint context expiration.
   */
  async updateContextTTL(
    contextId: string,
    ttlSeconds: number,
    tenantId?: string
  ): Promise<void> {
    // Find the context and update its expiration
    for (const [key, sessionMap] of this.storage.entries()) {
      if (tenantId && !key.startsWith(`${tenantId}:`)) {
        continue;
      }

      // Search through entries in the session map
      for (const entry of sessionMap.values()) {
        if (entry.contextId === contextId) {
          entry.expiresAt = Date.now() + (ttlSeconds * 1000);
          // Update the map (entry is already a reference, so it's updated)
          this.storage.set(key, sessionMap);
          return; // Found and updated, exit early
        }
      }
    }
  }

  /**
   * Get session statistics.
   */
  async getSessionStats(
    sessionId: string,
    tenantId?: string
  ): Promise<{
    totalContexts: number;
    activeContexts: number;
    expiredContexts: number;
    highestSensitivity: SensitivityLevel | null;
    hasSecrets: boolean;
  }> {
    const key = this.getCompositeKey(sessionId, tenantId);
    const sessionMap = this.storage.get(key);
    
    if (!sessionMap) {
      return {
        totalContexts: 0,
        activeContexts: 0,
        expiredContexts: 0,
        highestSensitivity: null,
        hasSecrets: false,
      };
    }

    const entries = Array.from(sessionMap.values());
    const now = Date.now();
    const active = entries.filter(e => e.expiresAt > now);
    const expired = entries.filter(e => e.expiresAt <= now);

    let highestSensitivity: SensitivityLevel | null = null;
    let highestSensitivityNum = -1;
    let hasSecrets = false;

    for (const entry of active) {
      const sensitivityNum = this.sensitivityToNumber(entry.sensitivity);
      if (sensitivityNum > highestSensitivityNum) {
        highestSensitivityNum = sensitivityNum;
        highestSensitivity = entry.sensitivity;
      }
      if (entry.containsSecrets) {
        hasSecrets = true;
      }
    }

    return {
      totalContexts: entries.length,
      activeContexts: active.length,
      expiredContexts: expired.length,
      highestSensitivity,
      hasSecrets,
    };
  }

  /**
   * Health check.
   */
  async healthCheck(): Promise<boolean> {
    // For in-memory storage, always healthy
    // In production with Redis, this would ping the cache backend
    return true;
  }

  /**
   * Get current configuration.
   */
  getConfig(): TaintRegistryConfig {
    return { ...this.config };
  }

  /**
   * Update configuration.
   */
  updateConfig(config: Partial<TaintRegistryConfig>): void {
    this.config = {
      ...this.config,
      ...config,
    };
  }
}

