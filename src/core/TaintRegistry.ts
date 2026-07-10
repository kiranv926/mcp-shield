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
 * 
 * IMPROVEMENT: Stores origin tools as Set to track data laundering paths.
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
   * Origin tools that produced this tainted data (Map for chronological tracking)
   * CRITICAL FIX: Changed from Set<string> to Map<string, number> to track data laundering paths
   * with chronological ordering (tool → first seen timestamp)
   * 
   * Example: Map([["databaseTool", 1234567890], ["apiTool", 1234567900]])
   * Shows: databaseTool (14:02:01) → apiTool (14:02:15)
   * 
   * Critical for audit trail: "Tool A (Source) -> Tool B (Laundered) -> Taint Registry -> Tool C (Blocked)"
   * 
   * IMPROVEMENT: Chronological ordering enables accurate data flow visualization in reports
   */
  originTools: Map<string, number>; // tool → first seen timestamp
  
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
 * Default traversal / token caps (DoS protection).
 *
 * SECURITY FIX (depth & token evasion): Raised from depth 5 / 500 tokens so an
 * attacker can no longer bury tainted data at depth >= 6 or beyond token 500 and
 * evade the lineage check. These are defaults for configurable instance fields
 * (see TaintRegistry.maxTraversalDepth / maxTokensPerRequest). The check-side cap
 * is kept >= the registration-side cap in ResponseScraper so anything registered
 * can still be matched.
 */
const DEFAULT_MAX_TRAVERSAL_DEPTH = 12;
const DEFAULT_MAX_TOKENS_PER_REQUEST = 2000; // Maximum tokens per lineage check (DoS protection)

/**
 * Common English / structural words that must NOT be treated as taint sub-tokens.
 * Mirrors ResponseScraper.STOPWORDS so registration and checking stay symmetric.
 */
const SUBTOKEN_STOPWORDS = new Set<string>([
  'the', 'and', 'for', 'are', 'was', 'you', 'your', 'from', 'with', 'this',
  'that', 'user', 'name', 'email', 'code', 'ids', 'item', 'items', 'tag',
  'tags', 'type', 'data', 'value', 'null', 'true', 'false', 'info', 'key',
  'secret', 'password', 'token', 'number', 'phone', 'address', 'account',
]);

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
   * Mutex for concurrent access protection (Issue #3: Race Condition Prevention)
   * 
   * In a distributed environment (Redis), this would use atomic operations (SADD, HSET).
   * For in-memory version, we use a simple mutex to prevent race conditions when
   * registerTaint() and checkLineage() are called concurrently for the same session.
   */
  private sessionLocks = new Map<string, Promise<void>>();

  /**
   * Configuration
   */
  private config: TaintRegistryConfig;

  /**
   * Configurable DoS caps for lineage-check tokenization (SECURITY FIX).
   * Defaults raised from depth 5 / 500 tokens; can be overridden via
   * setTokenizationLimits() without changing the shared TaintRegistryConfig interface.
   */
  private maxTraversalDepth = DEFAULT_MAX_TRAVERSAL_DEPTH;
  private maxTokensPerRequest = DEFAULT_MAX_TOKENS_PER_REQUEST;

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
    // Do not keep the event loop alive solely for this background timer.
    this.cleanupInterval.unref?.();
    
    // Unref to allow process to exit if this is the only timer
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }
  
  /**
   * Acquire lock for a session (simple mutex implementation)
   * 
   * IMPROVEMENT (Issue #3): Prevents race conditions in concurrent access scenarios.
   * In a distributed environment (Redis), this would use atomic operations.
   */
  private async acquireLock(sessionKey: string): Promise<() => void> {
    // Wait for any existing lock to complete
    const existingLock = this.sessionLocks.get(sessionKey);
    if (existingLock) {
      await existingLock;
    }
    
    // Create new lock
    let releaseLock!: () => void;
    const lockPromise = new Promise<void>((resolve) => {
      releaseLock = () => {
        this.sessionLocks.delete(sessionKey);
        resolve();
      };
    });
    
    this.sessionLocks.set(sessionKey, lockPromise);
    return releaseLock;
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
   * Normalize a value before hashing (Issue #4: Semantic Matching for PII)
   * 
   * Strips non-alphanumeric characters for patterns like SSNs, phone numbers, IDs.
   * This ensures "123456789" and "123-456-789" hash to the same value.
   * 
   * Examples:
   * - "123-45-6789" -> "123456789" (SSN normalization)
   * - "(555) 123-4567" -> "5551234567" (Phone normalization)
   * - "ACC-12345" -> "ACC12345" (ID normalization)
   */
  private normalizeValue(val: string): string {
    const trimmed = val.trim();
    
    // Check if value looks like a structured identifier (contains delimiters)
    // Pattern: Contains digits and common delimiters (dash, colon, space, parentheses, underscore)
    const structuredPattern = /^[\d\w\s\-:()_]+$/;
    
    if (structuredPattern.test(trimmed) && /\d/.test(trimmed)) {
      // Likely an ID, SSN, phone, etc. - normalize by removing non-alphanumeric
      // This handles: "ACC-12345", "ACC 12345", "ACC_12345" -> all become "ACC12345"
      // Use [^a-zA-Z0-9] instead of [^\w] because \w includes underscore
      return trimmed.replace(/[^a-zA-Z0-9]/g, '');
    }
    
    // For other strings, return as-is (email addresses, etc. should keep their format)
    return trimmed;
  }

  /**
   * Hash a value using SHA-256 (Issue #1, #15: Privacy Protection)
   * 
   * CRITICAL: Never store raw sensitive data. Only store hashes.
   * This prevents sensitive data leaks if memory is dumped.
   * 
   * IMPROVEMENT: Normalizes value before hashing for semantic matching (Issue #4)
   */
  private hashValue(val: string): string {
    const normalized = this.normalizeValue(val);
    const toHash = normalized.length > MAX_VALUE_LENGTH 
      ? normalized.substring(0, MAX_VALUE_LENGTH) 
      : normalized;
    return createHash('sha256').update(toHash).digest('hex');
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
    
    // IMPROVEMENT (Issue #3): Acquire lock to prevent race conditions
    const releaseLock = await this.acquireLock(key);
    
    try {
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
        
        // Store or update entry (same hash can come from different tools)
        // IMPROVEMENT: Track multiple origin tools for data laundering detection
        const existing = sessionMap.get(valueHash);
        const currentSensitivity = this.sensitivityToNumber(context.sensitivityLevel);
        
        if (!existing) {
          // New entry
          sessionMap.set(valueHash, {
            valueHash,
            sensitivity: context.sensitivityLevel,
            originTools: new Map([[context.sourceTool ?? 'unknown', timestamp]]),
            timestamp,
            contextId,
            containsSecrets: context.containsSecrets ?? false,
            expiresAt,
          });
        } else {
          // Update existing entry:
          // 1. Add new origin tool to map with timestamp (preserves first seen time)
          // 2. Upgrade sensitivity if new one is higher
          // 3. Update secrets flag if new one has secrets
          const existingSensitivity = this.sensitivityToNumber(existing.sensitivity);
          const sourceTool = context.sourceTool ?? 'unknown';
          
          // Only add if not already present (preserves chronological order)
          if (!existing.originTools.has(sourceTool)) {
            existing.originTools.set(sourceTool, timestamp);
          }
          
          if (currentSensitivity > existingSensitivity) {
            existing.sensitivity = context.sensitivityLevel;
          }
          
          if (context.containsSecrets) {
            existing.containsSecrets = true;
          }
          
          // Update expiration to latest
          existing.expiresAt = expiresAt;
        }
      }
    } else {
      // Legacy fallback: Create a taint signature (for backward compatibility)
      // This is less effective but maintains compatibility during migration
      const legacyValue = `${context.sourceTool}:${context.sensitivityLevel}:${timestamp}`;
      const valueHash = this.hashValue(legacyValue);
      
      const existing = sessionMap.get(valueHash);
      const sourceTool = context.sourceTool ?? 'unknown';
      if (!existing) {
        sessionMap.set(valueHash, {
          valueHash,
          sensitivity: context.sensitivityLevel,
          originTools: new Map([[sourceTool, timestamp]]),
          timestamp,
          contextId,
          containsSecrets: context.containsSecrets ?? false,
          expiresAt,
        });
      } else {
        // Only add if not already present (preserves chronological order)
        if (!existing.originTools.has(sourceTool)) {
          existing.originTools.set(sourceTool, timestamp);
        }
      }
    }
    
    return contextId;
    } finally {
      // Release lock
      releaseLock();
    }
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
    // IMPROVEMENT: Use first origin tool (chronologically) for sourceTool (primary source)
    // The full originTools map is available in internal storage for audit
    return filtered.map(entry => {
      // Get first tool chronologically (lowest timestamp)
      const sortedTools = Array.from(entry.originTools.entries())
        .sort((a, b) => a[1] - b[1]); // Sort by timestamp
      const primaryTool = sortedTools[0]?.[0] ?? 'unknown';
      
      return {
        contextId: entry.contextId,
        sessionId: options.sessionId,
        tenantId: options.tenantId,
        sensitivityLevel: entry.sensitivity,
        sourceTool: primaryTool,
        containsSecrets: entry.containsSecrets,
        timestamp: new Date(entry.timestamp),
      };
    });
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
   * 1. Tokenize parameters into searchable values (with sub-token extraction)
   * 2. Hash each token (with normalization for semantic matching)
   * 3. Lookup hash in session map (O(1) instead of O(n))
   * 
   * IMPROVEMENT: Returns origin tools for audit trail (Architectural Improvement)
   * 
   * Performance Constraints (DoS Protection):
   * - Max depth: 5 levels
   * - Max string length: 1024 characters
   * - Max tokens per request: 500
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
    originTools?: string[]; // IMPROVEMENT: Return origin tools for audit trail
  }> {
    const key = this.getCompositeKey(sessionId, tenantId);
    const sessionMap = this.storage.get(key);

    if (!sessionMap) {
      return {
        highestSensitivity: null,
        relevantContexts: [],
        containsSecrets: false,
        originTools: [],
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
        originTools: [],
      };
    }

    // CRITICAL FIX: Tokenize parameters and use hash-based matching
    const tokens = this.tokenizeParams(args);
    
    let highestSensitivity: SensitivityLevel | null = null;
    let highestSensitivityNum = -1;
    const relevantContexts: TaintContext[] = [];
    const matchedContextIds = new Set<string>(); // Prevent duplicates
    const originToolsMap = new Map<string, number>(); // Collect all origin tools with timestamps for chronological ordering
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

        // Collect origin tools for audit trail (with timestamps for chronological ordering)
        for (const [originTool, timestamp] of match.originTools.entries()) {
          // Only keep earliest timestamp for each tool
          if (!originToolsMap.has(originTool)) {
            originToolsMap.set(originTool, timestamp);
          } else {
            const existingTimestamp = originToolsMap.get(originTool)!;
            if (timestamp < existingTimestamp) {
              originToolsMap.set(originTool, timestamp);
            }
          }
        }

        // Add to relevant contexts (only once per context)
        matchedContextIds.add(match.contextId);
        
        // Get primary origin tool (chronologically first)
        const sortedTools = Array.from(match.originTools.entries())
          .sort((a, b) => a[1] - b[1]); // Sort by timestamp
        const primaryTool = sortedTools[0]?.[0] ?? 'unknown';
        
        relevantContexts.push({
          contextId: match.contextId,
          sessionId,
          tenantId,
          sensitivityLevel: match.sensitivity,
          sourceTool: primaryTool,
          containsSecrets: match.containsSecrets,
          timestamp: new Date(match.timestamp),
        });
      }
    }

    // Sort origin tools chronologically (by timestamp) for report generation
    const sortedOriginTools = Array.from(originToolsMap.entries())
      .sort((a, b) => a[1] - b[1]) // Sort by timestamp
      .map(([tool]) => tool); // Extract just the tool names

    return {
      highestSensitivity,
      relevantContexts,
      containsSecrets: hasSecrets,
      originTools: sortedOriginTools, // IMPROVEMENT: Return chronologically sorted origin tools
    };
  }
  
  /**
   * Tokenize parameters into searchable values (Issue #2, #10)
   * 
   * Extracts all string values, potential IDs, emails, and other meaningful tokens
   * from the parameters object for efficient hash-based matching.
   * 
   * IMPROVEMENT (Issue #1): Implements sub-string tokenization to handle partial matches.
   * Example: "Your secret code is X55-99" will extract both the full string and "X55-99"
   * 
   * @param params - Parameters object to tokenize
   * @returns Set of token strings
   */
  private tokenizeParams(params: Record<string, unknown>): Set<string> {
    const tokens = new Set<string>();
    let truncated = false;

    // Use recursive extraction to get all string values
    const extractStrings = (obj: unknown, depth = 0): void => {
      // DoS protection: max depth and max tokens (SECURITY FIX: raised caps + fail-safe)
      if (depth > this.maxTraversalDepth || tokens.size >= this.maxTokensPerRequest) {
        truncated = true;
        return;
      }

      if (typeof obj === 'string') {
        const trimmed = obj.trim();

        // Add the string itself (for exact matching)
        if (trimmed.length >= MIN_VALUE_LENGTH && trimmed.length <= MAX_VALUE_LENGTH) {
          tokens.add(trimmed);

          // IMPROVEMENT: Extract sub-tokens for partial matching (Issue #1)
          // Split by common delimiters (spaces, colons, dashes, slashes, underscores)
          // This handles cases like "Your secret code is X55-99" -> ["X55", "99"]
          this.extractSubTokens(trimmed, tokens);
        }
      } else if (typeof obj === 'number' && Number.isFinite(obj)) {
        // SECURITY FIX (numeric taint evasion): Only tokenize numbers as strings
        // with the same MIN length gate used at registration time, so registration
        // (ResponseScraper) and checking stay symmetric. Booleans are intentionally
        // NOT tokenized (they would match every request carrying a boolean).
        const asString = String(obj);
        if (asString.length >= MIN_VALUE_LENGTH) {
          tokens.add(asString);
        }
      } else if (Array.isArray(obj)) {
        for (const item of obj) {
          extractStrings(item, depth + 1);
        }
      } else if (typeof obj === 'object' && obj !== null) {
        for (const value of Object.values(obj)) {
          extractStrings(value, depth + 1);
        }
      }
    };

    extractStrings(params);

    // FAIL-SAFE: If a DoS cap was hit, we may have skipped tainted inputs. Log a
    // truncation warning rather than silently under-checking lineage.
    if (truncated) {
      // eslint-disable-next-line no-console
      console.warn(
        `[TaintRegistry] Tokenization cap hit (maxDepth=${this.maxTraversalDepth}, ` +
        `maxTokens=${this.maxTokensPerRequest}). Lineage check may be incomplete for ` +
        `this request; treating as potentially under-covered.`
      );
    }

    return tokens;
  }

  /**
   * Configure DoS tokenization limits (SECURITY FIX: configurable caps).
   * Depth and token caps guard against unbounded traversal; raising them closes
   * the "bury data deep / late" evasion while remaining bounded.
   */
  public setTokenizationLimits(limits: { maxDepth?: number; maxTokens?: number }): void {
    if (limits.maxDepth !== undefined) {
      if (!Number.isInteger(limits.maxDepth) || limits.maxDepth < 1 || limits.maxDepth > 100) {
        throw new Error(`maxDepth must be an integer between 1 and 100, got: ${limits.maxDepth}`);
      }
      this.maxTraversalDepth = limits.maxDepth;
    }
    if (limits.maxTokens !== undefined) {
      if (!Number.isInteger(limits.maxTokens) || limits.maxTokens < 1 || limits.maxTokens > 100000) {
        throw new Error(`maxTokens must be an integer between 1 and 100000, got: ${limits.maxTokens}`);
      }
      this.maxTokensPerRequest = limits.maxTokens;
    }
  }
  
  /**
   * Extract sub-tokens from a string by splitting on delimiters (Issue #1: Partial Match)
   * 
   * Resolves the "Partial Match" problem where a tool response contains
   * "Your secret code is X55-99" but a subsequent tool call uses only "X55-99".
   * 
   * Examples:
   * - "ACC-12345" -> ["ACC", "12345"]
   * - "User ID: 12345" -> ["User", "ID", "12345"]
   * - "123-45-6789" -> ["123", "45", "6789"]
   * 
   * @param val - String value to extract sub-tokens from
   * @param tokens - Set to add tokens to
   */
  private extractSubTokens(val: string, tokens: Set<string>): void {
    // Split by common delimiters: spaces, colons, dashes, slashes, underscores, parentheses
    const subParts = val.split(/[:\-_ /\\()[\]]+/);

    if (subParts.length > 1) {
      for (const part of subParts) {
        const trimmed = part.trim();
        // SECURITY FIX (sub-token false positives): Only register identifier/secret-like
        // sub-tokens. Plain dictionary words (e.g. "User" from "User ID: 12345") are
        // dropped so they don't over-taint unrelated later calls.
        if (this.isMeaningfulSubToken(trimmed)) {
          tokens.add(trimmed);
        }
      }
    }
  }

  /**
   * Decide whether a delimiter-split sub-token is worth tracking as a taint.
   *
   * Mirrors ResponseScraper.isMeaningfulSubToken so registration and checking are
   * symmetric. Kept: tokens with digits, camelCase/mixed-internal-case, long tokens
   * (>= 12 chars), and high-entropy random-looking tokens. Dropped: short plain
   * words like "User", "code", "secret".
   */
  private isMeaningfulSubToken(token: string): boolean {
    if (token.length < MIN_VALUE_LENGTH || token.length > MAX_VALUE_LENGTH) {
      return false;
    }
    if (SUBTOKEN_STOPWORDS.has(token.toLowerCase())) {
      return false;
    }
    // Plain dictionary-shaped word (optional leading capital + lowercase) -> skip unless long.
    if (/^[A-Za-z][a-z]+$/.test(token) && token.length < 12) {
      return false;
    }
    if (/\d/.test(token)) {
      return true; // ids / codes / secrets
    }
    if (/[a-z][A-Z]/.test(token)) {
      return true; // camelCase secrets
    }
    if (token.length >= 12) {
      return true; // long tokens are likely ids/secrets
    }
    if (this.shannonEntropy(token) >= 3.0) {
      return true; // random-looking high-entropy tokens
    }
    return false;
  }

  /**
   * Shannon entropy (bits) of a string. Random secrets have high entropy;
   * dictionary words have low entropy.
   */
  private shannonEntropy(s: string): number {
    const freq = new Map<string, number>();
    for (const ch of s) {
      freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / s.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
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
    // Clear all locks
    this.sessionLocks.clear();
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

      // IMPROVEMENT (Issue #3): Acquire lock for atomic operation
      const releaseLock = await this.acquireLock(storageKey);
      
      try {
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
      } finally {
        releaseLock();
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

