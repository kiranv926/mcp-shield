/**
 * MCP-Shield: ITaintRegistry Interface
 * 
 * State Manager interface for TaintRegistry.
 * 
 * The TaintRegistry implements context-aware taint tracking, maintaining
 * stateful session data while remaining stateless per request for scalability.
 * 
 * @see ARCHITECTURE.md - Supporting Components: TaintRegistry
 */

import type { TaintContext } from '../types/common';
import type { SensitivityLevel } from '../types/mcp-hints';

/**
 * Taint Registry Configuration
 */
export interface TaintRegistryConfig {
  /**
   * Session TTL in seconds
   * Default: 3600 (1 hour)
   */
  sessionTTL: number;
  
  /**
   * Context TTL in seconds (for individual taint contexts)
   * Default: 1800 (30 minutes)
   */
  contextTTL: number;
  
  /**
   * Whether to enable multi-tenant isolation
   * Default: true
   */
  enableMultiTenant: boolean;
  
  /**
   * Cache backend type ('redis' | 'memory' | 'custom')
   * Default: 'redis'
   */
  cacheBackend: 'redis' | 'memory' | 'custom';
  
  /**
   * Cache connection URL (for Redis)
   */
  cacheUrl?: string;
}

/**
 * Taint Query Options
 */
export interface TaintQueryOptions {
  /**
   * Session ID to query
   */
  sessionId: string;
  
  /**
   * Tenant ID for isolation (optional)
   */
  tenantId?: string;
  
  /**
   * Whether to include expired contexts
   * Default: false
   */
  includeExpired?: boolean;
  
  /**
   * Minimum sensitivity level to include
   * Default: 'public' (include all)
   */
  minSensitivity?: SensitivityLevel;
}

/**
 * ITaintRegistry - State Manager Interface
 * 
 * Responsibilities:
 * 1. Track context-aware taint (not session-wide)
 * 2. Maintain tool output lineage per context
 * 3. Support multi-tenant isolation
 * 4. Provide stateless per-request, stateful per-session design
 * 5. Enable horizontal scalability via distributed cache
 */
export interface ITaintRegistry {
  /**
   * Register a new taint context.
   * 
   * Creates a taint context when a tool returns sensitive data.
   * The taint is context-specific, not session-wide, to reduce false positives.
   * 
   * CRITICAL FIX (Issue #1, #3): Now accepts optional dataValues parameter
   * for actual data value extraction from tool responses.
   * 
   * @param context - Taint context to register
   * @param dataValues - Optional array of actual data values extracted from tool response
   *                    If provided, these values are hashed and stored for lineage matching.
   *                    If not provided, falls back to legacy behavior (tool name tracking).
   * @returns Promise resolving to registered context ID
   */
  registerTaint(
    context: Omit<TaintContext, 'contextId' | 'timestamp'>,
    dataValues?: string[]
  ): Promise<string>;

  /**
   * Query taint contexts for a session.
   * 
   * Returns all active taint contexts for the given session,
   * optionally filtered by tenant and sensitivity level.
   * 
   * @param options - Query options
   * @returns Promise resolving to array of taint contexts
   */
  queryTaints(options: TaintQueryOptions): Promise<TaintContext[]>;

  /**
   * Check if a session has any taint contexts.
   * 
   * @param sessionId - Session ID to check
   * @param tenantId - Tenant ID for isolation (optional)
   * @returns Promise resolving to true if session is tainted
   */
  isSessionTainted(sessionId: string, tenantId?: string): Promise<boolean>;

  /**
   * Get taint contexts that affect a specific tool call.
   * 
   * Returns taint contexts that are relevant to the given tool,
   * based on context lineage and tool parameter analysis.
   * 
   * @param toolName - Tool name being invoked
   * @param options - Query options
   * @returns Promise resolving to relevant taint contexts
   */
  getRelevantTaints(
    toolName: string,
    options: TaintQueryOptions
  ): Promise<TaintContext[]>;

  /**
   * Check argument lineage for taint propagation.
   * 
   * This method implements the taint propagation rule:
   * "If a tool argument contains a string or ID that was previously
   * tagged as 'Sensitive' in the TaintRegistry, the current request
   * inherits the highest Taint Level of its inputs."
   * 
   * **Algorithm: Recursive Depth-First Search (DFS)**
   * 
   * 1. **Traversal**: Recursive DFS through args object (depth-limited to 5 levels)
   * 2. **Extraction**: Convert all values to strings (max length 1000 chars per string)
   * 3. **Matching**: Check against active Taint IDs in current session using:
   *    - Exact match (preferred)
   *    - Substring match (if exact fails)
   *    - Bloom Filter or Set lookup for performance
   * 4. **Aggregation**: Return highest sensitivity level found across all matches
   * 
   * **Performance Constraints** (DoS Protection):
   * - Max depth: 5 levels
   * - Max string length: 1000 characters
   * - Timeout: 100ms (fail-closed if exceeded)
   * 
   * **Matching Strategy**:
   * - Extract contextId from registered taint contexts
   * - Match against string values in args
   * - If match found, inherit that context's sensitivity level
   * 
   * @param args - Tool arguments to check for tainted data
   * @param sessionId - Session ID to check within
   * @param tenantId - Tenant ID for isolation (optional)
   * @returns Promise resolving to highest taint level found, or null if none
   */
  checkLineage(
    args: Record<string, unknown>,
    sessionId: string,
    tenantId?: string
  ): Promise<{
    highestSensitivity: SensitivityLevel | null;
    relevantContexts: TaintContext[];
    containsSecrets: boolean;
  }>;

  /**
   * Clear taint contexts for a session.
   * 
   * Removes all taint contexts for the given session.
   * Used for session reset or expiration.
   * 
   * @param sessionId - Session ID to clear
   * @param tenantId - Tenant ID for isolation (optional)
   * @returns Promise resolving when complete
   */
  clearSession(sessionId: string, tenantId?: string): Promise<void>;

  /**
   * Clear a specific taint context.
   * 
   * @param contextId - Context ID to clear
   * @param tenantId - Tenant ID for isolation (optional)
   * @returns Promise resolving when complete
   */
  clearContext(contextId: string, tenantId?: string): Promise<void>;

  /**
   * Update taint context expiration.
   * 
   * Extends or reduces the TTL for a taint context.
   * 
   * @param contextId - Context ID to update
   * @param ttlSeconds - New TTL in seconds
   * @param tenantId - Tenant ID for isolation (optional)
   * @returns Promise resolving when complete
   */
  updateContextTTL(
    contextId: string,
    ttlSeconds: number,
    tenantId?: string
  ): Promise<void>;

  /**
   * Get session statistics.
   * 
   * Returns statistics about taint contexts for a session.
   * 
   * @param sessionId - Session ID
   * @param tenantId - Tenant ID for isolation (optional)
   * @returns Promise resolving to session statistics
   */
  getSessionStats(
    sessionId: string,
    tenantId?: string
  ): Promise<{
    totalContexts: number;
    activeContexts: number;
    expiredContexts: number;
    highestSensitivity: SensitivityLevel | null;
    hasSecrets: boolean;
  }>;

  /**
   * Health check.
   * 
   * Verifies that the registry backend is available and responsive.
   * 
   * @returns Promise resolving to true if healthy
   */
  healthCheck(): Promise<boolean>;

  /**
   * Get current configuration.
   * 
   * @returns Current configuration
   */
  getConfig(): TaintRegistryConfig;

  /**
   * Update configuration.
   * 
   * @param config - New configuration (partial update supported)
   */
  updateConfig(config: Partial<TaintRegistryConfig>): void;
}

