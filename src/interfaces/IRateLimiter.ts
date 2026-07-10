/**
 * TaintGate: IRateLimiter Interface
 * 
 * Rate limiting interface for DoS protection and resource quota management.
 * 
 * Rate limiting is implemented as a separate interface to maintain SOLID principles
 * and allow different strategies (in-memory, Redis-based, etc.) without changing
 * core governance logic.
 */

/**
 * Rate Limit Configuration
 */
export interface RateLimitConfig {
  /**
   * Maximum requests per time window
   */
  maxRequests: number;
  
  /**
   * Time window in seconds
   */
  windowSeconds: number;
  
  /**
   * Whether to apply rate limiting globally or per-tenant
   */
  scope: 'global' | 'tenant' | 'tool';
}

/**
 * Rate Limit Check Result
 */
export interface RateLimitResult {
  /**
   * Whether the request is allowed
   */
  allowed: boolean;
  
  /**
   * Current request count in the window
   */
  currentCount: number;
  
  /**
   * Maximum allowed requests
   */
  maxRequests: number;
  
  /**
   * Time until the rate limit window resets (seconds)
   */
  resetInSeconds: number;
  
  /**
   * Reason for rejection (if not allowed)
   */
  reason?: string;
}

/**
 * IRateLimiter - Rate Limiting Interface
 * 
 * Responsibilities:
 * 1. Enforce rate limits per tenant/tool to prevent DoS attacks
 * 2. Track request counts within time windows
 * 3. Support different rate limiting strategies (in-memory, distributed)
 * 4. Provide quota information for quota exceeded scenarios
 */
export interface IRateLimiter {
  /**
   * Check if a request is within rate limits.
   * 
   * This method checks if the tenant/tool has exceeded its rate limit
   * for the current time window. If the limit is exceeded, returns false.
   * 
   * @param tenantId - Tenant identifier (optional for global limits)
   * @param toolName - Tool name being invoked (optional for tenant-level limits)
   * @returns Promise resolving to rate limit check result
   */
  checkLimit(
    tenantId?: string,
    toolName?: string
  ): Promise<RateLimitResult>;

  /**
   * Atomically check the rate limit AND record the request in a single
   * synchronous critical section.
   *
   * This is the enforcement-safe primitive: because the check and the record
   * happen without any intervening `await`, concurrent callers cannot all pass
   * the check before any of them records (the TOCTOU race that the separate
   * checkLimit()/recordRequest() pair is vulnerable to).
   *
   * A token is consumed ONLY when the request is allowed. When the limit is
   * already reached the call returns `allowed: false` and records nothing.
   *
   * Returns synchronously (not a Promise) to make the atomicity guarantee
   * explicit — there is no suspension point between check and record.
   *
   * @param tenantId - Tenant identifier (optional for global limits)
   * @param toolName - Tool name being invoked (optional for tenant-level limits)
   * @returns Rate limit result reflecting the state AFTER any consumption
   */
  tryConsume(
    tenantId?: string,
    toolName?: string
  ): RateLimitResult;

  /**
   * Record a request for rate limit tracking.
   * 
   * This method increments the request counter for the given tenant/tool.
   * Should be called after a request is processed (successfully or not).
   * 
   * @param tenantId - Tenant identifier
   * @param toolName - Tool name
   * @returns Promise resolving when recorded
   */
  recordRequest(
    tenantId?: string,
    toolName?: string
  ): Promise<void>;

  /**
   * Get current rate limit status.
   * 
   * Returns current usage without incrementing the counter.
   * Useful for quota information in responses.
   * 
   * @param tenantId - Tenant identifier
   * @param toolName - Tool name
   * @returns Promise resolving to current rate limit status
   */
  getStatus(
    tenantId?: string,
    toolName?: string
  ): Promise<RateLimitResult>;

  /**
   * Reset rate limit counters for a tenant/tool.
   * 
   * Useful for administrative actions or testing.
   * 
   * @param tenantId - Tenant identifier
   * @param toolName - Tool name (optional, resets all tools if not provided)
   * @returns Promise resolving when reset
   */
  reset(
    tenantId?: string,
    toolName?: string
  ): Promise<void>;

  /**
   * Configure rate limits for a tenant/tool.
   * 
   * @param config - Rate limit configuration
   * @param tenantId - Tenant identifier (optional for global config)
   * @param toolName - Tool name (optional for tenant-level config)
   * @returns Promise resolving when configured
   */
  configure(
    config: RateLimitConfig,
    tenantId?: string,
    toolName?: string
  ): Promise<void>;

  /**
   * Health check for rate limiting system.
   * 
   * @returns Promise resolving to true if rate limiter is healthy
   */
  healthCheck(): Promise<boolean>;
}

