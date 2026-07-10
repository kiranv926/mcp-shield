/**
 * MCP-Shield: RateLimiter Implementation
 * 
 * Rate limiting implementation for DoS protection and resource quota management.
 * 
 * Implements a sliding window algorithm for efficient rate limiting with:
 * - Per-tenant and per-tool rate limiting
 * - Configurable time windows and request limits
 * - Automatic cleanup of expired entries
 * - Memory-efficient storage
 * 
 * @see ARCHITECTURE.md - Rate Limiting
 */

import type {
  IRateLimiter,
  RateLimitConfig,
  RateLimitResult,
} from '../interfaces/IRateLimiter';

/**
 * Rate Limit Entry
 */
interface RateLimitEntry {
  /**
   * Request timestamps within the current window
   */
  timestamps: number[];
  
  /**
   * Window start time (for cleanup)
   */
  windowStart: number;
  
  /**
   * Configuration for this entry
   */
  config: RateLimitConfig;
}

/**
 * RateLimiter Configuration
 */
export interface RateLimiterConfig {
  /**
   * Default global rate limit configuration
   */
  defaultConfig?: RateLimitConfig;
  
  /**
   * Cleanup interval in milliseconds (default: 60000 = 1 minute)
   */
  cleanupInterval?: number;
  
  /**
   * Maximum number of entries to keep in memory (DoS protection)
   */
  maxEntries?: number;
}

/**
 * Default configuration constants
 */
const DEFAULT_MAX_REQUESTS = 100;
const DEFAULT_WINDOW_SECONDS = 60;
const DEFAULT_CLEANUP_INTERVAL = 60000; // 1 minute
const DEFAULT_MAX_ENTRIES = 10000;
const DEFAULT_MAX_TIMESTAMPS_PER_ENTRY = 10000; // Prevent unbounded growth

/**
 * RateLimiter - Rate Limiting Implementation
 * 
 * Implements sliding window rate limiting for DoS protection.
 */
export class RateLimiter implements IRateLimiter {
  /**
   * Storage: key -> RateLimitEntry
   * Key format: "global" | "tenant:tenantId" | "tenant:tenantId:tool:toolName"
   */
  private entries = new Map<string, RateLimitEntry>();
  
  /**
   * Default configuration
   */
  private defaultConfig: RateLimitConfig;
  
  /**
   * Cleanup interval timer
   */
  private cleanupTimer?: NodeJS.Timeout;
  
  /**
   * Cleanup interval in milliseconds
   */
  private readonly cleanupInterval: number;
  
  /**
   * Maximum entries (DoS protection)
   */
  private readonly maxEntries: number;
  
  /**
   * Maximum timestamps per entry (memory protection)
   */
  private readonly maxTimestampsPerEntry: number;

  constructor(config?: RateLimiterConfig) {
    this.defaultConfig = config?.defaultConfig ?? {
      maxRequests: DEFAULT_MAX_REQUESTS,
      windowSeconds: DEFAULT_WINDOW_SECONDS,
      scope: 'global',
    };
    this.cleanupInterval = config?.cleanupInterval ?? DEFAULT_CLEANUP_INTERVAL;
    this.maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.maxTimestampsPerEntry = DEFAULT_MAX_TIMESTAMPS_PER_ENTRY;
    
    // Start periodic cleanup
    this.startCleanup();
  }

  /**
   * Check if a request is within rate limits
   */
  async checkLimit(
    tenantId?: string,
    toolName?: string
  ): Promise<RateLimitResult> {
    const key = this.buildKey(tenantId, toolName);
    const entry = this.getOrCreateEntry(key);
    
    const now = Date.now();
    this.updateWindow(entry, now);
    
    // Check if limit is exceeded
    const currentCount = entry.timestamps.length;
    const maxRequests = entry.config.maxRequests;
    const allowed = currentCount < maxRequests;
    
    // Calculate reset time (optimized: only calculate if needed)
    const resetInSeconds = this.calculateResetTime(entry, now);
    
    return {
      allowed,
      currentCount,
      maxRequests,
      resetInSeconds,
      reason: allowed ? undefined : `Rate limit exceeded: ${currentCount}/${maxRequests} requests in ${entry.config.windowSeconds}s window`,
    };
  }

  /**
   * Atomically check-and-record in a single synchronous critical section.
   *
   * Node.js runs this method to completion without yielding (no `await` inside),
   * so N concurrent callers are serialized: once the window is full, every
   * subsequent caller sees the recorded timestamps and is denied. This closes
   * the TOCTOU gap present in the separate checkLimit()/recordRequest() pattern.
   *
   * A token is consumed only when the request is allowed.
   */
  tryConsume(
    tenantId?: string,
    toolName?: string
  ): RateLimitResult {
    const key = this.buildKey(tenantId, toolName);
    const entry = this.getOrCreateEntry(key);

    const now = Date.now();
    this.updateWindow(entry, now);

    const currentCount = entry.timestamps.length;
    const maxRequests = entry.config.maxRequests;
    const allowed = currentCount < maxRequests;

    if (allowed) {
      // Record within the same synchronous section as the check.
      this.addTimestamp(entry, now);

      // Enforce max entries limit (DoS protection)
      if (this.entries.size > this.maxEntries) {
        this.evictOldestEntry();
      }
    }

    // Reported count reflects state AFTER any consumption.
    const reportedCount = allowed ? currentCount + 1 : currentCount;
    const resetInSeconds = this.calculateResetTime(entry, now);

    return {
      allowed,
      currentCount: reportedCount,
      maxRequests,
      resetInSeconds,
      reason: allowed
        ? undefined
        : `Rate limit exceeded: ${currentCount}/${maxRequests} requests in ${entry.config.windowSeconds}s window`,
    };
  }

  /**
   * Record a request for rate limit tracking
   */
  async recordRequest(
    tenantId?: string,
    toolName?: string
  ): Promise<void> {
    const key = this.buildKey(tenantId, toolName);
    const entry = this.getOrCreateEntry(key);
    
    const now = Date.now();
    this.updateWindow(entry, now);
    
    // Add current timestamp with size limit protection
    this.addTimestamp(entry, now);
    
    // Enforce max entries limit (DoS protection)
    if (this.entries.size > this.maxEntries) {
      this.evictOldestEntry();
    }
  }

  /**
   * Get current rate limit status without incrementing
   * 
   * NOTE: This method does NOT mutate entry state (read-only operation).
   * For state updates, use checkLimit() or recordRequest().
   */
  async getStatus(
    tenantId?: string,
    toolName?: string
  ): Promise<RateLimitResult> {
    const key = this.buildKey(tenantId, toolName);
    const entry = this.entries.get(key);
    
    if (!entry) {
      // No entry exists, return default status
      return {
        allowed: true,
        currentCount: 0,
        maxRequests: this.defaultConfig.maxRequests,
        resetInSeconds: this.defaultConfig.windowSeconds,
      };
    }
    
    const now = Date.now();
    const windowMs = entry.config.windowSeconds * 1000;
    const windowStart = now - windowMs;
    
    // Read-only: calculate without mutating entry
    const validTimestamps = entry.timestamps.filter(ts => ts > windowStart);
    const currentCount = validTimestamps.length;
    const maxRequests = entry.config.maxRequests;
    const allowed = currentCount < maxRequests;
    
    // Calculate reset time (read-only)
    const resetInSeconds = this.calculateResetTimeFromTimestamps(validTimestamps, now, windowMs, entry.config.windowSeconds);
    
    return {
      allowed,
      currentCount,
      maxRequests,
      resetInSeconds,
      reason: allowed ? undefined : `Rate limit exceeded: ${currentCount}/${maxRequests} requests in ${entry.config.windowSeconds}s window`,
    };
  }

  /**
   * Reset rate limit counters
   */
  async reset(
    tenantId?: string,
    toolName?: string
  ): Promise<void> {
    if (tenantId === undefined && toolName === undefined) {
      // Reset all entries
      this.entries.clear();
      return;
    }
    
    if (toolName === undefined) {
      // Reset all entries for tenant
      const tenantPrefix = `tenant:${tenantId}`;
      for (const [key] of this.entries.entries()) {
        if (key.startsWith(tenantPrefix)) {
          this.entries.delete(key);
        }
      }
      return;
    }
    
    // Reset specific tenant:tool entry
    const key = this.buildKey(tenantId, toolName);
    this.entries.delete(key);
  }

  /**
   * Configure rate limits
   */
  async configure(
    config: RateLimitConfig,
    tenantId?: string,
    toolName?: string
  ): Promise<void> {
    // Validate configuration
    this.validateConfig(config);
    
    const key = this.buildKey(tenantId, toolName);
    const entry = this.getOrCreateEntry(key);
    
    // Update configuration
    entry.config = { ...config };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Check if entries map is accessible
      const size = this.entries.size;
      
      // Basic health: entries map is accessible and within limits
      return size <= this.maxEntries;
    } catch (error) {
      return false;
    }
  }

  /**
   * Build storage key from tenant and tool
   */
  private buildKey(tenantId?: string, toolName?: string): string {
    if (tenantId === undefined && toolName === undefined) {
      return 'global';
    }
    
    if (toolName === undefined) {
      return `tenant:${tenantId}`;
    }
    
    return `tenant:${tenantId}:tool:${toolName}`;
  }

  /**
   * Get or create rate limit entry
   */
  private getOrCreateEntry(key: string): RateLimitEntry {
    let entry = this.entries.get(key);
    
    if (!entry) {
      entry = {
        timestamps: [],
        windowStart: Date.now(),
        config: { ...this.defaultConfig },
      };
      this.entries.set(key, entry);
    }
    
    return entry;
  }

  /**
   * Evict oldest entry (LRU-like eviction for DoS protection)
   */
  private evictOldestEntry(): void {
    if (this.entries.size === 0) return;
    
    // Find entry with oldest window start
    let oldestKey: string | undefined;
    let oldestTime = Infinity;
    
    for (const [key, entry] of this.entries.entries()) {
      if (entry.windowStart < oldestTime) {
        oldestTime = entry.windowStart;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.entries.delete(oldestKey);
    }
  }

  /**
   * Update window for an entry (filters expired timestamps)
   * This is the common logic used by checkLimit and recordRequest
   */
  private updateWindow(entry: RateLimitEntry, now: number): void {
    const windowMs = entry.config.windowSeconds * 1000;
    const windowStart = now - windowMs;
    
    // Remove timestamps outside the current window
    entry.timestamps = entry.timestamps.filter(ts => ts > windowStart);
    entry.windowStart = windowStart;
  }

  /**
   * Add timestamp with size limit protection
   */
  private addTimestamp(entry: RateLimitEntry, timestamp: number): void {
    // Enforce max timestamps per entry to prevent unbounded growth
    if (entry.timestamps.length >= this.maxTimestampsPerEntry) {
      // Keep most recent 90% to allow some headroom
      const keepCount = Math.floor(this.maxTimestampsPerEntry * 0.9);
      entry.timestamps = entry.timestamps.slice(-keepCount);
    }
    
    entry.timestamps.push(timestamp);
  }

  /**
   * Calculate reset time from entry (mutates entry state)
   */
  private calculateResetTime(entry: RateLimitEntry, now: number): number {
    if (entry.timestamps.length === 0) {
      return entry.config.windowSeconds;
    }
    
    return this.calculateResetTimeFromTimestamps(
      entry.timestamps,
      now,
      entry.config.windowSeconds * 1000,
      entry.config.windowSeconds
    );
  }

  /**
   * Calculate reset time from timestamps (read-only)
   */
  private calculateResetTimeFromTimestamps(
    timestamps: number[],
    now: number,
    windowMs: number,
    defaultWindowSeconds: number
  ): number {
    if (timestamps.length === 0) {
      return defaultWindowSeconds;
    }
    
    // Optimize: only calculate min if we have timestamps
    // For small arrays, Math.min is efficient; for large arrays, consider binary search
    const oldestTimestamp = timestamps.length <= 100 
      ? Math.min(...timestamps)
      : this.findOldestTimestamp(timestamps);
    
    const resetTime = oldestTimestamp + windowMs;
    const resetInSeconds = Math.max(0, Math.ceil((resetTime - now) / 1000));
    
    // Validate: reset time should be reasonable (prevent clock skew issues)
    if (resetInSeconds > 86400) { // More than 24 hours
      return defaultWindowSeconds;
    }
    
    return resetInSeconds;
  }

  /**
   * Find oldest timestamp efficiently
   * For small arrays, Math.min is fine; for large arrays, use linear search
   */
  private findOldestTimestamp(timestamps: number[]): number {
    if (timestamps.length === 0) {
      return Infinity;
    }
    
    // For arrays > 100, use linear search (O(n)) instead of spread operator
    // which can cause stack overflow for very large arrays
    let oldest: number = timestamps[0]!; // Safe: we checked length > 0
    for (let i = 1; i < timestamps.length; i++) {
      const ts = timestamps[i];
      if (ts !== undefined && ts < oldest) {
        oldest = ts;
      }
    }
    return oldest;
  }

  /**
   * Validate rate limit configuration
   */
  private validateConfig(config: RateLimitConfig): void {
    if (!Number.isInteger(config.maxRequests) || config.maxRequests < 1) {
      throw new Error('maxRequests must be a positive integer');
    }
    
    if (!Number.isInteger(config.windowSeconds) || config.windowSeconds < 1) {
      throw new Error('windowSeconds must be a positive integer');
    }
    
    if (!['global', 'tenant', 'tool'].includes(config.scope)) {
      throw new Error('scope must be one of: global, tenant, tool');
    }
  }

  /**
   * Start periodic cleanup of expired entries
   */
  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredEntries();
    }, this.cleanupInterval);
    // Do not keep the event loop alive solely for this background timer.
    this.cleanupTimer.unref?.();
    
    // Ensure cleanup runs on process exit
    // Increase max listeners for test environments to prevent warnings
    if (typeof process !== 'undefined' && process.on) {
      // Increase max listeners if we're approaching the limit (common in test environments)
      const currentSIGTERMCount = process.listenerCount('SIGTERM');
      const currentSIGINTCount = process.listenerCount('SIGINT');
      if (currentSIGTERMCount >= 5 || currentSIGINTCount >= 5) {
        process.setMaxListeners(Math.max(20, currentSIGTERMCount + currentSIGINTCount + 10));
      }
      
      // Add cleanup handlers (each instance manages its own cleanup)
      process.on('SIGTERM', () => this.stopCleanup());
      process.on('SIGINT', () => this.stopCleanup());
    }
  }

  /**
   * Stop cleanup timer
   */
  private stopCleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
  }

  /**
   * Cleanup expired entries
   */
  private cleanupExpiredEntries(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];
    
    for (const [key, entry] of this.entries.entries()) {
      const windowMs = entry.config.windowSeconds * 1000;
      
      // Clean up old timestamps within active entries first
      const windowStart = now - windowMs;
      entry.timestamps = entry.timestamps.filter(ts => ts > windowStart);
      entry.windowStart = windowStart;
      
      // Remove entries that are fully expired (2x window past) and have no timestamps
      const expirationTime = entry.windowStart + windowMs * 2; // Keep for 2x window
      if (now > expirationTime && entry.timestamps.length === 0) {
        keysToDelete.push(key);
      }
    }
    
    // Delete expired entries
    for (const key of keysToDelete) {
      this.entries.delete(key);
    }
  }

  /**
   * Destroy rate limiter (cleanup resources)
   */
  destroy(): void {
    this.stopCleanup();
    this.entries.clear();
    // Note: We don't remove process listeners as they may be shared
    // and removing them could affect other instances
  }
}

