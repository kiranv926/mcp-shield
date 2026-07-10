# RateLimiter Usage and Configuration Guide

## Overview

The `RateLimiter` component provides **DoS protection and resource quota management** for TaintGate. It implements a **sliding window algorithm** to efficiently track and limit requests per tenant, tool, or globally.

### Key Features

- **Multi-Scope Rate Limiting**: Global, per-tenant, or per-tool rate limits
- **Sliding Window Algorithm**: Efficient time-window based tracking
- **Automatic Cleanup**: Expired entries are automatically removed to prevent memory leaks
- **Memory-Efficient**: Configurable maximum entries to prevent DoS attacks
- **Thread-Safe**: Safe for concurrent access in multi-tenant environments

### Use Cases

1. **DoS Protection**: Prevent malicious actors from overwhelming the system
2. **Resource Quotas**: Enforce usage limits per tenant or tool
3. **Fair Usage**: Ensure fair resource distribution across tenants
4. **Cost Control**: Limit expensive operations to prevent runaway costs

## Architecture

The RateLimiter uses a **sliding window** algorithm that tracks request timestamps within a configurable time window. When a request arrives:

1. **Check**: Verify if the current request count is within the limit
2. **Filter**: Remove timestamps outside the current window
3. **Record**: Add the current timestamp if allowed
4. **Cleanup**: Periodically remove expired entries

### Storage Structure

Rate limits are stored using composite keys:
- `"global"` - Global rate limit
- `"tenant:tenantId"` - Per-tenant rate limit
- `"tenant:tenantId:tool:toolName"` - Per-tool rate limit

## Configuration

### Basic Configuration

```typescript
import { RateLimiter, RateLimiterConfig } from '@taintgate/core';

// Create a rate limiter with default settings
const rateLimiter = new RateLimiter();

// Or with custom configuration
const config: RateLimiterConfig = {
  // Default rate limit for all entries
  defaultConfig: {
    maxRequests: 100,        // Maximum requests per window
    windowSeconds: 60,      // Time window in seconds
    scope: 'global',         // 'global' | 'tenant' | 'tool'
  },
  cleanupInterval: 60000,   // Cleanup interval in milliseconds (default: 1 minute)
  maxEntries: 10000,        // Maximum entries in memory (DoS protection)
};

const rateLimiter = new RateLimiter(config);
```

### Configuration Options

#### `RateLimiterConfig`

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `defaultConfig` | `RateLimitConfig` | `{ maxRequests: 100, windowSeconds: 60, scope: 'global' }` | Default rate limit configuration for new entries |
| `cleanupInterval` | `number` | `60000` (1 minute) | Interval in milliseconds for automatic cleanup of expired entries |
| `maxEntries` | `number` | `10000` | Maximum number of entries to keep in memory (DoS protection) |

#### `RateLimitConfig`

| Property | Type | Description |
|----------|------|-------------|
| `maxRequests` | `number` | Maximum number of requests allowed within the time window |
| `windowSeconds` | `number` | Time window in seconds (e.g., 60 = 1 minute window) |
| `scope` | `'global' \| 'tenant' \| 'tool'` | Scope of the rate limit: global, per-tenant, or per-tool |

## Usage Examples

### Example 1: Global Rate Limiting

```typescript
import { RateLimiter } from '@taintgate/core';

const rateLimiter = new RateLimiter({
  defaultConfig: {
    maxRequests: 1000,      // 1000 requests
    windowSeconds: 60,      // per minute
    scope: 'global',
  },
});

// Check if a request is allowed (global limit)
const result = await rateLimiter.checkLimit();

if (result.allowed) {
  // Process request
  await processRequest();
  
  // Record the request
  await rateLimiter.recordRequest();
} else {
  // Rate limit exceeded
  console.log(`Rate limit exceeded: ${result.currentCount}/${result.maxRequests}`);
  console.log(`Reset in ${result.resetInSeconds} seconds`);
}
```

### Example 2: Per-Tenant Rate Limiting

```typescript
import { RateLimiter } from '@taintgate/core';

const rateLimiter = new RateLimiter();

// Configure per-tenant rate limits
await rateLimiter.configure(
  {
    maxRequests: 500,       // 500 requests
    windowSeconds: 60,      // per minute
    scope: 'tenant',
  },
  'tenant-123'              // Tenant ID
);

// Check rate limit for a specific tenant
const result = await rateLimiter.checkLimit('tenant-123');

if (result.allowed) {
  await processRequest();
  await rateLimiter.recordRequest('tenant-123');
} else {
  throw new Error(`Tenant rate limit exceeded: ${result.reason}`);
}
```

### Example 3: Per-Tool Rate Limiting

```typescript
import { RateLimiter } from '@taintgate/core';

const rateLimiter = new RateLimiter();

// Configure per-tool rate limits
await rateLimiter.configure(
  {
    maxRequests: 50,        // 50 requests
    windowSeconds: 60,      // per minute
    scope: 'tool',
  },
  'tenant-123',             // Tenant ID
  'expensive-tool'          // Tool name
);

// Check rate limit for a specific tool
const result = await rateLimiter.checkLimit('tenant-123', 'expensive-tool');

if (result.allowed) {
  await processRequest();
  await rateLimiter.recordRequest('tenant-123', 'expensive-tool');
} else {
  throw new Error(`Tool rate limit exceeded: ${result.reason}`);
}
```

### Example 4: Multi-Tier Rate Limiting

```typescript
import { RateLimiter } from '@taintgate/core';

const rateLimiter = new RateLimiter({
  defaultConfig: {
    maxRequests: 1000,      // Global default: 1000 req/min
    windowSeconds: 60,
    scope: 'global',
  },
});

// Configure tenant-level limits (more restrictive)
await rateLimiter.configure(
  {
    maxRequests: 500,       // Tenant limit: 500 req/min
    windowSeconds: 60,
    scope: 'tenant',
  },
  'tenant-123'
);

// Configure tool-level limits (most restrictive)
await rateLimiter.configure(
  {
    maxRequests: 10,        // Tool limit: 10 req/min
    windowSeconds: 60,
    scope: 'tool',
  },
  'tenant-123',
  'expensive-tool'
);

// Check all three levels
const globalResult = await rateLimiter.checkLimit();
const tenantResult = await rateLimiter.checkLimit('tenant-123');
const toolResult = await rateLimiter.checkLimit('tenant-123', 'expensive-tool');

// All must pass
if (globalResult.allowed && tenantResult.allowed && toolResult.allowed) {
  await processRequest();
  await rateLimiter.recordRequest('tenant-123', 'expensive-tool');
}
```

### Example 5: Getting Rate Limit Status

```typescript
import { RateLimiter } from '@taintgate/core';

const rateLimiter = new RateLimiter();

// Get current status without incrementing counter
const status = await rateLimiter.getStatus('tenant-123', 'my-tool');

console.log(`Current usage: ${status.currentCount}/${status.maxRequests}`);
console.log(`Reset in: ${status.resetInSeconds} seconds`);
console.log(`Allowed: ${status.allowed}`);

// Include in API response headers
const headers = {
  'X-RateLimit-Limit': status.maxRequests,
  'X-RateLimit-Remaining': status.maxRequests - status.currentCount,
  'X-RateLimit-Reset': Math.floor(Date.now() / 1000) + status.resetInSeconds,
};
```

### Example 6: Administrative Operations

```typescript
import { RateLimiter } from '@taintgate/core';

const rateLimiter = new RateLimiter();

// Reset rate limit for a specific tenant
await rateLimiter.reset('tenant-123');

// Reset rate limit for a specific tool
await rateLimiter.reset('tenant-123', 'my-tool');

// Reset all rate limits (use with caution!)
await rateLimiter.reset();

// Health check
const isHealthy = await rateLimiter.healthCheck();
if (!isHealthy) {
  console.error('Rate limiter is unhealthy');
}
```

## Integration with ShieldMediator

The RateLimiter is automatically integrated into ShieldMediator and is checked before policy evaluation:

```typescript
import { ShieldMediator, ShieldMediatorConfig } from '@taintgate/core';
import { RateLimiter } from '@taintgate/core';

// Create rate limiter
const rateLimiter = new RateLimiter({
  defaultConfig: {
    maxRequests: 1000,
    windowSeconds: 60,
    scope: 'global',
  },
});

// Configure ShieldMediator with rate limiter
const mediator = new ShieldMediator({
  // ... other config
  rateLimiter: rateLimiter,
});

// Rate limiting is automatically enforced
// If rate limit is exceeded, request is blocked with RATE_LIMITED error code
```

### Rate Limit Error Handling

When a rate limit is exceeded, ShieldMediator returns a JSON-RPC error:

```typescript
{
  jsonrpc: '2.0',
  id: 1,
  error: {
    code: -32002,  // MCPShieldErrorCodes.RATE_LIMITED
    message: 'Too many requests - rate limit exceeded',
    data: {
      reason: 'Rate limit exceeded: 1001/1000 requests in 60s window',
      requestId: '...',
    },
  },
}
```

## API Reference

### `checkLimit(tenantId?, toolName?): Promise<RateLimitResult>`

Checks if a request is within rate limits. This method filters expired timestamps and returns the current status.

**Parameters:**
- `tenantId` (optional): Tenant identifier
- `toolName` (optional): Tool name

**Returns:** `Promise<RateLimitResult>`

**Example:**
```typescript
const result = await rateLimiter.checkLimit('tenant-123', 'my-tool');
if (result.allowed) {
  // Process request
}
```

### `recordRequest(tenantId?, toolName?): Promise<void>`

Records a request for rate limit tracking. Should be called after a request is processed.

**Parameters:**
- `tenantId` (optional): Tenant identifier
- `toolName` (optional): Tool name

**Example:**
```typescript
await rateLimiter.recordRequest('tenant-123', 'my-tool');
```

### `getStatus(tenantId?, toolName?): Promise<RateLimitResult>`

Gets current rate limit status without incrementing the counter. Useful for quota information in responses.

**Parameters:**
- `tenantId` (optional): Tenant identifier
- `toolName` (optional): Tool name

**Returns:** `Promise<RateLimitResult>`

**Example:**
```typescript
const status = await rateLimiter.getStatus('tenant-123');
console.log(`Usage: ${status.currentCount}/${status.maxRequests}`);
```

### `reset(tenantId?, toolName?): Promise<void>`

Resets rate limit counters for a tenant/tool. Useful for administrative actions or testing.

**Parameters:**
- `tenantId` (optional): Tenant identifier (resets all tenants if not provided)
- `toolName` (optional): Tool name (resets all tools if not provided)

**Example:**
```typescript
// Reset specific tool
await rateLimiter.reset('tenant-123', 'my-tool');

// Reset all tools for tenant
await rateLimiter.reset('tenant-123');

// Reset everything (use with caution!)
await rateLimiter.reset();
```

### `configure(config, tenantId?, toolName?): Promise<void>`

Configures rate limits for a tenant/tool.

**Parameters:**
- `config`: `RateLimitConfig` - Rate limit configuration
- `tenantId` (optional): Tenant identifier (for tenant/tool scope)
- `toolName` (optional): Tool name (for tool scope)

**Example:**
```typescript
await rateLimiter.configure(
  {
    maxRequests: 500,
    windowSeconds: 60,
    scope: 'tenant',
  },
  'tenant-123'
);
```

### `healthCheck(): Promise<boolean>`

Performs a health check on the rate limiter.

**Returns:** `Promise<boolean>` - `true` if healthy, `false` otherwise

**Example:**
```typescript
const isHealthy = await rateLimiter.healthCheck();
```

### `destroy(): void`

Cleans up resources and stops the cleanup timer. Call this when shutting down the application.

**Example:**
```typescript
rateLimiter.destroy();
```

## Best Practices

### 1. Choose Appropriate Limits

- **Global limits**: Set high enough to handle normal traffic, low enough to prevent DoS
- **Tenant limits**: Based on subscription tier or SLA
- **Tool limits**: Based on tool cost/complexity (expensive tools should have lower limits)

### 2. Window Size Selection

- **Short windows (1-10 seconds)**: For burst protection
- **Medium windows (60-300 seconds)**: For sustained rate limiting
- **Long windows (3600+ seconds)**: For daily/monthly quotas

### 3. Memory Management

- Set `maxEntries` based on expected number of active tenants/tools
- Monitor memory usage in production
- Use `destroy()` when shutting down to clean up timers

### 4. Error Handling

```typescript
try {
  const result = await rateLimiter.checkLimit(tenantId, toolName);
  if (!result.allowed) {
    // Return rate limit error to client
    return {
      error: {
        code: -32002,
        message: result.reason || 'Rate limit exceeded',
        data: {
          resetInSeconds: result.resetInSeconds,
        },
      },
    };
  }
} catch (error) {
  // Fail-closed: Block request if rate limiter fails
  console.error('Rate limiter error:', error);
  return { error: { code: -32004, message: 'System error' } };
}
```

### 5. Monitoring and Observability

```typescript
// Log rate limit events
const result = await rateLimiter.checkLimit(tenantId, toolName);
if (!result.allowed) {
  logger.warn('Rate limit exceeded', {
    tenantId,
    toolName,
    currentCount: result.currentCount,
    maxRequests: result.maxRequests,
    resetInSeconds: result.resetInSeconds,
  });
}

// Export metrics
metrics.increment('rate_limit.checks', {
  allowed: result.allowed ? 'true' : 'false',
  scope: 'tenant',
});
```

### 6. Testing

```typescript
import { RateLimiter } from '@taintgate/core';

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter({
      cleanupInterval: 100, // Fast cleanup for tests
    });
  });

  afterEach(() => {
    rateLimiter.destroy();
  });

  it('should enforce rate limits', async () => {
    await rateLimiter.configure(
      { maxRequests: 5, windowSeconds: 1, scope: 'tenant' },
      'test-tenant'
    );

    // Make 5 requests (should all pass)
    for (let i = 0; i < 5; i++) {
      const result = await rateLimiter.checkLimit('test-tenant');
      expect(result.allowed).toBe(true);
      await rateLimiter.recordRequest('test-tenant');
    }

    // 6th request should be blocked
    const result = await rateLimiter.checkLimit('test-tenant');
    expect(result.allowed).toBe(false);
  });
});
```

## Troubleshooting

### Issue: Rate limits not working

**Symptoms:** Requests are not being rate limited even when limits are configured.

**Solutions:**
1. Verify configuration is applied: Check that `configure()` is called with the correct scope
2. Check key matching: Ensure `tenantId` and `toolName` match between `configure()` and `checkLimit()`
3. Verify scope: Global scope requires no `tenantId`, tenant scope requires `tenantId`, tool scope requires both

### Issue: Memory leaks

**Symptoms:** Memory usage grows over time.

**Solutions:**
1. Reduce `cleanupInterval`: More frequent cleanup (e.g., 30 seconds instead of 60)
2. Reduce `maxEntries`: Limit the number of entries kept in memory
3. Ensure `destroy()` is called: Clean up when shutting down
4. Monitor entry count: Log `entries.size` periodically

### Issue: Rate limits too strict

**Symptoms:** Legitimate requests are being blocked.

**Solutions:**
1. Increase `maxRequests`: Allow more requests per window
2. Increase `windowSeconds`: Use a longer time window
3. Check for multiple scopes: Ensure you're not hitting multiple limits simultaneously
4. Review tenant/tool limits: May need to adjust per-tenant or per-tool limits

### Issue: Rate limits not resetting

**Symptoms:** Counters don't reset after the window expires.

**Solutions:**
1. Verify window size: Check that `windowSeconds` is correct
2. Check cleanup: Ensure cleanup is running (check `cleanupInterval`)
3. Manual reset: Use `reset()` for testing or emergency resets
4. Check timestamps: Verify that `getStatus()` shows correct `resetInSeconds`

## Performance Considerations

### Sliding Window Algorithm

The RateLimiter uses a sliding window algorithm that:
- **Time Complexity**: O(n) where n is the number of timestamps in the window
- **Space Complexity**: O(n) where n is the number of active entries
- **Cleanup**: O(m) where m is the number of entries (runs periodically)

### Optimization Tips

1. **Shorter windows**: Reduce the number of timestamps stored
2. **Lower maxRequests**: Fewer timestamps per entry
3. **Frequent cleanup**: More frequent cleanup reduces memory usage
4. **Distributed rate limiting**: For high-scale deployments, consider Redis-based implementation

## Security Considerations

### DoS Protection

The RateLimiter provides DoS protection through:
- **Request limiting**: Prevents overwhelming the system
- **Memory limits**: `maxEntries` prevents memory exhaustion
- **Automatic cleanup**: Expired entries are removed automatically

### Multi-Tenant Isolation

Rate limits are isolated per tenant:
- Tenant A cannot affect Tenant B's rate limits
- Each tenant has independent counters
- Composite keys ensure isolation

### Fail-Closed Behavior

If the RateLimiter fails, ShieldMediator blocks requests (fail-closed):
- Errors in `checkLimit()` result in blocking
- System errors use `SYSTEM_ERROR` code (-32004)
- Rate limit errors use `RATE_LIMITED` code (-32002)

## Advanced Usage

### Custom Rate Limiting Strategies

You can implement custom rate limiting by implementing the `IRateLimiter` interface:

```typescript
import { IRateLimiter, RateLimitResult } from '@taintgate/core';

class RedisRateLimiter implements IRateLimiter {
  // Implement interface methods using Redis
  async checkLimit(tenantId?: string, toolName?: string): Promise<RateLimitResult> {
    // Redis-based implementation
  }
  // ... other methods
}
```

### Dynamic Rate Limit Adjustment

```typescript
// Adjust rate limits based on system load
const systemLoad = await getSystemLoad();

if (systemLoad > 0.8) {
  // Reduce rate limits under high load
  await rateLimiter.configure(
    { maxRequests: 100, windowSeconds: 60, scope: 'global' }
  );
} else {
  // Normal rate limits
  await rateLimiter.configure(
    { maxRequests: 1000, windowSeconds: 60, scope: 'global' }
  );
}
```

## Related Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) - Overall system architecture
- [POLICY_MANAGER_USAGE.md](./POLICY_MANAGER_USAGE.md) - Policy management
- [README.md](./README.md) - Project overview

## Support

For issues, questions, or contributions, please see:
- [GitHub Issues](https://github.com/kiranv926/taintgate/issues)
- [Security Policy](./SECURITY.md)

