/**
 * TaintGate: RateLimiter Unit Tests
 * 
 * Tests for the RateLimiter implementation.
 */

import { RateLimiter } from '../../core/RateLimiter';
import type { RateLimiterConfig } from '../../core/RateLimiter';
import type { RateLimitConfig } from '../../interfaces/IRateLimiter';

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter();
  });

  afterEach(() => {
    rateLimiter.destroy();
  });

  describe('checkLimit', () => {
    it('should allow requests within limit', async () => {
      const config: RateLimitConfig = {
        maxRequests: 5,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      // Make 4 requests (under limit)
      for (let i = 0; i < 4; i++) {
        await rateLimiter.recordRequest();
        const result = await rateLimiter.checkLimit();
        expect(result.allowed).toBe(true);
        expect(result.currentCount).toBe(i + 1);
        expect(result.maxRequests).toBe(5);
      }
    });

    it('should block requests exceeding limit', async () => {
      const config: RateLimitConfig = {
        maxRequests: 3,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      // Make 3 requests (at limit)
      for (let i = 0; i < 3; i++) {
        await rateLimiter.recordRequest();
      }
      
      // 4th request should be blocked
      const result = await rateLimiter.checkLimit();
      expect(result.allowed).toBe(false);
      expect(result.currentCount).toBe(3);
      expect(result.maxRequests).toBe(3);
      expect(result.reason).toContain('Rate limit exceeded');
    });

    it('should enforce per-tenant limits', async () => {
      const config: RateLimitConfig = {
        maxRequests: 2,
        windowSeconds: 60,
        scope: 'tenant',
      };
      
      await rateLimiter.configure(config, 'tenant-A');
      await rateLimiter.configure(config, 'tenant-B');
      
      // Tenant A: 2 requests
      await rateLimiter.recordRequest('tenant-A');
      await rateLimiter.recordRequest('tenant-A');
      
      // Tenant B: 2 requests
      await rateLimiter.recordRequest('tenant-B');
      await rateLimiter.recordRequest('tenant-B');
      
      // Both should be at limit
      const resultA = await rateLimiter.checkLimit('tenant-A');
      const resultB = await rateLimiter.checkLimit('tenant-B');
      
      expect(resultA.allowed).toBe(false);
      expect(resultB.allowed).toBe(false);
      expect(resultA.currentCount).toBe(2);
      expect(resultB.currentCount).toBe(2);
    });

    it('should enforce per-tool limits', async () => {
      const config: RateLimitConfig = {
        maxRequests: 2,
        windowSeconds: 60,
        scope: 'tool',
      };
      
      await rateLimiter.configure(config, 'tenant-A', 'tool-1');
      await rateLimiter.configure(config, 'tenant-A', 'tool-2');
      
      // Tool 1: 2 requests
      await rateLimiter.recordRequest('tenant-A', 'tool-1');
      await rateLimiter.recordRequest('tenant-A', 'tool-1');
      
      // Tool 2: 2 requests
      await rateLimiter.recordRequest('tenant-A', 'tool-2');
      await rateLimiter.recordRequest('tenant-A', 'tool-2');
      
      // Both should be at limit
      const result1 = await rateLimiter.checkLimit('tenant-A', 'tool-1');
      const result2 = await rateLimiter.checkLimit('tenant-A', 'tool-2');
      
      expect(result1.allowed).toBe(false);
      expect(result2.allowed).toBe(false);
    });

    it('should reset count after window expires', async () => {
      const config: RateLimitConfig = {
        maxRequests: 2,
        windowSeconds: 1, // 1 second window
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      // Make 2 requests (at limit)
      await rateLimiter.recordRequest();
      await rateLimiter.recordRequest();
      
      const result1 = await rateLimiter.checkLimit();
      expect(result1.allowed).toBe(false);
      
      // Wait for window to expire
      await new Promise(resolve => setTimeout(resolve, 1100));
      
      // Should be allowed again
      const result2 = await rateLimiter.checkLimit();
      expect(result2.allowed).toBe(true);
      expect(result2.currentCount).toBe(0);
    });

    it('should calculate reset time correctly', async () => {
      const config: RateLimitConfig = {
        maxRequests: 5,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      await rateLimiter.recordRequest();
      const result = await rateLimiter.checkLimit();
      
      expect(result.resetInSeconds).toBeGreaterThan(0);
      expect(result.resetInSeconds).toBeLessThanOrEqual(60);
    });
  });

  describe('tryConsume (atomic check-and-record)', () => {
    it('should not exceed the limit under many concurrent consumes (TOCTOU regression)', async () => {
      const config: RateLimitConfig = {
        maxRequests: 5,
        windowSeconds: 60,
        scope: 'global',
      };

      await rateLimiter.configure(config);

      // Fire far more concurrent consumes than the limit allows. Because tryConsume
      // checks-and-records atomically, exactly `maxRequests` must be allowed -- the
      // rest must be denied. The old check-then-record pattern would let all pass.
      const attempts = 50;
      const results = await Promise.all(
        Array.from({ length: attempts }, async () => rateLimiter.tryConsume())
      );

      const allowedCount = results.filter((r) => r.allowed).length;
      const deniedCount = results.filter((r) => !r.allowed).length;

      expect(allowedCount).toBe(5);
      expect(deniedCount).toBe(attempts - 5);

      // State reflects exactly the allowed consumes.
      const status = await rateLimiter.getStatus();
      expect(status.currentCount).toBe(5);
      expect(status.allowed).toBe(false);
    });

    it('should consume a token only when allowed', async () => {
      const config: RateLimitConfig = {
        maxRequests: 2,
        windowSeconds: 60,
        scope: 'global',
      };

      await rateLimiter.configure(config);

      const first = rateLimiter.tryConsume();
      const second = rateLimiter.tryConsume();
      expect(first.allowed).toBe(true);
      expect(second.allowed).toBe(true);
      expect(second.currentCount).toBe(2);

      // Over the limit: denied, and no further tokens consumed.
      const denied = rateLimiter.tryConsume();
      expect(denied.allowed).toBe(false);
      expect(denied.currentCount).toBe(2);
      expect(denied.reason).toContain('Rate limit exceeded');

      const status = await rateLimiter.getStatus();
      expect(status.currentCount).toBe(2);
    });

    it('should isolate consumption per tenant', async () => {
      const config: RateLimitConfig = {
        maxRequests: 1,
        windowSeconds: 60,
        scope: 'tenant',
      };

      await rateLimiter.configure(config, 'tenant-A');
      await rateLimiter.configure(config, 'tenant-B');

      expect(rateLimiter.tryConsume('tenant-A').allowed).toBe(true);
      expect(rateLimiter.tryConsume('tenant-A').allowed).toBe(false);
      // tenant-B is unaffected by tenant-A's consumption.
      expect(rateLimiter.tryConsume('tenant-B').allowed).toBe(true);
    });
  });

  describe('recordRequest', () => {
    it('should increment request count', async () => {
      const config: RateLimitConfig = {
        maxRequests: 10,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      for (let i = 0; i < 5; i++) {
        await rateLimiter.recordRequest();
        const status = await rateLimiter.getStatus();
        expect(status.currentCount).toBe(i + 1);
      }
    });

    it('should record requests per tenant', async () => {
      await rateLimiter.recordRequest('tenant-A');
      await rateLimiter.recordRequest('tenant-B');
      
      const statusA = await rateLimiter.getStatus('tenant-A');
      const statusB = await rateLimiter.getStatus('tenant-B');
      
      expect(statusA.currentCount).toBe(1);
      expect(statusB.currentCount).toBe(1);
    });

    it('should record requests per tool', async () => {
      await rateLimiter.recordRequest('tenant-A', 'tool-1');
      await rateLimiter.recordRequest('tenant-A', 'tool-2');
      
      const status1 = await rateLimiter.getStatus('tenant-A', 'tool-1');
      const status2 = await rateLimiter.getStatus('tenant-A', 'tool-2');
      
      expect(status1.currentCount).toBe(1);
      expect(status2.currentCount).toBe(1);
    });
  });

  describe('getStatus', () => {
    it('should return status without incrementing', async () => {
      const config: RateLimitConfig = {
        maxRequests: 5,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      await rateLimiter.recordRequest();
      
      const status1 = await rateLimiter.getStatus();
      const status2 = await rateLimiter.getStatus();
      
      // Count should not increment between calls
      expect(status1.currentCount).toBe(1);
      expect(status2.currentCount).toBe(1);
    });

    it('should return default status for non-existent entries', async () => {
      const status = await rateLimiter.getStatus('new-tenant');
      
      expect(status.allowed).toBe(true);
      expect(status.currentCount).toBe(0);
      expect(status.maxRequests).toBe(100); // Default
    });
  });

  describe('reset', () => {
    it('should reset all entries when no parameters provided', async () => {
      await rateLimiter.recordRequest('tenant-A');
      await rateLimiter.recordRequest('tenant-B');
      
      await rateLimiter.reset();
      
      const statusA = await rateLimiter.getStatus('tenant-A');
      const statusB = await rateLimiter.getStatus('tenant-B');
      
      expect(statusA.currentCount).toBe(0);
      expect(statusB.currentCount).toBe(0);
    });

    it('should reset all entries for a tenant', async () => {
      await rateLimiter.recordRequest('tenant-A', 'tool-1');
      await rateLimiter.recordRequest('tenant-A', 'tool-2');
      await rateLimiter.recordRequest('tenant-B', 'tool-1');
      
      await rateLimiter.reset('tenant-A');
      
      const statusA1 = await rateLimiter.getStatus('tenant-A', 'tool-1');
      const statusA2 = await rateLimiter.getStatus('tenant-A', 'tool-2');
      const statusB1 = await rateLimiter.getStatus('tenant-B', 'tool-1');
      
      expect(statusA1.currentCount).toBe(0);
      expect(statusA2.currentCount).toBe(0);
      expect(statusB1.currentCount).toBe(1); // Not reset
    });

    it('should reset specific tenant:tool entry', async () => {
      await rateLimiter.recordRequest('tenant-A', 'tool-1');
      await rateLimiter.recordRequest('tenant-A', 'tool-2');
      
      await rateLimiter.reset('tenant-A', 'tool-1');
      
      const status1 = await rateLimiter.getStatus('tenant-A', 'tool-1');
      const status2 = await rateLimiter.getStatus('tenant-A', 'tool-2');
      
      expect(status1.currentCount).toBe(0);
      expect(status2.currentCount).toBe(1); // Not reset
    });
  });

  describe('configure', () => {
    it('should configure global rate limits', async () => {
      const config: RateLimitConfig = {
        maxRequests: 50,
        windowSeconds: 120,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      const status = await rateLimiter.getStatus();
      expect(status.maxRequests).toBe(50);
    });

    it('should configure per-tenant rate limits', async () => {
      const config: RateLimitConfig = {
        maxRequests: 20,
        windowSeconds: 30,
        scope: 'tenant',
      };
      
      await rateLimiter.configure(config, 'tenant-A');
      
      const status = await rateLimiter.getStatus('tenant-A');
      expect(status.maxRequests).toBe(20);
    });

    it('should configure per-tool rate limits', async () => {
      const config: RateLimitConfig = {
        maxRequests: 10,
        windowSeconds: 15,
        scope: 'tool',
      };
      
      await rateLimiter.configure(config, 'tenant-A', 'tool-1');
      
      const status = await rateLimiter.getStatus('tenant-A', 'tool-1');
      expect(status.maxRequests).toBe(10);
    });

    it('should validate configuration', async () => {
      await expect(
        rateLimiter.configure({
          maxRequests: 0,
          windowSeconds: 60,
          scope: 'global',
        })
      ).rejects.toThrow('maxRequests must be a positive integer');

      await expect(
        rateLimiter.configure({
          maxRequests: 100,
          windowSeconds: 0,
          scope: 'global',
        })
      ).rejects.toThrow('windowSeconds must be a positive integer');

      await expect(
        rateLimiter.configure({
          maxRequests: 100,
          windowSeconds: 60,
          scope: 'invalid' as any,
        })
      ).rejects.toThrow('scope must be one of: global, tenant, tool');
    });
  });

  describe('healthCheck', () => {
    it('should return true when healthy', async () => {
      const healthy = await rateLimiter.healthCheck();
      expect(healthy).toBe(true);
    });

    it('should return true when entries are within limit', async () => {
      // Create many entries
      for (let i = 0; i < 100; i++) {
        await rateLimiter.recordRequest(`tenant-${i}`);
      }
      
      const healthy = await rateLimiter.healthCheck();
      expect(healthy).toBe(true);
    });
  });

  describe('Sliding Window', () => {
    it('should only count requests within the window', async () => {
      const config: RateLimitConfig = {
        maxRequests: 3,
        windowSeconds: 2, // 2 second window
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      // Make 3 requests quickly
      await rateLimiter.recordRequest();
      await rateLimiter.recordRequest();
      await rateLimiter.recordRequest();
      
      const result1 = await rateLimiter.checkLimit();
      expect(result1.allowed).toBe(false);
      expect(result1.currentCount).toBe(3);
      
      // Wait 1 second (still in window)
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const result2 = await rateLimiter.checkLimit();
      expect(result2.allowed).toBe(false);
      expect(result2.currentCount).toBe(3);
      
      // Wait another 1.5 seconds (window expired)
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const result3 = await rateLimiter.checkLimit();
      expect(result3.allowed).toBe(true);
      expect(result3.currentCount).toBe(0);
    });
  });

  describe('Memory Management', () => {
    it('should enforce max entries limit', async () => {
      const config: RateLimiterConfig = {
        maxEntries: 5,
      };
      
      const limitedRateLimiter = new RateLimiter(config);
      
      // Create more entries than max
      for (let i = 0; i < 10; i++) {
        await limitedRateLimiter.recordRequest(`tenant-${i}`);
      }
      
      // Should not exceed max entries
      const healthy = await limitedRateLimiter.healthCheck();
      expect(healthy).toBe(true);
      
      limitedRateLimiter.destroy();
    });

    it('should cleanup expired entries', async () => {
      const config: RateLimiterConfig = {
        cleanupInterval: 100, // 100ms cleanup interval
      };
      
      const cleanupRateLimiter = new RateLimiter(config);
      
      const rateLimitConfig: RateLimitConfig = {
        maxRequests: 5,
        windowSeconds: 1, // 1 second window
        scope: 'tenant', // Use tenant scope since we're testing with tenant-A
      };
      
      // Configure for the specific tenant
      await cleanupRateLimiter.configure(rateLimitConfig, 'tenant-A');
      
      // Create entry
      await cleanupRateLimiter.recordRequest('tenant-A');
      
      // Verify entry exists
      const statusBefore = await cleanupRateLimiter.getStatus('tenant-A');
      expect(statusBefore.currentCount).toBe(1);
      
      // Wait for window to expire (1 second) plus cleanup interval to ensure cleanup runs
      await new Promise(resolve => setTimeout(resolve, 1200));
      
      // getStatus filters timestamps, so currentCount should be 0 after window expires
      const status = await cleanupRateLimiter.getStatus('tenant-A');
      expect(status.currentCount).toBe(0);
      
      cleanupRateLimiter.destroy();
    });
  });

  describe('Edge Cases', () => {
    it('should handle undefined tenantId and toolName', async () => {
      await rateLimiter.recordRequest();
      const result = await rateLimiter.checkLimit();
      
      expect(result.allowed).toBe(true);
      expect(result.currentCount).toBe(1);
    });

    it('should handle concurrent requests', async () => {
      const config: RateLimitConfig = {
        maxRequests: 10,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      // Fire 10 concurrent requests
      const promises = Array.from({ length: 10 }, () =>
        rateLimiter.recordRequest()
      );
      
      await Promise.all(promises);
      
      const result = await rateLimiter.checkLimit();
      expect(result.currentCount).toBe(10);
      expect(result.allowed).toBe(false);
    });

    it('should handle very small time windows', async () => {
      const config: RateLimitConfig = {
        maxRequests: 2,
        windowSeconds: 1,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      await rateLimiter.recordRequest();
      await rateLimiter.recordRequest();
      
      const result = await rateLimiter.checkLimit();
      expect(result.allowed).toBe(false);
    });

    it('should handle very large request limits', async () => {
      const config: RateLimitConfig = {
        maxRequests: 10000,
        windowSeconds: 60,
        scope: 'global',
      };
      
      await rateLimiter.configure(config);
      
      // Make many requests
      for (let i = 0; i < 1000; i++) {
        await rateLimiter.recordRequest();
      }
      
      const result = await rateLimiter.checkLimit();
      expect(result.allowed).toBe(true);
      expect(result.currentCount).toBe(1000);
    });
  });

  describe('destroy', () => {
    it('should cleanup resources on destroy', () => {
      rateLimiter.recordRequest('tenant-A');
      
      rateLimiter.destroy();
      
      // After destroy, should be able to create new instance
      const newRateLimiter = new RateLimiter();
      expect(newRateLimiter).toBeDefined();
      
      newRateLimiter.destroy();
    });
  });
});

