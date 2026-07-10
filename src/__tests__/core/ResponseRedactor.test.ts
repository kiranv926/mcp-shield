/**
 * MCP-Shield: ResponseRedactor Unit Tests
 * 
 * Tests for the ResponseRedactor implementation.
 */

import { ResponseRedactor } from '../../core/ResponseRedactor';
import type { ResponseRedactorConfig } from '../../core/ResponseRedactor';
import type { PolicyDecision } from '../../types/governance';
import { createRiskScore } from '../../types/common';

describe('ResponseRedactor', () => {
  let redactor: ResponseRedactor;

  beforeEach(() => {
    redactor = new ResponseRedactor();
  });

  describe('redact', () => {
    it('should return response unchanged if error is present', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        error: { code: -32000, message: 'Server error' },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      expect(result).toEqual(response);
    });

    it('should return response unchanged if result is null', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: null,
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      expect(result).toEqual(response);
    });

    it('should apply Tier 1 field masking', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          username: 'john_doe',
          password: 'secret123',
          email: 'john@example.com',
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      
      expect(resultObj.password).toBe('[REDACTED]');
      expect(resultObj.username).toBe('john_doe'); // Not in default mask fields
    });

    it('should always apply Tier 1 masking regardless of riskBreakdown presence', async () => {
      // CRITICAL FIX TEST: Tier 1 should always apply, not conditional on riskBreakdown
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          password: 'secret123',
          token: 'abc123',
        },
      };

      // Decision without riskBreakdown
      const decisionWithoutBreakdown: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decisionWithoutBreakdown);
      const resultObj = result.result as Record<string, unknown>;
      
      // Tier 1 masking should still apply
      expect(resultObj.password).toBe('[REDACTED]');
      expect(resultObj.token).toBe('[REDACTED]');
    });

    it('should apply Tier 2 pattern scrubbing', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          message: 'Contact me at john@example.com or call 555-123-4567',
          ssn: '123-45-6789',
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      
      // Email should be scrubbed
      expect(resultObj.message).not.toContain('john@example.com');
      expect(resultObj.message).toContain('[REDACTED]');
      
      // Phone should be scrubbed
      expect(resultObj.message).not.toContain('555-123-4567');
      
      // SSN should be scrubbed
      expect(resultObj.ssn).not.toContain('123-45-6789');
    });

    it('should apply both Tier 1 and Tier 2 sanitization', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          password: 'secret123',
          message: 'Email: user@example.com',
          creditCard: '1234-5678-9012-3456',
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      
      // Tier 1: password field should be masked
      expect(resultObj.password).toBe('[REDACTED]');
      
      // Tier 2: email in message should be scrubbed
      expect(resultObj.message).not.toContain('user@example.com');
      
      // Tier 2: credit card should be scrubbed
      expect(resultObj.creditCard).not.toContain('1234-5678-9012-3456');
    });
  });

  describe('maskFields', () => {
    it('should mask specified fields in object', () => {
      const data = {
        username: 'john',
        password: 'secret123',
        email: 'john@example.com',
      };

      const masked = redactor.maskFields(data, ['password', 'email']);
      const maskedObj = masked as Record<string, unknown>;

      expect(maskedObj.password).toBe('[REDACTED]');
      expect(maskedObj.email).toBe('[REDACTED]');
      expect(maskedObj.username).toBe('john');
    });

    it('should handle case-insensitive field matching', () => {
      const data = {
        Password: 'secret123',
        PASSWORD: 'secret456',
        password: 'secret789',
      };

      const masked = redactor.maskFields(data, ['password']);
      const maskedObj = masked as Record<string, unknown>;

      expect(maskedObj.Password).toBe('[REDACTED]');
      expect(maskedObj.PASSWORD).toBe('[REDACTED]');
      expect(maskedObj.password).toBe('[REDACTED]');
    });

    it('should mask fields in nested objects', () => {
      const data = {
        user: {
          name: 'John',
          password: 'secret123',
          profile: {
            email: 'john@example.com',
            phone: '555-1234',
          },
        },
      };

      const masked = redactor.maskFields(data, ['password', 'email']);
      const maskedObj = masked as Record<string, unknown>;
      const userObj = maskedObj.user as Record<string, unknown>;
      const profileObj = userObj.profile as Record<string, unknown>;

      expect(userObj.password).toBe('[REDACTED]');
      expect(profileObj.email).toBe('[REDACTED]');
      expect(profileObj.phone).toBe('555-1234'); // Not in mask list
    });

    it('should mask fields in arrays', () => {
      const data = [
        { username: 'user1', password: 'pass1' },
        { username: 'user2', password: 'pass2' },
      ];

      const masked = redactor.maskFields(data, ['password']);
      const maskedArray = masked as Array<Record<string, unknown>>;

      expect(maskedArray[0]?.password).toBe('[REDACTED]');
      expect(maskedArray[1]?.password).toBe('[REDACTED]');
      expect(maskedArray[0]?.username).toBe('user1');
    });

    it('should respect depth limit for DoS protection', () => {
      // Create deeply nested object
      let data: any = { value: 'test' };
      for (let i = 0; i < 20; i++) {
        data = { nested: data };
      }

      const masked = redactor.maskFields(data, ['value']);
      
      // Should not crash, but may not mask deeply nested values
      expect(masked).toBeDefined();
    });

    it('should return primitive values unchanged', () => {
      expect(redactor.maskFields('string', ['field'])).toBe('string');
      expect(redactor.maskFields(123, ['field'])).toBe(123);
      expect(redactor.maskFields(true, ['field'])).toBe(true);
      expect(redactor.maskFields(null, ['field'])).toBe(null);
    });

    it('should return data unchanged if no fields to mask', () => {
      const data = { username: 'john', password: 'secret' };
      const masked = redactor.maskFields(data, []);
      
      expect(masked).toEqual(data);
    });
  });

  describe('scrubPatterns', () => {
    it('should scrub email addresses', () => {
      const text = 'Contact me at john@example.com for details';
      const scrubbed = redactor.scrubPatterns(text, [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g]);
      
      expect(scrubbed).not.toContain('john@example.com');
      expect(scrubbed).toContain('[REDACTED]');
    });

    it('should scrub SSN patterns', () => {
      const text = 'SSN: 123-45-6789';
      const scrubbed = redactor.scrubPatterns(text, [/\b\d{3}-\d{2}-\d{4}\b/g]);
      
      expect(scrubbed).not.toContain('123-45-6789');
      expect(scrubbed).toContain('[REDACTED]');
    });

    it('should scrub credit card patterns', () => {
      const text = 'Card: 1234-5678-9012-3456';
      const scrubbed = redactor.scrubPatterns(text, [/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g]);
      
      expect(scrubbed).not.toContain('1234-5678-9012-3456');
      expect(scrubbed).toContain('[REDACTED]');
    });

    it('should scrub phone number patterns', () => {
      const text = 'Call 555-123-4567 or (555) 123-4567';
      const scrubbed = redactor.scrubPatterns(text, [/\b\(?\d{3}\)?[-.]?\s?\d{3}[-.]?\d{4}\b/g]);
      
      expect(scrubbed).not.toContain('555-123-4567');
      expect(scrubbed).not.toContain('(555) 123-4567');
      expect(scrubbed).toContain('[REDACTED]');
    });

    it('should scrub multiple patterns', () => {
      const text = 'Email: user@example.com, Phone: 555-123-4567, SSN: 123-45-6789';
      const patterns = [
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        /\b\(?\d{3}\)?[-.]?\s?\d{3}[-.]?\d{4}\b/g,
        /\b\d{3}-\d{2}-\d{4}\b/g,
      ];
      
      const scrubbed = redactor.scrubPatterns(text, patterns);
      
      expect(scrubbed).not.toContain('user@example.com');
      expect(scrubbed).not.toContain('555-123-4567');
      expect(scrubbed).not.toContain('123-45-6789');
    });

    it('should not have regex state pollution between calls', () => {
      // CRITICAL FIX TEST: Global regex patterns should not retain state between calls
      const pattern = /\b\d{3}-\d{2}-\d{4}\b/g;
      const text1 = 'SSN: 123-45-6789';
      const text2 = 'SSN: 987-65-4321';
      
      // First call
      const scrubbed1 = redactor.scrubPatterns(text1, [pattern]);
      expect(scrubbed1).not.toContain('123-45-6789');
      expect(scrubbed1).toContain('[REDACTED]');
      
      // Second call - should work correctly even if pattern had state
      const scrubbed2 = redactor.scrubPatterns(text2, [pattern]);
      expect(scrubbed2).not.toContain('987-65-4321');
      expect(scrubbed2).toContain('[REDACTED]');
      
      // Verify pattern state doesn't affect subsequent matches
      const text3 = 'SSN: 111-22-3333';
      const scrubbed3 = redactor.scrubPatterns(text3, [pattern]);
      expect(scrubbed3).not.toContain('111-22-3333');
      expect(scrubbed3).toContain('[REDACTED]');
    });

    it('should handle empty string', () => {
      expect(redactor.scrubPatterns('', [/\d+/g])).toBe('');
    });

    it('should truncate very long strings for DoS protection', () => {
      const longText = 'a'.repeat(20000); // 20KB
      const scrubbed = redactor.scrubPatterns(longText, [/\d+/g]);
      
      expect(scrubbed.length).toBeLessThanOrEqual(10000 + 20); // maxStringLength + "... [TRUNCATED]"
      expect(scrubbed).toContain('[TRUNCATED]');
    });

    it('should handle non-string input', () => {
      expect(redactor.scrubPatterns(null as any, [/\d+/g])).toBe(null);
      expect(redactor.scrubPatterns(undefined as any, [/\d+/g])).toBe(undefined);
      expect(redactor.scrubPatterns(123 as any, [/\d+/g])).toBe(123);
    });
  });

  describe('Nested Data Structures', () => {
    it('should sanitize nested objects with arrays', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          users: [
            { name: 'John', email: 'john@example.com', password: 'secret1' },
            { name: 'Jane', email: 'jane@example.com', password: 'secret2' },
          ],
          metadata: {
            apiKey: 'sk_live_abc123xyz',
            contact: 'Call 555-123-4567',
          },
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      const users = resultObj.users as Array<Record<string, unknown>>;
      const metadata = resultObj.metadata as Record<string, unknown>;

      // Tier 1: passwords should be masked
      expect(users[0]?.password).toBe('[REDACTED]');
      expect(users[1]?.password).toBe('[REDACTED]');
      expect(metadata.apiKey).toBe('[REDACTED]');

      // Tier 2: emails should be scrubbed
      expect(users[0]?.email).not.toContain('john@example.com');
      expect(users[1]?.email).not.toContain('jane@example.com');
      
      // Tier 2: phone should be scrubbed
      expect(metadata.contact).not.toContain('555-123-4567');
    });

    it('should handle deeply nested structures', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          level1: {
            level2: {
              level3: {
                level4: {
                  secret: 'hidden',
                  email: 'deep@example.com',
                },
              },
            },
          },
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      const level1 = resultObj.level1 as Record<string, unknown>;
      const level2 = level1.level2 as Record<string, unknown>;
      const level3 = level2.level3 as Record<string, unknown>;
      const level4 = level3.level4 as Record<string, unknown>;

      expect(level4.secret).toBe('[REDACTED]');
      expect(level4.email).not.toContain('deep@example.com');
    });
  });

  describe('Configuration Validation', () => {
    it('should validate maxDepth range', () => {
      expect(() => {
        new ResponseRedactor({ maxDepth: 0 });
      }).toThrow('maxDepth must be an integer between 1 and 100');

      expect(() => {
        new ResponseRedactor({ maxDepth: 101 });
      }).toThrow('maxDepth must be an integer between 1 and 100');

      expect(() => {
        new ResponseRedactor({ maxDepth: 1.5 });
      }).toThrow('maxDepth must be an integer between 1 and 100');

      // Valid values should not throw
      expect(() => {
        new ResponseRedactor({ maxDepth: 1 });
      }).not.toThrow();
      expect(() => {
        new ResponseRedactor({ maxDepth: 50 });
      }).not.toThrow();
      expect(() => {
        new ResponseRedactor({ maxDepth: 100 });
      }).not.toThrow();
    });

    it('should validate maxStringLength range', () => {
      expect(() => {
        new ResponseRedactor({ maxStringLength: 0 });
      }).toThrow('maxStringLength must be an integer between 1 and 1,000,000');

      expect(() => {
        new ResponseRedactor({ maxStringLength: 1000001 });
      }).toThrow('maxStringLength must be an integer between 1 and 1,000,000');

      // Valid values should not throw
      expect(() => {
        new ResponseRedactor({ maxStringLength: 1 });
      }).not.toThrow();
      expect(() => {
        new ResponseRedactor({ maxStringLength: 10000 });
      }).not.toThrow();
    });

    it('should validate replacement string', () => {
      expect(() => {
        new ResponseRedactor({ replacement: '' });
      }).toThrow('replacement cannot be empty');

      expect(() => {
        new ResponseRedactor({ replacement: 'x'.repeat(101) });
      }).toThrow('replacement cannot exceed 100 characters');

      expect(() => {
        new ResponseRedactor({ replacement: null as any });
      }).toThrow('replacement must be a string');

      // Valid values should not throw
      expect(() => {
        new ResponseRedactor({ replacement: '[REDACTED]' });
      }).not.toThrow();
    });

    it('should validate piiPatterns array', () => {
      expect(() => {
        new ResponseRedactor({ piiPatterns: null as any });
      }).toThrow('piiPatterns must be an array');

      expect(() => {
        new ResponseRedactor({ piiPatterns: [null as any] });
      }).toThrow(/piiPatterns\[0\] must be a RegExp instance/);

      expect(() => {
        new ResponseRedactor({ piiPatterns: ['not a regex' as any] });
      }).toThrow(/piiPatterns\[0\] must be a RegExp instance/);

      // Note: Testing invalid regex patterns is tricky because invalid patterns
      // (like new RegExp('[')) throw during construction, not during our validation.
      // Our validation recompiles patterns to ensure they're valid, which would catch
      // patterns that can be constructed but fail to recompile. Since we can't easily
      // create such a pattern, we verify that valid patterns pass validation.
      // The validation logic itself is tested by ensuring valid patterns work correctly.

      // Valid patterns should not throw
      expect(() => {
        new ResponseRedactor({ piiPatterns: [/\d+/g] });
      }).not.toThrow();
    });

    it('should validate defaultMaskFields array', () => {
      expect(() => {
        new ResponseRedactor({ defaultMaskFields: null as any });
      }).toThrow('defaultMaskFields must be an array');

      expect(() => {
        new ResponseRedactor({ defaultMaskFields: [''] });
      }).toThrow('defaultMaskFields[0] must be a non-empty string');

      expect(() => {
        new ResponseRedactor({ defaultMaskFields: [null as any] });
      }).toThrow('defaultMaskFields[0] must be a non-empty string');

      // Valid values should not throw
      expect(() => {
        new ResponseRedactor({ defaultMaskFields: ['password', 'token'] });
      }).not.toThrow();
    });
  });

  describe('Configuration', () => {
    it('should use custom mask fields', () => {
      const customRedactor = new ResponseRedactor({
        defaultMaskFields: ['customField', 'anotherField'],
      });

      const data = {
        customField: 'value1',
        anotherField: 'value2',
        normalField: 'value3',
      };

      const masked = customRedactor.maskFields(data, ['customField', 'anotherField']);
      const maskedObj = masked as Record<string, unknown>;

      expect(maskedObj.customField).toBe('[REDACTED]');
      expect(maskedObj.anotherField).toBe('[REDACTED]');
      expect(maskedObj.normalField).toBe('value3');
    });

    it('should use custom replacement string', () => {
      const customRedactor = new ResponseRedactor({
        replacement: '***MASKED***',
      });

      const data = { password: 'secret' };
      const masked = customRedactor.maskFields(data, ['password']);
      const maskedObj = masked as Record<string, unknown>;

      expect(maskedObj.password).toBe('***MASKED***');
    });

    it('should use custom PII patterns', () => {
      const customPattern = /\bCUSTOM-\d+\b/g;
      const customRedactor = new ResponseRedactor({
        piiPatterns: [customPattern],
      });

      const text = 'ID: CUSTOM-12345';
      const scrubbed = customRedactor.scrubPatterns(text, [customPattern]);

      expect(scrubbed).not.toContain('CUSTOM-12345');
      expect(scrubbed).toContain('[REDACTED]');
    });

    it('should get current configuration', () => {
      const config = redactor.getConfig();
      
      expect(config.maskFields).toBeDefined();
      expect(config.scrubPatterns).toBeDefined();
      expect(config.replacement).toBe('[REDACTED]');
      expect(config.maxDepth).toBe(10);
      expect(config.maxStringLength).toBe(10000);
    });

    it('should update configuration', () => {
      redactor.updateConfig({
        replacement: '***',
        maxDepth: 5,
      });

      const config = redactor.getConfig();
      expect(config.replacement).toBe('***');
      expect(config.maxDepth).toBe(5);
      expect(config.maxStringLength).toBe(10000); // Unchanged
    });
  });

  describe('DoS Protection', () => {
    it('should limit recursion depth', () => {
      // Create object with depth > maxDepth
      let deepData: any = { value: 'test' };
      for (let i = 0; i < 15; i++) {
        deepData = { nested: deepData };
      }

      const masked = redactor.maskFields(deepData, ['value']);
      
      // Should not crash
      expect(masked).toBeDefined();
    });

    it('should limit string length', () => {
      const longText = 'a'.repeat(15000);
      const scrubbed = redactor.scrubPatterns(longText, [/\d+/g]);
      
      expect(scrubbed.length).toBeLessThanOrEqual(10000 + 20);
      expect(scrubbed).toContain('[TRUNCATED]');
    });

    it('should handle circular references gracefully', () => {
      const data: any = { value: 'test' };
      data.self = data; // Circular reference

      // Should not crash (though may not handle perfectly)
      expect(() => {
        redactor.maskFields(data, ['value']);
      }).not.toThrow();
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty objects', () => {
      expect(redactor.maskFields({}, ['field'])).toEqual({});
      expect(redactor.scrubPatterns('', [/\d+/g])).toBe('');
    });

    it('should handle empty arrays', () => {
      expect(redactor.maskFields([], ['field'])).toEqual([]);
    });

    it('should preserve response ID and jsonrpc version', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 123,
        result: { password: 'secret' },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      
      expect(result.jsonrpc).toBe('2.0');
      expect(result.id).toBe(123);
    });

    it('should handle mixed data types in arrays', () => {
      const data = [
        'string',
        123,
        { password: 'secret' },
        null,
        true,
      ];

      const masked = redactor.maskFields(data, ['password']);
      const maskedArray = masked as Array<unknown>;

      expect(maskedArray[0]).toBe('string');
      expect(maskedArray[1]).toBe(123);
      expect((maskedArray[2] as Record<string, unknown>).password).toBe('[REDACTED]');
      expect(maskedArray[3]).toBe(null);
      expect(maskedArray[4]).toBe(true);
    });
  });

  describe('Performance', () => {
    it('should sanitize typical response quickly', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          users: Array.from({ length: 100 }, (_, i) => ({
            id: i,
            name: `User ${i}`,
            email: `user${i}@example.com`,
            password: `pass${i}`,
          })),
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const startTime = Date.now();
      await redactor.redact(response, decision);
      const duration = Date.now() - startTime;

      // Should complete within reasonable time (< 100ms for 100 users)
      expect(duration).toBeLessThan(100);
    });
  });

  describe('Real-World Scenarios', () => {
    it('should sanitize database query results', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          rows: [
            {
              id: 1,
              name: 'John Doe',
              email: 'john.doe@company.com',
              ssn: '123-45-6789',
              creditCard: '4532-1234-5678-9010',
              phone: '555-123-4567',
            },
          ],
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      const rows = resultObj.rows as Array<Record<string, unknown>>;
      const row = rows[0] as Record<string, unknown>;

      // PII should be scrubbed
      expect(row.email).not.toContain('john.doe@company.com');
      expect(row.ssn).not.toContain('123-45-6789');
      expect(row.creditCard).not.toContain('4532-1234-5678-9010');
      expect(row.phone).not.toContain('555-123-4567');
    });

    it('should sanitize API response with sensitive data', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          user: {
            id: 123,
            username: 'johndoe',
            password: 'SuperSecret123!',
            apiKey: 'sk_live_abc123xyz789def456',
            profile: {
              email: 'john@example.com',
              phone: '(555) 123-4567',
            },
          },
          metadata: {
            ipAddress: '192.168.1.100',
            timestamp: '2024-01-01T00:00:00Z',
          },
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      const user = resultObj.user as Record<string, unknown>;
      const profile = user.profile as Record<string, unknown>;
      const metadata = resultObj.metadata as Record<string, unknown>;

      // Tier 1: password and apiKey should be masked
      expect(user.password).toBe('[REDACTED]');
      expect(user.apiKey).toBe('[REDACTED]');

      // Tier 2: email, phone, IP should be scrubbed
      expect(profile.email).not.toContain('john@example.com');
      expect(profile.phone).not.toContain('555');
      expect(metadata.ipAddress).not.toContain('192.168.1.100');
    });

    it('should handle multiple PII patterns in single string', async () => {
      const response = {
        jsonrpc: '2.0',
        id: 1,
        result: {
          message: 'Contact John at john@example.com or 555-123-4567. SSN: 123-45-6789. Card: 4532-1234-5678-9010',
        },
      };

      const decision: PolicyDecision = {
        action: 'REDACT',
        riskScore: createRiskScore(0.5),
        riskBreakdown: {
          sensitivity: 0.5,
          exposure: 1,
          trust: 0.5,
          weightSensitivity: 0.6,
          weightExposure: 0.4,
          rawScore: 0.5,
          finalScore: createRiskScore(0.5),
        },
        justification: 'Test',
        timestamp: new Date(),
        policyVersion: '1.0',
        requestId: 'req-1',
      };

      const result = await redactor.redact(response, decision);
      const resultObj = result.result as Record<string, unknown>;
      const message = resultObj.message as string;

      // All PII should be scrubbed
      expect(message).not.toContain('john@example.com');
      expect(message).not.toContain('555-123-4567');
      expect(message).not.toContain('123-45-6789');
      expect(message).not.toContain('4532-1234-5678-9010');
      expect(message).toContain('[REDACTED]');
    });
  });

  describe('Security Fixes', () => {
    const decision: PolicyDecision = {
      action: 'REDACT',
      riskScore: createRiskScore(0.5),
      justification: 'Test',
      timestamp: new Date(),
      policyVersion: '1.0',
      requestId: 'req-sec',
    };

    describe('4a: error message/data redaction', () => {
      it('should scrub PII from JSON-RPC error message', async () => {
        const response = {
          jsonrpc: '2.0' as const,
          id: 1,
          error: {
            code: -32000,
            message: 'Failed to email john@example.com (ssn 123-45-6789)',
          },
        };

        const result = await redactor.redact(response, decision);
        expect(result.error?.message).not.toContain('john@example.com');
        expect(result.error?.message).not.toContain('123-45-6789');
        expect(result.error?.message).toContain('[REDACTED]');
      });

      it('should mask sensitive fields and scrub PII inside error.data', async () => {
        const response = {
          jsonrpc: '2.0' as const,
          id: 1,
          error: {
            code: -32000,
            message: 'Server error',
            data: {
              password: 'hunter2',
              contact: 'call 555-123-4567',
            },
          },
        };

        const result = await redactor.redact(response, decision);
        const data = result.error?.data as Record<string, unknown>;
        expect(data.password).toBe('[REDACTED]');
        expect(data.contact).not.toContain('555-123-4567');
      });

      it('should leave a benign error unchanged', async () => {
        const response = {
          jsonrpc: '2.0' as const,
          id: 1,
          error: { code: -32000, message: 'Server error' },
        };
        const result = await redactor.redact(response, decision);
        expect(result.error?.message).toBe('Server error');
      });
    });

    describe('4b: numeric PII scrubbing', () => {
      it('should scrub SSN and credit card stored as JSON numbers', async () => {
        const response = {
          jsonrpc: '2.0' as const,
          id: 1,
          result: {
            ssn: 123456789, // SSN as a number
            card: 1234567890123456, // credit card as a number
            age: 42, // benign number, must be preserved
          },
        };

        const result = await redactor.redact(response, decision);
        const obj = result.result as Record<string, unknown>;
        expect(obj.ssn).toBe('[REDACTED]');
        expect(obj.card).toBe('[REDACTED]');
        expect(obj.age).toBe(42);
      });
    });

    describe('4c: sensitive field-name lexicon matching', () => {
      it('should mask snake_case / camelCase sensitive fields that are not exact matches', async () => {
        const response = {
          jsonrpc: '2.0' as const,
          id: 1,
          result: {
            user_password: 'p1',
            authToken: 't1',
            api_key: 'k1',
            privateKey: 'pk1',
            username: 'john', // must NOT be masked
            shipping: 'fast', // contains "pin" substring but must NOT be masked
          },
        };

        const result = await redactor.redact(response, decision);
        const obj = result.result as Record<string, unknown>;
        expect(obj.user_password).toBe('[REDACTED]');
        expect(obj.authToken).toBe('[REDACTED]');
        expect(obj.api_key).toBe('[REDACTED]');
        expect(obj.privateKey).toBe('[REDACTED]');
        expect(obj.username).toBe('john');
        expect(obj.shipping).toBe('fast');
      });
    });

    describe('4d: extended SSN matching', () => {
      it('should scrub contiguous and space-separated SSN forms', async () => {
        const response = {
          jsonrpc: '2.0' as const,
          id: 1,
          result: {
            a: 'SSN 123-45-6789',
            b: 'SSN 123 45 6789',
            c: 'SSN 123456789',
          },
        };

        const result = await redactor.redact(response, decision);
        const obj = result.result as Record<string, unknown>;
        expect(obj.a).not.toContain('123-45-6789');
        expect(obj.b).not.toContain('123 45 6789');
        expect(obj.c).not.toContain('123456789');
        expect(obj.a).toContain('[REDACTED]');
        expect(obj.b).toContain('[REDACTED]');
        expect(obj.c).toContain('[REDACTED]');
      });
    });
  });
});

