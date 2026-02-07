/**
 * MCP-Shield: ResponseRedactor Implementation
 * 
 * Response sanitization implementation for REDACT decision enforcement.
 * 
 * The ResponseRedactor implements two-tier sanitization:
 * - Tier 1: Schema-based field masking (fields marked as secret: true)
 * - Tier 2: Pattern-based NER scrubbing (PII patterns: SSN, credit cards, emails, phone numbers)
 * 
 * @see ARCHITECTURE.md - Supporting Components: ResponseRedactor
 */

import type {
  IResponseRedactor,
  SanitizationConfig,
} from '../interfaces/IResponseRedactor';
import type { JSONRPCResponse, PolicyDecision } from '../types/common';

/**
 * Default PII detection patterns
 */
const DEFAULT_PII_PATTERNS: RegExp[] = [
  // SSN: 123-45-6789
  /\b\d{3}-\d{2}-\d{4}\b/g,
  // Credit Card: 1234 5678 9012 3456 or 1234-5678-9012-3456
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  // Email: user@example.com
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  // Phone: (555) 123-4567 or 555-123-4567 or 555.123.4567
  /\b\(?\d{3}\)?[-.]?\s?\d{3}[-.]?\d{4}\b/g,
  // IP Address: 192.168.1.1
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  // API Key pattern: sk_live_... or similar
  /\b(sk|pk|api[_-]?key|secret[_-]?key)[_=:]\s*[A-Za-z0-9_-]{20,}\b/gi,
];

/**
 * Default configuration constants
 */
const DEFAULT_MAX_DEPTH = 10;
const DEFAULT_MAX_STRING_LENGTH = 10000; // 10KB per string
const DEFAULT_REPLACEMENT = '[REDACTED]';

/**
 * ResponseRedactor Configuration
 */
export interface ResponseRedactorConfig {
  /**
   * Default fields to mask (by name)
   * These are always masked regardless of schema
   */
  defaultMaskFields?: string[];
  
  /**
   * PII detection patterns
   */
  piiPatterns?: RegExp[];
  
  /**
   * Replacement string for scrubbed content
   */
  replacement?: string;
  
  /**
   * Maximum depth for nested object traversal
   */
  maxDepth?: number;
  
  /**
   * Maximum string length to process (DoS protection)
   */
  maxStringLength?: number;
  
  /**
   * Whether to enable Tier 1 (schema-based masking)
   */
  enableTier1Masking?: boolean;
  
  /**
   * Whether to enable Tier 2 (pattern-based scrubbing)
   */
  enableTier2Scrubbing?: boolean;
}

/**
 * ResponseRedactor - Response Sanitization Implementation
 * 
 * Implements two-tier sanitization for REDACT decisions.
 */
export class ResponseRedactor implements IResponseRedactor {
  private config: SanitizationConfig;

  constructor(config?: ResponseRedactorConfig) {
    // Validate configuration before applying
    this.validateConfig(config);
    
    this.config = {
      maskFields: config?.defaultMaskFields ?? [
        'password',
        'secret',
        'token',
        'apiKey',
        'api_key',
        'accessToken',
        'refreshToken',
        'ssn',
        'socialSecurityNumber',
        'creditCard',
        'credit_card',
        'cvv',
        'pin',
      ],
      scrubPatterns: config?.piiPatterns ?? DEFAULT_PII_PATTERNS,
      replacement: config?.replacement ?? DEFAULT_REPLACEMENT,
      maxDepth: config?.maxDepth ?? DEFAULT_MAX_DEPTH,
      maxStringLength: config?.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH,
    };
  }

  /**
   * Validate configuration values
   */
  private validateConfig(config?: ResponseRedactorConfig): void {
    if (!config) return;

    if (config.maxDepth !== undefined) {
      if (!Number.isInteger(config.maxDepth) || config.maxDepth < 1 || config.maxDepth > 100) {
        throw new Error(
          `maxDepth must be an integer between 1 and 100, got: ${config.maxDepth}`
        );
      }
    }

    if (config.maxStringLength !== undefined) {
      if (!Number.isInteger(config.maxStringLength) || config.maxStringLength < 1 || config.maxStringLength > 1000000) {
        throw new Error(
          `maxStringLength must be an integer between 1 and 1,000,000 (1MB), got: ${config.maxStringLength}`
        );
      }
    }

    if (config.replacement !== undefined) {
      if (typeof config.replacement !== 'string') {
        throw new Error('replacement must be a string');
      }
      if (config.replacement.length === 0) {
        throw new Error('replacement cannot be empty');
      }
      if (config.replacement.length > 100) {
        throw new Error('replacement cannot exceed 100 characters');
      }
    }

    // Validate regex patterns
    if (config.piiPatterns !== undefined) {
      if (!Array.isArray(config.piiPatterns)) {
        throw new Error('piiPatterns must be an array');
      }
      for (let i = 0; i < config.piiPatterns.length; i++) {
        const pattern = config.piiPatterns[i];
        if (!(pattern instanceof RegExp)) {
          throw new Error(`piiPatterns[${i}] must be a RegExp instance`);
        }
        try {
          // Test pattern compilation
          new RegExp(pattern.source, pattern.flags);
        } catch (error) {
          throw new Error(
            `Invalid regex pattern at index ${i}: ${pattern.source} - ${error instanceof Error ? error.message : String(error)}`
          );
        }
      }
    }

    // Validate maskFields
    if (config.defaultMaskFields !== undefined) {
      if (!Array.isArray(config.defaultMaskFields)) {
        throw new Error('defaultMaskFields must be an array');
      }
      for (let i = 0; i < config.defaultMaskFields.length; i++) {
        const field = config.defaultMaskFields[i];
        if (typeof field !== 'string' || field.length === 0) {
          throw new Error(`defaultMaskFields[${i}] must be a non-empty string`);
        }
      }
    }
  }

  /**
   * Primary entry point for sanitization
   * 
   * @param response - Raw JSON-RPC response from MCP Server
   * @param decision - Policy decision that triggered REDACT (kept for interface compliance and future enhancements)
   */
  async redact(
    response: JSONRPCResponse,
    decision: PolicyDecision
  ): Promise<JSONRPCResponse> {
    // Note: decision parameter is kept for interface compliance and potential future use
    // (e.g., schema-based field detection, per-decision configuration)
    void decision; // Suppress unused parameter warning
    // If response has error, return as-is (don't sanitize errors)
    if (response.error) {
      return response;
    }

    // If no result, return as-is
    if (response.result === undefined || response.result === null) {
      return response;
    }

    // Apply two-tier sanitization
    let sanitizedResult: unknown = response.result;

    // Tier 1: Schema-based field masking (always apply for REDACT decisions)
    // This ensures consistent sanitization regardless of riskBreakdown presence
    sanitizedResult = this.maskFields(
      sanitizedResult,
      this.config.maskFields
    );

    // Tier 2: Pattern-based scrubbing (always apply for REDACT)
    sanitizedResult = this.scrubPatternsRecursive(
      sanitizedResult,
      this.config.scrubPatterns,
      0
    );

    return {
      ...response,
      result: sanitizedResult,
    };
  }

  /**
   * Mask specific fields in structured data (Tier 1)
   */
  maskFields(data: unknown, fields: string[]): unknown {
    if (!data || fields.length === 0) {
      return data;
    }

    return this.maskFieldsRecursive(data, fields, 0);
  }

  /**
   * Recursive field masking with depth protection
   */
  private maskFieldsRecursive(
    data: unknown,
    fields: string[],
    depth: number
  ): unknown {
    // DoS protection: depth limit
    if (depth > this.config.maxDepth) {
      return data;
    }

    // Handle arrays
    if (Array.isArray(data)) {
      return data.map(item => this.maskFieldsRecursive(item, fields, depth + 1));
    }

    // Handle objects
    if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
      const masked: Record<string, unknown> = {};
      const dataObj = data as Record<string, unknown>;
      for (const [key, value] of Object.entries(dataObj)) {
        // Check if field should be masked (case-insensitive)
        const shouldMask = fields.some(
          field => key.toLowerCase() === field.toLowerCase()
        );

        if (shouldMask) {
          masked[key] = this.config.replacement;
        } else {
          masked[key] = this.maskFieldsRecursive(value, fields, depth + 1);
        }
      }
      return masked as unknown;
    }

    // Primitive values: return as-is
    return data;
  }

  /**
   * Scrub patterns from unstructured text (Tier 2)
   */
  scrubPatterns(text: string, patterns: RegExp[]): string {
    if (!text || typeof text !== 'string') {
      return text;
    }

    // DoS protection: string length limit
    if (text.length > this.config.maxStringLength) {
      // Truncate and scrub
      const truncated = text.substring(0, this.config.maxStringLength);
      return this.applyPatterns(truncated, patterns) + '... [TRUNCATED]';
    }

    return this.applyPatterns(text, patterns);
  }

  /**
   * Apply regex patterns to text
   * 
   * CRITICAL FIX: Clones patterns to avoid state pollution from global regex flags.
   * Global regex patterns (/g flag) retain state via lastIndex, which can cause
   * cross-request contamination and non-deterministic behavior.
   */
  private applyPatterns(text: string, patterns: RegExp[]): string {
    let scrubbed = text;
    
    for (const pattern of patterns) {
      // Clone pattern to avoid state pollution (global regex retains lastIndex)
      // This ensures deterministic behavior and prevents cross-request contamination
      const clonedPattern = new RegExp(pattern.source, pattern.flags);
      scrubbed = scrubbed.replace(clonedPattern, this.config.replacement);
    }
    
    return scrubbed;
  }

  /**
   * Recursively scrub patterns from nested data structures
   */
  private scrubPatternsRecursive(
    data: unknown,
    patterns: RegExp[],
    depth: number
  ): unknown {
    // DoS protection: depth limit
    if (depth > this.config.maxDepth) {
      return data;
    }

    // Handle strings
    if (typeof data === 'string') {
      return this.scrubPatterns(data, patterns);
    }

    // Handle arrays
    if (Array.isArray(data)) {
      return data.map(item => this.scrubPatternsRecursive(item, patterns, depth + 1));
    }

    // Handle objects
    if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
      const scrubbed: Record<string, unknown> = {};
      const dataObj = data as Record<string, unknown>;
      for (const [key, value] of Object.entries(dataObj)) {
        scrubbed[key] = this.scrubPatternsRecursive(value, patterns, depth + 1);
      }
      return scrubbed as unknown;
    }

    // Primitive values: return as-is
    return data;
  }

  /**
   * Get sanitization configuration
   */
  getConfig(): SanitizationConfig {
    return {
      ...this.config,
      scrubPatterns: [...this.config.scrubPatterns], // Clone array
    };
  }

  /**
   * Update sanitization configuration
   */
  updateConfig(config: Partial<SanitizationConfig>): void {
    this.config = {
      ...this.config,
      ...config,
      // Ensure arrays are cloned
      scrubPatterns: config.scrubPatterns ?? [...this.config.scrubPatterns],
      maskFields: config.maskFields ?? [...this.config.maskFields],
    };
  }
}

