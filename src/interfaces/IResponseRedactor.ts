/**
 * MCP-Shield: IResponseRedactor Interface
 * 
 * Response sanitization interface for REDACT decision enforcement.
 * 
 * The ResponseRedactor implements two-tier sanitization:
 * - Tier 1: Schema-based field masking
 * - Tier 2: Pattern-based NER scrubbing
 * 
 * @see ARCHITECTURE.md - Supporting Components: ResponseRedactor
 */

import type { JSONRPCResponse, PolicyDecision } from '../types/common';

/**
 * Sanitization Configuration
 */
export interface SanitizationConfig {
  /**
   * Fields to mask (by name)
   */
  maskFields: string[];
  
  /**
   * Regex patterns for pattern-based scrubbing
   */
  scrubPatterns: RegExp[];
  
  /**
   * Replacement string for scrubbed content
   */
  replacement: string;
  
  /**
   * Maximum depth for nested object traversal
   */
  maxDepth: number;
  
  /**
   * Maximum string length to process (DoS protection)
   */
  maxStringLength: number;
}

/**
 * Sanitization Result
 */
export interface SanitizationResult {
  /**
   * Sanitized response
   */
  sanitized: JSONRPCResponse;
  
  /**
   * Fields that were masked
   */
  maskedFields: string[];
  
  /**
   * Patterns that were scrubbed
   */
  scrubbedPatterns: number;
  
  /**
   * Whether sanitization was applied
   */
  wasSanitized: boolean;
}

/**
 * IResponseRedactor - Response Sanitization Interface
 * 
 * Responsibilities:
 * 1. Implement two-tier sanitization (Schema + Pattern)
 * 2. Mask fields marked as `secret: true` in MCP schema
 * 3. Scrub PII patterns from unstructured text
 * 4. Preserve response structure while removing sensitive content
 * 5. Provide deterministic output (same input → same sanitized output)
 */
export interface IResponseRedactor {
  /**
   * Primary entry point for sanitization.
   * 
   * This method implements two-tier sanitization:
   * - Tier 1: Schema-based field masking (if MCP schema identifies fields as secret)
   * - Tier 2: Pattern-based NER scrubbing (for unstructured text)
   * 
   * @param response - Raw JSON-RPC response from MCP Server
   * @param decision - Policy decision that triggered REDACT
   * @returns Promise resolving to sanitized response
   */
  redact(
    response: JSONRPCResponse,
    decision: PolicyDecision
  ): Promise<JSONRPCResponse>;

  /**
   * Mask specific fields in structured data.
   * 
   * Tier 1 sanitization: If MCP schema identifies a field as `secret: true`,
   * the entire field is masked.
   * 
   * @param data - Structured data (JSON object/array)
   * @param fields - Field names to mask
   * @returns Sanitized data with masked fields
   */
  maskFields(data: unknown, fields: string[]): unknown;

  /**
   * Scrub patterns from unstructured text.
   * 
   * Tier 2 sanitization: Uses regex patterns and Named Entity Recognition (NER)
   * to scrub PII patterns (SSN, credit cards, emails, phone numbers).
   * 
   * @param text - Unstructured text to scrub
   * @param patterns - Regex patterns to match and scrub
   * @returns Scrubbed text
   */
  scrubPatterns(text: string, patterns: RegExp[]): string;

  /**
   * Get sanitization configuration.
   * 
   * @returns Current sanitization configuration
   */
  getConfig(): SanitizationConfig;

  /**
   * Update sanitization configuration.
   * 
   * @param config - New configuration (partial update supported)
   */
  updateConfig(config: Partial<SanitizationConfig>): void;
}

