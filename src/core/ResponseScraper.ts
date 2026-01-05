/**
 * MCP-Shield: ResponseScraper Utility
 * 
 * Extracts searchable tokens from MCP server responses to populate the TaintRegistry.
 * Implements DoS protection via depth and length limits.
 * 
 * This utility provides the "Response-to-Registry" bridge, resolving Critical Issue #3
 * from the architecture review. It implements deep-traversal logic to find sensitive
 * strings in unstructured or structured JSON-RPC results.
 * 
 * @see TAINT_REGISTRY_REVIEW.md - Issue #3: Response Extraction
 */

/**
 * ResponseScraper Utility
 * 
 * Extracts potential sensitive values from JSON-RPC responses for taint registration.
 */
export class ResponseScraper {
  /**
   * Maximum traversal depth (DoS protection)
   */
  private static readonly MAX_DEPTH = 5;
  
  /**
   * Maximum tokens to extract per response (DoS protection)
   */
  private static readonly MAX_TOKENS = 200;
  
  /**
   * Minimum token length (noise filtering)
   */
  private static readonly MIN_TOKEN_LENGTH = 3;
  
  /**
   * Maximum token length (DoS protection)
   */
  private static readonly MAX_TOKEN_LENGTH = 1024;

  /**
   * Scrapes a JSON-RPC response for potential sensitive values.
   * 
   * Recursively traverses the response structure and extracts all string values
   * that could be sensitive data (emails, IDs, codes, etc.).
   * 
   * @param result - JSON-RPC response result (any JSON-serializable value)
   * @returns Array of extracted string values
   */
  public static scrape(result: unknown): string[] {
    const tokens = new Set<string>();
    this.traverse(result, 0, tokens);
    return Array.from(tokens);
  }

  /**
   * Recursively traverse the response structure to extract tokens.
   * 
   * @param obj - Current object/value being traversed
   * @param depth - Current depth level
   * @param tokens - Set to collect tokens in
   */
  private static traverse(obj: unknown, depth: number, tokens: Set<string>): void {
    // DoS protection: limit depth and total tokens
    if (depth > this.MAX_DEPTH || tokens.size >= this.MAX_TOKENS) {
      return;
    }

    if (typeof obj === 'string') {
      const clean = obj.trim();
      if (clean.length >= this.MIN_TOKEN_LENGTH && clean.length <= this.MAX_TOKEN_LENGTH) {
        tokens.add(clean);
        
        // IMPROVEMENT (Issue #1): Extract sub-tokens for partial matching
        // Example: "Your secret code is X55-99" -> ["X55", "99"]
        this.extractSubTokens(clean, tokens);
      }
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        this.traverse(item, depth + 1, tokens);
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const value of Object.values(obj)) {
        this.traverse(value, depth + 1, tokens);
      }
    }
    // Numbers and booleans are handled during tokenization in TaintRegistry
  }

  /**
   * Extract sub-tokens from a string by splitting on delimiters.
   * 
   * Resolves the "Partial Match" problem (Issue #1) where a tool response contains
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
  private static extractSubTokens(val: string, tokens: Set<string>): void {
    // Split by common delimiters: spaces, colons, dashes, slashes, underscores, parentheses
    const subParts = val.split(/[:\-_ \/\\()\[\]]+/);
    
    if (subParts.length > 1) {
      for (const part of subParts) {
        const trimmed = part.trim();
        // Only add meaningful sub-tokens
        if (
          trimmed.length >= this.MIN_TOKEN_LENGTH &&
          trimmed.length <= this.MAX_TOKEN_LENGTH &&
          tokens.size < this.MAX_TOKENS
        ) {
          tokens.add(trimmed);
        }
      }
    }
  }
}

