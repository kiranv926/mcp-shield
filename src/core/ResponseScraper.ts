/**
 * TaintGate: ResponseScraper Utility
 *
 * Extracts searchable tokens from MCP server responses to populate the TaintRegistry.
 * Implements DoS protection via depth and length limits.
 *
 * This utility provides the "Response-to-Registry" bridge, resolving Critical Issue #3
 * from the architecture review. It implements deep-traversal logic to find sensitive
 * strings in unstructured or structured JSON-RPC results.
 */

/**
 * Traversal context used to carry state (like truncation) across the recursion
 * without changing the public return type.
 */
interface ScrapeContext {
  /**
   * Set to true if any DoS cap (depth or token count) was hit during traversal.
   * When true, the caller logs a fail-safe warning because the response may
   * contain untracked tainted data beyond the traversal limits.
   */
  truncated: boolean;
}

export class ResponseScraper {
  /**
   * Maximum traversal depth (DoS protection).
   *
   * SECURITY FIX (depth evasion): Raised from 5 to 12 so that an attacker can no
   * longer bury tainted data just beyond the previous cap (depth >= 6). 12 levels
   * is deep enough for realistic nested JSON while still bounding recursion.
   * Configurable via {@link ResponseScraper.MAX_DEPTH}.
   */
  public static MAX_DEPTH = 12;

  /**
   * Maximum tokens to extract per response (DoS protection).
   *
   * SECURITY FIX (token evasion): Raised from 200 to 1000 so that tainted data
   * placed after the previous cap is still registered. Configurable via
   * {@link ResponseScraper.MAX_TOKENS}.
   */
  public static MAX_TOKENS = 1000;

  /**
   * Minimum token length (noise filtering)
   */
  private static readonly MIN_TOKEN_LENGTH = 3;

  /**
   * Maximum token length (DoS protection)
   */
  private static readonly MAX_TOKEN_LENGTH = 1024;

  /**
   * Common English / structural words that must NOT be registered as taints on
   * their own. Without this filter, splitting "User ID: 12345" produces "User",
   * which then over-taints unrelated later calls that merely contain the word.
   *
   * NOTE: This is a safety net. The primary defense is {@link isMeaningfulSubToken},
   * which rejects plain dictionary-shaped words regardless of this list.
   */
  private static readonly STOPWORDS = new Set<string>([
    'the', 'and', 'for', 'are', 'was', 'you', 'your', 'from', 'with', 'this',
    'that', 'user', 'name', 'email', 'code', 'ids', 'item', 'items', 'tag',
    'tags', 'type', 'data', 'value', 'null', 'true', 'false', 'info', 'key',
    'secret', 'password', 'token', 'number', 'phone', 'address', 'account',
  ]);

  /**
   * Scrapes a JSON-RPC response for potential sensitive values.
   *
   * Recursively traverses the response structure and extracts all string values
   * (and PII-shaped numeric leaves) that could be sensitive data.
   *
   * @param result - JSON-RPC response result (any JSON-serializable value)
   * @returns Array of extracted string values
   */
  public static scrape(result: unknown): string[] {
    const tokens = new Set<string>();
    const ctx: ScrapeContext = { truncated: false };
    this.traverse(result, 0, tokens, ctx);

    // FAIL-SAFE: If we hit a DoS cap, we may have skipped tainted data. Log a
    // truncation warning instead of silently ignoring it so operators can see
    // that taint coverage for this response was incomplete.
    if (ctx.truncated) {
      // eslint-disable-next-line no-console
      console.warn(
        `[ResponseScraper] Traversal cap hit (maxDepth=${this.MAX_DEPTH}, ` +
        `maxTokens=${this.MAX_TOKENS}). Response may contain untracked tainted ` +
        `data beyond these limits; treating extracted subset as potentially incomplete.`
      );
    }

    return Array.from(tokens);
  }

  /**
   * Recursively traverse the response structure to extract tokens.
   *
   * @param obj - Current object/value being traversed
   * @param depth - Current depth level
   * @param tokens - Set to collect tokens in
   * @param ctx - Traversal context (tracks truncation)
   */
  private static traverse(
    obj: unknown,
    depth: number,
    tokens: Set<string>,
    ctx: ScrapeContext
  ): void {
    // DoS protection: limit depth and total tokens
    if (depth > this.MAX_DEPTH || tokens.size >= this.MAX_TOKENS) {
      ctx.truncated = true;
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
    } else if (typeof obj === 'number' && Number.isFinite(obj)) {
      // SECURITY FIX (numeric taint evasion): Previously numbers were skipped at
      // registration but tokenized at check time, so a secret returned as a JSON
      // number was never tainted. Register numeric leaves in string form so
      // registration and checking are symmetric. Booleans are intentionally
      // NOT registered (1 bit of entropy => massive false positives).
      const asString = String(obj);
      if (asString.length >= this.MIN_TOKEN_LENGTH && tokens.size < this.MAX_TOKENS) {
        tokens.add(asString);
      }
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        this.traverse(item, depth + 1, tokens, ctx);
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const value of Object.values(obj)) {
        this.traverse(value, depth + 1, tokens, ctx);
      }
    }
  }

  /**
   * Extract sub-tokens from a string by splitting on delimiters.
   *
   * Resolves the "Partial Match" problem (Issue #1) where a tool response contains
   * "Your secret code is X55-99" but a subsequent tool call uses only "X55-99".
   *
   * SECURITY FIX (sub-token false positives): Only identifier/secret-like sub-tokens
   * are registered (see {@link isMeaningfulSubToken}). Plain dictionary words such
   * as "User" from "User ID: 12345" are dropped so they don't over-taint unrelated
   * later calls, while real high-entropy secrets and structured ids are preserved.
   *
   * @param val - String value to extract sub-tokens from
   * @param tokens - Set to add tokens to
   */
  private static extractSubTokens(val: string, tokens: Set<string>): void {
    // Split by common delimiters: spaces, colons, dashes, slashes, underscores, parentheses
    const subParts = val.split(/[:\-_ /\\()[\]]+/);

    if (subParts.length > 1) {
      for (const part of subParts) {
        const trimmed = part.trim();
        if (
          this.isMeaningfulSubToken(trimmed) &&
          tokens.size < this.MAX_TOKENS
        ) {
          tokens.add(trimmed);
        }
      }
    }
  }

  /**
   * Decide whether a delimiter-split sub-token is worth registering as a taint.
   *
   * A sub-token is "meaningful" (identifier/secret-like) when it is NOT a plain
   * dictionary word. Kept: tokens containing digits, camelCase/mixed-internal-case
   * tokens, long tokens (>= 12 chars), and high-entropy random-looking tokens.
   * Dropped: short alphabetic words like "User", "code", "secret".
   */
  public static isMeaningfulSubToken(token: string): boolean {
    if (token.length < this.MIN_TOKEN_LENGTH || token.length > this.MAX_TOKEN_LENGTH) {
      return false;
    }
    if (this.STOPWORDS.has(token.toLowerCase())) {
      return false;
    }
    // Plain dictionary-shaped word (optional leading capital + lowercase), e.g.
    // "User", "secret", "password" -> treat as a common word and skip, unless long.
    if (/^[A-Za-z][a-z]+$/.test(token) && token.length < 12) {
      return false;
    }
    // Contains a digit -> looks like an id / code / secret (e.g. "X55", "12345").
    if (/\d/.test(token)) {
      return true;
    }
    // Internal capitalization (camelCase secrets like "authToken").
    if (/[a-z][A-Z]/.test(token)) {
      return true;
    }
    // Long tokens are likely ids/secrets even if all letters.
    if (token.length >= 12) {
      return true;
    }
    // Random-looking high-entropy tokens.
    if (this.shannonEntropy(token) >= 3.0) {
      return true;
    }
    return false;
  }

  /**
   * Shannon entropy (bits) of a string. Random secrets have high entropy;
   * dictionary words have low entropy.
   */
  private static shannonEntropy(s: string): number {
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
}
