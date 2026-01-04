/**
 * MCP-Shield: Standardized Error Codes
 * 
 * JSON-RPC 2.0 compliant error codes for MCP-Shield governance violations.
 * 
 * Following JSON-RPC 2.0 standards, custom error codes use the range -32000 to -32099.
 */

/**
 * Standard JSON-RPC Error Codes
 */
export const JSONRPCErrorCodes = {
  /**
   * Invalid JSON was received by the server.
   */
  PARSE_ERROR: -32700,
  
  /**
   * The JSON sent is not a valid Request object.
   */
  INVALID_REQUEST: -32600,
  
  /**
   * The method does not exist / is not available.
   */
  METHOD_NOT_FOUND: -32601,
  
  /**
   * Invalid method parameter(s).
   */
  INVALID_PARAMS: -32602,
  
  /**
   * Internal JSON-RPC error.
   */
  INTERNAL_ERROR: -32603,
} as const;

/**
 * MCP-Shield Custom Error Codes (-32000 to -32099)
 */
export const MCPShieldErrorCodes = {
  /**
   * Access denied by MCP-Shield policy enforcement.
   * Used when a request is BLOCKED due to policy violation.
   */
  POLICY_VIOLATION: -32001,
  
  /**
   * Rate limit exceeded.
   * Used when IRateLimiter.checkLimit() returns false.
   */
  RATE_LIMITED: -32002,
  
  /**
   * Context sensitivity mismatch (taint escalation).
   * Used when taint propagation detects sensitivity conflict.
   */
  TAINT_ESCALATION: -32003,
  
  /**
   * Request validation failed (Zod schema validation).
   * Used when JSON-RPC request structure is invalid.
   */
  VALIDATION_FAILED: -32602, // Reuse standard INVALID_PARAMS
  
  /**
   * System error (fail-closed scenario).
   * Used when a component fails (PDP timeout, TaintRegistry unavailable, etc.).
   */
  SYSTEM_ERROR: -32004,
} as const;

/**
 * Error Code to Message Mapping
 */
export const ErrorMessages: Record<number, string> = {
  [MCPShieldErrorCodes.POLICY_VIOLATION]: 'Access denied by MCP-Shield policy enforcement',
  [MCPShieldErrorCodes.RATE_LIMITED]: 'Too many requests - rate limit exceeded',
  [MCPShieldErrorCodes.TAINT_ESCALATION]: 'Context sensitivity mismatch - taint escalation detected',
  [MCPShieldErrorCodes.VALIDATION_FAILED]: 'Invalid request parameters - validation failed',
  [MCPShieldErrorCodes.SYSTEM_ERROR]: 'System error - request blocked for security (fail-closed)',
};

/**
 * Get error message for a given error code.
 * 
 * @param code - Error code
 * @returns Error message or default message
 */
export function getErrorMessage(code: number): string {
  return ErrorMessages[code] || `Unknown error (code: ${code})`;
}

