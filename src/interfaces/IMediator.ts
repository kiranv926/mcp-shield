/**
 * TaintGate: IMediator Interface
 * 
 * Policy Enforcement Point (PEP) interface for TaintGate.
 * 
 * The Mediator intercepts all JSON-RPC requests between MCP Clients and Servers,
 * queries the Policy Decision Point (PDP) for decisions, and enforces those decisions.
 * 
 * @see ARCHITECTURE.md - Layer 1: Policy Enforcement Point (PEP)
 */

import type {
  JSONRPCRequest,
  JSONRPCResponse,
  RequestContext,
} from '../types/common';
import type { PolicyDecision } from '../types/governance';
import type { IAuditLogger } from './IAuditLogger';
import type { IRateLimiter } from './IRateLimiter';
import type { IResponseRedactor } from './IResponseRedactor';

/**
 * IMediator - Policy Enforcement Point Interface
 * 
 * Responsibilities:
 * 1. Validate JSON-RPC requests using Zod schemas
 * 2. Enforce rate limits via IRateLimiter
 * 3. Intercept JSON-RPC requests at transport layer
 * 4. Query PDP (RiskEvaluator) for policy decisions
 * 5. Enforce decisions: ALLOW, BLOCK, or REDACT
 * 6. Implement fail-closed behavior on errors/timeouts
 * 7. Log all governance decisions for audit
 * 
 * Execution Flow (Canonical Sequence - Fail-Closed):
 * 
 * 1. **Validation (Zod)**: Transform unknown input into typed JSONRPCRequest
 *    - Fail? → BLOCK immediately
 * 
 * 2. **Context Extraction**: Extract toolName from params.name if method is callTool
 *    - Build RequestContext with sessionId, tenantId, toolName, etc.
 * 
 * 3. **Rate Limiting (Check)**: Call IRateLimiter.checkLimit()
 *    - Fail? → BLOCK immediately
 * 
 * 4. **Governance (PDP/PEP)**:
 *    - TaintRegistry.checkLineage() to set current sensitivity
 *    - RiskEvaluator.evaluate() to get raw decision
 *    - PolicyManager.getResolvedPolicy() to apply MRW logic
 * 
 * 5. **Enforcement (Execution)**:
 *    - If BLOCK: Stop and return error
 *    - If ALLOW/REDACT: Forward to MCP Server
 * 
 * 6. **Rate Limiting (Record)**: Call IRateLimiter.recordRequest()
 *    - Record even if BLOCKED to prevent brute-force attacks
 * 
 * 7. **Sanitization**: If action was REDACT, pass response through IResponseRedactor
 *    - Tier 1: Schema-based field masking
 *    - Tier 2: Pattern-based NER scrubbing
 */
export interface IMediator {
  /**
   * Evaluate a JSON-RPC request and get policy decision.
   * 
   * This method intercepts the request, builds evaluation context,
   * queries the RiskEvaluator (PDP), and returns the policy decision.
   * 
   * Fail-closed behavior: If the PDP times out, TaintRegistry is unavailable,
   * or any evaluation error occurs, this method:
   * 1. Logs the system error via IAuditLogger
   * 2. Returns a BLOCK decision via handleFailure()
   * 
   * @param request - The JSON-RPC request to evaluate
   * @param context - Request context (sessionId, tenantId, tool info, etc.)
   * @returns Promise resolving to policy decision (never rejects - fail-closed)
   */
  evaluateRequest(
    request: JSONRPCRequest,
    context: RequestContext
  ): Promise<PolicyDecision>;

  /**
   * Enforce a policy decision on a request.
   * 
   * This method takes a policy decision and enforces it:
   * - ALLOW: Forwards request to MCP Server, returns response directly
   * - BLOCK: Returns security error to client (does not forward)
   * - REDACT: Forwards request to MCP Server, sanitizes response via IResponseRedactor
   * 
   * @param decision - The policy decision to enforce
   * @param request - The original JSON-RPC request
   * @returns Promise resolving to JSON-RPC response (or forwarded/sanitized response)
   */
  enforceDecision(
    decision: PolicyDecision,
    request: JSONRPCRequest
  ): Promise<JSONRPCResponse>;

  /**
   * Handle failures with fail-closed behavior.
   * 
   * When the PDP times out, TaintRegistry is unavailable, or any
   * evaluation error occurs, this method:
   * 1. Logs the system error via IAuditLogger
   * 2. Returns a BLOCK decision to ensure security by default
   * 
   * @param error - The error that occurred
   * @param context - Request context for logging
   * @param failedComponent - Component that failed (e.g., "PDP", "TaintRegistry")
   * @returns PolicyDecision with action=BLOCK
   */
  handleFailure(
    error: Error,
    context: RequestContext,
    failedComponent: string
  ): PolicyDecision;

  /**
   * Validate JSON-RPC request using Zod schema.
   * 
   * This method validates the incoming request structure before it touches
   * the RiskEvaluator. Malformed requests are blocked immediately (fail-closed).
   * 
   * @param request - The JSON-RPC request to validate
   * @returns Validation result with parsed request or error
   */
  validateRequest(request: unknown): {
    valid: boolean;
    parsed?: JSONRPCRequest;
    error?: string;
  };

  /**
   * Intercept and process an incoming JSON-RPC request.
   * 
   * This is the Master Orchestrator method that follows the canonical fail-closed sequence:
   * 
   * 1. **Validation (Zod)**: Transform unknown → JSONRPCRequest (Fail? → BLOCK)
   * 2. **Context Extraction**: Extract toolName from params.name if method is callTool
   * 3. **Rate Limiting (Check)**: IRateLimiter.checkLimit() (Fail? → BLOCK)
   * 4. **Governance**: TaintRegistry.checkLineage() → RiskEvaluator.evaluate() → PolicyManager.getResolvedPolicy()
   * 5. **Enforcement**: If BLOCK → return error; If ALLOW/REDACT → forward to server
   * 6. **Rate Limiting (Record)**: IRateLimiter.recordRequest() (even if BLOCKED)
   * 7. **Sanitization**: If REDACT → IResponseRedactor.redact()
   * 
   * All steps are fail-closed: any error defaults to BLOCK.
   * 
   * @param request - The JSON-RPC request from MCP Client (unvalidated, unknown type)
   * @param context - Request context (sessionId, tenantId, etc.)
   * @returns Promise resolving to JSON-RPC response (never rejects - fail-closed)
   */
  intercept(
    request: unknown,
    context: RequestContext
  ): Promise<JSONRPCResponse>;

  /**
   * Forward a request to the MCP Server (for ALLOW decisions).
   * 
   * Uses composite key (tenantId:sessionId:requestId) for request-response correlation
   * to ensure multi-tenant isolation and prevent ID collisions.
   * 
   * @param request - The JSON-RPC request to forward
   * @param context - Request context for composite key generation (tenantId, sessionId)
   * @returns Promise resolving to MCP Server response
   */
  forwardRequest(request: JSONRPCRequest, context: RequestContext): Promise<JSONRPCResponse>;

  /**
   * Create a security error response (for BLOCK decisions).
   * 
   * Uses standardized JSON-RPC error codes:
   * - -32602: Invalid params (validation failed)
   * - -32001: Access denied by TaintGate (policy violation)
   * - -32002: Too many requests (rate limited)
   * - -32003: Context sensitivity mismatch (taint escalation)
   * 
   * @param request - The original JSON-RPC request
   * @param reason - Reason for blocking
   * @param errorCode - JSON-RPC error code (default: -32001)
   * @returns JSON-RPC error response
   */
  createBlockResponse(
    request: JSONRPCRequest,
    reason: string,
    errorCode?: number
  ): JSONRPCResponse;

  /**
   * Get the audit logger instance.
   * 
   * @returns IAuditLogger instance
   */
  getAuditLogger(): IAuditLogger;

  /**
   * Get the rate limiter instance.
   * 
   * @returns IRateLimiter instance
   */
  getRateLimiter(): IRateLimiter;

  /**
   * Get the response redactor instance.
   * 
   * @returns IResponseRedactor instance
   */
  getResponseRedactor(): IResponseRedactor;
}

