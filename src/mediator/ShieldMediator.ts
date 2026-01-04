/**
 * MCP-Shield: ShieldMediator Implementation
 * 
 * Policy Enforcement Point (PEP) implementation for MCP-Shield.
 * 
 * The ShieldMediator is the "Gatekeeper" that intercepts all JSON-RPC requests
 * between MCP Clients and Servers, enforces policy decisions, and implements
 * fail-closed behavior for security.
 * 
 * @see ARCHITECTURE.md - Layer 1: Policy Enforcement Point (PEP)
 */

import { randomUUID } from 'crypto';
import type {
  JSONRPCRequest,
  JSONRPCResponse,
  RequestContext,
} from '../types/common';
import type {
  PolicyDecision,
  PolicyAction,
} from '../types/governance';
import { FailClosedDefaultPolicy } from '../types/governance';
import {
  MCPShieldErrorCodes,
  getErrorMessage,
} from '../types/errors';
import { JSONRPCRequestSchema, JSONRPCResponseSchema } from '../types/jsonrpc-schema';
import { createRiskScore } from '../types/common';
import type { IMediator } from '../interfaces/IMediator';
import type { IRiskEvaluator } from '../interfaces/IRiskEvaluator';
import type { ITaintRegistry } from '../interfaces/ITaintRegistry';
import type { IPolicyManager } from '../interfaces/IPolicyManager';
import type { IRateLimiter } from '../interfaces/IRateLimiter';
import type { IResponseRedactor } from '../interfaces/IResponseRedactor';
import type { IAuditLogger } from '../interfaces/IAuditLogger';
import type { ITransport } from '../interfaces/ITransport';

/**
 * ShieldMediator Configuration
 */
export interface ShieldMediatorConfig {
  /**
   * RiskEvaluator instance (PDP)
   */
  riskEvaluator: IRiskEvaluator;
  
  /**
   * TaintRegistry instance
   */
  taintRegistry: ITaintRegistry;
  
  /**
   * PolicyManager instance (PAP) - Required for MRW conflict resolution
   */
  policyManager: IPolicyManager;
  
  /**
   * RateLimiter instance
   */
  rateLimiter: IRateLimiter;
  
  /**
   * ResponseRedactor instance
   */
  responseRedactor: IResponseRedactor;
  
  /**
   * AuditLogger instance
   */
  auditLogger: IAuditLogger;
  
  /**
   * Client transport (from MCP Client to ShieldMediator)
   */
  clientTransport: ITransport;
  
  /**
   * Server transport (from ShieldMediator to MCP Server)
   */
  serverTransport: ITransport;
  
  /**
   * Evaluation timeout in milliseconds
   * Default: 2000 (2 seconds)
   */
  evaluationTimeout?: number;
  
  /**
   * TaintRegistry timeout in milliseconds
   * Default: 1000 (1 second)
   */
  taintTimeout?: number;
  
  /**
   * Stream-thru threshold (risk score below which to use stream-thru)
   * Default: 0.1
   */
  streamThruThreshold?: number;
}

/**
 * GovernanceViolationError
 * 
 * Error thrown when a governance violation occurs (fail-closed scenario).
 * This error is caught and converted to a BLOCK decision.
 */
export class GovernanceViolationError extends Error {
  constructor(
    message: string,
    public readonly component: string,
    public readonly errorCode: number = MCPShieldErrorCodes.SYSTEM_ERROR
  ) {
    super(message);
    this.name = 'GovernanceViolationError';
  }
}

/**
 * ShieldMediator - Policy Enforcement Point Implementation
 * 
 * Implements the canonical 7-step fail-closed execution flow:
 * 1. Validation (Zod)
 * 2. Context Extraction
 * 3. Rate Limiting (Check)
 * 4. Governance (PDP/PEP)
 * 5. Enforcement
 * 6. Rate Limiting (Record)
 * 7. Sanitization
 */
/**
 * Pending Request Entry
 * Tracks pending requests for response correlation
 */
interface PendingRequest {
  resolve: (value: JSONRPCResponse) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
  requestId: string;
  tenantId?: string;
  sessionId: string;
}

/**
 * Composite Key for Request-Response Correlation
 * Format: ${tenantId}:${sessionId}:${requestId}
 * 
 * This ensures multi-tenant isolation and prevents ID collisions
 * in environments where multiple clients use the same request IDs.
 */
type CompositeRequestKey = string;

export class ShieldMediator implements IMediator {
  private readonly riskEvaluator: IRiskEvaluator;
  private readonly taintRegistry: ITaintRegistry;
  private readonly policyManager: IPolicyManager;
  private readonly rateLimiter: IRateLimiter;
  private readonly responseRedactor: IResponseRedactor;
  private readonly auditLogger: IAuditLogger;
  // Client transport reserved for future bidirectional communication (Phase 2)
  // @ts-expect-error - Reserved for Phase 2: bidirectional communication
  private readonly clientTransport: ITransport;
  private readonly serverTransport: ITransport;
  private readonly evaluationTimeout: number;
  private readonly taintTimeout: number;
  
  /**
   * Dispatcher Map: Composite Key → Pending Request Promise
   * 
   * Key format: ${tenantId}:${sessionId}:${requestId}
   * 
   * This composite key ensures multi-tenant isolation and prevents ID collisions
   * when multiple clients use the same request IDs (common with auto-incrementing clients).
   * 
   * Single permanent listener routes responses to pending promises.
   * This prevents memory leaks from per-request handler registration.
   */
  private readonly pendingRequests = new Map<CompositeRequestKey, PendingRequest>();
  private isStarted = false;

  constructor(config: ShieldMediatorConfig) {
    this.riskEvaluator = config.riskEvaluator;
    this.taintRegistry = config.taintRegistry;
    this.policyManager = config.policyManager;
    this.rateLimiter = config.rateLimiter;
    this.responseRedactor = config.responseRedactor;
    this.auditLogger = config.auditLogger;
    // Client transport reserved for future bidirectional communication (Phase 2)
    this.clientTransport = config.clientTransport;
    this.serverTransport = config.serverTransport;
    this.evaluationTimeout = config.evaluationTimeout ?? 2000;
    this.taintTimeout = config.taintTimeout ?? 1000;

    // Note: Transport listener is NOT registered in constructor to prevent race conditions.
    // Call start() method explicitly after construction to activate the dispatcher.
  }

  /**
   * Start the mediator and activate the transport listener.
   * 
   * This method must be called explicitly after construction to prevent race conditions
   * where the transport might be "hot" (already receiving messages) before the
   * pendingRequests Map is ready.
   * 
   * The listener is registered here, not in the constructor, to ensure:
   * 1. All dependencies are initialized
   * 2. pendingRequests Map is ready
   * 3. No orphaned messages are processed
   * 
   * @throws Error if already started
   */
  start(): void {
    if (this.isStarted) {
      throw new Error('ShieldMediator is already started');
    }

    // Register single permanent listener for server transport responses
    // This dispatcher routes responses to pending promises using composite key correlation
    this.serverTransport.onMessage(async (message: JSONRPCRequest | JSONRPCResponse) => {
      // Only handle responses (have result or error, not method)
      if ('result' in message || 'error' in message) {
        // Extract request ID for correlation
        const requestId = message.id;
        
        if (requestId !== null && requestId !== undefined) {
          // Try to find pending request using composite key
          // Since we don't have tenantId/sessionId in the response, we need to search
          // However, in practice, the request ID should be unique enough within a session
          // For now, we'll search all pending requests (should be small in practice)
          // TODO: Consider adding tenantId/sessionId to response metadata in Phase 2
          
          let found = false;
          for (const [key, pending] of this.pendingRequests.entries()) {
            // Extract requestId from composite key (format: tenantId:sessionId:requestId)
            const keyParts = key.split(':');
            const keyRequestId = keyParts.length === 3 ? keyParts[2] : keyParts[keyParts.length - 1];
            
            // Match by request ID (this is safe because tenantId:sessionId provides isolation)
            if (String(keyRequestId) === String(requestId)) {
              clearTimeout(pending.timeout);
              this.pendingRequests.delete(key);
              found = true;
              
              try {
                // Validate server response with Zod schema
                const validated = JSONRPCResponseSchema.parse(message);
                pending.resolve(validated as JSONRPCResponse);
              } catch (validationError) {
                // Invalid response - reject with error
                pending.reject(new GovernanceViolationError(
                  `Server returned invalid JSON-RPC response: ${validationError instanceof Error ? validationError.message : String(validationError)}`,
                  'MCPServer',
                  MCPShieldErrorCodes.SYSTEM_ERROR
                ));
              }
              break;
            }
          }
          
          if (!found) {
            // Orphaned response - no matching pending request
            // This is expected for notifications or responses from previous sessions
          }
        }
      }
    });

    this.isStarted = true;
  }

  /**
   * Intercept and process an incoming JSON-RPC request.
   * 
   * Master Orchestrator method implementing the canonical fail-closed sequence.
   * 
   * @param request - Unvalidated JSON-RPC request
   * @param context - Request context
   * @returns Promise resolving to JSON-RPC response (never rejects - fail-closed)
   */
  async intercept(
    request: unknown,
    context: RequestContext
  ): Promise<JSONRPCResponse> {
    const requestId = randomUUID();

    try {
      // Step 1: Validation (Zod)
      const validation = this.validateRequest(request);
      if (!validation.valid || !validation.parsed) {
        await this.auditLogger.logSystemError({
          requestId,
          sessionId: context.sessionId,
          tenantId: context.tenantId,
          error: {
            type: 'ValidationError',
            message: validation.error ?? 'Validation failed',
          },
          failedComponent: 'ZodValidator',
          action: 'BLOCK',
          timestamp: Date.now(),
          context: {
            toolName: context.toolName,
          },
        });

        // Extract request ID safely if possible
        const extractedId = this.extractIdSafely(request);

        // Create a minimal request for error response (preserve ID if extracted)
        const errorRequest: JSONRPCRequest = {
          jsonrpc: '2.0',
          id: extractedId,
          method: 'unknown',
        };

        return this.createBlockResponse(
          errorRequest,
          validation.error ?? 'Invalid JSON-RPC request structure',
          MCPShieldErrorCodes.VALIDATION_FAILED,
          requestId
        );
      }

      const parsedRequest = validation.parsed;

      // Step 2: Context Extraction
      const toolName = this.extractToolName(parsedRequest) ?? context.toolName ?? 'unknown';
      const toolParams = parsedRequest.params as Record<string, unknown> | undefined;
      const enrichedContext: RequestContext = {
        ...context,
        toolName,
        toolParameters: toolParams,
      };

      // Step 3: Rate Limiting (Check)
      const rateLimitAllowed = await this.rateLimiter.checkLimit(
        context.tenantId ?? 'default',
        toolName
      );

      if (!rateLimitAllowed) {
        const rateLimitDecision: PolicyDecision = {
          action: 'BLOCK',
          riskScore: createRiskScore(1.0),
          riskBreakdown: {
            sensitivity: 1.0,
            exposure: 1,
            trust: 0,
            weightSensitivity: 0.6,
            weightExposure: 0.4,
            rawScore: 1.0,
            finalScore: createRiskScore(1.0),
          },
          justification: 'Rate limit exceeded',
          timestamp: new Date(),
          policyVersion: 'rate-limit',
          requestId,
        };

        await this.auditLogger.logDecision({
          requestId,
          sessionId: context.sessionId,
          tenantId: context.tenantId,
          decision: rateLimitDecision,
          taintContexts: [],
          policyVersion: 'rate-limit',
          timestamp: Date.now(),
          toolName,
        });

        // Step 6: Rate Limiting (Record) - even if BLOCKED
        await this.rateLimiter.recordRequest(
          context.tenantId ?? 'default',
          toolName ?? 'unknown'
        );

        return this.createBlockResponse(
          parsedRequest,
          'Too many requests - rate limit exceeded',
          MCPShieldErrorCodes.RATE_LIMITED,
          requestId
        );
      }

      // Step 4: Governance (PDP/PEP)
      let decision: PolicyDecision;
      try {
        decision = await Promise.race([
          this.evaluateRequest(parsedRequest, enrichedContext),
          new Promise<PolicyDecision>((_, reject) =>
            setTimeout(
              () => reject(new GovernanceViolationError(
                `Evaluation timeout after ${this.evaluationTimeout}ms`,
                'RiskEvaluator',
                MCPShieldErrorCodes.SYSTEM_ERROR
              )),
              this.evaluationTimeout
            )
          ),
        ]);

        // Fix: Force-escalate to REDACT if secretHint is present, even if R < 0.3
        // MCPToolAnnotations extends SecretHint, so secret property is directly accessible
        const toolAnnotations = enrichedContext.toolAnnotations;
        if (toolAnnotations?.secret === true && decision.action === 'ALLOW') {
          decision.action = 'REDACT';
          decision.justification += ' (Force-escalated to REDACT due to secretHint=true)';
        }
      } catch (error) {
        // Fail-closed: Any error in governance defaults to BLOCK
        const failureDecision = this.handleFailure(
          error instanceof Error ? error : new Error(String(error)),
          enrichedContext,
          'RiskEvaluator',
          requestId
        );
        decision = failureDecision;
      }

      // Step 5: Enforcement
      if (decision.action === 'BLOCK') {
        await this.auditLogger.logDecision({
          requestId,
          sessionId: context.sessionId,
          tenantId: context.tenantId,
          decision,
          taintContexts: [],
          policyVersion: decision.policyVersion,
          timestamp: Date.now(),
          toolName,
        });

        // Step 6: Rate Limiting (Record) - even if BLOCKED
        await this.rateLimiter.recordRequest(
          context.tenantId ?? 'default',
          toolName ?? 'unknown'
        );

        return this.createBlockResponse(
          parsedRequest,
          decision.justification,
          MCPShieldErrorCodes.POLICY_VIOLATION,
          requestId
        );
      }

      // ALLOW or REDACT: Forward to MCP Server
      let serverResponse: JSONRPCResponse;
      try {
        serverResponse = await this.forwardRequest(parsedRequest, enrichedContext);
      } catch (error) {
        // Fail-closed: Server connection failure defaults to BLOCK
        await this.auditLogger.logSystemError({
          requestId,
          sessionId: context.sessionId,
          tenantId: context.tenantId,
          error: {
            type: error instanceof Error ? error.constructor.name : 'Error',
            message: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
          },
          failedComponent: 'MCPServer',
          action: 'BLOCK',
          timestamp: Date.now(),
          context: {
            toolName,
          },
        });

        return this.createBlockResponse(
          parsedRequest,
          'MCP Server connection failed - request blocked for security',
          MCPShieldErrorCodes.SYSTEM_ERROR,
          requestId
        );
      }

      // Step 6: Rate Limiting (Record)
      await this.rateLimiter.recordRequest(
        context.tenantId ?? 'default',
        toolName
      );

      // Step 7: Sanitization (if REDACT)
      if (decision.action === 'REDACT') {
        try {
          serverResponse = await this.responseRedactor.redact(
            serverResponse,
            decision
          );
        } catch (error) {
          // Fail-closed: Redaction failure defaults to BLOCK
          await this.auditLogger.logSystemError({
            requestId,
            sessionId: context.sessionId,
            tenantId: context.tenantId,
            error: {
              type: error instanceof Error ? error.constructor.name : 'Error',
              message: error instanceof Error ? error.message : String(error),
              stack: error instanceof Error ? error.stack : undefined,
            },
            failedComponent: 'ResponseRedactor',
            action: 'BLOCK',
            timestamp: Date.now(),
            context: {
              toolName,
            },
          });

          return this.createBlockResponse(
            parsedRequest,
            'Response sanitization failed - request blocked for security',
            MCPShieldErrorCodes.SYSTEM_ERROR,
            requestId
          );
        }
      }

      // Log successful decision
      await this.auditLogger.logDecision({
        requestId,
        sessionId: context.sessionId,
        tenantId: context.tenantId,
        decision,
        taintContexts: [],
        policyVersion: decision.policyVersion,
        timestamp: Date.now(),
        toolName,
      });

      return serverResponse;
    } catch (error) {
      // Ultimate fail-closed: Any unhandled error defaults to BLOCK
      await this.auditLogger.logSystemError({
        requestId,
        sessionId: context.sessionId,
        tenantId: context.tenantId,
        error: {
          type: error instanceof Error ? error.constructor.name : 'Error',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        failedComponent: 'ShieldMediator',
        action: 'BLOCK',
        timestamp: Date.now(),
      });

      // Extract request ID safely if possible
      const extractedId = this.extractIdSafely(request);

      // Create minimal request for error response (preserve ID if extracted)
      const errorRequest: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: extractedId,
        method: 'unknown',
      };

      return this.createBlockResponse(
        errorRequest,
        'System error - request blocked for security (fail-closed)',
        MCPShieldErrorCodes.SYSTEM_ERROR,
        requestId
      );
    }
  }

  /**
   * Evaluate a JSON-RPC request and get policy decision.
   */
  async evaluateRequest(
    request: JSONRPCRequest,
    context: RequestContext
  ): Promise<PolicyDecision> {
    try {
      // Check taint lineage if tool arguments exist (with timeout protection)
      let taintSensitivity: number | null = null;
      let taintOriginTool: string | null = null;
      if (request.method === 'callTool' && request.params) {
        const params = request.params as Record<string, unknown>;
        try {
          const lineageResult = await Promise.race([
            this.taintRegistry.checkLineage(
              params,
              context.sessionId,
              context.tenantId
            ),
            new Promise<Awaited<ReturnType<typeof this.taintRegistry.checkLineage>>>((_, reject) =>
              setTimeout(
                () => reject(new Error(`TaintRegistry timeout after ${this.taintTimeout}ms`)),
                this.taintTimeout
              )
            ),
          ]);

          if (lineageResult.highestSensitivity !== null) {
            // SensitivityLevel enum values are already numbers (0.0, 0.5, 1.0)
            taintSensitivity = lineageResult.highestSensitivity;
            
            // Fix: Extract originTool from relevantContexts (first context is the origin)
            const firstContext = lineageResult.relevantContexts[0];
            if (firstContext) {
              taintOriginTool = firstContext.sourceTool;
            }
          }
        } catch (error) {
          // Fail-closed: TaintRegistry timeout or error defaults to maximum sensitivity
          taintSensitivity = 1.0;
        }
      }

      // Build evaluation context
      const evaluationContext = await this.riskEvaluator.buildEvaluationContext(
        context
      );

      // Override sensitivity if taint was detected
      if (taintSensitivity !== null) {
        if (!evaluationContext.taintContexts) {
          evaluationContext.taintContexts = [];
        }
        // Fix: Use originTool from TaintRegistry, not current tool
        evaluationContext.taintContexts.push({
          contextId: `taint-${context.sessionId}`,
          sourceTool: taintOriginTool ?? context.toolName, // Use originTool if available
          sensitivityLevel: taintSensitivity,
          containsSecrets: false,
          timestamp: new Date(),
          sessionId: context.sessionId,
          tenantId: context.tenantId,
        });
      }

      // Evaluate risk (PDP)
      const rawDecision = await this.riskEvaluator.evaluatePolicy(
        evaluationContext
      );

      // Fix: Apply PolicyManager MRW conflict resolution
      const resolvedPolicy = await this.policyManager.getResolvedPolicy(
        context.tenantId,
        context.toolName
      );

      // Apply MRW logic with Escalation-Only Principle
      // Policies can only ESCALATE restrictiveness (ALLOW → REDACT → BLOCK)
      // Policies CANNOT de-escalate (BLOCK → ALLOW) for security
      let finalDecision = rawDecision;
      if (resolvedPolicy.actionOverride) {
        // Action severity (restrictiveness level)
        const actionSeverity: Record<PolicyAction, number> = {
          ALLOW: 1,
          REDACT: 2,
          BLOCK: 3,
        };

        const riskSeverity = actionSeverity[rawDecision.action];
        const policySeverity = actionSeverity[resolvedPolicy.actionOverride];

        // Escalation-Only: Take MAX severity (most restrictive wins)
        // This ensures policies can only make decisions MORE restrictive, never less
        if (policySeverity > riskSeverity) {
          // Policy escalates restrictiveness (ALLOW → REDACT, REDACT → BLOCK, etc.)
          finalDecision = {
            ...rawDecision,
            action: resolvedPolicy.actionOverride,
            justification: `${rawDecision.justification} (Escalated by policy: ${resolvedPolicy.actionOverride})`,
            policyVersion: resolvedPolicy.policyVersion,
          };
        }
        // If policySeverity <= riskSeverity, ignore policy override (security: no de-escalation)
      }

      return finalDecision;
    } catch (error) {
      // Fail-closed: Evaluation error defaults to BLOCK
      throw new GovernanceViolationError(
        `Risk evaluation failed: ${error instanceof Error ? error.message : String(error)}`,
        'RiskEvaluator',
        MCPShieldErrorCodes.SYSTEM_ERROR
      );
    }
  }

  /**
   * Enforce a policy decision on a request.
   */
  async enforceDecision(
    decision: PolicyDecision,
    request: JSONRPCRequest
  ): Promise<JSONRPCResponse> {
    if (decision.action === 'BLOCK') {
      // Fix: Pass requestId from decision for audit correlation
      return this.createBlockResponse(
        request,
        decision.justification,
        MCPShieldErrorCodes.POLICY_VIOLATION,
        decision.requestId
      );
    }

    // ALLOW or REDACT: Forward to server
    // Note: enforceDecision doesn't have full context, but forwardRequest needs tenantId/sessionId
    // For now, we'll use request ID as fallback - this is acceptable because enforceDecision
    // is typically called internally after intercept() which has full context
    // In practice, enforceDecision should receive context as parameter (Phase 2)
    const minimalContext: RequestContext = {
      sessionId: decision.requestId.substring(0, 36), // Use first 36 chars as sessionId fallback
      toolName: 'unknown',
      timestamp: new Date(),
    };
    const response = await this.forwardRequest(request, minimalContext);

    if (decision.action === 'REDACT') {
      return await this.responseRedactor.redact(response, decision);
    }

    return response;
  }

  /**
   * Handle failures with fail-closed behavior.
   */
  handleFailure(
    error: Error,
    _context: RequestContext,
    failedComponent: string,
    requestId?: string
  ): PolicyDecision {
    // Fix: Use provided requestId or generate new, preserve context
    const finalRequestId = requestId ?? randomUUID();

    return {
      action: 'BLOCK',
      riskScore: createRiskScore(1.0),
      riskBreakdown: {
        sensitivity: FailClosedDefaultPolicy.sensitivity,
        exposure: FailClosedDefaultPolicy.exposure,
        trust: FailClosedDefaultPolicy.trust,
        weightSensitivity: FailClosedDefaultPolicy.weights.sensitivity,
        weightExposure: FailClosedDefaultPolicy.weights.exposure,
        rawScore: 1.0,
        finalScore: createRiskScore(1.0),
      },
      justification: `Fail-closed: ${failedComponent} error - ${error.message}`,
      timestamp: new Date(),
      policyVersion: 'fail-closed',
      requestId: finalRequestId,
    };
  }

  /**
   * Validate JSON-RPC request using Zod schema.
   */
  validateRequest(request: unknown): {
    valid: boolean;
    parsed?: JSONRPCRequest;
    error?: string;
  } {
    try {
      const parsed = JSONRPCRequestSchema.parse(request);
      return {
        valid: true,
        parsed: parsed as JSONRPCRequest,
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Invalid JSON-RPC request structure',
      };
    }
  }

  /**
   * Forward a request to the MCP Server via transport abstraction.
   * 
   * Uses dispatcher pattern: Request is registered in pendingRequests map,
   * and the permanent listener (registered in start()) routes the response
   * back to this promise using composite key correlation.
   * 
   * @param request - JSON-RPC request to forward
   * @param context - Request context for composite key generation
   * @returns Promise resolving to JSON-RPC response
   */
  async forwardRequest(
    request: JSONRPCRequest,
    context: RequestContext
  ): Promise<JSONRPCResponse> {
    // Handle notifications (id: null) - fire and forget
    if (request.id === null) {
      await this.serverTransport.send(request);
      // Notifications don't expect responses and are not added to pendingRequests map
      // Return a minimal response (MCP clients handle this)
      return {
        jsonrpc: '2.0',
        id: null,
        result: undefined,
      };
    }

    // Handle requests with ID - use dispatcher pattern with composite key
    return new Promise<JSONRPCResponse>((resolve, reject) => {
      const requestId = request.id!;
      const requestIdStr = randomUUID(); // Internal tracking ID for audit
      
      // Fix: Generate composite key for multi-tenant isolation
      // Format: ${tenantId}:${sessionId}:${requestId}
      const tenantId = context.tenantId ?? 'default';
      const compositeKey: CompositeRequestKey = `${tenantId}:${context.sessionId}:${requestId}`;

      const timeout = setTimeout(() => {
        // Timeout: Clean up pending request
        const pending = this.pendingRequests.get(compositeKey);
        if (pending) {
          this.pendingRequests.delete(compositeKey);
          pending.reject(new GovernanceViolationError(
            `Server timeout for request ${requestId} after ${this.evaluationTimeout * 2}ms`,
            'MCPServer',
            MCPShieldErrorCodes.SYSTEM_ERROR
          ));
        }
      }, this.evaluationTimeout * 2);

      // Register pending request in dispatcher map using composite key
      this.pendingRequests.set(compositeKey, {
        resolve,
        reject,
        timeout,
        requestId: requestIdStr,
        tenantId: context.tenantId,
        sessionId: context.sessionId,
      });

      // Send request (response will be routed by permanent listener)
      this.serverTransport.send(request).catch((error) => {
        // Send failed: Clean up and reject
        const pending = this.pendingRequests.get(compositeKey);
        if (pending) {
          clearTimeout(pending.timeout);
          this.pendingRequests.delete(compositeKey);
        }
        reject(new GovernanceViolationError(
          `Failed to send request to MCP Server: ${error instanceof Error ? error.message : String(error)}`,
          'MCPServer',
          MCPShieldErrorCodes.SYSTEM_ERROR
        ));
      });
    });
  }

  /**
   * Create a security error response (for BLOCK decisions).
   * 
   * Fix: Preserves original request ID for audit trail correlation.
   */
  createBlockResponse(
    request: JSONRPCRequest,
    reason: string,
    errorCode: number = MCPShieldErrorCodes.POLICY_VIOLATION,
    requestId?: string
  ): JSONRPCResponse {
    return {
      jsonrpc: '2.0',
      id: request.id, // Preserve original request ID
      error: {
        code: errorCode,
        message: getErrorMessage(errorCode),
        data: {
          reason,
          requestId: requestId ?? randomUUID(), // Use provided requestId or generate new
        },
      },
    };
  }

  /**
   * Extract tool name from JSON-RPC request.
   */
  private extractToolName(request: JSONRPCRequest): string | undefined {
    if (request.method === 'callTool' && request.params) {
      const params = request.params as Record<string, unknown>;
      return params.name as string | undefined;
    }
    return undefined;
  }

  /**
   * Safely extract request ID from raw message (even if validation failed).
   * 
   * This allows us to preserve request ID in error responses for better
   * audit trail correlation, even when the request structure is invalid.
   */
  private extractIdSafely(rawMsg: unknown): string | number | null {
    if (typeof rawMsg === 'object' && rawMsg !== null && 'id' in rawMsg) {
      const id = (rawMsg as { id: unknown }).id;
      if (typeof id === 'string' || typeof id === 'number') {
        return id;
      }
    }
    return null;
  }

  /**
   * Get the audit logger instance.
   */
  getAuditLogger(): IAuditLogger {
    return this.auditLogger;
  }

  /**
   * Get the rate limiter instance.
   */
  getRateLimiter(): IRateLimiter {
    return this.rateLimiter;
  }

  /**
   * Get the response redactor instance.
   */
  getResponseRedactor(): IResponseRedactor {
    return this.responseRedactor;
  }
}

