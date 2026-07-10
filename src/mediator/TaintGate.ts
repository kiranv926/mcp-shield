/**
 * TaintGate: TaintGate Implementation
 * 
 * Policy Enforcement Point (PEP) implementation for TaintGate.
 * 
 * The TaintGate is the "Gatekeeper" that intercepts all JSON-RPC requests
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
  TaintGateErrorCodes,
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
import { ResponseScraper } from '../core/ResponseScraper';
import { SensitivityLevel } from '../types/mcp-hints';

/**
 * Standard MCP JSON-RPC method names.
 *
 * These are the canonical method strings defined by the MCP specification.
 * Centralizing them in one constant block prevents string-literal drift such as
 * the legacy 'callTool'/'listTools' names, which silently no-op governance
 * (tool-name extraction, taint lineage, taint registration) on real MCP traffic.
 *
 * MCP `tools/call` request shape: { method: 'tools/call', params: { name, arguments } }
 *
 * @see https://spec.modelcontextprotocol.io - tools/call, tools/list
 */
export const MCP_METHODS = {
  /** Tool invocation. params = { name, arguments } */
  TOOLS_CALL: 'tools/call',
  /** Tool listing. */
  TOOLS_LIST: 'tools/list',
} as const;

/**
 * TaintGate Configuration
 */
export interface TaintGateConfig {
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
   * Client transport (from MCP Client to TaintGate)
   */
  clientTransport: ITransport;
  
  /**
   * Server transport (from TaintGate to MCP Server)
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
    public readonly errorCode: number = TaintGateErrorCodes.SYSTEM_ERROR
  ) {
    super(message);
    this.name = 'GovernanceViolationError';
  }
}

/**
 * TaintGate - Policy Enforcement Point Implementation
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
  /**
   * The ORIGINAL JSON-RPC id supplied by the client.
   *
   * Outbound requests are sent to the server with a globally-unique wire id
   * (the composite key) so responses can be correlated without cross-tenant
   * collisions. This field lets us restore the client's original id on the way back.
   */
  originalId: string | number;
}

/**
 * Composite Key for Request-Response Correlation
 * Format: ${tenantId}:${sessionId}:${requestId}
 * 
 * This ensures multi-tenant isolation and prevents ID collisions
 * in environments where multiple clients use the same request IDs.
 */
type CompositeRequestKey = string;

export class TaintGate implements IMediator {
  private readonly riskEvaluator: IRiskEvaluator;
  private readonly taintRegistry: ITaintRegistry;
  private readonly policyManager: IPolicyManager;
  private readonly rateLimiter: IRateLimiter;
  private readonly responseRedactor: IResponseRedactor;
  private readonly auditLogger: IAuditLogger;
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

  constructor(config: TaintGateConfig) {
    this.riskEvaluator = config.riskEvaluator;
    this.taintRegistry = config.taintRegistry;
    this.policyManager = config.policyManager;
    this.rateLimiter = config.rateLimiter;
    this.responseRedactor = config.responseRedactor;
    this.auditLogger = config.auditLogger;
    // Note: config.clientTransport is accepted for API compatibility but not retained;
    // the mediator only drives the server transport in the current request/response flow.
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
      throw new Error('TaintGate is already started');
    }

    // Register single permanent listener for server transport responses.
    //
    // Responses are correlated by the WIRE ID that forwardRequest() stamped on the
    // outbound request. The wire id IS the composite key (tenantId:sessionId:requestId:uuid),
    // so lookup is an O(1) exact match that CANNOT cross tenant/session boundaries.
    //
    // SECURITY: The previous implementation searched every pending request by JSON-RPC
    // id alone, ignoring tenant/session. Two tenants that both used id=1 could receive
    // each other's responses (cross-tenant data leak). Keying on the composite wire id
    // eliminates that entire class of mis-routing.
    this.serverTransport.onMessage(async (message: JSONRPCRequest | JSONRPCResponse) => {
      // Only handle responses (have result or error, not method)
      if (!('result' in message || 'error' in message)) {
        return;
      }

      const wireId = message.id;
      if (wireId === null || wireId === undefined) {
        return;
      }

      // Exact composite-key lookup (no cross-tenant scan).
      const pending = this.pendingRequests.get(String(wireId));
      if (!pending) {
        // Orphaned response - no matching pending request.
        // Expected for notifications or responses from previous sessions.
        return;
      }

      clearTimeout(pending.timeout);
      this.pendingRequests.delete(String(wireId));

      try {
        // Validate server response with Zod schema
        const validated = JSONRPCResponseSchema.parse(message) as JSONRPCResponse;
        // Restore the client's original JSON-RPC id (the wire id was internal only).
        pending.resolve({ ...validated, id: pending.originalId });
      } catch (validationError) {
        // Invalid response - reject with error
        pending.reject(new GovernanceViolationError(
          `Server returned invalid JSON-RPC response: ${validationError instanceof Error ? validationError.message : String(validationError)}`,
          'MCPServer',
          TaintGateErrorCodes.SYSTEM_ERROR
        ));
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
          TaintGateErrorCodes.VALIDATION_FAILED,
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

      // Step 3: Rate Limiting (atomic check-and-record)
      // Use tryConsume() so the check and the record happen in ONE synchronous
      // critical section. The previous check-then-record pattern had a TOCTOU
      // window: N concurrent intercept() calls could all pass checkLimit() before
      // any recordRequest() ran, bypassing the limit under concurrency.
      const rateLimitResult = this.rateLimiter.tryConsume(
        context.tenantId ?? 'default',
        toolName
      );

      if (!rateLimitResult.allowed) {
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

        // Rate limit blocks don't have lineage (request never reached governance)
        await this.auditLogger.logDecision({
          requestId,
          sessionId: context.sessionId,
          tenantId: context.tenantId,
          decision: rateLimitDecision,
          taintContexts: [],
          policyVersion: 'rate-limit',
          timestamp: Date.now(),
          toolName,
          metadata: {
            reason: 'rate_limit',
          },
        });

        // Note: tryConsume() only consumes a token when the request is allowed,
        // so a rate-limited request does not need (or get) a separate record call.
        return this.createBlockResponse(
          parsedRequest,
          'Too many requests - rate limit exceeded',
          TaintGateErrorCodes.RATE_LIMITED,
          requestId
        );
      }

      // Step 4: Governance (PDP/PEP)
      // Check taint lineage and evaluate risk
      // CRITICAL FIX: Capture lineage result for audit logging before governance evaluation
      let lineageResult: Awaited<ReturnType<typeof this.taintRegistry.checkLineage>> | null = null;
      
      // Perform lineage check if this is a tool call
      if (parsedRequest.method === MCP_METHODS.TOOLS_CALL && parsedRequest.params) {
        // MCP tools/call args live at params.arguments; scan those for taint lineage.
        const toolArgs = this.extractToolArguments(parsedRequest);
        try {
          lineageResult = await this.raceWithTimeout(
            this.taintRegistry.checkLineage(
              toolArgs,
              enrichedContext.sessionId,
              enrichedContext.tenantId
            ),
            this.taintTimeout,
            () => new Error(`TaintRegistry timeout after ${this.taintTimeout}ms`)
          );
        } catch (error) {
          // Fail-closed: TaintRegistry timeout or error - lineageResult remains null
          // This will be handled in evaluateRequest
        }
      }
      
      // Evaluate governance decision (lineageResult passed for efficiency)
      let decision: PolicyDecision;
      try {
        decision = await this.raceWithTimeout(
          this.evaluateRequest(parsedRequest, enrichedContext, lineageResult),
          this.evaluationTimeout,
          () => new GovernanceViolationError(
            `Evaluation timeout after ${this.evaluationTimeout}ms`,
            'RiskEvaluator',
            TaintGateErrorCodes.POLICY_VIOLATION
          )
        );

        // NOTE: Secret-driven escalation (ALLOW -> REDACT, REDACT -> BLOCK) is handled
        // in ONE place -- RiskEvaluator.evaluatePolicy() via hasSecretLeakage(). That is
        // the single, consistent signal for secret escalation (and it also fails closed
        // on a missing secret hint). The mediator no longer re-escalates here, which
        // previously duplicated that logic with a divergent `secret === true` check.
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
        // CRITICAL FIX: Include lineage metadata for BLOCK decisions too
        // This ensures origin tools are available in audit logs even when blocking
        const lineageMetadata = lineageResult ? {
          originTools: lineageResult.originTools || [],
          matchedContextIds: lineageResult.relevantContexts.map(c => c.contextId),
          highestSensitivity: lineageResult.highestSensitivity,
          containsSecrets: lineageResult.containsSecrets,
        } : undefined;

        await this.auditLogger.logDecision({
          requestId,
          sessionId: context.sessionId,
          tenantId: context.tenantId,
          decision,
          taintContexts: lineageResult?.relevantContexts || [],
          policyVersion: decision.policyVersion,
          timestamp: Date.now(),
          toolName,
          metadata: lineageMetadata,
        });

        // Rate limiting was already accounted for atomically in Step 3 (tryConsume),
        // which consumes a token for every request that passes rate limiting -- including
        // those later blocked by governance. No separate record call is needed here.
        return this.createBlockResponse(
          parsedRequest,
          decision.justification,
          TaintGateErrorCodes.POLICY_VIOLATION,
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
          TaintGateErrorCodes.SYSTEM_ERROR,
          requestId
        );
      }

      // Rate limiting was already recorded atomically in Step 3 (tryConsume);
      // no separate record call is needed on the success path.

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
            TaintGateErrorCodes.SYSTEM_ERROR,
            requestId
          );
        }
      }

      // CRITICAL FIX (Issue #3): Extract and register taint from server response
      // This enables actual data value tracking, not just tool name tracking
      if (serverResponse.result && toolName && (decision.action === 'ALLOW' || decision.action === 'REDACT')) {
        try {
          // Extract sensitive values from tool response
          const sensitiveValues = this.extractSensitiveValues(serverResponse.result);
          
          // Only register taint if tool produced sensitive data
          // Check if tool annotations indicate sensitivity or if decision was REDACT
          const toolAnnotations = enrichedContext.toolAnnotations;
          // `sensitive` is a SensitivityLevel enum (Public=0.0, Internal=0.5, Confidential=1.0),
          // NOT a boolean. Only treat it as sensitive when the level is above Public;
          // the previous `!== undefined` check tainted even an explicit Public (0.0)
          // classification (over-tainting).
          const annotatedSensitive =
            toolAnnotations?.sensitive !== undefined &&
            toolAnnotations.sensitive > SensitivityLevel.Public;
          const isSensitive =
            annotatedSensitive ||
            toolAnnotations?.secret === true ||
            decision.action === 'REDACT' ||
            decision.riskScore >= 0.3; // Moderate to high risk
          
          if (isSensitive && sensitiveValues.length > 0) {
            // Register taint with actual data values
            await this.taintRegistry.registerTaint(
              {
                sourceTool: toolName,
                sensitivityLevel: this.inferSensitivityFromDecision(decision) as number,
                containsSecrets: toolAnnotations?.secret === true || false,
                sessionId: context.sessionId,
                tenantId: context.tenantId,
              },
              sensitiveValues // CRITICAL: Pass actual data values
            );
          }
        } catch (error) {
          // Fail-closed: Taint registration failure is logged but doesn't block response
          // This is non-critical for the current request but important for future requests
          await this.auditLogger.logSystemError({
            requestId,
            sessionId: context.sessionId,
            tenantId: context.tenantId,
            error: {
              type: error instanceof Error ? error.constructor.name : 'Error',
              message: error instanceof Error ? error.message : String(error),
              stack: error instanceof Error ? error.stack : undefined,
            },
            failedComponent: 'TaintRegistry',
            action: 'BLOCK', // System error defaults to BLOCK for audit consistency
            timestamp: Date.now(),
            context: {
              toolName,
            },
          });
        }
      }

      // Log successful decision with lineage provenance metadata
      // CRITICAL FIX: Pass origin tools and taint contexts from lineage check to audit logger
      // This ensures the complete data laundering path is available for audit reports
      const lineageMetadata = lineageResult ? {
        originTools: lineageResult.originTools || [],
        matchedContextIds: lineageResult.relevantContexts.map(c => c.contextId),
        highestSensitivity: lineageResult.highestSensitivity,
        containsSecrets: lineageResult.containsSecrets,
      } : undefined;

      await this.auditLogger.logDecision({
        requestId,
        sessionId: context.sessionId,
        tenantId: context.tenantId,
        decision,
        taintContexts: lineageResult?.relevantContexts || [],
        policyVersion: decision.policyVersion,
        timestamp: Date.now(),
        toolName,
        metadata: lineageMetadata,
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
        failedComponent: 'TaintGate',
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
        TaintGateErrorCodes.SYSTEM_ERROR,
        requestId
      );
    }
  }

  /**
   * Evaluate a JSON-RPC request and get policy decision.
   * 
   * @param request - JSON-RPC request to evaluate
   * @param context - Request context
   * @param lineageResult - Optional pre-computed lineage check result (for audit logging)
   */
  async evaluateRequest(
    request: JSONRPCRequest,
    context: RequestContext,
    lineageResult?: Awaited<ReturnType<typeof this.taintRegistry.checkLineage>> | null
  ): Promise<PolicyDecision> {
    try {
      // Check taint lineage if tool arguments exist (with timeout protection)
      // CRITICAL FIX: Use pre-computed lineageResult if available (from intercept)
      // Otherwise, compute it here (for backward compatibility)
      let taintSensitivity: number | null = null;
      let taintOriginTool: string | null = null;
      
      if (!lineageResult && request.method === MCP_METHODS.TOOLS_CALL && request.params) {
        // MCP tools/call args live at params.arguments; scan those for taint lineage.
        const toolArgs = this.extractToolArguments(request);
        try {
          lineageResult = await this.raceWithTimeout(
            this.taintRegistry.checkLineage(
              toolArgs,
              context.sessionId,
              context.tenantId
            ),
            this.taintTimeout,
            () => new Error(`TaintRegistry timeout after ${this.taintTimeout}ms`)
          );
        } catch (error) {
          // Fail-closed: TaintRegistry timeout or error defaults to maximum sensitivity
          taintSensitivity = 1.0;
          lineageResult = null;
        }
      }

      if (lineageResult && lineageResult.highestSensitivity !== null) {
        // SensitivityLevel enum values are already numbers (0.0, 0.5, 1.0)
        taintSensitivity = lineageResult.highestSensitivity;
        
        // Fix: Extract originTool from relevantContexts (first context is the origin)
        const firstContext = lineageResult.relevantContexts[0];
        if (firstContext) {
          taintOriginTool = firstContext.sourceTool;
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
        TaintGateErrorCodes.SYSTEM_ERROR
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
        TaintGateErrorCodes.POLICY_VIOLATION,
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
   * Extract sensitive values from tool response (Issue #3: Response Extraction)
   * 
   * IMPROVEMENT: Now uses ResponseScraper utility for consistent extraction logic.
   * The ResponseScraper handles sub-token extraction and DoS protection.
   * 
   * @param result - Tool response result (any JSON-serializable value)
   * @returns Array of extracted string values
   */
  private extractSensitiveValues(result: unknown): string[] {
    // Use ResponseScraper for consistent extraction logic
    return ResponseScraper.scrape(result);
  }
  
  /**
   * Infer sensitivity level from policy decision
   * 
   * Maps risk score to sensitivity level for taint registration.
   */
  private inferSensitivityFromDecision(decision: PolicyDecision): number {
    // Map risk score to sensitivity level (returns numeric value)
    if (decision.riskScore >= 0.7) {
      return 1.0; // Confidential/Restricted
    } else if (decision.riskScore >= 0.3) {
      return 0.5; // Internal
    } else {
      return 0.0; // Public
    }
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

    // Handle requests with ID - use dispatcher pattern with composite wire id.
    return new Promise<JSONRPCResponse>((resolve, reject) => {
      const originalId = request.id!;
      const requestIdStr = randomUUID(); // Internal tracking ID for audit

      // Generate a globally-unique composite WIRE ID for multi-tenant isolation.
      // Format: ${tenantId}:${sessionId}:${originalId}:${uuid}
      //
      // This wire id is stamped onto the outbound request and echoed back by the
      // server, so the dispatcher can resolve the exact pending request without a
      // cross-tenant scan. The trailing uuid guarantees uniqueness even if a client
      // reuses an in-flight id within the same tenant/session.
      const tenantId = context.tenantId ?? 'default';
      const wireId: CompositeRequestKey = `${tenantId}:${context.sessionId}:${originalId}:${requestIdStr}`;

      // Rewrite the outbound id to the wire id; the client's original id is restored
      // by the dispatcher before the response is handed back.
      const outboundRequest: JSONRPCRequest = { ...request, id: wireId };

      const timeout = setTimeout(() => {
        // Timeout: Clean up pending request
        const pending = this.pendingRequests.get(wireId);
        if (pending) {
          this.pendingRequests.delete(wireId);
          pending.reject(new GovernanceViolationError(
            `Server timeout for request ${originalId} after ${this.evaluationTimeout * 2}ms`,
            'MCPServer',
            TaintGateErrorCodes.SYSTEM_ERROR
          ));
        }
      }, this.evaluationTimeout * 2);

      // Register pending request in dispatcher map using the composite wire id.
      this.pendingRequests.set(wireId, {
        resolve,
        reject,
        timeout,
        requestId: requestIdStr,
        tenantId: context.tenantId,
        sessionId: context.sessionId,
        originalId,
      });

      // Send request (response will be routed by permanent listener)
      this.serverTransport.send(outboundRequest).catch((error) => {
        // Send failed: Clean up and reject
        const pending = this.pendingRequests.get(wireId);
        if (pending) {
          clearTimeout(pending.timeout);
          this.pendingRequests.delete(wireId);
        }
        reject(new GovernanceViolationError(
          `Failed to send request to MCP Server: ${error instanceof Error ? error.message : String(error)}`,
          'MCPServer',
          TaintGateErrorCodes.SYSTEM_ERROR
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
    errorCode: number = TaintGateErrorCodes.POLICY_VIOLATION,
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
   * Race an async operation against a timeout, clearing the timer once the
   * operation settles so it does not linger and keep the event loop alive.
   *
   * Fail-closed semantics are preserved: if the timeout wins, it rejects with
   * the provided error and the caller's catch defaults to BLOCK.
   */
  private async raceWithTimeout<T>(
    operation: Promise<T>,
    timeoutMs: number,
    makeTimeoutError: () => Error
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<T>((_, reject) => {
      timer = setTimeout(() => reject(makeTimeoutError()), timeoutMs);
    });
    try {
      return await Promise.race([operation, timeout]);
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }
  }

  /**
   * Extract tool name from a JSON-RPC request.
   *
   * MCP `tools/call` shape: { method: 'tools/call', params: { name, arguments } }
   * The tool name lives at params.name.
   */
  private extractToolName(request: JSONRPCRequest): string | undefined {
    if (request.method === MCP_METHODS.TOOLS_CALL && request.params) {
      const params = request.params as Record<string, unknown>;
      return params.name as string | undefined;
    }
    return undefined;
  }

  /**
   * Extract the tool arguments object from a JSON-RPC request.
   *
   * MCP `tools/call` shape: { method: 'tools/call', params: { name, arguments } }
   * The actual arguments (the data flowing into the tool, which is what taint
   * lineage must scan) live at params.arguments.
   *
   * Fail-closed: if a well-formed `arguments` object is absent, fall back to
   * scanning the whole params object so taint detection errs toward inspecting
   * more rather than less.
   */
  private extractToolArguments(request: JSONRPCRequest): Record<string, unknown> {
    if (request.method === MCP_METHODS.TOOLS_CALL && request.params) {
      const params = request.params as Record<string, unknown>;
      const args = params.arguments;
      if (args !== null && typeof args === 'object' && !Array.isArray(args)) {
        return args as Record<string, unknown>;
      }
      return params;
    }
    return {};
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

