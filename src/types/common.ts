/**
 * TaintGate: Common Types
 * 
 * Shared types used across the TaintGate architecture.
 */

import type { MCPToolAnnotations, SensitivityLevel } from './mcp-hints';

/**
 * Policy Decision Actions
 * 
 * @deprecated Use PolicyAction from '../types/governance' instead.
 * This type is kept for backward compatibility but will be removed in v2.0.
 */
export type PolicyDecisionAction = 'ALLOW' | 'BLOCK' | 'REDACT';

/**
 * Risk Score
 * Branded type ensuring values are validated [0, 1].
 * 
 * This prevents accidental use of percentage values (0-100) or other ranges.
 * Use `createRiskScore()` helper to create validated RiskScore values.
 * 
 * Normalized value in range [0, 1] where:
 * - 0.0 = No risk
 * - 1.0 = Maximum risk
 */
export type RiskScore = number & { readonly __brand: 'RiskScore' };

/**
 * Creates a validated RiskScore value.
 * 
 * @param value - Raw number to validate and convert
 * @returns RiskScore if value is in [0, 1], throws otherwise
 * @throws {RangeError} If value is not in [0, 1]
 */
export function createRiskScore(value: number): RiskScore {
  if (value < 0 || value > 1) {
    throw new RangeError(`RiskScore must be in [0, 1], got ${value}`);
  }
  return value as RiskScore;
}

/**
 * Clamps a value to [0, 1] and returns as RiskScore.
 * 
 * @param value - Raw number to clamp
 * @returns RiskScore clamped to [0, 1]
 */
export function clampRiskScore(value: number): RiskScore {
  const clamped = Math.max(0, Math.min(1, value));
  return clamped as RiskScore;
}

/**
 * Policy Decision
 * Result of policy evaluation containing action and risk score.
 * 
 * @deprecated Use PolicyDecision from '../types/governance' instead.
 * This interface is kept for backward compatibility but will be removed in v2.0.
 */
export interface PolicyDecision {
  /**
   * The enforcement action to take
   */
  action: PolicyDecisionAction;
  
  /**
   * Calculated risk score [0, 1]
   */
  riskScore: RiskScore;
  
  /**
   * Breakdown of risk calculation
   */
  riskBreakdown: RiskBreakdown;
  
  /**
   * Justification for the decision
   */
  justification: string;
  
  /**
   * Timestamp of decision
   */
  timestamp: Date;
  
  /**
   * Whether human-in-the-loop approval is required
   */
  requiresHITL?: boolean;
  
  /**
   * Policy version ID that was active when this decision was made.
   * Used for auditability and policy rollback scenarios.
   */
  policyVersion: string;
  
  /**
   * Request ID for correlation with audit logs
   */
  requestId: string;
}

// Re-export from governance for unified types
// Note: PolicyDecision in common.ts is deprecated, use from './governance' instead
export type { 
  PolicyAction, 
} from './governance';

/**
 * Risk Calculation Breakdown
 * Detailed components of the risk score calculation.
 */
export interface RiskBreakdown {
  /**
   * Sensitivity value (S) used in calculation
   */
  sensitivity: number;
  
  /**
   * Exposure value (E) used in calculation
   */
  exposure: number;
  
  /**
   * Trust value (T) used in calculation
   */
  trust: number;
  
  /**
   * Weight for sensitivity (W_s)
   */
  weightSensitivity: number;
  
  /**
   * Weight for exposure (W_e)
   */
  weightExposure: number;
  
  /**
   * Raw calculation: (W_s × S + W_e × E) × (1 - T)
   */
  rawScore: number;
  
  /**
   * Final clamped risk score
   */
  finalScore: RiskScore;
}

/**
 * Request Context
 * Context information for policy evaluation.
 */
export interface RequestContext {
  /**
   * Unique session identifier
   */
  sessionId: string;
  
  /**
   * Tenant identifier for multi-tenant isolation
   */
  tenantId?: string;
  
  /**
   * Tool name being invoked
   */
  toolName: string;
  
  /**
   * Tool parameters
   */
  toolParameters?: Record<string, unknown>;
  
  /**
   * MCP tool annotations (security hints)
   */
  toolAnnotations?: MCPToolAnnotations;
  
  /**
   * Request timestamp
   */
  timestamp: Date;
  
  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>;
}

/**
 * JSON-RPC Request
 * Standard JSON-RPC 2.0 request structure.
 */
export interface JSONRPCRequest {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: Record<string, unknown> | unknown[];
}

/**
 * JSON-RPC Response
 * Standard JSON-RPC 2.0 response structure.
 */
export interface JSONRPCResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: JSONRPCError;
}

/**
 * JSON-RPC Error
 * Standard JSON-RPC 2.0 error structure.
 */
export interface JSONRPCError {
  code: number;
  message: string;
  data?: unknown;
}

/**
 * Taint Context
 * Represents a tainted data context in the session.
 */
export interface TaintContext {
  /**
   * Unique context identifier
   */
  contextId: string;
  
  /**
   * Tool that produced the tainted data
   */
  sourceTool: string;
  
  /**
   * Sensitivity level of the tainted data
   */
  sensitivityLevel: SensitivityLevel;
  
  /**
   * Whether the context contains secrets
   */
  containsSecrets: boolean;
  
  /**
   * Timestamp when taint was created
   */
  timestamp: Date;
  
  /**
   * Session ID this taint belongs to
   */
  sessionId: string;
  
  /**
   * Tenant ID for isolation
   */
  tenantId?: string;
}

/**
 * Evaluation Context
 * Complete context for risk evaluation.
 */
export interface EvaluationContext extends RequestContext {
  /**
   * Current taint contexts affecting this evaluation
   */
  taintContexts?: TaintContext[];
  
  /**
   * Historical trust score for the tool (if available)
   */
  historicalTrust?: number;
}

