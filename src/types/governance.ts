/**
 * TaintGate: Governance Types
 * 
 * Core governance types used across the TaintGate architecture.
 * This is the single source of truth for policy actions and governance decisions.
 */

import type { RiskScore, RiskBreakdown } from './common';

/**
 * Policy Action
 * 
 * The three possible enforcement actions for a policy decision.
 * This is the unified type used throughout the system.
 */
export type PolicyAction = 'ALLOW' | 'BLOCK' | 'REDACT';

/**
 * Policy Decision
 * Result of policy evaluation containing action and risk score.
 */
export interface PolicyDecision {
  /**
   * The enforcement action to take
   */
  action: PolicyAction;
  
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

/**
 * Fail-Closed Default Policy
 * 
 * When no policies exist, this static policy is applied:
 * - S = 1.0 (maximum sensitivity)
 * - E = 1 (maximum egress risk)
 * - T = 0 (untrusted)
 * 
 * This results in R = clamp((W_s × 1.0 + W_e × 1) × (1 - 0), 0, 1) = 1.0
 * Which always results in BLOCK.
 */
export const FailClosedDefaultPolicy = {
  sensitivity: 1.0,
  exposure: 1,
  trust: 0,
  thresholdAllow: 0.3,
  thresholdBlock: 0.7,
  weights: {
    sensitivity: 0.6,
    exposure: 0.4,
  },
} as const;

