/**
 * TaintGate: IRiskEvaluator Interface
 * 
 * Policy Decision Point (PDP) interface for RiskEvaluator.
 * 
 * The RiskEvaluator implements the deterministic risk calculation algorithm:
 * R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)
 * 
 * @see ARCHITECTURE.md - Layer 2: Policy Decision Point (PDP)
 */

import type {
  EvaluationContext,
  RiskScore,
  RiskBreakdown,
} from '../types/common';
import type { PolicyDecision } from '../types/governance';
import type { MCPToolAnnotations } from '../types/mcp-hints';
import type { IPolicyManager } from './IPolicyManager';

/**
 * Risk Evaluation Configuration
 */
export interface RiskEvaluationConfig {
  /**
   * Weight for sensitivity (W_s)
   * Default: 0.6
   */
  weightSensitivity: number;
  
  /**
   * Weight for exposure (W_e)
   * Default: 0.4
   */
  weightExposure: number;
  
  /**
   * Risk threshold for ALLOW decision
   * Default: 0.3
   */
  thresholdAllow: number;
  
  /**
   * Risk threshold for BLOCK decision
   * Default: 0.7
   */
  thresholdBlock: number;
  
  /**
   * Whether to enable context-aware taint evaluation
   * Default: true
   */
  enableTaintEvaluation: boolean;
}

/**
 * IRiskEvaluator - Policy Decision Point Interface
 * 
 * Responsibilities:
 * 1. Calculate risk scores using normalized formula
 * 2. Evaluate MCP tool annotations (security hints)
 * 3. Query TaintRegistry for context lineage
 * 4. Apply policies from PolicyManager (PAP)
 * 5. Return deterministic policy decisions
 */
export interface IRiskEvaluator {
  /**
   * Evaluate a request and calculate risk score.
   * 
   * This method implements the core risk calculation:
   * R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)
   * 
   * @param context - Complete evaluation context
   * @returns Promise resolving to risk score [0, 1]
   */
  calculateRisk(context: EvaluationContext): Promise<RiskScore>;

  /**
   * Evaluate a request and return policy decision.
   * 
   * This method:
   * 1. Calculates risk score
   * 2. Applies risk thresholds
   * 3. Determines action (ALLOW/BLOCK/REDACT)
   * 4. Returns complete policy decision
   * 
   * @param context - Complete evaluation context
   * @returns Promise resolving to policy decision
   */
  evaluatePolicy(context: EvaluationContext): Promise<PolicyDecision>;

  /**
   * Extract and normalize risk factors from tool annotations.
   * 
   * Extracts Sensitivity (S), Exposure (E), and Trust (T) from
   * MCP tool annotations, applying fail-closed defaults for missing hints.
   * 
   * @param annotations - MCP tool annotations
   * @returns Normalized risk factors {sensitivity, exposure, trust}
   */
  extractRiskFactors(annotations?: MCPToolAnnotations): {
    sensitivity: number;
    exposure: number;
    trust: number;
  };

  /**
   * Calculate risk score from risk factors.
   * 
   * Implements: R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)
   * 
   * @param sensitivity - Sensitivity value (S) {0, 0.5, 1.0}
   * @param exposure - Exposure value (E) {0, 1}
   * @param trust - Trust value (T) [0, 1]
   * @returns Risk score [0, 1]
   */
  calculateRiskScore(
    sensitivity: number,
    exposure: number,
    trust: number
  ): RiskScore;

  /**
   * Get detailed risk breakdown for audit logging.
   * 
   * @param context - Evaluation context
   * @returns Promise resolving to risk breakdown
   */
  getRiskBreakdown(context: EvaluationContext): Promise<RiskBreakdown>;

  /**
   * Determine policy action from risk score.
   * 
   * Decision logic (inclusive/exclusive boundaries):
   * - 0.0 ≤ R < thresholdAllow → ALLOW (low risk, full pass-through)
   * - thresholdAllow ≤ R < thresholdBlock → REDACT (moderate risk, scrub output)
   * - thresholdBlock ≤ R ≤ 1.0 → BLOCK (high risk, immediate termination)
   * 
   * @param riskScore - Calculated risk score [0, 1]
   * @returns Policy action
   */
  determineAction(riskScore: RiskScore): PolicyAction;

  /**
   * Build evaluation context from request context.
   * 
   * Enriches request context with:
   * - Taint contexts from TaintRegistry
   * - Historical trust scores
   * - Policy configurations (pulled from PolicyManager with caching)
   * 
   * **Policy Integration Pattern: Pull-with-Cache**
   * - RiskEvaluator holds a reference to PolicyManager
   * - During evaluate(), requests latest RiskEvaluationConfig
   * - PolicyManager handles caching and hot-reloading internally
   * - This keeps RiskEvaluator focused on math, not policy management
   * 
   * @param context - Base request context
   * @returns Promise resolving to complete evaluation context
   */
  buildEvaluationContext(context: RequestContext): Promise<EvaluationContext>;

  /**
   * Get the policy manager instance.
   * 
   * Used for pull-with-cache pattern: RiskEvaluator pulls policies
   * from PolicyManager when needed, rather than having policies pushed.
   * 
   * @returns IPolicyManager instance
   */
  getPolicyManager(): IPolicyManager;

  /**
   * Get current risk evaluation configuration.
   * 
   * @returns Current configuration
   */
  getConfig(): RiskEvaluationConfig;

  /**
   * Update risk evaluation configuration.
   * 
   * @param config - New configuration (partial update supported)
   */
  updateConfig(config: Partial<RiskEvaluationConfig>): void;
}

// Import RequestContext and PolicyAction for buildEvaluationContext
import type { RequestContext } from '../types/common';
import type { PolicyAction } from '../types/governance';

