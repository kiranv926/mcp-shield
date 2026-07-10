/**
 * TaintGate: RiskEvaluator Implementation
 * 
 * Policy Decision Point (PDP) implementation for TaintGate.
 * 
 * The RiskEvaluator implements the deterministic risk calculation algorithm:
 * R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)
 * 
 * @see ARCHITECTURE.md - Layer 2: Policy Decision Point (PDP)
 */

import { randomUUID } from 'crypto';
import type { IRiskEvaluator, RiskEvaluationConfig } from '../interfaces/IRiskEvaluator';
import type { IPolicyManager, PolicyResolution } from '../interfaces/IPolicyManager';
import type { ITaintRegistry } from '../interfaces/ITaintRegistry';
import type {
  EvaluationContext,
  RequestContext,
  RiskScore,
  RiskBreakdown,
  TaintContext,
} from '../types/common';
import type { PolicyDecision, PolicyAction } from '../types/governance';
import type { MCPToolAnnotations } from '../types/mcp-hints';
import {
  extractTrust,
  extractSensitivity,
  extractExposure,
  hasSecretLeakage,
  SensitivityLevel,
} from '../types/mcp-hints';
import { clampRiskScore, createRiskScore } from '../types/common';

/**
 * Constants for risk evaluation
 */
const HITL_THRESHOLD = 0.8;
const DEFAULT_EVALUATION_TIMEOUT = 5000; // 5 seconds
const SECRET_HINT_HIGH_RISK_THRESHOLD = 0.5;

/**
 * Optional logger interface for structured logging
 */
export interface ILogger {
  error(message: string, context?: Record<string, unknown>): void;
  warn(message: string, context?: Record<string, unknown>): void;
  info(message: string, context?: Record<string, unknown>): void;
}

/**
 * RiskEvaluator Configuration
 */
export interface RiskEvaluatorConfig {
  /**
   * PolicyManager instance (required for policy resolution)
   */
  policyManager: IPolicyManager;
  
  /**
   * TaintRegistry instance (required for lineage checking)
   */
  taintRegistry: ITaintRegistry;
  
  /**
   * Default risk evaluation configuration (used if PolicyManager unavailable)
   */
  defaultConfig?: Partial<RiskEvaluationConfig>;
  
  /**
   * Optional logger for structured logging
   */
  logger?: ILogger;
  
  /**
   * Evaluation timeout in milliseconds
   * Default: 5000ms
   */
  evaluationTimeout?: number;
  
  /**
   * Enable fail-closed behavior for TaintRegistry failures
   * Default: true
   */
  failClosedOnTaintError?: boolean;
}

/**
 * RiskEvaluator - Policy Decision Point Implementation
 * 
 * Calculates deterministic risk scores and makes policy decisions.
 */
export class RiskEvaluator implements IRiskEvaluator {
  private readonly policyManager: IPolicyManager;
  private readonly taintRegistry: ITaintRegistry;
  private readonly logger?: ILogger;
  private readonly evaluationTimeout: number;
  private readonly failClosedOnTaintError: boolean;
  private config: RiskEvaluationConfig;

  constructor(config: RiskEvaluatorConfig) {
    if (!config.policyManager) {
      throw new Error('PolicyManager is required');
    }
    if (!config.taintRegistry) {
      throw new Error('TaintRegistry is required');
    }

    this.policyManager = config.policyManager;
    this.taintRegistry = config.taintRegistry;
    this.logger = config.logger;
    this.evaluationTimeout = config.evaluationTimeout ?? DEFAULT_EVALUATION_TIMEOUT;
    this.failClosedOnTaintError = config.failClosedOnTaintError ?? true;
    
    // Initialize with defaults or provided config
    this.config = {
      weightSensitivity: config.defaultConfig?.weightSensitivity ?? 0.6,
      weightExposure: config.defaultConfig?.weightExposure ?? 0.4,
      thresholdAllow: config.defaultConfig?.thresholdAllow ?? 0.3,
      thresholdBlock: config.defaultConfig?.thresholdBlock ?? 0.7,
      enableTaintEvaluation: config.defaultConfig?.enableTaintEvaluation ?? true,
    };
    
    // Validate initial config
    this.validateRiskConfig(this.config);
  }

  /**
   * Calculate risk score from evaluation context
   * 
   * @param context - Evaluation context
   * @param riskConfig - Optional pre-fetched risk config (avoids duplicate calls)
   */
  async calculateRisk(
    context: EvaluationContext,
    riskConfig?: RiskEvaluationConfig
  ): Promise<RiskScore> {
    // Get risk factors
    const factors = this.extractRiskFactors(context.toolAnnotations);
    this.validateRiskFactors(factors);
    
    // Calculate effective sensitivity (incorporates taint contexts)
    const sensitivity = this.calculateEffectiveSensitivity(
      context.toolAnnotations,
      context.taintContexts
    );

    // Get configuration from PolicyManager if not provided
    const config = riskConfig ?? await this.withTimeout(
      this.policyManager.getRiskEvaluationConfig(context.tenantId, context.toolName),
      this.evaluationTimeout,
      'PolicyManager.getRiskEvaluationConfig'
    );
    
    this.validateRiskConfig(config);

    // Calculate risk score
    return this.calculateRiskScore(
      sensitivity,
      factors.exposure,
      factors.trust,
      config.weightSensitivity,
      config.weightExposure
    );
  }

  /**
   * Evaluate policy and return decision
   */
  async evaluatePolicy(context: EvaluationContext): Promise<PolicyDecision> {
    try {
      // Fetch config and policy once (avoid duplicate calls)
      const [riskConfig, resolvedPolicy] = await Promise.all([
        this.withTimeout(
          this.policyManager.getRiskEvaluationConfig(context.tenantId, context.toolName),
          this.evaluationTimeout,
          'PolicyManager.getRiskEvaluationConfig'
        ),
        this.withTimeout(
          this.policyManager.getResolvedPolicy(context.tenantId, context.toolName),
          this.evaluationTimeout,
          'PolicyManager.getResolvedPolicy'
        ),
      ]);
      
      this.validateRiskConfig(riskConfig);
      
      // Calculate risk score (pass config to avoid duplicate fetch)
      const riskScore = await this.calculateRisk(context, riskConfig);

      // Determine action from risk score
      let action = this.determineAction(riskScore, riskConfig.thresholdAllow, riskConfig.thresholdBlock);

      // Enhanced secretHint escalation: ALLOW → REDACT, REDACT → BLOCK (if high risk)
      if (hasSecretLeakage(context.toolAnnotations)) {
        if (action === 'ALLOW') {
          action = 'REDACT';
        } else if (action === 'REDACT' && (riskScore as number) >= SECRET_HINT_HIGH_RISK_THRESHOLD) {
          // High-risk with secrets → BLOCK
          action = 'BLOCK';
        }
      }

      // Get risk breakdown (reuse config)
      const breakdown = await this.getRiskBreakdown(context, riskConfig);

      // Build justification
      const justification = this.buildJustification(
        action,
        riskScore,
        context,
        resolvedPolicy,
        breakdown
      );

      // Check for HITL requirement
      const requiresHITL = this.checkHITLRequirement(context, riskScore);

      return {
        action,
        riskScore,
        riskBreakdown: breakdown,
        justification,
        timestamp: new Date(),
        requiresHITL,
        policyVersion: resolvedPolicy.policyVersion,
        requestId: context.metadata?.requestId as string || randomUUID(),
      };
    } catch (error) {
      // Fail-closed: PolicyManager failure defaults to maximum risk
      this.logger?.error('Policy evaluation failed', {
        error: error instanceof Error ? error.message : String(error),
        sessionId: context.sessionId,
        tenantId: context.tenantId,
        toolName: context.toolName,
      });
      
      return this.createFailClosedDecision(context, error);
    }
  }

  /**
   * Extract and normalize risk factors from tool annotations
   */
  extractRiskFactors(annotations?: MCPToolAnnotations): {
    sensitivity: number;
    exposure: number;
    trust: number;
  } {
    return {
      sensitivity: extractSensitivity(annotations),
      exposure: extractExposure(annotations),
      trust: extractTrust(annotations),
    };
  }

  /**
   * Calculate risk score from risk factors
   * 
   * Implements: R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)
   */
  calculateRiskScore(
    sensitivity: number,
    exposure: number,
    trust: number,
    weightSensitivity?: number,
    weightExposure?: number
  ): RiskScore {
    // Validate inputs
    if (!Number.isFinite(sensitivity) || !Number.isFinite(exposure) || !Number.isFinite(trust)) {
      throw new RangeError(
        `Risk factors must be finite numbers: sensitivity=${sensitivity}, exposure=${exposure}, trust=${trust}`
      );
    }
    
    // Use provided weights or default config
    const W_s = weightSensitivity ?? this.config.weightSensitivity;
    const W_e = weightExposure ?? this.config.weightExposure;
    
    if (!Number.isFinite(W_s) || !Number.isFinite(W_e)) {
      throw new RangeError(`Weights must be finite numbers: W_s=${W_s}, W_e=${W_e}`);
    }

    // Calculate: (W_s × S + W_e × E) × (1 - T)
    const weightedSum = W_s * sensitivity + W_e * exposure;
    const trustFactor = 1 - trust;
    const rawScore = weightedSum * trustFactor;

    // Clamp to [0, 1]
    return clampRiskScore(rawScore);
  }

  /**
   * Get detailed risk breakdown for audit logging
   * 
   * @param context - Evaluation context
   * @param riskConfig - Optional pre-fetched risk config (avoids duplicate calls)
   */
  async getRiskBreakdown(
    context: EvaluationContext,
    riskConfig?: RiskEvaluationConfig
  ): Promise<RiskBreakdown> {
    // Extract risk factors
    const factors = this.extractRiskFactors(context.toolAnnotations);
    this.validateRiskFactors(factors);
    
    // Calculate effective sensitivity (incorporates taint contexts)
    const sensitivity = this.calculateEffectiveSensitivity(
      context.toolAnnotations,
      context.taintContexts
    );

    // Get configuration if not provided
    const config = riskConfig ?? await this.withTimeout(
      this.policyManager.getRiskEvaluationConfig(context.tenantId, context.toolName),
      this.evaluationTimeout,
      'PolicyManager.getRiskEvaluationConfig'
    );
    
    this.validateRiskConfig(config);

    // Calculate risk score
    const finalScore = this.calculateRiskScore(
      sensitivity,
      factors.exposure,
      factors.trust,
      config.weightSensitivity,
      config.weightExposure
    );

    // Calculate raw score (before clamping)
    const weightedSum = config.weightSensitivity * sensitivity + config.weightExposure * factors.exposure;
    const trustFactor = 1 - factors.trust;
    const rawScore = weightedSum * trustFactor;

    return {
      sensitivity,
      exposure: factors.exposure,
      trust: factors.trust,
      weightSensitivity: config.weightSensitivity,
      weightExposure: config.weightExposure,
      rawScore,
      finalScore,
    };
  }

  /**
   * Determine policy action from risk score
   * 
   * Decision logic (inclusive/exclusive boundaries):
   * - 0.0 ≤ R < thresholdAllow → ALLOW
   * - thresholdAllow ≤ R < thresholdBlock → REDACT
   * - thresholdBlock ≤ R ≤ 1.0 → BLOCK
   */
  determineAction(
    riskScore: RiskScore,
    thresholdAllow?: number,
    thresholdBlock?: number
  ): PolicyAction {
    const allow = thresholdAllow ?? this.config.thresholdAllow;
    const block = thresholdBlock ?? this.config.thresholdBlock;
    
    // Validate thresholds
    if (!Number.isFinite(allow) || !Number.isFinite(block)) {
      throw new RangeError(`Thresholds must be finite numbers: allow=${allow}, block=${block}`);
    }
    if (allow >= block) {
      throw new RangeError(`thresholdAllow (${allow}) must be < thresholdBlock (${block})`);
    }

    const score = this.riskScoreToNumber(riskScore);

    if (score < allow) {
      return 'ALLOW';
    }
    if (score < block) {
      return 'REDACT';
    }
    return 'BLOCK';
  }

  /**
   * Build evaluation context from request context
   * 
   * Enriches request context with:
   * - Taint contexts from TaintRegistry
   * - Historical trust scores (future enhancement)
   * - Policy configurations (pulled from PolicyManager)
   */
  async buildEvaluationContext(context: RequestContext): Promise<EvaluationContext> {
    const evaluationContext: EvaluationContext = {
      ...context,
      taintContexts: [],
      historicalTrust: undefined, // Future enhancement
    };

    // Query TaintRegistry for lineage if enabled
    if (this.config.enableTaintEvaluation && context.toolParameters) {
      try {
        const lineageResult = await this.withTimeout(
          this.taintRegistry.checkLineage(
            context.toolParameters,
            context.sessionId,
            context.tenantId || 'default'
          ),
          this.evaluationTimeout,
          'TaintRegistry.checkLineage'
        );

        if (lineageResult.highestSensitivity !== null && lineageResult.relevantContexts.length > 0) {
          // Use relevant contexts directly from TaintRegistry
          evaluationContext.taintContexts = lineageResult.relevantContexts;
        }
      } catch (error) {
        // Fail-closed: If TaintRegistry fails and fail-closed is enabled, assume maximum sensitivity
        if (this.failClosedOnTaintError) {
          this.logger?.error('TaintRegistry query failed, applying fail-closed taint', {
            error: error instanceof Error ? error.message : String(error),
            sessionId: context.sessionId,
            tenantId: context.tenantId,
            toolName: context.toolName,
          });
          
          // Add fail-closed taint context (maximum sensitivity)
          evaluationContext.taintContexts = [{
            contextId: 'taint-fail-closed',
            sourceTool: 'unknown',
            sensitivityLevel: SensitivityLevel.Restricted,
            containsSecrets: true,
            timestamp: new Date(),
            sessionId: context.sessionId,
            tenantId: context.tenantId,
          }];
        } else {
          // Fail-open: Log but continue with empty taint contexts
          this.logger?.warn('TaintRegistry query failed, continuing without taint', {
            error: error instanceof Error ? error.message : String(error),
            sessionId: context.sessionId,
            tenantId: context.tenantId,
            toolName: context.toolName,
          });
        }
      }
    }

    return evaluationContext;
  }

  /**
   * Get the policy manager instance
   */
  getPolicyManager(): IPolicyManager {
    return this.policyManager;
  }

  /**
   * Get current risk evaluation configuration
   */
  getConfig(): RiskEvaluationConfig {
    return { ...this.config };
  }

  /**
   * Update risk evaluation configuration
   */
  updateConfig(config: Partial<RiskEvaluationConfig>): void {
    this.config = {
      ...this.config,
      ...config,
    };
  }

  /**
   * Build justification string for policy decision
   */
  private buildJustification(
    action: PolicyAction,
    riskScore: RiskScore,
    context: EvaluationContext,
    _resolvedPolicy: PolicyResolution,
    breakdown: RiskBreakdown
  ): string {
    const score = this.riskScoreToNumber(riskScore);
    const parts: string[] = [];

    // Base justification
    if (action === 'ALLOW') {
      parts.push(`Low risk (${score.toFixed(3)})`);
    } else if (action === 'REDACT') {
      parts.push(`Moderate risk (${score.toFixed(3)})`);
      if (hasSecretLeakage(context.toolAnnotations)) {
        parts.push('secretHint detected');
      }
    } else {
      parts.push(`High risk (${score.toFixed(3)})`);
    }

    // Add taint context information
    if (context.taintContexts && context.taintContexts.length > 0) {
      const taintSources = context.taintContexts.map(ctx => ctx.sourceTool).join(', ');
      parts.push(`taint from: ${taintSources}`);
    }

    // Add trust information
    if (breakdown.trust === 0) {
      parts.push('untrusted tool');
    } else if (breakdown.trust < 1.0) {
      parts.push(`partial trust (${breakdown.trust.toFixed(2)})`);
    }

    // Add sensitivity information
    if (breakdown.sensitivity >= 1.0) {
      parts.push('high sensitivity data');
    } else if (breakdown.sensitivity >= 0.5) {
      parts.push('moderate sensitivity data');
    }

    // Add exposure information
    if (breakdown.exposure === 1) {
      parts.push('open-world egress risk');
    }

    return parts.join('; ');
  }

  /**
   * Check if human-in-the-loop approval is required
   */
  private checkHITLRequirement(
    context: EvaluationContext,
    riskScore: RiskScore
  ): boolean {
    // Check if tool annotations require HITL
    if (context.toolAnnotations?.requireHITL === true) {
      return true;
    }

    // Check if risk score exceeds HITL threshold
    const score = this.riskScoreToNumber(riskScore);
    return score >= HITL_THRESHOLD;
  }

  /**
   * Calculate effective sensitivity from annotations and taint contexts
   * 
   * This method consolidates the sensitivity calculation logic that was
   * previously duplicated in calculateRisk() and getRiskBreakdown().
   */
  private calculateEffectiveSensitivity(
    annotations: MCPToolAnnotations | undefined,
    taintContexts?: TaintContext[]
  ): number {
    const baseSensitivity = extractSensitivity(annotations);
    
    if (!taintContexts?.length) {
      return baseSensitivity;
    }
    
    // Use highest sensitivity from taint contexts
    const maxTaintSensitivity = Math.max(
      ...taintContexts.map(ctx => 
        typeof ctx.sensitivityLevel === 'number' 
          ? ctx.sensitivityLevel 
          : SensitivityLevel.Restricted
      )
    );
    
    return Math.max(baseSensitivity, maxTaintSensitivity);
  }

  /**
   * Convert RiskScore to number (centralized type cast)
   */
  private riskScoreToNumber(score: RiskScore): number {
    return score as number;
  }

  /**
   * Validate risk evaluation configuration
   */
  private validateRiskConfig(config: RiskEvaluationConfig): void {
    if (!Number.isFinite(config.weightSensitivity) || config.weightSensitivity < 0 || config.weightSensitivity > 1) {
      throw new RangeError(`Invalid weightSensitivity: ${config.weightSensitivity} (must be in [0, 1])`);
    }
    if (!Number.isFinite(config.weightExposure) || config.weightExposure < 0 || config.weightExposure > 1) {
      throw new RangeError(`Invalid weightExposure: ${config.weightExposure} (must be in [0, 1])`);
    }
    if (config.weightSensitivity + config.weightExposure > 1.0) {
      this.logger?.warn('Weights sum > 1.0, consider normalizing', {
        weightSensitivity: config.weightSensitivity,
        weightExposure: config.weightExposure,
        sum: config.weightSensitivity + config.weightExposure,
      });
    }
    if (!Number.isFinite(config.thresholdAllow) || config.thresholdAllow < 0 || config.thresholdAllow > 1) {
      throw new RangeError(`Invalid thresholdAllow: ${config.thresholdAllow} (must be in [0, 1])`);
    }
    if (!Number.isFinite(config.thresholdBlock) || config.thresholdBlock < 0 || config.thresholdBlock > 1) {
      throw new RangeError(`Invalid thresholdBlock: ${config.thresholdBlock} (must be in [0, 1])`);
    }
    if (config.thresholdAllow >= config.thresholdBlock) {
      throw new RangeError(
        `thresholdAllow (${config.thresholdAllow}) must be < thresholdBlock (${config.thresholdBlock})`
      );
    }
  }

  /**
   * Validate risk factors
   */
  private validateRiskFactors(factors: {
    sensitivity: number;
    exposure: number;
    trust: number;
  }): void {
    if (!Number.isFinite(factors.sensitivity) || factors.sensitivity < 0 || factors.sensitivity > 1) {
      throw new RangeError(`Invalid sensitivity: ${factors.sensitivity} (must be in [0, 1])`);
    }
    if (!Number.isFinite(factors.exposure) || (factors.exposure !== 0 && factors.exposure !== 1)) {
      throw new RangeError(`Invalid exposure: ${factors.exposure} (must be 0 or 1)`);
    }
    if (!Number.isFinite(factors.trust) || factors.trust < 0 || factors.trust > 1) {
      throw new RangeError(`Invalid trust: ${factors.trust} (must be in [0, 1])`);
    }
  }

  /**
   * Timeout wrapper for async operations
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    operation: string
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<T>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)),
        timeoutMs
      );
    });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      // Cancel the timeout when the operation settles first, so the timer does
      // not linger and keep the event loop alive.
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }
  }

  /**
   * Create fail-closed decision when policy evaluation fails
   */
  private createFailClosedDecision(
    context: EvaluationContext,
    error: unknown
  ): PolicyDecision {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const defaultConfig = this.getConfig();
    
    return {
      action: 'BLOCK',
      riskScore: createRiskScore(1.0), // Maximum risk
      riskBreakdown: {
        sensitivity: 1.0,
        exposure: 1,
        trust: 0,
        weightSensitivity: defaultConfig.weightSensitivity,
        weightExposure: defaultConfig.weightExposure,
        rawScore: 1.0,
        finalScore: createRiskScore(1.0),
      },
      justification: `Policy evaluation failed: ${errorMessage}`,
      timestamp: new Date(),
      requiresHITL: true,
      policyVersion: 'fail-closed-default',
      requestId: context.metadata?.requestId as string || randomUUID(),
    };
  }

  /**
   * Health check for monitoring/observability
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Check PolicyManager health
      if (this.policyManager.healthCheck) {
        const pmHealthy = await this.policyManager.healthCheck();
        if (!pmHealthy) {
          return false;
        }
      }
      
      // Validate config
      this.validateRiskConfig(this.config);
      
      return true;
    } catch (error) {
      this.logger?.error('Health check failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }
}

