/**
 * TaintGate: IPolicyManager Interface
 * 
 * Policy Administration Point (PAP) interface for PolicyManager.
 * 
 * The PolicyManager manages security policies, handles policy conflicts using
 * "Most Restrictive Wins" (MRW) resolution, and provides policy versioning.
 * 
 * @see ARCHITECTURE.md - Layer 3: Policy Administration Point (PAP)
 */

import type { RiskEvaluationConfig } from './IRiskEvaluator';
import type { PolicyAction } from '../types/governance';

/**
 * Policy Scope
 * Defines the level at which a policy applies.
 */
export type PolicyScope = 'global' | 'tenant' | 'tool';

/**
 * Policy Rule
 * Individual policy rule that can be applied at different scopes.
 */
export interface PolicyRule {
  /**
   * Rule identifier
   */
  id: string;
  
  /**
   * Scope at which this rule applies
   */
  scope: PolicyScope;
  
  /**
   * Target identifier (tenant ID or tool name, depending on scope)
   */
  target?: string;
  
  /**
   * Risk threshold for ALLOW decision
   */
  thresholdAllow: number;
  
  /**
   * Risk threshold for BLOCK decision
   */
  thresholdBlock: number;
  
  /**
   * Risk evaluation weights
   */
  weights: {
    sensitivity: number;
    exposure: number;
  };
  
  /**
   * Action override (if set, forces this action regardless of risk score)
   */
  actionOverride?: PolicyAction;
  
  /**
   * Whether this rule is enabled
   */
  enabled: boolean;
  
  /**
   * Policy version this rule belongs to
   */
  version: string;
}

/**
 * Policy Set
 * Collection of policies at different scopes.
 */
export interface PolicySet {
  /**
   * Global policies (apply to all tenants/tools)
   */
  global: PolicyRule[];
  
  /**
   * Tenant-specific policies (override global)
   */
  tenants: Record<string, PolicyRule[]>;
  
  /**
   * Tool-specific policies (override tenant and global)
   */
  tools: Record<string, PolicyRule>;
  
  /**
   * Current policy version
   */
  version: string;
  
  /**
   * Timestamp when policy set was loaded
   */
  loadedAt: Date;
}

/**
 * Policy Conflict Resolution Result
 * Result of applying MRW (Most Restrictive Wins) logic.
 */
export interface PolicyResolution {
  /**
   * Resolved risk thresholds
   */
  thresholds: {
    allow: number;
    block: number;
  };
  
  /**
   * Resolved weights
   */
  weights: {
    sensitivity: number;
    exposure: number;
  };
  
  /**
   * Final action (if action override is present)
   */
  actionOverride?: PolicyAction;
  
  /**
   * Which policies were considered in resolution
   */
  appliedPolicies: string[];
  
  /**
   * Policy version used
   */
  policyVersion: string;
}

/**
 * IPolicyManager - Policy Administration Point Interface
 * 
 * Responsibilities:
 * 1. Load and manage policies from YAML/JSON
 * 2. Resolve policy conflicts using "Most Restrictive Wins" (MRW)
 * 3. Provide policy versioning and rollback
 * 4. Support hot-reload of policies
 * 5. Apply per-tenant and per-tool policy overrides
 */
export interface IPolicyManager {
  /**
   * Load policies from configuration file.
   * 
   * @param configPath - Path to policy configuration file (YAML/JSON). Optional - uses configured path if not provided.
   * @returns Promise resolving when policies are loaded
   */
  loadPolicies(configPath?: string): Promise<void>;

  /**
   * Get resolved policy for a specific context.
   * 
   * Applies "Most Restrictive Wins" (MRW) logic with precedence and clamping:
   * 
   * **Action Resolution (Highest Severity Wins)**:
   * - BLOCK > REDACT > ALLOW
   * - If any policy has actionOverride: BLOCK → Result is BLOCK
   * - If any policy has actionOverride: REDACT → Result is REDACT (unless BLOCK present)
   * - If all policies are ALLOW or no actionOverride → Use risk score thresholds
   * 
   * **Threshold Resolution (Most Restrictive)**:
   * - thresholdAllow: Use minimum (lowest) value across all policies
   * - thresholdBlock: Use minimum (lowest) value across all policies
   * - Validation: Ensure thresholdAllow < thresholdBlock (clamp if invalid)
   * 
   * **Weight Resolution (Most Restrictive)**:
   * - sensitivity weight: Use maximum (highest) value
   * - exposure weight: Use maximum (highest) value
   * - Validation: Ensure weights sum ≤ 1.0 (normalize if invalid)
   * 
   * **Default Behavior (No Policies)**:
   * - If no policies exist → Return FailClosedDefaultPolicy
   * - FailClosedDefaultPolicy: S=1.0, E=1, T=0 → Always results in BLOCK
   * 
   * **MRW Example Table**:
   * | Global Policy | Tenant Policy | Tool Override | Resolved Action |
   * | :--- | :--- | :--- | :--- |
   * | ALLOW | REDACT | ALLOW | REDACT (highest severity) |
   * | REDACT | ALLOW | BLOCK | BLOCK (highest severity) |
   * | ALLOW | (None) | (None) | ALLOW (use risk thresholds) |
   * 
   * @param tenantId - Tenant identifier (optional)
   * @param toolName - Tool name (optional)
   * @returns Promise resolving to resolved policy configuration
   */
  getResolvedPolicy(
    tenantId?: string,
    toolName?: string
  ): Promise<PolicyResolution>;

  /**
   * Get risk evaluation configuration for a context.
   * 
   * This is a convenience method that returns RiskEvaluationConfig
   * from the resolved policy.
   * 
   * @param tenantId - Tenant identifier (optional)
   * @param toolName - Tool name (optional)
   * @returns Promise resolving to risk evaluation configuration
   */
  getRiskEvaluationConfig(
    tenantId?: string,
    toolName?: string
  ): Promise<RiskEvaluationConfig>;

  /**
   * Hot-reload policies without service restart.
   * 
   * @returns Promise resolving when policies are reloaded
   */
  reloadPolicies(): Promise<void>;

  /**
   * Get current policy version.
   * 
   * @returns Current policy version string
   */
  getPolicyVersion(): string;

  /**
   * Get policy history (for rollback scenarios).
   * 
   * @returns Array of policy versions with timestamps
   */
  getPolicyHistory(): Array<{
    version: string;
    loadedAt: Date;
    description?: string;
  }>;

  /**
   * Rollback to a previous policy version.
   * 
   * @param version - Policy version to rollback to
   * @returns Promise resolving when rollback is complete
   */
  rollbackPolicy(version: string): Promise<void>;

  /**
   * Validate a policy rule.
   * 
   * @param rule - Policy rule to validate
   * @returns Validation result with errors (if any)
   */
  validatePolicy(rule: PolicyRule): {
    valid: boolean;
    errors: string[];
  };

  /**
   * Health check for policy management system.
   * 
   * @returns Promise resolving to true if policy manager is healthy
   */
  healthCheck(): Promise<boolean>;
}

