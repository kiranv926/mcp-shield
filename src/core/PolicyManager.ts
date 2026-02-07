/**
 * MCP-Shield: PolicyManager Implementation
 * 
 * Policy Administration Point (PAP) implementation for MCP-Shield.
 * 
 * The PolicyManager manages security policies, handles policy conflicts using
 * "Most Restrictive Wins" (MRW) resolution, and provides policy versioning.
 * 
 * @see ARCHITECTURE.md - Layer 3: Policy Administration Point (PAP)
 */

import { promises as fs } from 'fs';
import { resolve, normalize } from 'path';
import type { IPolicyManager, PolicyRule, PolicySet, PolicyResolution } from '../interfaces/IPolicyManager';
import type { RiskEvaluationConfig } from '../interfaces/IRiskEvaluator';
import type { PolicyAction } from '../types/governance';
import { FailClosedDefaultPolicy } from '../types/governance';

/**
 * PolicyManager Constants
 */
const DEFAULT_POLICY_PATH = './policies/default.json';
const DEFAULT_RELOAD_INTERVAL = 60000; // 1 minute
const DEFAULT_THRESHOLD_CLAMP_OFFSET = 0.1;
const MAX_POLICY_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_POLICY_HISTORY_SIZE = 100; // Keep last 100 versions
const DEFAULT_THRESHOLD_ALLOW = 0.3;
const DEFAULT_THRESHOLD_BLOCK = 0.7;
const DEFAULT_WEIGHT_SENSITIVITY = 0.6;
const DEFAULT_WEIGHT_EXPOSURE = 0.4;

/**
 * PolicyManager Configuration
 */
export interface PolicyManagerConfig {
  /**
   * Path to policy configuration file (JSON)
   * Default: './policies/default.json'
   */
  policyPath?: string;
  
  /**
   * Enable hot-reload of policies
   * Default: false
   */
  enableHotReload?: boolean;
  
  /**
   * Hot-reload check interval in milliseconds
   * Default: 60000 (1 minute)
   */
  reloadInterval?: number;
  
  /**
   * Whether to use fail-closed defaults when no policies exist
   * Default: true
   */
  failClosed?: boolean;
  
  /**
   * Maximum policy file size in bytes
   * Default: 10MB
   */
  maxFileSize?: number;
  
  /**
   * Maximum number of policy versions to keep in history
   * Default: 100
   */
  maxHistorySize?: number;
}

/**
 * Policy History Entry
 */
interface PolicyHistoryEntry {
  version: string;
  loadedAt: Date;
  description?: string;
  policySet: PolicySet;
}

/**
 * Raw Policy Configuration (from JSON file)
 */
interface RawPolicyConfig {
  version?: string;
  global?: {
    riskThresholds?: {
      allow?: number;
      block?: number;
    };
    weights?: {
      sensitivity?: number;
      exposure?: number;
    };
    actionOverride?: PolicyAction;
    enabled?: boolean;
  };
  tenants?: Record<string, {
    riskThresholds?: {
      allow?: number;
      block?: number;
    };
    weights?: {
      sensitivity?: number;
      exposure?: number;
    };
    actionOverride?: PolicyAction;
    enabled?: boolean;
  }>;
  tools?: Record<string, {
    riskThresholds?: {
      allow?: number;
      block?: number;
    };
    weights?: {
      sensitivity?: number;
      exposure?: number;
    };
    actionOverride?: PolicyAction;
    enabled?: boolean;
  }>;
}

/**
 * PolicyManager - Policy Administration Point Implementation
 * 
 * Manages security policies with MRW conflict resolution, versioning, and hot-reload.
 */
export class PolicyManager implements IPolicyManager {
  private currentPolicySet: PolicySet | null = null;
  private policyHistory: PolicyHistoryEntry[] = [];
  private config: Required<PolicyManagerConfig>;
  private reloadTimer: NodeJS.Timeout | null = null;
  private lastModifiedTime: number = 0;
  private reloadInProgress: boolean = false;
  private reloadLock: Promise<void> = Promise.resolve();

  constructor(config: PolicyManagerConfig = {}) {
    // Validate configuration
    if (config.reloadInterval !== undefined && config.reloadInterval < 1000) {
      throw new Error('reloadInterval must be at least 1000ms (1 second)');
    }
    if (config.maxFileSize !== undefined && config.maxFileSize <= 0) {
      throw new Error('maxFileSize must be greater than 0');
    }
    if (config.maxHistorySize !== undefined && config.maxHistorySize < 1) {
      throw new Error('maxHistorySize must be at least 1');
    }

    this.config = {
      policyPath: config.policyPath || DEFAULT_POLICY_PATH,
      enableHotReload: config.enableHotReload ?? false,
      reloadInterval: config.reloadInterval ?? DEFAULT_RELOAD_INTERVAL,
      failClosed: config.failClosed ?? true,
      maxFileSize: config.maxFileSize ?? MAX_POLICY_FILE_SIZE,
      maxHistorySize: config.maxHistorySize ?? MAX_POLICY_HISTORY_SIZE,
    };

    if (this.config.enableHotReload) {
      this.startHotReload();
    }
  }

  /**
   * Load policies from configuration file
   * 
   * @param configPath - Optional path override (validated for path traversal)
   * @throws Error if file is invalid, too large, or parsing fails
   */
  async loadPolicies(configPath?: string): Promise<void> {
    // Wait for any in-progress reload to complete
    await this.reloadLock;

    // Acquire reload lock
    let releaseLock: () => void;
    this.reloadLock = new Promise(resolve => {
      releaseLock = resolve;
    });

    try {
      const path = configPath || this.config.policyPath;
      
      // Validate path (prevent path traversal)
      const normalizedPath = normalize(resolve(path));
      if (path !== normalizedPath && !normalizedPath.startsWith(process.cwd())) {
        throw new Error(`Invalid policy path: ${path} (potential path traversal detected)`);
      }

      // Check file exists and get size
      let stats;
      try {
        stats = await fs.stat(path);
      } catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
          // File doesn't exist - use fail-closed defaults
          if (this.config.failClosed) {
            this.currentPolicySet = this.createFailClosedPolicySet();
            return;
          } else {
            throw new Error(`Policy file not found: ${path}`);
          }
        }
        throw error;
      }

      // Check file size
      if (stats.size > this.config.maxFileSize) {
        throw new Error(
          `Policy file too large: ${stats.size} bytes (max: ${this.config.maxFileSize} bytes). ` +
          `File: ${path}`
        );
      }

      // Read and parse JSON file
      let fileContent: string;
      let rawConfig: RawPolicyConfig;
      
      try {
        fileContent = await fs.readFile(path, 'utf-8');
      } catch (error) {
        throw new Error(
          `Failed to read policy file: ${path}. ` +
          `Error: ${error instanceof Error ? error.message : String(error)}`
        );
      }

      try {
        rawConfig = JSON.parse(fileContent);
      } catch (error) {
        throw new Error(
          `Invalid JSON in policy file: ${path}. ` +
          `Error: ${error instanceof Error ? error.message : String(error)}`
        );
      }

      // Validate raw config structure
      this.validateRawConfig(rawConfig);
      
      // Convert raw config to PolicySet
      const policySet = this.convertRawConfigToPolicySet(rawConfig);
      
      // Validate policy set
      this.validatePolicySet(policySet);
      
      // Store policy history (with size limit)
      this.policyHistory.push({
        version: policySet.version,
        loadedAt: policySet.loadedAt,
        description: `Loaded from ${path}`,
        policySet: this.deepClone(policySet),
      });

      // Limit history size
      if (this.policyHistory.length > this.config.maxHistorySize) {
        this.policyHistory = this.policyHistory.slice(-this.config.maxHistorySize);
      }
      
      // Atomic update: only update if validation passed
      this.currentPolicySet = policySet;
      
      // Update last modified time
      this.lastModifiedTime = stats.mtimeMs;
      
    } catch (error) {
      // Re-throw with context
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(`Unexpected error loading policies: ${String(error)}`);
    } finally {
      // Release reload lock
      releaseLock!();
    }
  }

  /**
   * Get resolved policy for a specific context using MRW logic
   * 
   * @param tenantId - Tenant identifier (optional, empty string treated as undefined)
   * @param toolName - Tool name (optional, empty string treated as undefined)
   * @returns Promise resolving to resolved policy configuration
   */
  async getResolvedPolicy(
    tenantId?: string,
    toolName?: string
  ): Promise<PolicyResolution> {
    // Normalize empty strings to undefined
    const normalizedTenantId = tenantId && tenantId.trim() ? tenantId.trim() : undefined;
    const normalizedToolName = toolName && toolName.trim() ? toolName.trim() : undefined;

    // If no policies loaded, return fail-closed defaults
    if (!this.currentPolicySet) {
      return this.getFailClosedResolution();
    }

    const appliedPolicies: string[] = [];
    const policies: PolicyRule[] = [];

    // 1. Collect global policies
    for (const rule of this.currentPolicySet.global) {
      if (rule.enabled) {
        policies.push(rule);
        appliedPolicies.push(`global:${rule.id}`);
      }
    }

    // 2. Collect tenant-specific policies
    if (normalizedTenantId && this.currentPolicySet.tenants[normalizedTenantId]) {
      for (const rule of this.currentPolicySet.tenants[normalizedTenantId]) {
        if (rule.enabled) {
          policies.push(rule);
          appliedPolicies.push(`tenant:${normalizedTenantId}:${rule.id}`);
        }
      }
    }

    // 3. Collect tool-specific policies
    if (normalizedToolName && this.currentPolicySet.tools[normalizedToolName]) {
      const toolRule = this.currentPolicySet.tools[normalizedToolName];
      if (toolRule.enabled) {
        policies.push(toolRule);
        appliedPolicies.push(`tool:${normalizedToolName}:${toolRule.id}`);
      }
    }

    // 4. If no policies found, return fail-closed defaults
    if (policies.length === 0) {
      return this.getFailClosedResolution();
    }

    // 5. Apply MRW (Most Restrictive Wins) resolution
    return this.resolveMRW(policies, appliedPolicies);
  }

  /**
   * Get risk evaluation configuration for a context
   */
  async getRiskEvaluationConfig(
    tenantId?: string,
    toolName?: string
  ): Promise<RiskEvaluationConfig> {
    const resolution = await this.getResolvedPolicy(tenantId, toolName);
    
    return {
      weightSensitivity: resolution.weights.sensitivity,
      weightExposure: resolution.weights.exposure,
      thresholdAllow: resolution.thresholds.allow,
      thresholdBlock: resolution.thresholds.block,
      enableTaintEvaluation: true,
    };
  }

  /**
   * Hot-reload policies without service restart
   * 
   * Thread-safe: prevents concurrent reloads.
   * Preserves previous policy on reload failure (fail-safe).
   */
  async reloadPolicies(): Promise<void> {
    // Prevent concurrent reloads
    if (this.reloadInProgress) {
      await this.reloadLock;
      return;
    }

    this.reloadInProgress = true;
    const previousPolicySet = this.currentPolicySet; // Preserve for rollback
    
    try {
      await this.loadPolicies();
    } catch (error) {
      // Fail-safe: restore previous policy on reload failure
      if (previousPolicySet) {
        this.currentPolicySet = previousPolicySet;
      }
      // Re-throw error for caller to handle
      throw new Error(
        `Policy reload failed: ${error instanceof Error ? error.message : String(error)}. ` +
        `Previous policy version (${previousPolicySet?.version || 'none'}) preserved.`
      );
    } finally {
      this.reloadInProgress = false;
    }
  }

  /**
   * Get current policy version
   */
  getPolicyVersion(): string {
    if (!this.currentPolicySet) {
      return 'fail-closed-default';
    }
    return this.currentPolicySet.version;
  }

  /**
   * Get policy history (for rollback scenarios)
   */
  getPolicyHistory(): Array<{
    version: string;
    loadedAt: Date;
    description?: string;
  }> {
    return this.policyHistory.map(entry => ({
      version: entry.version,
      loadedAt: entry.loadedAt,
      description: entry.description,
    }));
  }

  /**
   * Rollback to a previous policy version
   */
  async rollbackPolicy(version: string): Promise<void> {
    const historyEntry = this.policyHistory.find(entry => entry.version === version);
    
    if (!historyEntry) {
      throw new Error(`Policy version not found: ${version}`);
    }

    // Restore policy set from history
    this.currentPolicySet = this.deepClone(historyEntry.policySet);
    
    // Add rollback entry to history
    this.policyHistory.push({
      version: `${version}-rollback-${Date.now()}`,
      loadedAt: new Date(),
      description: `Rollback to version ${version}`,
      policySet: this.deepClone(this.currentPolicySet),
    });
  }

  /**
   * Validate a policy rule
   */
  validatePolicy(rule: PolicyRule): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    // Validate thresholds
    if (rule.thresholdAllow < 0 || rule.thresholdAllow > 1) {
      errors.push(`thresholdAllow must be between 0 and 1, got ${rule.thresholdAllow}`);
    }
    if (rule.thresholdBlock < 0 || rule.thresholdBlock > 1) {
      errors.push(`thresholdBlock must be between 0 and 1, got ${rule.thresholdBlock}`);
    }
    if (rule.thresholdAllow >= rule.thresholdBlock) {
      errors.push(`thresholdAllow (${rule.thresholdAllow}) must be less than thresholdBlock (${rule.thresholdBlock})`);
    }

    // Validate weights
    if (rule.weights.sensitivity < 0 || rule.weights.sensitivity > 1) {
      errors.push(`weights.sensitivity must be between 0 and 1, got ${rule.weights.sensitivity}`);
    }
    if (rule.weights.exposure < 0 || rule.weights.exposure > 1) {
      errors.push(`weights.exposure must be between 0 and 1, got ${rule.weights.exposure}`);
    }
    const weightSum = rule.weights.sensitivity + rule.weights.exposure;
    if (weightSum > 1.0) {
      errors.push(`weights sum (${weightSum}) must not exceed 1.0`);
    }

    // Validate action override
    if (rule.actionOverride && !['ALLOW', 'BLOCK', 'REDACT'].includes(rule.actionOverride)) {
      errors.push(`actionOverride must be one of: ALLOW, BLOCK, REDACT, got ${rule.actionOverride}`);
    }

    // Validate scope and target
    if (rule.scope === 'tenant' && !rule.target) {
      errors.push('target is required for tenant-scoped policies');
    }
    if (rule.scope === 'tool' && !rule.target) {
      errors.push('target is required for tool-scoped policies');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Health check for policy management system
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Check if policies are loaded
      if (!this.currentPolicySet) {
        return false;
      }

      // Check if policy file is accessible (if hot-reload is enabled)
      if (this.config.enableHotReload) {
        try {
          await fs.access(this.config.policyPath);
        } catch {
          return false;
        }
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Start hot-reload timer
   */
  private startHotReload(): void {
    if (this.reloadTimer) {
      clearInterval(this.reloadTimer);
    }

    this.reloadTimer = setInterval(async () => {
      try {
        const stats = await fs.stat(this.config.policyPath);
        if (stats.mtimeMs > this.lastModifiedTime) {
          // File has been modified, reload
          try {
            await this.reloadPolicies();
          } catch (error) {
            // Log error but don't throw (hot-reload is best-effort)
            // Previous policy remains active (fail-safe)
            // Suppress console.error in test environments to reduce noise
            if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'test' && !(global as any).jest) {
              console.error(`Hot-reload failed: ${error instanceof Error ? error.message : String(error)}`);
            }
          }
        }
      } catch {
        // File doesn't exist or can't be accessed - ignore (previous policy remains active)
      }
    }, this.config.reloadInterval);
  }

  /**
   * Stop hot-reload timer
   */
  private stopHotReload(): void {
    if (this.reloadTimer) {
      clearInterval(this.reloadTimer);
      this.reloadTimer = null;
    }
  }

  /**
   * Validate and normalize numeric value
   */
  private validateNumeric(value: unknown, defaultValue: number, name: string): number {
    if (typeof value !== 'number') {
      return defaultValue;
    }
    if (!Number.isFinite(value) || isNaN(value)) {
      throw new Error(`${name} must be a finite number, got ${value}`);
    }
    return value;
  }

  /**
   * Validate and normalize boolean value
   */
  private validateBoolean(value: unknown, defaultValue: boolean): boolean {
    if (typeof value === 'boolean') {
      return value;
    }
    return defaultValue;
  }

  /**
   * Validate and normalize string value
   */
  private validateString(value: unknown, defaultValue: string): string {
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
    return defaultValue;
  }

  /**
   * Convert raw config from JSON to PolicySet
   */
  private convertRawConfigToPolicySet(
    rawConfig: RawPolicyConfig
  ): PolicySet {
    const version = this.validateString(rawConfig.version, `v${Date.now()}`);
    const globalRules: PolicyRule[] = [];
    const tenantRules: Record<string, PolicyRule[]> = {};
    const toolRules: Record<string, PolicyRule> = {};

    // Convert global policy
    if (rawConfig.global) {
      globalRules.push({
        id: 'global-default',
        scope: 'global',
        thresholdAllow: this.validateNumeric(
          rawConfig.global.riskThresholds?.allow,
          DEFAULT_THRESHOLD_ALLOW,
          'global.riskThresholds.allow'
        ),
        thresholdBlock: this.validateNumeric(
          rawConfig.global.riskThresholds?.block,
          DEFAULT_THRESHOLD_BLOCK,
          'global.riskThresholds.block'
        ),
        weights: {
          sensitivity: this.validateNumeric(
            rawConfig.global.weights?.sensitivity,
            DEFAULT_WEIGHT_SENSITIVITY,
            'global.weights.sensitivity'
          ),
          exposure: this.validateNumeric(
            rawConfig.global.weights?.exposure,
            DEFAULT_WEIGHT_EXPOSURE,
            'global.weights.exposure'
          ),
        },
        actionOverride: rawConfig.global.actionOverride,
        enabled: this.validateBoolean(rawConfig.global.enabled, true),
        version,
      });
    }

    // Convert tenant policies
    if (rawConfig.tenants) {
      for (const [tenantId, tenantConfig] of Object.entries(rawConfig.tenants)) {
        if (!tenantId || typeof tenantId !== 'string' || tenantId.trim().length === 0) {
          throw new Error('Tenant ID must be a non-empty string');
        }
        tenantRules[tenantId] = [{
          id: `tenant-${tenantId}-default`,
          scope: 'tenant',
          target: tenantId,
          thresholdAllow: this.validateNumeric(
            tenantConfig.riskThresholds?.allow,
            DEFAULT_THRESHOLD_ALLOW,
            `tenants.${tenantId}.riskThresholds.allow`
          ),
          thresholdBlock: this.validateNumeric(
            tenantConfig.riskThresholds?.block,
            DEFAULT_THRESHOLD_BLOCK,
            `tenants.${tenantId}.riskThresholds.block`
          ),
          weights: {
            sensitivity: this.validateNumeric(
              tenantConfig.weights?.sensitivity,
              DEFAULT_WEIGHT_SENSITIVITY,
              `tenants.${tenantId}.weights.sensitivity`
            ),
            exposure: this.validateNumeric(
              tenantConfig.weights?.exposure,
              DEFAULT_WEIGHT_EXPOSURE,
              `tenants.${tenantId}.weights.exposure`
            ),
          },
          actionOverride: tenantConfig.actionOverride,
          enabled: this.validateBoolean(tenantConfig.enabled, true),
          version,
        }];
      }
    }

    // Convert tool policies
    if (rawConfig.tools) {
      for (const [toolName, toolConfig] of Object.entries(rawConfig.tools)) {
        if (!toolName || typeof toolName !== 'string' || toolName.trim().length === 0) {
          throw new Error('Tool name must be a non-empty string');
        }
        toolRules[toolName] = {
          id: `tool-${toolName}-default`,
          scope: 'tool',
          target: toolName,
          thresholdAllow: this.validateNumeric(
            toolConfig.riskThresholds?.allow,
            DEFAULT_THRESHOLD_ALLOW,
            `tools.${toolName}.riskThresholds.allow`
          ),
          thresholdBlock: this.validateNumeric(
            toolConfig.riskThresholds?.block,
            DEFAULT_THRESHOLD_BLOCK,
            `tools.${toolName}.riskThresholds.block`
          ),
          weights: {
            sensitivity: this.validateNumeric(
              toolConfig.weights?.sensitivity,
              DEFAULT_WEIGHT_SENSITIVITY,
              `tools.${toolName}.weights.sensitivity`
            ),
            exposure: this.validateNumeric(
              toolConfig.weights?.exposure,
              DEFAULT_WEIGHT_EXPOSURE,
              `tools.${toolName}.weights.exposure`
            ),
          },
          actionOverride: toolConfig.actionOverride,
          enabled: this.validateBoolean(toolConfig.enabled, true),
          version,
        };
      }
    }

    return {
      global: globalRules,
      tenants: tenantRules,
      tools: toolRules,
      version,
      loadedAt: new Date(),
    };
  }

  /**
   * Validate policy set
   */
  private validatePolicySet(policySet: PolicySet): void {
    // Validate all global rules
    for (const rule of policySet.global) {
      const validation = this.validatePolicy(rule);
      if (!validation.valid) {
        throw new Error(`Invalid global policy rule ${rule.id}: ${validation.errors.join(', ')}`);
      }
    }

    // Validate all tenant rules
    for (const [tenantId, rules] of Object.entries(policySet.tenants)) {
      for (const rule of rules) {
        const validation = this.validatePolicy(rule);
        if (!validation.valid) {
          throw new Error(`Invalid tenant policy rule ${rule.id} for tenant ${tenantId}: ${validation.errors.join(', ')}`);
        }
      }
    }

    // Validate all tool rules
    for (const [toolName, rule] of Object.entries(policySet.tools)) {
      const validation = this.validatePolicy(rule);
      if (!validation.valid) {
        throw new Error(`Invalid tool policy rule ${rule.id} for tool ${toolName}: ${validation.errors.join(', ')}`);
      }
    }
  }

  /**
   * Resolve policies using Most Restrictive Wins (MRW) algorithm
   */
  private resolveMRW(
    policies: PolicyRule[],
    appliedPolicies: string[]
  ): PolicyResolution {
    // Action Resolution: Highest severity wins (BLOCK > REDACT > ALLOW)
    const actionSeverity: Record<PolicyAction, number> = {
      ALLOW: 1,
      REDACT: 2,
      BLOCK: 3,
    };

    let maxActionSeverity = 0;
    let actionOverride: PolicyAction | undefined = undefined;

    for (const policy of policies) {
      if (policy.actionOverride) {
        const severity = actionSeverity[policy.actionOverride];
        if (severity > maxActionSeverity) {
          maxActionSeverity = severity;
          actionOverride = policy.actionOverride;
        }
      }
    }

    // Threshold Resolution: Most restrictive (minimum values)
    let minThresholdAllow = Infinity;
    let minThresholdBlock = Infinity;

    for (const policy of policies) {
      minThresholdAllow = Math.min(minThresholdAllow, policy.thresholdAllow);
      minThresholdBlock = Math.min(minThresholdBlock, policy.thresholdBlock);
    }

    // Clamp thresholds to ensure thresholdAllow < thresholdBlock
    if (minThresholdAllow >= minThresholdBlock) {
      minThresholdBlock = Math.min(1.0, minThresholdAllow + DEFAULT_THRESHOLD_CLAMP_OFFSET);
    }

    // Weight Resolution: Most restrictive (maximum values)
    let maxWeightSensitivity = 0;
    let maxWeightExposure = 0;

    for (const policy of policies) {
      maxWeightSensitivity = Math.max(maxWeightSensitivity, policy.weights.sensitivity);
      maxWeightExposure = Math.max(maxWeightExposure, policy.weights.exposure);
    }

    // Normalize weights if sum exceeds 1.0
    const weightSum = maxWeightSensitivity + maxWeightExposure;
    if (weightSum > 1.0) {
      maxWeightSensitivity = maxWeightSensitivity / weightSum;
      maxWeightExposure = maxWeightExposure / weightSum;
    }

    return {
      thresholds: {
        allow: minThresholdAllow,
        block: minThresholdBlock,
      },
      weights: {
        sensitivity: maxWeightSensitivity,
        exposure: maxWeightExposure,
      },
      actionOverride,
      appliedPolicies,
      policyVersion: policies[0]?.version || 'unknown',
    };
  }

  /**
   * Create fail-closed policy set
   */
  private createFailClosedPolicySet(): PolicySet {
    return {
      global: [{
        id: 'fail-closed-default',
        scope: 'global',
        thresholdAllow: FailClosedDefaultPolicy.thresholdAllow,
        thresholdBlock: FailClosedDefaultPolicy.thresholdBlock,
        weights: FailClosedDefaultPolicy.weights,
        enabled: true,
        version: 'fail-closed-default',
      }],
      tenants: {},
      tools: {},
      version: 'fail-closed-default',
      loadedAt: new Date(),
    };
  }

  /**
   * Get fail-closed resolution
   */
  private getFailClosedResolution(): PolicyResolution {
    return {
      thresholds: {
        allow: FailClosedDefaultPolicy.thresholdAllow,
        block: FailClosedDefaultPolicy.thresholdBlock,
      },
      weights: FailClosedDefaultPolicy.weights,
      appliedPolicies: ['fail-closed-default'],
      policyVersion: 'fail-closed-default',
    };
  }

  /**
   * Validate raw config structure
   */
  private validateRawConfig(rawConfig: RawPolicyConfig): void {
    // Basic structure validation
    if (typeof rawConfig !== 'object' || rawConfig === null) {
      throw new Error('Policy config must be an object');
    }

    // Validate global policy structure if present
    if (rawConfig.global !== undefined) {
      if (typeof rawConfig.global !== 'object' || rawConfig.global === null) {
        throw new Error('global policy must be an object');
      }
      if (rawConfig.global.riskThresholds) {
        if (typeof rawConfig.global.riskThresholds !== 'object') {
          throw new Error('global.riskThresholds must be an object');
        }
      }
      if (rawConfig.global.weights) {
        if (typeof rawConfig.global.weights !== 'object') {
          throw new Error('global.weights must be an object');
        }
      }
    }

    // Validate tenants structure if present
    if (rawConfig.tenants !== undefined) {
      if (typeof rawConfig.tenants !== 'object' || rawConfig.tenants === null || Array.isArray(rawConfig.tenants)) {
        throw new Error('tenants must be an object');
      }
    }

    // Validate tools structure if present
    if (rawConfig.tools !== undefined) {
      if (typeof rawConfig.tools !== 'object' || rawConfig.tools === null || Array.isArray(rawConfig.tools)) {
        throw new Error('tools must be an object');
      }
    }
  }

  /**
   * Deep clone an object efficiently
   * Uses structuredClone if available, falls back to JSON serialization
   */
  private deepClone<T>(obj: T): T {
    // Use structuredClone if available (Node.js 17+)
    if (typeof structuredClone !== 'undefined') {
      try {
        return structuredClone(obj);
      } catch {
        // Fall through to JSON method
      }
    }
    
    // Fallback to JSON serialization
    return JSON.parse(JSON.stringify(obj));
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    this.stopHotReload();
  }
}

