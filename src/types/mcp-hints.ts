/**
 * MCP-Shield: Tool Annotation Types
 * 
 * Maps to Model Context Protocol Security Enhancement Proposals (SEPs)
 * based on GitHub PRs in the modelcontextprotocol/specification repository.
 * 
 * @see https://github.com/modelcontextprotocol/specification
 */

/**
 * PR #1487: trustedHint
 * Indicates whether a tool is inherently safe to execute.
 * 
 * @see https://github.com/modelcontextprotocol/specification/pull/1487
 */
export interface TrustedHint {
  /**
   * Whether the tool is trusted and safe to execute.
   * - true: Tool is verified and trusted (T = 1.0)
   * - false: Tool is untrusted (T = 0)
   * - undefined: Missing hint, defaults to T = 0 (fail-closed)
   */
  trusted?: boolean;
}

/**
 * PR #1560: secretHint
 * Indicates whether tool output contains secrets or credentials.
 * 
 * @see https://github.com/modelcontextprotocol/specification/pull/1560
 */
export interface SecretHint {
  /**
   * Whether the tool output contains secrets or credentials.
   * - true: Output contains secrets, triggers REDACT or BLOCK
   * - false: Output does not contain secrets
   * - undefined: Missing hint, assumes potential secret leakage (fail-closed)
   */
  secret?: boolean;
}

/**
 * PR #1913: sensitiveHint
 * Indicates data sensitivity classification.
 * 
 * @see https://github.com/modelcontextprotocol/specification/pull/1913
 */
export enum SensitivityLevel {
  /**
   * Public data - no sensitivity (S = 0.0)
   */
  Public = 0.0,
  
  /**
   * Internal data - moderate sensitivity (S = 0.5)
   */
  Internal = 0.5,
  
  /**
   * Confidential data - high sensitivity (S = 1.0)
   */
  Confidential = 1.0,
  
  /**
   * Restricted data - maximum sensitivity (S = 1.0)
   * Note: Same numeric value as Confidential, but semantically distinct
   */
  Restricted = Confidential,
}

/**
 * Helper to convert SensitivityLevel enum to numeric value for risk calculation.
 */
export function sensitivityLevelToNumber(level: SensitivityLevel): number {
  return level;
}

export interface SensitiveHint {
  /**
   * Data sensitivity classification level.
   * 
   * Maps to Sensitivity (S) in risk calculation:
   * - SensitivityLevel.Public (0.0): S = 0
   * - SensitivityLevel.Internal (0.5): S = 0.5
   * - SensitivityLevel.Confidential (1.0): S = 1.0
   * - SensitivityLevel.Restricted (1.0): S = 1.0
   * - undefined: Missing hint, defaults to S = 1.0 (maximum sensitivity, fail-closed)
   * 
   * @deprecated Boolean values are deprecated. Use SensitivityLevel enum only.
   */
  sensitive?: SensitivityLevel;
}

/**
 * PR #711: openWorldHint
 * Indicates egress risk to open-world destinations.
 * 
 * @see https://github.com/modelcontextprotocol/specification/pull/711
 */
export interface OpenWorldHint {
  /**
   * Whether the tool operates in an open-world context (external/untrusted destinations).
   * Maps to Exposure (E) in risk calculation:
   * - true: Open-world, high egress risk (E = 1)
   * - false: Closed-world, internal only (E = 0)
   * - undefined: Missing hint, defaults to E = 1 (maximum egress risk, fail-closed)
   */
  openWorld?: boolean;
}

/**
 * PR #1561: Human-in-the-Loop
 * Triggers human approval for high-risk operations.
 * 
 * @see https://github.com/modelcontextprotocol/specification/pull/1561
 */
export interface HumanInTheLoopHint {
  /**
   * Whether this operation requires human approval.
   * - true: Triggers HITL workflow for R > 0.8
   * - false: No HITL required
   * - undefined: No HITL (default)
   */
  requireHITL?: boolean;
}

/**
 * Complete MCP Tool Annotations
 * Combines all security hints from MCP PRs.
 */
export interface MCPToolAnnotations
  extends TrustedHint,
          SecretHint,
          SensitiveHint,
          OpenWorldHint,
          HumanInTheLoopHint {
  /**
   * Tool name/identifier
   */
  toolName: string;
  
  /**
   * Tool description
   */
  description?: string;
  
  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>;
}

/**
 * Fail-Closed Default Values
 * 
 * When MCP servers don't provide security hints, MCP-Shield applies
 * fail-closed defaults to ensure maximum security.
 */
export const FailClosedDefaults = {
  /**
   * Default Trust value when trustedHint is missing.
   * T = 0 (lowest trust, highest risk)
   */
  TRUST: 0 as const,
  
  /**
   * Default Sensitivity value when sensitiveHint is missing.
   * S = 1.0 (maximum sensitivity)
   */
  SENSITIVITY: 1.0 as const,
  
  /**
   * Default Exposure value when openWorldHint is missing.
   * E = 1 (maximum egress risk)
   */
  EXPOSURE: 1 as const,
  
  /**
   * Default Sensitivity Level when sensitiveHint is missing.
   */
  SENSITIVITY_LEVEL: SensitivityLevel.Restricted,
  
  /**
   * Default behavior for missing secretHint.
   * Assumes potential secret leakage.
   */
  ASSUME_SECRET_LEAKAGE: true as const,
  
  /**
   * Default behavior for missing openWorldHint.
   * Assumes open-world context.
   */
  ASSUME_OPEN_WORLD: true as const,
} as const;

/**
 * Helper function to extract Trust (T) from trustedHint with fail-closed default.
 * 
 * @param hint - TrustedHint from tool annotations
 * @returns Trust value [0, 1] where 0 = untrusted, 1 = trusted
 */
export function extractTrust(hint?: TrustedHint): number {
  if (hint?.trusted === true) {
    return 1.0;
  }
  // Fail-closed: missing or false → T = 0
  return FailClosedDefaults.TRUST;
}

/**
 * Helper function to extract Sensitivity (S) from sensitiveHint with fail-closed default.
 * 
 * @param hint - SensitiveHint from tool annotations
 * @returns Sensitivity value {0, 0.5, 1.0}
 */
export function extractSensitivity(hint?: SensitiveHint): number {
  if (hint?.sensitive === undefined) {
    // Fail-closed: missing hint → S = 1.0 (maximum sensitivity)
    return FailClosedDefaults.SENSITIVITY;
  }
  
  // Use enum value directly (enum values are numeric)
  return sensitivityLevelToNumber(hint.sensitive);
}

/**
 * Helper function to extract Exposure (E) from openWorldHint with fail-closed default.
 * 
 * @param hint - OpenWorldHint from tool annotations
 * @returns Exposure value {0, 1} where 0 = closed-world, 1 = open-world
 */
export function extractExposure(hint?: OpenWorldHint): number {
  if (hint?.openWorld === false) {
    return 0;
  }
  
  if (hint?.openWorld === true) {
    return FailClosedDefaults.EXPOSURE;
  }
  
  // Fail-closed: missing hint → E = 1 (maximum egress risk)
  return FailClosedDefaults.EXPOSURE;
}

/**
 * Helper function to check if secret hint indicates secret leakage.
 * 
 * @param hint - SecretHint from tool annotations
 * @returns true if secrets are present or hint is missing (fail-closed)
 */
export function hasSecretLeakage(hint?: SecretHint): boolean {
  if (hint?.secret === true) {
    return true;
  }
  
  if (hint?.secret === false) {
    return false;
  }
  
  // Fail-closed: missing hint → assume potential secret leakage
  return FailClosedDefaults.ASSUME_SECRET_LEAKAGE;
}

