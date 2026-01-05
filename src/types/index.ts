/**
 * MCP-Shield: Type Definitions
 * 
 * Exports all type definitions for MCP-Shield.
 */

// MCP Hints (mapped to GitHub PRs)
export type {
  TrustedHint,
  SecretHint,
  SensitiveHint,
  OpenWorldHint,
  HumanInTheLoopHint,
  MCPToolAnnotations,
} from './mcp-hints';

export {
  SensitivityLevel,
  FailClosedDefaults,
  extractTrust,
  extractSensitivity,
  extractExposure,
  hasSecretLeakage,
  sensitivityLevelToNumber,
} from './mcp-hints';

// Common Types
export type {
  PolicyDecisionAction, // Deprecated - use PolicyAction from governance
  RiskScore,
  RiskBreakdown,
  RequestContext,
  EvaluationContext,
  JSONRPCRequest,
  JSONRPCResponse,
  JSONRPCError,
  TaintContext,
} from './common';

export {
  createRiskScore,
  clampRiskScore,
} from './common';

// Governance Types (Unified)
export type {
  PolicyAction,
  PolicyDecision,
} from './governance';
export {
  FailClosedDefaultPolicy,
} from './governance';

// JSON-RPC Schemas (Zod)
export {
  JSONRPCRequestSchema,
  JSONRPCResponseSchema,
  JSONRPCErrorSchema,
  type JSONRPCRequestInput,
  type JSONRPCResponseInput,
  type JSONRPCErrorInput,
} from './jsonrpc-schema';

// Error Codes
export {
  JSONRPCErrorCodes,
  MCPShieldErrorCodes,
  ErrorMessages,
  getErrorMessage,
} from './errors';

// Audit Types (Phase 3: Structured Audit Entries)
export type {
  AuditEntry,
  SecureAuditEntry,
  StructuredSystemErrorAuditEntry,
  AuditEntryConverter,
} from './audit';
export {
  DataTypePattern,
  detectDataTypePattern,
} from './audit';

