/**
 * MCP-Shield: Core Interfaces
 * 
 * Exports all core interfaces for the MCP-Shield architecture.
 */

export type { IMediator } from './IMediator';
export type { IRiskEvaluator, RiskEvaluationConfig } from './IRiskEvaluator';
export type {
  ITaintRegistry,
  TaintRegistryConfig,
  TaintQueryOptions,
} from './ITaintRegistry';
export type {
  IAuditLogger,
  AuditLogEntry,
  SystemErrorAuditEntry,
} from './IAuditLogger';
export type {
  IRateLimiter,
  RateLimitConfig,
  RateLimitResult,
} from './IRateLimiter';
export type {
  IPolicyManager,
  PolicyRule,
  PolicySet,
  PolicyResolution,
  PolicyScope,
} from './IPolicyManager';
export type {
  IResponseRedactor,
  SanitizationConfig,
  SanitizationResult,
} from './IResponseRedactor';
export type {
  ITransport,
  TransportConfig,
} from './ITransport';

