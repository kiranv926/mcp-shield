/**
 * MCP-Shield: Core Components
 * 
 * Exports core implementations of governance components.
 */

export { TaintRegistry } from './TaintRegistry';
export { ResponseScraper } from './ResponseScraper';
export { LineageProvenanceReport, ReportPrivacyLevel } from './reporters/LineageProvenanceReport';
export { AuditLogger } from './audit/AuditLogger';
export { SecureAuditLogger } from './audit/SecureAuditLogger';
export type { TaintRegistryConfig } from '../interfaces/ITaintRegistry';
export type { ReportOptions } from './reporters/LineageProvenanceReport';

