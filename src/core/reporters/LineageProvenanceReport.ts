/**
 * TaintGate: Lineage Provenance Report Generator
 * 
 * Generates human-readable and machine-readable audit reports showing data flow through tools.
 * This enables complete audit trails for compliance (GDPR, HIPAA, SOC 2) and security forensics.
 * 
 * The report shows the complete data laundering path from origin to block, addressing the
 * "blind system" concern where data laundering was blocked but evidence couldn't be explained.
 */

import type { IAuditLogger, AuditLogEntry } from '../../interfaces/IAuditLogger';
import { SensitivityLevel } from '../../types/mcp-hints';

/**
 * Report Privacy Levels
 * 
 * Different stakeholders need different levels of detail in audit reports.
 */
export enum ReportPrivacyLevel {
  /**
   * SYSTEM: Raw tool names + params (internal security debugging)
   */
  SYSTEM = 'system',
  
  /**
   * AUDITOR: Hashed params + full path (compliance evidence - SOC2/GDPR)
   */
  AUDITOR = 'auditor',
  
  /**
   * PUBLIC: Redacted tools + summary (public trust transparency)
   */
  PUBLIC = 'public',
}

/**
 * Report Generation Options
 */
export interface ReportOptions {
  /**
   * Privacy level for the report
   */
  privacyLevel?: ReportPrivacyLevel;
  
  /**
   * Maximum number of events to include (pagination)
   */
  limit?: number;
  
  /**
   * Offset for pagination
   */
  offset?: number;
  
  /**
   * Include system errors in the report
   */
  includeErrors?: boolean;
}

/**
 * Lineage Provenance Report Generator
 * 
 * Generates human-readable and machine-readable audit reports showing:
 * - Complete data laundering paths (toolA → toolB → toolC)
 * - Origin tools that produced sensitive data
 * - Taint contexts and sensitivity levels
 * - Policy decisions and risk scores
 * 
 * This class is production-ready and accepts the IAuditLogger interface
 * for integration with any audit logging implementation.
 */
export class LineageProvenanceReport {
  constructor(private auditLogger: IAuditLogger) {}

  /**
   * Generate a complete lineage provenance report for a session (human-readable text format)
   * 
   * @param sessionId - Session ID to generate report for
   * @param tenantId - Tenant ID for multi-tenant isolation
   * @param options - Report generation options
   * @returns Promise resolving to formatted report string
   */
  async generateReport(
    sessionId: string,
    tenantId: string,
    options: ReportOptions = {}
  ): Promise<string> {
    const {
      privacyLevel = ReportPrivacyLevel.AUDITOR,
      limit,
      offset = 0,
    } = options;

    // Query audit logs
    const logs = await this.auditLogger.queryLogs({
      sessionId,
      tenantId,
      limit,
    });

    if (logs.length === 0) {
      return `No audit logs found for session ${sessionId}`;
    }

    const report: string[] = [];
    report.push('='.repeat(80));
    report.push('MCP-SHIELD: LINEAGE PROVENANCE REPORT');
    report.push('='.repeat(80));
    report.push('');
    report.push(`Session ID: ${sessionId}`);
    report.push(`Tenant ID: ${tenantId}`);
    report.push(`Report Generated: ${new Date().toISOString()}`);
    report.push(`Privacy Level: ${privacyLevel}`);
    report.push(`Total Events: ${logs.length}`);
    if (limit) {
      report.push(`Pagination: Showing ${offset + 1}-${offset + logs.length} of ${logs.length} events`);
    }
    report.push('');

    // Group by request
    const requests = new Map<string, AuditLogEntry[]>();
    for (const log of logs) {
      const requestId = log.requestId || 'unknown';
      if (!requests.has(requestId)) {
        requests.set(requestId, []);
      }
      requests.get(requestId)!.push(log);
    }

    // Generate report for each request
    for (const [requestId, requestLogs] of requests.entries()) {
      const decisionLog = requestLogs.find(l => l.decision);
      if (!decisionLog) continue;

      const decision = decisionLog.decision;

      report.push('-'.repeat(80));
      report.push(`Request ID: ${requestId}`);
      report.push(`Tool: ${this.applyPrivacyFilter(decisionLog.toolName, privacyLevel)}`);
      report.push(`Action: ${decision.action}`);
      report.push(`Risk Score: ${decision.riskScore?.toFixed(3) || 'N/A'}`);
      report.push(`Policy Version: ${decisionLog.policyVersion || 'N/A'}`);
      report.push(`Timestamp: ${new Date(decisionLog.timestamp).toISOString()}`);
      report.push('');

      // Show taint context if available
      if (decisionLog.taintContexts && decisionLog.taintContexts.length > 0) {
        report.push('  Taint Lineage Detected:');
        const uniqueContexts = new Map();
        for (const taint of decisionLog.taintContexts) {
          // Group by contextId to avoid duplicates
          if (!uniqueContexts.has(taint.contextId)) {
            uniqueContexts.set(taint.contextId, taint);
            report.push(`    - Source Tool: ${this.applyPrivacyFilter(taint.sourceTool || 'unknown', privacyLevel)}`);
            report.push(`      Sensitivity: ${SensitivityLevel[taint.sensitivityLevel] || taint.sensitivityLevel || 'Unknown'}`);
            report.push(`      Contains Secrets: ${taint.containsSecrets || false}`);
            report.push(`      Context ID: ${this.applyPrivacyFilter(taint.contextId, privacyLevel)}`);
            report.push(`      Timestamp: ${new Date(taint.timestamp).toISOString()}`);
          }
        }
        report.push('');
      }

      // Show origin tools if available (with chronological ordering)
      const originTools = this.extractOriginTools(decisionLog);
      if (originTools && originTools.length > 0) {
        report.push('  Data Origin Path:');
        // Sort chronologically if timestamps are available
        const sortedPath = this.generateChronologicalPath(requestLogs, originTools);
        report.push(`    ${sortedPath.join(' → ')}`);
        report.push('');
      }

      // Show reason if available
      if (decision.justification) {
        report.push(`  Reason: ${decision.justification}`);
        report.push('');
      }

      // System errors are logged via logSystemError, not logDecision
      // They would need to be queried separately if needed
    }

    report.push('='.repeat(80));
    report.push('END OF REPORT');
    report.push('='.repeat(80));

    return report.join('\n');
  }

  /**
   * Generate a JSON-format report for SIEM integration
   * 
   * @param sessionId - Session ID to generate report for
   * @param tenantId - Tenant ID for multi-tenant isolation
   * @param options - Report generation options
   * @returns Promise resolving to JSON object
   */
  async generateReportJSON(
    sessionId: string,
    tenantId: string,
    options: ReportOptions = {}
  ): Promise<object> {
    const logs = await this.auditLogger.queryLogs({
      sessionId,
      tenantId,
      limit: options.limit,
    });

    const events = logs
      .filter(log => log.decision)
      .map(log => ({
        requestId: log.requestId,
        sessionId: log.sessionId,
        tenantId: log.tenantId,
        tool: log.toolName,
        action: log.decision.action,
        riskScore: log.decision.riskScore,
        policyVersion: log.policyVersion,
        timestamp: new Date(log.timestamp).toISOString(),
        originTools: this.extractOriginTools(log) || [],
        taintContexts: log.taintContexts.map(c => ({
          sourceTool: c.sourceTool,
          sensitivity: c.sensitivityLevel,
          containsSecrets: c.containsSecrets,
          contextId: c.contextId,
          timestamp: c.timestamp.toISOString(),
        })),
        reason: log.decision.justification,
      }));

    return {
      sessionId,
      tenantId,
      generatedAt: new Date().toISOString(),
      privacyLevel: options.privacyLevel || ReportPrivacyLevel.AUDITOR,
      totalEvents: events.length,
      events,
    };
  }

  /**
   * Extract origin tools from audit log entry
   * 
   * Checks multiple possible locations (metadata, taint contexts) to find origin tools.
   * Returns tools in chronological order if timestamps are available.
   */
  private extractOriginTools(log: AuditLogEntry): string[] | undefined {
    // Priority 1: Explicit originTools in metadata (already sorted chronologically by TaintRegistry)
    if (log.metadata?.originTools && Array.isArray(log.metadata.originTools)) {
      return log.metadata.originTools;
    }
    
    // Priority 2: Extract unique source tools from taint contexts (fallback)
    // Sort by timestamp if available for chronological ordering
    if (log.taintContexts && Array.isArray(log.taintContexts) && log.taintContexts.length > 0) {
      const toolsWithTimestamps = log.taintContexts
        .map(t => ({
          tool: t.sourceTool,
          timestamp: t.timestamp.getTime(),
        }))
        .filter((item): item is { tool: string; timestamp: number } => 
          Boolean(item.tool) && typeof item.tool === 'string'
        );
      
      // Group by tool, keeping earliest timestamp
      const toolMap = new Map<string, number>();
      for (const { tool, timestamp } of toolsWithTimestamps) {
        if (!toolMap.has(tool) || timestamp < toolMap.get(tool)!) {
          toolMap.set(tool, timestamp);
        }
      }
      
      // Sort by timestamp and return tool names
      if (toolMap.size > 0) {
        return Array.from(toolMap.entries())
          .sort((a, b) => a[1] - b[1]) // Sort by timestamp
          .map(([tool]) => tool);
      }
    }
    
    return undefined;
  }

  /**
   * Generate chronological path from origin tools
   * 
   * Sorts tools by their first appearance timestamp to show the actual data flow sequence.
   */
  private generateChronologicalPath(
    logs: AuditLogEntry[],
    originTools: string[]
  ): string[] {
    // Build map of tool → first seen timestamp
    const toolTimestamps = new Map<string, number>();
    
    for (const log of logs) {
      const tools = this.extractOriginTools(log);
      if (tools) {
        for (const tool of tools) {
          if (!toolTimestamps.has(tool)) {
            toolTimestamps.set(tool, log.timestamp);
          }
        }
      }
    }
    
    // If we have timestamps, sort by them; otherwise use original order
    if (toolTimestamps.size > 0) {
      return originTools
        .map(tool => ({
          tool,
          timestamp: toolTimestamps.get(tool) || 0,
        }))
        .sort((a, b) => a.timestamp - b.timestamp)
        .map(({ tool }) => tool);
    }
    
    return originTools;
  }

  /**
   * Apply privacy filter to sensitive data
   * 
   * Redacts or hashes data based on privacy level.
   */
  private applyPrivacyFilter(value: string, level: ReportPrivacyLevel): string {
    switch (level) {
      case ReportPrivacyLevel.SYSTEM:
        return value; // Show everything
      case ReportPrivacyLevel.AUDITOR:
        // Hash sensitive identifiers (context IDs, etc.)
        if (value.length > 20 && /^[a-f0-9-]{20,}$/i.test(value)) {
          // Looks like a UUID or hash - show first 8 chars
          return `${value.substring(0, 8)}...`;
        }
        return value;
      case ReportPrivacyLevel.PUBLIC:
        // Redact tool names that might be sensitive
        if (value.includes('database') || value.includes('secret') || value.includes('password')) {
          return '[REDACTED]';
        }
        return value;
      default:
        return value;
    }
  }
}

