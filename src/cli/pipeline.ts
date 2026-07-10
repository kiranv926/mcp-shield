/**
 * taintgate CLI: governance pipeline factory.
 *
 * Wires up the real TaintGate components (PolicyManager, TaintRegistry,
 * RiskEvaluator, ResponseRedactor, RateLimiter, AuditLogger) behind a
 * TaintGate. The mediator is constructed with a no-op transport because
 * the `wrap` bridge drives the raw child-process stdio itself and only calls
 * the mediator's evaluation / redaction helpers (evaluateRequest,
 * createBlockResponse, getResponseRedactor) — never intercept()/forwardRequest(),
 * which are the transport-coupled paths.
 */

import { TaintGate } from '../mediator/TaintGate';
import { RiskEvaluator } from '../core/RiskEvaluator';
import { PolicyManager } from '../core/PolicyManager';
import { TaintRegistry } from '../core/TaintRegistry';
import { ResponseRedactor } from '../core/ResponseRedactor';
import { RateLimiter } from '../core/RateLimiter';
import { AuditLogger } from '../core/audit/AuditLogger';
import type { ITransport } from '../interfaces/ITransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../types/common';

/**
 * Minimal ITransport used only to satisfy the TaintGate constructor.
 * None of its methods are exercised by the `wrap` bridge.
 */
class NoopTransport implements ITransport {
  async send(_message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    /* intentionally unused */
  }
  onMessage(_callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    /* intentionally unused */
  }
  async close(): Promise<void> {
    /* intentionally unused */
  }
  isReady(): boolean {
    return true;
  }
}

export interface PipelineOptions {
  /** Path to a policy JSON file. If omitted, PolicyManager fail-closed defaults apply. */
  policyPath?: string;
  /** Directory for JSONL audit logs. */
  logDir: string;
}

export interface Pipeline {
  mediator: TaintGate;
  taintRegistry: TaintRegistry;
  responseRedactor: ResponseRedactor;
  auditLogger: AuditLogger;
  policyVersion: string;
  destroy(): void;
}

export async function createPipeline(opts: PipelineOptions): Promise<Pipeline> {
  const policyManager = new PolicyManager({ policyPath: opts.policyPath, failClosed: true });
  if (opts.policyPath) {
    // Loads the user's policy. With failClosed:true a missing file falls back to
    // fail-closed defaults rather than throwing; malformed JSON still throws.
    await policyManager.loadPolicies(opts.policyPath);
  }

  const taintRegistry = new TaintRegistry();
  const riskEvaluator = new RiskEvaluator({ policyManager, taintRegistry });
  const responseRedactor = new ResponseRedactor();
  const rateLimiter = new RateLimiter();
  const auditLogger = new AuditLogger({ logDirectory: opts.logDir });
  const transport = new NoopTransport();

  const mediator = new TaintGate({
    riskEvaluator,
    taintRegistry,
    policyManager,
    rateLimiter,
    responseRedactor,
    auditLogger,
    clientTransport: transport,
    serverTransport: transport,
  });

  return {
    mediator,
    taintRegistry,
    responseRedactor,
    auditLogger,
    policyVersion: policyManager.getPolicyVersion(),
    destroy(): void {
      taintRegistry.destroy();
      rateLimiter.destroy();
      policyManager.destroy();
    },
  };
}
