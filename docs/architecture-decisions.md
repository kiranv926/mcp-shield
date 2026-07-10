# TaintGate: Finalized Architecture Decisions

## Executive Summary

This document codifies the final three strategic decisions that complete the TaintGate architectural foundation. These decisions ensure the system is **Enterprise-Grade** (robust and predictable) rather than a prototype.

---

## Decision 1: Policy Conflict Resolution - "Most Restrictive Wins" (MRW)

### Decision
**Implement "Most Restrictive Wins" (MRW) as the default resolution strategy.**

### Rationale
For a security-centric project like TaintGate, MRW is the only viable choice for an EB-1A or production-level governance framework.

### Logic
If any policy in the chain (Global, Tenant, or Tool) identifies a risk that requires a **BLOCK**, the request is blocked, regardless of other "ALLOW" signals.

### Implementation
- **Location**: `IPolicyManager.getResolvedPolicy()`
- **Resolution Rules**:
  1. **Action Override**: If any policy has `actionOverride: 'BLOCK'` → Result is BLOCK
  2. **Action Override**: If any policy has `actionOverride: 'REDACT'` → Result is REDACT (unless BLOCK present)
  3. **Thresholds**: Use most restrictive (lowest `thresholdAllow`, lowest `thresholdBlock`)
  4. **Weights**: Use most restrictive (highest `sensitivity` weight, highest `exposure` weight)

### Why MRW?
- **Principle of Least Privilege**: Security-first approach
- **Prevents Bypass**: A tenant cannot accidentally (or maliciously) bypass global safety guardrails
- **Predictable**: Clear precedence order eliminates ambiguity
- **Auditable**: Easy to trace which policy caused a BLOCK decision

### Alternative Rejected
- **Granular Override**: Would create security holes where tenant policies could override global safety rules

---

## Decision 2: Request Validation - Integrate Zod

### Decision
**Integrate Zod directly into the TaintGate for runtime validation.**

### Rationale
Since we are using TypeScript, Zod is the gold standard for bridging the gap between static types and dynamic JSON-RPC data.

### Logic
Every incoming JSON-RPC request is parsed through a Zod schema **before** it touches the RiskEvaluator.

### Implementation
- **Location**: `IMediator.validateRequest()`
- **Schema**: `JSONRPCRequestSchema` in `src/types/jsonrpc-schema.ts`
- **Flow**: 
  1. Request arrives (unknown type)
  2. Validate with Zod schema
  3. If invalid → BLOCK immediately (fail-closed)
  4. If valid → Proceed to rate limiting

### Why Zod?
- **Runtime Safety**: Catches malformed requests at the boundary
- **Type Inference**: Generates TypeScript types from schemas
- **Industry Standard**: Widely adopted in TypeScript ecosystem
- **Fail-Closed**: Invalid requests are blocked before they can crash components

### Resolves
- **Critical Issue #11**: Malformed requests cannot crash the RiskEvaluator
- **Attack Vector**: Invalid JSON-RPC structure is caught immediately

---

## Decision 3: Rate Limiting - Separate IRateLimiter Interface

### Decision
**Define a separate `IRateLimiter` interface, injected via Dependency Injection.**

### Rationale
To keep the architecture clean and maintainable (SOLID principles), rate limiting should not be hard-coded into the Mediator.

### Logic
```typescript
export interface IRateLimiter {
  checkLimit(tenantId?: string, toolName?: string): Promise<RateLimitResult>;
  recordRequest(tenantId?: string, toolName?: string): Promise<void>;
  // ... other methods
}
```

### Implementation
- **Location**: `src/interfaces/IRateLimiter.ts`
- **Injection**: Injected into `TaintGate` via constructor
- **Access**: Via `IMediator.getRateLimiter()`

### Why Separate Interface?
- **SOLID Principles**: Single Responsibility - rate limiting is separate concern
- **Flexibility**: Swap strategies (in-memory, Redis-based) without changing core logic
- **Testability**: Easy to mock for unit tests
- **Scalability**: Different implementations for different deployment scenarios

### Strategies Supported
- **In-Memory**: Simple counter for single-instance deployments
- **Redis-Based**: Distributed rate limiting for multi-instance deployments
- **Custom**: Any implementation that satisfies the interface

---

## The Finalized "Shield" Execution Flow

When these three decisions are combined, the `TaintGate` follows this **precise sequence** for every tool call:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Validation (Zod)                                         │
│    Is the JSON-RPC request syntactically valid?             │
│    └─ If NO → BLOCK (fail-closed)                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Rate Limit (IRateLimiter)                                │
│    Has this user exceeded their quota?                      │
│    └─ If YES → BLOCK                                        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Taint Check (TaintRegistry)                              │
│    Is the current session context already "Tainted"?         │
│    └─ Query context lineage via checkLineage()              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Risk Calculation (RiskEvaluator)                         │
│    Calculate R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)│
│    └─ Extract S, E, T from tool annotations                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Conflict Resolution (PolicyManager)                       │
│    Apply MRW logic between Global, Tenant, and Tool rules   │
│    └─ Most Restrictive Wins                                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Enforcement                                               │
│    Execute decision: ALLOW | BLOCK | REDACT                  │
│    └─ Log via IAuditLogger                                  │
└─────────────────────────────────────────────────────────────┘
```

### Flow Characteristics

1. **Fail-Closed at Every Step**: Any failure defaults to BLOCK
2. **Deterministic**: Same inputs always produce same outputs
3. **Auditable**: Every step is logged with full context
4. **Type-Safe**: Zod validation ensures type safety at boundary
5. **Scalable**: Rate limiting and taint registry support distributed deployments

---

## Architecture Completeness

### COMPLETED All Interfaces Defined

1. **IMediator** (PEP) - Policy Enforcement Point
2. **IRiskEvaluator** (PDP) - Policy Decision Point
3. **IPolicyManager** (PAP) - Policy Administration Point
4. **ITaintRegistry** - State Manager
5. **IAuditLogger** - Audit Logging
6. **IRateLimiter** - Rate Limiting

### COMPLETED All Types Defined

1. **RiskScore** - Branded type with validation
2. **SensitivityLevel** - Enum for data classification
3. **PolicyDecision** - Complete decision structure
4. **JSON-RPC Schemas** - Zod validation schemas
5. **Fail-Closed Defaults** - Security-first defaults

### COMPLETED All Decisions Finalized

1. COMPLETED Policy Conflict Resolution: **MRW**
2. COMPLETED Request Validation: **Zod Integration**
3. COMPLETED Rate Limiting: **Separate Interface**
4. COMPLETED Type Safety: **Branded Types**
5. COMPLETED Error Handling: **Fail-Closed**
6. COMPLETED Audit Logging: **Complete Interface**

---

## Next Steps

With all architectural decisions finalized, the project is ready for:

1. **Implementation**: Create concrete classes implementing all interfaces
2. **Testing**: Unit tests for each component
3. **Integration**: End-to-end testing of the execution flow
4. **Documentation**: API documentation and usage examples
5. **Deployment**: Production deployment guides

---

**Status**: COMPLETED **ARCHITECTURE COMPLETE**  
**Date**: 2024-2025  
**Version**: 1.0

