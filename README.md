# MCP-Shield

**Deterministic Policy Enforcement Point (PEP) for Model Context Protocol**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-orange)](https://modelcontextprotocol.io/)

## Overview

MCP-Shield is a non-permissive governance engine that acts as a deterministic Policy Enforcement Point (PEP) for the Model Context Protocol (MCP). It provides a mandatory security layer that sits between MCP Clients (LLMs) and MCP Servers, enforcing policy decisions based on metadata hints and risk assessment to resolve the **Metadata Enforcement Gap**—a critical security vulnerability where security hints are ignored by language models.

### Problem Statement

The Model Context Protocol enables AI agents to interact with external tools and data sources through a standardized interface. However, the protocol's security model relies on metadata hints that are advisory in nature. Language models, operating in an open-world context, may ignore these hints, leading to:

- **Unauthorized data egress**: Sensitive information flowing to untrusted destinations
- **PII exposure**: Personally Identifiable Information (PII) being processed or transmitted without proper controls
- **Secret leakage**: Credentials and secrets being exposed through tool outputs
- **Compliance violations**: Regulatory requirements (GDPR, HIPAA, SOC 2, etc.) being violated due to uncontrolled data flows

### Solution Architecture

MCP-Shield implements a **deterministic, non-permissive security model** that enforces policy decisions at the protocol boundary. Unlike advisory security hints, MCP-Shield operates as a mandatory access control (MAC) layer implemented as a **mandatory proxy** (sidecar pattern) in the transport layer, ensuring it cannot be bypassed by the model or client.

## Architecture

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         MCP Client (LLM)                                │
│                    (Claude, GPT-4, etc.)                                │
└────────────────────────────┬────────────────────────────────────────────┘
                              │
                              │ JSON-RPC Requests
                              │ (callTool, listTools, etc.)
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    MCP-Shield: Policy Enforcement Point                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    ShieldMediator (PEP)                          │  │
│  │  • Intercepts all JSON-RPC requests                              │  │
│  │  • Fail-Closed: BLOCK on timeout/failure                          │  │
│  │  • Enforces: ALLOW | BLOCK | REDACT                               │  │
│  │  • Stream-thru processing for R < 0.1                             │  │
│  └───────────────────────┬──────────────────────────────────────────┘  │
│                          │                                               │
│  ┌───────────────────────▼──────────────────────────────────────────┐  │
│  │                    RiskEvaluator (PDP)                            │  │
│  │  R = clamp((W_s·S + W_e·E) × (1 - T), 0, 1)                      │  │
│  │  • Evaluates tool metadata (MCP hints)                           │  │
│  │  • Consults TaintRegistry for context lineage                     │  │
│  │  • Deterministic: Same inputs → Same output                       │  │
│  │  • Returns policy decision with risk score                        │  │
│  └───────────────────────┬──────────────────────────────────────────┘  │
│                          │                                               │
│  ┌───────────────────────▼──────────────────────────────────────────┐  │
│  │                    TaintRegistry (State Manager)                 │  │
│  │  • Context-aware taint tracking (not session-wide)              │  │
│  │  • Tracks tool output lineage per context                        │  │
│  │  • Stateless per request, stateful per session                  │  │
│  │  • Multi-tenant isolation by tenantId                           │  │
│  └───────────────────────┬──────────────────────────────────────────┘  │
│                          │                                               │
│  ┌───────────────────────▼──────────────────────────────────────────┐  │
│  │                    PolicyManager (PAP)                            │  │
│  │  • Loads policies from YAML/JSON                                  │  │
│  │  • Per-tenant policy configurations                              │  │
│  │  • Dynamic policy updates (hot-reload)                            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                          │                                               │
│  ┌───────────────────────▼──────────────────────────────────────────┐  │
│  │                    ResponseRedactor                               │  │
│  │  • Two-tier sanitization: Schema + Pattern                       │  │
│  │  • Field-level masking for secret: true                           │  │
│  │  • NER-based scrubbing for unstructured text                     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────────────┘
                              │
                              │ Filtered/Enforced Requests
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         MCP Servers                                     │
│              (File System, Database, APIs, etc.)                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

#### 1. ShieldMediator (Policy Enforcement Point - PEP)
The mandatory proxy middleware that intercepts all JSON-RPC requests between the MCP Client and MCP Servers. It:
- Intercepts `callTool`, `listTools`, and other protocol methods at the transport layer
- Queries the RiskEvaluator (PDP) for policy decisions
- Implements **Fail-Closed** behavior: BLOCK on timeout, evaluation failure, or registry unavailability
- Enforces decisions: **ALLOW** (pass through), **BLOCK** (reject with security error), or **REDACT** (sanitize via ResponseRedactor)
- Uses stream-thru processing for low-risk requests (R < 0.1) to minimize buffer overhead
- Logs all governance decisions for audit trails

#### 2. RiskEvaluator (Policy Decision Point - PDP)
The deterministic decision engine that calculates risk scores using the normalized formula:

```
R = clamp((W_s × S + W_e × E) × (1 - T), 0, 1)
```

**Variables:**
- **S (Sensitivity)**: `{0, 0.5, 1.0}` representing Low, Medium, High data classification
- **E (Exposure)**: `{0, 1}` representing closed-world (0) vs open-world (1) egress risk
- **T (Trust)**: `[0, 1]` where 0 = unknown/untrusted, 1 = verified/trusted
- **W_s, W_e**: Configurable weights (default: W_s = 0.6, W_e = 0.4)

**Edge Cases:**
- Missing `trustedHint` → T = 0 (fail-closed)
- Missing `sensitiveHint` → S = 1.0 (maximum sensitivity)
- Missing `openWorldHint` → E = 1 (maximum egress risk)

**Determinism Guarantee:** For a given input tuple `(S, E, T)`, the output `R` is always identical, ensuring auditability and reproducibility. Historical behavior influences the Trust score `T` as an input, but the calculation itself is deterministic.

#### 3. TaintRegistry (State Manager)
A stateful session manager that implements **context-aware taint tracking** (not session-wide):
- Tracks data sensitivity per tool output context, not entire sessions
- Implements taint propagation: if Tool A returns sensitive data, only subsequent tool calls that consume that specific context are evaluated with increased risk
- Maintains context lineage to reduce false positives
- Stateless per request, stateful per session ID
- Supports multi-tenant isolation via `tenantId` scoping
- Session state stored in distributed cache (Redis-compatible) for horizontal scalability

#### 4. PolicyManager (Policy Administration Point - PAP)
The policy administration component that:
- Loads security policies from YAML/JSON configuration files
- Supports per-tenant policy configurations
- Enables dynamic policy updates (hot-reload) without service restart
- Defines risk thresholds, weights (W_s, W_e), and enforcement rules
- Manages allowlists/denylists for tools and destinations

#### 5. ResponseRedactor
The sanitization engine that implements **two-tier redaction**:

**Tier 1: Schema-Based Field Masking**
- If MCP schema identifies a field as `secret: true`, the entire field is masked
- Structured data (JSON) is sanitized at the field level
- Preserves data structure while removing sensitive content

**Tier 2: Pattern-Based NER Scrubbing**
- Uses Named Entity Recognition (NER) and regex patterns for unstructured text
- Scrubs PII patterns (SSN, credit cards, emails, phone numbers)
- Configurable pattern sets per data classification level

## Protocol Compliance

MCP-Shield enforces compliance with security metadata hints proposed in the Model Context Protocol community. These are based on GitHub PRs/Issues in the [modelcontextprotocol/specification](https://github.com/modelcontextprotocol/specification) repository:

| Reference | Standard | Description | Enforcement |
|-----------|----------|-------------|-------------|
| **PR #1487** | `trustedHint` | Indicates whether a tool is inherently safe to execute | Used in Trust (T) calculation: `trusted: true` → T = 1.0, `trusted: false` or missing → T = 0 |
| **PR #1560** | `secretHint` | Indicates whether tool output contains secrets or credentials | Triggers REDACT (Tier 1 masking) or BLOCK on high-risk operations |
| **PR #1913** | `sensitiveHint` | Indicates data sensitivity classification | Maps to Sensitivity (S): `sensitive: false` → S = 0, `sensitive: true` → S = 1.0 |
| **PR #711** | `openWorldHint` | Indicates egress risk to open-world destinations | Maps to Exposure (E): `openWorld: false` → E = 0, `openWorld: true` or missing → E = 1 |
| **PR #1561** | Human-in-the-Loop | Triggers human approval for high-risk operations | Integrated with RiskEvaluator: R > 0.8 triggers HITL workflow |

**Note:** These are proposed standards under discussion in the MCP community. MCP-Shield implements a fail-closed enforcement model: if a server doesn't provide hints, the Shield assumes maximum risk (S = 1.0, T = 0, E = 1).

### Secure-by-Default Policy (Fail-Closed)

MCP-Shield implements a **non-permissive security model** with fail-closed semantics:
- Missing `trustedHint` → T = 0 (lowest trust, highest risk)
- Missing `sensitiveHint` → S = 1.0 (highest sensitivity)
- Missing `openWorldHint` → E = 1 (maximum egress risk)
- Missing `secretHint` → Assumes potential secret leakage
- TaintRegistry timeout/failure → BLOCK (fail-closed)
- RiskEvaluator timeout/failure → BLOCK (fail-closed)

This ensures that tools without proper metadata are treated with maximum caution, and system failures default to blocking rather than allowing potentially unsafe operations.

## Security Model

### Threat Model

MCP-Shield addresses the following threat vectors:

1. **Metadata Enforcement Gap**: LLMs ignoring advisory security hints
   - **Mitigation**: Mandatory proxy at transport layer, cannot be bypassed

2. **Direct Bypass Attempts**: Client attempting to connect directly to servers
   - **Mitigation**: Sidecar pattern enforces all traffic through Shield

3. **Taint Evasion**: Attempting to exfiltrate sensitive data through untracked paths
   - **Mitigation**: Context-aware taint tracking with lineage propagation

4. **Policy Bypass**: Exploiting missing metadata to bypass controls
   - **Mitigation**: Fail-closed default: missing hints = maximum risk

5. **Session Hijacking**: Unauthorized access to tainted session state
   - **Mitigation**: Multi-tenant isolation, session ID validation, TTL expiration

6. **DoS via Policy Evaluation**: Overwhelming the evaluator with requests
   - **Mitigation**: Request rate limiting, timeout enforcement, fail-closed on timeout

### Policy Enforcement Modes

1. **ALLOW**: Request passes through unchanged (R < 0.3, trusted tool, safe data)
   - Stream-thru processing for R < 0.1 to minimize latency
   - Full audit logging maintained

2. **BLOCK**: Request is rejected with a security error (R ≥ 0.7, untrusted tool, sensitive data)
   - Returns JSON-RPC error with security violation code
   - Audit log includes full request context for forensics

3. **REDACT**: Response is sanitized before returning to the client (0.3 ≤ R < 0.7)
   - Two-tier sanitization: Schema-based field masking + Pattern-based NER scrubbing
   - Original response logged for audit, sanitized version returned to client

### Risk Thresholds

| Risk Score Range | Action | Description |
|-----------------|--------|-------------|
| 0.0 - 0.3 | **ALLOW** | Low risk: Trusted tool (T = 1), public data (S = 0), closed-world (E = 0) |
| 0.3 - 0.7 | **REDACT** | Moderate risk: Sanitize sensitive fields, allow safe operations |
| 0.7 - 1.0 | **BLOCK** | High risk: Untrusted tool (T = 0), sensitive data (S = 1.0), open-world (E = 1) |

**Thresholds are configurable** via PolicyManager. Default values (0.3, 0.7) are conservative and can be adjusted per tenant or use case.

### Context-Aware Taint Propagation

The TaintRegistry implements a **context-aware taint model** (not session-wide):

- **Context Lineage Tracking**: When Tool A returns data marked with `sensitiveHint: true` or `secretHint: true`, only the specific data context is marked as tainted
- **Selective Risk Elevation**: Subsequent tool calls are evaluated with increased risk only if they consume the tainted context (via parameter analysis or explicit context binding)
- **Reduced False Positives**: Unlike session-wide tainting, this allows safe operations on unrelated data within the same session
- **Taint Persistence**: Taint state persists for the duration of the session (identified by session ID) or until explicit context expiration
- **Taint Clearing**: Taint can be cleared through explicit session reset, context expiration, or administrative action

## Enterprise Features

### Audit Logging

All governance decisions are logged with comprehensive context for compliance and forensics:

- **Timestamp**: ISO 8601 with timezone
- **Session ID**: Unique session identifier
- **Tenant ID**: Multi-tenant isolation tracking
- **Tool Name & Parameters**: Full request context (parameters may be redacted in logs if sensitive)
- **Risk Score**: Calculated R value with breakdown (S, E, T, W_s, W_e)
- **Policy Decision**: ALLOW/BLOCK/REDACT with justification
- **Metadata Hints Evaluated**: Which hints were present/missing
- **Taint State**: Current context lineage and taint status
- **Response Status**: HTTP/JSON-RPC status codes
- **Latency Metrics**: Policy evaluation time, total request time

Logs are structured (JSON) for integration with SIEM systems and support retention policies for compliance (GDPR, HIPAA, SOC 2).

### Multi-Tenant Support

MCP-Shield provides enterprise-grade multi-tenancy:

- **Session Isolation**: TaintRegistry and PolicyManager are scoped by `tenantId`, ensuring complete data isolation
- **Per-Tenant Risk Thresholds**: Each tenant can configure custom risk thresholds (e.g., financial services: 0.5, development: 0.8)
- **Tenant-Specific Policies**: PolicyManager supports per-tenant policy configurations (YAML/JSON)
- **Resource Quotas**: Per-tenant rate limiting and session count limits
- **Audit Trail**: All logs include tenant ID for compliance and billing

### Performance Characteristics

**Target Performance Metrics:**
- **Policy Evaluation Latency**: < 2ms (p95) for standard requests
- **Request Processing**: Stateless per request (horizontal scalability)
- **Session State**: Stored in distributed cache (Redis-compatible) with sub-millisecond access
- **Stream-Thru Processing**: For R < 0.1, requests use stream-thru to minimize buffer overhead (not true zero-copy due to JSON parsing requirements, but optimized for low latency)
- **Throughput**: Designed for 10,000+ requests/second per instance (horizontal scaling)

**Scalability:**
- Stateless request processing enables horizontal scaling
- Session state in distributed cache supports multi-instance deployments
- Policy evaluation is CPU-bound and can be scaled independently

## Deployment Architecture

MCP-Shield is designed as a **mandatory proxy** (sidecar pattern) that must be deployed in the transport layer between MCP Clients and Servers. This ensures it cannot be bypassed.

### Deployment Patterns

1. **Sidecar Proxy**: Deploy as a sidecar container alongside MCP Client or Server
2. **API Gateway**: Deploy as a middleware layer in an API gateway (Kong, Envoy, etc.)
3. **Service Mesh**: Integrate with service mesh (Istio, Linkerd) as a policy enforcement plugin

### High Availability

- **Fail-Closed**: On system failure, all requests are BLOCKED (secure default)
- **Health Checks**: Exposes health endpoints for load balancer integration
- **Graceful Degradation**: Policy evaluation timeouts trigger BLOCK (fail-closed)
- **State Replication**: TaintRegistry uses distributed cache with replication for HA

## Installation

```bash
# Installation instructions will be available once the codebase is implemented
npm install @mcp-shield/core
```

## Usage

```typescript
// Usage examples will be provided once the implementation is complete
import { ShieldMediator, RiskEvaluator, TaintRegistry, PolicyManager } from '@mcp-shield/core';

const policyManager = new PolicyManager({
  policyPath: './policies/default.yaml',
  enableHotReload: true
});

const taintRegistry = new TaintRegistry({
  sessionTTL: 3600,
  cacheUrl: 'redis://localhost:6379',
  enableMultiTenant: true
});

const riskEvaluator = new RiskEvaluator({
  weights: { sensitivity: 0.6, exposure: 0.4 },
  thresholds: { allow: 0.3, block: 0.7 },
  policyManager,
  taintRegistry
});

const shield = new ShieldMediator({
  riskEvaluator,
  failClosed: true,
  enableAuditLogging: true,
  streamThruThreshold: 0.1
});
```

## Development Status

🚧 **Under Active Development**

This project is currently in the design and implementation phase. Core components are being developed with strict type safety and enterprise-grade security practices.

### Roadmap

- [x] Architecture design and threat model
- [x] Risk formula validation and normalization
- [ ] Core ShieldMediator implementation with fail-closed logic
- [ ] RiskEvaluator with normalized formula `R = clamp((W_s·S + W_e·E) × (1 - T), 0, 1)`
- [ ] TaintRegistry with context-aware taint tracking
- [ ] PolicyManager (PAP) with YAML/JSON policy loading
- [ ] ResponseRedactor with two-tier sanitization
- [ ] Protocol compliance testing (MCP PR validation)
- [ ] Enterprise audit logging with structured JSON
- [ ] Multi-tenant isolation and per-tenant policies
- [ ] Performance benchmarking and optimization
- [ ] Comprehensive test suite (unit, integration, security)
- [ ] Deployment guides and examples
- [ ] Security policy and responsible disclosure process

## Contributing

Contributions are welcome! Please read our contributing guidelines (to be added) before submitting pull requests.

### Development Principles

- **Type Safety**: Strict TypeScript with no `any` types, full type coverage
- **Secure-by-Default**: Missing hints = maximum risk (fail-closed)
- **Deterministic**: Same inputs always produce same policy decisions (auditability)
- **Auditable**: All decisions logged with full context for compliance
- **Stateless Requests**: Horizontal scalability per request
- **Fail-Closed**: System failures default to BLOCK, not ALLOW

## Security Policy

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for our responsible disclosure process, PGP key for encrypted reports, and response SLA.

## License

Copyright 2024 MCP-Shield Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [MCP Specification Repository](https://github.com/modelcontextprotocol/specification)
- [Policy Enforcement Point (PEP) Pattern](https://en.wikipedia.org/wiki/XACML)
- [XACML Architecture (PEP/PDP/PAP)](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)

---

**MCP-Shield**: Enforcing security at the protocol boundary, one request at a time.
