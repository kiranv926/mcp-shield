# MCP-Shield Source Code

## Structure

```
src/
├── interfaces/          # Core architecture interfaces
│   ├── IMediator.ts     # Policy Enforcement Point (PEP)
│   ├── IRiskEvaluator.ts # Policy Decision Point (PDP)
│   ├── ITaintRegistry.ts # State Manager
│   └── index.ts          # Interface exports
├── types/               # Type definitions
│   ├── mcp-hints.ts     # MCP tool annotations (PR mappings)
│   ├── common.ts        # Common types
│   └── index.ts         # Type exports
└── index.ts             # Main entry point
```

## Core Interfaces

### IMediator (PEP)
Policy Enforcement Point that intercepts and enforces decisions.

### IRiskEvaluator (PDP)
Policy Decision Point that calculates risk scores and makes decisions.

### ITaintRegistry
State Manager for context-aware taint tracking.

## MCP Protocol Mappings

All tool annotations are mapped to MCP GitHub PRs:

- **PR #1487**: `trustedHint` → Trust (T) calculation
- **PR #1560**: `secretHint` → Secret leakage detection
- **PR #1913**: `sensitiveHint` → Sensitivity (S) calculation
- **PR #711**: `openWorldHint` → Exposure (E) calculation
- **PR #1561**: `requireHITL` → Human-in-the-loop triggers

## Fail-Closed Defaults

When MCP servers don't provide security hints, `FailClosedDefaults` ensures maximum security:

- Missing `trustedHint` → T = 0 (untrusted)
- Missing `sensitiveHint` → S = 1.0 (maximum sensitivity)
- Missing `openWorldHint` → E = 1 (maximum egress risk)
- Missing `secretHint` → Assumes secret leakage

See `src/types/mcp-hints.ts` for implementation.

