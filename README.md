# TaintGate

**A taint-aware governance proxy for the Model Context Protocol (MCP).**

TaintGate sits between an MCP client (Claude Desktop, Cursor, your own agent) and the MCP servers it talks to, and enforces a deterministic policy on every tool call: **ALLOW**, **REDACT**, or **BLOCK**. Unlike advisory tool annotations that a model is free to ignore, TaintGate runs *outside* the model as a mandatory proxy — it cannot be prompted away.

Its distinguishing feature is **session-level taint tracking**: when a tool returns sensitive data, TaintGate remembers it, and a later tool call that tries to carry that data to an untrusted sink is caught as an information-flow violation — the "read a secret, then exfiltrate it" pattern that per-message scanners miss.

[![CI](https://github.com/kiranv926/taintgate/actions/workflows/ci.yml/badge.svg)](https://github.com/kiranv926/taintgate/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-governance-orange)](https://modelcontextprotocol.io/)

> **Status:** v0.1, pre-release. The `stdio` proxy and the governance engine are production-shaped and covered by 400+ tests. State is in-memory (single instance); the HTTP transport is experimental. See [Project status](#project-status) for the honest picture.

---

## 60-second quickstart

Wrap any stdio MCP server with `taintgate wrap -- <server command>`. No changes to the server, no changes to the client.

```bash
# Put TaintGate in front of the official filesystem server
npx taintgate wrap -- npx -y @modelcontextprotocol/server-filesystem ~/Documents
```

To protect the servers your **Claude Desktop** already uses, wrap the command in `claude_desktop_config.json`:

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "taintgate", "wrap", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/Documents"
      ]
    }
  }
}
```

Add a custom policy with `"--policy", "/path/to/policy.json"` before the `--`. Generate a starter policy with `npx taintgate init-config ./policy.json`.

---

## The demo: taint tracking stops an exfiltration

A tool that reads a secret is fine. A tool that publishes a message is fine. The *combination* — publishing a message that contains the secret — is the attack. TaintGate is one of the few OSS gateways that catches it, because it tracks the data, not just the string.

```
[taintgate] tools/call echo         -> ALLOW  :: low risk (0.00)
[taintgate] tools/call read_secret  -> REDACT :: secretHint detected; high-sensitivity output
[taintgate] tools/call publish      -> ALLOW  :: low risk; benign message
[taintgate] tools/call publish      -> REDACT :: taint from read_secret; untrusted egress sink
PUB+TAINT: published: "exfiltrating [REDACTED]"
```

The last call is a normally-allowed `publish`, but because its arguments carry data tainted by the earlier `read_secret`, TaintGate escalates it and scrubs the secret before it leaves. This exact scenario runs offline in the test suite (`src/__tests__/cli/wrap.e2e.test.ts`).

---

## What it enforces

Every request is scored deterministically and mapped to an action:

```
R = clamp((W_s · S + W_e · E) · (1 − T), 0, 1)
```

| Factor | Meaning | Source |
|---|---|---|
| **S** — Sensitivity | how sensitive the data is | tool annotations + taint lineage |
| **E** — Exposure | open-world / egress risk | tool annotations |
| **T** — Trust | how trusted the tool is | tool annotations |

| Risk | Action | Behavior |
|---|---|---|
| `0.0 – 0.3` | **ALLOW** | forwarded unchanged |
| `0.3 – 0.7` | **REDACT** | secrets/PII scrubbed from the response before it reaches the client |
| `0.7 – 1.0` | **BLOCK** | rejected with a JSON-RPC security error; never forwarded |

Thresholds and weights are configurable per tenant and per tool via policy. **Fail-closed by default:** missing hints, evaluation timeouts, and internal errors all resolve to maximum risk / BLOCK (opt into `--fail-open` for local development).

### The engine

- **Risk scoring** — deterministic, auditable, reproducible for the same inputs.
- **Taint tracking** — hash-based lineage of sensitive tool outputs, with sub-token matching and per-session/tenant isolation. Numeric and string secrets are tracked symmetrically.
- **Response redaction** — two tiers: schema/field masking for known-sensitive fields (normalized `password`/`token`/`api_key`/… matching) plus pattern scrubbing of PII (SSN, cards, emails) in strings *and* numeric leaves; errors are redacted too.
- **Tamper-evident audit log** — every decision is written to a hash-chained JSONL log signed with real HMAC-SHA256; `verifyIntegrity()` checks both the signatures (constant-time) and the chain linkage.
- **Rate limiting** — atomic sliding-window consume (no check-then-record race), per tenant/tool.

---

## Use it as a library

The CLI is a thin wrapper over the library, which you can embed directly in a TypeScript MCP client or server. The building blocks (sketch):

```typescript
import { TaintGate, RiskEvaluator, PolicyManager, TaintRegistry, ResponseRedactor } from 'taintgate';

const policyManager = new PolicyManager({ policyPath: './policy.json', enableHotReload: true });
await policyManager.loadPolicies();

const taintRegistry = new TaintRegistry({ sessionTTL: 3600 });
const riskEvaluator = new RiskEvaluator({ policyManager, taintRegistry });
// TaintGate wires these together and mediates a pair of transports.
```

For the exact, runnable wiring (including transports), see the examples — [`examples/`](examples/) contains stdio, HTTP, and policy-management demos that each run offline with `npx tsx examples/<name>.ts`.

---

## How it works

```
  MCP Client                TaintGate                    MCP Server
 (Claude, etc.) ──req──▶  PEP → risk eval → taint  ──▶  (filesystem,
                │           │      │         │            db, APIs…)
                │        ALLOW / BLOCK / REDACT
                ◀──resp── redactor ◀── taint register ◀──resp──
```

TaintGate implements the classic **PEP / PDP / PAP** split (à la XACML): the proxy is the enforcement point, the risk evaluator is the decision point, and the policy manager is the administration point. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and threat model.

---

## Where TaintGate fits

The MCP security ecosystem is mostly **scanners** (find bad servers before you install them) and **Python/Go/Rust gateways**. TaintGate's niche:

- **TypeScript-native.** The official MCP SDK and most MCP servers are Node/TS; TaintGate embeds directly in that ecosystem instead of running as a separate-language sidecar.
- **Runtime information-flow control.** Taint tracking across tool calls, not just per-message pattern matching — it reasons about where data *came from*, not only what a single payload looks like.
- **Graduated, explainable verdicts.** ALLOW / REDACT / BLOCK with a risk breakdown in every audit record, rather than binary allow/deny.

It is complementary to scanners (e.g. run one before install, TaintGate at runtime) and to L7 gateways that focus on auth/routing.

---

## Project status

Honest scope for v0.1 — no aspirational claims in this README:

| Area | Status |
|---|---|
| `stdio` proxy + governance engine | **Supported.** 400+ tests, strict TypeScript, fail-closed. |
| Taint tracking / redaction / audit / rate limiting | **Implemented and tested.** |
| State backend | **In-memory, single instance.** No Redis/distributed store yet — restarts drop taint/rate state. |
| HTTP transport | **Experimental** — not yet compliant with the MCP Streamable HTTP spec. `stdio` is the supported path. |
| SSE transport | **Deprecated** (the MCP HTTP+SSE transport is superseded by Streamable HTTP). |
| Tool annotations | `openWorldHint` is a shipped MCP annotation; some sensitivity/secret hints TaintGate consumes are proposed/community annotations — treated as untrusted inputs, exactly as the spec advises. |

### Roadmap

- [ ] Spec-compliant Streamable HTTP transport (single endpoint, `Mcp-Session-Id`), built on `@modelcontextprotocol/sdk` 1.x
- [ ] Pluggable distributed state backend (Redis) for multi-instance deployments
- [ ] SIEM-friendly audit sinks (Splunk HEC, OpenTelemetry)
- [ ] Policy pack presets (GDPR / HIPAA / PCI field sets)
- [ ] Annotation-vs-behavior divergence detection

---

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md). Run `npm install`, then `npm run build && npm test && npm run lint`.

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for security reports.

## License

Apache-2.0 — see [LICENSE](LICENSE).
