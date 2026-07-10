# TaintGate Examples

Runnable, self-contained examples for **TaintGate** — the deterministic
governance proxy (Policy Enforcement Point) for the Model Context Protocol.

Every example runs **offline**: no network access and no real MCP server are
required. Downstream MCP servers are simulated in-process (or via a local
loopback HTTP server), so you can run each file directly from the repo root.

All examples run straight from the TypeScript source with
[`tsx`](https://github.com/privatenumber/tsx) — no build step needed:

```bash
npx tsx examples/<file>.ts
```

## Examples

### `stdio-integration.ts`

Assembles the **full TaintGate stack** — `PolicyManager`, `RiskEvaluator`,
`TaintRegistry`, `RateLimiter`, `ResponseRedactor`, `SecureAuditLogger`, and the
`ShieldMediator` — and pushes a batch of `tools/call` requests through
`mediator.intercept()`. It demonstrates the four governance outcomes:

- **ALLOW** — a trusted, public, closed-world tool call.
- **REDACT** — an untrusted, internal-sensitivity call whose response is sanitized.
- **BLOCK (policy)** — a tool escalated to `BLOCK` by a policy override.
- **BLOCK (fail-closed)** — a call with no security hints, blocked by default.

The client side uses a real `StdioTransport` (bound to an in-memory stream so it
never blocks on `process.stdin`); the downstream server is an in-process mock
that echoes a canned result.

```bash
npx tsx examples/stdio-integration.ts
```

### `http-integration.ts`

Same governance stack, but placed in front of an **HTTP/JSON-RPC** MCP server.
The example starts a tiny local HTTP server on `127.0.0.1` (an ephemeral port)
to play the downstream MCP server, and points a real `HTTPTransport` at it — so
requests genuinely travel over HTTP while staying fully offline. It shows an
ALLOW round-trip and a policy-driven BLOCK.

```bash
npx tsx examples/http-integration.ts
```

### `policy-manager-example.ts`

Focuses on the **`PolicyManager`** in isolation: loading a policy file, resolving
policies for global / tenant / tool / combined scopes via Most-Restrictive-Wins
(MRW), deriving a `RiskEvaluationConfig`, inspecting policy history, running a
health check, and hot-reloading. It reads `examples/policy-example.json`.

```bash
npx tsx examples/policy-manager-example.ts
```

## Supporting files

- **`mock-transport.ts`** — minimal in-process `ITransport` implementations
  (`MockServerTransport`, `MockClientTransport`) used to run the proxy flow
  without a real MCP server.
- **`policy-example.json`** — sample policy used by `policy-manager-example.ts`.
- **`../policies/default.json`** — the default policy loaded by the integration
  examples (global thresholds/weights plus per-tenant and per-tool overrides).

## Notes

- Run the examples from the **repository root** so the relative policy path
  `./policies/default.json` resolves correctly.
- Audit logs are written to a throwaway directory under your system temp folder
  (`os.tmpdir()/taintgate-example-logs`) to keep the repo clean.
- Set `DEBUG=true` to enable verbose transport logging, e.g.
  `DEBUG=true npx tsx examples/stdio-integration.ts`.
