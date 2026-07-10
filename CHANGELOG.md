# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Project relaunched as TaintGate** — an MCP governance proxy (formerly named
  "MCP-Shield"). This relaunch includes a rename, correctness/crypto fixes,
  repository hygiene cleanup, community-health documentation, and CI.

### Added

- `taintgate wrap` — a transparent stdio governance proxy for any MCP server,
  with a bundled CLI and Claude Desktop integration.
- `taintgate scan` — static auditor for already-installed MCP configs (Claude
  Desktop, Cursor, Windsurf, VS Code); flags secrets in env, broad filesystem
  access, unpinned network packages, and remote endpoints. CI-friendly exit codes.
- **Tool-definition pinning** (`--pin`) — detects rug-pulls / tool poisoning
  when a server changes a tool's description or schema after it was pinned;
  policies `warn` / `block` / `update` / `off`.
- **Lethal-trifecta policy pack** (`policies/lethal-trifecta.json`) — tuned to
  block tainted data from reaching egress sinks.
- Continuous integration (GitHub Actions) across Node.js 18, 20, and 22, with a
  coverage run on Node 20.
- Community-health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and
  pull-request templates, and Dependabot configuration.
- Project documentation moved under `docs/`.

[Unreleased]: https://github.com/kiranv926/taintgate/commits/main
