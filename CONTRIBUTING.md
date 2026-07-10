# Contributing to TaintGate

Thanks for your interest in contributing to **TaintGate**, an MCP governance
proxy. This document explains how to build, test, and submit changes.

By participating in this project you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Getting Started

TaintGate is a TypeScript project targeting Node.js 18, 20, and 22.

```bash
# Clone your fork
git clone https://github.com/<your-username>/taintgate.git
cd taintgate

# Install dependencies (uses the committed package-lock.json)
npm ci
```

## Development Workflow

Common scripts:

```bash
npm run build        # Compile TypeScript to dist/
npm run type-check   # Type-check without emitting
npm run lint         # Run ESLint
npm run lint:fix     # Auto-fix lint issues
npm test             # Run the Jest test suite
npm run test:coverage # Run tests with coverage
```

Before opening a pull request, please make sure the following all pass locally:

```bash
npm run build && npm run type-check && npm run lint && npm test
```

CI runs these same checks across Node 18, 20, and 22, plus a coverage run on
Node 20.

## Branching & Pull Requests

- Create a topic branch off the default branch (e.g. `feature/policy-cache`,
  `fix/rate-limiter-window`).
- Keep pull requests focused; smaller PRs are easier to review.
- Fill out the pull request template and link any related issues.
- Ensure CI is green before requesting review.

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Examples:

```
feat(policy): add wildcard matching to resource rules
fix(transport): handle premature stream close
docs(rate-limiter): document sliding-window semantics
chore(deps): bump eslint to v9
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`.

## Developer Certificate of Origin (DCO)

All commits must be signed off to certify that you have the right to submit the
contribution under the project's license (the
[Developer Certificate of Origin](https://developercertificate.org/)).

Add a sign-off to each commit with the `-s` flag:

```bash
git commit -s -m "feat(policy): add wildcard matching"
```

This appends a line like the following to your commit message:

```
Signed-off-by: Your Name <you@example.com>
```

## Reporting Security Issues

Please **do not** open public issues for security vulnerabilities. Follow the
process described in [SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](./LICENSE).
