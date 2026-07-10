#!/usr/bin/env node
/**
 * Minimal offline MCP server fixture for taintgate e2e tests.
 *
 * Speaks JSON-RPC 2.0 over newline-delimited stdio. No network, no deps.
 *
 * Tools advertised (with MCP-Shield security annotations):
 *   - echo         benign, trusted, closed-world, public   -> ALLOW
 *   - read_secret  trusted but secret + confidential        -> REDACT (secret escalation)
 *   - publish      untrusted egress sink, public            -> ALLOW, but REDACT once its
 *                                                              args carry tainted secret data
 */

import { createInterface } from 'node:readline';

// A secret shaped so the redactor's API-key pattern (sk_...) scrubs it, and so
// the taint registry can hash/match it on a later call.
const FAKE_SECRET = 'secret_key=EXAMPLEfakeDoNotUse0123456789abcdef';

const TOOLS = [
  {
    name: 'echo',
    description: 'Echo the input back.',
    inputSchema: {
      type: 'object',
      properties: { message: { type: 'string' } },
    },
    annotations: { trusted: true, openWorld: false, sensitive: 0.0, secret: false },
  },
  {
    name: 'read_secret',
    description: 'Return a (fake) API credential.',
    inputSchema: { type: 'object', properties: {} },
    annotations: { trusted: true, openWorld: false, sensitive: 1.0, secret: true },
  },
  {
    name: 'publish',
    description: 'Publish data to an external destination.',
    inputSchema: {
      type: 'object',
      properties: { data: { type: 'string' } },
    },
    annotations: { trusted: false, openWorld: false, sensitive: 0.0, secret: false },
  },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function ok(id, result) {
  send({ jsonrpc: '2.0', id, result });
}

function fail(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

function handleToolCall(id, params) {
  const name = params && params.name;
  const args = (params && params.arguments) || {};
  switch (name) {
    case 'echo':
      return ok(id, { content: [{ type: 'text', text: JSON.stringify(args) }] });
    case 'read_secret':
      return ok(id, { content: [{ type: 'text', text: `API key: ${FAKE_SECRET}` }] });
    case 'publish':
      return ok(id, { content: [{ type: 'text', text: `published: ${args.data ?? ''}` }] });
    default:
      return fail(id, -32602, `unknown tool: ${name}`);
  }
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (trimmed === '') return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch {
    return;
  }

  const { id, method, params } = msg;
  // Notifications (no id) require no response.
  if (id === undefined || id === null) return;

  switch (method) {
    case 'initialize':
      return ok(id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'stub-mcp-server', version: '1.0.0' },
      });
    case 'ping':
      return ok(id, {});
    case 'tools/list':
      return ok(id, { tools: TOOLS });
    case 'tools/call':
      return handleToolCall(id, params);
    default:
      return fail(id, -32601, `method not found: ${method}`);
  }
});
