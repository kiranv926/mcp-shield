# TaintGate: Transport Module

This module provides transport implementations for MCP (Model Context Protocol) communication.

## Overview

TaintGate supports three transport mechanisms:

1. **StdioTransport** - Standard input/output (most common for MCP servers)
2. **SSETransport** - Server-Sent Events (HTTP-based, bidirectional)
3. **HTTPTransport** - HTTP/REST (stateless request-response)

## Usage

### StdioTransport

For MCP servers that communicate via stdin/stdout:

```typescript
import { StdioTransport } from 'taintgate';

const transport = new StdioTransport({
  debug: true, // Optional: enable debug logging
});

// Use with TaintGate
const mediator = new TaintGate({
  clientTransport: transport,
  serverTransport: transport,
  // ... other config
});
```

### SSETransport

For HTTP-based MCP servers using Server-Sent Events:

```typescript
import { SSETransport } from 'taintgate';

const transport = new SSETransport({
  baseUrl: 'https://mcp-server.example.com',
  headers: {
    'Authorization': 'Bearer token',
  },
  timeout: 30000,
  debug: true,
});
```

### HTTPTransport

For REST-based MCP servers:

```typescript
import { HTTPTransport } from 'taintgate';

const transport = new HTTPTransport({
  baseUrl: 'https://mcp-server.example.com',
  headers: {
    'Authorization': 'Bearer token',
  },
  timeout: 30000,
});
```

### Using Transport Factory

```typescript
import { createTransport } from 'taintgate';

// Create transport from configuration
const transport = createTransport({
  type: 'stdio',
  options: {
    debug: true,
  },
});

// Or for HTTP
const httpTransport = createTransport({
  type: 'http',
  options: {
    baseUrl: 'https://mcp-server.example.com',
    timeout: 30000,
  },
});
```

## Integration with TaintGate

```typescript
import { TaintGate } from 'taintgate';
import { StdioTransport } from 'taintgate';
import { PolicyManager } from 'taintgate';
import { RiskEvaluator } from 'taintgate';
import { TaintRegistry } from 'taintgate';
import { RateLimiter } from 'taintgate';
import { ResponseRedactor } from 'taintgate';
import { SecureAuditLogger } from 'taintgate';

// Create transports
const clientTransport = new StdioTransport();
const serverTransport = new StdioTransport();

// Create governance components
const policyManager = new PolicyManager();
const riskEvaluator = new RiskEvaluator(policyManager);
const taintRegistry = new TaintRegistry();
const rateLimiter = new RateLimiter();
const responseRedactor = new ResponseRedactor();
const auditLogger = new SecureAuditLogger({
  logDirectory: './logs',
});

// Create TaintGate
const mediator = new TaintGate({
  clientTransport,
  serverTransport,
  policyManager,
  riskEvaluator,
  taintRegistry,
  rateLimiter,
  responseRedactor,
  auditLogger,
});

// Start the mediator
await mediator.start();

// Now the mediator is ready to intercept MCP requests
```

## Protocol Details

### StdioTransport

- **Protocol**: Line-delimited JSON (NDJSON)
- **Format**: One JSON-RPC message per line, terminated by `\n`
- **Direction**: Bidirectional (stdin for input, stdout for output)
- **Use Case**: Most common MCP server deployment pattern

### SSETransport

- **Protocol**: HTTP with Server-Sent Events
- **Client → Server**: HTTP POST to `/messages`
- **Server → Client**: SSE stream at `/events`
- **Direction**: Bidirectional
- **Use Case**: HTTP-based MCP servers with real-time updates

### HTTPTransport

- **Protocol**: HTTP/REST
- **Client → Server**: HTTP POST to `/messages`
- **Server → Client**: HTTP response body
- **Direction**: Request-response (stateless)
- **Use Case**: REST-based MCP servers

## Error Handling

All transports implement proper error handling:

- Connection errors are caught and logged
- Timeouts are enforced (configurable)
- Invalid JSON messages are logged and skipped
- Transport state is tracked (`isReady()`)

## Testing

See `src/__tests__/transport/` for transport test examples.

## Notes

- **Node.js**: For HTTP/SSE transports in Node.js, you may need to install `node-fetch` or use a fetch polyfill
- **EventSource**: SSETransport requires `EventSource` (available in browsers, or use a polyfill for Node.js)
- **Streams**: StdioTransport uses Node.js streams (stdin/stdout)

