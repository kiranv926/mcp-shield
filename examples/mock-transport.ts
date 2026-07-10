/**
 * TaintGate: In-Process Mock Transport
 *
 * A tiny `ITransport` implementation used by the runnable examples so they can
 * demonstrate the full proxy flow OFFLINE — with no network and no real MCP
 * server process.
 *
 * The TaintGate forwards every ALLOW/REDACT request to its `serverTransport`
 * and then waits for a correlated response to come back through the same
 * transport's `onMessage` listener (keyed by the wire id it stamped on the
 * outbound request). `MockServerTransport` plays the role of the downstream MCP
 * server: whenever the mediator sends it a request, it synthesizes a JSON-RPC
 * response (echoing the wire id) and delivers it back to the mediator's listener.
 */

import type { ITransport } from '../src/interfaces/ITransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../src/types/common';

/**
 * Produces the `result` payload a fake MCP server would return for a given
 * tool-call request. Defaults to a small canned record.
 */
export type MockResponder = (request: JSONRPCRequest) => unknown;

const defaultResponder: MockResponder = (request) => {
  const params = (request.params ?? {}) as Record<string, unknown>;
  return {
    ok: true,
    tool: params.name ?? 'unknown',
    content: [
      {
        type: 'text',
        text: `Simulated response for ${String(params.name ?? 'unknown')}`,
      },
    ],
  };
};

/**
 * MockServerTransport — stands in for the downstream MCP server.
 */
export class MockServerTransport implements ITransport {
  private callback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private ready = true;
  private readonly responder: MockResponder;

  constructor(responder: MockResponder = defaultResponder) {
    this.responder = responder;
  }

  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    // Only requests (they carry a `method`) get a synthesized server response.
    // Notifications (id === null) are fire-and-forget.
    if ('method' in message && message.id !== null && message.id !== undefined) {
      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: message.id, // echo the wire id so the mediator can correlate it
        result: this.responder(message as JSONRPCRequest),
      };
      // Deliver asynchronously, mimicking a real transport round-trip.
      queueMicrotask(() => {
        this.callback?.(response).catch(() => {
          /* swallow: example transport, nothing to recover */
        });
      });
    }
  }

  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.callback = callback;
  }

  async close(): Promise<void> {
    this.ready = false;
  }

  isReady(): boolean {
    return this.ready;
  }
}

/**
 * MockClientTransport — stands in for the upstream MCP client.
 *
 * The current mediator request/response flow drives everything through the
 * server transport and `intercept()`, so the client transport only needs to
 * satisfy the `ITransport` contract. It is included to show the real wiring.
 */
export class MockClientTransport implements ITransport {
  private callback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private ready = true;

  async send(_message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    /* no-op for the examples */
  }

  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.callback = callback;
  }

  async close(): Promise<void> {
    this.ready = false;
  }

  isReady(): boolean {
    return this.ready;
  }
}
