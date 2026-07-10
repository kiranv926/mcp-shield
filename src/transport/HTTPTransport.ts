/**
 * TaintGate: HTTPTransport Implementation
 *
 * EXPERIMENTAL — NOT yet compliant with the MCP Streamable HTTP transport
 * spec (2025-06-18 and later). This is a simplified request/response HTTP
 * transport and should be treated as experimental / not production-ready.
 *
 * Follow-up: align with the MCP Streamable HTTP spec, including the
 * single-endpoint model, `Accept` header negotiation (application/json and
 * text/event-stream), and `Mcp-Session-Id` session semantics. Until then,
 * this implementation does not interoperate with spec-compliant MCP servers.
 *
 * Current (non-spec) behavior:
 * - Client → Server: HTTP POST with JSON-RPC request in body
 * - Server → Client: HTTP response with JSON-RPC response in body
 */

import type { ITransport } from '../interfaces/ITransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../types/common';

/**
 * HTTPTransport Configuration
 */
export interface HTTPTransportConfig {
  /**
   * Base URL for the MCP server
   */
  baseUrl: string;
  
  /**
   * HTTP headers to include in requests
   */
  headers?: Record<string, string>;
  
  /**
   * Request timeout in milliseconds (default: 30000)
   */
  timeout?: number;
  
  /**
   * Enable debug logging
   */
  debug?: boolean;
  
  /**
   * Custom fetch implementation (for testing or custom HTTP clients)
   */
  fetch?: typeof fetch;
}

/**
 * HTTPTransport - HTTP/REST Transport
 * 
 * Implements ITransport for HTTP-based MCP servers.
 * 
 * Features:
 * - HTTP POST for sending requests
 * - HTTP response for receiving responses
 * - Request/response correlation
 * - Connection pooling (via fetch)
 */
export class HTTPTransport implements ITransport {
  private messageCallback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;
  private debug: boolean;
  private fetchImpl: typeof fetch;
  private isReadyState: boolean = true; // HTTP is always "ready" (stateless)

  constructor(config: HTTPTransportConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.headers = {
      'Content-Type': 'application/json',
      ...config.headers,
    };
    this.timeout = config.timeout ?? 30000;
    this.debug = config.debug ?? false;
    this.fetchImpl = config.fetch ?? (typeof fetch !== 'undefined' ? fetch : this.createFetchPolyfill());
  }

  /**
   * Send a JSON-RPC message via HTTP POST
   */
  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    if (!this.isReady()) {
      throw new Error('[HTTPTransport] Transport is not ready');
    }

    try {
      const url = `${this.baseUrl}/messages`;
      const body = JSON.stringify(message);
      
      if (this.debug) {
        console.error(`[HTTPTransport] Sending to ${url}: ${body.substring(0, 100)}...`);
      }
      
      const response = await this.fetchImpl(url, {
        method: 'POST',
        headers: this.headers,
        body,
        signal: this.createAbortSignal(this.timeout),
      });
      
      if (!response.ok) {
        throw new Error(`[HTTPTransport] HTTP ${response.status}: ${response.statusText}`);
      }
      
      // For requests, parse response body
      if ('id' in message && message.id !== null && 'method' in message) {
        const responseBody = await response.json() as JSONRPCResponse;
        
        if (this.debug) {
          console.error(`[HTTPTransport] Received response: ${JSON.stringify(responseBody).substring(0, 100)}...`);
        }
        
        // Invoke callback with response
        if (this.messageCallback) {
          await this.messageCallback(responseBody);
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`[HTTPTransport] Failed to send message: ${errorMessage}`);
    }
  }

  /**
   * Register callback for incoming messages
   * 
   * For HTTP transport, responses come via the send() method's response.
   * This callback is invoked when a response is received.
   */
  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.messageCallback = callback;
  }

  /**
   * Close the transport connection
   * 
   * HTTP is stateless, so this is a no-op, but we mark as not ready.
   */
  async close(): Promise<void> {
    this.isReadyState = false;
  }

  /**
   * Check if transport is ready
   */
  isReady(): boolean {
    return this.isReadyState;
  }

  /**
   * Create AbortSignal with timeout (polyfill for older environments)
   */
  private createAbortSignal(timeoutMs: number): AbortSignal {
    // Use native AbortSignal.timeout if available (Node.js 17.3+)
    const abortSignalCtor = AbortSignal as typeof AbortSignal & {
      timeout?: (ms: number) => AbortSignal;
    };
    if (typeof AbortSignal !== 'undefined' && typeof abortSignalCtor.timeout === 'function') {
      return abortSignalCtor.timeout(timeoutMs);
    }
    
    // Polyfill for older environments
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, timeoutMs);
    
    // Clear timeout if signal is already aborted
    if (controller.signal.aborted) {
      clearTimeout(timeoutId);
    }
    
    return controller.signal;
  }

  /**
   * Create fetch polyfill for Node.js environments
   * 
   * Note: In production, you should use a proper fetch implementation like node-fetch
   */
  private createFetchPolyfill(): typeof fetch {
    if (typeof fetch !== 'undefined') {
      return fetch;
    }
    
    // Fallback: throw error if fetch is not available
    throw new Error('fetch is not available. Please install node-fetch or use a fetch polyfill.');
  }
}

