/**
 * TaintGate: SSETransport Implementation
 *
 * DEPRECATED — the MCP HTTP+SSE transport is deprecated in favor of the
 * Streamable HTTP transport. This implementation is retained only for legacy
 * compatibility and is NOT recommended for new integrations.
 *
 * Additionally, it relies on a global `EventSource` (browser-provided or
 * polyfilled) and therefore does NOT work on bare Node.js without an
 * EventSource polyfill.
 *
 * Legacy protocol (deprecated):
 * - Client → Server: HTTP POST with JSON-RPC request in body
 * - Server → Client: SSE stream with JSON-RPC responses
 */

import type { ITransport } from '../interfaces/ITransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../types/common';

/**
 * SSETransport Configuration
 */
export interface SSETransportConfig {
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
 * SSETransport - Server-Sent Events Transport
 * 
 * Implements ITransport for HTTP-based MCP servers using SSE.
 * 
 * Features:
 * - HTTP POST for sending requests
 * - SSE stream for receiving responses
 * - Automatic reconnection on connection loss
 * - Request/response correlation
 */
export class SSETransport implements ITransport {
  private messageCallback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;
  private debug: boolean;
  private fetchImpl: typeof fetch;
  private eventSource?: EventSource;
  private isReadyState: boolean = false;
  private pendingRequests = new Map<string | number, {
    resolve: (response: JSONRPCResponse) => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
  }>();
  
  /**
   * Maximum number of pending requests to prevent memory exhaustion
   */
  private static readonly MAX_PENDING_REQUESTS = 1000;

  constructor(config: SSETransportConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.headers = {
      'Content-Type': 'application/json',
      ...config.headers,
    };
    this.timeout = config.timeout ?? 30000;
    this.debug = config.debug ?? false;
    this.fetchImpl = config.fetch ?? (typeof fetch !== 'undefined' ? fetch : this.createFetchPolyfill());
    
    // Start SSE connection
    this.connect();
  }

  /**
   * Send a JSON-RPC message via HTTP POST
   */
  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    if (!this.isReady()) {
      throw new Error('[SSETransport] Transport is not ready');
    }

    try {
      const url = `${this.baseUrl}/messages`;
      const body = JSON.stringify(message);
      
      if (this.debug) {
        console.error(`[SSETransport] Sending to ${url}: ${body.substring(0, 100)}...`);
      }
      
      const response = await this.fetchImpl(url, {
        method: 'POST',
        headers: this.headers,
        body,
        signal: this.createAbortSignal(this.timeout),
      });
      
      if (!response.ok) {
        throw new Error(`[SSETransport] HTTP ${response.status}: ${response.statusText}`);
      }
      
      // For requests with IDs, check pending requests limit
      if ('id' in message && message.id !== null && 'method' in message) {
        if (this.pendingRequests.size >= SSETransport.MAX_PENDING_REQUESTS) {
          throw new Error(`[SSETransport] Too many pending requests (max: ${SSETransport.MAX_PENDING_REQUESTS})`);
        }
        
        // Note: Response correlation is handled in the SSE message handler
        // We don't create a promise here because responses come via SSE stream
      }
      
      // For responses, we just send them (no reply expected)
    } catch (error) {
      this.isReadyState = false;
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`[SSETransport] Failed to send message: ${errorMessage}`);
    }
  }

  /**
   * Register callback for incoming messages
   * 
   * For SSE transport, messages come via the EventSource stream.
   */
  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.messageCallback = callback;
  }

  /**
   * Close the transport connection
   */
  async close(): Promise<void> {
    this.isReadyState = false;
    
    // Close EventSource
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = undefined;
    }
    
    // Reject all pending requests with timeout cleanup
    for (const [, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('[SSETransport] Transport closed'));
    }
    this.pendingRequests.clear();
  }

  /**
   * Check if transport is ready
   */
  isReady(): boolean {
    return this.isReadyState && 
           this.eventSource !== undefined &&
           this.eventSource.readyState === EventSource.OPEN;
  }

  /**
   * Connect to SSE stream
   */
  private connect(): void {
    if (typeof EventSource === 'undefined') {
      throw new Error('EventSource is not available. SSETransport requires a browser or Node.js with EventSource polyfill.');
    }
    
    const url = `${this.baseUrl}/events`;
    
    if (this.debug) {
      console.error(`[SSETransport] Connecting to SSE stream: ${url}`);
    }
    
    this.eventSource = new EventSource(url);
    
    this.eventSource.onopen = (): void => {
      this.isReadyState = true;
      if (this.debug) {
        console.error('[SSETransport] SSE connection opened');
      }
    };
    
    this.eventSource.onmessage = (event: MessageEvent): void => {
      try {
        const message = JSON.parse(event.data) as JSONRPCRequest | JSONRPCResponse;
        
        if (this.debug) {
          console.error(`[SSETransport] Received SSE message: ${event.data.substring(0, 100)}...`);
        }
        
        // Handle response correlation (only for responses with IDs)
        if ('id' in message && message.id !== null && ('result' in message || 'error' in message)) {
          const messageId = message.id; // TypeScript now knows it's not null
          const pending = this.pendingRequests.get(messageId);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingRequests.delete(messageId);
            pending.resolve(message as JSONRPCResponse);
            return;
          }
          
          // If no pending request found, log warning (might be a duplicate or late response)
          if (this.debug) {
            console.error(`[SSETransport] Received response for unknown request ID: ${messageId}`);
          }
        }
        
        // Invoke callback for other messages
        if (this.messageCallback) {
          this.messageCallback(message).catch((error) => {
            console.error('[SSETransport] Error in message callback:', error);
          });
        }
      } catch (error) {
        console.error('[SSETransport] Failed to parse SSE message:', error);
      }
    };
    
    this.eventSource.onerror = (error: Event): void => {
      this.isReadyState = false;
      if (this.debug) {
        console.error('[SSETransport] SSE connection error:', error);
      }
      
      // Attempt reconnection (EventSource handles this automatically)
      // But we can add custom retry logic here if needed
    };
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

