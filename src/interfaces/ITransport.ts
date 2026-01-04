/**
 * MCP-Shield: ITransport Interface
 * 
 * Transport layer abstraction for MCP communication.
 * 
 * MCP supports multiple transport mechanisms:
 * - stdio (standard input/output)
 * - SSE (Server-Sent Events)
 * - HTTP (REST/JSON-RPC)
 * 
 * This interface allows ShieldMediator to work with any transport mechanism
 * without being coupled to a specific implementation.
 * 
 * @see ARCHITECTURE.md - Transport Layer Abstraction
 */

import type { JSONRPCRequest, JSONRPCResponse } from '../types/common';

/**
 * Transport Configuration
 */
export interface TransportConfig {
  /**
   * Transport type identifier
   */
  type: 'stdio' | 'sse' | 'http';
  
  /**
   * Additional transport-specific configuration
   */
  options?: Record<string, unknown>;
}

/**
 * ITransport - Transport Layer Interface
 * 
 * Responsibilities:
 * 1. Send JSON-RPC messages (requests or responses)
 * 2. Receive messages via callback registration
 * 3. Handle connection lifecycle (open/close)
 * 4. Support bidirectional communication
 */
export interface ITransport {
  /**
   * Send a JSON-RPC message (request or response).
   * 
   * @param message - JSON-RPC request or response to send
   * @returns Promise resolving when message is sent
   */
  send(message: JSONRPCRequest | JSONRPCResponse): Promise<void>;

  /**
   * Register a callback for incoming messages.
   * 
   * The callback will be invoked whenever a message is received
   * on this transport. The callback should handle both requests
   * and responses.
   * 
   * @param callback - Function to call when a message is received
   */
  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void;

  /**
   * Close the transport connection.
   * 
   * @returns Promise resolving when connection is closed
   */
  close(): Promise<void>;

  /**
   * Check if transport is connected and ready.
   * 
   * @returns true if transport is ready, false otherwise
   */
  isReady(): boolean;
}

