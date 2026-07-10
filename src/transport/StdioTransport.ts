/**
 * MCP-Shield: StdioTransport Implementation
 *
 * PRODUCTION-SUPPORTED transport. This is the primary, supported transport for
 * MCP communication over stdin/stdout, and the most common deployment pattern
 * for MCP servers.
 *
 * It handles JSON-RPC messages over standard input/output streams using a
 * line-delimited JSON (NDJSON) framing: one JSON-RPC message per line.
 *
 * Protocol: Line-delimited JSON (NDJSON) - one JSON-RPC message per line
 */

import type { ITransport } from '../interfaces/ITransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../types/common';

/**
 * StdioTransport Configuration
 */
export interface StdioTransportConfig {
  /**
   * Read stream (default: process.stdin)
   */
  inputStream?: NodeJS.ReadableStream;
  
  /**
   * Write stream (default: process.stdout)
   */
  outputStream?: NodeJS.WritableStream;
  
  /**
   * Enable debug logging
   */
  debug?: boolean;
}

/**
 * StdioTransport - Standard Input/Output Transport
 * 
 * Implements ITransport for stdin/stdout communication with MCP servers.
 * 
 * Features:
 * - Line-delimited JSON (NDJSON) protocol
 * - Automatic message parsing and framing
 * - Error handling and reconnection logic
 * - Bidirectional communication support
 */
export class StdioTransport implements ITransport {
  private messageCallback?: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>;
  private inputStream: NodeJS.ReadableStream;
  private outputStream: NodeJS.WritableStream;
  private buffer: string = '';
  private isReadyState: boolean = false;
  private debug: boolean;
  
  /**
   * Maximum buffer size to prevent memory exhaustion (1MB)
   */
  private static readonly MAX_BUFFER_SIZE = 1024 * 1024;
  
  constructor(config?: StdioTransportConfig) {
    this.inputStream = config?.inputStream ?? process.stdin;
    this.outputStream = config?.outputStream ?? process.stdout;
    this.debug = config?.debug ?? false;
    
    // Set streams to binary mode for proper line handling
    if (this.inputStream.setEncoding) {
      this.inputStream.setEncoding('utf8');
    }
    
    // Initialize ready state
    this.isReadyState = this.inputStream.readable && this.outputStream.writable;
    
    // Start reading from stdin
    this.startReading();
  }

  /**
   * Send a JSON-RPC message
   */
  async send(message: JSONRPCRequest | JSONRPCResponse): Promise<void> {
    if (!this.isReady()) {
      throw new Error('[StdioTransport] Transport is not ready');
    }

    try {
      // Serialize message to JSON
      const json = JSON.stringify(message);
      
      // Write line-delimited JSON (NDJSON format)
      // Each message is a single line terminated by \n
      const line = json + '\n';
      
      if (this.debug) {
        console.error(`[StdioTransport] Sending: ${json.substring(0, 100)}...`);
      }
      
      // Write to stdout with proper cleanup to prevent memory leaks
      return new Promise((resolve, reject) => {
        let resolved = false;
        
        const cleanup = (): void => {
          this.outputStream.removeListener('error', onError);
          this.outputStream.removeListener('drain', onDrain);
        };

        const onError = (error: Error): void => {
          if (!resolved) {
            resolved = true;
            cleanup();
            reject(new Error(`[StdioTransport] Failed to send message: ${error.message}`));
          }
        };
        
        const onDrain = (): void => {
          if (!resolved) {
            resolved = true;
            cleanup();
            resolve();
          }
        };
        
        if (!this.outputStream.write(line)) {
          // If write buffer is full, wait for drain
          this.outputStream.once('drain', onDrain);
        } else {
          // Write completed immediately
          process.nextTick(() => {
            if (!resolved) {
              resolved = true;
              cleanup();
              resolve();
            }
          });
        }
        
        // Handle write errors
        this.outputStream.once('error', onError);
      });
    } catch (error) {
      throw new Error(`[StdioTransport] Failed to send message: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Register callback for incoming messages
   */
  onMessage(callback: (message: JSONRPCRequest | JSONRPCResponse) => Promise<void>): void {
    this.messageCallback = callback;
  }

  /**
   * Close the transport connection
   */
  async close(): Promise<void> {
    this.isReadyState = false;
    
    // Remove listeners
    this.inputStream.removeAllListeners('data');
    this.inputStream.removeAllListeners('end');
    this.inputStream.removeAllListeners('error');
    
    // Close streams if they support it
    if ('destroy' in this.inputStream && typeof this.inputStream.destroy === 'function') {
      this.inputStream.destroy();
    }
    
    if ('end' in this.outputStream && typeof this.outputStream.end === 'function') {
      this.outputStream.end();
    }
  }

  /**
   * Check if transport is ready
   */
  isReady(): boolean {
    return this.isReadyState && 
           this.inputStream.readable && 
           this.outputStream.writable;
  }

  /**
   * Start reading from input stream
   */
  private startReading(): void {
    this.inputStream.on('data', (chunk: string | Buffer) => {
      const data = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      this.buffer += data;
      this.processBuffer();
    });

    this.inputStream.on('end', () => {
      this.isReadyState = false;
      if (this.debug) {
        console.error('[StdioTransport] Input stream ended');
      }
    });

    this.inputStream.on('error', (error: Error) => {
      this.isReadyState = false;
      if (this.debug) {
        console.error('[StdioTransport] Input stream error:', error);
      }
    });
  }

  /**
   * Process buffer for complete JSON-RPC messages
   * 
   * NDJSON format: One JSON object per line, terminated by \n
   */
  private processBuffer(): void {
    // Check buffer size limit to prevent memory exhaustion
    if (this.buffer.length > StdioTransport.MAX_BUFFER_SIZE) {
      console.error(`[StdioTransport] Buffer overflow (${this.buffer.length} bytes), clearing buffer`);
      this.buffer = '';
      return;
    }
    
    // Process complete lines (messages terminated by \n)
    // Optimized: find all newlines first, then process in batch
    let newlineIndex: number;
    while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.substring(0, newlineIndex).trim();
      this.buffer = this.buffer.substring(newlineIndex + 1);
      
      if (line.length === 0) {
        continue; // Skip empty lines
      }
      
      // Additional safety: skip extremely long lines (potential DoS)
      if (line.length > StdioTransport.MAX_BUFFER_SIZE) {
        console.error(`[StdioTransport] Skipping extremely long line (${line.length} bytes)`);
        continue;
      }
      
      try {
        // Parse JSON-RPC message
        const message = JSON.parse(line) as JSONRPCRequest | JSONRPCResponse;
        
        if (this.debug) {
          console.error(`[StdioTransport] Received: ${line.substring(0, 100)}...`);
        }
        
        // Invoke callback if registered
        if (this.messageCallback) {
          this.messageCallback(message).catch((error) => {
            console.error('[StdioTransport] Error in message callback:', error);
          });
        }
      } catch (error) {
        // Invalid JSON - log and continue
        console.error('[StdioTransport] Failed to parse message:', error);
        console.error('[StdioTransport] Invalid line:', line.substring(0, 200));
      }
    }
  }
}

