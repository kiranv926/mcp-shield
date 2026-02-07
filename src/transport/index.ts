/**
 * MCP-Shield: Transport Module
 * 
 * Transport implementations for MCP communication.
 */

import type { ITransport, TransportConfig } from '../interfaces/ITransport';
import { StdioTransport } from './StdioTransport';
import { SSETransport } from './SSETransport';
import { HTTPTransport } from './HTTPTransport';

export { StdioTransport } from './StdioTransport';
export type { StdioTransportConfig } from './StdioTransport';

export { SSETransport } from './SSETransport';
export type { SSETransportConfig } from './SSETransport';

export { HTTPTransport } from './HTTPTransport';
export type { HTTPTransportConfig } from './HTTPTransport';

export type { ITransport, TransportConfig } from '../interfaces/ITransport';

/**
 * Transport Factory
 * 
 * Creates transport instances based on configuration.
 */
export function createTransport(config: TransportConfig): ITransport {
  switch (config.type) {
    case 'stdio':
      return new StdioTransport(config.options as any);
    
    case 'sse':
      if (!config.options || typeof config.options.baseUrl !== 'string') {
        throw new Error('SSETransport requires baseUrl in options');
      }
      return new SSETransport(config.options as any);
    
    case 'http':
      if (!config.options || typeof config.options.baseUrl !== 'string') {
        throw new Error('HTTPTransport requires baseUrl in options');
      }
      return new HTTPTransport(config.options as any);
    
    default:
      throw new Error(`Unknown transport type: ${config.type}`);
  }
}

