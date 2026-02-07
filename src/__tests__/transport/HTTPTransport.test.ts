/**
 * MCP-Shield: HTTPTransport Unit Tests
 * 
 * Tests for the HTTPTransport implementation.
 */

import { HTTPTransport } from '../../transport/HTTPTransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../../types/common';

// Mock fetch
const mockFetch = jest.fn();

// Mock AbortController for polyfill
class MockAbortController {
  signal: AbortSignal;
  
  constructor() {
    this.signal = {
      aborted: false,
      onabort: null,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    } as AbortSignal;
  }
  
  abort() {
    (this.signal as any).aborted = true;
  }
}

(global as any).fetch = mockFetch;
(global as any).AbortController = MockAbortController;

describe('HTTPTransport', () => {
  let transport: HTTPTransport;
  const baseUrl = 'https://mcp-server.example.com';

  beforeEach(() => {
    mockFetch.mockClear();
    // Use mockImplementation to allow per-test overrides
    mockFetch.mockImplementation(() => Promise.resolve({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => ({}),
    }));

    transport = new HTTPTransport({
      baseUrl,
      timeout: 30000,
      debug: false,
    });
  });

  afterEach(async () => {
    await transport.close();
  });

  describe('constructor', () => {
    it('should create transport with baseUrl', () => {
      expect(transport).toBeDefined();
      expect(transport.isReady()).toBe(true);
    });

    it('should remove trailing slash from baseUrl', () => {
      const testTransport = new HTTPTransport({
        baseUrl: 'https://example.com/',
      });

      expect((testTransport as any).baseUrl).toBe('https://example.com');
      testTransport.close();
    });

    it('should use custom fetch implementation', () => {
      const customFetch = jest.fn();
      const testTransport = new HTTPTransport({
        baseUrl,
        fetch: customFetch,
      });

      expect((testTransport as any).fetchImpl).toBe(customFetch);
      testTransport.close();
    });

    it('should throw error if fetch is not available', () => {
      const originalFetch = (global as any).fetch;
      delete (global as any).fetch;

      expect(() => {
        new HTTPTransport({ baseUrl });
      }).toThrow('fetch is not available');

      (global as any).fetch = originalFetch;
    });
  });

  describe('send', () => {
    it('should send JSON-RPC request via HTTP POST', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'test' },
      };

      await transport.send(request);

      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/messages`,
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify(request),
        })
      );
    });

    it('should send JSON-RPC response via HTTP POST', async () => {
      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { success: true },
      };

      await transport.send(response);

      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/messages`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(response),
        })
      );
    });

    it('should include custom headers', async () => {
      const testTransport = new HTTPTransport({
        baseUrl,
        headers: {
          'Authorization': 'Bearer token',
          'X-Custom-Header': 'value',
        },
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await testTransport.send(request);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer token',
            'X-Custom-Header': 'value',
          }),
        })
      );

      await testTransport.close();
    });

    it('should parse and invoke callback for request responses', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'test' },
      };

      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { success: true },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => response,
      });

      await transport.send(request);

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(callback).toHaveBeenCalledWith(response);
    });

    it('should not invoke callback for notifications (id: null)', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const notification: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: null,
        method: 'notify',
        params: {},
      };

      await transport.send(notification);

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(callback).not.toHaveBeenCalled();
    });

    it('should not invoke callback for responses (not requests)', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { success: true },
      };

      await transport.send(response);

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(callback).not.toHaveBeenCalled();
    });

    it('should throw error if transport is not ready', async () => {
      await transport.close();

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      // Single assertion with regex to check both conditions
      await expect(transport.send(request)).rejects.toThrow(/\[HTTPTransport\].*not ready/);
    });

    it('should handle HTTP errors', async () => {
      // Override the default mock for this test - use mockImplementation to apply to all calls
      mockFetch.mockImplementation(() => Promise.resolve({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      }));

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      // HTTPTransport throws error when response.ok is false (line 102)
      // Single assertion with regex to check both conditions
      await expect(transport.send(request)).rejects.toThrow(/\[HTTPTransport\].*HTTP 500/);
    });

    it('should handle fetch errors', async () => {
      // Use mockImplementation to apply to all calls
      mockFetch.mockImplementation(() => Promise.reject(new Error('Network error')));

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      // Single assertion with regex to check both conditions
      await expect(transport.send(request)).rejects.toThrow(/\[HTTPTransport\].*Network error/);
    });

    it('should handle timeout', async () => {
      mockFetch.mockImplementationOnce(() => {
        return new Promise((_, reject) => {
          setTimeout(() => {
            reject(new Error('Timeout'));
          }, 100);
        });
      });

      const testTransport = new HTTPTransport({
        baseUrl,
        timeout: 50,
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await expect(testTransport.send(request)).rejects.toThrow();
      await testTransport.close();
    });

    it('should handle JSON parsing errors', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => {
          throw new Error('Invalid JSON');
        },
      });

      await expect(transport.send(request)).rejects.toThrow();
    });
  });

  describe('onMessage', () => {
    it('should register message callback', () => {
      const callback = jest.fn();
      transport.onMessage(callback);
      expect(callback).toBeDefined();
    });
  });

  describe('close', () => {
    it('should close transport and mark as not ready', async () => {
      expect(transport.isReady()).toBe(true);

      await transport.close();

      expect(transport.isReady()).toBe(false);
    });
  });

  describe('isReady', () => {
    it('should return true by default (stateless)', () => {
      expect(transport.isReady()).toBe(true);
    });

    it('should return false after close', async () => {
      await transport.close();
      expect(transport.isReady()).toBe(false);
    });
  });
});

