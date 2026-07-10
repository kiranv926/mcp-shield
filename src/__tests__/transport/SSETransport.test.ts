/**
 * TaintGate: SSETransport Unit Tests
 * 
 * Tests for the SSETransport implementation.
 */

import { SSETransport } from '../../transport/SSETransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../../types/common';

// Mock EventSource
class MockEventSource {
  url: string;
  readyState: number = EventSource.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(url: string) {
    this.url = url;
  }

  close() {
    this.readyState = EventSource.CLOSED;
  }

  simulateOpen() {
    // Set readyState first
    this.readyState = EventSource.OPEN;
    // Then call onopen handler synchronously to set isReadyState
    // This ensures the handler runs before any checks
    if (this.onopen) {
      try {
        this.onopen(new Event('open'));
      } catch (error) {
        // Ignore errors in handler
      }
    }
  }

  simulateMessage(data: string) {
    if (this.onmessage) {
      const event = new MessageEvent('message', { data });
      this.onmessage(event);
    }
  }

  simulateError() {
    this.readyState = EventSource.CLOSED;
    if (this.onerror) {
      this.onerror(new Event('error'));
    }
  }
}

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
      reason: undefined,
      throwIfAborted: jest.fn(),
    } as unknown as AbortSignal;
  }
  
  abort() {
    (this.signal as any).aborted = true;
  }
}

// Mock EventSource globally
(global as any).EventSource = MockEventSource;
(global as any).fetch = mockFetch;
(global as any).AbortController = MockAbortController;

describe('SSETransport', () => {
  let transport: SSETransport;
  const baseUrl = 'https://mcp-server.example.com';

  /**
   * Helper to ensure transport is ready for testing
   */
  async function ensureTransportReady(t: SSETransport): Promise<void> {
    // Ensure eventSource exists
    if (!(t as any).eventSource) {
      (t as any).eventSource = new MockEventSource('test-url');
    }
    
    const es = (t as any).eventSource as MockEventSource;
    
    // Manually set the state to ready for testing
    // This bypasses the async EventSource setup
    (t as any).isReadyState = true;
    es.readyState = EventSource.OPEN;
    
    // Also call the handler if it exists to ensure consistency
    if (es.onopen) {
      try {
        es.onopen(new Event('open'));
      } catch (error) {
        // Ignore errors
      }
    }
    
    // Wait a bit to ensure state is set
    await new Promise(resolve => setTimeout(resolve, 10));
    
    // Verify it's ready - all three conditions must be true
    if (!t.isReady()) {
      // Force it one more time
      (t as any).isReadyState = true;
      if (es) {
        es.readyState = EventSource.OPEN;
      }
    }
    
    // Final verification
    if (!t.isReady()) {
      throw new Error(`Failed to set transport to ready state. isReadyState: ${(t as any).isReadyState}, eventSource: ${!!(t as any).eventSource}, readyState: ${es?.readyState}`);
    }
  }

  beforeEach(() => {
    mockFetch.mockClear();
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
    });

    transport = new SSETransport({
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
    });

    it('should connect to SSE stream', () => {
      // EventSource should be created with correct URL
      const eventSource = (transport as any).eventSource as MockEventSource;
      expect(eventSource).toBeDefined();
      expect(eventSource.url).toBe(`${baseUrl}/events`);
    });

    it('should throw error if EventSource is not available', () => {
      const originalEventSource = (global as any).EventSource;
      delete (global as any).EventSource;

      expect(() => {
        new SSETransport({ baseUrl });
      }).toThrow('EventSource is not available');

      (global as any).EventSource = originalEventSource;
    });

    it('should use custom fetch implementation', () => {
      const customFetch = jest.fn();
      const testTransport = new SSETransport({
        baseUrl,
        fetch: customFetch,
      });

      expect((testTransport as any).fetchImpl).toBe(customFetch);
      testTransport.close();
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

      // Simulate transport ready
      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

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

      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

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
      const testTransport = new SSETransport({
        baseUrl,
        headers: {
          'Authorization': 'Bearer token',
          'X-Custom-Header': 'value',
        },
      });

      const eventSource = (testTransport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

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

    it('should throw error if transport is not ready', async () => {
      await transport.close();

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await expect(transport.send(request)).rejects.toThrow('[SSETransport]');
      await expect(transport.send(request)).rejects.toThrow('not ready');
    });

    it('should handle HTTP errors', async () => {
      // Ensure transport is ready before testing
      await ensureTransportReady(transport);
      expect(transport.isReady()).toBe(true);

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

      // Error is wrapped: "[SSETransport] Failed to send message: [SSETransport] HTTP 500: ..."
      await expect(transport.send(request)).rejects.toThrow(/\[SSETransport\].*HTTP 500/);
    });

    it('should handle fetch errors', async () => {
      // Ensure transport is ready before testing
      await ensureTransportReady(transport);
      expect(transport.isReady()).toBe(true);

      // Use mockImplementation to apply to all calls
      mockFetch.mockImplementation(() => Promise.reject(new Error('Network error')));

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      // Error is wrapped: "[SSETransport] Failed to send message: Network error"
      await expect(transport.send(request)).rejects.toThrow(/\[SSETransport\].*Network error/);
    });

    it('should handle timeout', async () => {
      mockFetch.mockImplementationOnce(() => {
        return new Promise((_, reject) => {
          setTimeout(() => {
            reject(new Error('Timeout'));
          }, 100);
        });
      });

      const testTransport = new SSETransport({
        baseUrl,
        timeout: 50,
      });

      const eventSource = (testTransport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await expect(testTransport.send(request)).rejects.toThrow('[SSETransport]');
      await testTransport.close();
    });

    it('should enforce maximum pending requests limit', async () => {
      // Ensure transport is ready before testing
      await ensureTransportReady(transport);
      expect(transport.isReady()).toBe(true);

      // Fill up pending requests to the limit
      const pendingRequests = (transport as any).pendingRequests;
      const MAX_PENDING = 1000; // SSETransport.MAX_PENDING_REQUESTS
      
      // Mock the pendingRequests size to be at limit
      const originalSize = pendingRequests.size;
      Object.defineProperty(pendingRequests, 'size', {
        get: () => MAX_PENDING,
        configurable: true,
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      // Error is wrapped: "[SSETransport] Failed to send message: [SSETransport] Too many pending requests..."
      await expect(transport.send(request)).rejects.toThrow(/\[SSETransport\].*Too many pending requests/);

      // Restore original size
      Object.defineProperty(pendingRequests, 'size', {
        get: () => originalSize,
        configurable: true,
      });
    });
  });

  describe('onMessage', () => {
    it('should register message callback', () => {
      const callback = jest.fn();
      transport.onMessage(callback);
      expect(callback).toBeDefined();
    });

    it('should invoke callback when SSE message is received', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateMessage(JSON.stringify(message));

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(callback).toHaveBeenCalledWith(message);
    });

    it('should handle response correlation', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { success: true },
      };

      const eventSource = (transport as any).eventSource as MockEventSource;
      
      // Register pending request
      const pendingRequests = (transport as any).pendingRequests;
      const resolveSpy = jest.fn();
      pendingRequests.set(1, {
        resolve: resolveSpy,
        reject: jest.fn(),
        timeout: setTimeout(() => {}, 1000),
      });

      eventSource.simulateMessage(JSON.stringify(response));

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(resolveSpy).toHaveBeenCalledWith(response);
      expect(callback).not.toHaveBeenCalled(); // Should not invoke callback for correlated responses
    });

    it('should handle callback errors gracefully', async () => {
      const callback = jest.fn().mockRejectedValue(new Error('Callback error'));
      transport.onMessage(callback);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateMessage(JSON.stringify(message));

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(callback).toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });

    it('should handle invalid JSON gracefully', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateMessage('invalid json');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(callback).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  describe('close', () => {
    it('should close transport and mark as not ready', async () => {
      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

      expect(transport.isReady()).toBe(true);

      await transport.close();

      expect(transport.isReady()).toBe(false);
      expect(eventSource.readyState).toBe(EventSource.CLOSED);
    });

    it('should reject all pending requests', async () => {
      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

      const pendingRequests = (transport as any).pendingRequests;
      const rejectSpy1 = jest.fn();
      const rejectSpy2 = jest.fn();

      pendingRequests.set(1, {
        resolve: jest.fn(),
        reject: rejectSpy1,
        timeout: setTimeout(() => {}, 1000),
      });

      pendingRequests.set(2, {
        resolve: jest.fn(),
        reject: rejectSpy2,
        timeout: setTimeout(() => {}, 1000),
      });

      await transport.close();

      expect(rejectSpy1).toHaveBeenCalledWith(expect.any(Error));
      expect(rejectSpy2).toHaveBeenCalledWith(expect.any(Error));
      expect(rejectSpy1.mock.calls[0][0].message).toContain('[SSETransport]');
      expect(rejectSpy1.mock.calls[0][0].message).toContain('Transport closed');
      expect(pendingRequests.size).toBe(0);
    });
  });

  describe('isReady', () => {
    it('should return false when EventSource is not open', () => {
      expect(transport.isReady()).toBe(false);
    });

    it('should return true when EventSource is open', () => {
      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

      expect(transport.isReady()).toBe(true);
    });

    it('should return false after close', async () => {
      const eventSource = (transport as any).eventSource as MockEventSource;
      eventSource.simulateOpen();

      expect(transport.isReady()).toBe(true);

      await transport.close();

      expect(transport.isReady()).toBe(false);
    });
  });

  describe('connection lifecycle', () => {
    it('should handle connection open event', () => {
      const eventSource = (transport as any).eventSource as MockEventSource;
      const isReadyState = (transport as any).isReadyState;

      expect(isReadyState).toBe(false);

      eventSource.simulateOpen();

      expect(transport.isReady()).toBe(true);
    });

    it('should handle connection error event', async () => {
      const eventSource = (transport as any).eventSource as MockEventSource;

      eventSource.simulateOpen();
      
      // Wait a bit for the ready state to update
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(transport.isReady()).toBe(true);

      eventSource.simulateError();

      // Wait a bit for event processing
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(transport.isReady()).toBe(false);
    });
  });
});

