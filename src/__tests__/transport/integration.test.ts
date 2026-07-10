/**
 * TaintGate: Transport Integration Tests
 * 
 * Integration tests for transports with TaintGate.
 */

import { TaintGate } from '../../mediator/TaintGate';
import { StdioTransport } from '../../transport/StdioTransport';
import { HTTPTransport } from '../../transport/HTTPTransport';
import { createTransport } from '../../transport/index';
import { PolicyManager } from '../../core/PolicyManager';
import { RiskEvaluator } from '../../core/RiskEvaluator';
import { TaintRegistry } from '../../core/TaintRegistry';
import { RateLimiter } from '../../core/RateLimiter';
import { ResponseRedactor } from '../../core/ResponseRedactor';
import { AuditLogger } from '../../core/audit/AuditLogger';
import type { JSONRPCRequest } from '../../types/common';
import { Readable, Writable } from 'stream';

// Mock fetch for HTTPTransport
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

(global as any).fetch = mockFetch;
(global as any).AbortController = MockAbortController;

describe('Transport Integration', () => {
  describe('StdioTransport with TaintGate', () => {
    let inputStream: Readable;
    let outputStream: Writable;
    let clientTransport: StdioTransport;
    let serverTransport: StdioTransport;
    let mediator: TaintGate | undefined;

    beforeEach(async () => {
      // Create mock streams
      inputStream = new Readable({
        read() {},
      });
      
      outputStream = new Writable({
        write(chunk, encoding, callback) {
          callback();
        },
      });

      clientTransport = new StdioTransport({
        inputStream,
        outputStream,
      });

      serverTransport = new StdioTransport({
        inputStream: new Readable({ read() {} }),
        outputStream: new Writable({ write() {} }),
      });

      // Create governance components
      const policyManager = new PolicyManager();
      const taintRegistry = new TaintRegistry();
      const riskEvaluator = new RiskEvaluator({
        policyManager,
        taintRegistry,
      });
      const rateLimiter = new RateLimiter();
      const responseRedactor = new ResponseRedactor();
      const auditLogger = new AuditLogger({
        logDirectory: './test-logs',
      });

      mediator = new TaintGate({
        clientTransport,
        serverTransport,
        policyManager,
        riskEvaluator,
        taintRegistry,
        rateLimiter,
        responseRedactor,
        auditLogger,
      });

      await mediator.start();
    });

    afterEach(async () => {
      if (mediator) {
        // TaintGate doesn't have a stop() method, just close transports
        await clientTransport.close();
        await serverTransport.close();
      }
    });

    it('should intercept requests through stdio transport', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'test_tool',
          arguments: {},
        },
      };

      const context = {
        tenantId: 'tenant-1',
        sessionId: 'session-1',
        toolName: 'test_tool',
        timestamp: new Date(),
      };

      // Mock server response
      const serverResponse = {
        jsonrpc: '2.0' as const,
        id: 1,
        result: { success: true },
      };

      // Simulate server response
      const serverInputStream = (serverTransport as any).inputStream as Readable;
      serverInputStream.push(JSON.stringify(serverResponse) + '\n');

      if (!mediator) {
        throw new Error('Mediator not initialized');
      }
      const decision = await mediator.intercept(request, context);

      expect(decision).toBeDefined();
      expect(decision.jsonrpc).toBe('2.0');
    });

    it('should handle multiple concurrent requests', async () => {
      const requests: JSONRPCRequest[] = [
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'tool1', arguments: {} },
        },
        {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'tool2', arguments: {} },
        },
      ];

      const context = {
        tenantId: 'tenant-1',
        sessionId: 'session-1',
        toolName: 'test_tool',
        timestamp: new Date(),
      };

      if (!mediator) {
        throw new Error('Mediator not initialized');
      }
      const initializedMediator = mediator;
      const decisions = await Promise.all(
        requests.map(req => initializedMediator.intercept(req, context))
      );

      expect(decisions).toHaveLength(2);
      decisions.forEach(decision => {
        expect(decision).toBeDefined();
        expect(decision.jsonrpc).toBe('2.0');
      });
    });
  });

  describe('HTTPTransport with TaintGate', () => {
    let clientTransport: HTTPTransport;
    let serverTransport: HTTPTransport;
    let mediator: TaintGate | undefined;

    beforeEach(async () => {
      mockFetch.mockClear();
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          jsonrpc: '2.0',
          id: 1,
          result: { success: true },
        }),
      });

      clientTransport = new HTTPTransport({
        baseUrl: 'https://mcp-server.example.com',
        fetch: mockFetch as typeof fetch,
      });

      serverTransport = new HTTPTransport({
        baseUrl: 'https://mcp-server.example.com',
        fetch: mockFetch as typeof fetch,
      });

      // Create governance components
      const policyManager = new PolicyManager();
      const taintRegistry = new TaintRegistry();
      const riskEvaluator = new RiskEvaluator({
        policyManager,
        taintRegistry,
      });
      const rateLimiter = new RateLimiter();
      const responseRedactor = new ResponseRedactor();
      const auditLogger = new AuditLogger({
        logDirectory: './test-logs',
      });

      mediator = new TaintGate({
        clientTransport,
        serverTransport,
        policyManager,
        riskEvaluator,
        taintRegistry,
        rateLimiter,
        responseRedactor,
        auditLogger,
      });

      await mediator.start();
    });

    afterEach(async () => {
      if (mediator) {
        // TaintGate doesn't have a stop() method, just close transports
        await clientTransport.close();
        await serverTransport.close();
      }
    });

    it('should intercept requests through HTTP transport', async () => {
      // Ensure mock is set up for this specific test
      mockFetch.mockClear();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({
          jsonrpc: '2.0',
          id: 1,
          result: { success: true },
        }),
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'test_tool',
          arguments: {},
        },
      };

      const context = {
        tenantId: 'tenant-1',
        sessionId: 'session-1',
        toolName: 'test_tool',
        timestamp: new Date(),
      };

      if (!mediator) {
        throw new Error('Mediator not initialized');
      }
      const decision = await mediator.intercept(request, context);

      expect(decision).toBeDefined();
      expect(decision.jsonrpc).toBe('2.0');
      
      // If the request was ALLOWED, it should have been forwarded to the server
      // Check if decision has a result (ALLOW) or error (BLOCK)
      if ('result' in decision) {
        // Request was allowed and forwarded
        expect(mockFetch).toHaveBeenCalled();
      } else if ('error' in decision) {
        // Request was blocked - fetch should not be called
        expect(mockFetch).not.toHaveBeenCalled();
        expect(decision.error).toBeDefined();
      }
    });

    it('should handle HTTP errors gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'test_tool',
          arguments: {},
        },
      };

      const context = {
        tenantId: 'tenant-1',
        sessionId: 'session-1',
        toolName: 'test_tool',
        timestamp: new Date(),
      };

      // Should handle error and return appropriate response
      if (!mediator) {
        throw new Error('Mediator not initialized');
      }
      const decision = await mediator.intercept(request, context);

      expect(decision).toBeDefined();
      // Error should be handled by mediator
    });
  });

  describe('Transport Factory', () => {
    it('should create StdioTransport from factory', () => {
      const transport = createTransport({
        type: 'stdio',
        options: {
          debug: true,
        },
      });

      expect(transport).toBeDefined();
      expect(transport).toBeInstanceOf(StdioTransport);
      expect(transport.isReady()).toBe(true);
    });

    it('should create HTTPTransport from factory', () => {
      const transport = createTransport({
        type: 'http',
        options: {
          baseUrl: 'https://example.com',
        },
      });

      expect(transport).toBeDefined();
      expect(transport).toBeInstanceOf(HTTPTransport);
      expect(transport.isReady()).toBe(true);
    });

    it('should throw error for invalid transport type', () => {
      expect(() => {
        createTransport({
          type: 'invalid' as any,
          options: {},
        });
      }).toThrow('Unknown transport type');
    });

    it('should throw error for missing baseUrl in HTTP transport', () => {
      expect(() => {
        createTransport({
          type: 'http',
          options: {},
        });
      }).toThrow('baseUrl');
    });
  });
});

