/**
 * MCP-Shield: Transport Performance Benchmarks
 * 
 * Performance tests for transport implementations.
 * 
 * Note: These tests measure performance and may take longer to run.
 * They are useful for identifying performance regressions.
 */

import { StdioTransport } from '../../transport/StdioTransport';
import { HTTPTransport } from '../../transport/HTTPTransport';
import type { JSONRPCRequest } from '../../types/common';
import { Readable, Writable } from 'stream';

// Mock fetch for HTTPTransport
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

describe('Transport Performance', () => {
  describe('StdioTransport Performance', () => {
    let transport: StdioTransport;
    let inputStream: Readable;
    let outputStream: Writable;

    beforeEach(() => {
      inputStream = new Readable({
        read() {},
      });
      
      outputStream = new Writable({
        write(chunk, encoding, callback) {
          callback();
        },
      });

      transport = new StdioTransport({
        inputStream,
        outputStream,
      });
    });

    afterEach(async () => {
      await transport.close();
    });

    it('should send messages quickly (100 messages)', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
        params: { data: 'test' },
      };

      const startTime = Date.now();
      
      for (let i = 0; i < 100; i++) {
        await transport.send({ ...request, id: i });
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      const avgTime = duration / 100;

      console.log(`[StdioTransport] 100 messages in ${duration}ms (avg: ${avgTime.toFixed(2)}ms/msg)`);

      // Should complete in reasonable time (< 1 second for 100 messages)
      expect(duration).toBeLessThan(1000);
      // Average should be < 10ms per message
      expect(avgTime).toBeLessThan(10);
    });

    it('should process received messages quickly (100 messages)', async () => {
      const messages: JSONRPCRequest[] = [];
      for (let i = 0; i < 100; i++) {
        messages.push({
          jsonrpc: '2.0',
          id: i,
          method: 'test',
          params: { data: `test-${i}` },
        });
      }

      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const startTime = Date.now();

      // Push all messages
      for (const message of messages) {
        inputStream.push(JSON.stringify(message) + '\n');
      }

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 100));

      const endTime = Date.now();
      const duration = endTime - startTime;
      const avgTime = duration / 100;

      console.log(`[StdioTransport] Processed 100 messages in ${duration}ms (avg: ${avgTime.toFixed(2)}ms/msg)`);

      expect(callback).toHaveBeenCalledTimes(100);
      // Should process quickly
      expect(duration).toBeLessThan(200);
    });

    it('should handle large messages efficiently', async () => {
      const largeData = 'x'.repeat(10000); // 10KB
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
        params: { data: largeData },
      };

      const startTime = Date.now();
      
      await transport.send(request);

      const endTime = Date.now();
      const duration = endTime - startTime;

      console.log(`[StdioTransport] Large message (10KB) sent in ${duration}ms`);

      // Should handle large messages in reasonable time
      expect(duration).toBeLessThan(100);
    });
  });

  describe('HTTPTransport Performance', () => {
    let transport: HTTPTransport;

    beforeEach(() => {
      mockFetch.mockClear();
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ jsonrpc: '2.0', id: 1, result: {} }),
      });

      transport = new HTTPTransport({
        baseUrl: 'https://example.com',
      });
    });

    afterEach(async () => {
      await transport.close();
    });

    it('should send messages quickly (100 messages)', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
        params: { data: 'test' },
      };

      const startTime = Date.now();
      
      const promises = [];
      for (let i = 0; i < 100; i++) {
        promises.push(transport.send({ ...request, id: i }));
      }
      await Promise.all(promises);

      const endTime = Date.now();
      const duration = endTime - startTime;
      const avgTime = duration / 100;

      console.log(`[HTTPTransport] 100 messages in ${duration}ms (avg: ${avgTime.toFixed(2)}ms/msg)`);

      // Should complete in reasonable time
      expect(duration).toBeLessThan(2000);
      // Average should be reasonable (< 20ms per message for mocked fetch)
      expect(avgTime).toBeLessThan(20);
    });

    it('should handle concurrent requests efficiently', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
        params: { data: 'test' },
      };

      const startTime = Date.now();
      
      const promises = [];
      for (let i = 0; i < 50; i++) {
        promises.push(transport.send({ ...request, id: i }));
      }
      await Promise.all(promises);

      const endTime = Date.now();
      const duration = endTime - startTime;

      console.log(`[HTTPTransport] 50 concurrent messages in ${duration}ms`);

      // Concurrent requests should be efficient
      expect(duration).toBeLessThan(1000);
    });
  });

  describe('Memory Usage', () => {
    it('should not leak memory with many messages (StdioTransport)', async () => {
      const inputStream = new Readable({ read() {} });
      const outputStream = new Writable({ write(chunk, encoding, callback) { callback(); } });
      
      const transport = new StdioTransport({
        inputStream,
        outputStream,
      });

      const initialMemory = process.memoryUsage().heapUsed;

      // Send many messages
      for (let i = 0; i < 1000; i++) {
        await transport.send({
          jsonrpc: '2.0',
          id: i,
          method: 'test',
        });
      }

      // Force GC if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      console.log(`[StdioTransport] Memory increase after 1000 messages: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);

      await transport.close();

      // Memory increase should be reasonable (< 10MB for 1000 messages)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });
});

