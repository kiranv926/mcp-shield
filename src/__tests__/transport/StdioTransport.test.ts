/**
 * TaintGate: StdioTransport Unit Tests
 * 
 * Tests for the StdioTransport implementation.
 */

import { StdioTransport } from '../../transport/StdioTransport';
import type { JSONRPCRequest, JSONRPCResponse } from '../../types/common';
import { Readable, Writable } from 'stream';

describe('StdioTransport', () => {
  let inputStream: Readable;
  let outputStream: Writable;
  let transport: StdioTransport;

  beforeEach(() => {
    // Create mock streams
    inputStream = new Readable({
      read() {
        // No-op: we'll push data manually
      },
    });
    
    outputStream = new Writable({
      write(chunk, encoding, callback) {
        callback();
      },
    });

    transport = new StdioTransport({
      inputStream,
      outputStream,
      debug: false,
    });
  });

  afterEach(async () => {
    await transport.close();
  });

  describe('constructor', () => {
    it('should create transport with default streams', async () => {
      const defaultTransport = new StdioTransport();
      expect(defaultTransport).toBeDefined();
      expect(defaultTransport.isReady()).toBe(true);
      await defaultTransport.close();
    });

    it('should create transport with custom streams', () => {
      expect(transport).toBeDefined();
      expect(transport.isReady()).toBe(true);
    });

    it('should set encoding on input stream', () => {
      const mockStream = new Readable({ read() {} });
      const setEncodingSpy = jest.spyOn(mockStream, 'setEncoding');
      
      new StdioTransport({
        inputStream: mockStream,
        outputStream: new Writable({ write() {} }),
      });
      
      expect(setEncodingSpy).toHaveBeenCalledWith('utf8');
    });
  });

  describe('send', () => {
    it('should send JSON-RPC request', async () => {
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'test' },
      };

      const writeSpy = jest.spyOn(outputStream, 'write');
      
      await transport.send(request);

      expect(writeSpy).toHaveBeenCalled();
      const writtenData = writeSpy.mock.calls[0][0] as Buffer;
      const writtenString = writtenData.toString('utf8');
      expect(writtenString).toContain('"jsonrpc":"2.0"');
      expect(writtenString).toContain('"method":"tools/call"');
      expect(writtenString.endsWith('\n')).toBe(true);
    });

    it('should send JSON-RPC response', async () => {
      const response: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: 1,
        result: { success: true },
      };

      const writeSpy = jest.spyOn(outputStream, 'write');
      
      await transport.send(response);

      expect(writeSpy).toHaveBeenCalled();
      const writtenData = writeSpy.mock.calls[0][0] as Buffer;
      const writtenString = writtenData.toString('utf8');
      expect(writtenString).toContain('"jsonrpc":"2.0"');
      expect(writtenString).toContain('"result"');
    });

    it('should handle write buffer full', async () => {
      let drainCallback: (() => void) | undefined;
      const mockStream = new Writable({
        write(chunk, encoding, callback) {
          // Simulate buffer full
          drainCallback = callback;
          return false; // Indicates buffer is full
        },
      });

      mockStream.on = jest.fn().mockImplementation((event, handler) => {
        if (event === 'drain') {
          // Store drain handler
          setTimeout(() => {
            if (drainCallback) {
              drainCallback();
            }
            if (handler) {
              handler();
            }
          }, 10);
        }
        return mockStream;
      });

      const testTransport = new StdioTransport({
        inputStream: new Readable({ read() {} }),
        outputStream: mockStream,
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await expect(testTransport.send(request)).resolves.not.toThrow();
      await testTransport.close();
    });

    it('should throw error if transport is not ready', async () => {
      await transport.close();
      
      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await expect(transport.send(request)).rejects.toThrow('[StdioTransport]');
      await expect(transport.send(request)).rejects.toThrow('not ready');
    });

    it('should handle write errors', async () => {
      const errorStream = new Writable({
        write(chunk, encoding, callback) {
          callback(new Error('Write failed'));
        },
      });

      const testTransport = new StdioTransport({
        inputStream: new Readable({ read() {} }),
        outputStream: errorStream,
      });

      const request: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      await expect(testTransport.send(request)).rejects.toThrow();
      await testTransport.close();
    });
  });

  describe('onMessage', () => {
    it('should register message callback', () => {
      const callback = jest.fn();
      transport.onMessage(callback);
      expect(callback).toBeDefined();
    });

    it('should invoke callback when message is received', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      // Push message to input stream
      inputStream.push(JSON.stringify(message) + '\n');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(callback).toHaveBeenCalledWith(message);
    });

    it('should handle multiple messages', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const message1: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test1',
      };

      const message2: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 2,
        method: 'test2',
      };

      // Push messages
      inputStream.push(JSON.stringify(message1) + '\n');
      inputStream.push(JSON.stringify(message2) + '\n');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(callback).toHaveBeenCalledTimes(2);
      expect(callback).toHaveBeenNthCalledWith(1, message1);
      expect(callback).toHaveBeenNthCalledWith(2, message2);
    });

    it('should handle partial messages (buffering)', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 1,
        method: 'test',
      };

      const messageStr = JSON.stringify(message);
      // Push partial message
      inputStream.push(messageStr.substring(0, 10));
      
      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Push rest of message
      inputStream.push(messageStr.substring(10) + '\n');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(callback).toHaveBeenCalledWith(message);
    });

    it('should skip empty lines', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      // Push empty line
      inputStream.push('\n\n');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(callback).not.toHaveBeenCalled();
    });

    it('should handle invalid JSON gracefully', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      // Push invalid JSON
      inputStream.push('invalid json\n');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(callback).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });

    it('should handle buffer overflow protection', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      // Push data without newlines to fill buffer (1MB+)
      const largeChunk = 'x'.repeat(1024 * 1024); // 1MB
      inputStream.push(largeChunk);
      inputStream.push(largeChunk); // Another 1MB to exceed limit

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      // Buffer should be cleared on overflow
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Buffer overflow')
      );

      consoleErrorSpy.mockRestore();
    });

    it('should skip extremely long lines', async () => {
      const callback = jest.fn().mockResolvedValue(undefined);
      transport.onMessage(callback);

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      // Push extremely long line (> 1MB)
      const longLine = 'x'.repeat(1024 * 1024 + 1) + '\n';
      inputStream.push(longLine);

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      // Should skip the line
      expect(callback).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
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

      inputStream.push(JSON.stringify(message) + '\n');

      // Wait for async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(callback).toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });

  describe('close', () => {
    it('should close transport and mark as not ready', async () => {
      expect(transport.isReady()).toBe(true);
      
      await transport.close();
      
      expect(transport.isReady()).toBe(false);
    });

    it('should remove event listeners', async () => {
      const removeAllListenersSpy = jest.spyOn(inputStream, 'removeAllListeners');
      
      await transport.close();
      
      expect(removeAllListenersSpy).toHaveBeenCalledWith('data');
      expect(removeAllListenersSpy).toHaveBeenCalledWith('end');
      expect(removeAllListenersSpy).toHaveBeenCalledWith('error');
    });

    it('should handle stream end event', async () => {
      const testTransport = new StdioTransport({
        inputStream,
        outputStream,
      });

      expect(testTransport.isReady()).toBe(true);
      
      // Simulate stream end
      inputStream.emit('end');
      
      // Wait a bit for event processing
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(testTransport.isReady()).toBe(false);
      
      await testTransport.close();
    });

    it('should handle stream error event', async () => {
      const testTransport = new StdioTransport({
        inputStream,
        outputStream,
      });

      expect(testTransport.isReady()).toBe(true);
      
      // Simulate stream error
      inputStream.emit('error', new Error('Stream error'));
      
      // Wait a bit for event processing
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(testTransport.isReady()).toBe(false);
      
      await testTransport.close();
    });
  });

  describe('isReady', () => {
    it('should return true when streams are ready', () => {
      expect(transport.isReady()).toBe(true);
    });

    it('should return false after close', async () => {
      await transport.close();
      expect(transport.isReady()).toBe(false);
    });

    it('should return false when input stream is not readable', () => {
      const nonReadableStream = new Readable({ read() {} });
      nonReadableStream.readable = false;

      const testTransport = new StdioTransport({
        inputStream: nonReadableStream,
        outputStream: new Writable({ write() {} }),
      });

      expect(testTransport.isReady()).toBe(false);
      
      testTransport.close();
    });

    it('should return false when output stream is not writable', () => {
      const nonWritableStream = new Writable({ write() {} });
      nonWritableStream.writable = false;

      const testTransport = new StdioTransport({
        inputStream: new Readable({ read() {} }),
        outputStream: nonWritableStream,
      });

      expect(testTransport.isReady()).toBe(false);
      
      testTransport.close();
    });
  });
});

