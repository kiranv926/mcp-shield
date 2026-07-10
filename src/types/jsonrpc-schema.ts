/**
 * TaintGate: JSON-RPC Schema Definitions
 * 
 * Zod schemas for validating JSON-RPC 2.0 requests and responses.
 * 
 * These schemas ensure that malformed requests are caught at the boundary
 * before they can crash the RiskEvaluator or other components.
 */

import { z } from 'zod';

/**
 * JSON-RPC 2.0 Request Schema
 * 
 * Validates the structure of incoming JSON-RPC requests.
 */
export const JSONRPCRequestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]),
  method: z.string().min(1),
  params: z.union([
    z.record(z.unknown()),
    z.array(z.unknown()),
  ]).optional(),
});

/**
 * JSON-RPC 2.0 Response Schema
 * 
 * Validates the structure of JSON-RPC responses.
 */
export const JSONRPCResponseSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]),
  result: z.unknown().optional(),
  error: z.object({
    code: z.number(),
    message: z.string(),
    data: z.unknown().optional(),
  }).optional(),
}).refine(
  (data) => data.result !== undefined || data.error !== undefined,
  {
    message: 'Response must have either result or error',
  }
);

/**
 * JSON-RPC 2.0 Error Schema
 */
export const JSONRPCErrorSchema = z.object({
  code: z.number(),
  message: z.string(),
  data: z.unknown().optional(),
});

/**
 * Type inference from schemas
 */
export type JSONRPCRequestInput = z.input<typeof JSONRPCRequestSchema>;
export type JSONRPCResponseInput = z.input<typeof JSONRPCResponseSchema>;
export type JSONRPCErrorInput = z.input<typeof JSONRPCErrorSchema>;

