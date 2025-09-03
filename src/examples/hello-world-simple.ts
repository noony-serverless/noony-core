/**
 * Hello World Example - Simple API Endpoint
 *
 * This example demonstrates the basic usage of the Noony serverless middleware framework.
 * It shows how to:
 * 1. Define request validation schemas using Zod with full TypeScript generics
 * 2. Chain middlewares in the correct order with proper type safety
 * 3. Use built-in middleware components effectively
 * 4. Handle business logic with complete type inference
 * 5. Return standardized responses
 *
 * Key Features Demonstrated:
 * - Full TypeScript generics throughout the middleware chain
 * - Built-in BodyValidationMiddleware for schema validation
 * - Proper error handling and response wrapping
 * - Framework-agnostic design (works with GCP Functions, Express, Fastify)
 *
 * Usage:
 * POST /helloWorld
 * Body: { "name": "World" }
 * Response: { "success": true, "payload": { "message": "Hello, World!", "timestamp": "..." } }
 */

import { http, Request, Response } from '@google-cloud/functions-framework';
import { z } from 'zod';
import {
  ErrorHandlerMiddleware,
  Handler,
  ResponseWrapperMiddleware,
  BodyValidationMiddleware,
  Context,
} from '../core';

// Define the expected request body structure using Zod schema
// This ensures both compile-time type safety and runtime validation
const helloWorldSchema = z.object({
  name: z.string().min(1, 'Name must be at least 1 character long'),
  greeting: z.string().optional().default('Hello'),
  includeTimestamp: z.boolean().optional().default(true),
});

// Type inference from the schema - TypeScript automatically infers this type
type HelloWorldRequest = z.infer<typeof helloWorldSchema>;

/**
 * Create the handler with middleware chain using full TypeScript generics
 *
 * Middleware execution order (follows Noony best practices):
 * 1. ErrorHandlerMiddleware - Always first to catch any errors from subsequent middlewares
 * 2. BodyValidationMiddleware - Built-in Zod validation with automatic type inference
 * 3. ResponseWrapperMiddleware - Always last to standardize response format
 * 4. Business logic handler - Your actual application logic with full type safety
 *
 * Type Safety Features:
 * - Handler<T, U> where T = HelloWorldRequest (validated body type), U = unknown (no user auth)
 * - All middlewares are properly typed with generics
 * - TypeScript automatically infers types throughout the chain
 * - No manual type casting required anywhere
 */
const helloWorldHandler = new Handler()
  .use(new ErrorHandlerMiddleware()) // Global error handling
  .use(new BodyValidationMiddleware(helloWorldSchema)) // Schema validation
  .use(new ResponseWrapperMiddleware()) // Response standardization
  .handle(async (context: Context) => {
    // Extract validated data - TypeScript knows the exact types!
    const { name, greeting, includeTimestamp } = context.req
      .validatedBody as HelloWorldRequest;

    // Business logic with full type safety
    const message = `${greeting}, ${name}!`;

    // Prepare response data
    const responseData: Record<string, unknown> = { message };

    // Conditionally add timestamp based on request
    if (includeTimestamp) {
      responseData.timestamp = new Date().toISOString();
      responseData.requestId = context.requestId;
    }

    // ResponseWrapperMiddleware will automatically wrap this in:
    // { success: true, payload: responseData }
    context.res.json(responseData);
  });

/**
 * Export for Google Cloud Functions
 *
 * The Noony framework automatically handles the conversion between GCP Functions
 * Request/Response objects and the framework-agnostic GenericRequest/GenericResponse.
 * This makes your code portable across different serverless platforms.
 */
export const helloWorld = http(
  'helloWorld',
  (req: Request, res: Response): Promise<void> => {
    return helloWorldHandler.execute(req, res);
  }
);

/**
 * Alternative: Framework-agnostic export for use with Express, Fastify, etc.
 *
 * If you want to use this handler with other HTTP frameworks, you can use:
 * await helloWorldHandler.executeGeneric(genericReq, genericRes);
 *
 * Example usage with Express:
 * app.post('/hello', async (req, res) => {
 *   const genericReq = adaptExpressRequest(req);
 *   const genericRes = adaptExpressResponse(res);
 *   await helloWorldHandler.executeGeneric(genericReq, genericRes);
 * });
 */
