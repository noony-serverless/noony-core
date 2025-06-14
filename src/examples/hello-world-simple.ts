/**
 * Hello World Example - Simple API Endpoint
 *
 * This example demonstrates the basic usage of the Noony serverless middleware framework.
 * It shows how to:
 * 1. Define request validation schemas using Zod
 * 2. Chain middlewares in the correct order
 * 3. Handle business logic in the main handler
 * 4. Return standardized responses
 *
 * Usage:
 * POST /helloWorld
 * Body: { "name": "World" }
 * Response: { "success": true, "payload": { "message": "Hello, World!" } }
 */

import { http, Request, Response } from '@google-cloud/functions-framework';
import { z } from 'zod';
import {
  ErrorHandlerMiddleware,
  Handler,
  ResponseWrapperMiddleware,
  BaseMiddleware,
  Context,
} from '../core';
import { ValidationError } from '../core/errors';

// Define the expected request body structure using Zod schema
// This ensures type safety and runtime validation
const requestSchema = z.object({
  name: z.string().min(1, 'Name must be at least 1 character long'),
});

// Type inference from the schema for better TypeScript support
type HelloWorldRequest = z.infer<typeof requestSchema>;

/**
 * Properly typed body validation middleware
 * This creates a middleware that works with the Handler's generic types
 */
class TypedBodyValidationMiddleware<T> implements BaseMiddleware<T, unknown> {
  constructor(private readonly schema: z.ZodSchema<T>) {}

  async before(context: Context<T, unknown>): Promise<void> {
    try {
      const parsedBody = context.req.parsedBody || context.req.body;
      context.req.validatedBody = await this.schema.parseAsync(parsedBody);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError('Validation error', error.errors);
      }
      throw error;
    }
  }
}

/**
 * Create the handler with middleware chain using proper generics
 *
 * Middleware execution order:
 * 1. ErrorHandlerMiddleware - Should always be first to catch any errors
 * 2. TypedBodyValidationMiddleware - Validates and parses the request body with proper typing
 * 3. ResponseWrapperMiddleware - Standardizes the response format
 * 4. Business logic handler - Your actual application logic
 *
 * Type Safety Approach:
 * We use the Handler's generic type parameters <T, U> where:
 * - T: The type of the validated request body (HelloWorldRequest)
 * - U: The type of user data (unknown in this simple example)
 *
 * The custom TypedBodyValidationMiddleware properly implements BaseMiddleware<T, U>
 * which allows the generic types to flow through correctly.
 */
const helloWorldHandler = new Handler<HelloWorldRequest, unknown>()
  .use<HelloWorldRequest, unknown>(
    new ErrorHandlerMiddleware() as BaseMiddleware<HelloWorldRequest, unknown>
  ) // Handle errors globally
  .use<HelloWorldRequest, unknown>(
    new TypedBodyValidationMiddleware(requestSchema)
  ) // Validate request body with proper typing
  .use<HelloWorldRequest, unknown>(
    new ResponseWrapperMiddleware() as BaseMiddleware<
      HelloWorldRequest,
      unknown
    >
  ) // Wrap response in standard format
  .handle(async (context) => {
    // Extract validated data from the request
    // TypeScript knows that validatedBody is of type HelloWorldRequest | undefined
    // No casting needed! The generic type flows through the Handler correctly
    const { name } = context.req.validatedBody!;

    // Perform business logic
    const greeting = `Hello, ${name}!`;

    // Set response data
    // ResponseWrapperMiddleware will automatically wrap this in { success: true, payload: ... }
    context.res.json({
      message: greeting,
      timestamp: new Date().toISOString(),
    });
  });

/**
 * Export the Cloud Function
 * This function will be deployed to Google Cloud Functions
 */
export const helloWorld = http(
  'helloWorld',
  (req: Request, res: Response): Promise<void> => {
    return helloWorldHandler.execute(req, res);
  }
);
