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
  BodyValidationMiddleware,
  ErrorHandlerMiddleware,
  Handler,
  ResponseWrapperMiddleware,
} from '../core';

// Define the expected request body structure using Zod schema
// This ensures type safety and runtime validation
const requestSchema = z.object({
  name: z.string().min(1, 'Name must be at least 1 character long'),
});

// Type inference from the schema for better TypeScript support
type HelloWorldRequest = z.infer<typeof requestSchema>;

/**
 * Create the handler with middleware chain
 *
 * Middleware execution order:
 * 1. ErrorHandlerMiddleware - Should always be first to catch any errors
 * 2. BodyValidationMiddleware - Validates and parses the request body
 * 3. ResponseWrapperMiddleware - Standardizes the response format
 * 4. Business logic handler - Your actual application logic
 */
const helloWorldHandler = Handler.use(new ErrorHandlerMiddleware()) // Handle errors globally
  .use(new BodyValidationMiddleware(requestSchema)) // Validate request body
  .use(new ResponseWrapperMiddleware()) // Wrap response in standard format
  .handle(async (context) => {
    // Extract validated data from the request
    // The body is now type-safe and guaranteed to match our schema
    const { name } = context.req.validatedBody as HelloWorldRequest;

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
