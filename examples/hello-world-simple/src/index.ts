/**
 * Hello World Simple - Noony Serverless Framework Example
 *
 * This example demonstrates the fundamental concepts and best practices of the
 * Noony Serverless Framework. It showcases how to build a type-safe, production-ready
 * serverless function with comprehensive middleware support.
 *
 * ## What This Example Teaches
 *
 * ### Core Concepts:
 * - Handler creation and middleware composition
 * - Type-safe request validation with Zod schemas
 * - Automatic response formatting and error handling
 * - Framework-agnostic design patterns
 *
 * ### Production Patterns:
 * - Comprehensive input validation and sanitization
 * - Structured error handling with proper HTTP status codes
 * - Request tracking and performance monitoring
 * - Environment-based configuration
 *
 * ### TypeScript Best Practices:
 * - Schema-driven type generation (Zod + TypeScript)
 * - Generic type safety throughout the middleware chain
 * - Comprehensive interface documentation
 * - Zero runtime type casting needed
 *
 * ## API Specification
 *
 * **Endpoint**: POST /helloWorld
 *
 * **Request Body**:
 * ```json
 * {
 *   "name": "World",              // Required: string (1-100 chars)
 *   "greeting": "Hello",          // Optional: string (max 50 chars), defaults to "Hello"
 *   "includeTimestamp": true,     // Optional: boolean, defaults to true
 *   "language": "en"              // Optional: 2-letter ISO language code
 * }
 * ```
 *
 * **Success Response** (200 OK):
 * ```json
 * {
 *   "success": true,
 *   "payload": {
 *     "message": "Hello, World!",
 *     "timestamp": "2024-01-15T10:30:45.123Z",
 *     "requestId": "req_abc123def456",
 *     "language": "en"
 *   },
 *   "timestamp": "2024-01-15T10:30:45.125Z"
 * }
 * ```
 *
 * **Error Response** (400 Bad Request):
 * ```json
 * {
 *   "success": false,
 *   "payload": {
 *     "error": "Validation failed",
 *     "details": [
 *       {
 *         "field": "name",
 *         "message": "Name must be at least 1 character long"
 *       }
 *     ]
 *   },
 *   "timestamp": "2024-01-15T10:30:45.125Z"
 * }
 * ```
 *
 * ## Example Usage
 *
 * ```bash
 * # Basic greeting
 * curl -X POST http://localhost:8080 \
 *   -H "Content-Type: application/json" \
 *   -d '{"name": "Developer"}'
 *
 * # Custom greeting without timestamp
 * curl -X POST http://localhost:8080 \
 *   -H "Content-Type: application/json" \
 *   -d '{"name": "Alice", "greeting": "Hi", "includeTimestamp": false}'
 *
 * # With language specification
 * curl -X POST http://localhost:8080 \
 *   -H "Content-Type: application/json" \
 *   -d '{"name": "María", "greeting": "Hola", "language": "es"}'
 * ```
 *
 * @author Noony Framework Team
 * @version 1.0.0
 * @since 2024-01-01
 */

import { http, Request, Response } from '@google-cloud/functions-framework';
import {
  ErrorHandlerMiddleware,
  Handler,
  ResponseWrapperMiddleware,
  BodyValidationMiddleware,
  BodyParserMiddleware,
  Context,
} from '@noony-serverless/core';

// Import our type definitions and validation schema
import {
  helloWorldSchema,
  HelloWorldRequest,
  HelloWorldResponseData,
  HelloWorldContext,
  HelloWorldError,
} from './types';

/**
 * Environment configuration with defaults
 *
 * Loads configuration from environment variables with sensible defaults.
 * This pattern ensures the function works out-of-the-box while allowing
 * customization for different deployment environments.
 */
const config = {
  /** Default greeting when none provided in request */
  defaultGreeting: process.env.DEFAULT_GREETING || 'Hello',

  /** Enable request ID generation for debugging */
  enableRequestId: process.env.ENABLE_REQUEST_ID === 'true',

  /** Development mode flag for enhanced logging */
  isDevelopment: process.env.NODE_ENV === 'development',

  /** Debug mode for additional console output */
  debugMode: process.env.DEBUG === 'true',
};

/**
 * Utility function to generate unique request IDs
 *
 * Creates a short, URL-safe identifier for request tracking.
 * Useful for correlating logs, debugging issues, and monitoring.
 *
 * @returns A unique request identifier (e.g., "req_abc123def456")
 */
function generateRequestId(): string {
  const timestamp = Date.now().toString(36); // Base36 timestamp
  const random = Math.random().toString(36).substring(2, 8); // 6 random chars
  return `req_${timestamp}${random}`;
}

/**
 * Business logic function for creating greeting messages
 *
 * Separated from the handler for better testability and reusability.
 * This pure function takes validated input and produces the greeting,
 * making it easy to unit test without middleware concerns.
 *
 * @param request - Validated and sanitized request data
 * @param requestId - Optional request ID for tracking
 * @returns Formatted greeting response data
 */
function createGreeting(
  request: HelloWorldRequest,
  requestId?: string
): HelloWorldResponseData {
  // Build the core greeting message
  const message = `${request.greeting}, ${request.name}!`;

  // Create base response object
  const responseData: HelloWorldResponseData = { message };

  // Conditionally add optional fields based on request preferences
  if (request.includeTimestamp) {
    responseData.timestamp = new Date().toISOString();
  }

  if (requestId && config.enableRequestId) {
    responseData.requestId = requestId;
  }

  if (request.language) {
    responseData.language = request.language;
  }

  return responseData;
}

/**
 * Custom validation middleware for additional business rules
 *
 * While Zod handles basic validation, this middleware demonstrates
 * how to add custom business logic validation that might depend on
 * external factors or complex rules.
 */
<<<<<<< Updated upstream
async function validateBusinessRules(context: Context): Promise<void> {
=======
async function validateBusinessRules(
  context: Context<HelloWorldRequest>
): Promise<void> {
>>>>>>> Stashed changes
  const request = context.req.validatedBody as HelloWorldRequest;

  // Example: Reject inappropriate names (this is just a demo)
  const inappropriateNames = ['admin', 'root', 'system'];
  if (inappropriateNames.includes(request.name.toLowerCase())) {
    throw new HelloWorldError(
      'Name contains inappropriate content',
      'INAPPROPRIATE_NAME',
      400
    );
  }

  // Example: Validate language codes against supported languages
  if (request.language) {
    const supportedLanguages = ['en', 'es', 'fr', 'de', 'it'];
    if (!supportedLanguages.includes(request.language)) {
      throw new HelloWorldError(
        `Language '${request.language}' is not supported`,
        'UNSUPPORTED_LANGUAGE',
        400
      );
    }
  }

  // Store business context for use in the handler
  const businessContext: HelloWorldContext = {
    validatedRequest: request,
    requestId: generateRequestId(),
    startTime: new Date(),
    preferredLanguage: request.language ?? '',
  };

  context.businessData?.set('helloWorldContext', businessContext);

  if (config.debugMode) {
    console.log('✅ Business rules validation passed', {
      name: request.name,
      greeting: request.greeting,
      language: request.language,
      requestId: businessContext.requestId,
    });
  }
}

/**
 * Performance monitoring middleware
 *
 * Demonstrates how to collect performance metrics for monitoring
 * and optimization. This middleware runs after the handler completes.
 */
<<<<<<< Updated upstream
async function performanceMonitoring(context: Context): Promise<void> {
=======
async function performanceMonitoring(
  context: Context<HelloWorldRequest>
): Promise<void> {
>>>>>>> Stashed changes
  const businessContext = context.businessData?.get(
    'helloWorldContext'
  ) as HelloWorldContext;

  if (!businessContext) return;

  const endTime = new Date();
  const duration = endTime.getTime() - businessContext.startTime.getTime();

  // Log performance metrics (in production, send to monitoring system)
  if (config.isDevelopment || config.debugMode) {
    console.log('📊 Request Performance Metrics', {
      requestId: businessContext.requestId,
      duration: `${duration}ms`,
      name: businessContext.validatedRequest.name,
      timestamp: endTime.toISOString(),
    });
  }

  // Example: Alert if request takes too long
  if (duration > 1000) {
    console.warn('⚠️ Slow request detected', {
      requestId: businessContext.requestId,
      duration,
      threshold: 1000,
    });
  }
}

/**
 * Main Hello World Handler
 *
 * This handler demonstrates the complete Noony middleware pipeline:
 *
 * 1. **ErrorHandlerMiddleware**: Catches and formats all errors
 * 2. **BodyValidationMiddleware**: Validates request against Zod schema
 * 3. **Custom Business Validation**: Applies business-specific rules
 * 4. **ResponseWrapperMiddleware**: Formats response in standard structure
 * 5. **Performance Monitoring**: Tracks request metrics (after handler)
 *
 * ## Middleware Execution Order:
 *
 * **Before Handler** (in order):
 * - ErrorHandler.before() → BodyValidation.before() → BusinessValidation()
 *
 * **Handler Execution**:
 * - Main business logic (createGreeting)
 *
 * **After Handler** (reverse order):
 * - Performance monitoring → ResponseWrapper.after() → ErrorHandler.after()
 *
 * **Error Handling** (reverse order, if error occurs):
 * - ErrorHandler.onError() handles all errors uniformly
 *
 * ## Type Safety:
 * The entire pipeline maintains type safety through:
 * - Generic Handler without explicit types (works with all middleware)
 * - Type assertions using validated schemas (context.req.validatedBody as HelloWorldRequest)
 * - Comprehensive TypeScript interfaces for all data structures
 */
const helloWorldHandler = new Handler()
  // 🛡️ Error handling - ALWAYS FIRST
  // Catches all errors from subsequent middleware and formats them consistently
  .use(new ErrorHandlerMiddleware())

  // 📋 Body parsing - BEFORE VALIDATION
  // Parses JSON request body and makes it available for validation
  .use(new BodyParserMiddleware())

  // ✅ Schema validation - EARLY IN CHAIN
  // Validates request body against Zod schema and makes validated data available
  .use(new BodyValidationMiddleware(helloWorldSchema))

  // 🔍 Custom business validation - AFTER SCHEMA VALIDATION
  // Applies business-specific rules that go beyond basic schema validation
  .use({
    before: validateBusinessRules,
  })

  // 📦 Response formatting - BEFORE HANDLER
  // Ensures all responses follow standard format with success/error indication
  .use(new ResponseWrapperMiddleware())

  // 📊 Performance monitoring - AFTER HANDLER
  // Tracks timing and performance metrics for optimization
  .use({
    after: performanceMonitoring,
  })

  // 🎯 Main business logic handler
  .handle(async (context: Context) => {
    // Extract validated and business-rule-checked data
    const businessContext = context.businessData?.get(
      'helloWorldContext'
    ) as HelloWorldContext;

    if (!businessContext) {
      throw new HelloWorldError(
        'Business context not found',
        'MISSING_CONTEXT',
        500
      );
    }

    try {
      // Execute core business logic
      const responseData = createGreeting(
        businessContext.validatedRequest,
        businessContext.requestId
      );

      // Log successful processing (development/debug only)
      if (config.debugMode) {
        console.log('✨ Successfully created greeting', {
          requestId: businessContext.requestId,
          message: responseData.message,
          includeTimestamp: businessContext.validatedRequest.includeTimestamp,
        });
      }

      // Send response (ResponseWrapperMiddleware will format it)
      context.res.json(responseData);
    } catch (error) {
      // Convert unexpected errors to HelloWorldError for consistent handling
      if (error instanceof HelloWorldError) {
        throw error;
      }

      throw new HelloWorldError(
        'Failed to create greeting',
        'GREETING_CREATION_FAILED',
        500
      );
    }
  });

/**
 * Google Cloud Functions Export
 *
 * This export makes the handler available to the Google Cloud Functions runtime.
 * The http() wrapper from @google-cloud/functions-framework automatically:
 * - Handles HTTP request/response conversion
 * - Provides Express-like req/res objects
 * - Manages the function lifecycle
 *
 * The handler.execute() method converts these to Noony's GenericRequest/GenericResponse
 * format, making the handler framework-agnostic and portable.
 *
 * ## Local Development:
 * ```bash
 * npm run dev
 * # Function available at: http://localhost:8080
 * ```
 *
 * ## Production Deployment:
 * ```bash
 * npm run deploy
 * # Deploys to Google Cloud Functions
 * ```
 *
 * @param req - HTTP request object from Functions Framework
 * @param res - HTTP response object from Functions Framework
 * @returns Promise that resolves when request is complete
 */
export const helloWorld = http(
  'helloWorld',
  async (req: Request, res: Response): Promise<void> => {
    try {
      // Let Noony handle the complete request lifecycle
      await helloWorldHandler.execute(req, res);
    } catch (error) {
      // Final safety net (should be handled by ErrorHandlerMiddleware)
      console.error('💥 Unhandled error in helloWorld function:', error);

      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          payload: {
            error: 'Internal server error',
            code: 'UNHANDLED_ERROR',
          },
          timestamp: new Date().toISOString(),
        });
      }
    }
  }
);

/**
 * Alternative Exports for Different Platforms
 *
 * The handler can be adapted to other serverless platforms or HTTP frameworks:
 *
 * ## Express.js Integration:
 * ```typescript
 * import express from 'express';
 * import { adaptExpressRequest, adaptExpressResponse } from '@noony-serverless/core';
 *
 * const app = express();
 * app.post('/hello', async (req, res) => {
 *   const genericReq = adaptExpressRequest(req);
 *   const genericRes = adaptExpressResponse(res);
 *   await helloWorldHandler.executeGeneric(genericReq, genericRes);
 * });
 * ```
 *
 * ## AWS Lambda Integration:
 * ```typescript
 * import { APIGatewayProxyHandler } from 'aws-lambda';
 * import { adaptLambdaRequest, adaptLambdaResponse } from '@noony-serverless/aws-adapter';
 *
 * export const handler: APIGatewayProxyHandler = async (event, context) => {
 *   const genericReq = adaptLambdaRequest(event, context);
 *   const genericRes = adaptLambdaResponse();
 *   await helloWorldHandler.executeGeneric(genericReq, genericRes);
 *   return genericRes.toAWSResponse();
 * };
 * ```
 *
 * ## Fastify Integration:
 * See the fastify-production-api example for detailed implementation.
 */

// Export handler for testing and alternative integrations
export { helloWorldHandler };

// Export types for external use
export type {
  HelloWorldRequest,
  HelloWorldResponseData,
  HelloWorldContext,
} from './types';
