import { BaseMiddleware, Context, HttpError, logger } from '../core';

interface ResponsePayload {
  success: boolean;
  payload: {
    error: string;
    details?: unknown;
    code?: string;
    stack?: string;
  };
  timestamp: string;
  error?: string;
}

/**
 * Handles errors thrown during request processing and sends an appropriate JSON response.
 *
 * - Logs error details including message, stack, request ID, user agent, and IP.
 * - For `HttpError` instances, responds with the error message, and optionally details and code based on environment and error type.
 * - For other errors, responds with a generic message in production, and includes stack trace in development.
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @param error - The error object thrown during request processing.
 * @param context - The request context containing request and response objects.
 * @returns A promise that resolves when the error response has been sent.
 */
const handleError = async <TBody = unknown, TUser = unknown>(
  error: Error,
  context: Context<TBody, TUser>
): Promise<void> => {
  const isDevelopment =
    process.env.NODE_ENV === 'development' || process.env.DEBUG === 'true';

  logger.error('Error processing request', {
    errorMessage: error?.message,
    errorStack: error?.stack,
    requestId: context.requestId,
    userAgent: context.req.headers?.['user-agent'],
    ip: context.req.ip || 'unknown',
  });

  if (error instanceof HttpError) {
    const responsePayload: ResponsePayload = {
      success: false,
      payload: {
        error: error.message,
      },
      timestamp: new Date().toISOString(),
    };

    // Only include sensitive details in development
    if (isDevelopment && error.details) {
      responsePayload.payload.details = error.details;
    }

    // Only include error codes for client errors (4xx), not server errors
    if (error.code && error.status < 500) {
      responsePayload.payload.code = error.code;
    }

    context.res.status(error.status).json(responsePayload);
  } else {
    // For non-HttpError exceptions, provide generic error message in production
    const errorMessage = isDevelopment
      ? error.message
      : 'Internal Server Error';
    const responsePayload: ResponsePayload = {
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: errorMessage,
      },
      timestamp: new Date().toISOString(),
    };

    // Add stack trace in development for non-HTTP errors
    if (isDevelopment && error.stack) {
      responsePayload.payload.stack = error.stack;
    }

    context.res.status(500).json(responsePayload);
  }
};

/**
 * Middleware class for handling errors in the application.
 * Implements the `BaseMiddleware` interface and provides an asynchronous
 * `onError` method that delegates error handling to the `handleError` function.
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 *
 * @remarks
 * This middleware should be registered to catch and process errors that occur
 * during request handling.
 *
 * @method onError
 * @param error - The error object that was thrown.
 * @param context - The context in which the error occurred.
 * @returns A promise that resolves when error handling is complete.
 *
 * @example
 * Basic handler with error handling:
 * ```typescript
 * import { Handler, ErrorHandlerMiddleware, HttpError } from '@noony-serverless/core';
 *
 * const createUserHandler = new Handler()
 *   .use(new ErrorHandlerMiddleware())
 *   .handle(async (request, context) => {
 *     if (!request.body?.email) {
 *       throw new HttpError(400, 'Email is required', 'MISSING_EMAIL');
 *     }
 *
 *     return {
 *       success: true,
 *       data: { id: 'user-123', email: request.body.email }
 *     };
 *   });
 * ```
 *
 * @example
 * Google Cloud Functions integration:
 * ```typescript
 * import { http } from '@google-cloud/functions-framework';
 * import { Handler, ErrorHandlerMiddleware } from '@noony-serverless/core';
 *
 * const orderHandler = new Handler()
 *   .use(new ErrorHandlerMiddleware())
 *   .handle(async (request, context) => {
 *     // Handler logic that might throw errors
 *     return { success: true, data: processedOrder };
 *   });
 *
 * export const processOrder = http('processOrder', (req, res) => {
 *   return orderHandler.execute(req, res);
 * });
 * ```
 */
export class ErrorHandlerMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async onError(error: Error, context: Context<TBody, TUser>): Promise<void> {
    await handleError<TBody, TUser>(error, context);
  }
}

/**
 * Creates an error handling middleware for processing errors in the application.
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @returns {BaseMiddleware} An object implementing the `onError` method to handle errors.
 *
 * @remarks
 * The middleware's `onError` method asynchronously delegates error handling to the `handleError` function,
 * passing the error and context objects.
 *
 * @example
 * Basic usage with factory function:
 * ```typescript
 * import { Handler, errorHandler, HttpError } from '@noony-serverless/core';
 *
 * const loginHandler = new Handler()
 *   .use(errorHandler())
 *   .handle(async (request, context) => {
 *     const { username, password } = request.body || {};
 *
 *     if (!username || !password) {
 *       throw new HttpError(400, 'Credentials required', 'MISSING_CREDENTIALS');
 *     }
 *
 *     const user = await authenticateUser(username, password);
 *     return { success: true, data: { token: generateToken(user) } };
 *   });
 * ```
 *
 * @example
 * Multiple middleware chain:
 * ```typescript
 * import { Handler, errorHandler, BodyParserMiddleware } from '@noony-serverless/core';
 *
 * const secureHandler = new Handler()
 *   .use(new BodyParserMiddleware())
 *   .use(new AuthenticationMiddleware())
 *   .use(errorHandler()) // Should be last to catch all errors
 *   .handle(async (request, context) => {
 *     // Handler logic
 *     return { success: true, data: result };
 *   });
 * ```
 */
export const errorHandler = <
  TBody = unknown,
  TUser = unknown,
>(): BaseMiddleware<TBody, TUser> => ({
  onError: async (
    error: Error,
    context: Context<TBody, TUser>
  ): Promise<void> => {
    await handleError<TBody, TUser>(error, context);
  },
});
