import { BaseMiddleware, Context, HttpError, logger } from '../core';

interface ResponsePayload {
  success: boolean;
  payload: {
    error: string;
    details?: unknown;
    code?: string;
    stack?: string;
    retryable?: boolean;
    debug?: {
      originalError: string;
      stack?: string;
      errorType?: string;
    };
  };
  timestamp: string;
  error?: string;
}

export interface ErrorCategory {
  type: string;
  userMessage: string;
  httpStatus: number;
  retryable: boolean;
}

export interface ErrorMatcher {
  /**
   * Function to determine if this category applies to the error.
   * Return true if the error matches this category.
   */
  matches: (error: Error) => boolean;
  /**
   * The category to return if the error matches.
   */
  category: ErrorCategory;
}

export interface ErrorHandlerOptions {
  /**
   * Custom error categories to check before default ones.
   * These are evaluated in order.
   */
  customCategories?: ErrorMatcher[];
}

// Optimization: Cache environment variables to avoid process.env access on every request
const IS_DEVELOPMENT =
  process.env.NODE_ENV === 'development' || process.env.DEBUG === 'true';
const DEBUG_API_RESPONSE = process.env.DEBUG_API_RESPONSE === 'true';

// Optimization: Pre-allocate static error categories to reduce garbage collection pressure
const DATABASE_ERROR: ErrorCategory = {
  type: 'DATABASE_ERROR',
  userMessage: 'Database temporarily unavailable. Please try again.',
  httpStatus: 503,
  retryable: true,
};

const TIMEOUT_ERROR: ErrorCategory = {
  type: 'TIMEOUT_ERROR',
  userMessage: 'Request took too long. Please try again.',
  httpStatus: 504,
  retryable: true,
};

const EXTERNAL_SERVICE_ERROR: ErrorCategory = {
  type: 'EXTERNAL_SERVICE_ERROR',
  userMessage: 'External service unavailable. Please try again later.',
  httpStatus: 502,
  retryable: true,
};

const INTERNAL_ERROR: ErrorCategory = {
  type: 'INTERNAL_ERROR',
  userMessage: 'An unexpected error occurred.',
  httpStatus: 500,
  retryable: false,
};

const categorizeError = (
  error: Error,
  customMatchers?: ErrorMatcher[]
): ErrorCategory => {
  // Check custom matchers first
  if (customMatchers) {
    for (const matcher of customMatchers) {
      if (matcher.matches(error)) {
        return matcher.category;
      }
    }
  }

  const message = error.message.toLowerCase();

  // Database errors (MongoDB, Mongoose)
  if (
    message.includes('mongodb') ||
    message.includes('mongoose') ||
    message.includes('buffering timed out')
  ) {
    return DATABASE_ERROR;
  }

  // Timeout errors
  if (message.includes('timeout') || message.includes('timed out')) {
    return TIMEOUT_ERROR;
  }

  // Network/external service errors
  if (
    message.includes('econnrefused') ||
    message.includes('network') ||
    message.includes('fetch failed')
  ) {
    return EXTERNAL_SERVICE_ERROR;
  }

  // Default: generic server error
  return INTERNAL_ERROR;
};

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
  context: Context<TBody, TUser>,
  options?: ErrorHandlerOptions
): Promise<void> => {
  // Safe property collection for logging
  const errorType = error?.constructor?.name;
  const errorMessage = error?.message;

  logger.error('Error processing request', {
    errorType,
    errorMessage,
    errorStack: error?.stack,
    errorCode: (error as HttpError)?.code,
    httpStatus: (error as HttpError)?.status,
    requestId: context.requestId,
    url: context.req.url,
    method: context.req.method,
    userAgent: context.req.headers?.['user-agent'],
    ip: context.req.ip || 'unknown',
  });

  const timestamp = new Date().toISOString();

  if (error instanceof HttpError) {
    const responsePayload: ResponsePayload = {
      success: false,
      payload: {
        error: error.message,
      },
      timestamp,
    };

    // Only include sensitive details in development
    if (IS_DEVELOPMENT && error.details) {
      responsePayload.payload.details = error.details;
    }

    // Only include error codes for client errors (4xx), not server errors
    if (error.code && error.status < 500) {
      responsePayload.payload.code = error.code;
    }

    context.res.status(error.status).json(responsePayload);
    return;
  }

  // Categorize the error for appropriate response
  const category = categorizeError(error, options?.customCategories);

  const responsePayload: ResponsePayload = {
    error: category.userMessage,
    success: false,
    payload: {
      error: category.userMessage,
      code: category.type,
    },
    timestamp,
  };

  // Add retryable hint for client
  if (category.retryable) {
    responsePayload.payload.retryable = true;
    context.res.header('Retry-After', '5');
  }

  // Include full error details when DEBUG_API_RESPONSE is enabled (dev/local)
  if (DEBUG_API_RESPONSE) {
    responsePayload.payload.debug = {
      originalError: error.message,
      stack: error.stack || 'No stack trace available',
      errorType: error.constructor?.name || 'UnknownError',
    };
  }

  context.res.status(category.httpStatus).json(responsePayload);
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
 * during request handling. It supports custom error categorization via options.
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
 * Usage with custom categories:
 * ```typescript
 * import { Handler, ErrorHandlerMiddleware } from '@noony-serverless/core';
 *
 * const customCategories = [{
 *   matches: (err) => err.message.includes('payment_failed'),
 *   category: {
 *     type: 'PAYMENT_ERROR',
 *     userMessage: 'Payment processing failed',
 *     httpStatus: 402,
 *     retryable: false
 *   }
 * }];
 *
 * const handler = new Handler()
 *   .use(new ErrorHandlerMiddleware({ customCategories }))
 *   .handle(...);
 * ```
 */
export class ErrorHandlerMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  /**
   * Creates an instance of ErrorHandlerMiddleware.
   * @param {ErrorHandlerOptions} [options] - Configuration options for the middleware, including custom error categories.
   */
  constructor(private options?: ErrorHandlerOptions) {}

  async onError(error: Error, context: Context<TBody, TUser>): Promise<void> {
    await handleError<TBody, TUser>(error, context, this.options);
  }
}

/**
 * Creates an error handling middleware for processing errors in the application.
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @param {ErrorHandlerOptions} [options] - Configuration options for the middleware.
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
 *     // ...
 *   });
 * ```
 *
 * @example
 * Usage with custom categories:
 * ```typescript
 * import { Handler, errorHandler } from '@noony-serverless/core';
 *
 * const customCategories = [{
 *   matches: (err) => err.message.includes('custom'),
 *   category: {
 *     type: 'CUSTOM_ERROR',
 *     userMessage: 'A custom error occurred',
 *     httpStatus: 400,
 *     retryable: false
 *   }
 * }];
 *
 * const handler = new Handler()
 *   .use(errorHandler({ customCategories }))
 *   .handle(...)
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
export const errorHandler = <TBody = unknown, TUser = unknown>(
  options?: ErrorHandlerOptions
): BaseMiddleware<TBody, TUser> => ({
  onError: async (
    error: Error,
    context: Context<TBody, TUser>
  ): Promise<void> => {
    await handleError<TBody, TUser>(error, context, options);
  },
});
