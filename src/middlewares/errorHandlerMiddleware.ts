import { BaseMiddleware, Context, HttpError, logger } from '../core';

const handleError = async (error: Error, context: Context): Promise<void> => {
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
    const responsePayload: any = {
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
    const responsePayload: any = {
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: errorMessage,
      },
      timestamp: new Date().toISOString(),
    };

    // Only include stack trace in development
    if (isDevelopment && error.stack) {
      responsePayload.payload.stack = error.stack;
    }

    context.res.status(500).json(responsePayload);
  }
};

export class ErrorHandlerMiddleware implements BaseMiddleware {
  async onError(error: Error, context: Context): Promise<void> {
    await handleError(error, context);
  }
}

export const errorHandler = (): BaseMiddleware => ({
  onError: async (error: Error, context: Context): Promise<void> => {
    await handleError(error, context);
  },
});
