import { errorHandler, ErrorHandlerMiddleware } from './errorHandlerMiddleware';
import { Context, HttpError, logger } from '../core';

jest.mock('../core/logger', () => ({
  logger: {
    error: jest.fn(),
  },
}));

describe('ErrorHandlerMiddleware', () => {
  let context: Context;
  let middleware: ErrorHandlerMiddleware;

  beforeEach(() => {
    context = {
      req: {
        headers: {},
        ip: 'unknown',
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
      requestId: undefined,
    } as unknown as Context;
    middleware = new ErrorHandlerMiddleware();
  });

  it('logs the error and returns 500 for generic errors', async () => {
    const error = new Error('Generic error');
    await middleware.onError(error, context);

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: error.message,
      errorStack: error.stack,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith({
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: 'Internal Server Error',
      },
      timestamp: expect.any(String),
    });
  });

  it('logs the error and returns the correct status and message for HttpError', async () => {
    // Set development environment to include error details
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    const error = new HttpError(
      404,
      'Not Found',
      undefined,
      'Resource not found'
    );
    await middleware.onError(error, context);

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: error.message,
      errorStack: error.stack,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(404);
    expect(context.res.json).toHaveBeenCalledWith({
      success: false,
      payload: {
        error: error.message,
        details: 'Resource not found',
      },
      timestamp: expect.any(String),
    });

    // Restore original NODE_ENV
    process.env.NODE_ENV = originalNodeEnv;
  });

  it('handles errors without a stack trace', async () => {
    const error = new Error('No stack trace');
    error.stack = undefined;
    await middleware.onError(error, context);

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: error.message,
      errorStack: undefined,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith({
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: 'Internal Server Error',
      },
      timestamp: expect.any(String),
    });
  });

  it('handles errors without a message', async () => {
    const error = new Error();
    error.message = '';
    await middleware.onError(error, context);

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: '',
      errorStack: error.stack,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith({
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: 'Internal Server Error',
      },
      timestamp: expect.any(String),
    });
  });
});

describe('errorHandler', () => {
  let context: Context;
  let middleware: ReturnType<typeof errorHandler>;

  beforeEach(() => {
    context = {
      req: {
        headers: {},
        ip: 'unknown',
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
      requestId: undefined,
    } as unknown as Context;
    middleware = errorHandler();
  });

  it('logs the error and returns 500 for generic errors', async () => {
    const error = new Error('Generic error');
    if (middleware.onError) {
      await middleware.onError(error, context);
    }

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: error.message,
      errorStack: error.stack,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith({
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: 'Internal Server Error',
      },
      timestamp: expect.any(String),
    });
  });

  it('logs the error and returns the correct status and message for HttpError', async () => {
    // Set development environment to include error details
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    const error = new HttpError(
      404,
      'Not Found',
      undefined,
      'Resource not found'
    );
    if (middleware.onError) {
      await middleware.onError(error, context);
    }

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: error.message,
      errorStack: error.stack,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(404);
    expect(context.res.json).toHaveBeenCalledWith({
      success: false,
      payload: {
        error: error.message,
        details: 'Resource not found',
      },
      timestamp: expect.any(String),
    });

    // Restore original NODE_ENV
    process.env.NODE_ENV = originalNodeEnv;
  });

  it('handles errors without a stack trace', async () => {
    const error = new Error('No stack trace');
    error.stack = undefined;
    if (middleware.onError) {
      await middleware.onError(error, context);
    }

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: error.message,
      errorStack: undefined,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith({
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: 'Internal Server Error',
      },
      timestamp: expect.any(String),
    });
  });

  it('handles errors without a message', async () => {
    const error = new Error();
    error.message = '';
    if (middleware.onError) {
      await middleware.onError(error, context);
    }

    expect(logger.error).toHaveBeenCalledWith('Error processing request', {
      errorMessage: '',
      errorStack: error.stack,
      requestId: undefined,
      userAgent: undefined,
      ip: 'unknown',
    });
    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith({
      error: 'Internal Server Error',
      success: false,
      payload: {
        error: 'Internal Server Error',
      },
      timestamp: expect.any(String),
    });
  });
});
