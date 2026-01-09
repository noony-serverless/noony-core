import {
  errorHandler,
  ErrorHandlerMiddleware,
  ErrorHandlerOptions,
} from './errorHandlerMiddleware';
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
    jest.clearAllMocks();
    context = {
      req: {
        headers: {},
        ip: 'unknown',
        url: '/test',
        method: 'GET',
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        header: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
      requestId: 'test-req-id',
    } as unknown as Context;
    process.env.NODE_ENV = 'test';
    process.env.DEBUG = 'false';
    process.env.DEBUG_API_RESPONSE = 'false';
    middleware = new ErrorHandlerMiddleware();
  });

  describe('Standard Error Handling', () => {
    it('logs the error and returns 500 for generic errors', async () => {
      const error = new Error('Generic error');
      await middleware.onError(error, context);

      expect(logger.error).toHaveBeenCalledWith('Error processing request', {
        errorMessage: error.message,
        errorStack: error.stack,
        errorType: 'Error',
        errorCode: undefined,
        httpStatus: undefined,
        requestId: 'test-req-id',
        url: '/test',
        method: 'GET',
        userAgent: undefined,
        ip: 'unknown',
      });

      expect(context.res.status).toHaveBeenCalledWith(500);
      expect(context.res.json).toHaveBeenCalledWith({
        error: 'An unexpected error occurred.',
        success: false,
        payload: {
          error: 'An unexpected error occurred.',
          code: 'INTERNAL_ERROR',
        },
        timestamp: expect.any(String),
      });
    });

    it('returns correct status and message for HttpError', async () => {
      const error = new HttpError(404, 'User not found', 'USER_NOT_FOUND', {
        userId: 123,
      });
      await middleware.onError(error, context);

      expect(context.res.status).toHaveBeenCalledWith(404);
      expect(context.res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          payload: {
            error: 'User not found',
            code: 'USER_NOT_FOUND', // 4xx should include code
          },
        })
      );
    });
  });

  describe('Built-in Categories', () => {
    it('categorizes MongoDB errors as DATABASE_ERROR (503)', async () => {
      const error = new Error('mongodb connection failed');
      await middleware.onError(error, context);

      expect(context.res.status).toHaveBeenCalledWith(503);
      expect(context.res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Database temporarily unavailable. Please try again.',
          payload: expect.objectContaining({
            code: 'DATABASE_ERROR',
            retryable: true,
          }),
        })
      );
      expect(context.res.header).toHaveBeenCalledWith('Retry-After', '5');
    });

    it('categorizes timeout errors as TIMEOUT_ERROR (504)', async () => {
      const error = new Error('Request timed out');
      await middleware.onError(error, context);

      expect(context.res.status).toHaveBeenCalledWith(504);
      expect(context.res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Request took too long. Please try again.',
          payload: expect.objectContaining({
            code: 'TIMEOUT_ERROR',
          }),
        })
      );
    });
  });

  describe('Custom Categories', () => {
    it('uses custom matched category when provided', async () => {
      const customOptions: ErrorHandlerOptions = {
        customCategories: [
          {
            matches: (err) => err.message.includes('payment'),
            category: {
              type: 'PAYMENT_ERROR',
              userMessage: 'Payment processing failed',
              httpStatus: 402,
              retryable: false,
            },
          },
        ],
      };

      const customMiddleware = new ErrorHandlerMiddleware(customOptions);
      const error = new Error('Stripe payment declined');

      await customMiddleware.onError(error, context);

      expect(context.res.status).toHaveBeenCalledWith(402);
      expect(context.res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Payment processing failed',
          payload: expect.objectContaining({
            code: 'PAYMENT_ERROR',
          }),
        })
      );
    });
  });
});

describe('errorHandler', () => {
  let context: Context;

  beforeEach(() => {
    context = {
      req: {
        headers: {},
        ip: 'unknown',
        method: 'GET',
        url: '/',
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      },
      container: null,
      error: null,
      requestId: 'req-id',
    } as unknown as Context;
  });

  it('creates middleware that functions correctly', async () => {
    const middleware = errorHandler();

    // Ensure onError is defined defined before calling it to satisfy TypeScript
    expect(middleware.onError).toBeDefined();
    if (middleware.onError) {
      await middleware.onError(new Error('test'), context);
    }

    expect(context.res.status).toHaveBeenCalledWith(500);
    expect(context.res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'An unexpected error occurred.',
      })
    );
  });

  it('accepts options including custom categories', async () => {
    const options: ErrorHandlerOptions = {
      customCategories: [
        {
          matches: () => true,
          category: {
            type: 'TEAPOT',
            httpStatus: 418,
            userMessage: 'I am a teapot',
            retryable: false,
          },
        },
      ],
    };
    const middleware = errorHandler(options);

    // Ensure onError is defined defined before calling it to satisfy TypeScript
    expect(middleware.onError).toBeDefined();
    if (middleware.onError) {
      await middleware.onError(new Error('test'), context);
    }
    expect(context.res.status).toHaveBeenCalledWith(418);
    expect(context.res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'I am a teapot',
      })
    );
  });
});
