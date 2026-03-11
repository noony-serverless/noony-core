/* eslint-disable @typescript-eslint/ban-ts-comment */
import type { Request, Response } from 'express';
import { createHttpFunction, wrapNoonyHandler } from './wrapper-utils';
import { Handler } from '../core/handler';
import { logger } from '../core/logger';

// Mock logger
jest.mock('../core/logger', () => ({
  logger: {
    error: jest.fn(),
  },
}));

describe('wrapper-utils', () => {
  let mockRequest: Request;
  let mockResponse: Response;
  let mockHandler: Handler<unknown>;
  let initializeDependencies: jest.Mock;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock Express request
    mockRequest = {
      method: 'POST',
      url: '/api/test',
      headers: { 'content-type': 'application/json' },
      query: {},
      params: {},
      body: { test: 'data' },
      ip: '127.0.0.1',
      path: '/api/test',
      get: jest.fn((header: string) => {
        if (header === 'content-type') return 'application/json';
        return undefined;
      }),
    } as unknown as Request;

    // Create mock Express response
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      header: jest.fn().mockReturnThis(),
      end: jest.fn(),
      headersSent: false,
      statusCode: undefined,
    } as unknown as Response;

    // Create mock handler
    mockHandler = {
      execute: jest.fn(),
      executeGeneric: jest.fn(),
    } as unknown as Handler<unknown>;

    // Create mock initialization function
    initializeDependencies = jest.fn().mockResolvedValue(undefined);
  });

  describe('createHttpFunction', () => {
    it('should create an HttpFunction that calls initializeDependencies', async () => {
      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(initializeDependencies).toHaveBeenCalledTimes(1);
    });

    it('should call handler.execute with request and response', async () => {
      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(mockHandler.execute).toHaveBeenCalledTimes(1);
      expect(mockHandler.execute).toHaveBeenCalledWith(
        mockRequest,
        mockResponse
      );
    });

    it('should handle successful execution', async () => {
      (mockHandler.execute as jest.Mock).mockResolvedValue(undefined);

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(mockHandler.execute).toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    it('should ignore RESPONSE_SENT errors', async () => {
      const responseSentError = new Error('RESPONSE_SENT');
      (mockHandler.execute as jest.Mock).mockRejectedValue(responseSentError);

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(logger.error).not.toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should handle errors and return 500 response', async () => {
      const testError = new Error('Test error');
      (mockHandler.execute as jest.Mock).mockRejectedValue(testError);

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testFunction function error', {
        error: 'Test error',
        stack: testError.stack,
      });

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    });

    it('should not send response if headers already sent', async () => {
      const testError = new Error('Test error');
      (mockHandler.execute as jest.Mock).mockRejectedValue(testError);
      mockResponse.headersSent = true;

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should handle non-Error exceptions', async () => {
      (mockHandler.execute as jest.Mock).mockRejectedValue('string error');

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testFunction function error', {
        error: 'Unknown error',
        stack: undefined,
      });

      expect(mockResponse.status).toHaveBeenCalledWith(500);
    });

    it('should handle initialization errors', async () => {
      const initError = new Error('Database connection failed');
      initializeDependencies.mockRejectedValue(initError);

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testFunction function error', {
        error: 'Database connection failed',
        stack: initError.stack,
      });

      expect(mockHandler.execute).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(500);
    });

    it('should call initializeDependencies before handler execution', async () => {
      const executionOrder: string[] = [];

      initializeDependencies.mockImplementation(async () => {
        executionOrder.push('init');
      });

      (mockHandler.execute as jest.Mock).mockImplementation(async () => {
        executionOrder.push('execute');
      });

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(executionOrder).toEqual(['init', 'execute']);
    });
  });

  describe('wrapNoonyHandler', () => {
    it('should create an Express handler that calls initializeDependencies', async () => {
      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(initializeDependencies).toHaveBeenCalledTimes(1);
    });

    it('should call handler.executeGeneric with request and response', async () => {
      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(mockHandler.executeGeneric).toHaveBeenCalledTimes(1);
      expect(mockHandler.executeGeneric).toHaveBeenCalledWith(
        mockRequest,
        mockResponse
      );
    });

    it('should handle successful execution', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockResolvedValue(undefined);

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(mockHandler.executeGeneric).toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    it('should ignore RESPONSE_SENT errors', async () => {
      const responseSentError = new Error('RESPONSE_SENT');
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(
        responseSentError
      );

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(logger.error).not.toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should handle errors and return 500 response', async () => {
      const testError = new Error('Test error');
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(testError);

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Test error',
        stack: testError.stack,
      });

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    });

    it('should not send response if headers already sent', async () => {
      const testError = new Error('Test error');
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(testError);
      mockResponse.headersSent = true;

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should handle non-Error exceptions', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(
        'string error'
      );

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Unknown error',
        stack: undefined,
      });

      expect(mockResponse.status).toHaveBeenCalledWith(500);
    });

    it('should handle initialization errors', async () => {
      const initError = new Error('Database connection failed');
      initializeDependencies.mockRejectedValue(initError);

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Database connection failed',
        stack: initError.stack,
      });

      expect(mockHandler.executeGeneric).not.toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(500);
    });

    it('should call initializeDependencies before handler execution', async () => {
      const executionOrder: string[] = [];

      initializeDependencies.mockImplementation(async () => {
        executionOrder.push('init');
      });

      (mockHandler.executeGeneric as jest.Mock).mockImplementation(async () => {
        executionOrder.push('executeGeneric');
      });

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(executionOrder).toEqual(['init', 'executeGeneric']);
    });

    it('should work with Express path parameters', async () => {
      mockRequest.params = { userId: '123', orderId: '456' };

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(mockHandler.executeGeneric).toHaveBeenCalledWith(
        expect.objectContaining({
          params: { userId: '123', orderId: '456' },
        }),
        mockResponse
      );
    });
  });

  describe('Comparison: createHttpFunction vs wrapNoonyHandler', () => {
    it('createHttpFunction should use handler.execute', async () => {
      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(mockHandler.execute).toHaveBeenCalled();
      expect(mockHandler.executeGeneric).not.toHaveBeenCalled();
    });

    it('wrapNoonyHandler should use handler.executeGeneric', async () => {
      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(mockHandler.executeGeneric).toHaveBeenCalled();
      expect(mockHandler.execute).not.toHaveBeenCalled();
    });

    it('both should handle the same error types consistently', async () => {
      const testError = new Error('Consistent error');

      // Test createHttpFunction
      (mockHandler.execute as jest.Mock).mockRejectedValue(testError);
      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        initializeDependencies
      );
      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testFunction function error', {
        error: 'Consistent error',
        stack: testError.stack,
      });

      jest.clearAllMocks();

      // Test wrapNoonyHandler
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(testError);
      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );
      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Consistent error',
        stack: testError.stack,
      });
    });
  });

  describe('Integration with real Handler', () => {
    it('createHttpFunction should work with real Handler instance', async () => {
      const realHandler = new Handler<unknown>().handle(async (context) => {
        context.res.status(200).json({ success: true });
      });

      const httpFunction = createHttpFunction(
        realHandler,
        'testFunction',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      expect(initializeDependencies).toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({ success: true });
    });

    it('wrapNoonyHandler should work with real Handler instance', async () => {
      const realHandler = new Handler<unknown>().handle(async (context) => {
        context.res.status(200).json({ success: true });
      });

      const expressHandler = wrapNoonyHandler(
        realHandler,
        'testHandler',
        initializeDependencies
      );

      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(initializeDependencies).toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({ success: true });
    });
  });

  describe('Singleton pattern for initializeDependencies', () => {
    it('should only call initializeDependencies once across multiple requests (singleton pattern)', async () => {
      let initialized = false;
      const singletonInit = jest.fn(async () => {
        if (initialized) return;
        initialized = true;
      });

      const httpFunction = createHttpFunction(
        mockHandler,
        'testFunction',
        singletonInit
      );

      // Call three times
      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);
      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);
      // @ts-ignore - Type conflict between Express and GCF Request types
      await httpFunction(mockRequest, mockResponse);

      // Init function called 3 times, but logic only executes once
      expect(singletonInit).toHaveBeenCalledTimes(3);
      expect(initialized).toBe(true);
    });

    it('should demonstrate singleton pattern with wrapNoonyHandler', async () => {
      let initCount = 0;
      const singletonInit = jest.fn(async () => {
        if (initCount > 0) return;
        initCount++;
      });

      const expressHandler = wrapNoonyHandler(
        mockHandler,
        'testHandler',
        singletonInit
      );

      // Call three times
      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);
      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);
      // @ts-ignore - Type conflict between Express and GCF Request types
      await expressHandler(mockRequest, mockResponse);

      expect(singletonInit).toHaveBeenCalledTimes(3);
      expect(initCount).toBe(1); // Only initialized once
    });
  });
});
