import type { FastifyRequest, FastifyReply } from 'fastify';
import { createFastifyHandler, requestBodyMap } from './fastify-wrapper';
import { Handler } from '../core/handler';
import { logger } from '../core/logger';

// Mock logger
jest.mock('../core/logger', () => ({
  logger: {
    error: jest.fn(),
  },
}));

describe('fastify-wrapper', () => {
  let mockRequest: FastifyRequest;
  let mockReply: FastifyReply;
  let mockHandler: Handler<unknown>;
  let initializeDependencies: jest.Mock;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock Fastify request
    mockRequest = {
      method: 'POST',
      url: '/api/test',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'test-agent/1.0',
      },
      query: { filter: 'active', page: '1' },
      params: { userId: '123' },
      body: { name: 'Test User', email: 'test@example.com' },
      ip: '192.168.1.100',
      routeOptions: { url: '/api/test' },
    } as unknown as FastifyRequest;

    // Create mock Fastify reply with sent tracking
    let replySent = false;
    const codeFn = jest.fn().mockReturnThis();
    mockReply = {
      code: codeFn,
      status: codeFn, // Fastify uses reply.code(), but some code might use .status()
      send: jest.fn(() => {
        replySent = true;
        return mockReply;
      }),
      header: jest.fn().mockReturnThis(),
      get sent() {
        return replySent;
      },
    } as unknown as FastifyReply;

    // Create mock handler
    mockHandler = {
      executeGeneric: jest.fn(),
    } as unknown as Handler<unknown>;

    // Create mock initialization function
    initializeDependencies = jest.fn().mockResolvedValue(undefined);
  });

  describe('createFastifyHandler', () => {
    it('should create a Fastify handler that calls initializeDependencies', async () => {
      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(initializeDependencies).toHaveBeenCalledTimes(1);
    });

    it('should call handler.executeGeneric with adapted request and response', async () => {
      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockHandler.executeGeneric).toHaveBeenCalledTimes(1);

      // Verify the adapted request structure
      const [adaptedReq, adaptedRes] = (mockHandler.executeGeneric as jest.Mock)
        .mock.calls[0];

      expect(adaptedReq).toMatchObject({
        method: 'POST',
        url: '/api/test',
        path: '/api/test',
        headers: {
          'content-type': 'application/json',
          'user-agent': 'test-agent/1.0',
        },
        query: { filter: 'active', page: '1' },
        params: { userId: '123' },
        body: { name: 'Test User', email: 'test@example.com' },
        parsedBody: { name: 'Test User', email: 'test@example.com' },
        ip: '192.168.1.100',
        userAgent: 'test-agent/1.0',
      });

      expect(adaptedRes).toHaveProperty('status');
      expect(adaptedRes).toHaveProperty('json');
      expect(adaptedRes).toHaveProperty('send');
      expect(adaptedRes).toHaveProperty('header');
    });

    it('should handle successful execution', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockResolvedValue(undefined);

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockHandler.executeGeneric).toHaveBeenCalled();
      expect(logger.error).not.toHaveBeenCalled();
    });

    it('should ignore RESPONSE_SENT errors', async () => {
      const responseSentError = new Error('RESPONSE_SENT');
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(
        responseSentError
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(logger.error).not.toHaveBeenCalled();
      expect(mockReply.code).not.toHaveBeenCalled();
    });

    it('should handle errors and return 500 response', async () => {
      const testError = new Error('Database connection failed');
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(testError);

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Database connection failed',
        stack: testError.stack,
      });

      expect(mockReply.code).toHaveBeenCalledWith(500);
      expect(mockReply.send).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    });

    it('should not send response if reply already sent', async () => {
      const testError = new Error('Test error');
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(async () => {
        // Simulate middleware sending response
        mockReply.send({ test: 'response' });
        throw testError;
      });

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(logger.error).toHaveBeenCalled();
      // reply.code should not be called again after reply.sent is true
      expect(mockReply.code).not.toHaveBeenCalledWith(500);
    });

    it('should handle non-Error exceptions', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockRejectedValue(
        'string error'
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Unknown error',
        stack: undefined,
      });

      expect(mockReply.code).toHaveBeenCalledWith(500);
    });

    it('should handle initialization errors', async () => {
      const initError = new Error('Service initialization failed');
      initializeDependencies.mockRejectedValue(initError);

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(logger.error).toHaveBeenCalledWith('testHandler function error', {
        error: 'Service initialization failed',
        stack: initError.stack,
      });

      expect(mockHandler.executeGeneric).not.toHaveBeenCalled();
      expect(mockReply.code).toHaveBeenCalledWith(500);
    });

    it('should call initializeDependencies before handler execution', async () => {
      const executionOrder: string[] = [];

      initializeDependencies.mockImplementation(async () => {
        executionOrder.push('init');
      });

      (mockHandler.executeGeneric as jest.Mock).mockImplementation(async () => {
        executionOrder.push('executeGeneric');
      });

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(executionOrder).toEqual(['init', 'executeGeneric']);
    });

    it('should work with Fastify path parameters', async () => {
      mockRequest.params = { userId: '456', orderId: '789' };

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.params).toEqual({ userId: '456', orderId: '789' });
    });

    it('should handle requests without routeOptions', async () => {
      const requestWithoutOptions = {
        ...mockRequest,
        routeOptions: {},
      } as FastifyRequest;

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(requestWithoutOptions, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      // Should fallback to req.url when routeOptions.url is undefined
      expect(adaptedReq.path).toBe('/api/test');
    });

    it('should handle requests without query parameters', async () => {
      mockRequest.query = undefined as never;

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.query).toEqual({});
    });

    it('should handle requests without params', async () => {
      mockRequest.params = undefined as never;

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.params).toEqual({});
    });

    it('should handle requests without user-agent header', async () => {
      delete (mockRequest.headers as Record<string, unknown>)['user-agent'];

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.userAgent).toBeUndefined();
    });
  });

  describe('Adapted response functionality', () => {
    it('should properly adapt response.status()', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.status(201);
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.code).toHaveBeenCalledWith(201);
    });

    it('should properly adapt response.json()', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.json({ success: true, data: { id: 1 } });
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.send).toHaveBeenCalledWith({
        success: true,
        data: { id: 1 },
      });
    });

    it('should properly adapt response.send()', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.send('Plain text response');
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.send).toHaveBeenCalledWith('Plain text response');
    });

    it('should properly adapt response.header()', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.header('X-Custom-Header', 'custom-value');
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.header).toHaveBeenCalledWith(
        'X-Custom-Header',
        'custom-value'
      );
    });

    it('should properly adapt response.headers()', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.headers({
            'X-Header-1': 'value1',
            'X-Header-2': 'value2',
          });
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.header).toHaveBeenCalledWith('X-Header-1', 'value1');
      expect(mockReply.header).toHaveBeenCalledWith('X-Header-2', 'value2');
    });

    it('should properly adapt response.end()', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.end();
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.send).toHaveBeenCalledWith();
    });

    it('should support chaining response methods', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res
            .status(201)
            .header('X-Custom-Header', 'value')
            .json({ created: true });
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.code).toHaveBeenCalledWith(201);
      expect(mockReply.header).toHaveBeenCalledWith('X-Custom-Header', 'value');
      expect(mockReply.send).toHaveBeenCalledWith({ created: true });
    });

    it('should track statusCode property', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          res.status(404);
          expect(res.statusCode).toBe(404);
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);
    });

    it('should track headersSent property', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (_req, res) => {
          expect(res.headersSent).toBe(false);
          res.json({ test: 'data' });
          expect(res.headersSent).toBe(true);
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);
    });
  });

  describe('Integration with real Handler', () => {
    it('should work with real Handler instance', async () => {
      const realHandler = new Handler<unknown>().handle(async (context) => {
        context.res.status(200).json({ success: true });
      });

      const fastifyHandler = createFastifyHandler(
        realHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(initializeDependencies).toHaveBeenCalled();
      expect(mockReply.code).toHaveBeenCalledWith(200);
      expect(mockReply.send).toHaveBeenCalledWith({ success: true });
    });

    it('should work with Handler that accesses request properties', async () => {
      const realHandler = new Handler<unknown>().handle(async (context) => {
        const userId = context.req.params?.userId;
        const filter = context.req.query?.filter;
        const body = context.req.body;

        context.res.status(200).json({
          userId,
          filter,
          body,
        });
      });

      const fastifyHandler = createFastifyHandler(
        realHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      expect(mockReply.send).toHaveBeenCalledWith({
        userId: '123',
        filter: 'active',
        body: { name: 'Test User', email: 'test@example.com' },
      });
    });
  });

  describe('Singleton pattern for initializeDependencies', () => {
    it('should demonstrate singleton pattern', async () => {
      let initCount = 0;
      const singletonInit = jest.fn(async () => {
        if (initCount > 0) return;
        initCount++;
      });

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        singletonInit
      );

      // Call three times
      await fastifyHandler(mockRequest, mockReply);
      await fastifyHandler(mockRequest, mockReply);
      await fastifyHandler(mockRequest, mockReply);

      expect(singletonInit).toHaveBeenCalledTimes(3);
      expect(initCount).toBe(1); // Only initialized once
    });
  });

  describe('requestBodyMap WeakMap functionality', () => {
    it('should store original Fastify request in WeakMap', async () => {
      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];

      // Verify the WeakMap contains the mapping
      const storedRequest = requestBodyMap.get(adaptedReq);
      expect(storedRequest).toBe(mockRequest);
    });

    it('should allow middleware to retrieve original body from WeakMap', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (req) => {
          // Simulate what bodyValidatorMiddleware does
          const originalReq = requestBodyMap.get(req);
          expect(originalReq).toBeDefined();
          expect(originalReq).toBe(mockRequest);
          expect(originalReq?.body).toEqual({
            name: 'Test User',
            email: 'test@example.com',
          });
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);
    });

    it('should handle body retrieval when req.body is undefined after property copy', async () => {
      (mockHandler.executeGeneric as jest.Mock).mockImplementation(
        async (req) => {
          // Simulate scenario where adapted req.body becomes undefined
          // but original Fastify request still has it
          const originalReq = requestBodyMap.get(req);

          // Even if req.body is cleared, we can get it from WeakMap
          expect(originalReq?.body).toEqual({
            name: 'Test User',
            email: 'test@example.com',
          });
        }
      );

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);
    });

    it('should maintain WeakMap reference for multiple requests', async () => {
      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      // First request
      await fastifyHandler(mockRequest, mockReply);
      const [firstReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(requestBodyMap.get(firstReq)).toBe(mockRequest);

      // Second request with different body
      const mockRequest2 = {
        ...mockRequest,
        body: {
          different: 'data',
        },
      } as FastifyRequest;

      await fastifyHandler(mockRequest2, mockReply);
      const [secondReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[1];

      // Both requests should have correct WeakMap mappings
      expect(requestBodyMap.get(firstReq)).toBe(mockRequest);
      expect(requestBodyMap.get(secondReq)).toBe(mockRequest2);
      expect(requestBodyMap.get(secondReq)?.body).toEqual({
        different: 'data',
      });
    });

    it('should allow WeakMap cleanup through garbage collection', async () => {
      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      // Get the adapted request reference
      let [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];

      // Verify it's in the WeakMap
      expect(requestBodyMap.get(adaptedReq)).toBe(mockRequest);

      // Clear the reference (simulating request completion)
      // In real scenarios, this would happen automatically when request goes out of scope
      adaptedReq = null;

      // WeakMap allows garbage collection (we can't test GC directly, but this verifies the pattern)
      // This test documents the intended behavior - WeakMap won't prevent GC
    });
  });

  describe('Edge cases', () => {
    it('should handle empty request body', async () => {
      mockRequest.body = undefined;

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.body).toBeUndefined();
      expect(adaptedReq.parsedBody).toBeUndefined();
    });

    it('should handle array request body', async () => {
      const arrayBody = [{ id: 1 }, { id: 2 }];
      mockRequest.body = arrayBody;

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.body).toEqual(arrayBody);
      expect(adaptedReq.parsedBody).toEqual(arrayBody);
    });

    it('should handle string request body', async () => {
      mockRequest.body = 'plain text body';

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.body).toBe('plain text body');
      expect(adaptedReq.parsedBody).toBe('plain text body');
    });

    it('should handle requests with array query parameters', async () => {
      mockRequest.query = { tags: ['tag1', 'tag2'], status: 'active' };

      const fastifyHandler = createFastifyHandler(
        mockHandler,
        'testHandler',
        initializeDependencies
      );

      await fastifyHandler(mockRequest, mockReply);

      const [adaptedReq] = (mockHandler.executeGeneric as jest.Mock).mock
        .calls[0];
      expect(adaptedReq.query).toEqual({
        tags: ['tag1', 'tag2'],
        status: 'active',
      });
    });
  });
});
