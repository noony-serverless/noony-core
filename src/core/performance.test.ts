/**
 * Performance benchmarking tests for Noony core framework optimizations
 *
 * Tests the performance improvements implemented in:
 * - Handler middleware execution pipeline
 * - Container pooling
 * - Body parser optimizations
 * - Logger performance enhancements
 */

import { performance } from 'perf_hooks';
import { z } from 'zod';
import {
  Handler,
  BodyParserMiddleware,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  AuthenticationMiddleware,
  ResponseWrapperMiddleware,
  Context,
  GenericRequest,
  GenericResponse,
  logger,
  containerPool,
} from '../core';

// Mock implementations for testing
const mockTokenVerifier = {
  async verifyToken(_token: string): Promise<{ userId: string }> {
    return { userId: 'test-user' };
  },
};

const testSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  age: z.number(),
});

// Helper function to create mock request/response
function createMockRequestResponse(body?: unknown): {
  req: GenericRequest;
  res: GenericResponse;
} {
  const mockResponse = {
    statusCode: 200,
    headersSent: false,
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
    send: jest.fn(),
    header: jest.fn().mockReturnThis(),
    headers: jest.fn().mockReturnThis(),
    end: jest.fn(),
  };

  const mockRequest = {
    method: 'POST',
    url: '/test',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer test-token',
    },
    query: {},
    params: {},
    body,
  };

  return {
    req: mockRequest as GenericRequest,
    res: mockResponse as unknown as GenericResponse,
  };
}

describe('Performance Benchmarks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Handler Pipeline Performance', () => {
    it('should show performance improvement with pre-computed middleware arrays', async () => {
      // Create a handler with multiple middlewares
      const handler = new Handler()
        .use(new ErrorHandlerMiddleware())
        .use(new BodyParserMiddleware())
        .use(new BodyValidationMiddleware(testSchema))
        .use(new AuthenticationMiddleware(mockTokenVerifier))
        .use(new ResponseWrapperMiddleware())
        .handle(async () => {
          // Minimal handler logic
        });

      const testData = {
        name: 'John Doe',
        email: 'john@example.com',
        age: 30,
      };

      // Warm up
      const { req, res } = createMockRequestResponse(testData);
      await handler.executeGeneric(req, res);

      // Benchmark multiple executions
      const iterations = 1000;
      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        const { req: testReq, res: testRes } =
          createMockRequestResponse(testData);
        await handler.executeGeneric(testReq, testRes);
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const averageTime = totalTime / iterations;

      console.log(`\nHandler Pipeline Performance:`);
      console.log(
        `Total time for ${iterations} iterations: ${totalTime.toFixed(2)}ms`
      );
      console.log(`Average time per request: ${averageTime.toFixed(3)}ms`);

      // Performance expectation: Should be under 5ms per request on average
      expect(averageTime).toBeLessThan(5);
    });

    it('should demonstrate container pooling performance improvement', async () => {
      const iterations = 500;

      // Test container pool stats
      const initialStats = containerPool.getStats();
      console.log(`\nContainer Pool Initial Stats:`, initialStats);

      const handler = new Handler()
        .use(new ErrorHandlerMiddleware())
        .handle(async () => {});

      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        const { req, res } = createMockRequestResponse();
        await handler.executeGeneric(req, res);
      }

      const endTime = performance.now();
      const finalStats = containerPool.getStats();

      console.log(`\nContainer Pool Performance:`);
      console.log(
        `Time for ${iterations} requests: ${(endTime - startTime).toFixed(2)}ms`
      );
      console.log(`Final pool stats:`, finalStats);

      // Container pool should be actively reusing containers
      expect(finalStats.available).toBeGreaterThan(0);
    });
  });

  describe('Body Parser Performance', () => {
    it('should handle small JSON payloads efficiently', async () => {
      const bodyParser = new BodyParserMiddleware();
      const smallPayload = { message: 'Hello World' };

      const iterations = 1000;
      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        const { req, res } = createMockRequestResponse(
          JSON.stringify(smallPayload)
        );
        const context = {
          req,
          res,
          businessData: new Map(),
          startTime: Date.now(),
          requestId: 'test',
        };
        await bodyParser.before(context as Context);
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      console.log(`\nBody Parser Small Payload Performance:`);
      console.log(
        `Time for ${iterations} small payloads: ${totalTime.toFixed(2)}ms`
      );
      console.log(
        `Average: ${(totalTime / iterations).toFixed(3)}ms per parse`
      );

      expect(totalTime / iterations).toBeLessThan(0.1); // Should be very fast for small payloads
    });

    it('should handle large JSON payloads with async parsing', async () => {
      const bodyParser = new BodyParserMiddleware();

      // Create a larger payload (around 50KB)
      const largePayload = {
        data: 'x'.repeat(50000),
        metadata: {
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          items: Array.from({ length: 1000 }, (_, i) => ({
            id: i,
            value: `item_${i}`,
          })),
        },
      };

      const iterations = 50;
      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        const { req, res } = createMockRequestResponse(
          JSON.stringify(largePayload)
        );
        const context = {
          req,
          res,
          businessData: new Map(),
          startTime: Date.now(),
          requestId: 'test',
        };
        await bodyParser.before(context as Context);
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      console.log(`\nBody Parser Large Payload Performance:`);
      console.log(
        `Time for ${iterations} large payloads: ${totalTime.toFixed(2)}ms`
      );
      console.log(
        `Average: ${(totalTime / iterations).toFixed(3)}ms per parse`
      );

      expect(totalTime / iterations).toBeLessThan(10); // Should handle large payloads reasonably
    });
  });

  describe('Logger Performance', () => {
    it('should demonstrate optimized logging performance', async () => {
      const iterations = 10000;

      // Test info logging
      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        logger.info('Test log message', { iteration: i, data: 'test_data' });
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      console.log(`\nLogger Performance:`);
      console.log(
        `Time for ${iterations} log calls: ${totalTime.toFixed(2)}ms`
      );
      console.log(`Average: ${(totalTime / iterations).toFixed(4)}ms per log`);
      console.log(`Logger stats:`, logger.getStats());

      expect(totalTime / iterations).toBeLessThan(0.2); // Fast logging with console output
    });

    it('should show debug logging performance with early returns', async () => {
      const iterations = 10000;

      // Debug logs should be very fast due to early returns in production
      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        logger.debug('Debug message', { iteration: i });
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      console.log(`\nDebug Logger Performance:`);
      console.log(
        `Time for ${iterations} debug calls: ${totalTime.toFixed(2)}ms`
      );
      console.log(
        `Average: ${(totalTime / iterations).toFixed(4)}ms per debug log`
      );

      // Debug logs should be extremely fast due to early returns
      expect(totalTime / iterations).toBeLessThan(0.01);
    });
  });

  describe('End-to-End Performance', () => {
    it('should measure complete request processing performance', async () => {
      const handler = new Handler()
        .use(new ErrorHandlerMiddleware())
        .use(new BodyParserMiddleware())
        .use(new BodyValidationMiddleware(testSchema))
        .use(new AuthenticationMiddleware(mockTokenVerifier))
        .use(new ResponseWrapperMiddleware())
        .handle(async (context) => {
          // Simulate some business logic
          const user = context.user as { userId: string };
          const body = context.req.validatedBody as z.infer<typeof testSchema>;

          context.res.json({
            message: `Hello ${body.name}`,
            userId: user.userId,
            processedAt: new Date().toISOString(),
          });
        });

      const testData = {
        name: 'John Doe',
        email: 'john@example.com',
        age: 30,
      };

      const iterations = 500;
      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        const { req, res } = createMockRequestResponse(testData);
        await handler.executeGeneric(req, res);
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const averageTime = totalTime / iterations;
      const requestsPerSecond = 1000 / averageTime;

      console.log(`\nEnd-to-End Performance:`);
      console.log(`Total time: ${totalTime.toFixed(2)}ms`);
      console.log(`Average time per request: ${averageTime.toFixed(3)}ms`);
      console.log(`Requests per second: ${requestsPerSecond.toFixed(0)}`);

      // Performance targets
      expect(averageTime).toBeLessThan(8); // Should be under 8ms per request
      expect(requestsPerSecond).toBeGreaterThan(125); // Should handle 125+ RPS
    });
  });

  describe('Memory Performance', () => {
    it('should demonstrate memory efficiency with object pooling', () => {
      const initialMemory = process.memoryUsage();

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const iterations = 1000;

      // Simulate memory-intensive operations
      for (let i = 0; i < iterations; i++) {
        logger.info('Memory test', { iteration: i, data: 'x'.repeat(100) });
      }

      const finalMemory = process.memoryUsage();
      const heapIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      console.log(`\nMemory Performance:`);
      console.log(
        `Initial heap: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`
      );
      console.log(
        `Final heap: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`
      );
      console.log(
        `Heap increase: ${(heapIncrease / 1024 / 1024).toFixed(2)}MB`
      );
      console.log(
        `Per operation: ${(heapIncrease / iterations).toFixed(0)} bytes`
      );

      // Memory increase should be reasonable - console.log creates temporary strings
      expect(heapIncrease / iterations).toBeLessThan(20000); // Less than 20KB per operation (accounting for console output)
    });
  });
});
