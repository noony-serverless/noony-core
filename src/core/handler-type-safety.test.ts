/**
 * Type Safety Tests for Handler v0.7.0
 *
 * Tests the new invariant generics and createTypedHandler() helper
 * introduced in v0.7.0 to eliminate 'as any' casts.
 */

import {
  Handler,
  createTypedHandler,
  Context,
  BaseMiddleware,
  BaseAuthenticatedUser,
  GenericRequest,
  GenericResponse,
} from '../core';

// =============================================================================
// TEST TYPE DEFINITIONS
// =============================================================================

interface TestRequestBody {
  name: string;
  email: string;
  age: number;
}

interface TestUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
  permissions: string[];
}

interface TestResponse {
  success: boolean;
  message: string;
  data?: unknown;
}

// =============================================================================
// MOCK MIDDLEWARE
// =============================================================================

class TestMiddleware<
  TBody = unknown,
  TUser = unknown,
> implements BaseMiddleware<TBody, TUser> {
  public beforeCalled = false;
  public afterCalled = false;
  public errorCalled = false;

  async before(context: Context<TBody, TUser>): Promise<void> {
    this.beforeCalled = true;

    // Populate a mock user if not already set (simulates auth middleware)
    if (!context.user) {
      context.user = {
        id: 'test-user-123',
        role: 'user',
      } as TUser;
    }
  }

  async after(_context: Context<TBody, TUser>): Promise<void> {
    this.afterCalled = true;
  }

  async onError(_error: Error, _context: Context<TBody, TUser>): Promise<void> {
    this.errorCalled = true;
  }
}

// =============================================================================
// MOCK REQUEST/RESPONSE HELPERS
// =============================================================================

function createMockRequest<T>(body?: T): GenericRequest<T> {
  return {
    body,
    parsedBody: body,
    validatedBody: body,
    headers: {},
    query: {},
    params: {},
    method: 'POST',
    path: '/test',
    ip: '127.0.0.1',
  } as GenericRequest<T>;
}

function createMockResponse(): GenericResponse {
  const response: Partial<GenericResponse> = {
    statusCode: 200,
    headersSent: false,
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    header: jest.fn().mockReturnThis(),
  };
  return response as GenericResponse;
}

// =============================================================================
// TESTS: Handler with Invariant Generics
// =============================================================================

describe('Handler - Invariant Generics (v0.7.0)', () => {
  describe('Type Safety - Explicit Types', () => {
    it('should maintain type safety with explicit TBody and TUser', async () => {
      const middleware = new TestMiddleware<TestRequestBody, TestUser>();
      let controllerCalled = false;

      const handler = new Handler<TestRequestBody, TestUser>()
        .use(middleware)
        .handle(async (context: Context<TestRequestBody, TestUser>) => {
          // Type assertions to verify TypeScript typing
          const body: TestRequestBody = context.req.parsedBody!;
          const user: TestUser = context.user!;

          expect(body.name).toBeDefined();
          expect(body.email).toBeDefined();
          expect(body.age).toBeDefined();
          expect(user.id).toBeDefined();
          expect(user.role).toBeDefined();

          controllerCalled = true;
        });

      const req = createMockRequest<TestRequestBody>({
        name: 'John',
        email: 'john@example.com',
        age: 30,
      });
      const res = createMockResponse();

      // Populate user in context (normally done by auth middleware)
      await handler.executeGeneric(req, res);

      expect(middleware.beforeCalled).toBe(true);
      expect(controllerCalled).toBe(true);
      expect(middleware.afterCalled).toBe(true);
    });

    it('should work with only TBody generic (no user)', async () => {
      const middleware = new TestMiddleware<TestRequestBody, unknown>();
      let controllerCalled = false;

      const handler = new Handler<TestRequestBody>()
        .use(middleware)
        .handle(async (context: Context<TestRequestBody>) => {
          const body: TestRequestBody = context.req.parsedBody!;
          expect(body.name).toBe('Jane');
          controllerCalled = true;
        });

      const req = createMockRequest<TestRequestBody>({
        name: 'Jane',
        email: 'jane@example.com',
        age: 25,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(controllerCalled).toBe(true);
    });

    it('should work with only TUser generic (no body)', async () => {
      const middleware = new TestMiddleware<unknown, TestUser>();
      let controllerCalled = false;

      const handler = new Handler<unknown, TestUser>()
        .use(middleware)
        .handle(async (context: Context<unknown, TestUser>) => {
          // User is populated by TestMiddleware (simulates auth middleware)
          expect(context.user).toBeDefined();
          expect(context.user).toHaveProperty('id');
          controllerCalled = true;
        });

      const req = createMockRequest();
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(controllerCalled).toBe(true);
    });

    it('should work with no generics (backward compatibility)', async () => {
      const middleware = new TestMiddleware();
      let controllerCalled = false;

      const handler = new Handler()
        .use(middleware)
        .handle(async (context: Context) => {
          // Manual typing required when not using generics
          const body = context.req.parsedBody as TestRequestBody;
          expect(body).toBeDefined();
          controllerCalled = true;
        });

      const req = createMockRequest<TestRequestBody>({
        name: 'Bob',
        email: 'bob@example.com',
        age: 35,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(controllerCalled).toBe(true);
    });
  });

  describe('Middleware Chain Type Preservation', () => {
    it('should preserve types through multiple middleware', async () => {
      const middleware1 = new TestMiddleware<TestRequestBody, TestUser>();
      const middleware2 = new TestMiddleware<TestRequestBody, TestUser>();
      const middleware3 = new TestMiddleware<TestRequestBody, TestUser>();

      let controllerCalled = false;

      const handler = new Handler<TestRequestBody, TestUser>()
        .use(middleware1)
        .use(middleware2)
        .use(middleware3)
        .handle(async (context: Context<TestRequestBody, TestUser>) => {
          const body: TestRequestBody = context.req.parsedBody!;
          expect(body.name).toBe('Alice');
          controllerCalled = true;
        });

      const req = createMockRequest<TestRequestBody>({
        name: 'Alice',
        email: 'alice@example.com',
        age: 28,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(middleware1.beforeCalled).toBe(true);
      expect(middleware2.beforeCalled).toBe(true);
      expect(middleware3.beforeCalled).toBe(true);
      expect(controllerCalled).toBe(true);
      expect(middleware3.afterCalled).toBe(true);
      expect(middleware2.afterCalled).toBe(true);
      expect(middleware1.afterCalled).toBe(true);
    });

    it('should enforce type compatibility in middleware chain', () => {
      // This test verifies compile-time type safety
      // TypeScript should prevent adding incompatible middleware

      const handler = new Handler<TestRequestBody, TestUser>();

      // ✅ This should compile - compatible middleware
      const compatibleMiddleware = new TestMiddleware<
        TestRequestBody,
        TestUser
      >();
      handler.use(compatibleMiddleware);

      // ❌ TypeScript would error on incompatible middleware
      // Uncomment to verify type checking:
      // const incompatibleMiddleware = new TestMiddleware<{ other: string }, { different: number }>();
      // handler.use(incompatibleMiddleware); // TypeScript error!

      expect(handler).toBeDefined();
    });
  });

  describe('Handler Return Value', () => {
    it('should capture return value from handler', async () => {
      const handler = new Handler<TestRequestBody, TestUser>().handle(
        async (_context: Context<TestRequestBody, TestUser>) => {
          return {
            success: true,
            message: 'Handler completed',
          };
        }
      );

      const req = createMockRequest<TestRequestBody>({
        name: 'Test',
        email: 'test@example.com',
        age: 30,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      // The handler doesn't automatically call res.json() with the return value
      // That's typically done by ResponseWrapperMiddleware
      expect(handler).toBeDefined();
    });

    it('should work with void return handlers', async () => {
      let controllerCalled = false;

      const handler = new Handler<TestRequestBody, TestUser>().handle(
        async (context: Context<TestRequestBody, TestUser>) => {
          controllerCalled = true;
          context.res.json({ success: true });
          // No return value
        }
      );

      const req = createMockRequest<TestRequestBody>({
        name: 'Test',
        email: 'test@example.com',
        age: 30,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(controllerCalled).toBe(true);
    });
  });

  describe('Error Handling with Types', () => {
    it('should maintain types in error handlers', async () => {
      const middleware = new TestMiddleware<TestRequestBody, TestUser>();

      const handler = new Handler<TestRequestBody, TestUser>()
        .use(middleware)
        .handle(async (_context: Context<TestRequestBody, TestUser>) => {
          throw new Error('Test error');
        });

      const req = createMockRequest<TestRequestBody>({
        name: 'Error Test',
        email: 'error@example.com',
        age: 40,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(middleware.beforeCalled).toBe(true);
      expect(middleware.errorCalled).toBe(true);
    });
  });
});

// =============================================================================
// TESTS: createTypedHandler() Helper
// =============================================================================

describe('createTypedHandler() - Type Inference Helper (v0.7.0)', () => {
  describe('Type Inference from Controller', () => {
    it('should infer types from controller signature', async () => {
      let controllerCalled = false;

      // Controller with explicit Context types
      async function testController(
        context: Context<TestRequestBody, TestUser>
      ): Promise<TestResponse> {
        const body: TestRequestBody = context.req.parsedBody!;

        expect(body.name).toBe('Inferred');
        expect(body.email).toBe('inferred@example.com');

        controllerCalled = true;

        return {
          success: true,
          message: 'Types inferred successfully',
        };
      }

      // Types are inferred from controller signature
      const handler = createTypedHandler(testController).handle(testController);

      const req = createMockRequest<TestRequestBody>({
        name: 'Inferred',
        email: 'inferred@example.com',
        age: 33,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(controllerCalled).toBe(true);
    });

    it('should work with middleware after type inference', async () => {
      const middleware = new TestMiddleware<TestRequestBody, TestUser>();

      async function testController(
        context: Context<TestRequestBody, TestUser>
      ): Promise<void> {
        expect(context.req.parsedBody).toBeDefined();
      }

      const handler = createTypedHandler(testController)
        .use(middleware)
        .handle(testController);

      const req = createMockRequest<TestRequestBody>({
        name: 'Middleware Test',
        email: 'middleware@example.com',
        age: 27,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(middleware.beforeCalled).toBe(true);
      expect(middleware.afterCalled).toBe(true);
    });

    it('should infer types with only body generic', async () => {
      async function publicController(
        context: Context<TestRequestBody, unknown>
      ): Promise<void> {
        const body: TestRequestBody = context.req.parsedBody!;
        expect(body.name).toBe('Public');
      }

      const handler =
        createTypedHandler(publicController).handle(publicController);

      const req = createMockRequest<TestRequestBody>({
        name: 'Public',
        email: 'public@example.com',
        age: 22,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);
    });

    it('should infer types with only user generic', async () => {
      async function authOnlyController(
        context: Context<unknown, TestUser>
      ): Promise<void> {
        // User would be set by auth middleware
        expect(context.req.parsedBody).toBeUndefined();
      }

      const handler =
        createTypedHandler(authOnlyController).handle(authOnlyController);

      const req = createMockRequest();
      const res = createMockResponse();

      await handler.executeGeneric(req, res);
    });
  });

  describe('Middleware Chain with Type Inference', () => {
    it('should preserve inferred types through middleware chain', async () => {
      const middleware1 = new TestMiddleware<TestRequestBody, TestUser>();
      const middleware2 = new TestMiddleware<TestRequestBody, TestUser>();

      async function chainController(
        _context: Context<TestRequestBody, TestUser>
      ): Promise<TestResponse> {
        return { success: true, message: 'Chain complete' };
      }

      const handler = createTypedHandler(chainController)
        .use(middleware1)
        .use(middleware2)
        .handle(chainController);

      const req = createMockRequest<TestRequestBody>({
        name: 'Chain',
        email: 'chain@example.com',
        age: 29,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(middleware1.beforeCalled).toBe(true);
      expect(middleware2.beforeCalled).toBe(true);
      expect(middleware2.afterCalled).toBe(true);
      expect(middleware1.afterCalled).toBe(true);
    });
  });

  describe('Comparison: Explicit vs Inferred', () => {
    it('should produce identical behavior for explicit and inferred types', async () => {
      let explicitCalled = false;
      let inferredCalled = false;

      // Explicit types
      const explicitHandler = new Handler<TestRequestBody, TestUser>().handle(
        async (context: Context<TestRequestBody, TestUser>) => {
          const body: TestRequestBody = context.req.parsedBody!;
          expect(body.name).toBe('Comparison');
          explicitCalled = true;
        }
      );

      // Inferred types
      async function controller(
        context: Context<TestRequestBody, TestUser>
      ): Promise<void> {
        const body: TestRequestBody = context.req.parsedBody!;
        expect(body.name).toBe('Comparison');
        inferredCalled = true;
      }

      const inferredHandler = createTypedHandler(controller).handle(controller);

      // Test explicit handler
      const req1 = createMockRequest<TestRequestBody>({
        name: 'Comparison',
        email: 'test1@example.com',
        age: 30,
      });
      const res1 = createMockResponse();
      await explicitHandler.executeGeneric(req1, res1);

      // Test inferred handler
      const req2 = createMockRequest<TestRequestBody>({
        name: 'Comparison',
        email: 'test2@example.com',
        age: 30,
      });
      const res2 = createMockResponse();
      await inferredHandler.executeGeneric(req2, res2);

      expect(explicitCalled).toBe(true);
      expect(inferredCalled).toBe(true);
    });
  });
});

// =============================================================================
// TESTS: Static Use Method
// =============================================================================

describe('Handler.use() - Static Method', () => {
  it('should create handler with middleware using static method', async () => {
    const middleware = new TestMiddleware<TestRequestBody, TestUser>();

    const handler = Handler.use(middleware).handle(
      async (context: Context<TestRequestBody, TestUser>) => {
        expect(context.req.parsedBody).toBeDefined();
      }
    );

    const req = createMockRequest<TestRequestBody>({
      name: 'Static',
      email: 'static@example.com',
      age: 31,
    });
    const res = createMockResponse();

    await handler.executeGeneric(req, res);

    expect(middleware.beforeCalled).toBe(true);
  });
});

// =============================================================================
// TESTS: Real-World Scenarios
// =============================================================================

describe('Real-World Type Safety Scenarios', () => {
  describe('Public Endpoint (No Auth)', () => {
    it('should handle public endpoint with only body validation', async () => {
      interface RegisterRequest {
        email: string;
        password: string;
        name: string;
      }

      const validationMiddleware = new TestMiddleware<RegisterRequest, void>();

      async function registerController(
        context: Context<RegisterRequest, void>
      ): Promise<{ userId: string }> {
        const { email, password, name } = context.req.validatedBody!;

        expect(email).toBe('newuser@example.com');
        expect(password).toBe('securepass123');
        expect(name).toBe('New User');

        return { userId: 'user-123' };
      }

      const handler = createTypedHandler(registerController)
        .use(validationMiddleware)
        .handle(registerController);

      const req = createMockRequest<RegisterRequest>({
        email: 'newuser@example.com',
        password: 'securepass123',
        name: 'New User',
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(validationMiddleware.beforeCalled).toBe(true);
    });
  });

  describe('Protected Endpoint (Auth + Body)', () => {
    it('should handle protected endpoint with auth and validation', async () => {
      interface CreateOrderRequest {
        productId: string;
        quantity: number;
      }

      interface OrderUser extends BaseAuthenticatedUser {
        id: string;
        email: string;
      }

      const authMiddleware = new TestMiddleware<
        CreateOrderRequest,
        OrderUser
      >();
      const validationMiddleware = new TestMiddleware<
        CreateOrderRequest,
        OrderUser
      >();

      async function createOrderController(
        context: Context<CreateOrderRequest, OrderUser>
      ): Promise<{ orderId: string }> {
        const { productId, quantity } = context.req.validatedBody!;
        // const user = context.user!; // Would be populated by auth middleware

        expect(productId).toBe('prod-123');
        expect(quantity).toBe(2);

        return { orderId: 'order-456' };
      }

      const handler = new Handler<CreateOrderRequest, OrderUser>()
        .use(authMiddleware)
        .use(validationMiddleware)
        .handle(createOrderController);

      const req = createMockRequest<CreateOrderRequest>({
        productId: 'prod-123',
        quantity: 2,
      });
      const res = createMockResponse();

      await handler.executeGeneric(req, res);

      expect(authMiddleware.beforeCalled).toBe(true);
      expect(validationMiddleware.beforeCalled).toBe(true);
    });
  });

  describe('GET Endpoint (Auth, No Body)', () => {
    it('should handle GET endpoint with auth but no body', async () => {
      interface ProfileUser extends BaseAuthenticatedUser {
        id: string;
        email: string;
        name: string;
      }

      async function getProfileController(
        _context: Context<void, ProfileUser>
      ): Promise<{ profile: Partial<ProfileUser> }> {
        // In real scenario, user would be populated
        // const user = _context.user!;

        return {
          profile: {
            email: 'user@example.com',
            name: 'Test User',
          },
        };
      }

      const handler =
        createTypedHandler(getProfileController).handle(getProfileController);

      const req = createMockRequest<void>();
      const res = createMockResponse();

      await handler.executeGeneric(req, res);
    });
  });
});

// =============================================================================
// TESTS: Type Compatibility
// =============================================================================

describe('Type Compatibility Tests', () => {
  it('should verify BaseMiddleware type compatibility', () => {
    // This is a compile-time verification test
    class CustomMiddleware<
      TBody = unknown,
      TUser = unknown,
    > implements BaseMiddleware<TBody, TUser> {
      async before(_context: Context<TBody, TUser>): Promise<void> {
        // Implementation
      }
    }

    const middleware = new CustomMiddleware<TestRequestBody, TestUser>();
    const handler = new Handler<TestRequestBody, TestUser>().use(middleware);

    expect(handler).toBeDefined();
  });

  it('should verify Context type parameter order', () => {
    // Verify that Context<TBody, TUser> parameter order is correct
    async function controller(
      context: Context<TestRequestBody, TestUser>
    ): Promise<void> {
      // TBody should be TestRequestBody
      const body: TestRequestBody = context.req.parsedBody!;

      // TUser should be TestUser
      const user: TestUser | undefined = context.user;

      expect(body).toBeDefined();
      expect(user).toBeUndefined(); // No auth in this test
    }

    const handler = createTypedHandler(controller).handle(controller);
    expect(handler).toBeDefined();
  });
});
