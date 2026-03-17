# Tutorial: Testing Noony Handlers

Step-by-step guide to testing Noony handlers, including full pipeline tests, middleware isolation tests, service mocking with DI, and error path testing.

**Related links:** [Error Handling](../guides/error-handling.md) | [Custom Middleware](../guides/custom-middleware.md) | [Dependency Injection](../guides/dependency-injection.md)

## Prerequisites

- Jest configured with `ts-jest`
- `@noony-serverless/core` installed
- A Noony handler to test

---

## What You Will Learn

1. How to create mock request and response objects
2. How to test a complete handler pipeline with `executeGeneric()`
3. How to test individual middleware hooks in isolation
4. How to inject mocked services via `DependencyInjectionMiddleware`
5. How to test error paths and HTTP status mapping

## Key Rule: executeGeneric() vs execute()

In tests, always use `handler.executeGeneric(mockReq, mockRes)`. The `handler.execute()` method is for Cloud Functions production only -- it expects Cloud Functions' native request/response objects.

## Step 1: Create Mock Factories

Every test needs mock request and response objects that satisfy the `GenericRequest` and `GenericResponse` interfaces.

```typescript
// test/helpers/mocks.ts

export function createMockRequest<T>(overrides: Partial<any> = {}): any {
  return {
    method: 'POST',
    url: '/api/test',
    path: '/api/test',
    headers: {},
    query: {},
    params: {},
    body: undefined,
    parsedBody: undefined,
    ...overrides
  };
}

export function createMockResponse(): any {
  let statusCode = 200;
  let responseData: any = null;

  return {
    statusCode,
    headersSent: false,
    status: function(code: number) {
      statusCode = code;
      this.statusCode = code;
      return this;
    },
    json: function(data: any) {
      responseData = data;
      this.headersSent = true;
      return this;
    },
    send: function(data: any) {
      responseData = data;
      this.headersSent = true;
      return this;
    },
    header: function(name: string, value: string) {
      return this;
    },
    end: function() {
      this.headersSent = true;
    },
    // Test assertion helpers
    getData: () => responseData,
    getStatus: () => statusCode
  };
}
```

Important details:

- `parsedBody` must be set when testing handlers that use `BodyValidationMiddleware`. The parser middleware populates this field before validation runs.
- The `status()` method must return `this` for chaining (e.g., `res.status(201).json(...)`).
- The `getData()` and `getStatus()` helpers make assertions cleaner.

## Step 2: Full Handler Chain Testing

Test the complete middleware pipeline end-to-end. This is the most common test type and catches integration issues between middlewares.

```typescript
import { Handler, Context } from '@noony-serverless/core';
import {
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  ResponseWrapperMiddleware
} from '@noony-serverless/core';
import { z } from 'zod';
import { createMockRequest, createMockResponse } from './helpers/mocks';

const createUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email()
});

type CreateUserRequest = z.infer<typeof createUserSchema>;
type AuthUser = { id: string; role: 'admin' | 'user' };

describe('UserHandler - Full Chain', () => {
  let mockUserService: { createUser: jest.Mock };
  let handler: any;

  beforeEach(() => {
    mockUserService = {
      createUser: jest.fn().mockResolvedValue({ id: '123', name: 'Alice', email: 'alice@example.com' })
    };

    handler = new Handler<CreateUserRequest, AuthUser>()
      .use(new ErrorHandlerMiddleware())
      .use(new BodyValidationMiddleware(createUserSchema))
      .use(new ResponseWrapperMiddleware())
      .handle(async (context: Context<CreateUserRequest, AuthUser>) => {
        const { name, email } = context.req.validatedBody!;
        const user = await mockUserService.createUser({ name, email });
        return { data: user };
      });
  });

  it('should create user successfully with valid data', async () => {
    const mockReq = createMockRequest({
      body: { name: 'Alice', email: 'alice@example.com' },
      parsedBody: { name: 'Alice', email: 'alice@example.com' }
    });
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(200);
    const data = mockRes.getData();
    expect(data.success).toBe(true);
    expect(data.payload.data.id).toBe('123');
    expect(data.payload.data.email).toBe('alice@example.com');
  });

  it('should return 400 for invalid email', async () => {
    const mockReq = createMockRequest({
      body: { name: 'Bob', email: 'not-an-email' },
      parsedBody: { name: 'Bob', email: 'not-an-email' }
    });
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(400);
    const data = mockRes.getData();
    expect(data.success).toBe(false);
    expect(data.error.code).toBe('VALIDATION_ERROR');
  });

  it('should return 400 for missing required fields', async () => {
    const mockReq = createMockRequest({
      body: { email: 'alice@example.com' },
      parsedBody: { email: 'alice@example.com' }
    });
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(400);
  });
});
```

### Why Both body and parsedBody?

In a real request, `BodyParserMiddleware` reads `body` and writes `parsedBody`. In tests, when you skip `BodyParserMiddleware` or include it in the chain, set both fields to ensure the validation middleware has data to work with.

## Step 3: Testing Middleware in Isolation

Test a single middleware without running the full handler chain. Use `createContext()` to build a minimal context object and call lifecycle hooks directly.

```typescript
import { createContext } from '@noony-serverless/core';
import { createMockRequest, createMockResponse } from './helpers/mocks';

class TimingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    context.businessData.set('startTime', Date.now());
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    const startTime = context.businessData.get('startTime') as number;
    const elapsed = Date.now() - startTime;
    console.log(`Request took ${elapsed}ms`);
  }
}

describe('TimingMiddleware', () => {
  it('should set start time in businessData', async () => {
    const middleware = new TimingMiddleware();
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    await middleware.before(context);

    expect(context.businessData.get('startTime')).toBeDefined();
    expect(typeof context.businessData.get('startTime')).toBe('number');
  });

  it('should log elapsed time in after()', async () => {
    const middleware = new TimingMiddleware();
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    await middleware.before(context);
    await new Promise(r => setTimeout(r, 50));
    await middleware.after(context);

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
```

## Step 4: Testing with DI Service Mocking

Use `DependencyInjectionMiddleware` to inject mocked services into the handler under test. This keeps tests isolated from real databases and external APIs.

```typescript
import {
  Handler,
  DependencyInjectionMiddleware,
  ErrorHandlerMiddleware,
  getService
} from '@noony-serverless/core';
import { createMockRequest, createMockResponse } from './helpers/mocks';

class UserService {
  async getUser(id: string) {
    throw new Error('Must be mocked in tests');
  }
}

describe('Handler with Dependency Injection', () => {
  it('should resolve mocked service from container', async () => {
    const mockUserService = {
      getUser: jest.fn().mockResolvedValue({ id: '123', name: 'Alice' })
    };

    const handler = new Handler<void, void>()
      .use(new ErrorHandlerMiddleware())
      .use(new DependencyInjectionMiddleware(
        [{ id: UserService, value: mockUserService }],
        { scope: 'local' }
      ))
      .handle(async (context) => {
        const userService = getService(context, UserService);
        const user = await userService.getUser('123');
        return { data: user };
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockUserService.getUser).toHaveBeenCalledWith('123');
  });

  it('should isolate mocks between tests', async () => {
    const mockService = {
      getUser: jest.fn().mockResolvedValue({ id: '456', name: 'Bob' })
    };

    const handler = new Handler<void, void>()
      .use(new DependencyInjectionMiddleware(
        [{ id: UserService, value: mockService }],
        { scope: 'local' }
      ))
      .handle(async (context) => {
        const service = getService(context, UserService);
        return await service.getUser('456');
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockService.getUser).toHaveBeenCalledWith('456');
  });
});
```

The `{ scope: 'local' }` option ensures the mock service is scoped to the request, avoiding pollution of the global container across tests.

## Step 5: Testing Error Paths

Verify that error classes map to the correct HTTP status codes and that the response format matches expectations.

```typescript
import {
  Handler,
  ErrorHandlerMiddleware,
  NotFoundError,
  InternalServerError
} from '@noony-serverless/core';
import { createMockRequest, createMockResponse } from './helpers/mocks';

describe('Error Handling', () => {
  it('should format NotFoundError as 404', async () => {
    const handler = new Handler<void, void>()
      .use(new ErrorHandlerMiddleware())
      .handle(async () => {
        throw new NotFoundError('User not found');
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(404);
    const data = mockRes.getData();
    expect(data.success).toBe(false);
    expect(data.error.code).toBe('NOT_FOUND');
  });

  it('should catch unexpected errors as 500', async () => {
    const handler = new Handler<void, void>()
      .use(new ErrorHandlerMiddleware())
      .handle(async () => {
        throw new Error('Something broke');
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(500);
    const data = mockRes.getData();
    expect(data.success).toBe(false);
    expect(data.error.code).toBe('INTERNAL_SERVER_ERROR');
  });

  it('should preserve error cause chaining', async () => {
    const handler = new Handler<void, void>()
      .use(new ErrorHandlerMiddleware())
      .handle(async () => {
        try {
          throw new Error('API unreachable');
        } catch (err) {
          throw new InternalServerError('External API failed', err as Error);
        }
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(500);
    const data = mockRes.getData();
    expect(data.error.cause).toBeDefined();
  });
});
```

### Error Class to HTTP Status Mapping

| Error Class | HTTP Status | Error Code |
|-------------|-------------|------------|
| `ValidationError` | 400 | `VALIDATION_ERROR` |
| `UnauthorizedError` | 401 | `UNAUTHORIZED` |
| `ForbiddenError` | 403 | `FORBIDDEN` |
| `NotFoundError` | 404 | `NOT_FOUND` |
| `ConflictError` | 409 | `CONFLICT` |
| `InternalServerError` | 500 | `INTERNAL_SERVER_ERROR` |
| `Error` (untyped) | 500 | `INTERNAL_SERVER_ERROR` |

## Understanding Response Wrapping in Tests

When `ResponseWrapperMiddleware` is in the pipeline, the handler's return value is wrapped in a standard envelope. Your assertions must account for this.

```typescript
// Without ResponseWrapperMiddleware
// handler returns: { name: 'Alice' }
// mockRes.getData() => { name: 'Alice' }

// With ResponseWrapperMiddleware
// handler returns: { name: 'Alice' }
// mockRes.getData() => { success: true, payload: { name: 'Alice' }, timestamp: '...' }
```

If you forget about wrapping, your assertions will fail looking for `data.name` when the actual path is `data.payload.name`.

## Test Helpers Summary

| Helper | Purpose |
|--------|---------|
| `createMockRequest(overrides)` | Build a `GenericRequest` with sensible defaults |
| `createMockResponse()` | Build a `GenericResponse` with `getData()`/`getStatus()` helpers |
| `createContext(req, res, user)` | Build a `Context` for middleware isolation testing |
| `handler.executeGeneric(req, res)` | Run the full pipeline with mock objects |

## Anti-Patterns

### Using execute() instead of executeGeneric()

```typescript
// WRONG -- execute() expects Cloud Functions native objects
await handler.execute(req, res);

// CORRECT -- executeGeneric() works with mock objects
await handler.executeGeneric(mockReq, mockRes);
```

### Using TypeDI Container directly

```typescript
// WRONG -- pollutes global TypeDI container, leaks between tests
Container.reset();
Container.set(UserService, mockUserService);

// CORRECT -- use framework DI middleware with local scope
.use(new DependencyInjectionMiddleware(
  [{ id: UserService, value: mockUserService }],
  { scope: 'local' }
))
```

### Forgetting to set parsedBody

```typescript
// WRONG -- BodyValidationMiddleware has nothing to validate
const mockReq = createMockRequest({
  body: { name: 'Alice' }
});

// CORRECT -- both body and parsedBody populated
const mockReq = createMockRequest({
  body: { name: 'Alice' },
  parsedBody: { name: 'Alice' }
});
```

### Asserting on unwrapped data when ResponseWrapperMiddleware is present

```typescript
// WRONG -- assumes no wrapping
expect(mockRes.getData().name).toBe('Alice');

// CORRECT -- accounts for standard envelope
expect(mockRes.getData().success).toBe(true);
expect(mockRes.getData().payload.name).toBe('Alice');
```

## See Also

- [Error Handling](../guides/error-handling.md) -- Error classes and status mapping
- [Custom Middleware](../guides/custom-middleware.md) -- Building testable middleware
- [Dependency Injection](../guides/dependency-injection.md) -- DI mocking patterns
- [Local Dev with Fastify](./03-local-dev-with-fastify.md) -- Integration testing with Fastify inject
