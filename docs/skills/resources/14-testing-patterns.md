# Resource: Handler Testing Patterns

## Pattern 1: Full Handler Chain Testing

Testing complete middleware pipeline with mock request/response.

```typescript
import { Handler, createContext, Context } from '@noony-serverless/core';
import { ErrorHandlerMiddleware, BodyValidationMiddleware, ResponseWrapperMiddleware } from '@noony-serverless/core';
import { z } from 'zod';

// Mock helper factories
function createMockRequest<T>(overrides: Partial<any> = {}): any {
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

function createMockResponse(): any {
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

// Define schema and types
const createUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email()
});

type CreateUserRequest = z.infer<typeof createUserSchema>;
type AuthUser = { id: string; role: 'admin' | 'user' };

// Mock service
class MockUserService {
  async createUser(data: CreateUserRequest) {
    return { id: '123', ...data };
  }
}

// Test suite
describe('UserHandler - Full Chain', () => {
  let mockUserService: MockUserService;
  let handler: Handler<CreateUserRequest, AuthUser>;

  beforeEach(() => {
    mockUserService = new MockUserService();

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
    const mockReq = createMockRequest<CreateUserRequest>({
      body: { name: 'Alice', email: 'alice@example.com' },
      parsedBody: { name: 'Alice', email: 'alice@example.com' }
    });

    const mockRes = createMockResponse();

    // Execute via executeGeneric (not execute!)
    await handler.executeGeneric(mockReq, mockRes);

    // Assert: check status and response shape
    expect(mockRes.getStatus()).toBe(200);
    const data = mockRes.getData();
    expect(data.success).toBe(true);
    expect(data.payload.data.id).toBe('123');
    expect(data.payload.data.email).toBe('alice@example.com');
  });

  it('should return 400 for invalid email', async () => {
    const mockReq = createMockRequest<CreateUserRequest>({
      body: { name: 'Bob', email: 'not-an-email' },
      parsedBody: { name: 'Bob', email: 'not-an-email' }
    });

    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    // BodyValidationMiddleware should trigger ErrorHandlerMiddleware
    expect(mockRes.getStatus()).toBe(400);
    const data = mockRes.getData();
    expect(data.success).toBe(false);
    expect(data.error.code).toBe('VALIDATION_ERROR');
  });

  it('should return 400 for missing name', async () => {
    const mockReq = createMockRequest<CreateUserRequest>({
      body: { email: 'alice@example.com' },
      parsedBody: { email: 'alice@example.com' }
    });

    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(400);
  });
});
```

## Pattern 2: Middleware in Isolation

Testing a single middleware without full handler chain.

```typescript
import { BaseMiddleware, Context, createContext } from '@noony-serverless/core';

// Custom timing middleware
class TimingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    context.businessData.set('startTime', Date.now());
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    const startTime = context.businessData.get('startTime') as number;
    const elapsed = Date.now() - startTime;
    console.log(`Request ${context.requestId} took ${elapsed}ms`);
  }
}

// Test it in isolation
describe('TimingMiddleware', () => {
  it('should set start time in businessData', async () => {
    const middleware = new TimingMiddleware();

    // Create a minimal context
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    // Call before() directly
    await middleware.before(context);

    // Assert
    expect(context.businessData.get('startTime')).toBeDefined();
    expect(typeof context.businessData.get('startTime')).toBe('number');
  });

  it('should log elapsed time in after()', async () => {
    const middleware = new TimingMiddleware();
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    // Simulate time passage
    await middleware.before(context);
    await new Promise(r => setTimeout(r, 50));  // Wait 50ms
    await middleware.after(context);

    // Assert
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('took'),
      expect.stringContaining('ms')
    );

    consoleSpy.mockRestore();
  });
});
```

## Pattern 3: Testing with DI Service Mocking

Using `DependencyInjectionMiddleware` to inject mocked services.

```typescript
import { DependencyInjectionMiddleware, getService } from '@noony-serverless/core';

class UserService {
  async getUser(id: string) {
    // Real implementation would query a database
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
        const userService = getService(context, UserService);  // Type-safe
        const user = await userService.getUser('123');
        return { data: user };
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockUserService.getUser).toHaveBeenCalledWith('123');
  });
});
```

## Pattern 4: Testing Error Handling

Testing error paths and error-to-HTTP-status mapping.

```typescript
import { NotFoundError, ValidationError, InternalServerError } from '@noony-serverless/core';

describe('Error Handling', () => {
  it('should catch and format NotFoundError as 404', async () => {
    const handler = new Handler<void, void>()
      .use(new ErrorHandlerMiddleware())
      .handle(async (context) => {
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
      .handle(async (context) => {
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

  it('should wrap errors with cause chaining', async () => {
    const handler = new Handler<void, void>()
      .use(new ErrorHandlerMiddleware())
      .handle(async (context) => {
        try {
          // Simulate external API failure
          throw new Error('API unreachable');
        } catch (err) {
          // Wrap with cause chaining
          throw new InternalServerError('External API failed', err as Error);
        }
      });

    const mockReq = createMockRequest();
    const mockRes = createMockResponse();

    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(500);
    const data = mockRes.getData();
    expect(data.error.cause).toBeDefined();  // Cause chaining preserved
  });
});
```

## Key Test Helpers Summary

### createMockRequest()
```typescript
// Returns GenericRequest with chainable methods
const req = createMockRequest({
  body: { name: 'test' },
  parsedBody: { name: 'test' },
  params: { userId: '123' },
  query: { page: '1' }
});
```

### createMockResponse()
```typescript
// Returns GenericResponse with status, json, send methods
const res = createMockResponse();
res.status(200).json({ data: 'test' });
expect(res.getStatus()).toBe(200);
expect(res.getData()).toEqual({ data: 'test' });
```

### createContext()
```typescript
// Creates Context from req/res + user data
const context = createContext(mockReq, mockRes, { id: '123' });
expect(context.req.method).toBe('POST');
expect(context.user.id).toBe('123');
```

## Anti-Patterns to Avoid

### ❌ Using execute() Instead of executeGeneric()

```typescript
// WRONG - execute() is for GCP Cloud Functions production
const req = { body: { name: 'test' } };
const res = { json: jest.fn() };
await handler.execute(req, res);  // ❌ Wrong API for unit tests

// CORRECT - executeGeneric() with proper adapters
const mockReq = createMockRequest({ body: { name: 'test' } });
const mockRes = createMockResponse();
await handler.executeGeneric(mockReq, mockRes);  // ✅
```

### ❌ Using TypeDI Container.set() Instead of DependencyInjectionMiddleware

```typescript
// WRONG - Pollutes global TypeDI container
Container.reset();
Container.set(UserService, mockUserService);
await handler.executeGeneric(mockReq, mockRes);

// CORRECT - Uses framework DI middleware
.use(new DependencyInjectionMiddleware(
  [{ id: UserService, value: mockUserService }],
  { scope: 'local' }
))
```

### ❌ Forgetting to Set parsedBody

```typescript
// WRONG - BodyParserMiddleware should set this
const mockReq = createMockRequest({
  body: { name: 'Alice' }
  // Missing parsedBody!
});

// CORRECT
const mockReq = createMockRequest({
  body: { name: 'Alice' },
  parsedBody: { name: 'Alice' }  // BodyParserMiddleware sets this
});
```

### ❌ Missing Response Wrapper Assertions

```typescript
// WRONG - Asserts on raw object instead of wrapped format
const data = mockRes.getData();
expect(data.name).toBe('Alice');  // Assumes no wrapping

// CORRECT - ResponseWrapperMiddleware wraps automatically
const data = mockRes.getData();
expect(data.success).toBe(true);
expect(data.payload.name).toBe('Alice');  // Wrapped structure
```
