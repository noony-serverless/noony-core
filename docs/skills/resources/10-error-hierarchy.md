# Skill 10: Error Handling - Complete Hierarchy

## Error Class Hierarchy Table

| Error Class | HTTP Status | Use Case | Example |
|------------|-------------|----------|---------|
| **HttpError** | Custom | Base class for HTTP errors | Generic error with custom status |
| **ValidationError** | 400 | Input validation failures | Invalid request schema |
| **UnauthorizedError** | 401 | Missing/invalid authentication | JWT token missing or invalid |
| **SecurityError** | 403 | Security violations | Invalid CSRF token, rate limit |
| **ForbiddenError** | 403 | Insufficient permissions | User lacks required role |
| **NotFoundError** | 404 | Resource not found | User ID doesn't exist |
| **ConflictError** | 409 | Resource conflict/duplicate | Email already registered |
| **TimeoutError** | 408 | Request timeout | External API timeout |
| **TooLargeError** | 413 | Request too large | File upload exceeds limit |
| **InternalServerError** | 500 | Unexpected errors | Database connection failed |
| **BusinessError** | 200-599 | Business logic errors | Custom status codes |
| **ServiceError** | N/A | Service layer errors | Non-HTTP service failures |

## Basic Error Usage

### HttpError Base Class

```typescript
import { HttpError } from '@noony-serverless/core';

// Generic custom error with status code
throw new HttpError('Custom error', 418); // 418 I'm a teapot
```

### Common Errors (4xx)

```typescript
import {
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  TimeoutError,
  TooLargeError
} from '@noony-serverless/core';

// 400 - Validation failure
throw new ValidationError('Email is required');

// 401 - Authentication required
throw new UnauthorizedError('JWT token missing');

// 403 - Permission denied
throw new ForbiddenError('You cannot delete this resource');

// 404 - Resource missing
const user = await userService.getById(userId);
if (!user) {
  throw new NotFoundError(`User ${userId} not found`);
}

// 409 - Conflict (duplicate)
const existing = await userService.findByEmail(email);
if (existing) {
  throw new ConflictError('Email already registered');
}

// 408 - Timeout
try {
  await externalAPI.call({ timeout: 5000 });
} catch (err) {
  throw new TimeoutError('External service timeout');
}

// 413 - Payload too large
if (fileSize > MAX_SIZE) {
  throw new TooLargeError('File exceeds 10MB limit');
}
```

### Server Errors (5xx)

```typescript
import { InternalServerError } from '@noony-serverless/core';

// 500 - Unexpected error
try {
  await database.query(sql);
} catch (err) {
  throw new InternalServerError('Database query failed', err as Error);
}
```

## Error Response Format

All errors are automatically formatted by `ErrorHandlerMiddleware`:

```typescript
// Client receives:
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",           // Error type
    "message": "Request validation failed", // Readable message
    "statusCode": 400,                    // HTTP status
    "details": [                          // Optional details
      {
        "path": ["email"],
        "message": "Invalid email format"
      }
    ]
  }
}
```

## Cause Chaining Pattern

Chain errors for debugging while keeping error messages clean:

```typescript
import { InternalServerError } from '@noony-serverless/core';

const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    try {
      const inventory = await inventoryService.reserve(productId, quantity);
      return { success: true, reservationId: inventory.id };
    } catch (err) {
      // Chain the original error for debugging
      throw new InternalServerError(
        'Failed to reserve inventory',
        err as Error
      );
    }
  });
```

**Error Stack (Internal Logging):**
```
InternalServerError: Failed to reserve inventory
  cause: Error: Connection timeout at InventoryService.reserve()
    at asyncFn (db.ts:42:15)
    at processRequest (handler.ts:120:8)
```

**Client Response (Clean):**
```json
{
  "success": false,
  "error": {
    "code": "INTERNAL_SERVER_ERROR",
    "message": "Failed to reserve inventory",
    "statusCode": 500
  }
}
```

## Custom Error Classes

Extend `HttpError` for domain-specific errors:

```typescript
// Define custom error class
export class PaymentError extends HttpError {
  constructor(
    message: string,
    readonly transactionId: string,
    readonly paymentMethod: string
  ) {
    super(message, 402); // 402 Payment Required
    this.name = 'PaymentError';
  }
}

// Use in handler
const handler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    try {
      const charge = await paymentService.charge(amount, cardId);
    } catch (err) {
      throw new PaymentError(
        'Payment declined by bank',
        'txn-12345',
        'visa-****1234'
      );
    }
  });

// Client receives:
{
  "success": false,
  "error": {
    "code": "PAYMENT_ERROR",
    "message": "Payment declined by bank",
    "statusCode": 402
  }
}
```

## ErrorHandlerMiddleware Lifecycle

The middleware catches errors from all middleware and the handler:

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())      // ← Catches errors from ALL below
  .use(new BodyParserMiddleware())        //   before hooks
  .use(new BodyValidationMiddleware())    //   and from handler
  .use(new AuthenticationMiddleware())    // ← Errors here caught
  .use(new SomeCustomMiddleware())
  .handle(async (context) => {
    // ↑ Any error here is caught
    throw new NotFoundError('Item not found');
  });
```

**Middleware Error Lifecycle:**

```typescript
// Each middleware can throw in before hooks
.use({
  before: async (context) => {
    // 1. BodyParserMiddleware runs
    // 2. BodyValidationMiddleware runs
    // 3. If validation fails, throws ValidationError
    // 4. ErrorHandlerMiddleware.onError catches it
    // 5. Response sent with 400 status
  }
});

// Handler can throw
.handle(async (context) => {
  throw new NotFoundError('Resource not found');
  // ErrorHandlerMiddleware.onError catches and returns 404
});
```

## Multiple Error Types in Single Handler

```typescript
const createUserHandler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    const { email, name } = context.req.validatedBody!;
    const user = context.user!;

    // Check permission
    if (user.role !== 'admin' && user.role !== 'moderator') {
      throw new ForbiddenError('Only admins can create users');
    }

    // Check for duplicate
    const existing = await userService.findByEmail(email);
    if (existing) {
      throw new ConflictError('Email already registered');
    }

    // Validate complex business logic
    if (!isValidOrganization(user.organizationId)) {
      throw new ValidationError('Invalid organization');
    }

    // Handle external service failure
    try {
      const createdUser = await userService.create({ email, name });
      return { success: true, userId: createdUser.id };
    } catch (err) {
      if (err instanceof DatabaseError) {
        throw new InternalServerError(
          'Failed to create user',
          err as Error
        );
      }
      throw err; // Re-throw unknown errors
    }
  });

// Request flows:
// 1. 400 ValidationError if email invalid
// 2. 401 UnauthorizedError if token missing
// 3. 403 ForbiddenError if insufficient permissions
// 4. 409 ConflictError if email exists
// 5. 400 ValidationError if org invalid
// 6. 500 InternalServerError if database fails
// 7. 201 success if all checks pass
```

## Conditional Error Handling

Handle some errors, re-throw others:

```typescript
const handler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    try {
      const data = await externalAPI.fetch();
      return { data };
    } catch (err) {
      // Check error type
      if (err instanceof TimeoutError) {
        // Retry logic
        return await externalAPI.fetch(); // Retry
      }

      if (err instanceof NotFoundError) {
        // Handle gracefully
        return { data: null }; // Return empty instead of error
      }

      // Let ErrorHandlerMiddleware handle it
      throw new InternalServerError(
        'External API call failed',
        err as Error
      );
    }
  });
```

## Error Logging Patterns

### Detailed Error Logging

```typescript
const errorLoggingMiddleware = <TBody = unknown, TUser = unknown>():
  BaseMiddleware<TBody, TUser> => ({
  onError: async (context, error) => {
    const logData = {
      requestId: context.requestId,
      method: context.req.method,
      path: context.req.path,
      userId: context.user?.id,
      errorCode: error.code,
      errorMessage: error.message,
      statusCode: error.statusCode,
      timestamp: new Date().toISOString(),
      duration: Date.now() - context.startTime
    };

    if (error.statusCode >= 500) {
      // Log server errors with full stack
      logger.error(logData, error);
    } else if (error.statusCode >= 400) {
      // Log client errors at info level
      logger.info(logData);
    }
  }
});

const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(errorLoggingMiddleware())
  .handle(async (context) => {
    // Errors logged with full context
  });
```

### Structured Error Data

```typescript
export class DetailedError extends HttpError {
  constructor(
    message: string,
    statusCode: number,
    readonly context: Record<string, any>
  ) {
    super(message, statusCode);
  }
}

const handler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    throw new DetailedError(
      'Invalid payment',
      400,
      {
        amount: 99.99,
        currency: 'USD',
        reason: 'Amount too low',
        minimumAmount: 100
      }
    );
  });
```

## Debugging with DEBUG_API_RESPONSE

Enable detailed error responses in development:

```bash
# In local development
DEBUG_API_RESPONSE=true npm run dev

# In handler
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware({
    debug: process.env.DEBUG_API_RESPONSE === 'true'
  }))
  .handle(async (context) => {
    throw new InternalServerError(
      'Database connection failed',
      new Error('ECONNREFUSED on localhost:5432')
    );
  });

// With debug=true, response includes stack trace:
{
  "success": false,
  "error": {
    "code": "INTERNAL_SERVER_ERROR",
    "message": "Database connection failed",
    "statusCode": 500,
    "stack": "Error: ECONNREFUSED on localhost:5432\n    at connect (db.ts:42:15)",
    "cause": {
      "message": "ECONNREFUSED on localhost:5432",
      "stack": "..."
    }
  }
}
```

## ServiceError for Non-HTTP Contexts

Use `ServiceError` in services that don't know about HTTP:

```typescript
// src/services/user.service.ts
import { ServiceError } from '@noony-serverless/core';

export class UserService {
  async validateEmail(email: string): Promise<void> {
    const exists = await this.findByEmail(email);
    if (exists) {
      // Service doesn't know about HTTP
      throw new ServiceError(
        'Email already in use',
        'DUPLICATE_EMAIL',
        { email }
      );
    }
  }
}

// src/handlers/user.handler.ts
// Handler translates ServiceError to HttpError
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    try {
      const user = await userService.create(context.req.validatedBody!);
    } catch (err) {
      if (err instanceof ServiceError) {
        // Translate to HTTP error based on error code
        if (err.code === 'DUPLICATE_EMAIL') {
          throw new ConflictError(err.message);
        }
        throw new InternalServerError(err.message, err as Error);
      }
      throw err;
    }
  });
```

## Testing Error Handling

### Unit Test Error Throwing

```typescript
import { NotFoundError } from '@noony-serverless/core';

describe('getUserHandler', () => {
  it('should throw NotFoundError for missing user', async () => {
    const mockUserService = {
      getById: jest.fn().mockResolvedValue(null)
    };

    const handler = new Handler<any, AuthUser>()
      .use(new ErrorHandlerMiddleware())
      .handle(async (context) => {
        const user = await mockUserService.getById('missing-id');
        if (!user) {
          throw new NotFoundError('User not found');
        }
        return user;
      });

    const context = createMockContext();
    await expect(handler.executeGeneric(...)).rejects.toThrow(NotFoundError);
  });
});
```

### Integration Test Error Responses

```typescript
describe('createUserHandler', () => {
  it('should return 409 Conflict for duplicate email', async () => {
    const validRequest = {
      email: 'existing@example.com',
      name: 'John',
      password: 'secure123'
    };

    // First request succeeds
    let response = await request(app)
      .post('/api/users')
      .send(validRequest);
    expect(response.status).toBe(201);

    // Second request with same email conflicts
    response = await request(app)
      .post('/api/users')
      .send(validRequest);
    expect(response.status).toBe(409);
    expect(response.body.error.code).toBe('CONFLICT_ERROR');
  });
});
```

## Anti-Patterns to Avoid

### ❌ Throwing Generic Error

```typescript
// WRONG - Generic error, no type safety
throw new Error('Something failed');

// ✅ CORRECT - Specific error type
throw new InternalServerError('Database query failed', originalError);
```

### ❌ Missing Error Handler

```typescript
// WRONG - Errors not caught
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(schema)) // Validation can throw!
  .handle(async (context) => {
    // If validation fails, handler crashes
  });

// ✅ CORRECT
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware()) // Always first
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // Validation errors caught and returned as 400
  });
```

### ❌ Swallowing Errors

```typescript
// WRONG - Error lost
try {
  await userService.create(userData);
} catch (err) {
  // Silently ignore!
}

// ✅ CORRECT - At least log
try {
  await userService.create(userData);
} catch (err) {
  logger.error('Failed to create user', err);
  throw new InternalServerError('User creation failed', err as Error);
}
```

### ❌ Wrong Status Code

```typescript
// WRONG - 500 for missing resource
if (!user) {
  throw new InternalServerError('User not found'); // Should be 404
}

// ✅ CORRECT
if (!user) {
  throw new NotFoundError('User not found');
}
```

## Real-World Error Patterns

### Pattern 1: API Integration with Fallback

```typescript
const handler = new Handler<SearchRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    const query = context.req.parsedBody.query;

    try {
      // Primary service
      const results = await primarySearchService.search(query);
      return { results };
    } catch (err) {
      if (err instanceof TimeoutError) {
        // Fallback to cached results
        const cached = await cacheService.get(`search:${query}`);
        if (cached) {
          return { results: cached, cached: true };
        }
      }

      // If fallback not available, return error
      throw new InternalServerError(
        'Search service unavailable',
        err as Error
      );
    }
  });
```

### Pattern 2: Business Rule Validation Chain

```typescript
const createOrderHandler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(orderSchema))
  .handle(async (context) => {
    const { productId, quantity } = context.req.validatedBody!;

    // Chain of validation checks with specific errors
    const product = await productService.getById(productId);
    if (!product) {
      throw new NotFoundError(`Product ${productId} not found`);
    }

    if (product.discontinued) {
      throw new ConflictError('Product is discontinued');
    }

    if (quantity > product.inventory) {
      throw new ValidationError('Insufficient inventory');
    }

    if (!product.availableRegions.includes(context.user!.region)) {
      throw new ForbiddenError('Product not available in your region');
    }

    const order = await orderService.create({
      productId,
      quantity,
      userId: context.user!.id
    });

    return { orderId: order.id };
  });
```

### Pattern 3: Async Operation with Retry

```typescript
const uploadHandler = new Handler<UploadRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    const file = context.req.files.document;

    if (file.size > 10 * 1024 * 1024) {
      throw new TooLargeError('File exceeds 10MB limit');
    }

    // Retry async operation with exponential backoff
    let lastError: Error | null = null;

    for (let i = 0; i < 3; i++) {
      try {
        const result = await storageService.upload(file);
        return { fileId: result.id };
      } catch (err) {
        lastError = err as Error;
        if (i < 2) {
          await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
        }
      }
    }

    throw new InternalServerError(
      'File upload failed after retries',
      lastError!
    );
  });
```
