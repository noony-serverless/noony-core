# Error Handling — Complete Reference

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

throw new HttpError('Custom error', 418); // 418 I'm a teapot
```

### Common Errors (4xx)

```typescript
import {
  ValidationError, UnauthorizedError, ForbiddenError,
  NotFoundError, ConflictError, TimeoutError, TooLargeError
} from '@noony-serverless/core';

throw new ValidationError('Email is required');           // 400
throw new UnauthorizedError('JWT token missing');         // 401
throw new ForbiddenError('You cannot delete this');       // 403

const user = await userService.getById(userId);
if (!user) throw new NotFoundError(`User ${userId} not found`); // 404

const existing = await userService.findByEmail(email);
if (existing) throw new ConflictError('Email already registered'); // 409

throw new TimeoutError('External service timeout');       // 408
throw new TooLargeError('File exceeds 10MB limit');       // 413
```

### Server Errors (5xx)

```typescript
import { InternalServerError } from '@noony-serverless/core';

try {
  await database.query(sql);
} catch (err) {
  throw new InternalServerError('Database query failed', err as Error);
}
```

## Error Response Format

`ErrorHandlerMiddleware` automatically formats all errors:

```json
{
  "success": false,
  "payload": {
    "error": "Request validation failed",
    "code": "MISSING_EMAIL"
  },
  "timestamp": "2025-03-10T12:00:00.000Z"
}
```

- `code` included only for client errors (4xx), not server errors
- `details` included only in development (`NODE_ENV=development` or `DEBUG=true`)
- `debug` block included when `DEBUG_API_RESPONSE=true`

## Cause Chaining Pattern

Chain errors for debugging while keeping client messages clean:

```typescript
const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    try {
      const inventory = await inventoryService.reserve(productId, quantity);
      return { success: true, reservationId: inventory.id };
    } catch (err) {
      throw new InternalServerError('Failed to reserve inventory', err as Error);
    }
  });
```

**Internal log** shows full chain:
```
InternalServerError: Failed to reserve inventory
  cause: Error: Connection timeout at InventoryService.reserve()
```

**Client response** is clean:
```json
{ "success": false, "payload": { "error": "Failed to reserve inventory" } }
```

## Custom Error Classes

Extend `HttpError` for domain-specific errors:

```typescript
export class PaymentError extends HttpError {
  constructor(
    message: string,
    readonly transactionId: string,
    readonly paymentMethod: string
  ) {
    super(message, 402);
    this.name = 'PaymentError';
  }
}

// Usage
throw new PaymentError('Payment declined', 'txn-12345', 'visa-****1234');
```

## ErrorHandlerMiddleware Lifecycle

The middleware catches errors from all middleware and the handler:

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())      // ← Catches errors from ALL below
  .use(new BodyParserMiddleware())        //   before hooks
  .use(new BodyValidationMiddleware())    //   and from handler
  .use(new AuthenticationMiddleware())    // ← Errors here caught
  .handle(async (context) => {
    throw new NotFoundError('Item not found'); // ← Caught too
  });
```

**Flow**: before hooks run top-to-bottom → controller → onError hooks run bottom-to-top → `ErrorHandlerMiddleware.onError` fires last.

## Multiple Error Types in Single Handler

```typescript
const createUserHandler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    const { email, name } = context.req.validatedBody!;
    const user = context.user!;

    if (user.role !== 'admin') throw new ForbiddenError('Only admins can create users');

    const existing = await userService.findByEmail(email);
    if (existing) throw new ConflictError('Email already registered');

    try {
      const createdUser = await userService.create({ email, name });
      return { success: true, userId: createdUser.id };
    } catch (err) {
      throw new InternalServerError('Failed to create user', err as Error);
    }
  });

// Possible responses: 400 (validation), 401 (auth), 403 (forbidden), 409 (conflict), 500 (server)
```

## Conditional Error Handling

Handle some errors, re-throw others:

```typescript
.handle(async (context) => {
  try {
    return { data: await externalAPI.fetch() };
  } catch (err) {
    if (err instanceof TimeoutError) {
      const cached = await cacheService.get(cacheKey);
      if (cached) return { data: cached, cached: true };
    }
    throw new InternalServerError('Service unavailable', err as Error);
  }
});
```

## ServiceError for Non-HTTP Contexts

Use `ServiceError` in services that shouldn't know about HTTP:

```typescript
// Service layer — no HTTP awareness
import { ServiceError } from '@noony-serverless/core';

export class UserService {
  async validateEmail(email: string): Promise<void> {
    const exists = await this.findByEmail(email);
    if (exists) throw new ServiceError('Email already in use', 'DUPLICATE_EMAIL', { email });
  }
}

// Handler — translates ServiceError to HTTP error
.handle(async (context) => {
  try {
    await userService.validateEmail(email);
  } catch (err) {
    if (err instanceof ServiceError && err.code === 'DUPLICATE_EMAIL') {
      throw new ConflictError(err.message);
    }
    throw new InternalServerError(err.message, err as Error);
  }
});
```

## Debugging

```bash
NODE_ENV=development npm run dev     # Shows error details in responses
DEBUG_API_RESPONSE=true npm run dev  # Shows full debug block (stack, original error)
```

## Testing Error Paths

```typescript
describe('getUserHandler', () => {
  it('should throw NotFoundError for missing user', async () => {
    const mockUserService = { getById: jest.fn().mockResolvedValue(null) };

    const handler = new Handler<any, AuthUser>()
      .use(new ErrorHandlerMiddleware())
      .handle(async (context) => {
        const user = await mockUserService.getById('missing-id');
        if (!user) throw new NotFoundError('User not found');
        return user;
      });

    await expect(handler.executeGeneric(req, res)).rejects.toThrow(NotFoundError);
  });
});
```

## Anti-Patterns Quick Reference

| Don't | Do Instead | Why |
|-------|-----------|-----|
| `throw new Error('Not found')` | `throw new NotFoundError(msg)` | Generic errors become opaque 500s |
| `context.res.status(404).json()` | `throw new NotFoundError(msg)` | Bypasses logging and formatting |
| `catch (err) { /* ignore */ }` | `throw new InternalServerError(msg, err)` | Silent failures hide bugs |
| `new InternalServerError('Not found')` | `new NotFoundError('Not found')` | Wrong status misleads clients |
| ErrorHandler not first | Always `.use(new ErrorHandlerMiddleware())` first | Earlier errors go uncaught |
