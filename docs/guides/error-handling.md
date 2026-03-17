# Error Handling Guide

How to throw, catch, and map errors in Noony handlers.

> **Related**: [Error Classes Reference](../reference/errors.md) | [ErrorHandlerMiddleware Reference](../reference/middlewares/error-handler.md) | [Middleware Index](../reference/middlewares/INDEX.md)

## The Golden Rule

**Throw typed errors — never call `res.status().json()` directly.**

The `ErrorHandlerMiddleware` catches all thrown errors and formats them into consistent JSON responses with the correct HTTP status code, logging, and optional debug information.

## Quick Reference

| Situation | Error to Throw | HTTP Status |
|-----------|---------------|-------------|
| Invalid input | `ValidationError` | 400 |
| Missing/bad auth token | `UnauthorizedError` | 401 |
| Insufficient permissions | `ForbiddenError` | 403 |
| Security violation | `SecurityError` | 403 |
| Resource not found | `NotFoundError` | 404 |
| Request timeout | `TimeoutError` | 408 |
| Duplicate/conflict | `ConflictError` | 409 |
| Payload too large | `TooLargeError` | 413 |
| Unexpected failure | `InternalServerError` | 500 |
| Business logic error | `BusinessError` | Custom |
| Non-HTTP service error | `ServiceError` | N/A |

All error classes are imported from `@noony-serverless/core`.

## Setup

Every handler needs `ErrorHandlerMiddleware` as the **first** middleware:

```typescript
import { Handler, ErrorHandlerMiddleware } from '@noony-serverless/core';

const handler = new Handler()
  .use(new ErrorHandlerMiddleware())  // Must be first
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // Errors from any middleware or handler are caught
  });
```

## Throwing Errors

### Client Errors (4xx)

```typescript
import {
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  TimeoutError,
  TooLargeError,
} from '@noony-serverless/core';

// 400 — Validation failure
throw new ValidationError('Email is required');

// 401 — Authentication required
throw new UnauthorizedError('JWT token missing');

// 403 — Permission denied
throw new ForbiddenError('You cannot delete this resource');

// 404 — Resource missing
const user = await userService.getById(userId);
if (!user) {
  throw new NotFoundError(`User ${userId} not found`);
}

// 409 — Duplicate resource
const existing = await userService.findByEmail(email);
if (existing) {
  throw new ConflictError('Email already registered');
}

// 408 — Request timeout
throw new TimeoutError('External service timeout');

// 413 — Payload too large
if (fileSize > MAX_SIZE) {
  throw new TooLargeError('File exceeds 10MB limit');
}
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

### Custom Status Codes

```typescript
import { HttpError } from '@noony-serverless/core';

// Any HTTP status code
throw new HttpError('I am a teapot', 418);
```

## Cause Chaining

When wrapping external errors, pass the original error as the second argument to preserve the stack trace for debugging:

```typescript
try {
  const inventory = await inventoryService.reserve(productId, quantity);
  return { success: true, reservationId: inventory.id };
} catch (err) {
  // Original error preserved for logging, clean message for client
  throw new InternalServerError('Failed to reserve inventory', err as Error);
}
```

**Internal log** shows the full chain:
```
InternalServerError: Failed to reserve inventory
  cause: Error: Connection timeout at InventoryService.reserve()
```

**Client response** is clean:
```json
{
  "success": false,
  "payload": { "error": "Failed to reserve inventory" }
}
```

## Custom Error Classes

Extend `HttpError` for domain-specific errors:

```typescript
export class PaymentError extends HttpError {
  constructor(
    message: string,
    readonly transactionId: string,
    readonly paymentMethod: string,
  ) {
    super(message, 402); // 402 Payment Required
    this.name = 'PaymentError';
  }
}

// Usage
throw new PaymentError('Payment declined', 'txn-12345', 'visa-****1234');
```

## ServiceError for Non-HTTP Contexts

Use `ServiceError` in service layers that shouldn't know about HTTP:

```typescript
// In your service layer
import { ServiceError } from '@noony-serverless/core';

export class UserService {
  async validateEmail(email: string): Promise<void> {
    const exists = await this.findByEmail(email);
    if (exists) {
      throw new ServiceError('Email already in use', 'DUPLICATE_EMAIL', { email });
    }
  }
}

// In your handler — translate to HTTP error
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

## Custom Error Categories

For non-HttpError exceptions (e.g., from third-party libraries), configure the `ErrorHandlerMiddleware` with custom matchers:

```typescript
const customCategories = [{
  matches: (err) => err.message.includes('payment_failed'),
  category: {
    type: 'PAYMENT_ERROR',
    userMessage: 'Payment processing failed',
    httpStatus: 402,
    retryable: false,
  },
}];

const handler = new Handler()
  .use(new ErrorHandlerMiddleware({ customCategories }))
  .handle(/* ... */);
```

Custom categories are checked **before** the built-in ones (database, timeout, network, generic).

## Error Handling Patterns

### Conditional Handling with Fallback

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

### Business Rule Validation Chain

```typescript
.handle(async (context) => {
  const { productId, quantity } = context.req.validatedBody!;

  const product = await productService.getById(productId);
  if (!product) throw new NotFoundError(`Product ${productId} not found`);
  if (product.discontinued) throw new ConflictError('Product is discontinued');
  if (quantity > product.inventory) throw new ValidationError('Insufficient inventory');

  return await orderService.create({ productId, quantity, userId: context.user!.id });
});
```

### Retry with Backoff

```typescript
.handle(async (context) => {
  let lastError: Error | null = null;

  for (let i = 0; i < 3; i++) {
    try {
      return { fileId: (await storageService.upload(file)).id };
    } catch (err) {
      lastError = err as Error;
      if (i < 2) await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i)));
    }
  }

  throw new InternalServerError('Upload failed after retries', lastError!);
});
```

## Debugging

Enable detailed error responses in development:

```bash
# Shows error details in HttpError responses
NODE_ENV=development npm run dev

# Shows full debug block (original error, stack, type) for ALL errors
DEBUG_API_RESPONSE=true npm run dev
```

## Testing Error Paths

```typescript
describe('getUserHandler', () => {
  it('should throw NotFoundError for missing user', async () => {
    const mockUserService = { getById: jest.fn().mockResolvedValue(null) };

    // Assert the specific error type
    await expect(handler.executeGeneric(req, res))
      .rejects.toThrow(NotFoundError);
  });

  it('should return 409 for duplicate email', async () => {
    const response = await request(app)
      .post('/api/users')
      .send({ email: 'existing@example.com' });

    expect(response.status).toBe(409);
    expect(response.body.success).toBe(false);
  });
});
```

## Anti-Patterns

| Don't | Do Instead | Why |
|-------|-----------|-----|
| `throw new Error('Not found')` | `throw new NotFoundError('User not found')` | Generic errors become 500s |
| `context.res.status(404).json({...})` | `throw new NotFoundError(...)` | Bypasses logging and formatting |
| `catch (err) { /* ignore */ }` | `catch (err) { throw new InternalServerError(..., err) }` | Silent failures hide bugs |
| `throw new InternalServerError('User not found')` | `throw new NotFoundError('User not found')` | Wrong status code misleads clients |
| ErrorHandler not first in chain | Always `.use(new ErrorHandlerMiddleware())` first | Earlier middleware errors uncaught |

## See Also

- [Error Classes Reference](../reference/errors.md) — Complete hierarchy with status codes
- [ErrorHandlerMiddleware Reference](../reference/middlewares/error-handler.md) — Configuration and response format
- [Testing Handlers](../tutorials/04-testing-handlers.md) — Testing error scenarios
