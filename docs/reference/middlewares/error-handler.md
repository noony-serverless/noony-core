# ErrorHandlerMiddleware

Catches all pipeline errors and maps them to structured HTTP JSON responses.

> **Related**: [Error Handling Guide](../../guides/error-handling.md) | [Error Classes Reference](../errors.md) | [Middleware Index](./INDEX.md)

## Purpose

The `ErrorHandlerMiddleware` is the safety net for your handler pipeline. It intercepts errors thrown by any middleware or the controller, categorizes them, and sends a structured JSON response with the appropriate HTTP status code.

## When to Use

**Every handler should include this middleware.** Place it first in the `.use()` chain so its `onError` hook (which runs in reverse order) fires last and can shape every error response.

## Import

```typescript
import { ErrorHandlerMiddleware, errorHandler } from '@noony-serverless/core';
```

## Constructor

### Class Form

```typescript
new ErrorHandlerMiddleware(options?: ErrorHandlerOptions)
```

### Factory Function

```typescript
errorHandler(options?: ErrorHandlerOptions)
```

Both forms are equivalent. The factory function returns a `BaseMiddleware` object.

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `customCategories` | `ErrorMatcher[]` | `undefined` | Custom error categories evaluated before built-in ones |

### ErrorMatcher Interface

```typescript
interface ErrorMatcher {
  matches: (error: Error) => boolean;  // Return true if this category applies
  category: ErrorCategory;             // Category to use when matched
}

interface ErrorCategory {
  type: string;           // Error type identifier (e.g., 'PAYMENT_ERROR')
  userMessage: string;    // Safe message shown to the client
  httpStatus: number;     // HTTP status code
  retryable: boolean;     // Whether the client should retry
}
```

## Usage

### Basic

```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())  // Always first
  .use(new BodyParserMiddleware())
  .handle(async (context) => {
    if (!context.req.parsedBody?.email) {
      throw new ValidationError('Email is required');
    }
    return { success: true };
  });
```

### With Custom Error Categories

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
  .handle(async (context) => {
    // If an error contains "payment_failed", returns 402
  });
```

## Response Format

### HttpError Responses (Known Errors)

When an `HttpError` subclass is thrown (e.g., `ValidationError`, `NotFoundError`):

```json
{
  "success": false,
  "payload": {
    "error": "Email is required",
    "code": "MISSING_EMAIL"
  },
  "timestamp": "2025-03-10T12:00:00.000Z"
}
```

- `code` is included only for client errors (4xx), not server errors
- `details` is included only in development mode (`NODE_ENV=development` or `DEBUG=true`)

### Categorized Responses (Unknown Errors)

For non-HttpError errors, the middleware categorizes them automatically:

| Category | Matches | Status | Retryable |
|----------|---------|--------|-----------|
| `DATABASE_ERROR` | `mongodb`, `mongoose`, `buffering timed out` | 503 | Yes |
| `TIMEOUT_ERROR` | `timeout`, `timed out` | 504 | Yes |
| `EXTERNAL_SERVICE_ERROR` | `econnrefused`, `network`, `fetch failed` | 502 | Yes |
| `INTERNAL_ERROR` | Everything else | 500 | No |

Retryable errors include a `Retry-After: 5` header.

## Environment Variables

| Variable | Effect |
|----------|--------|
| `NODE_ENV=development` | Includes error `details` in HttpError responses |
| `DEBUG=true` | Same as `NODE_ENV=development` |
| `DEBUG_API_RESPONSE=true` | Adds `debug` block with original error message, stack trace, and error type |

## Error Lifecycle

```
Request → before hooks (top-to-bottom) → controller → after hooks (bottom-to-top)
                                                         ↓ (on error)
                                              onError hooks (bottom-to-top)
                                                         ↓
                                           ErrorHandlerMiddleware.onError
                                                         ↓
                                              Categorize → Log → Respond
```

The middleware logs every error with:
- Error type, message, and stack trace
- HTTP status and error code
- Request ID, URL, method
- User agent and IP address

## Anti-Patterns

| Pattern | Problem | Fix |
|---------|---------|-----|
| Not placing first in chain | Errors from earlier middlewares aren't caught | Always `.use(new ErrorHandlerMiddleware())` first |
| Calling `res.status().json()` manually | Bypasses error formatting and logging | Throw typed errors instead |
| Multiple ErrorHandlerMiddlewares | Duplicate error responses | Use exactly one per handler |

## See Also

- [Error Handling Guide](../../guides/error-handling.md) — How to throw and handle errors effectively
- [Error Classes Reference](../errors.md) — Complete error class hierarchy
- [Middleware Index](./INDEX.md) — All available middlewares
