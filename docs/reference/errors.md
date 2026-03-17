# Error Classes Reference

Complete hierarchy of error classes for HTTP error mapping and business logic errors.

> **Related:** [Middleware Index](./INDEX.md) | [API Reference](./api.md)

## Purpose

Noony provides a structured error hierarchy rooted in `HttpError` that maps directly to HTTP status codes. Throwing any of these errors from a handler or middleware causes the framework to return the corresponding HTTP response. A separate `ServiceError` class exists for business logic errors that are not tied to HTTP status codes.

## Import

```typescript
import {
  HttpError,
  ValidationError,
  AuthenticationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  SecurityError,
  TimeoutError,
  TooLargeError,
  ConflictError,
  BusinessError,
  InternalServerError,
  ServiceError,
} from '@noony-serverless/core';
```

## Error Hierarchy

```
Error
├── HttpError (base for all HTTP errors)
│   ├── ValidationError ........... 400 Bad Request
│   ├── AuthenticationError ....... 401 Unauthorized
│   ├── UnauthorizedError ......... 401 Unauthorized (alias)
│   ├── SecurityError ............. 403 Forbidden
│   ├── ForbiddenError ............ 403 Forbidden
│   ├── NotFoundError ............. 404 Not Found
│   ├── TimeoutError .............. 408 Request Timeout
│   ├── ConflictError ............. 409 Conflict
│   ├── TooLargeError ............. 413 Payload Too Large
│   ├── BusinessError ............. configurable (default 500)
│   └── InternalServerError ....... 500 Internal Server Error
└── ServiceError (not HTTP-specific)
```

## Class Reference

### `HttpError` (base class)

```typescript
new HttpError(status: number, message: string, code?: string, details?: unknown)
```

| Property | Type | Description |
|---|---|---|
| `status` | `number` | HTTP status code |
| `message` | `string` | Error message |
| `code` | `string \| undefined` | Machine-readable error code |
| `details` | `unknown` | Additional error context |

---

### `ValidationError` -- 400

```typescript
new ValidationError(message: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `400` |
| `code` | `'VALIDATION_ERROR'` |

```typescript
throw new ValidationError('Invalid email format');
throw new ValidationError('Validation error', JSON.stringify(zodIssues));
```

---

### `AuthenticationError` -- 401

```typescript
new AuthenticationError(message?: string)
```

| Property | Value |
|---|---|
| `status` | `401` |
| `code` | `'AUTHENTICATION_ERROR'` |
| Default message | `'Unauthorized'` |

```typescript
throw new AuthenticationError();
throw new AuthenticationError('Token expired');
```

---

### `UnauthorizedError` -- 401 (alias)

```typescript
new UnauthorizedError(message?: string)
```

| Property | Value |
|---|---|
| `status` | `401` |
| `code` | `'UNAUTHORIZED_ERROR'` |
| Default message | `'Authentication required'` |

Semantic alias for `AuthenticationError`. Use when the intent is "authentication required" rather than "authentication failed."

```typescript
throw new UnauthorizedError();
```

---

### `SecurityError` -- 403

```typescript
new SecurityError(message?: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `403` |
| `code` | `'SECURITY_ERROR'` |
| Default message | `'Security violation detected'` |

Used by rate limiting, token blacklisting, and issuer/audience validation.

```typescript
throw new SecurityError('Token has been revoked');
throw new SecurityError('Too many authentication attempts');
```

---

### `ForbiddenError` -- 403

```typescript
new ForbiddenError(message?: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `403` |
| `code` | `'FORBIDDEN_ERROR'` |
| Default message | `'Access denied'` |

Use for authorization failures (user is authenticated but lacks permission).

```typescript
throw new ForbiddenError('Insufficient permissions for this resource');
```

---

### `NotFoundError` -- 404

```typescript
new NotFoundError(message?: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `404` |
| `code` | `'NOT_FOUND_ERROR'` |
| Default message | `'Resource not found'` |

```typescript
throw new NotFoundError('User not found');
throw new NotFoundError('Order not found', { orderId: '123' });
```

---

### `TimeoutError` -- 408

```typescript
new TimeoutError(message?: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `408` |
| `code` | `'TIMEOUT_ERROR'` |
| Default message | `'Request timeout'` |

```typescript
throw new TimeoutError('Database query timed out');
```

---

### `ConflictError` -- 409

```typescript
new ConflictError(message?: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `409` |
| `code` | `'CONFLICT_ERROR'` |
| Default message | `'Resource already exists'` |

```typescript
throw new ConflictError('Email already registered');
throw new ConflictError('Version conflict', { currentVersion: 3, attemptedVersion: 2 });
```

---

### `TooLargeError` -- 413

```typescript
new TooLargeError(message?: string, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `413` |
| `code` | `'TOO_LARGE_ERROR'` |
| Default message | `'Request entity too large'` |

```typescript
throw new TooLargeError('Request body exceeds 1MB limit');
```

---

### `BusinessError` -- configurable status

```typescript
new BusinessError(message: string, status?: number, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | Configurable (default `500`) |
| `code` | `'BUSINESS_ERROR'` |

Use for domain-specific errors that need a custom HTTP status.

```typescript
throw new BusinessError('Payment processing failed', 502);
throw new BusinessError('Insufficient funds', 422, { balance: 10, required: 50 });
```

---

### `InternalServerError` -- 500

```typescript
new InternalServerError(message?: string, cause?: Error, details?: unknown)
```

| Property | Value |
|---|---|
| `status` | `500` |
| `code` | `'INTERNAL_SERVER_ERROR'` |
| Default message | `'Internal server error'` |

Supports error cause chaining -- the `cause` error's stack trace is appended.

```typescript
try {
  await riskyOperation();
} catch (err) {
  throw new InternalServerError('Operation failed', err as Error);
}
```

---

### `ServiceError` (non-HTTP)

```typescript
new ServiceError(message: string, code: string, details?: unknown)
```

| Property | Type | Description |
|---|---|---|
| `message` | `string` | Error message |
| `code` | `string` | Application-specific error code |
| `details` | `unknown` | Additional context |

**Note:** `ServiceError` extends `Error`, not `HttpError`. It does not have a `status` property and will not be automatically mapped to an HTTP response. Use this in service layers for business logic errors that should be caught and mapped by the handler or an error-handling middleware.

```typescript
throw new ServiceError('User quota exceeded', 'QUOTA_EXCEEDED', { limit: 100, current: 101 });
```

## Quick Reference Table

| Class | Status | Code | Default Message |
|---|---|---|---|
| `HttpError` | any | any | -- |
| `ValidationError` | 400 | `VALIDATION_ERROR` | -- |
| `AuthenticationError` | 401 | `AUTHENTICATION_ERROR` | `'Unauthorized'` |
| `UnauthorizedError` | 401 | `UNAUTHORIZED_ERROR` | `'Authentication required'` |
| `SecurityError` | 403 | `SECURITY_ERROR` | `'Security violation detected'` |
| `ForbiddenError` | 403 | `FORBIDDEN_ERROR` | `'Access denied'` |
| `NotFoundError` | 404 | `NOT_FOUND_ERROR` | `'Resource not found'` |
| `TimeoutError` | 408 | `TIMEOUT_ERROR` | `'Request timeout'` |
| `ConflictError` | 409 | `CONFLICT_ERROR` | `'Resource already exists'` |
| `TooLargeError` | 413 | `TOO_LARGE_ERROR` | `'Request entity too large'` |
| `BusinessError` | 500* | `BUSINESS_ERROR` | -- |
| `InternalServerError` | 500 | `INTERNAL_SERVER_ERROR` | `'Internal server error'` |
| `ServiceError` | n/a | custom | -- |

*\* `BusinessError` status is configurable, defaults to 500.*

## See Also

- [API Reference](./api.md) -- error handling section
- [Authentication Middleware](./middlewares/authentication.md) -- throws `AuthenticationError`, `SecurityError`
- [Validation Middleware](./middlewares/validation.md) -- throws `ValidationError`
- [Rate Limiting Middleware](./middlewares/rate-limiting.md) -- throws `SecurityError`
- [Processing Middleware](./middlewares/processing.md) -- throws `ValidationError`, `TooLargeError`
