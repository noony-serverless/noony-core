---
name: noony-error-handling
description: Use when throwing errors, handling error types, mapping errors to HTTP status codes, wrapping external API errors, or implementing custom error classes in Noony handlers. Covers the full error class hierarchy, cause chaining, ErrorHandlerMiddleware lifecycle, and ServiceError for non-HTTP contexts.
---

# skill:noony-error-handling

## Does exactly this

Covers built-in error classes with HTTP status codes, cause chaining for wrapping errors, custom error types, and ErrorHandlerMiddleware lifecycle. ErrorHandlerMiddleware must be at position 1 in the canonical middleware order (see `noony-middleware-ordering`).

## When to use

- "Throw an error"
- "Handle different error types"
- "Map errors to HTTP status codes"
- "Wrap external API errors"
- "Custom error class"

## Do not use this skill when

- You need middleware ordering guidance -> `noony-middleware-ordering` is the canonical reference
- You need body validation schemas -> `noony-validation-schemas` for Zod integration
- You need validation error configuration -> `noony-validation-schemas` handles `ValidationError` responses
- You need custom middleware development -> `noony-middleware-development`

## Steps

1. Import typed error from `@noony-serverless/core` — never throw generic `Error()`
   -> See `references/error-hierarchy.md#error-class-hierarchy-table` for the complete error list with status codes
2. **Ensure ErrorHandlerMiddleware is at position 1** per `noony-middleware-ordering` — its `onError` fires last in reverse order, giving it final authority over error responses
3. Throw typed error in handler — `ErrorHandlerMiddleware` catches and formats the JSON response automatically
4. For external API errors, wrap with cause chaining to preserve the original stack trace:
   ```typescript
   throw new InternalServerError('API failed', originalError);
   ```
5. Never call `context.res.status().json()` for errors — always throw typed errors instead
6. For domain-specific errors, extend `HttpError` with a custom status code
   -> See `references/error-hierarchy.md#custom-error-classes` for the pattern
7. Use `ServiceError` in service layers that shouldn't know about HTTP
   -> See `references/error-hierarchy.md#serviceerror-for-non-http-contexts`

## Rules

- Always throw typed errors (`NotFoundError`, `ForbiddenError`) — generic `Error()` becomes an opaque 500
- `ErrorHandlerMiddleware` must be **first** (position 1) in the middleware chain per `noony-middleware-ordering` — its `onError` fires last in reverse, giving final authority over error responses
- Use cause chaining for wrapping: `new InternalServerError(message, causeError)` — preserves the original stack for logging while keeping the client response clean
- `ServiceError` for non-HTTP errors (business logic, internal services) — translate to `HttpError` subclass in the handler
- HTTP status codes are automatic based on error type — no manual status setting needed

## Anti-patterns

- `context.res.status(404).json()` — bypasses error formatting and logging
- `throw new Error('Not found')` — loses HTTP status code, becomes 500
- `catch (err) { /* ignore */ }` — silent failures hide bugs
- Wrapping errors without cause chaining — original error context lost for debugging
- `ErrorHandlerMiddleware` not at position 1 per `noony-middleware-ordering` — errors from earlier middlewares go uncaught

## Done when

- You know which error to throw for 400, 401, 403, 404, 409, 500
- You understand cause chaining pattern for wrapping external errors
- You can write custom error classes extending `HttpError`
- ErrorHandlerMiddleware is at position 1 per `noony-middleware-ordering`
- You know `ErrorHandlerMiddleware` runs on the error path (reverse order, fires last)

## If you need more detail

-> `references/error-hierarchy.md` — Complete error table with status codes, cause chaining examples, custom errors, ErrorHandlerMiddleware lifecycle, ServiceError patterns, debugging with DEBUG_API_RESPONSE, testing error paths
