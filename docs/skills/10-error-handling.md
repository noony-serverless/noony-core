# Skill 10: Robust Error Handling

## Does exactly this

Covers built-in error classes with HTTP status codes, cause chaining for wrapping errors, custom error types, and ErrorHandlerMiddleware lifecycle.

## When to use

- "Throw an error"
- "Handle different error types"
- "Map errors to HTTP status codes"
- "Wrap external API errors"

## Steps

1. Import typed error from @noony-serverless/core (NotFoundError, ForbiddenError, ValidationError, etc.)
2. Throw typed error in handler — ErrorHandlerMiddleware catches and formats automatically
   → See resources/10-error-hierarchy.md#error-class-reference-table for complete error list
3. For external API errors, wrap with cause chaining: `new InternalServerError('API failed', error)`
4. Never call `context.res.status().json()` for errors — use typed error throwing instead
5. Custom errors extend HttpError with status code

## Rules

- Always throw typed errors (NotFoundError, ForbiddenError) — never generic Error()
- ErrorHandlerMiddleware MUST be first in middleware chain to catch all errors
- Use cause chaining for wrapping: `new InternalServerError(message, causeError)`
- ServiceError for non-HTTP errors (business logic, internal services)
- Never return error response directly — let ErrorHandlerMiddleware format it
- HTTP status codes are automatic based on error type

## Anti-patterns

- ❌ `context.res.status(404).json()` instead of `throw new NotFoundError()` — bypasses error handling
- ❌ Throwing generic `new Error()` — loses HTTP status code, becomes 500
- ❌ Catching and swallowing errors silently — bugs never reported
- ❌ Wrapping errors without cause chaining — original error context lost
- ❌ ErrorHandlerMiddleware not first — errors from earlier middlewares not caught

## Done when

- You know which error to throw for 404, 403, 400, 500
- You understand cause chaining pattern
- You can write custom error classes
- You know ErrorHandlerMiddleware runs on error path

## If you need more detail

→ resources/10-error-hierarchy.md — Complete error table with status codes, cause chaining examples, custom errors, ErrorHandlerMiddleware lifecycle, debugging, logging patterns, testing error paths
