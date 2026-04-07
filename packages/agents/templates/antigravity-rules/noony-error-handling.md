---
description: Noony error handling rules. Apply whenever throwing errors, handling exceptions, or mapping to HTTP status codes in Noony handlers.
globs:
  - "src/**/*.ts"
  - "functions.ts"
alwaysApply: false
---

# Noony — Error Handling Rules

## Typed Error Classes (import from `@noony-serverless/core`)

| Class | HTTP Status | When to use |
|-------|-------------|-------------|
| `ValidationError` | 400 | Invalid request body, query params, path params |
| `UnauthorizedError` | 401 | Missing or invalid authentication token |
| `ForbiddenError` | 403 | Authenticated but lacks permission |
| `NotFoundError` | 404 | Resource does not exist |
| `ConflictError` | 409 | Duplicate resource, conflict |
| `InternalServerError` | 500 | Unexpected failures |
| `ServiceError` | n/a | Business logic errors in non-HTTP layers |

## Rules

- Always throw typed errors — `throw new NotFoundError('...')` not `throw new Error('...')`
- Never call `context.res.status(X).json(...)` for errors — always throw
- Wrap external errors with cause chaining: `new InternalServerError('msg', originalError)`
- Use `ServiceError` in service layers; translate to `HttpError` subclass in the handler
- `ErrorHandlerMiddleware` MUST be at position 1 — it formats all thrown errors into JSON responses

## Forbidden

- `throw new Error('...')` — becomes opaque 500
- `context.res.status(X).json(...)` — bypasses error formatting
- `catch (err) { /* silent */ }` — hides bugs
- Missing cause when wrapping: `new InternalServerError('msg')` when you have the original error

## Reference

→ `docs/noony-skills/error-handling/SKILL.md`
