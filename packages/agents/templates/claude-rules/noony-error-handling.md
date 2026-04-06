---
description: Noony error handling rules — apply when throwing errors or handling exceptions in Noony handlers.
globs: ["src/**/*.ts", "functions.ts"]
---

# Noony — Error Handling Rules

Typed errors from `@noony-serverless/core`: `ValidationError` (400), `UnauthorizedError` (401), `ForbiddenError` (403), `NotFoundError` (404), `ConflictError` (409), `InternalServerError` (500), `ServiceError` (non-HTTP).

- Always throw typed errors — never `throw new Error('...')`
- Never call `context.res.status(X).json(...)` — always throw
- Wrap external errors with cause chaining: `new InternalServerError('msg', originalError)`
- Use `ServiceError` in service layers; translate to `HttpError` in the handler
- `ErrorHandlerMiddleware` at position 1 — formats all thrown errors into JSON responses

Forbidden: generic `Error()` · manual `res.status()` · silent catch · missing cause on wraps.
