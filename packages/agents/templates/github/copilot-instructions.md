# GitHub Copilot Instructions — Noony Framework

This project uses the **Noony Serverless Framework** — a TypeScript middleware framework for Google Cloud Functions with Fastify local dev support. Apply all Noony conventions when generating code.

---

## Middleware Ordering

Every Noony handler MUST follow this exact chain order:

1. `ErrorHandlerMiddleware` — MUST be first; catches all errors
2. `OpenTelemetryMiddleware` — wraps full request lifecycle
3. Header/structural checks (cheap fast-fail)
4. `BodyParserMiddleware` — MUST precede BodyValidationMiddleware
5. `BodyValidationMiddleware`
6. `PathParametersMiddleware` — before auth guards
7. Auth middlewares (FirebaseAuth, OAuth2, RouteGuard)
8. DI / business logic (`DependencyInjectionMiddleware`, custom)
9. `ResponseWrapperMiddleware` — MUST be last

Execution: `before` runs forward (0→N), `after`/`onError` run reverse (N→0).

---

## Error Handling

Import error classes from `@noony-serverless/core`.

- `ValidationError` (400) — invalid body, params
- `UnauthorizedError` (401) — missing or invalid auth token
- `ForbiddenError` (403) — authenticated but no permission
- `NotFoundError` (404) — resource not found
- `ConflictError` (409) — duplicate resource
- `InternalServerError` (500) — unexpected failures
- `ServiceError` — business logic layers (non-HTTP)

Always throw typed errors — never `throw new Error('...')`.
Never call `context.res.status(X).json(...)` for errors.
Wrap external API errors with cause chaining: `new InternalServerError('msg', originalError)`.
Use `ServiceError` in service layers; translate to `HttpError` in handlers.

---

## Type Safety

Preserve `<TBody, TUser>` generics through every layer: `Handler`, all middleware, `Context`.

All custom middleware must implement both generics:
```typescript
class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>) { ... }
}
```

Never use `as any`. If `validatedBody` or `context.user` is `unknown`, find the missing generic.

---

## Dependency Injection

Two scopes:
- `containerPool.global` — process lifetime (DB, SDKs, connection pools)
- `containerPool.local` — per-request (auth user, request metadata)

Use the singleton guard for global service initialization:
```typescript
let initialized = false, initializing = false;
async function init() {
  if (initialized || initializing) return;
  initializing = true;
  try { containerPool.initializeGlobal(Service, new Service()); initialized = true; }
  catch (e) { initializing = false; throw e; }
}
```

Resolve services with `getService(ServiceClass, context.container)` — not `Container.get()`.
Never use `Container.set()` or `Container.reset()` in production.
Never initialize services inside the handler/controller body.

---

## Testing

- Test the full handler chain as a unit — not the controller in isolation.
- Mock services through DI (`DependencyInjectionMiddleware`) — not `jest.mock()`.
- At least one error path test per handler.
- Assert on typed error classes: `toBeInstanceOf(NotFoundError)`.
- Reset request-scoped state between tests: `containerPool.resetLocal()`.

---

## Forbidden Patterns

- `ErrorHandlerMiddleware` not at position 1
- `ResponseWrapperMiddleware` not last
- `throw new Error('...')` — use typed error class
- `context.res.status(X).json(...)` — throw instead
- Both `context.res.json()` AND a return value in the same handler (double-send)
- `as any` anywhere in the handler chain
- Modifying the `Context` interface — use `context.businessData` Map
- `Container.set()` or `Container.reset()` in production
- `@fastify/otel` — use Noony's `OpenTelemetryMiddleware` instead
