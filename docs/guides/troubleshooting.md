# Troubleshooting

Common issues organized by category, compiled from anti-patterns across the Noony Framework. Each entry includes the symptom, cause, and fix.

## Setup and Server

### Fastify server crashes on double-send

**Symptom**: `RESPONSE_SENT` error thrown during request handling, causing unhandled rejection.

**Cause**: The handler wrapper does not catch the `RESPONSE_SENT` error that Noony throws when a response has already been sent by a middleware.

**Fix**: Catch and ignore `RESPONSE_SENT` in your handler wrapper:

```typescript
try {
  await noonyHandler.executeGeneric(genericReq, genericRes);
} catch (error) {
  if (error instanceof Error && error.message === 'RESPONSE_SENT') {
    return; // Expected -- response already sent
  }
  throw error;
}
```

### Process hangs on shutdown

**Symptom**: SIGTERM received but process does not exit. Timeout errors in logs.

**Cause**: No graceful shutdown handler to close database connections, HTTP clients, or telemetry providers.

**Fix**: Add shutdown handlers:

```typescript
process.on('SIGTERM', async () => {
  await cleanup(); // Close DB, flush telemetry, etc.
  process.exit(0);
});
```

### Different behavior between local and production

**Symptom**: Handler works locally with Fastify but fails when deployed to Cloud Functions, or vice versa.

**Cause**: Using different middleware chains, validation schemas, or handler code for each environment.

**Fix**: Define the handler once and share it across both entry points. Use `handler.execute()` for Cloud Functions and `createFastifyHandler()` for Fastify, both pointing to the same handler instance.

---

## Middleware

### ErrorHandlerMiddleware does not catch errors

**Symptom**: Errors thrown by early middlewares are not caught. Unhandled rejections in logs.

**Cause**: `ErrorHandlerMiddleware` is not the first middleware in the chain. Its `onError` hook only catches errors from middlewares added after it.

**Fix**: Always register `ErrorHandlerMiddleware` first:

```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())  // Must be first
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => { /* ... */ });
```

### ResponseWrapperMiddleware wrapping is inconsistent

**Symptom**: Some responses are wrapped in `{ success, payload, timestamp }` format and others are not.

**Cause**: `ResponseWrapperMiddleware` is not last in the middleware chain. Its `after` hook runs in reverse order, so it must be registered last to execute its `after` first.

**Fix**: Always register `ResponseWrapperMiddleware` last:

```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  // ... other middlewares ...
  .use(new ResponseWrapperMiddleware())  // Must be last
  .handle(async (context) => { /* ... */ });
```

### Double-send error from middleware after hooks

**Symptom**: `RESPONSE_SENT` error when both `context.res.json()` and a return value are used in the same handler.

**Cause**: The handler sends a response via `context.res.json()`, and then `ResponseWrapperMiddleware` tries to wrap and send the return value.

**Fix**: Use one approach per handler. Either return data (let ResponseWrapperMiddleware send it) or call `context.res.json()` directly, not both.

### Middleware type chain broken

**Symptom**: TypeScript does not infer `context.req.validatedBody` type. Generic types are lost.

**Cause**: Middleware class does not use generics (`BaseMiddleware` instead of `BaseMiddleware<TBody, TUser>`).

**Fix**: Always include generics on middleware implementations:

```typescript
// Wrong
class MyMiddleware implements BaseMiddleware { /* ... */ }

// Correct
class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> { /* ... */ }
```

### businessData key conflicts between middlewares

**Symptom**: Data set by one middleware is overwritten by another.

**Cause**: Multiple middlewares use the same `context.businessData` key.

**Fix**: Use unique, namespaced keys. Avoid reserved keys like `otel_span` and `otel_provider` (used by OpenTelemetryMiddleware).

---

## Authentication and Authorization

### Guards fail because user is undefined

**Symptom**: `ForbiddenError` thrown even for users with correct permissions. `context.user` is `undefined`.

**Cause**: `RouteGuards` middleware is registered before `AuthenticationMiddleware`. The user context is not populated yet when guards run.

**Fix**: Always place authentication before guards:

```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))  // First: populates context.user
  .use(guardMiddleware)                                // After: checks permissions
  .handle(async (context) => { /* ... */ });
```

### RouteGuards used for token validation

**Symptom**: Token validation logic duplicated in guards. Guards rejecting valid tokens.

**Cause**: Confusing authentication (who are you?) with authorization (what can you do?). Guards check permissions, not tokens.

**Fix**: Use `AuthenticationMiddleware` for token verification. Use `RouteGuards` only for permission checks after the user is authenticated.

### RouteGuards.configure() called per request

**Symptom**: 50-100ms added to every request for guard configuration.

**Cause**: Calling `RouteGuards.configure()` inside the handler function instead of at module level.

**Fix**: Configure guards once at startup:

```typescript
// At module level, not inside a handler
const guardMiddleware = RouteGuards.configure({
  permissions: ['admin', 'editor'],
});

const handler = new Handler()
  .use(guardMiddleware)
  .handle(async (context) => { /* ... */ });
```

---

## Dependency Injection

### 300-500ms latency on every request

**Symptom**: Every request takes 300-500ms longer than expected. Database connections being created per request.

**Cause**: `initializeDependencies()` or `containerPool.initializeGlobal()` called inside the handler function instead of at startup.

**Fix**: Initialize once at startup using the three-condition guard pattern:

```typescript
let initialized = false;
let initPromise: Promise<void> | null = null;

async function initializeDependencies() {
  if (initialized) return;           // Condition 1: already done
  if (initPromise) return initPromise; // Condition 2: in progress
  initPromise = doInit();             // Condition 3: start init
  return initPromise;
}
```

### Concurrent requests initialize multiple times

**Symptom**: Multiple database connections created during cold start. Race condition errors.

**Cause**: Missing the `initPromise` check (Condition 2) in the initialization guard. Multiple concurrent requests each start their own initialization.

**Fix**: Add the `initPromise` guard as shown above.

### Initialization stuck in failure state

**Symptom**: After one initialization failure, all subsequent requests fail even if the underlying issue is resolved.

**Cause**: `initialized` flag is not reset on failure.

**Fix**: Reset state on error:

```typescript
try {
  await doInit();
  initialized = true;
} catch (error) {
  initPromise = null;  // Allow retry
  throw error;
}
```

### Direct Container.get() bypasses framework DI

**Symptom**: Services not properly scoped. Global state mutations between requests.

**Cause**: Using TypeDI's `Container.get()` directly instead of `getService()` helper.

**Fix**: Use the framework's DI access pattern:

```typescript
// Wrong
const service = Container.get(UserService);

// Correct
const service = getService<UserService>(context, 'userService');
```

### Database connections leak on shutdown

**Symptom**: Connection pool exhaustion after multiple restarts. Open socket warnings.

**Cause**: No cleanup function registered for SIGTERM/SIGINT.

**Fix**: Implement cleanup in your initialization module and call it on shutdown.

---

## Error Handling

### All errors return 500 status

**Symptom**: Validation errors, not-found errors, and auth errors all return HTTP 500.

**Cause**: Throwing generic `new Error()` instead of using Noony's error classes.

**Fix**: Use the appropriate error class:

| Error Class | Status Code |
|-------------|-------------|
| `ValidationError` | 400 |
| `UnauthorizedError` | 401 |
| `ForbiddenError` | 403 |
| `NotFoundError` | 404 |
| `ConflictError` | 409 |
| `TooLargeError` | 413 |
| `InternalServerError` | 500 |

### Original error context lost when wrapping

**Symptom**: Error logs show only the wrapper message, not the original cause.

**Cause**: Wrapping errors without cause chaining.

**Fix**: Use the `cause` option:

```typescript
try {
  await externalService.call();
} catch (error) {
  throw new InternalServerError('Service call failed', { cause: error });
}
```

### Errors swallowed silently

**Symptom**: Requests succeed (200) but expected side effects do not happen. No error logs.

**Cause**: Catching errors and not re-throwing or logging them.

**Fix**: Either re-throw with an appropriate error class, or log and re-throw. Never swallow errors in middleware or handler code.

### Response sent manually instead of throwing

**Symptom**: Error responses have inconsistent format. `ErrorHandlerMiddleware` not invoked.

**Cause**: Using `context.res.status(404).json()` instead of `throw new NotFoundError()`.

**Fix**: Always throw error classes. The `ErrorHandlerMiddleware` handles formatting and sending the error response.

---

## Validation

### BodyValidationMiddleware fails silently

**Symptom**: Validation does not run. `context.req.validatedBody` is `undefined`.

**Cause**: `BodyParserMiddleware` not included before `BodyValidationMiddleware`. Without it, `parsedBody` is not set, especially for Pub/Sub messages.

**Fix**: Include body parser before validator:

```typescript
.use(new BodyParserMiddleware())          // Sets parsedBody
.use(new BodyValidationMiddleware(schema)) // Reads from parsedBody
```

### Using parsedBody after validation

**Symptom**: TypeScript types do not match the validated data. Potential for unvalidated data usage.

**Cause**: Accessing `context.req.parsedBody` instead of `context.req.validatedBody` after the validation middleware runs.

**Fix**: Always use `validatedBody` after validation:

```typescript
// Wrong
const data = context.req.parsedBody;

// Correct
const data = context.req.validatedBody!;
```

### TypeScript interface duplicated alongside Zod schema

**Symptom**: Type and runtime validation drift apart as one is updated but not the other.

**Cause**: Defining a TypeScript interface separately from the Zod schema.

**Fix**: Infer the type from the schema:

```typescript
const userSchema = z.object({
  name: z.string(),
  email: z.string().email(),
});

type UserRequest = z.infer<typeof userSchema>; // Single source of truth
```

---

## Performance

### New HTTP clients or DB connections created per request

**Symptom**: High latency (50-500ms overhead). SSL handshake in every request trace.

**Cause**: Creating new service instances or connections inside the handler instead of using DI.

**Fix**: Register shared services as global dependencies during initialization. Use `DependencyInjectionMiddleware` to access them.

### Mutating global services during request processing

**Symptom**: Race conditions. Intermittent incorrect results under load.

**Cause**: Modifying state on globally shared services within request handlers.

**Fix**: Use local-scope services for per-request data. Global services should be stateless or read-only during request processing. See the proxy container pattern in the DI guide.

---

## Type Safety

### `as any` used to bypass type errors

**Symptom**: Runtime type errors that TypeScript did not catch.

**Cause**: Using `as any` to silence type errors instead of fixing the generic chain.

**Fix**: Ensure all middlewares in the chain include proper generics `<TBody, TUser>`. If the handler uses `new Handler<UserRequest, AuthUser>()`, all middlewares should use matching generics.

### Type inference lost in middleware chain

**Symptom**: `context.req.validatedBody` inferred as `unknown` instead of the expected type.

**Cause**: One or more middlewares in the chain omit generics.

**Fix**: Check every middleware in the chain. Each must implement `BaseMiddleware<TBody, TUser>` with the correct type parameters.

---

## Testing

### handler.execute() fails with mock objects

**Symptom**: Type errors or unexpected behavior when passing mock req/res to `execute()`.

**Cause**: `execute()` expects native framework (GCP/Express) request/response objects, not mock objects.

**Fix**: Use `executeGeneric()` with objects that satisfy `GenericRequest` and `GenericResponse` interfaces:

```typescript
const mockReq: GenericRequest<UserRequest> = {
  method: 'POST',
  url: '/api/users',
  path: '/api/users',
  headers: { 'content-type': 'application/json' },
  query: {},
  params: {},
  body: userData,
  parsedBody: userData,
};

await handler.executeGeneric(mockReq, mockRes);
```

### Container pollution between tests

**Symptom**: Tests pass individually but fail when run together. State leaks between tests.

**Cause**: Using `Container.set()` or `Container.reset()` directly, which affects the global TypeDI container.

**Fix**: Use `DependencyInjectionMiddleware` to inject mock services per test, which uses the framework's scoped container.

## Related

- [Middleware Ordering Guide](./middleware-ordering.md)
- [Error Handling Guide](./error-handling.md)
- [Dependency Injection Guide](./dependency-injection.md)
- [Custom Adapters Guide](./custom-adapters.md)
- [Validation Schemas Guide](./validation-schemas.md)
