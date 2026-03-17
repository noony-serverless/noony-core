# Middleware Ordering

How to compose middleware pipelines in the correct order, understand execution flow, and avoid subtle runtime failures caused by misordering.

**Related links:** [Custom Middleware](./custom-middleware.md) | [Middleware Reference](../reference/middlewares/INDEX.md) | [Error Handling](./error-handling.md)

## Prerequisites

- Understanding of the Noony Handler and middleware lifecycle
- Familiarity with the built-in middlewares (ErrorHandler, ResponseWrapper, BodyParser, etc.)

---

## The Core Rule

**Put cheap, structural middleware early; put expensive, semantic middleware late.** A request missing a required header should never trigger a database call.

Two ordering constraints are non-negotiable:

1. `ErrorHandlerMiddleware` must be **first** -- its `onError` hook runs last (reverse order), giving it final authority over error responses.
2. `ResponseWrapperMiddleware` must be **last** -- its `after` hook runs first (reverse order), wrapping the handler's return value before any other `after()` hook sees it.

## Execution Flow

The pipeline runs in two directions:

- **`before` hooks** execute top-to-bottom (position 0, 1, 2, ... N).
- **`after` and `onError` hooks** execute bottom-to-top (position N, N-1, ... 0).

```
Request arrives
    |
Middleware1.before()  <-- position 0 runs first
    |
Middleware2.before()  <-- position 1 runs second
    |
Middleware3.before()  <-- position 2 runs third
    |
Handler (business logic)
    |
    +-- [If error thrown]
    |   |
    |   Middleware3.onError()  <-- reverse: position 2 first
    |   |
    |   Middleware2.onError()  <-- reverse: position 1 second
    |   |
    |   Middleware1.onError()  <-- reverse: position 0 third (last say)
    |
    +-- [If success]
        |
        Middleware3.after()   <-- reverse: position 2 first
        |
        Middleware2.after()   <-- reverse: position 1 second
        |
        Middleware1.after()   <-- reverse: position 0 third
    |
Response sent
```

This reverse order is why ErrorHandler at position 0 gets the **last** say on errors, and ResponseWrapper at the last position gets the **first** shot at wrapping the response.

## Canonical Ordering Table

| Position | Middleware | Why Here |
|----------|-----------|----------|
| **1** | `ErrorHandlerMiddleware` | Its `onError` runs last (reverse), catching errors from every middleware below it |
| **2** | `DependencyInjectionMiddleware` | Services must be available before any subsequent middleware calls them |
| **3** | `OpenTelemetryMiddleware` | Wraps full request lifecycle including auth for complete tracing |
| **4** | `HeaderVariablesMiddleware` | Cheap fail-fast -- rejects requests without required headers before any expensive work |
| **5** | `PathParametersMiddleware` | Route params available to auth/guard logic |
| **6** | `QueryParametersMiddleware` | Optional presence-check before business logic |
| **7** | `BodyParserMiddleware` | Parses body only if earlier validations pass |
| **8** | `BodyValidationMiddleware` | Validates the parsed body with Zod schema |
| **9** | Auth / guard middlewares | Runs after all inputs are present and validated |
| **N-1** | Custom middlewares | Business-specific logic |
| **N** | `ResponseWrapperMiddleware` | Its `after` fires first (reverse), wrapping `context.responseData` before any other `after()` hook |

## Common Pipeline Recipes

### CRUD Handler with Validation

```typescript
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware(services))
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
  .use(new BodyParserMiddleware<CreateUserRequest>())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const userSvc = context.container?.get(UserService);
    const userData = context.req.validatedBody!;
    const user = await userSvc.create(userData);
    return { success: true, user };
  });
```

### Read Handler with Path Params, Query Params, and Headers

```typescript
const getUserHandler = new Handler<UserParams>()
  .use(new ErrorHandlerMiddleware())
  .use(new HeaderVariablesMiddleware(['authorization', 'accept']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const auth = context.req.headers.authorization as string;
    const { userId } = context.req.params as UserParams;
    const { page = '1', limit = '10' } = context.req.query;

    const user = await authenticateAndGetUser(auth, userId);
    return { success: true, user };
  });
```

### Fully-Typed REST Handler

```typescript
const productHandler = new Handler<ProductParams>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware([{ id: ProductService, value: productService }]))
  .use(new HeaderVariablesMiddleware(['authorization', 'x-client-version']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { productId } = context.req.params as ProductParams;
    const query = productQuerySchema.parse(context.req.query);

    const productSvc = context.container?.get(ProductService);
    const product = await productSvc.findById(productId);
    return { success: true, product };
  });
```

## Common Mistakes

### Mistake 1: ErrorHandlerMiddleware Not First

When ErrorHandler is placed after other middlewares, errors thrown by those earlier middlewares are not caught properly. ErrorHandler's `onError` runs too early in the reverse chain instead of having the final say.

```typescript
// WRONG -- ErrorHandler at position 2, onError runs first (too early)
const handler = new Handler()
  .use(new AuthenticationMiddleware())
  .use(new BodyValidationMiddleware())
  .use(new ErrorHandlerMiddleware())
  .handle(controller);

// CORRECT -- ErrorHandler at position 0, onError runs last (final authority)
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware())
  .use(new BodyValidationMiddleware())
  .handle(controller);
```

### Mistake 2: ResponseWrapperMiddleware Not Last

When ResponseWrapper is not in the last position, its `after()` hook does not run first in the reverse chain. Other middlewares may send the response before wrapping can occur, leading to unwrapped or double-sent responses.

```typescript
// WRONG -- ResponseWrapper at position 0, after() runs last (can't wrap)
const handler = new Handler()
  .use(new ResponseWrapperMiddleware())
  .use(new BodyValidationMiddleware())
  .use(new ErrorHandlerMiddleware())
  .handle(controller);

// CORRECT -- ResponseWrapper at last position, after() runs first (wraps immediately)
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(controller);
```

### Mistake 3: OpenTelemetryMiddleware Too Late

If OTEL is placed after AuthenticationMiddleware, JWT verification time is not traced. Authentication latency becomes invisible in spans.

```typescript
// WRONG -- auth runs before OTEL span starts
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware())
  .use(new OpenTelemetryMiddleware())
  .handle(controller);

// CORRECT -- OTEL span wraps the entire request including auth
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new OpenTelemetryMiddleware())
  .use(new AuthenticationMiddleware())
  .handle(controller);
```

### Mistake 4: BodyValidation Without BodyParser

`BodyValidationMiddleware` validates `context.req.parsedBody`, which is populated by `BodyParserMiddleware`. Without the parser, there is nothing to validate.

```typescript
// WRONG -- validation without parsing
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(controller);

// CORRECT -- parse then validate
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(controller);
```

### Mistake 5: Expensive Middleware Before Cheap Validation

```typescript
// WRONG -- DB call happens even for requests missing the authorization header
new Handler()
  .use(expensiveDbAuthMiddleware)
  .use(new HeaderVariablesMiddleware(['authorization']))

// CORRECT -- header check fails first at negligible cost
new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .use(expensiveDbAuthMiddleware)
```

## Response Sending Rules

A handler can send a response in one of two ways:

1. **Return a value** -- Handler sets `context.responseData`, and `ResponseWrapperMiddleware.after()` wraps it into the standard format.
2. **Call `context.res.json()` directly** -- Headers are sent immediately. `ResponseWrapperMiddleware` skips (it checks `context.res.headersSent`).

Never do both in the same handler:

```typescript
// WRONG -- double-send conflict
context.res.json({ data: user });  // First send
return { extra: 'data' };          // Second send attempt
```

### Prevention in Custom after() Hooks

If you write a custom middleware with an `after()` hook that may send a response, always check `headersSent` first:

```typescript
async after(context: Context): Promise<void> {
  if (!context.res.headersSent) {
    context.res.json({ custom: 'data' });
  }
}
```

## Inter-Middleware Communication

Use `context.businessData` (a Map) to pass data between middlewares. Never modify the Context interface.

```typescript
// In TimingMiddleware.before()
context.businessData.set('startTime', Date.now());

// In LoggingMiddleware.after() (runs after TimingMiddleware if registered later)
const startTime = context.businessData.get('startTime') as number;
```

**Reserved keys:**
- `'otel_span'` -- Used by `OpenTelemetryMiddleware` for span tracking. Do not overwrite.

## Anti-Patterns

- **Omitting ErrorHandlerMiddleware entirely.** Without it, unhandled errors bubble up as unformatted 500s with no body shaping.
- **Placing ResponseWrapperMiddleware anywhere except last.** Its `after` hook must fire first in the reverse chain.
- **Skipping ordering review when adding a new middleware.** Wrong order causes subtle failures that only appear at runtime under specific request shapes.
- **Sending responses in multiple middleware `after()` hooks.** Only one middleware should call `context.res.json()` -- usually ResponseWrapperMiddleware.
- **Using `context.businessData` with reserved keys.** The key `'otel_span'` breaks OpenTelemetry integration if overwritten.

## See Also

- [Custom Middleware](./custom-middleware.md) -- How to create your own middleware
- [Middleware Reference](../reference/middlewares/INDEX.md) -- Full signature list for all built-in middlewares
- [Error Handling](./error-handling.md) -- Error classes and HTTP status mapping
- [Validation Schemas](./validation-schemas.md) -- Zod schema patterns for body validation
