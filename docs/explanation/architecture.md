# Handler Pipeline Architecture

This document explains **why** the Handler class is designed the way it is, how the middleware lifecycle works, and what trade-offs the implementation accepts. It is not a usage guide -- for that, see [Getting Started](../tutorials/01-getting-started.md).

---

## Why the Handler exists

A raw Google Cloud Function receives an HTTP request and must: parse it, authenticate the caller, validate the body, run business logic, and produce a consistent response. Without a shared abstraction, every function repeats that ceremony differently. Bugs hide in subtle inconsistencies: one function skips error formatting, another leaks stack traces, a third forgets to check permissions.

The Handler addresses this by separating two distinct concerns:

1. **The pipeline** -- the ordered set of cross-cutting operations applied to every request (defined once, reused across endpoints).
2. **The controller** -- the business logic unique to each endpoint (written fresh for each use case).

The Handler owns the pipeline. The controller is just a function that receives a fully-prepared `Context`.

---

## The middleware lifecycle

The chain is built with `.use()` and executed when `.execute()` or `.executeGeneric()` is called. Each registered middleware can implement up to three lifecycle hooks:

| Hook | When it runs | Execution order |
|------|-------------|-----------------|
| `before(context)` | Before the controller | Registration order (forward) |
| `after(context)` | After the controller succeeds | Reverse registration order |
| `onError(error, context)` | When any step throws | Reverse registration order |

```typescript
export interface BaseMiddleware<T = unknown, U = unknown> {
  before?(context: Context<T, U>): Promise<void>;
  after?(context: Context<T, U>): Promise<void>;
  onError?(error: Error, context: Context<T, U>): Promise<void>;
}
```

### Visualizing the pipeline

Given this handler:

```typescript
new Handler()
  .use(new ErrorHandlerMiddleware())   // MW-1
  .use(new AuthMiddleware())           // MW-2
  .use(new ValidationMiddleware())     // MW-3
  .handle(controller)
```

The execution sequence on a successful request:

```text
  Request arrives
       |
       v
  MW-1.before  (ErrorHandler sets up scope)
       |
       v
  MW-2.before  (Auth verifies token, sets context.user)
       |
       v
  MW-3.before  (Validation checks body against schema)
       |
       v
  controller   (Business logic runs with full Context)
       |
       v
  MW-3.after   (Validation cleanup, if any)
       |
       v
  MW-2.after   (Auth cleanup, if any)
       |
       v
  MW-1.after   (ErrorHandler final inspection)
       |
       v
  Response sent
```

When an error is thrown at any point:

```text
  Error thrown!
       |
       v
  MW-3.onError  (Inner middleware cleans up first)
       |
       v
  MW-2.onError  (Auth-specific error handling)
       |
       v
  MW-1.onError  (ErrorHandler maps error to HTTP response)
       |
       v
  Error response sent
```

---

## Why before runs forward and after/onError run in reverse

The reversal exists because of **symmetry of responsibility**. A middleware that opens a resource in `before` needs the opportunity to close it in `after` -- before middleware registered earlier gets a chance to interfere. The innermost middleware is closest to the business logic, so it cleans up first. The outermost middleware (typically `ErrorHandlerMiddleware`) is last to see `after`, giving it visibility over the entire response before it is sent.

The same logic applies to `onError`. `ErrorHandlerMiddleware` is registered first but handles errors last in the reverse pass -- by which point every inner middleware has had a chance to perform its own error-specific cleanup.

This design means the first middleware in the chain is effectively **a wrapper around everything else**. That is why `ErrorHandlerMiddleware` must always be registered first: it wraps the entire pipeline, so its `onError` hook has the final say over what error response the client receives.

A concrete example makes the reversal intuitive:

```typescript
new Handler()
  .use(new ErrorHandlerMiddleware())  // MW-1
  .use(new LoggingMiddleware())       // MW-2
  .handle(controller)
```

During a successful request:

1. `ErrorHandlerMiddleware.before` -- sets up try/catch scope
2. `LoggingMiddleware.before` -- records request start
3. `controller` -- runs business logic
4. `LoggingMiddleware.after` -- records request end, logs duration
5. `ErrorHandlerMiddleware.after` -- nothing to do on success

During a failed request (controller throws):

1. `LoggingMiddleware.onError` -- logs the error
2. `ErrorHandlerMiddleware.onError` -- maps the error to an HTTP response

`LoggingMiddleware` cleans up before `ErrorHandlerMiddleware` formats the response. That order is correct: you want to log the error details before the outer layer decides what to tell the client.

---

## Why generics are central, not optional

Without generics, every controller must cast `context.req.parsedBody` and `context.user` to concrete types manually. Those casts are invisible to the compiler -- if the types change, no error is surfaced until runtime.

The dual-generic signature `Handler<TBody, TUser>` threads type information from the point of handler construction all the way through every middleware and into the controller:

```typescript
export class Handler<T = unknown, U = unknown> {
  private baseMiddlewares: BaseMiddleware<T, U>[] = [];
  private handler!: (context: Context<T, U>) => Promise<void | unknown>;
}
```

This means:

- `context.req.validatedBody` is typed as `TBody` -- no cast needed
- `context.user` is typed as `TUser` -- no cast needed
- The compiler rejects a middleware typed for a different `TBody` from the one the handler was constructed with

The cost is that every custom middleware must also carry the same generics:

```typescript
// This breaks the type chain -- TBody and TUser collapse to unknown
export class LoggingMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> { ... }
}

// This preserves it
export class LoggingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>): Promise<void> { ... }
}
```

Using `as any` to bypass a type error in a middleware defeats the purpose of the generic system. The type chain silently breaks at that point, and downstream code loses its guarantees. The correct fix is always to make the generics explicit.

### Invariant generics

Once a `Handler<TBody, TUser>` is constructed, its generic parameters are fixed. This is intentional -- a pipeline that changes the shape of its data mid-chain is difficult to type correctly and harder to test. If a middleware needs to enrich data, it should write to `context.businessData` (typed as `Map<string, unknown>`) and the downstream code reads from it with an explicit cast. This keeps the primary type channel (`TBody`, `TUser`) clean.

---

## Framework-agnostic execution

The Handler provides two execution methods:

```text
                       +------------------+
                       |   Handler<T,U>   |
                       +--------+---------+
                                |
              +-----------------+-----------------+
              |                                   |
    .execute(req, res)              .executeGeneric(req, res)
              |                                   |
    adaptGCPRequest/Response          Already GenericRequest/Response
              |                                   |
              +-----------------+-----------------+
                                |
                       executeCore(req, res)
                                |
                    (shared pipeline logic)
```

Both methods converge on `executeCore`, the single source of truth for request handling. The difference is only in how the request/response are adapted:

- **`execute()`** -- expects GCP Functions `Request`/`Response` and adapts them internally
- **`executeGeneric()`** -- expects `GenericRequest`/`GenericResponse` directly, used by framework adapters (Fastify, Express)

This design means the same handler definition works unchanged across GCP Cloud Functions, Fastify (local dev), and Express. The adapter layer translates framework-specific types into the `GenericRequest`/`GenericResponse` interfaces, and the handler never knows the difference.

---

## How the container connects to the Handler

The `Context` object that flows through every middleware carries a `container` property -- a TypeDI `Container` instance. The Handler does not own the container; it creates a proxy container per request via `containerPool.createProxyContainer()` inside `executeCore`.

The reason for this separation is performance. Creating a new TypeDI container per request is expensive. The Hybrid Proxy Container pattern provides a lightweight proxy that reads from the global singleton but writes to a per-request local map. The Handler receives this proxy as part of the `Context` and passes it through to every middleware and controller unchanged.

From a middleware author's perspective, the container is simply available on `context.container`. Services registered globally (database connections, repositories) are resolved through the proxy to the singleton. Services registered within the request (such as the current user object) are written to the local scope and invisible to other concurrent requests.

For a deep dive into the container architecture, see [Container Model](./container-model.md).

---

## Performance optimizations

### Pre-computed middleware arrays

When `.handle()` is called, the Handler pre-computes two arrays:

```typescript
private precomputeMiddlewareArrays(): void {
  this.reversedMiddlewares = [...this.baseMiddlewares].reverse();
  this.errorMiddlewares = this.reversedMiddlewares.filter((m) => m.onError);
  this.middlewaresPrecomputed = true;
}
```

This trades a small amount of memory at startup for faster per-request execution. The arrays are computed once and reused for every subsequent request. The trade-off is that middleware cannot be added dynamically after the first execution -- but dynamic middleware would break the pre-computation guarantee and is an anti-pattern regardless.

### Separated execution methods

The pipeline is split into three private methods: `executeBeforeMiddlewares`, `executeAfterMiddlewares`, and `executeErrorMiddlewares`. Each iterates over the appropriate pre-computed array. This avoids repeated conditional checks during execution and makes the hot path as tight as possible.

---

## Design trade-offs

### Class-based middleware over functional middleware

The `BaseMiddleware` interface is implemented by classes. The alternative -- plain functions -- would allow simpler authorship but would make it harder to carry private state (such as a token verifier instance or configuration) without closures. Classes make constructor injection explicit and testable. Factory functions (`errorHandler()`, `bodyParser()`) provide a lightweight syntax when no instance state is needed.

### Single pipeline, no branching

The Handler does not support conditional middleware branching (e.g., "apply this middleware only if the request has a body"). The reason is predictability: a pipeline where all requests follow the same path is easier to reason about, test, and trace. Conditional logic belongs in the middleware's `before` method or in the controller, not in the pipeline structure itself.

### Controller return value capture

The Handler captures the return value from the controller and stores it on `context.responseData` if not already set. This enables a cleaner controller style where you return data directly instead of calling `context.res.json()`, while still allowing `after` middlewares to intercept and modify the response.

---

## Cross-references

- For a step-by-step introduction: [Getting Started Tutorial](../tutorials/01-getting-started.md)
- For complete method signatures and parameter tables: [API Reference](../reference/api.md)
- For how the DI container integrates with the Context: [Container Model](./container-model.md)
- For design patterns used throughout the framework: [Design Patterns](./design-patterns.md)
