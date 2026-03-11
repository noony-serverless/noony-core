# Understanding the Handler: Architecture and Design

The `Handler` class exists because serverless functions need a repeatable, type-safe way to compose cross-cutting concerns — authentication, validation, error handling, logging — without coupling that logic to the business code that varies per endpoint. This document explains the design decisions behind `Handler`, why generics are central rather than optional, and what trade-offs the implementation accepts.

---

## Why the Handler exists

A raw Google Cloud Function receives an HTTP request and must: parse it, authenticate the caller, validate the body, run business logic, and produce a consistent response. Without a shared abstraction, every function repeats that ceremony differently. Bugs hide in subtle inconsistencies: one function skips error formatting, another leaks stack traces, a third forgets to check permissions.

The Handler addresses this by separating two distinct concerns:

1. **The pipeline** — the ordered set of cross-cutting operations applied to every request (defined once, reused across endpoints).
2. **The controller** — the business logic unique to each endpoint (written fresh for each use case).

The Handler owns the pipeline. The controller is just a function that receives a fully-prepared `Context`.

---

## How the middleware chain works

The chain is built with `.use()` and executed when `.execute()` or `.executeGeneric()` is called. Each registered middleware can implement up to three lifecycle methods:

- `before(context)` — runs before the controller, in registration order
- `after(context)` — runs after the controller, in reverse registration order
- `onError(error, context)` — runs when any step throws, in reverse registration order

```typescript
export interface BaseMiddleware<T = unknown, U = unknown> {
  before?(context: Context<T, U>): Promise<void>;
  after?(context: Context<T, U>): Promise<void>;
  onError?(error: Error, context: Context<T, U>): Promise<void>;
}
```

Given this handler:

```typescript
new Handler()
  .use(new ErrorHandlerMiddleware())   // MW-1
  .use(new AuthMiddleware())           // MW-2
  .use(new ValidationMiddleware())     // MW-3
  .handle(controller)
```

The execution sequence is:

```text
MW-1.before → MW-2.before → MW-3.before → controller
                                        ↓
                  MW-3.after ← MW-2.after ← MW-1.after

On error at any point:
  MW-3.onError ← MW-2.onError ← MW-1.onError
```

---

## Why before runs forward and after/onError run in reverse

The reason for the reversal is symmetry of responsibility. A middleware that opens a resource in `before` needs the opportunity to close it in `after` — before middleware registered earlier get a chance to interfere. The innermost middleware is closest to the business logic, so it cleans up first. The outermost middleware (typically `ErrorHandlerMiddleware`) is last to see `after`, giving it visibility over the entire response before it is sent.

The same logic applies to `onError`. `ErrorHandlerMiddleware` is registered first but handles errors last in the reverse pass — by which point every inner middleware has had a chance to perform its own error-specific cleanup.

This design means the first middleware in the chain is effectively a wrapper around everything else. That is why `ErrorHandlerMiddleware` must always be registered first: it wraps the entire pipeline, so its `onError` hook has the final say over what error response the client receives.

---

## Why generics matter

Without generics, every controller must cast `context.req.parsedBody` and `context.user` to concrete types manually. Those casts are invisible to the compiler — if the types change, no error is surfaced until runtime.

The dual-generic signature `Handler<TBody, TUser>` threads type information from the point of handler construction all the way through every middleware and into the controller:

```typescript
export class Handler<T = unknown, U = unknown> {
  private baseMiddlewares: BaseMiddleware<T, U>[] = [];
  private handler!: (context: Context<T, U>) => Promise<void>;
}
```

This means:

- `context.req.validatedBody` is typed as `TBody` — no cast needed
- `context.user` is typed as `TUser` — no cast needed
- The compiler rejects a middleware typed for a different `TBody` from the one the handler was constructed with

The cost is that every custom middleware must also carry the same generics:

```typescript
// This breaks the type chain — TBody and TUser collapse to unknown
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

---

## The before/after/onError lifecycle and why it is reversed

A concrete example makes the reversal intuitive. Consider a handler with a logging middleware and an error handler:

```typescript
new Handler()
  .use(new ErrorHandlerMiddleware())  // MW-1
  .use(new LoggingMiddleware())       // MW-2
  .handle(controller)
```

During a successful request:

1. `ErrorHandlerMiddleware.before` — sets up try/catch scope
2. `LoggingMiddleware.before` — records request start
3. `controller` — runs business logic
4. `LoggingMiddleware.after` — records request end, logs duration
5. `ErrorHandlerMiddleware.after` — nothing to do on success

During a failed request (controller throws):

1. `LoggingMiddleware.onError` — logs the error
2. `ErrorHandlerMiddleware.onError` — maps the error to an HTTP response

`LoggingMiddleware` cleans up before `ErrorHandlerMiddleware` formats the response. That order is correct: you want to log the error details before the outer layer decides what to tell the client.

---

## How the container pool connects to the Handler

The `Context` object that flows through every middleware carries a `container` property — a TypeDI `Container` instance. The Handler does not create this container itself; it is provided by the container pool infrastructure when the handler executes.

The reason for this separation is performance. Creating a new TypeDI container per request is expensive. The Hybrid Proxy Container pattern (described in [03-container-architecture.md](./03-container-architecture.md)) solves this by providing a lightweight proxy that reads from the global singleton but writes to a per-request local map. The Handler receives this proxy as part of the `Context` and passes it through to every middleware and controller unchanged.

From a middleware author's perspective, the container is simply available on `context.container`. Services registered globally (database connections, repositories) are resolved through the proxy to the singleton. Services registered within the request (such as the current user object) are written to the local scope and invisible to other concurrent requests.

---

## Design trade-offs

### Class-based middleware over functional middleware

The `BaseMiddleware` interface is implemented by classes. The alternative — plain functions — would allow simpler authorship but would make it harder to carry private state (such as a token verifier instance or configuration) without closures. Classes make constructor injection explicit and testable. Factory functions (`errorHandler()`, `bodyValidator<T>(schema)`) provide a lightweight syntax when no instance state is needed.

### Pre-computed middleware arrays

When the handler first executes, it pre-computes the reversed middleware array and a filtered array of only the middlewares that implement `onError`:

```typescript
private precomputeMiddlewareArrays(): void {
  if (this.middlewaresPrecomputed) return;
  this.reversedMiddlewares = [...this.baseMiddlewares].reverse();
  this.errorMiddlewares = this.reversedMiddlewares.filter((m) => m.onError);
  this.middlewaresPrecomputed = true;
}
```

This trades a small amount of memory at startup for faster per-request execution. The arrays are computed once and reused for every subsequent request. The trade-off is that middleware cannot be added dynamically after the first execution — but dynamic middleware would break the pre-computation guarantee and is an anti-pattern regardless.

### Single pipeline, no branching

The Handler does not support conditional middleware branching (e.g., "apply this middleware only if the request has a body"). The reason is predictability: a pipeline where all requests follow the same path is easier to reason about, test, and trace. Conditional logic belongs in the middleware's `before` method or in the controller, not in the pipeline structure itself.

### Invariant generics

Once a `Handler<TBody, TUser>` is constructed, its generic parameters are fixed. This is intentional — a pipeline that changes the shape of its data mid-chain is difficult to type correctly and harder to test. If a middleware needs to enrich data, it should write to `context.businessData` (typed as `Map<string, unknown>`) and the downstream code reads from it with an explicit cast. This keeps the primary type channel (`TBody`, `TUser`) clean.

---

## Cross-references

- For practical usage and step-by-step construction: [00-getting-started.md](./00-getting-started.md)
- For the full API surface (method signatures, parameter tables): [02-api-reference.md](./02-api-reference.md)
- For how the DI container integrates with the Context: [03-container-architecture.md](./03-container-architecture.md)
