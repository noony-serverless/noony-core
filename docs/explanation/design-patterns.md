# Design Patterns in the Noony Framework

This document identifies the classical design patterns used throughout the Noony Framework, explains where each appears in the codebase, and why it was chosen over alternatives. Understanding these patterns helps contributors work with the grain of the architecture rather than against it.

---

## Chain of Responsibility

### What it is

A sequence of handlers where each handler decides whether to process a request or pass it along. Each link in the chain has the opportunity to act on the request, modify it, or short-circuit the pipeline.

### Where it appears

The **middleware pipeline** in `Handler` is a Chain of Responsibility. Each middleware registered via `.use()` forms a link in the chain:

```text
  MW-1.before --> MW-2.before --> MW-3.before --> controller
                                                      |
                  MW-3.after <-- MW-2.after <-- MW-1.after
```

The chain is explicit and ordered. Every middleware sees every request (there is no "skip" mechanism at the pipeline level). The chain is traversed forward for `before` hooks and in reverse for `after` and `onError` hooks.

```typescript
// Each middleware is a link in the chain
export interface BaseMiddleware<T = unknown, U = unknown> {
  before?(context: Context<T, U>): Promise<void>;
  after?(context: Context<T, U>): Promise<void>;
  onError?(error: Error, context: Context<T, U>): Promise<void>;
}
```

### Why it was chosen

The middleware pipeline must be **predictable and traceable**. Every request follows the same path through the same middleware, in the same order. This makes debugging straightforward -- you always know which middleware ran and in what sequence. Alternative patterns like event buses or observer patterns would decouple the ordering, making the flow harder to reason about in a serverless context where cold starts and request isolation matter.

The decision to keep all middleware in a single linear chain (no branching, no conditional skipping) is deliberate. Conditional logic belongs inside individual middleware `before` methods, not in the pipeline structure itself.

---

## Strategy Pattern

### What it is

Define a family of algorithms, encapsulate each one, and make them interchangeable. The algorithm varies independently from clients that use it.

### Where it appears

**`CustomTokenVerificationPort<T>`** in the authentication middleware is a textbook Strategy. The authentication logic defines the interface; concrete implementations provide the algorithm:

```typescript
// The strategy interface
export interface CustomTokenVerificationPort<T> {
  verifyToken(token: string): Promise<T>;
}

// Strategy A: JWT verification
class JWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    const payload = jwt.verify(token, this.secret);
    return { id: payload.sub, email: payload.email };
  }
}

// Strategy B: API key verification
class APIKeyVerifier implements CustomTokenVerificationPort<APIKeyUser> {
  async verifyToken(token: string): Promise<APIKeyUser> {
    return await this.lookupKey(token);
  }
}
```

The `AuthenticationMiddleware` accepts any implementation through its constructor:

```typescript
export class AuthenticationMiddleware<TUser, TBody>
  implements BaseMiddleware<TBody, TUser> {
  constructor(
    private tokenVerificationPort: CustomTokenVerificationPort<TUser>,
    private options: AuthenticationOptions = {}
  ) {}
}
```

**Permission resolution strategies** in the guard system are another instance. The `PermissionResolutionStrategy` enum (`ON_DEMAND`, `PRE_EXPANSION`) selects between different algorithms for resolving wildcard permissions, each with different performance characteristics.

**Error categorization** in `ErrorHandlerMiddleware` uses the `ErrorMatcher` interface as a strategy for classifying errors. Custom matchers are evaluated before built-in ones:

```typescript
export interface ErrorMatcher {
  matches: (error: Error) => boolean;
  category: ErrorCategory;
}
```

### Why it was chosen

Authentication is the most variable concern across projects. Some use Firebase, others use JWT libraries, others verify against external OAuth2 providers. The Strategy pattern lets the framework define the contract (`verifyToken(token) => Promise<User>`) without knowing or caring about the implementation. Projects swap strategies without modifying the middleware or the Handler.

The same reasoning applies to error categorization -- different projects have different error classification needs, but the error handling pipeline remains constant.

---

## Factory Pattern

### What it is

Provide a function that creates and returns an object, encapsulating the construction logic. Callers get a configured instance without knowing the creation details.

### Where it appears

Most built-in middleware in Noony is available in **two forms**: a class and a factory function. The factory functions are the Factory pattern:

```typescript
// Factory function -- creates a configured middleware object
export const errorHandler = <TBody, TUser>(
  options?: ErrorHandlerOptions
): BaseMiddleware<TBody, TUser> => ({
  onError: async (error, context) => {
    await handleError(error, context, options);
  },
});

// Factory function -- creates a body parser with configuration
export const bodyParser = <TBody, TUser>(
  maxSize: number = MAX_JSON_SIZE
): BaseMiddleware<TBody, TUser> => ({
  before: async (context) => {
    // parsing logic with maxSize closure
  },
});

// Factory function -- creates a body validator with schema
export const bodyValidatorMiddleware = <T, U>(
  schema: z.ZodType<T>
): { before: (context: Context<T, U>) => Promise<void> } => ({
  before: async (context) => {
    context.req.validatedBody = validateBody(schema, context);
  },
});
```

These are used as:

```typescript
new Handler()
  .use(errorHandler())                    // Factory
  .use(bodyParser<UserRequest>())         // Factory with type param
  .use(bodyValidatorMiddleware(schema))   // Factory with runtime config
  .handle(controller);
```

### Why it was chosen

Factory functions provide a **lighter syntax** than class instantiation when the middleware has no mutable instance state beyond what is captured in the closure. They also enable partial application -- `bodyParser(2 * 1024 * 1024)` returns a middleware pre-configured with a 2MB limit.

The dual class/factory approach serves two audiences:

- **Factory functions** for simple, stateless middleware configuration (most use cases)
- **Classes** for middleware that needs constructor injection, private state, or method composition (e.g., `AuthenticationMiddleware` with its `tokenVerificationPort`)

---

## Flyweight Pattern

### What it is

Use sharing to support large numbers of fine-grained objects efficiently. Instead of each object owning its own copy of shared data, many objects reference a single shared instance.

### Where it appears

The **ContainerPool's global container** is a Flyweight. Process-lifetime services (database connections, logger, config) are stored once in the global container. Every request proxy references this same shared state:

```text
  Global Container (shared, read-only during requests)
    +-- Database:  1 instance, used by all requests
    +-- Logger:    1 instance, used by all requests
    +-- Config:    1 instance, used by all requests

  Request A Proxy --> reads from global (zero copy)
  Request B Proxy --> reads from global (zero copy)
  Request C Proxy --> reads from global (zero copy)
```

Without the Flyweight, each request would clone all global services -- O(N) memory per request where N is the number of global services. With the Flyweight, the overhead is O(1) per request (just the proxy wrapper and an empty local overrides map).

**Pre-allocated error category objects** in the error handler middleware are another Flyweight instance:

```typescript
// Pre-allocated, shared across all requests
const DATABASE_ERROR: ErrorCategory = {
  type: 'DATABASE_ERROR',
  userMessage: 'Database temporarily unavailable.',
  httpStatus: 503,
  retryable: true,
};

const TIMEOUT_ERROR: ErrorCategory = { ... };
const EXTERNAL_SERVICE_ERROR: ErrorCategory = { ... };
const INTERNAL_ERROR: ErrorCategory = { ... };
```

These objects are created once at module load and reused for every error categorization, avoiding per-request allocations.

### Why it was chosen

In serverless environments, cold start time and per-request memory are critical performance dimensions. The Flyweight pattern directly addresses both by ensuring shared resources are allocated once and referenced many times. The Hybrid Proxy Container is the framework's most impactful performance optimization -- it reduces per-request DI overhead from O(N) to O(1).

For a detailed analysis, see [Container Model](./container-model.md).

---

## Adapter Pattern

### What it is

Convert the interface of a class into another interface clients expect. Adapters let classes work together that could not otherwise because of incompatible interfaces.

### Where it appears

The framework-agnostic execution model relies on adapters to normalize different HTTP frameworks into the `GenericRequest`/`GenericResponse` interfaces:

```text
  GCP Cloud Functions              Fastify                    Express
  +------------------+    +------------------+    +------------------+
  | Request/Response |    | FastifyRequest/  |    | req/res          |
  | (GCP-specific)   |    | FastifyReply     |    | (Express-specific)|
  +--------+---------+    +--------+---------+    +--------+---------+
           |                       |                       |
    adaptGCPRequest()     adaptFastifyRequest()   (future adapter)
    adaptGCPResponse()    adaptFastifyResponse()
           |                       |                       |
           v                       v                       v
  +---------------------------------------------------+
  |       GenericRequest<T> / GenericResponse          |
  |       (Framework-agnostic interface)               |
  +---------------------------------------------------+
           |
           v
  +---------------------------------------------------+
  |       Handler.executeCore()                        |
  |       (Single pipeline, framework-unaware)         |
  +---------------------------------------------------+
```

Each adapter function translates framework-specific APIs into the `GenericRequest`/`GenericResponse` contracts:

- **`adaptGCPRequest()`** in `src/core/core.ts` -- converts GCP Functions `Request` to `GenericRequest`
- **`adaptGCPResponse()`** in `src/core/core.ts` -- wraps GCP Functions `Response` in `GenericResponse`
- **`adaptFastifyRequest()`** in `src/utils/fastify-wrapper.ts` -- converts Fastify's `FastifyRequest` to `GenericRequest`
- **`adaptFastifyResponse()`** in `src/utils/fastify-wrapper.ts` -- wraps Fastify's `FastifyReply` in `GenericResponse`

The **`CustomTokenVerificationPortAdapter`** in the guards system is another adapter, bridging the guard system's `TokenValidator` interface to the authentication middleware's `CustomTokenVerificationPort`:

```typescript
export class CustomTokenVerificationPortAdapter<TUser>
  implements CustomTokenVerificationPort<TUser> {
  // Adapts TokenValidator to CustomTokenVerificationPort
}
```

### Why it was chosen

The Adapter pattern allows the Handler to contain a single pipeline implementation that works across multiple HTTP frameworks. Without adapters, the Handler would need framework-specific code paths -- defeating the "write once, run anywhere" goal.

The adapter layer is also where framework-specific optimizations live. For example, `adaptFastifyRequest` stores the original Fastify request in a `WeakMap` so body validation middleware can access it even after properties are copied. This optimization is invisible to the Handler and middleware layers.

---

## Proxy Pattern

### What it is

Provide a surrogate or placeholder for another object to control access to it. The proxy has the same interface as the real object, so clients cannot tell the difference.

### Where it appears

The **Hybrid Proxy Container** uses a literal ES6 `Proxy` to wrap the global TypeDI container:

```typescript
const proxyContainer = new Proxy(this.globalContainer, {
  get(target, prop, receiver) {
    if (prop === 'get') {
      return function(serviceId) {
        // Check local overrides first, then fall back to global
        if (localOverrides.has(serviceId)) {
          return localOverrides.get(serviceId);
        }
        return target.get(serviceId);
      };
    }
    if (prop === 'set') {
      return function(serviceId, value) {
        // Write to local scope only
        localOverrides.set(serviceId, value);
      };
    }
    // ... intercepts for remove, reset, has
  }
});
```

The proxy implements the same `ContainerInstance` interface as the real container. Middleware authors call `context.container.get()` and `context.container.set()` without knowing whether they are talking to the real container or the proxy. The proxy transparently provides read-through to global state and write-isolation to request-local state.

### Why it was chosen

The Proxy pattern was chosen because it provides **interface compatibility** with TypeDI's existing container API. No middleware or handler code needs to change when the DI implementation switches from direct container access to the proxy model. The proxy also enables the Copy-on-Write semantics (via local overrides map and tombstone markers) that make request isolation possible without cloning.

---

## Template Method (implicit)

### What it is

Define the skeleton of an algorithm in a method, deferring some steps to subclasses or implementations. The overall structure is fixed; the variable parts are pluggable.

### Where it appears

The Handler's `executeCore` method defines a fixed algorithm skeleton:

```text
  1. Create proxy container
  2. Create context
  3. Run all before middlewares (forward)
  4. Run controller
  5. Capture return value
  6. Run all after middlewares (reverse)
  -- on error --
  7. Run all onError middlewares (reverse)
```

This sequence never changes. What varies is the **content** of the middleware hooks and the controller. The framework defines the template (steps 1-7); users fill in the variable parts by registering middleware and providing a controller function.

This is not a classical Template Method (no abstract base class with overridable methods), but the structural intent is the same: a fixed algorithm with pluggable steps.

### Why it was chosen

A fixed execution template makes the framework predictable. Users do not need to understand the execution engine -- they only need to know that `before` runs first, `after` runs last, and `onError` catches failures. The pipeline behaves identically regardless of which middleware are registered.

---

## Summary

| Pattern | Where in Noony | Key benefit |
|---------|---------------|-------------|
| **Chain of Responsibility** | Middleware pipeline (`Handler.use()`) | Predictable, ordered request processing |
| **Strategy** | `CustomTokenVerificationPort`, `ErrorMatcher`, permission resolvers | Swappable algorithms without changing pipeline |
| **Factory** | `errorHandler()`, `bodyParser()`, `bodyValidatorMiddleware()` | Lightweight middleware creation, partial application |
| **Flyweight** | Global container services, pre-allocated error categories | O(1) per-request memory in serverless |
| **Adapter** | GCP/Fastify/Express request/response adapters | Framework-agnostic handler execution |
| **Proxy** | Hybrid Proxy Container (`ContainerPool.createProxyContainer()`) | Transparent read-through with write-isolation |
| **Template Method** | `Handler.executeCore()` fixed execution sequence | Predictable lifecycle, pluggable middleware |

These patterns were not applied for their own sake. Each solves a specific problem in the serverless middleware domain: type-safe pipelines, framework independence, memory efficiency, and pluggable authentication. Understanding them helps when extending the framework -- new middleware, new adapters, and new DI strategies should follow the same patterns to maintain consistency.

---

## Cross-references

- For the pipeline architecture in detail: [Handler Architecture](./architecture.md)
- For the container proxy deep dive: [Container Model](./container-model.md)
- For the middleware API surface: [API Reference](../reference/api.md)
