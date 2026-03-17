# The Hybrid Proxy Container Model

This document explains **why** the Noony Framework uses a Hybrid Proxy Container for dependency injection, how it achieves zero-copy performance in serverless environments, and what alternatives were considered. For practical usage, see [Dependency Injection Guide](../guides/dependency-injection.md).

---

## The problem

Serverless environments require fast cold starts. Traditional DI frameworks build a new container for every request, which is expensive. The challenge is that two different lifetime requirements coexist in every serverless application:

| Lifetime | Examples | Characteristics |
|----------|----------|----------------|
| **Process Lifetime** | Database connections, logger, config | Initialized once, shared across all requests. Fast, but dangerous if mutable state leaks between requests. |
| **Request Lifetime** | Current user, trace ID, request-scoped data | Isolated per request. Safe, but expensive if the entire dependency graph is recreated. |

The naive solutions both have costs:

- **Clone the container per request** -- safe but O(N) memory and setup time where N is the number of global services
- **Share one container** -- fast but request data from one caller can leak to another

---

## The solution: Virtual Container Proxy

Instead of creating a new container for every request (which copies all services), the framework creates a lightweight JavaScript `Proxy` that wraps the global singleton container.

```text
  +--------------------------------------------------+
  |              Process Lifetime (Global)            |
  |                                                  |
  |  ContainerPool Singleton                         |
  |    +-- Database Connection                       |
  |    +-- Logger Service                            |
  |    +-- Config Service                            |
  |    +-- Repository Services                       |
  +--------------------------------------------------+
           ^                          ^
           | read                     | read
           |                          |
  +--------+---------+    +-----------+--------+
  | Request A Proxy  |    | Request B Proxy    |
  |                  |    |                    |
  | Local Overrides: |    | Local Overrides:   |
  |  CurrentUser: A  |    |  CurrentUser: B    |
  |  TraceId: abc    |    |  TraceId: xyz      |
  +------------------+    +--------------------+
```

Each proxy is a thin wrapper -- essentially a `Map` for local overrides plus a `Proxy` object. When you read a service, the proxy checks local overrides first, then falls back to the global container. When you write a service, it goes to the local map only. The global container is never mutated during request processing.

---

## How the proxy works internally

The `ContainerPool.createProxyContainer()` method creates an ES6 `Proxy` around the global TypeDI container. The proxy intercepts five operations:

### 1. `get(serviceId)` -- Service resolution

```text
  container.get('Database')
       |
       v
  Check localOverrides Map
       |
       +-- Found? Return local value
       |       (unless it's a TOMBSTONE -- then throw "not found")
       |
       +-- Not found? Delegate to global container
```

The local-first lookup means request-scoped services naturally shadow global ones. A request can even override a global service for its own scope without affecting other concurrent requests.

### 2. `set(serviceId, value)` -- Service registration

All writes go to the local overrides map. The global container is never touched.

```text
  container.set('CurrentUser', userObj)
       |
       v
  localOverrides.set('CurrentUser', userObj)
  // Global container unchanged
```

### 3. `remove(serviceId)` -- Service deletion

Instead of actually deleting from the global container, the proxy writes a `TOMBSTONE` symbol to the local map. Subsequent `get()` calls for that service in this request will throw a "not found" error, while other requests continue to see the global value.

### 4. `has(serviceId)` -- Existence check

Checks local overrides first (respecting tombstones), then falls back to the global container.

### 5. `reset()` -- Clear local scope

Clears the local overrides map, reverting the proxy to pure global state for this request. Does not affect the global container.

---

## Why this design over alternatives

### vs. Full container cloning (TypeDI `Container.of()`)

Full cloning copies every registered service into a new container instance. For a handler with 50 global services, that is 50 allocations per request -- even if the request only uses 3 of them and overrides none.

The proxy approach allocates exactly one empty `Map` and one `Proxy` wrapper. Memory cost: effectively O(1) regardless of how many global services exist.

### vs. Child containers (Inversify, tsyringe)

Child container patterns maintain a parent reference and walk up the chain on resolution. This is similar in spirit to the proxy approach, but:

- Requires adopting the full DI framework and its container API
- Often brings transient/singleton/scoped lifetime annotations that add complexity
- The proxy uses native ES6 `Proxy`, keeping the abstraction minimal and the API identical to TypeDI's `ContainerInstance`

### vs. No DI (manual wiring)

Without DI, every handler imports its dependencies directly. This works for simple cases but makes testing harder (no way to swap implementations without module mocking) and couples handlers to concrete implementations.

---

## Memory and performance characteristics

| Metric | Traditional (Clone) | Hybrid Proxy | Improvement |
|--------|---------------------|--------------|-------------|
| **Setup Time** | O(N) services copied | O(1) proxy creation | Instant |
| **Memory per request** | O(N) duplication | O(1) + overrides | ~99% reduction |
| **Read performance** | Direct lookup | Proxy intercept + map check | Negligible overhead |
| **Write safety** | Isolated by copy | Isolated by proxy | Equivalent |
| **Cleanup** | Must dispose container | Auto GC'd (no references) | Zero cleanup code |

The "~99% reduction" assumes a typical handler with many global services and few (0-3) request-scoped overrides. In practice, most requests read from global services and write only `CurrentUser` and `TraceId` locally.

### Garbage collection

The proxy container and its local overrides map are eligible for garbage collection as soon as the request handler returns. There is no manual cleanup step, no `dispose()` call, no pool to return the container to. The JavaScript runtime handles it.

---

## The global container lifecycle

The global container is initialized once at application startup:

```text
  Application start
       |
       v
  containerPool.initializeGlobal([
    { id: 'Database', value: dbConnection },
    { id: 'Logger', value: loggerInstance },
    { id: 'Config', value: appConfig }
  ])
       |
       v
  Global container sealed (read-only during requests)
       |
       +---> Request 1: createProxyContainer() --> proxy + local map
       +---> Request 2: createProxyContainer() --> proxy + local map
       +---> Request N: createProxyContainer() --> proxy + local map
```

The global container uses a named TypeDI container (`__noony_global__`) to avoid conflicts with any default container usage. It is treated as **effectively read-only** during the request processing phase. The `set`, `remove`, and `reset` operations on any proxy container only affect that proxy's local map.

### Concurrency safety

Node.js is single-threaded, but async/await interleaving means multiple requests can be in-flight simultaneously. Because the global container is read-only during request processing and each proxy has its own local map, there are no race conditions. Request A's `container.set('CurrentUser', userA)` cannot affect Request B's `container.get('CurrentUser')`.

---

## Integration with the Handler

The Handler creates a proxy container at the start of every request in its `executeCore` method:

```text
  executeCore(req, res)
       |
       v
  container = containerPool.createProxyContainer()
       |
       v
  context = createContext(req, res, { container })
       |
       v
  Middleware pipeline receives context.container
       |
       v
  Each middleware can:
    - Read global services:  context.container.get(Database)
    - Write request data:    context.container.set('CurrentUser', user)
    - Shadow global service: context.container.set('Logger', testLogger)
    - Remove for this request: context.container.remove('OptionalService')
```

The container is part of the `Context` interface and flows through every `before`, `after`, and `onError` hook unchanged. Middleware authors interact with it as a standard TypeDI container -- the proxy is transparent.

---

## Anti-patterns to avoid

**Do not treat the global container as writable during request processing.** The global scope is sealed after initialization. While technically possible to call `ContainerPool.initializeGlobal()` again, doing so during request handling would affect all concurrent and future requests.

**Do not clone the entire container per request.** This defeats the purpose of the proxy pattern and reintroduces the O(N) overhead it was designed to avoid.

**Do not mix request-lifetime and process-lifetime dependencies without explicit scoping.** If a service holds request state (current user, request ID), it must be registered through the proxy's local scope, not in the global container.

---

## Cross-references

- For practical DI setup and usage: [Dependency Injection Guide](../guides/dependency-injection.md)
- For the middleware reference including DI middleware: [Dependency Injection Middleware Reference](../reference/middlewares/dependency-injection.md)
- For how the Handler creates and uses the container: [Handler Architecture](./architecture.md)
- For the Flyweight pattern behind global services: [Design Patterns](./design-patterns.md)
