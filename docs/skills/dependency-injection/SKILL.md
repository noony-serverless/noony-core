---
name: noony-dependency-injection
description: Use when resolving services with getService(), managing ContainerPool scopes (global vs local), configuring DependencyInjectionMiddleware, understanding the hybrid proxy container memory model, or accessing type-safe services in Noony controllers. Covers service RESOLUTION, not initialization.
---

# skill:noony-dependency-injection

## Does exactly this

Service RESOLUTION — ContainerPool, `getService()`, global vs local scopes, and the hybrid proxy container memory model. This skill covers how to access and use services after they have been initialized.

## When to use

- "Resolve a service in a controller"
- "getService() for type-safe access"
- "Global vs local scope"
- "ContainerPool API"
- "DependencyInjectionMiddleware setup"
- "Proxy container memory model"

## Do not use this skill when

- For service INITIALIZATION (one-time setup, singleton guard) → use `noony-dependency-initialization`
- For cold start optimization and performance tuning → use `noony-performance-optimization`
- For DI inside custom middleware development → use `noony-middleware-development`
- For testing with mocked services → use `noony-testing-handlers`

## Steps

The DI flow: `noony-dependency-initialization` (init) → `noony-dependency-injection` (resolve) → `noony-middleware-development` (use in middleware).

1. First, initialize services with `noony-dependency-initialization`'s singleton guard pattern — services must exist before resolution
   → See `noony-dependency-initialization` for the three-condition guard

2. Add `DependencyInjectionMiddleware` to the handler for request-scoped services
   - Use `scope: 'local'` (default) for request-specific data like trace IDs, user context
   - Use `scope: 'global'` only at startup for process-lifetime services
   → See `references/di-patterns.md#local-scope-services` for scope options

3. Resolve services with `getService(context, ServiceClass)` in controllers — never access the container directly
   - Returns the typed service instance
   - Throws a clear error if the service is not registered
   → See `references/di-patterns.md#getservice-helper` for type-safe patterns

4. Understand the proxy container: local writes shadow global reads without mutation
   - Global services are shared across all requests (zero-copy)
   - Local services are isolated per request (cloned on write)
   → See `references/di-patterns.md#hybrid-proxy-container-pattern` for memory diagram

5. For testing, inject mocks via `DependencyInjectionMiddleware` with `scope: 'local'`
   → See `noony-testing-handlers` for complete testing patterns

## Rules

- `containerPool.initializeGlobal()` called ONCE at startup — never per-request (see `noony-dependency-initialization`)
- Global scope for expensive services (DB connections, HTTP clients, external APIs)
- Local scope for request-specific data (trace IDs, user context, request IDs)
- Always use `getService(context, ServiceClass)` for type-safe resolution
- Never call TypeDI `Container.get()` directly — bypasses framework scoping
- Proxy container: local writes shadow global reads without mutating global state
- Global services must be immutable after initialization — no mutation during requests

## Anti-patterns

- ❌ `containerPool.initializeGlobal()` inside handler — reconnects DB every request (~300-500ms penalty)
- ❌ `Container.get(Service)` or `Container.set()` — bypasses framework DI, misses proxy scoping
- ❌ Mutating global services during requests — race conditions with concurrent requests
- ❌ `new ServiceClass()` per request inside handler — defeats DI benefits entirely
- ❌ String-based service IDs without class references — loses type safety from `getService()`
- ❌ Request-specific data in global scope — state leaks between requests

## Done when

- Global services initialized once at startup via `noony-dependency-initialization`, resolved via `getService()`
- Request-scoped data injected via `DependencyInjectionMiddleware`
- All service access uses `getService(context, ServiceClass)`
- You understand proxy container prevents global mutation

## If you need more detail

→ `references/di-patterns.md` — ContainerPool API, global and local scope patterns, getService() helper, proxy container with memory comparison, complete handler setup, testing with DI mocking, cleanup patterns
