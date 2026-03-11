# Skill 11: Dependency Injection Best Practices

## Does exactly this

Covers containerPool API (initializeGlobal, getService), global scope (process-lifetime) vs local scope (request-scoped), proxy container pattern, and type-safe service resolution.

## When to use

- "Set up dependency injection"
- "Inject services into handler"
- "Use getService() helper"
- "Manage service lifetime"

## Steps

1. Initialize global services at startup: `containerPool.initializeGlobal([{ id: Service, value: instance }])`
2. For request-scoped data, use `DependencyInjectionMiddleware` with `scope: 'local'`
3. Access services via type-safe `getService(context, ServiceClass)` helper — never direct container access
4. Global services are singletons shared across all requests
5. Local services are isolated per-request via proxy container pattern

## Rules

- `containerPool.initializeGlobal()` called ONCE at startup — never per-request
- Global scope for expensive services (DB, HTTP clients, external APIs)
- Local scope for request-specific data (trace IDs, user, request ID)
- Use `getService(context, ServiceClass)` for type-safe resolution
- Never call `Container.get()` directly from TypeDI — breaks framework isolation
- Proxy container pattern: local writes shadow global reads without mutation

## Anti-patterns

- ❌ `containerPool.initializeGlobal()` inside handler — per-request latency (300-500ms)
- ❌ Direct `Container.get()` calls — bypasses framework DI, misses scoping
- ❌ Mutating global services during requests — race conditions with concurrent requests
- ❌ Creating new service instances per request — defeats dependency injection benefits
- ❌ String-based service IDs without types — loses type safety

## Done when

- You understand global vs local scope
- You can use `getService()` for type-safe access
- You know why `containerPool.initializeGlobal()` goes at startup
- You understand proxy container pattern prevents mutation

## If you need more detail

→ resources/11-di-patterns.md — containerPool API, global and local scope patterns, getService() helper, proxy container explanation with memory comparison, complete handler setup, testing with DI mocking, service instance management, cleanup patterns
