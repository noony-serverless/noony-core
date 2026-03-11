# Skill 08: Type-Safe Middleware Development

## Does exactly this

Provides 5 patterns for middleware: class-based, factory functions, DI-aware, conditional logic, and inter-middleware communication via context.businessData.

## When to use

- "Create custom middleware"
- "Add cross-cutting concerns"
- "Intercept requests/responses"
- "Implement before/after/onError logic"

## Steps

1. Define middleware class implementing `BaseMiddleware<TBody, TUser>` with both generics required
   → See resources/08-middleware-patterns.md#pattern-1-class-based-middleware for structure
2. Implement lifecycle hooks as needed: `before()` for preprocessing, `after()` for postprocessing, `onError()` for errors
3. Use `context.businessData` Map for inter-middleware communication — never extend Context interface
4. Access injected services via `getService(context, ServiceClass)` helper
   → See resources/08-middleware-patterns.md#pattern-3-middleware-with-dependency-injection
5. Use factory functions for stateless reusable middleware

## Rules

- MANDATORY: `implements BaseMiddleware<TBody, TUser>` with both generics — type chain breaks without them
- Default generic values: `<TBody = unknown, TUser = unknown>` — allows optional type specification
- Inter-middleware data ONLY via `context.businessData.set()` — never modify Context properties directly
- All lifecycle methods are optional — implement only what you need
- Middleware must not have side effects on framework state — readonly context properties

## Anti-patterns

- ❌ `BaseMiddleware` without generics — breaks type chain silently
- ❌ Extending Context interface for custom data — not portable, breaks compatibility
- ❌ Returning data from `before()` — return value is ignored, use businessData instead
- ❌ Mutating context.user or context.req directly — these are read-only, use businessData
- ❌ Multiple middlewares with same businessData key — key conflicts, lost data

## Done when

- You can write class-based middleware with proper generics
- You understand lifecycle hooks (before, after, onError)
- You can pass data between middlewares via businessData
- You know how to access DI services in middleware

## If you need more detail

→ resources/08-middleware-patterns.md — 5 patterns (class-based, factory, DI-aware, conditional, inter-middleware), anti-patterns with code examples, testing examples with assertions
