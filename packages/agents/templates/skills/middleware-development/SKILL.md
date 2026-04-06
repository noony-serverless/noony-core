---
name: noony-middleware-development
description: Use when creating custom middleware, adding cross-cutting concerns, intercepting requests or responses, implementing before/after/onError lifecycle hooks, passing data between middlewares via businessData, or accessing DI services inside middleware. PREREQUISITE — read `noony-middleware-ordering` first for where to place your middleware, then come here for how to build it.
---

# skill:noony-middleware-development

## Does exactly this

Provides 5 patterns for building type-safe middleware: class-based, factory functions, DI-aware, conditional logic, and inter-middleware communication via `context.businessData`. All with proper `<TBody, TUser>` generics. This skill is the BRIDGE between the pipeline order (`noony-middleware-ordering`) and your custom logic.

## When to use

- "Create custom middleware"
- "Add cross-cutting concerns" (logging, timing, caching, auditing)
- "Intercept requests/responses"
- "Implement before/after/onError logic"
- "Pass data between middlewares"
- "Access DI services in middleware"

## Do not use this skill when

- You need middleware ordering guidance -> `noony-middleware-ordering` is the authority on positioning
- You need body validation schemas -> `noony-validation-schemas` for Zod integration
- You need error class selection -> `noony-error-handling` for error types and cause chaining
- You need type inference guidance -> `noony-type-inference` for generics flow
- For built-in middleware configuration -> see individual middleware skills: `noony-validation-schemas`, `noony-error-handling`, `noony-dependency-injection`, `noony-guard-system`

## Steps

1. **Read `noony-middleware-ordering` first** to determine where your middleware belongs in the canonical order — ordering determines when your `before`/`after`/`onError` hooks run relative to other middleware
2. Define middleware class implementing `BaseMiddleware<TBody, TUser>` — both generics required to preserve the type chain (see `noony-type-inference` for why this matters)
   -> See `references/middleware-patterns.md#pattern-1-class-based-middleware` for structure
3. Implement lifecycle hooks as needed:
   - `before(context)` — preprocessing, runs top-to-bottom in registration order
   - `after(context)` — postprocessing, runs bottom-to-top (reverse order)
   - `onError(context, error)` — error handling, runs bottom-to-top (reverse order)
   - All hooks are optional — implement only what you need
4. Use `context.businessData` Map for inter-middleware communication — never extend Context interface
   -> See `references/middleware-patterns.md#pattern-5-inter-middleware-communication-via-businessdata`
5. Access injected services via `getService(context, ServiceClass)` helper — middleware does not need to know how the service was created
   -> See `references/middleware-patterns.md#pattern-3-middleware-with-dependency-injection`
6. Use factory functions for simpler, stateless middleware that needs configuration parameters
   -> See `references/middleware-patterns.md#pattern-2-factory-function-middleware`
7. **Register your middleware in the canonical order from `noony-middleware-ordering`** — place it at the correct position relative to ErrorHandler (position 1), validation (positions 6-7), auth (positions 9-12), and ResponseWrapper (last)

## Rules

- MANDATORY: `implements BaseMiddleware<TBody, TUser>` with both generics — omitting them silently breaks type inference for `validatedBody` and `user` downstream
- Default generic values: `<TBody = unknown, TUser = unknown>` — allows optional type specification at usage site
- Inter-middleware data ONLY via `context.businessData.set(key, value)` — never modify Context properties directly
- Use descriptive, namespaced businessData keys to avoid collisions — `'otel_span'` is reserved by `OpenTelemetryMiddleware`
- All lifecycle methods are optional — implement only what you need
- Middleware must not have side effects on framework state — context properties like `user` and `req` are read-only
- Consult `noony-middleware-ordering` for where to register your middleware — position determines execution timing

## Anti-patterns

- Writing middleware without reading `noony-middleware-ordering` first — ordering determines when your hooks run; wrong position = wrong behavior
- `BaseMiddleware` without generics — breaks type chain silently; `context.req.validatedBody` and `context.user` become `unknown`
- Extending Context interface (`interface CustomContext extends Context`) — not portable, breaks framework compatibility
- Returning data from `before()` — return value is ignored by the framework, use `businessData` instead
- Mutating `context.user` or `context.req.body` directly — these are read-only; use `businessData` for custom data
- Duplicate `businessData` keys across middlewares — second write silently overwrites first, causing lost data
- Heavy logic in `onError` without guard clauses — `onError` fires for every error type, check error class before acting

## Done when

- You have read `noony-middleware-ordering` and know where your middleware sits in the canonical order
- You can write class-based middleware with proper `<TBody, TUser>` generics
- You understand lifecycle hook execution order (before: top-down, after/onError: bottom-up)
- You can pass data between middlewares via `businessData`
- You know how to access DI services in middleware via `getService()`
- You can test middleware in isolation using `createContext()`

## If you need more detail

-> `references/middleware-patterns.md` — 5 complete patterns (class-based, factory, DI-aware, conditional, inter-middleware), anti-patterns with code examples, testing examples with assertions
