---
name: noony-testing-handlers
description: Use when writing tests for Noony handlers, creating mock request/response objects, testing middleware in isolation, mocking services with DI, testing error paths, testing validation schemas, testing guard authorization, using executeGeneric() in tests, or verifying response wrapping behavior.
---

# skill:noony-testing-handlers

## Does exactly this

Complete testing patterns for Noony handlers: full handler chain testing, middleware in isolation, service mocking via DI, error path testing, validation testing, and guard authorization testing. All use `executeGeneric()` with mock request/response factories.

## When to use

- "Write unit tests for a handler"
- "Create mock request/response objects"
- "Test middleware in isolation"
- "Mock services via DI"
- "Test error paths and HTTP status mapping"
- "Test validation schemas"
- "Test guard authorization"

## Do not use this skill when

- For setting up the things you are testing — use the relevant skill first:
  - Validation schemas → `noony-validation-schemas`
  - Error handling → `noony-error-handling`
  - DI container setup → `noony-dependency-injection`
  - Guard authorization → `noony-guard-system`
  - Middleware ordering → `noony-middleware-ordering`

## Steps

Tests should cover: middleware chain (`noony-middleware-ordering`), validation (`noony-validation-schemas`), errors (`noony-error-handling`), DI (`noony-dependency-injection`), and guards (`noony-guard-system`).

1. Create mock request/response factories satisfying `GenericRequest<T>` and `GenericResponse` interfaces
   - `res.status()` must return `this` for chaining
   → See `references/testing-patterns.md#pattern-1-full-handler-chain-testing` for factory code

2. Build handler with middlewares in canonical order and call `handler.executeGeneric(mockReq, mockRes)`
   - NOT `handler.execute()` which expects Cloud Functions native objects
   → See `references/testing-patterns.md#pattern-1-full-handler-chain-testing`

3. For service mocking, use `DependencyInjectionMiddleware` with `scope: 'local'` to inject mocks
   - Never use TypeDI `Container.set()` or `Container.reset()` — use framework DI
   → See `references/testing-patterns.md#pattern-3-testing-with-di-service-mocking`

4. For middleware isolation, use `createContext(mockReq, mockRes, user)` and call hooks directly
   → See `references/testing-patterns.md#pattern-2-middleware-in-isolation`

5. Test validation errors (`noony-validation-schemas` scenarios)
   - Send invalid body and assert `ValidationError` returns 400 with structured error response
   - Always set `parsedBody` on mock request when testing body validation
   → See `references/testing-patterns.md#pattern-4-error-handling-tests`

6. Test guard authorization (`noony-guard-system` scenarios)
   - Create mock users with specific permission arrays
   - Assert 403 Forbidden when permissions are missing
   - Assert success when permissions are present
   → See `references/testing-patterns.md#pattern-4-error-handling-tests`

7. Assert on wrapped response format when using `ResponseWrapperMiddleware`: `data.success`, `data.payload`, `data.timestamp`
   → See `references/testing-patterns.md#key-test-helpers-summary`

## Rules

- Always use `handler.executeGeneric(mockReq, mockRes)` in tests — never `execute()`
- Mock objects MUST satisfy `GenericRequest<T>` and `GenericResponse` interfaces completely
- Always set `parsedBody` on mock request when testing handlers with body validation
- Inject mocked services via `DependencyInjectionMiddleware` with `scope: 'local'` — never TypeDI `Container`
- Assert on wrapped format (`data.success`, `data.payload`) when `ResponseWrapperMiddleware` is in the chain
- Use `createContext(mockReq, mockRes, user)` for middleware isolation testing
- Include `ErrorHandlerMiddleware` in test handlers — without it, error responses will not match production behavior (see `noony-error-handling`)

## Anti-patterns

- ❌ `handler.execute(mockReq, mockRes)` — wrong API for unit tests, expects Cloud Functions objects
- ❌ `Container.reset()` or `Container.set()` in tests — pollutes global TypeDI, does not use framework DI
- ❌ Missing `parsedBody` on mock request — `BodyValidationMiddleware` has nothing to validate
- ❌ Plain objects without full `GenericRequest`/`GenericResponse` shape — causes runtime errors
- ❌ Asserting `data.name` when `ResponseWrapperMiddleware` wraps it to `data.payload.name`
- ❌ Testing without `ErrorHandlerMiddleware` — error responses will not match production (see `noony-error-handling`)
- ❌ Testing guards without setting `context.user` — guards always fail without authentication context

## Done when

- Full handler chain test passes with mock request/response
- Service mocks injected via `DependencyInjectionMiddleware`
- Validation error paths tested with correct 400 status codes (`noony-validation-schemas`)
- Guard authorization tested with 403 for missing permissions (`noony-guard-system`)
- Error paths tested with correct HTTP status codes (`noony-error-handling`)
- Response wrapping assertions account for standard envelope

## If you need more detail

→ `references/testing-patterns.md` — All 4 patterns with complete code (full chain, isolation, DI mocking, error handling), mock factory helpers, anti-pattern examples
