# Skill 14: Testing Handlers with GenericRequest/GenericResponse

## Does exactly this

Provides 4 complete testing patterns: full handler chain testing, middleware in isolation, service mocking via DI, and error path testing. All use `executeGeneric()` with mock request/response factories.

## When to use

- "Test handler"
- "Write unit test"
- "Mock services"
- "Test middleware"
- "How to test Noony handlers"

## Steps

1. Create mock request/response factories satisfying `GenericRequest<T>` and `GenericResponse` interfaces
   → See resources/14-testing-patterns.md#pattern-1-full-handler-chain-testing for factory code
2. Build handler with middlewares in canonical order and call `handler.executeGeneric(mockReq, mockRes)`
   → NOT `handler.execute()` which is for Cloud Functions production only
3. For service mocking, use `DependencyInjectionMiddleware` with `scope: 'local'` to inject mocks
   → See resources/14-testing-patterns.md#pattern-3-testing-with-di-service-mocking for example
4. Assert on response status and wrapped data format (success, payload, timestamp)
   → See resources/14-testing-patterns.md#pattern-1-full-handler-chain-testing for assertion examples

## Rules

- Always use `handler.executeGeneric(mockReq, mockRes)` in unit tests — never `execute()`
- Mock request/response MUST satisfy `GenericRequest<T>` and `GenericResponse` interfaces completely
- Always set `parsedBody` on mock request when testing handlers that depend on parsed data
- Inject mocked services via `DependencyInjectionMiddleware` with `scope: 'local'` — never use TypeDI `Container` directly
- Assert on wrapped response format: `data.success`, `data.payload`, `data.timestamp` when using ResponseWrapperMiddleware
- Use `createContext(mockReq, mockRes, user)` for middleware isolation testing

## Anti-patterns

- ❌ Using `handler.execute()` with mock objects instead of `executeGeneric()` — wrong API for unit tests
- ❌ `Container.reset()` or `Container.set()` in tests — pollutes global TypeDI, doesn't use framework DI
- ❌ Forgetting `parsedBody` on mock request — BodyParserMiddleware should set this before validation
- ❌ Plain object mocks without satisfying `GenericRequest`/`GenericResponse` interfaces — causes type errors
- ❌ Asserting on unwrapped response data when using ResponseWrapperMiddleware — middleware wraps automatically

## Done when

- You can write a full handler chain test with mock request/response
- You understand how to use `executeGeneric()` vs `execute()`
- You can inject mocked services with DependencyInjectionMiddleware
- You know how to test both success and error paths

## If you need more detail

→ resources/14-testing-patterns.md — All 4 patterns with complete code (full chain, isolation, DI mocking, error handling), mock factory helpers, anti-pattern examples with explanations
