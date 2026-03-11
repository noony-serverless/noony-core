# Skill 03: Custom Adapter for New Framework

## Does exactly this

Template for creating adapters for unsupported frameworks (Koa, Hapi, NestJS, etc.) by implementing `GenericRequest<T>` and `GenericResponse` interfaces. Complete Koa adapter example included.

## When to use

- "Add support for Koa/Hapi/[framework]"
- "Create adapter for my framework"
- "Make Noony work with [framework]"
- "I want to use Noony with [framework]"

## Steps

1. Implement `GenericRequest<T>` adapter: extract method, url, path, headers, query, params, body, parsedBody
   → See resources/03-custom-adapter.md#step-1-define-adapter-interfaces for exact implementation
2. Implement `GenericResponse` adapter: status(), json(), send(), header(), headers(), end(), plus statusCode and headersSent properties
   → See resources/03-custom-adapter.md#step-1-define-adapter-interfaces for chainable methods
3. Create handler wrapper function that calls `handler.executeGeneric(genericReq, genericRes)` with error handling
   → See resources/03-custom-adapter.md#step-3-koa-route-handler-wrapper for complete pattern
4. Test adapters with unit tests covering both request and response adaptation
   → See resources/03-custom-adapter.md#testing-the-adapter for test examples

## Rules

- `GenericRequest<T>` and `GenericResponse` interfaces MUST be fully implemented — no partial implementations
- Always track `headersSent` flag to prevent double-send errors
- Response methods MUST be chainable (return `this`)
- Never mutate framework request/response during adaptation — create new objects
- Always set `parsedBody` from framework's parsed body (required for BodyValidationMiddleware)
- Handle `RESPONSE_SENT` errors gracefully — response already sent is expected
- Read-only properties `statusCode` and `headersSent` must be accessible

## Anti-patterns

- ❌ Passing framework-native req/res directly to `executeGeneric()` without adapting — misses interface contract
- ❌ Forgetting `headersSent` check in response adapter — causes double-send errors
- ❌ Not setting `parsedBody` on adapted request — validation middlewares fail silently
- ❌ Breaking method chaining on response methods — middleware pipelines break
- ❌ Mutating framework request during adaptation — side effects on original object

## Done when

- You can implement both GenericRequest and GenericResponse adapters
- You understand how to prevent double-send errors
- You can write handler wrapper with proper error handling
- You know how to test adapters with unit tests

## If you need more detail

→ resources/03-custom-adapter.md — Complete 4-step Koa adapter (request, handler, wrapper, server), testing code with 3 test cases, adapter checklist, common gotchas with code examples
