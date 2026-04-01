---
name: noony-custom-adapter
description: Use ONLY when creating adapters for unsupported frameworks like Koa, Hapi, or NestJS. Fastify, Express, and Cloud Functions are already built-in — you do not need this skill for those.
---

# skill:noony-custom-adapter

## Does exactly this

Provides a template for creating adapters for any HTTP framework NOT already supported by Noony. Covers implementing `GenericRequest<T>` and `GenericResponse` interfaces, building handler wrappers, and testing adapters. Includes a complete Koa adapter as reference.

## When to use

- "Add support for Koa/Hapi/NestJS/[framework]"
- "Create adapter for my framework"
- "Make Noony work with [framework]"
- "I want to use Noony outside of Cloud Functions and Fastify"
- "Implement GenericRequest or GenericResponse"
- "How does executeGeneric work"

## Do not use this skill when

- **Fastify** -- built-in support via `createFastifyHandler()`. Use **`noony-create-fastify-server`** or **`noony-convert-cloud-functions-to-fastify`** skill instead.
- **Express** -- built-in support via `handler.execute()`. No adapter needed.
- **Google Cloud Functions** -- built-in support via `handler.execute()`. No adapter needed.
- You want the standard Fastify + Cloud Functions dual-entry pattern -- use **`noony-complete-dual-entry`** skill instead.

This skill is for Koa, Hapi, NestJS, or other frameworks that Noony does not natively support.

## Steps

1. Implement `GenericRequest<T>` adapter
   - Map framework's request to: method, url, path, headers, query, params, body, parsedBody
   - CRITICAL: Set `parsedBody` from framework's parsed body -- `BodyValidationMiddleware` reads from this
   - Adapters need correct generics -- see **`noony-type-inference`** skill for generic patterns
   -> See references/custom-adapter.md#step-1-define-adapter-interfaces

2. Implement `GenericResponse` adapter
   - Implement: `status()`, `json()`, `send()`, `header()`, `headers()`, `end()`
   - All methods MUST return `this` (chainable)
   - Track `headersSent` flag internally to prevent double-send
   - Expose read-only `statusCode` and `headersSent` properties
   -> See references/custom-adapter.md#step-1-define-adapter-interfaces

3. Create handler wrapper function
   - Call `handler.executeGeneric(genericReq, genericRes)` -- NOT `execute()`
   - Handle `RESPONSE_SENT` errors gracefully (expected when response already sent by middleware)
   - Check `headersSent` before sending error responses
   -> See references/custom-adapter.md#step-3-koa-route-handler-wrapper

4. Integrate with framework server and register routes
   -> See references/custom-adapter.md#step-4-koa-server-integration

5. Set up middleware chain in canonical order
   - After creating the adapter, use **`noony-middleware-ordering`** skill to verify handler middleware ordering

6. Write unit tests for both request and response adaptation
   -> See references/custom-adapter.md#testing-the-adapter

## Rules

- `GenericRequest<T>` and `GenericResponse` MUST be fully implemented -- no partial implementations
- Always track `headersSent` flag to prevent double-send errors
- Response methods MUST be chainable (return `this`)
- Never mutate the framework's native request/response during adaptation -- create new objects
- Always set `parsedBody` from framework's parsed body (required for BodyValidationMiddleware)
- Handle `RESPONSE_SENT` errors gracefully -- response already sent is expected behavior
- Use `executeGeneric()`, never `execute()` -- the latter is for native GCP/Express req/res only

## Anti-patterns

- Passing framework-native req/res directly to `executeGeneric()` without adapting -- misses the interface contract, middleware will fail
- Forgetting `headersSent` check in response adapter -- causes double-send errors and crashes
- Not setting `parsedBody` on adapted request -- validation middleware fails silently, body is always undefined
- Breaking method chaining on response methods -- middleware pipeline breaks when `.status(200).json(data)` fails
- Using `execute()` instead of `executeGeneric()` -- `execute()` expects native GCP/Express objects
- Building a custom adapter for Fastify, Express, or Cloud Functions -- these are already built-in

## Done when

- Both `GenericRequest<T>` and `GenericResponse` adapters are fully implemented
- Handler wrapper handles `RESPONSE_SENT` errors and checks `headersSent` before error responses
- Response adapter prevents double-send via `headersSent` tracking
- Unit tests verify request adaptation, response chaining, and double-send prevention
- Adapter checklist in resources is fully checked
- Middleware ordering verified against canonical order (**`noony-middleware-ordering`** skill)

## If you need more detail

- -> references/custom-adapter.md -- Complete Koa adapter (request adapter, response adapter, handler wrapper, server integration), unit tests with 3 test cases, adapter checklist, common gotchas with code examples
- -> **`noony-type-inference`** skill -- Type inference patterns for generics in adapters
- -> **`noony-middleware-ordering`** skill -- Middleware ordering reference for any handler setup
