---
name: noony-custom-adapter
description: Use when creating adapters for unsupported frameworks (Koa, Hapi, NestJS), OR when a Fastify route needs access to raw request data (rawBody, custom headers) that createFastifyHandler does not expose. The executeGeneric + custom adapter pattern is the correct solution for both cases.
---

# skill:noony-custom-adapter

## Does exactly this

Provides the pattern for building a custom `GenericRequest<T>` + `GenericResponse` adapter and calling `handler.executeGeneric()` directly. Use this for unsupported frameworks (Koa, Hapi, NestJS) **or** for Fastify routes that need fields not populated by the built-in `createFastifyHandler` — most commonly `rawBody` for signature verification.

## When to use

- "Add support for Koa/Hapi/NestJS/[framework]"
- "Create adapter for my framework"
- "Make Noony work with [framework]"
- "I want to use Noony outside of Cloud Functions and Fastify"
- "Implement GenericRequest or GenericResponse"
- "How does executeGeneric work"
- A Fastify route needs `context.req.rawBody` (e.g. webhook signature verification) — `createFastifyHandler` does not populate this field; write a custom adapter that sets it

## Do not use this skill when

- **Express** -- built-in support via `handler.execute()`. No adapter needed.
- **Google Cloud Functions** -- built-in support via `handler.execute()`. No adapter needed.
- You want the standard Fastify + Cloud Functions dual-entry pattern with no raw-body needs -- use **`noony-complete-dual-entry`** skill instead.

## The executeGeneric pattern (core concept)

```typescript
// Instead of createFastifyHandler (which doesn't populate rawBody):
server.post('/webhook/:id', async (req, reply) => {
  const genericReq = adaptFastifyRequestWithRawBody(req);  // custom adapter
  const genericRes = adaptFastifyReply(reply);
  await handler.executeGeneric(genericReq, genericRes);     // zero-overhead, no internal conversion
});
```

`executeGeneric()` accepts already-adapted `GenericRequest`/`GenericResponse` — you control exactly what fields are set.

## Steps

1. Capture raw bytes before Fastify parses JSON
   - Register `addContentTypeParser('application/json', { parseAs: 'buffer' }, ...)` on the Fastify server
   - Store the buffer on the Fastify request: `(req as any).rawBodyBuffer = buf`
   - Then call `JSON.parse(buf.toString('utf8'))` and pass to `done(null, parsed)`
   - This must be registered BEFORE routes

2. Implement `GenericRequest<T>` adapter
   - Map Fastify request to: method, url, path, headers, query, params, body, parsedBody
   - Set `rawBody: (req as any).rawBodyBuffer` — the Buffer captured in step 1
   - CRITICAL: Set `parsedBody` from `req.body` — `BodyValidationMiddleware` reads from this
   -> See references/custom-adapter.md#fastify-adapter-with-rawbody

3. Implement `GenericResponse` adapter
   - Implement: `status()`, `json()`, `send()`, `header()`, `headers()`, `end()`
   - All methods MUST return `this` (chainable)
   - Track `headersSent` via `reply.sent` to prevent double-send
   - Expose read-only `statusCode` and `headersSent` properties
   -> See references/custom-adapter.md#fastify-response-adapter

4. Create a route wrapper that calls `executeGeneric`
   - `await handler.executeGeneric(genericReq, genericRes)`
   - Handle `isResponseAlreadySent` errors gracefully
   -> See references/custom-adapter.md#fastify-executegeneic-wrapper

5. Register routes using the wrapper for routes that need rawBody; use `createFastifyHandler` for all others
   - Standard routes: `server.post('/api/users', createFastifyHandler(handler, 'name', initFn))`
   - Raw-body routes: `server.post('/webhook/:id', adaptWithRawBody(handler))`

6. In the GCF entry point, pass `req.rawBody` (GCF's original Buffer) as the `server.inject()` payload
   - GCF sets `req.rawBody: Buffer` with the original bytes before JSON parsing
   - `server.inject({ payload: gcfRawBody })` routes it through `addContentTypeParser` which stores it as `rawBodyBuffer`
   -> See references/custom-adapter.md#gcf-entry-point-rawbody

7. Read `context.req.rawBody` in the middleware — it is a `Buffer | string | undefined`
   ```typescript
   const raw = context.req.rawBody;
   const str = Buffer.isBuffer(raw) ? raw.toString('utf8') : raw ?? JSON.stringify(context.req.body ?? {});
   ```

8. Verify middleware ordering follows canonical order -- see **`noony-middleware-ordering`** skill

## Rules

- `GenericRequest<T>` and `GenericResponse` MUST be fully implemented — no partial implementations
- Always track `headersSent` flag to prevent double-send errors
- Response methods MUST be chainable (return `this`)
- Never mutate the framework's native request/response during adaptation — create new objects
- Always set `parsedBody` from framework's parsed body (required for BodyValidationMiddleware)
- Handle `RESPONSE_SENT` errors gracefully — response already sent is expected behavior
- Use `executeGeneric()`, never `execute()` — the latter is for native GCP/Express req/res only
- `addContentTypeParser` MUST be registered before routes on the Fastify server
- GCF `req.rawBody` (Buffer) must be passed as `server.inject()` payload — `extractAndStoreRequestBody` re-serializes and loses original bytes

## Anti-patterns

- Passing framework-native req/res directly to `executeGeneric()` without adapting — misses the interface contract, middleware will fail
- Forgetting `headersSent` check in response adapter — causes double-send errors and crashes
- Not setting `parsedBody` on adapted request — validation middleware fails silently, body is always undefined
- Breaking method chaining on response methods — middleware pipeline breaks when `.status(200).json(data)` fails
- Using `execute()` instead of `executeGeneric()` — `execute()` expects native GCP/Express objects
- Using `JSON.stringify(req.body)` as rawBody for signature verification — re-serialized bytes differ from original; always use the captured Buffer
- Bypassing Fastify entirely (pattern-matching URLs in the GCF handler) — loses Fastify routing, logging, and middleware; use `executeGeneric` inside a Fastify route instead

## Done when

- `addContentTypeParser` captures raw bytes into `rawBodyBuffer` on the Fastify request
- `GenericRequest` adapter sets `rawBody` from `rawBodyBuffer`
- `GenericResponse` adapter prevents double-send via `headersSent` tracking
- `executeGeneric` called in route handler with adapted request/response
- GCF entry point passes `req.rawBody` Buffer as `server.inject()` payload
- Middleware reads `context.req.rawBody` — no internal imports, no WeakMap hacks
- Middleware ordering verified against canonical order (**`noony-middleware-ordering`** skill)

## If you need more detail

- -> references/custom-adapter.md — Fastify adapter with rawBody, GCF entry point pattern, Koa adapter reference, adapter checklist, common gotchas
- -> **`noony-type-inference`** skill — Type inference patterns for generics in adapters
- -> **`noony-middleware-ordering`** skill — Middleware ordering reference for any handler setup
