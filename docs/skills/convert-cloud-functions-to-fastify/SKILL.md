---
name: noony-convert-cloud-functions-to-fastify
description: Use when MIGRATING existing Cloud Functions handlers to run locally with Fastify. Converts tightly-coupled Cloud Functions code into framework-agnostic handlers with dual deployment.
---

# skill:noony-convert-cloud-functions-to-fastify

## Does exactly this

Converts an existing Cloud Functions handler into a framework-agnostic Noony handler that runs in both Fastify (local dev) and Cloud Functions (production) with zero code duplication. This is a MIGRATION skill -- it takes what you already have and restructures it.

## When to use

- "Convert my Cloud Function to run locally"
- "Test handler locally before deploying"
- "Speed up development iteration"
- "Migrate Cloud Functions code to Noony"
- "No code changes between environments"
- You have existing `functions.ts` code with inline handler logic and want to add local dev support

## Do not use this skill when

- You are starting a new project from scratch -- use **`noony-complete-dual-entry`** skill instead. It gives you the production pattern without migration concerns.
- You only need a quick Fastify dev server without migration -- use **`noony-create-fastify-server`** skill instead.
- You need to support a non-Fastify framework -- use **`noony-custom-adapter`** skill instead.

## Steps

1. Extract handler logic into a framework-agnostic module
   - Create `src/handlers/[name].handler.ts` with `new Handler<TBody, TUser>()`
   - Move validation to `BodyValidationMiddleware(zodSchema)`
   - Move error handling to `ErrorHandlerMiddleware`
   - No imports from Cloud Functions or Fastify in this file
   -> See references/cloud-to-fastify.md#step-1-define-handler-framework-agnostic

2. Verify middleware ordering follows canonical order
   - ErrorHandlerMiddleware first, ResponseWrapperMiddleware last
   - See **`noony-middleware-ordering`** skill for the definitive reference and common mistakes

3. Create shared initialization module
   - Singleton guard with `initialized` flag and concurrent-safe promise
   - Register global services in `containerPool.initializeGlobal()`
   -> See references/cloud-to-fastify.md#step-4-shared-configuration

4. Set up Cloud Functions entry point
   - `handler.execute(req, res)` for Cloud Functions native req/res
   - Call `initializeDependencies()` before each execution (fast path if already init)
   -> See references/cloud-to-fastify.md#step-2-cloud-functions-entry-point

5. Set up Fastify entry point
   - `createFastifyHandler(handler, name, initFn)` wrapper
   - Initialize eagerly in `onReady` hook
   -> See references/cloud-to-fastify.md#step-3-fastify-entry-point

6. Test locally with Fastify, deploy to Cloud Functions with confidence
   -> See references/cloud-to-fastify.md#testing-locally-before-deploy

## Migration pattern (before/after)

**Before** (tightly coupled):
```
functions.ts -> handler logic inline with req.body, try/catch, res.status()
```

**After** (framework-agnostic):
```
handlers/user.handler.ts  -> Handler<T,U> with middleware chain
functions.ts               -> initDeps() + handler.execute(req, res)
server.ts                  -> createFastifyHandler(handler, name, initFn)
```

-> See references/cloud-to-fastify.md#migration-checklist-cloud-functions--fastify for full before/after code

## Rules

- Same handler instance for both entry points -- never duplicate handler code
- Same middleware chain in both environments -- if you add OTel in prod, add it locally too
- `handler.execute()` for Cloud Functions only (native req/res)
- `createFastifyHandler()` for Fastify only (adapts to GenericRequest/GenericResponse)
- `initializeDependencies()` in both paths -- idempotent, safe to call multiple times
- No environment-specific logic in handler modules

## Anti-patterns

- Different middleware chains for Fastify vs Cloud Functions -- production behavior differs from local testing
- Duplicating handler code between entry points -- bugs in one environment won't surface in the other
- Using `handler.executeGeneric()` with Cloud Functions req/res -- wrong API, use `execute()` instead
- Importing Fastify server code into `functions.ts` -- Cloud Functions cannot run Fastify
- Calling `handler.execute()` with Fastify req/res -- use `createFastifyHandler()` wrapper instead
- Converting without the dual-entry pattern -- locks you into Fastify and loses Cloud Functions deployment

## Done when

- Same handler runs in both Fastify and Cloud Functions without code changes
- `handler.execute()` used in `functions.ts`, `createFastifyHandler()` used in `server.ts`
- Local testing with `npm run dev` produces identical responses to deployed Cloud Function
- No Cloud Functions or Fastify imports in handler files
- Middleware ordering verified against canonical order (**`noony-middleware-ordering`** skill)

## If you need more detail

- -> references/cloud-to-fastify.md -- Architecture diagram, handler definition, both entry points, shared initialization, project structure, migration checklist, integration testing, performance comparison
- -> **`noony-complete-dual-entry`** skill -- Complete dual-entry reference if you want to see the end-state of a fully migrated project
- -> **`noony-middleware-ordering`** skill -- Middleware ordering reference for verifying your migrated handler chain
