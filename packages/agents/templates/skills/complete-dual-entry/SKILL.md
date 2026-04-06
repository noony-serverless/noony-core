---
name: noony-complete-dual-entry
description: The PRODUCTION PATTERN for Noony projects. Use when building a new project or graduating from `noony-create-fastify-server`. Complete dual-entry setup with Fastify (local dev) and Cloud Functions (production) working from the same handler code.
---

# skill:noony-complete-dual-entry

## Does exactly this

End-to-end production-ready setup of a Noony project where the same handler runs identically in both Fastify (local dev) and Cloud Functions (production). This is the recommended starting point for new projects and the graduation target from `noony-create-fastify-server` skill.

This is the recommended starting point for noony-uncle-noony's New Project journey.

## When to use

- "Show me a complete example"
- "How do I support both Fastify and Cloud Functions"
- "Write once, deploy anywhere"
- "Full integration setup"
- "How do the files connect"
- "Project structure for Noony"
- "Production-ready setup"
- Starting a new project that needs both local dev and Cloud Functions deployment
- Graduating from **`noony-create-fastify-server`** skill -- you have a Fastify server and now need Cloud Functions too

## Do not use this skill when

- You only need a quick Fastify dev server to get started -- use **`noony-create-fastify-server`** skill instead. Come back here when you are ready for production.
- You are migrating an existing Cloud Functions handler -- use **`noony-convert-cloud-functions-to-fastify`** skill instead. That skill handles migration-specific concerns like extracting inline logic.
- You need a custom adapter for a non-Fastify framework -- use **`noony-custom-adapter`** skill instead.

## Steps

1. Define handler once with all middlewares in canonical order
   - ErrorHandlerMiddleware first, then validation, then business logic
   - Verify ordering with **`noony-middleware-ordering`** skill -- this is critical for correct execution
   - No imports from Cloud Functions or Fastify in this file
   - Export handler for use by both entry points
   -> See references/dual-entry.md#1-handler-definition-used-by-both-environments

2. Create singleton initialization guard shared by both entry points
   - `initialized` flag + concurrent-safe promise pattern
   - Register global services in `containerPool.initializeGlobal()`
   - Include `cleanup()` function for graceful shutdown
   - See **`noony-dependency-initialization`** skill for detailed initialization patterns
   -> See references/dual-entry.md#2-initialization-shared-by-both

3. Create Fastify entry point (`server.ts`)
   - Eager initialization in `onReady` hook
   - Use `createFastifyHandler()` wrapper for route registration
   - Add graceful shutdown (SIGTERM/SIGINT -> close server -> cleanup)
   -> See references/dual-entry.md#3-local-development-fastify

4. Create Cloud Functions entry point (`functions.ts`)
   - Lazy initialization with `initializeDependencies()` before each execution
   - Use `handler.execute(req, res)` for native Cloud Functions req/res
   -> See references/dual-entry.md#4-production-cloud-functions

5. Configure npm scripts for both workflows
   -> See references/dual-entry.md#5-local-development-scripts

## Project structure

```
src/
  core/initialization.ts     # Singleton init guard (shared)
  handlers/user.handler.ts   # Framework-agnostic handler
  services/                  # Business logic
  server.ts                  # Fastify entry point (local dev)
  functions.ts               # Cloud Functions entry point (prod)
```

## Key differences between environments

| Aspect | Fastify (local) | Cloud Functions (prod) |
|--------|-----------------|------------------------|
| Entry point | `server.ts` | `functions.ts` |
| Handler execution | `createFastifyHandler()` | `handler.execute()` |
| Initialization | Eager (`onReady` hook) | Lazy (on first request) |
| Cleanup | Graceful shutdown | Automatic |
| Handler code | Identical | Identical |
| Middleware chain | Identical | Identical |

## Rules

- Handler module exports ONLY the handler -- no server or deployment code
- `server.ts` contains Fastify setup ONLY -- never import `functions-framework`
- `functions.ts` contains Cloud Functions exports ONLY -- never import Fastify
- Same handler instance, same middleware chain, same business logic in both environments
- Initialization is idempotent -- safe to call multiple times, fast path returns immediately
- Use `initializeDependencies()` in both Fastify (`onReady` hook) and Cloud Functions (before `execute()`)

## Anti-patterns

- Duplicating handler code between `server.ts` and `functions.ts` -- violates DRY, bugs diverge between environments
- Different middleware chains for local vs production -- testing locally becomes unreliable
- Calling `initializeDependencies()` inside handler function body -- adds latency per request
- Importing Fastify server startup code into `functions.ts` -- Cloud Functions runtime cannot run Fastify
- Adding OpenTelemetryMiddleware only in production -- tracing behavior diverges from local testing

## Done when

- Handler is defined once and imported by both `server.ts` and `functions.ts`
- Fastify entry point uses eager initialization via `onReady` hook
- Cloud Functions entry point uses lazy initialization before `handler.execute()`
- `npm run dev` starts Fastify locally, `npm run deploy` deploys to Cloud Functions
- No framework-specific imports in handler files
- Middleware ordering verified against canonical order (**`noony-middleware-ordering`** skill)

## If you need more detail

- -> references/dual-entry.md -- Full project structure, 4 code sections (handler, init, Fastify, Cloud Functions), usage examples for both environments, comparison table, key advantages, common gotchas with solutions
- -> **`noony-create-fastify-server`** skill -- If you want to start with just Fastify and add Cloud Functions later
- -> **`noony-dependency-initialization`** skill -- Dependency initialization patterns (singleton guard, containerPool)
- -> **`noony-middleware-ordering`** skill -- Middleware ordering reference for any handler setup
