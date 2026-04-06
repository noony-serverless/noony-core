---
name: noony-create-fastify-server
description: Use when setting up a Fastify server for local development from scratch. This is the STARTING POINT — get a dev server running fast, then graduate to `noony-complete-dual-entry` for production dual-entry.
---

# skill:noony-create-fastify-server

## Does exactly this

Creates a minimal Fastify server for local development with dependency initialization, route registration via `createFastifyHandler()`, and graceful shutdown. This is the fastest path to running Noony handlers locally.

## When to use

- "Set up local development server"
- "Create a Fastify server"
- "How do I start a dev server"
- "Add graceful shutdown to my server"
- "I need to run my handlers locally"
- "Configure server startup"
- Starting a new project and want to iterate locally before wiring up Cloud Functions

## Do not use this skill when

- You need a production-ready project with both Fastify AND Cloud Functions entry points -- use **`noony-complete-dual-entry`** skill instead. That is the graduation path from this skill.
- You are converting an existing Cloud Functions handler to also run in Fastify -- use **`noony-convert-cloud-functions-to-fastify`** skill instead. That skill handles migration-specific concerns.
- You need to support a non-Fastify framework (Koa, Hapi, NestJS) -- use **`noony-custom-adapter`** skill instead.

## Steps

1. Create a Fastify instance with logging configured
   -> See references/fastify-server.md#minimal-server for quickstart
   -> See references/fastify-server.md#production-ready-server-with-graceful-shutdown for full setup

2. Initialize dependencies in the `onReady` hook (eager initialization)
   - Call `initializeDependencies()` inside `server.addHook('onReady', ...)`
   - Exit process on init failure -- server cannot serve requests without dependencies

3. Register routes using `createFastifyHandler()` wrapper
   - `createFastifyHandler(handler, name, initFn)` takes three arguments
   - Pass `() => Promise.resolve()` as initFn since deps are already initialized eagerly
   - Use the same handler instances that will deploy to Cloud Functions

4. Add graceful shutdown on SIGTERM/SIGINT
   - Close HTTP server with `server.close()`
   - Call `cleanup()` to release DB connections and reset container pool
   -> See references/fastify-server.md#production-ready-server-with-graceful-shutdown

5. Add health check endpoint (`GET /health`)

6. Configure npm scripts: `"dev": "tsx watch src/server.ts"`
   -> See references/fastify-server.md#packagejson-scripts

7. Verify middleware ordering follows canonical order -- see **`noony-middleware-ordering`** skill for the definitive reference

8. When ready for production, graduate to **`noony-complete-dual-entry`** skill to add Cloud Functions alongside your Fastify server

## Rules

- MUST initialize dependencies in `server.addHook('onReady')` -- never inside route handlers
- MUST call `cleanup()` during graceful shutdown -- DB connections leak otherwise
- Always use `createFastifyHandler()` wrapper -- it handles error catching and response completion checks
- Register the same handler instance used in Cloud Functions -- no environment-specific code in handlers
- Never import Cloud Functions code (`functions-framework`) into the Fastify server

## Anti-patterns

- Calling `initializeDependencies()` inside handler function -- adds latency per request, defeats eager init
- Skipping graceful shutdown -- database connections leak on restart, port stays occupied
- Creating different handlers for Fastify vs Cloud Functions -- testing locally becomes meaningless
- Not catching `RESPONSE_SENT` errors in handler wrapper -- causes unhandled promise rejections
- Blocking on resources during shutdown without timeout -- process hangs indefinitely
- Setting up Fastify without planning for Cloud Functions deployment -- use **`noony-complete-dual-entry`** skill when you need both entry points

## Done when

- `npm run dev` starts Fastify server successfully
- `GET /health` returns 200 OK
- Graceful shutdown closes cleanly on SIGTERM/SIGINT (no hanging processes)
- Handlers are identical between local Fastify and Cloud Functions entry points
- Dependencies initialize once on startup, not per-request
- Middleware ordering follows canonical order (verify with **`noony-middleware-ordering`** skill)

## If you need more detail

- -> references/fastify-server.md -- Minimal example, production setup with error handling, package.json scripts, development workflow, Cloud Run deployment, troubleshooting
- -> **`noony-complete-dual-entry`** skill -- When you need the full dual-entry production pattern
- -> **`noony-middleware-ordering`** skill -- Middleware ordering reference for any handler setup
