# Skill 01: Create Type-Safe Fastify Server

## Does exactly this

Complete Fastify server setup for local development with dependency initialization, route registration, graceful shutdown, and logging. Includes minimal and production-ready examples.

## When to use

- "Set up local development server"
- "Create Fastify project"
- "How do I start a server"
- "Add graceful shutdown"

## Steps

1. Create Fastify instance and initialize dependencies on onReady hook
   → See resources/01-fastify-server.md#minimal-server for quickstart
2. Register routes using `createFastifyHandler()` wrapper
   → Wrapper handles request adaptation, init idempotency, error handling
3. Add graceful shutdown to close server and cleanup resources on SIGTERM/SIGINT
   → See resources/01-fastify-server.md#production-ready-server-with-graceful-shutdown for full pattern
4. Use same handler instances in both Fastify and Cloud Functions (no duplication)

## Rules

- MUST initialize dependencies on `server.addHook('onReady')` — never inside route handlers
- MUST call `cleanup()` during graceful shutdown — closes DB connections, clears resources
- Always use `createFastifyHandler()` wrapper — handles error catching and response completion checks
- Register same handler instance for all environments (no environment-specific code)
- Never import Cloud Functions code into Fastify server — keep entry points separate

## Anti-patterns

- ❌ Calling `initializeDependencies()` inside handler function — adds latency per request
- ❌ Skipping graceful shutdown — database connections leak on restart
- ❌ Different handlers/middleware for Fastify vs Cloud Functions — testing breaks on deploy
- ❌ Not catching `RESPONSE_SENT` errors in handler wrapper — crashes on double-send
- ❌ Blocking on resources during shutdown (timeout errors) — process hangs

## Done when

- You can start Fastify server with `npm run dev`
- Health check endpoint returns 200 OK
- Graceful shutdown closes cleanly on SIGTERM/SIGINT
- Handlers are identical between local and Cloud Functions

## If you need more detail

→ resources/01-fastify-server.md — Minimal example, production setup with error handling, package.json scripts, development workflow, Cloud Run deployment, troubleshooting
