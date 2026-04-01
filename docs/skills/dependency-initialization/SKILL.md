---
name: noony-dependency-initialization
description: Use when initializing database connections, setting up singleton services, implementing the three-condition guard for concurrent-safe one-time initialization, connecting to external APIs at startup, or preventing duplicate DB connections during cold starts in Noony handlers.
---

# skill:noony-dependency-initialization

## Does exactly this

The singleton initialization guard pattern — initialize database connections, services, and SDKs exactly once. Handles concurrent cold-start requests, initialization failures with retry, and graceful shutdown cleanup.

## When to use

- "Initialize database connection"
- "Set up singleton services at startup"
- "Prevent duplicate initialization under concurrent requests"
- "Three-condition guard pattern"
- "Graceful shutdown with cleanup"
- "Eager vs lazy initialization"

## Do not use this skill when

- For service RESOLUTION (getService, container scopes) → use `noony-dependency-injection` skill
- For broader performance optimization (memory, lazy vs eager strategy, containerPool tuning) → use `noony-performance-optimization` skill
- For testing with mocked services → use `noony-testing-handlers` skill
- For DI inside custom middleware → use `noony-middleware-development` skill

## Steps

1. Create the three-condition guard with `initialized` flag, `initializationPromise`, and first-run logic
   - Condition 1: fast path — return immediately if already initialized
   - Condition 2: concurrent path — `await initializationPromise` if another request started init
   - Condition 3: first request — perform actual initialization
   → See `references/dependency-init.md` for the complete guard implementation

2. Register all global services via `containerPool.initializeGlobal()` with `{ id, value }` pairs inside the guard
   - Never use `Container.set()` directly — it bypasses framework scoping
   - Services registered here are shared across all requests (zero-copy via proxy)
   → See `references/dependency-init.md` for registration examples

3. Reset state on failure so the next request can retry
   - Set `initialized = false` in the catch block
   - Call `containerPool.reset()` to clear partial state
   - Always clear `initializationPromise = null` in the finally block
   → See `references/dependency-init.md` for error recovery pattern

4. Call `initializeDependencies()` at the right time
   - **Eager (Fastify/Express):** call at server startup before listening
   - **Lazy (Cloud Functions):** pass as third argument to handler wrapper
   - Never call inside a handler function — adds 300-500ms per request

5. After initialization, resolve services using `noony-dependency-injection` skill patterns — `getService(context, ServiceClass)` in controllers
   → See `noony-dependency-injection` skill for resolution patterns

6. Add graceful shutdown with cleanup on SIGTERM/SIGINT
   - Disconnect database connections, call `containerPool.reset()`, set `initialized = false`
   → See `references/dependency-init.md` for shutdown handler

## Rules

- Three-condition guard is REQUIRED — all three conditions must be present
- Services registered ONLY via `containerPool.initializeGlobal()` with id/value pairs
- Never call `initializeDependencies()` inside a handler — adds latency per request
- Always reset `initialized = false` on error so next request retries
- Always clear `initializationPromise = null` in the finally block
- Graceful shutdown MUST call cleanup before process exit
- `noony-performance-optimization` skill uses this pattern as one component of cold start optimization

## Anti-patterns

- ❌ Missing Condition 2 (`initializationPromise` check) — concurrent requests each open their own DB connection
- ❌ Forgetting to reset `initialized` on failure — stuck in broken state permanently
- ❌ Calling init inside handler function — 300-500ms penalty on every request
- ❌ Using `Container.set()` instead of `containerPool.initializeGlobal()` — bypasses framework DI scoping
- ❌ No cleanup on shutdown — database connections leak, sockets left open
- ❌ Creating new service instances per request instead of resolving from container

## Done when

- Three-condition guard is implemented with all three conditions
- Global services registered via `containerPool.initializeGlobal()`
- Failure resets state so next request can retry
- Initialization called at startup (eager) or via wrapper (lazy) — not per-request
- Graceful shutdown handlers registered for SIGTERM and SIGINT

## If you need more detail

→ `references/dependency-init.md` — Complete guard implementation with comments, eager vs lazy patterns, service access via getService(), memory comparison, testing with mock services, and troubleshooting for common initialization problems
