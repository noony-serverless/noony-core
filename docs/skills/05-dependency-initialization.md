# Skill 05: Dependency Initialization Pattern

## Does exactly this

Provides singleton initialization guard pattern that ensures database connections and services initialize exactly once. Handles concurrent requests, failures, and safe state resets.

## When to use

- "Initialize database connection"
- "Set up dependency injection"
- "Singleton pattern for services"
- "Initialize services once"
- "Connect to database on startup"
- "Prevent multiple DB connections"

## Steps

1. Create three-condition guard with `initialized` flag, `initializationPromise`, and first-run logic
   → See resources/05-dependency-init.md#singleton-pattern-with-three-condition-guard for exact code to copy
2. Register all services via `containerPool.initializeGlobal()` — never use `Container.set()` in init
3. Reset state on failure: `initialized = false; containerPool.reset();` so next request can retry
4. Call `await initializeDependencies()` at server startup (eager) or on first request (lazy)
5. Add graceful shutdown with cleanup: `await cleanup()` on SIGTERM/SIGINT

## Rules

- Three-condition guard REQUIRED: check `initialized`, check `initializationPromise`, then initialize
- Services registered ONLY via `containerPool.initializeGlobal()` with id/value pairs
- Never call `initializeDependencies()` inside a handler function — adds latency per request
- Always reset `initialized = false` on error so next request can retry
- Always clear `initializationPromise = null` in finally block
- Graceful shutdown MUST call `cleanup()` before process exit

## Anti-patterns

- ❌ Missing CONDITION 2 (initPromise check) — concurrent requests initialize multiple times
- ❌ Forgetting to reset `initialized` on failure — stuck in failure state forever
- ❌ Calling init inside handler — adds 300-500ms per request
- ❌ Using `Container.set()` instead of `containerPool.initializeGlobal()` — breaks framework DI
- ❌ No cleanup on shutdown — database connections leak, sockets unclosed

## Done when

- You understand all three conditions in the guard pattern
- You can implement the pattern correctly without referring to docs
- You know when to use lazy (cloud functions) vs eager (Fastify)
- You understand the performance impact of per-request initialization

## If you need more detail

→ resources/05-dependency-init.md — Complete guard implementation with comments, usage in Fastify (eager) and Cloud Functions (lazy), service access patterns, performance implications, troubleshooting for common problems
