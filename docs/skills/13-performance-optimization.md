# Skill 13: Performance Optimization - Singleton Services

## Does exactly this

Provides singleton initialization guard pattern that ensures database connections and services initialize exactly once, preventing per-request initialization overhead (~300-500ms per request wasted).

## When to use

- "Initialize database connection"
- "Set up dependency injection"
- "Singleton pattern for services"
- "Initialize services once"
- "Cold start optimization"
- "Prevent multiple DB connections"

## Steps

1. Create three-condition guard with `initialized` flag, `initializationPromise`, and first-run initialization
   → See resources/13-performance-patterns.md#singleton-initialization-guard-pattern for exact implementation
2. Initialize container via `containerPool.initializeGlobal()` with all process-lifetime services (database, HTTP clients, caches)
   → Do NOT call inside handler — latency impact is ~500ms per request
3. Reset state on failure so next request can retry: `initialized = false; containerPool.reset();`
4. Call `await initializeDependencies()` once at server startup or on first request (cold start)

## Rules

- Three-condition guard REQUIRED: check `initialized`, check `initializationPromise`, then initialize
- Services registered ONLY via `containerPool.initializeGlobal()` — never `Container.set()` in initialization
- Never call `initializeDependencies()` inside a handler function — adds ~500ms per request
- Reset `initialized = false` on failure so next request can retry initialization
- Use `containerPool.isInitialized()` to verify container state before returning
- Global services must be immutable — initialized once, never mutated during requests

## Anti-patterns

- ❌ `initializeDependencies()` inside handler function — each request waits 300-500ms for DB connection
- ❌ Mutating global services during request processing — race conditions with concurrent requests
- ❌ Forgetting to reset `initialized` flag on error — subsequent requests fail silently
- ❌ Using `if (initialized) return` without also checking `containerPool.isInitialized()` — incomplete verification
- ❌ Creating new HTTP clients or database connections per request — socket/SSL overhead per request

## Done when

- You understand why initializing per-request costs 300-500ms per request
- You can implement the three-condition guard pattern correctly
- You know the difference between cold start (lazy) and warm start (eager) initialization
- You can identify performance anti-patterns in existing code

## If you need more detail

→ resources/13-performance-patterns.md — Complete guard implementation with comments, cold start vs warm start strategies, performance benchmarks, common anti-patterns with impact analysis, performance checklist
