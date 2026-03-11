# Skill 06: Complete Dual-Entry Example

## Does exactly this

End-to-end example of same Noony handler working identically in both Fastify (local dev) and Cloud Functions (production) with zero code duplication. Covers handler, services, initialization, and both entry points.

## When to use

- "Show me a complete example"
- "How do I support both Fastify and Cloud Functions"
- "Write once, deploy anywhere"
- "Full integration setup"

## Steps

1. Define handler once with all middlewares in canonical order
   → See resources/06-dual-entry.md#1-handler-definition for complete code
2. Create singleton initialization guard shared by both entry points
   → See resources/06-dual-entry.md#2-initialization for pattern
3. Fastify entry point: Use `createFastifyHandler()` wrapper with eager initialization
   → See resources/06-dual-entry.md#3-local-development-fastify for local dev setup
4. Cloud Functions entry point: Call `initializeDependencies()` then `handler.execute()`
   → See resources/06-dual-entry.md#4-production-cloud-functions for production setup
5. Never duplicate handler, middleware chain, or initialization code between entry points

## Rules

- Handler module exports ONLY the handler — no server or deployment code mixed in
- `server.ts` contains Fastify setup ONLY — never import Cloud Functions code
- `functions.ts` contains Cloud Functions exports ONLY — never import Fastify code
- Same handler instance, same middleware chain, same business logic in both environments
- Use `initializeDependencies()` in both Fastify (onReady hook) and Cloud Functions (on request)
- Initialization is idempotent — safe to call multiple times, fast path returns immediately

## Anti-patterns

- ❌ Duplicating handler code between `server.ts` and `functions.ts` — violates DRY principle, bugs in one won't be in the other
- ❌ Different middleware chains for local vs production — testing breaks when deployed
- ❌ Calling `initializeDependencies()` inside handler function — adds latency per request
- ❌ Importing server startup code into `functions.ts` — Cloud Functions can't run Fastify
- ❌ Different validation schemas or business logic between environments — production behavior differs from local

## Done when

- You understand the handler is defined once, used in both environments
- You know how to set up Fastify entry point with eager initialization
- You know how to set up Cloud Functions entry point with lazy initialization
- You can identify when code is properly separated (handler vs entry points)

## If you need more detail

→ resources/06-dual-entry.md — Complete project structure, 4 code sections (handler, init, Fastify, Cloud Functions), usage examples, comparison table of differences, key advantages, common gotchas with solutions
