---
description: Noony dependency injection rules. Apply when initializing services, resolving dependencies, or managing container state in a Noony project.
globs:
  - "src/**/*.ts"
  - "functions.ts"
  - "server.ts"
alwaysApply: false
---

# Noony — Dependency Injection Rules

## Two Scopes

| Scope | Lifetime | Use for |
|-------|---------|---------|
| `containerPool.global` | Process | DB clients, SDKs, connection pools |
| `containerPool.local` | Per-request | Auth user, request metadata, business data |

## Singleton Guard Pattern (required for global services)

```typescript
let initialized = false;
let initializing = false;

async function initializeDependencies() {
  if (initialized) return;
  if (initializing) return;
  initializing = true;
  try {
    containerPool.initializeGlobal(DatabaseService, new Firestore());
    initialized = true;
  } catch (err) {
    initializing = false;
    throw err;
  }
}
```

## Rules

- Initialize global services once — in Fastify `onReady` hook or before handler execution
- Resolve services with `getService(ServiceClass, context.container)` — not `Container.get()`
- Add `DependencyInjectionMiddleware` at position 13+ to expose services to context
- Never initialize services inside the controller — runs on every request
- Request-scoped data goes in `context.container.set()` / `.get()`

## Forbidden

- `Container.set()` in production — leaks between requests, bypasses scope isolation
- `Container.reset()` in production — destroys all global state
- Initializing DB/SDK inside the handler body

## Reference

→ `docs/noony-skills/dependency-injection/SKILL.md`
→ `docs/noony-skills/dependency-initialization/SKILL.md`
