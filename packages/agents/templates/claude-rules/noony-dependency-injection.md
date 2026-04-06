---
description: Noony DI rules — apply when initializing services or resolving dependencies.
globs: ["src/**/*.ts", "functions.ts", "server.ts"]
---

# Noony — Dependency Injection Rules

Two scopes: `containerPool.global` (process lifetime — DB, SDKs) and `containerPool.local` (per-request — auth user, metadata).

Singleton guard required for global services:
```typescript
let initialized = false, initializing = false;
async function init() {
  if (initialized || initializing) return;
  initializing = true;
  try { containerPool.initializeGlobal(Svc, new Svc()); initialized = true; }
  catch (e) { initializing = false; throw e; }
}
```

- Resolve with `getService(ServiceClass, context.container)` — not `Container.get()`
- Add `DependencyInjectionMiddleware` at position 13+
- Initialize in Fastify `onReady` or before handler — never inside the controller
- Request-scoped data: `context.container.set()` / `.get()`

Forbidden: `Container.set()` in production · `Container.reset()` in production · service init inside handler body.
