# Noony Framework Skills

Type-safe serverless middleware framework for Google Cloud Functions with Fastify local dev support.

## Skill Router

| Skill | Trigger | Purpose |
|-------|---------|---------|
| [`uncle-noony`](uncle-noony/SKILL.md) | "Help me with Noony", "how do I...", "where do I start" | **Start here if unsure.** Orchestrator that routes to all other skills. |
| [`create-fastify-server`](create-fastify-server/SKILL.md) | "Create Fastify server", "local dev setup" | Set up Fastify server for local development |
| [`convert-cloud-functions-to-fastify`](convert-cloud-functions-to-fastify/SKILL.md) | "Convert to Fastify", "run locally" | Run Cloud Functions handlers locally via Fastify |
| [`custom-adapter`](custom-adapter/SKILL.md) | "Custom adapter", "add Koa/Hapi support" | Create adapters for unsupported frameworks |
| [`path-parameters`](path-parameters/SKILL.md) | "Path parameters", ":userId", "route params" | Handle dynamic route parameters |
| [`dependency-initialization`](dependency-initialization/SKILL.md) | "Init database", "singleton guard" | Singleton initialization pattern |
| [`complete-dual-entry`](complete-dual-entry/SKILL.md) | "Dual entry", "complete example" | Full Fastify + Cloud Functions dual-entry example |
| [`type-inference`](type-inference/SKILL.md) | "Reduce boilerplate", "infer types" | Use createTypedHandler for less boilerplate |
| [`middleware-development`](middleware-development/SKILL.md) | "Create middleware", "BaseMiddleware" | Create type-safe custom middleware |
| [`validation-schemas`](validation-schemas/SKILL.md) | "Add validation", "Zod schema" | Type-safe Zod validation patterns |
| [`error-handling`](error-handling/SKILL.md) | "Handle errors", "return 400/401/500" | Built-in error classes and error handling |
| [`dependency-injection`](dependency-injection/SKILL.md) | "Inject service", "DI setup" | TypeDI dependency injection patterns |
| [`guard-system`](guard-system/SKILL.md) | "Setup auth", "protect routes", "guards" | Auth and permission guard configuration |
| [`performance-optimization`](performance-optimization/SKILL.md) | "Optimize cold start", "performance" | Performance optimization with container pool |
| [`testing-handlers`](testing-handlers/SKILL.md) | "Test handler", "mock services" | Unit testing patterns for handlers |
| [`middleware-ordering`](middleware-ordering/SKILL.md) | "Middleware order", "which middleware first" | Correct middleware chain ordering |

## Skill Clusters

| Cluster | Skills | Covers |
|---------|--------|--------|
| **Framework Setup** | `create-fastify-server`, `convert-cloud-functions-to-fastify`, `custom-adapter`, `complete-dual-entry` | Local dev, migration, adapters, dual-entry |
| **Type Safety** | `type-inference`, `middleware-development` | Generic inference, custom middleware types |
| **Request Pipeline** | `path-parameters`, `validation-schemas`, `error-handling`, `middleware-ordering` | Path params, validation, errors, ordering |
| **Data & Auth** | `dependency-initialization`, `dependency-injection`, `guard-system`, `performance-optimization` | Init, DI, guards, performance |
| **Quality** | `testing-handlers` | Testing patterns |

## Hard Rules

1. **Always preserve generics `<TBody, TUser>` through the entire chain** — Handler, middleware, Context must share the same type parameters.
2. **ErrorHandlerMiddleware must be first** in every middleware chain — it catches errors from all downstream middleware.
3. **Never duplicate handler code between entry points** — define once in a handler module, import into both `server.ts` (Fastify) and `functions.ts` (Cloud Functions).
