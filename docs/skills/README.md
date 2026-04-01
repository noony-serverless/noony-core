# Noony Framework Skills

Type-safe serverless middleware framework for Google Cloud Functions with Fastify local dev support.

## Skill Router

| Skill | Trigger | Purpose |
|-------|---------|---------|
| [`noony-uncle-noony`](uncle-noony/SKILL.md) | "Help me with Noony", "how do I...", "where do I start" | **Start here if unsure.** Orchestrator that routes to all other skills. |
| [`noony-create-fastify-server`](create-fastify-server/SKILL.md) | "Create Fastify server", "local dev setup" | Set up Fastify server for local development |
| [`noony-convert-cloud-functions-to-fastify`](convert-cloud-functions-to-fastify/SKILL.md) | "Convert to Fastify", "run locally" | Run Cloud Functions handlers locally via Fastify |
| [`noony-custom-adapter`](custom-adapter/SKILL.md) | "Custom adapter", "add Koa/Hapi support" | Create adapters for unsupported frameworks |
| [`noony-path-parameters`](path-parameters/SKILL.md) | "Path parameters", ":userId", "route params" | Handle dynamic route parameters |
| [`noony-dependency-initialization`](dependency-initialization/SKILL.md) | "Init database", "singleton guard" | Singleton initialization pattern |
| [`noony-complete-dual-entry`](complete-dual-entry/SKILL.md) | "Dual entry", "complete example" | Full Fastify + Cloud Functions dual-entry example |
| [`noony-type-inference`](type-inference/SKILL.md) | "Reduce boilerplate", "infer types" | Use createTypedHandler for less boilerplate |
| [`noony-middleware-development`](middleware-development/SKILL.md) | "Create middleware", "BaseMiddleware" | Create type-safe custom middleware |
| [`noony-validation-schemas`](validation-schemas/SKILL.md) | "Add validation", "Zod schema" | Type-safe Zod validation patterns |
| [`noony-error-handling`](error-handling/SKILL.md) | "Handle errors", "return 400/401/500" | Built-in error classes and error handling |
| [`noony-dependency-injection`](dependency-injection/SKILL.md) | "Inject service", "DI setup" | TypeDI dependency injection patterns |
| [`noony-guard-system`](guard-system/SKILL.md) | "Setup auth", "protect routes", "guards" | Auth and permission guard configuration |
| [`noony-performance-optimization`](performance-optimization/SKILL.md) | "Optimize cold start", "performance" | Performance optimization with container pool |
| [`noony-testing-handlers`](testing-handlers/SKILL.md) | "Test handler", "mock services" | Unit testing patterns for handlers |
| [`noony-middleware-ordering`](middleware-ordering/SKILL.md) | "Middleware order", "which middleware first" | Correct middleware chain ordering |

## Skill Clusters

| Cluster | Skills | Covers |
|---------|--------|--------|
| **Framework Setup** | `noony-create-fastify-server`, `noony-convert-cloud-functions-to-fastify`, `noony-custom-adapter`, `noony-complete-dual-entry` | Local dev, migration, adapters, dual-entry |
| **Type Safety** | `noony-type-inference`, `noony-middleware-development` | Generic inference, custom middleware types |
| **Request Pipeline** | `noony-path-parameters`, `noony-validation-schemas`, `noony-error-handling`, `noony-middleware-ordering` | Path params, validation, errors, ordering |
| **Data & Auth** | `noony-dependency-initialization`, `noony-dependency-injection`, `noony-guard-system`, `noony-performance-optimization` | Init, DI, guards, performance |
| **Quality** | `noony-testing-handlers` | Testing patterns |

## Hard Rules

1. **Always preserve generics `<TBody, TUser>` through the entire chain** — Handler, middleware, Context must share the same type parameters.
2. **ErrorHandlerMiddleware must be first** in every middleware chain — it catches errors from all downstream middleware.
3. **Never duplicate handler code between entry points** — define once in a handler module, import into both `server.ts` (Fastify) and `functions.ts` (Cloud Functions).
