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

---
---


Use this as a paste-ready instruction for a custom agent:

```md
## Noony Skills Router

When working in any project that uses Noony, always prefer the Noony skill system and route work through the appropriate `noony-` skill names.

### Core rule

If the task matches one or more Noony skills, explicitly apply the relevant Noony skills before giving guidance, writing code, or proposing architecture.

### Available Noony skills

- `noony-uncle-noony`
- `noony-create-fastify-server`
- `noony-convert-cloud-functions-to-fastify`
- `noony-custom-adapter`
- `noony-path-parameters`
- `noony-dependency-initialization`
- `noony-complete-dual-entry`
- `noony-type-inference`
- `noony-middleware-development`
- `noony-validation-schemas`
- `noony-error-handling`
- `noony-dependency-injection`
- `noony-guard-system`
- `noony-performance-optimization`
- `noony-testing-handlers`
- `noony-middleware-ordering`

### Routing behavior

- If the user is unsure where to start, asks broad Noony questions, or the task spans multiple concerns, start with `noony-uncle-noony`.
- If the task is narrow and clearly maps to one skill, use that skill directly.
- If the task spans multiple Noony concerns, combine skills in a sensible order instead of answering generically.
- Always mention which Noony skill or skills you are applying.

### Required skill routing by topic

- Local Fastify setup: `noony-create-fastify-server`
- Cloud Functions to Fastify migration: `noony-convert-cloud-functions-to-fastify`
- Unsupported framework adapters: `noony-custom-adapter`
- Route and path params: `noony-path-parameters`
- Service startup and singleton initialization: `noony-dependency-initialization`
- Full Fastify + Cloud Functions production pattern: `noony-complete-dual-entry`
- Generic flow and handler typing: `noony-type-inference`
- Custom middleware authoring: `noony-middleware-development`
- Zod validation and request typing: `noony-validation-schemas`
- Typed errors and HTTP mapping: `noony-error-handling`
- Container usage and service resolution: `noony-dependency-injection`
- Auth, permissions, and guards: `noony-guard-system`
- Cold starts and performance tuning: `noony-performance-optimization`
- Tests for handlers and middleware: `noony-testing-handlers`
- Middleware sequencing and lifecycle order: `noony-middleware-ordering`

### Non-negotiable Noony rules

- Preserve generics `<TBody, TUser>` across `Handler`, middleware, and `Context`.
- Never use `as any` to escape type flow problems.
- Treat `noony-middleware-ordering` as the authority for middleware order.
- Treat `noony-error-handling` as the authority for typed error usage.
- Prefer Noony-native patterns over generic framework advice.

### Response style

- Be practical and decisive.
- Give Noony-specific guidance, not generic Node.js or Express advice.
- When relevant, explain the recommended order of Noony skills to apply.
- If the task is ambiguous, ask a short clarifying question only if needed; otherwise make a reasonable Noony-first assumption.
```

If you want, I can also turn this into:
1. a shorter version for ChatGPT Custom Instructions
2. a stricter version for Claude/Codex agent files
3. a “router + workflow” version with explicit if/then rules





## Shorter Version for ChatGPT Custom Instructions

```md
When working on any Noony project, always use the relevant Noony skill names and prefer Noony-specific patterns over generic advice.

Available skills:
`noony-uncle-noony`, `noony-create-fastify-server`, `noony-convert-cloud-functions-to-fastify`, `noony-custom-adapter`, `noony-path-parameters`, `noony-dependency-initialization`, `noony-complete-dual-entry`, `noony-type-inference`, `noony-middleware-development`, `noony-validation-schemas`, `noony-error-handling`, `noony-dependency-injection`, `noony-guard-system`, `noony-performance-optimization`, `noony-testing-handlers`, `noony-middleware-ordering`.

Rules:
- If the task is broad, unclear, or spans multiple areas, start with `noony-uncle-noony`.
- If the task is specific, apply the matching Noony skill directly.
- Always mention which Noony skill(s) you are applying.
- Preserve generics `<TBody, TUser>` through Handler, middleware, and Context.
- Treat `noony-middleware-ordering` as the authority for middleware order.
- Treat `noony-error-handling` as the authority for typed errors and HTTP mapping.
- Prefer Noony-native guidance over generic Express/Fastify/Node patterns.
```

## Stricter Version for Claude/Codex Agent Files

```md
# Noony Skill Enforcement

When operating in a Noony-based project, you must route all relevant work through the Noony skill system.

## Approved Noony skills

- `noony-uncle-noony`
- `noony-create-fastify-server`
- `noony-convert-cloud-functions-to-fastify`
- `noony-custom-adapter`
- `noony-path-parameters`
- `noony-dependency-initialization`
- `noony-complete-dual-entry`
- `noony-type-inference`
- `noony-middleware-development`
- `noony-validation-schemas`
- `noony-error-handling`
- `noony-dependency-injection`
- `noony-guard-system`
- `noony-performance-optimization`
- `noony-testing-handlers`
- `noony-middleware-ordering`

## Mandatory behavior

- You MUST apply one or more Noony skills whenever the task touches Noony handlers, middleware, validation, errors, DI, auth, Fastify integration, Cloud Functions, testing, performance, or framework architecture.
- You MUST start with `noony-uncle-noony` when the request is broad, ambiguous, exploratory, or spans multiple Noony concerns.
- You MUST use the directly relevant skill when the task is narrow and clearly scoped.
- You MUST explicitly state which Noony skill(s) you are using.
- You MUST prefer Noony framework conventions over generic framework advice.

## Hard rules

- Preserve generics `<TBody, TUser>` through `Handler`, middleware, and `Context`.
- Never recommend `as any` as a way to resolve typing issues.
- Treat `noony-middleware-ordering` as the single source of truth for middleware sequencing.
- Treat `noony-error-handling` as the single source of truth for typed errors and HTTP status mapping.
- Use `noony-validation-schemas` for Zod/body/query validation concerns.
- Use `noony-dependency-initialization` for startup initialization and `noony-dependency-injection` for service resolution.
- Use `noony-guard-system` for auth and permissions.
- Use `noony-testing-handlers` for handler and middleware tests.
- Use `noony-complete-dual-entry` for the production Fastify + Cloud Functions pattern.

## Escalation

- If multiple skills apply, use them in a sensible sequence instead of answering generically.
- If unsure which Noony skill applies, use `noony-uncle-noony` first.
```

## Router + Workflow Version With Explicit If/Then Rules

```md
# Noony Router

Use these routing rules for any Noony project.

## Primary rule

- If a task involves Noony, route it through Noony skills first.

## If/Then routing

- If the user is unsure where to start, asks “how do I…”, is new to Noony, or the task spans multiple areas, then use `noony-uncle-noony`.
- If the user needs a local Fastify dev server, then use `noony-create-fastify-server`.
- If the user wants to migrate Cloud Functions code to run in Fastify too, then use `noony-convert-cloud-functions-to-fastify`.
- If the user needs support for Koa, Hapi, NestJS, or another unsupported framework, then use `noony-custom-adapter`.
- If the user is working with route params like `:id` or `:userId`, then use `noony-path-parameters`.
- If the user needs one-time startup/service initialization, then use `noony-dependency-initialization`.
- If the user wants the full production pattern for Fastify + Cloud Functions, then use `noony-complete-dual-entry`.
- If the user has generic/type-flow issues, then use `noony-type-inference`.
- If the user is creating custom middleware, then use `noony-middleware-development`.
- If the user is defining or applying Zod validation, then use `noony-validation-schemas`.
- If the user is handling errors, status codes, or typed exceptions, then use `noony-error-handling`.
- If the user is resolving services from the container, then use `noony-dependency-injection`.
- If the user is adding auth, permissions, or route guards, then use `noony-guard-system`.
- If the user is optimizing startup, memory, or request performance, then use `noony-performance-optimization`.
- If the user is writing tests for handlers or middleware, then use `noony-testing-handlers`.
- If the user is deciding middleware order, then use `noony-middleware-ordering`.

## Workflow rules

- If the task is broad, start with `noony-uncle-noony`, then dispatch to the needed skills.
- If the task is specific, use the matching skill directly.
- If validation is involved, usually pair `noony-validation-schemas` with `noony-middleware-ordering`.
- If auth is involved, usually pair `noony-guard-system` with `noony-middleware-ordering`, and confirm `noony-error-handling` is in place.
- If custom middleware is involved, usually pair `noony-middleware-development` with `noony-middleware-ordering`.
- If DI is involved, use `noony-dependency-initialization` for startup and `noony-dependency-injection` for runtime resolution.
- If types break across the pipeline, use `noony-type-inference` before changing middleware or handlers.
- If testing behavior, use `noony-testing-handlers` after the implementation skill, not before.

## Non-negotiable rules

- Preserve `<TBody, TUser>` end-to-end.
- Never use `as any` to bypass Noony type issues.
- `noony-middleware-ordering` is the authority on order.
- `noony-error-handling` is the authority on typed errors.
- Always say which Noony skill(s) are being applied.
```

If you want, I can also bundle these into:
- a single [AGENTS.md](/Users/javierbenavides/others/dev/noony/noony-core/AGENTS.md)-style section
- a polished `CLAUDE.md` block
- a one-line ultra-compact version for ChatGPT’s limited custom instruction space