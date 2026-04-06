## Noony Skill System

This project uses the **uncle-noony orchestrator** with 16 specialized skills. For any Noony-related task, route through the skill system rather than answering generically.

→ Full orchestrator: `docs/skills/uncle-noony/SKILL.md`
→ Skill router table: `docs/skills/README.md`

### Skill List

- `noony-uncle-noony` — orchestrator (broad/ambiguous questions start here)
- `noony-create-fastify-server` — local Fastify setup
- `noony-convert-cloud-functions-to-fastify` — Cloud Functions → Fastify migration
- `noony-custom-adapter` — unsupported framework adapters (Koa, Hapi, NestJS)
- `noony-path-parameters` — route params (`:id`, `:userId`)
- `noony-dependency-initialization` — startup singleton initialization
- `noony-complete-dual-entry` — Fastify + Cloud Functions production pattern
- `noony-type-inference` — generic flow and handler typing
- `noony-middleware-development` — custom middleware authoring
- `noony-validation-schemas` — Zod validation and request typing
- `noony-error-handling` — typed errors and HTTP status mapping
- `noony-dependency-injection` — service resolution with TypeDI
- `noony-guard-system` — auth, permissions, RBAC guards
- `noony-performance-optimization` — cold starts, memory, performance
- `noony-testing-handlers` — handler and middleware tests
- `noony-middleware-ordering` — middleware sequencing (canonical authority)

### Mandatory Routing Rules

- Broad or multi-concern tasks → read `docs/skills/uncle-noony/SKILL.md` first
- Specific tasks → read the matching skill's `SKILL.md` directly
- Always state which skill(s) you are applying
- Preserve `<TBody, TUser>` generics end-to-end — never use `as any`
- `noony-middleware-ordering` is the authority on middleware sequencing
- `noony-error-handling` is the authority on typed errors

### Noony Core Rules

These rules are non-negotiable in every Noony handler.

**Middleware Ordering** — Every handler chain MUST follow this order:

1. `ErrorHandlerMiddleware` — MUST be first; its `onError` fires last in reverse, catching all errors
2. `OpenTelemetryMiddleware` — wraps full request lifecycle including auth
3. Header/structural checks (positions 3–5) — cheap fast-fail
4. `BodyParserMiddleware` (position 6) — MUST come before `BodyValidationMiddleware`
5. `BodyValidationMiddleware` (position 7)
6. `PathParametersMiddleware` (position 8) — before auth guards that need route params
7. Auth middlewares (positions 9–12): Firebase, OAuth2, guards
8. DI setup, business logic middlewares (position 13+)
9. `ResponseWrapperMiddleware` — MUST be last; its `after` runs first in reverse

Execution: `before` runs forward (0→N), `after`/`onError` run reverse (N→0).

**Error Handling** — Always throw typed errors from `@noony-serverless/core`:
`ValidationError` (400), `UnauthorizedError` (401), `ForbiddenError` (403), `NotFoundError` (404), `ConflictError` (409), `InternalServerError` (500).
Never throw generic `Error()`. Never call `context.res.status().json()` — throw instead.
Wrap external errors with cause chaining: `new InternalServerError('msg', originalError)`.

**Type Safety** — Preserve `<TBody, TUser>` through every layer: `Handler`, middleware, `Context`.
All middleware MUST implement `BaseMiddleware<TBody, TUser>`. Never use `as any`.

**Forbidden**: `ErrorHandlerMiddleware` not at position 1 · `ResponseWrapperMiddleware` not last · double-send (json + return) · `throw new Error()` · `as any` · `Container.set()`/`Container.reset()` in production.
