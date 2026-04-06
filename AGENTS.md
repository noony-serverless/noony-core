# AGENTS.md

Guidance for Codex when working with the **Noony Serverless Framework** — a TypeScript middleware framework for Google Cloud Functions with full type safety and framework-agnostic support.

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

<!-- noony-section:end -->

---

## Quick Start

**Project Type**: Serverless middleware framework (TypeScript, Jest, ESLint, Prettier)

**Key Files**:

- Documentation Index: → `docs/INDEX.md`
- Getting Started: → `docs/tutorials/01-getting-started.md`
- API Reference: → `docs/reference/api.md`
- Architecture: → `docs/explanation/architecture.md`
- Container Model: → `docs/explanation/container-model.md`
- Middleware Reference: → `docs/reference/middlewares/INDEX.md`
- Auth Reference: → `docs/reference/auth/INDEX.md`
- Guides: → `docs/guides/`
- Adopter Template: → `docs/meta/ADOPTER_CLAUDE_MD_TEMPLATE.md`


## Architecture at a Glance
`
```
Handler<TBody, TUser>          (Middleware pipeline orchestrator)
  ├─ .use(BaseMiddleware)      (Before → After → OnError hooks)
  ├─ .handle(controller)       (Business logic)
  └─ .execute[Generic]()       (Run on GCP/Express/Fastify)

Context<TBody, TUser>          (Type-safe request/response/user)
  ├─ req: GenericRequest       (Headers, body, params, query)
  ├─ res: GenericResponse      (status, json, header, send)
  └─ container: ContainerPool  (DI with global+local scopes)
```

→ See `docs/explanation/container-model.md` for complete diagrams and patterns

## Core Principles

1. **Type Safety First** — Use generics `<TBody, TUser>` throughout; no `as any`
2. **Zero-Copy DI** — Global services (DB) shared, request data isolated (~99% memory savings)
3. **Framework Agnostic** — Same handler runs on GCP Functions, Express, Fastify
4. **Middleware Chain** — Execute `before` (order), `after`/`onError` (reverse order)
5. **Error Mapping** — All errors → HTTP status via error classes (400, 401, 403, 404, 500, etc.)

## Workflow Orchestration

### Plan Mode Default

- Enter **plan mode** for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways: **STOP and re-plan immediately** — don't keep pushing
- Use plan mode for **verification steps**, not just building
- Write **detailed specs upfront** to reduce ambiguity

### Subagent Strategy

- Use **subagents liberally** to keep main context window clean
- Offload **research, exploration, parallel analysis** to subagents
- For complex problems: **throw more compute via subagents**
- **One task per subagent** for focused execution

### Self-Improvement Loop

- After **ANY user correction**: update lessons with the pattern
- Write **rules that prevent the same mistake**
- Ruthlessly iterate until **mistake rate drops**
- Review lessons at **session start** for the project

### Verification Before Done

- **Never mark task complete without proving it works**
- Diff behavior between **main and changes** when relevant
- Ask: **"Would a staff engineer approve this?"**
- Run tests, check logs, **demonstrate correctness**

### Demand Elegance (Balanced)

- For non-trivial changes: pause and ask **"Is there a more elegant way?"**
- If fix feels hacky: **implement the elegant solution knowing everything now**
- Skip this for simple, obvious fixes — **don't over-engineer**
- **Challenge your own work** before presenting

### Autonomous Bug Fixing

- Given bug report: **just fix it** — no hand-holding needed
- Point at **logs, errors, tests** — then resolve them
- **Zero context switching** from user
- Fix **failing CI tests** without being told how

## Common Tasks

### Adding a New Middleware

→ `docs/guides/custom-middleware.md`

Required:
- Implement `BaseMiddleware<TBody, TUser>`
- Use generics (no untyped `Context`)
- Add tests alongside implementation

### Integrating with Fastify (Local Dev)

→ `docs/tutorials/03-local-dev-with-fastify.md`

Use `createFastifyHandler()` wrapper for type-safe integration.

### Using Dependency Injection

→ `docs/guides/dependency-injection.md`

Global services: Initialize once at startup.
Local services: Add per-request in middleware.

### Error Handling

→ `docs/guides/error-handling.md`

Use framework error classes:
- `ValidationError` (400), `UnauthorizedError` (401), `ForbiddenError` (403)
- `NotFoundError` (404), `ConflictError` (409), `InternalServerError` (500)

### OpenTelemetry & Tracing

→ `docs/reference/telemetry.md`

Auto-detects provider from environment; works with GCP CloudPropagator.

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `@google-cloud/functions-framework` | GCP Functions runtime |
| `@opentelemetry/sdk-node` | Distributed tracing |
| `zod` | Schema validation |
| `typedi` | Dependency injection |
| `fastify` | Optional local dev server |

## Project Structure

```
src/
├── core/                     # Handler, Context, ContainerPool
├── middlewares/              # Built-in middleware (10+ implementations)
│   └── guards/               # Permission & auth guard system
├── utils/                    # Query params, DI helpers, Pub/Sub tracing
└── index.ts                  # Main exports

docs/
├── INDEX.md                     # Site map + audience reading paths
├── tutorials/                   # Learning-oriented, sequential
│   ├── 01-getting-started.md    # First handler setup
│   ├── 02-add-authentication.md # Auth integration
│   ├── 03-local-dev-with-fastify.md # Local development
│   └── 04-testing-handlers.md   # Testing patterns
├── guides/                      # Task-oriented how-to guides
├── reference/                   # Lookup-oriented
│   ├── api.md                   # Full API reference
│   ├── errors.md                # Error class hierarchy
│   ├── telemetry.md             # OpenTelemetry config
│   ├── middlewares/             # All 15 middleware reference docs
│   └── auth/                    # Auth system reference
├── explanation/                 # Understanding-oriented
│   ├── architecture.md          # Handler pipeline deep dive
│   ├── container-model.md       # Zero-copy DI explanation
│   └── design-patterns.md       # Framework design patterns
├── skills/                      # Codex skill cards
└── meta/                        # Adopter templates
```

## When Modifying Code

**Before touching files:**
1. Read relevant `docs/*.md` section for patterns
2. Check existing tests in `*.test.ts` files
3. Ensure type generics flow: `Handler<T, U>` → all middlewares → `Context<T, U>`

**Middleware Type Chain (CRITICAL)**:
All middlewares **must** preserve generics `<TBody, TUser>`. See `docs/reference/middlewares/INDEX.md`.

**Testing**:
- Write tests alongside implementation
- Use `npm run test -- <file>` for quick iteration
- Coverage report: `npm run test:coverage`

## Git Workflow

| Scenario | Command |
|----------|---------|
| View changes | `git diff` |
| Commit work | `git commit -m "..."` |
| Create PR | `gh pr create` |
| View status | `git status` |

Current branch: `open-telemetry` | Main branch: `main`

## Documentation Standards

- **AGENTS.md**: This file (quick reference, routing to details)
- **docs/*.md**: Deep dives (150-500 lines each) with examples, tables, diagrams
- **Inline comments**: Only for "why", not "what" (code is self-documenting)
- **README.md**: User-facing setup & getting started

## Need Help?

| Question | Answer |
|----------|--------|
| How do I set up the project? | `npm install && npm run build` |
| How do I run tests? | `npm run test` or `npm run test:coverage` |
| Where's the handler pattern? | → `docs/explanation/architecture.md` |
| How does DI work? | → `docs/guides/dependency-injection.md` |
| How do I add a custom middleware? | → `docs/guides/custom-middleware.md` |
| How do I trace requests? | → `docs/reference/telemetry.md` |
| What error classes should I use? | → `docs/reference/errors.md` |
| Full documentation index? | → `docs/INDEX.md` |

## Task Management Workflow

### 1. Plan First

- Write plan to `tasks/todo.md` with checkable items
- Include: what, why, how, success criteria
- Review before starting implementation

### 2. Verify Plan

- Check in before starting work
- Get approval for complex architectural changes
- Identify blockers early

### 3. Track Progress

- Mark items complete as you go
- Update status in real-time (in_progress → completed)
- Link to verification steps

### 4. Explain Changes

- High-level summary at each step
- Point to code changes, test results, diffs
- No vague statements

### 5. Document Results

- Add review section to `tasks/todo.md` after completion
- Note any lessons learned
- Suggest follow-up work if needed

### 6. Capture Lessons

- Update `tasks/lessons.md` after corrections
- Document patterns that prevent mistakes
- Build playbook for common scenarios

## Core Development Standards

| Standard | Rule |
| --- | --- |
| **Simplicity** | Make every change as simple as possible. Impact minimal code. |
| **No Laziness** | Find root causes. No temporary fixes. Senior developer standards. |
| **Minimal Impact** | Changes touch only what's necessary. Avoid introducing bugs. |
| **Testing** | Run tests before claiming done. Show evidence. |
| **Code Review** | Ask: "Would a staff engineer approve this?" |

---

**Last updated**: 2025-03-10 | **Version**: 0.8.0
