# CLAUDE.md

Guidance for Claude Code when working with the **Noony Serverless Framework** — a TypeScript middleware framework for Google Cloud Functions with full type safety and framework-agnostic support.

## Quick Start

**Project Type**: Serverless middleware framework (TypeScript, Jest, ESLint, Prettier)

**Key Files**:

- Getting Started: → `docs/00-getting-started.md`
- Handler Guide: → `docs/01-handler-guide.md`
- API Reference: → `docs/02-api-reference.md`
- Container Architecture: → `docs/03-container-architecture.md`
- Middleware Guides: → `docs/middlewares/`
- Auth Guides: → `docs/auth/`
- Adopter Template: → `docs/meta/ADOPTER_CLAUDE_MD_TEMPLATE.md`


## Architecture at a Glance

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

→ See `docs/03-container-architecture.md` for complete diagrams and patterns

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

→ `docs/middlewares/01-overview.md`

Required:
- Implement `BaseMiddleware<TBody, TUser>`
- Use generics (no untyped `Context`)
- Add tests alongside implementation

### Integrating with Fastify (Local Dev)

→ `docs/00-getting-started.md`

Use `createFastifyHandler()` wrapper for type-safe integration.

### Using Dependency Injection

→ `docs/03-container-architecture.md`

Global services: Initialize once at startup.
Local services: Add per-request in middleware.

### Error Handling

→ `docs/02-api-reference.md`

Use framework error classes:
- `ValidationError` (400), `UnauthorizedError` (401), `ForbiddenError` (403)
- `NotFoundError` (404), `ConflictError` (409), `InternalServerError` (500)

### OpenTelemetry & Tracing

→ `docs/02-api-reference.md`

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
├── 00-getting-started.md        # Practical adoption guide with real examples
├── 01-handler-guide.md          # Handler class deep dive, generics, lifecycle
├── 02-api-reference.md          # Full API reference, OTel, error system
├── 03-container-architecture.md # Hybrid Proxy Container, zero-copy DI
├── middlewares/                 # Middleware guides (body, headers, query, DI)
├── auth/                        # Auth guides (RouteGuards, Firebase, OAuth2)
└── meta/                        # Adopter templates
```

## When Modifying Code

**Before touching files:**
1. Read relevant `docs/*.md` section for patterns
2. Check existing tests in `*.test.ts` files
3. Ensure type generics flow: `Handler<T, U>` → all middlewares → `Context<T, U>`

**Middleware Type Chain (CRITICAL)**:
All middlewares **must** preserve generics `<TBody, TUser>`. See `docs/middlewares/01-overview.md`.

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

- **CLAUDE.md**: This file (quick reference, routing to details)
- **docs/*.md**: Deep dives (150-500 lines each) with examples, tables, diagrams
- **Inline comments**: Only for "why", not "what" (code is self-documenting)
- **README.md**: User-facing setup & getting started

## Need Help?

| Question | Answer |
|----------|--------|
| How do I set up the project? | `npm install && npm run build` |
| How do I run tests? | `npm run test` or `npm run test:coverage` |
| Where's the handler pattern? | → `docs/01-handler-guide.md` |
| How does DI work? | → `docs/03-container-architecture.md` |
| How do I add a custom middleware? | → `docs/middlewares/01-overview.md` |
| How do I trace requests? | → `docs/02-api-reference.md` |
| What error classes should I use? | → `docs/02-api-reference.md` |

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
