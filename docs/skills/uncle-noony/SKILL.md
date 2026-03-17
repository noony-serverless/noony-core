---
name: uncle-noony
description: Use this skill whenever a developer asks for help with the Noony framework, is confused about where to start, asks "how do I...", needs guidance picking the right approach, or mentions being new to the framework. Also use when the developer's question spans multiple skills and you need to orchestrate a workflow. Think of this as the first skill to check — if someone mentions Noony, handlers, middleware, Cloud Functions, or serverless and seems to need direction, uncle-noony is your starting point.
---

# skill:uncle-noony

## Does exactly this

Acts as the central orchestrator for all 16 Noony skills. Diagnoses what the developer needs, routes them to the right skill or combination of skills, and provides guided workflows for multi-step tasks.

## When to use

- "How do I get started with Noony?"
- "I'm new to this framework"
- "What's the best way to..."
- "I need help building an endpoint"
- "How does this all fit together?"
- Developer seems lost or is asking broad questions
- Task clearly spans multiple skills

## Do not use this skill when

- Developer explicitly names a specific skill (e.g., "apply `validation-schemas`" — go directly there)
- Developer asks a narrowly scoped question that maps 1:1 to a single skill
- Question is purely about code syntax unrelated to Noony

## Quick Dispatch Table

When the developer knows exactly what they want, skip the journey and route directly:

| Intent | Apply skill |
|--------|-------------|
| Set up local Fastify dev server | `create-fastify-server` |
| Convert Cloud Functions to Fastify | `convert-cloud-functions-to-fastify` |
| Build adapter for Koa/Hapi/other | `custom-adapter` |
| Handle path parameters (`:id`, `:userId`) | `path-parameters` |
| Initialize DB/services at startup | `dependency-initialization` |
| Full dual-entry example (Fastify + GCP) | `complete-dual-entry` |
| Reduce boilerplate with type inference | `type-inference` |
| Create custom middleware | `middleware-development` |
| Add Zod body validation | `validation-schemas` |
| Handle errors with status codes | `error-handling` |
| Resolve services with TypeDI | `dependency-injection` |
| Add auth guards and permissions | `auth-guards` |
| Optimize cold starts and memory | `performance-optimization` |
| Write handler tests | `testing-handlers` |
| Get middleware ordering right | `middleware-ordering` |

## How uncle-noony works

Uncle Noony does not write code directly — he figures out what the developer needs and assembles the right skills in the right order.

### Step 1: Diagnose the developer's situation

Ask yourself: **What is this developer trying to accomplish?** Map their intent to one of these journeys:

| Developer says... | Journey | Skills to apply (in order) |
|------------------|---------|---------------------------|
| "I'm starting from scratch" | **New Project** | Apply `create-fastify-server`, then `dependency-initialization`, then `complete-dual-entry`, then `middleware-ordering`, then `error-handling` |
| "I need to build an endpoint" | **New Endpoint** | Apply `middleware-ordering`, then `validation-schemas`, then `error-handling`, then `middleware-development` if custom logic needed |
| "I need path parameters" | **Path Params** | Apply `path-parameters`, then `validation-schemas` or `auth-guards` as needed |
| "I need auth on my routes" | **Add Auth** | Apply `auth-guards`, then `middleware-ordering` (check: is `error-handling` already set up?) |
| "My handler is slow" | **Performance** | Apply `performance-optimization`, then `dependency-injection` |
| "I need to test this" | **Testing** | Apply `testing-handlers` |
| "I'm moving to Fastify for local dev" | **Local Dev** | Apply `create-fastify-server`, then `convert-cloud-functions-to-fastify`, then `complete-dual-entry` |
| "I want to add validation" | **Validation** | Apply `validation-schemas`, then `middleware-ordering` |
| "I need custom middleware" | **Custom Middleware** | Apply `middleware-development`, then `middleware-ordering` |
| "How do I resolve services?" | **DI Setup** | Apply `dependency-injection`, then `performance-optimization` for optimization |
| "Types are breaking" | **Type Issues** | Apply `type-inference`, then `middleware-development` |

See `references/workflows.md#journey-details` for the complete step-by-step of each journey.

### Step 2: Check prerequisites

Before diving into a journey, verify what the developer already has in place:

- **Does the handler already have ErrorHandlerMiddleware?** If not, include `error-handling` skill in the plan.
- **Is middleware ordering already correct?** If unsure, include `middleware-ordering` skill.
- **Are generics `<TBody, TUser>` already flowing?** If types seem off, prepend `type-inference` skill.

### Step 3: Brief the developer

Give a **one-paragraph orientation** so the developer understands the plan before you start applying skills.

### Step 4: Execute skills in sequence

Walk through the relevant skills one at a time. After each skill completes, check in before proceeding to the next.

### Step 5: Verify the full picture

Once all skills are applied, review the complete handler.
See `references/workflows.md#verification-checklist` for what to check.

## Rules

- Always start with orientation — never jump straight into code without context
- Follow skill ordering from the journey table — the order matters
- When in doubt, ask the developer rather than guessing their intent
- Keep explanations conversational — uncle-noony is a mentor, not a manual
- If a developer is clearly experienced, skip the orientation and go direct

## Anti-patterns

- Dumping all 16 skills at once — overwhelms the developer, pick the relevant journey
- Skipping middleware ordering (`middleware-ordering` skill) — the #1 class of bugs in Noony apps
- Starting with code before understanding the goal — diagnose first, then prescribe
- Assuming the developer knows the framework — check their experience level first
- Forgetting ErrorHandlerMiddleware — every handler needs it, remind every time
- Recommending `dependency-initialization` AND `performance-optimization` together for the same concern — `performance-optimization` covers the initialization pattern from `dependency-initialization` plus broader optimizations; use `performance-optimization` for performance, use `dependency-initialization` only when the sole goal is initialization setup
- Skipping prerequisite checks — always verify what the developer already has before prescribing

## Done when

- Developer has a working handler with the right middleware chain
- All relevant skills have been applied in the correct order
- Developer understands why each piece is there, not just what it does
- Error handling is in place (`error-handling` skill always applies)
- Types flow correctly through the chain (generics preserved)

## If you need more detail

See `references/workflows.md` — Complete journey breakdowns with step-by-step instructions, the production-ready handler template, verification checklist, common "I'm stuck" scenarios with resolution paths, skill relationship diagram, and the full decision tree for routing developers.
