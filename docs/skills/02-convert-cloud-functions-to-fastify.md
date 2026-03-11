# Skill 02: Convert Cloud Functions Handler to Fastify

## Does exactly this

Shows how to run same handler in both Cloud Functions and Fastify with zero code duplication. Handler is written once, deployed to both environments via different entry points.

## When to use

- "Test handler locally before deploying"
- "Speed up development iteration"
- "Support both Fastify and Cloud Functions"
- "No code changes between environments"

## Steps

1. Define handler once with all middlewares (same for both environments)
2. For Fastify: wrap with `createFastifyHandler()` and register route
   → See resources/02-cloud-to-fastify.md#fastify-entry-point for code
3. For Cloud Functions: call `handler.execute()` after init
   → See resources/02-cloud-to-fastify.md#cloud-functions-entry-point for code
4. Test locally with Fastify (2-3x faster iteration)
5. Deploy to Cloud Functions with confidence — exact same code

## Rules

- Same handler instance for both entry points — never duplicate
- Same middleware chain in both environments — testing breaks if different
- `handler.execute()` for Cloud Functions only
- `createFastifyHandler()` wrapper for Fastify only
- Initialize once via `initializeDependencies()` in both paths
- No environment-specific logic in handlers

## Anti-patterns

- ❌ Different middleware chains for Fastify vs Cloud Functions — production differs from local
- ❌ Duplicating handler code between entry points — bugs in one won't catch in other
- ❌ Using different validation schemas — behavior changes between environments
- ❌ Calling `handler.executeGeneric()` with Cloud Functions req/res — wrong API
- ❌ Importing server startup code into Cloud Functions — framework mismatch

## Done when

- You can run same handler in Fastify and Cloud Functions
- You understand handler.execute() vs createFastifyHandler()
- You can test locally and deploy with confidence
- You know there's zero code changes between environments

## If you need more detail

→ resources/02-cloud-to-fastify.md — Architecture diagram, handler definition, both entry points, shared initialization, project structure, migration checklist, local testing, performance comparison, environment config, dual-entry examples, gotchas
