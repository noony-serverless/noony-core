# Noony Framework — Documentation Site Map

> **Organization**: [Diataxis](https://diataxis.fr/) — Tutorials, Guides, Reference, Explanation.

---

## Documentation Structure

### Tutorials (Learning-Oriented, Sequential)

Step-by-step lessons that take you from zero to a working application.

| # | Document | What You Learn |
|---|----------|----------------|
| 1 | [Getting Started](tutorials/01-getting-started.md) | Install, create your first handler, deploy to GCP |
| 2 | [Add Authentication](tutorials/02-add-authentication.md) | Protect endpoints with Firebase Auth and RouteGuards |
| 3 | [Local Dev with Fastify](tutorials/03-local-dev-with-fastify.md) | Run handlers locally with hot reload |
| 4 | [Testing Handlers](tutorials/04-testing-handlers.md) | Write unit and integration tests for handlers |

### Guides (Task-Oriented)

Practical how-to guides for specific tasks. Pick what you need.

| Guide | Purpose |
|-------|---------|
| [Error Handling](guides/error-handling.md) | Map errors to HTTP status codes using framework error classes |
| [Custom Middleware](guides/custom-middleware.md) | Build your own middleware with before/after/onError hooks |
| [Middleware Ordering](guides/middleware-ordering.md) | Control execution order and understand the middleware chain |
| [Dependency Injection](guides/dependency-injection.md) | Register and resolve services with ContainerPool |
| [Validation Schemas](guides/validation-schemas.md) | Validate request bodies and query params with Zod |
| [Type Inference](guides/type-inference.md) | Leverage generics for end-to-end type safety |
| [Performance Tuning](guides/performance-tuning.md) | Optimize cold starts, memory, and throughput |
| [Pub/Sub Workflows](guides/pubsub-workflows.md) | Handle Pub/Sub messages with tracing and validation |
| [Custom Adapters](guides/custom-adapters.md) | Write adapters for frameworks beyond GCP/Express/Fastify |
| [Troubleshooting](guides/troubleshooting.md) | Diagnose common issues and error patterns |

### Reference (Lookup-Oriented)

Precise, complete descriptions of the framework API.

| Reference | Covers |
|-----------|--------|
| [API](reference/api.md) | Handler, Context, GenericRequest, GenericResponse — full signatures |
| [Errors](reference/errors.md) | All error classes, status codes, and error mapping behavior |
| [Telemetry](reference/telemetry.md) | OpenTelemetry integration, spans, propagation, providers |
| [Middlewares](reference/middlewares/INDEX.md) | All 15 built-in middlewares — config, behavior, examples |
| [Auth](reference/auth/INDEX.md) | Authentication strategies, RouteGuards, token validation |

### Explanation (Understanding-Oriented)

Background knowledge and design rationale.

| Explanation | Topic |
|-------------|-------|
| [Architecture](explanation/architecture.md) | Handler lifecycle, middleware chain, adapter model |
| [Container Model](explanation/container-model.md) | Hybrid Proxy Container, zero-copy DI, global vs local scope |
| [Design Patterns](explanation/design-patterns.md) | Why these patterns were chosen and the tradeoffs involved |

### Other Sections

| Section | Purpose |
|---------|---------|
| [Skills](skills/) | Claude Code skill cards for AI-assisted development |
| [Meta](meta/) | Adopter templates (CLAUDE.md template, onboarding) |

---

## Reading Paths by Audience

### New Adopter

Get up and running with Noony from scratch.

1. [Getting Started](tutorials/01-getting-started.md) — Install and create your first handler
2. [Add Authentication](tutorials/02-add-authentication.md) — Secure your endpoints
3. [Local Dev with Fastify](tutorials/03-local-dev-with-fastify.md) — Develop locally
4. [Testing Handlers](tutorials/04-testing-handlers.md) — Write your first tests
5. [Error Handling](guides/error-handling.md) — Handle failures properly

### Feature Builder

You know the basics. Build features efficiently.

- Pick from [Guides](guides/) based on what you need
- Look up specifics in [Middlewares Reference](reference/middlewares/INDEX.md)
- Check [Type Inference](guides/type-inference.md) for end-to-end type safety
- Use [Validation Schemas](guides/validation-schemas.md) for input validation

### Production Readiness

Prepare your application for production traffic.

1. [Performance Tuning](guides/performance-tuning.md) — Optimize cold starts and memory
2. [Telemetry Reference](reference/telemetry.md) — Set up tracing and monitoring
3. [Troubleshooting](guides/troubleshooting.md) — Know what to do when things break
4. [Container Model](explanation/container-model.md) — Understand memory and DI behavior

### Framework Contributor

Understand the internals and extend the framework.

1. [Architecture](explanation/architecture.md) — How the handler lifecycle works
2. [Container Model](explanation/container-model.md) — Zero-copy DI deep dive
3. [Design Patterns](explanation/design-patterns.md) — Rationale behind key decisions
4. [API Reference](reference/api.md) — Complete type signatures and contracts
