---
name: noony-middleware-ordering
description: THE canonical reference for middleware chain order — all other pipeline skills defer to this. Use when composing middleware pipelines, debugging execution order, fixing "response already sent" errors, understanding before/after/onError flow direction, sharing data between middlewares via context.businessData, or positioning any middleware in the chain.
---

# skill:noony-middleware-ordering

## Does exactly this

Defines the canonical middleware execution order for every Noony handler. Explains how middlewares execute (before forward 0->N, after/onError reverse N->0), why canonical order matters, and how to use `context.businessData` for inter-middleware communication. This is the single source of truth for pipeline ordering — all other pipeline skills defer to this one.

## When to use

- Composing a middleware pipeline for a new handler
- Debugging why errors aren't being caught properly
- Fixing "response already sent" or double-send errors
- Understanding why `ErrorHandlerMiddleware` must be first
- Understanding why `ResponseWrapperMiddleware` must be last
- Sharing data between middlewares via `context.businessData`
- Adding a new middleware and deciding where to place it
- Any time another skill tells you to "check `noony-middleware-ordering` for ordering"

## Do not use this skill when

- You need to create a custom middleware -> `noony-middleware-development` handles implementation
- You need error class details -> `noony-error-handling` covers error types and cause chaining
- You need DI container setup -> `noony-dependency-injection`
- This skill is REFERENCE for ordering, not implementation — use the linked skills for how to build each middleware

## Steps

1. Understand execution flow: `before` runs forward (0->N), `after`/`onError` run reverse (N->0)
   -> See `references/ordering-detail.md#visual-timeline-complete-request-lifecycle` for lifecycle diagram
2. Place middlewares in canonical order — here is the full positioning with implementation references:
   - **Position 1**: ErrorHandlerMiddleware -> `noony-error-handling` for error classes and lifecycle
   - **Position 2**: OpenTelemetryMiddleware -> wraps full request including auth
   - **Position 3-5**: Header/structural checks (cheap, fast-fail)
   - **Position 6**: BodyParserMiddleware -> `noony-validation-schemas` for Zod integration
   - **Position 7**: BodyValidationMiddleware -> `noony-validation-schemas` for schema patterns
   - **Position 8**: PathParametersMiddleware -> `noony-path-parameters` for extraction and typing
   - **Position 9-12**: Auth middlewares (Firebase, OAuth2, guards) -> `noony-guard-system` for guard system
   - **Position 13+**: DI setup, business logic middlewares -> `noony-middleware-development` for custom middleware
   - **Last**: ResponseWrapperMiddleware -> must be last, its `after` runs first in reverse
   -> See `references/ordering-detail.md#canonical-middleware-order-table` for full table with reasoning
3. Order principle: cheap structural checks early, expensive semantic operations late
4. Communicate between middlewares via `context.businessData` Map — never modify Context interface
   -> See `references/ordering-detail.md#via-contextbusinessdata-inter-middleware-state` for patterns
5. When sending responses, choose ONE method: return value (for wrapping) OR `context.res.json()` — never both
   -> See `references/ordering-detail.md#response-sending-decision-tree` for decision logic

## Rules

- `ErrorHandlerMiddleware` MUST be first (position 1) — its `onError` runs last in reverse, giving final authority
- `ResponseWrapperMiddleware` MUST be last — its `after` runs first in reverse, wrapping before others see it
- `OpenTelemetryMiddleware` at position 2 to wrap full request lifecycle including auth
- `BodyParserMiddleware` MUST come before `BodyValidationMiddleware` (positions 6-7) — `noony-validation-schemas` depends on this
- Path params at position 8, before auth guards that may need route params for ownership checks (`noony-path-parameters`, `noony-guard-system`)
- Never call `context.res.json()` AND return a value in the same handler — causes double-send
- Always check `context.res.headersSent` before sending in custom `after()` hooks
- Use `context.businessData` Map for inter-middleware state — do NOT extend Context interface
- Reserved key: `'otel_span'` — used by `OpenTelemetryMiddleware`, never overwrite

## Anti-patterns

- Ignoring this skill when setting up ANY handler — ordering errors are the #1 bug source in Noony pipelines
- `ErrorHandlerMiddleware` not first — errors from earlier middlewares go uncaught
- `ResponseWrapperMiddleware` not last — `after()` runs in wrong order, response wrapping fails
- `OpenTelemetryMiddleware` after auth — JWT verification time not traced
- `BodyValidationMiddleware` before `BodyParserMiddleware` — `parsedBody` is undefined, validation has nothing to work with
- Both `context.res.json()` AND return value — double-send error
- Sending response in multiple `after()` hooks — violates single-response contract
- Overwriting `context.businessData` key `'otel_span'` — breaks OpenTelemetry integration
- Expensive middleware (DB auth) before cheap validation (header check) — wastes resources on bad requests

## Done when

- Canonical ordering applied: ErrorHandler first, ResponseWrapper last
- You understand before->after reversed execution direction
- Each middleware is positioned per the canonical table above
- `RESPONSE_SENT` errors identified and prevented
- `context.businessData` used for inter-middleware communication

## If you need more detail

-> `references/ordering-detail.md` — Visual timeline, canonical table with reasoning, common mistake examples with code, RESPONSE_SENT explanation, response sending decision tree, inter-middleware communication patterns
