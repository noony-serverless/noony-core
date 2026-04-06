---
description: Noony canonical middleware chain order. Apply whenever composing, debugging, or modifying a Noony handler's middleware pipeline.
globs:
  - "src/**/*.ts"
  - "functions.ts"
  - "server.ts"
alwaysApply: false
---

# Noony — Middleware Ordering Rules

Every Noony handler MUST follow this exact middleware chain order.

## Canonical Chain

| Position | Middleware | Constraint |
|----------|-----------|-----------|
| 1 | `ErrorHandlerMiddleware` | **MUST be first** — `onError` runs last in reverse, final authority on errors |
| 2 | `OpenTelemetryMiddleware` | Must wrap full request including auth time |
| 3–5 | Header/structural checks | Cheap fast-fail checks (e.g. `ContentTypeMiddleware`) |
| 6 | `BodyParserMiddleware` | **MUST come before** `BodyValidationMiddleware` |
| 7 | `BodyValidationMiddleware` | Requires parsed body from position 6 |
| 8 | `PathParametersMiddleware` | Before auth guards — guards may need path params for ownership checks |
| 9–12 | Auth middlewares | `FirebaseAuthMiddleware`, `OAuth2Middleware`, `RouteGuardMiddleware` |
| 13+ | DI / business logic | `DependencyInjectionMiddleware`, custom middlewares |
| Last | `ResponseWrapperMiddleware` | **MUST be last** — `after` runs first in reverse, wraps before others |

## Execution Direction

- `before` runs forward 0→N
- `after` runs reverse N→0
- `onError` runs reverse N→0

## Rules

- `ErrorHandlerMiddleware` NOT at position 1 → errors from structural checks go uncaught
- `ResponseWrapperMiddleware` NOT last → response wrapping applies in wrong order
- `BodyValidationMiddleware` before `BodyParserMiddleware` → parsedBody is undefined
- Auth guard before `PathParametersMiddleware` → guard cannot read route params
- Never call `context.res.json()` AND return a value — causes double-send error
- Use `context.businessData` Map for inter-middleware state — do NOT modify the Context interface
- Reserved key `'otel_span'` belongs to `OpenTelemetryMiddleware` — never overwrite

## Reference

→ `docs/noony-skills/middleware-ordering/SKILL.md`
