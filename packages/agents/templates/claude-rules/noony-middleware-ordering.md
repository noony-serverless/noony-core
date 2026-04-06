---
description: Noony canonical middleware chain order — apply when composing or debugging a Noony handler pipeline.
globs: ["src/**/*.ts", "functions.ts", "server.ts"]
---

# Noony — Middleware Ordering Rules

Every Noony handler MUST follow this exact order:

| Position | Middleware | Rule |
|----------|-----------|------|
| 1 | `ErrorHandlerMiddleware` | MUST be first — catches all downstream errors |
| 2 | `OpenTelemetryMiddleware` | Wraps full request including auth |
| 3–5 | Header/structural checks | Cheap fast-fail |
| 6 | `BodyParserMiddleware` | MUST precede BodyValidationMiddleware |
| 7 | `BodyValidationMiddleware` | Needs parsed body from position 6 |
| 8 | `PathParametersMiddleware` | Before auth guards |
| 9–12 | Auth middlewares | FirebaseAuth, OAuth2, RouteGuard |
| 13+ | DI / business logic | DependencyInjectionMiddleware, custom |
| Last | `ResponseWrapperMiddleware` | MUST be last |

Execution: `before` → 0→N, `after`/`onError` → N→0.

Inter-middleware state: use `context.businessData` Map — never modify Context interface.
Reserved key: `'otel_span'` — do not overwrite.
Response: choose ONE method — return value OR `context.res.json()`, never both.
