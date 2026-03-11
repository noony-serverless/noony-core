# Skill 17: Middleware Execution Order & Pipeline

## Does exactly this

Explains how middlewares execute (before/after/onError flow), why canonical order matters (ErrorHandler first, ResponseWrapper last), and how to use context.responseData and context.businessData for inter-middleware communication.

## When to use

- "What order do middlewares run"
- "Why isn't my error handler catching errors"
- "Response already sent error"
- "How do I share data between middlewares"

## Steps

1. Understand execution flow: `before` runs forward (0→N), `after`/`onError` run in reverse (N→0)
   → See resources/17-ordering-detail.md#visual-timeline for full lifecycle diagram
2. Use canonical order: ErrorHandlerMiddleware first, ResponseWrapperMiddleware last
   → See resources/17-ordering-detail.md#canonical-middleware-order-table for positioning
3. Communicate between middlewares via `context.businessData` Map, not by modifying Context
   → See resources/17-ordering-detail.md#via-contextbusinessdata-inter-middleware-state for patterns
4. Debug with `context.res.headersSent` check before sending responses
   → See resources/17-ordering-detail.md#response-sending-decision-tree for decision logic

## Rules

- `ErrorHandlerMiddleware` MUST be first (position 1) — its onError runs last, giving final authority
- `ResponseWrapperMiddleware` MUST be last — its after runs first, wrapping return value before others
- Never call `context.res.json()` AND return value together — choose one or the other
- Always check `context.res.headersSent` before sending in custom after() hooks
- Use `context.businessData` Map for inter-middleware state — never extend Context interface
- `OpenTelemetryMiddleware` should be position 2 to wrap full request lifecycle including auth

## Anti-patterns

- ❌ ErrorHandlerMiddleware not first — errors from earlier middlewares not caught properly
- ❌ ResponseWrapperMiddleware not last — after() runs in wrong order, breaks wrapping
- ❌ Both `context.res.json()` AND return value in same handler — causes double-send errors
- ❌ Sending response in multiple middlewares' after() hooks — violates single-response contract
- ❌ Using `context.businessData` with reserved keys like 'otel_span' — breaks OpenTelemetry integration

## Done when

- You know which middleware goes in which position
- You understand why before→after order is reversed
- You can identify RESPONSE_SENT errors and prevent them
- You use context.businessData for passing data between middlewares

## If you need more detail

→ resources/17-ordering-detail.md — Visual timeline, canonical table with reasoning, complete mistake examples with code, RESPONSE_SENT explanation, response sending decision tree, inter-middleware communication patterns
