# CLAUDE.md Template for Noony Framework Projects

Copy and paste this into your `CLAUDE.md` file if your project uses `@noony-serverless/core`.

## Anti-Patterns

> ❌ Avoid these common mistakes:

- **Don't modify the five non-negotiable rules section — they are framework invariants that ensure type safety and correct middleware behavior.**
- **Don't omit type generics from handler definitions — always specify `Handler<TBody, TUser>` explicitly.**
- **Don't bypass the middleware chain for custom logic — all request processing must go through `.use()` middleware hooks.**

---

# CLAUDE.md - Noony Serverless Framework Project

This project uses **@noony-serverless/core**, a TypeScript serverless middleware framework optimized for Google Cloud Functions, Fastify, and Express.

## The 5 Non-Negotiable Rules

When working with Noony handlers and middlewares, these rules are NOT style preferences — they are correctness requirements.

### 1. Type Chain: Every Middleware MUST Use Generics

Every middleware class must explicitly implement `BaseMiddleware<TBody, TUser>` with both generics.

```typescript
// ✅ CORRECT
export class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {}
  async after(context: Context<TBody, TUser>): Promise<void> {}
}

// ❌ WRONG - Breaks type chain
export class MyMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {}
}
```

**Never use `as any` to escape type errors.** Instead, add the generics or use `createTypedHandler()`.

**Reference**: See `docs/skills/08-middleware-development.md` in @noony-serverless/core.

### 2. Middleware Order: ErrorHandler First, ResponseWrapper Last

Execution order is NOT intuitive — `before` runs forward (0→N), `after`/`onError` run in reverse (N→0).

| Position | Middleware | Reason |
| --- | --- | --- |
| 1 | ErrorHandlerMiddleware | onError runs last (final say on response) |
| 2 | OpenTelemetryMiddleware | Wraps full request lifecycle |
| 3 | AuthenticationMiddleware | Validates JWT before business logic |
| 4 | BodyParserMiddleware | Parses before validation |
| 5 | BodyValidationMiddleware | Validates before business logic |
| Last | ResponseWrapperMiddleware | after runs first (wraps return value) |

**Never put ErrorHandlerMiddleware anywhere but first. Never put ResponseWrapperMiddleware in the middle.**

**Reference**: See `docs/skills/17-middleware-ordering.md` in @noony-serverless/core.

### 3. Response Modes: Return Value OR context.res.json(), Never Both

Choose ONE way to return data:

```typescript
// ✅ CORRECT - Return value, wrapped by ResponseWrapperMiddleware
.handle(async (context) => {
  return { data: user };  // Wrapped: { success: true, payload: { data: user }, timestamp: "..." }
})

// ✅ CORRECT - Call context.res directly, no wrapping
.handle(async (context) => {
  context.res.status(201).json({ data: user });  // Not wrapped
})

// ❌ WRONG - Both together
.handle(async (context) => {
  context.res.json({ data: user });
  return { extra: 'data' };  // ❌ Double send or lost data
})
```

**Reference**: See `docs/skills/18-response-wrapper.md` in @noony-serverless/core.

### 4. Body Access: Use validatedBody or parsedBody, Never body

Always access validated or parsed data, never raw body:

```typescript
// ✅ CORRECT - After BodyValidationMiddleware
const data = context.req.validatedBody!;  // Type: YourBodyType | undefined

// ✅ CORRECT - After BodyParserMiddleware (for unvalidated parsing)
const data = context.req.parsedBody;      // Type: unknown | undefined

// ❌ WRONG - Raw body access
const data = context.req.body;            // Untyped, unvalidated
```

**Why**: Middleware chains ensure data is parsed and validated. Skipping them invites bugs.

**Reference**: See `docs/skills/09-validation-schemas.md` in @noony-serverless/core.

### 5. Error Throwing: Throw Typed Errors, Not `context.res.status()`

Inside a handler with `ErrorHandlerMiddleware`, throw typed errors. Never call `context.res.status()` for errors.

```typescript
import { NotFoundError, ForbiddenError, ValidationError } from '@noony-serverless/core';

// ✅ CORRECT - Throw typed error, middleware formats it
.handle(async (context) => {
  const user = await userService.getUser(id);
  if (!user) throw new NotFoundError('User not found');
  if (!user.active) throw new ForbiddenError('User account disabled');
  return user;
})

// ❌ WRONG - Call context.res directly for errors
.handle(async (context) => {
  const user = await userService.getUser(id);
  if (!user) {
    context.res.status(404).json({ error: 'Not found' });  // ❌
    return;
  }
})
```

**Why**: ErrorHandlerMiddleware formats all errors consistently, logs them, and handles edge cases like double-sends.

**Reference**: See `docs/skills/10-error-handling.md` in @noony-serverless/core.

---

## Middleware Quick Reference

| Need | Middleware | Position |
| --- | --- | --- |
| Catch and format errors | `ErrorHandlerMiddleware` | 1 (first) |
| Distributed tracing | `OpenTelemetryMiddleware` | 2 |
| JWT verification | `AuthenticationMiddleware` | 3 |
| JSON/Pub/Sub parsing | `BodyParserMiddleware` | 4 |
| Zod schema validation | `BodyValidationMiddleware` | 5 |
| RBAC checks | `RouteGuards.requirePermissions()` | After auth |
| Standard response format | `ResponseWrapperMiddleware` | Last |

---

## Dependency Injection

### Global Scope: Process Startup

Initialize expensive services once at process startup:

```typescript
// At server startup, ONCE
await containerPool.initializeGlobal([
  { id: 'Database', value: await db.connect() },
  { id: 'Logger', value: logger }
]);

// Inside handlers, access them (they're reused forever)
const db = getService(context, Database);
```

### Local Scope: Request Lifetime

Inject request-specific data via middleware:

```typescript
.use(new DependencyInjectionMiddleware([
  { id: 'RequestId', value: generateId() },
  { id: 'CurrentUser', value: extractUserFromContext(context) }
], { scope: 'local' }))  // 'local' is default
```

**Never call `containerPool.initializeGlobal()` inside a handler** — that defeats the point and causes per-request latency.

**Reference**: See `docs/skills/11-dependency-injection.md` in @noony-serverless/core.

---

## Local Development Commands

```bash
# Start local Fastify server (same handler code as production)
npm run dev

# Run tests
npm run test

# Run tests with coverage
npm run test:coverage

# Build TypeScript
npm run build

# Watch mode (compile on file change)
npm run watch

# Lint and format
npm run lint
npm run format
```

---

## Common Gotchas

### Gotcha 1: Never Install `@fastify/otel`

This package conflicts with Noony's HTTP instrumentation and causes 9+ second latency. Always use `OpenTelemetryMiddleware` instead.

### Gotcha 2: Always Set Generics on Middleware

The type chain breaks silently if you forget generics. TypeScript won't always catch it.

### Gotcha 3: ErrorHandlerMiddleware Must Be First

If it's second, it won't catch errors from first-position middleware's `before` hook.

### Gotcha 4: Never Mix execute() and executeGeneric()

- `handler.execute(req, res)` — GCP Cloud Functions and Express only
- `handler.executeGeneric(genericReq, genericRes)` — Fastify with adapters only

### Gotcha 5: context.responseData vs context.res.json()

Use return value + ResponseWrapperMiddleware, OR call context.res directly, but not both.

---

## When to Ask for Help

- **Type errors on middleware**: Check that you have `implements BaseMiddleware<TBody, TUser>`
- **Middleware not running**: Verify order matches canonical list (ErrorHandler 1st, ResponseWrapper last)
- **Headers already sent error**: Check for double `context.res.json()` calls or mixed return+res.json()
- **Validation not triggering**: Ensure `BodyValidationMiddleware` comes after `BodyParserMiddleware`
- **Service not resolved**: Check that `containerPool.initializeGlobal()` ran before handler executed
- **Response format unexpected**: Verify `ResponseWrapperMiddleware` is used and is last

---

## Key Documentation Files

- **Architecture**: `node_modules/@noony-serverless/core/docs/ARCHITECTURE.md`
- **API Reference**: `node_modules/@noony-serverless/core/docs/CORE_APIS.md`
- **Middleware Patterns**: `node_modules/@noony-serverless/core/docs/MIDDLEWARE_PATTERNS.md`
- **Examples**: `node_modules/@noony-serverless/core/docs/EXAMPLES.md`
- **Skill Cards** (1-21): `node_modules/@noony-serverless/core/docs/skills/`

---

## Local Project Structure

```
src/
├── handlers/          # Handler definitions
├── controllers/       # Business logic
├── services/          # Service classes
├── middlewares/       # Custom middlewares (if any)
└── utils/            # Utilities

tests/
├── handlers.test.ts
├── services.test.ts
└── integration.test.ts
```

---

## Git Workflow

1. Create feature branch from `main`
2. Make changes (handlers, services, tests)
3. Run `npm run test:coverage` — ensure coverage maintained
4. Run `npm run lint:fix && npm run format` — auto-fix issues
5. Commit with clear message: "feat: add user authentication"
6. Create PR with description of changes
7. Merge to `main` after review

---

## Deployment (GCP Cloud Functions)

```bash
# Build
npm run build

# Deploy to Cloud Functions
gcloud functions deploy myFunction \
  --runtime nodejs20 \
  --trigger-http \
  --entry-point myFunction
```

---

**Last Updated**: [DATE]
**Framework Version**: @noony-serverless/core ^0.8.0
