# Bug Fix: Body Validation Middleware Inconsistency

## Issue Summary

The `bodyValidatorMiddleware` factory function was reading from `context.req.body` instead of `context.req.parsedBody`, causing body validation to fail when used with Fastify integration.

## Root Cause

**Inconsistent behavior between two validation middleware implementations:**

1. **BodyValidationMiddleware (class)** ✅ - Correctly reads from `context.req.parsedBody`
2. **bodyValidatorMiddleware (factory)** ❌ - Incorrectly reads from `context.req.body`

## The Problem Flow

### With Fastify Integration:

```typescript
// 1. Fastify pre-parses the body
fastify.post('/api/users', handler);
// req.body = { name: "John", email: "john@example.com" }

// 2. Fastify adapter sets parsedBody
const genericReq = adaptFastifyRequest(req);
// genericReq.body = { name: "John", ... }
// genericReq.parsedBody = { name: "John", ... }  ← Set from req.body

// 3. bodyValidatorMiddleware reads from WRONG property
await validateBody(schema, context.req.body);  // ❌ May be undefined
// Should read from: context.req.parsedBody     // ✅ Always set by adapter
```

### Why It Failed:

- Fastify adapter sets **both** `body` and `parsedBody` to the same value
- In some cases, `context.req.body` becomes `undefined` between middleware executions
- The factory function was reading from `body` (undefined) instead of `parsedBody` (defined)

## The Fix

### Changed File: `src/middlewares/bodyValidationMiddleware.ts`

**Before:**
```typescript
export const bodyValidatorMiddleware = <T, U = unknown>(
  schema: z.ZodType<T>
): { before: (context: Context<T, U>) => Promise<void> } => ({
  before: async (context: Context<T, U>): Promise<void> => {
    context.req.parsedBody = await validateBody(schema, context.req.body); // ❌
  },
});
```

**After:**
```typescript
export const bodyValidatorMiddleware = <T, U = unknown>(
  schema: z.ZodType<T>
): { before: (context: Context<T, U>) => Promise<void> } => ({
  before: async (context: Context<T, U>): Promise<void> => {
    context.req.parsedBody = await validateBody(schema, context.req.parsedBody); // ✅
  },
});
```

### Changed File: `src/middlewares/bodyValidationMiddleware.test.ts`

Updated tests to reflect the corrected behavior:

**Before:**
```typescript
beforeEach(() => {
  context = {
    req: {
      body: {},  // ❌ Was testing with body
    },
    res: {},
  } as Context<any>;
});

it('validates and sets validatedBody on context for valid input', async () => {
  const schema = z.object({ name: z.string() });
  const middleware = bodyValidatorMiddleware<{ name: string }>(schema);
  context.req.body = { name: 'John Doe' };  // ❌

  await middleware.before(context);

  expect(context.req.body).toEqual({ name: 'John Doe' });     // ❌
  expect(context.req.parsedBody).toEqual({ name: 'John Doe' }); // ✅
});
```

**After:**
```typescript
beforeEach(() => {
  context = {
    req: {
      parsedBody: {},  // ✅ Now testing with parsedBody
    },
    res: {},
  } as Context<any>;
});

it('validates and sets parsedBody on context for valid input', async () => {
  const schema = z.object({ name: z.string() });
  const middleware = bodyValidatorMiddleware<{ name: string }>(schema);
  context.req.parsedBody = { name: 'John Doe' };  // ✅

  await middleware.before(context);

  expect(context.req.parsedBody).toEqual({ name: 'John Doe' }); // ✅
});
```

## Impact

### ✅ What Works Now:

1. **Fastify Integration**: Body validation now works correctly with Fastify
2. **Consistent Behavior**: Both class and factory function read from the same property
3. **Framework Agnostic**: Works with all framework adapters (Fastify, Express, GCP Functions)

### 📦 Affected Components:

- `BodyValidationMiddleware` class - **No change needed** (already correct)
- `bodyValidatorMiddleware` factory - **Fixed** to read from `parsedBody`
- Tests - **Updated** to match corrected behavior

## Additional Fixes

### Performance Test Stabilization

Fixed flaky performance test in `PlainPermissionResolver.test.ts`:

**Issue**: Single-iteration timing measurements had extreme variance for sub-millisecond operations.

**Solution**: Run 100 iterations and measure total time for stable benchmarks.

**Before:**
```typescript
const startSmall = process.hrtime();
await resolver.check(smallUser, smallRequired);  // Single execution
const [secondsSmall, nanosecondsSmall] = process.hrtime(startSmall);
const timeSmall = secondsSmall * 1000 + nanosecondsSmall / 1000000;
```

**After:**
```typescript
const iterations = 100;
const startSmall = process.hrtime.bigint();
for (let i = 0; i < iterations; i++) {
  await resolver.check(smallUser, smallRequired);  // 100 executions
}
const endSmall = process.hrtime.bigint();
const timeSmall = Number(endSmall - startSmall) / 1000000;
```

### Debug Logging Cleanup

Removed temporary debug console.log statements from:
- `src/middlewares/bodyParserMiddleware.ts`
- `src/middlewares/bodyValidationMiddleware.ts`

## Verification

### Test Results:

```bash
$ npm test

Test Suites: 34 passed, 34 total
Tests:       546 passed, 546 total
Snapshots:   0 total
Time:        7.619 s
✅ All tests passing!
```

### Build Results:

```bash
$ npm run build
✓ TypeScript compilation successful
✓ package.json copied to build/
```

## Recommendation

**Use `BodyValidationMiddleware` class** (not the factory function) for all new code:

```typescript
// ✅ Recommended (used in all examples)
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    const user = context.req.validatedBody!; // Fully typed
  });

// ⚠️ Works but class is preferred
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(bodyValidatorMiddleware(createUserSchema))
  .handle(async (context) => {
    const user = context.req.parsedBody as CreateUserRequest;
  });
```

## Related Files

- [src/middlewares/bodyValidationMiddleware.ts](src/middlewares/bodyValidationMiddleware.ts)
- [src/middlewares/bodyValidationMiddleware.test.ts](src/middlewares/bodyValidationMiddleware.test.ts)
- [src/utils/fastify-wrapper.ts](src/utils/fastify-wrapper.ts#L23)
- [src/middlewares/bodyParserMiddleware.ts](src/middlewares/bodyParserMiddleware.ts#L271)

## Version

This fix will be included in the next release of `@noony-serverless/core`.
