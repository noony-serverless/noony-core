# Changelog v0.7.0 - Type Safety Enhancement

## 🎯 Overview

Version 0.7.0 introduces **invariant generics** to the Handler class, eliminating the need for `as any` type casts when passing controllers to `.handle()`. This is a **breaking change** that significantly improves type safety and developer experience.

## 🚨 Breaking Changes

### 1. Handler.use() - Invariant Type Parameters

**Before v0.7.0** (Covariant - types could change):
```typescript
use<NewT = T, NewU = U>(
  middleware: BaseMiddleware<NewT, NewU>
): Handler<NewT, NewU>
```

**After v0.7.0** (Invariant - types remain constant):
```typescript
use(middleware: BaseMiddleware<T, U>): Handler<T, U>
```

**Impact**: Middleware must now match the Handler's declared types. This prevents type drift through the middleware chain.

### 2. Explicit Types Required (for type safety)

To eliminate `as any`, you must now declare Handler types explicitly or use the new `createTypedHandler()` helper.

## ✨ New Features

### createTypedHandler() - Type Inference Helper

A new **permanent** helper function that automatically infers types from your controller signature:

```typescript
export function createTypedHandler<T, U>(
  controller: (context: Context<T, U>) => Promise<void | unknown>
): Handler<T, U>
```

This is **NOT a temporary workaround** - it's a first-class feature for improved DX, similar to patterns in tRPC and Fastify.

## 📚 Migration Guide

### Pattern 1: From `as any` to Explicit Types

**❌ Before v0.7.0 - Required `as any`**:
```typescript
interface LoginRequest {
  email: string;
  password: string;
}

interface AuthUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

async function loginController(context: Context<LoginRequest, AuthUser>) {
  const { email, password } = context.req.validatedBody!;
  const user = await authService.login(email, password);
  return { token: user.token, user };
}

// ❌ Had to use 'as any' due to type drift
const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController as any);  // 😢 Type safety lost
```

**✅ After v0.7.0 - Option 1: Explicit Types**:
```typescript
// ✅ Declare both types upfront
const loginHandler = new Handler<LoginRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<LoginRequest, AuthUser>())
  .use(new BodyValidationMiddleware<LoginRequest, AuthUser>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware<LoginRequest, AuthUser>())
  .handle(loginController);  // ✅ Types match perfectly!
```

**✅ After v0.7.0 - Option 2: Type Inference with Helper**:
```typescript
// ✅ Types inferred from controller signature
const loginHandler = createTypedHandler(loginController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);  // ✅ Types match perfectly!
```

### Pattern 2: Handlers Without User Context

**❌ Before v0.7.0**:
```typescript
const getConfigHandler = new Handler()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('config:read'))
  .use(new ResponseWrapperMiddleware())
  .handle(getConfigController as any);
```

**✅ After v0.7.0 - Option 1: Explicit Types**:
```typescript
interface ConfigResponse {
  apiVersion: string;
  features: string[];
}

const getConfigHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware<void, AuthUser>())
  .use(new AuthenticationMiddleware<void, AuthUser>(tokenVerifier))
  .use(new ResponseWrapperMiddleware<void, AuthUser>())
  .handle(getConfigController);
```

**✅ After v0.7.0 - Option 2: Type Inference**:
```typescript
async function getConfigController(context: Context<void, AuthUser>) {
  const config = await configService.getConfig();
  return config;
}

const getConfigHandler = createTypedHandler(getConfigController)
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new ResponseWrapperMiddleware())
  .handle(getConfigController);
```

### Pattern 3: Backward Compatibility - Untyped Handlers

**✅ Still Works in v0.7.0**:
```typescript
// Generic handlers without specific types still work
const genericHandler = new Handler()  // Handler<unknown, unknown>
  .use(new ErrorHandlerMiddleware())
  .handle(async (context: Context) => {
    // Manual typing inside handler
    const body = context.req.parsedBody as SomeType;
    return { success: true };
  });
```

### Pattern 4: Middleware Generic Parameters

**❌ Before v0.7.0**:
```typescript
// Middleware didn't need type parameters
.use(new BodyValidationMiddleware(schema))
```

**✅ After v0.7.0 - With Explicit Types**:
```typescript
// Middleware needs explicit type parameters to match Handler
.use(new BodyValidationMiddleware<LoginRequest, AuthUser>(schema))
```

**✅ After v0.7.0 - With createTypedHandler**:
```typescript
// Type parameters inferred automatically
createTypedHandler(controller)
  .use(new BodyValidationMiddleware(schema))  // Types inferred
```

## 🔧 Step-by-Step Migration

### Step 1: Identify All Handlers Using `as any`

```bash
# Search for 'as any' in handler files
grep -r "\.handle.*as any" src/
```

### Step 2: Choose Your Pattern

For each handler, decide:
- **Option A**: Use explicit types if you want clear, upfront type declarations
- **Option B**: Use `createTypedHandler()` if your controller already has explicit Context types

### Step 3: Update Imports

```typescript
// Add createTypedHandler to imports if using Option B
import { Handler, createTypedHandler, Context } from '@noony-serverless/core';
```

### Step 4: Update Handler Declarations

**Option A - Explicit Types**:
```typescript
// 1. Add both TBody and TUser to Handler
const handler = new Handler<RequestType, UserType>()

// 2. Add types to all middleware
  .use(new SomeMiddleware<RequestType, UserType>())

// 3. Remove 'as any' from .handle()
  .handle(controller);
```

**Option B - Type Inference**:
```typescript
// 1. Ensure controller has explicit Context<TBody, TUser> signature
async function controller(context: Context<RequestType, UserType>) {
  // ...
}

// 2. Use createTypedHandler
const handler = createTypedHandler(controller)

// 3. Middleware doesn't need type parameters
  .use(new SomeMiddleware())

// 4. Remove 'as any' from .handle()
  .handle(controller);
```

### Step 5: Verify Type Safety

```bash
# Run TypeScript compiler to verify no errors
npm run build

# Run tests
npm test
```

## 📊 Migration Examples by Use Case

### Use Case 1: Public API Endpoint (No Auth)

**Before**:
```typescript
const createPublicResourceHandler = new Handler()
  .use(errorHandler())
  .use(bodyValidator(schema))
  .handle(createPublicResourceController as any);
```

**After (Explicit)**:
```typescript
interface CreateResourceRequest {
  name: string;
  description: string;
}

const createPublicResourceHandler = new Handler<CreateResourceRequest, void>()
  .use(new ErrorHandlerMiddleware<CreateResourceRequest, void>())
  .use(new BodyValidationMiddleware<CreateResourceRequest, void>(schema))
  .handle(createPublicResourceController);
```

**After (Inference)**:
```typescript
async function createPublicResourceController(
  context: Context<CreateResourceRequest, void>
) {
  const resource = await resourceService.create(context.req.validatedBody!);
  return { id: resource.id };
}

const createPublicResourceHandler = createTypedHandler(createPublicResourceController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(createPublicResourceController);
```

### Use Case 2: Authenticated API Endpoint

**Before**:
```typescript
const createOrderHandler = new Handler()
  .use(errorHandler())
  .use(authMiddleware())
  .use(bodyValidator(orderSchema))
  .handle(createOrderController as any);
```

**After (Explicit)**:
```typescript
interface CreateOrderRequest {
  productId: string;
  quantity: number;
}

interface AuthUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
}

const createOrderHandler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthUser>())
  .use(new AuthenticationMiddleware<CreateOrderRequest, AuthUser>(tokenVerifier))
  .use(new BodyValidationMiddleware<CreateOrderRequest, AuthUser>(orderSchema))
  .handle(createOrderController);
```

**After (Inference)**:
```typescript
async function createOrderController(
  context: Context<CreateOrderRequest, AuthUser>
) {
  const user = context.user!;
  const order = await orderService.create(user.id, context.req.validatedBody!);
  return { orderId: order.id };
}

const createOrderHandler = createTypedHandler(createOrderController)
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(orderSchema))
  .handle(createOrderController);
```

### Use Case 3: Pub/Sub Event Handler

**Before**:
```typescript
const processOrderEventHandler = new Handler()
  .use(errorHandler())
  .use(bodyParser())
  .handle(processOrderEventController as any);
```

**After (Explicit)**:
```typescript
interface OrderEventPayload {
  orderId: string;
  action: 'created' | 'updated' | 'cancelled';
}

const processOrderEventHandler = new Handler<OrderEventPayload, void>()
  .use(new ErrorHandlerMiddleware<OrderEventPayload, void>())
  .use(new BodyParserMiddleware<OrderEventPayload, void>())
  .handle(processOrderEventController);
```

## 🎓 Best Practices

### 1. When to Use Explicit Types vs. createTypedHandler()

**Use Explicit Types When**:
- You want clear, upfront type declarations at the handler level
- Your team prefers seeing all types in one place
- You're defining new handlers without controllers yet
- Documentation and readability are priorities

**Use createTypedHandler() When**:
- Your controller already has explicit Context types
- You want to avoid repeating type parameters
- You prefer type inference over explicit declarations
- You're migrating existing code with minimal changes

### 2. Define User Types Consistently

```typescript
// Create a base user type for your application
export interface AppUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user' | 'guest';
  permissions: string[];
}

// Use consistently across handlers
const handler1 = new Handler<Request1, AppUser>()...
const handler2 = new Handler<Request2, AppUser>()...
```

### 3. Use `void` for Handlers Without Body or User

```typescript
// No request body, but has authenticated user
const handler = new Handler<void, AuthUser>()

// Has request body, no authenticated user
const handler = new Handler<CreateRequest, void>()

// Neither request body nor authenticated user
const handler = new Handler<void, void>()
```

### 4. Type Guard for User Access

```typescript
function requireUser(context: Context<unknown, AuthUser>): AuthUser {
  if (!context.user) {
    throw new AuthenticationError('User not authenticated');
  }
  return context.user;
}

// Usage in controller
async function controller(context: Context<RequestType, AuthUser>) {
  const user = requireUser(context);  // Type-safe!
  // ...
}
```

## 🐛 Troubleshooting

### Error: Type 'SomeMiddleware' is not assignable to type 'BaseMiddleware<T, U>'

**Cause**: Middleware doesn't have proper generic parameters.

**Solution**: Update middleware to implement `BaseMiddleware<T, U>`:
```typescript
// ❌ Before
export class SomeMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> { }
}

// ✅ After
export class SomeMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>): Promise<void> { }
}
```

### Error: Types don't match at .handle() even with explicit types

**Cause**: Controller signature doesn't match Handler types.

**Solution**: Ensure controller has matching Context types:
```typescript
// Handler declaration
const handler = new Handler<LoginRequest, AuthUser>()

// Controller must match
async function controller(context: Context<LoginRequest, AuthUser>) {
  //                                   ^^^^^^^^^^^^  ^^^^^^^^
  //                                   Must match Handler types
}
```

### Warning: Middleware doesn't get type checking

**Cause**: Using `createTypedHandler()` but middleware doesn't support generics.

**Solution**: All middleware in Noony Core already support generics. If using custom middleware, update it to support `BaseMiddleware<T, U>`.

## 📈 Performance Impact

**Zero runtime overhead** - all changes are compile-time only:
- No additional code in production bundle
- No performance degradation
- TypeScript types are erased at runtime

## 🔗 Related Documentation

- **Type Chain Preservation**: See `docs/TYPE_CHAIN_FIX_SUMMARY.md`
- **Middleware Reference**: See `src/middlewares/bodyValidationMiddleware.ts` (gold standard implementation)
- **Handler API**: See `src/core/handler.ts`
- **Context Types**: See `src/core/core.ts`

## ❓ FAQ

### Q: Is createTypedHandler() temporary?
**A**: No, it's a permanent feature for improved DX, similar to patterns in tRPC and Fastify.

### Q: Do I have to migrate all handlers at once?
**A**: No, you can migrate incrementally. Untyped handlers (`new Handler()`) still work with manual typing.

### Q: Can I mix explicit types and createTypedHandler()?
**A**: Yes, both patterns are equally valid. Choose based on your preference and use case.

### Q: What if my middleware doesn't have generics?
**A**: All Noony Core middleware support generics. Custom middleware should be updated to implement `BaseMiddleware<T, U>`.

### Q: Will this break my existing code?
**A**: Yes, if you're using `.handle(controller as any)`. You'll need to add explicit types or use `createTypedHandler()`.

### Q: What's the recommended migration strategy?
**A**: Start with new handlers using the new patterns. Migrate existing handlers incrementally when you touch them.

## 🚀 Summary

v0.7.0 brings **true type safety** to Noony handlers by:
1. ✅ Eliminating `as any` type casts
2. ✅ Adding invariant generics to `.use()`
3. ✅ Providing `createTypedHandler()` for type inference
4. ✅ Maintaining backward compatibility for untyped handlers

**Migration is straightforward**: Choose explicit types or `createTypedHandler()`, update your handlers, and enjoy full type safety!

---

**Version**: 0.7.0
**Release Date**: 2026-01-21
**Breaking Changes**: Yes
**Migration Required**: Yes (for handlers using `as any`)
