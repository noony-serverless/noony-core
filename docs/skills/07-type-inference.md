# Skill 7: Type Inference with createTypedHandler()

## Triggers

When user asks to:
- "Reduce type boilerplate"
- "Avoid repeating types"
- "Infer types from controller"
- "Too much generic syntax"
- "Simplify handler types"
- "DRY - types are duplicated"
- "createTypedHandler usage"

## What it provides

Pattern for automatic type inference from controller signature, eliminating repetitive generic type annotations.

## Complete Example

### Option 1: Explicit Types (Traditional)

```typescript
// src/handlers/order.handlers.ts
import { Handler, Context } from '@noony-serverless/core';

interface CreateOrderRequest {
  productId: string;
  quantity: number;
  shippingAddress: Address;
}

interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'customer' | 'admin';
}

// Controller with explicit types
async function createOrderController(
  context: Context<CreateOrderRequest, AuthenticatedUser>
): Promise<void> {
  const { productId, quantity, shippingAddress } = context.req.validatedBody!;
  const user = context.user!;

  const order = await orderService.create({
    productId,
    quantity,
    shippingAddress,
    userId: user.id,
    customerEmail: user.email,
  });

  context.res.status(201).json({ data: order });
}

// Handler with explicit generics - types repeated!
export const createOrderHandler = new Handler<
  CreateOrderRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .handle(createOrderController);
```

### Option 2: Type Inference with createTypedHandler() (Recommended)

```typescript
// src/handlers/order.handlers.ts
import { createTypedHandler, Context } from '@noony-serverless/core';

// Same controller definition
async function createOrderController(
  context: Context<CreateOrderRequest, AuthenticatedUser>
): Promise<void> {
  const { productId, quantity, shippingAddress } = context.req.validatedBody!;
  const user = context.user!;

  const order = await orderService.create({
    productId,
    quantity,
    shippingAddress,
    userId: user.id,
    customerEmail: user.email,
  });

  context.res.status(201).json({ data: order });
}

// ✨ Types automatically inferred from controller signature!
export const createOrderHandler = createTypedHandler(createOrderController)
  .use(new ErrorHandlerMiddleware())  // No generics needed!
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .handle(createOrderController);
```

### Benefits Comparison

```typescript
// ❌ Without createTypedHandler - repetitive generics
export const handler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthenticatedUser>())
  .use(new BodyValidationMiddleware<CreateOrderRequest, AuthenticatedUser>(schema))
  .use(new ResponseWrapperMiddleware<OrderResponse, CreateOrderRequest, AuthenticatedUser>())
  .handle(controller);
  // 👆 Types written 4 times!

// ✅ With createTypedHandler - inferred automatically
export const handler = createTypedHandler(controller)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .use(new ResponseWrapperMiddleware())
  .handle(controller);
  // 👆 Types written once (in controller signature)
```

### Advanced: Multiple Handlers with Type Inference

```typescript
// src/handlers/user.handlers.ts
import { createTypedHandler, Context } from '@noony-serverless/core';

// Define controllers with types
async function getUserController(
  context: Context<void, AuthenticatedUser>
): Promise<void> {
  const userId = context.req.params.userId;
  const user = await userService.getById(userId);
  context.res.status(200).json({ data: user });
}

async function updateUserController(
  context: Context<UpdateUserRequest, AuthenticatedUser>
): Promise<void> {
  const updates = context.req.validatedBody!;
  const user = await userService.update(updates);
  context.res.status(200).json({ data: user });
}

async function deleteUserController(
  context: Context<void, AuthenticatedUser>
): Promise<void> {
  const userId = context.req.params.userId;
  await userService.delete(userId);
  context.res.status(204).end();
}

// All handlers use type inference - no repetition!
export const getUserHandler = createTypedHandler(getUserController)
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(getUserController);

export const updateUserHandler = createTypedHandler(updateUserController)
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(updateUserSchema))
  .handle(updateUserController);

export const deleteUserHandler = createTypedHandler(deleteUserController)
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new PermissionGuard(['users:delete']))
  .handle(deleteUserController);
```

### When to use createTypedHandler()

**✅ Use createTypedHandler() when:**
- Controller already has explicit type annotations
- Want to reduce boilerplate by ~50%
- Working with multiple handlers (DRY principle)
- Prefer cleaner, more concise code

**✅ Use new Handler<T, U>() when:**
- Defining types inline (not in controller signature)
- Working with very simple handlers
- Prefer explicit type declarations
- Need maximum clarity over brevity

### Full Type Safety Preserved

```typescript
// Both approaches provide identical type safety!

// Explicit approach
const handler1 = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new BodyValidationMiddleware(schema))
  .handle(controller);

// Inference approach
const handler2 = createTypedHandler(controller)
  .use(new BodyValidationMiddleware(schema))
  .handle(controller);

// Both have:
// - context.req.validatedBody typed as CreateOrderRequest
// - context.user typed as AuthenticatedUser
// - Full autocomplete and type checking
```

## When to use

- Want to reduce repetitive type annotations
- Have controllers with explicit type signatures
- Building multiple similar handlers
- Prefer DRY (Don't Repeat Yourself) principles
- Want cleaner, more maintainable code
