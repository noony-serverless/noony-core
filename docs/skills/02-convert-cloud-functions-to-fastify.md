# Skill 2: Convert Cloud Functions Handler to Fastify

## Triggers

When user asks to:
- "Make this work with Fastify"
- "I want to run this handler locally"
- "Convert to Fastify"
- "Use the same handler for local and production"
- "Add Fastify support to existing handlers"
- "How do I test this without deploying?"

## What it provides

Step-by-step pattern for enabling existing Cloud Functions handlers to work with both Fastify (local) and Cloud Functions (production) using the same handler code.

## Complete Example

### Step 1: Handler Definition (No Changes!)

```typescript
// src/handlers/order.handlers.ts
import { Handler, Context } from '@noony-serverless/core';

// Handler remains unchanged - works with both Fastify and Cloud Functions
export const createOrderHandler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateOrderRequest, AuthenticatedUser>) => {
    const { productId, quantity } = context.req.validatedBody!;
    const user = context.user!;

    const order = await orderService.create({
      productId,
      quantity,
      userId: user.id,
    });

    context.res.status(201).json({ data: order });
  });
```

### Step 2: Fastify Entry Point (Local Development)

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createOrderHandler } from './handlers/order.handlers';

const server = Fastify();

// Wrap Noony handler for Fastify
server.post(
  '/api/orders',
  createFastifyHandler(createOrderHandler, 'createOrder', initializeDependencies)
);

server.listen({ port: 3000 });
```

### Step 3: Cloud Functions Entry Point (Production)

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { createOrderHandler } from './handlers/order.handlers';

// Export for Cloud Functions
export const createOrder = http('createOrder', async (req, res) => {
  await initializeDependencies();
  await createOrderHandler.execute(req, res);
});
```

## Pattern Summary

```typescript
// ✅ BEFORE: Cloud Functions only
export const myFunction = http('myFunction', (req, res) => {
  return myHandler.execute(req, res);
});

// ✅ AFTER: Works with BOTH Fastify and Cloud Functions

// 1. Handler definition (unchanged)
const myHandler = new Handler<MyRequest, MyUser>()
  .use(...)
  .handle(myController);

// 2. Fastify entry (src/server.ts)
server.post('/api/my-endpoint',
  createFastifyHandler(myHandler, 'myFunction', initDeps)
);

// 3. Cloud Functions entry (src/functions.ts)
export const myFunction = http('myFunction', async (req, res) => {
  await initDeps();
  await myHandler.execute(req, res);
});
```

## When to use

- You have existing Cloud Functions handlers
- Want to test handlers locally without deploying
- Need faster development iteration
- Want to maintain same codebase for local and production
