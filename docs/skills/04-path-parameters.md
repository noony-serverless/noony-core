# Skill 4: Path Parameters with Fastify

## Triggers

When user asks to:
- "How do I use path parameters?"
- "Access URL parameters"
- "Get :userId from the URL"
- "Route with parameters"
- "Dynamic route segments"
- "RESTful routes with IDs"

## What it provides

Pattern for handlers that use path parameters (e.g., `/api/users/:userId`).

## Complete Example

### Handler with Path Parameters

```typescript
// src/handlers/user.handlers.ts
import { Handler, Context, NotFoundError } from '@noony-serverless/core';

export const getUserHandler = new Handler<void, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<void, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context: Context<void, AuthenticatedUser>) => {
    // Access path parameters from context.req.params
    const userId = context.req.params.userId;
    const user = context.user!;

    // Verify user can access this resource
    if (user.id !== userId && user.role !== 'admin') {
      throw new ForbiddenError('Cannot access other user data');
    }

    const userData = await userService.getById(userId);
    if (!userData) {
      throw new NotFoundError('User not found');
    }

    context.res.status(200).json({ data: userData });
  });

export const updateUserSectionHandler = new Handler<UpdateSectionRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<UpdateSectionRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(updateSectionSchema))
  .handle(async (context: Context<UpdateSectionRequest, AuthenticatedUser>) => {
    // Multiple path parameters
    const userId = context.req.params.userId;
    const sectionId = context.req.params.sectionId;
    const updates = context.req.validatedBody!;
    const currentUser = context.user!;

    // Permission check
    if (currentUser.id !== userId) {
      throw new ForbiddenError('Cannot update other user sections');
    }

    const updated = await userService.updateSection(userId, sectionId, updates);
    context.res.status(200).json({ data: updated });
  });
```

### Fastify Route Registration

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import {
  getUserHandler,
  updateUserSectionHandler,
} from './handlers/user.handlers';

const server = Fastify();
const adapt = (handler, name) =>
  createFastifyHandler(handler, name, initializeDependencies);

// Single path parameter
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));

// Multiple path parameters
server.patch(
  '/api/users/:userId/sections/:sectionId',
  adapt(updateUserSectionHandler, 'updateUserSection')
);

// Path parameters with query strings work too
// GET /api/users/123?include=orders
server.get('/api/users/:userId', adapt(getUserWithQueryHandler, 'getUserWithQuery'));
```

### Cloud Functions Route Registration

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { getUserHandler, updateUserSectionHandler } from './handlers/user.handlers';

// Path parameters from URL routing config
export const getUser = http('getUser', async (req, res) => {
  await initializeDependencies();
  await getUserHandler.execute(req, res);
});

export const updateUserSection = http('updateUserSection', async (req, res) => {
  await initializeDependencies();
  await updateUserSectionHandler.execute(req, res);
});
```

### Advanced: Type-Safe Path Parameters

```typescript
// src/types/route-params.ts
export interface UserRouteParams {
  userId: string;
}

export interface UserSectionRouteParams {
  userId: string;
  sectionId: string;
}

// Enhanced handler with type-safe params
export const getUserHandler = new Handler<void, AuthenticatedUser>()
  .use(...)
  .handle(async (context: Context<void, AuthenticatedUser>) => {
    const { userId } = context.req.params as UserRouteParams;
    // userId is now typed as string
  });
```

## When to use

- RESTful API endpoints with resource IDs
- CRUD operations on specific resources
- Nested resource routes (e.g., `/users/:userId/orders/:orderId`)
- Any route with dynamic segments
