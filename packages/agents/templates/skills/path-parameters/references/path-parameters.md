# Resource: Path Parameters Patterns

## Pattern 1: Simple String Path Parameter

```typescript
import { Handler, Context } from '@noony-serverless/core';
import { createFastifyHandler } from '@noony-serverless/core';
import { Fastify } from 'fastify';

// Define path params interface
interface GetUserParams {
  userId: string;
}

// Handler accesses via context.req.params
const getUserHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context: Context<void, AuthUser>) => {
    const params = context.req.params as GetUserParams;
    const userId = params.userId;  // Type: string

    const user = await userService.getById(userId);
    return { data: user };
  });

// Fastify route registration
const server = Fastify();
server.get('/api/users/:userId',
  createFastifyHandler(getUserHandler, 'getUser', initDeps)
);
```

## Pattern 2: Multiple Path Parameters

```typescript
// Define path params interface with all parameters
interface UpdateSectionParams {
  userId: string;
  sectionId: string;
}

const updateSectionHandler = new Handler<UpdateSectionRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(updateSectionSchema))
  .handle(async (context: Context<UpdateSectionRequest, AuthUser>) => {
    const params = context.req.params as UpdateSectionParams;
    const { userId, sectionId } = params;

    const section = await sectionService.update(userId, sectionId, context.req.validatedBody!);
    return { data: section };
  });

// Fastify route with multiple parameters
server.patch('/api/users/:userId/sections/:sectionId',
  createFastifyHandler(updateSectionHandler, 'updateSection', initDeps)
);
```

## Pattern 3: Type-Safe Path Parameters

For maximum type safety, use TypeScript to extract params:

```typescript
interface PathParams {
  userId: string;
  postId: string;
}

const deletePostHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware<void, AuthUser>())
  .handle(async (context: Context<void, AuthUser>) => {
    // Type-safe extraction
    const { userId, postId } = context.req.params as PathParams;

    // Validation
    if (!userId || !postId) {
      throw new ValidationError('Missing required parameters');
    }

    await postService.delete(userId, postId);
    return { success: true };
  });
```

## Pattern 4: Numeric Path Parameters

When path params should be parsed as numbers:

```typescript
interface NumericParams {
  userId: string;
  postId: string;
}

const getPostHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context: Context<void, AuthUser>) => {
    const params = context.req.params as NumericParams;

    // Parse from string to number
    const userId = parseInt(params.userId, 10);
    const postId = parseInt(params.postId, 10);

    // Validate parsing
    if (isNaN(userId) || isNaN(postId)) {
      throw new ValidationError('Invalid numeric parameters');
    }

    const post = await postService.getById(postId);
    return { data: post };
  });

// Fastify route
server.get('/api/users/:userId/posts/:postId',
  createFastifyHandler(getPostHandler, 'getPost', initDeps)
);
```

## Pattern 5: UUID Path Parameters

For UUID-based route parameters:

```typescript
import { v4 as uuidv4, validate as validateUUID } from 'uuid';

interface UUIDParams {
  organizationId: string;
  teamId: string;
}

const getTeamHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context: Context<void, AuthUser>) => {
    const params = context.req.params as UUIDParams;
    const { organizationId, teamId } = params;

    // Validate UUIDs
    if (!validateUUID(organizationId) || !validateUUID(teamId)) {
      throw new ValidationError('Invalid UUID format');
    }

    const team = await teamService.getTeam(organizationId, teamId);
    return { data: team };
  });

// Fastify route with UUID parameters
server.get('/api/organizations/:organizationId/teams/:teamId',
  createFastifyHandler(getTeamHandler, 'getTeam', initDeps)
);
```

## Pattern 6: Slug Path Parameters

For human-readable URL slugs:

```typescript
import { slugify, unslugify } from './utils';

interface SlugParams {
  category: string;
  postSlug: string;
}

const getPostBySlugHandler = new Handler<void, void>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context: Context<void, void>) => {
    const params = context.req.params as SlugParams;
    const { category, postSlug } = params;

    // Slugs come from URL as-is, no parsing needed
    const post = await postService.getBySlug(category, postSlug);

    if (!post) {
      throw new NotFoundError('Post not found');
    }

    return { data: post };
  });

// Fastify route with slug parameters
server.get('/blog/:category/:postSlug',
  createFastifyHandler(getPostBySlugHandler, 'getPostBySlug', initDeps)
);
```

## Pattern 7: Query Parameters vs Path Parameters

Understanding the difference:

```typescript
// Path parameters (required, part of resource identity)
server.get('/api/users/:userId/posts/:postId', handler);
// Access: context.req.params.userId, context.req.params.postId

// Query parameters (optional, for filtering/pagination)
server.get('/api/posts', handler);
// Access: context.req.query.category, context.req.query.limit
// Example: /api/posts?category=tech&limit=10
```

## Common Mistakes

### ❌ Forgetting :paramName Syntax

```typescript
// WRONG - Fastify won't recognize as parameter
server.get('/api/users/userId', handler);  // Not a parameter!

// CORRECT - Use :paramName syntax
server.get('/api/users/:userId', handler);  // Now it's a parameter
```

### ❌ Not Accessing params via context.req.params

```typescript
// WRONG - Tries to access from body
const userId = context.req.body.userId;  // Undefined!

// CORRECT - Access via params
const userId = context.req.params.userId;  // Correct
```

### ❌ Forgetting Parameter Validation

```typescript
// WRONG - Assumes param is always valid
const postId = parseInt(context.req.params.postId);  // Could be NaN!

// CORRECT - Validate before using
const postId = parseInt(context.req.params.postId, 10);
if (isNaN(postId)) {
  throw new ValidationError('postId must be numeric');
}
```

### ❌ Type Casting Without Validation

```typescript
// WRONG - Cast doesn't validate UUID format
const id = context.req.params.id as UUID;

// CORRECT - Validate UUID format
if (!validateUUID(context.req.params.id)) {
  throw new ValidationError('Invalid UUID');
}
const id = context.req.params.id;  // Now safe to use
```

## Testing Path Parameters

```typescript
describe('Path Parameters', () => {
  it('should extract and use path parameters', async () => {
    const mockReq = createMockRequest({
      params: { userId: '123', postId: '456' }  // Set params for testing
    });

    const mockRes = createMockResponse();
    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(200);
  });

  it('should validate UUID parameters', async () => {
    const mockReq = createMockRequest({
      params: { userId: 'not-a-uuid', postId: '456' }  // Invalid UUID
    });

    const mockRes = createMockResponse();
    await handler.executeGeneric(mockReq, mockRes);

    // Should return 400 for invalid UUID
    expect(mockRes.getStatus()).toBe(400);
  });

  it('should handle missing parameters', async () => {
    const mockReq = createMockRequest({
      params: {}  // Missing parameters
    });

    const mockRes = createMockResponse();
    await handler.executeGeneric(mockReq, mockRes);

    expect(mockRes.getStatus()).toBe(400);
  });
});
```
