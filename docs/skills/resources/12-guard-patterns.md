# Skill 12: Guard System - Authorization & Permissions

## Overview

The Guard system provides centralized authorization rules with two preset configurations (production/development) and three protection methods. Guards enforce permissions at request time after authentication.

## GuardSetup Presets

Initialize guards at application startup with predefined configurations:

```typescript
import { GuardSetup } from '@noony-serverless/core';

// Production - Strict access control
GuardSetup.production([
  {
    resource: 'posts',
    permissions: ['posts:list', 'posts:read', 'posts:create']
  },
  {
    resource: 'users',
    permissions: ['users:read']  // Basic users can only read
  },
  {
    resource: 'admin',
    permissions: ['admin:*']  // Admins can do anything
  }
]);

// Development - Permissive (skip guards or log only)
GuardSetup.development();
```

**Key Differences:**

| Aspect | Production | Development |
|--------|-----------|-------------|
| Permission Checks | Enforced strictly | Bypassed or logged |
| Access Denial | Returns 403 | Logs warning, allows access |
| Use Case | Live production | Local testing |

## RouteGuards.requirePermissions()

Simple permission checking for common RBAC patterns:

```typescript
import { RouteGuards } from '@noony-serverless/core';

const createPostHandler = new Handler<CreatePostRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions('posts:create')) // Check single permission
  .handle(async (context) => {
    const user = context.user!;
    const post = await postService.create(context.req.validatedBody!);
    return { postId: post.id };
  });

// User must have 'posts:create' permission or receive 403 Forbidden
```

**Multiple Permissions (User must have ALL):**

```typescript
const deletePostHandler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions(['posts:delete', 'audit:log']))
  .handle(async (context) => {
    const postId = context.req.params.postId;
    await postService.delete(postId);
    await auditService.log('post_deleted', { postId, userId: context.user!.id });
    return { success: true };
  });
```

## Three Protection Methods

### 1. requirePermissions() - Simple Straight Checks

For straightforward permission verification:

```typescript
import { RouteGuards } from '@noony-serverless/core';

const updateProfileHandler = new Handler<UpdateProfileRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions('profile:update'))
  .handle(async (context) => {
    const user = context.user!;
    const updated = await userService.update(user.id, context.req.validatedBody!);
    return { user: updated };
  });
```

**When to Use:**
- Fixed permission checks
- No dynamic conditions needed
- Simple RBAC scenarios

### 2. requireWildcardPermissions() - Flexible Pattern Matching

For role-based access with wildcards:

```typescript
const reportHandler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requireWildcardPermissions('reports:*'))
  .handle(async (context) => {
    // User needs any 'reports:*' permission
    // Valid: reports:read, reports:write, reports:export, reports:delete
    const report = await reportService.generate();
    return { reportId: report.id };
  });
```

**Wildcard Patterns:**
```typescript
RouteGuards.requireWildcardPermissions('admin:*')        // admin:*, admin:read, admin:write, etc.
RouteGuards.requireWildcardPermissions('resource:*:read') // resource:users:read, resource:posts:read, etc.
RouteGuards.requireWildcardPermissions('*:delete')       // Any resource delete
```

**When to Use:**
- Dynamic resource types
- Hierarchical permission systems
- Team/tenant isolation patterns

### 3. requireComplexPermissions() - Custom Logic

For sophisticated authorization rules:

```typescript
import { RouteGuards } from '@noony-serverless/core';
import { ForbiddenError } from '@noony-serverless/core';

const updatePostHandler = new Handler<UpdatePostRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use({
    before: async (context) => {
      const user = context.user!;
      const postId = context.req.params.postId;

      // Custom authorization logic
      const post = await postService.getById(postId);
      if (!post) {
        throw new NotFoundError('Post not found');
      }

      // Owner can edit their own posts
      if (post.authorId === user.id) {
        return; // Allowed
      }

      // Admins can edit any post
      if (user.permissions.includes('posts:admin')) {
        return; // Allowed
      }

      // Everyone else forbidden
      throw new ForbiddenError('You cannot edit this post');
    }
  })
  .handle(async (context) => {
    const post = await postService.update(
      context.req.params.postId,
      context.req.validatedBody!
    );
    return { post };
  });
```

**When to Use:**
- Ownership-based authorization
- Complex multi-condition rules
- Dynamic resource checks
- Business logic validation

## RBAC (Role-Based Access Control)

User roles map to permissions:

```typescript
// User types
interface AdminUser extends BaseAuthenticatedUser {
  role: 'admin';
  permissions: string[];
}

interface RegularUser extends BaseAuthenticatedUser {
  role: 'user';
  permissions: ['posts:read', 'posts:create', 'profile:update'];
}

type AuthenticatedUser = AdminUser | RegularUser;

// Token verifier maps roles to permissions
const tokenVerifier: CustomTokenVerificationPort<AuthenticatedUser> = {
  async verifyToken(token: string): Promise<AuthenticatedUser> {
    const payload = jwt.verify(token, secret) as any;

    if (payload.role === 'admin') {
      return {
        id: payload.sub,
        email: payload.email,
        role: 'admin',
        permissions: ['admin:*', 'posts:*', 'users:*', 'settings:*']
      };
    }

    return {
      id: payload.sub,
      email: payload.email,
      role: 'user',
      permissions: ['posts:read', 'posts:create', 'profile:update']
    };
  }
};

// Use in handlers
const deleteUserHandler = new Handler<any, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions('users:delete'))
  .handle(async (context) => {
    // Only admins have 'users:delete' permission
    const userId = context.req.params.userId;
    await userService.delete(userId);
    return { success: true };
  });
```

## Guards Must Come After Authentication

Critical ordering: Authentication → Authorization (Guards)

```typescript
// ✅ CORRECT ORDER
const handler = new Handler<UpdateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))  // 1. Verify JWT
  .use(RouteGuards.requirePermissions('users:update')) // 2. Check permissions
  .handle(async (context) => {
    // context.user guaranteed populated after authentication
    const user = context.user!;
  });

// ❌ WRONG - Guard before authentication
const handler = new Handler<UpdateUserRequest, AuthUser>()
  .use(RouteGuards.requirePermissions('users:update')) // ❌ user not loaded yet!
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // Guard runs before user is authenticated
  });
```

## Multi-Route Guard Configuration

Apply different guards to different endpoints:

```typescript
import { createFastifyHandler } from '@noony-serverless/core';
import Fastify from 'fastify';

const server = Fastify();

// Initialize guards once
GuardSetup.production([
  { resource: 'posts', permissions: ['posts:list', 'posts:read', 'posts:create'] },
  { resource: 'admin', permissions: ['admin:*'] }
]);

// Public route - no guard needed
server.get('/api/posts', createFastifyHandler(listPostsHandler, 'listPosts', init));

// Authenticated but not guarded
server.get('/api/profile',
  createFastifyHandler(getProfileHandler, 'getProfile', init)
);

// Authenticated + guarded
server.post('/api/posts',
  createFastifyHandler(createPostHandler, 'createPost', init)
);

server.delete('/api/posts/:postId',
  createFastifyHandler(deletePostHandler, 'deletePost', init)
);

server.post('/api/admin/users',
  createFastifyHandler(createAdminUserHandler, 'createAdminUser', init)
);
```

## Testing Guard Authorization

### Unit Test Permission Check

```typescript
import { RouteGuards } from '@noony-serverless/core';

describe('Guard Authorization', () => {
  it('should reject user without permission', async () => {
    const mockUser: AuthUser = {
      id: 'user-1',
      email: 'user@example.com',
      permissions: ['posts:read'] // Missing 'posts:create'
    };

    const context = {
      user: mockUser,
      req: {},
      res: {}
    } as any;

    const guard = RouteGuards.requirePermissions('posts:create');

    await expect(guard.before!(context)).rejects.toThrow(ForbiddenError);
  });

  it('should allow user with permission', async () => {
    const mockUser: AuthUser = {
      id: 'user-1',
      email: 'user@example.com',
      permissions: ['posts:create']
    };

    const context = {
      user: mockUser,
      req: {},
      res: {}
    } as any;

    const guard = RouteGuards.requirePermissions('posts:create');

    await expect(guard.before!(context)).resolves.not.toThrow();
  });
});
```

### Integration Test with Full Handler

```typescript
import request from 'supertest';
import { createFastifyHandler } from '@noony-serverless/core';

describe('Create Post Endpoint', () => {
  it('should return 403 for user without posts:create permission', async () => {
    const token = jwt.sign(
      {
        sub: 'user-1',
        email: 'user@example.com',
        role: 'user',
        permissions: ['posts:read'] // No posts:create
      },
      secret
    );

    const response = await request(app)
      .post('/api/posts')
      .set('Authorization', `Bearer ${token}`)
      .send({
        title: 'Test Post',
        content: 'Content'
      });

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('FORBIDDEN_ERROR');
  });

  it('should return 201 for user with posts:create permission', async () => {
    const token = jwt.sign(
      {
        sub: 'user-1',
        email: 'user@example.com',
        permissions: ['posts:create']
      },
      secret
    );

    const response = await request(app)
      .post('/api/posts')
      .set('Authorization', `Bearer ${token}`)
      .send({
        title: 'Test Post',
        content: 'Content'
      });

    expect(response.status).toBe(201);
    expect(response.body.data.id).toBeDefined();
  });
});
```

## Complex Authorization Patterns

### Pattern 1: Ownership + Role-Based

```typescript
const deleteCommentHandler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use({
    before: async (context) => {
      const user = context.user!;
      const commentId = context.req.params.commentId;

      const comment = await commentService.getById(commentId);
      if (!comment) {
        throw new NotFoundError('Comment not found');
      }

      // Owner can delete their own comments
      if (comment.authorId === user.id) {
        return; // Allowed
      }

      // Moderators can delete any comment
      if (user.permissions.includes('comments:moderate')) {
        return; // Allowed
      }

      // Everyone else forbidden
      throw new ForbiddenError('Cannot delete this comment');
    }
  })
  .handle(async (context) => {
    await commentService.delete(context.req.params.commentId);
    return { success: true };
  });
```

### Pattern 2: Resource-Based with Teams

```typescript
interface TeamUser extends BaseAuthenticatedUser {
  id: string;
  teams: string[]; // ['team-1', 'team-2']
  permissions: string[];
}

const updateTeamHandler = new Handler<UpdateTeamRequest, TeamUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use({
    before: async (context) => {
      const user = context.user as TeamUser;
      const teamId = context.req.params.teamId;

      // User must be member of team
      if (!user.teams.includes(teamId)) {
        throw new ForbiddenError('You are not a member of this team');
      }

      // User must have team:admin permission
      if (!user.permissions.includes('team:admin')) {
        throw new ForbiddenError('You lack team admin permissions');
      }
    }
  })
  .handle(async (context) => {
    const team = await teamService.update(
      context.req.params.teamId,
      context.req.validatedBody!
    );
    return { team };
  });
```

### Pattern 3: Hierarchical Resource Permissions

```typescript
const updateOrganizationHandler = new Handler<UpdateOrgRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use({
    before: async (context) => {
      const user = context.user!;
      const orgId = context.req.params.orgId;

      // Check if user belongs to organization
      const isMember = await orgService.isMember(user.id, orgId);
      if (!isMember) {
        throw new ForbiddenError('You do not belong to this organization');
      }

      // Check if user has org admin role
      const hasRole = await orgService.hasRole(user.id, orgId, 'admin');
      if (!hasRole) {
        throw new ForbiddenError('You must be an organization admin');
      }
    }
  })
  .handle(async (context) => {
    const org = await orgService.update(
      context.req.params.orgId,
      context.req.validatedBody!
    );
    return { org };
  });
```

## Configuring Guards at Startup

```typescript
import { GuardSetup } from '@noony-serverless/core';

// Initialize guards based on environment
async function initializeDependencies() {
  if (process.env.NODE_ENV === 'production') {
    GuardSetup.production([
      {
        resource: 'users',
        permissions: [
          'users:read',
          'users:create',
          'users:update',
          'users:delete'
        ]
      },
      {
        resource: 'posts',
        permissions: [
          'posts:list',
          'posts:read',
          'posts:create',
          'posts:update',
          'posts:delete'
        ]
      },
      {
        resource: 'admin',
        permissions: ['admin:*']
      }
    ]);
  } else {
    // Development - permissive
    GuardSetup.development();
  }

  // Initialize other dependencies...
}
```

## Anti-Patterns to Avoid

### ❌ Guard Before Authentication

```typescript
// WRONG - User not loaded yet
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(RouteGuards.requirePermissions('users:create'))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // Guard runs before user is authenticated
  });
```

### ✅ Correct Order

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions('users:create'))
  .handle(async (context) => {
    // Guard runs after user is authenticated
  });
```

### ❌ Hardcoding Permissions in Handler

```typescript
// WRONG - Authorization scattered across code
const handler = new Handler<any, AuthUser>()
  .handle(async (context) => {
    if (context.user?.role !== 'admin') {
      throw new ForbiddenError('Admin only');
    }
    // ... implementation
  });
```

### ✅ Use Guards for Authorization

```typescript
// CORRECT - Centralized in middleware
const handler = new Handler<any, AuthUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions('admin:*'))
  .handle(async (context) => {
    // Authorization already checked
  });
```

### ❌ Different Guards for Same Permission

```typescript
// WRONG - Inconsistent authorization
server.post('/api/posts', createPostHandler1); // Uses RouteGuards.requirePermissions
server.post('/api/posts', createPostHandler2); // Uses custom logic

// Different behavior for same operation!
```

### ✅ Standardized Approach

```typescript
// CORRECT - Consistent across endpoints
GuardSetup.production([
  { resource: 'posts', permissions: ['posts:create'] }
]);

server.post('/api/posts', createFastifyHandler(createPostHandler1, 'createPost', init));
server.post('/api/posts/bulk', createFastifyHandler(bulkCreateHandler, 'bulkCreatePosts', init));

// Both use the same guard configuration
```

## Common Gotchas

### Gotcha 1: Empty Permissions Array

```typescript
// ❌ WRONG - User with empty permissions
const user: AuthUser = {
  id: 'user-1',
  email: 'user@example.com',
  permissions: [] // No permissions!
};

// Will fail all permission checks
const handler = new Handler<any, AuthUser>()
  .use(RouteGuards.requirePermissions('posts:read'))
  .handle(async (context) => {
    // Throws ForbiddenError
  });

// ✅ CORRECT - Always provide permissions
const user: AuthUser = {
  id: 'user-1',
  email: 'user@example.com',
  permissions: ['posts:read', 'posts:create']
};
```

### Gotcha 2: Wildcard Matching Edge Cases

```typescript
// Wildcard matching is exact at component level
RouteGuards.requireWildcardPermissions('admin:*'); // ✓ Matches 'admin:read', 'admin:write'
RouteGuards.requireWildcardPermissions('admin:*'); // ✗ Does NOT match 'admin_read', 'admin-read'

// Be consistent with permission naming:
// Good: 'admin:read', 'admin:write', 'admin:delete'
// Bad: 'admin-read', 'admin-write', 'admin-delete' (wildcards won't work)
```

### Gotcha 3: Context Not Available in Custom Guard

```typescript
// ❌ WRONG - Trying to access req before it's available
const guard = {
  before: async (context) => {
    const postId = context.req.params.postId; // May be undefined
  }
};

// ✅ CORRECT - Check availability
const guard = {
  before: async (context) => {
    const postId = context.req.params?.postId;
    if (!postId) {
      throw new ValidationError('postId required');
    }
  }
};
```
