# Skill 12: Guard System - Authorization & Permissions

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
    permissions: ['users:read']
  },
  {
    resource: 'admin',
    permissions: ['admin:*']
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

**Environment-based setup:**

```typescript
async function initializeDependencies() {
  if (process.env.NODE_ENV === 'production') {
    GuardSetup.production([
      { resource: 'users', permissions: ['users:read', 'users:create', 'users:update', 'users:delete'] },
      { resource: 'posts', permissions: ['posts:list', 'posts:read', 'posts:create', 'posts:delete'] },
      { resource: 'admin', permissions: ['admin:*'] }
    ]);
  } else {
    GuardSetup.development();
  }
}
```

## requirePermissions() - Simple Checks

Simple permission checking for common RBAC patterns:

```typescript
import { RouteGuards } from '@noony-serverless/core';

// Single permission check
const createPostHandler = new Handler<CreatePostRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions('posts:create'))
  .handle(async (context) => {
    const post = await postService.create(context.req.validatedBody!);
    return { postId: post.id };
  });

// Multiple permissions (user must have ALL)
const deletePostHandler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requirePermissions(['posts:delete', 'audit:log']))
  .handle(async (context) => {
    await postService.delete(context.req.params.postId);
    return { success: true };
  });
```

**When to use:** Fixed permission checks, no dynamic conditions, simple RBAC scenarios.

## requireWildcardPermissions() - Pattern Matching

For role-based access with wildcard patterns:

```typescript
const reportHandler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(RouteGuards.requireWildcardPermissions('reports:*'))
  .handle(async (context) => {
    // User needs any 'reports:*' permission
    // Valid: reports:read, reports:write, reports:export
    const report = await reportService.generate();
    return { reportId: report.id };
  });
```

**Wildcard Patterns:**
```typescript
RouteGuards.requireWildcardPermissions('admin:*')         // admin:read, admin:write, etc.
RouteGuards.requireWildcardPermissions('resource:*:read')  // resource:users:read, resource:posts:read
RouteGuards.requireWildcardPermissions('*:delete')         // Any resource delete
```

**When to use:** Dynamic resource types, hierarchical permission systems, tenant isolation patterns.

**Matching rules:**
- Wildcard matches at component level separated by `:`
- `admin:*` matches `admin:read` but NOT `admin-read` or `admin_read`
- Be consistent: always use `resource:action` naming convention

## Complex Authorization: Ownership & Teams

For sophisticated authorization rules, use inline `before()` middleware:

### Ownership-Based Access

```typescript
const updatePostHandler = new Handler<UpdatePostRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use({
    before: async (context) => {
      const user = context.user!;
      const postId = context.req.params.postId;

      const post = await postService.getById(postId);
      if (!post) throw new NotFoundError('Post not found');

      // Owner can edit their own posts
      if (post.authorId === user.id) return;

      // Admins can edit any post
      if (user.permissions.includes('posts:admin')) return;

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

### Team-Based Access

```typescript
interface TeamUser extends BaseAuthenticatedUser {
  id: string;
  teams: string[];
  permissions: string[];
}

const updateTeamHandler = new Handler<UpdateTeamRequest, TeamUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use({
    before: async (context) => {
      const user = context.user as TeamUser;
      const teamId = context.req.params.teamId;

      if (!user.teams.includes(teamId)) {
        throw new ForbiddenError('You are not a member of this team');
      }

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

**When to use complex authorization:**
- Ownership-based access (user can edit only their own resources)
- Multi-condition rules (membership + role check)
- Dynamic resource checks requiring database lookups

## RBAC (Role-Based Access Control)

User roles map to permissions via the token verifier:

```typescript
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
  permissions: string[];
}

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
```

## Guards Must Come After Authentication

Critical ordering: Authentication -> Authorization (Guards)

```typescript
// CORRECT ORDER
const handler = new Handler<UpdateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))  // 1. Verify JWT
  .use(RouteGuards.requirePermissions('users:update')) // 2. Check permissions
  .handle(async (context) => {
    const user = context.user!;  // Guaranteed populated
  });

// WRONG - Guard before authentication
const handler = new Handler<UpdateUserRequest, AuthUser>()
  .use(RouteGuards.requirePermissions('users:update')) // user not loaded yet!
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {});
```

## Testing Guard Authorization

### Unit Test Permission Check

```typescript
describe('Guard Authorization', () => {
  it('should reject user without permission', async () => {
    const mockUser: AuthUser = {
      id: 'user-1',
      email: 'user@example.com',
      permissions: ['posts:read'] // Missing 'posts:create'
    };

    const context = { user: mockUser, req: {}, res: {} } as any;
    const guard = RouteGuards.requirePermissions('posts:create');

    await expect(guard.before!(context)).rejects.toThrow(ForbiddenError);
  });

  it('should allow user with permission', async () => {
    const mockUser: AuthUser = {
      id: 'user-1',
      email: 'user@example.com',
      permissions: ['posts:create']
    };

    const context = { user: mockUser, req: {}, res: {} } as any;
    const guard = RouteGuards.requirePermissions('posts:create');

    await expect(guard.before!(context)).resolves.not.toThrow();
  });
});
```

## Common Gotchas

### Empty Permissions Array

```typescript
// User with empty permissions fails all checks
const user: AuthUser = {
  id: 'user-1',
  email: 'user@example.com',
  permissions: [] // No permissions -- every guard check will throw ForbiddenError
};

// Always ensure token verifier returns at least base permissions
```

### Wildcard Matching Edge Cases

```typescript
// Wildcard matching is exact at component level (separated by :)
RouteGuards.requireWildcardPermissions('admin:*'); // Matches 'admin:read', 'admin:write'
RouteGuards.requireWildcardPermissions('admin:*'); // Does NOT match 'admin_read', 'admin-read'

// Be consistent: always use resource:action format
// Good: 'admin:read', 'admin:write', 'admin:delete'
// Bad:  'admin-read', 'admin-write' (wildcards won't work)
```

### Context Params Not Available

```typescript
// WRONG - params may be undefined
const guard = {
  before: async (context) => {
    const postId = context.req.params.postId; // May be undefined
  }
};

// CORRECT - validate availability
const guard = {
  before: async (context) => {
    const postId = context.req.params?.postId;
    if (!postId) throw new ValidationError('postId required');
  }
};
```

## Permission Strategy Decision Table

| Strategy | Method | Matching | Performance | Use When |
|----------|--------|----------|-------------|----------|
| Plain | `requirePermissions` | Exact string | Fastest | Simple permission lists |
| Wildcard | `requireWildcardPermissions` | Glob pattern (`*`) | Medium | Hierarchical resource access |
| Expression | `requireComplexPermissions` | Boolean tree | Slowest | Complex AND/OR/NOT business rules |

Avoid Expression permissions on endpoints receiving more than ~500 requests per minute. Prefer Plain or Wildcard at high throughput.
