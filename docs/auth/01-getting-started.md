# Add Authentication to a Noony Handler

In this tutorial, we will add JWT authentication to a Noony handler. By the end, you will have a protected endpoint that validates tokens and provides typed user context.

## What You Need

- `@noony-serverless/core` installed
- A running Noony handler (see the main getting-started guide)
- A JWT secret available as an environment variable

## Step 1: Install and Configure RouteGuards

RouteGuards is the central coordinator for authentication and authorization. Call `RouteGuards.configure` once at application startup — before any requests are handled.

```typescript
// src/auth/guards.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';

interface User {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
  sub: string;
  exp: number;
}
```

You'll notice that `User` contains both identity fields (`id`, `email`) and JWT standard claims (`sub`, `exp`). This lets the type serve both roles.

## Step 2: Create a Token Verifier

The token verifier is the single function that converts a raw token string into a typed user object. If verification fails, throw an error — RouteGuards will catch it and return a 401.

```typescript
// src/auth/guards.ts (continued)
import jwt from 'jsonwebtoken';

const tokenVerifier: CustomTokenVerificationPort<User> = {
  async verifyToken(token: string): Promise<User> {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
    return {
      id: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      sub: payload.sub,
      exp: payload.exp,
    };
  },
};
```

## Step 3: Define a Permission Source and Configure RouteGuards

The permission source loads a user's permissions from your database. RouteGuards uses this during each permission check.

```typescript
// src/auth/guards.ts (continued)
const userPermissionSource = {
  async getUserPermissions(userId: string) {
    const user = await db.users.findById(userId);
    return {
      permissions: user.permissions,
      roles: user.roles,
      metadata: { email: user.email },
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    const rolePerms = await db.roles.find({ name: { $in: roles } });
    return rolePerms.flatMap((role) => role.permissions);
  },

  async isUserContextStale(): Promise<boolean> {
    return false;
  },
};

export const setupGuards = async () => {
  await RouteGuards.configure(
    GuardSetup.production(),
    userPermissionSource,
    tokenVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
    }
  );
};
```

Call `setupGuards()` in your application entry point before registering any handlers.

## Step 4: Add AuthenticationMiddleware to Your Handler

With RouteGuards configured, protect a handler by adding `RouteGuards.requirePermissions` to the middleware chain. The generic parameter `<unknown, User>` tells the handler what types to expect for the request body and the user.

```typescript
// src/handlers/profile.handler.ts
import { Handler, RouteGuards } from '@noony-serverless/core';

export const getProfileHandler = new Handler<unknown, User>()
  .use(RouteGuards.requirePermissions(['user:read']))
  .handle(async (context) => {
    const user = context.user!;
    return { profile: user };
  });
```

At this point, any request that reaches this handler without a valid `Authorization: Bearer <token>` header will receive a 401 response automatically. No error handling code is needed in the controller.

## Step 5: Access User in the Controller

`context.user` is fully typed as `User` once the middleware chain has run. You can access all fields without casting.

```typescript
export const getProfileHandler = new Handler<unknown, User>()
  .use(RouteGuards.requirePermissions(['user:read']))
  .handle(async (context) => {
    const user = context.user!; // type: User
    return {
      id: user.id,
      email: user.email,
      roles: user.roles,
    };
  });
```

## Step 6: Test the Endpoint

When you call this endpoint without a token, you will see a 401 response:

```bash
curl http://localhost:3000/profile
# HTTP 401 Unauthorized
```

When you call it with a valid token:

```bash
curl -H "Authorization: Bearer <your-token>" http://localhost:3000/profile
# HTTP 200 { "id": "...", "email": "...", "roles": [...] }
```

When you call it with a token that belongs to a user who lacks the `user:read` permission, you will see a 403 response:

```bash
curl -H "Authorization: Bearer <token-without-permission>" http://localhost:3000/profile
# HTTP 403 Forbidden
```

## Anti-Patterns

These are the most common mistakes when setting up RouteGuards. Avoid them from the start.

**Calling `configure` inside a handler** — `RouteGuards.configure` must be called once at startup. If it runs per-request, you will create a new guard instance on every call, discarding cached permissions.

**Hardcoding the JWT secret** — Always read from environment variables. Never commit secrets to source code.

**Testing with production tokens** — Use dedicated test tokens and a mock permission source in tests. See below.

```typescript
// Testing setup: mock the permission source and verifier
await RouteGuards.configure(
  GuardSetup.testing(),
  {
    async getUserPermissions() {
      return { permissions: ['user:read'], roles: ['user'] };
    },
    async getRolePermissions() { return []; },
    async isUserContextStale() { return false; },
  },
  mockTokenVerifier,
  { tokenHeader: 'authorization', tokenPrefix: 'Bearer ' }
);
```

## Next Steps

- Full configuration options for `GuardSecurityConfig`, `GuardCacheConfig`, and all static methods: [02-complete-guide.md](./02-complete-guide.md)
- Supporting multiple auth methods in one app: [03-multi-auth-examples.md](./03-multi-auth-examples.md)
- Firebase token validation: [05-firebase.md](./05-firebase.md)
- OAuth 2.0 providers: [06-oauth2.md](./06-oauth2.md)
