# How to Build Your First Noony Handler

This guide walks you through creating a working Noony handler, wiring up middleware, and running it on both Google Cloud Functions and a local Fastify server. By the end you will have a deployable handler with request validation, authentication, and error handling.

## Prerequisites

- Node.js 18+ and npm installed
- TypeScript project configured (`tsconfig.json` with `"strict": true`)
- `@noony-serverless/core` installed
- For GCP deployment: `@google-cloud/functions-framework` installed
- For local development: `fastify` installed

```bash
npm install @noony-serverless/core
npm install @google-cloud/functions-framework   # GCP
npm install fastify                             # local dev
```

---

## Step 1: Install and import the framework

```bash
npm install @noony-serverless/core
```

Core imports you will use throughout:

```typescript
import {
  Handler,
  Context,
  BaseMiddleware,
  ErrorHandlerMiddleware,
  ResponseWrapperMiddleware,
  BodyValidationMiddleware,
} from '@noony-serverless/core';
```

---

## Step 2: Define your request type

Use Zod as the single source of truth for both runtime validation and static types. Infer the TypeScript type from the schema — do not write the type manually.

```typescript
import { z } from 'zod';

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

type LoginRequest = z.infer<typeof loginSchema>;
```

---

## Step 3: Write the controller

A controller is a plain async function that receives a typed `Context` and writes to `context.res`. It contains only business logic — no middleware concerns.

```typescript
import { Context } from '@noony-serverless/core';
import { LoginRequest } from './schemas.js';

export async function loginController(
  context: Context<LoginRequest>
): Promise<void> {
  const { email, password } = context.req.validatedBody!;

  const result = await authService.login(email, password);

  if (!result.success) {
    context.res.status(401).json({
      success: false,
      error: { message: 'Authentication failed', code: 'AUTH_FAILED' },
    });
    return;
  }

  context.res.status(200).json({ success: true, data: result.data });
}
```

---

## Step 4: Build the handler

Compose the middleware chain using `.use()`. The order matters: `ErrorHandlerMiddleware` always goes first so it can catch errors from every subsequent layer. `ResponseWrapperMiddleware` always goes last (before `.handle()`).

```typescript
import { Handler, ErrorHandlerMiddleware, ResponseWrapperMiddleware, BodyValidationMiddleware } from '@noony-serverless/core';
import { loginSchema, LoginRequest } from './schemas.js';
import { loginController } from './controllers.js';

export const loginHandler = new Handler<LoginRequest>()
  .use(new ErrorHandlerMiddleware())          // FIRST — catches all errors
  .use(new BodyValidationMiddleware(loginSchema))
  .use(new ResponseWrapperMiddleware())       // LAST — wraps the response
  .handle(loginController);
```

If the endpoint requires an authenticated user, pass a second generic to propagate the user type through every middleware and the controller:

```typescript
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

export const createOrderHandler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateOrderRequest, AuthenticatedUser>) => {
    const { productId, quantity } = context.req.validatedBody!; // CreateOrderRequest
    const user = context.user!;                                  // AuthenticatedUser
    // ...
  });
```

> If you implement a custom middleware, it must carry the same generics as the handler — otherwise the type chain breaks silently. See [Architecture](../explanation/architecture.md) for why this matters.

---

## Step 5: Add custom middleware (optional)

If you need cross-cutting logic such as authentication, write a class that implements `BaseMiddleware<TBody, TUser>` with the same generics as the handler:

```typescript
import { BaseMiddleware, Context, UnauthorizedError } from '@noony-serverless/core';

export class AuthenticationMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {

  async before(context: Context<TBody, TUser>): Promise<void> {
    const authHeader = context.req.headers['authorization'];
    if (!authHeader?.startsWith('Bearer ')) return;

    const token = authHeader.slice('Bearer '.length);
    const user = await this.tokenVerifier.verifyToken(token);
    context.user = user as TUser;
  }
}
```

Place authentication middleware before any permission guards, and permission guards before body validation. The `before` hooks run in the order they are registered; `after` and `onError` hooks run in reverse order.

---

## Step 6: Initialize dependencies once

In serverless environments, database connections and services must be initialized once per process (cold start) and reused on warm starts. Use a singleton promise to prevent race conditions when multiple requests arrive during initialization:

```typescript
let initialized = false;
let initializationPromise: Promise<void> | null = null;

async function initializeDependencies(): Promise<void> {
  if (initialized && containerPool.isInitialized()) return;
  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  initializationPromise = (async () => {
    const db = await databaseService.connect();
    await initializeServices(db);
    containerPool.setInitialized();
    initialized = true;
  })();

  await initializationPromise;
}
```

> Do not re-initialize services on every request. Doing so adds 300–500 ms per request and defeats the purpose of warm starts.

---

## Step 7: Deploy to Google Cloud Functions

Wrap the handler with the GCP entry point and register it with the functions framework:

```typescript
import { http, HttpFunction } from '@google-cloud/functions-framework';
import { loginHandler } from './handlers.js';

const loginFunction: HttpFunction = async (req, res) => {
  try {
    await initializeDependencies();
    await loginHandler.execute(req, res);
  } catch (error) {
    if (error instanceof Error && error.message === 'RESPONSE_SENT') return;
    if (!res.headersSent) {
      res.status(500).json({ success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected error occurred' } });
    }
  }
};

http('login', loginFunction);
export const login = loginFunction;
```

---

## Step 8: Run locally with Fastify

Use `createFastifyHandler()` to adapt the same handler for local development. The handler itself is unchanged — only the entry point differs:

```typescript
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { loginHandler } from './handlers.js';

const server = Fastify({ logger: true });

const adapt = (handler: Handler<unknown>, name: string) =>
  createFastifyHandler(handler, name, initializeDependencies);

server.post('/api/auth/login', adapt(loginHandler, 'login'));

// Register graceful shutdown — without this, in-flight requests are dropped on SIGTERM
const shutdown = async () => {
  await server.close();
  await databaseService.disconnect();
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen({ port: 3000, host: '0.0.0.0' });
```

> Do not call `adaptFastifyRequest()` or `adaptFastifyResponse()` directly — `createFastifyHandler()` handles adaptation internally. Do not write a separate handler for Fastify; the same `Handler` instance must run on both runtimes.

---

## Common handler patterns

### Public endpoint (no auth, body validation only)

```typescript
export const loginHandler = new Handler<LoginRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(loginSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);
```

### Protected endpoint (auth required)

```typescript
export const logoutHandler = new Handler<LogoutRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new RequireAuthMiddleware())
  .use(new BodyValidationMiddleware(logoutSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(logoutController);
```

### Protected with permission check

```typescript
export const replaceConfigHandler = new Handler<ReplaceConfigRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new RequirePermissionMiddleware('config:write'))
  .use(new BodyValidationMiddleware(replaceConfigSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(replaceConfigController);
```

---

## Next steps

- Understand why the middleware chain and lifecycle work the way they do: [Architecture](../explanation/architecture.md)
- Understand how global and per-request dependencies are managed without cloning: [Container Model](../explanation/container-model.md)
- Full API signatures and parameter tables: [API Reference](../reference/api.md)
