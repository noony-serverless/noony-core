# Express to Fastify Integration Guide

## The Type Mismatch Problem

When integrating Noony with multiple HTTP frameworks, you'll encounter a fundamental type incompatibility:

- **Google Cloud Functions** (`@google-cloud/functions-framework`) expects **Express-like** `Request`/`Response` types
- **Fastify** uses its own `FastifyRequest`/`FastifyReply` types
- **Express** has `express.Request`/`express.Response`
- **Koa** uses a unified `Context` object

**The Challenge**: How can the same Noony handler work across all these frameworks without type errors or runtime failures?

---

## Noony's Solution: Dual Execution Model

Noony solves this through a **dual-execution architecture** with type adapters:

### 1. `execute()` - For Google Cloud Functions (Express-like)

```typescript
// src/core/handler.ts (lines 103-129)
async execute(req: CustomRequest<T>, res: CustomResponse): Promise<void> {
  // 1. AUTOMATIC ADAPTATION: GCP types → Generic types
  const genericReq = adaptGCPRequest<T>(req as unknown as Request);
  const genericRes = adaptGCPResponse(res as unknown as Response);

  // 2. Execute middleware pipeline with generic types
  const context = createContext<T, U>(genericReq, genericRes, { container });

  await this.executeBeforeMiddlewares(context);
  await this.handler(context);
  await this.executeAfterMiddlewares(context);
}
```

**Key Features:**
- Accepts GCP Functions `Request`/`Response` (Express-like types)
- **Automatically converts** to framework-agnostic types via built-in adapters
- Zero configuration needed - just call `handler.execute(req, res)`

### 2. `executeGeneric()` - For Any HTTP Framework

```typescript
// src/core/handler.ts (lines 174-200)
async executeGeneric(
  req: GenericRequest<T>,
  res: GenericResponse
): Promise<void> {
  // NO ADAPTATION - types already framework-agnostic!
  const context = createContext<T, U>(req, res, { container });

  await this.executeBeforeMiddlewares(context);
  await this.handler(context);
  await this.executeAfterMiddlewares(context);
}
```

**Key Features:**
- Accepts **already-adapted** `GenericRequest`/`GenericResponse`
- No internal type conversion - zero overhead
- You provide the adapter for your specific framework (Fastify, Express, Koa, etc.)

---

## Generic Type Flow Through the Pipeline

### Understanding Noony's Type Transformation

Noony uses a **smart type transformation** system that preserves full type safety through the entire middleware pipeline:

```typescript
// 1. Handler level - uses T and U as generic parameters
export class Handler<T = unknown, U = unknown> {
  execute(req: CustomRequest<T>, res: CustomResponse): Promise<void>
  executeGeneric(req: GenericRequest<T>, res: GenericResponse): Promise<void>
}

// 2. Context level - T → TBody, U → TUser (automatic transformation)
export interface Context<TBody = unknown, TUser = unknown> {
  readonly req: NoonyRequest<TBody>;  // TBody for request body type
  user?: TUser;                        // TUser for authenticated user type
  // ...
}

// 3. Middleware level - BaseMiddleware uses T and U
export interface BaseMiddleware<T = unknown, U = unknown> {
  before?: (context: Context<T, U>) => Promise<void>;
  after?: (context: Context<T, U>) => Promise<void>;
  onError?: (error: Error, context: Context<T, U>) => Promise<void>;
}

// 4. Implementation level - middlewares use TBody and TUser naming
export class BodyValidationMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>): Promise<void> {
    // context.req.parsedBody: TBody | undefined
    // context.user: TUser | undefined
  }
}
```

### Type Flow Diagram

```
Handler<T, U>
   ↓ (automatic transformation)
Context<TBody, TUser>  (where T → TBody, U → TUser)
   ↓
req: NoonyRequest<TBody>
   ├── parsedBody: TBody | undefined
   └── validatedBody: TBody | undefined
   ↓
user: TUser | undefined
```

**Why Two Naming Conventions?**

- **Handler/BaseMiddleware level**: Uses simple `T, U` for generic type parameters (standard TypeScript convention)
- **Context/Implementation level**: Uses descriptive `TBody, TUser` for clarity (makes code self-documenting)
- **Automatic mapping**: TypeScript automatically maps `T → TBody` and `U → TUser` when you use the Handler

### Type Aliases: NoonyRequest vs GenericRequest

Noony provides **modern type aliases** for better naming:

```typescript
// Recommended (modern naming - v0.3.0+)
export type NoonyRequest<T = unknown> = GenericRequest<T>;
export type NoonyResponse = GenericResponse;

// Legacy (still supported for backward compatibility)
export interface GenericRequest<T = unknown> { /* ... */ }
export interface GenericResponse { /* ... */ }
```

**Best Practice**: Use `NoonyRequest`/`NoonyResponse` in new code for clearer intent.

---

## Framework-Agnostic Type System

Noony defines minimal common interfaces that work across **all** HTTP frameworks:

### GenericRequest<T>

```typescript
// src/core/core.ts (lines 20-33)
export interface GenericRequest<T = unknown> {
  method: HttpMethod | string;
  url: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  params: Record<string, string>;
  body?: unknown;
  rawBody?: Buffer | string;
  parsedBody?: T;        // Set by BodyParserMiddleware
  validatedBody?: T;     // Set by BodyValidationMiddleware
  ip?: string;
  userAgent?: string;
}
```

### GenericResponse

```typescript
// src/core/core.ts (lines 38-47)
export interface GenericResponse {
  status(code: number): GenericResponse;
  json(data: unknown): GenericResponse | void;
  send(data: unknown): GenericResponse | void;
  header(name: string, value: string): GenericResponse;
  headers(headers: Record<string, string>): GenericResponse;
  end(): void;
  statusCode?: number;
  headersSent?: boolean;
}
```

**Design Principles:**
- **Minimal Common Denominator**: Only includes properties/methods available in ALL frameworks
- **Framework Neutral**: No Express/Fastify/Koa-specific features
- **Type Safe**: Generic `<T>` flows through entire pipeline for request body typing
- **Fluent Interface**: Chainable methods for developer ergonomics

---

## Practical Implementation Guide

### Step 1: Define Handlers Once (Framework-Agnostic)

```typescript
// src/handlers/user.handlers.ts
import { Handler, Context } from '@noony-serverless/core';
import { z } from 'zod';

// Define request schema
const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18).max(120),
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

interface AuthenticatedUser {
  userId: string;
  role: 'admin' | 'user';
  permissions: string[];
}

// Create handler - works in ALL environments!
export const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateUserRequest, AuthenticatedUser>) => {
    // ✅ Full type safety!
    const userData = context.req.validatedBody!;  // Type: CreateUserRequest
    const user = context.user!;                   // Type: AuthenticatedUser

    // Business logic - identical in ALL environments
    const newUser = await userService.create({
      ...userData,
      createdBy: user.userId,
    });

    return { success: true, data: newUser };
  });
```

**Key Points:**
- Handler defined **once** with full TypeScript type safety
- No framework-specific code in business logic
- Same code works in Fastify (local dev) AND GCP Functions (production)

---

### Step 2: Fastify Server (Local Development)

```typescript
// src/server.ts - Fast local development with hot reload
import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { Handler, GenericRequest, GenericResponse } from '@noony-serverless/core';
import { createUserHandler, getUserHandler } from './handlers/user.handlers';

const fastify = Fastify({ logger: true });

// Custom Fastify → Generic adapter
const executeHandler = async (
  handler: Handler,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> => {
  // 1. Adapt Fastify Request → GenericRequest
  const req: GenericRequest = {
    method: request.method,
    url: request.url,
    path: request.url.split('?')[0],
    headers: request.headers as Record<string, string | string[]>,
    query: (request.query as Record<string, string>) || {},
    params: (request.params as Record<string, string>) || {},
    body: request.body,
    ip: request.ip,
    userAgent: request.headers['user-agent'],
  };

  // 2. Wrap Fastify Reply → GenericResponse
  const res: GenericResponse = {
    status: (code: number): GenericResponse => {
      reply.status(code);
      res.statusCode = code;
      return res;
    },
    json: (data: unknown): void => {
      reply.type('application/json').send(data);
    },
    send: (data: unknown): void => {
      reply.send(data);
    },
    header: (name: string, value: string): GenericResponse => {
      reply.header(name, value);
      return res;
    },
    headers: (headers: Record<string, string>): GenericResponse => {
      Object.entries(headers).forEach(([key, value]) => {
        reply.header(key, value);
      });
      return res;
    },
    end: (): void => {
      reply.send();
    },
    statusCode: 200,
    headersSent: false,
  };

  try {
    // 3. Execute handler with generic types - NO type conversion!
    await handler.executeGeneric(req, res);
  } catch (error) {
    fastify.log.error(`Unhandled error: ${error}`);
    if (!reply.sent) {
      reply.status(500).send({
        success: false,
        error: 'Internal Server Error',
      });
    }
  }
};

// Register routes - use same handlers as production!
fastify.post('/api/users', async (request, reply) => {
  await executeHandler(createUserHandler, request, reply);
});

fastify.get('/api/users/:id', async (request, reply) => {
  await executeHandler(getUserHandler, request, reply);
});

// Start server
fastify.listen({ port: 3000 }, (err) => {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
  fastify.log.info('Server running on http://localhost:3000');
});
```

**Key Points:**
- **Custom adapter function** (`executeHandler`) converts Fastify types to Generic types
- **Same handlers** (`createUserHandler`, etc.) used as in production
- **Fast local development** with Fastify's performance and hot reload
- **Use `executeGeneric()`** - no internal type conversion overhead

---

### Step 3: GCP Functions Export (Production)

```typescript
// src/createUser.ts - Production deployment
import { http } from '@google-cloud/functions-framework';
import { createUserHandler } from './handlers/user.handlers';

// ✅ Direct execution - built-in GCP adapter handles everything!
export const createUser = http('createUser', (req, res) => {
  return createUserHandler.execute(req, res);
});
```

```typescript
// src/getUser.ts
import { http } from '@google-cloud/functions-framework';
import { getUserHandler } from './handlers/user.handlers';

export const getUser = http('getUser', (req, res) => {
  return getUserHandler.execute(req, res);
});
```

**Key Points:**
- **Minimal wrapper** - just call `handler.execute(req, res)`
- **Built-in adapter** - `execute()` automatically converts GCP types to Generic types
- **Same handlers** as local development - zero business logic changes
- **Use `execute()`** - automatic GCP Functions type adaptation

---

## When to Use Each Method

### Use `handler.execute(req, res)` When:

✅ Deploying to **Google Cloud Functions**
✅ Working with **Express-like Request/Response** types
✅ You want **automatic type conversion** with zero configuration

**Example:**
```typescript
export const myFunction = http('myFunction', (req, res) => {
  return handler.execute(req, res);  // ✅ Built-in GCP adapter
});
```

### Use `handler.executeGeneric(req, res)` When:

✅ Working with **Fastify** (local dev)
✅ Working with **Koa**, **Hapi**, or any custom HTTP framework
✅ You've already adapted types to `GenericRequest`/`GenericResponse`
✅ You want **zero overhead** (no internal conversion)

**Example:**
```typescript
fastify.post('/api/users', async (request, reply) => {
  const req = adaptFastifyRequest(request);
  const res = adaptFastifyResponse(reply);
  await handler.executeGeneric(req, res);  // ✅ No conversion needed
});
```

---

## Built-in GCP Adapters

Noony provides built-in adapters for Google Cloud Functions:

### adaptGCPRequest

```typescript
// src/core/core.ts (lines 146-161)
export function adaptGCPRequest<T = unknown>(
  gcpRequest: Request
): GenericRequest<T> {
  return {
    method: (gcpRequest.method as HttpMethod) || HttpMethod.GET,
    url: gcpRequest.url || '/',
    path: gcpRequest.path,
    headers: (gcpRequest.headers as Record<string, string>) || {},
    query: (gcpRequest.query as Record<string, string>) || {},
    params: (gcpRequest.params as Record<string, string>) || {},
    body: gcpRequest.body,
    rawBody: gcpRequest.rawBody,
    ip: gcpRequest.ip,
    userAgent: gcpRequest.get?.('user-agent'),
  };
}
```

### adaptGCPResponse

```typescript
// src/core/core.ts (lines 166-205)
export function adaptGCPResponse(gcpResponse: Response): GenericResponse {
  let currentStatusCode = 200;
  let isHeadersSent = false;

  return {
    status: (code: number): GenericResponse => {
      currentStatusCode = code;
      gcpResponse.status(code);
      return adaptGCPResponse(gcpResponse); // Re-wrap for chaining
    },
    json: (data: unknown): void => {
      isHeadersSent = true;
      gcpResponse.json(data);
    },
    send: (data: unknown): void => {
      isHeadersSent = true;
      gcpResponse.send(data);
    },
    header: (name: string, value: string): GenericResponse => {
      gcpResponse.header(name, value);
      return adaptGCPResponse(gcpResponse);
    },
    headers: (headers: Record<string, string>): GenericResponse => {
      Object.entries(headers).forEach(([key, value]) => {
        gcpResponse.header(key, value);
      });
      return adaptGCPResponse(gcpResponse);
    },
    end: (): void => {
      isHeadersSent = true;
      gcpResponse.end();
    },
    get statusCode(): number {
      return gcpResponse.statusCode || currentStatusCode;
    },
    get headersSent(): boolean {
      return gcpResponse.headersSent || isHeadersSent;
    },
  };
}
```

**Adapter Strategy:**
- **Wrapper pattern** - wraps GCP Response methods with GenericResponse interface
- **State tracking** - maintains local state for `statusCode` and `headersSent`
- **Delegation** - forwards all operations to underlying GCP Response
- **Re-wrapping** - returns new wrapper for method chaining

---

## Custom Framework Adapters

You can create adapters for **any HTTP framework**:

### Express Adapter

```typescript
function adaptExpressRequest(req: express.Request): GenericRequest {
  return {
    method: req.method,
    url: req.url,
    path: req.path,
    headers: req.headers as Record<string, string>,
    query: req.query as Record<string, string>,
    params: req.params,
    body: req.body,
    ip: req.ip,
    userAgent: req.get('user-agent'),
  };
}

function adaptExpressResponse(res: express.Response): GenericResponse {
  return {
    status: (code: number) => {
      res.status(code);
      return adaptExpressResponse(res);
    },
    json: (data: unknown) => {
      res.json(data);
    },
    send: (data: unknown) => {
      res.send(data);
    },
    header: (name: string, value: string) => {
      res.header(name, value);
      return adaptExpressResponse(res);
    },
    // ... other methods
  };
}

// Usage
app.post('/api/users', async (req, res) => {
  const genericReq = adaptExpressRequest(req);
  const genericRes = adaptExpressResponse(res);
  await handler.executeGeneric(genericReq, genericRes);
});
```

### Koa Adapter

```typescript
function adaptKoaContext(ctx: Koa.Context): {
  req: GenericRequest;
  res: GenericResponse;
} {
  const req: GenericRequest = {
    method: ctx.method,
    url: ctx.url,
    path: ctx.path,
    headers: ctx.headers,
    query: ctx.query as Record<string, string>,
    params: ctx.params,
    body: ctx.request.body,
    ip: ctx.ip,
    userAgent: ctx.get('user-agent'),
  };

  const res: GenericResponse = {
    status: (code: number) => {
      ctx.status = code;
      return res;
    },
    json: (data: unknown) => {
      ctx.body = data;
      ctx.type = 'application/json';
    },
    send: (data: unknown) => {
      ctx.body = data;
    },
    header: (name: string, value: string) => {
      ctx.set(name, value);
      return res;
    },
    // ... other methods
  };

  return { req, res };
}

// Usage
router.post('/api/users', async (ctx) => {
  const { req, res } = adaptKoaContext(ctx);
  await handler.executeGeneric(req, res);
});
```

---

## Architecture Benefits

### 1. Write Once, Deploy Anywhere

```typescript
// Define handler ONCE
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // Business logic
  });

// Use in Fastify (local dev)
fastify.post('/users', (req, reply) =>
  executeHandler(handler, req, reply)
);

// Use in GCP Functions (production)
export const createUser = http('createUser', (req, res) =>
  handler.execute(req, res)
);

// Use in Express (alternative)
app.post('/users', (req, res) =>
  handler.executeGeneric(adaptExpress(req), adaptExpress(res))
);
```

### 2. Full Type Safety Preserved

```typescript
interface CreateUserRequest {
  name: string;
  email: string;
}

interface AuthUser {
  userId: string;
  role: 'admin' | 'user';
}

const handler = new Handler<CreateUserRequest, AuthUser>()
  .handle(async (context) => {
    // ✅ Full autocomplete and type checking!
    const body = context.req.validatedBody;  // Type: CreateUserRequest | undefined
    const user = context.user;               // Type: AuthUser | undefined

    if (user?.role === 'admin') {
      // TypeScript knows user.role is 'admin' | 'user'
    }
  });
```

### 3. Zero Framework Lock-in

- Business logic completely isolated from HTTP framework
- Easy to migrate between frameworks (Fastify → Express → Koa)
- Only the **entry point adapter** changes, not the handler code

### 4. Performance Optimized

| Method | Type Conversion | Overhead | Use Case |
|--------|----------------|----------|----------|
| `execute()` | Automatic (built-in) | One-time adaptation | GCP Functions production |
| `executeGeneric()` | Manual (you provide) | Zero overhead | Fastify/Express local dev |

### 5. Development Experience

```
Local Development (Fast Iteration):
┌─────────────┐
│   Fastify   │ ← Hot reload, fast startup
│   Server    │ ← Same handlers as production
└─────────────┘

Production Deployment (Serverless):
┌─────────────┐
│ GCP Functions│ ← Same business logic
│  (Express)   │ ← Zero code changes
└─────────────┘
```

---

## Complete Working Example

### Project Structure

```
src/
├── handlers/
│   └── user.handlers.ts      # Handler definitions (framework-agnostic)
├── server.ts                  # Fastify server (local dev)
├── createUser.ts              # GCP Function export (production)
└── getUser.ts                 # GCP Function export (production)
```

### handlers/user.handlers.ts

```typescript
import { Handler, Context } from '@noony-serverless/core';
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

export const createUserHandler = new Handler<CreateUserRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context: Context<CreateUserRequest>) => {
    const { name, email } = context.req.validatedBody!;
    const user = await userService.create({ name, email });
    return { success: true, data: user };
  });
```

### server.ts (Fastify - Local Dev)

```typescript
import Fastify from 'fastify';
import { createUserHandler } from './handlers/user.handlers';

const fastify = Fastify();

fastify.post('/api/users', async (request, reply) => {
  const req = adaptFastifyRequest(request);
  const res = adaptFastifyResponse(reply);
  await createUserHandler.executeGeneric(req, res);  // ✅ No type conversion
});

fastify.listen({ port: 3000 });
```

### createUser.ts (GCP Functions - Production)

```typescript
import { http } from '@google-cloud/functions-framework';
import { createUserHandler } from './handlers/user.handlers';

export const createUser = http('createUser', (req, res) => {
  return createUserHandler.execute(req, res);  // ✅ Automatic GCP adapter
});
```

---

## Best Practices

### ✅ DO

1. **Define handlers once** in framework-agnostic way
2. **Use `executeGeneric()`** for Fastify/Express/Koa (local dev)
3. **Use `execute()`** for GCP Functions (production)
4. **Write custom adapters** for each framework you use
5. **Keep business logic** completely framework-independent

### ❌ DON'T

1. **Don't call GCP `http()` wrapper in Fastify** - type mismatch!
2. **Don't duplicate handlers** for different frameworks
3. **Don't put framework-specific code** in handlers
4. **Don't skip type adaptation** - causes runtime errors
5. **Don't mix `execute()` and `executeGeneric()`** for same framework

---

## Common Pitfalls

### ❌ Calling HttpFunction in Fastify

```typescript
// ❌ WRONG - Type mismatch!
import { createUser } from './createUser';  // HttpFunction

fastify.post('/api/users', async (request, reply) => {
  // createUser expects Express Request/Response, not Fastify!
  await createUser(request, reply);  // 💥 Runtime error
});
```

**Solution:**
```typescript
// ✅ CORRECT - Use handler directly
import { createUserHandler } from './handlers/user.handlers';

fastify.post('/api/users', async (request, reply) => {
  await executeHandler(createUserHandler, request, reply);  // ✅ Works!
});
```

### ❌ Forgetting Type Adaptation

```typescript
// ❌ WRONG - Fastify types passed directly
await handler.executeGeneric(request, reply);  // 💥 Type error
```

**Solution:**
```typescript
// ✅ CORRECT - Adapt Fastify → Generic
const req = adaptFastifyRequest(request);
const res = adaptFastifyResponse(reply);
await handler.executeGeneric(req, res);  // ✅ Works!
```

---

## Summary

Noony achieves **true framework-agnostic portability** through:

1. **Dual execution model**: `execute()` for GCP, `executeGeneric()` for everything else
2. **Adapter pattern**: Convert framework types → `GenericRequest`/`GenericResponse`
3. **Type preservation**: Generics `<TBody, TUser>` flow through entire pipeline
4. **Minimal interface**: Common HTTP operations only
5. **Zero business logic changes**: Same handlers work everywhere

**Result**: Write your handlers once, deploy to any HTTP framework or serverless platform with minimal wrapper code and full type safety! 🎯
