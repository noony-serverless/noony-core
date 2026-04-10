# Skill 02: Convert Cloud Functions to Fastify - Dual-Entry Pattern

## Overview

The beauty of Noony Framework is that **the exact same handler code runs in both Cloud Functions and Fastify**. No refactoring needed - just different entry points. This skill shows how to leverage the same handler in local (Fastify) and production (Cloud Functions) environments.

## Architecture: Same Handler, Two Deployments

```
Handler Code (src/handlers/user.handler.ts)
    |
    +-- Cloud Functions Entry Point
    |   (src/functions.ts)
    |   +-- execute(req, res)
    |   +-- Deploy to GCP
    |
    +-- Fastify Entry Point
        (src/server.ts)
        +-- createFastifyHandler()
        +-- npm run dev
```

**Key Insight:** The handler doesn't care about the HTTP framework - it works with `GenericRequest` and `GenericResponse` interfaces that both Cloud Functions and Fastify adapt to.

## Step 1: Define Handler (Framework-Agnostic)

Create handler once, use everywhere:

```typescript
// src/handlers/user.handler.ts
import { Handler, Context } from '@noony-serverless/core';
import { z } from 'zod';
import { BodyValidationMiddleware } from '@noony-serverless/core';

// 1. Define request type
const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1),
  age: z.number().min(18)
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

// 2. Define user type
interface AuthUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

// 3. Create handler (completely framework-agnostic)
export const createUserHandler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateUserRequest, AuthUser>) => {
    const { email, name, age } = context.req.validatedBody!;
    const user = context.user!;

    // Business logic here
    const newUser = await userService.create({
      email,
      name,
      age,
      createdBy: user.id
    });

    // Return the value — ResponseWrapperMiddleware sends { success: true, payload: newUser }
    // Never call context.res.status().json() — always return from the handler.
    return newUser;
  });

// No mention of Cloud Functions or Fastify!
// This handler works everywhere.
```

## Step 2: Cloud Functions Entry Point

Deploy to Google Cloud Functions using `server.inject()` — NOT `server.routing()` or `handler.execute()` directly.
Pass GCF's `req.rawBody` Buffer as the inject payload so `addContentTypeParser` receives original bytes (required for routes that verify request signatures).

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { extractAndStoreRequestBody, CloudFunctionRequest } from '@noony-serverless/core';
import { server, initializeDependencies } from './server';

let serverReady = false;

async function ensureServerReady(): Promise<void> {
  if (serverReady) return;
  await initializeDependencies();
  await server.ready();
  serverReady = true;
}

http('myHandler', async (req, res) => {
  try {
    await ensureServerReady();

    // GCF sets req.rawBody as Buffer with original bytes before JSON parsing.
    // Pass it as payload so addContentTypeParser receives the real bytes.
    const gcfRawBody: Buffer | undefined = (req as any).rawBody;
    extractAndStoreRequestBody(req);  // fallback: stores re-parsed body on req.__rawBody
    const payload = gcfRawBody ?? (req as unknown as CloudFunctionRequest).__rawBody;

    const response = await server.inject({
      method: req.method as any,
      url: req.url || '/',
      headers: req.headers as Record<string, string>,
      payload,  // ← original Buffer flows to addContentTypeParser → rawBodyBuffer
    });

    res.statusCode = response.statusCode;
    for (const [key, value] of Object.entries(response.headers)) {
      if (value !== undefined) res.setHeader(key, value as string);
    }
    res.end(response.payload);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[myHandler] error', { message, url: req.url });
    res.statusCode = 500;
    res.end(JSON.stringify({ success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: 'An error occurred' } }));
  }
});
```

> **Anti-patterns**
> - `server.routing(req, res)` — response never terminates, causes upstream request timeout
> - `handler.execute(req, res)` in GCF when you need rawBody in Fastify — bypasses Fastify entirely

## Step 3: Fastify Entry Point

Two patterns depending on whether the route needs `rawBody`:

**Standard routes** (no rawBody needed) — use `createFastifyHandler`:

```typescript
// src/functions.ts (Fastify server setup)
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers/user.handler';
import { initializeDependencies } from './config/di.config';

export const server = Fastify({ logger: true });

// MUST register addContentTypeParser BEFORE routes when any route needs rawBody
server.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body as string, 'utf8');
  (req as unknown as { rawBodyBuffer: Buffer }).rawBodyBuffer = buf;
  try {
    done(null, JSON.parse(buf.toString('utf8')));
  } catch (err) {
    done(err as Error, undefined);
  }
});

// Standard routes — createFastifyHandler (rawBody not populated)
server.post('/api/users', createFastifyHandler(createUserHandler, 'createUser', initializeDependencies));
server.get('/health', createFastifyHandler(healthHandler, 'health', initializeDependencies));
```

**Routes needing rawBody** (webhook signature verification) — use `executeGeneric` with custom adapter.
See **`noony-custom-adapter`** skill for full pattern. Summary:

```typescript
import type { FastifyRequest, FastifyReply } from 'fastify';
import type { GenericRequest, GenericResponse, Handler } from '@noony-serverless/core';
import { isResponseAlreadySent, INTERNAL_ERROR_RESPONSE } from '@noony-serverless/core';

function adaptFastifyRequestWithRawBody<T = unknown>(req: FastifyRequest): GenericRequest<T> {
  const rawBuf = (req as unknown as { rawBodyBuffer?: Buffer }).rawBodyBuffer;
  return {
    method: req.method, url: req.url,
    path: (req.routeOptions as unknown as { url?: string })?.url ?? req.url,
    headers: req.headers as Record<string, string | string[] | undefined>,
    query: (req.query as Record<string, string | string[] | undefined>) ?? {},
    params: (req.params as Record<string, string>) ?? {},
    body: req.body, parsedBody: req.body as T,
    rawBody: rawBuf,          // ← original bytes for signature verification
    ip: req.ip, userAgent: req.headers['user-agent'],
  };
}

function adaptFastifyReply(reply: FastifyReply): GenericResponse {
  let statusCode = 200, headersSent = false;
  const res: GenericResponse = {
    status(code) { statusCode = code; reply.code(code); return res; },
    json(data) { if (reply.sent) return res; headersSent = true; reply.send(data); return res; },
    send(data) { if (reply.sent) return res; headersSent = true; reply.send(data); return res; },
    header(name, val) { reply.header(name, val); return res; },
    headers(hdrs) { for (const k in hdrs) reply.header(k, hdrs[k]); return res; },
    end() { if (!reply.sent) { headersSent = true; reply.send(); } },
    get statusCode() { return statusCode; },
    get headersSent() { return headersSent || reply.sent; },
  };
  return res;
}

function adaptWithRawBody(handler: Handler<any, any>, initFn: () => Promise<void>) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    await initFn();
    try {
      await handler.executeGeneric(adaptFastifyRequestWithRawBody(req), adaptFastifyReply(reply));
    } catch (error) {
      if (isResponseAlreadySent(error)) return;
      if (!reply.sent) reply.code(500).send(INTERNAL_ERROR_RESPONSE);
    }
  };
}

// Routes needing rawBody — use executeGeneric with custom adapter
server.get('/webhook/:id', adaptWithRawBody(challengeHandler, initializeDependencies));
server.post('/webhook/:id', adaptWithRawBody(notificationHandler, initializeDependencies));
```

## Step 4: Shared Configuration

Both environments share the same dependencies and config:

```typescript
// src/config/di.config.ts
import { containerPool } from '@noony-serverless/core';
import { DatabaseService } from '../services/database.service';
import { UserService } from '../services/user.service';

let initialized = false;

export async function initializeDependencies(): Promise<void> {
  // Prevent re-initialization (Cloud Functions reuses container)
  if (initialized && containerPool.isInitialized()) {
    return;
  }

  // Initialize database
  const database = new DatabaseService();
  await database.connect();

  // Register global services
  containerPool.initializeGlobal([
    { id: 'Database', value: database },
    { id: 'UserService', value: new UserService(database) }
  ]);

  initialized = true;
}
```

## Migration Checklist: Cloud Functions -> Fastify

### Step 1: Extract Handler Logic

**Before (Tightly Coupled):**
```typescript
// OLD - Cloud Functions specific
export const createUser = http('createUser', async (req, res) => {
  try {
    const { email, name, age } = req.body;

    if (!email || !name) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const user = await userService.create({ email, name, age });
    res.status(201).json({ data: user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});
```

**After (Framework-Agnostic):**
```typescript
// NEW - Works everywhere
const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1),
  age: z.number().min(18)
});

export const createUserHandler = new Handler<z.infer<typeof createUserSchema>>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { email, name, age } = context.req.validatedBody!;
    const user = await userService.create({ email, name, age });
    // Return the value — never call context.res.status().json()
    return user;
  });
```

### Step 2: Use in Cloud Functions

Use `server.inject()` — do NOT call `handler.execute()` directly (bypasses Fastify) or `server.routing()` (causes timeout).

```typescript
// src/functions.ts
http('createUser', async (req, res) => {
  await ensureServerReady();
  const gcfRawBody: Buffer | undefined = (req as any).rawBody;
  extractAndStoreRequestBody(req);
  const payload = gcfRawBody ?? (req as unknown as CloudFunctionRequest).__rawBody;
  const response = await server.inject({
    method: req.method as any, url: req.url || '/',
    headers: req.headers as Record<string, string>, payload,
  });
  res.statusCode = response.statusCode;
  for (const [k, v] of Object.entries(response.headers)) {
    if (v !== undefined) res.setHeader(k, v as string);
  }
  res.end(response.payload);
});
```

### Step 3: Use in Fastify

Standard routes use `createFastifyHandler`. Routes needing rawBody (webhooks, signature verification) use `executeGeneric` with a custom adapter — see **`noony-custom-adapter`** skill.

```typescript
// Standard route
server.post('/api/users', createFastifyHandler(createUserHandler, 'createUser', initializeDependencies));

// Webhook route needing rawBody
server.post('/webhook/:id', adaptWithRawBody(webhookHandler, initializeDependencies));
```

## Testing Locally Before Deploy

Use Fastify to test handlers with real dependencies:

```typescript
// test/integration.test.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from '../src/handlers/user.handler';
import { initializeDependencies } from '../src/config/di.config';

describe('User Handler Integration', () => {
  let app: any;

  beforeAll(async () => {
    app = Fastify();
    app.post(
      '/api/users',
      createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
    );
  });

  it('should create user successfully', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/users',
      headers: { Authorization: `Bearer ${token}` },
      payload: {
        email: 'new@example.com',
        name: 'New User',
        age: 30
      }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().data.id).toBeDefined();
  });

  it('should reject invalid email', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/users',
      headers: { Authorization: `Bearer ${token}` },
      payload: {
        email: 'invalid-email',
        name: 'User',
        age: 30
      }
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error.code).toBe('VALIDATION_ERROR');
  });
});
```

## Performance Comparison

| Metric | Fastify (Local) | Cloud Functions | Fastify Benefits |
|--------|-----------------|-----------------|------------------|
| Startup Time | 150ms | 3000ms+ | ~20x faster |
| Request Time | 5-10ms | 50-200ms | ~10x faster |
| Iteration Speed | 1s (code save) | 5min+ (deploy) | 300x faster |
| Debugging | Full local tools | Cloud Logging | Immensely better |

## npm Scripts

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "test": "jest",
    "deploy": "npm run build && gcloud functions deploy myFunctions --source dist/"
  }
}
```

## Common Gotchas

### Gotcha 1: Forgetting initializeDependencies

```typescript
// WRONG - Dependencies not initialized
http('myHandler', async (req, res) => {
  await server.inject({ ... }); // Database not connected!
});

// CORRECT
http('myHandler', async (req, res) => {
  await ensureServerReady(); // connects DB + awaits server.ready()
  await server.inject({ ... });
});
```

### Gotcha 2: Using Wrong Execution Method

```typescript
// WRONG - execute() with Fastify req/res
await handler.execute(fastifyReq, fastifyReply);

// CORRECT for Cloud Functions (native req/res)
await handler.execute(gcfReq, gcfRes);

// CORRECT for Fastify without rawBody
server.post('/api/users', createFastifyHandler(handler, 'name', initFn));

// CORRECT for Fastify with rawBody (webhook signatures)
server.post('/webhook/:id', adaptWithRawBody(handler, initFn)); // uses executeGeneric
```

### Gotcha 3: Using JSON.stringify as rawBody

```typescript
// WRONG - re-serialized bytes differ from original; signature verification fails
const rawBody = JSON.stringify(req.body);

// CORRECT - pass GCF's original Buffer through server.inject → addContentTypeParser → rawBodyBuffer
const gcfRawBody: Buffer | undefined = (req as any).rawBody;
const payload = gcfRawBody ?? (req as unknown as CloudFunctionRequest).__rawBody;
await server.inject({ ..., payload });
// Then in middleware: context.req.rawBody (Buffer set by custom adapter)
```

### Gotcha 4: Using server.routing() in GCF

```typescript
// WRONG - response is never terminated, causes upstream timeout
http('myHandler', async (req, res) => {
  await server.routing(req, res);
});

// CORRECT - use server.inject() and forward the response manually
http('myHandler', async (req, res) => {
  const response = await server.inject({ ... });
  res.statusCode = response.statusCode;
  res.end(response.payload);
});
```

### Gotcha 5: Top-level await in functions.ts

```typescript
// WRONG - forces ESM (TLA), breaks require() used by GCF Functions Framework
const db = await connectDB();

// CORRECT - wrap in guarded async function, build with --format=cjs
async function ensureServerReady() {
  if (serverReady) return;
  await initializeDependencies();
  await server.ready();
  serverReady = true;
}
```

### Gotcha 6: Missing Request ID Tracking

```typescript
// WRONG - Different trace IDs locally and in production

// CORRECT - Use OpenTelemetryMiddleware in both
const handler = new Handler()
  .use(new OpenTelemetryMiddleware())
  .handle(...);
// Same tracing behavior everywhere
```
