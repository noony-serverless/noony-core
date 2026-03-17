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

    // No framework-specific code!
    context.res.status(201).json({ data: newUser });
  });

// No mention of Cloud Functions or Fastify!
// This handler works everywhere.
```

## Step 2: Cloud Functions Entry Point

Deploy to Google Cloud Functions:

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { createUserHandler } from './handlers/user.handler';
import { initializeDependencies } from './config/di.config';

// Export function for Cloud Functions runtime
export const createUser = http('createUser', async (req, res) => {
  // Initialize dependencies once per process
  await initializeDependencies();

  // Execute handler with Cloud Functions' req/res
  // handler.execute() adapts req/res to GenericRequest/GenericResponse
  await createUserHandler.execute(req, res);
});
```

## Step 3: Fastify Entry Point

Enable local development with Fastify:

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers/user.handler';
import { initializeDependencies } from './config/di.config';

const server = Fastify({ logger: true });

// Use createFastifyHandler() wrapper
// Same handler, different entry point!
server.post(
  '/api/users',
  createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
);

// Start server
server.listen({ port: 3000 }, (err, address) => {
  if (err) throw err;
  console.log(`Server listening on ${address}`);
});
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
  .handle(async (context) => {
    const { email, name, age } = context.req.validatedBody!;
    const user = await userService.create({ email, name, age });
    context.res.status(201).json({ data: user });
  });
```

### Step 2: Use in Cloud Functions

```typescript
// src/functions.ts
export const createUser = http('createUser', async (req, res) => {
  await initializeDependencies();
  await createUserHandler.execute(req, res);
});
```

### Step 3: Use in Fastify

```typescript
// src/server.ts
server.post(
  '/api/users',
  createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
);
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
export const createUser = http('createUser', async (req, res) => {
  await createUserHandler.execute(req, res); // Database not connected!
});

// CORRECT
export const createUser = http('createUser', async (req, res) => {
  await initializeDependencies(); // Connect database first
  await createUserHandler.execute(req, res);
});
```

### Gotcha 2: Using Wrong Execution Method

```typescript
// WRONG - execute() expects native GCP/Express req/res
await handler.executeGeneric(cloudFunctionsReq, cloudFunctionsRes);

// CORRECT for Cloud Functions
await handler.execute(req, res);

// CORRECT for Fastify
createFastifyHandler(handler, 'name', initFn);
```

### Gotcha 3: Missing Request ID Tracking

```typescript
// WRONG - Different trace IDs locally and in production

// CORRECT - Use OpenTelemetryMiddleware in both
const handler = new Handler()
  .use(new OpenTelemetryMiddleware())
  .handle(...);
// Same tracing behavior everywhere
```
