# Skill 02: Convert Cloud Functions to Fastify - Dual-Entry Pattern

## Overview

The beauty of Noony Framework is that **the exact same handler code runs in both Cloud Functions and Fastify**. No refactoring needed - just different entry points. This skill shows how to leverage the same handler in local (Fastify) and production (Cloud Functions) environments.

## Architecture: Same Handler, Two Deployments

```
Handler Code (src/handlers/user.handler.ts)
    ↓
    ├─→ Cloud Functions Entry Point
    │   (src/functions.ts)
    │   ├─→ execute(req, res)
    │   ├─→ Deploy to GCP
    │
    └─→ Fastify Entry Point
        (src/server.ts)
        ├─→ createFastifyHandler()
        ├─→ npm run dev
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

**Deploy Command:**

```bash
# Deploy to Cloud Functions
gcloud functions deploy createUser \
  --runtime nodejs18 \
  --entry-point createUser \
  --trigger-http

# Test
curl -X POST https://us-central1-myproject.cloudfunctions.net/createUser \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"user@example.com","name":"John","age":30}'
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

**Start Local Development:**

```bash
# Install dependencies
npm install

# Start Fastify server
npm run dev

# Test locally
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"user@example.com","name":"John","age":30}'
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

// src/config/auth.config.ts
import jwt from 'jsonwebtoken';
import { CustomTokenVerificationPort } from '@noony-serverless/core';

interface AuthUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

export const tokenVerifier: CustomTokenVerificationPort<AuthUser> = {
  async verifyToken(token: string): Promise<AuthUser> {
    const secret = process.env.JWT_SECRET!;
    const payload = jwt.verify(token, secret) as any;

    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role
    };
  }
};
```

## Complete Project Structure

```
my-api/
├── src/
│   ├── config/
│   │   ├── di.config.ts        # Shared DI setup
│   │   └── auth.config.ts      # Shared auth setup
│   ├── handlers/
│   │   ├── user.handler.ts     # Framework-agnostic
│   │   └── post.handler.ts     # Framework-agnostic
│   ├── services/
│   │   ├── user.service.ts
│   │   ├── post.service.ts
│   │   └── database.service.ts
│   ├── functions.ts            # Cloud Functions entry points
│   ├── server.ts               # Fastify entry point
│   └── index.ts
├── package.json
├── tsconfig.json
└── .env

# Running
npm run dev        # Fastify: http://localhost:3000
npm run build
npm run deploy     # Cloud Functions
```

## Migration Checklist: Cloud Functions → Fastify

If you have existing Cloud Functions handlers, convert them this way:

### ✅ Step 1: Extract Handler Logic

**Before (Tightly Coupled):**
```typescript
// ❌ OLD - Cloud Functions specific
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
// ✅ NEW - Works everywhere
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

### ✅ Step 2: Use in Cloud Functions

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { createUserHandler } from './handlers/user.handler';

export const createUser = http('createUser', async (req, res) => {
  await initializeDependencies();
  await createUserHandler.execute(req, res);
});
```

### ✅ Step 3: Use in Fastify

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers/user.handler';

const server = Fastify();

server.post(
  '/api/users',
  createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
);
```

### ✅ Step 4: Test Locally

```bash
npm run dev
# Test: curl -X POST http://localhost:3000/api/users ...
```

### ✅ Step 5: Deploy to Production

```bash
npm run build && npm run deploy
# Cloud Functions: curl -X POST https://<cloud-function-url>/createUser ...
```

**No Code Changes Between Steps 4 and 5!**

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
    const token = jwt.sign({ sub: 'admin-1', role: 'admin' }, secret);

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
    const token = jwt.sign({ sub: 'admin-1', role: 'admin' }, secret);

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
| Memory (Per Request) | ~2MB | ~50MB | ~25x smaller |
| Iteration Speed | 1s (code save) | 5min+ (deploy) | 300x faster |
| Debugging | Full local tools | Cloud Logging | Immensely better |

**Development Workflow Impact:**
- With Fastify: 1 minute iteration cycle
- Without Fastify: 10+ minute deployment cycle
- Time saved per day: 2+ hours
- Developer satisfaction: Immeasurably higher

## Multi-Handler Fastify Setup

Register multiple handlers on different routes:

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import {
  createUserHandler,
  getUserHandler,
  updateUserHandler,
  deleteUserHandler
} from './handlers/user.handlers';
import { initializeDependencies } from './config/di.config';

const server = Fastify({ logger: true });

// POST /api/users
server.post(
  '/api/users',
  createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
);

// GET /api/users/:userId
server.get(
  '/api/users/:userId',
  createFastifyHandler(getUserHandler, 'getUser', initializeDependencies)
);

// PATCH /api/users/:userId
server.patch(
  '/api/users/:userId',
  createFastifyHandler(updateUserHandler, 'updateUser', initializeDependencies)
);

// DELETE /api/users/:userId
server.delete(
  '/api/users/:userId',
  createFastifyHandler(deleteUserHandler, 'deleteUser', initializeDependencies)
);

server.listen({ port: 3000 });
```

## Dual-Entry Functions File

Export all handlers for Cloud Functions:

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import {
  createUserHandler,
  getUserHandler,
  updateUserHandler,
  deleteUserHandler
} from './handlers/user.handlers';
import { initializeDependencies } from './config/di.config';

// All handlers use the same execute() method
export const createUser = http('createUser', async (req, res) => {
  await initializeDependencies();
  await createUserHandler.execute(req, res);
});

export const getUser = http('getUser', async (req, res) => {
  await initializeDependencies();
  await getUserHandler.execute(req, res);
});

export const updateUser = http('updateUser', async (req, res) => {
  await initializeDependencies();
  await updateUserHandler.execute(req, res);
});

export const deleteUser = http('deleteUser', async (req, res) => {
  await initializeDependencies();
  await deleteUserHandler.execute(req, res);
});
```

## Environment-Specific Configuration

Handle local vs production configuration:

```typescript
// src/config/env.config.ts
export const config = {
  // Database
  databaseUrl: process.env.DATABASE_URL ||
    'postgresql://localhost:5432/myapp',

  // JWT
  jwtSecret: process.env.JWT_SECRET ||
    'dev-secret-key',

  // Logging
  logLevel: process.env.LOG_LEVEL ||
    (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),

  // Environment
  isDevelopment: process.env.NODE_ENV !== 'production',
  isProduction: process.env.NODE_ENV === 'production'
};
```

## npm Scripts

Setup efficient development and deployment:

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/",
    "format": "prettier --write src/",
    "deploy": "npm run build && gcloud functions deploy myFunctions --source dist/",
    "deploy:watch": "npm run build && gcloud functions deploy --runtime nodejs18 --entry-point myFunction --trigger-http"
  }
}
```

## Anti-Patterns to Avoid

### ❌ Different Code for Different Platforms

```typescript
// WRONG - Duplicate handlers
const createUserFastify = async (req: FastifyRequest) => {
  // Fastify-specific code
};

const createUserCloudFunctions = async (req: CloudFunctionsRequest) => {
  // Cloud Functions-specific code
};
```

### ✅ One Handler, Multiple Entry Points

```typescript
// CORRECT - Same handler everywhere
const createUserHandler = new Handler<CreateUserRequest>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // Framework-agnostic code
  });

// Use in Fastify
server.post('/api/users',
  createFastifyHandler(createUserHandler, ...)
);

// Use in Cloud Functions
export const createUser = http('createUser', async (req, res) => {
  await createUserHandler.execute(req, res);
});
```

### ❌ Tight Coupling to Framework

```typescript
// WRONG - Cloud Functions specific
const handler = new Handler()
  .handle(async (context) => {
    // Assuming context.req is specifically Express-like
    const queryParam = context.req.query.param;
  });
```

### ✅ Framework-Agnostic

```typescript
// CORRECT - Works with any adapter
const handler = new Handler()
  .handle(async (context) => {
    // Works with GenericRequest
    const queryParam = context.req.query.param;
  });
```

## Common Gotchas

### Gotcha 1: Forgetting initializeDependencies

```typescript
// ❌ WRONG - Dependencies not initialized
export const createUser = http('createUser', async (req, res) => {
  await createUserHandler.execute(req, res); // Database not connected!
});

// ✅ CORRECT
export const createUser = http('createUser', async (req, res) => {
  await initializeDependencies(); // Connect database first
  await createUserHandler.execute(req, res);
});
```

### Gotcha 2: Different Fastify and Cloud Routes

```typescript
// ❌ WRONG - Route paths differ
server.post('/api/v1/users', ...) // Fastify
export const createUser = ...      // Cloud Functions at /createUser

// ✅ CORRECT - Logical equivalence
server.post('/api/users', ...)  // Fastify /api/users
export const createUser = ...   // Cloud Functions (maps to endpoint)
```

### Gotcha 3: Missing Request ID Tracking

```typescript
// ❌ WRONG - Different trace IDs locally and in production
// Fastify and Cloud Functions generate different IDs

// ✅ CORRECT - Use OpenTelemetryMiddleware
const handler = new Handler()
  .use(new OpenTelemetryMiddleware())
  .handle(...);

// Same tracing behavior everywhere
```
