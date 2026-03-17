# Tutorial: Local Development with Fastify

Step-by-step guide to setting up a local development server with Fastify, using the same handlers that deploy to Google Cloud Functions with zero code duplication.

**Related links:** [API Reference](../reference/api.md) | [Dependency Injection](../guides/dependency-injection.md) | [Performance Tuning](../guides/performance-tuning.md)

## Prerequisites

- Node.js 18+ installed
- `@noony-serverless/core` and `fastify` installed
- A Noony handler already defined (or you will create one in this tutorial)

---

## What You Will Build

By the end of this tutorial you will have:

1. A Fastify server running locally for rapid development
2. Handler code that works identically in Fastify and Cloud Functions
3. A dual-entry project structure with separate entry points for each environment
4. Graceful shutdown with proper resource cleanup

## The Dual-Entry Pattern

The key insight of Noony's architecture: **handlers are framework-agnostic**. They work with `GenericRequest` and `GenericResponse` interfaces. Both Cloud Functions and Fastify adapt their native request/response objects to these interfaces.

```
Handler Code (src/handlers/user.handler.ts)
    |
    +-- Cloud Functions Entry Point (src/functions.ts)
    |     handler.execute(req, res)
    |
    +-- Fastify Entry Point (src/server.ts)
          createFastifyHandler(handler, name, initFn)
```

You write the handler once. The entry points are thin wrappers.

## Step 1: Define Your Handler

Create a handler with all middlewares. This file has no imports from Fastify or Cloud Functions.

```typescript
// src/handlers/user.handler.ts
import { Handler, Context } from '@noony-serverless/core';
import {
  ErrorHandlerMiddleware,
  BodyParserMiddleware,
  BodyValidationMiddleware,
  ResponseWrapperMiddleware
} from '@noony-serverless/core';
import { z } from 'zod';

const createUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1),
  age: z.number().min(18)
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

interface AuthUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

export const createUserHandler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware<CreateUserRequest>())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateUserRequest, AuthUser>) => {
    const { email, name, age } = context.req.validatedBody!;

    // Business logic -- no framework-specific code
    const newUser = await userService.create({ email, name, age });
    return { data: newUser };
  });
```

## Step 2: Create the Initialization Module

Both entry points share the same initialization logic. The singleton guard ensures it runs exactly once.

```typescript
// src/core/initialization.ts
import { logger, containerPool } from '@noony-serverless/core';
import { DatabaseService } from '../services/database.service';
import { UserService } from '../services/user.service';

let initialized = false;
let initializationPromise: Promise<void> | null = null;

export async function initializeDependencies(): Promise<void> {
  if (initialized && containerPool.isInitialized()) {
    return;
  }

  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  initializationPromise = (async () => {
    try {
      logger.info('[Init] Starting initialization');

      const db = new DatabaseService();
      await db.connect();

      const userService = new UserService(db);

      containerPool.initializeGlobal([
        { id: 'Database', value: db },
        { id: 'UserService', value: userService }
      ]);

      containerPool.setInitialized();
      initialized = true;
      logger.info('[Init] Initialization complete');
    } catch (error) {
      logger.error('[Init] Failed', { error });
      initialized = false;
      containerPool.reset();
      throw error;
    } finally {
      initializationPromise = null;
    }
  })();

  await initializationPromise;
}

export async function cleanup(): Promise<void> {
  logger.info('[Cleanup] Starting');
  containerPool.reset();
  initialized = false;
  logger.info('[Cleanup] Complete');
}
```

## Step 3: Create the Fastify Server

This is your local development entry point. It uses eager initialization -- all services are ready before the first request arrives.

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers/user.handler';
import { initializeDependencies, cleanup } from './core/initialization';

const server = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    transport: {
      target: 'pino-pretty',
      options: { colorize: true }
    }
  }
});

// Initialize on server startup (eager)
server.addHook('onReady', async () => {
  try {
    await initializeDependencies();
    server.log.info('[Server] Dependencies initialized');
  } catch (error) {
    server.log.error('[Server] Initialization failed', error);
    process.exit(1);
  }
});

// Health check
server.get('/health', async () => {
  return { status: 'ok', uptime: process.uptime() };
});

// Register routes -- same handler used in Cloud Functions
server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve())
);

// Graceful shutdown
const gracefulShutdown = async (signal: string) => {
  server.log.info(`[Server] ${signal} received, shutting down...`);
  try {
    await server.close();
    await cleanup();
    process.exit(0);
  } catch (error) {
    server.log.error('[Server] Error during shutdown', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start
const start = async () => {
  try {
    await server.listen({ port: 3000, host: '0.0.0.0' });
    server.log.info('[Server] Fastify server started on http://0.0.0.0:3000');
  } catch (error) {
    server.log.error('[Server] Failed to start server', error);
    process.exit(1);
  }
};

start();

export default server;
```

### The createFastifyHandler() Wrapper

`createFastifyHandler()` adapts a Noony handler for use with Fastify. It takes three arguments:

1. **handler** -- The Noony handler instance.
2. **name** -- A name for logging and tracing.
3. **initFn** -- An async function called before each request. Since we initialize eagerly via `onReady`, we pass a no-op: `() => Promise.resolve()`.

## Step 4: Create the Cloud Functions Entry Point

This is your production entry point. It uses lazy initialization -- the first request triggers setup.

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { createUserHandler } from './handlers/user.handler';
import { initializeDependencies } from './core/initialization';

export const createUser = http('createUser', async (req, res) => {
  await initializeDependencies();
  await createUserHandler.execute(req, res);
});
```

Notice the handler is identical. Only the wrapper differs.

## Step 5: Configure npm Scripts

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js",
    "test": "jest",
    "test:coverage": "jest --coverage",
    "deploy": "npm run build && gcloud functions deploy createUser --runtime nodejs20 --trigger-http --entry-point createUser"
  }
}
```

## Step 6: Test Locally

Start the server:

```bash
npm run dev
# Output: [Server] Fastify server started on http://0.0.0.0:3000
```

Test with curl:

```bash
# Create user
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","age":30}'

# Health check
curl http://localhost:3000/health
```

## Adding More Routes

Register multiple handlers on different routes:

```typescript
// src/server.ts
import {
  createUserHandler,
  getUserHandler,
  updateUserHandler,
  deleteUserHandler
} from './handlers/user.handlers';

server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve())
);

server.get('/api/users/:userId',
  createFastifyHandler(getUserHandler, 'getUser', () => Promise.resolve())
);

server.patch('/api/users/:userId',
  createFastifyHandler(updateUserHandler, 'updateUser', () => Promise.resolve())
);

server.delete('/api/users/:userId',
  createFastifyHandler(deleteUserHandler, 'deleteUser', () => Promise.resolve())
);
```

And the corresponding Cloud Functions exports:

```typescript
// src/functions.ts
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

## Project Structure

```
my-api/
  src/
    core/
      initialization.ts      # Singleton init guard (shared)
    handlers/
      user.handler.ts         # Framework-agnostic handlers
    services/
      user.service.ts         # Business logic
      database.service.ts     # Database connection
    server.ts                 # Fastify entry point (local dev)
    functions.ts              # Cloud Functions entry point (production)
  package.json
  tsconfig.json
  .env
```

## Key Differences Between Environments

| Aspect | Local (Fastify) | Production (Cloud Functions) |
|--------|-----------------|----------------------------|
| Entry point | `server.ts` | `functions.ts` |
| Handler execution | `createFastifyHandler()` wrapper | `handler.execute()` |
| Initialization | Eager (`onReady` hook) | Lazy (on first request) |
| Cleanup | Graceful shutdown on SIGTERM | Automatic (function ends) |
| Same handler | Yes | Yes |
| Same middleware chain | Yes | Yes |
| Same business logic | Yes | Yes |

## Integration Testing with Fastify

Use Fastify's `inject()` method for integration tests:

```typescript
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from '../src/handlers/user.handler';
import { initializeDependencies } from '../src/core/initialization';

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
      headers: { 'Content-Type': 'application/json' },
      payload: {
        email: 'new@example.com',
        name: 'New User',
        age: 30
      }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().success).toBe(true);
  });

  it('should reject invalid email', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/users',
      payload: {
        email: 'invalid-email',
        name: 'User',
        age: 30
      }
    });

    expect(response.statusCode).toBe(400);
  });
});
```

## Performance Benefits

| Metric | Fastify (Local) | Cloud Functions |
|--------|-----------------|-----------------|
| Startup time | ~150ms | ~3000ms+ |
| Request latency | ~5-10ms | ~50-200ms |
| Iteration speed | ~1s (code save) | ~5min+ (deploy) |
| Debugging | Full local IDE tools | Cloud Logging |

Using Fastify for local development typically saves 2+ hours per day in iteration time.

## Deployment

Build and deploy to Cloud Functions:

```bash
npm run build
npm run deploy

# Test deployed service
curl -X POST https://us-central1-myproject.cloudfunctions.net/createUser \
  -H "Content-Type: application/json" \
  -d '{"name":"Bob","email":"bob@example.com","age":25}'
```

For Cloud Run deployment:

```bash
gcloud builds submit --tag gcr.io/[PROJECT_ID]/noony-server

gcloud run deploy noony-server \
  --image gcr.io/[PROJECT_ID]/noony-server \
  --platform managed \
  --region us-central1 \
  --memory 512Mi \
  --timeout 60
```

## Troubleshooting

### Port already in use

```bash
lsof -i :3000
kill -9 <PID>
```

Or use a different port: `PORT=8080 npm run dev`

### "Service not found in container"

The `onReady` hook has not completed. Ensure `initializeDependencies()` is called in the `onReady` hook and that it succeeds before routes are hit.

### Graceful shutdown not working

Test it explicitly:

```bash
npm run dev &
kill -SIGTERM $!
# Should see: [Server] SIGTERM received, shutting down...
```

## Anti-Patterns

- **Different middleware chains for Fastify vs Cloud Functions.** The handler definition must be identical. If you add `OpenTelemetryMiddleware` in production but not locally, behavior will diverge.
- **Duplicating handler code between entry points.** Always import from the shared handler module.
- **Calling `initializeDependencies()` inside the handler function.** Use the `onReady` hook for Fastify and the wrapper function for Cloud Functions.
- **Using `handler.execute()` with Fastify.** Use `createFastifyHandler()` instead -- it handles the request/response adaptation.

## See Also

- [API Reference](../reference/api.md) -- `createFastifyHandler()` and `handler.execute()` signatures
- [Dependency Injection](../guides/dependency-injection.md) -- Global vs local scope and the initialization guard
- [Performance Tuning](../guides/performance-tuning.md) -- Eager vs lazy initialization benchmarks
- [Testing Handlers](./04-testing-handlers.md) -- Unit and integration testing patterns
