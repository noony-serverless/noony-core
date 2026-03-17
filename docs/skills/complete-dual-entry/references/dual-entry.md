# Resource: Complete Dual-Entry Example

## Full Project Structure

```
src/
├── core/
│   └── initialization.ts      # Singleton init guard
├── handlers/
│   └── user.handlers.ts       # Handler definitions
├── services/
│   └── user.service.ts        # Business logic
├── server.ts                  # Fastify for local dev
└── functions.ts               # Cloud Functions for prod

package.json
```

## 1. Handler Definition (Used by Both Environments)

```typescript
// src/handlers/user.handlers.ts
import { Handler, Context } from '@noony-serverless/core';
import { ErrorHandlerMiddleware, BodyValidationMiddleware, ResponseWrapperMiddleware } from '@noony-serverless/core';
import { z } from 'zod';
import { UserService } from '../services/user.service';

// Request/response types
const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email()
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

interface AuthenticatedUser {
  id: string;
  role: 'admin' | 'user';
}

// Define handler once, use in both Fastify and Cloud Functions
export const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .use(new ResponseWrapperMiddleware<CreateUserRequest, AuthenticatedUser>())
  .handle(async (context: Context<CreateUserRequest, AuthenticatedUser>) => {
    const { name, email } = context.req.validatedBody!;
    const userService = new UserService();  // Or injected via DI

    const user = await userService.create({ name, email });
    return { data: user };
  });
```

## 2. Initialization (Shared by Both)

```typescript
// src/core/initialization.ts
import { logger, containerPool } from '@noony-serverless/core';
import { DatabaseService } from '../services/database.service';
import { UserService } from '../services/user.service';

let initialized = false;
let initializationPromise: Promise<void> | null = null;

export async function initializeDependencies(): Promise<void> {
  // Fast path
  if (initialized && containerPool.isInitialized()) {
    return;
  }

  // Concurrent path
  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  // First run
  initializationPromise = (async () => {
    try {
      logger.info('[Init] Starting initialization');

      // Initialize expensive services once
      const db = new DatabaseService();
      await db.connect();

      const userService = new UserService(db);

      // Register in container
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

## 3. Local Development (Fastify)

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers/user.handlers';
import { initializeDependencies, cleanup } from './core/initialization';

const server = Fastify({ logger: true });

// Initialize on server startup (eager)
server.addHook('onReady', async () => {
  await initializeDependencies();
});

// Register routes
server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve())
);

// Graceful shutdown
const gracefulShutdown = async () => {
  await server.close();
  await cleanup();
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
server.listen({ port: 3000 }, (err, address) => {
  if (err) {
    logger.error(err);
    process.exit(1);
  }
  logger.info(`Server listening at ${address}`);
});
```

## 4. Production (Cloud Functions)

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { createUserHandler } from './handlers/user.handlers';
import { initializeDependencies } from './core/initialization';

export const createUser = http('createUser', async (req, res) => {
  // Lazy initialization on first request (cold start)
  // Subsequent requests reuse initialized services
  await initializeDependencies();

  // Same handler, same business logic
  await createUserHandler.execute(req, res);
});
```

## 5. Local Development Scripts

```json
{
  "scripts": {
    "dev": "ts-node src/server.ts",
    "build": "tsc",
    "test": "jest",
    "deploy": "npm run build && gcloud functions deploy createUser --runtime nodejs20 --trigger-http --entry-point createUser"
  }
}
```

## Usage Flow

### Local Development (Fastify)

```bash
npm run dev
# Server listening at http://localhost:3000

curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com"}'

# Response:
# {
#   "success": true,
#   "payload": { "data": { "id": "123", "name": "Alice", "email": "alice@example.com" } },
#   "timestamp": "2025-03-10T15:30:00Z"
# }
```

### Production (Cloud Functions)

```bash
npm run build
npm run deploy

curl -X POST https://us-central1-myproject.cloudfunctions.net/createUser \
  -H "Content-Type: application/json" \
  -d '{"name":"Bob","email":"bob@example.com"}'

# Same response format, same business logic
```

## Key Differences

| Aspect | Local (Fastify) | Production (Cloud Functions) |
|--------|-----------------|----------------------------|
| Entry Point | `server.ts` | `functions.ts` |
| Handler Execution | `createFastifyHandler()` wrapper | `handler.execute()` |
| Initialization | Eager (on server startup) | Lazy (on first request) |
| Cleanup | Graceful shutdown on SIGTERM | Automatic (function ends) |
| Concurrency | Multiple concurrent requests | Each invocation isolated |
| Same Handler | ✅ Yes, identical | ✅ Yes, identical |
| Same Middleware Chain | ✅ Yes, identical | ✅ Yes, identical |
| Same Business Logic | ✅ Yes, identical | ✅ Yes, identical |

## Advantages of Dual-Entry Pattern

1. **Same Code Everywhere**: Handler, services, middleware all identical between local and production
2. **Fast Local Testing**: Fastify is 2-3x faster than Cloud Functions emulator
3. **Production Verified**: Test locally with exact same code as production
4. **No Duplication**: Single handler definition used by both environments
5. **Easy Debugging**: Local development with full IDE support before deploying

## Gotchas

### ❌ Different Middleware Chains

```typescript
// WRONG - different for local vs production
const localHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  // Missing OpenTelemetryMiddleware
  .handle(controller);

const prodHandler = new Handler()
  .use(new OpenTelemetryMiddleware())  // Added only in prod
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(controller);
```

### ✅ Correct: Single Definition

```typescript
// CORRECT - used by both
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new OpenTelemetryMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(controller);

// Local: via Fastify
server.post('/api/endpoint', createFastifyHandler(handler, 'endpoint', initDeps));

// Prod: via Cloud Functions
export const endpoint = http('endpoint', async (req, res) => {
  await initDeps();
  await handler.execute(req, res);
});
```

### ❌ Initialization in Wrong Place

```typescript
// WRONG - initializes in handler
const handler = new Handler()
  .handle(async (context) => {
    const db = await DatabaseService.connect();  // Each request waits!
  });
```

### ✅ Correct: Initialize Once

```typescript
// CORRECT - initialize at startup
server.addHook('onReady', () => initializeDependencies());

export const endpoint = http('endpoint', async (req, res) => {
  await initializeDependencies();  // Fast path — already initialized
  await handler.execute(req, res);
});
```
