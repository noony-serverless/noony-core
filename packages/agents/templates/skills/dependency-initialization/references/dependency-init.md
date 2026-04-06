# Resource: Complete Dependency Initialization Pattern

## Singleton Pattern with Three-Condition Guard

The exact implementation to copy/paste with all three conditions for safe concurrent initialization.

```typescript
// src/core/initialization.ts
import { logger, containerPool } from '@noony-serverless/core';
import { databaseService } from '../services/database.service';
import { UserRepository } from '../repositories/user.repository';
import { AuthService } from '../services/auth.service';

// Global state for singleton pattern
let initialized = false;
let initializationPromise: Promise<void> | null = null;

/**
 * Initialize all application dependencies (singleton pattern)
 *
 * This function ensures that:
 * 1. Dependencies are initialized exactly once
 * 2. Concurrent initialization requests wait for the first one to complete
 * 3. Initialization failures are properly handled
 * 4. Services are registered in the dependency injection container
 */
export async function initializeDependencies(): Promise<void> {
  // CONDITION 1: Fast path - already initialized
  if (initialized && containerPool.isInitialized()) {
    logger.debug('[Init] Dependencies already initialized');
    return;
  }

  // CONDITION 2: Concurrent request path - wait for in-progress initialization
  if (initializationPromise) {
    logger.debug('[Init] Waiting for in-progress initialization');
    await initializationPromise;
    return;
  }

  // CONDITION 3: First request path - perform initialization
  logger.info('[Init] Starting dependency initialization');

  initializationPromise = (async () => {
    try {
      // 1. Connect to database
      logger.debug('[Init] Connecting to database');
      const db = await databaseService.connect();
      logger.info('[Init] Database connected', {
        host: db.connection.host,
        name: db.connection.name,
      });

      // 2. Initialize repositories
      logger.debug('[Init] Initializing repositories');
      const userRepository = new UserRepository(db);
      const configRepository = new ConfigRepository(db);

      // 3. Initialize services
      logger.debug('[Init] Initializing services');
      const authService = new AuthService(userRepository);
      const configService = new ConfigService(configRepository);

      // 4. Register services in container pool for DI
      logger.debug('[Init] Registering services in container');
      containerPool.initializeGlobal([
        { id: 'UserRepository', value: userRepository },
        { id: 'ConfigRepository', value: configRepository },
        { id: 'AuthService', value: authService },
        { id: 'ConfigService', value: configService }
      ]);

      // 5. Mark as initialized
      containerPool.setInitialized();
      initialized = true;

      logger.info('[Init] Dependency initialization complete', {
        duration: process.uptime(),
      });
    } catch (error) {
      logger.error('[Init] Failed to initialize dependencies', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });

      // IMPORTANT: Reset state on failure so next request can retry
      initialized = false;
      containerPool.reset();

      throw error;
    } finally {
      // Always clear the promise to allow next attempt
      initializationPromise = null;
    }
  })();

  await initializationPromise;
}

/**
 * Cleanup function for graceful shutdown
 */
export async function cleanup(): Promise<void> {
  logger.info('[Init] Starting cleanup');

  try {
    await databaseService.disconnect();
    containerPool.reset();
    initialized = false;

    logger.info('[Init] Cleanup complete');
  } catch (error) {
    logger.error('[Init] Error during cleanup', {
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}
```

## Usage in Fastify Server (Eager Initialization)

Initialize at server startup, all requests are fast.

```typescript
// src/server.ts
import Fastify from 'fastify';
import { initializeDependencies, cleanup } from './core/initialization';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers';

const server = Fastify();

// Initialize on server start (eager)
server.addHook('onReady', async () => {
  await initializeDependencies();
});

server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve())
);

const gracefulShutdown = async () => {
  await server.close();
  await cleanup();
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

server.listen({ port: 3000 });
```

## Usage in Cloud Functions (Lazy Initialization)

Initialize on first request, first request is slow but subsequent are fast.

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { initializeDependencies } from './core/initialization';
import { createUserHandler } from './handlers';

export const createUser = http('createUser', async (req, res) => {
  // Lazy initialization on first request (cold start)
  // Subsequent requests hit fast path and return immediately
  await initializeDependencies();

  await createUserHandler.execute(req, res);
});
```

## Usage in Service Layer (Accessing Initialized Services)

Once initialized, access services via `getService()` helper or direct container access.

```typescript
// src/services/user.service.ts
import { getService, Context } from '@noony-serverless/core';

export class UserService {
  async createUser(context: Context, data: CreateUserRequest) {
    // Option 1: Type-safe getService() helper
    const userRepository = getService(context, UserRepository);
    const authService = getService(context, AuthService);

    // Option 2: Direct container access
    const userRepo = context.container.get('UserRepository');

    // Use services
    const user = await userRepository.create(data);
    return user;
  }
}
```

## Performance Implications

### Lazy Initialization (Cloud Functions)

```
Cold start:  100ms (function startup)
+ First req: 500ms (init DB + services) + 50ms (business logic) = 550ms total
+ Req 2-N:   50ms (fast path)
+ Average:   ~51ms per request

Total for 1000 req: 550ms + (999 * 50ms) = ~50 seconds
```

### Eager Initialization (Fastify)

```
Server start: 500ms (init DB + services)
+ Req 1-N:    50ms (fast path, all requests)
+ Average:    ~50ms per request

Total for 1000 req: 500ms + (1000 * 50ms) = ~50.5 seconds (first req is fast!)
```

**Recommendation:** Eager initialization for production (Cloud Run, App Engine warm servers). Lazy initialization acceptable for low-traffic endpoints.

## Troubleshooting

### Problem: "Service not found" Error

**Cause:** Called handler before `initializeDependencies()` completed.

**Fix:** Always await initialization before handler execution:
```typescript
await initializeDependencies();  // Ensure this completes first
await handler.execute(req, res);
```

### Problem: Multiple Concurrent Requests Initializing

**Cause:** Missing or broken CONDITION 2 (initializationPromise check).

**Fix:** Ensure promise tracking is correct:
```typescript
if (initializationPromise) {
  await initializationPromise;  // Wait for in-progress initialization
  return;
}
```

### Problem: "Already initialized" on Retry After Failure

**Cause:** Forgot to reset `initialized = false` in error handler.

**Fix:** Reset state in catch block:
```typescript
} catch (error) {
  initialized = false;          // Reset so next request retries
  containerPool.reset();
  throw error;
}
```

### Problem: Cleanup Never Runs, DB Connection Leaks

**Cause:** Missing graceful shutdown handlers in Fastify or Cloud Functions.

**Fix:** Add cleanup on process termination:
```typescript
process.on('SIGTERM', async () => {
  await server.close();
  await cleanup();
  process.exit(0);
});
```
