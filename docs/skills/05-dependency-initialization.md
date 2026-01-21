# Skill 5: Dependency Initialization Pattern

## Triggers

When user asks to:
- "Initialize database connection"
- "Set up dependency injection"
- "Singleton pattern for services"
- "Initialize services once"
- "Connect to database on startup"
- "Prevent multiple DB connections"
- "Cold start optimization"

## What it provides

Reusable singleton initialization pattern that ensures services (database, caches, etc.) are initialized exactly once across all requests.

## Complete Example

```typescript
// src/core/initialization.ts
import { logger, containerPool } from '@noony-serverless/core';
import { databaseService } from '../services/database.service';
import { UserRepository } from '../repositories/user.repository';
import { AuthService } from '../services/auth.service';

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
  // Fast path: already initialized
  if (initialized && containerPool.isInitialized()) {
    logger.debug('[Init] Dependencies already initialized');
    return;
  }

  // Concurrent request path: wait for in-progress initialization
  if (initializationPromise) {
    logger.debug('[Init] Waiting for in-progress initialization');
    await initializationPromise;
    return;
  }

  // First request path: perform initialization
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
      containerPool.register('UserRepository', userRepository);
      containerPool.register('ConfigRepository', configRepository);
      containerPool.register('AuthService', authService);
      containerPool.register('ConfigService', configService);

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

      // Reset state on failure so next request can retry
      initialized = false;
      containerPool.reset();

      throw error;
    } finally {
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

### Usage in Fastify Server

```typescript
// src/server.ts
import Fastify from 'fastify';
import { initializeDependencies, cleanup } from './core/initialization';

const server = Fastify();

// Initialize on server start (optional - can also be lazy)
server.addHook('onReady', async () => {
  await initializeDependencies();
});

// Cleanup on shutdown
const gracefulShutdown = async () => {
  await server.close();
  await cleanup();
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
```

### Usage in Cloud Functions

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { initializeDependencies } from './core/initialization';

export const myFunction = http('myFunction', async (req, res) => {
  // Lazy initialization on first request (cold start)
  await initializeDependencies();

  await myHandler.execute(req, res);
});
```

## When to use

- Database connection management
- Service initialization (caches, external API clients)
- Cold start optimization for serverless
- Preventing duplicate resource initialization
- Managing singleton services
