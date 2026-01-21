# Skill 1: Create Type-Safe Fastify Server

## Triggers

When user asks to:
- "Create a Fastify server"
- "Set up local development server"
- "Add Fastify for local dev"
- "Create development server"
- "Set up local testing environment"
- "I want to test my handlers locally"

## What it provides

Complete Fastify server template with:
- Dependency initialization (singleton pattern)
- Route registration using `createFastifyHandler()`
- Graceful shutdown
- Health check endpoint
- Type-safe request/response handling

## Complete Example

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler, logger } from '@noony-serverless/core';
import { databaseService } from './services/database.service';
import { containerPool } from './core/container-pool';

// Import your Noony handlers
import { loginHandler, logoutHandler } from './handlers/auth.handlers';
import { getUserHandler, updateUserHandler } from './handlers/user.handlers';

// ============================================================================
// DEPENDENCY INITIALIZATION (Singleton Pattern)
// ============================================================================

let initialized = false;
let initializationPromise: Promise<void> | null = null;

async function initializeDependencies(): Promise<void> {
  if (initialized && containerPool.isInitialized()) {
    logger.debug('[Fastify] Reusing initialized dependencies');
    return;
  }

  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  initializationPromise = (async () => {
    try {
      logger.info('[Fastify] Initializing dependencies');
      const db = await databaseService.connect();
      await initializeServices(db);
      containerPool.setInitialized();
      initialized = true;
      logger.info('[Fastify] Dependencies initialized successfully');
    } catch (error) {
      logger.error('[Fastify] Failed to initialize dependencies', { error });
      throw error;
    } finally {
      initializationPromise = null;
    }
  })();

  await initializationPromise;
}

// ============================================================================
// FASTIFY SERVER SETUP
// ============================================================================

const server = Fastify({
  logger: true,
  requestIdLogLabel: 'reqId',
});

// Helper shorthand for creating Fastify handlers
const adapt = (handler: Handler<unknown>, name: string) =>
  createFastifyHandler(handler, name, initializeDependencies);

// ============================================================================
// ROUTE REGISTRATION
// ============================================================================

// Auth routes
server.post('/api/auth/login', adapt(loginHandler, 'login'));
server.post('/api/auth/logout', adapt(logoutHandler, 'logout'));

// User routes (with path parameters)
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));
server.patch('/api/users/:userId', adapt(updateUserHandler, 'updateUser'));

// Health check
server.get('/health', async (request, reply) => {
  reply.send({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

server.listen({ port: PORT, host: HOST }, (err, address) => {
  if (err) {
    logger.error('[Fastify] Server failed to start', { error: err.message });
    process.exit(1);
  }
  logger.info(`[Fastify] Server listening at ${address}`);
});

// Graceful shutdown
const gracefulShutdown = async () => {
  logger.info('[Fastify] Shutting down gracefully...');
  try {
    await server.close();
    await databaseService.disconnect();
    logger.info('[Fastify] Shutdown complete');
    process.exit(0);
  } catch (error) {
    logger.error('[Fastify] Error during shutdown', { error });
    process.exit(1);
  }
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
```

### Package.json Scripts

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "dev:nodemon": "nodemon --exec tsx src/server.ts",
    "start": "node dist/server.js"
  }
}
```

## When to use

- **Local development**: Fast iteration without deploying to cloud
- **Integration testing**: Test handlers with real HTTP framework
- **Performance testing**: Benchmark handler performance locally
- **Development workflow**: Start here before deploying to production
