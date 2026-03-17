# Resource: Performance Optimization Patterns

## Singleton Initialization Guard Pattern

The three-condition guard prevents race conditions during cold start and ensures dependencies initialize exactly once.

```typescript
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
  // CONDITION 1: Fast path - already initialized and verified
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

## Cold Start Optimization: Lazy Initialization

Initialize dependencies on first request instead of at process startup. Reduces cold start latency but adds latency to first request.

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { initializeDependencies } from './core/initialization';

export const createUser = http('createUser', async (req, res) => {
  // Lazy initialization on first request (cold start)
  await initializeDependencies();

  await createUserHandler.execute(req, res);
});
```

**Trade-off:** First request pays initialization cost (~200-500ms for DB connection), subsequent requests are fast (~30-50ms).

## Warm Start Optimization: Eager Initialization

Initialize dependencies on server startup before handling requests. Adds ~500ms to startup but all requests are fast.

```typescript
// src/server.ts
import Fastify from 'fastify';
import { initializeDependencies, cleanup } from './core/initialization';
import { createUserHandler } from './handlers';

const server = Fastify();

// Initialize on server start (eager)
server.addHook('onReady', async () => {
  await initializeDependencies();
});

server.post('/api/users', createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve()));

// Graceful shutdown
const gracefulShutdown = async () => {
  await server.close();
  await cleanup();
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

server.listen({ port: 3000 });
```

**Benefits:** All requests fast, no initialization latency per request.

## Performance Benchmark: Cold Start vs Warm Start

| Scenario | Cold Start | First Request | Subsequent | Total Time 1000 req |
|----------|-----------|----------------|-----------|-------------------|
| Lazy Init (Cloud Fn) | ~100ms | ~400ms | ~30ms | 30,100ms |
| Eager Init (Fastify) | ~600ms | ~50ms | ~50ms | 50,600ms |
| No Init (no DB) | ~50ms | ~10ms | ~10ms | 10,050ms |

**Cold start** dominates first scenario. **Eager init** recommended for production (warm start servers like Cloud Run, App Engine).

## Common Performance Anti-Patterns

### ❌ Initializing Inside Handler

```typescript
// WRONG - ~500ms latency per request!
export const createUser = http('createUser', async (req, res) => {
  // Initialize on EVERY request
  const db = await databaseService.connect();
  const userRepository = new UserRepository(db);

  // Business logic
  const user = await userRepository.create(req.body);
  res.json({ data: user });
});
```

**Impact:** Each request waits 300-500ms for DB connection. 1000 requests = 300-500 seconds!

### ✅ Correct: Initialize Once

```typescript
// Startup
let db: DatabaseService;
server.addHook('onReady', async () => {
  db = await databaseService.connect();
});

// Handler reuses same connection
export const createUser = http('createUser', async (req, res) => {
  const user = await new UserRepository(db).create(req.body);
  res.json({ data: user });
});
```

**Impact:** First request ~500ms, remaining 999 requests ~30ms each. Total: ~32 seconds!

### ❌ Mutating Global Services During Request

```typescript
// WRONG - Race condition with concurrent requests
class GlobalCache {
  static cache: Map<string, any> = new Map();
}

export const getUser = http('getUser', async (req, res) => {
  const userId = req.query.id;

  // Concurrent request A and B both check cache, both miss
  if (!GlobalCache.cache.has(userId)) {
    // A and B both fetch from DB
    const user = await userRepository.getById(userId);
    // A and B both set cache — one overwrites the other
    GlobalCache.cache.set(userId, user);
  }

  res.json({ data: GlobalCache.cache.get(userId) });
});
```

**Impact:** Cache inconsistency, double-fetching, memory bloat.

### ✅ Correct: Immutable Services

```typescript
// Services initialized once, never mutated during requests
const db = await databaseService.connect();  // Once at startup
const cache = new RedisCache();              // Once at startup

export const getUser = http('getUser', async (req, res) => {
  const userId = req.query.id;

  // Multiple concurrent requests safely read cache
  let user = await cache.get(userId);
  if (!user) {
    user = await userRepository.getById(userId);
    await cache.set(userId, user);
  }

  res.json({ data: user });
});
```

**Impact:** No race conditions, safe concurrency.

### ❌ Initializing Expensive Resources Per Request

```typescript
// WRONG - Creates new HttpClient per request
export const fetchUserData = http('fetchUserData', async (req, res) => {
  const httpClient = new HttpClient({ timeout: 30000 });  // New instance!
  const data = await httpClient.get('https://api.example.com/users');

  res.json({ data });
});
```

**Each new instance:** Socket allocation, SSL handshake, memory allocation.

### ✅ Correct: Reuse Singleton Client

```typescript
// Once at startup
const httpClient = new HttpClient({ timeout: 30000 });

export const fetchUserData = http('fetchUserData', async (req, res) => {
  // Reuse same client across all requests
  const data = await httpClient.get('https://api.example.com/users');
  res.json({ data });
});
```

**Impact:** Connection pooling, faster requests, lower memory footprint.

## Performance Checklist

- [ ] Database connection initialized once at startup using singleton guard
- [ ] HTTP clients (axios, fetch) initialized once and reused
- [ ] Cache services initialized once and reused
- [ ] No `await initializeDependencies()` inside handler function
- [ ] Concurrent initialization requests wait for first one (check `initializationPromise`)
- [ ] Container state reset on failure so retry is possible
- [ ] External API clients configured with connection pooling enabled
- [ ] No service mutations during request processing
- [ ] Global services marked `const` to prevent reassignment
