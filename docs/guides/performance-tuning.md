# Performance Tuning

How to optimize Noony applications for cold start latency, memory usage, and connection management in serverless and long-running environments.

**Related links:** [Container Model](../explanation/container-model.md) | [Dependency Injection](./dependency-injection.md) | [Local Dev with Fastify](../tutorials/03-local-dev-with-fastify.md)

## Prerequisites

- Understanding of the Noony DI system (global vs local scope)
- Familiarity with serverless cold start behavior
- `@noony-serverless/core` installed

---

## The Cost of Per-Request Initialization

The single biggest performance mistake in serverless applications is initializing expensive resources on every request. Database connections, HTTP client setup, and SSL handshakes cost 300-500ms each. In a typical application handling 1000 requests:

| Strategy | First Request | Subsequent | Total (1000 req) |
|----------|---------------|-----------|-------------------|
| Per-request init | ~500ms each | ~500ms each | ~500 seconds |
| Lazy init (Cloud Functions) | ~550ms | ~30ms | ~30 seconds |
| Eager init (Fastify) | ~50ms (after startup) | ~50ms | ~50 seconds |
| No DB | ~10ms | ~10ms | ~10 seconds |

The singleton initialization guard pattern eliminates this overhead.

## Cold Start Optimization

### Lazy Initialization (Cloud Functions)

In Google Cloud Functions, the function process may be recycled at any time. Use the singleton guard to initialize on the first request and reuse for all subsequent requests within the same process.

```typescript
import { http } from '@google-cloud/functions-framework';
import { initializeDependencies } from './core/initialization';
import { createUserHandler } from './handlers';

export const createUser = http('createUser', async (req, res) => {
  // First request: ~500ms (DB connect + service init)
  // Subsequent requests: <1ms (fast path returns immediately)
  await initializeDependencies();

  await createUserHandler.execute(req, res);
});
```

**Trade-off:** The first request after a cold start pays the initialization cost. All subsequent requests are fast until the process is recycled.

### Eager Initialization (Fastify / Cloud Run)

For long-running servers, initialize at startup so every request is fast from the start.

```typescript
import Fastify from 'fastify';
import { initializeDependencies, cleanup } from './core/initialization';

const server = Fastify();

// Initialize before handling any requests
server.addHook('onReady', async () => {
  await initializeDependencies();
});

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

server.listen({ port: 3000 });
```

**Recommendation:** Use eager initialization for production (Cloud Run, App Engine, long-running containers). Use lazy initialization for low-traffic Cloud Functions endpoints.

## The Singleton Initialization Guard

The three-condition guard prevents race conditions and ensures initialization happens exactly once. See the [Dependency Injection guide](./dependency-injection.md) for the full implementation.

The critical aspects for performance:

1. **Condition 1 (fast path):** `if (initialized && containerPool.isInitialized()) return;` -- This runs in microseconds and is the path every request takes after startup.
2. **Condition 2 (concurrent wait):** `if (initializationPromise) { await initializationPromise; return; }` -- Prevents duplicate initialization when multiple requests arrive during cold start.
3. **Condition 3 (initialization):** Runs once, connects to database, creates services, registers in container.

**Never skip Condition 2.** Without it, concurrent cold-start requests each open their own database connection, potentially exhausting connection limits.

## Memory Management: Zero-Copy DI

Noony's hybrid proxy container provides global service access without cloning. Each request gets a lightweight proxy (~2KB overhead) that reads from the global container by reference and writes to a local overlay.

```
Traditional approach (clone per request):
  1000 requests x 15KB per clone = 15MB

Noony proxy approach:
  1KB global + (1000 requests x 2KB proxy) = ~2MB

Memory savings: ~87%
```

### When Memory Matters

In serverless environments, memory directly affects cost. Cloud Functions bills per GB-second. Reducing memory usage from 256MB to 128MB cuts your bill in half.

To maximize memory efficiency:
- Use global scope for all stateless services (database, HTTP clients, loggers).
- Use local scope only for truly per-request data (request IDs, trace context).
- Avoid storing large objects in `context.businessData` -- they persist until the request ends.

## Connection Pooling

### Database Connections

Initialize the database connection once and share it across all requests through the global container.

```typescript
// WRONG -- new connection per request (~300ms + socket overhead each time)
const handler = new Handler()
  .handle(async (context) => {
    const db = await databaseService.connect();
    return await db.query(...);
  });

// CORRECT -- shared connection, reused forever
async function initializeDependencies() {
  const db = await databaseService.connect();
  containerPool.initializeGlobal([
    { id: 'Database', value: db }
  ]);
}

const handler = new Handler()
  .use(new DependencyInjectionMiddleware())
  .handle(async (context) => {
    const db = getService(context, 'Database');
    return await db.query(...);
  });
```

### HTTP Clients

HTTP clients maintain connection pools, perform SSL handshakes, and allocate sockets. Creating them per request wastes all of this setup work.

```typescript
// WRONG -- new client per request (socket allocation + SSL handshake)
const handler = new Handler()
  .handle(async (context) => {
    const httpClient = new HttpClient({ timeout: 30000 });
    const data = await httpClient.get('https://api.example.com/users');
    return data;
  });

// CORRECT -- singleton client with connection pooling
const httpClient = new HttpClient({ timeout: 30000 });

containerPool.initializeGlobal([
  { id: 'HttpClient', value: httpClient }
]);
```

## Avoiding Global State Mutation

Global services must be immutable after initialization. Mutating them during request processing creates race conditions with concurrent requests.

```typescript
// WRONG -- race condition: concurrent requests overwrite each other
class GlobalCache {
  static cache: Map<string, any> = new Map();
}

const handler = new Handler()
  .handle(async (context) => {
    // Request A and B both check, both miss, both write
    if (!GlobalCache.cache.has(userId)) {
      const user = await db.getUser(userId);
      GlobalCache.cache.set(userId, user);  // Race condition!
    }
    return GlobalCache.cache.get(userId);
  });

// CORRECT -- use an external cache service initialized once
const cache = new RedisCache();
containerPool.initializeGlobal([
  { id: 'Cache', value: cache }
]);

const handler = new Handler()
  .handle(async (context) => {
    const cache = getService(context, 'Cache');
    let user = await cache.get(userId);
    if (!user) {
      user = await db.getUser(userId);
      await cache.set(userId, user);  // Redis handles concurrency
    }
    return user;
  });
```

## Performance Checklist

Use this checklist when reviewing a Noony application for performance:

- [ ] Database connection initialized once at startup using the singleton guard
- [ ] HTTP clients initialized once and reused across all requests
- [ ] Cache services initialized once and reused
- [ ] No `await initializeDependencies()` calls inside handler functions
- [ ] Concurrent initialization requests wait for the first one (Condition 2 present)
- [ ] Container state resets on failure so retry is possible
- [ ] External API clients configured with connection pooling enabled
- [ ] No service mutations during request processing
- [ ] Global services declared as `const` to prevent accidental reassignment
- [ ] Cheap middleware (header checks) ordered before expensive middleware (DB auth)
- [ ] Graceful shutdown cleans up database connections and resets the container

## Anti-Patterns

### Initializing inside the handler

```typescript
// WRONG -- ~500ms latency on EVERY request
export const createUser = http('createUser', async (req, res) => {
  const db = await databaseService.connect();
  const userRepository = new UserRepository(db);
  const user = await userRepository.create(req.body);
  res.json({ data: user });
});
```

**Impact:** 1000 requests = 500 seconds wasted on redundant connections.

### Creating service instances per request

```typescript
// WRONG -- defeats DI, wastes memory and initialization time
const handler = new Handler()
  .handle(async (context) => {
    const userService = new UserService();
  });
```

### Forgetting to reset state on initialization failure

```typescript
// WRONG -- stuck in failed state, all subsequent requests fail
} catch (error) {
  throw error;  // initialized remains true, but services are broken
}

// CORRECT -- reset so next request retries
} catch (error) {
  initialized = false;
  containerPool.reset();
  throw error;
}
```

### Skipping graceful shutdown

Without cleanup on SIGTERM/SIGINT, database connections leak when the process restarts. Over time, this exhausts connection pool limits.

## See Also

- [Container Model](../explanation/container-model.md) -- Deep dive into the hybrid proxy container architecture
- [Dependency Injection](./dependency-injection.md) -- Full DI setup including the initialization guard
- [Middleware Ordering](./middleware-ordering.md) -- Ordering cheap middleware before expensive middleware
- [Local Dev with Fastify](../tutorials/03-local-dev-with-fastify.md) -- Eager initialization in practice
