# Dependency Injection

How to use Noony's hybrid proxy container for dependency injection, including global vs local scopes, the singleton initialization guard, and type-safe service resolution.

**Related links:** [DI Middleware Reference](../reference/middlewares/dependency-injection.md) | [Container Model](../explanation/container-model.md) | [Performance Tuning](./performance-tuning.md)

## Prerequisites

- `@noony-serverless/core` installed
- Understanding of TypeScript classes and interfaces
- Familiarity with the Noony Handler pipeline

---

## Overview

Noony's DI system uses TypeDI under the hood with a hybrid proxy container optimized for serverless environments. It has two scopes:

- **Global (process-lifetime):** Services created once at startup, shared across all requests. Use for database connections, HTTP clients, caches.
- **Local (request-scoped):** Services isolated per-request, automatically garbage-collected when the request ends. Use for request IDs, trace context, per-request caches.

The proxy container gives you zero-copy access to global services while keeping local services isolated -- roughly 85% memory savings compared to cloning the entire container per request.

## The ContainerPool API

The `containerPool` singleton manages the global container and creates lightweight proxy containers for each request.

```typescript
import { containerPool } from '@noony-serverless/core';

// Initialize global services once at startup
containerPool.initializeGlobal([
  { id: 'Database', value: new DatabaseService() },
  { id: 'Logger', value: new LoggerService() },
  { id: 'Config', value: new ConfigService() }
]);

// Check initialization state
if (containerPool.isInitialized()) {
  console.log('Global services ready');
}

// Create a lightweight proxy for each request (done automatically by DI middleware)
const proxyContainer = containerPool.createProxyContainer();

// Reset everything (testing only)
containerPool.reset();
```

## Singleton Initialization Guard

The three-condition guard ensures dependencies initialize exactly once, even when concurrent requests arrive during cold start.

```typescript
import { logger, containerPool } from '@noony-serverless/core';
import { databaseService } from '../services/database.service';

let initialized = false;
let initializationPromise: Promise<void> | null = null;

export async function initializeDependencies(): Promise<void> {
  // CONDITION 1: Fast path -- already initialized
  if (initialized && containerPool.isInitialized()) {
    logger.debug('[Init] Dependencies already initialized');
    return;
  }

  // CONDITION 2: Concurrent request path -- wait for in-progress initialization
  if (initializationPromise) {
    logger.debug('[Init] Waiting for in-progress initialization');
    await initializationPromise;
    return;
  }

  // CONDITION 3: First request path -- perform initialization
  logger.info('[Init] Starting dependency initialization');

  initializationPromise = (async () => {
    try {
      const db = await databaseService.connect();

      const userRepository = new UserRepository(db);
      const authService = new AuthService(userRepository);

      containerPool.initializeGlobal([
        { id: 'UserRepository', value: userRepository },
        { id: 'AuthService', value: authService }
      ]);

      containerPool.setInitialized();
      initialized = true;
    } catch (error) {
      // Reset state on failure so the next request can retry
      initialized = false;
      containerPool.reset();
      throw error;
    } finally {
      // Always clear the promise to allow the next attempt
      initializationPromise = null;
    }
  })();

  await initializationPromise;
}
```

### Why All Three Conditions Matter

- **Condition 1** is the fast path. After initialization, every request returns immediately.
- **Condition 2** prevents duplicate initialization. If Request A is still connecting to the database when Request B arrives, B waits on the same promise instead of starting a second connection.
- **Condition 3** performs the actual work only once.

If you skip Condition 2, concurrent cold-start requests each open their own database connection -- a race condition that wastes resources and may hit connection limits.

## Global Scope: Process-Lifetime Services

Register expensive services once at startup. Every request reads the same instance through the proxy container with zero copying overhead.

```typescript
async function initializeDependencies(): Promise<void> {
  const database = new DatabaseService();
  await database.connect();

  containerPool.initializeGlobal([
    { id: 'Database', value: database },
    { id: 'Logger', value: new LoggerService() },
    { id: 'EmailService', value: new EmailService() }
  ]);
}

// In handler -- all requests share the same database connection
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new DependencyInjectionMiddleware())
  .handle(async (context) => {
    const database = getService(context, DatabaseService);
    const user = await database.users.create(context.req.validatedBody!);
    return { userId: user.id };
  });
```

**When to use global scope:**
- Database connections
- HTTP clients (axios instances, fetch wrappers)
- External API clients
- Configuration services
- Logger instances

## Local Scope: Request-Scoped Services

Use `DependencyInjectionMiddleware` with local services for data that must be isolated per request.

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware([
    { id: 'RequestId', value: generateRequestId() },
    { id: 'TraceContext', value: extractTraceContext(req) },
    { id: 'StartTime', value: Date.now() }
  ]))
  .handle(async (context) => {
    const requestId = getService(context, 'RequestId');
    console.log(`[${requestId}] Processing request`);
  });
```

**When to use local scope:**
- Request IDs and tracing context
- Authenticated user information
- Request start time
- Per-request caches
- Temporary state during request processing

## The getService() Helper

Always use the type-safe `getService()` helper to resolve services. It returns properly typed instances without manual casting.

```typescript
import { getService, Context } from '@noony-serverless/core';

// Type-safe -- no casting needed
const userService = getService(context, UserService);
const user = await userService.create(context.req.validatedBody!);
```

Compare this to direct container access, which is verbose and loses type safety:

```typescript
// WRONG -- manual casting, no type safety
const userService = (context.container as ContainerInstance)
  .get<UserService>(UserService);
```

## The Hybrid Proxy Container

When `DependencyInjectionMiddleware` runs, it creates a proxy container for the request. The proxy reads from the global container by default and writes to a local overlay. This means:

- **Global services** are shared by reference (zero copy).
- **Local writes** shadow global reads without mutating the global container.
- **Other requests** never see local data from a different request.

```typescript
// Request 1
const proxy1 = containerPool.createProxyContainer();
const db1 = proxy1.get('Database');        // From global (no copy)
proxy1.set('UserId', 'user-123');          // Stored locally only

// Request 2 (different proxy)
const proxy2 = containerPool.createProxyContainer();
const db2 = proxy2.get('Database');        // Same instance as db1
proxy2.get('UserId');                      // Throws -- not in request 2
```

### Memory Comparison

```
Traditional Container Pooling (clone per request):
  Global services: 1KB
  + Request 1 clone: 15KB
  + Request 2 clone: 15KB
  Total: 31KB for 2 requests

Hybrid Proxy Container:
  Global services: 1KB
  + Proxy 1 overhead: ~2KB
  + Proxy 2 overhead: ~2KB
  Total: ~5KB for 2 requests (~85% savings)
```

## Complete Handler Setup

Combining global initialization and request-scoped DI in a typical handler:

```typescript
import { Handler, DependencyInjectionMiddleware, getService } from '@noony-serverless/core';

// 1. Initialize global services once
async function initializeDependencies(): Promise<void> {
  if (containerPool.isInitialized()) return;

  const database = new DatabaseService();
  await database.connect();

  containerPool.initializeGlobal([
    { id: 'Database', value: database },
    { id: 'UserService', value: new UserService(database) }
  ]);
}

// 2. Create handler with DI middleware
const createUserHandler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware([
    { id: 'RequestId', value: generateRequestId() }
  ]))
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    const userService = getService(context, UserService);
    const requestId = getService(context, 'RequestId');

    const user = await userService.create(context.req.validatedBody!);
    console.log(`[${requestId}] Created user: ${user.id}`);

    return { userId: user.id };
  });

// 3. Use in Fastify
server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
);
```

## Graceful Shutdown and Cleanup

Always clean up global services when the process shuts down.

```typescript
export async function cleanup(): Promise<void> {
  logger.info('[Init] Starting cleanup');
  await databaseService.disconnect();
  containerPool.reset();
  initialized = false;
  logger.info('[Init] Cleanup complete');
}

// Register shutdown handlers
process.on('SIGTERM', async () => {
  await server.close();
  await cleanup();
  process.exit(0);
});

process.on('SIGINT', async () => {
  await server.close();
  await cleanup();
  process.exit(0);
});
```

## Testing with DI Mocking

### Unit Test with Mock Services

```typescript
describe('UserHandler', () => {
  it('should create user with mock service', async () => {
    const mockUserService = {
      create: jest.fn().mockResolvedValue({ id: 'user-123', email: 'test@example.com' })
    };

    const handler = new Handler<CreateUserRequest, AuthUser>()
      .use(new DependencyInjectionMiddleware([
        { id: 'UserService', value: mockUserService }
      ]))
      .handle(async (context) => {
        const userService = getService(context, 'UserService');
        return await userService.create({ email: 'test@example.com', name: 'Test' });
      });

    const context = createMockContext();
    const result = await handler.executeGeneric(context.req, context.res);

    expect(mockUserService.create).toHaveBeenCalledWith({
      email: 'test@example.com',
      name: 'Test'
    });
  });
});
```

### Integration Test with Real Services

```typescript
describe('UserHandler Integration', () => {
  let database: DatabaseService;

  beforeAll(async () => {
    database = new DatabaseService();
    await database.connect();

    containerPool.initializeGlobal([
      { id: 'Database', value: database },
      { id: 'UserService', value: new UserService(database) }
    ]);
  });

  afterAll(async () => {
    await database.disconnect();
    containerPool.reset();
  });

  it('should create and retrieve user', async () => {
    // ... test with real database
  });
});
```

## Anti-Patterns

### Initializing global services per request

```typescript
// WRONG -- reconnects to DB on every request (~300-500ms penalty)
const handler = new Handler()
  .handle(async (context) => {
    const database = new DatabaseService();
    await database.connect();
    return await database.query(...);
  });

// CORRECT -- initialize once, reuse forever
containerPool.initializeGlobal([
  { id: 'Database', value: database }
]);
```

### Using Container.get() directly

```typescript
// WRONG -- bypasses framework DI, misses scoping
const userService = Container.get(UserService);

// CORRECT -- type-safe, respects global/local scoping
const userService = getService(context, UserService);
```

### Creating new service instances per request

```typescript
// WRONG -- defeats DI benefits
const handler = new Handler()
  .handle(async (context) => {
    const userService = new UserService();
  });

// CORRECT -- resolve from container
const handler = new Handler()
  .use(new DependencyInjectionMiddleware())
  .handle(async (context) => {
    const userService = getService(context, UserService);
  });
```

### Treating request-scoped data as global

```typescript
// WRONG -- request state leaks between requests
containerPool.initializeGlobal([
  { id: 'CurrentUser', value: null }
]);

// CORRECT -- use local scope for per-request data
.use(new DependencyInjectionMiddleware([
  { id: 'CurrentUser', value: context.user }
]))
```

### Missing Condition 2 in the initialization guard

Without the `initializationPromise` check, concurrent cold-start requests each perform full initialization independently -- opening multiple database connections and wasting startup time.

## Troubleshooting

### "Service not found" error

**Cause:** Handler ran before `initializeDependencies()` completed.
**Fix:** Always `await initializeDependencies()` before handler execution.

### Multiple concurrent requests initializing

**Cause:** Missing or broken Condition 2 (`initializationPromise` check).
**Fix:** Ensure the promise tracking code is intact.

### "Already initialized" on retry after failure

**Cause:** Forgot to reset `initialized = false` in the catch block.
**Fix:** Always reset state on error so the next request can retry.

### Cleanup never runs, DB connections leak

**Cause:** Missing graceful shutdown handlers.
**Fix:** Add `process.on('SIGTERM', ...)` and `process.on('SIGINT', ...)` with cleanup logic.

## See Also

- [DI Middleware Reference](../reference/middlewares/dependency-injection.md) -- Full API for DependencyInjectionMiddleware
- [Container Model](../explanation/container-model.md) -- Deep dive into the hybrid proxy container
- [Performance Tuning](./performance-tuning.md) -- Cold start and connection pooling optimization
- [Local Dev with Fastify](../tutorials/03-local-dev-with-fastify.md) -- Eager vs lazy initialization in practice
