# Skill 11: Dependency Injection - Container & Service Patterns

## ContainerPool API

The `containerPool` singleton manages the global container and creates request-scoped proxies:

```typescript
import { containerPool } from '@noony-serverless/core';

// Initialize global services once at startup
containerPool.initializeGlobal([
  { id: 'Database', value: new DatabaseService() },
  { id: 'Logger', value: new LoggerService() },
  { id: 'Config', value: new ConfigService() }
]);

// Check if initialized
if (containerPool.isInitialized()) {
  console.log('Global services ready');
}

// Create lightweight proxy for each request
const proxyContainer = containerPool.createProxyContainer();

// Reset all (testing only)
containerPool.reset();
```

## Global Scope Services

Process-lifetime services initialized once at startup:

```typescript
import { containerPool, getService } from '@noony-serverless/core';
import { DatabaseService } from './services/database.service';
import { LoggerService } from './services/logger.service';

// Startup (once per process)
async function initializeDependencies(): Promise<void> {
  const database = new DatabaseService();
  await database.connect();

  containerPool.initializeGlobal([
    { id: 'Database', value: database },
    { id: 'Logger', value: new LoggerService() },
    { id: 'EmailService', value: new EmailService() }
  ]);
}

// Per-request (thousands of times)
const createUserHandler = new Handler<CreateUserRequest, AuthUser>()
  .use(new DependencyInjectionMiddleware())
  .handle(async (context) => {
    // Read global database connection (zero copy)
    const database = getService(context, DatabaseService);
    const user = await database.users.create(context.req.validatedBody!);
    return { userId: user.id };
  });
```

**When to use global scope:**
- Database connections (reused across all requests)
- HTTP clients (connection pooling, SSL handshake done once)
- External API clients
- Configuration and logger instances

## Local Scope Services

Request-scoped services created per-request via `DependencyInjectionMiddleware`:

```typescript
import { DependencyInjectionMiddleware } from '@noony-serverless/core';

const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware([
    { id: 'RequestId', value: generateRequestId() },
    { id: 'TraceContext', value: extractTraceContext(req) },
    { id: 'StartTime', value: Date.now() }
  ]))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    const requestId = getService(context, 'RequestId');
    const startTime = getService(context, 'StartTime');
    console.log(`[${requestId}] Processing request`);
  });
```

**When to use local scope:**
- Request IDs and tracing context
- Authenticated user information
- Request start time
- Per-request caches
- Temporary state during request

## getService() Helper

Type-safe service resolution with no boilerplate:

```typescript
import { getService, Context } from '@noony-serverless/core';
import { UserService } from './services/user.service';

// Type-safe - no casting needed
const handler = new Handler<CreateUserRequest, AuthUser>()
  .handle(async (context: Context<CreateUserRequest, AuthUser>) => {
    const userService = getService(context, UserService);
    const user = await userService.create(context.req.validatedBody!);
    return { userId: user.id };
  });
```

**Without getService() - Verbose:**
```typescript
// WRONG - Manual casting, no type safety
const userService = (context.container as ContainerInstance)
  .get<UserService>(UserService);
```

**With getService() - Clean:**
```typescript
// CORRECT - Type-safe, no casting
const userService = getService(context, UserService);
```

## Hybrid Proxy Container Pattern

The proxy container provides zero-copy access to global services:

```typescript
import { containerPool } from '@noony-serverless/core';

// Global container (process-lifetime)
containerPool.initializeGlobal([
  { id: 'Database', value: new DatabaseService() },
  { id: 'Logger', value: new LoggerService() }
]);

// Request 1
const proxy1 = containerPool.createProxyContainer();
const db1 = proxy1.get('Database');        // From global (no copy)
proxy1.set('UserId', 'user-123');          // Stored locally only
proxy1.get('UserId');                      // 'user-123'

// Request 2 (different proxy)
const proxy2 = containerPool.createProxyContainer();
const db2 = proxy2.get('Database');        // Same instance as db1
proxy2.get('UserId');                      // Throws - not in request 2
proxy2.set('UserId', 'user-456');          // Different local value
```

**Memory Comparison:**

```
Traditional Container Pooling (Per-Request Clone):
  Global Services: 1KB
  + Request 1 clone: 15KB
  + Request 2 clone: 15KB
  Total: 31KB for 2 requests

Hybrid Proxy Container (WeakMap + Proxy):
  Global Services: 1KB
  + Proxy 1 overhead: ~2KB
  + Proxy 2 overhead: ~2KB
  Total: ~5KB for 2 requests (~85% savings)
```

## Complete Handler Setup Pattern

Combining global initialization and request-scoped DI:

```typescript
import { Handler, DependencyInjectionMiddleware, getService } from '@noony-serverless/core';
import { containerPool } from '@noony-serverless/core';

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

// 3. Fastify integration
import { createFastifyHandler } from '@noony-serverless/core';
import Fastify from 'fastify';

const server = Fastify();
server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', initializeDependencies)
);
server.listen({ port: 3000 });
```

## Service Class with DI

Define services to be injected:

```typescript
// src/services/user.service.ts
export class UserService {
  constructor(private db: DatabaseService) {}

  async getById(id: string) {
    return await this.db.users.findOne({ id });
  }

  async create(data: CreateUserRequest) {
    return await this.db.users.insert(data);
  }
}

// src/handlers/user.handler.ts
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new DependencyInjectionMiddleware())
  .handle(async (context) => {
    const userService = getService(context, UserService);
    const user = await userService.create(context.req.validatedBody!);
    return { userId: user.id };
  });
```

## Managing Service Instances

### Singleton Services (Shared)

```typescript
// Global scope - one instance shared
containerPool.initializeGlobal([
  { id: 'DatabaseConnection', value: new DatabaseService() },
  { id: 'Logger', value: new LoggerService() }
]);

// All requests get the same instance
const db1 = containerPool.createProxyContainer().get('DatabaseConnection');
const db2 = containerPool.createProxyContainer().get('DatabaseConnection');
console.log(db1 === db2); // true - same instance
```

### Request-Scoped Services (Isolated)

```typescript
const handler = new Handler<any, AuthUser>()
  .use(new DependencyInjectionMiddleware([
    { id: 'RequestCache', value: new Map() },  // New Map per request
    { id: 'TraceContext', value: generateTraceId() }
  ]))
  .handle(async (context) => {
    const cache = getService(context, 'RequestCache');
    cache.set('key', 'value');
    // In next request, cache is a different instance
  });
```

## Testing with DI Mocking

### Unit Test with Mock Services

```typescript
import { Handler, DependencyInjectionMiddleware, getService } from '@noony-serverless/core';

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
    const handler = new Handler<CreateUserRequest, AuthUser>()
      .use(new DependencyInjectionMiddleware([
        { id: 'RequestId', value: 'test-123' }
      ]))
      .handle(async (context) => {
        const userService = getService(context, UserService);
        return await userService.create({
          email: 'new@example.com',
          name: 'New User'
        });
      });

    const result = await handler.executeGeneric(...);
    expect(result.id).toBeDefined();
  });
});
```

## Container Cleanup Pattern

```typescript
import { containerPool } from '@noony-serverless/core';

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  const database = containerPool.createProxyContainer().get('Database');
  await database.disconnect();
  containerPool.reset();
  process.exit(0);
});
```
