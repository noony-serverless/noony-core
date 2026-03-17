# Custom Middleware Development

How to create custom middleware implementing `BaseMiddleware<TBody, TUser>` with full lifecycle hooks and type-safe inter-middleware communication.

**Related links:** [Middleware Reference](../reference/middlewares/INDEX.md) | [Middleware Ordering](./middleware-ordering.md) | [Type Inference](./type-inference.md)

## Prerequisites

- Familiarity with TypeScript generics
- Understanding of the Noony Handler lifecycle (before -> handler -> after/onError)
- `@noony-serverless/core` installed

---

## The BaseMiddleware Interface

Every Noony middleware implements `BaseMiddleware<TBody, TUser>` with three optional lifecycle hooks:

- **`before(context)`** -- Runs before the handler, in registration order (top-to-bottom). Use for preprocessing: parsing, validation, authentication.
- **`after(context)`** -- Runs after a successful handler execution, in reverse registration order (bottom-to-top). Use for response wrapping, logging, cleanup.
- **`onError(context, error)`** -- Runs when an error is thrown, in reverse registration order. Use for error formatting, alerting, recovery.

All hooks are optional. Implement only the ones you need.

## Pattern 1: Class-Based Middleware

The standard approach. Define a class with generics, implement the hooks you need, and store shared state in `context.businessData`.

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

export class TimingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    context.businessData.set('startTime', Date.now());
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    const startTime = context.businessData.get('startTime') as number;
    const elapsed = Date.now() - startTime;
    console.log(`[Timing] Request completed in ${elapsed}ms`);
  }

  async onError(context: Context<TBody, TUser>, error: unknown): Promise<void> {
    const startTime = context.businessData.get('startTime') as number;
    const elapsed = Date.now() - startTime;
    console.error(`[Timing] Request failed after ${elapsed}ms`, error);
  }
}

// Usage
const handler = new Handler<RequestType, UserType>()
  .use(new TimingMiddleware<RequestType, UserType>())
  .handle(controller);
```

### Why Both Generics Are Required

The `<TBody, TUser>` generics preserve the type chain through the entire middleware pipeline. When you omit them, `context.req.validatedBody` and `context.user` lose their types, and downstream middleware and the handler receive `unknown` instead of the specific types you defined on the Handler.

## Pattern 2: Factory Function Middleware

For simpler, stateless middleware you can use a factory function that returns a middleware object. This is lighter-weight and works well when the middleware needs configuration parameters.

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

export const loggingMiddleware = <TBody = unknown, TUser = unknown>(
  logLevel: 'debug' | 'info' | 'error' = 'info'
): BaseMiddleware<TBody, TUser> => ({
  async before(context: Context<TBody, TUser>): Promise<void> {
    console.log(`[${logLevel}] Request started: ${context.req.method} ${context.req.path}`);
  },

  async after(context: Context<TBody, TUser>): Promise<void> {
    console.log(`[${logLevel}] Request completed: ${context.res.statusCode}`);
  },

  async onError(context: Context<TBody, TUser>, error: unknown): Promise<void> {
    console.error(`[error] Request failed:`, error);
  }
});

// Usage with configuration
const handler = new Handler<RequestType, UserType>()
  .use(loggingMiddleware<RequestType, UserType>('debug'))
  .handle(controller);
```

## Pattern 3: Middleware with Dependency Injection

Access services from the DI container within middleware using the `getService()` helper.

```typescript
import { BaseMiddleware, Context, getService } from '@noony-serverless/core';

class AuditMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async after(context: Context<TBody, TUser>): Promise<void> {
    const auditService = getService(context, AuditService);

    await auditService.log({
      userId: context.user?.id,
      action: `${context.req.method} ${context.req.path}`,
      status: context.res.statusCode,
      timestamp: new Date()
    });
  }
}
```

This middleware does not need to know how `AuditService` was created or where it lives. The DI container resolves it at runtime from either the global or local scope.

## Pattern 4: Conditional Middleware

Middleware that runs its logic only when certain conditions are met. This is useful for caching, feature flags, or method-specific behavior.

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

export class ConditionalCachingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  constructor(private cacheConfig: { enabled: boolean; ttl: number }) {}

  async before(context: Context<TBody, TUser>): Promise<void> {
    if (!this.cacheConfig.enabled) return;
    if (context.req.method !== 'GET') return;

    const cacheKey = `${context.req.path}`;
    const cached = await cacheService.get(cacheKey);

    if (cached) {
      context.businessData.set('cachedResponse', cached);
    }
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    if (!this.cacheConfig.enabled) return;
    if (context.req.method !== 'GET') return;

    const cachedResponse = context.businessData.get('cachedResponse');
    if (cachedResponse) {
      context.res.json(cachedResponse);
      return;
    }

    if (context.res.statusCode === 200 && context.responseData) {
      const cacheKey = `${context.req.path}`;
      await cacheService.set(cacheKey, context.responseData, this.cacheConfig.ttl);
    }
  }
}
```

## Pattern 5: Inter-Middleware Communication via businessData

The `context.businessData` Map is the only supported way to pass data between middlewares. Never extend the Context interface or modify its built-in properties directly.

```typescript
// Middleware 1: Extract and store user info
class UserExtractionMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    const token = context.req.headers['authorization']?.replace('Bearer ', '');
    if (token) {
      const user = await tokenService.verify(token);
      context.businessData.set('extractedUser', user);
    }
  }
}

// Middleware 2: Use data from Middleware 1
class PermissionCheckMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    const user = context.businessData.get('extractedUser');
    if (!user) {
      throw new UnauthorizedError('No user found');
    }
    if (!user.permissions.includes('write')) {
      throw new ForbiddenError('Write permission required');
    }
  }
}

// Usage -- order matters: extraction must come before permission check
const handler = new Handler()
  .use(new UserExtractionMiddleware())
  .use(new PermissionCheckMiddleware())
  .handle(controller);
```

**Important:** Avoid key collisions in `businessData`. Use descriptive, namespaced keys. The key `'otel_span'` is reserved by `OpenTelemetryMiddleware`.

## Testing Custom Middleware

Test middleware in isolation by creating a context manually and calling lifecycle hooks directly.

```typescript
import { createContext } from '@noony-serverless/core';

describe('TimingMiddleware', () => {
  it('should record and calculate elapsed time', async () => {
    const middleware = new TimingMiddleware();
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    await middleware.before(context);
    await new Promise(r => setTimeout(r, 100));
    await middleware.after(context);

    const startTime = context.businessData.get('startTime') as number;
    expect(startTime).toBeDefined();
    expect(typeof startTime).toBe('number');
  });

  it('should handle errors in onError hook', async () => {
    const middleware = new TimingMiddleware();
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    await middleware.before(context);
    const error = new Error('Test error');
    await middleware.onError(context, error);

    const startTime = context.businessData.get('startTime') as number;
    expect(startTime).toBeDefined();
  });
});
```

For full handler chain testing patterns, see [Testing Handlers](../tutorials/04-testing-handlers.md).

## Anti-Patterns

### Middleware without generics

```typescript
// WRONG -- breaks the type chain silently
export class MyMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    // TBody and TUser are lost!
  }
}

// CORRECT -- always include both generics
export class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Full type safety preserved
  }
}
```

### Extending the Context interface

```typescript
// WRONG -- not portable, breaks framework compatibility
interface CustomContext extends Context {
  customData: string;
}

// CORRECT -- use the standard businessData Map
context.businessData.set('customData', 'test');
```

### Returning data from before()

```typescript
// WRONG -- the return value is ignored by the framework
async before(context: Context): Promise<void> {
  return { processedData: 'value' };  // Lost!
}

// CORRECT -- store in businessData for other middlewares to read
async before(context: Context): Promise<void> {
  context.businessData.set('processedData', 'value');
}
```

### Mutating read-only context properties

```typescript
// WRONG -- context.user and context.req are read-only
context.user = myUser;
context.req.body = parsedData;

// CORRECT -- use businessData for custom data
context.businessData.set('myUser', myUser);
context.businessData.set('parsedData', parsedData);
```

### Duplicate businessData keys across middlewares

If two middlewares write to the same key, the second silently overwrites the first. Use unique, descriptive keys to avoid collisions.

## See Also

- [Middleware Ordering](./middleware-ordering.md) -- Canonical ordering table and execution flow
- [Middleware Reference](../reference/middlewares/INDEX.md) -- Built-in middleware API reference
- [Type Inference](./type-inference.md) -- How generics flow through the pipeline
- [Dependency Injection](./dependency-injection.md) -- Using services inside middleware
