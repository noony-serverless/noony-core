# Resource: Middleware Development Patterns

## Pattern 1: Class-Based Middleware

Standard implementation with full lifecycle hooks (before, after, onError).

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

// Define middleware with proper generics
export class TimingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Record start time in context.businessData
    context.businessData.set('startTime', Date.now());
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    // Calculate elapsed time
    const startTime = context.businessData.get('startTime') as number;
    const elapsed = Date.now() - startTime;

    // Log or send metric
    console.log(`[Timing] Request completed in ${elapsed}ms`);
  }

  async onError(context: Context<TBody, TUser>, error: unknown): Promise<void> {
    // Track error timing
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

## Pattern 2: Factory Function Middleware

Stateless middleware created via factory function for simpler use.

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

// Factory function returns middleware instance
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
  .use(loggingMiddleware('info'))
  .use(loggingMiddleware<RequestType, UserType>('debug'))
  .handle(controller);
```

## Pattern 3: Middleware with Dependency Injection

Access services from the container within middleware.

```typescript
import { BaseMiddleware, Context, getService } from '@noony-serverless/core';

class AuditMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async after(context: Context<TBody, TUser>): Promise<void> {
    // Access injected service
    const auditService = getService(context, AuditService);

    // Log the action
    await auditService.log({
      userId: context.user?.id,
      action: `${context.req.method} ${context.req.path}`,
      status: context.res.statusCode,
      timestamp: new Date()
    });
  }
}
```

## Pattern 4: Conditional Middleware

Middleware that operates conditionally based on request or configuration.

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

export class ConditionalCachingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  constructor(private cacheConfig: { enabled: boolean; ttl: number }) {}

  async before(context: Context<TBody, TUser>): Promise<void> {
    if (!this.cacheConfig.enabled) return;

    // Only cache GET requests
    if (context.req.method !== 'GET') return;

    // Check if cached
    const cacheKey = `${context.req.path}`;
    const cached = await cacheService.get(cacheKey);

    if (cached) {
      // Store cached response for after() hook
      context.businessData.set('cachedResponse', cached);
    }
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    if (!this.cacheConfig.enabled) return;
    if (context.req.method !== 'GET') return;

    // Use cached response if available — set responseData so ResponseWrapperMiddleware sends it
    const cachedResponse = context.businessData.get('cachedResponse');
    if (cachedResponse) {
      context.responseData = cachedResponse;
      return;
    }

    // Cache successful responses (responseData set by the handler return value)
    if (context.responseData) {
      const cacheKey = `${context.req.path}`;
      await cacheService.set(cacheKey, context.responseData, this.cacheConfig.ttl);
    }
  }
}

// Usage
const handler = new Handler()
  .use(new ConditionalCachingMiddleware({ enabled: true, ttl: 3600 }))
  .handle(controller);
```

## Pattern 5: inter-Middleware Communication via businessData

Passing data between middlewares using the context.businessData Map.

```typescript
// Middleware 1: Extract and store user info
class UserExtractionMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Extract user from token and store in businessData
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

    // Verify permissions
    if (!user.permissions.includes('write')) {
      throw new ForbiddenError('Write permission required');
    }
  }
}

// Usage
const handler = new Handler()
  .use(new UserExtractionMiddleware())
  .use(new PermissionCheckMiddleware())
  .handle(controller);
```

## Anti-Patterns

### ❌ Middleware Without Generics

```typescript
// WRONG - Breaks type chain
export class MyMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    // Lost TBody and TUser types!
  }
}
```

### ✅ Correct: Always Include Generics

```typescript
// CORRECT
export class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Full type safety preserved
  }
}
```

### ❌ Extending Context Interface

```typescript
// WRONG - Creates custom interface, loses framework compatibility
interface CustomContext extends Context {
  customData: string;
}

class MyMiddleware {
  async before(context: CustomContext): Promise<void> {
    context.customData = 'test';  // Not portable
  }
}
```

### ✅ Correct: Use businessData Map

```typescript
// CORRECT - Uses standard framework pattern
class MyMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    context.businessData.set('customData', 'test');  // Standard approach
  }
}
```

### ❌ Returning Data from before()

```typescript
// WRONG - Return value is ignored
async before(context: Context): Promise<void> {
  return { processedData: 'value' };  // Lost!
}
```

### ✅ Correct: Store in businessData

```typescript
// CORRECT - Data available to other middlewares
async before(context: Context): Promise<void> {
  context.businessData.set('processedData', 'value');  // Available to others
}
```

## Testing Middleware

```typescript
import { createContext } from '@noony-serverless/core';

describe('TimingMiddleware', () => {
  it('should record and calculate elapsed time', async () => {
    const middleware = new TimingMiddleware();
    const mockReq = createMockRequest();
    const mockRes = createMockResponse();
    const context = createContext(mockReq, mockRes, {});

    // Simulate request
    await middleware.before(context);
    await new Promise(r => setTimeout(r, 100));  // Wait 100ms
    await middleware.after(context);

    // Verify timing was recorded
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

    // Verify error was logged/tracked
    const startTime = context.businessData.get('startTime') as number;
    expect(startTime).toBeDefined();
  });
});
```
