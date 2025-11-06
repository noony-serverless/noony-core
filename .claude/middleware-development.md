# Noony Framework Middleware Development Rules

## BaseMiddleware Interface Implementation

### Core Middleware Pattern

```typescript
// Always implement BaseMiddleware with proper generics
interface BaseMiddleware<T = unknown, U = unknown> {
  before?: (context: Context<T, U>) => Promise<void>;
  after?: (context: Context<T, U>) => Promise<void>;
  onError?: (error: Error, context: Context<T, U>) => Promise<void>;
}

// ✅ CORRECT: Full generic implementation
class CustomMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Pre-processing logic with full type safety
    const requestData = context.req.validatedBody; // Type: T | undefined
    const user = context.user; // Type: U | undefined
  }
  
  async after(context: Context<T, U>): Promise<void> {
    // Post-processing logic
    const processingTime = Date.now() - context.startTime;
    console.log(`Request ${context.requestId} processed in ${processingTime}ms`);
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Error handling logic
    console.error(`Error in request ${context.requestId}:`, error.message);
  }
}
```

### Middleware Lifecycle Execution Order

```typescript
// Execution flow:
// 1. before() methods execute in registration order
// 2. Main handler executes
// 3. after() methods execute in REVERSE order
// 4. onError() methods execute in REVERSE order (if error occurs)

const handler = new Handler<RequestType, UserType>()
  .use(new MiddlewareA())  // before: 1st, after: 3rd, onError: 3rd
  .use(new MiddlewareB())  // before: 2nd, after: 2nd, onError: 2nd  
  .use(new MiddlewareC())  // before: 3rd, after: 1st, onError: 1st
  .handle(async (context) => {
    // Main business logic
  });
```

## Built-in Middleware Usage Patterns

### Error Handler Middleware (Always First)

```typescript
// ✅ CORRECT: ErrorHandlerMiddleware always goes first
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware<RequestType, UserType>())  // Always first
  .use(new AuthenticationMiddleware<RequestType, UserType>(tokenVerifier))
  .use(new BodyValidationMiddleware<RequestType, UserType>(schema))
  .handle(async (context) => {
    // Business logic - errors are properly caught and formatted
  });

// ❌ INCORRECT: Other middleware before error handler
const badHandler = new Handler<RequestType, UserType>()
  .use(new AuthenticationMiddleware<RequestType, UserType>(tokenVerifier))
  .use(new ErrorHandlerMiddleware<RequestType, UserType>())  // Too late
```

### Body Parsing and Validation Chain

```typescript
// ✅ CORRECT: Parse then validate
const handler = new Handler<CreateUserRequest, UserType>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, UserType>())
  .use(new BodyParserMiddleware<CreateUserRequest, UserType>())      // Parse JSON
  .use(new BodyValidationMiddleware<CreateUserRequest, UserType>(    // Validate parsed
    z.object({
      name: z.string().min(2),
      email: z.string().email(),
      age: z.number().min(18)
    })
  ))
  .handle(async (context) => {
    const { name, email, age } = context.req.validatedBody!; // Fully typed
  });
```

### Authentication Flow

```typescript
interface AuthTokenVerifier {
  verify(token: string): Promise<{ valid: boolean; user?: UserType; error?: string }>;
}

const tokenVerifier: AuthTokenVerifier = {
  async verify(token: string) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!);
      const user = await userService.findById(decoded.sub);
      return { valid: true, user };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }
};

const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware<RequestType, UserType>())
  .use(new AuthenticationMiddleware<RequestType, UserType>(tokenVerifier))
  .handle(async (context) => {
    const user = context.user!; // User is guaranteed to exist after authentication
  });
```

### Response Wrapper (Always Last)

```typescript
// ✅ CORRECT: ResponseWrapperMiddleware goes last
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware<RequestType, UserType>())
  .use(new AuthenticationMiddleware<RequestType, UserType>(tokenVerifier))
  .use(new BodyValidationMiddleware<RequestType, UserType>(schema))
  // ... other middleware
  .use(new ResponseWrapperMiddleware<RequestType, UserType>())  // Always last
  .handle(async (context) => {
    // Business logic
    return { message: "Success" };  // Will be wrapped in standard format
  });
```

## Custom Middleware Development Patterns

### Data Enrichment Middleware

```typescript
class UserEnrichmentMiddleware<T, U extends { id: string }> implements BaseMiddleware<T, U> {
  constructor(private userService: UserService) {}
  
  async before(context: Context<T, U>): Promise<void> {
    const user = context.user;
    if (!user?.id) return;
    
    // Enrich user with additional data
    const profile = await this.userService.getProfile(user.id);
    const preferences = await this.userService.getPreferences(user.id);
    
    // Store in businessData for other middleware to use
    context.businessData?.set('userProfile', profile);
    context.businessData?.set('userPreferences', preferences);
  }
}
```

### Conditional Middleware

```typescript
class ConditionalMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(
    private condition: (context: Context<T, U>) => boolean,
    private middleware: BaseMiddleware<T, U>
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    if (this.condition(context) && this.middleware.before) {
      await this.middleware.before(context);
    }
  }
  
  async after(context: Context<T, U>): Promise<void> {
    if (this.condition(context) && this.middleware.after) {
      await this.middleware.after(context);
    }
  }
}

// Usage
const handler = new Handler<RequestType, UserType>()
  .use(new ConditionalMiddleware(
    (context) => context.req.headers['x-debug'] === 'true',
    new DetailedLoggingMiddleware()
  ));
```

### Rate Limiting Middleware

```typescript
class RateLimitingMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(
    private rateLimit: number = 100,
    private windowMs: number = 15 * 60 * 1000  // 15 minutes
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    const clientId = this.getClientId(context);
    const currentCount = await this.getCurrentCount(clientId);
    
    if (currentCount > this.rateLimit) {
      throw new TooManyRequestsError('Rate limit exceeded');
    }
    
    await this.incrementCount(clientId);
  }
  
  private getClientId(context: Context<T, U>): string {
    return context.req.ip || context.user?.id || 'anonymous';
  }
}
```

### Audit Trail Middleware

```typescript
class AuditTrailMiddleware<T, U extends { id: string }> implements BaseMiddleware<T, U> {
  constructor(private auditService: AuditService) {}
  
  async before(context: Context<T, U>): Promise<void> {
    context.businessData?.set('auditStartTime', Date.now());
  }
  
  async after(context: Context<T, U>): Promise<void> {
    const startTime = context.businessData?.get('auditStartTime');
    const duration = Date.now() - startTime;
    
    await this.auditService.logSuccess({
      requestId: context.requestId,
      userId: context.user?.id,
      action: this.getActionFromPath(context.req.path),
      duration,
      timestamp: new Date()
    });
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    const startTime = context.businessData?.get('auditStartTime');
    const duration = Date.now() - startTime;
    
    await this.auditService.logError({
      requestId: context.requestId,
      userId: context.user?.id,
      action: this.getActionFromPath(context.req.path),
      error: error.message,
      duration,
      timestamp: new Date()
    });
  }
}
```

## Middleware Composition Patterns

### Middleware Factory Pattern

```typescript
class MiddlewareFactory {
  static createValidatedHandler<T, U>(
    schema: z.ZodSchema<T>,
    tokenVerifier: AuthTokenVerifier,
    businessLogic: (context: Context<T, U>) => Promise<void>
  ): Handler<T, U> {
    return new Handler<T, U>()
      .use(new ErrorHandlerMiddleware<T, U>())
      .use(new HeaderVariablesMiddleware<T, U>(['authorization']))
      .use(new AuthenticationMiddleware<T, U>(tokenVerifier))
      .use(new BodyParserMiddleware<T, U>())
      .use(new BodyValidationMiddleware<T, U>(schema))
      .use(new ResponseWrapperMiddleware<T, U>())
      .handle(businessLogic);
  }
  
  static createPublicHandler<T>(
    schema: z.ZodSchema<T>,
    businessLogic: (context: Context<T, unknown>) => Promise<void>
  ): Handler<T, unknown> {
    return new Handler<T, unknown>()
      .use(new ErrorHandlerMiddleware<T, unknown>())
      .use(new BodyParserMiddleware<T, unknown>())
      .use(new BodyValidationMiddleware<T, unknown>(schema))
      .use(new ResponseWrapperMiddleware<T, unknown>())
      .handle(businessLogic);
  }
}
```

### Middleware Pipeline Builder

```typescript
class PipelineBuilder<T, U> {
  private middleware: BaseMiddleware<T, U>[] = [];
  
  withErrorHandling(): PipelineBuilder<T, U> {
    this.middleware.push(new ErrorHandlerMiddleware<T, U>());
    return this;
  }
  
  withAuthentication(verifier: AuthTokenVerifier): PipelineBuilder<T, U> {
    this.middleware.push(new AuthenticationMiddleware<T, U>(verifier));
    return this;
  }
  
  withValidation(schema: z.ZodSchema<T>): PipelineBuilder<T, U> {
    this.middleware.push(new BodyParserMiddleware<T, U>());
    this.middleware.push(new BodyValidationMiddleware<T, U>(schema));
    return this;
  }
  
  withCustom(middleware: BaseMiddleware<T, U>): PipelineBuilder<T, U> {
    this.middleware.push(middleware);
    return this;
  }
  
  build(businessLogic: (context: Context<T, U>) => Promise<void>): Handler<T, U> {
    const handler = new Handler<T, U>();
    this.middleware.forEach(middleware => handler.use(middleware));
    return handler.handle(businessLogic);
  }
}

// Usage
const handler = new PipelineBuilder<CreateUserRequest, AuthenticatedUser>()
  .withErrorHandling()
  .withAuthentication(tokenVerifier)
  .withValidation(createUserSchema)
  .withCustom(new AuditTrailMiddleware(auditService))
  .build(async (context) => {
    // Business logic
  });
```

## Performance Considerations

### Avoid Heavy Operations in Middleware

```typescript
// ✅ CORRECT: Lightweight middleware with async operations
class OptimizedMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Fast synchronous checks first
    if (!context.req.headers.authorization) {
      throw new AuthenticationError('Authorization header required');
    }
    
    // Then async operations
    const user = await this.userService.getUser(context.userId);
    context.businessData?.set('user', user);
  }
}

// ❌ INCORRECT: Heavy synchronous operations
class SlowMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Avoid heavy sync operations
    const heavyComputation = this.performExpensiveSync(); // Blocks event loop
  }
}
```

### Cache Frequently Accessed Data

```typescript
class CachedUserMiddleware<T, U> implements BaseMiddleware<T, U> {
  private cache = new Map<string, any>();
  private readonly cacheTTL = 5 * 60 * 1000; // 5 minutes
  
  async before(context: Context<T, U>): Promise<void> {
    const userId = this.extractUserId(context);
    if (!userId) return;
    
    const cacheKey = `user:${userId}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp) < this.cacheTTL) {
      context.businessData?.set('user', cached.data);
      return;
    }
    
    const user = await this.userService.getUser(userId);
    this.cache.set(cacheKey, { data: user, timestamp: Date.now() });
    context.businessData?.set('user', user);
  }
}
```

## Testing Middleware

### Unit Testing Pattern

```typescript
describe('CustomMiddleware', () => {
  let middleware: CustomMiddleware<TestRequest, TestUser>;
  let mockContext: Context<TestRequest, TestUser>;
  
  beforeEach(() => {
    middleware = new CustomMiddleware();
    mockContext = {
      req: { validatedBody: { test: 'data' } },
      res: { json: jest.fn(), status: jest.fn() },
      user: { id: 'test-user', role: 'user' },
      requestId: 'test-request-id',
      startTime: Date.now(),
      businessData: new Map()
    } as any;
  });
  
  it('should process request correctly', async () => {
    await middleware.before!(mockContext);
    
    expect(mockContext.businessData?.get('processed')).toBe(true);
  });
  
  it('should handle errors gracefully', async () => {
    const error = new Error('Test error');
    
    await middleware.onError!(error, mockContext);
    
    expect(mockContext.businessData?.get('errorHandled')).toBe(true);
  });
});
```

## Middleware Best Practices

1. **Always use generics** for type safety
2. **Keep middleware focused** - single responsibility
3. **Use context.businessData** to share data between middleware
4. **Handle errors appropriately** in onError hooks
5. **Consider performance impact** - avoid heavy sync operations
6. **Cache frequently accessed data** when appropriate
7. **Test middleware in isolation** with proper mocks
8. **Document middleware behavior** and dependencies
9. **Use proper error types** from the framework's error system
10. **Consider middleware order** - some operations depend on others