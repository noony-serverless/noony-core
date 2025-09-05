# Noony Framework Core Architecture Rules

## Handler System Patterns

### Always Use Generics for Type Safety

```typescript
// ✅ CORRECT: Full generics provide complete type safety
const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware<CreateUserRequest, AuthenticatedUser>(tokenVerifier))
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(schema))
  .handle(async (context: Context<CreateUserRequest, AuthenticatedUser>) => {
    const data = context.req.validatedBody!; // Type: CreateUserRequest
    const user = context.user!; // Type: AuthenticatedUser
  });

// ❌ INCORRECT: No generics lose type safety
const badHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    const data = context.req.validatedBody; // Type: any
    const user = context.user; // Type: any
  });
```

### Handler Generic Type Flow

```typescript
// T = Request body type after validation
// U = User type after authentication
interface Handler<T = unknown, U = unknown> {
  use<TReq = T, UUser = U>(middleware: BaseMiddleware<TReq, UUser>): Handler<TReq, UUser>
  handle(businessLogic: (context: Context<T, U>) => Promise<void>): void
  execute(req: any, res: any): Promise<void>
  executeGeneric(req: GenericRequest<T>, res: GenericResponse): Promise<void>
}
```

### Context System Usage

```typescript
interface Context<T = unknown, U = unknown> {
  req: {
    body?: any;                    // Raw body
    parsedBody?: any;             // After JSON parsing
    validatedBody?: T;            // After Zod validation (Type: T)
    headers: Record<string, string | string[]>;
    query?: Record<string, any>;
    params?: Record<string, any>;
  };
  res: GenericResponse;
  user?: U;                       // After authentication (Type: U)
  requestId: string;              // Auto-generated UUID
  startTime: number;              // Performance tracking
  timeoutSignal?: AbortSignal;    // Request timeout handling
  businessData?: Map<string, any>; // Share data between middleware
}
```

### Framework Execution Patterns

```typescript
// Google Cloud Functions (Legacy)
export const myFunction = http('myFunction', (req, res) => {
  return handler.execute(req, res);
});

// Framework Agnostic (Fastify, Express, etc.)
fastify.post('/users', async (request, reply) => {
  return handler.executeGeneric(request, reply);
});

// Express middleware adapter
const expressAdapter = (handler: Handler) => async (req, res, next) => {
  try {
    await handler.executeGeneric(req, res);
    if (!res.headersSent) next();
  } catch (error) {
    next(error);
  }
};
```

## Container Pool Performance Optimization

### Use Container Pool for Cold Start Performance

```typescript
// ✅ CORRECT: Use containerPool for better performance
import { containerPool } from './core/containerPool';

const handler = new Handler<RequestType, UserType>()
  .handle(async (context) => {
    // Container is pre-warmed and pooled
    const userService = containerPool.get(UserService);
  });

// ❌ INCORRECT: Direct Container usage in serverless
import { Container } from 'typedi';
const userService = Container.get(UserService); // Slower cold starts
```

### Container Pool Best Practices

```typescript
// Initialize services once during cold start
const initializeServices = () => {
  containerPool.register([
    UserService,
    EmailService,
    DatabaseService
  ]);
};

// Pre-warm container pool
await initializeServices();
```

## Request/Response Flow Patterns

### GenericRequest/GenericResponse Interfaces

```typescript
// Framework-agnostic interfaces work with any HTTP framework
interface GenericRequest<T = unknown> {
  method: HttpMethod | string;
  url: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  params: Record<string, string>;
  body?: unknown;
  rawBody?: Buffer | string;
  parsedBody?: T;      // After JSON parsing
  validatedBody?: T;   // After validation (matches Handler<T>)
  ip?: string;
  userAgent?: string;
}

interface GenericResponse {
  status(code: number): GenericResponse;
  json(data: unknown): GenericResponse | void;
  send(data: unknown): GenericResponse | void;
  header(name: string, value: string): GenericResponse;
  headers(headers: Record<string, string>): GenericResponse;
  end(): void;
  statusCode?: number;
  headersSent?: boolean;
}
```

### Context Creation Patterns

```typescript
// Context is automatically created with proper typing
const createContext = <T, U>(
  req: GenericRequest<T>,
  res: GenericResponse,
  user?: U
): Context<T, U> => ({
  req,
  res,
  user,
  requestId: generateRequestId(),
  startTime: Date.now(),
  businessData: new Map()
});
```

## Error System Integration

### Built-in Error Classes

```typescript
// Use framework's built-in error classes for proper HTTP status codes
import {
  HttpError,           // Base error with custom status
  ValidationError,     // 400 - Input validation failures
  AuthenticationError, // 401 - Authentication failures  
  SecurityError,       // 403 - Security violations
  TimeoutError,        // 408 - Request timeouts
  TooLargeError,      // 413 - Request size limits
  BusinessError       // Custom business logic errors
} from '@noony-serverless/core';

// ✅ CORRECT: Use specific error types
throw new ValidationError('Email format is invalid');
throw new AuthenticationError('Invalid JWT token');
throw new BusinessError('Insufficient balance', 'INSUFFICIENT_FUNDS');

// ❌ INCORRECT: Generic errors lose HTTP status information
throw new Error('Something went wrong'); // No status code context
```

## Performance Monitoring

### Built-in Performance Tracking

```typescript
// Context automatically includes performance tracking
const handler = new Handler<RequestType, UserType>()
  .handle(async (context) => {
    // requestId and startTime are automatically available
    console.log(`Processing request ${context.requestId}`);
    
    // Business logic timing
    const operationStart = Date.now();
    await someOperation();
    const operationTime = Date.now() - operationStart;
    
    // Total request time available in onError/after hooks
    const totalTime = Date.now() - context.startTime;
  });
```

### Performance Monitor Integration

```typescript
import { PerformanceMonitor } from '@noony-serverless/core';

class CustomMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    PerformanceMonitor.startTimer(`custom-operation-${context.requestId}`);
  }
  
  async after(context: Context<T, U>): Promise<void> {
    PerformanceMonitor.endTimer(`custom-operation-${context.requestId}`);
  }
}
```

## Key Architecture Principles

### 1. Middleware Order Always Matters
```typescript
// ✅ CORRECT: Proper middleware ordering
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())        // 1. First - catches all errors
  .use(new HeaderVariablesMiddleware())     // 2. Early validation
  .use(new AuthenticationMiddleware())      // 3. Authentication
  .use(new BodyParserMiddleware())          // 4. Parse body
  .use(new BodyValidationMiddleware())      // 5. Validate parsed body
  .use(new BusinessMiddleware())            // 6. Business logic
  .use(new ResponseWrapperMiddleware())     // 7. Last - wraps response
```

### 2. Error Propagation Flow
- Errors trigger `onError` handlers in **reverse** middleware order
- Use `context.businessData` to share error context between middleware
- Always use appropriate error types for proper HTTP status codes

### 3. Shared State Management
```typescript
// Use context.businessData to share data between middleware
class ValidationMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    const validatedData = await validate(context.req.body);
    context.businessData?.set('validatedData', validatedData);
    context.businessData?.set('validationTimestamp', Date.now());
  }
}

class BusinessMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    const data = context.businessData?.get('validatedData');
    const timestamp = context.businessData?.get('validationTimestamp');
  }
}
```

### 4. Request Tracking and Observability
```typescript
// Every request gets automatic tracking
class LoggingMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    console.log(`[${context.requestId}] Request started at ${context.startTime}`);
  }
  
  async after(context: Context<T, U>): Promise<void> {
    const duration = Date.now() - context.startTime;
    console.log(`[${context.requestId}] Request completed in ${duration}ms`);
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    const duration = Date.now() - context.startTime;
    console.error(`[${context.requestId}] Request failed after ${duration}ms:`, error);
  }
}
```