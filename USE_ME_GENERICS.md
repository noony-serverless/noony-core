# TypeScript Request Handler System

A flexible and type-safe request handling system for TypeScript applications with middleware support. This system provides a robust way to handle HTTP requests and manage request context with proper typing.

## Core Components

### Context<T, V>

The `Context` interface provides a wrapper for request handling with type-safe request and user data.

```typescript
interface Context<T = unknown, V = unknown> {
  req: CustomRequest<T>;
  res: CustomResponse;
  container?: Container;
  error?: Error | null;
  businessData: Map<string, unknown>;
  user?: V;
}
```

Generic Parameters:
- `T`: Type for request body (defaults to `unknown`)
- `V`: Type for user data (defaults to `unknown`)

### Handler<T, U>

The `Handler` class manages the request processing pipeline through middleware chains.

```typescript
const handler = new Handler<RequestType, UserType>()
  .use(middleware1())
  .use(middleware2())
  .handle(async (context) => {
    // Handler logic
  });
```

Generic Parameters:
- `T`: Type for request/input data
- `U`: Type for user/context data

### BaseMiddleware<T, U>

Interface for creating middleware with lifecycle hooks:

```typescript
interface BaseMiddleware<T = unknown, U = unknown> {
  before?: (context: Context<T, U>) => Promise<void>;
  after?: (context: Context<T, U>) => Promise<void>;
  onError?: (error: Error, context: Context<T, U>) => Promise<void>;
}
```

## Middleware Types

### 1. Class-based Middleware

```typescript
class AuthenticationMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Authentication logic
  }
  
  async after(context: Context<T, U>): Promise<void> {
    // Post-processing
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Error handling
  }
}
```

### 2. Functional Middleware

```typescript
const errorHandler = (): BaseMiddleware => ({
  onError: async (error: Error, context: Context): Promise<void> => {
    // Error handling logic
  }
});

const bodyParser = () => async <T>(
  context: Context<T>,
  next: () => Promise<void>
) => {
  // Body parsing logic
  return next();
};
```

## Usage Examples

### Basic Request Handler

```typescript
interface UserRequest {
  name: string;
  email: string;
}

interface UserData {
  id: string;
  role: string;
}

const createUser = new Handler<UserRequest, UserData>()
  .use(errorHandler())
  .use(bodyParser())
  .handle(async (context) => {
    const { parsedBody } = context.req;
    const { user } = context;
    // Handler implementation
  });
```

### Middleware Chain

```typescript
const apiHandler = new Handler<ApiRequest, UserContext>()
  .use(errorHandler())       // Error handling
  .use(bodyParser())         // Request parsing
  .use(authentication())     // Auth checks
  .use(validation())         // Input validation
  .use(businessLogic())     // Business rules
  .handle(async (context) => {
    // Main handler logic
  });
```

## Best Practices

1. **Type Safety**
   ```typescript
   // Define clear interfaces
   interface RequestType {
     data: string;
   }
   
   interface UserType {
     id: string;
   }
   
   // Use with proper typing
   const handler = new Handler<RequestType, UserType>();
   ```

2. **Error Handling**
   ```typescript
   const errorMiddleware = (): BaseMiddleware => ({
     onError: async (error, context) => {
       context.error = error;
       // Handle error appropriately
     }
   });
   ```

3. **Business Data Management**
   ```typescript
   // Store computed values
   context.businessData.set('key', value);
   
   // Retrieve values
   const value = context.businessData.get('key');
   ```

## Error Types

The system includes built-in error types:

- `HttpError`: Base class for HTTP errors
- `ValidationError`: For request validation failures
- `AuthenticationError`: For authentication issues

## Notes

- Always implement proper error handling in your middlewares
- Use type parameters consistently throughout your middleware chain
- Consider the order of middleware execution
- Leverage the container for dependency injection when needed

