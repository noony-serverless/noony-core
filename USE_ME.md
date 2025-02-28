# TypeScript Request Handler System

A flexible request handling system for TypeScript applications with middleware support. This system provides a robust way to handle HTTP requests and manage request context.

## Core Components

### Context

The `Context` interface provides a wrapper for request handling with request and response data.

```typescript
interface Context {
  req: CustomRequest;
  res: CustomResponse;
  container?: Container;
  error?: Error | null;
  businessData: Map<string, unknown>;
  user?: unknown;
}
```

Key Properties:
- `req`: The enhanced request object
- `res`: The response object
- `container`: Optional dependency injection container
- `error`: Error handling property
- `businessData`: Storage for business logic data
- `user`: Optional user information

### Handler

The `Handler` class manages the request processing pipeline through middleware chains.

```typescript
const handler = new Handler()
  .use(middleware1())
  .use(middleware2())
  .handle(async (context) => {
    // Handler logic
  });
```

### BaseMiddleware

Interface for creating middleware with lifecycle hooks:

```typescript
interface BaseMiddleware {
  before?: (context: Context) => Promise<void>;
  after?: (context: Context) => Promise<void>;
  onError?: (error: Error, context: Context) => Promise<void>;
}
```

## Middleware Types

### 1. Class-based Middleware

```typescript
class AuthenticationMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    const token = context.req.headers.authorization;
    if (!token) {
      throw new Error('No authorization header');
    }
    // Authentication logic
  }
  
  async after(context: Context): Promise<void> {
    // Post-processing
  }
  
  async onError(error: Error, context: Context): Promise<void> {
    // Error handling
  }
}
```

### 2. Functional Middleware

```typescript
const errorHandler = () => ({
  onError: async (error: Error, context: Context) => {
    context.error = error;
    context.res.status(500).json({
      error: error.message
    });
  }
});

const bodyParser = () => async (context: Context) => {
  if (context.req.body) {
    context.req.parsedBody = JSON.parse(context.req.body);
  }
};
```

## Usage Examples

### Basic Request Handler

```typescript
const createUser = new Handler()
  .use(errorHandler())
  .use(bodyParser())
  .handle(async (context) => {
    const { parsedBody } = context.req;
    // Handler implementation
  });
```

### Middleware Chain

```typescript
const apiHandler = new Handler()
  .use(errorHandler())       // Error handling
  .use(bodyParser())        // Request parsing
  .use(authentication())    // Auth checks
  .use(validation())       // Input validation
  .use(businessLogic())    // Business rules
  .handle(async (context) => {
    // Main handler logic
  });
```

## Built-in Middleware Examples

### 1. Error Handler Middleware

```typescript
const errorHandler = () => ({
  onError: async (error: Error, context: Context) => {
    if (error instanceof HttpError) {
      context.res.status(error.status).json({
        error: error.message
      });
    } else {
      context.res.status(500).json({
        error: 'Internal Server Error'
      });
    }
  }
});
```

### 2. Authentication Middleware

```typescript
const authMiddleware = () => ({
  before: async (context: Context) => {
    const token = context.req.headers.authorization;
    if (!token) {
      throw new Error('Unauthorized');
    }
    context.user = await validateToken(token);
  }
});
```

### 3. Body Parser Middleware

```typescript
const bodyParser = () => ({
  before: async (context: Context) => {
    if (context.req.body) {
      context.req.parsedBody = JSON.parse(context.req.body);
    }
  }
});
```

## Best Practices

1. **Middleware Order**
   ```typescript
   new Handler()
     .use(errorHandler())    // Always first
     .use(bodyParser())      // Then parse input
     .use(authentication())  // Then authenticate
     .use(validation())      // Then validate
     .handle(async (context) => {
       // Handler logic
     });
   ```

2. **Error Handling**
   ```typescript
   try {
     // Your logic
   } catch (error) {
     context.error = error;
     // Handle appropriately
   }
   ```

3. **Business Data Management**
   ```typescript
   // Store computed values
   context.businessData.set('orderTotal', 100);
   
   // Retrieve values
   const total = context.businessData.get('orderTotal');
   ```

## Error Types

The system includes built-in error classes:

- `HttpError`: Base class for HTTP errors
```typescript
class HttpError extends Error {
  status: number;
  code?: string;
}
```

- `ValidationError`: For request validation failures
- `AuthenticationError`: For authentication issues

## Notes

- Implement proper error handling in your middlewares
- Consider the order of middleware execution
- Use the container for dependency injection when needed
- Keep middleware functions focused and single-purpose
- Use the businessData map for sharing data between middlewares

## Common Patterns

### Request Processing

```typescript
const processRequest = new Handler()
  .use(errorHandler())
  .handle(async (context) => {
    try {
      // Process the request
      return { success: true };
    } catch (error) {
      context.error = error;
    }
  });
```

### Response Formatting

```typescript
const responseWrapper = () => ({
  after: async (context: Context) => {
    const response = {
      success: !context.error,
      data: context.businessData.get('result'),
      error: context.error?.message
    };
    context.res.json(response);
  }
});
```
