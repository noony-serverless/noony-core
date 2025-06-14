# Noony Serverless Framework - Usage Guide

A flexible and type-safe serverless middleware framework for Google Cloud Functions. This guide provides detailed examples of how to use the framework's features.

## Core Components

### Context with Generic Types

The `Context` interface provides type-safe request handling with generic support:

```typescript
interface Context<T = unknown, U = unknown> {
  req: CustomRequest<T>;     // Request with typed parsedBody and validatedBody
  res: CustomResponse;       // Response object
  container?: Container;     // TypeDI dependency injection container
  error?: Error | null;      // Error handling
  businessData: Map<string, unknown>; // Inter-middleware data sharing
  user?: U;                  // Typed authenticated user data
}
```

Key Properties:
- `req`: Enhanced request object with `parsedBody` and `validatedBody`
- `res`: Response object with `json()`, `status()`, and `send()` methods
- `container`: TypeDI dependency injection container
- `error`: Error object for centralized error handling
- `businessData`: Map for sharing data between middlewares
- `user`: Authenticated user information with proper typing

### Handler with Generics

The `Handler` class manages the request processing pipeline with full TypeScript support:

```typescript
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // TypeScript knows the exact types of validatedBody and user
    const { name } = context.req.validatedBody!; // No casting needed!
    const { userId } = context.user!;
  });
```

### BaseMiddleware with Generics

Interface for creating type-safe middleware with lifecycle hooks:

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
