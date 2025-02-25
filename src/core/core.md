# Custom Request and Context Guide

## Overview
This guide explains how to use the `CustomRequest` and `Context` interfaces for handling HTTP requests in your TypeScript application with type safety.

## Interface Definitions

### CustomRequest<T>
Extends the standard HTTP Request with generic type support for request bodies.

#### Generic Parameters
- `T`: Type for both parsed and validated request body (defaults to `unknown`)

#### Properties
- `parsedBody?: T`: The parsed request body
- `validatedBody?: T`: The validated request body

### Context<T, V>
Provides a wrapper for request handling with type-safe request and user data.

#### Generic Parameters
- `T`: Type for request body (defaults to `unknown`)
- `V`: Type for user data (defaults to `unknown`)

#### Properties
- `req: CustomRequest<T>`: The enhanced request object
- `res: CustomResponse`: The response object
- `container?: Container`: Dependency injection container
- `error?: Error | null`: Error handling
- `businessData: Map<string, unknown>`: Storage for business logic data
- `user?: V`: User information

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

export const createUser = new Handler()
  .use(errorHandler())
  .use(bodyParser())
  .use(bodyValidator(userSchema))
  .handle(async (context: Context<UserRequest, UserData>) => {
    const { parsedBody, validatedBody } = context.req;
    const { user } = context;

    // Both parsedBody and validatedBody are typed as UserRequest
    console.log(validatedBody.name, validatedBody.email);

    // User is typed as UserData
    console.log(user?.role);

    return { success: true };
  });
```

### Using Business Data
```typescript
interface OrderRequest {
  items: Array<{ id: string; quantity: number }>;
}

export const processOrder = new Handler()
  .use(errorHandler())
  .handle(async (context: Context<OrderRequest>) => {
    // Store computed values
    context.businessData.set('orderTotal', 100);
    context.businessData.set('processedAt', new Date());

    // Retrieve values
    const total = context.businessData.get('orderTotal');

    return { total };
  });
```

### Error Handling Pattern
```typescript
export const safeHandler = new Handler()
  .use(errorHandler())
  .handle(async (context: Context<unknown>) => {
    try {
      // Your logic here
    } catch (error) {
      context.error = error as Error;
      // Handle error appropriately
    }
  });
```

## Common Middleware Examples

### 1. Body Parser
```typescript
const bodyParser = () => async <T>(
  context: Context<T>,
  next: () => Promise<void>
) => {
  if (context.req.body) {
    context.req.parsedBody = JSON.parse(context.req.body);
  }
  return next();
};
```

### 2. Validation Middleware
```typescript
const bodyValidator = (schema: z.ZodSchema) => async <T>(
  context: Context<T>,
  next: () => Promise<void>
) => {
  const { parsedBody } = context.req;
  const validated = await schema.parseAsync(parsedBody);
  context.req.validatedBody = validated as T;
  return next();
};
```

## Best Practices

1. **Type Definition**
```typescript
// Define clear interfaces for your request types
interface ApiRequest {
  data: string;
}

// Use them with Context
type ApiContext = Context<ApiRequest>;
```

2. **Error Handling**
```typescript
// Always check for errors in your handlers
if (context.error) {
  // Handle the error appropriately
  return { error: context.error.message };
}
```

3. **Business Data Management**
```typescript
// Type-safe business data access
function getBusinessValue<T>(
  context: Context<unknown>,
  key: string
): T | undefined {
  return context.businessData.get(key) as T;
}
```

4. **Container Usage**
```typescript
// Leverage the container for dependency injection
if (context.container) {
  const service = context.container.get(ServiceToken);
  await service.process();
}
```

## Tips and Tricks

1. **Type Inference**
```typescript
// Let TypeScript infer the types when possible
const handler = new Handler()
  .handle(async (context: Context<UserRequest>) => {
    const { parsedBody } = context.req; // Type is inferred as UserRequest
  });
```

2. **Middleware Chaining**
```typescript
// Chain middleware in a logical order
new Handler()
  .use(errorHandler())    // First for error catching
  .use(bodyParser())      // Then parse the body
  .use(authenticate())    // Then authenticate
  .use(validate())       // Then validate
  .handle(async (context) => {
    // Your handler logic
  });
```

3. **Business Data Type Safety**
```typescript
// Create type-safe business data keys
const BUSINESS_KEYS = {
  TOTAL: 'total',
  TIMESTAMP: 'timestamp'
} as const;

// Use them consistently
context.businessData.set(BUSINESS_KEYS.TOTAL, 100);
```

## Notes
- All generic parameters default to `unknown` if not specified
- The `CustomResponse` interface extends the standard Response interface
- The container property is optional and uses the `typedi` Container
- Always handle the possibility of undefined values for optional properties
