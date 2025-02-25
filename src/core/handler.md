# Handler and Middleware System Documentation

## Overview
The Handler system provides a flexible and type-safe way to process requests through a middleware chain. It's designed to handle both HTTP and Pub/Sub messages with proper error handling and request validation.

## Core Components

### Handler<T, U>
A class that manages the request processing pipeline with type parameters:
- `T`: Type for request/input data
- `U`: Type for user/context data

### BaseMiddleware<T, U>
An interface for creating middleware with lifecycle hooks:
- `before`: Executes before the main handler
- `after`: Executes after the main handler
- `onError`: Handles errors in the pipeline

## Basic Usage

### 1. Creating a Basic Handler
```typescript
interface MessagePayload {
  action: string;
  data: Record<string, unknown>;
}

const handler = new Handler<MessagePayload>()
  .use(errorHandler())
  .use(bodyParser())
  .handle(async (context) => {
    const { req } = context;
    // Handle the request
  });
```

### 2. Creating Custom Middleware
```typescript
const loggingMiddleware: BaseMiddleware<MessagePayload> = {
  before: async (context) => {
    console.log('Request started:', context.req.parsedBody);
  },
  after: async (context) => {
    console.log('Request completed');
  },
  onError: async (error, context) => {
    console.error('Error occurred:', error);
  }
};
```

### 3. Complete Pub/Sub Handler Example
```typescript
interface PubSubMessage {
  action: 'CREATE' | 'UPDATE' | 'DELETE';
  payload: Record<string, unknown>;
}

// Define validation schema
const messageSchema = z.object({
  action: z.enum(['CREATE', 'UPDATE', 'DELETE']),
  payload: z.record(z.unknown())
});

// Create the handler
export const processPubSubMessage = new Handler<PubSubMessage>()
  .use(errorHandler())
  .use(bodyParser())
  .use(bodyValidator(messageSchema))
  .handle(async (context) => {
    const { validatedBody } = context.req;

    switch (validatedBody.action) {
      case 'CREATE':
        await handleCreateAction(validatedBody.payload);
        break;
      case 'UPDATE':
        await handleUpdateAction(validatedBody.payload);
        break;
      case 'DELETE':
        await handleDeleteAction(validatedBody.payload);
        break;
    }
  });
```

## Advanced Usage

### 1. Type Transformation in Middleware Chain
```typescript
interface RawMessage {
  data: string;
}

interface ParsedMessage {
  action: string;
  payload: unknown;
}

const parsingMiddleware: BaseMiddleware<RawMessage, ParsedMessage> = {
  before: async (context) => {
    // Transform raw message to parsed message
    const parsed = JSON.parse(context.req.parsedBody?.data ?? '');
    context.req.parsedBody = parsed;
  }
};

const handler = new Handler<RawMessage>()
  .use(parsingMiddleware)
  .handle(async (context) => {
    // Context now has ParsedMessage type
  });
```

### 2. Error Handling Middleware
```typescript
const errorHandler = (): BaseMiddleware => ({
  onError: async (error, context) => {
    context.error = error;
    context.res.status(500).json({
      error: error.message
    });
  }
});
```

### 3. Authentication Middleware
```typescript
interface User {
  id: string;
  role: string;
}

const authMiddleware: BaseMiddleware<unknown, User> = {
  before: async (context) => {
    const token = context.req.headers.authorization;
    if (!token) {
      throw new Error('Unauthorized');
    }
    context.user = await validateToken(token);
  }
};
```

## Best Practices

### 1. Middleware Order
```typescript
new Handler()
  .use(errorHandler())       // First for error catching
  .use(bodyParser())         // Parse raw input
  .use(authMiddleware())     // Authenticate
  .use(bodyValidator())      // Validate parsed input
  .use(businessMiddleware()) // Business logic
  .handle(async (context) => {
    // Main handler logic
  });
```

### 2. Type Safety
```typescript
// Always define interfaces for your data
interface RequestType {
  id: string;
  data: Record<string, unknown>;
}

// Use type parameters in Handler
const typedHandler = new Handler<RequestType>()
  .use(typedMiddleware)
  .handle(async (context) => {
    // Full type safety here
    const { id, data } = context.req.parsedBody!;
  });
```

### 3. Context Usage
```typescript
// Store data in context.businessData for middleware communication
const dataMiddleware: BaseMiddleware = {
  before: async (context) => {
    context.businessData.set('startTime', Date.now());
  },
  after: async (context) => {
    const startTime = context.businessData.get('startTime');
    console.log('Processing time:', Date.now() - startTime);
  }
};
```

## Tips
1. Always include error handling middleware first in the chain
2. Use type parameters to ensure type safety throughout the pipeline
3. Keep middleware functions focused and single-purpose
4. Use the context.businessData map for sharing data between middleware
5. Handle errors appropriately in each middleware's onError hook

## Common Patterns

### Request Validation
```typescript
const validateRequest = <T>(schema: Schema): BaseMiddleware<T> => ({
  before: async (context) => {
    const validated = await schema.parse(context.req.parsedBody);
    context.req.validatedBody = validated;
  }
});
```

### Response Formatting
```typescript
const formatResponse: BaseMiddleware = {
  after: async (context) => {
    const response = context.res;
    if (!response.headersSent) {
      response.json({
        success: true,
        data: context.req.validatedBody
      });
    }
  }
};
```
