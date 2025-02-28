# Custom Request Handling

This project demonstrates a type-safe approach to handling HTTP and Pub/Sub requests using a flexible middleware system. The design centers on four core concepts:

- **Context**: Encapsulates the request, response, and additional metadata.
- **Handler**: Manages a sequence of middleware executions and the main request processing function.
- **Functional Middlewares**: Functions that execute specific tasks (e.g., parsing, validation, authentication) during the lifecycle of a request.
- **BaseMiddleware**: A generic interface for creating middleware classes that implement lifecycle hooks.

---

## Table of Contents

1. [Overview](#overview)
2. [Context](#context)
3. [Handler](#handler)
4. [Functional Middlewares](#functional-middlewares)
5. [BaseMiddleware and Generics](#basemiddleware-and-generics)
6. [Usage Examples](#usage-examples)
7. [Best Practices](#best-practices)

---

## Overview

The project provides a middleware-based request processing system that gives you:

- **Type Safety** – Define and enforce the structure of request payloads and user data using generics.
- **Separation of Concerns** – Break down the request lifecycle into smaller, reusable middleware functions.
- **Enhanced Flexibility** – Easily compose and extend middleware chains for various scenarios, including error handling, body parsing, and schema validation.

---

## Context

The `Context` interface is the central data structure that encapsulates all aspects of a request:

- `req`: A custom request object that includes optionally parsed and validated bodies.
- `res`: A response object that can be customized as needed.
- `container`: An optional dependency injection container.
- `error`: An error object (if one occurs during processing).
- `businessData`: A map to store transient business-specific data.
- `user`: Information about the authenticated user.

### Example Definition

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

---

## Handler

The `Handler` class is responsible for processing the incoming request through a series of middlewares and ultimately executing the main handler function. It is generic over two types:

- `T`: The type for request data.
- `U`: The type for additional context or user data.

The middleware chain supports lifecycle hooks such as `before`, `after`, and `onError`.

### Creating a Handler

```typescript
const handler = new Handler<UserRequest, UserData>()
  .use(errorHandler()) // Example: error handling middleware
  .use(bodyParser())   // Example: body parsing middleware
  .handle(async (context: Context<UserRequest, UserData>) => {
    // Your main processing logic here
    const { parsedBody, validatedBody } = context.req;
    console.log(parsedBody, validatedBody);
  });
```

---

## Functional Middlewares

Functional middlewares are simple functions applied as part of the middleware chain. They typically use the following signature:

```typescript
const sampleMiddleware = () => async <T>(
  context: Context<T>,
  next: () => Promise<void>
) => {
  // Pre-processing logic here
  await next();
  // Post-processing logic here (if needed)
};
```

### Body Parsing Middleware Example

```typescript
const bodyParser = () => async <T>(
  context: Context<T>,
  next: () => Promise<void>
) => {
  if (context.req.body) {
    context.req.parsedBody = JSON.parse(context.req.body);
  }
  await next();
};
```

---

## BaseMiddleware and Generics

The `BaseMiddleware` interface defines the structure for middleware classes that come with lifecycle hooks:

- `before`: Executes before the main handler.
- `after`: Executes after the main handler.
- `onError`: Handles errors encountered during processing.

The interface is generic and allows you to define input and output types.

### BaseMiddleware Interface

```typescript
export interface BaseMiddleware<T = unknown, U = unknown> {
  before?: (context: Context<T, U>) => Promise<void>;
  after?: (context: Context<T, U>) => Promise<void>;
  onError?: (error: Error, context: Context<T, U>) => Promise<void>;
}
```

### Creating a Custom Middleware Class

```typescript
class LoggingMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    console.log('Request started:', context.req);
  }

  async after(context: Context<T, U>): Promise<void> {
    console.log('Request completed');
  }

  async onError(error: Error, context: Context<T, U>): Promise<void> {
    console.error('An error occurred:', error.message);
  }
}
```

---

## Usage Examples

### Example 1: Process User Request

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
  .handle(async (context: Context<UserRequest, UserData>) => {
    const { parsedBody, validatedBody } = context.req;
    // Process user data
    console.log('Name:', validatedBody.name);
    console.log('Email:', validatedBody.email);
    console.log('User Role:', context.user?.role);
  });
```

### Example 2: Processing Orders with Business Data

```typescript
interface OrderRequest {
  items: Array<{ id: string; quantity: number }>;
}

const processOrder = new Handler<OrderRequest>()
  .use(errorHandler())
  .handle(async (context: Context<OrderRequest>) => {
    // Set business data
    context.businessData.set('orderTotal', 100);
    // Retrieve processed total
    const total = context.businessData.get('orderTotal');
    console.log('Order Total:', total);
  });
```

---

## Best Practices

- **Define Explicit Types:**  
  Always create clear interfaces for your request and user data. This helps maintain type safety across your application.

- **Middleware Order:**  
  Pay attention to the order of middleware. Error handling should generally be among the first, while transformations like parsing and validation should follow.

- **Error Handling:**  
  Ensure each middleware that might throw errors is wrapped with proper error-handling logic. Use the onError hook in your BaseMiddleware for consistency.

- **Reuse Middlewares:**  
  Consider creating generic middlewares (e.g., for token authentication, logging, or validation) that can be reused across different handlers.

---

This README provides an overview of how to leverage Context, Handler, functional middlewares, and BaseMiddleware with generics to build a robust and scalable request processing system in TypeScript. Adjust and extend these examples as necessary to fit your application’s needs.

Happy coding!
