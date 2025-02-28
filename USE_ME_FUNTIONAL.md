Below is a sample content for your README.md file that explains how to use the `Context`, `Handler`, functional middlewares, and the `BaseMiddleware` class without using generics:

---

# Project Overview

This project demonstrates how to organize and implement a middleware-based flow for handling requests. It covers the following components:

- **Context**: Carries request-specific data across different processing stages.
- **Handler**: Acts as the endpoint function that completes the processing of a request.
- **Functional Middlewares**: Functions that wrap request handling logic for tasks such as logging, authentication, or data transformation.
- **BaseMiddleware Class**: A class-based approach to implement middleware logic using inheritance.

> **Note**: All examples are implemented without using generics to keep the implementation straightforward.

---

# Components

## Context

The `Context` is an object that holds data for each request. It typically contains properties such as request parameters, user information, or other metadata that needs to be shared across multiple processing layers.

### Example

```javascript
// context.js

/**
 * Creates a new context for handling a request.
 * @param {object} requestData - The data associated with the incoming request.
 * @returns {object} The new context object.
 */
function createContext(requestData) {
  return {
    data: requestData,
    startTime: Date.now(),
    // ... other common properties
  };
}

module.exports = { createContext };
```

## Handler

The `Handler` is a function that takes a context, processes the information, and returns a response. It is the final step in the middleware chain.

### Example

```javascript
// handler.js

/**
 * A simple handler function to process the context and return a response.
 * @param {object} context - The context created for the request.
 * @returns {object} The response object.
 */
function handler(context) {
  // Process context.data and perform business logic
  console.log("Processing request data:", context.data);
  return {
    status: 200,
    message: "Request processed successfully",
  };
}

module.exports = { handler };
```

## Functional Middlewares

Functional middlewares are functions that accept a context and a "next" function. The middleware performs an operation (e.g., logging or authentication) and then calls `next()` to proceed to the next middleware or the final handler.

### Example

```javascript
// middlewares.js

/**
 * Middleware to log request details.
 * @param {object} context - The current request context.
 * @param {Function} next - The function to call the next middleware/handler.
 */
function logMiddleware(context, next) {
  console.log("Request received at:", new Date(context.startTime).toISOString());
  // Continue to the next middleware or handler
  return next(context);
}

/**
 * Middleware to perform a simple check on context data.
 * @param {object} context - The current request context.
 * @param {Function} next - The function to call the next middleware/handler.
 */
function checkMiddleware(context, next) {
  if (!context.data || !context.data.requiredField) {
    return {
      status: 400,
      message: "Missing required field",
    };
  }
  return next(context);
}

module.exports = { logMiddleware, checkMiddleware };
```

## BaseMiddleware Class

The `BaseMiddleware` class serves as a foundation for building middleware using an object-oriented approach. It contains a common structure that can be extended to create custom middleware classes.

### Example

```javascript
// BaseMiddleware.js

/**
 * The BaseMiddleware class defines a standard structure for middleware.
 */
class BaseMiddleware {
  /**
   * Process the context and call the next middleware/handler.
   * @param {object} context - The current request context.
   * @param {Function} next - The function to call the next middleware/handler.
   * @returns {object} The result after processing the context.
   */
  execute(context, next) {
    // Default implementation simply calls the next function
    return next(context);
  }
}

module.exports = BaseMiddleware;
```

### Extending BaseMiddleware

Here is an example of how a custom middleware can extend `BaseMiddleware`:

```javascript
// customMiddleware.js
const BaseMiddleware = require('./BaseMiddleware');

/**
 * Custom middleware that extends BaseMiddleware to add authentication logic.
 */
class AuthMiddleware extends BaseMiddleware {
  execute(context, next) {
    // Example: Check if the user is authenticated
    if (!context.data || !context.data.userAuthenticated) {
      return {
        status: 401,
        message: "Unauthorized",
      };
    }
    // Proceed to the next middleware/handler
    return next(context);
  }
}

module.exports = AuthMiddleware;
```

---

# How it All Fits Together

You can compose your middleware stack by chaining the functional middlewares and the final handler. For class-based middlewares, instantiate the middleware class and call its `execute` method.

### Example of a Middleware Pipeline

```javascript
// server.js
const { createContext } = require('./context');
const { handler } = require('./handler');
const { logMiddleware, checkMiddleware } = require('./middlewares');
const AuthMiddleware = require('./customMiddleware');

/**
 * Compose middlewares and the final handler into a single pipeline.
 * @param {object} requestData - The incoming request data.
 */
function processRequest(requestData) {
  // Create a new context for the request
  const context = createContext(requestData);
  
  // Define the 'next' function that eventually calls the main handler
  const finalHandler = (ctx) => handler(ctx);

  // Chain middlewares manually. In a real application, you might automate this chain.
  const authMiddleware = new AuthMiddleware();
  
  // Execute chain: log -> check -> auth -> handler
  const chain = (ctx) =>
    logMiddleware(ctx, (ctx2) =>
      checkMiddleware(ctx2, (ctx3) =>
        authMiddleware.execute(ctx3, finalHandler)
      )
    );
  
  // Start processing the request
  return chain(context);
}

// Example usage:
const requestData = {
  requiredField: true,
  userAuthenticated: true, // Set to false to simulate unauthorized access
};

console.log(processRequest(requestData));
```

---

# Conclusion

This sample project provides a basic architecture for handling requests using a context-driven approach combined with both functional and class-based middlewares. By following these patterns, you can create a robust middleware chain that manages request processing in a clean and modular manner.

Feel free to modify and extend the examples to suit the needs of your project!

---
