# Skill 8: Type-Safe Middleware Development

## Triggers

When user asks to:
- "Create middleware"
- "Add custom logic to handler"
- "Intercept requests"
- "How to write middleware"
- "Implement BaseMiddleware"

## What it provides

Template for `BaseMiddleware` implementation with:
- Full generic type safety
- `before`, `after`, and `onError` lifecycle hooks
- Context access

## Complete Example

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

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

## When to use

- Need to process request before handler
- Need to process response after handler
- Need global error handling logic
- Adding cross-cutting concerns (logging, metrics, etc.)
