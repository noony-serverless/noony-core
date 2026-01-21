# Skill 9: Advanced Validation Schemas

## Triggers

When user asks to:
- "Add validation"
- "Validate request body"
- "Use Zod schema"
- "Type safe validation"

## What it provides

Zod schema patterns with type inference and complex validation rules (nested objects, arrays).

## Complete Example

```typescript
import { z } from 'zod';
import { Handler, BodyValidationMiddleware, ErrorHandlerMiddleware } from '@noony-serverless/core';

// define complex schema
const orderSchema = z.object({
  customerId: z.string().uuid('Invalid customer ID format'),
  items: z.array(z.object({
    productId: z.string().uuid(),
    quantity: z.number().min(1).max(99),
    price: z.number().positive(),
  })).min(1, 'Order must contain at least one item')
});

// Extract TypeScript type from schema
type CreateOrderRequest = z.infer<typeof orderSchema>;

// Use in handler
const handler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(orderSchema))
  .handle(async (ctx) => {
    // Fully typed access
    const { customerId, items } = ctx.req.validatedBody!; 
  });
```

## When to use

- Every endpoint that accepts input
- When you need strict type checking
- To generate TypeScript types automatically
