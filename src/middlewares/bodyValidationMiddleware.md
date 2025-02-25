# Request Handler with Validator

A type-safe request validation middleware using Zod schemas for Google Cloud Functions and Firebase.

## Features

- Schema-based validation using Zod
- Type inference from schemas
- Detailed validation error messages
- Integration with Handler framework
- TypeScript support

## Installation

```bash
npm install @noony/core zod
```

## Basic Usage

### 1. Define Your Schema

```typescript
import { z } from 'zod';
import { Handler, bodyValidator } from '@noony/core';

const userSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  age: z.number().min(18)
});

type User = z.infer<typeof userSchema>;
```

### 2. Create Handler with Validation

```typescript
const createUser = new Handler()
  .use(errorHandler())
  .use(bodyValidator(userSchema))
  .handle(async (context) => {
    const { validatedBody } = context.req;
    // validatedBody is fully typed as User
  });
```

## Schema Examples

### Complex Objects

```typescript
const complexSchema = z.object({
  id: z.string().uuid(),
  data: z.object({
    items: z.array(z.object({
      id: z.number(),
      name: z.string()
    })),
    metadata: z.record(z.unknown())
  })
});
```

### Pub/Sub Messages

```typescript
const pubSubSchema = z.object({
  action: z.enum(['CREATE', 'UPDATE', 'DELETE']),
  timestamp: z.number(),
  payload: z.object({
    // Your payload schema
  })
});
```

## Error Handling

Validation errors include detailed information:

```typescript
const handler = new Handler()
  .use(errorHandler())
  .use(bodyValidator(schema))
  .handle(async (context) => {
    // Validation errors are caught by error handler
    // and include field-specific details
  });
```

## Type Safety

```typescript
const schema = z.object({
  user: z.object({
    id: z.string(),
    roles: z.array(z.string())
  })
});

type ValidatedData = z.infer<typeof schema>;

const handler = new Handler()
  .use(bodyValidator(schema))
  .handle(async (context) => {
    const { validatedBody } = context.req; // Type: ValidatedData
    const { user } = validatedBody; // Fully typed
  });
```

## Testing

```typescript
describe('Validation', () => {
  it('validates correct data', async () => {
    const handler = new Handler()
      .use(bodyValidator(schema))
      .handle(async (context) => {
        // Test logic
      });

    const req = { body: validData };
    const res = {};
    
    await handler.execute(req, res);
  });

  it('rejects invalid data', async () => {
    // Test with invalid data
  });
});
```

## Best Practices

1. **Define Reusable Schemas**
   ```typescript
   const baseSchema = z.object({...});
   const extendedSchema = baseSchema.extend({...});
   ```

2. **Use Type Inference**
   ```typescript
   type ValidatedType = z.infer<typeof yourSchema>;
   ```

3. **Compose Validators**
   ```typescript
   const handler = new Handler()
     .use(bodyValidator(schemaA))
     .use(bodyValidator(schemaB))
   ```

## Common Validation Patterns

```typescript
// Required fields
const required = z.object({
  id: z.string(),
  email: z.string().email()
});

// Optional fields
const optional = z.object({
  name: z.string().optional(),
  age: z.number().optional()
});

// Arrays
const arraySchema = z.array(z.string());

// Enums
const enumSchema = z.enum(['A', 'B', 'C']);
```
