# Validation Middleware

Validates request body or query parameters against a Zod schema.

> **Related:** [Middleware Index](./INDEX.md) | [HTTP Attributes Middleware](./http-attributes.md)

## Purpose

The Validation Middleware uses Zod schemas to validate incoming request data. For `GET` requests, it validates `context.req.query`; for all other methods, it validates `context.req.parsedBody`. Validated data is stored in `context.req.validatedBody` (for non-GET) or overwrites `context.req.query` (for GET), giving handlers access to typed, validated data.

## When to Use

- Validating JSON request bodies before processing (POST, PUT, PATCH)
- Validating and transforming query parameters for GET endpoints
- Enforcing input contracts with rich Zod schemas (nested objects, enums, transforms)

## Import

```typescript
import {
  ValidationMiddleware,
  validationMiddleware,
} from '@noony-serverless/core';
```

## Constructor

### Class: `ValidationMiddleware<TBody, TUser>`

```typescript
new ValidationMiddleware(schema: z.ZodSchema)
```

| Parameter | Type | Description |
|---|---|---|
| `schema` | `z.ZodSchema` | Zod schema to validate against |

### Factory: `validationMiddleware()`

```typescript
validationMiddleware<TBody, TUser>(schema: z.ZodSchema): BaseMiddleware<TBody, TUser>
```

## Validation Behavior

| HTTP Method | Data Source | Result Location |
|---|---|---|
| `GET` | `context.req.query` | `context.req.query` (overwritten with validated data) |
| `POST`, `PUT`, `PATCH`, `DELETE` | `context.req.parsedBody` | `context.req.validatedBody` |

## Usage

### Body validation

```typescript
import { z } from 'zod';

const userSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().min(1),
  age: z.number().int().min(18).max(120),
});

const handler = new Handler()
  .use(new ProcessingMiddleware())
  .use(new ValidationMiddleware(userSchema))
  .handle(async (context) => {
    const user = context.req.validatedBody;
    const created = await createUser(user);
    return { id: created.id };
  });
```

### Query parameter validation

```typescript
const searchSchema = z.object({
  q: z.string().min(1),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
  status: z.enum(['active', 'inactive', 'pending']).optional(),
});

const handler = new Handler()
  .use(validationMiddleware(searchSchema))
  .handle(async (context) => {
    const { q, page, limit, status } = context.req.query;
    const results = await search(q, { page, limit, status });
    return { results };
  });
```

### Nested object validation

```typescript
const orderSchema = z.object({
  items: z.array(z.object({
    productId: z.string().uuid(),
    quantity: z.number().int().positive(),
  })).min(1),
  shipping: z.object({
    address: z.string().min(1),
    city: z.string().min(1),
    zip: z.string().regex(/^\d{5}(-\d{4})?$/),
  }),
  couponCode: z.string().optional(),
});

const handler = new Handler()
  .use(new ProcessingMiddleware())
  .use(new ValidationMiddleware(orderSchema))
  .handle(async (context) => {
    const order = context.req.validatedBody;
    return await processOrder(order);
  });
```

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | Determines data source by HTTP method, runs `schema.parseAsync()`, stores validated data. Throws `ValidationError` with Zod issue details on failure. |
| `after` | -- |
| `onError` | -- |

## Error Behavior

On validation failure, throws `ValidationError` (HTTP 400) with the Zod issues array serialized as the error `details` field:

```json
{
  "status": 400,
  "message": "Validation error",
  "code": "VALIDATION_ERROR",
  "details": "[{\"code\":\"invalid_type\",\"expected\":\"string\",\"received\":\"undefined\",\"path\":[\"email\"],\"message\":\"Required\"}]"
}
```

## Anti-patterns

- **Do not** use this middleware without a body parser for non-GET requests -- `context.req.parsedBody` must be populated first.
- **Do not** access `context.req.body` after validation -- use `context.req.validatedBody` for typed data.

## See Also

- [Processing Middleware](./processing.md) -- parses bodies before validation
- [HTTP Attributes Middleware](./http-attributes.md) -- `validatedQueryParameters()` for query-only validation
- [Error Classes Reference](../errors.md) -- `ValidationError` (400)
