# HTTP Attributes Middleware

Extracts path parameters, validates headers, and validates query parameters from incoming requests.

> **Related:** [Middleware Index](./INDEX.md) | [Processing Middleware](./processing.md)

## Purpose

This file provides three focused factory functions and one class for HTTP request attribute handling: extracting URL path parameters into `context.req.params`, validating that required headers are present, and validating query parameters against a Zod schema. These are lightweight, composable middlewares for request preprocessing.

## When to Use

- Extracting path parameters from RESTful URLs
- Enforcing required headers (API keys, tenant IDs, content-type)
- Validating query parameters with Zod schemas before handler execution

## Import

```typescript
import {
  PathParametersMiddleware,
  pathParameters,
  headerVariablesValidator,
  validatedQueryParameters,
} from '@noony-serverless/core';
```

## Functions and Classes

### Class: `PathParametersMiddleware<TBody, TUser>`

```typescript
new PathParametersMiddleware()
```

Extracts URL path segments that start with `:` and sets them on `context.req.params`.

### Factory: `pathParameters()`

```typescript
pathParameters(): BaseMiddleware
```

Functional equivalent of `PathParametersMiddleware`.

### Factory: `headerVariablesValidator()`

```typescript
headerVariablesValidator(requiredHeaders: string[]): BaseMiddleware
```

| Parameter | Type | Description |
|---|---|---|
| `requiredHeaders` | `string[]` | Header names that must be present (checked case-insensitively) |

Throws `ValidationError` if any required header is missing.

### Factory: `validatedQueryParameters()`

```typescript
validatedQueryParameters(schema: ZodSchema): BaseMiddleware
```

| Parameter | Type | Description |
|---|---|---|
| `schema` | `ZodSchema` | Zod schema to validate `context.req.query` against |

Throws `ValidationError` with Zod issue details if validation fails.

## Usage

### Path parameters

```typescript
// URL: /users/123/posts/456
const handler = new Handler()
  .use(pathParameters())
  .handle(async (context) => {
    const { userId, postId } = context.req.params || {};
    return { userId, postId };
  });
```

### Required headers

```typescript
const handler = new Handler()
  .use(headerVariablesValidator(['x-tenant-id', 'authorization']))
  .handle(async (context) => {
    const tenantId = context.req.headers['x-tenant-id'];
    return { tenantId };
  });
```

### Query parameter validation

```typescript
import { z } from 'zod';

const paginationSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).default('1'),
  limit: z.string().regex(/^\d+$/).transform(Number).default('10'),
  sort: z.enum(['asc', 'desc']).default('asc'),
});

const handler = new Handler()
  .use(validatedQueryParameters(paginationSchema))
  .handle(async (context) => {
    const { page, limit, sort } = context.req.query;
    return { page, limit, sort };
  });
```

## Middleware Lifecycle

All three run in the `before` hook only.

| Function | Hook | Behavior |
|---|---|---|
| `pathParameters` | `before` | Parses URL, extracts `:param` segments into `context.req.params` |
| `headerVariablesValidator` | `before` | Checks each required header exists; throws `ValidationError` if missing |
| `validatedQueryParameters` | `before` | Parses `context.req.query` against Zod schema; throws `ValidationError` on failure |

## See Also

- [Processing Middleware](./processing.md) -- consolidated alternative that includes query processing and attribute extraction
- [Validation Middleware](./validation.md) -- validates request body or query with Zod
- [Error Classes Reference](../errors.md) -- `ValidationError` (400)
