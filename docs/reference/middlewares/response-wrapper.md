# Response Wrapper Middleware

Wraps handler return values in a standardized `{ success, payload, timestamp }` envelope.

> **Related:** [Middleware Index](./INDEX.md) | [Handler Guide](../../explanation/architecture.md)

## Purpose

The Response Wrapper Middleware runs in the `after` hook to wrap `context.responseData` into a consistent JSON response format. This ensures all API responses share the same envelope structure, making client-side parsing predictable. The Handler automatically sets `context.responseData` from your handler's return value.

## When to Use

- Standardizing API response format across all endpoints
- Adding a `success` flag and `timestamp` to every response
- Wrapping data in a `payload` field for consistent client consumption

## Import

```typescript
import {
  ResponseWrapperMiddleware,
  responseWrapperMiddleware,
} from '@noony-serverless/core';
```

## Constructor

### Class: `ResponseWrapperMiddleware<T, TBody, TUser>`

```typescript
new ResponseWrapperMiddleware(defaultStatusCode?: number)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `defaultStatusCode` | `number` | `200` | HTTP status code to use if none is set on the response |

### Factory: `responseWrapperMiddleware()`

```typescript
responseWrapperMiddleware<T, TBody, TUser>(defaultStatusCode?: number): BaseMiddleware<TBody, TUser>
```

## Response Format

```json
{
  "success": true,
  "payload": { /* your handler return value */ },
  "timestamp": "2026-03-17T12:00:00.000Z"
}
```

## Usage

### Basic

```typescript
interface UserResponse {
  id: string;
  name: string;
}

const handler = new Handler()
  .use(new ResponseWrapperMiddleware<UserResponse>())
  .handle(async (context) => {
    const user = await getUser(context.req.params.id);
    return user; // Wrapped as { success: true, payload: user, timestamp: "..." }
  });
```

### With custom status code

```typescript
const createHandler = new Handler()
  .use(responseWrapperMiddleware(201))
  .handle(async (context) => {
    const item = await createItem(context.req.parsedBody);
    return { id: item.id };
    // Response: 201 { success: true, payload: { id: "..." }, timestamp: "..." }
  });
```

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | -- |
| `after` | Reads `context.responseData`, sends JSON response with `success: true`, `payload`, and `timestamp`. Skips if `context.res.headersSent` is already true. |
| `onError` | -- |

## Anti-patterns

- **Do not** call `context.res.json()` manually in your handler when using this middleware -- the wrapper will attempt to send a second response.
- **Do not** use the deprecated `setResponseData()` helper. Simply return values from your handler.

## See Also

- [Handler Guide](../../explanation/architecture.md) -- how return values become `context.responseData`
- [Validation Middleware](./validation.md)
- [Error Classes Reference](../errors.md)
