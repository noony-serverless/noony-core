# Rate Limiting Middleware

Enforces request rate limits per client with dynamic tiers and pluggable storage.

> **Related:** [Middleware Index](./INDEX.md) | [Security Headers Middleware](./security-headers.md)

## Purpose

The Rate Limiting Middleware tracks request counts per key (IP, user, or custom) within sliding time windows and rejects excess requests with a `SecurityError`. It supports dynamic per-tier limits, custom key generation, skip conditions, pluggable storage backends, and standard `X-RateLimit-*` response headers.

## When to Use

- Protecting endpoints from abuse (login, registration, password reset)
- Enforcing per-user or per-subscription API quotas
- Complementing WAF/API Gateway rate limits with business-logic-aware rules

## Import

```typescript
import {
  RateLimitingMiddleware,
  rateLimiting,
  RateLimitOptions,
  RateLimitStore,
  RateLimitPresets,
  MemoryStore,
} from '@noony-serverless/core';
```

## Constructor

### Class: `RateLimitingMiddleware<TBody, TUser>`

```typescript
new RateLimitingMiddleware(options?: RateLimitOptions)
```

### Factory: `rateLimiting()`

```typescript
rateLimiting(options?: RateLimitOptions): BaseMiddleware
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `maxRequests` | `number` | `100` | Maximum requests per window |
| `windowMs` | `number` | `60000` (1 min) | Time window in milliseconds |
| `keyGenerator` | `(context) => string` | IP-based (includes user ID if authenticated) | Function to generate the rate limit key |
| `message` | `string` | `'Too many requests, please try again later'` | Error message when limit exceeded |
| `statusCode` | `number` | `429` | HTTP status code for limit exceeded |
| `skip` | `(context) => boolean` | -- | Skip rate limiting for certain requests |
| `headers` | `boolean` | `true` | Include `X-RateLimit-*` response headers |
| `dynamicLimits` | `Record<string, DynamicLimit>` | -- | Per-tier limits with matcher functions |
| `store` | `RateLimitStore` | `MemoryStore` | Storage backend for counters |

### `RateLimitStore` Interface

```typescript
interface RateLimitStore {
  increment(key: string, windowMs: number): Promise<{ count: number; resetTime: number }>;
  get(key: string): Promise<{ count: number; resetTime: number } | null>;
  reset(key: string): Promise<void>;
}
```

## Presets

| Preset | Requests/Min | Description |
|---|---|---|
| `RateLimitPresets.STRICT` | 5 | Sensitive operations (password reset, payment) |
| `RateLimitPresets.AUTH` | 10 | Authentication endpoints, keyed by IP + email |
| `RateLimitPresets.PUBLIC` | 50 | Public APIs, lower limits for suspicious user agents |
| `RateLimitPresets.API` | 100 (1000 authenticated) | Standard API with dynamic scaling |
| `RateLimitPresets.DEVELOPMENT` | 10,000 | Development mode, skips localhost |
| `RateLimitPresets.ENTERPRISE` | 200 (tiered up to 10,000) | Multi-tier: free/premium/enterprise/admin |

## Usage

### Basic

```typescript
const handler = new Handler()
  .use(new RateLimitingMiddleware({
    maxRequests: 100,
    windowMs: 60000,
  }))
  .handle(async (context) => {
    return { data: 'ok' };
  });
```

### Dynamic limits by user tier

```typescript
const handler = new Handler()
  .use(rateLimiting({
    maxRequests: 50,
    windowMs: 60000,
    dynamicLimits: {
      authenticated: {
        maxRequests: 1000,
        windowMs: 60000,
        matcher: (context) => !!context.user,
      },
      premium: {
        maxRequests: 5000,
        windowMs: 60000,
        matcher: (context) => context.user?.plan === 'premium',
      },
    },
  }))
  .handle(async (context) => {
    return { data: 'tiered' };
  });
```

### Using presets

```typescript
// Login endpoint
.use(rateLimiting(RateLimitPresets.AUTH))

// Standard API
.use(rateLimiting(RateLimitPresets.API))
```

## Response Headers

When `headers: true` (default), these headers are set on every response:

| Header | Description |
|---|---|
| `X-RateLimit-Limit` | Maximum requests allowed in window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `Retry-After` | Seconds until the client can retry |

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | Checks skip condition, generates key, increments counter, sets rate limit headers, throws `SecurityError` if limit exceeded |
| `after` | -- |
| `onError` | -- |

## Anti-patterns

- **Do not** use the default `MemoryStore` in multi-instance serverless deployments -- each instance tracks limits independently. Use a Redis-backed store for shared state.
- **Do not** use a single global key (`keyGenerator: () => 'global'`) -- this limits all users together.
- **Do not** order dynamic limit matchers from least to most specific -- the first match wins, so put the most specific matchers first.

## See Also

- [Error Classes Reference](../errors.md) -- `SecurityError` (403)
- [Authentication Middleware](./authentication.md) -- has its own built-in auth rate limiting
- [Security Audit Middleware](./security-audit.md)
