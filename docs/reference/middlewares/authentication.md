# Authentication Middleware

Verifies Bearer tokens and populates `context.user` with decoded user data.

> **Related:** [Middleware Index](./INDEX.md) | [Auth Reference](../auth/INDEX.md)

## Purpose

The Authentication Middleware extracts a Bearer token from the `Authorization` header, verifies it through a pluggable `CustomTokenVerificationPort`, and sets the authenticated user on the context. It supports JWT security validation (expiration, not-before, issuer, audience), token blacklisting, and per-IP rate limiting of authentication attempts.

## When to Use

- Protecting endpoints that require authenticated users
- Integrating with JWT, OAuth, Firebase, or custom token providers
- Enforcing token expiration, issuer/audience claims, and blacklist checks

## Import

```typescript
import {
  AuthenticationMiddleware,
  verifyAuthTokenMiddleware,
  CustomTokenVerificationPort,
  AuthenticationOptions,
  JWTPayload,
} from '@noony-serverless/core';
```

## Constructor

### Class: `AuthenticationMiddleware<TUser, TBody>`

```typescript
new AuthenticationMiddleware(
  tokenVerificationPort: CustomTokenVerificationPort<TUser>,
  options?: AuthenticationOptions
)
```

### Factory: `verifyAuthTokenMiddleware()`

```typescript
verifyAuthTokenMiddleware<TUser, TBody>(
  tokenVerificationPort: CustomTokenVerificationPort<TUser>,
  options?: AuthenticationOptions
): BaseMiddleware<TBody, TUser>
```

## Interfaces

### `CustomTokenVerificationPort<T>`

```typescript
interface CustomTokenVerificationPort<T> {
  verifyToken(token: string): Promise<T>;
}
```

Implement this interface to integrate any authentication provider. The returned value is assigned to `context.user`.

### `JWTPayload`

Standard JWT claims interface with optional fields: `exp`, `iat`, `nbf`, `jti`, `iss`, `aud`, `sub`, plus an index signature for custom claims.

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `maxTokenAge` | `number` | -- | Maximum token age in seconds (validates against `iat` claim) |
| `clockTolerance` | `number` | `60` | Clock skew tolerance in seconds for time-based validations |
| `isTokenBlacklisted` | `(tokenId?: string) => Promise<boolean> \| boolean` | -- | Async function to check if a token's `jti` has been revoked |
| `rateLimiting` | `{ maxAttempts: number; windowMs: number }` | -- | Rate limit auth attempts per client IP |
| `requiredClaims` | `{ issuer?: string; audience?: string \| string[] }` | -- | Required JWT issuer and/or audience claims |

## Usage

### Basic

```typescript
interface User {
  id: string;
  email: string;
  roles: string[];
}

class JWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
    return { id: payload.sub, email: payload.email, roles: payload.roles || [] };
  }
}

const handler = new Handler()
  .use(new AuthenticationMiddleware(new JWTVerifier()))
  .handle(async (request, context) => {
    const user = context.user as User;
    return { message: `Hello ${user.email}` };
  });
```

### Advanced (with security options)

```typescript
const secureAuth = new AuthenticationMiddleware(new JWTVerifier(), {
  maxTokenAge: 1800,
  clockTolerance: 30,
  rateLimiting: { maxAttempts: 5, windowMs: 15 * 60 * 1000 },
  isTokenBlacklisted: async (tokenId) => {
    return await redis.sismember('revoked_tokens', tokenId);
  },
  requiredClaims: {
    issuer: 'my-auth-server',
    audience: 'my-api',
  },
});

const handler = new Handler()
  .use(secureAuth)
  .handle(async (request, context) => {
    return { success: true, data: 'Secure data' };
  });
```

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | Extracts Bearer token, runs rate limit check, calls `verifyToken()`, validates JWT claims, checks blacklist, sets `context.user` |
| `after` | -- |
| `onError` | -- |

## Error Behavior

| Condition | Error Thrown |
|---|---|
| Missing `Authorization` header | `HttpError(401)` |
| Invalid token format (no `Bearer ` prefix) | `AuthenticationError` |
| Rate limit exceeded | `SecurityError` |
| Token expired / not yet valid / too old | `AuthenticationError` |
| Invalid issuer or audience | `SecurityError` |
| Blacklisted token | `SecurityError` |
| Verification port throws | `AuthenticationError` |

## Anti-patterns

- **Do not** hardcode secrets in the verification port -- use environment variables or a secret manager.
- **Do not** rely solely on the in-memory rate limit store in production multi-instance deployments. The built-in store is per-process; use Redis for shared state.
- **Do not** skip this middleware for "internal" endpoints without an alternative auth mechanism.

## See Also

- [Error Classes Reference](../errors.md)
- [Security Headers Middleware](./security-headers.md)
- [Rate Limiting Middleware](./rate-limiting.md)
