# RouteGuards Configuration Reference

## GuardSecurityConfig

Controls security policies and expression complexity limits.

```typescript
export interface GuardSecurityConfig {
  permissionResolutionStrategy?: PermissionResolutionStrategy;
  conservativeCacheInvalidation?: boolean;
  maxExpressionComplexity?: number;
  maxPatternDepth?: number;
  maxNestingDepth?: number;
}
```

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `permissionResolutionStrategy` | `PRE_EXPANSION \| ON_DEMAND` | `PRE_EXPANSION` | `PRE_EXPANSION` resolves wildcards at load time (faster runtime, more memory). `ON_DEMAND` resolves at check time (slower runtime, less memory). |
| `conservativeCacheInvalidation` | `boolean` | `true` | When `true`, all related cache entries are cleared on any permission change. When `false`, only the specific entry is invalidated. |
| `maxExpressionComplexity` | `number` | `100` | Maximum complexity score for permission expressions. Prevents DoS via deeply nested boolean logic. |
| `maxPatternDepth` | `number` | `5` | Maximum depth for wildcard patterns, e.g. `admin.users.groups.permissions.*`. Prevents deep recursion. |
| `maxNestingDepth` | `number` | `3` | Maximum nesting depth for boolean expressions. Prevents constructs like `((((A AND B) OR C) AND D) OR E)`. |

## GuardCacheConfig

Controls TTL and capacity for the in-memory permission cache.

```typescript
export interface GuardCacheConfig {
  maxEntries: number;
  defaultTtlMs: number;
  userContextTtlMs: number;
  authTokenTtlMs: number;
}
```

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `maxEntries` | `number` | `5000` | Maximum number of entries held in the cache at one time. Entries are evicted LRU when the limit is reached. |
| `defaultTtlMs` | `number` | `300000` (5 min) | Default TTL for cached entries that do not match a more specific TTL. |
| `userContextTtlMs` | `number` | `600000` (10 min) | TTL for cached user permission contexts (the aggregated result of `getUserPermissions`). |
| `authTokenTtlMs` | `number` | `900000` (15 min) | TTL for cached authentication token validation results. |

**TTL guidelines by environment:**

| Environment | `defaultTtlMs` | `userContextTtlMs` | `authTokenTtlMs` |
| --- | --- | --- | --- |
| Development | 5 min | 2 min | 2 min |
| Production | 15 min | 10 min | 5 min |
| High-security | 2 min | 1 min | 30 sec |
| Testing | 1 sec | 1 sec | 1 sec |

## GuardMonitoringConfig

Controls logging and performance metrics collection.

```typescript
export interface GuardMonitoringConfig {
  enablePerformanceTracking: boolean;
  enableDetailedLogging: boolean;
  logLevel: string;
  metricsCollectionInterval: number;
}
```

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `enablePerformanceTracking` | `boolean` | `true` | Tracks timing for each guard operation. Results available via `getSystemStats()`. |
| `enableDetailedLogging` | `boolean` | `false` in production | Emits per-request authentication and permission check logs. |
| `logLevel` | `'debug' \| 'info' \| 'warn' \| 'error'` | `'info'` | Minimum log level for guard system messages. |
| `metricsCollectionInterval` | `number` | `60000` (1 min) | Interval at which aggregated metrics are collected internally. |

## GuardEnvironmentProfile

Pre-configured profiles for common deployment environments.

```typescript
export interface GuardEnvironmentProfile {
  environment: string;
  cacheType: 'memory' | 'redis' | 'none';
  security: GuardSecurityConfig;
  cache: GuardCacheConfig;
  monitoring: GuardMonitoringConfig;
}
```

**Factory methods:**

| Method | `cacheType` | Logging | Use Case |
| --- | --- | --- | --- |
| `GuardSetup.development()` | `'memory'` | Detailed | Local development |
| `GuardSetup.production()` | `'memory'` | Warnings only | Standard cloud deployment |
| `GuardSetup.serverless()` | `'none'` | Minimal | Cloud Functions cold starts |
| `GuardSetup.testing()` | `'none'` | Disabled | Unit and integration tests |

## Cache Control via Environment Variable

The `NOONY_GUARD_CACHE_ENABLE` environment variable overrides any `cacheType` setting.

| `cacheType` config | `NOONY_GUARD_CACHE_ENABLE` | Effective result |
| --- | --- | --- |
| `'memory'` | Not set | No caching |
| `'memory'` | `'true'` | Memory caching |
| `'redis'` | Not set | No caching |
| `'redis'` | `'true'` | Redis caching |
| `'none'` | Any value | No caching |

Caching is **disabled by default** until the environment variable is explicitly set. This prevents accidental caching of sensitive permission data.

## RouteGuards Static Methods

### `RouteGuards.configure`

```typescript
static async configure(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  tokenVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig
): Promise<void>
```

General-purpose configuration. Accepts any `CustomTokenVerificationPort<T>` implementation. Must be called once before any handler runs.

### `RouteGuards.configureWithJWT`

```typescript
static async configureWithJWT<T extends { sub: string; exp?: number }>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  jwtVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig
): Promise<void>
```

Convenience wrapper for JWT authentication. The type constraint `{ sub: string; exp?: number }` ensures the user object contains the JWT `sub` claim.

### `RouteGuards.configureWithAPIKey`

```typescript
static async configureWithAPIKey<T extends Record<string, unknown>>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  apiKeyVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig,
  userIdField: keyof T,
  expirationField?: keyof T
): Promise<void>
```

Configures API key authentication. `userIdField` names the property on `T` that holds the user/key identifier. `expirationField` is optional and names the property holding a Unix timestamp expiration.

### `RouteGuards.configureWithOAuth`

```typescript
static async configureWithOAuth<T extends { sub: string; exp?: number; scope?: string[] }>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  oauthVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig,
  requiredScopes?: string[]
): Promise<void>
```

Configures OAuth 2.0 token validation. `requiredScopes` lists OAuth scopes that must be present in the token.

### `RouteGuards.configureWithCustom`

```typescript
static async configureWithCustom<T>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  customVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig,
  adapterConfig: AdapterConfig<T>
): Promise<void>
```

For token formats that do not follow JWT conventions. `adapterConfig` provides extractors for the user ID and expiration from the custom type `T`.

```typescript
interface AdapterConfig<T> {
  userIdExtractor: (user: T) => string;
  expirationExtractor?: (user: T) => number;
  additionalValidation?: (user: T) => boolean;
}
```

### `RouteGuards.requireAuth`

```typescript
static requireAuth(options?: { extractToken?: (context: Context) => string | null }): BaseMiddleware
```

Returns a middleware that validates the token from the configured header. Responds 401 if the token is absent or invalid. Does not check permissions.

### `RouteGuards.requirePermissions`

```typescript
static requirePermissions(permissions: string[]): BaseMiddleware
```

Returns a middleware that authenticates the request and then checks that the user holds **at least one** of the listed permissions (OR logic). Responds 401 if unauthenticated, 403 if authenticated but lacking all listed permissions.

### `RouteGuards.requireWildcardPermissions`

```typescript
static requireWildcardPermissions(patterns: string[]): BaseMiddleware
```

Same as `requirePermissions` but matches against wildcard patterns. A pattern `admin.*` matches `admin.users`, `admin.reports`, etc.

### `RouteGuards.requireComplexPermissions`

```typescript
static requireComplexPermissions(expression: PermissionExpression): BaseMiddleware
```

Evaluates a boolean expression tree against the user's permission set. Supports `and`, `or`, and `not` nodes.

```typescript
type PermissionExpression =
  | { permission: string }
  | { and: PermissionExpression[] }
  | { or: PermissionExpression[] }
  | { not: PermissionExpression };
```

### `RouteGuards.getSystemStats`

```typescript
static getSystemStats(): SystemStats
```

Returns aggregate performance metrics. Available only when `enablePerformanceTracking` is `true`.

```typescript
interface SystemStats {
  systemHealth: {
    cacheEfficiency: number;      // Cache hit rate as a percentage
    averageResponseTime: number;  // Average permission check time in milliseconds
    totalGuardChecks: number;     // Total number of permission checks since startup
  };
}
```

## Permission Strategies

| Strategy | Method | Matching | Performance | Use When |
| --- | --- | --- | --- | --- |
| Plain | `requirePermissions` | Exact string match | Fastest | Simple permission lists |
| Wildcard | `requireWildcardPermissions` | Glob pattern (`*`) | Medium | Hierarchical resource access |
| Expression | `requireComplexPermissions` | Boolean tree | Slowest | Complex AND/OR/NOT business rules |

Avoid Expression permissions on endpoints receiving more than ~500 requests per minute. Prefer Plain or Wildcard at high throughput.

## AuthGuardConfig

Passed to all `configure*` methods as the last (or second-to-last) argument.

```typescript
interface AuthGuardConfig {
  tokenHeader: string;
  tokenPrefix: string;
  requireEmailVerification?: boolean;
  allowInactiveUsers?: boolean;
  customValidation?: (token: string, user: T, context?: Context) => Promise<boolean>;
}
```

| Property | Type | Default | Description |
| --- | --- | --- | --- |
| `tokenHeader` | `string` | — | HTTP header name to read the token from. Typically `'authorization'` or `'x-api-key'`. |
| `tokenPrefix` | `string` | — | String to strip before passing the value to the verifier. Use `'Bearer '` for JWT, `''` for API keys. |
| `requireEmailVerification` | `boolean` | `false` | When `true`, tokens for users with unverified emails are rejected. |
| `allowInactiveUsers` | `boolean` | `false` | When `false`, tokens for disabled or inactive users are rejected. |
| `customValidation` | `function` | — | Additional validation logic run after the verifier returns a user. Return `false` to reject with 401. |

## Error HTTP Status Mappings

| Condition | HTTP Status | Description |
| --- | --- | --- |
| Missing or malformed token | `401` | No `Authorization` header, or header present but empty. |
| Token verification failed | `401` | The verifier threw an error or returned an invalid result. |
| Token expired | `401` | The decoded token's `exp` claim is in the past. |
| Email not verified | `401` | `requireEmailVerification: true` and the user's email is unverified. |
| User disabled | `401` | `allowInactiveUsers: false` and the user account is inactive. |
| Permission denied | `403` | Token is valid but the user lacks the required permissions. |
| RouteGuards not configured | `500` | A handler ran before `configure` was called. |
