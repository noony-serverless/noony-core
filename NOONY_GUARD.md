# Noony Guard System - Complete Documentation

The **Noony Guard System** is a high-performance authentication and authorization middleware designed for serverless environments. It provides sub-millisecond cached permission checks with three distinct resolution strategies, conservative cache invalidation, and comprehensive monitoring capabilities.

## 🚀 Key Features

- **Sub-millisecond Performance**: Cached permission checks in <1ms
- **Three Resolution Strategies**: Plain (O(1)), Wildcard, and Expression-based permissions
- **Multi-layer Caching**: L1 memory + configurable L2 with intelligent invalidation
- **Conservative Security**: Security-first cache invalidation strategies
- **Framework Agnostic**: Works with Express, Fastify, Google Cloud Functions, and more
- **Production Ready**: Comprehensive monitoring, audit trails, and error handling
- **TypeScript Native**: Full type safety and IntelliSense support

## 📑 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Permission Resolution Strategies](#permission-resolution-strategies)
4. [Authentication System](#authentication-system)
5. [Configuration & Setup](#configuration--setup)
6. [API Reference](#api-reference)
7. [Usage Examples](#usage-examples)
8. [Performance & Monitoring](#performance--monitoring)
9. [Security Considerations](#security-considerations)
10. [Advanced Topics](#advanced-topics)
11. [FAQ](#faq)
12. [Migration Guide](#migration-guide)

---

## Architecture Overview

The Noony Guard System follows a modular architecture designed for high performance and security:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   RouteGuards   │────│  FastAuthGuard   │────│ TokenValidator  │
│    (Facade)     │    │ (Authentication) │    │  (JWT Verify)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│PermissionGuard  │────│FastUserContext   │────│UserPermission   │
│    Factory      │    │     Service      │    │     Source      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Resolvers:    │    │   CacheAdapter   │    │PermissionRegistry│
│ Plain/Wildcard/ │    │ (Memory/Redis)   │    │  (Optional)     │
│   Expression    │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Design Principles

- **Single Responsibility**: Each component has a focused purpose
- **Strategy Pattern**: Pluggable permission resolution strategies
- **Facade Pattern**: Simple API hiding complex orchestration
- **Cache-First**: Aggressive caching with security-conscious invalidation
- **Performance Oriented**: Sub-millisecond response times for cached operations

---

## Core Components

### 1. RouteGuards (Facade)

The main entry point providing a clean, NestJS-inspired API for protecting routes.

**Key Responsibilities:**
- Orchestrates all guard components
- Provides fluent API for middleware creation
- Manages system-wide configuration and statistics
- Handles service dependency injection

**Main Methods:**
```typescript
RouteGuards.configure()              // System configuration
RouteGuards.requirePermissions()     // Plain permission strategy
RouteGuards.requireWildcardPermissions() // Wildcard strategy
RouteGuards.requireComplexPermissions()  // Expression strategy
RouteGuards.requireAuth()            // Authentication only
RouteGuards.getSystemStats()         // Performance metrics
```

### 2. FastAuthGuard

High-performance authentication with multi-layer caching.

**Key Features:**
- JWT token validation with caching
- User context loading and caching
- Multi-layer cache strategy (L1 memory + L2 distributed)
- Token blocking and security events
- Performance tracking and audit logging

**Performance Characteristics:**
- Cached authentication: ~0.1ms
- Cold authentication: ~2-5ms
- Memory usage: Low (LRU cache with limits)

### 3. PermissionGuardFactory

Factory for creating optimized permission guards tailored to specific requirements.

**Guard Types:**
- **PlainPermissionGuard**: Simple permission lists (fastest)
- **WildcardPermissionGuard**: Hierarchical wildcard patterns
- **ExpressionPermissionGuard**: Complex boolean expressions
- **CompositePermissionGuard**: Mixed permission requirements

### 4. FastUserContextService

User context management with configurable permission resolution.

**Key Features:**
- Configurable resolution strategies (pre-expansion vs on-demand)
- Permission expansion and validation
- Batch permission checking
- Conservative cache invalidation
- Performance monitoring

### 5. GuardConfiguration

Environment-specific configuration management.

**Configuration Areas:**
- Permission resolution strategies
- Cache settings and TTL
- Security policies
- Monitoring and logging levels

---

## Permission Resolution Strategies

The Noony Guard System provides three distinct strategies, each optimized for different use cases:

### 1. Plain Permissions (Fastest - O(1))

**Use Cases:**
- High-traffic API endpoints
- Simple permission models
- Sub-millisecond requirements
- Performance-critical paths

**Performance:** ~0.1ms cached, ~1-2ms uncached

**Example:**
```typescript
// Usage
RouteGuards.requirePermissions(['user:create', 'admin:users'])

// Handler Example
const createUser = new Handler<CreateUserRequest, User>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['user:create', 'admin:users']))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { validatedBody } = context.req;
    const user = await userService.create(validatedBody);
    return user;
  });
```

**How it Works:**
- Uses JavaScript Set for O(1) membership testing
- Checks if user has ANY of the required permissions (OR logic)
- No caching needed due to speed
- Direct set membership: `userPermissions.has(requiredPermission)`

### 2. Wildcard Permissions (Pattern Matching)

**Use Cases:**
- Role-based hierarchical permissions
- Administrative operations
- Department-based access control
- Organizational hierarchies

**Performance:** ~0.2ms cached (pre-expansion), ~2-5ms cached (on-demand)

**Example:**
```typescript
// Usage
RouteGuards.requireWildcardPermissions(['admin.*', 'user.profile.*'])

// Handler Example
const getUser = new Handler<GetUserRequest, User>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions(['admin.*', 'user.profile.*']))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { userId } = context.req.params;
    const user = await userService.findById(userId);
    return user;
  });
```

**Pattern Examples:**
```typescript
// Hierarchical patterns
'admin.*'           // Matches: admin.users, admin.reports, admin.settings
'user.profile.*'    // Matches: user.profile.read, user.profile.update
'org.department.*'  // Matches: org.department.view, org.department.manage

// Multi-level patterns
'system.users.*'    // Matches: system.users.create, system.users.delete
'reports.*.view'    // More complex patterns possible
```

**Resolution Strategies:**
- **Pre-expansion**: Expand wildcards at user context load time (faster runtime)
- **On-demand**: Match wildcards at permission check time (lower memory)

### 3. Expression Permissions (Boolean Logic)

**Use Cases:**
- Complex business rules
- Fine-grained access control
- Conditional permissions
- Advanced authorization scenarios

**Performance:** ~0.5ms cached, ~5-15ms uncached (depends on complexity)

**Example:**
```typescript
// Usage - Complex boolean expression
RouteGuards.requireComplexPermissions({
  or: [
    { and: [{ permission: 'admin.users' }, { permission: 'admin.read' }] },
    { and: [{ permission: 'user.list' }, { permission: 'user.department' }] }
  ]
})

// Handler Example
const listUsers = new Handler<ListUsersRequest, PaginatedResponse<User>>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { and: [{ permission: 'admin.users' }, { permission: 'admin.read' }] },
      { and: [{ permission: 'user.list' }, { permission: 'user.department' }] }
    ]
  }))
  .use(new QueryParametersMiddleware(listUsersQuerySchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { page, limit, search, department } = context.req.query;
    const result = await userService.list({ page, limit, search, department });
    return result;
  });
```

**Expression Structure:**
```typescript
interface PermissionExpression {
  and?: PermissionExpression[];  // All must be true
  or?: PermissionExpression[];   // At least one must be true  
  not?: PermissionExpression;    // Must be false
  permission?: string;           // Leaf permission to check
}
```

**Complex Examples:**
```typescript
// Admin OR (Moderator AND Department Access)
{
  or: [
    { permission: 'admin.full' },
    { and: [
      { permission: 'moderator.content' },
      { permission: 'department.reports' }
    ]}
  ]
}

// NOT expression example
{
  and: [
    { permission: 'user.read' },
    { not: { permission: 'user.restricted' } }
  ]
}
```

---

## Authentication System

The authentication system provides high-performance JWT validation with comprehensive caching and security features.

### JWT Token Validation

**Configuration:**
```typescript
interface AuthGuardConfig {
  jwtSecret?: string;
  jwtPublicKey?: string;
  tokenHeader: string;              // Default: 'authorization'
  tokenPrefix: string;              // Default: 'Bearer '
  allowedIssuers?: string[];
  requireEmailVerification: boolean;
  allowInactiveUsers: boolean;
  customValidation?: (token: any, user: UserContext) => Promise<boolean>;
}
```

**Token Validator Interface:**
```typescript
interface TokenValidator {
  validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }>;
  
  extractUserId(decoded: any): string;
  isTokenExpired(decoded: any): boolean;
}
```

### User Context Loading

**User Context Structure:**
```typescript
interface UserContext {
  userId: string;
  permissions: Set<string>;
  roles: string[];
  metadata: Record<string, any>;
  expandedPermissions?: Set<string>;  // For pre-expansion strategy
  lastUpdated: string;
  expiresAt?: string;
}
```

**Permission Source Interface:**
```typescript
interface UserPermissionSource {
  getUserPermissions(userId: string): Promise<{
    permissions: string[];
    roles: string[];
    metadata?: Record<string, any>;
  } | null>;
  
  getRolePermissions(roles: string[]): Promise<string[]>;
  isUserContextStale(userId: string, lastUpdated: string): Promise<boolean>;
}
```

### Multi-layer Caching

**Cache Layers:**
1. **L1 Memory Cache**: LRU-based caching with configurable TTL
2. **L2 Distributed Cache**: Redis or other distributed cache (optional)

**Cache Keys:**
- `auth:token:{tokenHash}` - Authentication results
- `user:context:{userId}` - User context data
- `perm:{resolverType}:{userId}:{permHash}` - Permission check results

**Cache TTL Configuration:**
```typescript
interface GuardCacheConfig {
  maxEntries: number;        // Maximum cache entries
  defaultTtlMs: number;      // Default TTL (15 minutes)
  userContextTtlMs: number;  // User context TTL (10 minutes)
  authTokenTtlMs: number;    // Auth token TTL (5 minutes)
}
```

### Security Features

**Conservative Cache Invalidation:**
- Permission changes flush ALL related caches
- Security-first approach trades performance for maximum security
- Immediate revocation capabilities
- Audit trail for all cache invalidations

**Token Security:**
- Token signature validation
- Token expiration checks
- User status validation (active/suspended/deleted)
- Token blocking for compromised tokens
- Rate limiting integration
- Suspicious activity detection

**Security Events:**
```typescript
// Token blocking
await authGuard.blockToken(compromisedToken, 'Security incident #1234');

// User permission invalidation
await RouteGuards.invalidateUserPermissions(userId, 'Role change');

// Emergency system-wide invalidation
await RouteGuards.emergencyInvalidation('Security breach detected');
```

---

## Configuration & Setup

### Environment Profiles

The guard system supports different configuration profiles optimized for specific environments:

#### Development Configuration
```typescript
const devConfig = GuardConfiguration.development();
// Settings:
// - Strategy: On-demand matching (memory efficient)
// - Cache TTL: 5 minutes (faster development cycles)
// - Cache Size: 500 entries
// - Invalidation: Less conservative for faster iteration
// - Monitoring: Detailed logging enabled
```

#### Production Configuration
```typescript
const prodConfig = GuardConfiguration.production();
// Settings:
// - Strategy: Pre-expansion (maximum runtime performance)
// - Cache TTL: 15 minutes (optimal balance)
// - Cache Size: 2000 entries
// - Invalidation: Conservative (security-first)
// - Monitoring: Essential metrics only
```

#### Custom Environment Profile
```typescript
const customProfile: GuardEnvironmentProfile = {
  environment: 'staging',
  cacheType: 'redis',
  security: {
    permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
    conservativeCacheInvalidation: true,
    maxExpressionComplexity: 75,
    maxPatternDepth: 3,
    maxNestingDepth: 2,
  },
  cache: {
    maxEntries: 1500,
    defaultTtlMs: 10 * 60 * 1000,     // 10 minutes
    userContextTtlMs: 8 * 60 * 1000,  // 8 minutes
    authTokenTtlMs: 3 * 60 * 1000,    // 3 minutes
  },
  monitoring: {
    enablePerformanceTracking: true,
    enableDetailedLogging: false,
    logLevel: 'warn',
    metricsCollectionInterval: 45000,  // 45 seconds
  }
};
```

### Cache Adapters

#### Memory Cache Adapter (Default)
```typescript
const memoryCache = new MemoryCacheAdapter({
  maxSize: 1000,
  defaultTTL: 15 * 60 * 1000,  // 15 minutes
  name: 'guard-cache',
});
```

#### Redis Cache Adapter (Production)
```typescript
// Custom Redis adapter implementation
class RedisCacheAdapter implements CacheAdapter {
  // Implementation details...
}

const redisCache = new RedisCacheAdapter({
  host: 'redis.example.com',
  port: 6379,
  db: 0,
  keyPrefix: 'noony:guard:',
});
```

#### No-Op Cache Adapter (Testing)
```typescript
const noCache = new NoopCacheAdapter(); // No caching for testing
```

### Complete Setup Example

```typescript
import { RouteGuards, GuardConfiguration } from '@noony-serverless/core';

// 1. Define your token validator
class MyTokenValidator implements TokenValidator {
  async validateToken(token: string) {
    // Your JWT validation logic
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!);
      return { valid: true, decoded };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || decoded.userId;
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp * 1000 < Date.now();
  }
}

// 2. Define your permission source
class DatabasePermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    const user = await db.users.findById(userId);
    if (!user) return null;

    return {
      permissions: user.permissions,
      roles: user.roles,
      metadata: {
        email: user.email,
        status: user.status,
        emailVerified: user.emailVerified,
      }
    };
  }

  async getRolePermissions(roles: string[]): Promise<string[]> {
    const rolePerms = await db.roles.find({ name: { $in: roles } });
    return rolePerms.flatMap(role => role.permissions);
  }

  async isUserContextStale(userId: string, lastUpdated: string): Promise<boolean> {
    const user = await db.users.findById(userId);
    return user ? user.updatedAt > new Date(lastUpdated) : true;
  }
}

// 3. Configure the guard system
const setupGuards = async () => {
  const profile: GuardEnvironmentProfile = {
    environment: process.env.NODE_ENV || 'development',
    cacheType: process.env.CACHE_TYPE as 'memory' | 'redis' | 'none' || 'memory',
    security: {
      permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
      conservativeCacheInvalidation: true,
      maxExpressionComplexity: 100,
      maxPatternDepth: 3,
      maxNestingDepth: 2,
    },
    cache: {
      maxEntries: parseInt(process.env.CACHE_MAX_ENTRIES || '2000'),
      defaultTtlMs: 15 * 60 * 1000,
      userContextTtlMs: 10 * 60 * 1000,
      authTokenTtlMs: 5 * 60 * 1000,
    },
    monitoring: {
      enablePerformanceTracking: true,
      enableDetailedLogging: process.env.NODE_ENV === 'development',
      logLevel: process.env.LOG_LEVEL || 'info',
      metricsCollectionInterval: 60000,
    }
  };

  const tokenValidator = new MyTokenValidator();
  const permissionSource = new DatabasePermissionSource();

  const authConfig: AuthGuardConfig = {
    jwtSecret: process.env.JWT_SECRET,
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: true,
    allowInactiveUsers: false,
    customValidation: async (token, user) => {
      // Custom business logic validation
      return user.metadata?.status === 'active';
    },
  };

  // Initialize the guard system
  await RouteGuards.configure(
    profile,
    permissionSource,
    tokenValidator,
    authConfig
  );

  console.log('🛡️ Noony Guard System configured successfully');
};

// 4. Initialize on application startup
await setupGuards();
```

---

## API Reference

### RouteGuards (Main Facade)

#### Static Methods

##### `configure(profile, permissionSource, tokenValidator, authConfig)`
Configure the guard system with environment-specific settings.

**Parameters:**
- `profile: GuardEnvironmentProfile` - Environment configuration
- `permissionSource: UserPermissionSource` - User data source
- `tokenValidator: TokenValidator` - JWT validation service
- `authConfig: AuthGuardConfig` - Authentication configuration

**Returns:** `Promise<void>`

**Example:**
```typescript
await RouteGuards.configure(
  GuardConfiguration.production(),
  new DatabasePermissionSource(),
  new JWTTokenValidator(),
  {
    jwtSecret: process.env.JWT_SECRET,
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: true,
    allowInactiveUsers: false,
  }
);
```

##### `requirePermissions(permissions, options?)`
Create middleware for simple permission list checks (fastest).

**Parameters:**
- `permissions: string[]` - Array of required permissions (OR logic)
- `options?: RouteGuardOptions` - Optional configuration

**Returns:** `BaseMiddleware`

**Performance:** ~0.1ms cached, ~1-2ms uncached

**Example:**
```typescript
.use(RouteGuards.requirePermissions(['user:create', 'admin:users'], {
  requireAuth: true,
  cacheResults: true,
  auditTrail: true,
  errorMessage: 'Access denied: Insufficient permissions for user creation'
}))
```

##### `requireWildcardPermissions(patterns, options?)`
Create middleware for wildcard permission pattern checks.

**Parameters:**
- `patterns: string[]` - Array of wildcard patterns
- `options?: RouteGuardOptions` - Optional configuration

**Returns:** `BaseMiddleware`

**Performance:** ~0.2ms cached (pre-expansion), ~2-5ms cached (on-demand)

**Example:**
```typescript
.use(RouteGuards.requireWildcardPermissions(['admin.*', 'user.profile.*'], {
  requireAuth: true,
  cacheResults: true,
  auditTrail: false,
}))
```

##### `requireComplexPermissions(expression, options?)`
Create middleware for complex boolean expression checks.

**Parameters:**
- `expression: PermissionExpression` - Permission expression with boolean logic
- `options?: RouteGuardOptions` - Optional configuration

**Returns:** `BaseMiddleware`

**Performance:** ~0.5ms cached, ~5-15ms uncached (depends on complexity)

**Example:**
```typescript
.use(RouteGuards.requireComplexPermissions({
  or: [
    { permission: 'admin.users' },
    { and: [
      { permission: 'moderator.content' },
      { permission: 'org.reports.view' }
    ]}
  ]
}, {
  requireAuth: true,
  cacheResults: true,
  auditTrail: true,
}))
```

##### `requireAuth(options?)`
Get authentication-only middleware without permission checking.

**Parameters:**
- `options?: RouteGuardOptions` - Optional configuration

**Returns:** `BaseMiddleware`

**Example:**
```typescript
.use(RouteGuards.requireAuth({
  requireAuth: true,
  errorMessage: 'Authentication required'
}))
```

##### `invalidateUserPermissions(userId, reason)`
Invalidate user permissions cache when permissions change.

**Parameters:**
- `userId: string` - User ID to invalidate
- `reason: string` - Reason for invalidation (for audit)

**Returns:** `Promise<void>`

**Example:**
```typescript
// After updating user permissions
await RouteGuards.invalidateUserPermissions('user123', 'Role updated');
```

##### `invalidateAllPermissions(reason)`
System-wide cache invalidation for major updates or security incidents.

**Parameters:**
- `reason: string` - Reason for system-wide invalidation

**Returns:** `Promise<void>`

**Example:**
```typescript
await RouteGuards.invalidateAllPermissions('Security policy update');
```

##### `emergencyInvalidation(reason)`
Emergency security invalidation with immediate cache clearing.

**Parameters:**
- `reason: string` - Security incident description

**Returns:** `Promise<void>`

**Example:**
```typescript
await RouteGuards.emergencyInvalidation('Security breach - credential compromise');
```

##### `getSystemStats()`
Get comprehensive system statistics and performance metrics.

**Returns:** `GuardSystemStats`

**Example:**
```typescript
const stats = RouteGuards.getSystemStats();
console.log('Cache hit rate:', stats.systemHealth.cacheEfficiency);
console.log('Average response time:', stats.systemHealth.averageResponseTime);
```

##### `healthCheck()`
Health check for the guard system with recommendations.

**Returns:** `Promise<{ status: 'healthy' | 'degraded' | 'unhealthy', details: Record<string, unknown>, timestamp: string }>`

**Example:**
```typescript
const health = await RouteGuards.healthCheck();
if (health.status !== 'healthy') {
  console.warn('Guard system issues:', health.details);
}
```

### RouteGuardOptions Interface

```typescript
interface RouteGuardOptions {
  requireAuth?: boolean;        // Default: true
  cacheResults?: boolean;       // Default: true
  auditTrail?: boolean;         // Default: false
  errorMessage?: string;        // Custom error message
  cacheTtlMs?: number;         // Override global TTL
}
```

### PermissionExpression Interface

```typescript
interface PermissionExpression {
  and?: PermissionExpression[];  // All must be true
  or?: PermissionExpression[];   // At least one must be true
  not?: PermissionExpression;    // Must be false
  permission?: string;           // Leaf permission string
}
```

### GuardSystemStats Interface

```typescript
interface GuardSystemStats {
  authentication: {
    authAttempts: number;
    authFailures: number;
    successRate: number;
    cacheHitRate: number;
    averageResolutionTimeUs: number;
    suspiciousAttempts: number;
    blockedTokens: number;
  };
  userContextService: {
    contextLoads: number;
    permissionChecks: number;
    cacheHitRate: number;
    averageResolutionTimeUs: number;
  };
  permissionGuardFactory: {
    totalGuards: number;
    guardsByType: Record<string, number>;
    aggregatedStats: {
      totalChecks: number;
      totalSuccesses: number;
      overallSuccessRate: number;
      averageProcessingTimeUs: number;
    };
  };
  systemHealth: {
    totalGuardChecks: number;
    averageResponseTime: number;
    errorRate: number;
    cacheEfficiency: number;
    uptime: number;
  };
}
```

---

## Usage Examples

### Basic Setup and Integration

#### Google Cloud Functions Integration

```typescript
import { http } from '@google-cloud/functions-framework';
import { Handler, ErrorHandlerMiddleware, ResponseWrapperMiddleware } from '@noony-serverless/core';
import { RouteGuards } from '@noony-serverless/core';

// Configure guards on cold start
await RouteGuards.configure(/*...config...*/);

// Create protected function
const protectedFunction = new Handler<CreateUserRequest, User>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['user:create']))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const user = context.businessData.get('user');
    return { message: `Hello ${user.userId}` };
  });

// Export for GCP Functions
export const createUser = http('createUser', (req, res) => {
  return protectedFunction.execute(req, res);
});
```

#### Fastify Integration

```typescript
import Fastify from 'fastify';
import { Handler } from '@noony-serverless/core';

const fastify = Fastify({ logger: true });

// Configure guards
await RouteGuards.configure(/*...config...*/);

// Protected route with different strategies
fastify.post('/users', async (request, reply) => {
  const handler = new Handler()
    .use(RouteGuards.requirePermissions(['user:create', 'admin:users']))
    .handle(async (context) => {
      // Your business logic
      return await userService.create(context.req.body);
    });
  
  return handler.executeGeneric(request, reply);
});

fastify.get('/users/:id', async (request, reply) => {
  const handler = new Handler()
    .use(RouteGuards.requireWildcardPermissions(['admin.*', 'user.profile.*']))
    .handle(async (context) => {
      return await userService.findById(context.req.params.id);
    });
  
  return handler.executeGeneric(request, reply);
});

fastify.get('/users', async (request, reply) => {
  const handler = new Handler()
    .use(RouteGuards.requireComplexPermissions({
      or: [
        { and: [{ permission: 'admin.users' }, { permission: 'admin.read' }] },
        { and: [{ permission: 'user.list' }, { permission: 'user.department' }] }
      ]
    }))
    .handle(async (context) => {
      return await userService.list(context.req.query);
    });
  
  return handler.executeGeneric(request, reply);
});
```

#### Express Integration

```typescript
import express from 'express';
import { Handler } from '@noony-serverless/core';

const app = express();

// Configure guards
await RouteGuards.configure(/*...config...*/);

// Express middleware adapter
const guardMiddleware = (guardFn) => {
  return async (req, res, next) => {
    const handler = new Handler()
      .use(guardFn)
      .handle(async () => ({ success: true }));
    
    try {
      await handler.executeGeneric(req, res);
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Protected routes
app.post('/users', 
  guardMiddleware(RouteGuards.requirePermissions(['user:create'])),
  (req, res) => {
    res.json({ message: 'User created' });
  }
);

app.get('/admin/*', 
  guardMiddleware(RouteGuards.requireWildcardPermissions(['admin.*'])),
  (req, res) => {
    res.json({ message: 'Admin access granted' });
  }
);
```

### Complete Production Example

```typescript
/**
 * Production-ready user management API with all guard strategies
 */
import 'reflect-metadata';
import { Container } from 'typedi';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  QueryParametersMiddleware,
  ResponseWrapperMiddleware,
} from '@noony-serverless/core';
import { RouteGuards } from '@noony-serverless/core';

// === TOKEN VALIDATOR IMPLEMENTATION ===
class ProductionTokenValidator implements TokenValidator {
  private readonly jwtSecret = process.env.JWT_SECRET!;

  async validateToken(token: string) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);
      return { valid: true, decoded };
    } catch (error) {
      return { 
        valid: false, 
        error: error instanceof Error ? error.message : 'Invalid token' 
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || decoded.userId;
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp * 1000 < Date.now();
  }
}

// === PERMISSION SOURCE IMPLEMENTATION ===
class DatabasePermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    // Your database query logic
    const user = await db.collection('users').doc(userId).get();
    if (!user.exists) return null;

    const userData = user.data()!;
    return {
      permissions: userData.permissions || [],
      roles: userData.roles || [],
      metadata: {
        email: userData.email,
        status: userData.status,
        emailVerified: userData.emailVerified,
        department: userData.department,
      }
    };
  }

  async getRolePermissions(roles: string[]): Promise<string[]> {
    if (roles.length === 0) return [];
    
    const roleSnapshot = await db.collection('roles')
      .where('name', 'in', roles)
      .get();
    
    return roleSnapshot.docs.flatMap(doc => doc.data().permissions || []);
  }

  async isUserContextStale(userId: string, lastUpdated: string): Promise<boolean> {
    const user = await db.collection('users').doc(userId).get();
    if (!user.exists) return true;
    
    const userData = user.data()!;
    return userData.updatedAt.toDate() > new Date(lastUpdated);
  }
}

// === GUARD SYSTEM CONFIGURATION ===
const configureGuardSystem = async () => {
  const environment = process.env.NODE_ENV || 'development';
  
  const profile: GuardEnvironmentProfile = {
    environment,
    cacheType: environment === 'production' ? 'redis' : 'memory',
    security: {
      permissionResolutionStrategy: environment === 'production' 
        ? PermissionResolutionStrategy.PRE_EXPANSION 
        : PermissionResolutionStrategy.ON_DEMAND,
      conservativeCacheInvalidation: environment === 'production',
      maxExpressionComplexity: 100,
      maxPatternDepth: 3,
      maxNestingDepth: 2,
    },
    cache: {
      maxEntries: environment === 'production' ? 5000 : 1000,
      defaultTtlMs: 15 * 60 * 1000,    // 15 minutes
      userContextTtlMs: 10 * 60 * 1000, // 10 minutes
      authTokenTtlMs: 5 * 60 * 1000,    // 5 minutes
    },
    monitoring: {
      enablePerformanceTracking: true,
      enableDetailedLogging: environment === 'development',
      logLevel: environment === 'production' ? 'warn' : 'debug',
      metricsCollectionInterval: 60000, // 1 minute
    }
  };

  await RouteGuards.configure(
    profile,
    new DatabasePermissionSource(),
    new ProductionTokenValidator(),
    {
      jwtSecret: process.env.JWT_SECRET!,
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: true,
      allowInactiveUsers: false,
      customValidation: async (token, user) => {
        // Additional business logic validation
        return user.metadata?.status === 'active' && 
               user.metadata?.emailVerified === true;
      }
    }
  );

  console.log(`🛡️ Guard system configured for ${environment}`);
};

// === VALIDATION SCHEMAS ===
const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().int().min(18).max(120),
  department: z.string().min(1).max(50),
});

const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  department: z.string().min(1).max(50).optional(),
  bio: z.string().max(500).optional(),
});

const listUsersQuerySchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
  search: z.string().optional(),
  department: z.string().optional(),
  includeDeleted: z.boolean().default(false),
  sortBy: z.enum(['name', 'email', 'createdAt']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

// === HANDLER IMPLEMENTATIONS ===

// 1. CREATE USER - Plain Permission Strategy
export const createUser = new Handler<z.infer<typeof createUserSchema>, User>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(
    ['user:create', 'admin:users'], // OR logic: user needs either permission
    {
      requireAuth: true,
      cacheResults: true,
      auditTrail: true,
      errorMessage: 'Access denied: User creation requires user:create or admin:users permission'
    }
  ))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { validatedBody } = context.req;
    const currentUser = context.businessData.get('user') as UserContext;
    
    // Business logic with audit
    const newUser = await userService.create({
      ...validatedBody,
      createdBy: currentUser.userId,
      createdAt: new Date(),
    });

    // Log successful creation
    console.log('✅ User created', {
      userId: newUser.id,
      createdBy: currentUser.userId,
      permissions: Array.from(currentUser.permissions),
    });

    return newUser;
  });

// 2. GET USER - Wildcard Permission Strategy  
export const getUser = new Handler<{ userId: string }, User>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions(
    ['admin.*', 'user.profile.*'], // Hierarchical pattern matching
    {
      requireAuth: true,
      cacheResults: true,
      auditTrail: false, // High frequency, skip audit
    }
  ))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { userId } = context.req.params;
    const currentUser = context.businessData.get('user') as UserContext;

    // Additional business rule: users can only see their own profile unless admin
    const hasAdminWildcard = Array.from(currentUser.permissions)
      .some(p => p.startsWith('admin.'));
    
    if (!hasAdminWildcard && currentUser.userId !== userId) {
      throw new SecurityError('Access denied: Cannot view other user profiles');
    }

    const user = await userService.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    return user;
  });

// 3. LIST USERS - Expression Permission Strategy
export const listUsers = new Handler<
  z.infer<typeof listUsersQuerySchema>, 
  PaginatedResponse<User>
>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireComplexPermissions(
    {
      or: [
        // Admin path: needs both admin.users AND admin.read
        { 
          and: [
            { permission: 'admin.users' }, 
            { permission: 'admin.read' }
          ] 
        },
        // User path: needs both user.list AND user.department
        { 
          and: [
            { permission: 'user.list' }, 
            { permission: 'user.department' }
          ] 
        }
      ]
    },
    {
      requireAuth: true,
      cacheResults: true,
      auditTrail: true,
      errorMessage: 'Access denied: User listing requires (admin.users AND admin.read) OR (user.list AND user.department)'
    }
  ))
  .use(new QueryParametersMiddleware(listUsersQuerySchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const query = context.req.query;
    const currentUser = context.businessData.get('user') as UserContext;

    // Additional business rule: includeDeleted only for admins
    if (query.includeDeleted) {
      const hasAdminUsers = currentUser.permissions.has('admin.users');
      if (!hasAdminUsers) {
        throw new SecurityError('Access denied: includeDeleted parameter requires admin.users permission');
      }
    }

    // Business logic with filtering
    const result = await userService.list({
      page: query.page,
      limit: query.limit,
      search: query.search,
      department: query.department,
      includeDeleted: query.includeDeleted,
      sortBy: query.sortBy,
      sortOrder: query.sortOrder,
    });

    return result;
  });

// 4. UPDATE USER - Plain Permission Strategy (Self + Admin)
export const updateUser = new Handler<
  z.infer<typeof updateUserSchema> & { userId: string }, 
  User
>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(
    ['user:update', 'admin:users'], // OR logic for basic auth
    { requireAuth: true, cacheResults: true }
  ))
  .use(new BodyValidationMiddleware(updateUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { userId } = context.req.params;
    const { validatedBody } = context.req;
    const currentUser = context.businessData.get('user') as UserContext;

    // Business rule: non-admin users can only update their own profile
    const hasAdminUsers = currentUser.permissions.has('admin:users');
    if (!hasAdminUsers && currentUser.userId !== userId) {
      throw new SecurityError('Access denied: Cannot update other user profiles');
    }

    const updatedUser = await userService.update(userId, {
      ...validatedBody,
      updatedBy: currentUser.userId,
      updatedAt: new Date(),
    });

    // Invalidate cache if permissions might have changed
    if (updatedUser && (validatedBody as any).roles) {
      await RouteGuards.invalidateUserPermissions(userId, 'Roles updated');
    }

    return updatedUser;
  });

// 5. DELETE USER - Wildcard Permission Strategy with Business Rules
export const deleteUser = new Handler<{ userId: string }, { success: boolean }>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions(
    ['admin.*', 'system.users.*'], // High-level administrative permissions
    {
      requireAuth: true,
      cacheResults: true,
      auditTrail: true,
      errorMessage: 'Access denied: User deletion requires admin.* or system.users.* permissions'
    }
  ))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { userId } = context.req.params;
    const currentUser = context.businessData.get('user') as UserContext;

    // Business rule: prevent self-deletion even with permissions
    if (currentUser.userId === userId) {
      throw new SecurityError('Access denied: Cannot delete your own account');
    }

    // Additional business rule: check if user has admin role
    const targetUser = await userService.findById(userId);
    if (targetUser?.roles.includes('admin')) {
      const hasSystemUserPermissions = Array.from(currentUser.permissions)
        .some(p => p.startsWith('system.users.'));
      
      if (!hasSystemUserPermissions) {
        throw new SecurityError('Access denied: Deleting admin users requires system.users.* permissions');
      }
    }

    await userService.softDelete(userId, currentUser.userId);
    
    // Invalidate user's cache after deletion
    await RouteGuards.invalidateUserPermissions(userId, 'User deleted');

    return { success: true };
  });

// === SYSTEM INITIALIZATION ===
export const initializeSystem = async () => {
  try {
    // Configure guard system
    await configureGuardSystem();
    
    // Health check endpoint (no auth required)
    const healthCheck = new Handler()
      .use(new ErrorHandlerMiddleware())
      .use(new ResponseWrapperMiddleware())
      .handle(async () => {
        const stats = RouteGuards.getSystemStats();
        const health = await RouteGuards.healthCheck();
        
        return {
          status: 'ok',
          timestamp: new Date().toISOString(),
          guardSystem: {
            health: health.status,
            cacheHitRate: stats.systemHealth.cacheEfficiency,
            averageResponseTime: stats.systemHealth.averageResponseTime,
            totalChecks: stats.systemHealth.totalGuardChecks,
            errorRate: stats.systemHealth.errorRate,
          }
        };
      });

    console.log('🚀 User management API initialized successfully');
    
    return {
      createUser,
      getUser,
      listUsers,
      updateUser,
      deleteUser,
      healthCheck,
    };
  } catch (error) {
    console.error('❌ Failed to initialize system:', error);
    throw error;
  }
};

// Export metadata for monitoring and documentation
export const userHandlersMetadata = {
  createUser: {
    method: 'POST',
    path: '/users',
    guardStrategy: 'plain',
    permissions: ['user:create', 'admin:users'],
    description: 'Create a new user with plain permission strategy'
  },
  getUser: {
    method: 'GET',
    path: '/users/:id',
    guardStrategy: 'wildcard',
    permissions: ['admin.*', 'user.profile.*'],
    description: 'Get user by ID with wildcard permission strategy'
  },
  listUsers: {
    method: 'GET',
    path: '/users',
    guardStrategy: 'expression',
    permissions: '(admin.users AND admin.read) OR (user.list AND user.department)',
    description: 'List users with complex expression permission strategy'
  },
  updateUser: {
    method: 'PUT',
    path: '/users/:id',
    guardStrategy: 'plain',
    permissions: ['user:update', 'admin:users'],
    description: 'Update user with plain permission strategy'
  },
  deleteUser: {
    method: 'DELETE',
    path: '/users/:id',
    guardStrategy: 'wildcard',
    permissions: ['admin.*', 'system.users.*'],
    description: 'Delete user with wildcard permission strategy'
  },
};

// Export system metrics helper
export const getGuardSystemMetrics = () => {
  const stats = RouteGuards.getSystemStats();
  return {
    summary: {
      totalGuardChecks: stats.systemHealth.totalGuardChecks,
      averageResponseTime: `${stats.systemHealth.averageResponseTime.toFixed(2)}ms`,
      errorRate: `${stats.systemHealth.errorRate.toFixed(2)}%`,
      cacheEfficiency: `${stats.systemHealth.cacheEfficiency.toFixed(1)}%`,
      uptime: `${Math.round(stats.systemHealth.uptime / 1000)}s`,
    },
    authentication: {
      totalAttempts: stats.authentication.authAttempts,
      successRate: `${stats.authentication.successRate.toFixed(1)}%`,
      cacheHitRate: `${stats.authentication.cacheHitRate.toFixed(1)}%`,
      averageTime: `${(stats.authentication.averageResolutionTimeUs / 1000).toFixed(2)}ms`,
    },
    userContext: {
      contextLoads: stats.userContextService.contextLoads,
      permissionChecks: stats.userContextService.permissionChecks,
      cacheHitRate: `${stats.userContextService.cacheHitRate.toFixed(1)}%`,
    },
    guards: {
      totalGuards: stats.permissionGuardFactory.totalGuards,
      guardTypes: stats.permissionGuardFactory.guardsByType,
      overallSuccessRate: `${stats.permissionGuardFactory.aggregatedStats.overallSuccessRate.toFixed(1)}%`,
    }
  };
};
```

### Custom Token Validation Examples

#### Firebase Authentication Integration
```typescript
import { auth } from 'firebase-admin';

class FirebaseTokenValidator implements TokenValidator {
  async validateToken(token: string) {
    try {
      const decodedToken = await auth().verifyIdToken(token);
      return { valid: true, decoded: decodedToken };
    } catch (error) {
      return { 
        valid: false, 
        error: error instanceof Error ? error.message : 'Invalid Firebase token' 
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.uid;
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp * 1000 < Date.now();
  }
}
```

#### Auth0 Integration
```typescript
import { auth } from 'express-oauth-server';

class Auth0TokenValidator implements TokenValidator {
  private readonly jwksClient = jwks({
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  });

  async validateToken(token: string) {
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        return { valid: false, error: 'Invalid token format' };
      }

      const kid = decoded.header.kid;
      const key = await this.jwksClient.getSigningKey(kid);
      const publicKey = key.getPublicKey();

      const verified = jwt.verify(token, publicKey, {
        audience: process.env.AUTH0_AUDIENCE,
        issuer: `https://${process.env.AUTH0_DOMAIN}/`,
      });

      return { valid: true, decoded: verified };
    } catch (error) {
      return { 
        valid: false, 
        error: error instanceof Error ? error.message : 'Auth0 validation failed' 
      };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub;
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp * 1000 < Date.now();
  }
}
```

---

## Performance & Monitoring

### Performance Characteristics Summary

| Component | Operation | Cached Performance | Uncached Performance | Memory Usage |
|-----------|-----------|-------------------|---------------------|---------------|
| Authentication | Token validation | ~0.1ms | ~2-5ms | Low |
| Plain Permissions | Permission check | ~0.1ms | ~1-2ms | Low |
| Wildcard Permissions | Pattern matching | ~0.2ms (pre-exp) | ~2-5ms | Medium |
| Expression Permissions | Boolean evaluation | ~0.5ms | ~5-15ms | Medium |
| User Context | Context loading | ~0.1ms | ~10-50ms | Low-Medium |

### System Monitoring

#### Getting Performance Metrics
```typescript
// Get comprehensive system statistics
const stats = RouteGuards.getSystemStats();

console.log('System Performance:', {
  totalChecks: stats.systemHealth.totalGuardChecks,
  avgResponseTime: stats.systemHealth.averageResponseTime,
  errorRate: stats.systemHealth.errorRate,
  cacheEfficiency: stats.systemHealth.cacheEfficiency,
  uptime: stats.systemHealth.uptime,
});

// Authentication statistics
console.log('Authentication Performance:', {
  attempts: stats.authentication.authAttempts,
  failures: stats.authentication.authFailures,
  successRate: stats.authentication.successRate,
  cacheHitRate: stats.authentication.cacheHitRate,
  avgTime: stats.authentication.averageResolutionTimeUs,
});

// User context statistics
console.log('User Context Performance:', {
  loads: stats.userContextService.contextLoads,
  checks: stats.userContextService.permissionChecks,
  cacheHitRate: stats.userContextService.cacheHitRate,
  avgTime: stats.userContextService.averageResolutionTimeUs,
});
```

#### Health Monitoring
```typescript
// Periodic health checks
setInterval(async () => {
  const health = await RouteGuards.healthCheck();
  
  if (health.status === 'unhealthy') {
    console.error('🚨 Guard system unhealthy:', health.details);
    // Send alert to monitoring system
    await alertingService.sendAlert({
      severity: 'critical',
      service: 'noony-guards',
      message: 'Guard system performance degraded',
      details: health.details
    });
  } else if (health.status === 'degraded') {
    console.warn('⚠️ Guard system degraded:', health.details);
  }
}, 60000); // Check every minute
```

#### Custom Metrics Integration

##### Prometheus Integration
```typescript
import { register, Counter, Histogram, Gauge } from 'prom-client';

// Create custom metrics
const guardChecksTotal = new Counter({
  name: 'noony_guard_checks_total',
  help: 'Total number of guard permission checks',
  labelNames: ['strategy', 'result']
});

const guardDuration = new Histogram({
  name: 'noony_guard_duration_seconds',
  help: 'Duration of guard permission checks',
  labelNames: ['strategy'],
  buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]
});

const cacheHitRate = new Gauge({
  name: 'noony_guard_cache_hit_rate',
  help: 'Cache hit rate for guard operations'
});

// Update metrics periodically
setInterval(() => {
  const stats = RouteGuards.getSystemStats();
  
  cacheHitRate.set(stats.systemHealth.cacheEfficiency);
  
  // Update individual resolver metrics
  Object.entries(stats.userContextService.resolverStats).forEach(([strategy, resolverStats]) => {
    guardDuration.labels(strategy).observe(resolverStats.averageResolutionTimeUs / 1000000);
  });
}, 30000); // Update every 30 seconds
```

##### DataDog Integration
```typescript
import StatsD from 'node-statsd';

const statsd = new StatsD({
  host: process.env.DATADOG_HOST,
  port: 8125,
  prefix: 'noony.guard.'
});

// Track metrics
setInterval(() => {
  const stats = RouteGuards.getSystemStats();
  
  statsd.gauge('cache.hit_rate', stats.systemHealth.cacheEfficiency);
  statsd.gauge('response.time.avg', stats.systemHealth.averageResponseTime);
  statsd.gauge('error.rate', stats.systemHealth.errorRate);
  statsd.gauge('checks.total', stats.systemHealth.totalGuardChecks);
  
  // Authentication metrics
  statsd.gauge('auth.success_rate', stats.authentication.successRate);
  statsd.gauge('auth.cache_hit_rate', stats.authentication.cacheHitRate);
  
}, 30000);
```

### Performance Optimization Tips

#### 1. Cache Configuration Optimization
```typescript
// Production optimizations
const productionConfig = {
  cache: {
    maxEntries: 5000,           // Increase for high-traffic
    defaultTtlMs: 20 * 60 * 1000, // 20 minutes for longer sessions
    userContextTtlMs: 15 * 60 * 1000, // 15 minutes
    authTokenTtlMs: 10 * 60 * 1000,   // 10 minutes for security
  },
  security: {
    // Use pre-expansion for maximum runtime performance
    permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
    conservativeCacheInvalidation: true, // Security first
  }
};
```

#### 2. Permission Strategy Selection
```typescript
// Choose the right strategy for your use case
const endpointStrategies = {
  // High-traffic endpoints: Use Plain permissions
  'POST /users': 'plain',           // ~0.1ms cached
  'PUT /users/:id': 'plain',        // ~0.1ms cached
  
  // Admin/hierarchical: Use Wildcard  
  'GET /admin/*': 'wildcard',       // ~0.2ms cached
  'DELETE /users/:id': 'wildcard',  // ~0.2ms cached
  
  // Complex business rules: Use Expression (sparingly)
  'GET /users': 'expression',       // ~0.5ms cached
  'GET /reports': 'expression',     // ~0.5ms cached
};
```

#### 3. Monitoring Alerting Thresholds
```typescript
const performanceThresholds = {
  cacheHitRate: {
    warning: 85,    // < 85% cache hit rate
    critical: 70,   // < 70% cache hit rate
  },
  responseTime: {
    warning: 50,    // > 50ms average response time
    critical: 100,  // > 100ms average response time
  },
  errorRate: {
    warning: 2,     // > 2% error rate
    critical: 5,    // > 5% error rate
  }
};

// Implement alerting logic
const checkPerformanceThresholds = async () => {
  const health = await RouteGuards.healthCheck();
  const stats = RouteGuards.getSystemStats();
  
  if (stats.systemHealth.cacheEfficiency < performanceThresholds.cacheHitRate.critical) {
    await sendAlert('critical', 'Low cache hit rate', stats.systemHealth);
  }
  
  if (stats.systemHealth.averageResponseTime > performanceThresholds.responseTime.warning) {
    await sendAlert('warning', 'High response times', stats.systemHealth);
  }
};
```

---

## Security Considerations

The Noony Guard System implements multiple layers of security to protect against various threats and ensure compliance with security best practices.

### Conservative Cache Invalidation

The system uses a "security-first" approach to caching that prioritizes security over performance when conflicts arise.

#### How Conservative Invalidation Works
```typescript
// When a user's permissions change
await RouteGuards.invalidateUserPermissions(userId, 'Role updated');

// This triggers:
// 1. Immediate removal of user context cache
// 2. Clearing of all related permission check caches
// 3. Clearing of authentication token caches for the user
// 4. Optional clearing of related user caches (configurable)

// Cache patterns cleared:
// - user:context:{userId}
// - auth:token:*:{userId}  
// - perm:*:{userId}:*
// - expr:*:{userId}:*
// - wild:*:{userId}:*
```

#### Configuration Options
```typescript
const securityConfig = {
  // Enable conservative invalidation (recommended for production)
  conservativeCacheInvalidation: true,
  
  // Maximum complexity limits to prevent DoS
  maxExpressionComplexity: 100,
  maxPatternDepth: 3,
  maxNestingDepth: 2,
  
  // Permission resolution strategy
  permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION
};
```

### Authentication Security

#### Token Validation Security
```typescript
// Multi-layer token validation
class SecureTokenValidator implements TokenValidator {
  async validateToken(token: string) {
    // 1. Format validation
    if (!token || token.length < 10) {
      return { valid: false, error: 'Invalid token format' };
    }

    // 2. Signature validation
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: ['RS256', 'HS256'], // Restrict algorithms
        audience: this.audience,         // Validate audience
        issuer: this.issuer,            // Validate issuer
      });

      // 3. Custom validation
      if (!this.customValidation(decoded)) {
        return { valid: false, error: 'Custom validation failed' };
      }

      return { valid: true, decoded };
    } catch (error) {
      // Log security events
      this.logSecurityEvent('token_validation_failed', { error: error.message });
      return { valid: false, error: 'Token validation failed' };
    }
  }

  private customValidation(decoded: any): boolean {
    // Check token age (max 24 hours)
    const tokenAge = Date.now() - (decoded.iat * 1000);
    if (tokenAge > 24 * 60 * 60 * 1000) return false;

    // Check required claims
    if (!decoded.sub || !decoded.aud) return false;

    // Check against blocked user list (implement as needed)
    if (this.isUserBlocked(decoded.sub)) return false;

    return true;
  }
}
```

#### Token Security Features
```typescript
// Block compromised tokens
await authGuard.blockToken(compromisedToken, 'Security incident #123');

// Monitor suspicious activity
const suspiciousPatterns = [
  'Multiple failed attempts',
  'Unusual IP address',
  'Token reuse patterns',
  'Rapid sequential requests'
];

// Automatic token blocking on suspicious activity
if (isSuspiciousActivity(context)) {
  await authGuard.blockToken(token, 'Suspicious activity detected');
  await alertSecurityTeam('Token blocked', { userId, reason, timestamp });
}
```

### Permission Model Security

#### Principle of Least Privilege
```typescript
// Example: Hierarchical permission design
const permissionHierarchy = {
  // User permissions - most restrictive
  user: [
    'user:profile:read',
    'user:profile:update',
    'user:content:create'
  ],
  
  // Moderator permissions - inherit user + moderate content
  moderator: [
    ...userPermissions,
    'content:moderate',
    'user:suspend'
  ],
  
  // Admin permissions - inherit moderator + system access
  admin: [
    ...moderatorPermissions,
    'admin:users',
    'admin:system',
    'admin:reports'
  ],
  
  // System permissions - for automated systems only
  system: [
    'system:*',
    'admin:*'
  ]
};

// Implementation with validation
class SecurePermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    const user = await this.loadUser(userId);
    
    // Validate role hierarchy
    const validatedRoles = this.validateRoleHierarchy(user.roles);
    
    // Apply principle of least privilege
    const permissions = this.calculateMinimalPermissions(validatedRoles);
    
    return {
      permissions,
      roles: validatedRoles,
      metadata: {
        ...user.metadata,
        lastPermissionCheck: new Date().toISOString()
      }
    };
  }

  private validateRoleHierarchy(roles: string[]): string[] {
    // Prevent role escalation
    const allowedRoles = this.getAllowedRoles();
    return roles.filter(role => allowedRoles.includes(role));
  }
}
```

### Audit Logging and Compliance

#### Comprehensive Audit Trail
```typescript
// Enable audit logging for sensitive operations
const sensitiveOperations = [
  RouteGuards.requireComplexPermissions(/* ... */, { 
    auditTrail: true,  // Log all permission grants/denials
    requireAuth: true 
  }),
  
  RouteGuards.requireWildcardPermissions(['admin.*'], { 
    auditTrail: true   // Log all admin operations
  })
];

// Audit log structure
interface AuditLogEntry {
  timestamp: string;
  userId: string;
  operation: string;
  resource: string;
  permissions: string[];
  result: 'granted' | 'denied';
  reason?: string;
  ipAddress: string;
  userAgent: string;
  requestId: string;
}

// Custom audit logger
class ComplianceAuditLogger {
  async logPermissionCheck(entry: AuditLogEntry) {
    // Log to secure audit system
    await this.auditSystem.log({
      ...entry,
      source: 'noony-guards',
      category: 'authorization',
      severity: entry.result === 'denied' ? 'warning' : 'info'
    });
    
    // For high-security environments, also log to immutable storage
    if (this.isHighSecurity) {
      await this.immutableStorage.append(entry);
    }
  }
}
```

#### GDPR and Privacy Compliance
```typescript
// Privacy-aware logging
class PrivacyAwareAuditLogger {
  async logPermissionCheck(entry: AuditLogEntry) {
    // Hash personally identifiable information
    const hashedEntry = {
      ...entry,
      userId: this.hashPII(entry.userId),
      ipAddress: this.anonymizeIP(entry.ipAddress),
      userAgent: this.sanitizeUserAgent(entry.userAgent)
    };
    
    await this.auditSystem.log(hashedEntry);
  }

  private hashPII(value: string): string {
    return crypto.createHash('sha256')
      .update(value + process.env.AUDIT_SALT!)
      .digest('hex')
      .substring(0, 16); // Shortened hash for logs
  }

  private anonymizeIP(ip: string): string {
    // Remove last octet for IPv4, last 80 bits for IPv6
    return ip.includes(':') 
      ? ip.split(':').slice(0, -5).join(':') + '::'
      : ip.split('.').slice(0, 3).join('.') + '.0';
  }
}
```

### Security Incident Response

#### Incident Detection
```typescript
// Automatic threat detection
class ThreatDetectionSystem {
  private readonly alertThresholds = {
    failedAuthAttempts: 10,      // per minute
    rapidPermissionChecks: 100,   // per minute  
    suspiciousPatterns: 5,        // per hour
    cacheManipulation: 1,         // immediate alert
  };

  async analyzeSecurityMetrics() {
    const stats = RouteGuards.getSystemStats();
    
    // Check authentication anomalies
    if (stats.authentication.authFailures > this.alertThresholds.failedAuthAttempts) {
      await this.escalateSecurityIncident('high_auth_failure_rate', {
        failures: stats.authentication.authFailures,
        threshold: this.alertThresholds.failedAuthAttempts
      });
    }

    // Check for unusual permission patterns
    if (stats.systemHealth.errorRate > 10) {
      await this.investigatePermissionAnomalies();
    }
  }

  async escalateSecurityIncident(type: string, details: any) {
    // 1. Log security incident
    await this.securityLog.critical('Security incident detected', { type, details });
    
    // 2. Notify security team
    await this.alerting.sendSecurityAlert(type, details);
    
    // 3. Take automatic protective action
    switch (type) {
      case 'high_auth_failure_rate':
        await this.enableRateLimiting();
        break;
      case 'suspicious_permission_pattern':
        await RouteGuards.emergencyInvalidation('Suspicious activity detected');
        break;
    }
  }
}
```

#### Emergency Response Procedures
```typescript
// Emergency security invalidation
const handleSecurityBreach = async (incident: SecurityIncident) => {
  console.error('🚨 SECURITY BREACH DETECTED', incident);
  
  // 1. Immediate cache invalidation
  await RouteGuards.emergencyInvalidation(
    `Security breach: ${incident.type} - ${incident.id}`
  );
  
  // 2. Block affected tokens
  if (incident.affectedTokens) {
    for (const token of incident.affectedTokens) {
      await authGuard.blockToken(token, `Security incident ${incident.id}`);
    }
  }
  
  // 3. Invalidate affected users
  if (incident.affectedUsers) {
    for (const userId of incident.affectedUsers) {
      await RouteGuards.invalidateUserPermissions(
        userId, 
        `Security incident ${incident.id}`
      );
    }
  }
  
  // 4. Enable enhanced monitoring
  await enableEnhancedSecurityMonitoring();
  
  // 5. Notify security team
  await notifySecurityTeam(incident);
  
  console.log('✅ Emergency security measures activated');
};

// Recovery procedures
const recoverFromSecurityIncident = async (incidentId: string) => {
  // 1. Verify threat is contained
  await verifyThreatContainment(incidentId);
  
  // 2. Gradual cache warming
  await gradualCacheWarming();
  
  // 3. Restore normal monitoring
  await restoreNormalMonitoring();
  
  // 4. Generate incident report
  await generateIncidentReport(incidentId);
  
  console.log('🔒 System recovered from security incident');
};
```

### Penetration Testing Support

#### Security Testing Hooks
```typescript
// Enable security testing mode (development/staging only)
if (process.env.NODE_ENV !== 'production' && process.env.ENABLE_SECURITY_TESTING) {
  // Expose security testing endpoints
  const securityTestingHandler = new Handler()
    .handle(async (context) => {
      const { action, userId, token } = context.req.body;
      
      switch (action) {
        case 'simulate_token_compromise':
          await authGuard.blockToken(token, 'Security test');
          return { result: 'Token blocked for testing' };
          
        case 'test_cache_invalidation':
          await RouteGuards.invalidateUserPermissions(userId, 'Security test');
          return { result: 'User cache invalidated for testing' };
          
        case 'stress_test_permissions':
          return await this.runPermissionStressTest(userId);
          
        default:
          throw new Error('Unknown security test action');
      }
    });
}

// Security test validation
const validateSecurityTestResults = async (testResults: any) => {
  const expectedBehaviors = {
    'blocked_token_rejection': true,
    'cache_invalidation_immediate': true,
    'permission_escalation_prevention': true,
    'audit_log_generation': true,
  };
  
  for (const [behavior, expected] of Object.entries(expectedBehaviors)) {
    if (testResults[behavior] !== expected) {
      throw new Error(`Security test failed: ${behavior}`);
    }
  }
  
  return { passed: true, details: testResults };
};
```

---

## Advanced Topics

### Custom Permission Resolvers

You can create custom permission resolvers for specialized business logic by extending the base `PermissionResolver` class:

```typescript
/**
 * Custom Time-based Permission Resolver
 * Grants permissions based on time windows and user context
 */
class TimeBasedPermissionResolver extends PermissionResolver<{
  permission: string;
  timeWindows: Array<{ start: string; end: string; days: string[] }>;
}> {
  
  async check(userPermissions: Set<string>, requirement: {
    permission: string;
    timeWindows: Array<{ start: string; end: string; days: string[] }>;
  }): Promise<boolean> {
    // First check if user has the base permission
    if (!userPermissions.has(requirement.permission)) {
      return false;
    }

    // Then check time windows
    const now = new Date();
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase();
    const currentTime = now.toTimeString().slice(0, 5); // HH:MM format

    return requirement.timeWindows.some(window => {
      const isDayAllowed = window.days.map(d => d.toLowerCase()).includes(currentDay);
      const isTimeAllowed = currentTime >= window.start && currentTime <= window.end;
      return isDayAllowed && isTimeAllowed;
    });
  }

  getType(): PermissionResolverType {
    return 'time-based' as PermissionResolverType;
  }

  getPerformanceCharacteristics(): PerformanceCharacteristics {
    return {
      timeComplexity: 'O(n) where n is number of time windows',
      memoryUsage: 'low',
      cacheUtilization: 'medium',
      recommendedFor: ['Time-sensitive operations', 'Business hours restrictions']
    };
  }

  canHandle(requirement: any): boolean {
    return requirement && 
           typeof requirement.permission === 'string' &&
           Array.isArray(requirement.timeWindows);
  }
}

// Usage in guard factory
class ExtendedPermissionGuardFactory extends PermissionGuardFactory {
  private timeBasedResolver: TimeBasedPermissionResolver;

  constructor(/* ... */) {
    super(/* ... */);
    this.timeBasedResolver = new TimeBasedPermissionResolver();
  }

  createTimeBasedGuard(requirement: any, config: Partial<GuardConfig> = {}) {
    // Implementation for time-based guard creation
    return new CustomTimeBasedGuard(
      { ...config, permissions: requirement },
      this.userContextService,
      this.guardConfig,
      this.cache,
      this.timeBasedResolver
    );
  }
}

// Example usage
const businessHoursOnly = {
  permission: 'admin:financial',
  timeWindows: [
    {
      start: '09:00',
      end: '17:00',
      days: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']
    }
  ]
};

.use(extendedGuardFactory.createTimeBasedGuard(businessHoursOnly))
```

### Batch Permission Checking

For scenarios where you need to check multiple permissions efficiently:

```typescript
/**
 * Batch Permission Checker
 * Optimizes multiple permission checks by sharing user context loading
 */
class BatchPermissionChecker {
  constructor(private userContextService: FastUserContextService) {}

  async checkMultiplePermissions(
    userId: string,
    checks: Array<{
      id: string;
      requirement: any;
      resolverType?: PermissionResolverType;
    }>
  ): Promise<Map<string, PermissionCheckResult>> {
    // Load user context once
    const userContext = await this.userContextService.getUserContext(userId);
    if (!userContext) {
      const failResult: PermissionCheckResult = {
        allowed: false,
        resolverType: PermissionResolverType.PLAIN,
        resolutionTimeUs: 0,
        cached: false,
        reason: 'User not found'
      };
      return new Map(checks.map(check => [check.id, failResult]));
    }

    // Batch all permission checks
    const batchRequirements = checks.map(check => ({
      requirement: check.requirement,
      resolverType: check.resolverType
    }));

    const results = await this.userContextService.checkPermissions(
      userId,
      batchRequirements,
      { useCache: true }
    );

    // Map results back to check IDs
    const resultMap = new Map<string, PermissionCheckResult>();
    checks.forEach((check, index) => {
      resultMap.set(check.id, results[index]);
    });

    return resultMap;
  }
}

// Usage example
const batchChecker = new BatchPermissionChecker(userContextService);

const permissionChecks = [
  { id: 'read_users', requirement: ['user:read'] },
  { id: 'admin_access', requirement: ['admin.*'], resolverType: PermissionResolverType.WILDCARD },
  { id: 'complex_rule', requirement: { or: [{ permission: 'A' }, { permission: 'B' }] } }
];

const results = await batchChecker.checkMultiplePermissions('user123', permissionChecks);

console.log('Read users allowed:', results.get('read_users')?.allowed);
console.log('Admin access allowed:', results.get('admin_access')?.allowed);
```

### Dynamic Permission Registry

For applications with dynamically changing permission schemas:

```typescript
/**
 * Dynamic Permission Registry
 * Supports runtime permission schema updates with versioning
 */
class DynamicPermissionRegistry implements PermissionRegistry {
  private permissions = new Map<string, PermissionDefinition>();
  private version = 1;
  private changeListeners: Array<(change: PermissionChange) => void> = [];

  async registerPermission(definition: PermissionDefinition): Promise<void> {
    this.permissions.set(definition.name, definition);
    this.version++;
    
    await this.notifyChange({
      type: 'permission_added',
      permission: definition.name,
      version: this.version
    });
  }

  async removePermission(permissionName: string): Promise<void> {
    if (this.permissions.delete(permissionName)) {
      this.version++;
      
      await this.notifyChange({
        type: 'permission_removed',
        permission: permissionName,
        version: this.version
      });
    }
  }

  async updatePermissionHierarchy(updates: PermissionHierarchyUpdate[]): Promise<void> {
    for (const update of updates) {
      const permission = this.permissions.get(update.permission);
      if (permission) {
        permission.children = update.children;
        permission.parent = update.parent;
      }
    }
    
    this.version++;
    
    await this.notifyChange({
      type: 'hierarchy_updated',
      version: this.version,
      affectedPermissions: updates.map(u => u.permission)
    });
  }

  getExpandedPermissions(wildcardPattern: string): string[] {
    const expanded: string[] = [];
    const basePattern = wildcardPattern.replace('.*', '');
    
    for (const [name, definition] of this.permissions) {
      if (name.startsWith(basePattern + '.')) {
        expanded.push(name);
      }
    }
    
    return expanded;
  }

  onPermissionChange(listener: (change: PermissionChange) => void): void {
    this.changeListeners.push(listener);
  }

  private async notifyChange(change: PermissionChange): Promise<void> {
    // Invalidate relevant caches
    await this.invalidateRelatedCaches(change);
    
    // Notify listeners
    for (const listener of this.changeListeners) {
      try {
        listener(change);
      } catch (error) {
        console.error('Permission change listener error:', error);
      }
    }
  }

  private async invalidateRelatedCaches(change: PermissionChange): Promise<void> {
    switch (change.type) {
      case 'permission_added':
      case 'permission_removed':
        // Conservative: invalidate all wildcard caches
        await cache.deletePattern('wild:*');
        break;
      case 'hierarchy_updated':
        // Invalidate caches for affected permissions
        for (const permission of change.affectedPermissions || []) {
          await cache.deletePattern(`*${permission}*`);
        }
        break;
    }
  }
}

interface PermissionDefinition {
  name: string;
  description: string;
  children?: string[];
  parent?: string;
  metadata?: Record<string, any>;
}

interface PermissionChange {
  type: 'permission_added' | 'permission_removed' | 'hierarchy_updated';
  permission?: string;
  version: number;
  affectedPermissions?: string[];
}

// Usage
const dynamicRegistry = new DynamicPermissionRegistry();

// Listen for permission changes to update UI
dynamicRegistry.onPermissionChange(async (change) => {
  console.log('Permission schema changed:', change);
  await notifyUI('permission_schema_updated', change);
});

// Add new permission at runtime
await dynamicRegistry.registerPermission({
  name: 'feature.beta.access',
  description: 'Access to beta features',
  parent: 'feature',
  metadata: { 
    category: 'beta',
    introduced: '2024-01-15' 
  }
});
```

### Advanced Caching Strategies

#### Multi-tier Caching with Redis
```typescript
/**
 * Multi-tier Cache Adapter
 * L1: Memory cache for ultra-fast access
 * L2: Redis for distributed caching
 * L3: Database for persistence
 */
class MultiTierCacheAdapter implements CacheAdapter {
  private l1Cache: MemoryCacheAdapter;
  private l2Cache: RedisCacheAdapter;
  private stats = {
    l1Hits: 0,
    l2Hits: 0,
    l3Hits: 0,
    misses: 0
  };

  constructor(
    private memoryConfig: MemoryCacheConfig,
    private redisConfig: RedisCacheConfig
  ) {
    this.l1Cache = new MemoryCacheAdapter(memoryConfig);
    this.l2Cache = new RedisCacheAdapter(redisConfig);
  }

  async get<T>(key: string): Promise<T | null> {
    // Try L1 cache first
    const l1Result = await this.l1Cache.get<T>(key);
    if (l1Result !== null) {
      this.stats.l1Hits++;
      return l1Result;
    }

    // Try L2 cache
    const l2Result = await this.l2Cache.get<T>(key);
    if (l2Result !== null) {
      this.stats.l2Hits++;
      // Populate L1 cache
      await this.l1Cache.set(key, l2Result, this.getL1TTL());
      return l2Result;
    }

    this.stats.misses++;
    return null;
  }

  async set<T>(key: string, value: T, ttlMs?: number): Promise<void> {
    // Write to both levels
    await Promise.all([
      this.l1Cache.set(key, value, this.getL1TTL(ttlMs)),
      this.l2Cache.set(key, value, ttlMs)
    ]);
  }

  async delete(key: string): Promise<void> {
    await Promise.all([
      this.l1Cache.delete(key),
      this.l2Cache.delete(key)
    ]);
  }

  async deletePattern(pattern: string): Promise<void> {
    await Promise.all([
      this.l1Cache.deletePattern(pattern),
      this.l2Cache.deletePattern(pattern)
    ]);
  }

  getName(): string {
    return 'multi-tier-cache';
  }

  getStats() {
    const total = this.stats.l1Hits + this.stats.l2Hits + this.stats.misses;
    return {
      ...this.stats,
      l1HitRate: total > 0 ? (this.stats.l1Hits / total) * 100 : 0,
      l2HitRate: total > 0 ? (this.stats.l2Hits / total) * 100 : 0,
      overallHitRate: total > 0 ? ((this.stats.l1Hits + this.stats.l2Hits) / total) * 100 : 0
    };
  }

  private getL1TTL(l2TTL?: number): number {
    // L1 cache should have shorter TTL to ensure freshness
    const baseTTL = l2TTL || this.memoryConfig.defaultTTL;
    return Math.min(baseTTL, 5 * 60 * 1000); // Max 5 minutes in L1
  }
}

// Smart cache warming
class SmartCacheWarmer {
  constructor(
    private userContextService: FastUserContextService,
    private cache: CacheAdapter
  ) {}

  async warmupActiveUsers(): Promise<void> {
    // Get list of recently active users
    const activeUsers = await this.getRecentlyActiveUsers(1000); // Last 1000 active users
    
    // Batch warm their contexts
    const warmupBatch = 50; // Process 50 users at a time
    for (let i = 0; i < activeUsers.length; i += warmupBatch) {
      const batch = activeUsers.slice(i, i + warmupBatch);
      await Promise.all(
        batch.map(userId => 
          this.userContextService.getUserContext(userId, true) // Force refresh
        )
      );
      
      // Small delay to avoid overwhelming the system
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    console.log(`🔥 Cache warmed for ${activeUsers.length} active users`);
  }

  async warmupCommonPermissions(): Promise<void> {
    // Pre-calculate common permission patterns
    const commonPatterns = [
      ['user:read'],
      ['user:create'],
      ['admin:users'],
      ['admin.*']
    ];

    const sampleUsers = await this.getSampleUsers(100);
    
    for (const userId of sampleUsers) {
      for (const pattern of commonPatterns) {
        try {
          await this.userContextService.checkPermission(
            userId,
            pattern,
            { useCache: true }
          );
        } catch (error) {
          // Ignore errors during warmup
        }
      }
    }
    
    console.log(`🔥 Common permissions warmed for ${sampleUsers.length} users`);
  }

  private async getRecentlyActiveUsers(limit: number): Promise<string[]> {
    // Implementation depends on your user activity tracking
    // This could query a database, analytics system, etc.
    return []; // Placeholder
  }

  private async getSampleUsers(limit: number): Promise<string[]> {
    // Get a representative sample of users for warmup
    return []; // Placeholder
  }
}
```

#### Cache Analytics and Optimization
```typescript
/**
 * Cache Analytics System
 * Provides insights for cache optimization
 */
class CacheAnalytics {
  private accessPatterns = new Map<string, AccessPattern>();
  private hitRateHistory: Array<{ timestamp: number; hitRate: number }> = [];

  recordAccess(key: string, hit: boolean, size?: number): void {
    const pattern = this.accessPatterns.get(key) || {
      key,
      totalAccesses: 0,
      hits: 0,
      misses: 0,
      averageSize: 0,
      lastAccess: 0
    };

    pattern.totalAccesses++;
    pattern.lastAccess = Date.now();
    
    if (hit) {
      pattern.hits++;
    } else {
      pattern.misses++;
    }

    if (size) {
      pattern.averageSize = (pattern.averageSize + size) / 2;
    }

    this.accessPatterns.set(key, pattern);
  }

  getHotKeys(limit = 10): AccessPattern[] {
    return Array.from(this.accessPatterns.values())
      .sort((a, b) => b.totalAccesses - a.totalAccesses)
      .slice(0, limit);
  }

  getColdKeys(olderThanMs = 60 * 60 * 1000): AccessPattern[] {
    const cutoff = Date.now() - olderThanMs;
    return Array.from(this.accessPatterns.values())
      .filter(pattern => pattern.lastAccess < cutoff);
  }

  getLowHitRateKeys(threshold = 0.5): AccessPattern[] {
    return Array.from(this.accessPatterns.values())
      .filter(pattern => (pattern.hits / pattern.totalAccesses) < threshold)
      .sort((a, b) => (a.hits / a.totalAccesses) - (b.hits / b.totalAccesses));
  }

  generateOptimizationReport(): CacheOptimizationReport {
    const totalAccesses = Array.from(this.accessPatterns.values())
      .reduce((sum, pattern) => sum + pattern.totalAccesses, 0);
    
    const totalHits = Array.from(this.accessPatterns.values())
      .reduce((sum, pattern) => sum + pattern.hits, 0);

    const overallHitRate = totalAccesses > 0 ? totalHits / totalAccesses : 0;
    
    const hotKeys = this.getHotKeys(10);
    const coldKeys = this.getColdKeys();
    const lowHitRateKeys = this.getLowHitRateKeys(0.3);

    return {
      overallHitRate,
      totalAccesses,
      totalKeys: this.accessPatterns.size,
      recommendations: this.generateRecommendations(hotKeys, coldKeys, lowHitRateKeys),
      hotKeys: hotKeys.slice(0, 5),
      problematicKeys: lowHitRateKeys.slice(0, 5)
    };
  }

  private generateRecommendations(
    hotKeys: AccessPattern[],
    coldKeys: AccessPattern[],
    lowHitRateKeys: AccessPattern[]
  ): string[] {
    const recommendations: string[] = [];

    if (hotKeys.length > 0) {
      recommendations.push(
        `Consider increasing TTL for hot keys: ${hotKeys.slice(0, 3).map(k => k.key).join(', ')}`
      );
    }

    if (coldKeys.length > this.accessPatterns.size * 0.3) {
      recommendations.push(
        `High number of cold keys (${coldKeys.length}). Consider reducing cache size or implementing LRU eviction.`
      );
    }

    if (lowHitRateKeys.length > 0) {
      recommendations.push(
        `Keys with low hit rates detected. Consider removing caching for: ${lowHitRateKeys.slice(0, 3).map(k => k.key).join(', ')}`
      );
    }

    return recommendations;
  }
}

interface AccessPattern {
  key: string;
  totalAccesses: number;
  hits: number;
  misses: number;
  averageSize: number;
  lastAccess: number;
}

interface CacheOptimizationReport {
  overallHitRate: number;
  totalAccesses: number;
  totalKeys: number;
  recommendations: string[];
  hotKeys: AccessPattern[];
  problematicKeys: AccessPattern[];
}
```

---

## FAQ

### General Questions

**Q: What is the main advantage of the Noony Guard System over custom authorization middleware?**

A: The Noony Guard System provides sub-millisecond cached permission checks (vs. 50-200ms for typical database-backed authorization), three optimized resolution strategies, comprehensive security features, and production-ready monitoring. It's specifically designed for serverless environments where cold starts and latency are critical concerns.

**Q: Can I use the guard system with existing authentication systems?**

A: Yes, the guard system is authentication-agnostic. You implement the `TokenValidator` interface to integrate with any JWT-based system including Firebase Auth, Auth0, AWS Cognito, or custom JWT implementations.

**Q: Is the guard system framework-specific?**

A: No, it's framework-agnostic. It works with Express, Fastify, Google Cloud Functions, AWS Lambda, and any HTTP framework through the `executeGeneric()` method.

### Performance Questions

**Q: How does caching work and what are the performance characteristics?**

A: The system uses multi-layer caching:
- **L1 Memory Cache**: Sub-millisecond access (~0.1ms)
- **L2 Distributed Cache**: Fast network access (~1-5ms) 
- **Database Fallback**: Traditional query (~10-100ms)

Performance by strategy:
- Plain permissions: ~0.1ms cached, ~1-2ms uncached
- Wildcard permissions: ~0.2ms cached, ~2-5ms uncached  
- Expression permissions: ~0.5ms cached, ~5-15ms uncached

**Q: How much memory does the cache use?**

A: Memory usage is configurable and bounded:
- Default: 1000 entries (development) / 2000 entries (production)
- Average entry size: ~500 bytes to 2KB depending on user permissions
- Total memory: ~1MB to 4MB typical usage
- LRU eviction prevents unbounded growth

**Q: What's the cache hit rate I should expect?**

A: Target cache hit rates:
- **95%+**: Excellent (optimal configuration)
- **85-95%**: Good (may need TTL tuning)
- **70-85%**: Acceptable (consider cache size increase)
- **<70%**: Poor (investigate cache invalidation patterns)

### Security Questions

**Q: How does conservative cache invalidation work?**

A: When a user's permissions change, the system:
1. Immediately removes the user's context from cache
2. Clears all permission check results for that user
3. Optionally clears authentication tokens for that user
4. In conservative mode, may clear related user caches

This "security-first" approach ensures permission changes take effect immediately, trading some performance for maximum security.

**Q: How do I handle token revocation?**

A: Use the `blockToken()` method:
```typescript
await authGuard.blockToken(compromisedToken, 'Security incident #123');
```
This immediately blocks the token and clears all related caches.

**Q: Is the system suitable for high-security environments?**

A: Yes, the system includes:
- Conservative cache invalidation strategies
- Comprehensive audit logging
- Token blocking and security event monitoring
- Principle of least privilege enforcement  
- Configurable security policies
- Emergency invalidation procedures

### Configuration Questions

**Q: How do I choose between pre-expansion and on-demand wildcard resolution?**

A: Choose based on your constraints:

**Pre-expansion** (recommended for production):
- Faster runtime (~0.2ms vs ~2-5ms)
- Higher memory usage
- Requires permission registry
- Best for: High-traffic, stable permission schemas

**On-demand** (good for development):
- Lower memory usage
- Slower runtime
- More flexible for dynamic permissions
- Best for: Development, changing schemas, memory-constrained environments

**Q: What cache TTL should I use?**

A: Recommended starting points:
- **Authentication tokens**: 5 minutes (security vs. performance balance)
- **User contexts**: 10 minutes (permission changes are less frequent)
- **Permission results**: 15 minutes (can be longer for stable permissions)

Adjust based on:
- How frequently permissions change
- Security requirements
- Performance needs
- Cache hit rate monitoring

### Integration Questions

**Q: How do I integrate with my existing user management system?**

A: Implement the `UserPermissionSource` interface:

```typescript
class MyUserPermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    // Query your user database/service
    const user = await myUserService.getById(userId);
    return {
      permissions: user.permissions,
      roles: user.roles,
      metadata: { /* user metadata */ }
    };
  }

  async getRolePermissions(roles: string[]) {
    // Query role-based permissions
    return await myRoleService.getPermissionsForRoles(roles);
  }

  async isUserContextStale(userId: string, lastUpdated: string) {
    // Check if user data has changed since cache time
    const user = await myUserService.getById(userId);
    return user.updatedAt > new Date(lastUpdated);
  }
}
```

**Q: Can I customize error messages and HTTP status codes?**

A: Yes, through the `errorMessage` option and by extending the error handling middleware:

```typescript
.use(RouteGuards.requirePermissions(['admin:users'], {
  errorMessage: 'Access denied: Administrative privileges required'
}))
```

For custom status codes, catch and transform the errors in your error handler.

**Q: How do I handle multiple permission requirements (AND vs OR logic)?**

A: Different strategies handle this differently:

**Plain permissions**: Always OR logic (user needs ANY of the permissions)
```typescript
.use(RouteGuards.requirePermissions(['user:create', 'admin:users'])) // OR
```

**Expression permissions**: Full boolean logic support
```typescript
.use(RouteGuards.requireComplexPermissions({
  and: [                           // AND logic
    { permission: 'user:create' },
    { permission: 'user:verify' }
  ]
}))

.use(RouteGuards.requireComplexPermissions({
  or: [                            // OR logic  
    { permission: 'admin:users' },
    { and: [                       // Nested AND within OR
      { permission: 'moderator:users' },
      { permission: 'department:hr' }
    ]}
  ]
}))
```

### Troubleshooting Questions

**Q: My cache hit rate is low. How do I improve it?**

A: Low cache hit rates can be caused by:

1. **Frequent cache invalidation**: Check invalidation logs
   - Solution: Adjust TTL settings or reduce invalidation frequency

2. **High user churn**: Many unique users, few repeat requests
   - Solution: Increase cache size or implement cache warming

3. **Permission changes**: Users' permissions change frequently
   - Solution: Consider less conservative invalidation if security allows

4. **Short TTL**: Cache entries expiring too quickly
   - Solution: Increase TTL based on permission change frequency

Debug with:
```typescript
const stats = RouteGuards.getSystemStats();
console.log('Cache hit rate:', stats.systemHealth.cacheEfficiency);
console.log('Total checks:', stats.systemHealth.totalGuardChecks);
```

**Q: I'm getting authentication errors. How do I debug?**

A: Enable detailed logging and check:

1. **Token format**: Ensure proper "Bearer " prefix
2. **Token validation**: Check your `TokenValidator` implementation
3. **User context loading**: Verify `UserPermissionSource` returns data
4. **Network issues**: Check connectivity to user data source

Debug steps:
```typescript
// Enable debug logging
const authConfig = {
  // ... other config
  customValidation: async (token, user) => {
    console.log('Token validation:', { token: token.sub, user: user.userId });
    return true; // Your validation logic
  }
};

// Check authentication stats  
const stats = RouteGuards.getSystemStats();
console.log('Auth stats:', stats.authentication);
```

**Q: Performance is slower than expected. What should I check?**

A: Performance issues are usually caused by:

1. **Cache misses**: Check cache hit rates (should be >85%)
2. **Slow user data source**: Database/API queries taking too long
3. **Complex expressions**: Deeply nested permission expressions
4. **Cache size**: Too small cache causing frequent evictions

Diagnostic steps:
```typescript
// Monitor performance
const health = await RouteGuards.healthCheck();
console.log('System health:', health);

// Check individual component performance
const stats = RouteGuards.getSystemStats();
console.log('Average auth time:', stats.authentication.averageResolutionTimeUs);
console.log('Average context load time:', stats.userContextService.averageResolutionTimeUs);
```

**Q: How do I test the guard system?**

A: Testing strategies:

1. **Unit tests**: Test individual resolvers and components
2. **Integration tests**: Test full middleware pipeline
3. **Performance tests**: Load test with realistic traffic
4. **Security tests**: Test with invalid tokens, permission escalation attempts

Example test:
```typescript
describe('RouteGuards', () => {
  beforeEach(async () => {
    await RouteGuards.configure(testConfig, mockPermissionSource, mockTokenValidator, authConfig);
  });

  test('should allow access with correct permissions', async () => {
    const mockUser = { userId: 'test', permissions: ['user:create'] };
    mockTokenValidator.validateToken.mockResolvedValue({ valid: true, decoded: { sub: 'test' } });
    mockPermissionSource.getUserPermissions.mockResolvedValue({
      permissions: ['user:create'],
      roles: ['user']
    });

    const handler = new Handler()
      .use(RouteGuards.requirePermissions(['user:create']))
      .handle(async () => ({ success: true }));

    const result = await handler.execute(mockRequest, mockResponse);
    expect(result).toEqual({ success: true });
  });
});
```

---

## Migration Guide

### Migrating from Custom Authorization Middleware

This guide helps you migrate from custom authorization implementations to the Noony Guard System.

#### Pre-Migration Assessment

Before starting the migration, assess your current authorization system:

```typescript
// Current custom authorization patterns to identify:

// 1. Simple permission checks
app.get('/users', requirePermission('user:read'), handler);

// 2. Role-based checks  
app.get('/admin', requireRole('admin'), handler);

// 3. Complex logic
app.get('/reports', (req, res, next) => {
  if (user.role === 'admin' || (user.role === 'manager' && user.department === 'finance')) {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
}, handler);

// 4. Resource ownership checks
app.put('/users/:id', (req, res, next) => {
  if (req.user.id === req.params.id || req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
}, handler);
```

#### Step 1: Install and Configure

```bash
npm install @noony-serverless/core
```

```typescript
// 1. Create your token validator (adapt your existing JWT logic)
class ExistingTokenValidator implements TokenValidator {
  async validateToken(token: string) {
    // Use your existing JWT validation logic
    try {
      const decoded = await yourExistingJWTVerify(token);
      return { valid: true, decoded };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  extractUserId(decoded: any): string {
    // Adapt to your token structure
    return decoded.userId || decoded.sub || decoded.id;
  }

  isTokenExpired(decoded: any): boolean {
    return decoded.exp * 1000 < Date.now();
  }
}

// 2. Create your permission source (adapt your existing user/role queries)
class ExistingPermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    // Use your existing user query logic
    const user = await yourExistingUserQuery(userId);
    return {
      permissions: user.permissions || [],
      roles: user.roles || [],
      metadata: {
        email: user.email,
        department: user.department,
        // ... other metadata you need
      }
    };
  }

  async getRolePermissions(roles: string[]): Promise<string[]> {
    // Use your existing role permission logic
    return await yourExistingRolePermissionQuery(roles);
  }

  async isUserContextStale(userId: string, lastUpdated: string): Promise<boolean> {
    // Check if user changed since cache time
    const user = await yourExistingUserQuery(userId);
    return user.updatedAt > new Date(lastUpdated);
  }
}

// 3. Configure the guard system
await RouteGuards.configure(
  GuardConfiguration.production(), // or development()
  new ExistingPermissionSource(),
  new ExistingTokenValidator(),
  {
    jwtSecret: process.env.JWT_SECRET, // Your existing secret
    tokenHeader: 'authorization',      // Your existing header
    tokenPrefix: 'Bearer ',            // Your existing prefix
    requireEmailVerification: true,    // Your existing requirements
    allowInactiveUsers: false,
  }
);
```

#### Step 2: Migration Strategy by Pattern

##### Simple Permission Checks
```typescript
// BEFORE: Custom middleware
const requirePermission = (permission) => {
  return async (req, res, next) => {
    const user = await getUserFromToken(req.headers.authorization);
    if (user.permissions.includes(permission)) {
      req.user = user;
      next();
    } else {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
};

app.get('/users', requirePermission('user:read'), userHandler);

// AFTER: Noony Guards
const getUsersHandler = new Handler<{}, User[]>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['user:read']))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    // Your existing business logic
    return await userService.getAll();
  });

app.get('/users', (req, res) => getUsersHandler.executeGeneric(req, res));
```

##### Role-based Checks
```typescript
// BEFORE: Role checking
const requireRole = (role) => {
  return async (req, res, next) => {
    const user = await getUserFromToken(req.headers.authorization);
    if (user.roles.includes(role)) {
      req.user = user;
      next();
    } else {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
};

app.get('/admin', requireRole('admin'), adminHandler);

// AFTER: Noony Guards (convert roles to wildcard patterns)
const getAdminHandler = new Handler()
  .use(RouteGuards.requireWildcardPermissions(['admin.*']))
  .handle(async (context) => {
    // Your existing admin logic
    return await adminService.getDashboard();
  });

// Update your permission source to include role-based wildcards
class MigratedPermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    const user = await yourExistingUserQuery(userId);
    
    // Convert roles to wildcard permissions
    const roleWildcards = user.roles.map(role => `${role}.*`);
    
    return {
      permissions: [...(user.permissions || []), ...roleWildcards],
      roles: user.roles || [],
      metadata: { /* ... */ }
    };
  }
  // ...
}
```

##### Complex Logic
```typescript
// BEFORE: Complex custom logic
const complexAuth = async (req, res, next) => {
  const user = await getUserFromToken(req.headers.authorization);
  if (user.role === 'admin' || 
     (user.role === 'manager' && user.department === 'finance')) {
    req.user = user;
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
};

app.get('/reports', complexAuth, reportHandler);

// AFTER: Noony Guards with expressions
const getReportsHandler = new Handler()
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { permission: 'admin.reports' },
      { and: [
        { permission: 'manager.reports' },
        { permission: 'department.finance' }
      ]}
    ]
  }))
  .handle(async (context) => {
    return await reportService.getFinancialReports();
  });

// Update permission source to include department permissions
class EnhancedPermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string) {
    const user = await yourExistingUserQuery(userId);
    
    const permissions = [...(user.permissions || [])];
    
    // Add role-based permissions
    if (user.roles.includes('admin')) {
      permissions.push('admin.reports', 'admin.users', 'admin.*');
    }
    if (user.roles.includes('manager')) {
      permissions.push('manager.reports', 'manager.team');
    }
    
    // Add department permissions
    if (user.department) {
      permissions.push(`department.${user.department}`);
    }
    
    return {
      permissions,
      roles: user.roles || [],
      metadata: { department: user.department, /* ... */ }
    };
  }
}
```

##### Resource Ownership
```typescript
// BEFORE: Resource ownership checks
const requireOwnershipOrAdmin = async (req, res, next) => {
  const user = await getUserFromToken(req.headers.authorization);
  const resourceId = req.params.id;
  
  if (user.id === resourceId || user.roles.includes('admin')) {
    req.user = user;
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
};

app.put('/users/:id', requireOwnershipOrAdmin, updateUserHandler);

// AFTER: Noony Guards + business logic
const updateUserHandler = new Handler<UpdateUserRequest, User>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['user:update', 'admin:users'])) // Basic auth
  .use(new BodyValidationMiddleware(updateUserSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const { userId } = context.req.params;
    const currentUser = context.businessData.get('user') as UserContext;
    
    // Business logic for ownership check
    const hasAdminUsers = currentUser.permissions.has('admin:users');
    if (!hasAdminUsers && currentUser.userId !== userId) {
      throw new SecurityError('Access denied: Cannot update other user profiles');
    }
    
    return await userService.update(userId, context.req.validatedBody);
  });
```

#### Step 3: Gradual Migration Strategy

##### Phase 1: Parallel Implementation
```typescript
// Run both systems in parallel for comparison
const dualAuthMiddleware = async (req, res, next) => {
  let legacyResult, guardResult;
  
  try {
    // Test legacy system
    await legacyAuthCheck(req, res, () => {
      legacyResult = 'allowed';
    });
  } catch {
    legacyResult = 'denied';
  }
  
  try {
    // Test guard system
    const handler = new Handler()
      .use(RouteGuards.requirePermissions(['user:read']))
      .handle(async () => ({ success: true }));
    
    await handler.executeGeneric(req, res);
    guardResult = 'allowed';
  } catch {
    guardResult = 'denied';
  }
  
  // Log discrepancies
  if (legacyResult !== guardResult) {
    console.warn('Authorization mismatch:', {
      endpoint: req.path,
      legacy: legacyResult,
      guard: guardResult,
      user: req.user?.id
    });
  }
  
  // Use legacy result for now
  if (legacyResult === 'allowed') {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
};
```

##### Phase 2: Feature Flag Migration
```typescript
const useGuardSystem = process.env.USE_GUARD_SYSTEM === 'true';

const authMiddleware = useGuardSystem 
  ? (req, res) => guardHandler.executeGeneric(req, res)
  : legacyAuthMiddleware;

// Gradually enable per endpoint
const endpointFlags = {
  'GET /users': process.env.GUARD_GET_USERS === 'true',
  'POST /users': process.env.GUARD_POST_USERS === 'true',
  // ...
};

const selectAuthMiddleware = (endpoint) => {
  return endpointFlags[endpoint] ? guardMiddleware : legacyMiddleware;
};
```

##### Phase 3: Performance Comparison
```typescript
// Monitor performance during migration
const performanceComparison = {
  legacy: { totalTime: 0, count: 0 },
  guard: { totalTime: 0, count: 0 }
};

const timedLegacyAuth = async (req, res, next) => {
  const start = Date.now();
  try {
    await legacyAuthCheck(req, res, next);
  } finally {
    performanceComparison.legacy.totalTime += Date.now() - start;
    performanceComparison.legacy.count++;
  }
};

const timedGuardAuth = async (req, res, next) => {
  const start = Date.now();
  try {
    await guardHandler.executeGeneric(req, res);
    next();
  } finally {
    performanceComparison.guard.totalTime += Date.now() - start;
    performanceComparison.guard.count++;
  }
};

// Log comparison every hour
setInterval(() => {
  const legacyAvg = performanceComparison.legacy.totalTime / performanceComparison.legacy.count;
  const guardAvg = performanceComparison.guard.totalTime / performanceComparison.guard.count;
  
  console.log('Performance comparison:', {
    legacy: `${legacyAvg.toFixed(2)}ms`,
    guard: `${guardAvg.toFixed(2)}ms`,
    improvement: `${((legacyAvg - guardAvg) / legacyAvg * 100).toFixed(1)}%`
  });
}, 60 * 60 * 1000);
```

#### Step 4: Testing Strategy

##### Unit Tests
```typescript
describe('Migration Tests', () => {
  test('should produce same results as legacy system', async () => {
    const testCases = [
      { user: { id: 'user1', permissions: ['user:read'] }, resource: '/users', expected: 'allowed' },
      { user: { id: 'user2', permissions: [] }, resource: '/users', expected: 'denied' },
      // ... more test cases
    ];

    for (const testCase of testCases) {
      const legacyResult = await legacyAuthCheck(testCase.user, testCase.resource);
      const guardResult = await guardAuthCheck(testCase.user, testCase.resource);
      
      expect(guardResult).toBe(legacyResult);
    }
  });
});
```

##### Integration Tests
```typescript
describe('End-to-End Authorization', () => {
  test('should handle real request flow', async () => {
    const mockRequest = createMockRequest('/users', 'Bearer valid-token');
    const mockResponse = createMockResponse();
    
    const handler = new Handler()
      .use(RouteGuards.requirePermissions(['user:read']))
      .handle(async () => ({ users: [] }));
    
    const result = await handler.executeGeneric(mockRequest, mockResponse);
    
    expect(mockResponse.statusCode).toBe(200);
    expect(result).toHaveProperty('users');
  });
});
```

#### Step 5: Monitoring and Rollback Plan

##### Migration Monitoring
```typescript
const migrationMetrics = {
  endpoints: new Map(),
  errors: [],
  performance: []
};

const trackMigration = (endpoint: string, method: 'legacy' | 'guard', success: boolean, duration: number) => {
  const key = `${endpoint}:${method}`;
  const current = migrationMetrics.endpoints.get(key) || { success: 0, failure: 0, totalDuration: 0 };
  
  if (success) {
    current.success++;
  } else {
    current.failure++;
  }
  current.totalDuration += duration;
  
  migrationMetrics.endpoints.set(key, current);
};

// Dashboard for monitoring
const getMigrationDashboard = () => {
  const comparison = {};
  
  for (const [key, stats] of migrationMetrics.endpoints) {
    const [endpoint, method] = key.split(':');
    if (!comparison[endpoint]) comparison[endpoint] = {};
    
    comparison[endpoint][method] = {
      successRate: stats.success / (stats.success + stats.failure) * 100,
      averageTime: stats.totalDuration / (stats.success + stats.failure),
      totalRequests: stats.success + stats.failure
    };
  }
  
  return comparison;
};
```

##### Rollback Procedures
```typescript
// Automated rollback triggers
const rollbackTriggers = {
  errorRateThreshold: 5,    // 5% error rate
  performanceDegradation: 50, // 50% slower than legacy
  criticalErrors: 1          // Any critical error
};

const checkRollbackConditions = async () => {
  const stats = RouteGuards.getSystemStats();
  const health = await RouteGuards.healthCheck();
  
  let shouldRollback = false;
  let reason = '';
  
  if (stats.systemHealth.errorRate > rollbackTriggers.errorRateThreshold) {
    shouldRollback = true;
    reason = 'High error rate';
  }
  
  if (health.status === 'unhealthy') {
    shouldRollback = true;
    reason = 'System unhealthy';
  }
  
  if (shouldRollback) {
    console.error(`🚨 ROLLBACK TRIGGERED: ${reason}`);
    await executeRollback(reason);
  }
};

const executeRollback = async (reason: string) => {
  // 1. Switch back to legacy system
  process.env.USE_GUARD_SYSTEM = 'false';
  
  // 2. Clear guard system caches
  await RouteGuards.emergencyInvalidation('Migration rollback');
  
  // 3. Notify operations team
  await notifyOpsTeam('Guard system rollback', { reason, timestamp: new Date() });
  
  // 4. Log rollback event
  console.error('Guard system rolled back to legacy authorization', { reason });
};
```

#### Step 6: Complete Migration Checklist

- [ ] **Assessment Complete**: Current authorization patterns documented
- [ ] **Dependencies Installed**: @noony-serverless/core installed and configured
- [ ] **Token Validator**: Implemented and tested with existing JWT logic
- [ ] **Permission Source**: Implemented and tested with existing user/role queries
- [ ] **Simple Permissions**: Migrated and tested in parallel
- [ ] **Complex Logic**: Converted to expressions or business logic patterns
- [ ] **Resource Ownership**: Handled via business logic in handlers
- [ ] **Feature Flags**: Implemented for gradual rollout
- [ ] **Monitoring**: Performance and error tracking in place
- [ ] **Testing**: Unit and integration tests passing
- [ ] **Rollback Plan**: Automated rollback procedures tested
- [ ] **Performance Baseline**: Guard system performance meets expectations
- [ ] **Security Validation**: Security features tested and validated
- [ ] **Documentation**: Updated with new authorization patterns
- [ ] **Team Training**: Team familiar with new guard system patterns
- [ ] **Legacy Cleanup**: Old authorization middleware removed

#### Common Migration Pitfalls

1. **Inconsistent Permission Models**: Ensure your new permission model covers all existing authorization scenarios
2. **Cache Cold Start**: Plan for cache warming strategies to maintain performance
3. **Token Format Changes**: Ensure token validation works identically to legacy system
4. **Error Handling**: Guard system errors may differ from legacy error formats
5. **Async Boundary Issues**: Ensure proper async handling in middleware pipeline
6. **Context Propagation**: User context must be properly available to business logic
7. **Testing Coverage**: Test all permission combinations, not just happy paths

By following this migration guide, you can safely transition from custom authorization to the Noony Guard System while maintaining security and performance throughout the process.

---

## Conclusion

The Noony Guard System provides a comprehensive, high-performance solution for authentication and authorization in serverless environments. With its three distinct permission resolution strategies, multi-layer caching, and security-first design, it offers significant performance improvements over traditional authorization middleware while maintaining enterprise-grade security features.

Key benefits:
- **10-100x performance improvement** through intelligent caching
- **Three optimized strategies** for different use cases and performance requirements
- **Production-ready features** including monitoring, audit trails, and security incident response
- **Framework-agnostic design** that works with any HTTP framework
- **Comprehensive documentation and examples** for rapid adoption

For support and contributions, visit the [Noony Framework repository](https://github.com/noony-framework/noony-core).

---

*Generated with ❤️ by the Noony Framework Team*