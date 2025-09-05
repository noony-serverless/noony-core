# Noony Framework Guard System Rules

## Guard System Configuration

### Initial Setup

```typescript
import { RouteGuards, GuardConfiguration } from '@noony-serverless/core';

// ✅ CORRECT: Always configure guards during cold start
const setupGuards = async () => {
  // 1. Define your token validator
  class MyTokenValidator implements TokenValidator {
    async validateToken(token: string) {
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
        metadata: { email: user.email, status: user.status }
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

  // 3. Configure the system
  await RouteGuards.configure(
    process.env.NODE_ENV === 'production' 
      ? GuardConfiguration.production()
      : GuardConfiguration.development(),
    new DatabasePermissionSource(),
    new MyTokenValidator(),
    {
      jwtSecret: process.env.JWT_SECRET,
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: true,
      allowInactiveUsers: false
    }
  );
};

// Initialize on cold start
await setupGuards();
```

## Permission Resolution Strategies

### 1. Plain Permissions (Fastest - O(1))

```typescript
// ✅ USE FOR: High-traffic endpoints, simple permission models
// Performance: ~0.1ms cached, ~1-2ms uncached

const handler = new Handler<CreateUserRequest, User>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, User>())
  .use(RouteGuards.requirePermissions(['user:create', 'admin:users']))
  .use(new BodyValidationMiddleware<CreateUserRequest, User>(createUserSchema))
  .handle(async (context) => {
    // User has 'user:create' OR 'admin:users' permission
    const userData = context.req.validatedBody!;
    const user = await userService.create(userData);
    context.res.json({ user });
  });

// Multiple handlers with different permission requirements
const readHandler = new Handler<unknown, User>()
  .use(RouteGuards.requirePermissions(['user:read']))
  .handle(async (context) => { /* Read logic */ });

const updateHandler = new Handler<UpdateUserRequest, User>()
  .use(RouteGuards.requirePermissions(['user:update', 'admin:users']))
  .handle(async (context) => { /* Update logic */ });

const deleteHandler = new Handler<DeleteUserRequest, User>()
  .use(RouteGuards.requirePermissions(['user:delete', 'admin:full']))
  .handle(async (context) => { /* Delete logic */ });
```

### 2. Wildcard Permissions (Pattern Matching)

```typescript
// ✅ USE FOR: Role-based hierarchical permissions, administrative operations
// Performance: ~0.2ms cached (pre-expansion), ~2-5ms cached (on-demand)

const adminHandler = new Handler<AdminRequest, AdminUser>()
  .use(new ErrorHandlerMiddleware<AdminRequest, AdminUser>())
  .use(RouteGuards.requireWildcardPermissions(['admin.*']))
  .handle(async (context) => {
    // Matches: admin.users, admin.reports, admin.settings, etc.
  });

const userProfileHandler = new Handler<ProfileRequest, User>()
  .use(RouteGuards.requireWildcardPermissions(['user.profile.*', 'admin.*']))
  .handle(async (context) => {
    // Matches: user.profile.read, user.profile.update, admin.*, etc.
  });

// ✅ CORRECT: Hierarchical permission patterns
const organizationHandler = new Handler<OrgRequest, OrgUser>()
  .use(RouteGuards.requireWildcardPermissions([
    'org.department.*',      // org.department.view, org.department.manage
    'system.users.*',        // system.users.create, system.users.delete
    'reports.*.view'         // Complex multi-level patterns
  ]))
  .handle(async (context) => {
    // Business logic for organization management
  });
```

### 3. Expression Permissions (Boolean Logic)

```typescript
// ✅ USE FOR: Complex business rules, fine-grained access control
// Performance: ~0.5ms cached, ~5-15ms uncached

const complexHandler = new Handler<ComplexRequest, BusinessUser>()
  .use(new ErrorHandlerMiddleware<ComplexRequest, BusinessUser>())
  .use(RouteGuards.requireComplexPermissions({
    or: [
      // Admin with read access
      { and: [{ permission: 'admin.users' }, { permission: 'admin.read' }] },
      // Moderator with department access
      { and: [
        { permission: 'moderator.content' },
        { permission: 'org.department.reports' }
      ]}
    ]
  }))
  .handle(async (context) => {
    // Complex authorization logic satisfied
  });

// Advanced permission expressions
const advancedHandler = new Handler<AdvancedRequest, User>()
  .use(RouteGuards.requireComplexPermissions({
    and: [
      { permission: 'user.read' },
      { not: { permission: 'user.restricted' } }, // Must NOT have this
      { or: [
        { permission: 'department.finance' },
        { permission: 'department.hr' }
      ]}
    ]
  }))
  .handle(async (context) => {
    // Must have 'user.read' AND NOT 'user.restricted' 
    // AND ('department.finance' OR 'department.hr')
  });
```

## Guard Configuration Profiles

### Environment-Specific Profiles

```typescript
// Development configuration
const devConfig = GuardConfiguration.development();
// - Strategy: On-demand matching (memory efficient)
// - Cache TTL: 5 minutes (faster development cycles)
// - Cache Size: 500 entries
// - Invalidation: Less conservative for faster iteration
// - Monitoring: Detailed logging enabled

// Production configuration  
const prodConfig = GuardConfiguration.production();
// - Strategy: Pre-expansion (maximum runtime performance)
// - Cache TTL: 15 minutes (optimal balance)
// - Cache Size: 2000 entries
// - Invalidation: Conservative (security-first)
// - Monitoring: Essential metrics only

// Custom configuration
const customConfig: GuardEnvironmentProfile = {
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
    metricsCollectionInterval: 45000,
  }
};
```

## Cache Management and Invalidation

### Manual Cache Invalidation

```typescript
// ✅ CORRECT: Invalidate user permissions after changes
const updateUserPermissions = async (userId: string, newPermissions: string[]) => {
  // Update permissions in database
  await userService.updatePermissions(userId, newPermissions);
  
  // Invalidate user's permission cache immediately
  await RouteGuards.invalidateUserPermissions(userId, 'Permissions updated');
};

// Role-based invalidation
const updateUserRole = async (userId: string, newRole: string) => {
  await userService.updateRole(userId, newRole);
  
  // Invalidate since role change affects permissions
  await RouteGuards.invalidateUserPermissions(userId, 'Role updated');
};

// System-wide invalidation for major changes
const updateSecurityPolicy = async () => {
  await securityService.updateGlobalPolicy();
  
  // Invalidate all permission caches
  await RouteGuards.invalidateAllPermissions('Security policy update');
};

// Emergency security response
const handleSecurityBreach = async () => {
  // Immediate cache clearing for security incidents
  await RouteGuards.emergencyInvalidation('Security breach - credential compromise');
};
```

### Conservative Cache Invalidation Strategy

```typescript
// The framework uses conservative invalidation by default:
// - Permission changes flush ALL related caches
// - Security-first approach trades performance for maximum security
// - Immediate revocation capabilities
// - Audit trail for all cache invalidations

// ✅ CORRECT: Trust the framework's conservative approach
// Don't try to optimize cache invalidation for security operations
```

## Performance Monitoring and Optimization

### System Statistics

```typescript
// Monitor guard system performance
const monitorGuardPerformance = () => {
  const stats = RouteGuards.getSystemStats();
  
  console.log('Authentication Stats:', {
    successRate: stats.authentication.successRate,
    cacheHitRate: stats.authentication.cacheHitRate,
    averageTime: stats.authentication.averageResolutionTimeUs,
    suspiciousAttempts: stats.authentication.suspiciousAttempts
  });
  
  console.log('Permission Stats:', {
    totalChecks: stats.permissionGuardFactory.aggregatedStats.totalChecks,
    successRate: stats.permissionGuardFactory.aggregatedStats.overallSuccessRate,
    averageTime: stats.permissionGuardFactory.aggregatedStats.averageProcessingTimeUs
  });
  
  console.log('System Health:', {
    cacheEfficiency: stats.systemHealth.cacheEfficiency,
    averageResponseTime: stats.systemHealth.averageResponseTime,
    errorRate: stats.systemHealth.errorRate
  });
};

// Set up periodic monitoring
setInterval(monitorGuardPerformance, 60000); // Every minute
```

### Health Checks

```typescript
const guardHealthCheck = async () => {
  const health = await RouteGuards.healthCheck();
  
  if (health.status === 'degraded') {
    console.warn('Guard system performance degraded:', health.details);
    // Alert monitoring systems
  } else if (health.status === 'unhealthy') {
    console.error('Guard system unhealthy:', health.details);
    // Trigger alerts and potentially fallback mechanisms
  }
  
  return health;
};
```

## Authentication-Only Guards

### Skip Permission Checks

```typescript
// ✅ USE FOR: Endpoints that only need authentication, no specific permissions
const profileHandler = new Handler<unknown, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<unknown, AuthenticatedUser>())
  .use(RouteGuards.requireAuth({
    requireAuth: true,
    errorMessage: 'Authentication required to access profile'
  }))
  .handle(async (context) => {
    // User is authenticated but no permission checking
    const user = context.user!; // Guaranteed to exist
    return { profile: user };
  });
```

## Multi-Tenant Guard Usage

### Tenant-Aware Permission Checking

```typescript
interface TenantUser {
  id: string;
  tenantId: string;
  role: string;
  permissions: string[];
}

// Tenant-scoped permissions
const tenantHandler = new Handler<TenantRequest, TenantUser>()
  .use(new ErrorHandlerMiddleware<TenantRequest, TenantUser>())
  .use(RouteGuards.requirePermissions(['tenant:manage', 'admin:tenants']))
  .handle(async (context) => {
    const user = context.user!;
    
    // Additional tenant validation in business logic
    if (user.tenantId !== context.req.body.tenantId && user.role !== 'system-admin') {
      throw new SecurityError('Access denied to tenant resources');
    }
    
    // Process tenant-specific operation
  });
```

## Custom Guard Options

### Advanced Configuration

```typescript
const handler = new Handler<RequestType, UserType>()
  .use(RouteGuards.requirePermissions(['user:create'], {
    requireAuth: true,              // Default: true
    cacheResults: true,             // Default: true
    auditTrail: true,              // Default: false
    errorMessage: 'Custom access denied message',
    cacheTtlMs: 5 * 60 * 1000      // Override global TTL: 5 minutes
  }))
  .handle(async (context) => {
    // Handler logic
  });
```

## Error Handling with Guards

### Guard-Specific Error Handling

```typescript
class GuardErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    if (error.message?.includes('Guard:')) {
      // Handle guard-specific errors
      const guardError = this.parseGuardError(error.message);
      
      context.res.status(guardError.statusCode).json({
        success: false,
        error: {
          type: 'guard_error',
          code: guardError.code,
          message: guardError.message
        }
      });
      return;
    }
    
    // Handle other errors...
  }
  
  private parseGuardError(message: string) {
    // Parse guard error messages for specific handling
    if (message.includes('Authentication failed')) {
      return { statusCode: 401, code: 'AUTH_FAILED', message: 'Authentication required' };
    }
    if (message.includes('Permission denied')) {
      return { statusCode: 403, code: 'PERMISSION_DENIED', message: 'Insufficient permissions' };
    }
    return { statusCode: 403, code: 'ACCESS_DENIED', message: 'Access denied' };
  }
}
```

## Best Practices

### 1. Guard Strategy Selection

```typescript
// High-traffic, simple permissions → Plain
.use(RouteGuards.requirePermissions(['user:read']))

// Hierarchical, role-based → Wildcard  
.use(RouteGuards.requireWildcardPermissions(['admin.*']))

// Complex business rules → Expression
.use(RouteGuards.requireComplexPermissions({ and: [/*...*/] }))
```

### 2. Performance Optimization

```typescript
// ✅ CORRECT: Use appropriate caching strategies
const config = {
  cache: {
    maxEntries: 2000,                    // Size based on user count
    defaultTtlMs: 15 * 60 * 1000,       // 15 min for production
    userContextTtlMs: 10 * 60 * 1000,   // User data TTL
    authTokenTtlMs: 5 * 60 * 1000,      // Token cache TTL
  }
};
```

### 3. Security Best Practices

```typescript
// ✅ CORRECT: Always invalidate on permission changes
await RouteGuards.invalidateUserPermissions(userId, 'Permission updated');

// ✅ CORRECT: Use conservative invalidation in production
const config = GuardConfiguration.production(); // Conservative by default

// ✅ CORRECT: Monitor suspicious activity
const stats = RouteGuards.getSystemStats();
if (stats.authentication.suspiciousAttempts > threshold) {
  // Alert security team
}
```

### 4. Error Handling

```typescript
// ✅ CORRECT: Specific error messages for debugging
.use(RouteGuards.requirePermissions(['user:create'], {
  errorMessage: 'User creation requires user:create or admin:users permission'
}))

// ✅ CORRECT: Audit trail for sensitive operations
.use(RouteGuards.requireComplexPermissions(complexExpression, {
  auditTrail: true  // Log all access attempts
}))
```

## Common Anti-Patterns

```typescript
// ❌ INCORRECT: Don't bypass guards for "simple" endpoints
const badHandler = new Handler()
  .handle(async (context) => {
    // No authentication or authorization - security risk
  });

// ❌ INCORRECT: Don't implement custom permission checking
const badHandler = new Handler()
  .use(RouteGuards.requireAuth())
  .handle(async (context) => {
    // Don't do this - use guard system instead
    if (!context.user.permissions.includes('admin')) {
      throw new Error('Access denied');
    }
  });

// ❌ INCORRECT: Don't mix guard strategies in same handler
const confusingHandler = new Handler()
  .use(RouteGuards.requirePermissions(['user:read']))
  .use(RouteGuards.requireWildcardPermissions(['admin.*'])) // Confusing
  .handle(async (context) => {
    // Unclear what permissions are actually required
  });
```