# RouteGuards Getting Started Guide

A practical, focused guide to quickly implement authentication and authorization with the Noony Framework's RouteGuards system. This guide is designed for developers who want to get up and running quickly with copy-paste examples.

## Table of Contents

1. [5-Minute Quick Setup](#5-minute-quick-setup)
2. [Environment Configuration](#environment-configuration)
3. [Simple Scenarios](#simple-scenarios)
4. [Complex Scenarios](#complex-scenarios)
5. [Practical FAQ](#practical-faq)

---

## 5-Minute Quick Setup

### Step 1: Install Dependencies

```bash
npm install @noony-serverless/core
```

### Step 2: Basic Configuration

Create your authentication setup:

```typescript
// src/auth/guards.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';

// Define your user type
interface User {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
  sub: string;  // JWT subject
  exp: number;  // JWT expiration
}

// Create token verifier
const tokenVerifier: CustomTokenVerificationPort<User> = {
  async verifyToken(token: string): Promise<User> {
    // Replace with your JWT verification logic
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
    return {
      id: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      sub: payload.sub,
      exp: payload.exp
    };
  }
};

// Define permission source
const userPermissionSource = {
  async getUserPermissions(userId: string) {
    // Replace with your database logic
    const user = await db.users.findById(userId);
    return {
      permissions: user.permissions,
      roles: user.roles,
      metadata: { email: user.email }
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    // Replace with your role-to-permissions mapping
    const rolePerms = await db.roles.find({ name: { $in: roles } });
    return rolePerms.flatMap(role => role.permissions);
  },

  async isUserContextStale(): Promise<boolean> {
    return false; // Implement based on your needs
  }
};

// Configure RouteGuards
export const setupGuards = async () => {
  await RouteGuards.configure(
    GuardSetup.production(), // or .development() for dev
    userPermissionSource,
    tokenVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
    }
  );
};
```

### Step 3: Use in Handlers

```typescript
// src/handlers/user.handlers.ts
import { Handler, RouteGuards } from '@noony-serverless/core';

// Simple permission check
export const getUserProfile = new Handler<unknown, User>()
  .use(RouteGuards.requirePermissions(['user:read']))
  .handle(async (context) => {
    const user = context.user!; // Fully typed and authenticated
    return { profile: user };
  });

// Multiple permissions (OR logic)
export const manageUsers = new Handler<unknown, User>()
  .use(RouteGuards.requirePermissions(['user:admin', 'admin:users']))
  .handle(async (context) => {
    // User has either 'user:admin' OR 'admin:users'
    return { message: 'Access granted' };
  });
```

---

## Environment Configuration

### NEW: Cache Control with Environment Variables

By default, **caching is disabled** for security. Enable it explicitly:

```bash
# Development (cache disabled for debugging)
npm run dev

# Production (cache enabled for performance)
NOONY_GUARD_CACHE_ENABLE=true npm start
```

### Environment-Specific Setups

**Development:**
```bash
NODE_ENV=development npm run dev
# - Detailed logging
# - Fast iteration
# - Cache disabled by default
```

**Production:**
```bash
NODE_ENV=production NOONY_GUARD_CACHE_ENABLE=true npm start
# - Optimized performance
# - Conservative security
# - Cache enabled for speed
```

**Docker:**
```dockerfile
FROM node:18-alpine
# ... other setup ...
ENV NODE_ENV=production
ENV NOONY_GUARD_CACHE_ENABLE=true
CMD ["npm", "start"]
```

**Kubernetes:**
```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        - name: NODE_ENV
          value: "production"
        - name: NOONY_GUARD_CACHE_ENABLE
          value: "true"
```

---

## Simple Scenarios

### Authentication Only

For endpoints that just need to verify the user is logged in:

```typescript
// Just check if user is authenticated
const getProfile = new Handler<unknown, User>()
  .use(RouteGuards.requireAuth())
  .handle(async (context) => {
    const user = context.user!; // Guaranteed to exist
    return { id: user.id, email: user.email };
  });
```

### Basic CRUD Operations

```typescript
// READ - Basic permission
const getUsers = new Handler<unknown, User>()
  .use(RouteGuards.requirePermissions(['user:read']))
  .handle(async (context) => {
    const users = await userService.getAll();
    return { users };
  });

// CREATE - Single permission
const createUser = new Handler<CreateUserRequest, User>()
  .use(RouteGuards.requirePermissions(['user:create']))
  .handle(async (context) => {
    const userData = context.req.validatedBody!;
    const newUser = await userService.create(userData);
    return { user: newUser };
  });

// UPDATE - Multiple permissions (admin OR owner)
const updateUser = new Handler<UpdateUserRequest, User>()
  .use(RouteGuards.requirePermissions(['user:update', 'admin:users']))
  .handle(async (context) => {
    // Business logic here
    return { success: true };
  });

// DELETE - Admin only
const deleteUser = new Handler<DeleteUserRequest, User>()
  .use(RouteGuards.requirePermissions(['admin:users']))
  .handle(async (context) => {
    // Admin-only operation
    return { success: true };
  });
```

### Role-Based Access

```typescript
// Admin endpoints
const adminDashboard = new Handler<unknown, User>()
  .use(RouteGuards.requireWildcardPermissions(['admin.*']))
  .handle(async (context) => {
    // Matches: admin.users, admin.reports, admin.settings, etc.
    return { dashboard: 'admin_data' };
  });

// Department-specific access
const departmentReports = new Handler<unknown, User>()
  .use(RouteGuards.requireWildcardPermissions(['reports.finance.*', 'reports.hr.*']))
  .handle(async (context) => {
    // User has access to finance OR hr reports
    return { reports: [] };
  });
```

---

## Complex Scenarios

### Multi-Tenant Systems

```typescript
interface TenantUser extends User {
  tenantId: string;
  tenantRole: string;
}

// Tenant-aware permission checking
const getTenantData = new Handler<TenantRequest, TenantUser>()
  .use(RouteGuards.requirePermissions(['tenant:read']))
  .handle(async (context) => {
    const user = context.user!;
    const requestedTenantId = context.req.params.tenantId;
    
    // Additional business logic for tenant isolation
    if (user.tenantId !== requestedTenantId && !user.permissions.includes('super:admin')) {
      throw new SecurityError('Access denied to tenant data');
    }
    
    return { data: await getTenantSpecificData(requestedTenantId) };
  });
```

### Complex Business Rules

```typescript
// Complex permission expressions
const sensitiveOperation = new Handler<unknown, User>()
  .use(RouteGuards.requireComplexPermissions({
    and: [
      { permission: 'finance:read' },
      { not: { permission: 'finance:restricted' } }, // Must NOT have this
      { or: [
        { permission: 'manager:approve' },
        { permission: 'admin:override' }
      ]}
    ]
  }))
  .handle(async (context) => {
    // Complex business rule satisfied
    // User has finance:read AND NOT finance:restricted 
    // AND (manager:approve OR admin:override)
    return { access: 'granted' };
  });
```

### Dynamic Permission Loading

```typescript
// Custom permission source with caching
const dynamicPermissionSource = {
  async getUserPermissions(userId: string) {
    // Load from multiple sources
    const [userPerms, rolePerms, groupPerms] = await Promise.all([
      db.userPermissions.find({ userId }),
      db.rolePermissions.find({ userId }),
      db.groupPermissions.find({ userId })
    ]);
    
    return {
      permissions: [
        ...userPerms.map(p => p.permission),
        ...rolePerms.map(p => p.permission),
        ...groupPerms.map(p => p.permission)
      ],
      roles: rolePerms.map(r => r.role),
      metadata: {
        lastLogin: userPerms[0]?.lastLogin,
        groups: groupPerms.map(g => g.groupId)
      }
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    const roleDefinitions = await db.roles.find({ 
      name: { $in: roles } 
    });
    return roleDefinitions.flatMap(role => role.permissions);
  },

  async isUserContextStale(userId: string, lastUpdated: string): Promise<boolean> {
    const user = await db.users.findById(userId);
    return user ? new Date(user.updatedAt) > new Date(lastUpdated) : true;
  }
};
```

### Performance Optimization

```typescript
// Batch permission checks for efficiency
const batchOperations = new Handler<BatchRequest, User>()
  .use(RouteGuards.requirePermissions(['batch:process']))
  .handle(async (context) => {
    const requests = context.req.validatedBody!.requests;
    
    // Batch check permissions for multiple operations
    const permissionChecks = requests.map(req => ({
      requirement: req.requiredPermission,
      resolverType: PermissionResolverType.PLAIN
    }));
    
    const results = await RouteGuards.getInstance()
      .getUserContextService()
      .checkPermissions(context.user!.id, permissionChecks);
    
    // Process only allowed operations
    const allowedOperations = requests.filter((_, index) => results[index].allowed);
    
    return { processed: allowedOperations.length };
  });
```

---

## Practical FAQ

### "How do I debug permission issues?"

**1. Disable caching for debugging:**
```bash
# Run without cache to see real-time permission changes
npm run dev  # Cache is disabled by default
```

**2. Enable detailed logging:**
```typescript
// Use development setup for detailed logs
await RouteGuards.configure(
  GuardSetup.development(), // Enables detailed logging
  userPermissionSource,
  tokenVerifier,
  authConfig
);
```

**3. Check user permissions:**
```typescript
// In your handler, log the user's actual permissions
.handle(async (context) => {
  console.log('User permissions:', context.user!.permissions);
  console.log('User roles:', context.user!.roles);
  // ... rest of handler
});
```

### "How do I handle authentication errors?"

```typescript
import { ErrorHandlerMiddleware } from '@noony-serverless/core';

const secureHandler = new Handler<unknown, User>()
  .use(new ErrorHandlerMiddleware()) // Always add error handling first
  .use(RouteGuards.requirePermissions(['secure:access']))
  .handle(async (context) => {
    // Your secure logic here
  });

// Errors are automatically formatted as:
// 401 Unauthorized - Authentication failed
// 403 Forbidden - Permission denied
```

### "How do I migrate from custom auth?"

**Gradual Migration Approach:**

```typescript
// 1. Start with new endpoints
const newEndpoint = new Handler()
  .use(RouteGuards.requirePermissions(['new:feature']))
  .handle(newLogic);

// 2. Create bridge for existing auth
const bridgeTokenVerifier: CustomTokenVerificationPort<User> = {
  async verifyToken(token: string): Promise<User> {
    // Use your existing auth validation
    return await yourExistingAuthSystem.validateToken(token);
  }
};

// 3. Gradually replace middleware in existing handlers
const existingEndpoint = new Handler()
  .use(RouteGuards.requirePermissions(['existing:permission'])) // New
  // .use(yourOldAuthMiddleware) // Remove this
  .handle(existingLogic);
```

### "How do I test with RouteGuards?"

```typescript
// Testing with mock permissions
const testSetup = async () => {
  const mockPermissionSource = {
    async getUserPermissions(userId: string) {
      // Return test permissions based on userId
      const testUsers = {
        'user1': { permissions: ['user:read'], roles: ['user'] },
        'admin1': { permissions: ['admin:all'], roles: ['admin'] }
      };
      return testUsers[userId] || { permissions: [], roles: [] };
    },
    async getRolePermissions(): Promise<string[]> { return []; },
    async isUserContextStale(): Promise<boolean> { return false; }
  };

  await RouteGuards.configure(
    GuardSetup.testing(), // Uses cacheType: 'none' for predictable tests
    mockPermissionSource,
    mockTokenVerifier,
    testAuthConfig
  );
};
```

### "How do I handle different permission models?"

**Hierarchical Permissions:**
```typescript
// Use wildcards for hierarchy
RouteGuards.requireWildcardPermissions(['admin.users.*'])
// Matches: admin.users.read, admin.users.write, admin.users.delete
```

**Flat Permission Lists:**
```typescript
// Use plain permissions for simple lists
RouteGuards.requirePermissions(['read_users', 'write_users'])
// Exact string matching
```

**Complex Business Rules:**
```typescript
// Use expressions for complex logic
RouteGuards.requireComplexPermissions({
  and: [
    { permission: 'document:read' },
    { or: [
      { permission: 'department:hr' },
      { permission: 'role:manager' }
    ]}
  ]
})
```

### "How do I monitor performance?"

```typescript
// Get system statistics
const checkPerformance = () => {
  const stats = RouteGuards.getSystemStats();
  
  console.log('Cache Performance:', {
    hitRate: stats.systemHealth.cacheEfficiency,
    avgResponseTime: stats.systemHealth.averageResponseTime,
    totalChecks: stats.systemHealth.totalGuardChecks
  });
  
  // Alert if performance degrades
  if (stats.systemHealth.cacheEfficiency < 90) {
    console.warn('Low cache efficiency detected');
  }
  
  if (stats.systemHealth.averageResponseTime > 10) {
    console.warn('Slow permission checks detected');
  }
};

// Check every minute
setInterval(checkPerformance, 60000);
```

### "Common Error Messages and Solutions"

**❌ "RouteGuards not configured"**
```typescript
// ✅ Solution: Call configure before using guards
await RouteGuards.configure(/* ... */);
```

**❌ "Authentication failed"**
```bash
# ✅ Check your token format and JWT secret
curl -H "Authorization: Bearer your-jwt-token" http://localhost:3000/api/protected
```

**❌ "Permission denied"**
```typescript
// ✅ Check user's actual permissions
console.log('User permissions:', context.user!.permissions);
console.log('Required permissions:', ['your:permission']);
```

**❌ "Cache hit rate too low"**
```bash
# ✅ Enable caching for better performance
NOONY_GUARD_CACHE_ENABLE=true npm start
```

---

## Next Steps

1. **Production Setup**: Enable caching with `NOONY_GUARD_CACHE_ENABLE=true`
2. **Monitoring**: Set up performance monitoring with `getSystemStats()`
3. **Advanced Features**: Explore complex permissions and multi-tenant patterns
4. **Comprehensive Guide**: Check [RouteGuards-Complete-Guide.md](./RouteGuards-Complete-Guide.md) for in-depth analysis

For more examples, see the [examples directory](../examples/) with working implementations.