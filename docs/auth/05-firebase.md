# Firebase Authentication with Noony Guards

Complete guide for integrating Firebase Authentication with Noony's Guard System for authentication and permission-based access control.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Complete Setup](#complete-setup)
- [Firestore Data Structure](#firestore-data-structure)
- [Advanced Usage](#advanced-usage)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Overview

Noony's Guard System provides a high-performance, production-ready authentication and authorization layer that integrates seamlessly with Firebase Authentication. Key features include:

- **Sub-millisecond permission checks** with intelligent caching
- **Firebase ID token validation** with automatic key rotation
- **Role-based access control (RBAC)** with Firestore integration
- **Department-based permissions** for organization hierarchies
- **Wildcard permission matching** for flexible access control
- **Permission expressions** for complex authorization logic
- **Comprehensive audit logging** and security monitoring

## Prerequisites

- Node.js 18+ and npm
- Firebase project with Authentication enabled
- Firebase Admin SDK service account
- Firestore database for storing user permissions
- `@noony-serverless/core` package installed

## Installation

```bash
# Install required dependencies
npm install firebase-admin @noony-serverless/core

# Optional: Install Zod for request validation
npm install zod
```

## Quick Start

### 1. Environment Configuration

Create a `.env` file with your Firebase credentials:

```bash
# Firebase Configuration
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# Authentication Settings
REQUIRE_EMAIL_VERIFIED=true
NODE_ENV=production

# Guard System Settings (optional)
NOONY_GUARD_CACHE_ENABLE=true
```

### 2. Initialize Firebase Admin

```typescript
// src/config/firebase.config.ts
import * as admin from 'firebase-admin';

// Initialize Firebase Admin SDK (one-time setup)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

export const firebaseAuth = admin.auth();
export const firestore = admin.firestore();
```

### 3. Create Protected Endpoint

```typescript
// src/handlers/user.handler.ts
import { Handler } from '@noony-serverless/core';
import { routeGuards } from '../config/guard.config';

export const getUserHandler = new Handler()
  // Require Firebase authentication
  .use(routeGuards.requireAuth())
  // Require permission
  .use(routeGuards.requirePermission('users.read'))
  .handle(async (context) => {
    // context.user contains authenticated Firebase user
    const userId = context.req.params?.userId;
    const user = await userService.getById(userId);

    context.res.status(200).json({
      success: true,
      data: user,
    });
  });
```

### 4. Deploy to Cloud Functions

```typescript
// src/index.ts
import { http } from '@google-cloud/functions-framework';
import { getUserHandler } from './handlers/user.handler';

export const getUser = http('getUser', (req, res) => {
  return getUserHandler.execute(req, res);
});
```

## Complete Setup

### Step 1: Firebase Token Validator

Create a token validator that integrates with Firebase Admin SDK:

```typescript
// src/auth/firebase-token-validator.ts
import { auth } from 'firebase-admin';
import { TokenValidator } from '@noony-serverless/core';

export interface FirebaseTokenValidatorConfig {
  requireEmailVerified: boolean;
  enableCaching: boolean;
  cacheTTL: number;
  clockTolerance?: number;
}

export class FirebaseTokenValidator implements TokenValidator {
  private readonly firebaseAuth: auth.Auth;
  private readonly config: FirebaseTokenValidatorConfig;
  private cache = new Map<string, { result: any; expiry: number }>();

  constructor(firebaseAuth: auth.Auth, config: FirebaseTokenValidatorConfig) {
    this.firebaseAuth = firebaseAuth;
    this.config = {
      clockTolerance: 30, // 30 seconds default
      ...config,
    };
  }

  /**
   * Validate Firebase ID token
   */
  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }> {
    try {
      // Check cache first
      if (this.config.enableCaching) {
        const cached = this.getCachedResult(token);
        if (cached) return cached;
      }

      // Verify Firebase ID token (checkRevoked: true ensures revoked tokens fail)
      const decodedToken = await this.firebaseAuth.verifyIdToken(token, true);

      // Fetch user record for additional validation
      const userRecord = await this.firebaseAuth.getUser(decodedToken.uid);

      // Validate user account
      if (userRecord.disabled) {
        throw new Error('User account is disabled');
      }

      if (this.config.requireEmailVerified && !userRecord.emailVerified) {
        throw new Error('Email not verified');
      }

      const result = {
        valid: true,
        decoded: {
          ...decodedToken,
          sub: decodedToken.uid,
          email: decodedToken.email,
          name: decodedToken.name || userRecord.displayName,
          email_verified: userRecord.emailVerified,
          // Include custom claims
          ...userRecord.customClaims,
        },
      };

      // Cache successful result
      if (this.config.enableCaching) {
        this.setCachedResult(token, result);
      }

      return result;
    } catch (error: any) {
      return {
        valid: false,
        error: this.extractFirebaseError(error),
      };
    }
  }

  /**
   * Extract user ID from decoded Firebase token
   */
  extractUserId(decoded: any): string {
    return decoded.sub || decoded.uid || '';
  }

  /**
   * Check if Firebase token is expired
   */
  isTokenExpired(decoded: any): boolean {
    const now = Math.floor(Date.now() / 1000);
    return decoded.exp ? decoded.exp <= now : false;
  }

  private extractFirebaseError(error: any): string {
    const errorMap: Record<string, string> = {
      'auth/id-token-expired': 'Firebase ID token has expired',
      'auth/id-token-revoked': 'Firebase ID token has been revoked',
      'auth/invalid-id-token': 'Invalid Firebase ID token',
      'auth/user-not-found': 'Firebase user not found',
      'auth/user-disabled': 'User account is disabled',
      'auth/argument-error': 'Invalid token format',
    };

    return errorMap[error.code] || error.message || 'Firebase token validation failed';
  }

  private getCachedResult(token: string): any | null {
    const key = this.getCacheKey(token);
    const entry = this.cache.get(key);
    if (entry && Date.now() < entry.expiry) {
      return { ...entry.result, metadata: { ...entry.result.metadata, cached: true } };
    }
    if (entry) this.cache.delete(key);
    return null;
  }

  private setCachedResult(token: string, result: any): void {
    const key = this.getCacheKey(token);
    const ttl = this.getCacheTTL(result.decoded);
    this.cache.set(key, {
      result,
      expiry: Date.now() + ttl,
    });

    // Periodic cleanup to prevent memory leaks
    if (this.cache.size > 1000) {
      this.cleanupCache();
    }
  }

  private getCacheKey(token: string): string {
    return token.length > 16
      ? `${token.substring(0, 8)}...${token.substring(token.length - 8)}`
      : token;
  }

  private getCacheTTL(decoded?: any): number {
    if (!decoded?.exp) {
      return this.config.cacheTTL;
    }

    // Cache until halfway to token expiration
    const now = Math.floor(Date.now() / 1000);
    const timeToExpiry = decoded.exp - now;
    const cacheDuration = Math.floor(timeToExpiry / 2);

    // Ensure cache duration is between 1 minute and 30 minutes
    return Math.max(60 * 1000, Math.min(cacheDuration * 1000, 30 * 60 * 1000));
  }

  private cleanupCache(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiry) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.debug(`🧹 Firebase cache cleanup: removed ${cleaned} expired entries`);
    }
  }

  public clearCache(): void {
    this.cache.clear();
  }

  public getCacheSize(): number {
    return this.cache.size;
  }
}
```

### Step 2: Firestore Permission Source

Create a permission source that fetches permissions from Firestore:

```typescript
// src/permissions/firestore-permission-source.ts
import { firestore } from '../config/firebase.config';
import { UserPermissionSource } from '@noony-serverless/core';

export class FirestorePermissionSource implements UserPermissionSource {
  /**
   * Fetch user permissions from Firestore
   * Aggregates permissions from:
   * 1. Direct user permissions
   * 2. Role-based permissions
   * 3. Department-based permissions
   */
  async getUserPermissions(userId: string): Promise<string[]> {
    try {
      // Fetch user document from Firestore
      const userDoc = await firestore.collection('users').doc(userId).get();

      if (!userDoc.exists) {
        console.warn(`⚠️ User ${userId} not found in Firestore`);
        return [];
      }

      const userData = userDoc.data();
      const permissions: Set<string> = new Set();

      // 1. Direct permissions
      if (Array.isArray(userData?.permissions)) {
        userData.permissions.forEach((p: string) => permissions.add(p));
      }

      // 2. Role-based permissions
      if (Array.isArray(userData?.roles)) {
        for (const role of userData.roles) {
          const rolePermissions = await this.getRolePermissions(role);
          rolePermissions.forEach((p) => permissions.add(p));
        }
      }

      // 3. Department-based permissions
      if (userData?.department) {
        const deptPermissions = await this.getDepartmentPermissions(
          userData.department
        );
        deptPermissions.forEach((p) => permissions.add(p));
      }

      // 4. Team-based permissions (optional)
      if (Array.isArray(userData?.teams)) {
        for (const team of userData.teams) {
          const teamPermissions = await this.getTeamPermissions(team);
          teamPermissions.forEach((p) => permissions.add(p));
        }
      }

      console.log(`✅ Loaded ${permissions.size} permissions for user ${userId}`);
      return Array.from(permissions);
    } catch (error) {
      console.error(`❌ Error fetching permissions for user ${userId}:`, error);
      return [];
    }
  }

  /**
   * Fetch permissions for a given role
   */
  private async getRolePermissions(role: string): Promise<string[]> {
    try {
      const roleDoc = await firestore.collection('roles').doc(role).get();

      if (!roleDoc.exists) {
        console.warn(`⚠️ Role ${role} not found`);
        return [];
      }

      const roleData = roleDoc.data();
      return Array.isArray(roleData?.permissions) ? roleData.permissions : [];
    } catch (error) {
      console.error(`❌ Error fetching role ${role} permissions:`, error);
      return [];
    }
  }

  /**
   * Fetch permissions for a given department
   */
  private async getDepartmentPermissions(department: string): Promise<string[]> {
    try {
      const deptDoc = await firestore
        .collection('departments')
        .doc(department)
        .get();

      if (!deptDoc.exists) {
        console.warn(`⚠️ Department ${department} not found`);
        return [];
      }

      const deptData = deptDoc.data();
      return Array.isArray(deptData?.permissions) ? deptData.permissions : [];
    } catch (error) {
      console.error(
        `❌ Error fetching department ${department} permissions:`,
        error
      );
      return [];
    }
  }

  /**
   * Fetch permissions for a given team (optional)
   */
  private async getTeamPermissions(team: string): Promise<string[]> {
    try {
      const teamDoc = await firestore.collection('teams').doc(team).get();

      if (!teamDoc.exists) {
        return [];
      }

      const teamData = teamDoc.data();
      return Array.isArray(teamData?.permissions) ? teamData.permissions : [];
    } catch (error) {
      console.error(`❌ Error fetching team ${team} permissions:`, error);
      return [];
    }
  }

  /**
   * Invalidate cached permissions for a user
   * Call this when user permissions change
   */
  async invalidateUserPermissions(userId: string): Promise<void> {
    console.log(`🔄 Invalidating permissions cache for user ${userId}`);
    // The Guard System will handle cache invalidation
  }
}
```

### Step 3: Configure Noony Guards

```typescript
// src/config/guard.config.ts
import {
  GuardSetup,
  RouteGuards,
  PermissionResolutionStrategy,
} from '@noony-serverless/core';
import { firebaseAuth } from './firebase.config';
import { FirebaseTokenValidator } from '../auth/firebase-token-validator';
import { FirestorePermissionSource } from '../permissions/firestore-permission-source';

// Initialize Firebase token validator
const tokenValidator = new FirebaseTokenValidator(firebaseAuth, {
  requireEmailVerified: process.env.REQUIRE_EMAIL_VERIFIED === 'true',
  enableCaching: true,
  cacheTTL: 5 * 60 * 1000, // 5 minutes
  clockTolerance: 30, // 30 seconds
});

// Initialize permission source
const permissionSource = new FirestorePermissionSource();

// Configure guards based on environment
const guardProfile =
  process.env.NODE_ENV === 'production'
    ? GuardSetup.production()
    : process.env.NODE_ENV === 'development'
      ? GuardSetup.development()
      : GuardSetup.serverless();

// Create RouteGuards instance
export const routeGuards = new RouteGuards({
  environment: guardProfile.environment,
  cacheType: guardProfile.cacheType,
  security: {
    ...guardProfile.security,
    permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
    conservativeCacheInvalidation: true, // Always invalidate on security events
  },
  cache: {
    ...guardProfile.cache,
    // Adjust cache TTLs for production
    userContextTtlMs: process.env.NODE_ENV === 'production' ? 10 * 60 * 1000 : 2 * 60 * 1000,
    authTokenTtlMs: process.env.NODE_ENV === 'production' ? 5 * 60 * 1000 : 2 * 60 * 1000,
  },
  monitoring: {
    ...guardProfile.monitoring,
    enablePerformanceTracking: true,
    enableDetailedLogging: process.env.NODE_ENV !== 'production',
  },
});

// Initialize guards with Firebase
routeGuards.initialize({
  tokenValidator,
  permissionSource,
  authConfig: {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFIED === 'true',
    allowInactiveUsers: false,
  },
});

console.log(`🛡️ RouteGuards initialized for ${guardProfile.environment} environment`);

export { tokenValidator, permissionSource };
```

### Step 4: Create Protected Handlers

```typescript
// src/handlers/user.handlers.ts
import { Handler, Context } from '@noony-serverless/core';
import { routeGuards } from '../config/guard.config';
import { z } from 'zod';
import { BodyValidationMiddleware } from '@noony-serverless/core';

// ============================================================================
// REQUEST SCHEMAS
// ============================================================================

const createUserSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email(),
  department: z.string(),
  role: z.enum(['user', 'admin', 'manager']).default('user'),
});

const updateUserSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  department: z.string().optional(),
  role: z.enum(['user', 'admin', 'manager']).optional(),
});

type CreateUserRequest = z.infer<typeof createUserSchema>;
type UpdateUserRequest = z.infer<typeof updateUserSchema>;

// ============================================================================
// HANDLER: CREATE USER
// ============================================================================

/**
 * Create a new user
 * Requires: Authentication + "users.create" permission
 */
export const createUserHandler = new Handler<CreateUserRequest>()
  // 1. Authenticate with Firebase
  .use(
    routeGuards.requireAuth({
      extractToken: (context) => {
        const authHeader = context.req.headers?.authorization;
        return authHeader?.replace('Bearer ', '') || null;
      },
    })
  )
  // 2. Check permission
  .use(routeGuards.requirePermission('users.create'))
  // 3. Validate request body
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context: Context<CreateUserRequest>) => {
    // context.user is now populated with Firebase user data
    const authenticatedUser = context.user!;
    const requestData = context.req.validatedBody!;

    console.log(`👤 User ${authenticatedUser.email} creating new user: ${requestData.email}`);

    // Your business logic here
    const newUser = await userService.create({
      ...requestData,
      createdBy: authenticatedUser.sub,
      createdAt: new Date(),
    });

    context.res.status(201).json({
      success: true,
      data: newUser,
    });
  });

// ============================================================================
// HANDLER: GET USER
// ============================================================================

/**
 * Get user by ID
 * Requires: Authentication + "users.read" OR "users.manage" permission
 */
export const getUserHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requireAnyPermission(['users.read', 'users.manage']))
  .handle(async (context) => {
    const userId = context.req.params?.userId;

    if (!userId) {
      context.res.status(400).json({
        success: false,
        error: 'User ID is required',
      });
      return;
    }

    const user = await userService.getById(userId);

    if (!user) {
      context.res.status(404).json({
        success: false,
        error: 'User not found',
      });
      return;
    }

    context.res.status(200).json({
      success: true,
      data: user,
    });
  });

// ============================================================================
// HANDLER: UPDATE USER
// ============================================================================

/**
 * Update user
 * Requires: Authentication + "users.update" permission
 */
export const updateUserHandler = new Handler<UpdateUserRequest>()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users.update'))
  .use(new BodyValidationMiddleware(updateUserSchema))
  .handle(async (context: Context<UpdateUserRequest>) => {
    const userId = context.req.params?.userId;
    const updates = context.req.validatedBody!;

    const updatedUser = await userService.update(userId, updates);

    context.res.status(200).json({
      success: true,
      data: updatedUser,
    });
  });

// ============================================================================
// HANDLER: DELETE USER
// ============================================================================

/**
 * Delete user
 * Requires: Authentication + BOTH "users.delete" AND "users.manage" permissions
 */
export const deleteUserHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requireAllPermissions(['users.delete', 'users.manage']))
  .handle(async (context) => {
    const userId = context.req.params?.userId;
    const authenticatedUser = context.user!;

    // Prevent self-deletion
    if (userId === authenticatedUser.sub) {
      context.res.status(400).json({
        success: false,
        error: 'Cannot delete your own account',
      });
      return;
    }

    await userService.delete(userId);

    context.res.status(200).json({
      success: true,
      message: 'User deleted successfully',
    });
  });

// ============================================================================
// HANDLER: LIST USERS
// ============================================================================

/**
 * List all users
 * Requires: Authentication + wildcard "users.*" permission
 */
export const listUsersHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users.*'))
  .handle(async (context) => {
    const page = parseInt(context.req.query?.page as string) || 1;
    const limit = parseInt(context.req.query?.limit as string) || 20;

    const result = await userService.list({ page, limit });

    context.res.status(200).json({
      success: true,
      data: result.users,
      pagination: {
        page,
        limit,
        total: result.total,
        totalPages: Math.ceil(result.total / limit),
      },
    });
  });

// ============================================================================
// HANDLER: ADMIN DASHBOARD
// ============================================================================

/**
 * Admin dashboard access
 * Requires: Complex permission expression
 */
export const adminDashboardHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(
    routeGuards.requirePermission({
      expression: 'admin.* AND (users.manage OR roles.manage)',
    })
  )
  .handle(async (context) => {
    const stats = await adminService.getDashboardStats();

    context.res.status(200).json({
      success: true,
      data: stats,
    });
  });
```

## Firestore Data Structure

Set up your Firestore collections with the following structure:

### Users Collection

```typescript
// Collection: users/{userId}
{
  // Basic Info
  email: "john.doe@company.com",
  name: "John Doe",
  displayName: "John D.",
  photoURL: "https://...",

  // Organization
  department: "engineering",
  team: "backend",
  title: "Senior Developer",

  // Access Control
  roles: ["developer", "reviewer"],           // Role assignments
  permissions: ["projects.read", "code.write"], // Direct permissions
  teams: ["backend-team", "platform-team"],   // Team memberships (optional)

  // Status
  status: "active",                           // active | inactive | suspended
  emailVerified: true,

  // Timestamps
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lastLoginAt: Timestamp,

  // Metadata
  metadata: {
    onboardingComplete: true,
    preferences: {},
    customFields: {}
  }
}
```

### Roles Collection

```typescript
// Collection: roles/{roleId}
{
  name: "developer",
  displayName: "Software Developer",
  description: "Standard software developer permissions",

  permissions: [
    "code.read",
    "code.write",
    "projects.read",
    "pull-requests.create",
    "pull-requests.review",
    "issues.create",
    "issues.update"
  ],

  // Hierarchy
  inheritsFrom: ["base-user"],  // Role inheritance (optional)

  // Metadata
  createdAt: Timestamp,
  updatedAt: Timestamp,
  createdBy: "admin-user-id"
}
```

### Departments Collection

```typescript
// Collection: departments/{departmentId}
{
  name: "engineering",
  displayName: "Engineering Department",
  description: "Engineering team",

  // Department-wide permissions
  permissions: [
    "tools.read",
    "resources.read",
    "documentation.read"
  ],

  // Hierarchy
  parentDepartment: null,  // For nested departments

  // Metadata
  manager: "user-id",
  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

### Teams Collection (Optional)

```typescript
// Collection: teams/{teamId}
{
  name: "backend-team",
  displayName: "Backend Engineering Team",
  description: "Backend services team",
  department: "engineering",

  // Team-specific permissions
  permissions: [
    "backend.*",
    "services.deploy",
    "databases.read"
  ],

  // Team members
  members: ["user-id-1", "user-id-2"],
  lead: "user-id-1",

  createdAt: Timestamp,
  updatedAt: Timestamp
}
```

### Permission Naming Convention

Use a hierarchical dot-notation for permissions:

```typescript
// Resource-based permissions
"users.read"       // Read user data
"users.create"     // Create new users
"users.update"     // Update existing users
"users.delete"     // Delete users
"users.manage"     // Full user management
"users.*"          // All user permissions (wildcard)

// Feature-based permissions
"admin.dashboard"  // Access admin dashboard
"admin.settings"   // Modify system settings
"admin.*"          // All admin permissions

// Action-based permissions
"code.read"        // Read code
"code.write"       // Write code
"code.approve"     // Approve code changes

// Complex hierarchies
"projects.team-a.read"     // Read team-a projects
"projects.team-a.write"    // Write to team-a projects
"projects.*.read"          // Read all team projects
```

## Advanced Usage

### Custom Permission Expressions

```typescript
// Complex AND/OR logic
export const superAdminHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(
    routeGuards.requirePermission({
      expression: '(admin.* OR superuser.*) AND settings.modify',
    })
  )
  .handle(async (context) => {
    // Only users with (admin.* OR superuser.*) AND settings.modify
    context.res.json({ message: 'Super admin access granted' });
  });

// Nested expressions
export const criticalOperationHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(
    routeGuards.requirePermission({
      expression: 'admin.* AND (users.delete OR roles.delete) AND security.approve',
    })
  )
  .handle(async (context) => {
    // Requires all three conditions
    context.res.json({ message: 'Critical operation authorized' });
  });
```

### Dynamic Permission Checks

```typescript
export const resourceAccessHandler = new Handler()
  .use(routeGuards.requireAuth())
  .handle(async (context) => {
    const resourceId = context.req.params?.resourceId;
    const resource = await resourceService.getById(resourceId);

    // Dynamic permission based on resource type
    const requiredPermission = `${resource.type}.read`;

    // Manual permission check
    const hasPermission = await routeGuards.checkPermission(
      context,
      requiredPermission
    );

    if (!hasPermission) {
      context.res.status(403).json({
        success: false,
        error: `Missing required permission: ${requiredPermission}`,
      });
      return;
    }

    context.res.status(200).json({
      success: true,
      data: resource,
    });
  });
```

### Middleware Stacking

```typescript
// Combine multiple permission checks
export const complexHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('base.access'))
  .use(routeGuards.requireAnyPermission(['admin.*', 'manager.*']))
  .use(routeGuards.requireAllPermissions(['reports.read', 'analytics.access']))
  .handle(async (context) => {
    // User must pass ALL permission checks above
    context.res.json({ message: 'All checks passed' });
  });
```

### Cache Invalidation

```typescript
// Invalidate user permissions after role change
export const updateUserRoleHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users.manage'))
  .handle(async (context) => {
    const userId = context.req.params?.userId;
    const newRole = context.req.body?.role;

    // Update role in Firestore
    await userService.updateRole(userId, newRole);

    // Invalidate permissions cache
    await routeGuards.invalidateUserContext(userId);

    context.res.status(200).json({
      success: true,
      message: 'Role updated and cache invalidated',
    });
  });
```

### Performance Monitoring

```typescript
export const monitoredHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users.read'))
  .handle(async (context) => {
    // Get guard system statistics
    const stats = routeGuards.getStats();

    console.log('Guard System Performance:', {
      authAttempts: stats.authAttempts,
      successRate: stats.successRate,
      cacheHitRate: stats.cacheHitRate,
      avgResolutionTime: `${stats.averageResolutionTimeUs}μs`,
    });

    context.res.json({ success: true });
  });
```

## Production Deployment

### Security Best Practices

1. **Enable Email Verification**

```bash
REQUIRE_EMAIL_VERIFIED=true
```

2. **Use Environment-Specific Configurations**

```typescript
// Different settings per environment
const guardProfile =
  process.env.NODE_ENV === 'production'
    ? GuardSetup.production()
    : process.env.NODE_ENV === 'staging'
      ? GuardSetup.serverless()
      : GuardSetup.development();
```

3. **Enable Conservative Cache Invalidation**

```typescript
security: {
  conservativeCacheInvalidation: true,  // Always invalidate on security events
  permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
}
```

4. **Monitor Security Events**

```typescript
// Log all authentication failures
routeGuards.onAuthenticationFailure((event) => {
  console.warn('🚨 Authentication failure:', {
    userId: event.userId,
    reason: event.reason,
    ip: event.clientIp,
    timestamp: event.timestamp,
  });

  // Optionally send to monitoring service
  securityMonitor.logFailure(event);
});
```

5. **Rate Limiting** (optional)

```typescript
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many authentication attempts, please try again later',
});

app.use('/api/', authLimiter);
```

### Cloud Functions Deployment

```bash
# Deploy individual function
gcloud functions deploy createUser \
  --runtime nodejs20 \
  --trigger-http \
  --entry-point createUser \
  --allow-unauthenticated \
  --set-env-vars FIREBASE_PROJECT_ID=your-project-id \
  --set-env-vars REQUIRE_EMAIL_VERIFIED=true \
  --set-env-vars NOONY_GUARD_CACHE_ENABLE=true

# Deploy all functions
gcloud functions deploy --config functions.yaml
```

### Cloud Run Deployment

```dockerfile
# Dockerfile
FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source
COPY . .

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 8080

# Start server
CMD ["npm", "start"]
```

```bash
# Deploy to Cloud Run
gcloud run deploy noony-api \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars FIREBASE_PROJECT_ID=your-project-id \
  --set-env-vars REQUIRE_EMAIL_VERIFIED=true \
  --set-env-vars NOONY_GUARD_CACHE_ENABLE=true
```

## Troubleshooting

### Common Issues

#### 1. "Firebase ID token has expired"

**Cause**: Token expired on client side.

**Solution**: Implement token refresh logic in your frontend:

```typescript
// Frontend: Auto-refresh Firebase tokens
firebase.auth().onAuthStateChanged(async (user) => {
  if (user) {
    // Refresh token every 55 minutes (tokens expire after 1 hour)
    setInterval(async () => {
      const token = await user.getIdToken(true); // Force refresh
      // Update your auth header
    }, 55 * 60 * 1000);
  }
});
```

#### 2. "User account is disabled"

**Cause**: User account disabled in Firebase Console.

**Solution**: Re-enable user in Firebase Console or via Admin SDK:

```typescript
await firebaseAuth.updateUser(userId, { disabled: false });
```

#### 3. "Email not verified"

**Cause**: `REQUIRE_EMAIL_VERIFIED=true` but user email not verified.

**Solution**: Send verification email or set `REQUIRE_EMAIL_VERIFIED=false`:

```typescript
await firebaseAuth.generateEmailVerificationLink(email);
```

#### 4. "Permission denied: users.create"

**Cause**: User doesn't have required permission.

**Solution**: Add permission to user's Firestore document:

```typescript
await firestore.collection('users').doc(userId).update({
  permissions: admin.firestore.FieldValue.arrayUnion('users.create'),
});

// Then invalidate cache
await routeGuards.invalidateUserContext(userId);
```

#### 5. Slow permission checks

**Cause**: Cache disabled or not warmed up.

**Solution**: Enable caching and pre-load permissions:

```bash
# Enable caching
NOONY_GUARD_CACHE_ENABLE=true
```

```typescript
// Pre-warm cache for common users
await routeGuards.preloadUserContext(userId);
```

### Debug Mode

Enable detailed logging for troubleshooting:

```typescript
// Enable debug logging
const routeGuards = new RouteGuards({
  // ... other config
  monitoring: {
    enablePerformanceTracking: true,
    enableDetailedLogging: true,
    logLevel: 'debug',
  },
});
```

### Performance Tuning

Monitor and optimize permission checks:

```typescript
// Get performance statistics
const stats = routeGuards.getStats();

console.log('Performance Stats:', {
  cacheHitRate: `${stats.cacheHitRate.toFixed(2)}%`,
  avgResolutionTime: `${stats.averageResolutionTimeUs.toFixed(1)}μs`,
  cachedChecks: stats.cacheHits,
  uncachedChecks: stats.cacheMisses,
});

// If cache hit rate < 80%, consider:
// 1. Increasing cache TTL
// 2. Pre-loading common users
// 3. Checking cache configuration
```

## Additional Resources

- [Noony Guard System Architecture](./GUARD_SYSTEM.md)
- [Firebase Admin SDK Documentation](https://firebase.google.com/docs/admin/setup)
- [Complete Example: Guard System Showcase](../examples/guard-system-showcase/)
- [OpenTelemetry Integration](./OTEL_NOONY.md)

## Support

For issues or questions:

- GitHub Issues: [noony-core/issues](https://github.com/noony-serverless/noony-core/issues)
- Documentation: [noony-core/docs](https://github.com/noony-serverless/noony-core/tree/main/docs)
- Examples: [noony-core/examples](https://github.com/noony-serverless/noony-core/tree/main/examples)
