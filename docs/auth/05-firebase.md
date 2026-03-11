# How to Authenticate with Firebase

This guide shows how to validate Firebase ID tokens using the Firebase Admin SDK and load permissions from Firestore. At the end you will have a handler that requires a valid Firebase token and a named permission.

## Prerequisites

- Firebase project with Authentication enabled
- Firebase Admin SDK service account JSON (for local development) or Application Default Credentials (for GCP)
- Firestore database with a `users` collection that stores permissions per user

## Step 1: Install Dependencies

```bash
npm install firebase-admin @noony-serverless/core
```

## Step 2: Create FirebaseTokenValidator

The validator calls `firebaseAuth.verifyIdToken` with `checkRevoked: true`, fetches the user record for status checks, and caches the result until halfway to token expiry.

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
    this.config = { clockTolerance: 30, ...config };
  }

  async validateToken(token: string): Promise<{ valid: boolean; decoded?: any; error?: string }> {
    try {
      if (this.config.enableCaching) {
        const cached = this.getCachedResult(token);
        if (cached) return cached;
      }

      // checkRevoked: true ensures revoked tokens are rejected immediately
      const decodedToken = await this.firebaseAuth.verifyIdToken(token, true);
      const userRecord = await this.firebaseAuth.getUser(decodedToken.uid);

      if (userRecord.disabled) throw new Error('User account is disabled');
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
          // Custom claims from Firebase (roles, permissions set via Admin SDK)
          ...userRecord.customClaims,
        },
      };

      if (this.config.enableCaching) this.setCachedResult(token, result);
      return result;
    } catch (error: any) {
      return { valid: false, error: this.extractFirebaseError(error) };
    }
  }

  extractUserId(decoded: any): string {
    return decoded.sub || decoded.uid || '';
  }

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
    const key = token.length > 16
      ? `${token.substring(0, 8)}...${token.substring(token.length - 8)}`
      : token;
    const entry = this.cache.get(key);
    if (entry && Date.now() < entry.expiry) return entry.result;
    if (entry) this.cache.delete(key);
    return null;
  }

  private setCachedResult(token: string, result: any): void {
    const key = token.length > 16
      ? `${token.substring(0, 8)}...${token.substring(token.length - 8)}`
      : token;
    const now = Math.floor(Date.now() / 1000);
    const timeToExpiry = (result.decoded?.exp || 0) - now;
    const ttl = result.decoded?.exp
      ? Math.max(60_000, Math.min(Math.floor(timeToExpiry / 2) * 1000, 30 * 60_000))
      : this.config.cacheTTL;
    this.cache.set(key, { result, expiry: Date.now() + ttl });
    if (this.cache.size > 1000) {
      for (const [k, v] of this.cache.entries()) {
        if (Date.now() > v.expiry) this.cache.delete(k);
      }
    }
  }
}
```

## Step 3: Create FirestorePermissionSource

Load permissions from Firestore by aggregating direct user permissions, role-based permissions, and department-based permissions.

```typescript
// src/permissions/firestore-permission-source.ts
import { firestore } from '../config/firebase.config';
import { UserPermissionSource } from '@noony-serverless/core';

export class FirestorePermissionSource implements UserPermissionSource {
  async getUserPermissions(userId: string): Promise<string[]> {
    const userDoc = await firestore.collection('users').doc(userId).get();
    if (!userDoc.exists) return [];

    const userData = userDoc.data()!;
    const permissions = new Set<string>();

    // 1. Direct permissions on the user document
    if (Array.isArray(userData.permissions)) {
      userData.permissions.forEach((p: string) => permissions.add(p));
    }

    // 2. Role-based permissions
    if (Array.isArray(userData.roles)) {
      for (const role of userData.roles) {
        const roleDoc = await firestore.collection('roles').doc(role).get();
        if (roleDoc.exists) {
          const roleData = roleDoc.data()!;
          if (Array.isArray(roleData.permissions)) {
            roleData.permissions.forEach((p: string) => permissions.add(p));
          }
        }
      }
    }

    // 3. Department-based permissions
    if (userData.department) {
      const deptDoc = await firestore.collection('departments').doc(userData.department).get();
      if (deptDoc.exists) {
        const deptData = deptDoc.data()!;
        if (Array.isArray(deptData.permissions)) {
          deptData.permissions.forEach((p: string) => permissions.add(p));
        }
      }
    }

    return Array.from(permissions);
  }
}
```

Don't store service account JSON in source code. Use Secret Manager to store credentials and mount them as environment variables or files at runtime.

## Step 4: Configure RouteGuards with Both

```typescript
// src/config/firebase.config.ts
import * as admin from 'firebase-admin';

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

```typescript
// src/config/guard.config.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { firebaseAuth } from './firebase.config';
import { FirebaseTokenValidator } from '../auth/firebase-token-validator';
import { FirestorePermissionSource } from '../permissions/firestore-permission-source';

const tokenValidator = new FirebaseTokenValidator(firebaseAuth, {
  requireEmailVerified: process.env.REQUIRE_EMAIL_VERIFIED === 'true',
  enableCaching: true,
  cacheTTL: 5 * 60 * 1000, // 5 minutes
  clockTolerance: 30,
});

const permissionSource = new FirestorePermissionSource();

const guardProfile =
  process.env.NODE_ENV === 'production'
    ? GuardSetup.production()
    : process.env.NODE_ENV === 'development'
      ? GuardSetup.development()
      : GuardSetup.serverless();

export const routeGuards = new RouteGuards({
  environment: guardProfile.environment,
  cacheType: guardProfile.cacheType,
  security: {
    ...guardProfile.security,
    conservativeCacheInvalidation: true,
  },
  cache: {
    ...guardProfile.cache,
    userContextTtlMs: process.env.NODE_ENV === 'production' ? 10 * 60 * 1000 : 2 * 60 * 1000,
    authTokenTtlMs: process.env.NODE_ENV === 'production' ? 5 * 60 * 1000 : 2 * 60 * 1000,
  },
  monitoring: {
    ...guardProfile.monitoring,
    enablePerformanceTracking: true,
    enableDetailedLogging: process.env.NODE_ENV !== 'production',
  },
});

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
```

## Step 5: Protect a Handler

```typescript
// src/handlers/user.handler.ts
import { Handler } from '@noony-serverless/core';
import { routeGuards } from '../config/guard.config';

export const getUserHandler = new Handler()
  .use(routeGuards.requireAuth())
  .use(routeGuards.requirePermission('users.read'))
  .handle(async (context) => {
    const userId = context.req.params?.userId;
    const user = await userService.getById(userId);

    context.res.status(200).json({ success: true, data: user });
  });
```

Deploy to Cloud Functions:

```typescript
// src/index.ts
import { http } from '@google-cloud/functions-framework';
import { getUserHandler } from './handlers/user.handler';

export const getUser = http('getUser', (req, res) => {
  return getUserHandler.execute(req, res);
});
```

## If Deploying to GCP: Use Application Default Credentials

When running on Cloud Functions or Cloud Run, the runtime service account already has the required Firebase Admin permissions. Remove the explicit credential object and let the SDK discover credentials automatically.

```typescript
// On GCP — no service account file needed
if (!admin.apps.length) {
  admin.initializeApp(); // uses Application Default Credentials
}
```

This avoids having to manage service account key files on the runtime environment entirely.

## Required Environment Variables

```bash
# For local development (not needed on GCP with ADC)
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# Authentication settings
REQUIRE_EMAIL_VERIFIED=true
NODE_ENV=production
NOONY_GUARD_CACHE_ENABLE=true
```
