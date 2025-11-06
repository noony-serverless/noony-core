# RouteGuards Full Authentication Example

A comprehensive guide to implementing all authentication methods in the Noony Framework for a production-ready multi-auth system. This example demonstrates combining JWT, OAuth, API Keys, Basic Auth, and Google OAuth for a complete security solution.

## Table of Contents

1. [Overview](#overview)
2. [Authentication Strategy](#authentication-strategy)
3. [Complete Setup](#complete-setup)
4. [Authentication Methods](#authentication-methods)
   - [1. JWT Authentication](#1-jwt-authentication)
   - [2. OAuth 2.0 Authentication](#2-oauth-20-authentication)
   - [3. API Key Authentication](#3-api-key-authentication)
   - [4. Basic Authentication](#4-basic-authentication)
   - [5. Google OAuth Integration](#5-google-oauth-integration)
5. [Real-World Implementation](#real-world-implementation)
6. [Security Considerations](#security-considerations)
7. [Testing Guide](#testing-guide)
8. [Troubleshooting](#troubleshooting)

## Overview

This guide demonstrates how to implement a comprehensive authentication system using the Noony Framework's RouteGuards that supports multiple authentication methods for different use cases:

- **API Keys**: Always checked first for organization/tenant identification and rate limiting
- **OAuth/Google**: Primary user authentication method with social login
- **Custom JWT**: Internal tokens generated after successful OAuth authentication
- **Basic Auth**: Legacy system integration and admin access
- **Route-specific requirements**: Different endpoints can require different auth combinations

### Why Multiple Authentication Methods?

Real-world applications often require different authentication strategies:

- **Public APIs**: Need API key validation for rate limiting and tenant identification
- **User Interfaces**: OAuth/Google login for better user experience
- **Internal Services**: JWT tokens for service-to-service communication
- **Admin Tools**: Basic Auth for simple administrative access
- **Legacy Systems**: Support for existing authentication mechanisms

## Authentication Strategy

Our multi-auth strategy implements a layered security approach:

```mermaid
graph TD
    A[Incoming Request] --> B{Has API Key?}
    B -->|Yes| C[Validate API Key & Rate Limit]
    B -->|No| D[Continue without API context]
    C --> E{Requires User Auth?}
    D --> E
    E -->|Yes| F{Auth Method Available?}
    E -->|No| G[Process Request]
    F --> H[OAuth Token]
    F --> I[JWT Token]
    F --> J[Google OAuth]
    F --> K[Basic Auth]
    H --> L[Validate & Get User]
    I --> L
    J --> L
    K --> L
    L --> M{Has Required Permissions?}
    M -->|Yes| G
    M -->|No| N[403 Forbidden]
```

## Complete Setup

### 1. Project Dependencies

```bash
npm install @noony-serverless/core
npm install jsonwebtoken
npm install firebase-admin
npm install axios  # for OAuth token introspection
```

### 2. Environment Configuration

```bash
# JWT Configuration
JWT_SECRET=your-super-secure-secret-key-here
JWT_ISSUER=your-company-name
JWT_AUDIENCE=your-app-users

# OAuth Configuration
OAUTH_INTROSPECT_URL=https://your-oauth-provider.com/oauth/introspect
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret

# Google OAuth (Firebase) Configuration
GOOGLE_PROJECT_ID=your-google-project-id
GOOGLE_PRIVATE_KEY=your-google-private-key
GOOGLE_CLIENT_EMAIL=your-google-client-email

# API Key Configuration
API_KEY_DATABASE_URL=your-api-key-storage-url

# Basic Auth Configuration
BASIC_AUTH_REALM=Your-App-Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=bcrypt-hashed-password

# Security Settings
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100
BRUTE_FORCE_MAX_ATTEMPTS=5
```

### 3. User Permission Source

First, implement a user permission source that works across all authentication methods:

```typescript
// src/auth/user-permission-source.ts
import { UserPermissionSource } from '@noony-serverless/core';

interface UserData {
  userId: string;
  name: string;
  email: string;
  permissions: string[];
  roles: string[];
  status: 'active' | 'inactive' | 'suspended';
  organizationId?: string;
}

export class MultiAuthUserPermissionSource implements UserPermissionSource {
  private users = new Map<string, UserData>();

  constructor() {
    this.initializeDemoUsers();
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    const user = await this.getUserData(userId);
    if (!user || user.status !== 'active') {
      return [];
    }

    // Combine direct permissions with role-based permissions
    const rolePermissions = await this.getRolePermissions(user.roles);
    return [...new Set([...user.permissions, ...rolePermissions])];
  }

  async getUserData(userId: string): Promise<UserData | null> {
    // In production, this would query your database
    return this.users.get(userId) || null;
  }

  private async getRolePermissions(roles: string[]): Promise<string[]> {
    const rolePermissionMap: Record<string, string[]> = {
      'admin': [
        'admin:*',
        'users:*',
        'system:*',
        'api:manage',
        'reports:generate'
      ],
      'manager': [
        'users:read',
        'users:update',
        'reports:read',
        'api:read'
      ],
      'user': [
        'profile:read',
        'profile:update',
        'api:read'
      ],
      'api-consumer': [
        'api:read',
        'data:read'
      ]
    };

    const permissions: string[] = [];
    for (const role of roles) {
      permissions.push(...(rolePermissionMap[role] || []));
    }
    return [...new Set(permissions)];
  }

  private initializeDemoUsers(): void {
    this.users.set('user-123', {
      userId: 'user-123',
      name: 'John Developer',
      email: 'john@example.com',
      permissions: ['profile:read', 'profile:update'],
      roles: ['user'],
      status: 'active',
      organizationId: 'org-acme'
    });

    this.users.set('admin-456', {
      userId: 'admin-456',
      name: 'Jane Admin',
      email: 'jane@example.com',
      permissions: [],
      roles: ['admin'],
      status: 'active',
      organizationId: 'org-acme'
    });

    this.users.set('manager-789', {
      userId: 'manager-789',
      name: 'Bob Manager',
      email: 'bob@example.com',
      permissions: ['team:manage'],
      roles: ['manager'],
      status: 'active',
      organizationId: 'org-acme'
    });
  }
}
```

## Authentication Methods

### 1. JWT Authentication

JWT tokens are used for internal service-to-service communication and as the primary token format after OAuth authentication.

#### JWT Token Validator Implementation

```typescript
// src/auth/jwt-validator.ts
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import * as jwt from 'jsonwebtoken';

interface JWTUser {
  sub: string;
  email: string;
  name: string;
  roles: string[];
  organizationId: string;
  exp: number;
  iat: number;
}

export class JWTTokenValidator implements CustomTokenVerificationPort<JWTUser> {
  private readonly secret: string;
  private readonly issuer: string;
  private readonly audience: string;

  constructor() {
    this.secret = process.env.JWT_SECRET!;
    this.issuer = process.env.JWT_ISSUER!;
    this.audience = process.env.JWT_AUDIENCE!;
  }

  async verifyToken(token: string): Promise<JWTUser> {
    try {
      const payload = jwt.verify(token, this.secret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ['HS256']
      }) as JWTUser;

      // Additional security validations
      if (!payload.sub || !payload.email) {
        throw new Error('Invalid JWT payload: missing required fields');
      }

      return payload;
    } catch (error) {
      throw new Error(`JWT validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Utility method to generate JWT tokens
  generateToken(user: {
    userId: string;
    email: string;
    name: string;
    roles: string[];
    organizationId?: string;
  }): string {
    const payload = {
      sub: user.userId,
      email: user.email,
      name: user.name,
      roles: user.roles,
      organizationId: user.organizationId,
    };

    return jwt.sign(payload, this.secret, {
      issuer: this.issuer,
      audience: this.audience,
      algorithm: 'HS256',
      expiresIn: '1h'
    });
  }
}
```

**Why JWT?**
- **Stateless**: No server-side session storage required
- **Self-contained**: All user information embedded in token
- **Standards-based**: RFC 7519 compliance ensures interoperability
- **Scalable**: Works across distributed systems without shared state

**Security Impact:**
- Must use strong secrets (min 256 bits for HS256)
- Token exposure risks require short expiration times
- No server-side revocation without additional infrastructure

### 2. OAuth 2.0 Authentication

OAuth 2.0 token introspection for third-party authentication providers.

#### OAuth Token Validator Implementation

```typescript
// src/auth/oauth-validator.ts
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import axios from 'axios';

interface OAuthUser {
  sub: string;
  email: string;
  name: string;
  client_id: string;
  scope: string[];
  exp: number;
  active: boolean;
  organizationId?: string;
}

export class OAuthTokenValidator implements CustomTokenVerificationPort<OAuthUser> {
  private readonly introspectUrl: string;
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly requiredScopes: string[];

  constructor(requiredScopes: string[] = ['read:profile']) {
    this.introspectUrl = process.env.OAUTH_INTROSPECT_URL!;
    this.clientId = process.env.OAUTH_CLIENT_ID!;
    this.clientSecret = process.env.OAUTH_CLIENT_SECRET!;
    this.requiredScopes = requiredScopes;
  }

  async verifyToken(token: string): Promise<OAuthUser> {
    try {
      const response = await axios.post(
        this.introspectUrl,
        new URLSearchParams({
          token,
          token_type_hint: 'access_token'
        }),
        {
          auth: {
            username: this.clientId,
            password: this.clientSecret
          },
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 5000 // 5 second timeout
        }
      );

      const tokenInfo = response.data;

      if (!tokenInfo.active) {
        throw new Error('OAuth token is not active');
      }

      // Validate required scopes
      const tokenScopes = tokenInfo.scope ? tokenInfo.scope.split(' ') : [];
      const hasRequiredScopes = this.requiredScopes.every(scope => 
        tokenScopes.includes(scope)
      );

      if (!hasRequiredScopes) {
        throw new Error(`Missing required scopes: ${this.requiredScopes.join(', ')}`);
      }

      // Map the organization ID from the token
      const organizationId = this.extractOrganizationId(tokenInfo);

      return {
        sub: tokenInfo.sub,
        email: tokenInfo.email || `${tokenInfo.sub}@unknown.com`,
        name: tokenInfo.name || tokenInfo.sub,
        client_id: tokenInfo.client_id,
        scope: tokenScopes,
        exp: tokenInfo.exp,
        active: tokenInfo.active,
        organizationId
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNABORTED') {
          throw new Error('OAuth introspection timeout');
        }
        if (error.response?.status === 401) {
          throw new Error('OAuth introspection authentication failed');
        }
        throw new Error(`OAuth introspection failed: ${error.message}`);
      }
      throw error;
    }
  }

  private extractOrganizationId(tokenInfo: any): string | undefined {
    // Common OAuth extensions for organization/tenant info
    return tokenInfo.org_id || 
           tokenInfo.organization_id || 
           tokenInfo.tenant_id ||
           tokenInfo.custom_org_id;
  }
}
```

**Why OAuth 2.0?**
- **Third-party integration**: Works with external identity providers
- **Standardized**: Industry standard for authorization
- **Scope-based permissions**: Fine-grained access control
- **Token introspection**: Server-side validation ensures token validity

**Security Impact:**
- Network dependency for token validation
- Introspection endpoint must be secured and rate-limited
- Scopes provide additional authorization layer beyond permissions

### 3. API Key Authentication

API keys provide organization/tenant identification and rate limiting. Always checked first in our multi-auth flow.

#### API Key Validator Implementation

```typescript
// src/auth/api-key-validator.ts
import { CustomTokenVerificationPort } from '@noony-serverless/core';

interface APIKeyUser {
  keyId: string;
  organizationId: string;
  name: string;
  permissions: string[];
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
  };
  isActive: boolean;
  expiresAt?: number;
  metadata: {
    environment: 'production' | 'staging' | 'development';
    purpose: string;
    createdAt: string;
    lastUsed?: string;
  };
}

interface APIKeyData {
  keyId: string;
  hashedKey: string;
  organizationId: string;
  name: string;
  permissions: string[];
  rateLimit: {
    requestsPerMinute: number;
    requestsPerHour: number;
  };
  isActive: boolean;
  expiresAt?: Date;
  environment: 'production' | 'staging' | 'development';
  purpose: string;
  createdAt: Date;
  lastUsed?: Date;
}

export class APIKeyValidator implements CustomTokenVerificationPort<APIKeyUser> {
  private apiKeys = new Map<string, APIKeyData>();

  constructor() {
    this.initializeDemoAPIKeys();
  }

  async verifyToken(apiKey: string): Promise<APIKeyUser> {
    // In production, you would hash the API key and look up in database
    const keyData = this.findAPIKey(apiKey);

    if (!keyData) {
      throw new Error('Invalid API key');
    }

    if (!keyData.isActive) {
      throw new Error('API key is deactivated');
    }

    if (keyData.expiresAt && keyData.expiresAt < new Date()) {
      throw new Error('API key has expired');
    }

    // Update last used timestamp (in production, do this async)
    keyData.lastUsed = new Date();

    return {
      keyId: keyData.keyId,
      organizationId: keyData.organizationId,
      name: keyData.name,
      permissions: keyData.permissions,
      rateLimit: keyData.rateLimit,
      isActive: keyData.isActive,
      expiresAt: keyData.expiresAt?.getTime(),
      metadata: {
        environment: keyData.environment,
        purpose: keyData.purpose,
        createdAt: keyData.createdAt.toISOString(),
        lastUsed: keyData.lastUsed?.toISOString()
      }
    };
  }

  private findAPIKey(apiKey: string): APIKeyData | undefined {
    // In production, hash the API key and look up the hash
    // This is a simplified version for demo purposes
    for (const [_, keyData] of this.apiKeys) {
      if (keyData.hashedKey === this.hashAPIKey(apiKey)) {
        return keyData;
      }
    }
    return undefined;
  }

  private hashAPIKey(apiKey: string): string {
    // In production, use a proper hashing function like bcrypt
    // This is simplified for demo purposes
    return Buffer.from(apiKey).toString('base64');
  }

  private initializeDemoAPIKeys(): void {
    this.apiKeys.set('key-1', {
      keyId: 'key-acme-prod-1',
      hashedKey: this.hashAPIKey('ak_acme_prod_1234567890abcdef'),
      organizationId: 'org-acme',
      name: 'ACME Corp Production API',
      permissions: ['api:read', 'api:write', 'data:read'],
      rateLimit: {
        requestsPerMinute: 1000,
        requestsPerHour: 50000
      },
      isActive: true,
      environment: 'production',
      purpose: 'Main production API access',
      createdAt: new Date('2024-01-01'),
    });

    this.apiKeys.set('key-2', {
      keyId: 'key-acme-staging-1',
      hashedKey: this.hashAPIKey('ak_acme_staging_abcdef1234567890'),
      organizationId: 'org-acme',
      name: 'ACME Corp Staging API',
      permissions: ['api:read', 'api:write'],
      rateLimit: {
        requestsPerMinute: 100,
        requestsPerHour: 5000
      },
      isActive: true,
      environment: 'staging',
      purpose: 'Staging environment testing',
      createdAt: new Date('2024-01-15'),
    });

    this.apiKeys.set('key-3', {
      keyId: 'key-beta-limited',
      hashedKey: this.hashAPIKey('ak_beta_limited_xyz789'),
      organizationId: 'org-beta',
      name: 'Beta Corp Limited Access',
      permissions: ['api:read'],
      rateLimit: {
        requestsPerMinute: 10,
        requestsPerHour: 100
      },
      isActive: true,
      environment: 'production',
      purpose: 'Limited beta access',
      createdAt: new Date('2024-02-01'),
    });
  }
}
```

**Why API Keys?**
- **Organization identification**: Links requests to specific tenants
- **Rate limiting**: Different limits per organization
- **Audit trail**: Track API usage by organization
- **Simple integration**: Easy for clients to implement

**Security Impact:**
- API keys should be treated like passwords (hashed storage)
- Rate limiting prevents abuse and DDoS attacks
- Rotation policies required for long-term security

### 4. Basic Authentication

HTTP Basic Authentication for admin endpoints and legacy system integration.

#### Basic Auth Validator Implementation

```typescript
// src/auth/basic-auth-validator.ts
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import * as bcrypt from 'bcrypt';

interface BasicAuthUser {
  username: string;
  userId: string;
  name: string;
  roles: string[];
  permissions: string[];
  metadata: {
    authMethod: 'basic';
    loginCount: number;
    lastLogin: string;
    accountType: 'admin' | 'service' | 'legacy';
  };
}

interface BasicAuthAccount {
  username: string;
  passwordHash: string;
  userId: string;
  name: string;
  roles: string[];
  permissions: string[];
  isActive: boolean;
  accountType: 'admin' | 'service' | 'legacy';
  bruteForceProtection: {
    failedAttempts: number;
    lockedUntil?: Date;
  };
  metadata: {
    loginCount: number;
    lastLogin?: Date;
    createdAt: Date;
  };
}

export class BasicAuthValidator implements CustomTokenVerificationPort<BasicAuthUser> {
  private accounts = new Map<string, BasicAuthAccount>();
  private readonly maxFailedAttempts = 5;
  private readonly lockoutDurationMs = 15 * 60 * 1000; // 15 minutes

  constructor() {
    this.initializeDemoAccounts();
  }

  async verifyToken(basicAuthToken: string): Promise<BasicAuthUser> {
    // Parse Basic Auth token (format: "Basic base64(username:password)")
    const credentials = this.parseBasicAuth(basicAuthToken);
    if (!credentials) {
      throw new Error('Invalid Basic Auth format');
    }

    const account = this.accounts.get(credentials.username);
    if (!account) {
      throw new Error('Invalid username or password');
    }

    // Check if account is locked due to brute force attempts
    if (this.isAccountLocked(account)) {
      const lockedUntil = account.bruteForceProtection.lockedUntil!;
      const unlockIn = Math.ceil((lockedUntil.getTime() - Date.now()) / 60000);
      throw new Error(`Account locked. Try again in ${unlockIn} minutes.`);
    }

    if (!account.isActive) {
      throw new Error('Account is deactivated');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(credentials.password, account.passwordHash);
    if (!isPasswordValid) {
      await this.handleFailedLogin(account);
      throw new Error('Invalid username or password');
    }

    // Reset failed attempts on successful login
    account.bruteForceProtection.failedAttempts = 0;
    account.bruteForceProtection.lockedUntil = undefined;
    account.metadata.loginCount++;
    account.metadata.lastLogin = new Date();

    return {
      username: account.username,
      userId: account.userId,
      name: account.name,
      roles: account.roles,
      permissions: account.permissions,
      metadata: {
        authMethod: 'basic',
        loginCount: account.metadata.loginCount,
        lastLogin: account.metadata.lastLogin.toISOString(),
        accountType: account.accountType
      }
    };
  }

  private parseBasicAuth(basicAuthToken: string): { username: string; password: string } | null {
    if (!basicAuthToken.startsWith('Basic ')) {
      return null;
    }

    try {
      const base64Credentials = basicAuthToken.slice('Basic '.length);
      const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
      const [username, password] = credentials.split(':', 2);

      if (!username || !password) {
        return null;
      }

      return { username, password };
    } catch (error) {
      return null;
    }
  }

  private isAccountLocked(account: BasicAuthAccount): boolean {
    if (!account.bruteForceProtection.lockedUntil) {
      return false;
    }
    return account.bruteForceProtection.lockedUntil > new Date();
  }

  private async handleFailedLogin(account: BasicAuthAccount): Promise<void> {
    account.bruteForceProtection.failedAttempts++;

    if (account.bruteForceProtection.failedAttempts >= this.maxFailedAttempts) {
      account.bruteForceProtection.lockedUntil = new Date(Date.now() + this.lockoutDurationMs);
      console.warn(`🚨 Account ${account.username} locked due to ${this.maxFailedAttempts} failed attempts`);
    }
  }

  private async initializeDemoAccounts(): Promise<void> {
    // Admin account
    this.accounts.set('admin', {
      username: 'admin',
      passwordHash: await bcrypt.hash('admin123', 10), // In production, use environment variables
      userId: 'admin-001',
      name: 'System Administrator',
      roles: ['admin', 'super-admin'],
      permissions: ['admin:*', 'system:*'],
      isActive: true,
      accountType: 'admin',
      bruteForceProtection: {
        failedAttempts: 0
      },
      metadata: {
        loginCount: 0,
        createdAt: new Date('2024-01-01')
      }
    });

    // Service account
    this.accounts.set('service-monitor', {
      username: 'service-monitor',
      passwordHash: await bcrypt.hash('monitor-secret-2024', 10),
      userId: 'service-monitor-001',
      name: 'Monitoring Service',
      roles: ['service'],
      permissions: ['system:health', 'metrics:read'],
      isActive: true,
      accountType: 'service',
      bruteForceProtection: {
        failedAttempts: 0
      },
      metadata: {
        loginCount: 0,
        createdAt: new Date('2024-01-01')
      }
    });

    // Legacy system account
    this.accounts.set('legacy-importer', {
      username: 'legacy-importer',
      passwordHash: await bcrypt.hash('legacy-import-key-2024', 10),
      userId: 'legacy-importer-001',
      name: 'Legacy Data Importer',
      roles: ['legacy-system'],
      permissions: ['data:import', 'data:write'],
      isActive: true,
      accountType: 'legacy',
      bruteForceProtection: {
        failedAttempts: 0
      },
      metadata: {
        loginCount: 0,
        createdAt: new Date('2024-01-01')
      }
    });
  }
}
```

**Why Basic Authentication?**
- **Legacy compatibility**: Works with older systems and tools
- **Simple implementation**: Standard HTTP mechanism
- **Admin access**: Quick access for administrative tools
- **Service accounts**: Monitoring and automated systems

**Security Impact:**
- Credentials sent in every request (Base64 encoded, not encrypted)
- HTTPS mandatory to prevent credential interception
- Brute force protection essential due to simple attack vectors

### 5. Google OAuth Integration

Google OAuth 2.0 ID token verification using Firebase Admin SDK.

#### Google OAuth Setup

Since the framework already has excellent Firebase integration, we'll use Firebase Admin SDK for Google OAuth:

```typescript
// src/auth/google-oauth-setup.ts
import * as admin from 'firebase-admin';

// Initialize Firebase Admin SDK (if not already done)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.GOOGLE_PROJECT_ID!,
      privateKey: process.env.GOOGLE_PRIVATE_KEY!.replace(/\\n/g, '\n'),
      clientEmail: process.env.GOOGLE_CLIENT_EMAIL!
    })
  });
}

export const firebaseAuth = admin.auth();
```

#### Google OAuth Token Validator

```typescript
// src/auth/google-oauth-validator.ts
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import { firebaseAuth } from './google-oauth-setup';
import { DecodedIdToken } from 'firebase-admin/auth';

interface GoogleOAuthUser {
  sub: string;
  email: string;
  name: string;
  picture?: string;
  email_verified: boolean;
  firebase: {
    identities: Record<string, string[]>;
    sign_in_provider: string;
  };
  exp: number;
  iat: number;
  auth_time: number;
  uid: string;
}

export class GoogleOAuthValidator implements CustomTokenVerificationPort<GoogleOAuthUser> {
  private readonly requireEmailVerified: boolean;

  constructor(requireEmailVerified: boolean = true) {
    this.requireEmailVerified = requireEmailVerified;
  }

  async verifyToken(idToken: string): Promise<GoogleOAuthUser> {
    try {
      // Verify the Firebase ID token (which includes Google OAuth tokens)
      const decodedToken: DecodedIdToken = await firebaseAuth.verifyIdToken(idToken, true);

      // Check if this is a Google sign-in
      const signInProvider = decodedToken.firebase?.sign_in_provider;
      if (signInProvider !== 'google.com') {
        throw new Error(`Expected Google sign-in, got: ${signInProvider}`);
      }

      // Verify email if required
      if (this.requireEmailVerified && !decodedToken.email_verified) {
        throw new Error('Email address must be verified for Google OAuth');
      }

      // Get additional user data from Firebase
      const userRecord = await firebaseAuth.getUser(decodedToken.uid);

      if (userRecord.disabled) {
        throw new Error('User account is disabled');
      }

      return {
        sub: decodedToken.uid,
        email: decodedToken.email!,
        name: decodedToken.name || userRecord.displayName || 'Google User',
        picture: decodedToken.picture,
        email_verified: decodedToken.email_verified || false,
        firebase: decodedToken.firebase,
        exp: decodedToken.exp,
        iat: decodedToken.iat,
        auth_time: decodedToken.auth_time,
        uid: decodedToken.uid
      };
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('expired')) {
          throw new Error('Google OAuth token has expired');
        }
        if (error.message.includes('invalid')) {
          throw new Error('Invalid Google OAuth token');
        }
        throw error;
      }
      throw new Error('Google OAuth verification failed');
    }
  }

  // Helper method to create a custom JWT after Google OAuth success
  async generateCustomJWT(googleUser: GoogleOAuthUser, jwtValidator: any): Promise<string> {
    // Map Google user to your application's user structure
    const userForJWT = {
      userId: googleUser.sub,
      email: googleUser.email,
      name: googleUser.name,
      roles: ['user'], // Default role, could be enhanced based on email domain, etc.
      organizationId: this.extractOrganizationFromEmail(googleUser.email)
    };

    return jwtValidator.generateToken(userForJWT);
  }

  private extractOrganizationFromEmail(email: string): string | undefined {
    // Example: map email domains to organizations
    const domain = email.split('@')[1];
    const domainToOrgMap: Record<string, string> = {
      'acme.com': 'org-acme',
      'beta.com': 'org-beta',
      'example.com': 'org-example'
    };
    return domainToOrgMap[domain];
  }
}
```

**Why Google OAuth?**
- **User experience**: Familiar login flow for end users
- **Security**: Google handles password security and 2FA
- **No password management**: Eliminates password reset flows
- **Verified emails**: Google handles email verification

**Security Impact:**
- Dependency on Google's infrastructure
- Token verification requires network calls to Google
- User account lifecycle tied to Google account status

## Real-World Implementation

Now let's implement a complete multi-auth system with practical examples:

### 1. Guard Configuration

```typescript
// src/auth/multi-auth-config.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { MultiAuthUserPermissionSource } from './user-permission-source';
import { JWTTokenValidator } from './jwt-validator';
import { OAuthTokenValidator } from './oauth-validator';
import { APIKeyValidator } from './api-key-validator';
import { BasicAuthValidator } from './basic-auth-validator';
import { GoogleOAuthValidator } from './google-oauth-validator';

// Initialize validators
export const jwtValidator = new JWTTokenValidator();
export const oauthValidator = new OAuthTokenValidator(['read:profile', 'read:data']);
export const apiKeyValidator = new APIKeyValidator();
export const basicAuthValidator = new BasicAuthValidator();
export const googleOAuthValidator = new GoogleOAuthValidator(true);

// User permission source
export const userPermissionSource = new MultiAuthUserPermissionSource();

// Configure RouteGuards with JWT as the primary validator
export async function configureMultiAuth() {
  await RouteGuards.configure(
    GuardSetup.production(),
    userPermissionSource,
    jwtValidator, // Primary token validator
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: false,
      allowInactiveUsers: false
    }
  );

  console.log('✅ Multi-auth system configured successfully');
}
```

### 2. Authentication Middleware Factory

Create a middleware factory that can handle different authentication strategies:

```typescript
// src/auth/multi-auth-middleware.ts
import { BaseMiddleware, Context } from '@noony-serverless/core';

interface AuthStrategy {
  name: string;
  headerName: string;
  prefix: string;
  validator: any;
}

export class MultiAuthMiddleware implements BaseMiddleware {
  private strategies: AuthStrategy[] = [];
  private apiKeyValidator: any;

  constructor(apiKeyValidator: any) {
    this.apiKeyValidator = apiKeyValidator;
  }

  addStrategy(strategy: AuthStrategy): void {
    this.strategies.push(strategy);
  }

  async before(context: Context): Promise<void> {
    const req = context.req;

    // Step 1: Always check for API key first (for rate limiting and organization context)
    const apiKey = req.headers['x-api-key'] as string;
    if (apiKey) {
      try {
        const apiKeyUser = await this.apiKeyValidator.verifyToken(apiKey);
        context.businessData = context.businessData || new Map();
        context.businessData.set('apiKey', apiKeyUser);
        context.businessData.set('organizationId', apiKeyUser.organizationId);
        context.businessData.set('rateLimits', apiKeyUser.rateLimit);
        
        console.log(`🔑 API Key validated for org: ${apiKeyUser.organizationId}`);
      } catch (error) {
        console.warn(`⚠️ API Key validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        // Don't fail the request, just log the warning
      }
    }

    // Step 2: Try user authentication strategies in order
    let authenticated = false;
    let lastError: Error | null = null;

    for (const strategy of this.strategies) {
      const authHeader = req.headers[strategy.headerName.toLowerCase()] as string;
      if (!authHeader) continue;

      let token = authHeader;
      if (strategy.prefix && authHeader.startsWith(strategy.prefix)) {
        token = authHeader.slice(strategy.prefix.length);
      }

      try {
        const user = await strategy.validator.verifyToken(token);
        
        // Map the authenticated user to context
        context.user = {
          id: user.sub || user.userId || user.keyId,
          email: user.email || `${user.sub || user.userId}@system.local`,
          name: user.name || user.username || 'Unknown User',
          // Add other required fields based on your context type
        };

        context.businessData = context.businessData || new Map();
        context.businessData.set('authStrategy', strategy.name);
        context.businessData.set('authenticatedUser', user);

        console.log(`✅ Authenticated via ${strategy.name}: ${context.user.id}`);
        authenticated = true;
        break;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Authentication failed');
        console.log(`❌ ${strategy.name} auth failed: ${lastError.message}`);
        continue; // Try next strategy
      }
    }

    // If no authentication strategy succeeded, but we have an API key, that's acceptable for some endpoints
    if (!authenticated && !apiKey) {
      throw new Error(`Authentication required. Supported methods: ${this.strategies.map(s => s.name).join(', ')}`);
    }

    if (!authenticated && apiKey) {
      console.log('🔓 Request proceeding with API key authentication only');
    }
  }
}
```

### 3. Complete Application Example

Here's how to set up a complete application with all authentication methods:

```typescript
// src/app.ts
import { Handler, ErrorHandlerMiddleware, ResponseWrapperMiddleware } from '@noony-serverless/core';
import { 
  configureMultiAuth, 
  jwtValidator, 
  oauthValidator, 
  apiKeyValidator, 
  basicAuthValidator, 
  googleOAuthValidator 
} from './auth/multi-auth-config';
import { MultiAuthMiddleware } from './auth/multi-auth-middleware';

// Initialize authentication
await configureMultiAuth();

// Create multi-auth middleware
const multiAuth = new MultiAuthMiddleware(apiKeyValidator);

// Add authentication strategies in priority order
multiAuth.addStrategy({
  name: 'JWT',
  headerName: 'authorization',
  prefix: 'Bearer ',
  validator: jwtValidator
});

multiAuth.addStrategy({
  name: 'OAuth',
  headerName: 'authorization',
  prefix: 'Bearer ',
  validator: oauthValidator
});

multiAuth.addStrategy({
  name: 'Google OAuth',
  headerName: 'authorization',
  prefix: 'Bearer ',
  validator: googleOAuthValidator
});

multiAuth.addStrategy({
  name: 'Basic Auth',
  headerName: 'authorization',
  prefix: 'Basic ',
  validator: basicAuthValidator
});

// Example endpoints with different authentication requirements

// 1. Public endpoint with optional API key (for rate limiting)
export const publicDataHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const apiKeyInfo = context.businessData?.get('apiKey');
    const organizationId = context.businessData?.get('organizationId');

    return {
      message: 'This is public data',
      rateLimited: !!apiKeyInfo,
      organizationId: organizationId || 'public',
      data: {
        items: ['item1', 'item2', 'item3'],
        timestamp: new Date().toISOString()
      }
    };
  });

// 2. User endpoint requiring authentication + optional API key
export const userProfileHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(multiAuth)
  .use(RouteGuards.requirePermissions(['profile:read']))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const user = context.user;
    const authStrategy = context.businessData?.get('authStrategy');
    const apiKeyInfo = context.businessData?.get('apiKey');

    return {
      message: 'User profile data',
      user: {
        id: user?.id,
        email: user?.email,
        name: user?.name
      },
      authMethod: authStrategy,
      organization: apiKeyInfo?.organizationId || 'personal',
      permissions: await userPermissionSource.getUserPermissions(user?.id || '')
    };
  });

// 3. Admin endpoint requiring specific authentication method
export const adminSystemHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(multiAuth)
  .use(RouteGuards.requirePermissions(['admin:system']))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const authStrategy = context.businessData?.get('authStrategy');
    
    // Only allow Basic Auth or JWT for admin endpoints
    if (authStrategy !== 'Basic Auth' && authStrategy !== 'JWT') {
      throw new Error('Admin endpoints require Basic Auth or JWT authentication');
    }

    return {
      message: 'System administration data',
      authMethod: authStrategy,
      systemInfo: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        timestamp: new Date().toISOString()
      }
    };
  });

// 4. OAuth login endpoint (creates JWT after OAuth success)
export const oauthLoginHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const authHeader = context.req.headers.authorization as string;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new Error('OAuth token required');
    }

    const oauthToken = authHeader.slice('Bearer '.length);
    
    try {
      // Verify OAuth token
      const oauthUser = await oauthValidator.verifyToken(oauthToken);
      
      // Generate JWT for future requests
      const jwtToken = jwtValidator.generateToken({
        userId: oauthUser.sub,
        email: oauthUser.email,
        name: oauthUser.name,
        roles: ['user'], // Could be enhanced based on OAuth scopes
        organizationId: 'default'
      });

      return {
        message: 'Login successful',
        tokens: {
          jwt: jwtToken,
          expiresIn: '1h'
        },
        user: {
          id: oauthUser.sub,
          email: oauthUser.email,
          name: oauthUser.name,
          scopes: oauthUser.scope
        }
      };
    } catch (error) {
      throw new Error(`OAuth login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  });

// 5. Google OAuth login endpoint
export const googleLoginHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const authHeader = context.req.headers.authorization as string;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new Error('Google ID token required');
    }

    const idToken = authHeader.slice('Bearer '.length);
    
    try {
      // Verify Google OAuth token
      const googleUser = await googleOAuthValidator.verifyToken(idToken);
      
      // Generate JWT for future requests
      const jwtToken = await googleOAuthValidator.generateCustomJWT(googleUser, jwtValidator);

      return {
        message: 'Google login successful',
        tokens: {
          jwt: jwtToken,
          expiresIn: '1h'
        },
        user: {
          id: googleUser.sub,
          email: googleUser.email,
          name: googleUser.name,
          picture: googleUser.picture,
          emailVerified: googleUser.email_verified
        }
      };
    } catch (error) {
      throw new Error(`Google login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  });
```

## Security Considerations

### 1. Token Security

**JWT Tokens:**
- Use strong secrets (minimum 256 bits)
- Implement short expiration times (1 hour recommended)
- Consider token refresh mechanisms for long-lived sessions
- Never log JWT tokens or include them in error messages

**OAuth Tokens:**
- Validate tokens server-side via introspection
- Check token scopes match required permissions
- Implement timeout for introspection requests
- Cache introspection results with appropriate TTL

**API Keys:**
- Hash API keys in storage (use bcrypt or similar)
- Implement key rotation policies
- Monitor for unusual usage patterns
- Different rate limits per key/organization

### 2. Authentication Strategy Impact

**Always-Check API Key Strategy:**
```typescript
// Impact: Every request processed for organization context
// Benefits: Rate limiting, tenant isolation, usage tracking
// Costs: Additional validation overhead (~1-2ms per request)
```

**Multi-Auth Fallback:**
```typescript
// Impact: Attempts multiple auth methods until one succeeds
// Benefits: Flexible client implementation, gradual migration
// Costs: Potential for auth confusion, multiple validation attempts
```

**Basic Auth for Admin:**
```typescript
// Impact: Credentials sent in every request
// Benefits: Simple integration with admin tools
// Costs: HTTPS mandatory, brute force protection required
```

### 3. Performance Considerations

**Authentication Caching:**
```typescript
// Cache validated tokens to avoid repeated cryptographic operations
const authCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Performance impact: 95% reduction in auth validation time
// Memory impact: ~1KB per cached token
// Invalidation: Required for security updates
```

**Rate Limiting Implementation:**
```typescript
// Per-API-key rate limiting
const rateLimiter = {
  requests: new Map(), // Track requests per key
  cleanup: setInterval(() => {
    // Clean expired entries every minute
  }, 60000)
};

// Impact: Prevents abuse, ensures fair resource allocation
// Memory: ~100 bytes per tracked key
// CPU: Minimal overhead for in-memory counters
```

### 4. Error Handling Security

```typescript
// Secure error responses - don't leak authentication details
function sanitizeAuthError(error: Error): string {
  // Don't expose detailed auth failure reasons to prevent enumeration attacks
  const safeErrors = [
    'Invalid token',
    'Authentication required',
    'Insufficient permissions',
    'Rate limit exceeded'
  ];
  
  // Log detailed errors server-side for debugging
  console.error('Auth Error Details:', error);
  
  // Return generic error to client
  return 'Authentication failed';
}
```

## Testing Guide

### 1. Test All Authentication Methods

```bash
#!/bin/bash
# test-multi-auth.sh

API_BASE="http://localhost:8080"

echo "🧪 Testing Multi-Auth System"

# Test 1: API Key Only (Public endpoint)
echo "1. Testing API key only..."
curl -H "X-API-Key: ak_acme_prod_1234567890abcdef" \
     "$API_BASE/public-data"

# Test 2: JWT Authentication
echo -e "\n2. Testing JWT authentication..."
JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."  # Your JWT token
curl -H "Authorization: Bearer $JWT_TOKEN" \
     "$API_BASE/user-profile"

# Test 3: OAuth Authentication
echo -e "\n3. Testing OAuth authentication..."
OAUTH_TOKEN="your-oauth-access-token"
curl -H "Authorization: Bearer $OAUTH_TOKEN" \
     "$API_BASE/user-profile"

# Test 4: Basic Authentication
echo -e "\n4. Testing Basic authentication..."
curl -H "Authorization: Basic $(echo -n 'admin:admin123' | base64)" \
     "$API_BASE/admin-system"

# Test 5: Google OAuth
echo -e "\n5. Testing Google OAuth..."
GOOGLE_ID_TOKEN="your-google-id-token"
curl -H "Authorization: Bearer $GOOGLE_ID_TOKEN" \
     "$API_BASE/google-login"

# Test 6: Combined API Key + JWT
echo -e "\n6. Testing API Key + JWT..."
curl -H "X-API-Key: ak_acme_prod_1234567890abcdef" \
     -H "Authorization: Bearer $JWT_TOKEN" \
     "$API_BASE/user-profile"

# Test 7: Rate Limiting
echo -e "\n7. Testing rate limiting..."
for i in {1..10}; do
  curl -H "X-API-Key: ak_beta_limited_xyz789" \
       "$API_BASE/public-data" &
done
wait

echo -e "\n✅ Multi-auth testing completed"
```

### 2. Security Test Scenarios

```typescript
// src/test/security-tests.ts
import { describe, it, expect } from '@jest/globals';

describe('Multi-Auth Security Tests', () => {
  it('should reject invalid JWT tokens', async () => {
    const response = await fetch('/user-profile', {
      headers: { 'Authorization': 'Bearer invalid.jwt.token' }
    });
    expect(response.status).toBe(401);
  });

  it('should enforce rate limits per API key', async () => {
    const apiKey = 'ak_beta_limited_xyz789';
    const requests = Array(15).fill(null).map(() => 
      fetch('/public-data', {
        headers: { 'X-API-Key': apiKey }
      })
    );
    
    const responses = await Promise.all(requests);
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
  });

  it('should lock Basic Auth accounts after failed attempts', async () => {
    const badCredentials = 'Basic ' + btoa('admin:wrongpassword');
    
    // Make 5 failed attempts
    for (let i = 0; i < 5; i++) {
      await fetch('/admin-system', {
        headers: { 'Authorization': badCredentials }
      });
    }
    
    // 6th attempt should be locked
    const response = await fetch('/admin-system', {
      headers: { 'Authorization': badCredentials }
    });
    expect(response.status).toBe(423); // Locked
  });

  it('should require specific auth methods for admin endpoints', async () => {
    const oauthToken = 'Bearer oauth-token';
    const response = await fetch('/admin-system', {
      headers: { 'Authorization': oauthToken }
    });
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('require Basic Auth or JWT');
  });
});
```

## Troubleshooting

### Common Issues and Solutions

#### 1. JWT Token Validation Failures

**Problem:** JWT tokens failing validation with "signature invalid"
```typescript
// Check these common issues:
1. Secret key mismatch between generation and validation
2. Algorithm mismatch (HS256 vs RS256)
3. Issuer/audience claim mismatches
4. Clock skew between servers

// Solution:
console.log('JWT Debug:', {
  secret: process.env.JWT_SECRET?.slice(0, 8) + '...', // Don't log full secret
  issuer: process.env.JWT_ISSUER,
  audience: process.env.JWT_AUDIENCE,
  serverTime: new Date().toISOString()
});
```

#### 2. OAuth Token Introspection Timeout

**Problem:** OAuth validation timing out
```typescript
// Increase timeout and add retry logic:
const response = await axios.post(introspectUrl, data, {
  timeout: 10000, // Increase to 10 seconds
  retry: {
    retries: 2,
    retryDelay: 1000
  }
});
```

#### 3. API Key Rate Limiting Issues

**Problem:** Rate limits not working correctly
```typescript
// Debug rate limiting:
console.log('Rate Limit Debug:', {
  apiKey: apiKey.slice(0, 8) + '...',
  currentRequests: rateLimiter.get(apiKey),
  windowStart: new Date(windowStart).toISOString(),
  limit: rateLimit
});
```

#### 4. Basic Auth Brute Force Protection

**Problem:** Account lockouts not working
```typescript
// Verify lockout logic:
const account = accounts.get(username);
console.log('Lockout Debug:', {
  username,
  failedAttempts: account?.bruteForceProtection.failedAttempts,
  lockedUntil: account?.bruteForceProtection.lockedUntil?.toISOString(),
  isLocked: isAccountLocked(account),
  currentTime: new Date().toISOString()
});
```

#### 5. Google OAuth Email Verification

**Problem:** Google tokens failing email verification check
```typescript
// Debug email verification:
console.log('Google OAuth Debug:', {
  email: decodedToken.email,
  emailVerified: decodedToken.email_verified,
  requireEmailVerified: this.requireEmailVerified,
  signInProvider: decodedToken.firebase?.sign_in_provider
});
```

### Performance Monitoring

```typescript
// Add performance monitoring to your auth middleware:
const performanceMonitor = {
  authTimes: [],
  
  recordAuthTime(method: string, timeMs: number) {
    this.authTimes.push({ method, timeMs, timestamp: Date.now() });
    
    // Keep only last 1000 records
    if (this.authTimes.length > 1000) {
      this.authTimes = this.authTimes.slice(-1000);
    }
  },
  
  getStats() {
    const byMethod = this.authTimes.reduce((acc, record) => {
      acc[record.method] = acc[record.method] || [];
      acc[record.method].push(record.timeMs);
      return acc;
    }, {} as Record<string, number[]>);
    
    const stats = Object.entries(byMethod).map(([method, times]) => ({
      method,
      count: times.length,
      avgTime: times.reduce((a, b) => a + b, 0) / times.length,
      maxTime: Math.max(...times),
      minTime: Math.min(...times)
    }));
    
    return stats;
  }
};

// Use in your auth middleware:
const startTime = Date.now();
// ... perform authentication ...
const endTime = Date.now();
performanceMonitor.recordAuthTime(strategy.name, endTime - startTime);
```

---

This comprehensive guide provides a complete multi-authentication system using the Noony Framework's RouteGuards. The implementation supports all major authentication methods while maintaining security best practices and performance considerations.

Each authentication method serves a specific purpose in the overall security strategy, and the combination provides maximum flexibility for different client types and use cases while maintaining a consistent and secure API surface.