# RouteGuards Multi-Authentication Examples

A comprehensive guide demonstrating how to use the Noony Framework's RouteGuards system with multiple authentication types: JWT, OAuth, API Keys, Basic Auth, and Google OAuth.

## Table of Contents

- [RouteGuards Multi-Authentication Examples](#routeguards-multi-authentication-examples)
  - [Table of Contents](#table-of-contents)
  - [JWT Authentication](#jwt-authentication)
    - [Standard JWT Setup](#standard-jwt-setup)
  - [OAuth Authentication](#oauth-authentication)
    - [OAuth 2.0 Token Validation](#oauth-20-token-validation)
  - [API Key Authentication](#api-key-authentication)
    - [API Key Validation](#api-key-validation)
  - [Basic Authentication](#basic-authentication)
    - [HTTP Basic Auth](#http-basic-auth)
  - [Google OAuth Integration](#google-oauth-integration)
    - [Google OAuth 2.0 Setup](#google-oauth-20-setup)
  - [Multi-Auth Strategies](#multi-auth-strategies)
    - [Combining Multiple Authentication Types](#combining-multiple-authentication-types)
  - [Testing Examples](#testing-examples)
    - [Comprehensive Testing Suite](#comprehensive-testing-suite)
  - [Deployment](#deployment)
    - [Environment Configuration](#environment-configuration)
    - [Monitoring and Observability](#monitoring-and-observability)

---

## JWT Authentication

### Standard JWT Setup

```typescript
// src/auth/jwt-auth.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import jwt from 'jsonwebtoken';

interface JWTUser {
  sub: string;           // JWT subject (user ID)
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  exp: number;           // JWT expiration
  iat: number;           // Issued at
  iss?: string;          // Issuer
  aud?: string;          // Audience
}

// JWT Token Verifier
const jwtVerifier: CustomTokenVerificationPort<JWTUser> = {
  async verifyToken(token: string): Promise<JWTUser> {
    try {
      const secret = process.env.JWT_SECRET;
      if (!secret) {
        throw new Error('JWT_SECRET environment variable not set');
      }

      const payload = jwt.verify(token, secret, {
        algorithms: ['HS256', 'RS256'],
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
      }) as any;

      // Validate required claims
      if (!payload.sub || !payload.email) {
        throw new Error('Invalid JWT: missing required claims');
      }

      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name || payload.email,
        roles: payload.roles || [],
        permissions: payload.permissions || [],
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
        aud: payload.aud,
      };
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error(`JWT verification failed: ${error.message}`);
      }
      throw error;
    }
  }
};

// Permission source that combines user permissions with role-based permissions
const userPermissionSource = {
  async getUserPermissions(userId: string) {
    try {
      // Fetch user from your database
      const user = await database.users.findById(userId);
      if (!user) {
        throw new Error(`User ${userId} not found`);
      }

      // Get role-based permissions
      const rolePermissions = await this.getRolePermissions(user.roles);
      
      // Combine user-specific permissions with role permissions
      const allPermissions = [
        ...user.permissions,
        ...rolePermissions
      ];

      return {
        permissions: Array.from(new Set(allPermissions)), // Remove duplicates
        roles: user.roles,
        metadata: { 
          email: user.email,
          lastLogin: user.lastLogin,
          isActive: user.isActive 
        }
      };
    } catch (error) {
      console.error('Error fetching user permissions:', error);
      throw error;
    }
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    if (!roles || roles.length === 0) return [];

    const rolePermissions = await database.roles.find({
      name: { $in: roles },
      isActive: true
    });

    return rolePermissions.flatMap(role => role.permissions);
  },

  async isUserContextStale(userId: string, lastFetched: number): Promise<boolean> {
    // Check if user permissions have been updated since last cache
    const user = await database.users.findById(userId, { select: ['updatedAt'] });
    return user && user.updatedAt.getTime() > lastFetched;
  }
};

// Configure JWT authentication
export const setupJWTAuth = async () => {
  await RouteGuards.configureWithJWT(
    GuardSetup.production(),
    userPermissionSource,
    jwtVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: true,
      allowInactiveUsers: false,
      customValidation: async (token, user) => {
        // Additional custom validation logic
        if (!user.isActive) {
          throw new Error('Account is deactivated');
        }
        return true;
      }
    }
  );
};

// Usage in handlers
export const createUserHandler = new Handler()
  .use(RouteGuards.requirePermissions(['user:create']))
  .handle(async (context) => {
    const user = context.user as JWTUser;
    console.log(`Creating user, requested by: ${user.email}`);
    
    // Your business logic here
    return { success: true, message: 'User created successfully' };
  });
```

---

## OAuth Authentication

### OAuth 2.0 Token Validation

```typescript
// src/auth/oauth-auth.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import axios from 'axios';

interface OAuthUser {
  sub: string;           // OAuth subject
  email: string;
  name: string;
  scope: string[];       // OAuth scopes
  exp: number;
  client_id: string;
  token_type: string;
  active: boolean;
}

// OAuth Token Verifier with introspection endpoint
const oauthVerifier: CustomTokenVerificationPort<OAuthUser> = {
  async verifyToken(token: string): Promise<OAuthUser> {
    try {
      const introspectUrl = process.env.OAUTH_INTROSPECT_URL;
      const clientId = process.env.OAUTH_CLIENT_ID;
      const clientSecret = process.env.OAUTH_CLIENT_SECRET;

      if (!introspectUrl || !clientId || !clientSecret) {
        throw new Error('OAuth configuration missing');
      }

      // Token introspection request
      const response = await axios.post(
        introspectUrl,
        new URLSearchParams({
          token,
          token_type_hint: 'access_token'
        }),
        {
          auth: {
            username: clientId,
            password: clientSecret
          },
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 5000
        }
      );

      const tokenInfo = response.data;

      if (!tokenInfo.active) {
        throw new Error('OAuth token is not active');
      }

      // Validate required scopes
      const requiredScopes = ['read:profile', 'write:data'];
      const tokenScopes = tokenInfo.scope?.split(' ') || [];
      
      const hasRequiredScopes = requiredScopes.some(scope => 
        tokenScopes.includes(scope)
      );

      if (!hasRequiredScopes) {
        throw new Error(`Token missing required scopes: ${requiredScopes.join(', ')}`);
      }

      return {
        sub: tokenInfo.sub,
        email: tokenInfo.email || `${tokenInfo.sub}@oauth-provider.com`,
        name: tokenInfo.name || tokenInfo.username || tokenInfo.sub,
        scope: tokenScopes,
        exp: tokenInfo.exp,
        client_id: tokenInfo.client_id,
        token_type: tokenInfo.token_type || 'Bearer',
        active: tokenInfo.active
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`OAuth introspection failed: ${error.message}`);
      }
      throw error;
    }
  }
};

// OAuth-specific permission source
const oauthPermissionSource = {
  async getUserPermissions(userId: string) {
    // For OAuth, permissions often come from scopes
    const user = await database.oauthUsers.findById(userId);
    
    // Map OAuth scopes to internal permissions
    const scopePermissionMap = {
      'read:profile': ['user:read', 'profile:view'],
      'write:data': ['data:create', 'data:update'],
      'admin:manage': ['admin:users', 'admin:system'],
      'read:reports': ['reports:view', 'analytics:view']
    };

    const permissions = user.scopes.flatMap(scope => 
      scopePermissionMap[scope] || []
    );

    return {
      permissions: Array.from(new Set(permissions)),
      roles: user.roles || [],
      metadata: { 
        scopes: user.scopes,
        clientId: user.clientId,
        grantType: user.grantType 
      }
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    // OAuth roles might be mapped differently
    const roleMap = {
      'oauth_user': ['user:read', 'user:update'],
      'oauth_admin': ['admin:read', 'admin:write', 'user:manage']
    };

    return roles.flatMap(role => roleMap[role] || []);
  },

  async isUserContextStale(): Promise<boolean> {
    // OAuth tokens are typically short-lived, so less stale checking needed
    return false;
  }
};

// Configure OAuth authentication
export const setupOAuthAuth = async () => {
  await RouteGuards.configureWithOAuth(
    GuardSetup.production(),
    oauthPermissionSource,
    oauthVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: false, // OAuth provider handles verification
      customValidation: async (token, user) => {
        // Check if client is still authorized
        const client = await database.oauthClients.findById(user.client_id);
        return client && client.isActive;
      }
    },
    ['read:profile', 'write:data'] // Required OAuth scopes
  );
};

// Usage with scope-based permissions
export const accessDataHandler = new Handler()
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { permission: 'data:read' },
      { and: [
        { permission: 'user:read' },
        { permission: 'profile:view' }
      ]}
    ]
  }))
  .handle(async (context) => {
    const user = context.user as OAuthUser;
    console.log(`Data access by OAuth user: ${user.sub}, scopes: ${user.scope.join(', ')}`);
    
    return { success: true, data: 'sensitive data' };
  });
```

---

## API Key Authentication

### API Key Validation

```typescript
// src/auth/apikey-auth.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import crypto from 'crypto';

interface APIKeyUser {
  keyId: string;
  name: string;
  organization: string;
  permissions: string[];
  rateLimit: number;
  expiresAt?: number;
  isActive: boolean;
  usage: {
    requestCount: number;
    lastUsed: Date;
  };
}

// API Key Verifier
const apiKeyVerifier: CustomTokenVerificationPort<APIKeyUser> = {
  async verifyToken(apiKey: string): Promise<APIKeyUser> {
    try {
      // Validate API key format
      if (!apiKey || apiKey.length < 32) {
        throw new Error('Invalid API key format');
      }

      // Hash the API key for database lookup (keys should be stored hashed)
      const hashedKey = crypto
        .createHash('sha256')
        .update(apiKey)
        .digest('hex');

      // Look up API key in database
      const keyRecord = await database.apiKeys.findOne({
        hashedKey,
        isActive: true
      });

      if (!keyRecord) {
        throw new Error('API key not found or inactive');
      }

      // Check expiration
      if (keyRecord.expiresAt && keyRecord.expiresAt < new Date()) {
        throw new Error('API key has expired');
      }

      // Check rate limiting
      const now = new Date();
      const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      
      if (keyRecord.usage.lastUsed > hourAgo && 
          keyRecord.usage.requestCount >= keyRecord.rateLimit) {
        throw new Error('API key rate limit exceeded');
      }

      // Update usage tracking
      await database.apiKeys.updateOne(
        { _id: keyRecord._id },
        {
          $inc: { 'usage.requestCount': 1 },
          $set: { 'usage.lastUsed': now }
        }
      );

      return {
        keyId: keyRecord._id.toString(),
        name: keyRecord.name,
        organization: keyRecord.organization,
        permissions: keyRecord.permissions,
        rateLimit: keyRecord.rateLimit,
        expiresAt: keyRecord.expiresAt?.getTime(),
        isActive: keyRecord.isActive,
        usage: keyRecord.usage
      };
    } catch (error) {
      console.error('API key verification failed:', error);
      throw error;
    }
  }
};

// API Key permission source
const apiKeyPermissionSource = {
  async getUserPermissions(keyId: string) {
    const apiKey = await database.apiKeys.findById(keyId);
    
    return {
      permissions: apiKey.permissions,
      roles: [`org:${apiKey.organization}`, 'api_client'],
      metadata: { 
        organization: apiKey.organization,
        rateLimit: apiKey.rateLimit,
        usage: apiKey.usage 
      }
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    // API keys might have organization-based permissions
    const orgRoles = roles.filter(role => role.startsWith('org:'));
    const orgPermissions = [];

    for (const orgRole of orgRoles) {
      const orgName = orgRole.split(':')[1];
      const org = await database.organizations.findOne({ name: orgName });
      if (org) {
        orgPermissions.push(...org.defaultPermissions);
      }
    }

    // Standard role permissions
    if (roles.includes('api_client')) {
      orgPermissions.push('api:read', 'api:write');
    }

    return Array.from(new Set(orgPermissions));
  },

  async isUserContextStale(): Promise<boolean> {
    // API key permissions change less frequently
    return false;
  }
};

// Configure API Key authentication
export const setupAPIKeyAuth = async () => {
  await RouteGuards.configureWithAPIKey(
    GuardSetup.production(),
    apiKeyPermissionSource,
    apiKeyVerifier,
    {
      tokenHeader: 'x-api-key', // Custom header for API keys
      tokenPrefix: '',          // No prefix needed
      allowInactiveUsers: false,
      customValidation: async (token, keyUser) => {
        // Additional validation for API keys
        if (!keyUser.isActive) {
          throw new Error('API key is deactivated');
        }

        // Check organization status
        const org = await database.organizations.findOne({
          name: keyUser.organization,
          isActive: true
        });

        if (!org) {
          throw new Error('Organization is not active');
        }

        return true;
      }
    },
    'keyId',        // User ID field
    'expiresAt'     // Expiration field
  );
};

// Usage with API key specific features
export const apiDataHandler = new Handler()
  .use(RouteGuards.requirePermissions(['api:read']))
  .handle(async (context) => {
    const keyUser = context.user as APIKeyUser;
    
    console.log(`API request from: ${keyUser.organization}, key: ${keyUser.name}`);
    console.log(`Usage: ${keyUser.usage.requestCount}/${keyUser.rateLimit} requests`);
    
    return { 
      success: true, 
      data: 'API data',
      rateLimit: {
        remaining: keyUser.rateLimit - keyUser.usage.requestCount,
        resetTime: new Date(Date.now() + 60 * 60 * 1000).toISOString()
      }
    };
  });
```

---

## Basic Authentication

### HTTP Basic Auth

```typescript
// src/auth/basic-auth.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import bcrypt from 'bcrypt';

interface BasicAuthUser {
  userId: string;
  username: string;
  email: string;
  roles: string[];
  isActive: boolean;
  lastLogin: Date;
  failedLoginAttempts: number;
}

// Basic Auth Verifier
const basicAuthVerifier: CustomTokenVerificationPort<BasicAuthUser> = {
  async verifyToken(authHeader: string): Promise<BasicAuthUser> {
    try {
      // Parse Basic auth header: "Basic base64(username:password)"
      if (!authHeader || !authHeader.startsWith('Basic ')) {
        throw new Error('Invalid Basic authentication header');
      }

      const base64Credentials = authHeader.substring(6);
      const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
      const [username, password] = credentials.split(':', 2);

      if (!username || !password) {
        throw new Error('Missing username or password');
      }

      // Rate limiting for brute force protection
      const rateLimitKey = `basic_auth_attempts:${username}`;
      const attempts = await redis.get(rateLimitKey);
      
      if (attempts && parseInt(attempts) > 5) {
        throw new Error('Too many failed login attempts. Please try again later.');
      }

      // Look up user
      const user = await database.users.findOne({
        $or: [
          { username: username },
          { email: username }
        ],
        isActive: true
      });

      if (!user) {
        // Increment failed attempts even for non-existent users
        await redis.setex(rateLimitKey, 900, (parseInt(attempts) || 0) + 1); // 15 min lockout
        throw new Error('Invalid credentials');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.passwordHash);
      
      if (!isValidPassword) {
        // Increment failed attempts
        await database.users.updateOne(
          { _id: user._id },
          { $inc: { failedLoginAttempts: 1 } }
        );
        await redis.setex(rateLimitKey, 900, (parseInt(attempts) || 0) + 1);
        throw new Error('Invalid credentials');
      }

      // Check account lockout
      if (user.failedLoginAttempts >= 5) {
        throw new Error('Account locked due to multiple failed login attempts');
      }

      // Reset failed attempts and update last login
      await database.users.updateOne(
        { _id: user._id },
        { 
          $set: { 
            failedLoginAttempts: 0,
            lastLogin: new Date()
          }
        }
      );

      // Clear rate limit
      await redis.del(rateLimitKey);

      return {
        userId: user._id.toString(),
        username: user.username,
        email: user.email,
        roles: user.roles,
        isActive: user.isActive,
        lastLogin: new Date(),
        failedLoginAttempts: 0
      };
    } catch (error) {
      console.error('Basic auth verification failed:', error);
      throw error;
    }
  }
};

// Basic Auth permission source
const basicAuthPermissionSource = {
  async getUserPermissions(userId: string) {
    const user = await database.users.findById(userId);
    
    return {
      permissions: user.permissions || [],
      roles: user.roles || [],
      metadata: { 
        username: user.username,
        email: user.email,
        lastLogin: user.lastLogin,
        accountType: 'basic_auth'
      }
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    const rolePermissions = await database.roles.find({
      name: { $in: roles },
      isActive: true
    });

    return rolePermissions.flatMap(role => role.permissions);
  },

  async isUserContextStale(userId: string, lastFetched: number): Promise<boolean> {
    const user = await database.users.findById(userId, { select: ['updatedAt'] });
    return user && user.updatedAt.getTime() > lastFetched;
  }
};

// Configure Basic Authentication
export const setupBasicAuth = async () => {
  await RouteGuards.configureWithCustom(
    GuardSetup.production(),
    basicAuthPermissionSource,
    basicAuthVerifier,
    {
      tokenHeader: 'authorization', // Uses Authorization header
      tokenPrefix: '',               // No prefix needed, handled in verifier
      allowInactiveUsers: false,
      customValidation: async (token, user) => {
        // Additional security checks
        if (user.failedLoginAttempts >= 3) {
          console.warn(`User ${user.username} has ${user.failedLoginAttempts} failed attempts`);
        }

        // Check if password needs to be changed (90 days)
        const passwordAge = Date.now() - user.lastLogin.getTime();
        const maxPasswordAge = 90 * 24 * 60 * 60 * 1000; // 90 days

        if (passwordAge > maxPasswordAge) {
          throw new Error('Password has expired. Please change your password.');
        }

        return true;
      }
    },
    {
      userIdExtractor: (user: BasicAuthUser) => user.userId,
      expirationExtractor: () => undefined, // Basic auth doesn't expire
      additionalValidation: (user: BasicAuthUser) => user.isActive
    }
  );
};

// Usage with Basic Auth
export const basicAuthHandler = new Handler()
  .use(RouteGuards.requirePermissions(['admin:access']))
  .handle(async (context) => {
    const user = context.user as BasicAuthUser;
    
    console.log(`Basic auth access by: ${user.username} (${user.email})`);
    
    return { 
      success: true, 
      message: 'Authenticated with Basic Auth',
      user: {
        username: user.username,
        lastLogin: user.lastLogin
      }
    };
  });
```

---

## Google OAuth Integration

### Google OAuth 2.0 Setup

```typescript
// src/auth/google-oauth.ts
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import { CustomTokenVerificationPort } from '@noony-serverless/core';
import { OAuth2Client } from 'google-auth-library';

interface GoogleOAuthUser {
  sub: string;           // Google user ID
  email: string;
  name: string;
  picture: string;
  email_verified: boolean;
  locale: string;
  aud: string;           // Client ID
  exp: number;
  iss: string;           // Google issuer
}

// Google OAuth Verifier
const googleOAuthVerifier: CustomTokenVerificationPort<GoogleOAuthUser> = {
  async verifyToken(idToken: string): Promise<GoogleOAuthUser> {
    try {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      if (!clientId) {
        throw new Error('GOOGLE_CLIENT_ID not configured');
      }

      const client = new OAuth2Client(clientId);

      // Verify the ID token
      const ticket = await client.verifyIdToken({
        idToken: idToken,
        audience: clientId,
      });

      const payload = ticket.getPayload();
      
      if (!payload) {
        throw new Error('Invalid Google ID token payload');
      }

      // Verify email is verified
      if (!payload.email_verified) {
        throw new Error('Google email not verified');
      }

      // Check if user is from allowed domain (optional)
      const allowedDomains = process.env.GOOGLE_ALLOWED_DOMAINS?.split(',') || [];
      if (allowedDomains.length > 0) {
        const emailDomain = payload.email?.split('@')[1];
        if (!emailDomain || !allowedDomains.includes(emailDomain)) {
          throw new Error(`Domain ${emailDomain} not allowed`);
        }
      }

      return {
        sub: payload.sub!,
        email: payload.email!,
        name: payload.name!,
        picture: payload.picture!,
        email_verified: payload.email_verified!,
        locale: payload.locale || 'en',
        aud: payload.aud as string,
        exp: payload.exp!,
        iss: payload.iss!,
      };
    } catch (error) {
      console.error('Google OAuth verification failed:', error);
      throw error;
    }
  }
};

// Google OAuth permission source
const googleOAuthPermissionSource = {
  async getUserPermissions(userId: string) {
    // Look up user in local database by Google sub
    const user = await database.users.findOne({ googleId: userId });
    
    if (!user) {
      // First-time Google user - create with default permissions
      const newUser = await database.users.create({
        googleId: userId,
        email: user.email, // From Google token
        name: user.name,   // From Google token
        roles: ['user'],   // Default role
        permissions: ['user:read', 'profile:view'],
        createdAt: new Date(),
        authProvider: 'google'
      });

      return {
        permissions: newUser.permissions,
        roles: newUser.roles,
        metadata: { 
          authProvider: 'google',
          isNewUser: true,
          googleId: userId 
        }
      };
    }

    return {
      permissions: user.permissions || [],
      roles: user.roles || ['user'],
      metadata: { 
        authProvider: 'google',
        googleId: userId,
        lastGoogleLogin: new Date()
      }
    };
  },

  async getRolePermissions(roles: string[]): Promise<string[]> {
    const rolePermissions = await database.roles.find({
      name: { $in: roles },
      isActive: true
    });

    return rolePermissions.flatMap(role => role.permissions);
  },

  async isUserContextStale(userId: string, lastFetched: number): Promise<boolean> {
    const user = await database.users.findOne({ googleId: userId });
    return user && user.updatedAt.getTime() > lastFetched;
  }
};

// Configure Google OAuth
export const setupGoogleOAuth = async () => {
  await RouteGuards.configureWithJWT(
    GuardSetup.production(),
    googleOAuthPermissionSource,
    googleOAuthVerifier,
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      requireEmailVerification: true, // Google handles email verification
      customValidation: async (token, user) => {
        // Additional Google-specific validation
        if (user.iss !== 'https://accounts.google.com' && 
            user.iss !== 'accounts.google.com') {
          throw new Error('Invalid Google token issuer');
        }

        // Check if user's email domain is still allowed
        const allowedDomains = process.env.GOOGLE_ALLOWED_DOMAINS?.split(',') || [];
        if (allowedDomains.length > 0) {
          const emailDomain = user.email.split('@')[1];
          if (!allowedDomains.includes(emailDomain)) {
            throw new Error('User domain no longer allowed');
          }
        }

        return true;
      }
    }
  );
};

// Google-specific handlers
export const googleProfileHandler = new Handler()
  .use(RouteGuards.requirePermissions(['profile:view']))
  .handle(async (context) => {
    const user = context.user as GoogleOAuthUser;
    
    // Update user's last Google login
    await database.users.updateOne(
      { googleId: user.sub },
      { $set: { lastGoogleLogin: new Date() } }
    );
    
    return { 
      success: true, 
      profile: {
        name: user.name,
        email: user.email,
        picture: user.picture,
        locale: user.locale,
        verified: user.email_verified
      }
    };
  });
```

---

## Multi-Auth Strategies

### Combining Multiple Authentication Types

```typescript
// src/auth/multi-auth-strategy.ts
import { Handler, Context } from '@noony-serverless/core';
import { 
  setupJWTAuth,
  setupOAuthAuth,
  setupAPIKeyAuth,
  setupBasicAuth,
  setupGoogleOAuth
} from './auth-types';

// Unified user interface
interface UnifiedUser {
  id: string;
  email: string;
  name: string;
  authType: 'jwt' | 'oauth' | 'apikey' | 'basic' | 'google';
  permissions: string[];
  roles: string[];
  metadata: Record<string, any>;
}

// Smart authentication middleware that detects auth type
export const createMultiAuthGuard = (requiredPermissions: string[]) => {
  return {
    async before(context: Context): Promise<void> {
      const authHeader = context.req.headers['authorization'] as string;
      const apiKey = context.req.headers['x-api-key'] as string;
      
      let authType: string;
      let authValue: string;

      // Determine authentication type based on headers
      if (apiKey) {
        authType = 'apikey';
        authValue = apiKey;
      } else if (authHeader) {
        if (authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          
          // Detect JWT vs OAuth vs Google token
          if (token.startsWith('ya29.') || token.startsWith('1//')) {
            authType = 'google'; // Google access token pattern
          } else if (token.includes('.') && token.split('.').length === 3) {
            authType = 'jwt'; // JWT format
          } else {
            authType = 'oauth'; // Assume OAuth access token
          }
          
          authValue = token;
        } else if (authHeader.startsWith('Basic ')) {
          authType = 'basic';
          authValue = authHeader;
        } else {
          throw new Error('Unsupported authentication type');
        }
      } else {
        throw new Error('No authentication provided');
      }

      // Route to appropriate auth handler
      let user: UnifiedUser;
      
      switch (authType) {
        case 'jwt':
          user = await validateJWTUser(authValue, requiredPermissions);
          break;
        case 'oauth':
          user = await validateOAuthUser(authValue, requiredPermissions);
          break;
        case 'apikey':
          user = await validateAPIKeyUser(authValue, requiredPermissions);
          break;
        case 'basic':
          user = await validateBasicAuthUser(authValue, requiredPermissions);
          break;
        case 'google':
          user = await validateGoogleUser(authValue, requiredPermissions);
          break;
        default:
          throw new Error('Authentication type not supported');
      }

      // Unified permission check
      const hasPermission = requiredPermissions.length === 0 || 
        requiredPermissions.some(permission => 
          user.permissions.includes(permission)
        );

      if (!hasPermission) {
        throw new Error('Insufficient permissions');
      }

      context.user = user;
    }
  };
};

// Individual auth validators (simplified)
async function validateJWTUser(token: string, permissions: string[]): Promise<UnifiedUser> {
  // Use JWT verification logic
  const jwtUser = await jwtVerifier.verifyToken(token);
  const userPerms = await userPermissionSource.getUserPermissions(jwtUser.sub);
  
  return {
    id: jwtUser.sub,
    email: jwtUser.email,
    name: jwtUser.name,
    authType: 'jwt',
    permissions: userPerms.permissions,
    roles: userPerms.roles,
    metadata: { tokenType: 'jwt', exp: jwtUser.exp }
  };
}

async function validateAPIKeyUser(apiKey: string, permissions: string[]): Promise<UnifiedUser> {
  const keyUser = await apiKeyVerifier.verifyToken(apiKey);
  const keyPerms = await apiKeyPermissionSource.getUserPermissions(keyUser.keyId);
  
  return {
    id: keyUser.keyId,
    email: `${keyUser.name}@${keyUser.organization}`,
    name: keyUser.name,
    authType: 'apikey',
    permissions: keyPerms.permissions,
    roles: keyPerms.roles,
    metadata: { organization: keyUser.organization, rateLimit: keyUser.rateLimit }
  };
}

// Usage with multi-auth support
export const multiAuthHandler = new Handler()
  .use(createMultiAuthGuard(['data:read']))
  .handle(async (context) => {
    const user = context.user as UnifiedUser;
    
    console.log(`Request from ${user.authType} user: ${user.email}`);
    
    // Auth-type specific logic
    switch (user.authType) {
      case 'apikey':
        // Log API usage
        console.log(`API request from org: ${user.metadata.organization}`);
        break;
      case 'jwt':
        // Check token expiration warning
        const timeToExpiry = user.metadata.exp - Date.now() / 1000;
        if (timeToExpiry < 300) { // 5 minutes
          console.warn(`JWT token expires soon for user: ${user.email}`);
        }
        break;
      case 'google':
        // Update last Google login
        await updateGoogleLastLogin(user.id);
        break;
    }
    
    return { 
      success: true, 
      data: 'Protected data',
      authInfo: {
        type: user.authType,
        user: user.email,
        permissions: user.permissions
      }
    };
  });

// Environment-specific multi-auth setup
export const setupMultiAuth = async () => {
  const authTypes = process.env.ENABLED_AUTH_TYPES?.split(',') || ['jwt'];
  
  for (const authType of authTypes) {
    switch (authType.trim()) {
      case 'jwt':
        await setupJWTAuth();
        console.log('✅ JWT authentication enabled');
        break;
      case 'oauth':
        await setupOAuthAuth();
        console.log('✅ OAuth authentication enabled');
        break;
      case 'apikey':
        await setupAPIKeyAuth();
        console.log('✅ API Key authentication enabled');
        break;
      case 'basic':
        await setupBasicAuth();
        console.log('✅ Basic authentication enabled');
        break;
      case 'google':
        await setupGoogleOAuth();
        console.log('✅ Google OAuth enabled');
        break;
      default:
        console.warn(`⚠️ Unknown auth type: ${authType}`);
    }
  }
};
```

---

## Testing Examples

### Comprehensive Testing Suite

```typescript
// tests/auth-integration.test.ts
import { describe, it, expect, beforeAll } from '@jest/globals';
import { Handler } from '@noony-serverless/core';
import jwt from 'jsonwebtoken';
import { 
  setupJWTAuth,
  setupAPIKeyAuth,
  setupGoogleOAuth,
  createMultiAuthGuard 
} from '../src/auth';

describe('Multi-Authentication Integration Tests', () => {
  beforeAll(async () => {
    // Setup test environment
    process.env.JWT_SECRET = 'test-secret';
    process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
    
    // Initialize auth systems
    await setupJWTAuth();
    await setupAPIKeyAuth();
    await setupGoogleOAuth();
  });

  describe('JWT Authentication', () => {
    it('should authenticate valid JWT token', async () => {
      const payload = {
        sub: 'user123',
        email: 'test@example.com',
        name: 'Test User',
        permissions: ['user:read'],
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
      };
      
      const token = jwt.sign(payload, 'test-secret');
      
      const handler = new Handler()
        .use(createMultiAuthGuard(['user:read']))
        .handle(async (context) => {
          return { user: context.user };
        });

      const mockReq = {
        headers: { authorization: `Bearer ${token}` }
      };
      const mockRes = { json: jest.fn() };

      await handler.executeGeneric(mockReq, mockRes);
      
      expect(mockRes.json).toHaveBeenCalledWith({
        user: expect.objectContaining({
          email: 'test@example.com',
          authType: 'jwt'
        })
      });
    });

    it('should reject expired JWT token', async () => {
      const payload = {
        sub: 'user123',
        email: 'test@example.com',
        exp: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
      };
      
      const token = jwt.sign(payload, 'test-secret');
      
      const handler = new Handler()
        .use(createMultiAuthGuard(['user:read']))
        .handle(async () => ({}));

      const mockReq = {
        headers: { authorization: `Bearer ${token}` }
      };
      const mockRes = { status: jest.fn().mockReturnThis(), json: jest.fn() };

      await expect(
        handler.executeGeneric(mockReq, mockRes)
      ).rejects.toThrow('JWT verification failed');
    });
  });

  describe('API Key Authentication', () => {
    it('should authenticate valid API key', async () => {
      // Mock API key lookup
      const mockAPIKey = 'test-api-key-12345678901234567890123456789012';
      
      jest.spyOn(database.apiKeys, 'findOne').mockResolvedValue({
        _id: 'key123',
        name: 'Test API Key',
        organization: 'TestOrg',
        permissions: ['api:read', 'data:read'],
        isActive: true,
        usage: { requestCount: 0, lastUsed: new Date() }
      });

      const handler = new Handler()
        .use(createMultiAuthGuard(['api:read']))
        .handle(async (context) => {
          return { user: context.user };
        });

      const mockReq = {
        headers: { 'x-api-key': mockAPIKey }
      };
      const mockRes = { json: jest.fn() };

      await handler.executeGeneric(mockReq, mockRes);
      
      expect(mockRes.json).toHaveBeenCalledWith({
        user: expect.objectContaining({
          authType: 'apikey',
          metadata: expect.objectContaining({
            organization: 'TestOrg'
          })
        })
      });
    });
  });

  describe('Multi-Auth Detection', () => {
    it('should detect JWT token correctly', () => {
      const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ';
      
      // JWT tokens have 3 parts separated by dots
      expect(token.split('.').length).toBe(3);
      expect(token.includes('.')).toBe(true);
    });

    it('should detect Google token pattern', () => {
      const googleToken = 'ya29.a0AfH6SMBexample_google_token';
      
      expect(googleToken.startsWith('ya29.')).toBe(true);
    });

    it('should detect API key header', () => {
      const headers = {
        'x-api-key': 'api-key-example-123456789'
      };
      
      expect(headers['x-api-key']).toBeTruthy();
    });
  });

  describe('Permission Validation', () => {
    it('should enforce permission requirements across auth types', async () => {
      const testCases = [
        {
          authType: 'jwt',
          permissions: ['user:read'],
          requiredPermissions: ['admin:write'],
          shouldFail: true
        },
        {
          authType: 'apikey',
          permissions: ['api:read', 'data:read'],
          requiredPermissions: ['data:read'],
          shouldFail: false
        }
      ];

      for (const testCase of testCases) {
        const handler = new Handler()
          .use(createMultiAuthGuard(testCase.requiredPermissions))
          .handle(async () => ({ success: true }));

        // Mock appropriate auth response
        if (testCase.authType === 'jwt') {
          const token = jwt.sign({
            sub: 'test',
            email: 'test@example.com',
            permissions: testCase.permissions,
            exp: Math.floor(Date.now() / 1000) + 3600
          }, 'test-secret');

          const mockReq = {
            headers: { authorization: `Bearer ${token}` }
          };
          const mockRes = { status: jest.fn().mockReturnThis(), json: jest.fn() };

          if (testCase.shouldFail) {
            await expect(
              handler.executeGeneric(mockReq, mockRes)
            ).rejects.toThrow('Insufficient permissions');
          } else {
            await expect(
              handler.executeGeneric(mockReq, mockRes)
            ).resolves.not.toThrow();
          }
        }
      }
    });
  });
});

// Performance tests
describe('Authentication Performance', () => {
  it('should handle concurrent authentication requests', async () => {
    const concurrentRequests = 100;
    const token = jwt.sign({
      sub: 'perf-test',
      email: 'perf@example.com',
      permissions: ['user:read'],
      exp: Math.floor(Date.now() / 1000) + 3600
    }, 'test-secret');

    const handler = new Handler()
      .use(createMultiAuthGuard(['user:read']))
      .handle(async () => ({ success: true }));

    const requests = Array(concurrentRequests).fill(null).map(async () => {
      const mockReq = {
        headers: { authorization: `Bearer ${token}` }
      };
      const mockRes = { json: jest.fn() };

      const startTime = Date.now();
      await handler.executeGeneric(mockReq, mockRes);
      return Date.now() - startTime;
    });

    const times = await Promise.all(requests);
    const averageTime = times.reduce((a, b) => a + b, 0) / times.length;

    console.log(`Average auth time: ${averageTime}ms`);
    expect(averageTime).toBeLessThan(50); // Should be under 50ms with caching
  });
});
```

---

## Deployment

### Environment Configuration

```bash
# .env.production
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-min-256-bits
JWT_ISSUER=https://your-auth-server.com
JWT_AUDIENCE=https://your-api.com

# OAuth Configuration
OAUTH_INTROSPECT_URL=https://oauth-provider.com/token/introspect
OAUTH_CLIENT_ID=your-oauth-client-id
OAUTH_CLIENT_SECRET=your-oauth-client-secret

# Google OAuth Configuration
GOOGLE_CLIENT_ID=123456789-abcdef.apps.googleusercontent.com
GOOGLE_ALLOWED_DOMAINS=yourcompany.com,trusted-partner.com

# Guard System Configuration
NOONY_GUARD_CACHE_ENABLE=true
NOONY_GUARD_CACHE_TYPE=memory
ENABLED_AUTH_TYPES=jwt,oauth,apikey,google

# Database Configuration
DATABASE_URL=mongodb://user:pass@host:27017/dbname
REDIS_URL=redis://user:pass@host:6379

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX_ATTEMPTS=5
```

### Monitoring and Observability

```typescript
// src/monitoring/auth-metrics.ts
import { RouteGuards } from '@noony-serverless/core';

// Health check endpoint
export const healthCheckHandler = new Handler()
  .handle(async (context) => {
    const guardHealth = await RouteGuards.healthCheck();
    const stats = RouteGuards.getSystemStats();
    
    const health = {
      status: guardHealth.status,
      timestamp: new Date().toISOString(),
      guards: {
        status: guardHealth.status,
        authCacheHitRate: stats.systemHealth.cacheEfficiency,
        totalChecks: stats.systemHealth.totalGuardChecks,
        errorRate: stats.systemHealth.errorRate,
        avgResponseTime: stats.systemHealth.averageResponseTime
      },
      database: await checkDatabaseHealth(),
      cache: await checkCacheHealth()
    };

    const statusCode = health.status === 'healthy' ? 200 : 503;
    context.res.status(statusCode).json(health);
  });

// Metrics endpoint for Prometheus
export const metricsHandler = new Handler()
  .handle(async (context) => {
    const stats = RouteGuards.getSystemStats();
    
    const metrics = [
      `# HELP auth_cache_hit_rate Authentication cache hit rate`,
      `# TYPE auth_cache_hit_rate gauge`,
      `auth_cache_hit_rate ${stats.systemHealth.cacheEfficiency}`,
      
      `# HELP auth_total_checks Total authentication checks`,
      `# TYPE auth_total_checks counter`, 
      `auth_total_checks ${stats.systemHealth.totalGuardChecks}`,
      
      `# HELP auth_error_rate Authentication error rate percentage`,
      `# TYPE auth_error_rate gauge`,
      `auth_error_rate ${stats.systemHealth.errorRate}`,
      
      `# HELP auth_response_time_avg Average auth response time in ms`,
      `# TYPE auth_response_time_avg gauge`,
      `auth_response_time_avg ${stats.systemHealth.averageResponseTime}`,
      ''
    ].join('\n');

    context.res.setHeader('Content-Type', 'text/plain');
    context.res.send(metrics);
  });
```

This comprehensive example demonstrates how to implement multiple authentication types with the Noony Framework's RouteGuards system, providing flexibility, security, and performance optimization for various authentication scenarios.