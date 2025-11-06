# TokenValidatorFactory with AuthenticationMiddleware Integration

This guide demonstrates how to use the `TokenValidatorFactory` with the `AuthenticationMiddleware` to create reusable, enterprise-grade authentication for your handlers.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
   - [Simple Factory + Custom Verifier Pattern](#1-simple-factory--custom-verifier-pattern)
   - [Usage in Handlers](#2-usage-in-handlers)
3. [Singleton Pattern for Maximum Reusability](#singleton-pattern-for-maximum-reusability)
   - [Single Setup File](#1-single-setup-file)
   - [Use Across Multiple Handlers](#2-use-across-multiple-handlers)
4. [Advanced Configuration](#advanced-configuration)
   - [Multi-Provider Setup with Failover](#multi-provider-setup-with-failover)
   - [Social Authentication (Google & Facebook)](#social-authentication-google--facebook)
   - [Using Social Authentication in Handlers](#using-social-authentication-in-handlers)
   - [Environment Variables for Social Authentication](#environment-variables-for-social-authentication)
   - [Required Dependencies](#required-dependencies)
   - [Different Security Levels](#different-security-levels)
   - [Usage with Different Security Levels](#usage-with-different-security-levels)
5. [Error Handling](#error-handling)
6. [Performance Monitoring](#performance-monitoring)
7. [Best Practices](#best-practices)
   - [Environment Configuration](#1-environment-configuration)
   - [Type Safety](#2-type-safety)
   - [Testing](#3-testing)
8. [Key Benefits](#key-benefits)
9. [Summary](#summary)

## Overview

The `TokenValidatorFactory` provides advanced token validation capabilities (multi-provider support, failover, circuit breakers, health monitoring) while maintaining the simple `CustomTokenVerificationPort<T>` interface that the `AuthenticationMiddleware` expects.

## Quick Start

### 1. Simple Factory + Custom Verifier Pattern

Create a custom verifier that wraps the factory:

```typescript
// jwt-verifier.ts - Custom verifier that uses the factory
import { TokenValidatorFactory, ValidatorFactoryConfig } from '@/auth/token-validator-factory';
import { CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';
import { AuthProviderType } from '@/types/auth.types';

// Define your user type
interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  sub: string;
  exp: number;
  iat: number;
}

// Factory configuration
const factoryConfig: ValidatorFactoryConfig = {
  primaryProvider: AuthProviderType.JWT,
  providers: {
    [AuthProviderType.JWT]: {
      secret: process.env.JWT_SECRET!,
      issuer: 'my-app',
      audience: 'my-api'
    }
  },
  settings: {
    enableFailover: false,
    maxFailoverAttempts: 1,
    circuitBreakerThreshold: 5,
    circuitBreakerResetTimeout: 60000,
    enableHealthMonitoring: false,
    healthCheckInterval: 30000
  }
};

// Create the factory
const validatorFactory = new TokenValidatorFactory(factoryConfig);

// Custom verifier that wraps the factory
export class JWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    // Use the factory to validate the token
    const validator = validatorFactory.getPrimaryValidator();
    const result = await validator.validateToken(token);
    
    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Token validation failed');
    }
    
    // Transform the decoded token into your User type
    return {
      id: result.decoded.sub || '',
      email: result.decoded.email || '',
      name: result.decoded.name || '',
      roles: result.decoded.roles || [],
      sub: result.decoded.sub || '',
      exp: result.decoded.exp || 0,
      iat: result.decoded.iat || 0
    };
  }
}
```

### 2. Usage in Handlers

Use the exact same pattern as the standard authentication middleware:

```typescript
// user-handlers.ts
import { Handler } from '@/core/handler';
import { AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';
import { JWTVerifier } from './jwt-verifier';

// Simple reusable handler - exactly like standard pattern
const userProfileHandler = new Handler()
  .use(new AuthenticationMiddleware(new JWTVerifier()))
  .handle(async (request, context) => {
    const user = context.user as User;
    const profile = await getUserProfile(user.id);
    return { success: true, data: profile };
  });

// Another handler using the same pattern
const updateProfileHandler = new Handler()
  .use(new AuthenticationMiddleware(new JWTVerifier()))
  .handle(async (request, context) => {
    const user = context.user as User;
    const updatedProfile = await updateUserProfile(user.id, request.body);
    return { success: true, data: updatedProfile };
  });

// Admin handler with role checking
const adminDashboardHandler = new Handler()
  .use(new AuthenticationMiddleware(new JWTVerifier()))
  .handle(async (request, context) => {
    const user = context.user as User;
    
    if (!user.roles.includes('admin')) {
      throw new Error('Admin access required');
    }
    
    const dashboardData = await getAdminDashboard();
    return { success: true, data: dashboardData };
  });
```

## Singleton Pattern for Maximum Reusability

For better performance and consistency, create the authentication middleware once and reuse it:

### 1. Single Setup File

```typescript
// auth.ts - Single file setup
import { TokenValidatorFactory } from '@/auth/token-validator-factory';
import { CustomTokenVerificationPort, AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';
import { AuthProviderType } from '@/types/auth.types';

interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
  sub: string;
  exp: number;
  iat: number;
}

// Create factory once
const factory = new TokenValidatorFactory({
  primaryProvider: AuthProviderType.JWT,
  providers: {
    [AuthProviderType.JWT]: {
      secret: process.env.JWT_SECRET!,
      issuer: 'my-app',
      audience: 'my-api'
    }
  },
  settings: {
    enableFailover: false,
    maxFailoverAttempts: 1,
    circuitBreakerThreshold: 5,
    circuitBreakerResetTimeout: 60000,
    enableHealthMonitoring: false,
    healthCheckInterval: 30000
  }
});

// Simple verifier
class SimpleJWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    const result = await factory.validateToken(token);
    
    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Invalid token');
    }
    
    return {
      id: result.decoded.sub || '',
      email: result.decoded.email || '',
      name: result.decoded.name || '',
      roles: result.decoded.roles || [],
      sub: result.decoded.sub || '',
      exp: result.decoded.exp || 0,
      iat: result.decoded.iat || 0
    };
  }
}

// Export reusable auth middleware
export const authMiddleware = new AuthenticationMiddleware(new SimpleJWTVerifier());
```

### 2. Use Across Multiple Handlers

```typescript
// handlers.ts
import { Handler } from '@/core/handler';
import { authMiddleware } from './auth'; // Import the reusable middleware

// Handler 1 - clean and simple
const userProfileHandler = new Handler()
  .use(authMiddleware)
  .handle(async (request, context) => {
    const user = context.user as User;
    const profile = await getUserProfile(user.id);
    return { success: true, data: profile };
  });

// Handler 2 - same pattern
const ordersHandler = new Handler()
  .use(authMiddleware)
  .handle(async (request, context) => {
    const user = context.user as User;
    const orders = await getUserOrders(user.id);
    return { success: true, data: orders };
  });

// Handler 3 - same pattern
const settingsHandler = new Handler()
  .use(authMiddleware)
  .handle(async (request, context) => {
    const user = context.user as User;
    const settings = await getUserSettings(user.id);
    return { success: true, data: settings };
  });

// Export for GCP Functions
export const getUserProfile = http('getUserProfile', (req, res) => {
  return userProfileHandler.execute(req, res);
});

export const getUserOrders = http('getUserOrders', (req, res) => {
  return ordersHandler.execute(req, res);
});

export const getUserSettings = http('getUserSettings', (req, res) => {
  return settingsHandler.execute(req, res);
});
```

## Advanced Configuration

### Multi-Provider Setup with Failover

```typescript
// advanced-auth.ts
import { TokenValidatorFactory, ValidatorFactoryConfig } from '@/auth/token-validator-factory';
import { AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';
import { AuthProviderType } from '@/types/auth.types';

const advancedConfig: ValidatorFactoryConfig = {
  primaryProvider: AuthProviderType.JWT,
  fallbackProviders: [AuthProviderType.FIREBASE], // Automatic failover
  providers: {
    [AuthProviderType.JWT]: {
      secret: process.env.JWT_SECRET!,
      issuer: 'my-app',
      audience: 'my-api',
      algorithms: ['HS256', 'RS256']
    },
    [AuthProviderType.FIREBASE]: {
      projectId: process.env.FIREBASE_PROJECT_ID!,
      audience: 'my-firebase-app'
    }
  },
  settings: {
    enableFailover: true,              // Enable automatic failover
    maxFailoverAttempts: 3,            // Try up to 3 providers
    circuitBreakerThreshold: 5,        // Open circuit after 5 failures
    circuitBreakerResetTimeout: 60000, // Reset after 1 minute
    enableHealthMonitoring: true,      // Monitor validator health
    healthCheckInterval: 30000         // Check every 30 seconds
  }
};

const advancedFactory = new TokenValidatorFactory(advancedConfig);

// Advanced verifier with failover capabilities
class AdvancedJWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    // Factory automatically handles failover between JWT and Firebase
    const result = await advancedFactory.validateToken(token);
    
    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Token validation failed');
    }
    
    // The factory metadata tells us which provider was used
    console.log(`Token validated using: ${result.metadata?.validatorType}`);
    
    return {
      id: result.decoded.sub || '',
      email: result.decoded.email || '',
      name: result.decoded.name || '',
      roles: result.decoded.roles || [],
      sub: result.decoded.sub || '',
      exp: result.decoded.exp || 0,
      iat: result.decoded.iat || 0
    };
  }
}

export const advancedAuthMiddleware = new AuthenticationMiddleware(
  new AdvancedJWTVerifier(),
  {
    maxTokenAge: 3600,      // 1 hour max token age
    clockTolerance: 60,     // 1 minute clock tolerance
    requiredClaims: {
      issuer: 'my-app',
      audience: ['my-api', 'my-firebase-app']
    }
  }
);
```

### Social Authentication (Google & Facebook)

For applications that need to support social authentication providers like Google and Facebook, you can configure the factory to handle OAuth tokens:

```typescript
// social-auth.ts
import { TokenValidatorFactory, ValidatorFactoryConfig } from '@/auth/token-validator-factory';
import { AuthenticationMiddleware, CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';
import { AuthProviderType } from '@/types/auth.types';
import { OAuth2Client } from 'google-auth-library';
import axios from 'axios';

// Extended user interface for social providers
interface SocialUser extends User {
  provider: 'google' | 'facebook' | 'jwt';
  providerId: string;
  picture?: string;
  verified_email?: boolean;
}

// Google OAuth configuration
const googleConfig = {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  audience: process.env.GOOGLE_CLIENT_ID!
};

// Facebook OAuth configuration
const facebookConfig = {
  appId: process.env.FACEBOOK_APP_ID!,
  appSecret: process.env.FACEBOOK_APP_SECRET!,
  version: 'v18.0'
};

// Create a custom token validator for Google
class GoogleTokenValidator {
  private client: OAuth2Client;

  constructor() {
    this.client = new OAuth2Client(googleConfig.clientId);
  }

  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
    metadata?: any;
  }> {
    try {
      const ticket = await this.client.verifyIdToken({
        idToken: token,
        audience: googleConfig.clientId,
      });

      const payload = ticket.getPayload();
      
      if (!payload) {
        return { valid: false, error: 'Invalid Google token payload' };
      }

      return {
        valid: true,
        decoded: {
          sub: payload.sub,
          email: payload.email,
          name: payload.name,
          picture: payload.picture,
          email_verified: payload.email_verified,
          provider: 'google',
          providerId: payload.sub,
          iss: payload.iss,
          aud: payload.aud,
          exp: payload.exp,
          iat: payload.iat
        },
        metadata: {
          validatorType: 'google',
          cached: false,
          validationTimeUs: 0
        }
      };
    } catch (error) {
      return { 
        valid: false, 
        error: `Google token validation failed: ${error.message}` 
      };
    }
  }
}

// Create a custom token validator for Facebook
class FacebookTokenValidator {
  async validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
    metadata?: any;
  }> {
    try {
      // Verify token with Facebook Graph API
      const response = await axios.get(
        `https://graph.facebook.com/me?access_token=${token}&fields=id,name,email,picture`
      );

      const userData = response.data;

      if (!userData.id) {
        return { valid: false, error: 'Invalid Facebook token' };
      }

      // Get additional token info
      const tokenInfoResponse = await axios.get(
        `https://graph.facebook.com/debug_token?input_token=${token}&access_token=${facebookConfig.appId}|${facebookConfig.appSecret}`
      );

      const tokenInfo = tokenInfoResponse.data.data;

      if (!tokenInfo.is_valid) {
        return { valid: false, error: 'Facebook token is not valid' };
      }

      return {
        valid: true,
        decoded: {
          sub: userData.id,
          email: userData.email,
          name: userData.name,
          picture: userData.picture?.data?.url,
          provider: 'facebook',
          providerId: userData.id,
          exp: tokenInfo.expires_at,
          iat: tokenInfo.issued_at
        },
        metadata: {
          validatorType: 'facebook',
          cached: false,
          validationTimeUs: 0
        }
      };
    } catch (error) {
      return { 
        valid: false, 
        error: `Facebook token validation failed: ${error.message}` 
      };
    }
  }
}

// Multi-provider configuration with social authentication
const socialAuthConfig: ValidatorFactoryConfig = {
  primaryProvider: AuthProviderType.JWT,
  fallbackProviders: [AuthProviderType.FIREBASE],
  providers: {
    [AuthProviderType.JWT]: {
      secret: process.env.JWT_SECRET!,
      issuer: 'my-app',
      audience: 'my-api'
    },
    [AuthProviderType.FIREBASE]: {
      projectId: process.env.FIREBASE_PROJECT_ID!
    },
    // Custom providers can be added to extend the factory
    ['GOOGLE' as AuthProviderType]: googleConfig,
    ['FACEBOOK' as AuthProviderType]: facebookConfig
  },
  settings: {
    enableFailover: true,
    maxFailoverAttempts: 4, // JWT -> Firebase -> Google -> Facebook
    circuitBreakerThreshold: 3,
    circuitBreakerResetTimeout: 60000,
    enableHealthMonitoring: true,
    healthCheckInterval: 30000
  }
};

// Multi-provider verifier that handles different token types
class SocialAuthVerifier implements CustomTokenVerificationPort<SocialUser> {
  private jwtFactory: TokenValidatorFactory;
  private googleValidator: GoogleTokenValidator;
  private facebookValidator: FacebookTokenValidator;

  constructor() {
    this.jwtFactory = new TokenValidatorFactory(socialAuthConfig);
    this.googleValidator = new GoogleTokenValidator();
    this.facebookValidator = new FacebookTokenValidator();
  }

  async verifyToken(token: string): Promise<SocialUser> {
    // Determine token type based on format
    const tokenType = this.detectTokenType(token);

    let result;
    
    switch (tokenType) {
      case 'google':
        result = await this.googleValidator.validateToken(token);
        break;
      case 'facebook':
        result = await this.facebookValidator.validateToken(token);
        break;
      case 'jwt':
      default:
        // Use the factory for JWT and Firebase tokens
        result = await this.jwtFactory.validateToken(token);
        break;
    }

    if (!result.valid || !result.decoded) {
      throw new Error(result.error || 'Token validation failed');
    }

    return this.transformToSocialUser(result.decoded, tokenType);
  }

  private detectTokenType(token: string): 'jwt' | 'google' | 'facebook' {
    // Google ID tokens are JWT format but much longer
    if (token.startsWith('eyJ') && token.length > 500) {
      return 'google';
    }
    
    // Facebook access tokens are usually shorter alphanumeric strings
    if (!token.includes('.') && token.length > 50 && token.length < 300) {
      return 'facebook';
    }
    
    // Default to JWT
    return 'jwt';
  }

  private transformToSocialUser(decoded: any, provider: string): SocialUser {
    return {
      id: decoded.providerId || decoded.sub || '',
      email: decoded.email || '',
      name: decoded.name || '',
      roles: decoded.roles || ['user'], // Default role for social users
      sub: decoded.sub || decoded.providerId || '',
      exp: decoded.exp || 0,
      iat: decoded.iat || 0,
      provider: decoded.provider || provider as 'google' | 'facebook' | 'jwt',
      providerId: decoded.providerId || decoded.sub || '',
      picture: decoded.picture,
      verified_email: decoded.email_verified || decoded.verified_email
    };
  }
}

// Export social authentication middleware
export const socialAuthMiddleware = new AuthenticationMiddleware(
  new SocialAuthVerifier(),
  {
    maxTokenAge: 3600,
    clockTolerance: 60,
    // Don't require specific claims for social tokens
  }
);
```

### Using Social Authentication in Handlers

```typescript
// social-handlers.ts
import { Handler } from '@/core/handler';
import { socialAuthMiddleware } from './social-auth';

// Handler that accepts Google, Facebook, or JWT tokens
const profileHandler = new Handler()
  .use(socialAuthMiddleware)
  .handle(async (request, context) => {
    const user = context.user as SocialUser;
    
    // Handle different provider types
    let profileData;
    switch (user.provider) {
      case 'google':
        profileData = await getGoogleUserProfile(user.providerId);
        break;
      case 'facebook':
        profileData = await getFacebookUserProfile(user.providerId);
        break;
      default:
        profileData = await getStandardUserProfile(user.id);
    }
    
    return {
      success: true,
      data: {
        ...profileData,
        provider: user.provider,
        picture: user.picture,
        verified_email: user.verified_email
      }
    };
  });

// Provider-specific handlers
const googleOnlyHandler = new Handler()
  .use(new AuthenticationMiddleware(new GoogleTokenValidator()))
  .handle(async (request, context) => {
    const user = context.user as SocialUser;
    // This handler only accepts Google tokens
    return { success: true, data: await getGoogleSpecificData(user.providerId) };
  });

const facebookOnlyHandler = new Handler()
  .use(new AuthenticationMiddleware(new FacebookTokenValidator()))
  .handle(async (request, context) => {
    const user = context.user as SocialUser;
    // This handler only accepts Facebook tokens
    return { success: true, data: await getFacebookSpecificData(user.providerId) };
  });
```

### Environment Variables for Social Authentication

```bash
# .env file
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Facebook OAuth
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret

# Standard JWT
JWT_SECRET=your-jwt-secret
JWT_ISSUER=my-app
JWT_AUDIENCE=my-api

# Firebase
FIREBASE_PROJECT_ID=your-firebase-project
```

### Required Dependencies

```json
{
  "dependencies": {
    "google-auth-library": "^9.0.0",
    "axios": "^1.6.0"
  }
}
```

### Different Security Levels

```typescript
// security-levels.ts
import { AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';
import { JWTVerifier } from './jwt-verifier';

// Standard security for regular endpoints
export const standardAuth = new AuthenticationMiddleware(
  new JWTVerifier(),
  {
    maxTokenAge: 3600,    // 1 hour
    clockTolerance: 60    // 1 minute tolerance
  }
);

// High security for sensitive endpoints
export const highSecurityAuth = new AuthenticationMiddleware(
  new JWTVerifier(),
  {
    maxTokenAge: 1800,    // 30 minutes only
    clockTolerance: 30,   // 30 second tolerance
    requiredClaims: {
      issuer: 'my-app',
      audience: 'secure-api'
    }
  }
);

// Admin-only authentication
export const adminAuth = new AuthenticationMiddleware(
  new JWTVerifier(),
  {
    maxTokenAge: 900,     // 15 minutes for admin tokens
    clockTolerance: 15,   // Very tight tolerance
    requiredClaims: {
      issuer: 'my-app',
      audience: 'admin-api'
    }
  }
);
```

### Usage with Different Security Levels

```typescript
// secure-handlers.ts
import { Handler } from '@/core/handler';
import { standardAuth, highSecurityAuth, adminAuth } from './security-levels';

// Regular endpoint
const userDataHandler = new Handler()
  .use(standardAuth)
  .handle(async (request, context) => {
    const user = context.user as User;
    return { success: true, data: await getUserData(user.id) };
  });

// Sensitive endpoint (financial data)
const financialDataHandler = new Handler()
  .use(highSecurityAuth)
  .handle(async (request, context) => {
    const user = context.user as User;
    return { success: true, data: await getFinancialData(user.id) };
  });

// Admin endpoint
const adminDashboardHandler = new Handler()
  .use(adminAuth)
  .handle(async (request, context) => {
    const user = context.user as User;
    
    // Additional role check for admin endpoints
    if (!user.roles.includes('admin')) {
      throw new Error('Admin role required');
    }
    
    return { success: true, data: await getAdminDashboard() };
  });
```

## Error Handling

The factory provides detailed error information that you can use for better error handling:

```typescript
// error-aware-verifier.ts
export class ErrorAwareJWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    try {
      const result = await factory.validateToken(token);
      
      if (!result.valid) {
        // Factory provides specific error types
        if (result.error?.includes('expired')) {
          throw new Error('TOKEN_EXPIRED');
        } else if (result.error?.includes('invalid')) {
          throw new Error('TOKEN_INVALID');
        } else if (result.error?.includes('blacklisted')) {
          throw new Error('TOKEN_BLACKLISTED');
        } else {
          throw new Error('TOKEN_VERIFICATION_FAILED');
        }
      }
      
      return this.transformUser(result.decoded!);
    } catch (error) {
      // Handle factory-specific errors
      if (error.message.includes('Circuit breaker')) {
        throw new Error('AUTHENTICATION_SERVICE_UNAVAILABLE');
      }
      throw error;
    }
  }
  
  private transformUser(decoded: any): User {
    return {
      id: decoded.sub || '',
      email: decoded.email || '',
      name: decoded.name || '',
      roles: decoded.roles || [],
      sub: decoded.sub || '',
      exp: decoded.exp || 0,
      iat: decoded.iat || 0
    };
  }
}
```

## Performance Monitoring

Monitor the performance of your authentication:

```typescript
// monitoring.ts
export class MonitoredJWTVerifier implements CustomTokenVerificationPort<User> {
  async verifyToken(token: string): Promise<User> {
    const startTime = process.hrtime.bigint();
    
    try {
      const result = await factory.validateToken(token);
      
      const duration = Number(process.hrtime.bigint() - startTime) / 1000;
      console.log(`Token validation completed in ${duration.toFixed(1)}μs`);
      
      if (result.metadata?.cached) {
        console.log('Token validation result served from cache');
      }
      
      if (!result.valid || !result.decoded) {
        throw new Error(result.error || 'Token validation failed');
      }
      
      return this.transformUser(result.decoded);
    } catch (error) {
      const duration = Number(process.hrtime.bigint() - startTime) / 1000;
      console.error(`Token validation failed after ${duration.toFixed(1)}μs:`, error.message);
      throw error;
    }
  }
  
  private transformUser(decoded: any): User {
    return {
      id: decoded.sub || '',
      email: decoded.email || '',
      name: decoded.name || '',
      roles: decoded.roles || [],
      sub: decoded.sub || '',
      exp: decoded.exp || 0,
      iat: decoded.iat || 0
    };
  }
}
```

## Best Practices

### 1. Environment Configuration

```typescript
// config/auth-config.ts
export const getAuthConfig = (): ValidatorFactoryConfig => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    primaryProvider: AuthProviderType.JWT,
    fallbackProviders: isProduction ? [AuthProviderType.FIREBASE] : undefined,
    providers: {
      [AuthProviderType.JWT]: {
        secret: process.env.JWT_SECRET!,
        issuer: process.env.JWT_ISSUER || 'my-app',
        audience: process.env.JWT_AUDIENCE || 'my-api'
      },
      [AuthProviderType.FIREBASE]: isProduction ? {
        projectId: process.env.FIREBASE_PROJECT_ID!
      } : undefined
    },
    settings: {
      enableFailover: isProduction,
      maxFailoverAttempts: isProduction ? 3 : 1,
      circuitBreakerThreshold: 5,
      circuitBreakerResetTimeout: 60000,
      enableHealthMonitoring: isProduction,
      healthCheckInterval: 30000
    }
  };
};
```

### 2. Type Safety

```typescript
// types/auth.types.ts
export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  sub: string;
  exp: number;
  iat: number;
  department?: string;
  title?: string;
}

// Use with handlers for full type safety
const typedHandler = new Handler<any, AuthenticatedUser>()
  .use(authMiddleware)
  .handle(async (request, context) => {
    // context.user is now fully typed as AuthenticatedUser
    const user = context.user!;
    return { success: true, userId: user.id };
  });
```

### 3. Testing

```typescript
// test/auth.test.ts
describe('Authentication Integration', () => {
  it('should authenticate valid JWT tokens', async () => {
    const verifier = new JWTVerifier();
    const validToken = 'eyJ...'; // Your test token
    
    const user = await verifier.verifyToken(validToken);
    
    expect(user.id).toBeDefined();
    expect(user.email).toBeDefined();
    expect(user.roles).toBeInstanceOf(Array);
  });
  
  it('should reject invalid tokens', async () => {
    const verifier = new JWTVerifier();
    const invalidToken = 'invalid.token.here';
    
    await expect(verifier.verifyToken(invalidToken))
      .rejects.toThrow('Token validation failed');
  });
});
```

## Key Benefits

1. **Same Pattern**: Uses exactly the same syntax as standard authentication middleware
2. **Enterprise Features**: Gets circuit breakers, failover, health monitoring automatically
3. **Performance**: Built-in caching and optimization
4. **Flexibility**: Easy to switch between different validation strategies
5. **Type Safety**: Full TypeScript support with proper user typing
6. **Reusability**: Create once, use across all handlers
7. **Monitoring**: Built-in performance metrics and health checks
8. **Resilience**: Automatic failover and circuit breaker protection

## Summary

The `TokenValidatorFactory` integrates seamlessly with `AuthenticationMiddleware` through the `CustomTokenVerificationPort<T>` interface. This gives you:

- **Simple usage**: Same handler pattern you're already using
- **Advanced features**: Enterprise-grade authentication capabilities
- **Easy setup**: Minimal configuration for maximum functionality
- **High performance**: Built-in optimizations and caching
- **Production ready**: Monitoring, failover, and resilience patterns

Your handlers stay clean and simple while getting enterprise-grade authentication under the hood!