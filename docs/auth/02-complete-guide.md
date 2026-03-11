# RouteGuards Complete Setup and Usage Guide

A comprehensive guide to implementing authentication and authorization with the Noony Framework's RouteGuards system. This guide covers everything from basic setup to complex enterprise scenarios with detailed pros/cons analysis and decision-making guidance.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Permission Strategies Comparison](#permission-strategies-comparison)
3. [Authentication Methods Analysis](#authentication-methods-analysis)
4. [Simple Scenarios](#simple-scenarios)
5. [Complex Scenarios](#complex-scenarios)
6. [Performance Optimization](#performance-optimization)
7. [Production Deployment](#production-deployment)
8. [Decision Matrices](#decision-matrices)
9. [Real-World Examples](#real-world-examples)
10. [FAQ with Decision Guidance](#faq-with-decision-guidance)

## Quick Start

### Basic Setup with CustomTokenVerificationPort

The fastest way to get started with RouteGuards using the new integrated authentication system:

```typescript
import { RouteGuards, GuardSetup } from '@/middlewares/guards';
import { CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';

// 1. Define your user type
interface User {
  id: string;
  email: string;
  roles: string[];
  permissions: string[];
  sub: string;  // JWT subject
  exp: number;  // JWT expiration
}

// 2. Create token verifier (works with both systems!)
const tokenVerifier: CustomTokenVerificationPort<User> = {
  async verifyToken(token: string): Promise<User> {
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

// 3. Define permission source
const userPermissionSource = {
  async getUserPermissions(userId: string) {
    const user = await userService.getUser(userId);
    return {
      userId,
      permissions: user.permissions,
      roles: user.roles,
      metadata: { email: user.email, status: user.status }
    };
  }
};

// 4. One-line configuration (NEW!)
await RouteGuards.configureWithJWT(
  GuardSetup.production(),
  userPermissionSource,
  tokenVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: true
  }
);

// 5. Use in handlers
const handler = new Handler()
  .use(RouteGuards.requirePermissions(['user:read']))
  .handle(async (context) => {
    const user = context.user!; // Fully typed!
    return { profile: user };
  });
```

### Environment-Specific Setup

Choose the right configuration for your environment:

```typescript
// Development: Fast iteration, detailed logging
await RouteGuards.configure(
  GuardSetup.development(),
  userPermissionSource,
  tokenVerifier,
  authConfig
);

// Production: Maximum performance, conservative security
await RouteGuards.configure(
  GuardSetup.production(),
  userPermissionSource,
  tokenVerifier,
  authConfig
);

// Serverless: Optimized for cold starts
await RouteGuards.configure(
  GuardSetup.serverless(),
  userPermissionSource,
  tokenVerifier,
  authConfig
);
```

## Cache Control with Environment Variables

**NEW**: The RouteGuards system now supports environment variable-based cache control for enhanced security and flexibility.

### Security-First Caching Approach

By default, **caching is disabled** until explicitly enabled via the `NOONY_GUARD_CACHE_ENABLE` environment variable. This provides a security-first approach where sensitive permission data is never cached accidentally.

```bash
# Caching disabled (default - secure)
npm start

# Caching enabled (high performance)
NOONY_GUARD_CACHE_ENABLE=true npm start
```

### Environment Variable Behavior

The environment variable takes precedence over configuration settings:

| Configuration | Environment Variable | Effective Result |
|--------------|---------------------|------------------|
| `cacheType: 'memory'` | Not set | **No caching** |
| `cacheType: 'memory'` | `NOONY_GUARD_CACHE_ENABLE=true` | **Memory caching** |
| `cacheType: 'redis'` | Not set | **No caching** |
| `cacheType: 'redis'` | `NOONY_GUARD_CACHE_ENABLE=true` | **Redis caching** |
| `cacheType: 'none'` | Any value | **No caching** |

### Production Usage Examples

**Development with caching disabled (debugging):**
```bash
NODE_ENV=development npm run dev
# Logs: 🚫 Guard caching disabled by environment variable NOONY_GUARD_CACHE_ENABLE
```

**Production with caching enabled (recommended):**
```bash
NODE_ENV=production NOONY_GUARD_CACHE_ENABLE=true npm start
# Logs: ✅ RouteGuards configured successfully { cachingEnabled: true, effectiveCacheType: 'memory' }
```

**Docker deployment with caching:**
```dockerfile
ENV NOONY_GUARD_CACHE_ENABLE=true
```

**Kubernetes deployment:**
```yaml
env:
  - name: NOONY_GUARD_CACHE_ENABLE
    value: "true"
```

### Benefits of Environment Variable Control

**Security Benefits:**
- Prevents accidental caching of sensitive permission data
- Explicit opt-in for performance optimization
- Easy to disable caching for compliance requirements

**Operational Benefits:**
- Runtime cache control without code changes
- Easy debugging by disabling cache
- Environment-specific cache strategies

**Development Benefits:**
- Fast iteration with cache disabled
- Predictable behavior during development
- Easy troubleshooting of permission issues

---

## Complete Configuration Reference

This section provides comprehensive documentation for all RouteGuards configuration options, interfaces, and factory methods.

### Configuration Interfaces

#### GuardSecurityConfig Interface

Controls security policies and performance limits to prevent attacks.

```typescript
export interface GuardSecurityConfig {
  /** Strategy for resolving permissions (default: PRE_EXPANSION) */
  permissionResolutionStrategy?: PermissionResolutionStrategy;
  
  /** Whether to use conservative cache invalidation (default: true) */
  conservativeCacheInvalidation?: boolean;
  
  /** Maximum complexity for permission expressions (default: 100) */
  maxExpressionComplexity?: number;
  
  /** Maximum depth for wildcard patterns (default: 5) */
  maxPatternDepth?: number;
  
  /** Maximum nesting depth for boolean expressions (default: 3) */
  maxNestingDepth?: number;
}
```

**Property Details:**

- **permissionResolutionStrategy**: Choose between `PRE_EXPANSION` (faster runtime, more memory) or `ON_DEMAND` (slower runtime, less memory)
- **conservativeCacheInvalidation**: When `true`, related cache entries are cleared on any permission change. When `false`, only specific entries are invalidated
- **maxExpressionComplexity**: Prevents DoS attacks through complex boolean expressions
- **maxPatternDepth**: Limits patterns like 'admin.users.groups.permissions.*' to prevent deep recursion
- **maxNestingDepth**: Prevents deeply nested expressions like '((((A AND B) OR C) AND D) OR E)'

#### GuardCacheConfig Interface

Controls caching behavior for optimal performance with configurable TTL values.

```typescript
export interface GuardCacheConfig {
  /** Maximum number of entries to cache (default: 5000) */
  maxEntries: number;
  
  /** Default TTL in milliseconds for cached entries (default: 300000 = 5 minutes) */
  defaultTtlMs: number;
  
  /** TTL in milliseconds for user context cache (default: 600000 = 10 minutes) */
  userContextTtlMs: number;
  
  /** TTL in milliseconds for authentication token cache (default: 900000 = 15 minutes) */
  authTokenTtlMs: number;
}
```

**TTL Guidelines:**

| Environment | defaultTtlMs | userContextTtlMs | authTokenTtlMs | Security Level |
|-------------|--------------|------------------|----------------|----------------|
| Development | 5 min | 2 min | 2 min | Low (fast iteration) |
| Production | 15 min | 10 min | 5 min | High (performance) |
| High-Security | 2 min | 1 min | 30 sec | Maximum (quick revocation) |
| Testing | 1 sec | 1 sec | 1 sec | N/A (predictable) |

#### GuardMonitoringConfig Interface

Controls performance tracking, logging, and metrics collection.

```typescript
export interface GuardMonitoringConfig {
  /** Enable performance tracking for guard operations (default: true) */
  enablePerformanceTracking: boolean;
  
  /** Enable detailed logging for debugging (default: false in production) */
  enableDetailedLogging: boolean;
  
  /** Log level for guard system messages (default: 'info') */
  logLevel: string;
  
  /** Interval in milliseconds for metrics collection (default: 60000 = 1 minute) */
  metricsCollectionInterval: number;
}
```

**Log Level Options:**
- `'debug'`: All messages (development)
- `'info'`: General information (staging)
- `'warn'`: Warnings and errors (production)
- `'error'`: Only errors (high-security production)

#### GuardEnvironmentProfile Interface

Provides pre-configured profiles for different deployment environments.

```typescript
export interface GuardEnvironmentProfile {
  /** Environment name identifier */
  environment: string;
  
  /** Cache implementation type ('memory' | 'redis' | 'none') */
  cacheType: 'memory' | 'redis' | 'none';
  
  /** Security configuration for this environment */
  security: GuardSecurityConfig;
  
  /** Cache configuration for this environment */
  cache: GuardCacheConfig;
  
  /** Monitoring configuration for this environment */
  monitoring: GuardMonitoringConfig;
}
```

### Factory Configuration Methods

The RouteGuards class provides several factory methods for common authentication scenarios:

#### 1. JWT Token Configuration

```typescript
static async configureWithJWT<T extends { sub: string; exp?: number }>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  jwtVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig
): Promise<void>
```

**Example:**
```typescript
interface JWTUser {
  sub: string;
  email: string;
  roles: string[];
  exp: number;
}

const jwtVerifier: CustomTokenVerificationPort<JWTUser> = {
  async verifyToken(token: string): Promise<JWTUser> {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
    return {
      sub: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
      exp: payload.exp
    };
  }
};

await RouteGuards.configureWithJWT(
  GuardSetup.production(),
  userPermissionSource,
  jwtVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: true
  }
);
```

#### 2. API Key Configuration

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

**Example:**
```typescript
interface APIKeyUser {
  keyId: string;
  permissions: string[];
  organization: string;
  expiresAt?: number;
  isActive: boolean;
}

const apiKeyVerifier: CustomTokenVerificationPort<APIKeyUser> = {
  async verifyToken(token: string): Promise<APIKeyUser> {
    const keyData = await validateAPIKeyInDatabase(token);
    if (!keyData || !keyData.isActive) {
      throw new Error('Invalid or inactive API key');
    }
    return keyData;
  }
};

await RouteGuards.configureWithAPIKey(
  GuardSetup.production(),
  userPermissionSource,
  apiKeyVerifier,
  {
    tokenHeader: 'x-api-key',
    tokenPrefix: '',
    allowInactiveUsers: false
  },
  'keyId',
  'expiresAt'
);
```

**Custom API-Key Header Examples:**

```typescript
// Example 1: Custom header 'x-custom-key' with organization validation
interface CustomAPIKeyUser {
  keyId: string;
  permissions: string[];
  organization: string;
  scopes: string[];
  isActive: boolean;
  rateLimitTier: 'basic' | 'premium' | 'enterprise';
}

const customApiKeyVerifier: CustomTokenVerificationPort<CustomAPIKeyUser> = {
  async verifyToken(token: string): Promise<CustomAPIKeyUser> {
    // Validate API key format (e.g., must start with 'ck_' for custom keys)
    if (!token.startsWith('ck_')) {
      throw new Error('Invalid API key format');
    }
    
    const keyData = await validateAPIKeyInDatabase(token);
    if (!keyData || !keyData.isActive) {
      throw new Error('Invalid or inactive API key');
    }
    
    // Additional organization-level validation
    if (!keyData.organization) {
      throw new Error('API key must be associated with an organization');
    }
    
    return keyData;
  }
};

// Configure with custom header name
await RouteGuards.configureWithAPIKey(
  GuardSetup.production(),
  userPermissionSource,
  customApiKeyVerifier,
  {
    tokenHeader: 'x-custom-key',        // Custom header name
    tokenPrefix: '',                    // No prefix for API keys
    allowInactiveUsers: false,
    customValidation: async (token, user) => {
      // Additional validation: check if organization is active
      const org = await getOrganization(user.organization);
      return org && org.isActive;
    }
  },
  'keyId',
  undefined // No expiration field for this API key type
);

// Example 2: Multiple custom headers for different API key types
interface MultiAPIKeyUser {
  keyId: string;
  keyType: 'service' | 'personal' | 'webhook';
  permissions: string[];
  userId?: string;
  serviceId?: string;
  webhookId?: string;
  isActive: boolean;
}

const multiApiKeyVerifier: CustomTokenVerificationPort<MultiAPIKeyUser> = {
  async verifyToken(token: string): Promise<MultiAPIKeyUser> {
    let keyType: 'service' | 'personal' | 'webhook';
    
    // Determine key type based on prefix
    if (token.startsWith('sk_')) {
      keyType = 'service';
    } else if (token.startsWith('pk_')) {
      keyType = 'personal';
    } else if (token.startsWith('wk_')) {
      keyType = 'webhook';
    } else {
      throw new Error('Unknown API key type');
    }
    
    const keyData = await validateAPIKeyByType(token, keyType);
    if (!keyData || !keyData.isActive) {
      throw new Error(`Invalid or inactive ${keyType} API key`);
    }
    
    return { ...keyData, keyType };
  }
};

// You can use different headers for different key types in different handlers:
// For service keys - use 'x-service-key' header
await RouteGuards.configureWithAPIKey(
  GuardSetup.production(),
  userPermissionSource,
  multiApiKeyVerifier,
  {
    tokenHeader: 'x-service-key',
    tokenPrefix: '',
    allowInactiveUsers: false
  },
  'keyId'
);

// Example 3: API Gateway style with custom validation
interface GatewayAPIKeyUser {
  keyId: string;
  clientId: string;
  permissions: string[];
  quotaLimit: number;
  quotaUsed: number;
  isActive: boolean;
  metadata: {
    ipWhitelist?: string[];
    referrerWhitelist?: string[];
  };
}

const gatewayApiKeyVerifier: CustomTokenVerificationPort<GatewayAPIKeyUser> = {
  async verifyToken(token: string): Promise<GatewayAPIKeyUser> {
    const keyData = await validateGatewayAPIKey(token);
    if (!keyData || !keyData.isActive) {
      throw new Error('Invalid or inactive API key');
    }
    
    // Check quota limits
    if (keyData.quotaUsed >= keyData.quotaLimit) {
      throw new Error('API key quota exceeded');
    }
    
    return keyData;
  }
};

await RouteGuards.configureWithAPIKey(
  GuardSetup.production(),
  userPermissionSource,
  gatewayApiKeyVerifier,
  {
    tokenHeader: 'x-api-gateway-key',   // API Gateway style header
    tokenPrefix: '',
    allowInactiveUsers: false,
    customValidation: async (token, user, context) => {
      // IP-based validation
      const clientIP = context?.req.headers['x-forwarded-for'] || context?.req.connection.remoteAddress;
      if (user.metadata.ipWhitelist && clientIP) {
        return user.metadata.ipWhitelist.includes(clientIP);
      }
      
      // Referrer-based validation
      const referrer = context?.req.headers['referer'];
      if (user.metadata.referrerWhitelist && referrer) {
        return user.metadata.referrerWhitelist.some(allowed => referrer.includes(allowed));
      }
      
      return true;
    }
  },
  'keyId'
);
```

**Common API-Key Header Names:**

| Header Name | Usage | Example |
|-------------|-------|---------|
| `x-api-key` | Standard API key | `x-api-key: abc123def456` |
| `x-custom-key` | Custom application key | `x-custom-key: ck_1234567890` |
| `x-service-key` | Service-to-service auth | `x-service-key: sk_service_key_here` |
| `x-webhook-key` | Webhook authentication | `x-webhook-key: wk_webhook_secret` |
| `x-client-key` | Client application key | `x-client-key: client_abc123` |
| `x-integration-key` | Third-party integration | `x-integration-key: int_xyz789` |
| `x-api-gateway-key` | API Gateway style | `x-api-gateway-key: gateway_key_123` |

**Usage Examples:**

```bash
# Standard API key header
curl -H "x-api-key: your-api-key-here" https://api.example.com/endpoint

# Custom header with service key
curl -H "x-service-key: sk_your-service-key" https://api.example.com/service-endpoint

# API Gateway style
curl -H "x-api-gateway-key: your-gateway-key" https://api.example.com/gateway-endpoint
```

#### 3. OAuth Token Configuration

```typescript
static async configureWithOAuth<T extends { sub: string; exp?: number; scope?: string[] }>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  oauthVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig,
  requiredScopes?: string[]
): Promise<void>
```

**Example:**
```typescript
interface OAuthUser {
  sub: string;
  email: string;
  scope: string[];
  exp: number;
  client_id: string;
}

const oauthVerifier: CustomTokenVerificationPort<OAuthUser> = {
  async verifyToken(token: string): Promise<OAuthUser> {
    const response = await fetch(`${OAUTH_INTROSPECT_URL}`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: new URLSearchParams({ token })
    });

    const tokenInfo = await response.json();
    if (!tokenInfo.active) {
      throw new Error('Token is not active');
    }

    return tokenInfo as OAuthUser;
  }
};

await RouteGuards.configureWithOAuth(
  GuardSetup.production(),
  userPermissionSource,
  oauthVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: false
  },
  ['read:profile', 'write:data'] // Required OAuth scopes
);
```

#### 4. Custom Token Configuration

```typescript
static async configureWithCustom<T>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  customVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig,
  adapterConfig: AdapterConfig<T>
): Promise<void>
```

**Example:**
```typescript
interface CustomUser {
  userId: string;
  tenantId: string;
  roles: string[];
  sessionExpiry: number;
  isVerified: boolean;
}

const customVerifier: CustomTokenVerificationPort<CustomUser> = {
  async verifyToken(token: string): Promise<CustomUser> {
    return await verifyCustomToken(token);
  }
};

await RouteGuards.configureWithCustom(
  GuardSetup.production(),
  userPermissionSource,
  customVerifier,
  {
    tokenHeader: 'x-auth-token',
    tokenPrefix: 'Custom ',
    customValidation: async (token, user) => {
      return user.isVerified && user.tenantId === 'valid-tenant';
    }
  },
  {
    userIdExtractor: (user) => user.userId,
    expirationExtractor: (user) => user.sessionExpiry,
    additionalValidation: (user) => user.isVerified
  }
);
```

#### 5. Basic Authentication Configuration

```typescript
static async configureWithCustom<T>(
  profile: GuardEnvironmentProfile,
  permissionSource: UserPermissionSource,
  basicAuthVerifier: CustomTokenVerificationPort<T>,
  authConfig: AuthGuardConfig,
  adapterConfig: AdapterConfig<T>
): Promise<void>
```

Basic Authentication uses the `Authorization: Basic <base64>` header where the base64 string contains `username:password`.

**Example:**
```typescript
interface BasicAuthUser {
  username: string;
  userId: string;
  permissions: string[];
  roles: string[];
  email: string;
  isActive: boolean;
}

const basicAuthVerifier: CustomTokenVerificationPort<BasicAuthUser> = {
  async verifyToken(token: string): Promise<BasicAuthUser> {
    try {
      // Decode base64 credentials
      const credentials = Buffer.from(token, 'base64').toString('ascii');
      const [username, password] = credentials.split(':');
      
      if (!username || !password) {
        throw new Error('Invalid credentials format');
      }
      
      // Validate credentials against your user database
      const user = await validateUserCredentials(username, password);
      if (!user) {
        throw new Error('Invalid username or password');
      }
      
      // Check if user account is active
      if (!user.isActive) {
        throw new Error('User account is disabled');
      }
      
      // Load user permissions from your permission system
      const userPermissions = await getUserPermissions(user.id);
      
      return {
        username: user.username,
        userId: user.id,
        permissions: userPermissions.permissions,
        roles: userPermissions.roles,
        email: user.email,
        isActive: user.isActive
      };
    } catch (error) {
      throw new Error(`Basic authentication failed: ${error.message}`);
    }
  }
};

// Helper function to validate user credentials (implement your own logic)
async function validateUserCredentials(username: string, password: string): Promise<{ 
  id: string; 
  username: string; 
  email: string; 
  isActive: boolean; 
} | null> {
  // Example implementation - replace with your actual validation logic
  const user = await userDatabase.findByUsername(username);
  if (!user) {
    return null;
  }
  
  // Use proper password hashing (bcrypt, scrypt, etc.)
  const isValidPassword = await bcrypt.compare(password, user.hashedPassword);
  if (!isValidPassword) {
    return null;
  }
  
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    isActive: user.isActive
  };
}

// Configure RouteGuards with Basic Authentication
await RouteGuards.configureWithCustom(
  GuardSetup.production(),
  userPermissionSource,
  basicAuthVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Basic ',
    allowInactiveUsers: false,
    requireEmailVerification: false, // Usually not applicable for Basic Auth
    customValidation: async (token, user) => {
      // Additional validation logic if needed
      return user.isActive && user.permissions.length > 0;
    }
  },
  {
    userIdExtractor: (user) => user.userId,
    additionalValidation: (user) => user.isActive && user.permissions.length > 0,
    errorMessage: 'Basic authentication failed'
  }
);
```

**Security Considerations for Basic Auth:**

- **Always use HTTPS**: Basic Auth credentials are base64 encoded (not encrypted)
- **Strong Passwords**: Implement password complexity requirements
- **Password Hashing**: Use bcrypt, scrypt, or Argon2 for password storage
- **Rate Limiting**: Implement rate limiting to prevent brute force attacks
- **Account Lockout**: Lock accounts after failed attempts
- **Audit Logging**: Log all authentication attempts for security monitoring

**Usage Example:**

```bash
# Client sends Basic Auth header
curl -H "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=" \
     https://api.example.com/protected-endpoint

# Where "dXNlcm5hbWU6cGFzc3dvcmQ=" is base64 encoding of "username:password"
```

### Authentication Methods Comparison

This comprehensive comparison helps you choose the right authentication method for your use case.

#### Overview Table

| Authentication Method | Security Level | Implementation Complexity | Performance | Use Cases | Header Format |
|----------------------|----------------|---------------------------|-------------|-----------|---------------|
| **JWT** | High | Medium | High (cached) | Web apps, SPAs, mobile apps | `Authorization: Bearer <jwt>` |
| **Basic Auth** | Low-Medium | Low | Medium | Internal APIs, dev environments | `Authorization: Basic <base64>` |
| **API Keys** | Medium-High | Low | High (cached) | Service-to-service, third-party | `x-api-key: <key>` |
| **OAuth** | High | High | Medium | Third-party integrations | `Authorization: Bearer <token>` |
| **Custom** | Variable | High | Variable | Special requirements | `<custom-header>: <token>` |

#### Detailed Comparison

##### 1. JWT (JSON Web Tokens)

**Strengths:**
- **Stateless**: No server-side session storage required
- **Rich Claims**: Can contain user info, permissions, roles
- **Industry Standard**: Widely adopted and supported
- **Expiration Built-in**: Automatic token expiration handling
- **Cross-Service**: Works across different services/domains

**Weaknesses:**
- **Token Size**: Larger than simple API keys
- **Revocation Complexity**: Hard to revoke before expiration
- **Key Management**: Requires secure key/secret management

**Best For:**
- Single Page Applications (SPAs)
- Mobile applications
- Microservices architecture
- User-facing applications with complex permissions

**Configuration Difficulty:** ⭐⭐⭐ (Medium)
**Security Level:** ⭐⭐⭐⭐⭐ (High)
**Performance:** ⭐⭐⭐⭐⭐ (Excellent with caching)

```typescript
// JWT Configuration Example
await RouteGuards.configureWithJWT(
  GuardSetup.production(),
  userPermissionSource,
  jwtVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: true
  }
);
```

##### 2. Basic Authentication

**Strengths:**
- **Simplicity**: Easy to implement and understand
- **Universal Support**: Supported by all HTTP clients
- **No Setup**: No token generation/management needed
- **Debugging Friendly**: Easy to test with curl/Postman

**Weaknesses:**
- **Security Risk**: Credentials sent with every request
- **No Expiration**: Passwords don't auto-expire
- **Base64 Encoding**: Not encryption (easily decoded)
- **Brute Force Risk**: Vulnerable to brute force attacks

**Best For:**
- Development environments
- Internal APIs with trusted networks
- Simple services with basic security needs
- Legacy system integration

**Configuration Difficulty:** ⭐ (Easy)
**Security Level:** ⭐⭐ (Low-Medium)
**Performance:** ⭐⭐⭐ (Good with caching)

```typescript
// Basic Auth Configuration Example
await RouteGuards.configureWithCustom(
  GuardSetup.production(),
  userPermissionSource,
  basicAuthVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Basic '
  }
);
```

##### 3. API Keys

**Strengths:**
- **Simple Implementation**: Easy to generate and validate
- **Good Performance**: Fast lookup and validation
- **Flexible Headers**: Can use any custom header name
- **Revocation Control**: Easy to revoke specific keys
- **Usage Tracking**: Can track usage per key

**Weaknesses:**
- **Key Management**: Need secure key storage
- **Limited Context**: Usually just identify, not authenticate users
- **Rotation Complexity**: Manual key rotation process
- **Exposure Risk**: Keys can be logged or exposed

**Best For:**
- Service-to-service authentication
- Third-party API access
- Webhook authentication
- Rate limiting by client
- Simple client identification

**Configuration Difficulty:** ⭐⭐ (Easy-Medium)
**Security Level:** ⭐⭐⭐⭐ (Medium-High)
**Performance:** ⭐⭐⭐⭐⭐ (Excellent)

```typescript
// API Key Configuration Example
await RouteGuards.configureWithAPIKey(
  GuardSetup.production(),
  userPermissionSource,
  apiKeyVerifier,
  {
    tokenHeader: 'x-api-key', // Custom header
    tokenPrefix: ''
  },
  'keyId'
);
```

##### 4. OAuth Tokens

**Strengths:**
- **Industry Standard**: OAuth 2.0/OpenID Connect compliance
- **Delegation**: Users don't share credentials directly
- **Scope Control**: Fine-grained permission scopes
- **Third-party Integration**: Works with Google, GitHub, etc.
- **Token Introspection**: Can validate with OAuth provider

**Weaknesses:**
- **Complexity**: Requires OAuth flow implementation
- **Network Dependency**: May need external validation
- **Setup Overhead**: OAuth provider configuration required
- **Token Management**: Refresh token handling complexity

**Best For:**
- Third-party application integration
- Social login scenarios
- Enterprise SSO integration
- Applications requiring delegated access
- Multi-tenant systems with external identity providers

**Configuration Difficulty:** ⭐⭐⭐⭐ (High)
**Security Level:** ⭐⭐⭐⭐⭐ (High)
**Performance:** ⭐⭐⭐ (Medium, depends on validation)

```typescript
// OAuth Configuration Example
await RouteGuards.configureWithOAuth(
  GuardSetup.production(),
  userPermissionSource,
  oauthVerifier,
  {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer '
  },
  ['read:profile', 'write:data'] // Required scopes
);
```

##### 5. Custom Authentication

**Strengths:**
- **Flexibility**: Complete control over authentication logic
- **Tailored Security**: Custom security measures for specific needs
- **Integration**: Can integrate with any existing system
- **Innovation**: Support for new/experimental auth methods

**Weaknesses:**
- **Development Time**: Requires custom implementation
- **Security Risk**: Custom crypto is error-prone
- **Maintenance**: Full responsibility for security updates
- **Testing**: Extensive security testing required

**Best For:**
- Legacy system integration
- Specialized security requirements
- Existing proprietary authentication
- Experimental authentication methods
- Highly regulated industries

**Configuration Difficulty:** ⭐⭐⭐⭐⭐ (Very High)
**Security Level:** ⭐⭐⭐ (Variable)
**Performance:** ⭐⭐⭐ (Variable)

```typescript
// Custom Configuration Example
await RouteGuards.configureWithCustom(
  GuardSetup.production(),
  userPermissionSource,
  customVerifier,
  customAuthConfig,
  customAdapterConfig
);
```

#### Decision Matrix

Use this matrix to choose the right authentication method:

| Your Need | Recommended Method | Alternative |
|-----------|-------------------|-------------|
| **Web Application with Users** | JWT | OAuth (if external identity) |
| **Mobile Application** | JWT | OAuth (for social login) |
| **Service-to-Service** | API Keys | JWT (for complex permissions) |
| **Third-party Integration** | OAuth | API Keys (if simple) |
| **Development/Testing** | Basic Auth | JWT (for production-like) |
| **Legacy System Integration** | Custom | Basic Auth (if supported) |
| **Microservices** | JWT | API Keys (for simple services) |
| **Webhook Authentication** | API Keys | Custom (for complex validation) |
| **High Security Requirements** | JWT + MFA | OAuth + Custom validation |
| **Simple Internal Tools** | Basic Auth | API Keys |

#### Security Considerations by Method

| Method | HTTPS Required | Credential Storage | Revocation | Audit Trail |
|--------|----------------|-------------------|------------|-------------|
| JWT | ⚠️ Recommended | Client-side | ❌ Complex | ✅ Good |
| Basic Auth | ⚡ **MANDATORY** | Every request | ✅ Easy | ✅ Good |
| API Keys | ⚠️ Recommended | Client config | ✅ Easy | ✅ Excellent |
| OAuth | ⚠️ Recommended | Token storage | ✅ Provider handles | ✅ Excellent |
| Custom | ⚡ **DEPENDS** | Custom logic | Custom logic | Custom logic |

### RouteGuardOptions Interface

Provides fine-grained control over guard behavior for specific endpoints.

```typescript
export interface RouteGuardOptions {
  /** Enable authentication requirement (default: true) */
  requireAuth?: boolean;
  
  /** Enable permission result caching (default: true) */
  cacheResults?: boolean;
  
  /** Enable detailed audit logging (default: false) */
  auditTrail?: boolean;
  
  /** Custom error message for access denials */
  errorMessage?: string;
  
  /** Cache TTL in milliseconds (overrides global config) */
  cacheTtlMs?: number;
}
```

**Usage Examples:**

```typescript
// High-security endpoint with audit trail
const secureOptions: RouteGuardOptions = {
  requireAuth: true,
  cacheResults: false, // Always check fresh permissions
  auditTrail: true,    // Enable detailed logging
  errorMessage: 'Unauthorized access to sensitive data',
  cacheTtlMs: 30000    // Short cache TTL for security
};

const sensitiveHandler = new Handler()
  .use(RouteGuards.requirePermissions(['sensitive:access'], secureOptions))
  .handle(async (context) => {
    return { success: true, data: 'sensitive information' };
  });

// Public endpoint with authentication check only
const publicOptions: RouteGuardOptions = {
  requireAuth: false,  // Allow unauthenticated access
  cacheResults: true,
  auditTrail: false
};

const publicHandler = new Handler()
  .use(RouteGuards.requirePermissions(['public:read'], publicOptions))
  .handle(async (context) => {
    return { success: true, data: 'public data' };
  });
```

### Security Considerations and Best Practices

This section covers essential security considerations and best practices for implementing authentication with RouteGuards.

#### General Security Principles

##### 1. Defense in Depth
- **Multiple Layers**: Combine authentication with authorization, input validation, and rate limiting
- **Fail Secure**: When in doubt, deny access rather than allow
- **Principle of Least Privilege**: Grant minimum permissions required for functionality

##### 2. Token Security
- **Secure Storage**: Store tokens securely (never in localStorage for sensitive apps)
- **Token Rotation**: Implement regular token rotation mechanisms
- **Expiration**: Always use appropriate token expiration times
- **Revocation**: Implement token blacklisting/revocation capabilities

##### 3. Transport Security
- **HTTPS Only**: Always use HTTPS in production, especially for Basic Auth
- **Header Security**: Use secure headers (HSTS, CSP, etc.)
- **Certificate Validation**: Ensure proper SSL/TLS certificate validation

#### Authentication-Specific Security

##### Basic Authentication Security
```typescript
// ✅ Good: Proper Basic Auth implementation with security measures
const secureBasicAuth: CustomTokenVerificationPort<BasicAuthUser> = {
  async verifyToken(token: string): Promise<BasicAuthUser> {
    // Rate limiting check
    await rateLimiter.checkLimit(context.req.ip);
    
    // Decode and validate format
    const credentials = Buffer.from(token, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    
    if (!username || !password || password.length < 8) {
      await rateLimiter.recordFailedAttempt(context.req.ip);
      throw new Error('Invalid credentials format');
    }
    
    // Secure password validation with timing attack protection
    const user = await getUserByUsername(username);
    const isValid = await secureCompare(password, user?.hashedPassword);
    
    if (!isValid) {
      await rateLimiter.recordFailedAttempt(context.req.ip);
      throw new Error('Authentication failed');
    }
    
    return user;
  }
};
```

**Basic Auth Security Checklist:**
- ✅ Always use HTTPS (never HTTP)
- ✅ Implement rate limiting per IP/user
- ✅ Use secure password hashing (bcrypt, Argon2)
- ✅ Implement account lockout after failed attempts
- ✅ Log authentication attempts for audit
- ✅ Use timing-safe password comparison
- ❌ Don't log credentials in plain text
- ❌ Don't cache credentials

##### JWT Security
```typescript
// ✅ Good: Secure JWT implementation
const secureJWTVerifier: CustomTokenVerificationPort<JWTUser> = {
  async verifyToken(token: string): Promise<JWTUser> {
    try {
      // Verify with proper algorithm specification
      const payload = jwt.verify(token, process.env.JWT_SECRET!, {
        algorithms: ['HS256'], // Specify algorithm to prevent attacks
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
        maxAge: '15m' // Maximum token age
      }) as any;
      
      // Additional security checks
      if (!payload.sub || !payload.exp) {
        throw new Error('Invalid token structure');
      }
      
      // Check token against blacklist
      if (await isTokenBlacklisted(token)) {
        throw new Error('Token has been revoked');
      }
      
      return payload;
    } catch (error) {
      // Log security events
      await logSecurityEvent('jwt_validation_failed', {
        error: error.message,
        token_hash: hashToken(token)
      });
      throw error;
    }
  }
};
```

**JWT Security Checklist:**
- ✅ Use strong secrets (256+ bits entropy)
- ✅ Specify allowed algorithms explicitly
- ✅ Validate issuer, audience, and expiration
- ✅ Implement token blacklisting for revocation
- ✅ Use short expiration times (15-60 minutes)
- ✅ Store secrets securely (environment variables/secrets management)
- ❌ Don't put sensitive data in JWT payload
- ❌ Don't use 'none' algorithm in production

##### API Key Security
```typescript
// ✅ Good: Secure API key implementation
const secureAPIKeyVerifier: CustomTokenVerificationPort<APIKeyUser> = {
  async verifyToken(token: string): Promise<APIKeyUser> {
    // Validate key format and length
    if (!token || token.length < 32) {
      throw new Error('Invalid API key format');
    }
    
    // Hash the key for database lookup (never store keys in plain text)
    const keyHash = await hashAPIKey(token);
    const keyData = await getAPIKeyByHash(keyHash);
    
    if (!keyData || !keyData.isActive) {
      await logSecurityEvent('invalid_api_key_attempt', {
        key_prefix: token.substring(0, 8),
        ip: context.req.ip
      });
      throw new Error('Invalid or inactive API key');
    }
    
    // Check rate limits per key
    await checkAPIKeyRateLimit(keyData.id);
    
    // Update last used timestamp
    await updateKeyLastUsed(keyData.id);
    
    return keyData;
  }
};
```

**API Key Security Checklist:**
- ✅ Generate keys with cryptographically secure randomness
- ✅ Store key hashes, never plain text keys
- ✅ Implement key rotation mechanisms
- ✅ Add key prefixes for identification (e.g., 'pk_', 'sk_')
- ✅ Implement per-key rate limiting
- ✅ Log key usage and suspicious activity
- ✅ Set key expiration dates
- ❌ Don't expose keys in URLs or logs
- ❌ Don't reuse revoked keys

#### Production Security Hardening

##### 1. Environment Configuration
```bash
# Production environment variables
NODE_ENV=production
NOONY_GUARD_CACHE_ENABLE=true

# Security settings
JWT_SECRET=<256-bit-random-secret>
JWT_ISSUER=your-app-name
JWT_AUDIENCE=your-app-users

# Rate limiting
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX_ATTEMPTS=5

# Monitoring
SECURITY_LOG_LEVEL=warn
AUDIT_LOG_ENABLED=true
```

##### 2. Infrastructure Security
```yaml
# Docker security configuration
security_opt:
  - no-new-privileges:true
user: "1000:1000"
read_only: true
cap_drop:
  - ALL
```

##### 3. Monitoring and Alerting
```typescript
// Security monitoring setup
const securityMonitoring = {
  // Failed authentication attempts
  async onAuthFailure(event: AuthFailureEvent) {
    await logSecurityEvent('auth_failure', event);
    
    if (event.failureCount > 5) {
      await alertSecurityTeam('Multiple auth failures', event);
    }
  },
  
  // Suspicious activity detection
  async detectSuspiciousActivity(context: Context) {
    const patterns = [
      // Multiple IPs for same user
      await checkMultipleIPs(context.user.id),
      // Unusual access patterns
      await checkAccessPatterns(context.user.id),
      // Geographic anomalies
      await checkGeographicAnomalies(context.user.id, context.req.ip)
    ];
    
    if (patterns.some(p => p.suspicious)) {
      await flagSuspiciousActivity(context.user.id);
    }
  }
};
```

#### Common Security Anti-Patterns

##### ❌ What NOT to Do

```typescript
// ❌ BAD: Logging sensitive information
console.log('Authentication failed for token:', token);

// ❌ BAD: Weak secret or hardcoded values
const JWT_SECRET = '12345';

// ❌ BAD: No expiration validation
if (payload.sub === userId) { return payload; } // Missing exp check

// ❌ BAD: Plain text password storage
const isValid = password === user.password;

// ❌ BAD: No rate limiting
// Any number of attempts allowed

// ❌ BAD: Exposing internal errors
catch (error) {
  throw new Error(`Database error: ${error.message}`);
}
```

##### ✅ What TO Do

```typescript
// ✅ GOOD: Secure logging
logger.warn('Authentication failed', { 
  userId: context.user?.id,
  ip: context.req.ip,
  userAgent: context.req.headers['user-agent']
});

// ✅ GOOD: Strong secret from environment
const JWT_SECRET = process.env.JWT_SECRET!;
if (JWT_SECRET.length < 32) {
  throw new Error('JWT secret must be at least 32 characters');
}

// ✅ GOOD: Comprehensive validation
if (!payload.exp || Date.now() >= payload.exp * 1000) {
  throw new Error('Token expired');
}

// ✅ GOOD: Secure password handling
const isValid = await bcrypt.compare(password, user.hashedPassword);

// ✅ GOOD: Rate limiting implementation
await rateLimiter.checkLimit(context.req.ip, {
  windowMs: 60000,
  maxAttempts: 5
});

// ✅ GOOD: Generic error messages
catch (error) {
  logger.error('Authentication error', error);
  throw new Error('Authentication failed');
}
```

#### Security Audit Checklist

Use this checklist to audit your RouteGuards security implementation:

**Authentication Security:**
- [ ] Strong secrets (256+ bit entropy)
- [ ] Proper token expiration handling
- [ ] Secure token storage (server-side)
- [ ] Token revocation mechanism
- [ ] Rate limiting on authentication endpoints

**Authorization Security:**
- [ ] Principle of least privilege applied
- [ ] Permission checks on all protected endpoints
- [ ] Proper error handling (no information leakage)
- [ ] Audit logging for permission denials

**Infrastructure Security:**
- [ ] HTTPS enforced in production
- [ ] Security headers implemented (HSTS, CSP)
- [ ] Secrets managed properly (not in code)
- [ ] Container security measures applied

**Monitoring Security:**
- [ ] Security event logging implemented
- [ ] Failed attempt monitoring and alerting
- [ ] Suspicious activity detection
- [ ] Regular security log review process

### GuardSetup Helper Methods

Pre-configured environment profiles with environment variable support:

#### Environment Variable Behavior

All GuardSetup methods respect the `NOONY_GUARD_CACHE_ENABLE` environment variable:

| Method | Configured cacheType | NOONY_GUARD_CACHE_ENABLE | Effective Cache |
|--------|---------------------|-------------------------|----------------|
| `development()` | 'memory' | Not set | 'none' (disabled) |
| `development()` | 'memory' | 'true' | 'memory' (enabled) |
| `production()` | 'memory' | Not set | 'none' (disabled) |
| `production()` | 'memory' | 'true' | 'memory' (enabled) |
| `serverless()` | 'memory' | Not set | 'none' (disabled) |
| `serverless()` | 'memory' | 'true' | 'memory' (enabled) |
| `testing()` | 'none' | Any value | 'none' (always disabled) |

#### GuardSetup.development()

```typescript
static development(): GuardEnvironmentProfile
```

**Configuration:**
- **Security**: ON_DEMAND resolution, non-conservative invalidation, lower complexity limits
- **Cache**: 500 max entries, short TTLs (2-5 minutes)
- **Monitoring**: Detailed logging, debug level, frequent metrics collection

**When to Use:**
- Local development
- Fast iteration cycles
- Debugging permission issues

#### GuardSetup.production()

```typescript
static production(): GuardEnvironmentProfile
```

**Configuration:**
- **Security**: PRE_EXPANSION resolution, conservative invalidation, higher complexity limits
- **Cache**: 2000 max entries, longer TTLs (5-15 minutes)
- **Monitoring**: Performance tracking, info level, standard metrics collection

**When to Use:**
- Production environments
- High-traffic applications
- Maximum performance requirements

#### GuardSetup.serverless()

```typescript
static serverless(): GuardEnvironmentProfile
```

**Configuration:**
- **Security**: PRE_EXPANSION resolution, conservative invalidation, balanced complexity limits
- **Cache**: 1000 max entries, medium TTLs (3-10 minutes)
- **Monitoring**: Performance tracking, warn level, less frequent metrics collection

**When to Use:**
- AWS Lambda, Google Cloud Functions
- Serverless deployments
- Cold start optimization

#### GuardSetup.testing()

```typescript
static testing(): GuardEnvironmentProfile
```

**Configuration:**
- **Security**: ON_DEMAND resolution, non-conservative invalidation, low complexity limits
- **Cache**: 100 max entries, very short TTLs (1 second), cacheType: 'none'
- **Monitoring**: No performance tracking, detailed logging, frequent metrics collection

**When to Use:**
- Unit tests
- Integration tests
- Predictable test behavior

### System Statistics and Health Check

#### GuardSystemStats Interface

```typescript
export interface GuardSystemStats {
  authentication: Record<string, unknown>;
  userContextService: Record<string, unknown>;
  permissionGuardFactory: Record<string, unknown>;
  cacheInvalidation: Record<string, unknown>;
  cacheAdapter: Record<string, unknown>;
  systemHealth: {
    totalGuardChecks: number;
    averageResponseTime: number;
    errorRate: number;
    cacheEfficiency: number;
    uptime: number;
  };
}
```

**Usage Example:**

```typescript
// Get comprehensive system statistics
const stats = RouteGuards.getSystemStats();

console.log('System Health:', {
  totalChecks: stats.systemHealth.totalGuardChecks,
  avgResponseTime: stats.systemHealth.averageResponseTime,
  errorRate: stats.systemHealth.errorRate,
  cacheEfficiency: stats.systemHealth.cacheEfficiency,
  uptime: Math.round(stats.systemHealth.uptime / 1000) + 's'
});

// Set up monitoring alerts
setInterval(async () => {
  const stats = RouteGuards.getSystemStats();
  
  if (stats.systemHealth.averageResponseTime > 10) {
    await sendAlert('Slow guard performance detected', {
      avgTime: stats.systemHealth.averageResponseTime,
      cacheHitRate: stats.systemHealth.cacheEfficiency
    });
  }
  
  if (stats.systemHealth.cacheEfficiency < 95) {
    await sendAlert('Cache efficiency below threshold', {
      efficiency: stats.systemHealth.cacheEfficiency,
      totalChecks: stats.systemHealth.totalGuardChecks
    });
  }
}, 60000); // Check every minute
```

#### Health Check Functionality

```typescript
static async healthCheck(): Promise<{
  status: 'healthy' | 'degraded' | 'unhealthy';
  details: Record<string, unknown>;
  timestamp: string;
}>
```

**Health Check Criteria:**

| Status | Error Rate | Average Response Time | Recommendations |
|--------|------------|-----------------------|----------------|
| Healthy | < 1% | < 10ms | System operating optimally |
| Degraded | 1-5% | 10-50ms | Monitor closely, consider optimization |
| Unhealthy | > 5% | > 50ms | Immediate attention required |

**Usage Example:**

```typescript
const health = await RouteGuards.healthCheck();

if (health.status === 'unhealthy') {
  console.error('Guard system unhealthy:', health.details);
  console.log('Recommendations:', health.details.recommendations);
  
  // Potential actions:
  // - Emergency cache invalidation
  // - Check user permission source performance
  // - Review error logs
  // - Scale infrastructure
}
```

### Permission Resolution Strategy Deep Dive

#### PRE_EXPANSION Strategy

**How it Works:**
1. At user context load time, expand all wildcard permissions
2. Convert "admin.*" to ["admin.users", "admin.reports", "admin.settings"]
3. Store expanded permissions in cache
4. Runtime checks become O(1) set lookups

**Performance Characteristics:**
- **Runtime**: ~0.1ms (cached), ~1-2ms (uncached)
- **Memory Usage**: Higher (stores expanded permissions)
- **Cache Efficiency**: Very high (95%+)
- **CPU Usage**: Low at runtime, higher at load time

**When to Use:**
- Production environments with high traffic
- Performance-critical applications
- Stable permission hierarchies
- When memory is abundant

**Configuration Example:**
```typescript
const productionConfig = {
  security: {
    permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
    conservativeCacheInvalidation: true
  },
  cache: {
    maxEntries: 5000, // Higher cache to store expanded permissions
    defaultTtlMs: 15 * 60 * 1000 // Longer TTL for stability
  }
};
```

#### ON_DEMAND Strategy

**How it Works:**
1. Store wildcard patterns as-is in user context
2. At runtime, match patterns against required permissions
3. Use regex or string matching for wildcard evaluation
4. Cache pattern matching results

**Performance Characteristics:**
- **Runtime**: ~0.2-0.5ms (cached), ~2-5ms (uncached)
- **Memory Usage**: Lower (stores patterns, not expansions)
- **Cache Efficiency**: Good (85-90%)
- **CPU Usage**: Higher at runtime due to pattern matching

**When to Use:**
- Development environments
- Memory-constrained environments
- Dynamic permission systems
- When permission hierarchies change frequently

**Configuration Example:**
```typescript
const developmentConfig = {
  security: {
    permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
    conservativeCacheInvalidation: false // Less aggressive for dev
  },
  cache: {
    maxEntries: 1000, // Lower cache acceptable
    defaultTtlMs: 5 * 60 * 1000 // Shorter TTL for dynamic changes
  }
};
```

#### Strategy Comparison Table

| Aspect | PRE_EXPANSION | ON_DEMAND |
|--------|---------------|-----------|
| **Runtime Performance** | ⭐⭐⭐ Excellent (~0.1ms) | ⭐⭐ Good (~0.2ms) |
| **Memory Usage** | ⭐ Higher | ⭐⭐⭐ Lower |
| **Setup Time** | ⭐⭐ Slower (expansion) | ⭐⭐⭐ Faster |
| **Dynamic Permissions** | ⭐ Poor (needs re-expansion) | ⭐⭐⭐ Excellent |
| **Cache Efficiency** | ⭐⭐⭐ Very High (95%+) | ⭐⭐ Good (85-90%) |
| **Best For** | Production, High Traffic | Development, Dynamic Systems |

---

## Permission Strategies Comparison

RouteGuards offers three distinct permission strategies. Understanding their trade-offs is crucial for optimal performance.

### 1. Plain Permissions Strategy

**Use Case**: Direct permission string matching with OR logic

```typescript
// Example: User needs 'user:create' OR 'admin:users'
RouteGuards.requirePermissions(['user:create', 'admin:users'])
```

#### ✅ Pros
- **Fastest Performance**: O(1) set-based lookups (~0.1ms cached)
- **Lowest Memory Usage**: Minimal memory footprint
- **Simplest Logic**: Easy to understand and debug
- **Highest Cache Efficiency**: Simple cache keys, high hit rates
- **Predictable Performance**: Consistent response times

#### ❌ Cons
- **Limited Flexibility**: Only supports OR logic between permissions
- **No Hierarchy**: Cannot express nested or hierarchical permissions
- **Maintenance Overhead**: Need explicit permission for each operation
- **Scale Challenges**: Permission list grows with feature complexity

#### 🎯 **When to Use**
- **High-traffic endpoints** (>1000 requests/minute)
- **Simple CRUD operations** (create, read, update, delete)
- **Basic role checking** (user vs admin)
- **API endpoints with clear, discrete permissions**
- **Mobile app backends** (need maximum performance)

#### 📊 **Performance Characteristics**
| Metric | First Request | Cached Request | Memory Usage |
|--------|---------------|----------------|--------------|
| Response Time | ~1-2ms | ~0.1ms | Very Low |
| CPU Usage | Minimal | Negligible | - |
| Cache Efficiency | 95%+ | - | - |

### 2. Wildcard Permissions Strategy

**Use Case**: Hierarchical permission patterns with wildcard matching

```typescript
// Example: User needs any admin permission OR user profile permission
RouteGuards.requireWildcardPermissions(['admin.*', 'user.profile.*'])
```

#### ✅ Pros
- **Hierarchical Support**: Natural role-based permission modeling
- **Maintenance Friendly**: Fewer explicit permissions needed
- **Flexible Patterns**: Multiple levels of hierarchy support
- **Role-Based**: Excellent for organizational structures
- **Scalable**: Grows well with complex permission structures

#### ❌ Cons
- **Moderate Performance**: ~0.2ms cached (2x slower than plain)
- **Higher Memory Usage**: Pattern expansion requires more storage
- **Complex Debugging**: Harder to trace which pattern matched
- **Pattern Complexity**: Can create unexpected matches
- **Cache Complexity**: More complex cache invalidation

#### 🎯 **When to Use**
- **Role-based systems** (admin, manager, employee)
- **Organizational hierarchies** (department.team.function)
- **Multi-level access control** (system.app.feature)
- **Administrative interfaces** (admin panels, management tools)
- **Enterprise applications** with complex org structures

#### 📊 **Performance Characteristics**
| Strategy | Response Time | Memory Usage | Best For |
|----------|---------------|--------------|----------|
| Pre-expansion | ~0.2ms | Higher | Production |
| On-demand | ~2-5ms | Lower | Development |

### 3. Expression Permissions Strategy

**Use Case**: Complex boolean logic with AND, OR, NOT operations

```typescript
// Example: Complex business rule
RouteGuards.requireComplexPermissions({
  or: [
    { permission: 'admin.users' },
    { and: [
      { permission: 'moderator.content' },
      { permission: 'org.reports.view' }
    ]}
  ]
})
```

#### ✅ Pros
- **Maximum Flexibility**: Complex business rules support
- **Precise Control**: Fine-grained permission logic
- **Expressive**: Natural business rule representation
- **Boolean Logic**: Full AND, OR, NOT operation support
- **Future-Proof**: Handles evolving permission requirements

#### ❌ Cons
- **Slowest Performance**: ~0.5ms cached (5x slower than plain)
- **Highest Complexity**: Difficult to understand and debug
- **Memory Intensive**: AST parsing and caching overhead
- **Maintenance Burden**: Complex expressions hard to modify
- **Error-Prone**: Easy to create logical contradictions

#### 🎯 **When to Use**
- **Complex business rules** that can't be simplified
- **Conditional access** based on multiple factors
- **Advanced compliance requirements**
- **Fine-grained security controls**
- **When other strategies can't express the logic**

#### ⚠️ **When NOT to Use**
- High-traffic endpoints (>500 requests/minute)
- Simple permission checks (use Plain instead)
- Performance-critical paths
- When simpler strategies can achieve the same result

## Authentication Methods Analysis

RouteGuards supports multiple authentication approaches. Choose based on your existing infrastructure and requirements.

### 1. CustomTokenVerificationPort (Recommended)

**New unified interface that works with both AuthenticationMiddleware and RouteGuards**

```typescript
const tokenVerifier: CustomTokenVerificationPort<User> = {
  async verifyToken(token: string): Promise<User> {
    // Your verification logic
    return await verifyAndDecodeToken(token);
  }
};

// Works everywhere!
await RouteGuards.configureWithJWT(profile, permissionSource, tokenVerifier, config);
```

#### ✅ Pros
- **Unified Interface**: One implementation works across entire framework
- **Type Safety**: Full TypeScript support with generics
- **Simplified Setup**: Factory methods for common scenarios
- **Consistent Patterns**: Same interface everywhere
- **Easy Migration**: Gradual adoption possible

#### ❌ Cons
- **New Interface**: Requires migration from existing TokenValidator
- **Learning Curve**: Different from traditional middleware patterns

#### 🎯 **When to Use**
- **New projects** starting with RouteGuards
- **Existing projects** using AuthenticationMiddleware
- **When you want unified authentication** across the framework
- **TypeScript projects** that benefit from strong typing

### 2. Traditional TokenValidator

**Original RouteGuards interface (still supported)**

```typescript
const tokenValidator: TokenValidator = {
  async validateToken(token: string) { /* ... */ },
  extractUserId(decoded: any): string { /* ... */ },
  isTokenExpired(decoded: any): boolean { /* ... */ }
};
```

#### ✅ Pros
- **Proven Interface**: Battle-tested in production
- **Explicit Control**: Fine-grained control over each step
- **Backward Compatible**: No migration needed
- **Familiar Pattern**: Traditional middleware approach

#### ❌ Cons
- **More Boilerplate**: Three methods vs one
- **Framework-Specific**: Only works with RouteGuards
- **Manual Type Management**: Less TypeScript integration

#### 🎯 **When to Use**
- **Existing RouteGuards implementations** (no rush to migrate)
- **Custom token validation logic** that doesn't fit standard patterns
- **When you need explicit control** over each validation step

### Factory Method Comparison

The new CustomTokenVerificationPort supports convenient factory methods:

| Factory Method | Use Case | Setup Complexity | Type Safety |
|----------------|----------|------------------|-------------|
| `configureWithJWT()` | Standard JWT tokens | ⭐ Simple | ⭐⭐⭐ Excellent |
| `configureWithAPIKey()` | API key authentication | ⭐⭐ Moderate | ⭐⭐⭐ Excellent |
| `configureWithOAuth()` | OAuth token validation | ⭐⭐ Moderate | ⭐⭐⭐ Excellent |
| `configureWithCustom()` | Custom token logic | ⭐⭐⭐ Complex | ⭐⭐⭐ Excellent |
| `configure()` (traditional) | Any token validator | ⭐⭐⭐ Complex | ⭐⭐ Good |

## Simple Scenarios

### Authentication-Only Endpoints

For endpoints that only need to verify user identity:

```typescript
const profileHandler = new Handler()
  .use(RouteGuards.requireAuth()) // No permission checking
  .handle(async (context) => {
    const user = context.user!; // Guaranteed authenticated
    return { profile: user };
  });
```

#### ✅ Pros
- **Fastest Setup**: No permission configuration needed
- **Maximum Performance**: Skip permission checking overhead
- **Simple Logic**: Just verify authentication

#### ❌ Cons
- **No Authorization**: Anyone with valid token can access
- **Security Risk**: May expose sensitive data to any authenticated user

#### 🎯 **When to Use**
- Public user profile endpoints
- General user information endpoints
- Dashboard home pages
- Non-sensitive data endpoints

### Single Permission Checks

For endpoints requiring one specific permission:

```typescript
const createHandler = new Handler()
  .use(RouteGuards.requirePermissions(['user:create']))
  .handle(async (context) => {
    // User has 'user:create' permission
  });
```

#### ✅ Pros
- **Clear Intent**: Obvious what permission is required
- **Optimal Performance**: Single permission lookup
- **Easy Debugging**: Simple to trace permission failures

#### ❌ Cons
- **Inflexible**: No alternative permission paths
- **Maintenance**: Need exact permission string match

#### 🎯 **When to Use**
- CRUD operations with specific permissions
- Feature-specific endpoints
- When you have granular permission model

### Multiple Permission Checks (OR Logic)

For endpoints where user needs ANY of several permissions:

```typescript
const adminHandler = new Handler()
  .use(RouteGuards.requirePermissions(['admin:full', 'manager:users', 'support:level3']))
  .handle(async (context) => {
    // User has ANY of the three permissions
  });
```

#### ✅ Pros
- **Flexible Access**: Multiple ways to grant access
- **Role Compatibility**: Works with different role structures
- **Easy to Extend**: Add new permissions as needed

#### ❌ Cons
- **OR Logic Only**: Can't express AND relationships
- **Permission Explosion**: List can grow large over time

#### 🎯 **When to Use**
- Administrative functions accessible by different roles
- Endpoints with multiple access paths
- Gradual permission model migration

## Complex Scenarios

### Hierarchical Permission Management

For organizations with structured permission hierarchies:

```typescript
// Department-based access
const departmentHandler = new Handler()
  .use(RouteGuards.requireWildcardPermissions([
    'department.finance.*',    // Any finance permission
    'department.hr.*',         // Any HR permission
    'admin.departments.*'      // Admin department access
  ]))
  .handle(async (context) => {
    // Complex organizational access logic
  });
```

#### ✅ Pros
- **Natural Modeling**: Matches organizational structure
- **Scalable**: Easy to add new departments/teams
- **Maintenance Friendly**: Fewer explicit permissions
- **Role Evolution**: Handles changing org structures

#### ❌ Cons
- **Performance Impact**: Pattern matching overhead
- **Debug Complexity**: Harder to trace which pattern matched
- **Overpermissioning Risk**: Wildcards might grant too much access

#### 🎯 **When to Use**
- Enterprise applications with organizational hierarchies
- Multi-department systems
- Role-based access control (RBAC) systems
- Growing organizations with evolving structures

### Complex Business Rules

For sophisticated permission logic that requires boolean operations:

```typescript
const complianceHandler = new Handler()
  .use(RouteGuards.requireComplexPermissions({
    and: [
      { permission: 'compliance.read' },
      { not: { permission: 'employee.restricted' } },
      { or: [
        { permission: 'manager.reports' },
        { and: [
          { permission: 'auditor.access' },
          { permission: 'external.certified' }
        ]}
      ]}
    ]
  }))
  .handle(async (context) => {
    // Complex compliance access granted
  });
```

#### ✅ Pros
- **Precise Control**: Exact business rule implementation
- **Compliance Ready**: Meets complex regulatory requirements
- **Expressive**: Natural business language representation
- **Future-Proof**: Handles evolving compliance needs

#### ❌ Cons
- **Performance Cost**: Significant overhead (~0.5ms)
- **Complexity**: Hard to understand and maintain
- **Error-Prone**: Easy to create logical contradictions
- **Testing Complexity**: Many edge cases to validate

#### 🎯 **When to Use**
- Regulatory compliance requirements
- Financial services applications
- Healthcare systems with strict access controls
- When other strategies cannot express the required logic

#### ⚠️ **Decision Criteria**
**Use Complex Permissions only when:**
1. Business rules cannot be simplified
2. Regulatory compliance requires exact logic
3. Performance is not critical (< 500 req/min)
4. You have resources for extensive testing

### Multi-Tenant Permission Management

For SaaS applications with tenant isolation:

```typescript
interface TenantUser extends User {
  tenantId: string;
  tenantRole: string;
}

const tenantHandler = new Handler<TenantRequest, TenantUser>()
  .use(RouteGuards.requirePermissions(['tenant:manage']))
  .handle(async (context) => {
    const user = context.user!;
    const requestedTenantId = context.req.params.tenantId;
    
    // Additional tenant validation
    if (user.tenantId !== requestedTenantId && user.role !== 'system-admin') {
      throw new SecurityError('Tenant access denied');
    }
    
    // Tenant-specific logic
  });
```

#### ✅ Pros
- **Tenant Isolation**: Built-in security boundaries
- **Scalable**: Works with growing tenant base
- **Flexible Roles**: Different roles per tenant
- **Audit Trail**: Clear tenant-specific logging

#### ❌ Cons
- **Additional Complexity**: Extra validation logic needed
- **Performance**: Additional database lookups
- **Context Management**: Need to track tenant context

#### 🎯 **When to Use**
- Multi-tenant SaaS applications
- Enterprise software with customer isolation
- Platform-as-a-Service offerings
- Any system requiring data isolation

## Performance Optimization

### Cache Configuration Strategies

Choose the right caching approach based on your performance and security requirements:

#### Memory Cache (Recommended for most cases)

```typescript
GuardSetup.production() // Uses memory cache by default
```

##### ✅ Pros
- **Fastest Performance**: Sub-millisecond cache access
- **No Network Overhead**: Local memory access
- **Simple Setup**: No external dependencies
- **Cost Effective**: No additional infrastructure

##### ❌ Cons
- **Memory Usage**: Consumes application memory
- **Single Instance**: No sharing across application instances
- **Cold Start Impact**: Cache rebuilt on restart
- **Scale Limitations**: Memory bounds limit cache size

##### 🎯 **When to Use**
- Single-instance applications
- Memory is not a constraint
- Maximum performance required
- Simple deployment architecture

#### Redis Cache (For distributed systems)

```typescript
// Custom configuration with Redis
const customProfile: GuardEnvironmentProfile = {
  environment: 'production',
  cacheType: 'redis', // When implemented
  // ... other config
};
```

##### ✅ Pros
- **Distributed**: Shared cache across instances
- **Persistent**: Survives application restarts
- **Scalable**: No memory limitations
- **Advanced Features**: TTL, eviction policies

##### ❌ Cons
- **Network Latency**: Additional network round-trip
- **Infrastructure**: Requires Redis deployment
- **Complexity**: More moving parts
- **Cost**: Additional infrastructure costs

##### 🎯 **When to Use**
- Multi-instance deployments
- Microservices architecture
- Large-scale applications
- When cache persistence is important

#### No Cache (For maximum security)

```typescript
GuardSetup.testing() // Disables caching
```

##### ✅ Pros
- **Maximum Security**: Always fresh permission checks
- **No Stale Data**: Immediate permission revocation
- **Simple**: No cache invalidation complexity
- **Debugging**: Predictable behavior

##### ❌ Cons
- **Poor Performance**: Every check requires database lookup
- **High Load**: Increased database pressure
- **Scalability Issues**: Cannot handle high traffic
- **Cost**: Higher infrastructure requirements

##### 🎯 **When to Use**
- Testing environments
- Maximum security requirements
- Low-traffic applications
- Development debugging

### TTL Configuration Guidance

Choose the right Time-To-Live settings based on your security vs performance balance:

| TTL Setting | Security | Performance | Use Case |
|-------------|----------|-------------|----------|
| 1-5 minutes | ⭐⭐⭐ High | ⭐ Low | High-security systems |
| 5-15 minutes | ⭐⭐ Medium | ⭐⭐ Medium | Balanced applications |
| 15-60 minutes | ⭐ Low | ⭐⭐⭐ High | Performance-critical systems |

#### Short TTL (1-5 minutes)

```typescript
cache: {
  defaultTtlMs: 5 * 60 * 1000,      // 5 minutes
  userContextTtlMs: 3 * 60 * 1000,  // 3 minutes
  authTokenTtlMs: 2 * 60 * 1000,    // 2 minutes
}
```

##### ✅ Pros
- **High Security**: Quick permission revocation
- **Fresh Data**: Minimal stale data risk
- **Compliance**: Meets strict security requirements

##### ❌ Cons
- **Frequent Cache Misses**: More database lookups
- **Higher Load**: Increased system pressure
- **Cost**: More infrastructure usage

##### 🎯 **When to Use**
- Financial services
- Healthcare applications
- Government systems
- High-security environments

#### Long TTL (15-60 minutes)

```typescript
cache: {
  defaultTtlMs: 30 * 60 * 1000,     // 30 minutes
  userContextTtlMs: 20 * 60 * 1000, // 20 minutes
  authTokenTtlMs: 15 * 60 * 1000,   // 15 minutes
}
```

##### ✅ Pros
- **High Performance**: Maximum cache efficiency
- **Low Load**: Minimal database pressure
- **Cost Effective**: Reduced infrastructure needs

##### ❌ Cons
- **Security Risk**: Delayed permission revocation
- **Stale Data**: Longer exposure to outdated permissions
- **Compliance Issues**: May not meet security standards

##### 🎯 **When to Use**
- High-traffic consumer applications
- Performance-critical systems
- Low-security requirements
- Cost-sensitive deployments

## Production Deployment

### Environment Configuration Comparison

| Environment | Performance | Security | Logging | Use Case |
|-------------|-------------|----------|---------|----------|
| Development | ⭐⭐ | ⭐ | ⭐⭐⭐ Detailed | Local development |
| Staging | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ Moderate | Pre-production testing |
| Production | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ Minimal | Live traffic |
| Serverless | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ Critical only | Cold start optimized |

### Development Configuration

```typescript
GuardSetup.development()
```

#### ✅ Pros
- **Detailed Logging**: Comprehensive debug information
- **Fast Iteration**: Lower cache TTL for quick testing
- **Debugging**: All guard operations logged
- **Flexible**: Less conservative cache invalidation

#### ❌ Cons
- **Performance**: Not optimized for speed
- **Memory Usage**: More logging overhead
- **Security**: Less strict settings

#### 🎯 **Best Practices**
- Use for local development only
- Enable all logging for debugging
- Use shorter TTL for testing permission changes
- Test permission scenarios thoroughly

### Production Configuration

```typescript
GuardSetup.production()
```

#### ✅ Pros
- **Maximum Performance**: Optimized for speed
- **Conservative Security**: Strict cache invalidation
- **Stable**: Battle-tested configuration
- **Efficient**: Minimal logging overhead

#### ❌ Cons
- **Limited Debugging**: Minimal log output
- **Fixed Settings**: Less flexibility for testing

#### 🎯 **Best Practices**
- Use for all production environments
- Monitor cache hit rates (target >95%)
- Set up proper alerting for guard failures
- Regular security audit of permission grants

### Serverless Configuration

```typescript
GuardSetup.serverless()
```

#### ✅ Pros
- **Cold Start Optimized**: Faster initialization
- **Memory Efficient**: Reduced memory footprint
- **Simplified**: Optimized settings for serverless

#### ❌ Cons
- **Less Caching**: Shorter TTL due to function lifecycle
- **Limited Flexibility**: Fewer configuration options

#### 🎯 **Best Practices**
- Ideal for AWS Lambda, Google Cloud Functions
- Monitor cold start times
- Consider external cache for multi-function sharing
- Optimize for function memory limits

## Decision Matrices

### Permission Strategy Selection Matrix

Use this matrix to choose the right permission strategy:

| Requirement | Plain | Wildcard | Expression | Recommendation |
|-------------|--------|----------|------------|----------------|
| High traffic (>1000 req/min) | ⭐⭐⭐ | ⭐⭐ | ⭐ | **Plain** |
| Simple permissions | ⭐⭐⭐ | ⭐ | ⭐ | **Plain** |
| Role-based system | ⭐ | ⭐⭐⭐ | ⭐⭐ | **Wildcard** |
| Complex business rules | ❌ | ⭐ | ⭐⭐⭐ | **Expression** |
| Easy maintenance | ⭐⭐⭐ | ⭐⭐ | ⭐ | **Plain** |
| Organizational hierarchy | ⭐ | ⭐⭐⭐ | ⭐⭐ | **Wildcard** |
| Debugging simplicity | ⭐⭐⭐ | ⭐⭐ | ⭐ | **Plain** |
| Memory efficiency | ⭐⭐⭐ | ⭐⭐ | ⭐ | **Plain** |

### Authentication Method Selection

| Factor | CustomTokenVerificationPort | TokenValidator | Traditional Auth |
|--------|----------------------------|----------------|------------------|
| **Setup Complexity** | ⭐ Simple | ⭐⭐ Moderate | ⭐⭐⭐ Complex |
| **Type Safety** | ⭐⭐⭐ Excellent | ⭐⭐ Good | ⭐ Basic |
| **Framework Integration** | ⭐⭐⭐ Unified | ⭐⭐ RouteGuards only | ⭐ Manual |
| **Migration Effort** | ⭐⭐ Easy from AuthMiddleware | ⭐⭐⭐ No migration | ⭐ High effort |
| **Flexibility** | ⭐⭐⭐ Factory methods | ⭐⭐ Custom logic | ⭐⭐⭐ Full control |
| **Learning Curve** | ⭐⭐ Moderate | ⭐⭐⭐ Familiar | ⭐ Low |

### Environment Configuration Guide

| Factor | Development | Staging | Production | Serverless |
|--------|-------------|---------|------------|------------|
| **Cache TTL** | 5 min | 10 min | 15 min | 10 min |
| **Cache Size** | 500 | 1000 | 2000 | 1000 |
| **Logging** | Detailed | Moderate | Minimal | Critical |
| **Security** | Relaxed | Moderate | Strict | Strict |
| **Performance** | Debug-focused | Balanced | Optimized | Cold-start optimized |

### Performance vs Security Trade-off Matrix

| Priority | Configuration | Cache TTL | Security Level | Performance |
|----------|---------------|-----------|----------------|-------------|
| **Maximum Security** | Conservative + Short TTL | 1-5 min | ⭐⭐⭐ | ⭐ |
| **Balanced** | Moderate + Medium TTL | 10-15 min | ⭐⭐ | ⭐⭐ |
| **Maximum Performance** | Aggressive + Long TTL | 30-60 min | ⭐ | ⭐⭐⭐ |

## Real-World Examples

### E-commerce Platform

A comprehensive e-commerce system with different permission strategies for different endpoints:

#### Product Catalog (High Traffic - Plain Permissions)

```typescript
// High-traffic product viewing
const productHandler = new Handler()
  .use(RouteGuards.requirePermissions(['product:read', 'customer:browse']))
  .handle(async (context) => {
    // Fast product lookup
  });
```

**Why Plain Permissions:**
- ✅ High traffic endpoint (1000+ req/min)
- ✅ Simple permission logic
- ✅ Maximum performance needed
- ❌ No complex business rules required

#### Administrative Panel (Hierarchical - Wildcard Permissions)

```typescript
// Admin operations across different areas
const adminHandler = new Handler()
  .use(RouteGuards.requireWildcardPermissions([
    'admin.products.*',    // Product management
    'admin.orders.*',      // Order management
    'admin.customers.*',   // Customer service
    'manager.reports.*'    // Manager reporting
  ]))
  .handle(async (context) => {
    // Administrative operations
  });
```

**Why Wildcard Permissions:**
- ✅ Role-based access (admin, manager)
- ✅ Multiple functional areas
- ✅ Easy to extend with new admin features
- ❌ Moderate traffic (acceptable performance)

#### Fraud Detection (Complex Rules - Expression Permissions)

```typescript
// Complex fraud prevention logic
const fraudHandler = new Handler()
  .use(RouteGuards.requireComplexPermissions({
    and: [
      { permission: 'security.investigate' },
      { not: { permission: 'employee.restricted' } },
      { or: [
        { permission: 'security.supervisor' },
        { and: [
          { permission: 'security.analyst' },
          { permission: 'fraud.certified' }
        ]}
      ]}
    ]
  }))
  .handle(async (context) => {
    // Fraud investigation tools
  });
```

**Why Expression Permissions:**
- ✅ Complex compliance requirements
- ✅ Multiple certification levels
- ✅ Strict access control needed
- ❌ Low traffic acceptable

#### Performance Recommendations

| Endpoint Type | Strategy | Expected RPS | Cache TTL | Monitoring |
|---------------|----------|--------------|-----------|------------|
| Product Catalog | Plain | 1000+ | 15 min | Cache hit rate |
| User Dashboard | Plain | 500+ | 10 min | Response time |
| Admin Panel | Wildcard | 50+ | 15 min | Permission usage |
| Fraud Tools | Expression | 10+ | 5 min | Access patterns |

### Multi-Tenant SaaS Application

A B2B SaaS platform with tenant isolation and role hierarchies:

#### Tenant Setup Strategy

```typescript
interface TenantUser extends User {
  tenantId: string;
  tenantRole: 'owner' | 'admin' | 'manager' | 'user';
  departments: string[];
}

// Tenant-aware authentication
const tenantTokenVerifier: CustomTokenVerificationPort<TenantUser> = {
  async verifyToken(token: string): Promise<TenantUser> {
    const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
    
    // Load tenant-specific user data
    const user = await tenantUserService.getUser(payload.sub, payload.tenant_id);
    
    return {
      ...user,
      sub: payload.sub,
      exp: payload.exp,
      tenantId: payload.tenant_id
    };
  }
};

await RouteGuards.configureWithCustom(
  GuardSetup.production(),
  tenantPermissionSource,
  tenantTokenVerifier,
  authConfig,
  {
    userIdExtractor: (user) => user.id,
    expirationExtractor: (user) => user.exp,
    additionalValidation: (user) => user.tenantId && user.tenantRole !== 'suspended'
  }
);
```

#### Tenant Data Access (Wildcard + Custom Validation)

```typescript
const tenantDataHandler = new Handler<TenantDataRequest, TenantUser>()
  .use(RouteGuards.requireWildcardPermissions([
    'tenant.data.*',
    'admin.tenant.*',
    'manager.department.*'
  ]))
  .handle(async (context) => {
    const user = context.user!;
    const requestedTenantId = context.req.params.tenantId;
    
    // Strict tenant isolation
    if (user.tenantId !== requestedTenantId) {
      // Only system admins can cross-tenant access
      if (!user.permissions.includes('system.admin')) {
        throw new SecurityError('Cross-tenant access denied');
      }
    }
    
    // Department-level isolation for managers
    if (user.tenantRole === 'manager') {
      const requestedDepartment = context.req.params.department;
      if (!user.departments.includes(requestedDepartment)) {
        throw new SecurityError('Department access denied');
      }
    }
    
    return await getData(requestedTenantId, requestedDepartment);
  });
```

#### System Administration (Expression Permissions)

```typescript
// Multi-tenant system administration
const systemAdminHandler = new Handler<SystemRequest, TenantUser>()
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { permission: 'system.admin' }, // Full system access
      { and: [
        { permission: 'support.escalated' },
        { permission: 'tenant.specific.admin' },
        { not: { permission: 'support.restricted' } }
      ]}
    ]
  }))
  .handle(async (context) => {
    // System-level operations
  });
```

#### Tenant Isolation Best Practices

| Isolation Level | Implementation | Performance | Security |
|----------------|----------------|-------------|----------|
| **Token Level** | Tenant ID in JWT | ⭐⭐⭐ | ⭐⭐⭐ |
| **Permission Level** | Tenant-scoped permissions | ⭐⭐ | ⭐⭐⭐ |
| **Data Level** | Application-level checks | ⭐ | ⭐⭐⭐ |
| **Database Level** | Multi-tenant database | ⭐⭐⭐ | ⭐⭐⭐ |

### High-Traffic API Gateway

A high-performance API gateway handling millions of requests:

#### Rate-Limited Public Endpoints (Plain Permissions)

```typescript
// Public API with rate limiting
const publicApiHandler = new Handler()
  .use(new RateLimitingMiddleware({ limit: 1000, window: '1m' }))
  .use(RouteGuards.requirePermissions(['api.public']))
  .handle(async (context) => {
    // High-traffic public endpoint
  });
```

#### Partner API Access (Wildcard Permissions)

```typescript
// Partner integration endpoints
const partnerHandler = new Handler()
  .use(RouteGuards.requireWildcardPermissions([
    'partner.integration.*',
    'api.partner.*'
  ]))
  .handle(async (context) => {
    // Partner-specific functionality
  });
```

#### Performance Optimizations

```typescript
// Ultra-high performance configuration
const highPerformanceProfile: GuardEnvironmentProfile = {
  environment: 'production',
  cacheType: 'memory',
  security: {
    permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
    conservativeCacheInvalidation: false, // Risk vs performance trade-off
    maxExpressionComplexity: 50, // Limit complexity for performance
  },
  cache: {
    maxEntries: 10000,           // Large cache for high traffic
    defaultTtlMs: 30 * 60 * 1000, // 30 minutes for stability
    userContextTtlMs: 20 * 60 * 1000,
    authTokenTtlMs: 15 * 60 * 1000,
  },
  monitoring: {
    enablePerformanceTracking: true,
    enableDetailedLogging: false, // Minimal logging for performance
    logLevel: 'error',           // Only log errors
    metricsCollectionInterval: 300000, // 5 minutes
  }
};
```

#### Monitoring Strategy

```typescript
// High-traffic monitoring
setInterval(async () => {
  const stats = RouteGuards.getSystemStats();
  
  // Alert on performance degradation
  if (stats.systemHealth.averageResponseTime > 1.0) {
    await sendAlert('Guard response time degraded', {
      avgTime: stats.systemHealth.averageResponseTime,
      cacheHitRate: stats.systemHealth.cacheEfficiency
    });
  }
  
  // Alert on cache efficiency
  if (stats.systemHealth.cacheEfficiency < 95) {
    await sendAlert('Cache efficiency below threshold', {
      efficiency: stats.systemHealth.cacheEfficiency,
      totalChecks: stats.systemHealth.totalGuardChecks
    });
  }
}, 60000); // Check every minute
```

## FAQ with Decision Guidance

### "Which permission strategy should I use?"

**Use this decision tree:**

1. **Is your endpoint high-traffic (>500 req/min)?**
   - Yes → Use **Plain Permissions**
   - No → Continue to question 2

2. **Do you have role-based or hierarchical permissions?**
   - Yes → Use **Wildcard Permissions**
   - No → Continue to question 3

3. **Do you need complex AND/OR/NOT logic?**
   - Yes → Use **Expression Permissions**
   - No → Use **Plain Permissions**

**Quick Reference:**
- **Plain**: Simple, fast, explicit permissions
- **Wildcard**: Role-based, hierarchical, admin systems
- **Expression**: Complex business rules, compliance

### "Should I migrate from custom auth to RouteGuards?"

**Migration Benefits Analysis:**

#### ✅ Migrate When:
- **Performance issues** with current auth system
- **Maintenance burden** of custom auth logic
- **Scaling challenges** with permission management
- **Compliance requirements** need audit trails
- **Team wants standardization** across projects

#### ❌ Don't Migrate When:
- **Current system works well** and meets all needs
- **Limited development resources** for migration
- **Very custom auth requirements** that don't fit patterns
- **Legacy system integration** makes migration complex

#### Migration Strategies:

**Gradual Migration (Recommended):**
```typescript
// 1. Start with new endpoints
const newHandler = new Handler()
  .use(RouteGuards.requirePermissions(['new:feature']))
  .handle(newFeatureLogic);

// 2. Migrate high-value endpoints
const criticalHandler = new Handler()
  .use(RouteGuards.requirePermissions(['critical:operation']))
  .handle(existingCriticalLogic);

// 3. Keep legacy endpoints unchanged until ready
const legacyHandler = new Handler()
  .use(oldAuthMiddleware)
  .handle(legacyLogic);
```

**Complete Migration:**
```typescript
// Replace all auth middleware at once
// Requires thorough testing and rollback plan
```

### "How do I choose between JWT, API Key, and OAuth?"

**Authentication Method Comparison:**

#### JWT Tokens
```typescript
await RouteGuards.configureWithJWT(profile, permissionSource, jwtVerifier, config);
```

##### ✅ **Use JWT When:**
- **Stateless authentication** required
- **Microservices architecture** (no shared session state)
- **Mobile applications** (offline capability)
- **Standard web applications** with token-based auth
- **Performance is critical** (no database lookup per request)

##### ❌ **Avoid JWT When:**
- **Immediate revocation** is critical (JWT can't be revoked easily)
- **Large permission sets** (JWT size becomes an issue)
- **Sensitive data in tokens** (JWT payload is readable)

#### API Keys
```typescript
await RouteGuards.configureWithAPIKey(
  profile, permissionSource, apiKeyVerifier, config, 'keyId', 'expiresAt'
);
```

##### ✅ **Use API Keys When:**
- **Machine-to-machine** communication
- **Third-party integrations** (partners, webhooks)
- **Simple authentication** needed
- **Easy revocation** required
- **Rate limiting** per client

##### ❌ **Avoid API Keys When:**
- **User authentication** (not suitable for humans)
- **Complex permission models** (limited metadata)
- **Short-lived sessions** (API keys are typically long-lived)

#### OAuth Tokens
```typescript
await RouteGuards.configureWithOAuth(
  profile, permissionSource, oauthVerifier, config, ['required:scope']
);
```

##### ✅ **Use OAuth When:**
- **Third-party applications** need access
- **Delegated authorization** (user grants access to app)
- **Scope-based permissions** fit your model
- **Integration with OAuth providers** (Google, Microsoft, etc.)
- **Industry standard compliance** required

##### ❌ **Avoid OAuth When:**
- **First-party applications only** (unnecessary complexity)
- **Simple authentication** needs (OAuth is complex)
- **No third-party access** requirements
- **Performance is critical** (OAuth validation overhead)

### "When should I invalidate cache?"

**Cache Invalidation Strategy Decision Matrix:**

#### Conservative Approach (Recommended for Production)
```typescript
// Invalidate immediately on any permission change
await RouteGuards.invalidateUserPermissions(userId, 'Role updated');
```

##### ✅ **Pros:**
- **Maximum Security**: Immediate permission revocation
- **Compliance Ready**: Meets strict security requirements
- **Audit Trail**: Clear invalidation logging
- **Zero Risk**: No stale permission exposure

##### ❌ **Cons:**
- **Performance Impact**: More database lookups
- **Higher Load**: Increased system pressure
- **Cost**: More infrastructure usage

##### 🎯 **Use When:**
- Financial services
- Healthcare systems
- Government applications
- High-security environments

#### Performance-Optimized Approach
```typescript
// Invalidate only on major changes, rely on TTL for minor changes
await RouteGuards.invalidateUserPermissions(userId, 'Major role change');
// Let TTL handle minor permission updates
```

##### ✅ **Pros:**
- **High Performance**: Fewer cache misses
- **Lower Load**: Reduced database pressure
- **Cost Effective**: Minimal infrastructure impact
- **User Experience**: Faster response times

##### ❌ **Cons:**
- **Security Risk**: Delayed permission revocation
- **Compliance Issues**: May not meet regulations
- **Stale Data**: Exposure window for old permissions

##### 🎯 **Use When:**
- Consumer applications
- Performance-critical systems
- Low-security requirements
- Cost-sensitive deployments

#### Hybrid Approach (Balanced)
```typescript
// Immediate invalidation for security-critical changes
if (isSecurityCriticalChange(change)) {
  await RouteGuards.invalidateUserPermissions(userId, 'Security-critical change');
} else {
  // Let TTL handle non-critical changes
  console.log('Non-critical change, relying on TTL');
}
```

##### ✅ **Pros:**
- **Balanced**: Security where needed, performance where possible
- **Flexible**: Adapt to different change types
- **Risk Management**: Focus security efforts appropriately

##### ❌ **Cons:**
- **Complexity**: Need to classify change types
- **Decision Logic**: Must maintain classification rules
- **Testing**: More scenarios to validate

##### 🎯 **Use When:**
- Most production applications
- Mixed security requirements
- Need balance between security and performance

### "How do I optimize performance?"

**Performance Optimization Checklist:**

#### 1. **Choose the Right Strategy**
```typescript
// High traffic = Plain permissions
RouteGuards.requirePermissions(['user:read']) // ~0.1ms

// Role-based = Wildcard permissions  
RouteGuards.requireWildcardPermissions(['admin.*']) // ~0.2ms

// Complex rules = Expression permissions (sparingly)
RouteGuards.requireComplexPermissions(complexRule) // ~0.5ms
```

#### 2. **Optimize Cache Configuration**
```typescript
// For high-traffic applications
const optimizedConfig = {
  cache: {
    maxEntries: 5000,              // Large cache
    defaultTtlMs: 30 * 60 * 1000,  // Long TTL
    userContextTtlMs: 20 * 60 * 1000,
    authTokenTtlMs: 15 * 60 * 1000,
  }
};
```

#### 3. **Monitor Key Metrics**
```typescript
// Target performance metrics
const performanceTargets = {
  cacheHitRate: 95,         // >95% cache hits
  avgResponseTime: 0.5,     // <0.5ms average
  errorRate: 0.1,           // <0.1% errors
};

// Regular monitoring
setInterval(() => {
  const stats = RouteGuards.getSystemStats();
  if (stats.systemHealth.cacheEfficiency < performanceTargets.cacheHitRate) {
    console.warn('Cache efficiency below target');
  }
}, 60000);
```

#### 4. **Pre-warm Critical Caches**
```typescript
// Pre-warm cache during application startup
const criticalUsers = ['admin1', 'service-account', 'system-user'];
for (const userId of criticalUsers) {
  await userPermissionSource.getUserPermissions(userId);
}
```

#### 5. **Use Appropriate TTL**
| Application Type | Recommended TTL | Rationale |
|------------------|----------------|-----------|
| High-security | 5 minutes | Quick revocation |
| Balanced | 15 minutes | Good performance + security |
| High-performance | 30 minutes | Maximum cache efficiency |
| Development | 2 minutes | Fast iteration |

### "How do I control caching with the NOONY_GUARD_CACHE_ENABLE environment variable?"

**Cache Control Strategy Decision Guide:**

#### Security-First Approach (Default)

```bash
# Caching disabled by default - maximum security
npm start
```

**Benefits:**

- **Maximum Security**: No accidental caching of sensitive data
- **Debugging Friendly**: Predictable behavior during development
- **Compliance Ready**: Meets strict security requirements out-of-the-box

**Use When:**

- Development and testing environments
- High-security applications
- Debugging permission issues
- First-time setup and configuration

#### Performance-Optimized Approach

```bash
# Explicitly enable caching for performance
NOONY_GUARD_CACHE_ENABLE=true npm start
```

**Benefits:**

- **High Performance**: Sub-millisecond cached permission checks
- **Scalability**: Reduced database load
- **Cost Efficiency**: Lower infrastructure costs

**Use When:**

- Production environments
- High-traffic applications
- Performance is critical
- System has been tested and verified

#### Environment-Specific Configuration

**Development:**

```bash
# Fast iteration with cache disabled
NODE_ENV=development npm run dev
```

**Staging:**

```bash
# Test with production-like caching
NODE_ENV=staging NOONY_GUARD_CACHE_ENABLE=true npm start
```

**Production:**

```bash
# High-performance production setup
NODE_ENV=production NOONY_GUARD_CACHE_ENABLE=true npm start
```

#### Docker and Container Deployments

**Dockerfile:**

```dockerfile
# Enable caching in container
ENV NOONY_GUARD_CACHE_ENABLE=true
```

**Docker Compose:**

```yaml
environment:
  - NOONY_GUARD_CACHE_ENABLE=true
  - NODE_ENV=production
```

**Kubernetes:**

```yaml
env:
  - name: NOONY_GUARD_CACHE_ENABLE
    value: "true"
  - name: NODE_ENV
    value: "production"
```

### "What are common mistakes to avoid?"

#### ❌ **Common Mistakes:**

1. **Using Expression Permissions for Simple Cases**
   ```typescript
   // Wrong: Complex expression for simple permission
   RouteGuards.requireComplexPermissions({
     or: [{ permission: 'user:read' }]
   });
   
   // Right: Simple permission check
   RouteGuards.requirePermissions(['user:read']);
   ```

2. **Ignoring Cache Hit Rates**
   ```typescript
   // Wrong: Not monitoring cache performance
   // Right: Regular monitoring
   const stats = RouteGuards.getSystemStats();
   if (stats.systemHealth.cacheEfficiency < 90) {
     // Investigate cache configuration
   }
   ```

3. **Over-Permissioning with Wildcards**
   ```typescript
   // Wrong: Too broad permissions
   RouteGuards.requireWildcardPermissions(['*']); // Grants everything!
   
   // Right: Specific wildcard patterns
   RouteGuards.requireWildcardPermissions(['admin.users.*']);
   ```

4. **Not Planning for Scale**
   ```typescript
   // Wrong: Single permission per endpoint
   RouteGuards.requirePermissions(['very:specific:permission:1']);
   RouteGuards.requirePermissions(['very:specific:permission:2']);
   // ... hundreds of specific permissions
   
   // Right: Hierarchical permission model
   RouteGuards.requireWildcardPermissions(['feature.*']);
   ```

5. **Inconsistent Permission Naming**
   ```typescript
   // Wrong: Inconsistent naming
   RouteGuards.requirePermissions(['user-create', 'userRead', 'USER_UPDATE']);
   
   // Right: Consistent naming convention
   RouteGuards.requirePermissions(['user:create', 'user:read', 'user:update']);
   ```

#### ✅ **Best Practices:**

1. **Start Simple, Add Complexity Only When Needed**
2. **Monitor Performance Continuously**
3. **Use Consistent Permission Naming**
4. **Plan Permission Hierarchy Early**
5. **Test Permission Changes Thoroughly**
6. **Document Permission Requirements**
7. **Regular Security Audits**

---

## Real-World Multi-Authentication Examples

This section demonstrates practical scenarios where multiple authentication methods are used together in production applications. Each example shows how to configure RouteGuards for different authentication strategies based on user types, endpoints, or organizational requirements.

### Multi-Tenant SaaS Platform

A comprehensive example showing how to handle different authentication methods for different user types in a multi-tenant SaaS platform.

```typescript
import { RouteGuards, GuardSetup } from '@/middlewares/guards';
import { CustomTokenVerificationPortAdapter, TokenVerificationAdapterFactory } from '@/middlewares/guards/adapters';

// User types for different authentication methods
interface JWTUser {
  sub: string;
  email: string;
  role: 'admin' | 'user';
  tenantId: string;
  permissions: string[];
  exp: number;
  iat: number;
}

interface APIKeyUser {
  keyId: string;
  organizationId: string;
  permissions: string[];
  isActive: boolean;
  expiresAt: number;
  keyType: 'internal' | 'partner' | 'integration';
}

interface BasicAuthUser {
  username: string;
  userId: string;
  role: 'system' | 'service';
  permissions: string[];
  isActive: boolean;
}

// Multi-authentication service that routes to appropriate verifier
class MultiAuthService {
  private jwtVerifier: CustomTokenVerificationPortAdapter<JWTUser>;
  private apiKeyVerifier: CustomTokenVerificationPortAdapter<APIKeyUser>;
  private basicAuthVerifier: CustomTokenVerificationPortAdapter<BasicAuthUser>;

  constructor() {
    // JWT for web application users
    this.jwtVerifier = TokenVerificationAdapterFactory.forJWT({
      async verifyToken(token: string): Promise<JWTUser> {
        const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
        
        // Load user context from database
        const user = await userService.getByUserId(payload.sub);
        if (!user || !user.isActive) {
          throw new Error('User not found or inactive');
        }

        return {
          sub: payload.sub,
          email: payload.email,
          role: payload.role,
          tenantId: payload.tenantId,
          permissions: await permissionService.getUserPermissions(payload.sub),
          exp: payload.exp,
          iat: payload.iat
        };
      }
    });

    // API Keys for partner integrations
    this.apiKeyVerifier = TokenVerificationAdapterFactory.forAPIKey(
      {
        async verifyToken(token: string): Promise<APIKeyUser> {
          const keyData = await apiKeyService.validateKey(token);
          
          if (!keyData || !keyData.isActive) {
            throw new Error('Invalid or inactive API key');
          }

          if (keyData.expiresAt && keyData.expiresAt < Date.now()) {
            throw new Error('API key has expired');
          }

          return {
            keyId: keyData.id,
            organizationId: keyData.organizationId,
            permissions: keyData.permissions,
            isActive: keyData.isActive,
            expiresAt: keyData.expiresAt,
            keyType: keyData.keyType
          };
        }
      },
      'keyId',
      'expiresAt'
    );

    // Basic Auth for system services
    this.basicAuthVerifier = new CustomTokenVerificationPortAdapter(
      {
        async verifyToken(token: string): Promise<BasicAuthUser> {
          const credentials = Buffer.from(token, 'base64').toString('ascii');
          const [username, password] = credentials.split(':');

          const user = await systemUserService.authenticate(username, password);
          if (!user) {
            throw new Error('Invalid system credentials');
          }

          return {
            username: user.username,
            userId: user.id,
            role: user.role,
            permissions: user.permissions,
            isActive: user.isActive
          };
        }
      },
      {
        userIdExtractor: (user) => user.userId,
        additionalValidation: (user) => user.isActive
      }
    );
  }

  // Route authentication based on request characteristics
  getAuthenticatorForRequest(req: any) {
    const authHeader = req.headers.authorization || '';
    const apiKey = req.headers['x-api-key'];
    const systemAuth = req.headers['x-system-auth'];

    // API Key authentication (partner integrations)
    if (apiKey) {
      return {
        verifier: this.apiKeyVerifier,
        config: {
          tokenHeader: 'x-api-key',
          tokenPrefix: '',
          allowInactiveUsers: false,
          requireEmailVerification: false
        }
      };
    }

    // Basic Auth for system services
    if (systemAuth && systemAuth.startsWith('Basic ')) {
      return {
        verifier: this.basicAuthVerifier,
        config: {
          tokenHeader: 'x-system-auth',
          tokenPrefix: 'Basic ',
          allowInactiveUsers: false,
          requireEmailVerification: false
        }
      };
    }

    // JWT for regular users (default)
    if (authHeader.startsWith('Bearer ')) {
      return {
        verifier: this.jwtVerifier,
        config: {
          tokenHeader: 'authorization',
          tokenPrefix: 'Bearer ',
          allowInactiveUsers: false,
          requireEmailVerification: true
        }
      };
    }

    throw new Error('No valid authentication method found');
  }
}

// Configure RouteGuards with multi-auth support
export const setupMultiAuth = async () => {
  const multiAuth = new MultiAuthService();
  
  // Permission source that handles all user types
  const userPermissionSource = {
    async getUserPermissions(userId: string): Promise<string[]> {
      // Determine user type and fetch permissions accordingly
      const userType = await determineUserType(userId);
      
      switch (userType) {
        case 'jwt':
          return await permissionService.getJWTUserPermissions(userId);
        case 'apikey':
          return await permissionService.getAPIKeyPermissions(userId);
        case 'system':
          return await permissionService.getSystemUserPermissions(userId);
        default:
          return [];
      }
    }
  };

  // Configure with production settings
  await RouteGuards.configure(
    GuardSetup.production(),
    userPermissionSource,
    multiAuth.jwtVerifier, // Default authenticator
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      allowInactiveUsers: false,
      requireEmailVerification: true
    }
  );
};
```

### E-commerce Platform with Multiple Access Levels

An e-commerce platform example showing different authentication methods for customers, merchants, and system integrations.

```typescript
// Configure different auth methods for different endpoint groups
export const setupEcommerceAuth = async () => {
  // Customer JWT authentication
  const customerAuth = TokenVerificationAdapterFactory.forJWT({
    async verifyToken(token: string) {
      const payload = jwt.verify(token, process.env.CUSTOMER_JWT_SECRET!);
      return {
        sub: payload.sub,
        email: payload.email,
        customerTier: payload.tier, // 'standard', 'premium', 'vip'
        permissions: await getCustomerPermissions(payload.sub, payload.tier),
        exp: payload.exp
      };
    }
  });

  // Merchant API Key authentication
  const merchantAuth = TokenVerificationAdapterFactory.forAPIKey(
    {
      async verifyToken(apiKey: string) {
        const merchant = await merchantService.validateAPIKey(apiKey);
        if (!merchant.store.isActive) {
          throw new Error('Merchant store is inactive');
        }
        return {
          merchantId: merchant.id,
          storeId: merchant.storeId,
          subscription: merchant.subscription, // 'basic', 'pro', 'enterprise'
          permissions: await getMerchantPermissions(merchant.subscription),
          expiresAt: merchant.apiKey.expiresAt
        };
      }
    },
    'merchantId',
    'expiresAt'
  );

  // Payment processor webhook authentication
  const webhookAuth = new CustomTokenVerificationPortAdapter(
    {
      async verifyToken(signature: string) {
        // Verify webhook signature from payment processor
        const isValid = await paymentService.verifyWebhookSignature(signature);
        if (!isValid) {
          throw new Error('Invalid webhook signature');
        }
        return {
          processorId: 'stripe', // or 'paypal', etc.
          permissions: ['webhook.process', 'payment.update', 'order.complete'],
          verified: true
        };
      }
    },
    {
      userIdExtractor: (user) => user.processorId,
      additionalValidation: (user) => user.verified
    }
  );

  // Route-specific authentication configurations
  const routeConfigs = {
    '/api/customer/*': {
      authenticator: customerAuth,
      config: { 
        tokenHeader: 'authorization', 
        tokenPrefix: 'Bearer ',
        requireEmailVerification: true 
      }
    },
    '/api/merchant/*': {
      authenticator: merchantAuth,
      config: { 
        tokenHeader: 'x-merchant-key', 
        tokenPrefix: '',
        allowInactiveUsers: false 
      }
    },
    '/webhook/payment/*': {
      authenticator: webhookAuth,
      config: { 
        tokenHeader: 'x-signature', 
        tokenPrefix: '',
        allowInactiveUsers: true 
      }
    }
  };

  // Configure main system with customer auth as default
  await RouteGuards.configure(
    GuardSetup.production(),
    createEcommercePermissionSource(),
    customerAuth,
    routeConfigs['/api/customer/*'].config
  );
};
```

### Microservices Architecture with Service-to-Service Auth

Example showing how to handle authentication in a microservices environment with different auth methods for external users vs internal services.

```typescript
interface ExternalUser {
  sub: string;
  scope: string[];
  client_id: string;
  exp: number;
  aud: string;
}

interface ServiceUser {
  serviceId: string;
  serviceName: string;
  permissions: string[];
  environment: 'development' | 'staging' | 'production';
  isActive: boolean;
}

export const setupMicroserviceAuth = async () => {
  // OAuth2 for external API consumers
  const oauth2Auth = TokenVerificationAdapterFactory.forOAuth(
    {
      async verifyToken(token: string): Promise<ExternalUser> {
        // Validate with OAuth2 provider
        const introspectResponse = await fetch(`${process.env.OAUTH2_INTROSPECT_URL}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`
          },
          body: `token=${token}`
        });

        const tokenInfo = await introspectResponse.json();
        if (!tokenInfo.active) {
          throw new Error('OAuth2 token is not active');
        }

        return tokenInfo as ExternalUser;
      }
    },
    ['api:read', 'api:write'] // Required OAuth2 scopes
  );

  // mTLS + JWT for service-to-service communication
  const serviceAuth = new CustomTokenVerificationPortAdapter(
    {
      async verifyToken(token: string): Promise<ServiceUser> {
        // Verify service JWT with service-specific secret
        const payload = jwt.verify(token, process.env.SERVICE_JWT_SECRET!) as any;
        
        // Validate service registration
        const service = await serviceRegistry.getService(payload.serviceId);
        if (!service || !service.isActive) {
          throw new Error('Service not registered or inactive');
        }

        // Verify environment constraints
        if (service.environment !== process.env.NODE_ENV) {
          throw new Error('Service environment mismatch');
        }

        return {
          serviceId: payload.serviceId,
          serviceName: payload.serviceName,
          permissions: service.permissions,
          environment: service.environment,
          isActive: service.isActive
        };
      }
    },
    {
      userIdExtractor: (user) => user.serviceId,
      additionalValidation: (user) => user.isActive && user.environment === process.env.NODE_ENV
    }
  );

  // Admin panel with enhanced JWT
  const adminAuth = TokenVerificationAdapterFactory.forJWT({
    async verifyToken(token: string) {
      const payload = jwt.verify(token, process.env.ADMIN_JWT_SECRET!) as any;
      
      // Additional admin validations
      const admin = await adminService.getAdmin(payload.sub);
      if (!admin.isSuperUser && !admin.hasValidMFA) {
        throw new Error('Admin requires valid MFA');
      }

      return {
        sub: payload.sub,
        email: payload.email,
        role: 'admin',
        permissions: await getAdminPermissions(payload.sub),
        mfaVerified: admin.hasValidMFA,
        lastLogin: admin.lastLogin,
        exp: payload.exp
      };
    }
  });

  // Route-based authentication strategy
  const authRoutes = new Map([
    ['/api/public/*', oauth2Auth],
    ['/api/internal/*', serviceAuth], 
    ['/api/admin/*', adminAuth]
  ]);

  // Configure with appropriate defaults
  await RouteGuards.configure(
    GuardSetup.production(),
    createMicroservicePermissionSource(),
    oauth2Auth, // Default for public API
    {
      tokenHeader: 'authorization',
      tokenPrefix: 'Bearer ',
      allowInactiveUsers: false,
      requireEmailVerification: false
    }
  );
};

// Helper to create environment-aware permission source
function createMicroservicePermissionSource() {
  return {
    async getUserPermissions(userId: string): Promise<string[]> {
      // Route to appropriate permission service based on user ID format
      if (userId.startsWith('service_')) {
        return await servicePermissionService.getPermissions(userId);
      } else if (userId.startsWith('admin_')) {
        return await adminPermissionService.getPermissions(userId);
      } else {
        return await externalUserPermissionService.getPermissions(userId);
      }
    }
  };
}
```

### Mobile App with Progressive Authentication

Example showing how to handle different authentication levels in a mobile application.

```typescript
interface GuestUser {
  sessionId: string;
  deviceId: string;
  permissions: string[];
  isGuest: true;
}

interface AuthenticatedUser {
  sub: string;
  email: string;
  phoneVerified: boolean;
  emailVerified: boolean;
  authLevel: 'basic' | 'verified' | 'premium';
  permissions: string[];
  isGuest: false;
}

export const setupMobileAuth = async () => {
  // Guest session for unauthenticated users
  const guestAuth = new CustomTokenVerificationPortAdapter(
    {
      async verifyToken(sessionToken: string): Promise<GuestUser> {
        const session = await sessionService.validateGuestSession(sessionToken);
        if (!session || session.isExpired) {
          throw new Error('Invalid or expired guest session');
        }

        return {
          sessionId: session.id,
          deviceId: session.deviceId,
          permissions: ['catalog.read', 'product.view'],
          isGuest: true
        };
      }
    },
    {
      userIdExtractor: (user) => user.sessionId
    }
  );

  // Authenticated users with progressive verification
  const userAuth = TokenVerificationAdapterFactory.forJWT({
    async verifyToken(token: string): Promise<AuthenticatedUser> {
      const payload = jwt.verify(token, process.env.MOBILE_JWT_SECRET!) as any;
      const user = await userService.getUserById(payload.sub);

      // Calculate authentication level based on verification status
      let authLevel: 'basic' | 'verified' | 'premium' = 'basic';
      if (user.emailVerified && user.phoneVerified) {
        authLevel = user.isPremium ? 'premium' : 'verified';
      }

      return {
        sub: payload.sub,
        email: payload.email,
        phoneVerified: user.phoneVerified,
        emailVerified: user.emailVerified,
        authLevel,
        permissions: await getMobileUserPermissions(payload.sub, authLevel),
        isGuest: false
      };
    }
  });

  // Biometric authentication for high-value operations
  const biometricAuth = new CustomTokenVerificationPortAdapter(
    {
      async verifyToken(biometricToken: string): Promise<AuthenticatedUser> {
        // Verify biometric signature
        const biometricData = await biometricService.verifySignature(biometricToken);
        if (!biometricData.isValid) {
          throw new Error('Biometric verification failed');
        }

        // Load user associated with biometric
        const user = await userService.getUserById(biometricData.userId);
        
        return {
          ...user,
          authLevel: 'premium', // Biometric always grants premium level
          permissions: await getMobileUserPermissions(user.sub, 'premium'),
          isGuest: false
        };
      }
    },
    {
      userIdExtractor: (user) => user.sub,
      additionalValidation: async (user) => {
        // Ensure biometric auth is recent (within 5 minutes)
        const lastBiometric = await biometricService.getLastVerification(user.sub);
        return lastBiometric && (Date.now() - lastBiometric) < 5 * 60 * 1000;
      }
    }
  );

  // Authentication strategy based on endpoint sensitivity
  const endpointAuthStrategy = {
    '/api/browse/*': guestAuth,           // Guest browsing
    '/api/user/*': userAuth,              // Authenticated user operations  
    '/api/payment/*': biometricAuth,      // High-value operations
    '/api/account/settings/*': biometricAuth // Sensitive account changes
  };

  // Configure with guest as default for mobile-first experience
  await RouteGuards.configure(
    GuardSetup.serverless(), // Optimized for mobile backend
    createMobilePermissionSource(),
    guestAuth,
    {
      tokenHeader: 'x-session-token',
      tokenPrefix: '',
      allowInactiveUsers: false,
      requireEmailVerification: false
    }
  );
};

function createMobilePermissionSource() {
  return {
    async getUserPermissions(userId: string): Promise<string[]> {
      // Handle different user types in mobile context
      if (userId.startsWith('guest_')) {
        return ['catalog.read', 'product.view'];
      } else if (userId.startsWith('user_')) {
        const user = await userService.getUserById(userId);
        return await getMobileUserPermissions(userId, user.authLevel);
      }
      return [];
    }
  };
}

async function getMobileUserPermissions(userId: string, authLevel: string): Promise<string[]> {
  const basePermissions = ['catalog.read', 'product.view', 'cart.manage'];
  
  switch (authLevel) {
    case 'verified':
      return [...basePermissions, 'order.create', 'profile.update'];
    case 'premium':
      return [...basePermissions, 'order.create', 'profile.update', 'payment.process', 'account.settings'];
    default:
      return basePermissions;
  }
}
```

### Configuration Best Practices

#### Environment-Based Configuration

```typescript
// config/auth.ts
export const getAuthConfig = () => {
  const environment = process.env.NODE_ENV || 'development';
  
  const configs = {
    development: {
      cache: { enabled: false, ttl: 60000 },
      security: { strictValidation: false, logLevel: 'debug' },
      authentication: { 
        requireEmailVerification: false,
        allowTestTokens: true 
      }
    },
    staging: {
      cache: { enabled: true, ttl: 300000 },
      security: { strictValidation: true, logLevel: 'info' },
      authentication: { 
        requireEmailVerification: true,
        allowTestTokens: false 
      }
    },
    production: {
      cache: { enabled: true, ttl: 900000 },
      security: { strictValidation: true, logLevel: 'warn' },
      authentication: { 
        requireEmailVerification: true,
        allowTestTokens: false 
      }
    }
  };

  return configs[environment] || configs.development;
};
```

#### Monitoring and Observability

```typescript
// monitoring/auth-metrics.ts
export const setupAuthMonitoring = () => {
  // Track authentication method usage
  const authMethodMetrics = new Map<string, number>();
  
  // Monitor authentication performance
  const performanceMetrics = {
    jwtValidation: new TimingHistogram(),
    apiKeyLookup: new TimingHistogram(),
    basicAuthValidation: new TimingHistogram()
  };

  // Set up alerts for authentication failures
  const failureThresholds = {
    jwt: { count: 100, window: '5m' },
    apiKey: { count: 50, window: '5m' },
    basicAuth: { count: 25, window: '5m' }
  };

  return {
    trackAuthMethod: (method: string) => {
      authMethodMetrics.set(method, (authMethodMetrics.get(method) || 0) + 1);
    },
    trackPerformance: (method: string, duration: number) => {
      performanceMetrics[method]?.record(duration);
    },
    getMetrics: () => ({
      usage: Object.fromEntries(authMethodMetrics),
      performance: Object.fromEntries(
        Object.entries(performanceMetrics).map(([key, histogram]) => 
          [key, histogram.summary()]
        )
      )
    })
  };
};
```

These real-world examples demonstrate how RouteGuards can be configured to handle complex authentication scenarios in production applications. Each example shows different strategies for combining multiple authentication methods while maintaining security, performance, and usability.

---

## Conclusion

RouteGuards provides a powerful, flexible authentication and authorization system for the Noony Framework. By understanding the trade-offs between different strategies and configurations, you can build secure, high-performance applications that scale with your needs.

### Key Takeaways:

1. **Choose the Right Strategy**: Plain for performance, Wildcard for hierarchy, Expression for complex rules
2. **Balance Security vs Performance**: Configure cache TTL and invalidation based on your requirements
3. **Monitor Continuously**: Track cache hit rates and response times
4. **Start Simple**: Begin with Plain permissions and add complexity only when needed
5. **Plan for Scale**: Design permission models that grow with your application

For additional help, refer to the [examples directory](../examples/) for working implementations and the [API documentation](./api/) for detailed interface specifications.
