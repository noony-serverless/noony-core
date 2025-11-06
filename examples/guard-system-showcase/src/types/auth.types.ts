/**
 * Authentication System Type Definitions
 *
 * Comprehensive type definitions for the Guard System Showcase authentication
 * components. These types support multiple authentication strategies and
 * provide full type safety throughout the authentication pipeline.
 *
 * @module AuthTypes
 * @version 1.0.0
 */

import { PermissionResolverType } from '@noony-serverless/core';

// ============================================================================
// CORE AUTHENTICATION TYPES
// ============================================================================

/**
 * User authentication context with comprehensive metadata
 */
export interface UserContext {
  /** Unique user identifier */
  userId: string;

  /** User's display name */
  name: string;

  /** User's email address */
  email: string;

  /** Set of user's permissions for O(1) lookup */
  permissions: Set<string>;

  /** User's assigned roles */
  roles: string[];

  /** Additional user metadata */
  metadata: {
    /** User account status */
    status: 'active' | 'inactive' | 'suspended' | 'pending';

    /** Email verification status */
    emailVerified: boolean;

    /** User's department/organization unit */
    department?: string;

    /** User's job title or position */
    title?: string;

    /** Account creation timestamp */
    createdAt: string;

    /** Last login timestamp */
    lastLoginAt?: string;

    /** Account last updated timestamp */
    updatedAt: string;

    /** Any additional custom metadata */
    [key: string]: unknown;
  };

  /** Pre-expanded permissions for wildcard resolution (optional) */
  expandedPermissions?: Set<string>;

  /** Context creation timestamp */
  lastUpdated: string;

  /** Context expiration time (optional) */
  expiresAt?: string;
}

/**
 * JWT token payload structure
 */
export interface TokenPayload {
  /** Subject (user ID) */
  sub: string;

  /** Token issuer */
  iss: string;

  /** Token audience */
  aud: string;

  /** Expiration time (Unix timestamp) */
  exp: number;

  /** Issued at time (Unix timestamp) */
  iat: number;

  /** Not before time (Unix timestamp) */
  nbf?: number;

  /** JWT ID */
  jti?: string;

  /** User's email */
  email?: string;

  /** User's name */
  name?: string;

  /** User's roles */
  roles?: string[];

  /** Custom claims */
  [key: string]: unknown;
}

/**
 * Token validation result
 */
export interface TokenValidationResult {
  /** Whether the token is valid */
  valid: boolean;

  /** Decoded token payload (if valid) */
  decoded?: TokenPayload;

  /** Validation error message (if invalid) */
  error?: string;

  /** Token validation metadata */
  metadata?: {
    /** Validation duration in microseconds */
    validationTimeUs: number;

    /** Whether result was cached */
    cached: boolean;

    /** Token validator type used */
    validatorType: string;
  };
}

// ============================================================================
// PERMISSION SYSTEM TYPES
// ============================================================================

/**
 * Permission check request
 */
export interface PermissionCheckRequest {
  /** User ID to check permissions for */
  userId: string;

  /** Permission requirement (varies by resolver type) */
  requirement: string[] | string | PermissionExpression;

  /** Preferred resolver type */
  resolverType?: PermissionResolverType;

  /** Additional context for permission resolution */
  context?: Record<string, unknown>;
}

/**
 * Complex permission expression for boolean logic
 */
export interface PermissionExpression {
  /** Logical AND - all sub-expressions must be true */
  and?: PermissionExpression[];

  /** Logical OR - at least one sub-expression must be true */
  or?: PermissionExpression[];

  /** Logical NOT - sub-expression must be false */
  not?: PermissionExpression;

  /** Leaf permission string to check */
  permission?: string;

  /** Optional metadata for the expression */
  metadata?: {
    description?: string;
    businessRule?: string;
  };
}

/**
 * Permission check result with detailed metadata
 */
export interface PermissionCheckResult {
  /** Whether permission check passed */
  allowed: boolean;

  /** Resolver type used for the check */
  resolverType: PermissionResolverType;

  /** Time taken to resolve permission in microseconds */
  resolutionTimeUs: number;

  /** Whether the result was served from cache */
  cached: boolean;

  /** Reason for denial (if not allowed) */
  reason?: string;

  /** Permissions that matched the requirement */
  matchedPermissions?: string[];

  /** Additional metadata about the check */
  metadata?: {
    /** Cache key used (if applicable) */
    cacheKey?: string;

    /** User context load time */
    userContextLoadTimeUs?: number;

    /** Number of permissions evaluated */
    permissionsEvaluated?: number;

    /** Pattern matching time for wildcard resolver */
    patternMatchTimeUs?: number;

    /** Expression evaluation time for expression resolver */
    expressionEvaluationTimeUs?: number;

    /** Expression complexity score */
    expressionComplexity?: number;

    /** Whether short-circuit evaluation was used */
    shortCircuited?: boolean;

    /** Original expression string */
    originalExpression?: string;

    /** Expanded permissions count */
    expandedPermissions?: number;

    /** Patterns matched */
    patterns?: string[];

    /** Resolver selection metadata */
    resolverSelection?: {
      selectedType: PermissionResolverType;
      reason: string;
      autoSelected: boolean;
    };

    /** Error information */
    error?: string;

    /** Failover attempt number */
    failoverAttempt?: number;

    /** Performance comparison metadata */
    performanceComparison?: {
      compared: number;
      fastestResolver: PermissionResolverType;
      performanceDifference: number;
      recommendedResolver: PermissionResolverType;
    };

    /** A/B test metadata */
    abTest?: {
      controlResolver: PermissionResolverType;
      testResolver: PermissionResolverType;
      performanceDifference: number;
      consistentResult: boolean;
    };
  };
}

// ============================================================================
// AUTHENTICATION PROVIDERS
// ============================================================================

/**
 * Supported authentication provider types
 */
export enum AuthProviderType {
  JWT = 'jwt',
  FIREBASE = 'firebase',
  AUTH0 = 'auth0',
  CUSTOM = 'custom',
}

/**
 * Firebase authentication configuration
 */
export interface FirebaseAuthConfig {
  projectId: string;
  privateKey: string;
  clientEmail: string;
}

/**
 * Auth0 authentication configuration
 */
export interface Auth0Config {
  domain: string;
  clientId: string;
  clientSecret: string;
  audience: string;
}

/**
 * JWT authentication configuration
 */
export interface JWTAuthConfig {
  secret?: string;
  publicKey?: string;
  algorithm: string;
  issuer: string;
  audience: string;
}

/**
 * General authentication configuration
 */
export interface AuthConfig {
  /** Authentication provider type */
  provider: AuthProviderType;

  /** Token header name (default: 'authorization') */
  tokenHeader: string;

  /** Token prefix (default: 'Bearer ') */
  tokenPrefix: string;

  /** Provider-specific configuration */
  config: JWTAuthConfig | FirebaseAuthConfig | Auth0Config;

  /** Whether to require email verification */
  requireEmailVerification: boolean;

  /** Whether to allow inactive users */
  allowInactiveUsers: boolean;

  /** Custom token validation function */
  customValidation?: (
    token: TokenPayload,
    user: UserContext
  ) => Promise<boolean>;

  /** Token refresh configuration */
  refresh?: {
    enabled: boolean;
    ttl: number;
    sliding: boolean;
  };
}

// ============================================================================
// USER MANAGEMENT TYPES
// ============================================================================

/**
 * User account status options
 */
export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  PENDING = 'pending',
}

/**
 * Role definition with metadata
 */
export interface Role {
  /** Unique role identifier */
  id: string;

  /** Human-readable role name */
  name: string;

  /** Role description */
  description: string;

  /** Permissions granted by this role */
  permissions: string[];

  /** Parent role (for role hierarchy) */
  parent?: string;

  /** Child roles (for role hierarchy) */
  children?: string[];

  /** Role metadata */
  metadata: {
    /** Role creation timestamp */
    createdAt: string;

    /** Role last updated timestamp */
    updatedAt: string;

    /** Role priority/weight */
    priority?: number;

    /** Whether role is system-defined */
    system?: boolean;
  };
}

/**
 * Permission definition with metadata
 */
export interface Permission {
  /** Permission string identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Permission description */
  description: string;

  /** Permission category */
  category: string;

  /** Resource this permission applies to */
  resource: string;

  /** Action this permission allows */
  action: string;

  /** Permission metadata */
  metadata: {
    /** Creation timestamp */
    createdAt: string;

    /** Last updated timestamp */
    updatedAt: string;

    /** Whether permission is dangerous */
    sensitive?: boolean;

    /** Required conditions for permission */
    conditions?: string[];
  };
}

// ============================================================================
// DEMO AND TESTING TYPES
// ============================================================================

/**
 * Demo user account for testing
 */
export interface DemoUser {
  /** User basic information */
  userId: string;
  name: string;
  email: string;

  /** Authentication information */
  password: string;
  roles: string[];
  permissions: string[];

  /** Demo-specific metadata */
  demo: {
    /** Demo scenario this user represents */
    scenario: string;

    /** User type for demo purposes */
    type: 'basic' | 'admin' | 'moderator' | 'restricted';

    /** JWT tokens for testing */
    tokens: {
      access: string;
      refresh?: string;
    };

    /** Expected behavior in tests */
    expectedBehavior: {
      [endpoint: string]: 'allow' | 'deny';
    };
  };
}

/**
 * Security test scenario
 */
export interface SecurityTestScenario {
  /** Test scenario identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Test description */
  description: string;

  /** Test category */
  category: 'authentication' | 'authorization' | 'injection' | 'abuse';

  /** Test steps */
  steps: SecurityTestStep[];

  /** Expected results */
  expectedResults: {
    shouldSucceed: boolean;
    expectedStatus?: number;
    expectedMessage?: string;
  };
}

/**
 * Individual security test step
 */
export interface SecurityTestStep {
  /** Step name */
  name: string;

  /** HTTP method */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

  /** Request path */
  path: string;

  /** Request headers */
  headers?: Record<string, string>;

  /** Request body */
  body?: unknown;

  /** Expected response */
  expect: {
    status: number;
    body?: unknown;
    headers?: Record<string, string>;
  };
}

// ============================================================================
// MONITORING AND ANALYTICS TYPES
// ============================================================================

/**
 * Authentication metrics
 */
export interface AuthMetrics {
  /** Total authentication attempts */
  totalAttempts: number;

  /** Successful authentications */
  successfulAuths: number;

  /** Failed authentication attempts */
  failedAttempts: number;

  /** Authentication success rate (0-100) */
  successRate: number;

  /** Cache hit rate for authentication (0-100) */
  cacheHitRate: number;

  /** Average authentication time in microseconds */
  averageAuthTimeUs: number;

  /** Blocked tokens count */
  blockedTokens: number;

  /** Suspicious activity events */
  suspiciousActivity: number;
}

/**
 * Permission system metrics
 */
export interface PermissionMetrics {
  /** Permission checks by resolver type */
  checksByResolver: Record<PermissionResolverType, number>;

  /** Average resolution times by resolver type */
  averageTimesByResolver: Record<PermissionResolverType, number>;

  /** Cache hit rates by resolver type */
  cacheHitRatesByResolver: Record<PermissionResolverType, number>;

  /** Most frequently checked permissions */
  topPermissions: Array<{ permission: string; count: number }>;

  /** Permission check success rate */
  overallSuccessRate: number;
}

/**
 * System health metrics
 */
export interface SystemHealthMetrics {
  /** System uptime in milliseconds */
  uptimeMs: number;

  /** Memory usage statistics */
  memory: {
    used: number;
    available: number;
    percentage: number;
  };

  /** Cache statistics */
  cache: {
    entries: number;
    hitRate: number;
    memoryUsage: number;
  };

  /** Request statistics */
  requests: {
    total: number;
    errors: number;
    errorRate: number;
    averageResponseTime: number;
  };

  /** Guard system specific metrics */
  guards: {
    totalChecks: number;
    averageProcessingTime: number;
    errorRate: number;
  };
}
