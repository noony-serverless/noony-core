/**
 * Domain Entity Type Definitions for Fastify Production API Example
 *
 * This file contains domain-specific type definitions including:
 * - Core business entities (User, Session, etc.)
 * - Authentication and authorization types
 * - Service interfaces and contracts
 * - Configuration and environment types
 *
 * These types represent the core business domain and are independent
 * of API transport concerns (HTTP, JSON, etc.).
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

/**
 * =============================================================================
 * CORE DOMAIN ENTITIES
 * =============================================================================
 */

/**
 * User entity representing a system user
 *
 * This is the core domain model for users, containing:
 * - Identity information (id, email, name)
 * - Profile data (age, department, bio, phone)
 * - System metadata (timestamps, status)
 *
 * Design Notes:
 * - ID is UUID for distributed systems compatibility
 * - Email serves as unique identifier for authentication
 * - Timestamps track creation and modification for audit trails
 * - Status allows for soft deletion and account management
 */
export interface User {
  /** Unique identifier - UUID v4 */
  id: string;

  /** Full name of the user */
  name: string;

  /** Email address - unique, used for authentication */
  email: string;

  /** Age in years */
  age: number;

  /** Optional department/organization */
  department?: string;

  /** Optional phone number */
  phoneNumber?: string;

  /** Optional bio/description */
  bio?: string;

  /** Account status */
  status: UserStatus;

  /** When the user account was created */
  createdAt: string;

  /** When the user account was last updated */
  updatedAt?: string;

  /** When the user account was soft deleted (if applicable) */
  deletedAt?: string;

  /** User's role in the system */
  role: UserRole;

  /** User's permissions (derived from role and custom assignments) */
  permissions: Permission[];

  /** Last time user was active in the system */
  lastLoginAt?: string;

  /** Whether the user's email has been verified */
  emailVerified: boolean;

  /** User preferences and settings */
  preferences: UserPreferences;
}

/**
 * User account status enumeration
 *
 * Allows for flexible account management:
 * - active: Normal operational status
 * - inactive: Temporarily disabled account
 * - suspended: Account suspended due to violations
 * - deleted: Soft-deleted account (can be restored)
 */
export type UserStatus = 'active' | 'inactive' | 'suspended' | 'deleted';

/**
 * User role enumeration
 *
 * Hierarchical role system for access control:
 * - user: Standard user with basic permissions
 * - moderator: Extended permissions for content management
 * - admin: Full administrative access
 * - system: System-level operations (automated processes)
 */
export type UserRole = 'user' | 'moderator' | 'admin' | 'system';

/**
 * Permission enumeration
 *
 * Granular permissions for fine-grained access control
 * Follows the pattern: resource:action
 */
export type Permission =
  // User management permissions
  | 'user:create'
  | 'user:read'
  | 'user:update'
  | 'user:delete'
  | 'user:list'

  // Administrative permissions
  | 'admin:users'
  | 'admin:system'
  | 'admin:monitoring'

  // Content management permissions
  | 'content:create'
  | 'content:read'
  | 'content:update'
  | 'content:delete'
  | 'content:moderate'

  // System permissions
  | 'system:health'
  | 'system:metrics'
  | 'system:logs';

/**
 * User preferences and settings
 *
 * Customizable user settings for personalization
 * Can be extended with additional preferences
 */
export interface UserPreferences {
  /** Preferred language (ISO 639-1 code) */
  language: string;

  /** Preferred timezone (IANA timezone identifier) */
  timezone: string;

  /** Email notification settings */
  notifications: {
    email: boolean;
    push: boolean;
    marketing: boolean;
  };

  /** UI/UX preferences */
  ui: {
    theme: 'light' | 'dark' | 'auto';
    compactMode: boolean;
  };
}

/**
 * =============================================================================
 * AUTHENTICATION & SESSION TYPES
 * =============================================================================
 */

/**
 * Authenticated user context
 *
 * Represents the current authenticated user in the system
 * Used throughout the application for authorization decisions
 * Contains essential information from JWT token claims
 */
export interface AuthenticatedUser {
  /** User's unique identifier */
  userId: string;

  /** User's email address */
  email: string;

  /** User's display name */
  name: string;

  /** User's role for role-based access control */
  role: UserRole;

  /** User's specific permissions */
  permissions: Permission[];

  /** When the authentication token was issued */
  issuedAt: number;

  /** When the authentication token expires */
  expiresAt: number;

  /** JWT token identifier for revocation */
  jti?: string;
}

/**
 * JWT token payload structure
 *
 * Standard JWT claims plus custom application claims
 * Used for token generation and verification
 */
export interface JWTPayload {
  /** Subject - user ID */
  sub: string;

  /** Issued at - timestamp */
  iat: number;

  /** Expires at - timestamp */
  exp: number;

  /** JWT ID for token revocation */
  jti: string;

  /** Issuer */
  iss: string;

  /** Audience */
  aud: string;

  /** Custom claims */
  email: string;
  name: string;
  role: UserRole;
  permissions: Permission[];
}

/**
 * Session information
 *
 * Tracks user sessions for security and monitoring
 * Can be used for concurrent session limits
 */
export interface UserSession {
  /** Unique session identifier */
  id: string;

  /** User ID associated with this session */
  userId: string;

  /** JWT token ID */
  tokenId: string;

  /** When the session was created */
  createdAt: string;

  /** When the session was last active */
  lastActiveAt: string;

  /** When the session expires */
  expiresAt: string;

  /** Client information */
  client: {
    userAgent: string;
    ipAddress: string;
    device?: string;
    os?: string;
    browser?: string;
  };

  /** Whether the session is still valid */
  isActive: boolean;
}

/**
 * =============================================================================
 * SERVICE INTERFACES
 * =============================================================================
 */

/**
 * User service interface
 *
 * Defines the contract for user management operations
 * Implemented by concrete service classes
 */
export interface IUserService {
  /** Create a new user account */
  createUser(
    userData: Omit<
      User,
      | 'id'
      | 'createdAt'
      | 'updatedAt'
      | 'status'
      | 'role'
      | 'permissions'
      | 'preferences'
      | 'emailVerified'
    >
  ): Promise<{ id: string; user: User }>;

  /** Retrieve a user by their ID */
  getUserById(id: string): Promise<User | null>;

  /** Retrieve a user by their email address */
  getUserByEmail(email: string): Promise<User | null>;

  /** Update an existing user */
  updateUser(id: string, updateData: Partial<User>): Promise<User | null>;

  /** Soft delete a user */
  deleteUser(id: string): Promise<boolean>;

  /** Get a paginated list of users */
  getAllUsers(query: {
    page: number;
    limit: number;
    search?: string;
    department?: string;
    sortBy: string;
    sortOrder: 'asc' | 'desc';
    minAge?: number;
    maxAge?: number;
    includeDeleted?: boolean;
  }): Promise<{
    users: User[];
    total: number;
    pagination: {
      page: number;
      limit: number;
      totalPages: number;
      hasNextPage: boolean;
      hasPreviousPage: boolean;
    };
  }>;

  /** Verify if an email address is already in use */
  isEmailTaken(email: string, excludeUserId?: string): Promise<boolean>;
}

/**
 * Authentication service interface
 *
 * Defines the contract for authentication operations
 */
export interface IAuthService {
  /** Authenticate a user with email and password */
  login(
    email: string,
    password: string
  ): Promise<{
    token: string;
    user: AuthenticatedUser;
    expiresAt: string;
  }>;

  /** Verify a JWT token and return user context */
  verifyToken(token: string): Promise<AuthenticatedUser>;

  /** Generate a new JWT token for a user */
  generateToken(user: User): Promise<{
    token: string;
    expiresAt: string;
  }>;

  /** Revoke a JWT token */
  revokeToken(tokenId: string): Promise<void>;

  /** Change a user's password */
  changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<boolean>;

  /** Hash a password for storage */
  hashPassword(password: string): Promise<string>;

  /** Verify a password against a hash */
  verifyPassword(password: string, hash: string): Promise<boolean>;
}

/**
 * =============================================================================
 * CONFIGURATION TYPES
 * =============================================================================
 */

/**
 * Application configuration interface
 *
 * Centralized configuration with proper typing
 * Loaded from environment variables with defaults
 */
export interface AppConfig {
  /** Server configuration */
  server: {
    fastify: {
      port: number;
      host: string;
    };
    functions: {
      port: number;
    };
  };

  /** Security configuration */
  security: {
    jwt: {
      secret: string;
      expiresIn: string;
      algorithm: string;
    };
    bcrypt: {
      rounds: number;
    };
    rateLimit: {
      max: number;
      windowMs: number;
    };
  };

  /** API configuration */
  api: {
    version: string;
    prefix: string;
    pagination: {
      defaultPageSize: number;
      maxPageSize: number;
    };
    limits: {
      maxRequestSize: string;
      maxUploadSize: string;
    };
  };

  /** Feature flags */
  features: {
    advancedSearch: boolean;
    userAnalytics: boolean;
    betaEndpoints: boolean;
  };

  /** Development settings */
  development: {
    enableRequestId: boolean;
    performanceTracking: boolean;
    prettyPrintLogs: boolean;
    mockExternalServices: boolean;
  };

  /** Environment information */
  environment: {
    nodeEnv: 'development' | 'staging' | 'production';
    logLevel: string;
    debug: boolean;
  };
}

/**
 * =============================================================================
 * ERROR TYPES
 * =============================================================================
 */

/**
 * Application-specific error types
 *
 * Extends the base Error class with additional context
 * for better error handling and API responses
 */
export class AppError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 400,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/**
 * Validation error for invalid input data
 */
export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 'VALIDATION_ERROR', 400, details);
    this.name = 'ValidationError';
  }
}

/**
 * Authentication error for invalid credentials
 */
export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTHENTICATION_ERROR', 401);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization error for insufficient permissions
 */
export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 'AUTHORIZATION_ERROR', 403);
    this.name = 'AuthorizationError';
  }
}

/**
 * Not found error for missing resources
 */
export class NotFoundError extends AppError {
  constructor(resource: string = 'Resource') {
    super(`${resource} not found`, 'NOT_FOUND', 404);
    this.name = 'NotFoundError';
  }
}

/**
 * Conflict error for duplicate resources
 */
export class ConflictError extends AppError {
  constructor(message: string) {
    super(message, 'CONFLICT', 409);
    this.name = 'ConflictError';
  }
}

/**
 * Rate limit error for too many requests
 */
export class RateLimitError extends AppError {
  constructor(message: string = 'Too many requests') {
    super(message, 'RATE_LIMIT_EXCEEDED', 429);
    this.name = 'RateLimitError';
  }
}

/**
 * =============================================================================
 * UTILITY TYPES
 * =============================================================================
 */

/**
 * Request context for middleware
 *
 * Contains shared data between middlewares in a single request
 */
export interface RequestContext {
  /** Unique request identifier */
  requestId: string;

  /** When the request started processing */
  startTime: Date;

  /** Current authenticated user (if any) */
  user?: AuthenticatedUser;

  /** Client information */
  client: {
    ipAddress: string;
    userAgent: string;
  };

  /** Request metadata */
  metadata: {
    method: string;
    path: string;
    query: Record<string, any>;
    headers: Record<string, string>;
  };
}

/**
 * Performance metrics for monitoring
 */
export interface PerformanceMetrics {
  /** Request processing duration in milliseconds */
  duration: number;

  /** Memory usage at request start */
  memoryStart: NodeJS.MemoryUsage;

  /** Memory usage at request end */
  memoryEnd: NodeJS.MemoryUsage;

  /** Database query count */
  dbQueries: number;

  /** External API calls count */
  externalCalls: number;

  /** Cache hits/misses */
  cache: {
    hits: number;
    misses: number;
  };
}

/**
 * Health check status for monitoring
 */
export interface ServiceHealth {
  /** Overall service status */
  status: 'healthy' | 'degraded' | 'unhealthy';

  /** Individual component health */
  components: {
    database: 'healthy' | 'degraded' | 'unhealthy';
    cache: 'healthy' | 'degraded' | 'unhealthy';
    externalServices: 'healthy' | 'degraded' | 'unhealthy';
  };

  /** Performance metrics */
  metrics: {
    uptime: number;
    memoryUsage: NodeJS.MemoryUsage;
    requestsPerMinute: number;
    averageResponseTime: number;
    errorRate: number;
  };
}
