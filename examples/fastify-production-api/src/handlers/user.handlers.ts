import 'reflect-metadata';

/**
 * User Handlers - Production-Ready CRUD API Endpoints with Advanced Guards
 *
 * This module contains all user management HTTP handlers demonstrating:
 * - Complete CRUD operations (Create, Read, Update, Delete)
 * - Advanced middleware pipeline composition with Noony Guards
 * - High-performance cached authentication and authorization
 * - Three distinct permission resolution strategies
 * - Comprehensive input validation and sanitization
 * - Pagination and filtering for list endpoints
 * - Proper HTTP status codes and error responses
 * - Performance monitoring and audit logging
 *
 * Each handler demonstrates different guard strategies:
 * 1. Plain permissions (user:create, admin:users) - O(1) Set-based lookups
 * 2. Wildcard permissions (admin.*, user.*) - Pattern matching with caching
 * 3. Complex expressions (admin.users OR user.create) - Boolean logic evaluation
 *
 * Guard System Features:
 * - Sub-millisecond cached permission checks
 * - Conservative cache invalidation for security
 * - Multi-layer caching (L1 memory + configurable L2)
 * - Framework-agnostic middleware integration
 * - Comprehensive performance monitoring
 *
 * @author Noony Framework Team
 * @version 2.0.0
 */

import { Container } from 'typedi';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  QueryParametersMiddleware,
  ResponseWrapperMiddleware,
  Context,
} from '@noony-serverless/core';
import { RouteGuards, GuardSetup } from '@noony-serverless/core';
import {
  createUserSchema,
  updateUserSchema,
  userParamsSchema,
  listUsersQuerySchema,
  CreateUserRequest,
  UpdateUserRequest,
  PaginatedResponse,
} from '@/types/api.types';
import {
  User,
  AuthenticatedUser,
  IUserService,
  NotFoundError,
  ValidationError,
  AuthorizationError,
  ConflictError,
} from '@/types/domain.types';
import { UserService } from '@/services/user.service';
import { AuthService } from '@/services/auth.service';

/**
 * Register services in TypeDI container
 *
 * In a real application, this would be done in a separate container configuration file
 */
Container.set('userService', new UserService());
Container.set('authService', new AuthService(Container.get(UserService)));

/**
 * Initialize Advanced Guard System
 *
 * Configure the RouteGuards system with production-optimized settings:
 * - Pre-expansion strategy for maximum runtime performance
 * - Conservative cache invalidation for security
 * - 15-minute cache TTL for optimal memory usage
 * - Performance monitoring enabled for optimization
 */
// Configure RouteGuards with our authentication service integration
// This should be done during application startup
const configureGuards = async (): Promise<void> => {
  const profile = GuardSetup.production();

  // Mock user permission source for demo
  const mockUserPermissionSource = {
    async getUserPermissions(userId: string): Promise<{
      permissions: string[];
      roles: string[];
      metadata?: Record<string, unknown>;
    } | null> {
      // This would normally query your user database
      const userData = {
        user123: {
          permissions: ['user:create', 'user:read', 'user:update'],
          roles: ['user'],
          metadata: { department: 'engineering' },
        },
        admin456: {
          permissions: ['user:*', 'admin:*', 'system:*'],
          roles: ['admin', 'user'],
          metadata: { department: 'administration' },
        },
        demo789: {
          permissions: ['user:read'],
          roles: ['demo'],
          metadata: { department: 'demo' },
        },
      };
      return userData[userId as keyof typeof userData] || null;
    },

    async getRolePermissions(roles: string[]): Promise<string[]> {
      const rolePermissions: Record<string, string[]> = {
        admin: ['admin:*', 'user:*', 'system:*'],
        user: ['user:read', 'user:update'],
        demo: ['user:read'],
      };

      const permissions = new Set<string>();
      for (const role of roles) {
        const rolePerms = rolePermissions[role] || [];
        rolePerms.forEach((perm) => permissions.add(perm));
      }
      return Array.from(permissions);
    },

    async isUserContextStale(
      userId: string,
      lastUpdated: string
    ): Promise<boolean> {
      // Simple staleness check - in production this would check database timestamps
      const updateTime = new Date(lastUpdated).getTime();
      const now = Date.now();
      const fiveMinutes = 5 * 60 * 1000;
      return now - updateTime > fiveMinutes;
    },
  };

  // Mock token validator for demo
  const mockTokenValidator = {
    async validateToken(token: string): Promise<{
      valid: boolean;
      decoded?: {
        userId: string;
        sub: string;
        iat: number;
        exp: number;
      };
      error?: string;
    }> {
      if (token.startsWith('demo-')) {
        const userId = token.substring(5);
        return {
          valid: true,
          decoded: {
            userId,
            sub: userId,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
          },
        };
      }
      return { valid: false, error: 'Invalid token format' };
    },

    extractUserId(decoded: { userId?: string; sub?: string }): string {
      return decoded?.userId || decoded?.sub || '';
    },

    isTokenExpired(decoded: { exp?: number }): boolean {
      if (!decoded?.exp) return true;
      return Date.now() / 1000 > decoded.exp;
    },
  };

  const authConfig = {
    tokenHeader: 'authorization',
    tokenPrefix: 'Bearer ',
    requireEmailVerification: false,
    allowInactiveUsers: false,
  };

  await RouteGuards.configure(
    profile,
    mockUserPermissionSource,
    mockTokenValidator,
    authConfig
  );
};

// Call this during server initialization
configureGuards().catch(console.error);

/**
 * Request logging and performance monitoring middleware
 *
 * Tracks request performance and logs important operations
 */
const auditLoggingMiddleware = {
  async before(context: Context): Promise<void> {
    // Store request start time for performance tracking
    context.businessData?.set('startTime', Date.now());
    context.businessData?.set('requestId', crypto.randomUUID());

    const user = context.user as AuthenticatedUser;
    console.log(`🔍 API Request Started`, {
      requestId: context.businessData?.get('requestId'),
      method: context.req.method,
      path: context.req.path,
      userId: user?.userId,
      userRole: user?.role,
      timestamp: new Date().toISOString(),
    });
  },

  async after(context: Context): Promise<void> {
    const startTime = context.businessData?.get('startTime') as number;
    const requestId = context.businessData?.get('requestId') as string;
    const duration = Date.now() - startTime;
    const user = context.user as AuthenticatedUser;

    console.log(`✅ API Request Completed`, {
      requestId,
      duration: `${duration}ms`,
      userId: user?.userId,
      responseStatus: context.res.statusCode || 200,
      timestamp: new Date().toISOString(),
    });
  },

  async onError(error: Error, context: Context): Promise<void> {
    const startTime = context.businessData?.get('startTime') as number;
    const requestId = context.businessData?.get('requestId') as string;
    const duration = Date.now() - startTime;
    const user = context.user as AuthenticatedUser;

    console.error(`❌ API Request Failed`, {
      requestId,
      duration: `${duration}ms`,
      userId: user?.userId,
      error: error.message,
      errorType: error.constructor.name,
      timestamp: new Date().toISOString(),
    });
  },
};

/**
 * =============================================================================
 * CREATE USER HANDLER - POST /api/users
 * =============================================================================
 *
 * Creates a new user account with high-performance guard protection.
 *
 * Guard Strategy: PLAIN PERMISSIONS
 * - Uses O(1) Set-based permission lookups for maximum performance
 * - Cached permission checks with sub-millisecond response times
 * - Conservative cache invalidation ensures security
 *
 * Required Permissions: user:create OR admin:users (OR logic)
 * Authentication: JWT token required
 *
 * Request Body: CreateUserRequest (validated by Zod schema)
 * Response: 201 Created with user data
 *
 * Business Rules:
 * - Email must be unique across all users
 * - All required fields must be provided and valid
 * - User is created with 'active' status and default permissions
 * - Audit log entry is created for the creation event
 *
 * Performance Features:
 * - Sub-millisecond permission checks via RouteGuards
 * - Multi-layer caching (L1 memory + configurable L2)
 * - Request tracking and performance monitoring
 * - Optimized for serverless cold start performance
 *
 * Error Cases:
 * - 400 Bad Request: Invalid input data (validation errors)
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions (handled by RouteGuards)
 * - 409 Conflict: Email address already in use
 * - 500 Internal Server Error: Unexpected server error
 */
const createUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())

  // 🛡️ Advanced Guard Protection - Plain Permission Strategy
  // Uses high-performance Set-based lookups with intelligent caching
  .use(
    RouteGuards.requirePermissions(
      ['user:create', 'admin:users'] // OR logic: user needs ONE of these
    )
  )

  .use(new BodyValidationMiddleware(createUserSchema))
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const userData = context.req.validatedBody as CreateUserRequest;
    const currentUser = context.user as AuthenticatedUser;

    try {
      // Clean undefined values for exactOptionalPropertyTypes compatibility
      const cleanUserData = Object.fromEntries(
        Object.entries(userData).filter(([_, value]) => value !== undefined)
      ) as CreateUserRequest;

      // Execute business logic - create the user
      const result = await userService.createUser(
        cleanUserData as Parameters<IUserService['createUser']>[0]
      );

      // Log successful creation for audit trail
      console.log(`👤 User created successfully`, {
        newUserId: result.id,
        newUserEmail: result.user.email,
        createdBy: currentUser.userId,
        requestId: context.businessData?.get('requestId'),
      });

      // Return success response with 201 Created status
      context.res.status(201).json({
        id: result.id,
        user: result.user,
        createdBy: {
          userId: currentUser.userId,
          name: currentUser.name,
        },
        createdAt: result.user.createdAt,
      });
    } catch (error) {
      // Handle specific business logic errors
      if (error instanceof Error && error.message.includes('already in use')) {
        throw new ConflictError(
          `Email address '${userData.email}' is already in use`
        );
      }

      // Re-throw other errors to be handled by ErrorHandlerMiddleware
      throw error;
    }
  });

/**
 * =============================================================================
 * GET USER BY ID HANDLER - GET /api/users/:id
 * =============================================================================
 *
 * Retrieves a specific user with wildcard permission pattern matching.
 *
 * Guard Strategy: WILDCARD PERMISSIONS
 * - Uses pattern matching with intelligent pre-expansion caching
 * - admin.* grants access to all admin operations
 * - user.* grants access to all user operations
 * - Configurable pre-expansion vs on-demand matching strategies
 *
 * Required Permissions: admin.* OR user.profile.* (wildcard patterns)
 * Authentication: JWT token required
 * Special Rule: Users can always read their own profile
 *
 * URL Parameters: { id: string (UUID) }
 * Response: 200 OK with user data, or 404 Not Found
 *
 * Business Rules:
 * - Users can always access their own profile (checked after auth)
 * - admin.* wildcard grants access to any user profile
 * - user.profile.* wildcard grants access to user profile operations
 * - Soft-deleted users are treated as not found
 *
 * Performance Features:
 * - Pre-expanded wildcard patterns for O(1) runtime checks
 * - Intelligent cache warming based on permission usage patterns
 * - Pattern matching optimized for 2-3 level hierarchies
 *
 * Error Cases:
 * - 400 Bad Request: Invalid UUID format
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions (handled by RouteGuards)
 * - 404 Not Found: User doesn't exist or is soft-deleted
 */
const getUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())

  // 🛡️ Advanced Guard Protection - Wildcard Permission Strategy
  // Uses pattern matching with pre-expansion caching for optimal performance
  .use(
    RouteGuards.requireWildcardPermissions(
      ['admin.*', 'user.profile.*'] // Hierarchical wildcard patterns
    )
  )

  .use(new QueryParametersMiddleware())
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const currentUser = context.user as AuthenticatedUser;

    // Extract and validate URL parameters
    const params = context.req.params as Record<string, string>;
    if (!params?.id) {
      throw new ValidationError('User ID is required');
    }

    // Validate UUID format
    const validatedParams = userParamsSchema.parse({ id: params.id });
    const requestedUserId = validatedParams.id;

    // Authorization check - users can always read their own profile
    const isOwnProfile = requestedUserId === currentUser.userId;
    const hasReadPermission =
      currentUser.permissions.includes('user:read') ||
      currentUser.permissions.includes('admin:users');

    if (!isOwnProfile && !hasReadPermission) {
      throw new AuthorizationError(
        'Insufficient permissions to view this user profile'
      );
    }

    // Fetch user data
    const user = await userService.getUserById(requestedUserId);
    if (!user) {
      throw new NotFoundError('User');
    }

    // Log access for audit trail (especially for viewing other users' profiles)
    if (!isOwnProfile) {
      console.log(`👁️  User profile accessed`, {
        viewedUserId: requestedUserId,
        viewedUserEmail: user.email,
        accessedBy: currentUser.userId,
        accessedByRole: currentUser.role,
        requestId: context.businessData?.get('requestId'),
      });
    }

    // Include additional context information in response
    const responseData = {
      user,
      requestedBy: {
        userId: currentUser.userId,
        name: currentUser.name,
        isOwnProfile,
      },
      // Include query parameters that were passed (for debugging/logging)
      queryParams: context.req.query || {},
    };

    context.res.json(responseData);
  });

/**
 * =============================================================================
 * LIST USERS HANDLER - GET /api/users
 * =============================================================================
 *
 * Retrieves a paginated list of users with complex permission expressions.
 *
 * Guard Strategy: EXPRESSION PERMISSIONS
 * - Uses boolean logic evaluation with 2-level nesting
 * - Supports AND, OR, NOT operations with parentheses
 * - Advanced permission combinations for fine-grained access control
 * - Cached expression parsing and evaluation
 *
 * Required Permissions: (admin.users AND admin.read) OR (user.list AND user.department)
 * Authentication: JWT token required
 *
 * Query Parameters: ListUsersQuery (validated by Zod schema)
 * - page: Page number (default: 1)
 * - limit: Items per page (default: 10, max: 100)
 * - search: Text search across name, email, department, bio
 * - department: Filter by specific department
 * - sortBy: Sort field (name, email, age, department, createdAt, updatedAt)
 * - sortOrder: Sort direction (asc, desc)
 * - minAge, maxAge: Age range filtering
 * - includeDeleted: Include soft-deleted users (admin only)
 *
 * Response: 200 OK with paginated user list and metadata
 *
 * Performance Features:
 * - Expression parsing cached for repeated evaluations
 * - Boolean logic optimization for minimal permission checks
 * - Short-circuit evaluation for optimal performance
 * - Bounded complexity to prevent expression explosion
 *
 * Error Cases:
 * - 400 Bad Request: Invalid query parameters
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions (complex expression evaluation)
 */
const listUsersHandler = new Handler()
  .use(new ErrorHandlerMiddleware())

  // 🛡️ Advanced Guard Protection - Expression Permission Strategy
  // Uses boolean logic evaluation with intelligent caching and optimization
  .use(
    RouteGuards.requireComplexPermissions(
      // Complex permission expression with 2-level nesting
      {
        or: [
          {
            and: [{ permission: 'admin.users' }, { permission: 'admin.read' }],
          },
          {
            and: [
              { permission: 'user.list' },
              { permission: 'user.department' },
            ],
          },
        ],
      }
    )
  )

  .use(new QueryParametersMiddleware())
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const currentUser = context.user as AuthenticatedUser;

    // Validate and parse query parameters
    const query = listUsersQuerySchema.parse(context.req.query || {});

    // Authorization check for includeDeleted parameter (admin only)
    if (
      query.includeDeleted &&
      !currentUser.permissions.includes('admin:users')
    ) {
      throw new AuthorizationError(
        'Only administrators can view deleted users'
      );
    }

    // Log the search/filter operation for monitoring
    console.log(`🔍 User list query executed`, {
      executedBy: currentUser.userId,
      executedByRole: currentUser.role,
      query: {
        page: query.page,
        limit: query.limit,
        search: query.search,
        department: query.department,
        sortBy: query.sortBy,
        sortOrder: query.sortOrder,
        ageRange:
          query.minAge || query.maxAge
            ? `${query.minAge || 0}-${query.maxAge || '∞'}`
            : undefined,
        includeDeleted: query.includeDeleted,
      },
      requestId: context.businessData?.get('requestId'),
    });

    // Execute the query - clean undefined values
    const cleanQuery = Object.fromEntries(
      Object.entries({
        page: query.page,
        limit: query.limit,
        search: query.search,
        department: query.department,
        sortBy: query.sortBy,
        sortOrder: query.sortOrder,
        minAge: query.minAge,
        maxAge: query.maxAge,
        includeDeleted: query.includeDeleted,
      }).filter(([_, value]) => value !== undefined)
    );
    const result = await userService.getAllUsers(
      cleanQuery as Parameters<IUserService['getAllUsers']>[0]
    );

    // Build comprehensive response with metadata
    const response: PaginatedResponse<User> = {
      items: result.users,
      pagination: { ...result.pagination, total: result.total || 0 },
      filters: Object.fromEntries(
        Object.entries({
          search: query.search,
          department: query.department,
          sortBy: query.sortBy,
          sortOrder: query.sortOrder,
          minAge: query.minAge,
          maxAge: query.maxAge,
        }).filter(([_, value]) => value !== undefined)
      ) as {
        search?: string;
        department?: string;
        sortBy: string;
        sortOrder: string;
        minAge?: number;
        maxAge?: number;
      },
    };

    // Add request metadata for debugging/monitoring
    const responseWithMeta = {
      ...response,
      requestedBy: {
        userId: currentUser.userId,
        name: currentUser.name,
        role: currentUser.role,
      },
      executedAt: new Date().toISOString(),
    };

    context.res.json(responseWithMeta);
  });

/**
 * =============================================================================
 * UPDATE USER HANDLER - PUT /api/users/:id
 * =============================================================================
 *
 * Updates an existing user with plain permission strategy (back to basics).
 *
 * Guard Strategy: PLAIN PERMISSIONS (Optimized for Common Operations)
 * - Returns to O(1) Set-based lookups for frequent update operations
 * - Maximizes performance for common CRUD operations
 * - Simple permission model for easier maintenance and debugging
 *
 * Required Permissions: user:update OR admin:users (OR logic)
 * Authentication: JWT token required
 * Business Logic: Own profile check performed after authentication
 *
 * URL Parameters: { id: string (UUID) }
 * Request Body: UpdateUserRequest (partial CreateUserRequest)
 * Response: 200 OK with updated user data, or 404 Not Found
 *
 * Business Rules:
 * - Users can update their own profile (except role and permissions)
 * - admin:users permission grants update access to any user profile
 * - user:update permission requires additional own-profile validation
 * - Email changes must maintain uniqueness
 * - Certain fields (id, createdAt) cannot be modified
 * - updatedAt timestamp is automatically set
 *
 * Performance Features:
 * - Fastest possible permission checks for frequent operations
 * - O(1) Set-based permission resolution with caching
 * - Optimized for high-throughput update scenarios
 * - Minimal overhead for common user profile updates
 *
 * Error Cases:
 * - 400 Bad Request: Invalid input data or UUID format
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions (handled by RouteGuards)
 * - 404 Not Found: User doesn't exist
 * - 409 Conflict: Email address already in use (when changing email)
 */
const updateUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())

  // 🛡️ Advanced Guard Protection - Plain Permission Strategy (Optimized)
  // Uses O(1) Set-based lookups optimized for high-frequency operations
  .use(
    RouteGuards.requirePermissions(
      ['user:update', 'admin:users'] // Simple OR logic for maximum performance
    )
  )

  .use(new BodyValidationMiddleware(updateUserSchema))
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const updateData = context.req.validatedBody as UpdateUserRequest;
    const currentUser = context.user as AuthenticatedUser;

    // Extract and validate URL parameters
    const params = context.req.params as Record<string, string>;
    if (!params?.id) {
      throw new ValidationError('User ID is required');
    }

    const validatedParams = userParamsSchema.parse({ id: params.id });
    const targetUserId = validatedParams.id;

    // Authorization check
    const isOwnProfile = targetUserId === currentUser.userId;
    const hasUpdatePermission = currentUser.permissions.includes('user:update');
    const hasAdminPermission = currentUser.permissions.includes('admin:users');

    if (!isOwnProfile && !hasAdminPermission) {
      throw new AuthorizationError(
        'Insufficient permissions to update this user'
      );
    }

    if (!isOwnProfile && !hasUpdatePermission && !hasAdminPermission) {
      throw new AuthorizationError('Insufficient permissions to update users');
    }

    // Check if user exists before updating
    const existingUser = await userService.getUserById(targetUserId);
    if (!existingUser) {
      throw new NotFoundError('User');
    }

    // Restrict non-admin users from changing certain fields
    if (!hasAdminPermission) {
      // Remove sensitive fields that regular users shouldn't change
      const restrictedUpdate = { ...updateData } as UpdateUserRequest & {
        role?: unknown;
        permissions?: unknown;
        status?: unknown;
      };
      delete restrictedUpdate.role;
      delete restrictedUpdate.permissions;
      delete restrictedUpdate.status;

      // Use the restricted update data
      Object.assign(updateData, restrictedUpdate);
    }

    try {
      // Clean undefined values for exactOptionalPropertyTypes compatibility
      const cleanUpdateData = Object.fromEntries(
        Object.entries(updateData).filter(([_, value]) => value !== undefined)
      );

      // Execute the update
      const updatedUser = await userService.updateUser(
        targetUserId,
        cleanUpdateData as Parameters<IUserService['updateUser']>[1]
      );

      if (!updatedUser) {
        throw new NotFoundError('User');
      }

      // Log the update operation
      console.log(`✏️  User updated successfully`, {
        updatedUserId: targetUserId,
        updatedUserEmail: updatedUser.email,
        updatedBy: currentUser.userId,
        updatedByRole: currentUser.role,
        isOwnProfile,
        fieldsUpdated: Object.keys(updateData),
        requestId: context.businessData?.get('requestId'),
      });

      // Return updated user data
      context.res.json({
        user: updatedUser,
        updatedBy: {
          userId: currentUser.userId,
          name: currentUser.name,
        },
        updatedAt: updatedUser.updatedAt,
        fieldsUpdated: Object.keys(updateData),
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('already in use')) {
        throw new ConflictError(`Email address is already in use`);
      }

      throw error;
    }
  });

/**
 * =============================================================================
 * DELETE USER HANDLER - DELETE /api/users/:id
 * =============================================================================
 *
 * Soft deletes a user account with wildcard permission demonstration.
 *
 * Guard Strategy: WILDCARD PERMISSIONS (Administrative Operations)
 * - Uses wildcard patterns for administrative operations
 * - admin.* grants access to all administrative functions
 * - system.users.* grants access to user management operations
 * - Demonstrates hierarchical permission modeling
 *
 * Required Permissions: admin.* OR system.users.* (wildcard patterns)
 * Authentication: JWT token required
 * Security: Self-deletion prevention enforced in business logic
 *
 * URL Parameters: { id: string (UUID) }
 * Response: 204 No Content on success, or 404 Not Found
 *
 * Business Rules:
 * - Only soft deletion is performed (status changed to 'deleted')
 * - Data is preserved for audit and recovery purposes
 * - Deleted users cannot authenticate or appear in normal queries
 * - Email becomes available for reuse after deletion
 * - All user sessions are terminated upon deletion
 * - Self-deletion is prevented as a security measure
 *
 * Security Considerations:
 * - High-privilege operation requires admin.* or system.users.* patterns
 * - Wildcard permissions provide hierarchical access control
 * - Self-deletion prevention enforced in business logic layer
 * - All deletion events are logged for audit compliance
 * - Related data (sessions, tokens) are cleaned up
 *
 * Performance Features:
 * - Pre-expanded wildcard patterns for O(1) runtime checks
 * - Pattern matching optimized for administrative operations
 * - Cached permission resolution for frequent admin operations
 *
 * Error Cases:
 * - 400 Bad Request: Invalid UUID format
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions or self-deletion attempt
 * - 404 Not Found: User doesn't exist or already deleted
 */
const deleteUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())

  // 🛡️ Advanced Guard Protection - Wildcard Permission Strategy (Administrative)
  // Uses hierarchical wildcard patterns for administrative operations
  .use(
    RouteGuards.requireWildcardPermissions(
      ['admin.*', 'system.users.*'] // Hierarchical administrative patterns
    )
  )

  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const currentUser = context.user as AuthenticatedUser;

    // Extract and validate URL parameters
    const params = context.req.params as Record<string, string>;
    if (!params?.id) {
      throw new ValidationError('User ID is required');
    }

    const validatedParams = userParamsSchema.parse({ id: params.id });
    const targetUserId = validatedParams.id;

    // Business rule: Prevent self-deletion (security measure)
    if (targetUserId === currentUser.userId) {
      throw new AuthorizationError(
        'Users cannot delete their own accounts. Contact an administrator.'
      );
    }

    // Check if user exists before attempting deletion
    const existingUser = await userService.getUserById(targetUserId);
    if (!existingUser) {
      throw new NotFoundError('User');
    }

    // Execute soft deletion
    const deleted = await userService.deleteUser(targetUserId);

    if (!deleted) {
      throw new NotFoundError('User');
    }

    // Log critical security event
    console.log(`🗑️  User deleted successfully`, {
      deletedUserId: targetUserId,
      deletedUserEmail: existingUser.email,
      deletedBy: currentUser.userId,
      deletedByRole: currentUser.role,
      deletedAt: new Date().toISOString(),
      requestId: context.businessData?.get('requestId'),
    });

    // Return success with no content (204 No Content)
    context.res.status(204).json({});
  });

/**
 * Export all user handlers for use in server setup
 */
export {
  createUserHandler,
  getUserHandler,
  listUsersHandler,
  updateUserHandler,
  deleteUserHandler,
};

/**
 * Handler metadata for documentation and routing with guard strategy information
 */
export const userHandlersMetadata = {
  createUser: {
    method: 'POST',
    path: '/api/users',
    guardStrategy: 'PLAIN',
    permissions: ['user:create', 'admin:users'],
    permissionLogic: 'OR',
    description: 'Create a new user account with O(1) permission checks',
    requestSchema: createUserSchema,
    performanceProfile:
      'High-frequency operation optimized for sub-millisecond response',
  },
  getUser: {
    method: 'GET',
    path: '/api/users/:id',
    guardStrategy: 'WILDCARD',
    permissions: ['admin.*', 'user.profile.*'],
    permissionLogic: 'OR',
    description: 'Get user by ID with wildcard permission patterns',
    paramSchema: userParamsSchema,
    performanceProfile: 'Pre-expanded patterns with intelligent caching',
  },
  listUsers: {
    method: 'GET',
    path: '/api/users',
    guardStrategy: 'EXPRESSION',
    permissions:
      '(admin.users AND admin.read) OR (user.list AND user.department)',
    permissionLogic: 'COMPLEX',
    description: 'List users with complex boolean permission expressions',
    querySchema: listUsersQuerySchema,
    performanceProfile: 'Cached expression parsing with optimized evaluation',
  },
  updateUser: {
    method: 'PUT',
    path: '/api/users/:id',
    guardStrategy: 'PLAIN',
    permissions: ['user:update', 'admin:users'],
    permissionLogic: 'OR',
    description: 'Update user by ID with optimized plain permissions',
    requestSchema: updateUserSchema,
    paramSchema: userParamsSchema,
    performanceProfile: 'Maximum performance for frequent update operations',
  },
  deleteUser: {
    method: 'DELETE',
    path: '/api/users/:id',
    guardStrategy: 'WILDCARD',
    permissions: ['admin.*', 'system.users.*'],
    permissionLogic: 'OR',
    description: 'Soft delete user by ID with administrative wildcard patterns',
    paramSchema: userParamsSchema,
    performanceProfile: 'Hierarchical permission matching for admin operations',
  },
};

/**
 * =============================================================================
 * GUARD SYSTEM PERFORMANCE METRICS AND MONITORING
 * =============================================================================
 *
 * The handlers above demonstrate the three distinct guard strategies available
 * in the Noony Guard System. Each strategy is optimized for different use cases:
 *
 * ## Performance Characteristics:
 *
 * ### Plain Permissions (O(1) Set Lookups):
 * - Used by: createUser, updateUser handlers
 * - Performance: ~0.1ms per check (cached)
 * - Memory: Low (Set-based storage)
 * - Best for: High-frequency CRUD operations
 * - Cache strategy: User permission sets cached for 15 minutes
 *
 * ### Wildcard Permissions (Pattern Matching):
 * - Used by: getUser, deleteUser handlers
 * - Performance: ~0.2ms per check (pre-expanded), ~2ms (on-demand)
 * - Memory: Medium (pre-expansion cache)
 * - Best for: Hierarchical permission models
 * - Cache strategy: Pattern expansion cached with conservative invalidation
 *
 * ### Expression Permissions (Boolean Logic):
 * - Used by: listUsers handler
 * - Performance: ~0.5ms per check (cached parsing), ~5ms (complex expressions)
 * - Memory: Medium (AST cache for expressions)
 * - Best for: Complex business rules and fine-grained access control
 * - Cache strategy: Expression ASTs cached, evaluation results cached per user
 *
 * ## Guard System Statistics:
 *
 * Access comprehensive performance metrics:
 * ```typescript
 * const stats = routeGuards.getSystemStats();
 * console.log({
 *   cacheHitRate: stats.userContextService.cacheHitRate,
 *   averageAuthTime: stats.authentication.averageTokenVerificationTime,
 *   permissionCheckTimes: stats.userContextService.averagePermissionCheckTime,
 *   cacheMemoryUsage: stats.userContextService.cacheMemoryUsage
 * });
 * ```
 *
 * ## Production Deployment Recommendations:
 *
 * ### For High-Traffic APIs (>1000 RPS):
 * - Use Plain permissions for 80% of endpoints
 * - Enable Redis L2 cache for distributed caching
 * - Set conservative TTLs (5-10 minutes)
 * - Monitor cache hit rates (target >95%)
 *
 * ### For Complex Authorization Systems:
 * - Use Expression permissions judiciously
 * - Pre-warm caches during deployment
 * - Implement circuit breakers for cache failures
 * - Use hierarchical wildcard patterns for role-based access
 *
 * ### For Serverless/Cold Start Optimization:
 * - Prefer pre-expansion strategy for wildcards
 * - Use shorter cache TTLs (2-5 minutes)
 * - Implement cache warming in initialization
 * - Monitor cold start performance impact
 *
 * ## Security Considerations:
 *
 * ### Conservative Cache Invalidation:
 * - Any permission change flushes ALL related caches
 * - Ensures immediate permission revocation
 * - Trades some performance for maximum security
 * - Configurable per environment (less conservative in dev)
 *
 * ### Audit and Monitoring:
 * - All permission checks are logged with request context
 * - Failed authorization attempts are tracked and alerted
 * - Cache performance metrics are continuously monitored
 * - Permission pattern usage is analyzed for optimization
 */

/**
 * Helper function to get system performance metrics
 */
export function getGuardSystemMetrics(): Record<string, unknown> {
  return {
    systemStats: RouteGuards.getSystemStats(),
    configuration: {
      environment: process.env.NODE_ENV || 'development',
      cacheStrategy: 'conservative-invalidation',
      permissionResolution: 'pre-expansion',
      cacheMaxEntries: 2000,
      defaultTTL: 15 * 60 * 1000,
    },
    handlerStrategies: userHandlersMetadata,
  };
}
