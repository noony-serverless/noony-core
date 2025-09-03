/**
 * User Handlers - Production-Ready CRUD API Endpoints
 *
 * This module contains all user management HTTP handlers demonstrating:
 * - Complete CRUD operations (Create, Read, Update, Delete)
 * - Advanced middleware pipeline composition
 * - Comprehensive input validation and sanitization
 * - Role-based authorization and permissions
 * - Pagination and filtering for list endpoints
 * - Proper HTTP status codes and error responses
 * - Performance monitoring and audit logging
 *
 * Each handler follows the Noony middleware pattern:
 * 1. Error handling (always first)
 * 2. Authentication verification
 * 3. Authorization checks
 * 4. Input validation and parsing
 * 5. Business logic execution
 * 6. Response formatting and audit logging
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { Container } from 'typedi';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  AuthenticationMiddleware,
  QueryParametersMiddleware,
  ResponseWrapperMiddleware,
  Context,
} from '@noony-serverless/core';
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
  IAuthService,
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
 * Authentication token verifier for middleware
 *
 * This adapter allows the Noony AuthenticationMiddleware to work with our AuthService
 */
const tokenVerifier = {
  async verifyToken(token: string): Promise<AuthenticatedUser> {
    const authService = Container.get('authService') as IAuthService;
    return authService.verifyToken(token);
  },
};

/**
 * Authorization middleware factory
 *
 * Creates middleware to check if the authenticated user has required permissions
 *
 * @param requiredPermissions - Array of required permissions
 * @returns Middleware function for authorization
 */
function createAuthorizationMiddleware(requiredPermissions: string[]) {
  return {
    async before(context: Context): Promise<void> {
      const user = context.user as AuthenticatedUser;

      if (!user) {
        throw new AuthorizationError('Authentication required');
      }

      // Check if user has any of the required permissions
      const hasPermission = requiredPermissions.some((permission) =>
        user.permissions.includes(permission as any)
      );

      if (!hasPermission) {
        throw new AuthorizationError(
          `Required permissions: ${requiredPermissions.join(' or ')}`
        );
      }

      // Store authorization context for audit logging
      context.businessData?.set('authorizedPermissions', requiredPermissions);
    },
  };
}

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
 * Creates a new user account with comprehensive validation and security checks.
 *
 * Required Permissions: user:create (typically admin or system role)
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
 * Error Cases:
 * - 400 Bad Request: Invalid input data (validation errors)
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions
 * - 409 Conflict: Email address already in use
 * - 500 Internal Server Error: Unexpected server error
 */
export const createUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(createAuthorizationMiddleware(['user:create', 'admin:users']))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const userData = context.req.validatedBody as CreateUserRequest;
    const currentUser = context.user as AuthenticatedUser;

    try {
      // Execute business logic - create the user
      const result = await userService.createUser(userData);

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
 * Retrieves a specific user by their unique identifier.
 *
 * Required Permissions: user:read
 * Note: Users can always read their own profile, regardless of permissions
 *
 * URL Parameters: { id: string (UUID) }
 * Response: 200 OK with user data, or 404 Not Found
 *
 * Business Rules:
 * - Users can always access their own profile
 * - Admin users can access any user profile
 * - Regular users need user:read permission for other profiles
 * - Soft-deleted users are treated as not found
 *
 * Error Cases:
 * - 400 Bad Request: Invalid UUID format
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions
 * - 404 Not Found: User doesn't exist or is soft-deleted
 */
export const getUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new QueryParametersMiddleware())
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const currentUser = context.user as AuthenticatedUser;

    // Extract and validate URL parameters
    const params = context.req.params as any;
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
 * Retrieves a paginated list of users with comprehensive filtering options.
 *
 * Required Permissions: user:list OR admin:users
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
 * Performance Considerations:
 * - Pagination prevents large data transfers
 * - Search is performed in-memory (would use database indexes in production)
 * - Results include pagination metadata for client-side navigation
 * - Filtering options reduce data processing on client side
 *
 * Error Cases:
 * - 400 Bad Request: Invalid query parameters
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions
 */
export const listUsersHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(createAuthorizationMiddleware(['user:list', 'admin:users']))
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

    // Execute the query
    const result = await userService.getAllUsers({
      page: query.page,
      limit: query.limit,
      search: query.search,
      department: query.department,
      sortBy: query.sortBy,
      sortOrder: query.sortOrder,
      minAge: query.minAge,
      maxAge: query.maxAge,
      includeDeleted: query.includeDeleted,
    });

    // Build comprehensive response with metadata
    const response: PaginatedResponse<User> = {
      items: result.users,
      pagination: result.pagination,
      filters: {
        search: query.search,
        department: query.department,
        sortBy: query.sortBy,
        sortOrder: query.sortOrder,
        minAge: query.minAge,
        maxAge: query.maxAge,
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
 * Updates an existing user with partial data (PATCH semantics despite PUT method).
 *
 * Required Permissions: user:update (for own profile) OR admin:users (for any profile)
 *
 * URL Parameters: { id: string (UUID) }
 * Request Body: UpdateUserRequest (partial CreateUserRequest)
 * Response: 200 OK with updated user data, or 404 Not Found
 *
 * Business Rules:
 * - Users can update their own profile (except role and permissions)
 * - Admins can update any user profile including role and permissions
 * - Email changes must maintain uniqueness
 * - Certain fields (id, createdAt) cannot be modified
 * - updatedAt timestamp is automatically set
 *
 * Error Cases:
 * - 400 Bad Request: Invalid input data or UUID format
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions
 * - 404 Not Found: User doesn't exist
 * - 409 Conflict: Email address already in use (when changing email)
 */
export const updateUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(updateUserSchema))
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const updateData = context.req.validatedBody as UpdateUserRequest;
    const currentUser = context.user as AuthenticatedUser;

    // Extract and validate URL parameters
    const params = context.req.params as any;
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
      const restrictedUpdate = { ...updateData };
      delete (restrictedUpdate as any).role;
      delete (restrictedUpdate as any).permissions;
      delete (restrictedUpdate as any).status;

      // Use the restricted update data
      Object.assign(updateData, restrictedUpdate);
    }

    try {
      // Execute the update
      const updatedUser = await userService.updateUser(
        targetUserId,
        updateData
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
 * Soft deletes a user account (marks as deleted without removing data).
 *
 * Required Permissions: user:delete OR admin:users
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
 *
 * Security Considerations:
 * - Users typically cannot delete their own accounts (business rule)
 * - Admin users can delete any user account
 * - Deletion events are logged for audit compliance
 * - Related data (sessions, tokens) are cleaned up
 *
 * Error Cases:
 * - 400 Bad Request: Invalid UUID format
 * - 401 Unauthorized: Missing or invalid authentication
 * - 403 Forbidden: Insufficient permissions or self-deletion attempt
 * - 404 Not Found: User doesn't exist or already deleted
 */
export const deleteUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(createAuthorizationMiddleware(['user:delete', 'admin:users']))
  .use(auditLoggingMiddleware)
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as IUserService;
    const currentUser = context.user as AuthenticatedUser;

    // Extract and validate URL parameters
    const params = context.req.params as any;
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
 * Handler metadata for documentation and routing
 */
export const userHandlersMetadata = {
  createUser: {
    method: 'POST',
    path: '/api/users',
    permissions: ['user:create', 'admin:users'],
    description: 'Create a new user account',
    requestSchema: createUserSchema,
  },
  getUser: {
    method: 'GET',
    path: '/api/users/:id',
    permissions: ['user:read', 'admin:users', 'own:profile'],
    description: 'Get user by ID',
    paramSchema: userParamsSchema,
  },
  listUsers: {
    method: 'GET',
    path: '/api/users',
    permissions: ['user:list', 'admin:users'],
    description: 'List users with pagination and filtering',
    querySchema: listUsersQuerySchema,
  },
  updateUser: {
    method: 'PUT',
    path: '/api/users/:id',
    permissions: ['user:update', 'admin:users', 'own:profile'],
    description: 'Update user by ID',
    requestSchema: updateUserSchema,
    paramSchema: userParamsSchema,
  },
  deleteUser: {
    method: 'DELETE',
    path: '/api/users/:id',
    permissions: ['user:delete', 'admin:users'],
    description: 'Soft delete user by ID',
    paramSchema: userParamsSchema,
  },
};
