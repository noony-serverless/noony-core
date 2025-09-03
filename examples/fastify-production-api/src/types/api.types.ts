/**
 * API Type Definitions for Fastify Production API Example
 *
 * This file contains all API-related type definitions including:
 * - Request/response schemas with Zod validation
 * - TypeScript type inference from schemas
 * - API endpoint specifications
 * - Error response structures
 *
 * The types demonstrate production patterns for:
 * - Comprehensive input validation
 * - Type-safe API contracts
 * - Consistent response formats
 * - Pagination and filtering
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { z } from 'zod';

/**
 * =============================================================================
 * USER MANAGEMENT SCHEMAS
 * =============================================================================
 */

/**
 * User creation request schema
 *
 * Validates all required fields for creating a new user with:
 * - Comprehensive string validation (length, format)
 * - Email format validation
 * - Age constraints for business rules
 * - Optional fields with proper defaults
 *
 * Business Rules Enforced:
 * - Names must be 2-50 characters, letters and spaces only
 * - Emails must be valid format and unique (checked in service layer)
 * - Age must be 18-120 for legal and practical constraints
 * - Phone numbers follow international format patterns
 */
export const createUserSchema = z.object({
  /** User's full name - required, 2-50 characters, letters and spaces only */
  name: z
    .string({ required_error: 'Name is required' })
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name cannot exceed 50 characters')
    .regex(
      /^[a-zA-Z\s'-]+$/,
      'Name can only contain letters, spaces, hyphens, and apostrophes'
    )
    .trim(),

  /** Email address - must be valid format and will be checked for uniqueness */
  email: z
    .string({ required_error: 'Email is required' })
    .email('Must be a valid email address')
    .max(100, 'Email cannot exceed 100 characters')
    .toLowerCase()
    .trim(),

  /** Age in years - must be between 18-120 for legal compliance */
  age: z
    .number({ required_error: 'Age is required' })
    .int('Age must be a whole number')
    .min(18, 'Must be at least 18 years old')
    .max(120, 'Age cannot exceed 120'),

  /** Optional department/organization */
  department: z
    .string()
    .max(100, 'Department name cannot exceed 100 characters')
    .trim()
    .optional(),

  /** Optional phone number with international format support */
  phoneNumber: z
    .string()
    .regex(/^\+?[\d\s-()]+$/, 'Invalid phone number format')
    .min(10, 'Phone number must be at least 10 characters')
    .max(20, 'Phone number cannot exceed 20 characters')
    .trim()
    .optional(),

  /** Optional bio/description */
  bio: z
    .string()
    .max(500, 'Bio cannot exceed 500 characters')
    .trim()
    .optional(),
});

/**
 * User update request schema
 *
 * Similar to create schema but all fields are optional
 * Allows partial updates while maintaining validation rules
 */
export const updateUserSchema = createUserSchema.partial();

/**
 * URL parameter schema for user ID
 *
 * Validates UUID format for user identification
 * Provides clear error messages for invalid IDs
 */
export const userParamsSchema = z.object({
  /** User UUID - must be valid UUID v4 format */
  id: z
    .string({ required_error: 'User ID is required' })
    .uuid('User ID must be a valid UUID'),
});

/**
 * Query parameters schema for user listing
 *
 * Provides comprehensive filtering, sorting, and pagination options:
 * - Pagination with reasonable defaults and limits
 * - Text search across multiple fields
 * - Department filtering for organizational queries
 * - Flexible sorting options
 * - Age range filtering
 */
export const listUsersQuerySchema = z.object({
  /** Page number for pagination - starts at 1 */
  page: z.coerce.number().int().min(1, 'Page must be at least 1').default(1),

  /** Number of items per page - reasonable limits to prevent abuse */
  limit: z.coerce
    .number()
    .int()
    .min(1, 'Limit must be at least 1')
    .max(100, 'Limit cannot exceed 100 items')
    .default(10),

  /** Text search across name and email fields */
  search: z
    .string()
    .max(100, 'Search term cannot exceed 100 characters')
    .trim()
    .optional(),

  /** Filter by specific department */
  department: z
    .string()
    .max(100, 'Department filter cannot exceed 100 characters')
    .trim()
    .optional(),

  /** Sort field - limited to safe, indexed fields */
  sortBy: z
    .enum(['name', 'email', 'age', 'department', 'createdAt', 'updatedAt'])
    .default('createdAt'),

  /** Sort direction */
  sortOrder: z.enum(['asc', 'desc']).default('desc'),

  /** Minimum age filter */
  minAge: z.coerce.number().int().min(18).max(120).optional(),

  /** Maximum age filter */
  maxAge: z.coerce.number().int().min(18).max(120).optional(),

  /** Include soft-deleted users (admin only) */
  includeDeleted: z.coerce.boolean().default(false),
});

/**
 * =============================================================================
 * AUTHENTICATION SCHEMAS
 * =============================================================================
 */

/**
 * Login request schema
 *
 * Simple email/password authentication
 * In production, consider additional fields like:
 * - Remember me flag
 * - Device fingerprinting
 * - Two-factor authentication codes
 */
export const loginSchema = z.object({
  /** Email address for authentication */
  email: z
    .string({ required_error: 'Email is required' })
    .email('Must be a valid email address')
    .toLowerCase()
    .trim(),

  /** Password - minimum security requirements */
  password: z
    .string({ required_error: 'Password is required' })
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password cannot exceed 128 characters'),

  /** Optional: remember login for extended session */
  rememberMe: z.boolean().default(false),
});

/**
 * Password change request schema
 *
 * Requires current password for security
 * Validates new password complexity
 */
export const changePasswordSchema = z.object({
  /** Current password for verification */
  currentPassword: z
    .string({ required_error: 'Current password is required' })
    .min(1, 'Current password cannot be empty'),

  /** New password with security requirements */
  newPassword: z
    .string({ required_error: 'New password is required' })
    .min(8, 'New password must be at least 8 characters')
    .max(128, 'New password cannot exceed 128 characters')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'New password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
    ),
});

/**
 * =============================================================================
 * INFERRED TYPESCRIPT TYPES
 * =============================================================================
 */

/** TypeScript type for user creation requests */
export type CreateUserRequest = z.infer<typeof createUserSchema>;

/** TypeScript type for user update requests */
export type UpdateUserRequest = z.infer<typeof updateUserSchema>;

/** TypeScript type for user ID parameters */
export type UserParams = z.infer<typeof userParamsSchema>;

/** TypeScript type for user listing query parameters */
export type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;

/** TypeScript type for login requests */
export type LoginRequest = z.infer<typeof loginSchema>;

/** TypeScript type for password change requests */
export type ChangePasswordRequest = z.infer<typeof changePasswordSchema>;

/**
 * =============================================================================
 * API RESPONSE TYPES
 * =============================================================================
 */

/**
 * Standard API response wrapper
 *
 * All API responses follow this consistent format:
 * - success: Boolean indicating operation success
 * - payload: The actual data or error information
 * - timestamp: When the response was generated
 * - requestId: For request tracking and debugging
 */
export interface ApiResponse<T = any> {
  /** Whether the request was successful */
  success: boolean;

  /** The response data or error information */
  payload: T;

  /** ISO timestamp of response generation */
  timestamp: string;

  /** Unique request identifier for debugging */
  requestId?: string;
}

/**
 * Paginated response structure
 *
 * Used for list endpoints with pagination support
 * Provides all necessary information for client-side pagination
 */
export interface PaginatedResponse<T> {
  /** Array of items for current page */
  items: T[];

  /** Pagination metadata */
  pagination: {
    /** Current page number (1-based) */
    page: number;

    /** Items per page */
    limit: number;

    /** Total number of items across all pages */
    total: number;

    /** Total number of pages */
    totalPages: number;

    /** Whether there's a next page available */
    hasNextPage: boolean;

    /** Whether there's a previous page available */
    hasPreviousPage: boolean;
  };

  /** Optional filtering/sorting information */
  filters?: {
    search?: string;
    department?: string;
    sortBy: string;
    sortOrder: string;
    minAge?: number;
    maxAge?: number;
  };
}

/**
 * Error response structure
 *
 * Provides detailed error information for debugging and user feedback
 * Includes validation errors, field-specific messages, and error codes
 */
export interface ErrorResponse {
  /** Human-readable error message */
  error: string;

  /** Machine-readable error code for programmatic handling */
  code?: string;

  /** Detailed validation errors (for 400 Bad Request) */
  details?: Array<{
    field: string;
    message: string;
    value?: any;
  }>;

  /** Additional context for debugging */
  context?: Record<string, any>;

  /** Stack trace (development only) */
  stack?: string;
}

/**
 * Authentication response structure
 *
 * Returned after successful login/registration
 * Includes token and user information
 */
export interface AuthResponse {
  /** JWT access token */
  token: string;

  /** Token expiration time */
  expiresAt: string;

  /** User information */
  user: {
    id: string;
    name: string;
    email: string;
    role: string;
    permissions: string[];
  };

  /** Optional refresh token for extended sessions */
  refreshToken?: string;
}

/**
 * Health check response structure
 *
 * Provides system status and diagnostic information
 * Used for monitoring and load balancer health checks
 */
export interface HealthCheckResponse {
  /** Overall system status */
  status: 'healthy' | 'degraded' | 'unhealthy';

  /** ISO timestamp of health check */
  timestamp: string;

  /** Uptime in milliseconds */
  uptime: number;

  /** API version */
  version: string;

  /** Environment (development, staging, production) */
  environment: string;

  /** Detailed service checks */
  checks?: {
    database: 'healthy' | 'degraded' | 'unhealthy';
    redis: 'healthy' | 'degraded' | 'unhealthy';
    externalServices: 'healthy' | 'degraded' | 'unhealthy';
  };

  /** Performance metrics */
  metrics?: {
    memoryUsage: NodeJS.MemoryUsage;
    requestsPerMinute: number;
    averageResponseTime: number;
  };
}
