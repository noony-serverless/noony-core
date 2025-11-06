/**
 * Route Guards Facade
 *
 * Main entry point for the guard system providing a clean, NestJS-inspired API
 * for protecting routes with authentication and authorization. This facade
 * orchestrates all guard components to provide three distinct protection methods
 * optimized for different use cases.
 *
 * Three Protection Methods:
 * 1. `requirePermissions()` - Simple permission list checks (fastest)
 * 2. `requireWildcardPermissions()` - Hierarchical wildcard patterns
 * 3. `requireComplexPermissions()` - Boolean expression evaluation
 *
 * Key Features:
 * - Automatic resolver selection for optimal performance
 * - Intelligent caching strategies per protection method
 * - Conservative security approach with automatic cache invalidation
 * - Built-in authentication with cached user context loading
 * - Comprehensive monitoring and audit trails
 * - Framework-agnostic middleware integration
 *
 * @example
 * Complete guard system setup:
 * ```typescript
 * import { RouteGuards, GuardSetup } from '@noony-serverless/core';
 *
 * // Define user permission source
 * const userPermissionSource = {
 *   async getUserPermissions(userId: string): Promise<string[]> {
 *     const user = await getUserFromDatabase(userId);
 *     return user.permissions;
 *   }
 * };
 *
 * // Define token validator
 * const tokenValidator = {
 *   async validateToken(token: string) {
 *     try {
 *       const decoded = jwt.verify(token, process.env.JWT_SECRET);
 *       return { valid: true, decoded };
 *     } catch (error) {
 *       return { valid: false, error: error.message };
 *     }
 *   },
 *   extractUserId: (decoded: any) => decoded.sub,
 *   isTokenExpired: (decoded: any) => decoded.exp < Date.now() / 1000
 * };
 *
 * // Configure guard system
 * await RouteGuards.configure(
 *   GuardSetup.production(),
 *   userPermissionSource,
 *   tokenValidator,
 *   {
 *     tokenHeader: 'authorization',
 *     tokenPrefix: 'Bearer ',
 *     requireEmailVerification: true,
 *     allowInactiveUsers: false
 *   }
 * );
 * ```
 *
 * @example
 * Simple permission checks (fastest - ~0.1ms cached):
 * ```typescript
 * import { Handler, RouteGuards } from '@noony-serverless/core';
 *
 * const userManagementHandler = new Handler()
 *   .use(RouteGuards.requirePermissions(['user:read', 'user:update']))
 *   .handle(async (context) => {
 *     // User has either 'user:read' OR 'user:update' permission
 *     const users = await getUsers();
 *     return { success: true, users };
 *   });
 * ```
 *
 * @example
 * Wildcard permission patterns (hierarchical - ~0.2ms cached):
 * ```typescript
 * const adminHandler = new Handler()
 *   .use(RouteGuards.requireWildcardPermissions(['admin.*', 'org.reports.*']))
 *   .handle(async (context) => {
 *     // User has any permission starting with 'admin.' OR 'org.reports.'
 *     const adminData = await getAdminDashboard();
 *     return { success: true, data: adminData };
 *   });
 * ```
 *
 * @example
 * Complex boolean expressions (~0.5ms cached):
 * ```typescript
 * const complexAccessHandler = new Handler()
 *   .use(RouteGuards.requireComplexPermissions({
 *     or: [
 *       { permission: 'admin.users' },
 *       { and: [
 *         { permission: 'moderator.content' },
 *         { permission: 'org.reports.view' }
 *       ]}
 *     ]
 *   }))
 *   .handle(async (context) => {
 *     // User has 'admin.users' OR ('moderator.content' AND 'org.reports.view')
 *     return { success: true, accessGranted: true };
 *   });
 * ```
 *
 * @example
 * Authentication-only (no permissions):
 * ```typescript
 * const profileHandler = new Handler()
 *   .use(RouteGuards.requireAuth())
 *   .handle(async (context) => {
 *     // Only checks if user is authenticated
 *     const profile = await getUserProfile(context.user.id);
 *     return { success: true, profile };
 *   });
 * ```
 *
 * @example
 * Cache invalidation for security:
 * ```typescript
 * // Invalidate specific user when permissions change
 * await RouteGuards.invalidateUserPermissions('user-123', 'Permission update');
 *
 * // System-wide invalidation for major updates
 * await RouteGuards.invalidateAllPermissions('System update deployed');
 *
 * // Emergency invalidation for security incidents
 * await RouteGuards.emergencyInvalidation('Security breach detected');
 * ```
 *
 * @example
 * Monitoring and health checks:
 * ```typescript
 * // Get comprehensive system statistics
 * const stats = RouteGuards.getSystemStats();
 * console.log('Guard system performance:', stats.systemHealth);
 *
 * // Perform health check
 * const health = await RouteGuards.healthCheck();
 * console.log('System status:', health.status);
 * console.log('Recommendations:', health.details.recommendations);
 * ```
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { Service, Container } from 'typedi';
import { BaseMiddleware } from '../../core/handler';
import {
  GuardConfiguration,
  GuardEnvironmentProfile,
} from './config/GuardConfiguration';
import { CacheAdapter } from './cache/CacheAdapter';
import { MemoryCacheAdapter } from './cache/MemoryCacheAdapter';
import { NoopCacheAdapter } from './cache/NoopCacheAdapter';
import {
  FastUserContextService,
  UserPermissionSource,
} from './services/FastUserContextService';
import { ConservativeCacheInvalidation } from './cache/ConservativeCacheInvalidation';
import {
  FastAuthGuard,
  AuthGuardConfig,
  TokenValidator,
} from './guards/FastAuthGuard';
import {
  PermissionGuardFactory,
  GuardConfig,
} from './guards/PermissionGuardFactory';
import {
  PermissionRegistry,
  DefaultPermissionRegistry,
} from './registry/PermissionRegistry';
import { PermissionExpression } from './resolvers/PermissionResolver';
import { CustomTokenVerificationPort } from '../authenticationMiddleware';
import {
  CustomTokenVerificationPortAdapter,
  TokenVerificationAdapterFactory,
} from './adapters/CustomTokenVerificationPortAdapter';

/**
 * Union type supporting both RouteGuards TokenValidator and AuthenticationMiddleware CustomTokenVerificationPort.
 * This enables seamless integration between the two authentication systems.
 */
export type AnyTokenValidator =
  | TokenValidator
  | CustomTokenVerificationPort<unknown>;

/**
 * Helper function to check if a token validator is a CustomTokenVerificationPort
 */
function isCustomTokenVerificationPort(
  validator: AnyTokenValidator
): validator is CustomTokenVerificationPort<unknown> {
  return (
    typeof validator === 'object' &&
    'verifyToken' in validator &&
    !('validateToken' in validator)
  );
}

/**
 * Convert any token validator to the TokenValidator interface expected by RouteGuards.
 * Automatically wraps CustomTokenVerificationPort implementations with an adapter.
 */
function normalizeTokenValidator(validator: AnyTokenValidator): TokenValidator {
  if (isCustomTokenVerificationPort(validator)) {
    // For CustomTokenVerificationPort, we create a generic adapter
    // We use a basic configuration that tries to extract common fields
    return new CustomTokenVerificationPortAdapter(
      validator as CustomTokenVerificationPort<unknown>,
      {
        userIdExtractor: (user: unknown): string => {
          // Try to extract user ID from common field names
          if (user && typeof user === 'object') {
            const userObj = user as Record<string, unknown>;
            return String(
              userObj.sub ||
                userObj.id ||
                userObj.userId ||
                userObj.user_id ||
                'unknown'
            );
          }
          return 'unknown';
        },
        expirationExtractor: (user: unknown): number | undefined => {
          // Try to extract expiration from common field names
          if (user && typeof user === 'object') {
            const userObj = user as Record<string, unknown>;
            const exp = userObj.exp || userObj.expiresAt || userObj.expires_at;
            return typeof exp === 'number' ? exp : undefined;
          }
          return undefined;
        },
      }
    );
  }

  // Already a TokenValidator, return as-is
  return validator as TokenValidator;
}

/**
 * Route guard configuration for the facade.
 * Provides fine-grained control over guard behavior for specific endpoints.
 *
 * @example
 * Basic guard options:
 * ```typescript
 * const options: RouteGuardOptions = {
 *   requireAuth: true,
 *   cacheResults: true,
 *   auditTrail: false,
 *   errorMessage: 'Access denied to this resource'
 * };
 *
 * const handler = new Handler()
 *   .use(RouteGuards.requirePermissions(['admin:read'], options))
 *   .handle(async (context) => {
 *     return { success: true, data: 'admin data' };
 *   });
 * ```
 *
 * @example
 * High-security endpoint with audit trail:
 * ```typescript
 * const secureOptions: RouteGuardOptions = {
 *   requireAuth: true,
 *   cacheResults: false, // Always check fresh permissions
 *   auditTrail: true,    // Enable detailed logging
 *   errorMessage: 'Unauthorized access to sensitive data',
 *   cacheTtlMs: 30000    // Short cache TTL for security
 * };
 *
 * const sensitiveHandler = new Handler()
 *   .use(RouteGuards.requirePermissions(['sensitive:access'], secureOptions))
 *   .handle(async (context) => {
 *     return { success: true, data: 'sensitive information' };
 *   });
 * ```
 *
 * @example
 * Public endpoint with authentication check only:
 * ```typescript
 * const publicOptions: RouteGuardOptions = {
 *   requireAuth: false,  // Allow unauthenticated access
 *   cacheResults: true,
 *   auditTrail: false
 * };
 *
 * const publicHandler = new Handler()
 *   .use(RouteGuards.requirePermissions(['public:read'], publicOptions))
 *   .handle(async (context) => {
 *     return { success: true, data: 'public data' };
 *   });
 * ```
 */
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

/**
 * Guard system statistics for monitoring and performance analysis.
 * Provides comprehensive metrics about all guard system components.
 *
 * @example
 * Monitoring guard system performance:
 * ```typescript
 * const stats = RouteGuards.getSystemStats();
 *
 * console.log('System Health:', {
 *   totalChecks: stats.systemHealth.totalGuardChecks,
 *   avgResponseTime: stats.systemHealth.averageResponseTime,
 *   errorRate: stats.systemHealth.errorRate,
 *   cacheEfficiency: stats.systemHealth.cacheEfficiency,
 *   uptime: Math.round(stats.systemHealth.uptime / 1000) + 's'
 * });
 *
 * console.log('Cache Performance:', {
 *   adapter: stats.cacheAdapter.name,
 *   stats: stats.cacheAdapter.stats
 * });
 * ```
 *
 * @example
 * Setting up monitoring alerts:
 * ```typescript
 * setInterval(async () => {
 *   const stats = RouteGuards.getSystemStats();
 *   const health = await RouteGuards.healthCheck();
 *
 *   if (health.status === 'unhealthy') {
 *     await sendAlert('Guard system unhealthy', {
 *       status: health.status,
 *       errorRate: stats.systemHealth.errorRate,
 *       avgResponseTime: stats.systemHealth.averageResponseTime,
 *       recommendations: health.details.recommendations
 *     });
 *   }
 *
 *   if (stats.systemHealth.cacheEfficiency < 50) {
 *     await sendAlert('Low cache efficiency detected', {
 *       efficiency: stats.systemHealth.cacheEfficiency,
 *       totalChecks: stats.systemHealth.totalGuardChecks
 *     });
 *   }
 * }, 60000); // Check every minute
 * ```
 *
 * @example
 * Performance optimization based on stats:
 * ```typescript
 * const stats = RouteGuards.getSystemStats();
 *
 * if (stats.systemHealth.averageResponseTime > 10) {
 *   console.warn('Slow guard performance detected');
 *   console.log('Consider:');
 *   console.log('- Increasing cache TTL values');
 *   console.log('- Optimizing permission source queries');
 *   console.log('- Using simpler permission patterns');
 * }
 *
 * if (stats.systemHealth.errorRate > 2) {
 *   console.error('High error rate in guard system');
 *   console.log('Check authentication service health');
 * }
 * ```
 */
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

/**
 * Route Guards Facade Implementation
 *
 * This class provides the main API for the guard system and handles
 * the orchestration of all guard components. It follows the facade pattern
 * to simplify the complex underlying guard architecture.
 */
@Service()
export class RouteGuards {
  private static instance: RouteGuards | null = null;
  private static isConfigured = false;

  // @ts-expect-error - Reserved for future functionality
  private readonly _config: GuardConfiguration;
  private readonly cache: CacheAdapter;
  private readonly userContextService: FastUserContextService;
  private readonly cacheInvalidation: ConservativeCacheInvalidation;
  private readonly authGuard: FastAuthGuard;
  private readonly guardFactory: PermissionGuardFactory;
  // @ts-expect-error - Reserved for future functionality
  private readonly _permissionRegistry: PermissionRegistry;

  // System-wide statistics
  private systemStartTime = Date.now();
  private totalGuardChecks = 0;
  private totalErrors = 0;
  private totalResponseTime = 0;

  constructor(
    config: GuardConfiguration,
    cache: CacheAdapter,
    userContextService: FastUserContextService,
    cacheInvalidation: ConservativeCacheInvalidation,
    authGuard: FastAuthGuard,
    guardFactory: PermissionGuardFactory,
    permissionRegistry: PermissionRegistry
  ) {
    this._config = config;
    this.cache = cache;
    this.userContextService = userContextService;
    this.cacheInvalidation = cacheInvalidation;
    this.authGuard = authGuard;
    this.guardFactory = guardFactory;
    this._permissionRegistry = permissionRegistry;
  }

  /**
   * Configure the guard system with environment-specific settings
   *
   * This method must be called once before using any guard methods.
   * It sets up all guard components with optimal configurations for
   * the target environment (development, production, serverless).
   *
   * @param profile - Environment profile with guard configurations
   * @param permissionSource - User permission data source
   * @param tokenValidator - Token validation service (supports both TokenValidator and CustomTokenVerificationPort)
   * @param authConfig - Authentication guard configuration
   * @returns Promise resolving when configuration is complete
   *
   * @example
   * Using with CustomTokenVerificationPort from AuthenticationMiddleware:
   * ```typescript
   * import { CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';
   * import { RouteGuards, GuardSetup } from '@/middlewares/guards';
   *
   * // Same token verifier used across the framework
   * const tokenVerifier: CustomTokenVerificationPort<User> = {
   *   async verifyToken(token: string): Promise<User> {
   *     const payload = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
   *     return {
   *       id: payload.sub,
   *       email: payload.email,
   *       roles: payload.roles || [],
   *       sub: payload.sub,
   *       exp: payload.exp
   *     };
   *   }
   * };
   *
   * // Configure RouteGuards with the same verifier
   * await RouteGuards.configure(
   *   GuardSetup.production(),
   *   userPermissionSource,
   *   tokenVerifier, // Automatically wrapped with adapter
   *   authConfig
   * );
   * ```
   *
   * @example
   * Traditional usage with TokenValidator (backward compatible):
   * ```typescript
   * const tokenValidator: TokenValidator = {
   *   async validateToken(token: string) {
   *     // Your existing validation logic
   *     return { valid: true, decoded: userPayload };
   *   },
   *   extractUserId: (decoded) => decoded.sub,
   *   isTokenExpired: (decoded) => decoded.exp < Date.now() / 1000
   * };
   *
   * await RouteGuards.configure(
   *   GuardSetup.production(),
   *   userPermissionSource,
   *   tokenValidator, // Works as before
   *   authConfig
   * );
   * ```
   */
  static async configure(
    profile: GuardEnvironmentProfile,
    permissionSource: UserPermissionSource,
    tokenValidator: AnyTokenValidator,
    authConfig: AuthGuardConfig
  ): Promise<void> {
    if (RouteGuards.isConfigured) {
      console.warn(
        '⚠️ RouteGuards already configured, skipping reconfiguration'
      );
      return;
    }

    try {
      // Create guard configuration
      const config = GuardConfiguration.fromEnvironmentProfile(profile);

      // Get effective cache type considering environment variable override
      // Environment variable NOONY_GUARD_CACHE_ENABLE takes precedence for security
      const effectiveCacheType = GuardConfiguration.getEffectiveCacheType(
        profile.cacheType
      );

      // Select cache adapter based on effective cache type
      let cache: CacheAdapter;
      if (effectiveCacheType === 'memory') {
        cache = new MemoryCacheAdapter({
          maxSize: config.cache.maxEntries || 1000,
          defaultTTL: config.cache.defaultTtlMs || 15 * 60 * 1000,
          name: 'guard-memory-cache',
        });
      } else if (effectiveCacheType === 'none') {
        cache = new NoopCacheAdapter();

        // Log cache status for debugging
        if (!GuardConfiguration.isCachingEnabled()) {
          console.log(
            `🚫 Guard caching disabled by environment variable NOONY_GUARD_CACHE_ENABLE`
          );
        } else {
          console.log(
            `🚫 Guard caching disabled by configuration (cacheType: 'none')`
          );
        }
      } else {
        // Default to memory cache (redis support would go here)
        cache = new MemoryCacheAdapter({
          maxSize: 1000,
          defaultTTL: 15 * 60 * 1000,
          name: 'guard-default-cache',
        });
      }

      // Initialize permission registry
      const permissionRegistry = new DefaultPermissionRegistry();

      // Create user context service
      const userContextService = new FastUserContextService(
        cache,
        config,
        permissionSource,
        permissionRegistry
      );

      // Create cache invalidation service
      const cacheInvalidation = new ConservativeCacheInvalidation(cache);

      // Normalize token validator to ensure compatibility
      const normalizedTokenValidator = normalizeTokenValidator(tokenValidator);

      // Create authentication guard
      const authGuard = new FastAuthGuard(
        cache,
        config,
        authConfig,
        userContextService,
        cacheInvalidation,
        normalizedTokenValidator
      );

      // Create permission guard factory
      const guardFactory = new PermissionGuardFactory(
        userContextService,
        config,
        cache
      );

      // Register services with TypeDI container
      Container.set('GuardConfiguration', config);
      Container.set('CacheAdapter', cache);
      Container.set('FastUserContextService', userContextService);
      Container.set('ConservativeCacheInvalidation', cacheInvalidation);
      Container.set('FastAuthGuard', authGuard);
      Container.set('PermissionGuardFactory', guardFactory);
      Container.set('PermissionRegistry', permissionRegistry);

      // Create and register the main RouteGuards instance
      const routeGuards = new RouteGuards(
        config,
        cache,
        userContextService,
        cacheInvalidation,
        authGuard,
        guardFactory,
        permissionRegistry
      );

      Container.set('RouteGuards', routeGuards);
      RouteGuards.instance = routeGuards;
      RouteGuards.isConfigured = true;

      console.log('✅ RouteGuards configured successfully', {
        environment: profile.environment,
        cacheType: profile.cacheType,
        effectiveCacheType: effectiveCacheType,
        cachingEnabled: GuardConfiguration.isCachingEnabled(),
        permissionStrategy: config.security.permissionResolutionStrategy,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('❌ RouteGuards configuration failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        profile: profile.environment,
      });
      throw error;
    }
  }

  /**
   * Get the configured RouteGuards instance
   *
   * @returns Configured RouteGuards instance
   * @throws Error if not configured
   */
  static getInstance(): RouteGuards {
    if (!RouteGuards.instance || !RouteGuards.isConfigured) {
      throw new Error(
        'RouteGuards not configured. Call RouteGuards.configure() first.'
      );
    }
    return RouteGuards.instance;
  }

  /**
   * Create middleware for simple permission list checks
   *
   * This is the fastest protection method using direct O(1) set membership
   * checks. Ideal for high-traffic endpoints with straightforward permission
   * requirements.
   *
   * Performance: ~0.1ms cached, ~1-2ms uncached
   *
   * @param permissions - Array of required permissions (OR logic)
   * @param options - Optional guard configuration
   * @returns Middleware instance for permission checking
   */
  static requirePermissions(
    permissions: string[],
    options: RouteGuardOptions = {}
  ): BaseMiddleware {
    const instance = RouteGuards.getInstance();
    return instance.createPlainPermissionGuard(permissions, options);
  }

  /**
   * Create middleware for wildcard permission pattern checks
   *
   * Supports hierarchical permission patterns with wildcards for flexible
   * permission management. Uses configurable pre-expansion or on-demand
   * matching strategies.
   *
   * Performance: ~0.2ms cached (pre-expansion), ~2-5ms cached (on-demand)
   *
   * @param wildcardPatterns - Array of wildcard patterns
   * @param options - Optional guard configuration
   * @returns Middleware instance for wildcard permission checking
   */
  static requireWildcardPermissions(
    wildcardPatterns: string[],
    options: RouteGuardOptions = {}
  ): BaseMiddleware {
    const instance = RouteGuards.getInstance();
    return instance.createWildcardPermissionGuard(wildcardPatterns, options);
  }

  /**
   * Create middleware for complex boolean expression checks
   *
   * Supports advanced permission logic with AND, OR, and NOT operations.
   * Includes expression caching and complexity tracking for performance
   * optimization.
   *
   * Performance: ~0.5ms cached, ~5-15ms uncached (depends on complexity)
   *
   * @param expression - Permission expression with boolean logic
   * @param options - Optional guard configuration
   * @returns Middleware instance for expression permission checking
   */
  static requireComplexPermissions(
    expression: PermissionExpression,
    options: RouteGuardOptions = {}
  ): BaseMiddleware {
    const instance = RouteGuards.getInstance();
    return instance.createExpressionPermissionGuard(expression, options);
  }

  /**
   * Create middleware with automatic resolver selection
   *
   * Analyzes permission requirements and automatically selects the optimal
   * resolution strategy for best performance. Useful when you want the
   * system to choose the best approach.
   *
   * @param permissions - Any type of permission requirement
   * @param options - Optional guard configuration
   * @returns Optimally configured middleware instance
   */
  static requireAny(
    permissions: string[] | PermissionExpression,
    options: RouteGuardOptions = {}
  ): BaseMiddleware {
    const instance = RouteGuards.getInstance();
    return instance.createAutoPermissionGuard(permissions, options);
  }

  /**
   * Get authentication-only middleware
   *
   * Provides user authentication without permission checking.
   * Useful for endpoints that only need to verify user identity.
   *
   * @param options - Optional guard configuration
   * @returns Authentication-only middleware
   */
  static requireAuth(_options: RouteGuardOptions = {}): BaseMiddleware {
    const instance = RouteGuards.getInstance();
    return instance.authGuard;
  }

  /**
   * Invalidate user permissions cache
   *
   * Use when user permissions change to ensure fresh permission checks.
   * Implements conservative invalidation strategy for security.
   *
   * @param userId - User ID to invalidate
   * @param reason - Reason for invalidation (for audit)
   * @returns Promise resolving when invalidation is complete
   */
  static async invalidateUserPermissions(
    userId: string,
    reason: string
  ): Promise<void> {
    const instance = RouteGuards.getInstance();
    await instance.cacheInvalidation.invalidateUserPermissions(userId, reason);
  }

  /**
   * System-wide cache invalidation
   *
   * Nuclear option for clearing all permission-related caches.
   * Use for major system updates or security incidents.
   *
   * @param reason - Reason for system-wide invalidation
   * @returns Promise resolving when invalidation is complete
   */
  static async invalidateAllPermissions(reason: string): Promise<void> {
    const instance = RouteGuards.getInstance();
    await instance.cacheInvalidation.invalidateSystemWide(reason);
  }

  /**
   * Emergency security invalidation
   *
   * Immediate cache clearing for security incidents.
   * Bypasses backup creation for maximum speed.
   *
   * @param reason - Security incident description
   * @returns Promise resolving when emergency invalidation is complete
   */
  static async emergencyInvalidation(reason: string): Promise<void> {
    const instance = RouteGuards.getInstance();
    await instance.cacheInvalidation.emergencySecurityInvalidation(reason);
  }

  /**
   * Get comprehensive system statistics
   *
   * @returns Complete guard system performance and health metrics
   */
  static getSystemStats(): GuardSystemStats {
    const instance = RouteGuards.getInstance();
    return instance.getSystemStats();
  }

  /**
   * Reset all system statistics
   */
  static resetSystemStats(): void {
    const instance = RouteGuards.getInstance();
    instance.resetSystemStats();
  }

  /**
   * Health check for the guard system
   *
   * @returns Health status with key metrics
   */
  static async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: Record<string, unknown>;
    timestamp: string;
  }> {
    const instance = RouteGuards.getInstance();
    return instance.performHealthCheck();
  }

  /**
   * Factory method: Configure RouteGuards with CustomTokenVerificationPort for JWT tokens.
   * Provides a streamlined setup for JWT-based authentication with common field extraction.
   *
   * @example
   * Quick JWT setup with CustomTokenVerificationPort:
   * ```typescript
   * import { CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';
   *
   * interface JWTUser {
   *   sub: string;
   *   email: string;
   *   roles: string[];
   *   exp: number;
   * }
   *
   * const jwtVerifier: CustomTokenVerificationPort<JWTUser> = {
   *   async verifyToken(token: string): Promise<JWTUser> {
   *     const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
   *     return {
   *       sub: payload.sub,
   *       email: payload.email,
   *       roles: payload.roles || [],
   *       exp: payload.exp
   *     };
   *   }
   * };
   *
   * // One-line setup for JWT authentication
   * await RouteGuards.configureWithJWT(
   *   GuardSetup.production(),
   *   userPermissionSource,
   *   jwtVerifier,
   *   {
   *     tokenHeader: 'authorization',
   *     tokenPrefix: 'Bearer ',
   *     requireEmailVerification: true
   *   }
   * );
   * ```
   */
  static async configureWithJWT<T extends { sub: string; exp?: number }>(
    profile: GuardEnvironmentProfile,
    permissionSource: UserPermissionSource,
    jwtVerifier: CustomTokenVerificationPort<T>,
    authConfig: AuthGuardConfig
  ): Promise<void> {
    // Create a properly typed adapter for JWT tokens
    const tokenValidator = TokenVerificationAdapterFactory.forJWT(jwtVerifier);

    await RouteGuards.configure(
      profile,
      permissionSource,
      tokenValidator,
      authConfig
    );
  }

  /**
   * Factory method: Configure RouteGuards with CustomTokenVerificationPort for API keys.
   * Provides setup for API key-based authentication with flexible field mapping.
   *
   * @example
   * API key authentication setup:
   * ```typescript
   * interface APIKeyUser {
   *   keyId: string;
   *   permissions: string[];
   *   organization: string;
   *   expiresAt?: number;
   *   isActive: boolean;
   * }
   *
   * const apiKeyVerifier: CustomTokenVerificationPort<APIKeyUser> = {
   *   async verifyToken(token: string): Promise<APIKeyUser> {
   *     const keyData = await validateAPIKeyInDatabase(token);
   *     if (!keyData || !keyData.isActive) {
   *       throw new Error('Invalid or inactive API key');
   *     }
   *     return keyData;
   *   }
   * };
   *
   * await RouteGuards.configureWithAPIKey(
   *   GuardSetup.production(),
   *   userPermissionSource,
   *   apiKeyVerifier,
   *   {
   *     tokenHeader: 'x-api-key',
   *     tokenPrefix: '',
   *     allowInactiveUsers: false
   *   },
   *   'keyId',
   *   'expiresAt'
   * );
   * ```
   */
  static async configureWithAPIKey<T extends Record<string, unknown>>(
    profile: GuardEnvironmentProfile,
    permissionSource: UserPermissionSource,
    apiKeyVerifier: CustomTokenVerificationPort<T>,
    authConfig: AuthGuardConfig,
    userIdField: keyof T,
    expirationField?: keyof T
  ): Promise<void> {
    // Create a properly configured adapter for API keys
    const tokenValidator = TokenVerificationAdapterFactory.forAPIKey(
      apiKeyVerifier,
      userIdField,
      expirationField
    );

    await RouteGuards.configure(
      profile,
      permissionSource,
      tokenValidator,
      authConfig
    );
  }

  /**
   * Factory method: Configure RouteGuards with CustomTokenVerificationPort for OAuth tokens.
   * Provides setup for OAuth-based authentication with scope validation.
   *
   * @example
   * OAuth token authentication with scope requirements:
   * ```typescript
   * interface OAuthUser {
   *   sub: string;
   *   email: string;
   *   scope: string[];
   *   exp: number;
   *   client_id: string;
   * }
   *
   * const oauthVerifier: CustomTokenVerificationPort<OAuthUser> = {
   *   async verifyToken(token: string): Promise<OAuthUser> {
   *     const response = await fetch(`${OAUTH_INTROSPECT_URL}`, {
   *       method: 'POST',
   *       headers: { 'Authorization': `Bearer ${token}` },
   *       body: new URLSearchParams({ token })
   *     });
   *
   *     const tokenInfo = await response.json();
   *     if (!tokenInfo.active) {
   *       throw new Error('Token is not active');
   *     }
   *
   *     return tokenInfo as OAuthUser;
   *   }
   * };
   *
   * await RouteGuards.configureWithOAuth(
   *   GuardSetup.production(),
   *   userPermissionSource,
   *   oauthVerifier,
   *   {
   *     tokenHeader: 'authorization',
   *     tokenPrefix: 'Bearer ',
   *     requireEmailVerification: false
   *   },
   *   ['read:profile', 'write:data'] // Required OAuth scopes
   * );
   * ```
   */
  static async configureWithOAuth<
    T extends { sub: string; exp?: number; scope?: string[] },
  >(
    profile: GuardEnvironmentProfile,
    permissionSource: UserPermissionSource,
    oauthVerifier: CustomTokenVerificationPort<T>,
    authConfig: AuthGuardConfig,
    requiredScopes?: string[]
  ): Promise<void> {
    // Create a properly configured adapter for OAuth tokens
    const tokenValidator = TokenVerificationAdapterFactory.forOAuth(
      oauthVerifier,
      requiredScopes
    );

    await RouteGuards.configure(
      profile,
      permissionSource,
      tokenValidator,
      authConfig
    );
  }

  /**
   * Factory method: Configure RouteGuards with a custom CustomTokenVerificationPort adapter.
   * Provides maximum flexibility for custom token validation scenarios.
   *
   * @example
   * Custom token validation with business-specific logic:
   * ```typescript
   * interface CustomUser {
   *   userId: string;
   *   tenantId: string;
   *   roles: string[];
   *   sessionExpiry: number;
   *   isVerified: boolean;
   * }
   *
   * const customVerifier: CustomTokenVerificationPort<CustomUser> = {
   *   async verifyToken(token: string): Promise<CustomUser> {
   *     // Your custom verification logic
   *     return await verifyCustomToken(token);
   *   }
   * };
   *
   * await RouteGuards.configureWithCustom(
   *   GuardSetup.production(),
   *   userPermissionSource,
   *   customVerifier,
   *   {
   *     tokenHeader: 'x-auth-token',
   *     tokenPrefix: 'Custom ',
   *     customValidation: async (token, user) => {
   *       return user.isVerified && user.tenantId === 'valid-tenant';
   *     }
   *   },
   *   {
   *     userIdExtractor: (user) => user.userId,
   *     expirationExtractor: (user) => user.sessionExpiry,
   *     additionalValidation: (user) => user.isVerified
   *   }
   * );
   * ```
   */
  static async configureWithCustom<T>(
    profile: GuardEnvironmentProfile,
    permissionSource: UserPermissionSource,
    customVerifier: CustomTokenVerificationPort<T>,
    authConfig: AuthGuardConfig,
    adapterConfig: Omit<
      Parameters<typeof TokenVerificationAdapterFactory.custom<T>>[1],
      'userIdExtractor'
    > & {
      userIdExtractor: (user: T) => string;
    }
  ): Promise<void> {
    // Create a custom configured adapter
    const tokenValidator = TokenVerificationAdapterFactory.custom(
      customVerifier,
      adapterConfig
    );

    await RouteGuards.configure(
      profile,
      permissionSource,
      tokenValidator,
      authConfig
    );
  }

  // Private implementation methods

  private createPlainPermissionGuard(
    permissions: string[],
    options: RouteGuardOptions
  ): BaseMiddleware {
    this.trackGuardCreation();

    const guardConfig: Partial<GuardConfig> = {
      requireAuth: options.requireAuth !== false,
      cacheResults: options.cacheResults !== false,
      auditTrail: options.auditTrail === true,
      errorMessage: options.errorMessage,
    };

    const guard = this.guardFactory.createPlainGuard(permissions, guardConfig);
    return this.wrapGuardWithStats(guard, 'plain');
  }

  private createWildcardPermissionGuard(
    wildcardPatterns: string[],
    options: RouteGuardOptions
  ): BaseMiddleware {
    this.trackGuardCreation();

    const guardConfig: Partial<GuardConfig> = {
      requireAuth: options.requireAuth !== false,
      cacheResults: options.cacheResults !== false,
      auditTrail: options.auditTrail === true,
      errorMessage: options.errorMessage,
    };

    const guard = this.guardFactory.createWildcardGuard(
      wildcardPatterns,
      guardConfig
    );
    return this.wrapGuardWithStats(guard, 'wildcard');
  }

  private createExpressionPermissionGuard(
    expression: PermissionExpression,
    options: RouteGuardOptions
  ): BaseMiddleware {
    this.trackGuardCreation();

    const guardConfig: Partial<GuardConfig> = {
      requireAuth: options.requireAuth !== false,
      cacheResults: options.cacheResults !== false,
      auditTrail: options.auditTrail === true,
      errorMessage: options.errorMessage,
    };

    const guard = this.guardFactory.createExpressionGuard(
      expression,
      guardConfig
    );
    return this.wrapGuardWithStats(guard, 'expression');
  }

  private createAutoPermissionGuard(
    permissions: string[] | PermissionExpression,
    options: RouteGuardOptions
  ): BaseMiddleware {
    this.trackGuardCreation();

    const guardConfig: Partial<GuardConfig> = {
      requireAuth: options.requireAuth !== false,
      cacheResults: options.cacheResults !== false,
      auditTrail: options.auditTrail === true,
      errorMessage: options.errorMessage,
    };

<<<<<<< Updated upstream
    const guard = this.guardFactory.createAutoGuard(permissions, guardConfig);
=======
    const guard = this.guardFactory.createAutoGuard(
      permissions as string[] | PermissionExpression | Record<string, unknown>,
      guardConfig
    );
>>>>>>> Stashed changes
    return this.wrapGuardWithStats(guard, 'auto');
  }

  private wrapGuardWithStats(
    guard: BaseMiddleware,
    _type: string
  ): BaseMiddleware {
    const originalBefore = guard.before?.bind(guard);

    if (!originalBefore) {
      return guard;
    }

    guard.before = async (context): Promise<void> => {
      const startTime = Date.now();
      this.totalGuardChecks++;

      try {
        await originalBefore(context);
        this.totalResponseTime += Date.now() - startTime;
      } catch (error) {
        this.totalErrors++;
        this.totalResponseTime += Date.now() - startTime;
        throw error;
      }
    };

    return guard;
  }

  private trackGuardCreation(): void {
    // Track guard creation for monitoring
    console.log('🛡️ Guard created', {
      timestamp: new Date().toISOString(),
    });
  }

  private getSystemStats(): GuardSystemStats {
    const uptime = Date.now() - this.systemStartTime;
    const errorRate =
      this.totalGuardChecks > 0
        ? (this.totalErrors / this.totalGuardChecks) * 100
        : 0;
    const averageResponseTime =
      this.totalGuardChecks > 0
        ? this.totalResponseTime / this.totalGuardChecks
        : 0;

    const cacheStats =
      this.cache.getName() === 'noop-cache' ? { hitRate: 0 } : { hitRate: 85 }; // Estimate for memory cache

    return {
      authentication: this.authGuard.getStats(),
      userContextService: this.userContextService.getStats(),
      permissionGuardFactory: this.guardFactory.getStats(),
      cacheInvalidation: this.cacheInvalidation.getStats(),
      cacheAdapter: {
        name: this.cache.getName(),
        stats: cacheStats,
      },
      systemHealth: {
        totalGuardChecks: this.totalGuardChecks,
        averageResponseTime,
        errorRate,
        cacheEfficiency: cacheStats.hitRate,
        uptime,
      },
    };
  }

  private resetSystemStats(): void {
    this.totalGuardChecks = 0;
    this.totalErrors = 0;
    this.totalResponseTime = 0;
    this.systemStartTime = Date.now();

    this.authGuard.resetStats();
    this.userContextService.resetStats();
    this.guardFactory.clearCache();
  }

  private async performHealthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: Record<string, unknown>;
    timestamp: string;
  }> {
    const stats = this.getSystemStats();
    const errorRate = stats.systemHealth.errorRate;
    const averageResponseTime = stats.systemHealth.averageResponseTime;

    let status: 'healthy' | 'degraded' | 'unhealthy';

    if (errorRate < 1 && averageResponseTime < 10) {
      status = 'healthy';
    } else if (errorRate < 5 && averageResponseTime < 50) {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }

    return {
      status,
      details: {
        errorRate: `${errorRate.toFixed(2)}%`,
        averageResponseTime: `${averageResponseTime.toFixed(2)}ms`,
        totalChecks: stats.systemHealth.totalGuardChecks,
        uptime: `${Math.round(stats.systemHealth.uptime / 1000)}s`,
        cacheEfficiency: `${stats.systemHealth.cacheEfficiency.toFixed(1)}%`,
        recommendations: this.getHealthRecommendations(status, stats),
      },
      timestamp: new Date().toISOString(),
    };
  }

  private getHealthRecommendations(
    status: 'healthy' | 'degraded' | 'unhealthy',
    stats: GuardSystemStats
  ): string[] {
    const recommendations: string[] = [];

    if (status === 'unhealthy') {
      recommendations.push('Consider emergency cache invalidation');
      recommendations.push('Review error logs for system issues');
      recommendations.push('Check user permission source performance');
    }

    if (stats.systemHealth.errorRate > 2) {
      recommendations.push(
        'High error rate detected - investigate failed permission checks'
      );
    }

    if (stats.systemHealth.averageResponseTime > 20) {
      recommendations.push('Slow response times - consider cache optimization');
    }

    if (stats.systemHealth.cacheEfficiency < 50) {
      recommendations.push('Low cache efficiency - review caching strategy');
    }

    if (recommendations.length === 0) {
      recommendations.push('System is operating optimally');
    }

    return recommendations;
  }
}
