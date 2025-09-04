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
 * Usage Examples:
 * ```typescript
 * // Simple permissions (fastest)
 * .use(RouteGuards.requirePermissions(['user:read', 'user:update']))
 *
 * // Wildcard patterns (hierarchical)
 * .use(RouteGuards.requireWildcardPermissions(['admin.*', 'org.reports.*']))
 *
 * // Complex expressions (boolean logic)
 * .use(RouteGuards.requireComplexPermissions({
 *   or: [
 *     { permission: 'admin.users' },
 *     { and: [
 *       { permission: 'moderator.content' },
 *       { permission: 'org.reports.view' }
 *     ]}
 *   ]
 * }))
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

/**
 * Route guard configuration for the facade
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
 * Guard system statistics
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
   * @param tokenValidator - JWT token validation service
   * @param authConfig - Authentication guard configuration
   * @returns Promise resolving when configuration is complete
   */
  static async configure(
    profile: GuardEnvironmentProfile,
    permissionSource: UserPermissionSource,
    tokenValidator: TokenValidator,
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

      // Select cache adapter based on environment
      let cache: CacheAdapter;
      if (profile.cacheType === 'memory') {
        cache = new MemoryCacheAdapter({
          maxSize: config.cache.maxEntries || 1000,
          defaultTTL: config.cache.defaultTtlMs || 15 * 60 * 1000,
          name: 'guard-memory-cache',
        });
      } else if (profile.cacheType === 'none') {
        cache = new NoopCacheAdapter();
      } else {
        // Default to memory cache
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

      // Create authentication guard
      const authGuard = new FastAuthGuard(
        cache,
        config,
        authConfig,
        userContextService,
        cacheInvalidation,
        tokenValidator
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

    const guard = this.guardFactory.createAutoGuard(permissions, guardConfig);
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
