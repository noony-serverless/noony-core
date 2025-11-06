/**
 * Fast User Context Service
 *
 * High-performance user context management with configurable permission resolution.
 * This service orchestrates the permission resolution strategies, manages caching,
 * and provides sub-millisecond user permission checks for serverless environments.
 *
 * Key Features:
 * - Configurable permission resolution (pre-expansion vs on-demand)
 * - Multi-layer caching (L1 memory + L2 distributed)
 * - Conservative cache invalidation for security
 * - Permission expansion and validation
 * - Performance monitoring and metrics
 * - TypeDI integration for dependency injection
 *
 * Architecture:
 * - Uses strategy pattern for different resolution approaches
 * - Implements repository pattern for user context storage
 * - Follows single responsibility principle with focused methods
 * - Provides comprehensive error handling and logging
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { Service } from 'typedi';
import { CacheAdapter, CacheKeyBuilder } from '../cache/CacheAdapter';
import {
  GuardConfiguration,
  PermissionResolutionStrategy,
} from '../config/GuardConfiguration';
import { PlainPermissionResolver } from '../resolvers/PlainPermissionResolver';
import { WildcardPermissionResolver } from '../resolvers/WildcardPermissionResolver';
import { ExpressionPermissionResolver } from '../resolvers/ExpressionPermissionResolver';
import { PermissionRegistry } from '../registry/PermissionRegistry';
import {
  PermissionResolverType,
  PermissionCheckResult,
  PermissionExpression,
} from '../resolvers/PermissionResolver';
import { NoopCacheAdapter } from '../cache/NoopCacheAdapter';

/**
 * Type alias for permission requirements that can be strings, string arrays, or complex expressions
 * Note: Currently defined but reserved for future use
 */
export type PermissionRequirement =
  | string
  | string[]
  | PermissionExpression
  | Record<string, unknown>;

/**
 * User context with cached permissions and metadata
 */
export interface UserContext {
  userId: string;
  permissions: Set<string>;
  roles: string[];
  metadata: Record<string, any>;
  expandedPermissions?: Set<string>; // For pre-expansion strategy
  lastUpdated: string;
  expiresAt?: string;
}

/**
 * User permission source for loading raw user data
 */
export interface UserPermissionSource {
  /**
   * Load user's basic information and permissions
   */
  getUserPermissions(userId: string): Promise<{
    permissions: string[];
    roles: string[];
    metadata?: Record<string, any>;
  } | null>;

  /**
   * Get role-based permissions for expansion
   */
  getRolePermissions(roles: string[]): Promise<string[]>;

  /**
   * Check if user context needs refresh
   */
  isUserContextStale(userId: string, lastUpdated: string): Promise<boolean>;
}

/**
 * Permission check options
 */
export interface PermissionCheckOptions {
  resolverType?: PermissionResolverType;
  useCache?: boolean;
  trackMetrics?: boolean;
  auditTrail?: boolean;
}

/**
 * Fast User Context Service Implementation
 */
@Service()
export class FastUserContextService {
  private readonly cache: CacheAdapter;
  private readonly config: GuardConfiguration;
  private readonly permissionSource: UserPermissionSource;
  private readonly _permissionRegistry: PermissionRegistry;

  // Permission resolvers
  private readonly plainResolver: PlainPermissionResolver;
  private readonly wildcardResolver: WildcardPermissionResolver;
  private readonly expressionResolver: ExpressionPermissionResolver;

  // Performance tracking
  private contextLoads = 0;
  private cacheHits = 0;
  private cacheMisses = 0;
  private permissionChecks = 0;
  private totalResolutionTimeUs = 0;

  constructor(
    cache: CacheAdapter,
    config: GuardConfiguration,
    permissionSource: UserPermissionSource,
    permissionRegistry: PermissionRegistry
  ) {
    this.cache = cache;
    this.config = config;
    this.permissionSource = permissionSource;
    this._permissionRegistry = permissionRegistry;

    // Initialize permission resolvers
    this.plainResolver = new PlainPermissionResolver();
    this.wildcardResolver = new WildcardPermissionResolver(
      config.security.permissionResolutionStrategy ??
        PermissionResolutionStrategy.PRE_EXPANSION,
      this._permissionRegistry,
      cache
    );
    this.expressionResolver = new ExpressionPermissionResolver(cache);
  }

  /**
   * Check if caching is effectively disabled
   *
   * @returns true if caching is disabled (either by environment variable or NoopCacheAdapter)
   */
  private isCachingDisabled(): boolean {
    return (
      !GuardConfiguration.isCachingEnabled() ||
      this.cache instanceof NoopCacheAdapter
    );
  }

  /**
   * Get or load user context with permissions
   *
   * This is the primary method for retrieving user contexts with caching.
   * It handles both pre-expansion and on-demand permission strategies.
   *
   * @param userId - Unique user identifier
   * @param forceRefresh - Skip cache and force reload
   * @returns User context with permissions or null if user not found
   */
  async getUserContext(
    userId: string,
    forceRefresh = false
  ): Promise<UserContext | null> {
    const startTime = process.hrtime.bigint();
    this.contextLoads++;

    try {
      const cachingDisabled = this.isCachingDisabled();

      // Check cache first unless forced refresh or caching is disabled
      if (!forceRefresh && !cachingDisabled) {
        const cachedContext = await this.loadFromCache(userId);
        if (cachedContext) {
          this.cacheHits++;
          return cachedContext;
        }
      }

      this.cacheMisses++;

      // Load from permission source
      const userData = await this.permissionSource.getUserPermissions(userId);
      if (!userData) {
        return null;
      }

      // Build user context
      const context = await this.buildUserContext(userId, userData);

      // Cache the context only if caching is enabled
      if (!cachingDisabled) {
        await this.saveToCache(context);
      }

      return context;
    } finally {
      const endTime = process.hrtime.bigint();
      this.totalResolutionTimeUs += Number(endTime - startTime) / 1000;
    }
  }

  /**
   * Check user permission using appropriate resolver
   *
   * Routes permission checks to the optimal resolver based on requirement type.
   * Provides detailed results including performance metrics and cache status.
   *
   * @param userId - User identifier
   * @param requirement - Permission requirement (string[], wildcard pattern, or expression)
   * @param options - Check options
   * @returns Detailed permission check result
   */
  async checkPermission(
    userId: string,
    requirement: any,
    options: PermissionCheckOptions = {}
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();
    this.permissionChecks++;

    try {
      // Load user context
      const userContext = await this.getUserContext(userId, !options.useCache);

      if (!userContext) {
        return {
          allowed: false,
          resolverType: PermissionResolverType.PLAIN,
          resolutionTimeUs: 0,
          cached: false,
          reason: 'User not found',
        };
      }

      // Select appropriate resolver
      const resolver = this.selectResolver(requirement, options.resolverType);
      if (!resolver) {
        return {
          allowed: false,
          resolverType: PermissionResolverType.PLAIN,
          resolutionTimeUs: 0,
          cached: false,
          reason: 'No suitable resolver found',
        };
      }

      // Perform permission check
      const permissions =
        userContext.expandedPermissions || userContext.permissions;
      const result = await resolver.checkWithResult(permissions, requirement);

      // Add audit trail if enabled
      if (options.auditTrail && result.allowed) {
        await this.recordAuditTrail(userId, requirement, result);
      }

      return result;
    } finally {
      const endTime = process.hrtime.bigint();
      this.totalResolutionTimeUs += Number(endTime - startTime) / 1000;
    }
  }

  /**
   * Batch check multiple permissions for a user
   *
   * Optimized for checking multiple permissions at once.
   * Uses the same user context for all checks to minimize overhead.
   *
   * @param userId - User identifier
   * @param requirements - Array of permission requirements
   * @param options - Check options
   * @returns Array of permission check results
   */
  async checkPermissions(
    userId: string,
    requirements: Array<{
      requirement: any;
      resolverType?: PermissionResolverType;
    }>,
    options: PermissionCheckOptions = {}
  ): Promise<PermissionCheckResult[]> {
    const startTime = process.hrtime.bigint();

    try {
      // Load user context once for all checks
      const userContext = await this.getUserContext(userId, !options.useCache);

      if (!userContext) {
        const failResult: PermissionCheckResult = {
          allowed: false,
          resolverType: PermissionResolverType.PLAIN,
          resolutionTimeUs: 0,
          cached: false,
          reason: 'User not found',
        };
        return requirements.map(() => ({ ...failResult }));
      }

      // Process all requirements
      const results: PermissionCheckResult[] = [];
      const permissions =
        userContext.expandedPermissions || userContext.permissions;

      for (const { requirement, resolverType } of requirements) {
        const resolver = this.selectResolver(requirement, resolverType);

        if (!resolver) {
          results.push({
            allowed: false,
            resolverType: PermissionResolverType.PLAIN,
            resolutionTimeUs: 0,
            cached: false,
            reason: 'No suitable resolver found',
          });
          continue;
        }

        const result = await resolver.checkWithResult(permissions, requirement);
        results.push(result);

        // Add audit trail for allowed permissions
        if (options.auditTrail && result.allowed) {
          await this.recordAuditTrail(userId, requirement, result);
        }
      }

      return results;
    } finally {
      const endTime = process.hrtime.bigint();
      this.totalResolutionTimeUs += Number(endTime - startTime) / 1000;
      this.permissionChecks += requirements.length;
    }
  }

  /**
   * Invalidate user context cache
   *
   * Removes user context from cache when permissions change.
   * Uses conservative approach by also clearing related cached data.
   *
   * @param userId - User identifier
   * @param clearRelated - Also clear permission-related caches
   */
  async invalidateUserContext(
    userId: string,
    clearRelated = true
  ): Promise<void> {
    const cacheKey = CacheKeyBuilder.userContext(userId);
    await this.cache.delete(cacheKey);

    if (clearRelated && this.config.security.conservativeCacheInvalidation) {
      // Clear permission check caches that might be affected
      await this.cache.deletePattern(`perm:*:${userId}:*`);
      await this.cache.deletePattern(`expr:*:${userId}:*`);
      await this.cache.deletePattern(`wild:*:${userId}:*`);
    }

    console.log(`🔄 Invalidated user context cache`, {
      userId,
      clearRelated,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Pre-expand wildcard permissions for user context
   *
   * Used when pre-expansion strategy is enabled to convert
   * wildcard permissions to concrete permission sets.
   *
   * @param permissions - Raw permissions from user/roles
   * @returns Expanded permission set
   */
  async expandPermissions(permissions: string[]): Promise<Set<string>> {
    const expanded = new Set<string>();

    for (const permission of permissions) {
      if (permission.includes('*')) {
        // Expand wildcard
        const concretePermissions =
          await this.wildcardResolver.expandWildcardPatterns([permission]);
        concretePermissions.forEach((p) => expanded.add(p));
      } else {
        // Add concrete permission
        expanded.add(permission);
      }
    }

    return expanded;
  }

  /**
   * Get service performance statistics
   */
  getStats() {
    const totalCacheRequests = this.cacheHits + this.cacheMisses;

    return {
      contextLoads: this.contextLoads,
      permissionChecks: this.permissionChecks,
      cacheHitRate:
        totalCacheRequests > 0
          ? (this.cacheHits / totalCacheRequests) * 100
          : 0,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      averageResolutionTimeUs:
        this.contextLoads > 0
          ? this.totalResolutionTimeUs / this.contextLoads
          : 0,
      totalResolutionTimeUs: this.totalResolutionTimeUs,
      resolverStats: {
        plain: this.plainResolver.getStats(),
        wildcard: this.wildcardResolver.getStats(),
        expression: this.expressionResolver.getStats(),
      },
    };
  }

  /**
   * Reset performance statistics
   */
  resetStats(): void {
    this.contextLoads = 0;
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.permissionChecks = 0;
    this.totalResolutionTimeUs = 0;

    this.plainResolver.resetStats();
    this.wildcardResolver.resetStats();
    this.expressionResolver.resetStats();
  }

  /**
   * Load user context from cache
   */
  private async loadFromCache(userId: string): Promise<UserContext | null> {
    const cacheKey = CacheKeyBuilder.userContext(userId);
    const cachedData = await this.cache.get<{
      context: Omit<UserContext, 'permissions' | 'expandedPermissions'>;
      permissions: string[];
      expandedPermissions?: string[];
    }>(cacheKey);

    if (!cachedData) {
      return null;
    }

    // Check if context is stale
    if (
      await this.permissionSource.isUserContextStale(
        userId,
        cachedData.context.lastUpdated
      )
    ) {
      await this.cache.delete(cacheKey);
      return null;
    }

    // Reconstruct context with Set objects
    return {
      ...cachedData.context,
      permissions: new Set(cachedData.permissions),
      expandedPermissions: cachedData.expandedPermissions
        ? new Set(cachedData.expandedPermissions)
        : undefined,
    };
  }

  /**
   * Save user context to cache
   */
  private async saveToCache(context: UserContext): Promise<void> {
    const cacheKey = CacheKeyBuilder.userContext(context.userId);

    // Serialize Sets to arrays for caching
    const cacheData = {
      context: {
        userId: context.userId,
        roles: context.roles,
        metadata: context.metadata,
        lastUpdated: context.lastUpdated,
        expiresAt: context.expiresAt,
      },
      permissions: Array.from(context.permissions),
      expandedPermissions: context.expandedPermissions
        ? Array.from(context.expandedPermissions)
        : undefined,
    };

    const ttlMs = this.config.cache.userContextTtlMs || 15 * 60 * 1000; // 15 minutes default
    await this.cache.set(cacheKey, cacheData, ttlMs);
  }

  /**
   * Build user context from raw user data
   */
  private async buildUserContext(
    userId: string,
    userData: {
      permissions: string[];
      roles: string[];
      metadata?: Record<string, any>;
    }
  ): Promise<UserContext> {
    const now = new Date().toISOString();

    // Combine user and role permissions
    const rolePermissions = await this.permissionSource.getRolePermissions(
      userData.roles
    );
    const allPermissions = [
      ...new Set([...userData.permissions, ...rolePermissions]),
    ];

    // Create base context
    const context: UserContext = {
      userId,
      permissions: new Set(allPermissions),
      roles: userData.roles,
      metadata: userData.metadata || {},
      lastUpdated: now,
    };

    // Add expanded permissions for pre-expansion strategy
    if (
      this.config.security.permissionResolutionStrategy ===
      PermissionResolutionStrategy.PRE_EXPANSION
    ) {
      context.expandedPermissions =
        await this.expandPermissions(allPermissions);
    }

    return context;
  }

  /**
   * Select appropriate permission resolver
   */
  private selectResolver(
    requirement: any,
    preferredType?: PermissionResolverType
  ): any {
    // Use preferred type if specified and resolver can handle it
    if (preferredType) {
      const resolver = this.getResolverByType(preferredType);
      if (resolver && resolver.canHandle(requirement)) {
        return resolver;
      }
    }

    // Auto-select based on requirement type
    if (this.expressionResolver.canHandle(requirement)) {
      return this.expressionResolver;
    }

    if (this.wildcardResolver.canHandle(requirement)) {
      return this.wildcardResolver;
    }

    if (this.plainResolver.canHandle(requirement)) {
      return this.plainResolver;
    }

    return null;
  }

  /**
   * Get resolver by type
   */
  private getResolverByType(type: PermissionResolverType): any {
    switch (type) {
      case PermissionResolverType.PLAIN:
        return this.plainResolver;
      case PermissionResolverType.WILDCARD:
        return this.wildcardResolver;
      case PermissionResolverType.EXPRESSION:
        return this.expressionResolver;
      default:
        return null;
    }
  }

  /**
   * Record audit trail for permission checks
   */
  private async recordAuditTrail(
    userId: string,
    requirement: any,
    result: PermissionCheckResult
  ): Promise<void> {
    // In production, this would write to an audit log
    console.log(`🔍 Permission granted`, {
      userId,
      requirement:
        typeof requirement === 'object'
          ? JSON.stringify(requirement)
          : requirement,
      resolverType: result.resolverType,
      resolutionTimeUs: result.resolutionTimeUs,
      matchedPermissions: result.matchedPermissions,
      timestamp: new Date().toISOString(),
    });
  }
}
