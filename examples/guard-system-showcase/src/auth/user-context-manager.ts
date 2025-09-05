/**
 * User Context Manager
 *
 * Centralized user context management system for the Guard System Showcase.
 * Provides efficient user data loading, caching, permission pre-expansion,
 * and context lifecycle management with security-focused invalidation.
 *
 * Features:
 * - Multi-layer caching (L1 memory + L2 distributed with Redis)
 * - Permission pre-expansion for wildcard resolution
 * - Conservative cache invalidation for security
 * - Performance monitoring and metrics collection
 * - Automatic context expiration and refresh
 * - Concurrent access protection with locks
 *
 * @module UserContextManager
 * @version 1.0.0
 */

import { UserContext, UserStatus } from '@/types/auth.types';
import { PermissionResolverType } from '@noony-serverless/core';
import { config } from '@/config/environment.config';
import { testUserRegistry } from '@/utils/demo-data';

/**
 * User context cache entry with metadata
 */
interface ContextCacheEntry {
  /** User context data */
  context: UserContext;

  /** Cache entry expiration timestamp */
  expiresAt: number;

  /** Entry creation timestamp */
  createdAt: number;

  /** Last access timestamp */
  lastAccessedAt: number;

  /** Access count for LRU eviction */
  accessCount: number;

  /** Cache source (memory/redis) */
  source: 'memory' | 'redis';
}

/**
 * User context statistics
 */
export interface ContextManagerStats {
  /** Total context requests */
  totalRequests: number;

  /** Cache hits by source */
  cacheHits: {
    memory: number;
    redis: number;
    total: number;
  };

  /** Cache misses requiring database fetch */
  cacheMisses: number;

  /** Average context load time by source (microseconds) */
  averageLoadTime: {
    memory: number;
    redis: number;
    database: number;
    overall: number;
  };

  /** Permission expansion statistics */
  permissionExpansion: {
    totalExpansions: number;
    averageExpansionTime: number;
    averagePermissionCount: number;
  };

  /** Cache eviction statistics */
  evictions: {
    expired: number;
    lru: number;
    manual: number;
    total: number;
  };

  /** Last statistics reset timestamp */
  lastReset: number;
}

/**
 * User Context Manager
 *
 * Provides comprehensive user context management with:
 * - Efficient multi-layer caching strategy
 * - Permission pre-expansion for performance
 * - Security-focused cache invalidation
 * - Concurrent access protection
 * - Performance monitoring and optimization
 */
export class UserContextManager {
  private static instance: UserContextManager;

  // L1 Memory Cache
  private readonly memoryCache = new Map<string, ContextCacheEntry>();
  private readonly accessLocks = new Map<string, Promise<UserContext>>();

  // Statistics
  private stats: ContextManagerStats;

  // Configuration
  private readonly maxMemoryEntries: number;
  private readonly contextTTL: number;
  private readonly enableRedis: boolean;

  constructor() {
    const envConfig = config.getConfig();

    this.maxMemoryEntries = envConfig.GUARD_CACHE_MAX_ENTRIES;
    this.contextTTL = envConfig.GUARD_USER_CONTEXT_TTL_MS;
    this.enableRedis = envConfig.ENABLE_REDIS_CACHE;

    this.stats = this.initializeStats();

    // Start cache maintenance interval
    this.startCacheMaintenance();

    console.log(
      `👤 User Context Manager initialized (cache: ${this.enableRedis ? 'redis+memory' : 'memory'}, TTL: ${this.contextTTL}ms)`
    );
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): UserContextManager {
    if (!UserContextManager.instance) {
      UserContextManager.instance = new UserContextManager();
    }
    return UserContextManager.instance;
  }

  // ============================================================================
  // USER CONTEXT OPERATIONS
  // ============================================================================

  /**
   * Get user context with multi-layer caching
   *
   * @param userId - User ID to fetch context for
   * @param options - Context loading options
   * @returns Promise resolving to user context
   * @throws Error if user not found or context loading fails
   */
  public async getUserContext(
    userId: string,
    options: {
      /** Force refresh from database */
      forceRefresh?: boolean;
      /** Include permission pre-expansion */
      expandPermissions?: boolean;
      /** Preferred resolver type for expansion */
      resolverType?: PermissionResolverType;
    } = {}
  ): Promise<UserContext> {
    const startTime = process.hrtime.bigint();
    const cacheKey = this.getCacheKey(userId, options.expandPermissions);

    try {
      this.stats.totalRequests++;

      // Check for existing lock to prevent concurrent loads
      const existingLock = this.accessLocks.get(cacheKey);
      if (existingLock) {
        const context = await existingLock;
        this.trackLoadTime('memory', startTime); // Approximate - it was queued
        return context;
      }

      // Create loading lock
      const loadPromise = this.doGetUserContext(userId, options, startTime);
      this.accessLocks.set(cacheKey, loadPromise);

      try {
        const context = await loadPromise;
        return context;
      } finally {
        this.accessLocks.delete(cacheKey);
      }
    } catch (error) {
      console.error(`❌ Failed to load user context for ${userId}:`);
      throw error;
    }
  }

  /**
   * Internal user context loading with caching logic
   *
   * @param userId - User ID
   * @param options - Loading options
   * @param startTime - Request start time
   * @returns Promise resolving to user context
   */
  private async doGetUserContext(
    userId: string,
    options: {
      forceRefresh?: boolean;
      expandPermissions?: boolean;
      resolverType?: PermissionResolverType;
    },
    startTime: bigint
  ): Promise<UserContext> {
    const cacheKey = this.getCacheKey(userId, options.expandPermissions);

    // L1 Memory cache check (unless force refresh)
    if (!options.forceRefresh) {
      const memoryEntry = this.getFromMemoryCache(cacheKey);
      if (memoryEntry) {
        this.stats.cacheHits.memory++;
        this.stats.cacheHits.total++;
        this.trackLoadTime('memory', startTime);
        return memoryEntry.context;
      }

      // L2 Redis cache check (if enabled)
      if (this.enableRedis) {
        const redisContext = await this.getFromRedisCache(cacheKey);
        if (redisContext) {
          this.stats.cacheHits.redis++;
          this.stats.cacheHits.total++;

          // Store in L1 cache for faster subsequent access
          this.storeInMemoryCache(cacheKey, redisContext, 'redis');

          this.trackLoadTime('redis', startTime);
          return redisContext;
        }
      }
    }

    // Cache miss - load from database
    this.stats.cacheMisses++;
    const context = await this.loadUserContextFromDatabase(userId, options);

    // Store in cache layers
    await this.storeCachedContext(cacheKey, context);

    this.trackLoadTime('database', startTime);
    return context;
  }

  /**
   * Invalidate user context cache
   *
   * @param userId - User ID to invalidate (or 'all' for complete invalidation)
   * @param reason - Reason for invalidation (for audit logging)
   */
  public async invalidateUserContext(
    userId: string | 'all',
    reason = 'manual_invalidation'
  ): Promise<void> {
    const startTime = process.hrtime.bigint();

    try {
      if (userId === 'all') {
        // Clear all contexts
        this.memoryCache.clear();

        if (this.enableRedis) {
          await this.clearRedisCache();
        }

        this.stats.evictions.manual += this.memoryCache.size;
        console.log(`🧹 All user contexts invalidated (reason: ${reason})`);
      } else {
        // Clear specific user contexts (both expanded and non-expanded)
        const keysToRemove = [
          this.getCacheKey(userId, false),
          this.getCacheKey(userId, true),
        ];

        for (const key of keysToRemove) {
          if (this.memoryCache.delete(key)) {
            this.stats.evictions.manual++;
          }

          if (this.enableRedis) {
            await this.removeFromRedisCache(key);
          }
        }

        console.log(
          `🧹 User context invalidated for ${userId} (reason: ${reason})`
        );
      }

      const duration = Number(process.hrtime.bigint() - startTime) / 1000;
      console.debug(`⏱️ Context invalidation took ${duration.toFixed(1)}μs`);
    } catch (error) {
      console.error(`❌ Failed to invalidate user context:`, error);
      throw error;
    }
  }

  // ============================================================================
  // DATABASE INTEGRATION
  // ============================================================================

  /**
   * Load user context from database/data source
   *
   * @param userId - User ID to load
   * @param options - Loading options
   * @returns Promise resolving to user context
   */
  private async loadUserContextFromDatabase(
    userId: string,
    options: {
      expandPermissions?: boolean;
      resolverType?: PermissionResolverType;
    }
  ): Promise<UserContext> {
    // In a real implementation, this would query your user database
    // For the showcase, we'll use the demo data
    const { getDemoUser } = await import('@/utils/demo-data');
    let demoUser = getDemoUser(userId);

    // If user not found, check if it's a test user that needs to be retrieved
    if (!demoUser && userId.includes('-')) {
      try {
        console.log(`🔍 Checking for test user: ${userId}`);

        const debugInfo = testUserRegistry.getDebugInfo();
        console.log(
          `📋 Test registry has ${debugInfo.count} users:`,
          debugInfo.userIds.slice(0, 5).join(', ')
        );
        // Using static import for singleton consistency
        demoUser = testUserRegistry.getTestUser(userId);
        if (demoUser) {
          console.log(`🧪 Retrieved test user: ${userId}`);
        } else {
          console.log(`❌ Test user not found in registry: ${userId}`);
          // Check if user ID might have testRunId pattern
          const possibleMatches = debugInfo.userIds.filter((key) =>
            key.includes(userId.split('-')[0])
          );
          if (possibleMatches.length > 0) {
            console.log(
              `🔍 Possible matches in registry:`,
              possibleMatches.slice(0, 3)
            );
          }
        }
      } catch (error) {
        console.log(`❌ Error retrieving test user ${userId}:`, error);
        // Test user retrieval failed, continue with normal error
      }
    }

    if (!demoUser) {
      throw new Error(`User not found: ${userId}`);
    }

    // Convert demo user to user context
    const permissions = new Set<string>(demoUser.permissions);
    let expandedPermissions: Set<string> | undefined;

    // Perform permission expansion if requested
    if (options.expandPermissions) {
      expandedPermissions = await this.expandUserPermissions(
        permissions,
        demoUser.roles,
        options.resolverType
      );
    }

    const context: UserContext = {
      userId: demoUser.userId,
      name: demoUser.name,
      email: demoUser.email,
      permissions: expandedPermissions || permissions,
      roles: demoUser.roles,
      metadata: {
        status: 'active' as UserStatus,
        emailVerified: true,
        department: 'Demo Department',
        title: 'Demo User',
        createdAt: new Date().toISOString(),
        lastLoginAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
      expandedPermissions,
      lastUpdated: new Date().toISOString(),
      expiresAt: new Date(Date.now() + this.contextTTL).toISOString(),
    };

    return context;
  }

  /**
   * Expand user permissions for wildcard/expression resolvers
   *
   * @param basePermissions - User's base permissions
   * @param roles - User's roles
   * @param resolverType - Target resolver type
   * @returns Promise resolving to expanded permissions set
   */
  private async expandUserPermissions(
    basePermissions: Set<string>,
    roles: string[],
    resolverType: PermissionResolverType = PermissionResolverType.WILDCARD
  ): Promise<Set<string>> {
    const expansionStart = process.hrtime.bigint();

    try {
      // Get role-based permissions
      const { getRolePermissions } = await import('@/utils/demo-data');
      const allPermissions = new Set<string>();

      // Add base permissions
      basePermissions.forEach((perm) => allPermissions.add(perm));

      // Add role permissions
      for (const role of roles) {
        const rolePermissions = getRolePermissions(role);
        rolePermissions.forEach((perm) => allPermissions.add(perm));
      }

      // Perform expansion based on resolver type
      const expandedPermissions = await this.performPermissionExpansion(
        allPermissions,
        resolverType
      );

      // Update statistics
      const expansionTime =
        Number(process.hrtime.bigint() - expansionStart) / 1000;
      this.stats.permissionExpansion.totalExpansions++;
      this.stats.permissionExpansion.averageExpansionTime =
        (this.stats.permissionExpansion.averageExpansionTime + expansionTime) /
        2;
      this.stats.permissionExpansion.averagePermissionCount =
        (this.stats.permissionExpansion.averagePermissionCount +
          expandedPermissions.size) /
        2;

      console.debug(
        `🔧 Permission expansion completed: ${basePermissions.size} → ${expandedPermissions.size} (${expansionTime.toFixed(1)}μs)`
      );

      return expandedPermissions;
    } catch (error) {
      console.error('❌ Permission expansion failed:', error);
      return basePermissions; // Fallback to base permissions
    }
  }

  /**
   * Perform permission expansion based on resolver type
   *
   * @param permissions - Base permissions set
   * @param resolverType - Target resolver type
   * @returns Promise resolving to expanded permissions
   */
  private async performPermissionExpansion(
    permissions: Set<string>,
    resolverType: PermissionResolverType
  ): Promise<Set<string>> {
    switch (resolverType) {
      case PermissionResolverType.PLAIN:
        // No expansion needed for plain resolver
        return permissions;

      case PermissionResolverType.WILDCARD:
        return this.expandWildcardPermissions(permissions);

      case PermissionResolverType.EXPRESSION:
        return this.expandExpressionPermissions(permissions);

      default:
        return permissions;
    }
  }

  /**
   * Expand permissions for wildcard pattern matching
   *
   * @param permissions - Base permissions
   * @returns Expanded permissions set
   */
  private expandWildcardPermissions(permissions: Set<string>): Set<string> {
    const expanded = new Set<string>();

    // Add original permissions
    permissions.forEach((perm) => expanded.add(perm));

    // Generate common wildcard expansions
    permissions.forEach((perm) => {
      const parts = perm.split(':');

      // Create hierarchical permissions
      for (let i = 1; i <= parts.length; i++) {
        const partial = parts.slice(0, i).join(':');
        expanded.add(partial);

        // Add wildcard variations
        if (i < parts.length) {
          expanded.add(partial + ':*');
        }
      }

      // Add common CRUD operations if it's a resource permission
      if (parts.length === 2) {
        const [resource] = parts;
        ['read', 'write', 'create', 'update', 'delete'].forEach((action) => {
          expanded.add(`${resource}:${action}`);
        });
      }
    });

    return expanded;
  }

  /**
   * Expand permissions for expression-based resolution
   *
   * @param permissions - Base permissions
   * @returns Expanded permissions set
   */
  private expandExpressionPermissions(permissions: Set<string>): Set<string> {
    const expanded = new Set<string>();

    // Add original permissions
    permissions.forEach((perm) => expanded.add(perm));

    // Generate logical permission expressions
    const permArray = Array.from(permissions);

    // Create common AND combinations
    for (let i = 0; i < permArray.length - 1; i++) {
      for (let j = i + 1; j < permArray.length; j++) {
        expanded.add(`(${permArray[i]} AND ${permArray[j]})`);
      }
    }

    // Create common OR combinations for related permissions
    permArray.forEach((perm) => {
      const parts = perm.split(':');
      if (parts.length === 2) {
        const [resource] = parts;
        const relatedPerms = permArray.filter((p) =>
          p.startsWith(resource + ':')
        );
        if (relatedPerms.length > 1) {
          expanded.add(`(${relatedPerms.join(' OR ')})`);
        }
      }
    });

    return expanded;
  }

  // ============================================================================
  // CACHING IMPLEMENTATION
  // ============================================================================

  /**
   * Get context from memory cache
   *
   * @param cacheKey - Cache key
   * @returns Cache entry or null if not found/expired
   */
  private getFromMemoryCache(cacheKey: string): ContextCacheEntry | null {
    const entry = this.memoryCache.get(cacheKey);

    if (!entry) {
      return null;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.memoryCache.delete(cacheKey);
      this.stats.evictions.expired++;
      return null;
    }

    // Update access metadata
    entry.lastAccessedAt = Date.now();
    entry.accessCount++;

    return entry;
  }

  /**
   * Store context in memory cache with LRU eviction
   *
   * @param cacheKey - Cache key
   * @param context - User context
   * @param source - Cache source
   */
  private storeInMemoryCache(
    cacheKey: string,
    context: UserContext,
    source: 'memory' | 'redis' = 'memory'
  ): void {
    // Check if we need to evict entries
    if (this.memoryCache.size >= this.maxMemoryEntries) {
      this.evictLeastRecentlyUsed();
    }

    const entry: ContextCacheEntry = {
      context,
      expiresAt: Date.now() + this.contextTTL,
      createdAt: Date.now(),
      lastAccessedAt: Date.now(),
      accessCount: 1,
      source,
    };

    this.memoryCache.set(cacheKey, entry);
  }

  /**
   * Evict least recently used cache entries
   */
  private evictLeastRecentlyUsed(): void {
    if (this.memoryCache.size === 0) {
      return;
    }

    // Find least recently used entry
    let lruKey: string | null = null;
    let lruTimestamp = Date.now();

    for (const [key, entry] of this.memoryCache) {
      if (entry.lastAccessedAt < lruTimestamp) {
        lruTimestamp = entry.lastAccessedAt;
        lruKey = key;
      }
    }

    if (lruKey) {
      this.memoryCache.delete(lruKey);
      this.stats.evictions.lru++;
    }
  }

  /**
   * Get context from Redis cache (mock implementation)
   *
   * @param cacheKey - Cache key
   * @returns User context or null if not found
   */
  private async getFromRedisCache(
    _cacheKey: string
  ): Promise<UserContext | null> {
    // TODO: Implement actual Redis integration
    // For now, return null to simulate cache miss
    return null;
  }

  /**
   * Store context in Redis cache (mock implementation)
   *
   * @param cacheKey - Cache key
   * @param context - User context
   */
  private async storeInRedisCache(
    _cacheKey: string,
    _context: UserContext
  ): Promise<void> {
    // TODO: Implement actual Redis storage
    // For now, this is a no-op
  }

  /**
   * Remove context from Redis cache (mock implementation)
   *
   * @param cacheKey - Cache key
   */
  private async removeFromRedisCache(_cacheKey: string): Promise<void> {
    // TODO: Implement actual Redis removal
    // For now, this is a no-op
  }

  /**
   * Clear all contexts from Redis cache (mock implementation)
   */
  private async clearRedisCache(): Promise<void> {
    // TODO: Implement actual Redis clearing
    // For now, this is a no-op
  }

  /**
   * Store context in all cache layers
   *
   * @param cacheKey - Cache key
   * @param context - User context
   */
  private async storeCachedContext(
    cacheKey: string,
    context: UserContext
  ): Promise<void> {
    // Store in L1 memory cache
    this.storeInMemoryCache(cacheKey, context);

    // Store in L2 Redis cache (if enabled)
    if (this.enableRedis) {
      await this.storeInRedisCache(cacheKey, context);
    }
  }

  // ============================================================================
  // MAINTENANCE AND UTILITIES
  // ============================================================================

  /**
   * Start cache maintenance tasks
   */
  private startCacheMaintenance(): void {
    // Run cache cleanup every 5 minutes
    setInterval(
      () => {
        this.performCacheCleanup();
      },
      5 * 60 * 1000
    );

    // Run statistics reset every hour
    setInterval(
      () => {
        this.resetStatistics();
      },
      60 * 60 * 1000
    );
  }

  /**
   * Perform cache cleanup (remove expired entries)
   */
  private performCacheCleanup(): void {
    const now = Date.now();
    const keysToRemove: string[] = [];

    for (const [key, entry] of this.memoryCache) {
      if (now > entry.expiresAt) {
        keysToRemove.push(key);
      }
    }

    keysToRemove.forEach((key) => {
      this.memoryCache.delete(key);
      this.stats.evictions.expired++;
    });

    if (keysToRemove.length > 0) {
      console.debug(
        `🧹 Cache cleanup: removed ${keysToRemove.length} expired entries`
      );
    }
  }

  /**
   * Generate cache key for user context
   *
   * @param userId - User ID
   * @param expanded - Whether permissions are expanded
   * @returns Cache key string
   */
  private getCacheKey(userId: string, expanded = false): string {
    return `user-context:${userId}:${expanded ? 'expanded' : 'basic'}`;
  }

  /**
   * Track context load time by source
   *
   * @param source - Load source (memory/redis/database)
   * @param startTime - Request start time
   */
  private trackLoadTime(
    source: 'memory' | 'redis' | 'database',
    startTime: bigint
  ): void {
    const duration = Number(process.hrtime.bigint() - startTime) / 1000;

    const currentAvg = this.stats.averageLoadTime[source];
    this.stats.averageLoadTime[source] =
      currentAvg > 0 ? (currentAvg + duration) / 2 : duration;

    const overallAvg = this.stats.averageLoadTime.overall;
    this.stats.averageLoadTime.overall =
      overallAvg > 0 ? (overallAvg + duration) / 2 : duration;
  }

  /**
   * Initialize statistics object
   */
  private initializeStats(): ContextManagerStats {
    return {
      totalRequests: 0,
      cacheHits: {
        memory: 0,
        redis: 0,
        total: 0,
      },
      cacheMisses: 0,
      averageLoadTime: {
        memory: 0,
        redis: 0,
        database: 0,
        overall: 0,
      },
      permissionExpansion: {
        totalExpansions: 0,
        averageExpansionTime: 0,
        averagePermissionCount: 0,
      },
      evictions: {
        expired: 0,
        lru: 0,
        manual: 0,
        total: 0,
      },
      lastReset: Date.now(),
    };
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get current statistics
   */
  public getStatistics(): ContextManagerStats {
    // Calculate total evictions
    this.stats.evictions.total =
      this.stats.evictions.expired +
      this.stats.evictions.lru +
      this.stats.evictions.manual;

    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  public resetStatistics(): void {
    this.stats = this.initializeStats();
    console.debug('📊 User context statistics reset');
  }

  /**
   * Get cache status
   */
  public getCacheStatus(): {
    memoryEntries: number;
    memoryUsage: string;
    hitRate: number;
  } {
    const total = this.stats.cacheHits.total + this.stats.cacheMisses;
    const hitRate = total > 0 ? (this.stats.cacheHits.total / total) * 100 : 0;

    return {
      memoryEntries: this.memoryCache.size,
      memoryUsage: `${this.memoryCache.size}/${this.maxMemoryEntries}`,
      hitRate: Math.round(hitRate * 100) / 100,
    };
  }

  /**
   * Shutdown context manager
   */
  public shutdown(): void {
    this.memoryCache.clear();
    console.log('👤 User Context Manager shutdown complete');
  }
}
