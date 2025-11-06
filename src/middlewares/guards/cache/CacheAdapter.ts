/**
 * Cache Abstraction Layer for High-Performance Guard System
 *
 * This module provides a pluggable caching interface that allows different
 * cache implementations to be injected based on deployment requirements:
 * - MemoryCacheAdapter: LRU cache for single-instance deployments
 * - RedisCacheAdapter: Distributed cache for multi-instance deployments
 * - HybridCacheAdapter: L1 (memory) + L2 (Redis) for maximum performance
 * - NoopCacheAdapter: Disabled caching for testing scenarios
 *
 * The abstraction enables sub-millisecond authentication lookups while
 * maintaining flexibility for different environments.
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

/**
 * Cache adapter interface for pluggable caching strategies.
 * Provides async operations for storing and retrieving cached data
 * with optional TTL support and pattern-based operations.
 *
 * @example
 * Basic usage with any cache adapter:
 * ```typescript
 * import { CacheAdapter } from '@noony/core';
 *
 * class MyService {
 *   constructor(private cache: CacheAdapter) {}
 *
 *   async getUserPermissions(userId: string) {
 *     const cacheKey = `user:${userId}:permissions`;
 *
 *     // Try cache first
 *     let permissions = await this.cache.get<string[]>(cacheKey);
 *     if (permissions) {
 *       return permissions;
 *     }
 *
 *     // Load from database and cache
 *     permissions = await this.loadPermissionsFromDB(userId);
 *     await this.cache.set(cacheKey, permissions, 600000); // 10 minutes
 *
 *     return permissions;
 *   }
 * }
 * ```
 *
 * @example
 * Pattern-based cache invalidation:
 * ```typescript
 * // Invalidate all user-related cache entries
 * await cache.deletePattern('user:123:*');
 *
 * // Clear all permission caches
 * await cache.deletePattern('permissions:*');
 *
 * // Clear everything (use with caution)
 * await cache.clear();
 * ```
 */
export interface CacheAdapter {
  /**
   * Retrieve a cached value by key.
   * Returns null if the key doesn't exist or has expired.
   *
   * @param key - Cache key to retrieve
   * @returns Promise resolving to cached value or null if not found
   *
   * @example
   * ```typescript
   * // Retrieve user permissions from cache
   * const permissions = await cache.get<string[]>('user:123:permissions');
   * if (permissions) {
   *   console.log('Cache hit:', permissions);
   * } else {
   *   console.log('Cache miss - need to load from database');
   * }
   * ```
   */
  get<T>(key: string): Promise<T | null>;

  /**
   * Store a value in cache with optional TTL.
   * If TTL is not provided, uses the cache adapter's default TTL.
   *
   * @param key - Cache key to store under
   * @param value - Value to cache (must be serializable)
   * @param ttlMs - Time to live in milliseconds (optional)
   *
   * @example
   * ```typescript
   * // Cache user permissions for 10 minutes
   * await cache.set('user:123:permissions', ['read', 'write'], 600000);
   *
   * // Cache with default TTL
   * await cache.set('session:abc123', { userId: 123, roles: ['user'] });
   *
   * // Cache complex objects
   * await cache.set('user:123:profile', {
   *   id: 123,
   *   name: 'John Doe',
   *   permissions: ['read', 'write'],
   *   lastLogin: new Date()
   * }, 300000);
   * ```
   */
  set<T>(key: string, value: T, ttlMs?: number): Promise<void>;

  /**
   * Delete a specific cache entry.
   * Silently succeeds if the key doesn't exist.
   *
   * @param key - Cache key to delete
   *
   * @example
   * ```typescript
   * // Remove specific user permissions from cache
   * await cache.delete('user:123:permissions');
   *
   * // Clean up expired session
   * await cache.delete('session:abc123');
   * ```
   */
  delete(key: string): Promise<void>;

  /**
   * Delete multiple cache entries matching a pattern.
   * Pattern syntax varies by implementation (Redis vs memory cache).
   *
   * @param pattern - Pattern to match keys (implementation-specific)
   *
   * @example
   * ```typescript
   * // Clear all cache entries for a specific user
   * await cache.deletePattern('user:123:*');
   *
   * // Clear all permission caches
   * await cache.deletePattern('permissions:*');
   *
   * // Clear all session data
   * await cache.deletePattern('session:*');
   *
   * // Redis-style patterns (if using Redis cache)
   * await cache.deletePattern('auth:token:*');  // All auth tokens
   * await cache.deletePattern('user:*:profile'); // All user profiles
   * ```
   */
  deletePattern(pattern: string): Promise<void>;

  /**
   * Clear all cache entries (conservative invalidation strategy).
   * Used for secure cache invalidation when permissions change globally.
   * Use with caution in production as this affects all cached data.
   *
   * @example
   * ```typescript
   * // Emergency cache clear after security update
   * await cache.flush();
   *
   * // Clear cache after major permission system changes
   * if (permissionSystemUpdated) {
   *   await cache.flush();
   *   console.log('Cache cleared due to permission system update');
   * }
   * ```
   */
  flush(): Promise<void>;

  /**
   * Get cache statistics for monitoring.
   * Provides performance metrics for monitoring cache effectiveness.
   *
   * @returns Cache statistics object with hit/miss ratios and entry counts
   *
   * @example
   * ```typescript
   * const stats = await cache.getStats();
   * console.log(`Cache hit rate: ${stats.hitRate}%`);
   * console.log(`Total entries: ${stats.totalEntries}`);
   * console.log(`Memory usage: ${stats.memoryUsage} bytes`);
   *
   * // Monitor cache performance
   * if (stats.hitRate < 70) {
   *   console.warn('Cache hit rate is low - consider adjusting TTL values');
   * }
   * ```
   */
  getStats(): Promise<CacheStats>;

  /**
   * Get the name of the cache adapter for debugging.
   * Useful for logging and debugging to identify which cache implementation is active.
   *
   * @returns Cache adapter name (e.g., 'MemoryCache', 'RedisCache', 'NoopCache')
   *
   * @example
   * ```typescript
   * console.log(`Using cache adapter: ${cache.getName()}`);
   *
   * // Environment-specific logging
   * if (cache.getName() === 'NoopCache') {
   *   console.warn('Caching is disabled - performance may be reduced');
   * }
   * ```
   */
  getName(): string;
}

/**
 * Cache statistics for performance monitoring.
 * Provides comprehensive metrics for analyzing cache performance and effectiveness.
 *
 * @example
 * Using cache statistics for monitoring:
 * ```typescript
 * const stats = await cache.getStats();
 *
 * // Performance monitoring
 * console.log(`Cache Performance Report:
 *   Hit Rate: ${stats.hitRate}%
 *   Total Entries: ${stats.totalEntries}
 *   Memory Usage: ${(stats.memoryUsage / 1024 / 1024).toFixed(2)} MB
 *   Average TTL: ${stats.averageTtlMs / 1000}s
 *   Evictions: ${stats.evictions}`);
 *
 * // Alert on poor performance
 * if (stats.hitRate < 70) {
 *   console.warn('Low cache hit rate detected');
 * }
 *
 * if (stats.memoryUsage > stats.maxMemoryUsage * 0.9) {
 *   console.warn('Cache memory usage near limit');
 * }
 * ```
 *
 * @example
 * Integration with monitoring systems:
 * ```typescript
 * // Send metrics to monitoring service
 * async function reportCacheMetrics() {
 *   const stats = await cache.getStats();
 *
 *   metrics.gauge('cache.hit_rate', stats.hitRate);
 *   metrics.gauge('cache.total_entries', stats.totalEntries);
 *   metrics.gauge('cache.memory_usage', stats.memoryUsage);
 *   metrics.counter('cache.evictions', stats.evictions);
 * }
 * ```
 */
export interface CacheStats {
  /**
   * Total number of cache entries currently stored.
   * Includes all cached items regardless of TTL status.
   */
  totalEntries: number;

  /**
   * Number of cache hits since startup.
   * Incremented each time a requested key is found in cache.
   */
  hits: number;

  /**
   * Number of cache misses since startup.
   * Incremented each time a requested key is not found in cache.
   */
  misses: number;

  /**
   * Cache hit rate as percentage (0-100).
   * Calculated as: (hits / (hits + misses)) * 100
   */
  hitRate: number;

  /**
   * Memory usage in bytes (if applicable).
   * Available for memory-based cache adapters, optional for others.
   */
  memoryUsage?: number;

  /**
   * Time since cache was created, in milliseconds.
   * Useful for calculating rates and monitoring uptime.
   */
  uptime: number;
}

/**
 * Configuration options for cache adapters.
 * Provides standardized configuration interface for all cache implementations.
 *
 * @example
 * Memory cache configuration:
 * ```typescript
 * const memoryConfig: CacheConfiguration = {
 *   maxSize: 10000,           // Store up to 10k entries
 *   defaultTTL: 300000,       // 5 minutes default TTL
 *   name: 'UserPermissions'   // For debugging and monitoring
 * };
 *
 * const cache = new MemoryCacheAdapter(memoryConfig);
 * ```
 *
 * @example
 * Redis cache configuration:
 * ```typescript
 * const redisConfig: CacheConfiguration = {
 *   maxSize: 50000,           // Higher capacity for distributed cache
 *   defaultTTL: 600000,       // 10 minutes default TTL
 *   name: 'DistributedAuth'   // Identify this cache instance
 * };
 *
 * const cache = new RedisCacheAdapter(redisConfig, redisClient);
 * ```
 */
export interface CacheConfiguration {
  /**
   * Maximum number of entries to store.
   * When exceeded, cache will use eviction policy (usually LRU).
   */
  maxSize: number;

  /**
   * Default time to live in milliseconds.
   * Applied to cache entries when no specific TTL is provided.
   */
  defaultTTL: number;

  /**
   * Name for debugging/logging purposes.
   * Helps identify cache instances in logs and monitoring.
   */
  name?: string;
}

/**
 * Cache key utilities for consistent key generation.
 * Provides standardized key generation methods for different types of cached data
 * in the guard system, ensuring consistent naming and avoiding key collisions.
 *
 * @example
 * Basic key generation:
 * ```typescript
 * // Generate cache keys for different data types
 * const userKey = CacheKeyBuilder.userContext('user123');
 * // Returns: "noony:guard:user:user123"
 *
 * const tokenKey = CacheKeyBuilder.authToken('jwt-token-here');
 * // Returns: "noony:guard:auth:jwt-toke...ken-here"
 *
 * const permKey = CacheKeyBuilder.userPermission('user123', 'admin.users.read');
 * // Returns: "noony:guard:perm:user123:admin.users.read"
 * ```
 *
 * @example
 * Pattern-based cache keys:
 * ```typescript
 * // Cache wildcard resolution results
 * const patterns = ['admin.*', 'user.read'];
 * const userPerms = ['admin.users', 'admin.reports', 'user.read'];
 * const wildcardKey = CacheKeyBuilder.wildcardPattern(patterns, userPerms);
 *
 * // Cache expression evaluation results
 * const expr = '(admin.users OR admin.reports) AND user.active';
 * const exprKey = CacheKeyBuilder.expressionResult(expr, userPerms);
 * ```
 *
 * @example
 * Custom key generation:
 * ```typescript
 * // Generate application-specific keys
 * const customKey = CacheKeyBuilder.custom('feature', 'value1', 'value2');
 * // Returns: "noony:guard:feature:value1:value2"
 * ```
 */
export class CacheKeyBuilder {
  private static readonly PREFIX = 'noony:guard';

  /**
   * Generate a cache key for user context.
   * Creates a standardized key for caching user authentication and role data.
   *
   * @param userId - Unique identifier for the user
   * @returns Cache key string for user context
   *
   * @example
   * ```typescript
   * const key = CacheKeyBuilder.userContext('user123');
   * // Returns: "noony:guard:user:user123"
   *
   * await cache.set(key, {
   *   userId: 'user123',
   *   roles: ['admin', 'user'],
   *   permissions: ['read', 'write'],
   *   lastLogin: new Date()
   * });
   * ```
   */
  static userContext(userId: string): string {
    return `${this.PREFIX}:user:${userId}`;
  }

  /**
   * Generate a cache key for authentication token.
   * Creates a secure key by using partial token hash to avoid storing full tokens.
   *
   * @param token - Authentication token (JWT, API key, etc.)
   * @returns Cache key string for auth token
   *
   * @example
   * ```typescript
   * const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
   * const key = CacheKeyBuilder.authToken(token);
   * // Returns: "noony:guard:auth:eyJhbGci...dCI6IkpXVCJ9"
   *
   * await cache.set(key, {
   *   valid: true,
   *   userId: 'user123',
   *   expires: new Date(Date.now() + 3600000)
   * });
   * ```
   */
  static authToken(token: string): string {
    const tokenHash =
      token.substring(0, 8) + '...' + token.substring(token.length - 8);
    return `${this.PREFIX}:auth:${tokenHash}`;
  }

  /**
   * Generate a cache key for wildcard permission resolution.
   * Creates a key for caching the results of wildcard pattern matching
   * against user permissions.
   *
   * @param patterns - Array of wildcard patterns to match
   * @param userPermissions - Array of user's actual permissions
   * @returns Cache key string for wildcard resolution
   *
   * @example
   * ```typescript
   * const patterns = ['admin.*', 'user.read'];
   * const userPerms = ['admin.users', 'admin.reports', 'user.read'];
   * const key = CacheKeyBuilder.wildcardPattern(patterns, userPerms);
   * // Returns: "noony:guard:wildcard:hash1:hash2"
   *
   * // Cache the expansion result
   * await cache.set(key, {
   *   matched: ['admin.users', 'admin.reports', 'user.read'],
   *   expandedPatterns: {
   *     'admin.*': ['admin.users', 'admin.reports'],
   *     'user.read': ['user.read']
   *   }
   * });
   * ```
   */
  static wildcardPattern(
    patterns: string[],
    userPermissions: string[]
  ): string {
    const patternHash = this.hashArray(patterns);
    const permissionHash = this.hashArray(userPermissions);
    return `${this.PREFIX}:wildcard:${patternHash}:${permissionHash}`;
  }

  /**
   * Generate a cache key for expression permission resolution.
   * Creates a key for caching the results of boolean expression evaluation
   * against user permissions.
   *
   * @param expression - Boolean expression object to evaluate
   * @param userPermissions - Array of user's actual permissions
   * @returns Cache key string for expression evaluation
   *
   * @example
   * ```typescript
   * const expression = {
   *   type: 'AND',
   *   left: { type: 'permission', value: 'admin.users' },
   *   right: { type: 'permission', value: 'admin.reports' }
   * };
   * const userPerms = ['admin.users', 'admin.reports', 'user.read'];
   * const key = CacheKeyBuilder.expressionResult(expression, userPerms);
   * // Returns: "noony:guard:expression:exprHash:permHash"
   *
   * // Cache the evaluation result
   * await cache.set(key, {
   *   result: true,
   *   evaluatedAt: new Date(),
   *   usedPermissions: ['admin.users', 'admin.reports']
   * });
   * ```
   */
  static expressionResult(
    expression: object,
    userPermissions: string[]
  ): string {
    const expressionHash = this.hashObject(expression);
    const permissionHash = this.hashArray(userPermissions);
    return `${this.PREFIX}:expression:${expressionHash}:${permissionHash}`;
  }

  /**
   * Generate a cache key for permission registry data
   */
  static permissionRegistry(category?: string): string {
    return category
      ? `${this.PREFIX}:registry:${category}`
      : `${this.PREFIX}:registry:all`;
  }

  /**
   * Simple hash function for arrays (not cryptographically secure)
   */
  private static hashArray(arr: string[]): string {
    return arr
      .sort()
      .join(':')
      .split('')
      .reduce((hash, char) => {
        const charCode = char.charCodeAt(0);
        hash = (hash << 5) - hash + charCode;
        return hash & hash; // Convert to 32-bit integer
      }, 0)
      .toString(36);
  }

  /**
   * Simple hash function for objects (not cryptographically secure)
   */
  private static hashObject(obj: object): string {
    const str = JSON.stringify(obj, Object.keys(obj).sort());
    return this.hashArray([str]);
  }
}
