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
 * Cache adapter interface for pluggable caching strategies
 *
 * Provides async operations for storing and retrieving cached data
 * with optional TTL support and pattern-based operations.
 */
export interface CacheAdapter {
  /**
   * Retrieve a cached value by key
   *
   * @param key - Cache key to retrieve
   * @returns Promise resolving to cached value or null if not found
   */
  get<T>(key: string): Promise<T | null>;

  /**
   * Store a value in cache with optional TTL
   *
   * @param key - Cache key to store under
   * @param value - Value to cache (must be serializable)
   * @param ttlMs - Time to live in milliseconds (optional)
   */
  set<T>(key: string, value: T, ttlMs?: number): Promise<void>;

  /**
   * Delete a specific cache entry
   *
   * @param key - Cache key to delete
   */
  delete(key: string): Promise<void>;

  /**
   * Delete multiple cache entries matching a pattern
   *
   * @param pattern - Pattern to match keys (implementation-specific)
   */
  deletePattern(pattern: string): Promise<void>;

  /**
   * Clear all cache entries (conservative invalidation strategy)
   *
   * Used for secure cache invalidation when permissions change
   */
  flush(): Promise<void>;

  /**
   * Get cache statistics for monitoring
   *
   * @returns Cache statistics object
   */
  getStats(): Promise<CacheStats>;

  /**
   * Get the name of the cache adapter for debugging
   *
   * @returns Cache adapter name
   */
  getName(): string;
}

/**
 * Cache statistics for performance monitoring
 */
export interface CacheStats {
  /** Total number of cache entries */
  totalEntries: number;

  /** Number of cache hits since startup */
  hits: number;

  /** Number of cache misses since startup */
  misses: number;

  /** Cache hit rate as percentage (0-100) */
  hitRate: number;

  /** Memory usage in bytes (if applicable) */
  memoryUsage?: number;

  /** Time since cache was created */
  uptime: number;
}

/**
 * Configuration options for cache adapters
 */
export interface CacheConfiguration {
  /** Maximum number of entries to store */
  maxSize: number;

  /** Default time to live in milliseconds */
  defaultTTL: number;

  /** Name for debugging/logging purposes */
  name?: string;
}

/**
 * Cache key utilities for consistent key generation
 */
export class CacheKeyBuilder {
  private static readonly PREFIX = 'noony:guard';

  /**
   * Generate a cache key for user context
   */
  static userContext(userId: string): string {
    return `${this.PREFIX}:user:${userId}`;
  }

  /**
   * Generate a cache key for authentication token
   */
  static authToken(token: string): string {
    const tokenHash =
      token.substring(0, 8) + '...' + token.substring(token.length - 8);
    return `${this.PREFIX}:auth:${tokenHash}`;
  }

  /**
   * Generate a cache key for wildcard permission resolution
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
   * Generate a cache key for expression permission resolution
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
