/**
 * No-Operation Cache Adapter
 *
 * A cache adapter implementation that doesn't actually cache anything.
 * Useful for testing scenarios, disabled caching configurations, or
 * development environments where cache behavior needs to be bypassed.
 *
 * All operations return immediately without storing or retrieving data,
 * ensuring that the guard system can operate without caching when needed.
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { CacheAdapter, CacheStats } from './CacheAdapter';

/**
 * No-operation cache adapter that doesn't cache anything
 *
 * This implementation provides the CacheAdapter interface but performs
 * no actual caching operations. All get operations return null, all set
 * operations are ignored, and all delete operations are no-ops.
 *
 * Useful for:
 * - Testing scenarios where caching should be disabled
 * - Development environments with live data
 * - Troubleshooting cache-related issues
 * - Performance baseline measurements
 */
export class NoopCacheAdapter implements CacheAdapter {
  private readonly startTime = Date.now();
  private readonly name: string;

  // Track statistics even though we don't cache
  private stats = {
    gets: 0,
    sets: 0,
    deletes: 0,
    flushes: 0,
  };

  constructor(name: string = 'noop-cache') {
    this.name = name;
  }

  /**
   * Always returns null (no caching)
   *
   * @param key - Cache key to retrieve (ignored)
   * @returns Promise resolving to null
   */
  async get<T>(_key: string): Promise<T | null> {
    this.stats.gets++;
    return null;
  }

  /**
   * Does nothing (no caching)
   *
   * @param key - Cache key to store under (ignored)
   * @param value - Value to cache (ignored)
   * @param ttlMs - Time to live in milliseconds (ignored)
   */
  async set<T>(_key: string, _value: T, _ttlMs?: number): Promise<void> {
    this.stats.sets++;
    // Intentionally do nothing
  }

  /**
   * Does nothing (no caching)
   *
   * @param key - Cache key to delete (ignored)
   */
  async delete(_key: string): Promise<void> {
    this.stats.deletes++;
    // Intentionally do nothing
  }

  /**
   * Does nothing (no caching)
   *
   * @param pattern - Pattern to match keys (ignored)
   */
  async deletePattern(_pattern: string): Promise<void> {
    this.stats.deletes++;
    // Intentionally do nothing
  }

  /**
   * Does nothing (no caching)
   */
  async flush(): Promise<void> {
    this.stats.flushes++;
    // Intentionally do nothing
  }

  /**
   * Get statistics for monitoring
   *
   * Returns statistics about operations performed, even though
   * no actual caching occurs. This helps with monitoring and
   * understanding system behavior.
   *
   * @returns Cache statistics with 0% hit rate
   */
  async getStats(): Promise<CacheStats> {
    return {
      totalEntries: 0, // Never stores anything
      hits: 0, // Never hits (always returns null)
      misses: this.stats.gets, // Every get is a miss
      hitRate: 0, // Always 0% hit rate
      memoryUsage: 0, // Uses no memory for caching
      uptime: Date.now() - this.startTime,
    };
  }

  /**
   * Get adapter name for debugging
   */
  getName(): string {
    return this.name;
  }

  /**
   * Get operation statistics for debugging
   */
  getOperationStats(): {
    gets: number;
    sets: number;
    deletes: number;
    flushes: number;
  } {
    return { ...this.stats };
  }

  /**
   * Check if this is a no-op cache adapter
   *
   * Utility method for other components to detect when
   * caching is disabled and adjust behavior accordingly.
   */
  isNoop(): boolean {
    return true;
  }
}
