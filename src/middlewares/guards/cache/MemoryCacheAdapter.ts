/**
 * Memory Cache Adapter with LRU Eviction
 *
 * High-performance in-memory cache implementation using Least Recently Used (LRU)
 * eviction strategy. Optimized for single-instance deployments where sub-millisecond
 * cache lookups are critical for authentication performance.
 *
 * Features:
 * - O(1) get/set operations using Map and doubly-linked list
 * - TTL support with lazy expiration checking
 * - Configurable size limits with automatic eviction
 * - Pattern-based deletion for cache invalidation
 * - Performance metrics for monitoring
 * - Memory usage tracking
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { CacheAdapter, CacheStats, CacheConfiguration } from './CacheAdapter';

/**
 * Cache entry with TTL and linked list pointers
 */
interface CacheEntry<T> {
  key: string;
  value: T;
  expiresAt?: number;
  prev?: CacheEntry<T>;
  next?: CacheEntry<T>;
}

/**
 * Memory cache adapter with LRU eviction policy
 *
 * Uses a combination of Map for O(1) key lookups and a doubly-linked list
 * for O(1) LRU operations. TTL is implemented with lazy expiration checking
 * to avoid timer overhead.
 */
export class MemoryCacheAdapter implements CacheAdapter {
  private readonly cache = new Map<string, CacheEntry<any>>();
  private readonly maxSize: number;
  private readonly defaultTTL: number;
  private readonly name: string;

  // Doubly-linked list for LRU tracking
  private head?: CacheEntry<any>;
  private tail?: CacheEntry<any>;

  // Performance metrics
  private stats = {
    hits: 0,
    misses: 0,
    evictions: 0,
    startTime: Date.now(),
  };

  constructor(config: CacheConfiguration) {
    this.maxSize = config.maxSize;
    this.defaultTTL = config.defaultTTL;
    this.name = config.name || 'memory-cache';

    // Validate configuration
    if (this.maxSize <= 0) {
      throw new Error('Cache maxSize must be greater than 0');
    }
    if (this.defaultTTL <= 0) {
      throw new Error('Cache defaultTTL must be greater than 0');
    }
  }

  /**
   * Retrieve a value from cache
   *
   * @param key - Cache key to retrieve
   * @returns Promise resolving to cached value or null if not found/expired
   */
  async get<T>(key: string): Promise<T | null> {
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      return null;
    }

    // Check expiration (lazy expiration)
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.removeEntry(entry);
      this.stats.misses++;
      return null;
    }

    // Move to head (mark as recently used)
    this.moveToHead(entry);
    this.stats.hits++;
    return entry.value as T;
  }

  /**
   * Store a value in cache with optional TTL
   *
   * @param key - Cache key to store under
   * @param value - Value to cache
   * @param ttlMs - Time to live in milliseconds (defaults to defaultTTL)
   */
  async set<T>(key: string, value: T, ttlMs?: number): Promise<void> {
    const ttl = ttlMs ?? this.defaultTTL;
    const expiresAt = ttl > 0 ? Date.now() + ttl : undefined;

    // Check if key already exists
    const existingEntry = this.cache.get(key);
    if (existingEntry) {
      // Update existing entry
      existingEntry.value = value;
      existingEntry.expiresAt = expiresAt;
      this.moveToHead(existingEntry);
      return;
    }

    // Create new entry
    const entry: CacheEntry<T> = {
      key,
      value,
      expiresAt,
    };

    // Add to cache and linked list
    this.cache.set(key, entry);
    this.addToHead(entry);

    // Evict oldest entry if cache is full
    if (this.cache.size > this.maxSize) {
      this.evictTail();
    }
  }

  /**
   * Delete a specific cache entry
   *
   * @param key - Cache key to delete
   */
  async delete(key: string): Promise<void> {
    const entry = this.cache.get(key);
    if (entry) {
      this.removeEntry(entry);
    }
  }

  /**
   * Delete multiple cache entries matching a pattern
   *
   * Supports simple wildcard patterns:
   * - "user:*" matches all keys starting with "user:"
   * - "*:123" matches all keys ending with ":123"
   * - "*pattern*" matches all keys containing "pattern"
   *
   * @param pattern - Pattern to match keys
   */
  async deletePattern(pattern: string): Promise<void> {
    const regex = this.patternToRegex(pattern);
    const keysToDelete: string[] = [];

    // Collect matching keys
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        keysToDelete.push(key);
      }
    }

    // Delete matching entries
    for (const key of keysToDelete) {
      await this.delete(key);
    }
  }

  /**
   * Clear all cache entries
   */
  async flush(): Promise<void> {
    this.cache.clear();
    this.head = undefined;
    this.tail = undefined;
    this.stats.evictions += this.cache.size;
  }

  /**
   * Get cache statistics for monitoring
   *
   * @returns Cache statistics including hit rate and memory usage
   */
  async getStats(): Promise<CacheStats> {
    const totalRequests = this.stats.hits + this.stats.misses;
    const hitRate =
      totalRequests > 0 ? (this.stats.hits / totalRequests) * 100 : 0;

    // Estimate memory usage (rough approximation)
    let memoryUsage = 0;
    for (const entry of this.cache.values()) {
      memoryUsage += this.estimateEntrySize(entry);
    }

    return {
      totalEntries: this.cache.size,
      hits: this.stats.hits,
      misses: this.stats.misses,
      hitRate: Math.round(hitRate * 100) / 100, // Round to 2 decimal places
      memoryUsage,
      uptime: Date.now() - this.stats.startTime,
    };
  }

  /**
   * Get cache name for debugging
   */
  getName(): string {
    return this.name;
  }

  /**
   * Get current cache size
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Check if cache is at maximum capacity
   */
  isFull(): boolean {
    return this.cache.size >= this.maxSize;
  }

  // === Private LRU Implementation Methods ===

  /**
   * Add entry to head of linked list (most recently used)
   */
  private addToHead(entry: CacheEntry<any>): void {
    entry.prev = undefined;
    entry.next = this.head;

    if (this.head) {
      this.head.prev = entry;
    }

    this.head = entry;

    if (!this.tail) {
      this.tail = entry;
    }
  }

  /**
   * Move existing entry to head of linked list
   */
  private moveToHead(entry: CacheEntry<any>): void {
    // Remove from current position
    this.removeFromList(entry);
    // Add to head
    this.addToHead(entry);
  }

  /**
   * Remove entry from linked list (but not from cache)
   */
  private removeFromList(entry: CacheEntry<any>): void {
    if (entry.prev) {
      entry.prev.next = entry.next;
    } else {
      // This was the head
      this.head = entry.next;
    }

    if (entry.next) {
      entry.next.prev = entry.prev;
    } else {
      // This was the tail
      this.tail = entry.prev;
    }
  }

  /**
   * Remove entry from both cache and linked list
   */
  private removeEntry(entry: CacheEntry<any>): void {
    this.cache.delete(entry.key);
    this.removeFromList(entry);
  }

  /**
   * Evict least recently used entry (tail)
   */
  private evictTail(): void {
    if (this.tail) {
      this.removeEntry(this.tail);
      this.stats.evictions++;
    }
  }

  /**
   * Convert glob pattern to regular expression
   */
  private patternToRegex(pattern: string): RegExp {
    // Convert * to placeholder first to avoid escaping issues
    const withPlaceholder = pattern.replace(/\*/g, '__WILDCARD__');
    // Escape special regex characters
    const escaped = withPlaceholder.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    // Convert placeholder to regex equivalent
    const regexPattern = escaped.replace(/__WILDCARD__/g, '.*');
    return new RegExp(`^${regexPattern}$`);
  }

  /**
   * Estimate memory usage of a cache entry (rough approximation)
   */
  private estimateEntrySize(entry: CacheEntry<any>): number {
    let size = 0;

    // Key size (2 bytes per character for UTF-16)
    size += entry.key.length * 2;

    // Value size estimation
    if (typeof entry.value === 'string') {
      size += entry.value.length * 2;
    } else if (typeof entry.value === 'number') {
      size += 8;
    } else if (typeof entry.value === 'boolean') {
      size += 1;
    } else if (entry.value && typeof entry.value === 'object') {
      // JSON string length as approximation
      size += JSON.stringify(entry.value).length * 2;
    }

    // Overhead for entry object and pointers
    size += 64;

    return size;
  }
}
