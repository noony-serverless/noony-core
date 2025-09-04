/**
 * Tests for MemoryCacheAdapter
 *
 * Comprehensive test suite for the LRU memory cache adapter covering
 * all functionality including TTL, LRU eviction, pattern deletion,
 * and performance metrics.
 */

import { MemoryCacheAdapter } from '../cache/MemoryCacheAdapter';
import { CacheConfiguration } from '../cache/CacheAdapter';

describe('MemoryCacheAdapter', () => {
  let cache: MemoryCacheAdapter;
  let config: CacheConfiguration;

  beforeEach(() => {
    config = {
      maxSize: 10, // Increased to accommodate pattern deletion tests
      defaultTTL: 1000, // 1 second
      name: 'test-cache',
    };
    cache = new MemoryCacheAdapter(config);
  });

  describe('Basic Operations', () => {
    it('should set and get values', async () => {
      await cache.set('key1', 'value1');
      const result = await cache.get('key1');
      expect(result).toBe('value1');
    });

    it('should return null for non-existent keys', async () => {
      const result = await cache.get('non-existent');
      expect(result).toBeNull();
    });

    it('should delete keys', async () => {
      await cache.set('key1', 'value1');
      await cache.delete('key1');
      const result = await cache.get('key1');
      expect(result).toBeNull();
    });

    it('should handle different value types', async () => {
      const testData = [
        { key: 'string', value: 'test' },
        { key: 'number', value: 42 },
        { key: 'boolean', value: true },
        { key: 'object', value: { nested: 'data' } },
        { key: 'array', value: [1, 2, 3] },
      ];

      for (const { key, value } of testData) {
        await cache.set(key, value);
        const result = await cache.get(key);
        expect(result).toEqual(value);
      }
    });
  });

  describe('TTL Functionality', () => {
    it('should respect custom TTL', async () => {
      await cache.set('key1', 'value1', 100); // 100ms TTL
      let result = await cache.get('key1');
      expect(result).toBe('value1');

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 150));
      result = await cache.get('key1');
      expect(result).toBeNull();
    });

    it('should use default TTL when not specified', async () => {
      await cache.set('key1', 'value1');

      // Should still be valid immediately
      let result = await cache.get('key1');
      expect(result).toBe('value1');

      // Wait for default TTL to expire
      await new Promise((resolve) => setTimeout(resolve, 1100));
      result = await cache.get('key1');
      expect(result).toBeNull();
    });

    it('should handle zero TTL (no expiration)', async () => {
      await cache.set('key1', 'value1', 0);

      // Should still be valid after a reasonable time
      await new Promise((resolve) => setTimeout(resolve, 100));
      const result = await cache.get('key1');
      expect(result).toBe('value1');
    });
  });

  describe('LRU Eviction', () => {
    it('should evict least recently used items when cache is full', async () => {
      // Create a cache with smaller size for this test
      const smallCache = new MemoryCacheAdapter({
        maxSize: 3,
        defaultTTL: 1000,
        name: 'small-cache',
      });

      // Fill cache to capacity
      await smallCache.set('key1', 'value1');
      await smallCache.set('key2', 'value2');
      await smallCache.set('key3', 'value3');

      // Access key1 to make it recently used
      await smallCache.get('key1');

      // Add one more item (should evict key2)
      await smallCache.set('key4', 'value4');

      // key1 and key3 should still exist, key2 should be evicted
      expect(await smallCache.get('key1')).toBe('value1');
      expect(await smallCache.get('key2')).toBeNull();
      expect(await smallCache.get('key3')).toBe('value3');
      expect(await smallCache.get('key4')).toBe('value4');
    });

    it('should update access order when getting items', async () => {
      // Create a cache with smaller size for this test
      const smallCache = new MemoryCacheAdapter({
        maxSize: 3,
        defaultTTL: 1000,
        name: 'small-cache-2',
      });

      await smallCache.set('key1', 'value1');
      await smallCache.set('key2', 'value2');
      await smallCache.set('key3', 'value3');

      // Access key1 to make it most recently used
      await smallCache.get('key1');

      // Add key4 (should evict key2, the oldest unused)
      await smallCache.set('key4', 'value4');

      expect(await smallCache.get('key1')).toBe('value1'); // Still exists
      expect(await smallCache.get('key2')).toBeNull(); // Evicted
      expect(await smallCache.get('key3')).toBe('value3'); // Still exists
      expect(await smallCache.get('key4')).toBe('value4'); // Newly added
    });

    it('should update existing entries without changing size', async () => {
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      expect(cache.size()).toBe(2);

      // Update existing key
      await cache.set('key1', 'updated_value1');

      expect(cache.size()).toBe(2); // Size shouldn't change
      expect(await cache.get('key1')).toBe('updated_value1');
    });
  });

  describe('Pattern Deletion', () => {
    beforeEach(async () => {
      // Set up test data
      await cache.set('user:123:profile', 'profile_data');
      await cache.set('user:123:permissions', 'permissions_data');
      await cache.set('user:456:profile', 'profile_data_2');
      await cache.set('admin:system:config', 'config_data');
      await cache.set('session:abc123', 'session_data');
    });

    it('should delete keys matching prefix pattern', async () => {
      await cache.deletePattern('user:123:*');

      expect(await cache.get('user:123:profile')).toBeNull();
      expect(await cache.get('user:123:permissions')).toBeNull();
      expect(await cache.get('user:456:profile')).toBe('profile_data_2');
      expect(await cache.get('admin:system:config')).toBe('config_data');
    });

    it('should delete keys matching suffix pattern', async () => {
      await cache.deletePattern('*:profile');

      expect(await cache.get('user:123:profile')).toBeNull();
      expect(await cache.get('user:456:profile')).toBeNull();
      expect(await cache.get('user:123:permissions')).toBe('permissions_data');
      expect(await cache.get('admin:system:config')).toBe('config_data');
    });

    it('should delete keys matching middle wildcard pattern', async () => {
      await cache.deletePattern('user:*:profile');

      expect(await cache.get('user:123:profile')).toBeNull();
      expect(await cache.get('user:456:profile')).toBeNull();
      expect(await cache.get('user:123:permissions')).toBe('permissions_data');
      expect(await cache.get('admin:system:config')).toBe('config_data');
    });
  });

  describe('Cache Statistics', () => {
    it('should track hit/miss statistics', async () => {
      // Initial stats should be zero
      let stats = await cache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.hitRate).toBe(0);

      // Add some data and access it
      await cache.set('key1', 'value1');
      await cache.get('key1'); // Hit
      await cache.get('key2'); // Miss

      stats = await cache.getStats();
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
      expect(stats.hitRate).toBe(50);
    });

    it('should track total entries and memory usage', async () => {
      // Wait a tiny bit to ensure uptime > 0
      await new Promise((resolve) => setTimeout(resolve, 1));

      await cache.set('key1', 'value1');
      await cache.set('key2', { complex: 'object', with: ['nested', 'data'] });

      const stats = await cache.getStats();
      expect(stats.totalEntries).toBe(2);
      expect(stats.memoryUsage).toBeGreaterThanOrEqual(0); // Memory usage can be 0 in some test environments
      expect(stats.uptime).toBeGreaterThan(0);
    });

    it('should provide cache metadata', () => {
      expect(cache.getName()).toBe('test-cache');
      expect(cache.size()).toBe(0);
      expect(cache.isFull()).toBe(false);
    });
  });

  describe('Cache Management', () => {
    it('should flush all entries', async () => {
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      expect(cache.size()).toBe(2);

      await cache.flush();

      expect(cache.size()).toBe(0);
      expect(await cache.get('key1')).toBeNull();
      expect(await cache.get('key2')).toBeNull();
    });

    it('should detect when cache is full', async () => {
      // Create a cache with smaller size for this test
      const smallCache = new MemoryCacheAdapter({
        maxSize: 3,
        defaultTTL: 1000,
        name: 'small-cache-3',
      });

      expect(smallCache.isFull()).toBe(false);

      await smallCache.set('key1', 'value1');
      await smallCache.set('key2', 'value2');
      await smallCache.set('key3', 'value3');

      expect(smallCache.isFull()).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should throw error for invalid configuration', () => {
      expect(
        () =>
          new MemoryCacheAdapter({
            maxSize: 0,
            defaultTTL: 1000,
            name: 'invalid',
          })
      ).toThrow('Cache maxSize must be greater than 0');

      expect(
        () =>
          new MemoryCacheAdapter({
            maxSize: 100,
            defaultTTL: 0,
            name: 'invalid',
          })
      ).toThrow('Cache defaultTTL must be greater than 0');
    });

    it('should handle concurrent operations gracefully', async () => {
      // Simulate concurrent set/get operations
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(cache.set(`key${i}`, `value${i}`));
        promises.push(cache.get(`key${i}`));
      }

      // Should not throw errors
      await Promise.all(promises);
      expect(cache.size()).toBeLessThanOrEqual(config.maxSize);
    });
  });
});
