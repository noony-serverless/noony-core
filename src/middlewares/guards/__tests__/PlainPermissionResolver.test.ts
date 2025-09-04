/**
 * Tests for PlainPermissionResolver
 *
 * Test suite for the plain permission resolver covering
 * O(1) permission checks, Set-based operations, and performance
 * characteristics.
 */

import { PlainPermissionResolver } from '../resolvers/PlainPermissionResolver';
import { PermissionResolverType } from '../resolvers/PermissionResolver';

describe('PlainPermissionResolver', () => {
  let resolver: PlainPermissionResolver;

  beforeEach(() => {
    resolver = new PlainPermissionResolver();
  });

  describe('Permission Checking', () => {
    it('should allow permissions in the required set', async () => {
      const requiredPermissions = ['user.create', 'user.read', 'admin.manage'];
      const userPermissions = new Set([
        'user.create',
        'user.read',
        'user.update',
        'admin.manage',
      ]);

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(true);
    });

    it('should deny when user lacks required permissions', async () => {
      const requiredPermissions = ['user.create', 'admin.manage'];
      const userPermissions = new Set(['user.read', 'user.update']);

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(false);
    });

    it('should handle empty required permissions', async () => {
      const requiredPermissions: string[] = [];
      const userPermissions = new Set(['user.read']);

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(false); // No permissions required means access denied
    });

    it('should handle empty user permissions', async () => {
      const requiredPermissions = ['user.create'];
      const userPermissions = new Set<string>();

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(false);
    });

    it('should handle both empty arrays', async () => {
      const requiredPermissions: string[] = [];
      const userPermissions = new Set<string>();

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(false); // No permissions required means access denied
    });

    it('should be case sensitive', async () => {
      const requiredPermissions = ['User.Create'];
      const userPermissions = new Set(['user.create']);

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(false);
    });

    it('should handle duplicate permissions correctly', async () => {
      const requiredPermissions = ['user.create', 'user.create', 'user.read'];
      const userPermissions = new Set(['user.create', 'user.read']);

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(true);
    });

    it('should use OR logic for required permissions', async () => {
      const requiredPermissions = ['admin.super', 'user.read']; // User needs EITHER admin.super OR user.read
      const userPermissions = new Set(['user.read']); // User only has user.read

      const result = await resolver.check(userPermissions, requiredPermissions);

      expect(result).toBe(true); // Should pass because user has one of the required permissions
    });
  });

  describe('Performance Characteristics', () => {
    it('should have O(1) complexity characteristics', async () => {
      // Test with small set
      const smallRequired = ['user.create'];
      const smallUser = new Set(['user.create']);

      const startSmall = process.hrtime();
      await resolver.check(smallUser, smallRequired);
      const [secondsSmall, nanosecondsSmall] = process.hrtime(startSmall);
      const timeSmall = secondsSmall * 1000 + nanosecondsSmall / 1000000;

      // Test with large set
      const largeRequired = Array.from(
        { length: 100 },
        (_, i) => `permission.${i}`
      );
      const largeUser = new Set(
        Array.from({ length: 1000 }, (_, i) => `permission.${i}`)
      );

      const startLarge = process.hrtime();
      await resolver.check(largeUser, largeRequired);
      const [secondsLarge, nanosecondsLarge] = process.hrtime(startLarge);
      const timeLarge = secondsLarge * 1000 + nanosecondsLarge / 1000000;

      // Large set should not be significantly slower (within reason for Set operations)
      // Allow for some variance due to system factors
      expect(timeLarge).toBeLessThan(timeSmall * 20); // More lenient for test environments
    });

    it('should have consistent performance across multiple calls', async () => {
      const requiredPermissions = ['user.create', 'user.read', 'admin.manage'];
      const userPermissions = new Set(['user.create', 'user.read']);

      const times = [];
      for (let i = 0; i < 10; i++) {
        const start = process.hrtime.bigint();
        await resolver.check(userPermissions, requiredPermissions);
        const end = process.hrtime.bigint();
        times.push(Number(end - start) / 1000000); // Convert to ms
      }

      // All calls should be reasonably fast (< 1ms for plain permission checks in most cases)
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      expect(avgTime).toBeLessThan(5); // Allow some variance in test environments
    });
  });

  describe('Edge Cases', () => {
    it('should handle valid permission names with hyphens', async () => {
      const validPermissions = [
        'user.read-data',
        'admin.user-management',
        'billing.invoice-view',
      ];
      const userPermissions = new Set(validPermissions);

      const result = await resolver.check(userPermissions, validPermissions);

      expect(result).toBe(true);
    });

    it('should handle very long permission names', async () => {
      const longPermission = 'a'.repeat(1000) + '.create';
      const userPermissions = new Set([longPermission]);

      const result = await resolver.check(userPermissions, [longPermission]);

      expect(result).toBe(true);
    });

    it('should handle large number of permissions efficiently', async () => {
      const manyUserPermissions = new Set(
        Array.from({ length: 10000 }, (_, i) => `perm.${i}`)
      );
      const requiredPermissions = Array.from(
        { length: 100 },
        (_, i) => `perm.${i}`
      );

      const start = process.hrtime();
      const result = await resolver.check(
        manyUserPermissions,
        requiredPermissions
      );
      const [seconds, nanoseconds] = process.hrtime(start);
      const duration = seconds * 1000 + nanoseconds / 1000000;

      expect(result).toBe(true);
      expect(duration).toBeLessThan(10); // Should complete within 10ms
    });

    it('should handle invalid permission formats gracefully', async () => {
      const invalidPermissions = ['invalid', 'a.b.c.d'];
      const userPermissions = new Set(['user.valid']);

      // Should throw error for invalid permissions
      await expect(
        resolver.check(userPermissions, invalidPermissions)
      ).rejects.toThrow();
    });
  });

  describe('Resolver Metadata', () => {
    it('should provide correct resolver type', () => {
      expect(resolver.getType()).toBe(PermissionResolverType.PLAIN);
    });

    it('should provide performance characteristics', () => {
      const characteristics = resolver.getPerformanceCharacteristics();

      expect(characteristics.timeComplexity).toBe('O(1) per permission check');
      expect(characteristics.memoryUsage).toBe('low');
      expect(characteristics.cacheUtilization).toBe('none');
      expect(Array.isArray(characteristics.recommendedFor)).toBe(true);
      expect(characteristics.recommendedFor.length).toBeGreaterThan(0);
    });
  });
});
