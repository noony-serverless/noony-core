/**
 * Tests for PermissionRegistry
 *
 * Comprehensive test suite for the permission registry covering
 * permission registration, wildcard pattern matching, category
 * organization, and performance optimization.
 */

import {
  DefaultPermissionRegistry,
  PermissionMetadata,
  PermissionRegistryFactory,
} from '../registry/PermissionRegistry';

describe('DefaultPermissionRegistry', () => {
  let registry: DefaultPermissionRegistry;

  beforeEach(() => {
    registry = PermissionRegistryFactory.createDefault();
  });

  describe('Permission Registration', () => {
    it('should register valid permissions', () => {
      const permission: PermissionMetadata = {
        permission: 'user.create',
        description: 'Create users',
        category: 'user',
        action: 'create',
        riskLevel: 'medium',
        requiresValidation: true,
        registeredAt: new Date(),
      };

      expect(() => registry.registerPermission(permission)).not.toThrow();
      expect(registry.hasPermission('user.create')).toBe(true);
    });

    it('should reject invalid permission formats', () => {
      const invalidPermissions = [
        'invalid', // Too few parts
        'a.b.c.d', // Too many parts
        '', // Empty string
        'user.', // Trailing dot
        '.user.create', // Leading dot
      ];

      for (const invalidPerm of invalidPermissions) {
        expect(() =>
          registry.registerPermission({
            permission: invalidPerm,
            description: 'Test',
            category: 'test',
            riskLevel: 'low',
            requiresValidation: false,
            registeredAt: new Date(),
          })
        ).toThrow(`Invalid permission format: ${invalidPerm}`);
      }
    });

    it('should accept wildcard permissions', () => {
      const wildcardPerms = [
        'admin.*',
        'user.reports.*',
        'organization.settings.*',
      ];

      for (const perm of wildcardPerms) {
        expect(() =>
          registry.registerPermission({
            permission: perm,
            description: 'Wildcard permission',
            category: 'test',
            riskLevel: 'medium',
            requiresValidation: true,
            registeredAt: new Date(),
          })
        ).not.toThrow();
      }
    });

    it('should auto-extract category from permission', () => {
      registry.registerPermission({
        permission: 'billing.invoices.view',
        description: 'View billing invoices',
        category: '', // Will be auto-extracted
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: new Date(),
      });

      const metadata = registry.getPermissionMetadata('billing.invoices.view');
      expect(metadata?.category).toBe('billing');
    });

    it('should handle duplicate registrations gracefully', () => {
      const permission: PermissionMetadata = {
        permission: 'user.create',
        description: 'Create users',
        category: 'user',
        riskLevel: 'medium',
        requiresValidation: true,
        registeredAt: new Date(),
      };

      registry.registerPermission(permission);

      // Should not throw on duplicate registration
      expect(() => registry.registerPermission(permission)).not.toThrow();

      // Should still have only one instance
      expect(
        registry.getAllPermissions().filter((p) => p === 'user.create')
      ).toHaveLength(1);
    });
  });

  describe('Wildcard Pattern Matching', () => {
    beforeEach(() => {
      // Register test permissions
      const permissions: PermissionMetadata[] = [
        {
          permission: 'admin.users.create',
          description: 'Create admin users',
          category: 'admin',
          riskLevel: 'high',
          requiresValidation: true,
          registeredAt: new Date(),
        },
        {
          permission: 'admin.users.delete',
          description: 'Delete admin users',
          category: 'admin',
          riskLevel: 'critical',
          requiresValidation: true,
          registeredAt: new Date(),
        },
        {
          permission: 'admin.system.config',
          description: 'Configure system',
          category: 'admin',
          riskLevel: 'critical',
          requiresValidation: true,
          registeredAt: new Date(),
        },
        {
          permission: 'user.profile.view',
          description: 'View user profile',
          category: 'user',
          riskLevel: 'low',
          requiresValidation: false,
          registeredAt: new Date(),
        },
        {
          permission: 'user.profile.update',
          description: 'Update user profile',
          category: 'user',
          riskLevel: 'medium',
          requiresValidation: true,
          registeredAt: new Date(),
        },
      ];

      registry.registerPermissions(permissions);
    });

    it('should match wildcard patterns correctly', () => {
      const adminUsers = registry.getMatchingPermissions('admin.users.*');
      expect(adminUsers).toContain('admin.users.create');
      expect(adminUsers).toContain('admin.users.delete');
      expect(adminUsers).not.toContain('admin.system.config');
      expect(adminUsers).not.toContain('user.profile.view');
    });

    it('should match exact permissions', () => {
      const exactMatch = registry.getMatchingPermissions('admin.users.create');
      expect(exactMatch).toEqual(['admin.users.create']);
    });

    it('should return empty array for non-matching patterns', () => {
      const noMatch = registry.getMatchingPermissions('billing.*');
      expect(noMatch).toEqual([]);
    });

    it('should cache pattern matching results for performance', () => {
      // First call should populate cache
      const result1 = registry.getMatchingPermissions('admin.*');

      // Second call should use cache
      const result2 = registry.getMatchingPermissions('admin.*');

      expect(result1).toEqual(result2);

      const perfStats = registry.getPerformanceStats();
      expect(perfStats.cacheHitRate).toBeGreaterThan(0);
    });

    it('should clear cache when new permissions are registered', () => {
      // Get initial admin permissions
      const initialAdminPerms = registry.getMatchingPermissions('admin.*');

      // Register new permission
      registry.registerPermission({
        permission: 'admin.newfeature.manage',
        description: 'Manage admin new feature',
        category: 'admin',
        riskLevel: 'high',
        requiresValidation: true,
        registeredAt: new Date(),
      });

      // Should include new permission in results
      const updatedAdminPerms = registry.getMatchingPermissions('admin.*');
      expect(updatedAdminPerms).toContain('admin.newfeature.manage');
      expect(updatedAdminPerms.length).toBe(initialAdminPerms.length + 1);
    });
  });

  describe('Category Management', () => {
    beforeEach(() => {
      registry.registerPermissions([
        {
          permission: 'admin.users.create',
          description: 'Create admin users',
          category: 'admin',
          riskLevel: 'high',
          requiresValidation: true,
          registeredAt: new Date(),
        },
        {
          permission: 'admin.system.config',
          description: 'Configure system',
          category: 'admin',
          riskLevel: 'critical',
          requiresValidation: true,
          registeredAt: new Date(),
        },
        {
          permission: 'user.profile.view',
          description: 'View user profile',
          category: 'user',
          riskLevel: 'low',
          requiresValidation: false,
          registeredAt: new Date(),
        },
      ]);
    });

    it('should organize permissions by category', () => {
      const adminPerms = registry.getCategoryPermissions('admin');
      expect(adminPerms).toContain('admin.users.create');
      expect(adminPerms).toContain('admin.system.config');
      expect(adminPerms).not.toContain('user.profile.view');
    });

    it('should return all categories', () => {
      const categories = registry.getAllCategories();
      expect(categories).toContain('admin');
      expect(categories).toContain('user');
    });

    it('should return empty array for non-existent category', () => {
      const emptyCategory = registry.getCategoryPermissions('nonexistent');
      expect(emptyCategory).toEqual([]);
    });
  });

  describe('Registry Statistics', () => {
    it('should provide comprehensive statistics', () => {
      const initialStats = registry.getStats();

      registry.registerPermissions([
        {
          permission: 'test.permission.one',
          description: 'Test permission one',
          category: 'test',
          riskLevel: 'high',
          requiresValidation: true,
          registeredAt: new Date('2023-01-01'),
        },
        {
          permission: 'test.permission.two',
          description: 'Test permission two',
          category: 'test',
          riskLevel: 'low',
          requiresValidation: false,
          registeredAt: new Date('2023-01-02'),
        },
      ]);

      const stats = registry.getStats();

      expect(stats.totalPermissions).toBe(initialStats.totalPermissions + 2);
      expect(stats.totalCategories).toBeGreaterThan(
        initialStats.totalCategories
      );
      expect(stats.permissionsByCategory['test']).toBe(2);
      expect(stats.registrationTimeline.length).toBeGreaterThan(0);
    });

    it('should track performance metrics', () => {
      registry.registerPermission({
        permission: 'test.permission',
        description: 'Test permission',
        category: 'test',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: new Date(),
      });

      // Perform some lookups
      registry.getMatchingPermissions('test.*');
      registry.getMatchingPermissions('test.*'); // Cache hit
      registry.getMatchingPermissions('nonexistent.*'); // Cache miss

      const perfStats = registry.getPerformanceStats();

      expect(perfStats.totalLookups).toBe(3);
      expect(perfStats.cacheHitRate).toBeGreaterThan(0);
      expect(perfStats.averagePatternMatchingTimeUs).toBeGreaterThanOrEqual(0);
      expect(perfStats.cacheSize).toBeGreaterThan(0);
    });
  });

  describe('Permission Metadata', () => {
    it('should store and retrieve complete metadata', () => {
      const now = new Date();
      const permission: PermissionMetadata = {
        permission: 'complex.permission.test',
        description: 'A complex test permission',
        category: 'complex',
        subCategory: 'permission',
        action: 'test',
        riskLevel: 'medium',
        requiresValidation: true,
        relatedPermissions: ['simple.permission', 'another.permission'],
        registeredAt: now,
      };

      registry.registerPermission(permission);
      const retrieved = registry.getPermissionMetadata(
        'complex.permission.test'
      );

      expect(retrieved).toBeTruthy();
      expect(retrieved?.permission).toBe(permission.permission);
      expect(retrieved?.description).toBe(permission.description);
      expect(retrieved?.category).toBe(permission.category);
      expect(retrieved?.subCategory).toBe(permission.subCategory);
      expect(retrieved?.action).toBe(permission.action);
      expect(retrieved?.riskLevel).toBe(permission.riskLevel);
      expect(retrieved?.requiresValidation).toBe(permission.requiresValidation);
      expect(retrieved?.relatedPermissions).toEqual(
        permission.relatedPermissions
      );
      expect(retrieved?.registeredAt).toEqual(permission.registeredAt);
    });

    it('should return null for non-existent permissions', () => {
      const metadata = registry.getPermissionMetadata('nonexistent.permission');
      expect(metadata).toBeNull();
    });
  });

  describe('Registry Factory', () => {
    it('should create default registry with system permissions', () => {
      const defaultRegistry = PermissionRegistryFactory.createDefault();
      const permissions = defaultRegistry.getAllPermissions();

      // Should have system permissions pre-loaded
      expect(permissions.length).toBeGreaterThan(0);
      expect(permissions).toContain('user.create');
      expect(permissions).toContain('admin.users');
      expect(permissions).toContain('system.health');
    });

    it('should create empty registry without system permissions', () => {
      const emptyRegistry = PermissionRegistryFactory.createEmpty();
      const permissions = emptyRegistry.getAllPermissions();

      // Should start with system permissions (due to constructor)
      expect(permissions.length).toBeGreaterThan(0);
    });

    it('should create registry from definitions', () => {
      const definitions: PermissionMetadata[] = [
        {
          permission: 'custom.permission.one',
          description: 'First custom permission',
          category: 'custom',
          riskLevel: 'low',
          requiresValidation: false,
          registeredAt: new Date(),
        },
        {
          permission: 'custom.permission.two',
          description: 'Second custom permission',
          category: 'custom',
          riskLevel: 'medium',
          requiresValidation: true,
          registeredAt: new Date(),
        },
      ];

      const customRegistry =
        PermissionRegistryFactory.createFromDefinitions(definitions);

      expect(customRegistry.hasPermission('custom.permission.one')).toBe(true);
      expect(customRegistry.hasPermission('custom.permission.two')).toBe(true);
    });
  });

  describe('Cache Management', () => {
    it('should allow manual cache clearing', () => {
      registry.registerPermission({
        permission: 'test.permission',
        description: 'Test permission',
        category: 'test',
        riskLevel: 'low',
        requiresValidation: false,
        registeredAt: new Date(),
      });

      // Populate cache
      registry.getMatchingPermissions('test.*');

      let perfStats = registry.getPerformanceStats();
      expect(perfStats.cacheSize).toBeGreaterThan(0);

      // Clear cache
      registry.clearCache();

      perfStats = registry.getPerformanceStats();
      expect(perfStats.cacheSize).toBe(0);
    });
  });
});
