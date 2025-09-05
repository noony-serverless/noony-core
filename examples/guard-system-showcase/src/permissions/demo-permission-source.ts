/**
 * Demo Permission Source
 *
 * In-memory permission source implementation for the Guard System Showcase
 * that uses the demo data. Provides comprehensive permission management with
 * role hierarchy, caching, and performance optimization for demonstration
 * and testing purposes.
 *
 * Features:
 * - In-memory storage for fast demonstration
 * - Role hierarchy with inheritance
 * - Permission caching and invalidation
 * - Comprehensive demo scenarios
 * - Performance monitoring and statistics
 *
 * @module DemoPermissionSource
 * @version 1.0.0
 */

import {
  BasePermissionSource,
  PermissionQueryOptions,
} from './permission-source';
import { Role, Permission } from '@/types/auth.types';
import {
  getDemoUsers,
  getDemoRoles,
  getDemoPermissions,
  getRolePermissions,
  testUserRegistry,
} from '@/utils/demo-data';

/**
 * Cache entry for permission data
 */
interface PermissionCacheEntry {
  data: unknown;
  timestamp: number;
  expires: number;
}

/**
 * Demo Permission Source Implementation
 *
 * Provides a fully-featured permission source using in-memory demo data.
 * Supports role hierarchies, permission inheritance, caching, and all
 * advanced features needed to demonstrate the Guard system capabilities.
 */
export class DemoPermissionSource extends BasePermissionSource {
  private readonly cache = new Map<string, PermissionCacheEntry>();
  private readonly defaultCacheTTL = 5 * 60 * 1000; // 5 minutes
  private readonly roleHierarchyCache = new Map<string, Set<string>>();

  // Demo data
  private demoUsers: ReturnType<typeof getDemoUsers>;
  private demoRoles: ReturnType<typeof getDemoRoles>;
  private demoPermissions: ReturnType<typeof getDemoPermissions>;

  constructor() {
    super('DemoPermissionSource');

    // Load demo data
    this.demoUsers = getDemoUsers();
    this.demoRoles = getDemoRoles();
    this.demoPermissions = getDemoPermissions();

    // Build role hierarchy cache
    this.buildRoleHierarchyCache();

    console.log(
      `📊 Demo Permission Source initialized with ${this.demoUsers.length} users, ${this.demoRoles.length} roles, ${this.demoPermissions.length} permissions`
    );
  }

  // ============================================================================
  // CORE PERMISSION OPERATIONS
  // ============================================================================

  /**
   * Get user permissions with role expansion and caching
   *
   * @param userId - User ID to query
   * @param options - Query options
   * @returns Promise resolving to set of user permissions
   */
  public async getUserPermissions(
    userId: string,
    options: PermissionQueryOptions = {}
  ): Promise<Set<string>> {
    const startTime = process.hrtime.bigint();
    const cacheKey = this.getCacheKey('user-permissions', userId, options);

    try {
      // Check cache first (unless force refresh)
      if (!options.forceRefresh) {
        const cached = this.getFromCache<Set<string>>(
          cacheKey,
          options.maxCacheAge
        );
        if (cached) {
          this.trackCacheHit();
          this.trackQuery(startTime, true);
          return cached;
        }
      }

      this.trackCacheMiss();

      // Find user in demo data
      let user = this.demoUsers.find((u) => u.userId === userId);
      
      // If not found and it looks like a test user, try the test user registry
      if (!user && userId.includes('-')) {
        try {
          // Using static import for singleton consistency
          user = testUserRegistry.getTestUser(userId);
          if (user) {
            console.log(`🧪 Found test user in permission source: ${userId}`);
          }
        } catch (error) {
          // Test user registry not available or user not found
        }
      }
      
      if (!user) {
        throw this.createError(`User not found: ${userId}`, 'USER_NOT_FOUND');
      }

      // Start with user's direct permissions
      const permissions = new Set<string>(user.permissions);

      // Add role permissions if requested
      if (options.includeRolePermissions !== false) {
        const rolePermissions = await this.getRolePermissionsForUser(
          userId,
          options
        );
        rolePermissions.forEach((perm) => permissions.add(perm));
      }

      // Expand wildcards if requested
      if (options.expandWildcards) {
        const expandedPermissions = this.expandWildcardPermissions(permissions);
        expandedPermissions.forEach((perm) => permissions.add(perm));
      }

      // Apply resource filter if provided
      let filteredPermissions = permissions;
      if (options.resourceFilter && options.resourceFilter.length > 0) {
        filteredPermissions = new Set<string>();
        for (const permission of permissions) {
          if (this.matchesResourceFilter(permission, options.resourceFilter)) {
            filteredPermissions.add(permission);
          }
        }
      }

      // Cache the result
      this.storeInCache(cacheKey, filteredPermissions);

      this.trackQuery(startTime, true);
      this.log(
        `Retrieved ${filteredPermissions.size} permissions for user ${userId}`
      );

      return filteredPermissions;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Get user roles
   *
   * @param userId - User ID to query
   * @param options - Query options
   * @returns Promise resolving to array of role IDs
   */
  public async getUserRoles(
    userId: string,
    options: PermissionQueryOptions = {}
  ): Promise<string[]> {
    const startTime = process.hrtime.bigint();
    const cacheKey = this.getCacheKey('user-roles', userId, options);

    try {
      // Check cache first
      if (!options.forceRefresh) {
        const cached = this.getFromCache<string[]>(
          cacheKey,
          options.maxCacheAge
        );
        if (cached) {
          this.trackCacheHit();
          this.trackQuery(startTime, true);
          return cached;
        }
      }

      this.trackCacheMiss();

      // Find user in demo data
      let user = this.demoUsers.find((u) => u.userId === userId);
      
      // If not found and it looks like a test user, try the test user registry
      if (!user && userId.includes('-')) {
        try {
          // Using static import for singleton consistency
          user = testUserRegistry.getTestUser(userId);
          if (user) {
            console.log(`🧪 Found test user in permission source (roles): ${userId}`);
          }
        } catch (error) {
          // Test user registry not available or user not found
        }
      }
      
      if (!user) {
        throw this.createError(`User not found: ${userId}`, 'USER_NOT_FOUND');
      }

      let roles = [...user.roles];

      // Include role hierarchy if requested
      if (options.includeRoleHierarchy) {
        const hierarchicalRoles = new Set<string>(roles);

        for (const role of roles) {
          const inheritedRoles = this.getInheritedRoles(role);
          inheritedRoles.forEach((r) => hierarchicalRoles.add(r));
        }

        roles = Array.from(hierarchicalRoles);
      }

      // Cache the result
      this.storeInCache(cacheKey, roles);

      this.trackQuery(startTime, true);
      this.log(
        `Retrieved ${roles.length} roles for user ${userId}`,
        roles as unknown as Record<string, unknown>
      );

      return roles;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Get role definition
   *
   * @param roleId - Role ID to query
   * @param options - Query options
   * @returns Promise resolving to role definition or null
   */
  public async getRole(
    roleId: string,
    options: PermissionQueryOptions = {}
  ): Promise<Role | null> {
    const startTime = process.hrtime.bigint();
    const cacheKey = this.getCacheKey('role', roleId, options);

    try {
      // Check cache first
      if (!options.forceRefresh) {
        const cached = this.getFromCache<Role | null>(
          cacheKey,
          options.maxCacheAge
        );
        if (cached !== undefined) {
          this.trackCacheHit();
          this.trackQuery(startTime, true);
          return cached;
        }
      }

      this.trackCacheMiss();

      const role = this.demoRoles.find((r) => r.id === roleId) || null;

      // Cache the result (including null results)
      this.storeInCache(cacheKey, role);

      this.trackQuery(startTime, true);
      this.log(
        `Retrieved role: ${roleId}`,
        role?.name as unknown as Record<string, unknown>
      );

      return role;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Get multiple role definitions
   *
   * @param roleIds - Array of role IDs
   * @param options - Query options
   * @returns Promise resolving to map of role definitions
   */
  public async getRoles(
    roleIds: string[],
    options: PermissionQueryOptions = {}
  ): Promise<Map<string, Role>> {
    const startTime = process.hrtime.bigint();

    try {
      const roleMap = new Map<string, Role>();

      // Use individual role queries to benefit from caching
      const rolePromises = roleIds.map(async (roleId) => {
        const role = await this.getRole(roleId, options);
        return { roleId, role };
      });

      const results = await Promise.all(rolePromises);

      for (const { roleId, role } of results) {
        if (role) {
          roleMap.set(roleId, role);
        }
      }

      this.trackQuery(startTime, true);
      this.log(
        `Retrieved ${roleMap.size} roles from ${roleIds.length} requested`
      );

      return roleMap;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Get permission definition
   *
   * @param permissionId - Permission ID to query
   * @returns Promise resolving to permission definition or null
   */
  public async getPermission(permissionId: string): Promise<Permission | null> {
    const startTime = process.hrtime.bigint();

    try {
      const permission =
        this.demoPermissions.find((p) => p.id === permissionId) || null;

      this.trackQuery(startTime, true);
      this.log(
        `Retrieved permission: ${permissionId}`,
        permission?.name as unknown as Record<string, unknown>
      );

      return permission;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Invalidate cached permissions for user
   *
   * @param userId - User ID to invalidate or 'all'
   * @returns Promise that resolves when invalidation is complete
   */
  public async invalidateUser(userId: string | 'all'): Promise<void> {
    try {
      if (userId === 'all') {
        this.cache.clear();
        this.log('All caches invalidated');
      } else {
        const keysToRemove: string[] = [];

        for (const key of this.cache.keys()) {
          if (key.includes(`user:${userId}:`)) {
            keysToRemove.push(key);
          }
        }

        keysToRemove.forEach((key) => this.cache.delete(key));
        this.log(
          `Invalidated ${keysToRemove.length} cache entries for user ${userId}`
        );
      }
    } catch (error) {
      console.error('Cache invalidation failed:', error);
      throw error;
    }
  }

  /**
   * Shutdown source and cleanup resources
   */
  public async shutdown(): Promise<void> {
    this.cache.clear();
    this.roleHierarchyCache.clear();
    console.log('📊 Demo Permission Source shutdown complete');
  }

  // ============================================================================
  // ROLE HIERARCHY AND INHERITANCE
  // ============================================================================

  /**
   * Build role hierarchy cache for performance
   */
  private buildRoleHierarchyCache(): void {
    for (const role of this.demoRoles) {
      const inherited = new Set<string>();
      this.collectInheritedRoles(role.id, inherited, new Set());
      this.roleHierarchyCache.set(role.id, inherited);
    }

    this.log(
      `Built role hierarchy cache for ${this.roleHierarchyCache.size} roles`
    );
  }

  /**
   * Recursively collect inherited roles
   *
   * @param roleId - Current role ID
   * @param inherited - Set to collect inherited roles
   * @param visited - Set to prevent circular references
   */
  private collectInheritedRoles(
    roleId: string,
    inherited: Set<string>,
    visited: Set<string>
  ): void {
    if (visited.has(roleId)) {
      return; // Prevent infinite recursion
    }

    visited.add(roleId);
    const role = this.demoRoles.find((r) => r.id === roleId);

    if (role && role.parent) {
      inherited.add(role.parent);
      this.collectInheritedRoles(role.parent, inherited, visited);
    }
  }

  /**
   * Get inherited roles for a specific role
   *
   * @param roleId - Role ID
   * @returns Set of inherited role IDs
   */
  private getInheritedRoles(roleId: string): Set<string> {
    return this.roleHierarchyCache.get(roleId) || new Set();
  }

  /**
   * Get role permissions for a user including inheritance
   *
   * @param userId - User ID
   * @param options - Query options
   * @returns Promise resolving to set of role permissions
   */
  private async getRolePermissionsForUser(
    userId: string,
    options: PermissionQueryOptions
  ): Promise<Set<string>> {
    const userRoles = await this.getUserRoles(userId, {
      ...options,
      includeRoleHierarchy: true,
    });
    const permissions = new Set<string>();

    for (const roleId of userRoles) {
      const rolePermissions = getRolePermissions(roleId);
      rolePermissions.forEach((perm) => permissions.add(perm));
    }

    return permissions;
  }

  // ============================================================================
  // PERMISSION EXPANSION AND FILTERING
  // ============================================================================

  /**
   * Expand wildcard permissions to concrete permissions
   *
   * @param permissions - Base permission set
   * @returns Set of expanded permissions
   */
  private expandWildcardPermissions(permissions: Set<string>): Set<string> {
    const expanded = new Set<string>();

    for (const permission of permissions) {
      // Add the original permission
      expanded.add(permission);

      // If it contains wildcards, expand them
      if (permission.includes('*')) {
        const expansions = this.generateWildcardExpansions(permission);
        expansions.forEach((exp) => expanded.add(exp));
      }
    }

    return expanded;
  }

  /**
   * Generate concrete permissions from wildcard patterns
   *
   * @param pattern - Wildcard permission pattern
   * @returns Array of concrete permissions
   */
  private generateWildcardExpansions(pattern: string): string[] {
    const expansions: string[] = [];

    // For demo purposes, create common CRUD expansions
    if (pattern.endsWith(':*')) {
      const resource = pattern.slice(0, -2);
      const actions = ['read', 'write', 'create', 'update', 'delete', 'list'];

      actions.forEach((action) => {
        expansions.push(`${resource}:${action}`);
      });
    }

    // Admin wildcard expansions
    if (pattern === 'admin:*') {
      expansions.push(
        'admin:users',
        'admin:roles',
        'admin:permissions',
        'admin:system',
        'admin:reports',
        'admin:audit'
      );
    }

    return expansions;
  }

  /**
   * Check if permission matches resource filter
   *
   * @param permission - Permission to check
   * @param resourceFilter - Array of resource patterns
   * @returns True if permission matches filter
   */
  private matchesResourceFilter(
    permission: string,
    resourceFilter: string[]
  ): boolean {
    const parts = permission.split(':');
    const resource = parts[0];

    return resourceFilter.some((filter) => {
      if (filter.includes('*')) {
        // Simple glob matching
        const regex = new RegExp(filter.replace(/\*/g, '.*'));
        return regex.test(resource);
      } else {
        return resource === filter;
      }
    });
  }

  // ============================================================================
  // CACHING IMPLEMENTATION
  // ============================================================================

  /**
   * Generate cache key for permission data
   *
   * @param type - Data type
   * @param identifier - User/role/permission ID
   * @param options - Query options
   * @returns Cache key string
   */
  private getCacheKey(
    type: string,
    identifier: string,
    options: PermissionQueryOptions
  ): string {
    const optionsHash = this.hashOptions(options);
    return `${type}:user:${identifier}:${optionsHash}`;
  }

  /**
   * Hash options to create consistent cache key
   *
   * @param options - Query options
   * @returns Hash string
   */
  private hashOptions(options: PermissionQueryOptions): string {
    const normalized = {
      includeRoles: options.includeRolePermissions !== false,
      includeHierarchy: options.includeRoleHierarchy || false,
      expandWildcards: options.expandWildcards || false,
      resourceFilter: options.resourceFilter?.sort().join(',') || '',
    };

    return Buffer.from(JSON.stringify(normalized))
      .toString('base64')
      .substring(0, 8);
  }

  /**
   * Get data from cache
   *
   * @param cacheKey - Cache key
   * @param maxAge - Maximum acceptable age (optional)
   * @returns Cached data or undefined if not found/expired
   */
  private getFromCache<T>(cacheKey: string, maxAge?: number): T | undefined {
    const entry = this.cache.get(cacheKey);
    if (!entry) {
      return undefined;
    }

    const now = Date.now();

    // Check if expired
    if (now > entry.expires || (maxAge && now - entry.timestamp > maxAge)) {
      this.cache.delete(cacheKey);
      return undefined;
    }

    return entry.data as T;
  }

  /**
   * Store data in cache
   *
   * @param cacheKey - Cache key
   * @param data - Data to cache
   * @param ttl - Time to live (optional)
   */
  private storeInCache<T>(cacheKey: string, data: T, ttl?: number): void {
    const now = Date.now();
    const effectiveTTL = ttl || this.defaultCacheTTL;

    const entry: PermissionCacheEntry = {
      data,
      timestamp: now,
      expires: now + effectiveTTL,
    };

    this.cache.set(cacheKey, entry);

    // Periodic cleanup to prevent memory leaks
    if (this.cache.size > 10000) {
      this.cleanupExpiredCache();
    }
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupExpiredCache(): void {
    const now = Date.now();
    const keysToRemove: string[] = [];

    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expires) {
        keysToRemove.push(key);
      }
    }

    keysToRemove.forEach((key) => this.cache.delete(key));

    if (keysToRemove.length > 0) {
      this.log(`Cleaned up ${keysToRemove.length} expired cache entries`);
    }
  }

  // ============================================================================
  // PUBLIC API EXTENSIONS
  // ============================================================================

  /**
   * Get cache status for monitoring
   */
  public getCacheStatus(): {
    entries: number;
    hitRate: number;
    memoryUsage: string;
  } {
    return {
      entries: this.cache.size,
      hitRate: Math.round(this.getCacheHitRate() * 100) / 100,
      memoryUsage: `${this.cache.size}/10000`,
    };
  }

  /**
   * Get detailed statistics including demo data info
   */
  public getDetailedStats(): Record<string, unknown> {
    const baseStats = this.getStats();
    const cacheStatus = this.getCacheStatus();

    return {
      ...baseStats,
      cache: cacheStatus,
      dataSource: {
        users: this.demoUsers.length,
        roles: this.demoRoles.length,
        permissions: this.demoPermissions.length,
        roleHierarchies: this.roleHierarchyCache.size,
      },
      performance: {
        cacheHitRate: cacheStatus.hitRate,
        averageQueryTime: Math.round(baseStats.averageQueryTime * 100) / 100,
        errorRate:
          baseStats.totalQueries > 0
            ? Math.round(
                (baseStats.errors / baseStats.totalQueries) * 100 * 100
              ) / 100
            : 0,
      },
    };
  }

  /**
   * Force rebuild role hierarchy cache
   */
  public rebuildRoleHierarchy(): void {
    this.roleHierarchyCache.clear();
    this.buildRoleHierarchyCache();
    this.log('Role hierarchy cache rebuilt');
  }

  /**
   * Get all permissions for debugging
   */
  public getAllPermissions(): Permission[] {
    return [...this.demoPermissions];
  }

  /**
   * Get all roles for debugging
   */
  public getAllRoles(): Role[] {
    return [...this.demoRoles];
  }
}
