/**
 * Permission Source Interface
 *
 * Defines the contract for permission data sources in the Guard System
 * Showcase. Permission sources provide user permissions, role definitions,
 * and permission metadata to the guard system resolvers.
 *
 * Features:
 * - Pluggable permission data sources (database, cache, API, etc.)
 * - Support for hierarchical permissions and role inheritance
 * - Performance optimizations with caching and prefetching
 * - Real-time permission updates and invalidation
 *
 * @module PermissionSource
 * @version 1.0.0
 */

import { Role, Permission } from '@/types/auth.types';

/**
 * Permission query options for fine-tuned data loading
 */
export interface PermissionQueryOptions {
  /** Include inherited permissions from roles */
  includeRolePermissions?: boolean;

  /** Include role hierarchy (parent/child roles) */
  includeRoleHierarchy?: boolean;

  /** Expand wildcard permissions */
  expandWildcards?: boolean;

  /** Filter permissions by resource */
  resourceFilter?: string[];

  /** Maximum cache age for results (milliseconds) */
  maxCacheAge?: number;

  /** Force refresh from source */
  forceRefresh?: boolean;
}

/**
 * Permission source statistics for monitoring
 */
export interface PermissionSourceStats {
  /** Total permission queries */
  totalQueries: number;

  /** Cache hits */
  cacheHits: number;

  /** Cache misses */
  cacheMisses: number;

  /** Average query time (microseconds) */
  averageQueryTime: number;

  /** Error count */
  errors: number;

  /** Last query timestamp */
  lastQuery: number;
}

/**
 * Permission Source Interface
 *
 * Abstract interface that all permission sources must implement.
 * Provides a consistent API for retrieving user permissions, roles,
 * and permission metadata regardless of the underlying data store.
 */
export interface PermissionSource {
  /**
   * Get user permissions with optional role expansion
   *
   * @param userId - User ID to query permissions for
   * @param options - Query options
   * @returns Promise resolving to set of user permissions
   */
  getUserPermissions(
    userId: string,
    options?: PermissionQueryOptions
  ): Promise<Set<string>>;

  /**
   * Get user roles
   *
   * @param userId - User ID to query roles for
   * @param options - Query options
   * @returns Promise resolving to array of role IDs
   */
  getUserRoles(
    userId: string,
    options?: PermissionQueryOptions
  ): Promise<string[]>;

  /**
   * Get role definition
   *
   * @param roleId - Role ID to query
   * @param options - Query options
   * @returns Promise resolving to role definition or null
   */
  getRole(
    roleId: string,
    options?: PermissionQueryOptions
  ): Promise<Role | null>;

  /**
   * Get multiple role definitions
   *
   * @param roleIds - Array of role IDs
   * @param options - Query options
   * @returns Promise resolving to map of role definitions
   */
  getRoles(
    roleIds: string[],
    options?: PermissionQueryOptions
  ): Promise<Map<string, Role>>;

  /**
   * Get permission definition
   *
   * @param permissionId - Permission ID to query
   * @returns Promise resolving to permission definition or null
   */
  getPermission(permissionId: string): Promise<Permission | null>;

  /**
   * Check if user has specific permission
   *
   * @param userId - User ID to check
   * @param permission - Permission to check for
   * @param options - Query options
   * @returns Promise resolving to boolean result
   */
  hasPermission(
    userId: string,
    permission: string,
    options?: PermissionQueryOptions
  ): Promise<boolean>;

  /**
   * Get all permissions for multiple users (batch operation)
   *
   * @param userIds - Array of user IDs
   * @param options - Query options
   * @returns Promise resolving to map of user permissions
   */
  getBatchUserPermissions(
    userIds: string[],
    options?: PermissionQueryOptions
  ): Promise<Map<string, Set<string>>>;

  /**
   * Invalidate cached permissions for user
   *
   * @param userId - User ID to invalidate (or 'all' for complete invalidation)
   * @returns Promise that resolves when invalidation is complete
   */
  invalidateUser(userId: string | 'all'): Promise<void>;

  /**
   * Get source statistics
   *
   * @returns Current source statistics
   */
  getStats(): PermissionSourceStats;

  /**
   * Get source health status
   *
   * @returns Health status information
   */
  getHealthStatus(): {
    healthy: boolean;
    lastError?: string;
    uptime: number;
  };

  /**
   * Shutdown source and cleanup resources
   */
  shutdown(): Promise<void>;
}

/**
 * Base Permission Source
 *
 * Abstract base class that provides common functionality for permission
 * sources including statistics tracking, health monitoring, and caching utilities.
 */
export abstract class BasePermissionSource implements PermissionSource {
  protected stats: PermissionSourceStats;
  protected readonly sourceName: string;
  protected lastError?: Error;
  protected readonly startTime: number;

  constructor(sourceName: string) {
    this.sourceName = sourceName;
    this.startTime = Date.now();
    this.stats = this.initializeStats();
  }

  // Abstract methods that subclasses must implement
  public abstract getUserPermissions(
    userId: string,
    options?: PermissionQueryOptions
  ): Promise<Set<string>>;
  public abstract getUserRoles(
    userId: string,
    options?: PermissionQueryOptions
  ): Promise<string[]>;
  public abstract getRole(
    roleId: string,
    options?: PermissionQueryOptions
  ): Promise<Role | null>;
  public abstract getRoles(
    roleIds: string[],
    options?: PermissionQueryOptions
  ): Promise<Map<string, Role>>;
  public abstract getPermission(
    permissionId: string
  ): Promise<Permission | null>;
  public abstract invalidateUser(userId: string | 'all'): Promise<void>;
  public abstract shutdown(): Promise<void>;

  /**
   * Default implementation of hasPermission using getUserPermissions
   */
  public async hasPermission(
    userId: string,
    permission: string,
    options?: PermissionQueryOptions
  ): Promise<boolean> {
    const startTime = process.hrtime.bigint();

    try {
      const permissions = await this.getUserPermissions(userId, options);
      const result = permissions.has(permission);

      this.trackQuery(startTime, true);
      return result;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Default implementation of getBatchUserPermissions
   */
  public async getBatchUserPermissions(
    userIds: string[],
    options?: PermissionQueryOptions
  ): Promise<Map<string, Set<string>>> {
    const startTime = process.hrtime.bigint();
    const results = new Map<string, Set<string>>();

    try {
      // Simple implementation - could be optimized in subclasses
      const promises = userIds.map(async (userId) => {
        const permissions = await this.getUserPermissions(userId, options);
        return { userId, permissions };
      });

      const results_array = await Promise.all(promises);

      for (const { userId, permissions } of results_array) {
        results.set(userId, permissions);
      }

      this.trackQuery(startTime, true);
      return results;
    } catch (error) {
      this.trackQuery(startTime, false, error as Error);
      throw error;
    }
  }

  /**
   * Get source statistics
   */
  public getStats(): PermissionSourceStats {
    return { ...this.stats };
  }

  /**
   * Get source health status
   */
  public getHealthStatus(): {
    healthy: boolean;
    lastError?: string;
    uptime: number;
  } {
    return {
      healthy: !this.lastError || Date.now() - this.stats.lastQuery < 60000, // Healthy if no recent errors
      lastError: this.lastError?.message,
      uptime: Date.now() - this.startTime,
    };
  }

  /**
   * Track query performance and update statistics
   *
   * @param startTime - Query start time
   * @param success - Whether query was successful
   * @param error - Error object if query failed
   */
  protected trackQuery(
    startTime: bigint,
    success: boolean,
    error?: Error
  ): void {
    const duration = Number(process.hrtime.bigint() - startTime) / 1000; // microseconds

    this.stats.totalQueries++;
    this.stats.lastQuery = Date.now();

    if (success) {
      // Update average query time
      const currentAvg = this.stats.averageQueryTime;
      this.stats.averageQueryTime =
        currentAvg > 0 ? (currentAvg + duration) / 2 : duration;
    } else {
      this.stats.errors++;
      this.lastError = error;
      console.error(`❌ Permission source error [${this.sourceName}]:`, error);
    }
  }

  /**
   * Track cache hit
   */
  protected trackCacheHit(): void {
    this.stats.cacheHits++;
  }

  /**
   * Track cache miss
   */
  protected trackCacheMiss(): void {
    this.stats.cacheMisses++;
  }

  /**
   * Get cache hit rate as percentage
   */
  protected getCacheHitRate(): number {
    const total = this.stats.cacheHits + this.stats.cacheMisses;
    return total > 0 ? (this.stats.cacheHits / total) * 100 : 0;
  }

  /**
   * Initialize statistics
   */
  private initializeStats(): PermissionSourceStats {
    return {
      totalQueries: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageQueryTime: 0,
      errors: 0,
      lastQuery: 0,
    };
  }

  /**
   * Log source activity
   *
   * @param message - Log message
   * @param data - Additional data to log
   */
  protected log(message: string, data?: Record<string, unknown>): void {
    if (process.env.NODE_ENV === 'development') {
      console.debug(`🔍 [${this.sourceName}] ${message}`, data || '');
    }
  }

  /**
   * Create standardized error
   *
   * @param message - Error message
   * @param code - Error code
   * @param details - Additional error details
   * @returns Error object
   */
  protected createError(
    message: string,
    code: string,
    details?: Record<string, unknown>
  ): Error {
    const error = new Error(`[${this.sourceName}] ${message}`);
    (error as unknown as Record<string, unknown>).code = code;
    (error as unknown as Record<string, unknown>).source = this.sourceName;
    (error as unknown as Record<string, unknown>).details = details;
    return error;
  }
}
