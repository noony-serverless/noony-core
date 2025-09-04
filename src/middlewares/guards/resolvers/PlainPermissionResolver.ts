/**
 * Plain Permission Resolver
 *
 * Fastest permission resolver using direct O(1) set membership checks.
 * Optimized for high-performance scenarios where sub-millisecond permission
 * checks are critical. No pattern matching or complex logic - just pure
 * set-based lookups for maximum speed.
 *
 * Use Cases:
 * - High-traffic API endpoints requiring maximum performance
 * - Simple permission models without wildcards or expressions
 * - Scenarios where all required permissions are known at compile time
 * - Serverless functions with strict latency requirements
 *
 * Performance Characteristics:
 * - Time Complexity: O(1) for permission lookup
 * - Space Complexity: O(n) where n is the number of user permissions
 * - Cache Utilization: None (no caching needed due to speed)
 * - Memory Footprint: Minimal (uses JavaScript Set)
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import {
  PermissionResolver,
  PermissionResolverType,
  PerformanceCharacteristics,
  PermissionCheckResult,
  PermissionUtils,
} from './PermissionResolver';

/**
 * Plain permission resolver for direct O(1) permission checks
 *
 * This resolver performs the simplest and fastest permission checks by
 * using JavaScript Set's has() method for O(1) membership testing.
 * It checks if the user has ANY of the required permissions (OR logic).
 */
export class PlainPermissionResolver extends PermissionResolver<string[]> {
  private checkCount = 0;
  private totalResolutionTimeUs = 0;

  /**
   * Check if user has any of the required permissions
   *
   * Uses OR logic: user needs only ONE of the required permissions
   * to pass the check. This is the most common permission pattern.
   *
   * @param userPermissions - Set of user's permissions for O(1) lookup
   * @param requiredPermissions - Array of required permissions (OR logic)
   * @returns Promise resolving to true if user has any required permission
   */
  async check(
    userPermissions: Set<string>,
    requiredPermissions: string[]
  ): Promise<boolean> {
    const startTime = process.hrtime.bigint();

    try {
      // Validate inputs
      if (!userPermissions || userPermissions.size === 0) {
        return false;
      }

      if (!requiredPermissions || requiredPermissions.length === 0) {
        return false; // No permissions required means access denied
      }

      // Validate permission format
      for (const permission of requiredPermissions) {
        if (!PermissionUtils.isValidPermission(permission)) {
          throw new Error(`Invalid permission format: ${permission}`);
        }
      }

      // O(1) set membership check for each required permission
      // Return true as soon as we find a match (short-circuit OR)
      for (const requiredPermission of requiredPermissions) {
        if (userPermissions.has(requiredPermission)) {
          return true;
        }
      }

      return false;
    } finally {
      // Track performance metrics
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000; // Convert to microseconds

      this.checkCount++;
      this.totalResolutionTimeUs += resolutionTimeUs;
    }
  }

  /**
   * Check permissions with detailed result information
   *
   * Provides additional metadata about the permission check for
   * debugging, monitoring, and audit purposes.
   *
   * @param userPermissions - Set of user's permissions
   * @param requiredPermissions - Array of required permissions
   * @returns Detailed permission check result
   */
  async checkWithResult(
    userPermissions: Set<string>,
    requiredPermissions: string[]
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();
    const matchedPermissions: string[] = [];

    try {
      // Validate inputs
      if (!userPermissions || userPermissions.size === 0) {
        return {
          allowed: false,
          resolverType: this.getType(),
          resolutionTimeUs: 0,
          cached: false,
          reason: 'User has no permissions',
        };
      }

      if (!requiredPermissions || requiredPermissions.length === 0) {
        return {
          allowed: false,
          resolverType: this.getType(),
          resolutionTimeUs: 0,
          cached: false,
          reason: 'No permissions specified',
        };
      }

      // Find all matching permissions (not just the first one)
      for (const requiredPermission of requiredPermissions) {
        if (!PermissionUtils.isValidPermission(requiredPermission)) {
          throw new Error(`Invalid permission format: ${requiredPermission}`);
        }

        if (userPermissions.has(requiredPermission)) {
          matchedPermissions.push(requiredPermission);
        }
      }

      const allowed = matchedPermissions.length > 0;
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      return {
        allowed,
        resolverType: this.getType(),
        resolutionTimeUs,
        cached: false, // Plain resolver doesn't use caching
        reason: allowed
          ? undefined
          : `Missing required permissions: ${requiredPermissions.join(', ')}`,
        matchedPermissions: allowed ? matchedPermissions : undefined,
      };
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      return {
        allowed: false,
        resolverType: this.getType(),
        resolutionTimeUs,
        cached: false,
        reason: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Check if user has ALL required permissions (AND logic)
   *
   * Alternative method for scenarios requiring ALL permissions
   * instead of ANY permission. Less commonly used but available
   * for completeness.
   *
   * @param userPermissions - Set of user's permissions
   * @param requiredPermissions - Array of ALL required permissions
   * @returns Promise resolving to true if user has ALL permissions
   */
  async checkAllRequired(
    userPermissions: Set<string>,
    requiredPermissions: string[]
  ): Promise<boolean> {
    const startTime = process.hrtime.bigint();

    try {
      // Validate inputs
      if (!userPermissions || userPermissions.size === 0) {
        return false;
      }

      if (!requiredPermissions || requiredPermissions.length === 0) {
        return true; // No permissions required means access allowed
      }

      // Check that user has ALL required permissions
      for (const requiredPermission of requiredPermissions) {
        if (!PermissionUtils.isValidPermission(requiredPermission)) {
          throw new Error(`Invalid permission format: ${requiredPermission}`);
        }

        if (!userPermissions.has(requiredPermission)) {
          return false; // Missing at least one required permission
        }
      }

      return true;
    } finally {
      // Track performance metrics
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      this.checkCount++;
      this.totalResolutionTimeUs += resolutionTimeUs;
    }
  }

  /**
   * Get resolver type for identification
   */
  getType(): PermissionResolverType {
    return PermissionResolverType.PLAIN;
  }

  /**
   * Get performance characteristics for monitoring
   */
  getPerformanceCharacteristics(): PerformanceCharacteristics {
    return {
      timeComplexity: 'O(1) per permission check',
      memoryUsage: 'low',
      cacheUtilization: 'none',
      recommendedFor: [
        'High-traffic API endpoints',
        'Sub-millisecond permission checks',
        'Simple permission models',
        'Serverless functions',
        'Performance-critical paths',
      ],
    };
  }

  /**
   * Get performance statistics for monitoring
   */
  getStats(): {
    checkCount: number;
    averageResolutionTimeUs: number;
    totalResolutionTimeUs: number;
  } {
    return {
      checkCount: this.checkCount,
      averageResolutionTimeUs:
        this.checkCount > 0 ? this.totalResolutionTimeUs / this.checkCount : 0,
      totalResolutionTimeUs: this.totalResolutionTimeUs,
    };
  }

  /**
   * Reset performance statistics
   */
  resetStats(): void {
    this.checkCount = 0;
    this.totalResolutionTimeUs = 0;
  }

  /**
   * Get resolver name for debugging
   */
  getName(): string {
    return 'PlainPermissionResolver';
  }

  /**
   * Check if this resolver can handle the given requirement type
   *
   * @param requirement - The requirement to check
   * @returns true if this resolver can handle the requirement
   */
  canHandle(requirement: any): requirement is string[] {
    return (
      Array.isArray(requirement) &&
      requirement.length > 0 &&
      requirement.every((item) => typeof item === 'string')
    );
  }
}
