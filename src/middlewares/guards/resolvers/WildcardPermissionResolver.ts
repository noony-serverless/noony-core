/**
 * Wildcard Permission Resolver
 *
 * Configurable permission resolver supporting hierarchical wildcard patterns
 * with two distinct strategies for optimal performance in different scenarios:
 *
 * 1. PRE_EXPANSION Strategy:
 *    - Expand wildcards at user context load time
 *    - Store expanded permissions in user context
 *    - Runtime: O(1) set membership checks (fastest)
 *    - Memory: Higher usage due to expanded permission sets
 *    - Best for: Production environments with predictable permission sets
 *
 * 2. ON_DEMAND Strategy:
 *    - Pattern matching at permission check time
 *    - Cache pattern matching results
 *    - Runtime: Pattern matching cost with caching benefits
 *    - Memory: Lower usage, only caches results
 *    - Best for: Development, dynamic permissions, memory-constrained environments
 *
 * Supported Patterns:
 * - 2 levels: "admin.users", "org.reports"
 * - 3 levels: "admin.users.create", "org.reports.view"
 * - Wildcards: "admin.*", "org.reports.*"
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
import { CacheAdapter, CacheKeyBuilder } from '../cache/CacheAdapter';
import { PermissionResolutionStrategy } from '../config/GuardConfiguration';

/**
 * Permission registry interface for wildcard expansion
 */
export interface PermissionRegistry {
  /**
   * Get all permissions matching a wildcard pattern
   *
   * @param wildcardPattern - Pattern like "admin.*"
   * @returns Array of concrete permissions matching the pattern
   */
  getMatchingPermissions(wildcardPattern: string): string[];

  /**
   * Get all available permissions in a category
   *
   * @param category - Permission category like "admin"
   * @returns Array of permissions in that category
   */
  getCategoryPermissions(category: string): string[];

  /**
   * Check if a permission exists in the registry
   */
  hasPermission(permission: string): boolean;
}

/**
 * Wildcard permission resolver with configurable resolution strategies
 */
export class WildcardPermissionResolver extends PermissionResolver<string[]> {
  private readonly strategy: PermissionResolutionStrategy;
  private readonly permissionRegistry: PermissionRegistry;
  private readonly cache: CacheAdapter;
  private readonly maxPatternDepth: number;

  // Performance tracking
  private checkCount = 0;
  private totalResolutionTimeUs = 0;
  private cacheHits = 0;
  private cacheMisses = 0;

  constructor(
    strategy: PermissionResolutionStrategy,
    permissionRegistry: PermissionRegistry,
    cache: CacheAdapter,
    maxPatternDepth: number = 3
  ) {
    super();
    this.strategy = strategy;
    this.permissionRegistry = permissionRegistry;
    this.cache = cache;
    this.maxPatternDepth = maxPatternDepth;

    if (maxPatternDepth < 2 || maxPatternDepth > 3) {
      throw new Error('Max pattern depth must be 2 or 3');
    }
  }

  /**
   * Check if user permissions satisfy wildcard patterns
   *
   * @param userPermissions - Set of user's permissions (may be pre-expanded)
   * @param wildcardPatterns - Array of wildcard patterns to check
   * @returns Promise resolving to true if user matches any pattern
   */
  async check(
    userPermissions: Set<string>,
    wildcardPatterns: string[]
  ): Promise<boolean> {
    const startTime = process.hrtime.bigint();

    try {
      // Validate inputs
      if (!userPermissions || userPermissions.size === 0) {
        return false;
      }

      if (!wildcardPatterns || wildcardPatterns.length === 0) {
        return false;
      }

      // Validate patterns
      for (const pattern of wildcardPatterns) {
        if (!this.isValidWildcardPattern(pattern)) {
          throw new Error(`Invalid wildcard pattern: ${pattern}`);
        }
      }

      // Route to appropriate strategy
      if (this.strategy === PermissionResolutionStrategy.PRE_EXPANSION) {
        return await this.checkPreExpanded(userPermissions, wildcardPatterns);
      } else {
        return await this.checkOnDemand(userPermissions, wildcardPatterns);
      }
    } finally {
      // Track performance metrics
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      this.checkCount++;
      this.totalResolutionTimeUs += resolutionTimeUs;
    }
  }

  /**
   * Pre-expansion strategy: O(1) set membership checks
   *
   * Assumes user permissions have been pre-expanded to include all
   * concrete permissions that match wildcard patterns in their roles.
   * This provides the fastest runtime performance.
   */
  private async checkPreExpanded(
    userPermissions: Set<string>,
    wildcardPatterns: string[]
  ): Promise<boolean> {
    // For pre-expanded permissions, we check both:
    // 1. Exact pattern matches (if user was granted the wildcard directly)
    // 2. Concrete permission matches (if user has specific permissions)

    for (const pattern of wildcardPatterns) {
      // Check if user has the wildcard permission directly
      if (userPermissions.has(pattern)) {
        return true;
      }

      // If it's a wildcard pattern, check for any matching concrete permissions
      if (pattern.includes('*')) {
        const concretePermissions =
          this.permissionRegistry.getMatchingPermissions(pattern);
        for (const concretePermission of concretePermissions) {
          if (userPermissions.has(concretePermission)) {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * On-demand strategy: Pattern matching with caching
   *
   * Performs pattern matching at runtime but caches results to avoid
   * repeated pattern matching for the same user/pattern combinations.
   */
  private async checkOnDemand(
    userPermissions: Set<string>,
    wildcardPatterns: string[]
  ): Promise<boolean> {
    // Create cache key for this specific check
    const userPermissionArray = Array.from(userPermissions).sort();
    const cacheKey = CacheKeyBuilder.wildcardPattern(
      wildcardPatterns,
      userPermissionArray
    );

    // Check cache first
    const cachedResult = await this.cache.get<boolean>(cacheKey);
    if (cachedResult !== null) {
      this.cacheHits++;
      return cachedResult;
    }

    this.cacheMisses++;

    // Perform pattern matching
    let result = false;

    for (const pattern of wildcardPatterns) {
      if (this.matchesAnyUserPermission(userPermissions, pattern)) {
        result = true;
        break; // Short-circuit on first match
      }
    }

    // Cache the result for 1 minute (configurable)
    await this.cache.set(cacheKey, result, 60 * 1000);

    return result;
  }

  /**
   * Check if any user permission matches the given pattern
   */
  private matchesAnyUserPermission(
    userPermissions: Set<string>,
    pattern: string
  ): boolean {
    // Direct exact match
    if (userPermissions.has(pattern)) {
      return true;
    }

    // If not a wildcard pattern, no further matching needed
    if (!pattern.includes('*')) {
      return false;
    }

    // Pattern matching for wildcard
    for (const userPermission of userPermissions) {
      if (PermissionUtils.matchesWildcard(userPermission, pattern)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Expand wildcard patterns to concrete permissions
   *
   * Used by the user context service when pre-expansion strategy is enabled.
   * Converts wildcard patterns to all matching concrete permissions.
   *
   * @param patterns - Array of wildcard patterns
   * @returns Set of concrete permissions
   */
  async expandWildcardPatterns(patterns: string[]): Promise<Set<string>> {
    const expandedPermissions = new Set<string>();

    for (const pattern of patterns) {
      if (!this.isValidWildcardPattern(pattern)) {
        throw new Error(`Invalid wildcard pattern: ${pattern}`);
      }

      if (pattern.includes('*')) {
        // Expand wildcard to concrete permissions
        const concretePermissions =
          this.permissionRegistry.getMatchingPermissions(pattern);
        concretePermissions.forEach((permission) =>
          expandedPermissions.add(permission)
        );
      } else {
        // Add concrete permission as-is
        expandedPermissions.add(pattern);
      }
    }

    return expandedPermissions;
  }

  /**
   * Check permissions with detailed result information
   */
  async checkWithResult(
    userPermissions: Set<string>,
    wildcardPatterns: string[]
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();
    const cached = false;
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

      if (!wildcardPatterns || wildcardPatterns.length === 0) {
        return {
          allowed: false,
          resolverType: this.getType(),
          resolutionTimeUs: 0,
          cached: false,
          reason: 'No patterns specified',
        };
      }

      // Find all matching patterns/permissions
      for (const pattern of wildcardPatterns) {
        if (!this.isValidWildcardPattern(pattern)) {
          throw new Error(`Invalid wildcard pattern: ${pattern}`);
        }

        if (this.strategy === PermissionResolutionStrategy.PRE_EXPANSION) {
          // Check pre-expanded permissions
          if (userPermissions.has(pattern)) {
            matchedPermissions.push(pattern);
          } else if (pattern.includes('*')) {
            const concretePermissions =
              this.permissionRegistry.getMatchingPermissions(pattern);
            for (const concretePermission of concretePermissions) {
              if (userPermissions.has(concretePermission)) {
                matchedPermissions.push(concretePermission);
              }
            }
          }
        } else {
          // On-demand pattern matching
          if (this.matchesAnyUserPermission(userPermissions, pattern)) {
            matchedPermissions.push(pattern);
          }
        }
      }

      const allowed = matchedPermissions.length > 0;
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      return {
        allowed,
        resolverType: this.getType(),
        resolutionTimeUs,
        cached,
        reason: allowed
          ? undefined
          : `No matching patterns: ${wildcardPatterns.join(', ')}`,
        matchedPermissions: allowed ? matchedPermissions : undefined,
      };
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      return {
        allowed: false,
        resolverType: this.getType(),
        resolutionTimeUs,
        cached,
        reason: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Validate wildcard pattern format
   */
  private isValidWildcardPattern(pattern: string): boolean {
    if (!pattern || typeof pattern !== 'string') {
      return false;
    }

    // Check basic permission format first
    if (!PermissionUtils.isValidPermission(pattern)) {
      return false;
    }

    // Count depth levels
    const parts = pattern.split('.');
    if (parts.length < 2 || parts.length > this.maxPatternDepth) {
      return false;
    }

    // If contains wildcard, it should be at the end
    if (pattern.includes('*')) {
      if (
        !pattern.endsWith('*') ||
        pattern.indexOf('*') !== pattern.length - 1
      ) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get resolver type for identification
   */
  getType(): PermissionResolverType {
    return PermissionResolverType.WILDCARD;
  }

  /**
   * Get performance characteristics for monitoring
   */
  getPerformanceCharacteristics(): PerformanceCharacteristics {
    const isPreExpansion =
      this.strategy === PermissionResolutionStrategy.PRE_EXPANSION;

    return {
      timeComplexity: isPreExpansion
        ? 'O(1) per pattern'
        : 'O(n*m) with caching',
      memoryUsage: isPreExpansion ? 'high' : 'medium',
      cacheUtilization: isPreExpansion ? 'none' : 'high',
      recommendedFor: isPreExpansion
        ? [
            'Production environments',
            'Predictable permission sets',
            'Maximum performance',
          ]
        : [
            'Development environments',
            'Dynamic permissions',
            'Memory-constrained scenarios',
          ],
    };
  }

  /**
   * Get performance statistics
   */
  getStats(): {
    strategy: PermissionResolutionStrategy;
    checkCount: number;
    averageResolutionTimeUs: number;
    totalResolutionTimeUs: number;
    cacheHitRate: number;
    cacheHits: number;
    cacheMisses: number;
  } {
    const totalCacheRequests = this.cacheHits + this.cacheMisses;

    return {
      strategy: this.strategy,
      checkCount: this.checkCount,
      averageResolutionTimeUs:
        this.checkCount > 0 ? this.totalResolutionTimeUs / this.checkCount : 0,
      totalResolutionTimeUs: this.totalResolutionTimeUs,
      cacheHitRate:
        totalCacheRequests > 0
          ? (this.cacheHits / totalCacheRequests) * 100
          : 0,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
    };
  }

  /**
   * Reset performance statistics
   */
  resetStats(): void {
    this.checkCount = 0;
    this.totalResolutionTimeUs = 0;
    this.cacheHits = 0;
    this.cacheMisses = 0;
  }

  /**
   * Get resolver name for debugging
   */
  getName(): string {
    return `WildcardPermissionResolver(${this.strategy})`;
  }

  /**
   * Check if this resolver can handle the given requirement type
   */
  canHandle(requirement: any): requirement is string[] {
    return (
      Array.isArray(requirement) &&
      requirement.length > 0 &&
      requirement.every(
        (item) => typeof item === 'string' && this.isValidWildcardPattern(item)
      )
    );
  }
}
