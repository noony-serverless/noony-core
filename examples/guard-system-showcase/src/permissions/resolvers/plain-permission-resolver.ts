/**
 * Plain Permission Resolver
 *
 * High-performance O(1) permission resolution implementation for the Guard
 * System Showcase. Uses direct Set lookup for exact permission matching,
 * providing the fastest possible permission checks at the cost of requiring
 * exact permission matches.
 *
 * Features:
 * - O(1) permission lookup performance
 * - Exact string matching only
 * - Optimized for high-throughput scenarios
 * - Minimal memory overhead
 * - Comprehensive performance monitoring
 *
 * @module PlainPermissionResolver
 * @version 1.0.0
 */

import {
  PermissionResolver,
  PermissionResolverType,
} from '@noony-serverless/core';
import { PermissionSource } from '../permission-source';
import { PermissionCheckResult } from '@/types/auth.types';

/**
 * Plain resolver statistics for monitoring
 */
export interface PlainResolverStats {
  /** Total permission checks performed */
  totalChecks: number;

  /** Successful (allowed) permission checks */
  allowedChecks: number;

  /** Failed (denied) permission checks */
  deniedChecks: number;

  /** Cache hits from permission source */
  cacheHits: number;

  /** Cache misses requiring data source access */
  cacheMisses: number;

  /** Average resolution time in microseconds */
  averageResolutionTimeUs: number;

  /** Permission set load failures */
  loadFailures: number;

  /** Last check timestamp */
  lastCheck: number;

  /** Performance percentiles (P50, P95, P99) */
  performancePercentiles: {
    p50: number;
    p95: number;
    p99: number;
  };
}

/**
 * Plain Permission Resolver Implementation
 *
 * Provides the fastest possible permission resolution using direct Set.has()
 * lookups. This resolver is ideal for scenarios where:
 * - All permissions are explicitly defined
 * - No wildcard or pattern matching is needed
 * - Maximum performance is required
 * - Permission sets are reasonably sized
 */
export class PlainPermissionResolver implements PermissionResolver<string[]> {
  private readonly permissionSource: PermissionSource;
  private readonly stats: PlainResolverStats;
  private readonly performanceSamples: number[] = [];
  private readonly maxSamples = 1000; // Keep last 1000 samples for percentiles

  constructor(permissionSource: PermissionSource) {
    this.permissionSource = permissionSource;
    this.stats = this.initializeStats();

    console.log(
      '⚡ Plain Permission Resolver initialized (O(1) exact matching)'
    );
  }

  /**
   * Get resolver type identifier
   */
  public getType(): PermissionResolverType {
    return PermissionResolverType.PLAIN;
  }

  /**
   * Check if user permissions satisfy requirement using exact matching
   *
   * @param userPermissions - Set of user permissions
   * @param requirement - Array of required permissions (OR logic)
   * @returns Promise resolving to true if any required permission matches
   */
  public async check(
    userPermissions: Set<string>,
    requirement: string[]
  ): Promise<boolean> {
    // Validate requirement
    if (!Array.isArray(requirement) || requirement.length === 0) {
      return false;
    }

    // Check if user has any of the required permissions (OR logic)
    for (const requiredPermission of requirement) {
      if (userPermissions.has(requiredPermission)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get performance characteristics for this resolver
   */
  public getPerformanceCharacteristics(): any {
    return {
      timeComplexity: 'O(1) per permission check',
      memoryUsage: 'low' as const,
      cacheUtilization: 'none' as const,
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
   * Get human-readable resolver name
   */
  public getName(): string {
    return 'Plain Permission Resolver (O(1) Exact Match)';
  }

  /**
   * Check if user has required permission using exact matching
   *
   * @param userId - User ID to check permissions for
   * @param requirement - Permission requirement (must be single string for plain resolver)
   * @param context - Additional context (unused in plain resolver)
   * @returns Promise resolving to permission check result
   */
  public async checkPermission(
    userId: string,
    requirement: string | string[],
    _context: Record<string, unknown> = {}
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();

    try {
      this.stats.totalChecks++;
      this.stats.lastCheck = Date.now();

      // Validate requirement format for plain resolver
      const permissionToCheck =
        this.validateAndNormalizeRequirement(requirement);

      // Load user permissions from source
      const userPermissions = await this.loadUserPermissions(userId);

      // Perform O(1) exact match lookup
      const hasPermission = userPermissions.has(permissionToCheck);

      // Track result
      if (hasPermission) {
        this.stats.allowedChecks++;
      } else {
        this.stats.deniedChecks++;
      }

      // Calculate resolution time and update statistics
      const resolutionTime = this.updatePerformanceStats(startTime);

      // Create result
      const result: PermissionCheckResult = {
        allowed: hasPermission,
        resolverType: PermissionResolverType.PLAIN,
        resolutionTimeUs: resolutionTime,
        cached: false, // Will be updated based on source cache status
        reason: hasPermission
          ? undefined
          : `Permission denied: ${permissionToCheck}`,
        matchedPermissions: hasPermission ? [permissionToCheck] : undefined,
        metadata: {
          cacheKey: `plain:${userId}:${permissionToCheck}`,
          permissionsEvaluated: 1, // Always 1 for plain resolver
          userContextLoadTimeUs: resolutionTime * 0.8, // Approximate - most time is context loading
        },
      };

      this.logResolutionResult(userId, permissionToCheck, result);
      return result;
    } catch (error) {
      this.stats.loadFailures++;
      const errorTime = this.updatePerformanceStats(startTime);

      console.error(`❌ Plain resolver error for user ${userId}:`, error);

      return {
        allowed: false,
        resolverType: PermissionResolverType.PLAIN,
        resolutionTimeUs: errorTime,
        cached: false,
        reason: `Resolution error: ${(error as Error).message}`,
        metadata: {
          error: (error as Error).message,
        },
      };
    }
  }

  /**
   * Validate and normalize permission requirement for plain resolver
   *
   * @param requirement - Permission requirement
   * @returns Normalized permission string
   * @throws Error if requirement format is invalid for plain resolver
   */
  private validateAndNormalizeRequirement(
    requirement: string | string[]
  ): string {
    if (Array.isArray(requirement)) {
      if (requirement.length === 0) {
        throw new Error('Empty permission requirement array');
      }
      if (requirement.length > 1) {
        throw new Error(
          'Plain resolver only supports single permission checks. Use array resolver for multiple permissions.'
        );
      }
      return requirement[0];
    }

    if (typeof requirement !== 'string' || requirement.trim().length === 0) {
      throw new Error('Permission requirement must be a non-empty string');
    }

    const normalized = requirement.trim();

    // Check for patterns that suggest wrong resolver usage
    if (
      normalized.includes('*') ||
      normalized.includes('|') ||
      normalized.includes('&')
    ) {
      console.warn(
        `⚠️ Plain resolver received pattern '${normalized}' - consider using WildcardResolver or ExpressionResolver`
      );
    }

    return normalized;
  }

  /**
   * Load user permissions from permission source
   *
   * @param userId - User ID
   * @returns Promise resolving to user permission set
   */
  private async loadUserPermissions(userId: string): Promise<Set<string>> {
    try {
      // For plain resolver, we don't need wildcard expansion
      const permissions = await this.permissionSource.getUserPermissions(
        userId,
        {
          includeRolePermissions: true,
          expandWildcards: false, // Plain resolver uses exact matching only
          maxCacheAge: 5 * 60 * 1000, // 5 minute cache tolerance
        }
      );

      // Track cache performance (approximation based on source stats)
      const sourceStats = this.permissionSource.getStats();
      if (sourceStats.lastQuery === Date.now()) {
        // Recent query, likely cache hit
        this.stats.cacheHits++;
      } else {
        this.stats.cacheMisses++;
      }

      return permissions;
    } catch (error) {
      console.error(`❌ Failed to load permissions for user ${userId}:`, error);
      throw new Error(`Permission loading failed: ${(error as Error).message}`);
    }
  }

  /**
   * Update performance statistics
   *
   * @param startTime - Operation start time
   * @returns Resolution time in microseconds
   */
  private updatePerformanceStats(startTime: bigint): number {
    const resolutionTime = Number(process.hrtime.bigint() - startTime) / 1000;

    // Update average resolution time using exponential moving average
    if (this.stats.averageResolutionTimeUs === 0) {
      this.stats.averageResolutionTimeUs = resolutionTime;
    } else {
      this.stats.averageResolutionTimeUs =
        this.stats.averageResolutionTimeUs * 0.9 + resolutionTime * 0.1;
    }

    // Store sample for percentile calculation
    this.performanceSamples.push(resolutionTime);
    if (this.performanceSamples.length > this.maxSamples) {
      this.performanceSamples.shift(); // Remove oldest sample
    }

    // Update percentiles every 100 samples
    if (this.performanceSamples.length % 100 === 0) {
      this.updatePerformancePercentiles();
    }

    return resolutionTime;
  }

  /**
   * Update performance percentiles based on recent samples
   */
  private updatePerformancePercentiles(): void {
    if (this.performanceSamples.length === 0) {
      return;
    }

    const sorted = [...this.performanceSamples].sort((a, b) => a - b);
    const length = sorted.length;

    this.stats.performancePercentiles = {
      p50: sorted[Math.floor(length * 0.5)],
      p95: sorted[Math.floor(length * 0.95)],
      p99: sorted[Math.floor(length * 0.99)],
    };
  }

  /**
   * Log resolution result for debugging and monitoring
   *
   * @param userId - User ID
   * @param permission - Permission checked
   * @param result - Check result
   */
  private logResolutionResult(
    userId: string,
    permission: string,
    result: PermissionCheckResult
  ): void {
    if (process.env.NODE_ENV === 'development') {
      const symbol = result.allowed ? '✅' : '❌';
      console.debug(
        `${symbol} Plain resolver [${userId}]: ${permission} (${result.resolutionTimeUs.toFixed(1)}μs)`
      );
    }

    // Log slow resolutions in production
    if (result.resolutionTimeUs > 10000) {
      // > 10ms
      console.warn(
        `🐌 Slow plain resolution: ${result.resolutionTimeUs.toFixed(1)}μs for ${permission} (user: ${userId})`
      );
    }
  }

  /**
   * Initialize statistics object
   */
  private initializeStats(): PlainResolverStats {
    return {
      totalChecks: 0,
      allowedChecks: 0,
      deniedChecks: 0,
      cacheHits: 0,
      cacheMisses: 0,
      averageResolutionTimeUs: 0,
      loadFailures: 0,
      lastCheck: 0,
      performancePercentiles: {
        p50: 0,
        p95: 0,
        p99: 0,
      },
    };
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get current resolver statistics
   */
  public getStats(): PlainResolverStats {
    // Update percentiles before returning stats
    if (this.performanceSamples.length > 0) {
      this.updatePerformancePercentiles();
    }

    return { ...this.stats };
  }

  /**
   * Get resolver performance summary
   */
  public getPerformanceSummary(): {
    type: string;
    totalChecks: number;
    successRate: number;
    cacheHitRate: number;
    averageLatency: string;
    p95Latency: string;
    p99Latency: string;
    checksPerSecond?: number;
  } {
    const successRate =
      this.stats.totalChecks > 0
        ? (this.stats.allowedChecks / this.stats.totalChecks) * 100
        : 0;

    const cacheTotal = this.stats.cacheHits + this.stats.cacheMisses;
    const cacheHitRate =
      cacheTotal > 0 ? (this.stats.cacheHits / cacheTotal) * 100 : 0;

    // Calculate checks per second based on recent activity
    const recentWindowMs = 60 * 1000; // 1 minute
    const checksPerSecond =
      this.stats.lastCheck > 0 &&
      Date.now() - this.stats.lastCheck < recentWindowMs
        ? Math.round(
            this.stats.totalChecks /
              ((Date.now() - this.stats.lastCheck) / 1000)
          )
        : undefined;

    return {
      type: 'Plain (O(1) Exact Match)',
      totalChecks: this.stats.totalChecks,
      successRate: Math.round(successRate * 100) / 100,
      cacheHitRate: Math.round(cacheHitRate * 100) / 100,
      averageLatency: `${this.stats.averageResolutionTimeUs.toFixed(1)}μs`,
      p95Latency: `${this.stats.performancePercentiles.p95.toFixed(1)}μs`,
      p99Latency: `${this.stats.performancePercentiles.p99.toFixed(1)}μs`,
      checksPerSecond,
    };
  }

  /**
   * Reset resolver statistics
   */
  public resetStats(): void {
    Object.assign(this.stats, this.initializeStats());
    this.performanceSamples.length = 0;
    console.log('📊 Plain resolver statistics reset');
  }

  /**
   * Check resolver health status
   */
  public getHealthStatus(): {
    healthy: boolean;
    issues: string[];
    recommendations: string[];
  } {
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Check error rate
    if (this.stats.totalChecks > 100) {
      const errorRate =
        (this.stats.loadFailures / this.stats.totalChecks) * 100;
      if (errorRate > 5) {
        issues.push(`High error rate: ${errorRate.toFixed(1)}%`);
        recommendations.push('Check permission source connectivity');
      }
    }

    // Check performance
    if (this.stats.averageResolutionTimeUs > 5000) {
      // > 5ms
      issues.push(
        `High average latency: ${this.stats.averageResolutionTimeUs.toFixed(1)}μs`
      );
      recommendations.push('Consider checking permission source performance');
    }

    // Check cache hit rate
    const cacheTotal = this.stats.cacheHits + this.stats.cacheMisses;
    if (cacheTotal > 50) {
      const hitRate = (this.stats.cacheHits / cacheTotal) * 100;
      if (hitRate < 70) {
        issues.push(`Low cache hit rate: ${hitRate.toFixed(1)}%`);
        recommendations.push(
          'Consider increasing cache TTL or pre-warming cache'
        );
      }
    }

    return {
      healthy: issues.length === 0,
      issues,
      recommendations,
    };
  }

  /**
   * Get optimal usage recommendations
   */
  public getUsageRecommendations(): string[] {
    const recommendations = [
      'Use Plain resolver for exact permission matching scenarios',
      'Ensure all required permissions are explicitly granted (no wildcards)',
      'Consider pre-warming permission cache for frequently accessed users',
      'Monitor cache hit rates and adjust TTL settings accordingly',
      'Use batch permission loading for multiple users when possible',
    ];

    // Add specific recommendations based on current statistics
    const stats = this.getPerformanceSummary();

    if (stats.cacheHitRate < 80) {
      recommendations.push(
        'Consider increasing permission cache TTL to improve hit rate'
      );
    }

    if (this.stats.averageResolutionTimeUs > 1000) {
      recommendations.push(
        'Consider optimizing permission source queries or increasing cache'
      );
    }

    if (this.stats.totalChecks > 10000) {
      recommendations.push(
        'High volume detected - consider implementing rate limiting or load balancing'
      );
    }

    return recommendations;
  }
}
