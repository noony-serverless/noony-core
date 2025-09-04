/**
 * Wildcard Permission Resolver
 *
 * Advanced wildcard pattern matching permission resolver for the Guard System
 * Showcase. Supports glob-style pattern matching with '*' wildcards, hierarchical
 * permissions, and intelligent caching for optimal performance in complex
 * permission scenarios.
 *
 * Features:
 * - Glob-style wildcard pattern matching (* and **)
 * - Hierarchical permission inheritance
 * - Pattern caching for performance optimization
 * - Support for complex permission hierarchies
 * - Comprehensive pattern matching statistics
 *
 * @module WildcardPermissionResolver
 * @version 1.0.0
 */

import {
  PermissionResolver,
  PermissionResolverType,
} from '@noony-serverless/core';
import { PermissionSource } from '../permission-source';
import {
  UserContext,
  PermissionCheckRequest,
  PermissionCheckResult,
} from '@/types/auth.types';

/**
 * Pattern matching cache entry
 */
interface PatternCacheEntry {
  /** Compiled regex for pattern matching */
  regex: RegExp;
  /** Original pattern */
  pattern: string;
  /** Pattern matching statistics */
  stats: {
    matches: number;
    misses: number;
    lastUsed: number;
  };
}

/**
 * Wildcard resolver statistics
 */
export interface WildcardResolverStats {
  /** Total permission checks performed */
  totalChecks: number;

  /** Successful (allowed) permission checks */
  allowedChecks: number;

  /** Failed (denied) permission checks */
  deniedChecks: number;

  /** Pattern cache hits */
  patternCacheHits: number;

  /** Pattern cache misses */
  patternCacheMisses: number;

  /** Permission source cache hits */
  sourceCacheHits: number;

  /** Permission source cache misses */
  sourceCacheMisses: number;

  /** Average resolution time in microseconds */
  averageResolutionTimeUs: number;

  /** Average pattern matching time in microseconds */
  averagePatternMatchTimeUs: number;

  /** Number of patterns evaluated per check */
  averagePatternsEvaluated: number;

  /** Permission set load failures */
  loadFailures: number;

  /** Last check timestamp */
  lastCheck: number;
}

/**
 * Wildcard Permission Resolver Implementation
 *
 * Provides sophisticated wildcard pattern matching for permissions with:
 * - Support for * (single level) and ** (multi level) wildcards
 * - Hierarchical permission inheritance
 * - Intelligent pattern caching and optimization
 * - Comprehensive performance monitoring
 */
export class WildcardPermissionResolver
  implements PermissionResolver<string[]>
{
  private readonly permissionSource: PermissionSource;
  private readonly stats: WildcardResolverStats;
  private readonly patternCache = new Map<string, PatternCacheEntry>();
  private readonly maxPatternCacheSize = 1000;

  constructor(permissionSource: PermissionSource) {
    this.permissionSource = permissionSource;
    this.stats = this.initializeStats();

    console.log(
      '🎯 Wildcard Permission Resolver initialized (pattern matching)'
    );
  }

  /**
   * Get resolver type identifier
   */
  public getType(): PermissionResolverType {
    return PermissionResolverType.WILDCARD;
  }

  /**
   * Check if user permissions satisfy requirement using wildcard matching
   *
   * @param userPermissions - Set of user permissions
   * @param requirement - Array of required permissions with wildcards (OR logic)
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

    // Check each requirement
    for (const req of requirement) {
      const { matched } = this.matchSingleRequirementSync(userPermissions, req);
      if (matched) {
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
      timeComplexity: 'O(n) where n is number of permissions',
      memoryUsage: 'medium' as const,
      cacheUtilization: 'high' as const,
      recommendedFor: [
        'Hierarchical permission models',
        'Dynamic permission structures',
        'Resource-based permissions',
        'Role-based access control',
        'Multi-tenant applications',
      ],
    };
  }

  /**
   * Get human-readable resolver name
   */
  public getName(): string {
    return 'Wildcard Permission Resolver (Pattern Matching)';
  }

  /**
   * Check if user has required permission using wildcard pattern matching
   *
   * @param userId - User ID to check permissions for
   * @param requirement - Permission requirement (single string or array)
   * @param context - Additional context for permission resolution
   * @returns Promise resolving to permission check result
   */
  public async checkPermission(
    userId: string,
    requirement: string | string[],
    context: Record<string, unknown> = {}
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();

    try {
      this.stats.totalChecks++;
      this.stats.lastCheck = Date.now();

      // Normalize requirement to array format
      const requirementArray = Array.isArray(requirement)
        ? requirement
        : [requirement];

      if (requirementArray.length === 0) {
        throw new Error('Empty permission requirement');
      }

      // Load user permissions with wildcard expansion
      const userPermissions = await this.loadUserPermissions(userId);

      // Perform wildcard matching
      const matchResult = await this.performWildcardMatching(
        userPermissions,
        requirementArray,
        startTime
      );

      // Track result statistics
      if (matchResult.allowed) {
        this.stats.allowedChecks++;
      } else {
        this.stats.deniedChecks++;
      }

      // Update performance statistics
      const resolutionTime = this.updatePerformanceStats(
        startTime,
        matchResult.patternsEvaluated
      );

      // Create comprehensive result
      const result: PermissionCheckResult = {
        allowed: matchResult.allowed,
        resolverType: PermissionResolverType.WILDCARD,
        resolutionTimeUs: resolutionTime,
        cached: matchResult.cached,
        reason: matchResult.allowed
          ? undefined
          : this.generateDenialReason(requirementArray, matchResult),
        matchedPermissions: matchResult.matchedPermissions,
        metadata: {
          cacheKey: `wildcard:${userId}:${this.hashRequirement(requirementArray)}`,
          permissionsEvaluated: matchResult.patternsEvaluated,
          userContextLoadTimeUs: matchResult.contextLoadTime,
          patternMatchTimeUs: matchResult.patternMatchTime,
          expandedPermissions: userPermissions.size,
          patterns: matchResult.patterns,
        },
      };

      this.logResolutionResult(userId, requirementArray, result);
      return result;
    } catch (error) {
      this.stats.loadFailures++;
      const errorTime = this.updatePerformanceStats(startTime, 0);

      console.error(`❌ Wildcard resolver error for user ${userId}:`, error);

      return {
        allowed: false,
        resolverType: PermissionResolverType.WILDCARD,
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
   * Load user permissions with wildcard expansion
   *
   * @param userId - User ID
   * @returns Promise resolving to expanded permission set
   */
  private async loadUserPermissions(userId: string): Promise<Set<string>> {
    const loadStart = process.hrtime.bigint();

    try {
      // Load permissions with wildcard expansion enabled
      const permissions = await this.permissionSource.getUserPermissions(
        userId,
        {
          includeRolePermissions: true,
          expandWildcards: true, // Essential for wildcard resolver
          maxCacheAge: 10 * 60 * 1000, // 10 minute cache tolerance
        }
      );

      const loadTime = Number(process.hrtime.bigint() - loadStart) / 1000;

      // Track cache performance based on load time (approximation)
      if (loadTime < 1000) {
        // < 1ms suggests cache hit
        this.stats.sourceCacheHits++;
      } else {
        this.stats.sourceCacheMisses++;
      }

      return permissions;
    } catch (error) {
      console.error(`❌ Failed to load permissions for user ${userId}:`, error);
      throw new Error(`Permission loading failed: ${(error as Error).message}`);
    }
  }

  /**
   * Perform wildcard pattern matching
   *
   * @param userPermissions - User's expanded permission set
   * @param requirements - Permission requirements to check
   * @param startTime - Check start time for performance tracking
   * @returns Match result with detailed metadata
   */
  private async performWildcardMatching(
    userPermissions: Set<string>,
    requirements: string[],
    startTime: bigint
  ): Promise<{
    allowed: boolean;
    cached: boolean;
    matchedPermissions: string[];
    patternsEvaluated: number;
    contextLoadTime: number;
    patternMatchTime: number;
    patterns: string[];
  }> {
    const patternMatchStart = process.hrtime.bigint();
    const matchedPermissions: string[] = [];
    const patterns: string[] = [];
    let patternsEvaluated = 0;

    // Check each requirement
    for (const requirement of requirements) {
      const { matched, matchingPermissions, evaluatedCount } =
        await this.matchSingleRequirement(userPermissions, requirement);

      if (matched) {
        matchedPermissions.push(...matchingPermissions);
        patterns.push(requirement);
      }

      patternsEvaluated += evaluatedCount;
    }

    const patternMatchTime =
      Number(process.hrtime.bigint() - patternMatchStart) / 1000;
    const contextLoadTime = Number(patternMatchStart - startTime) / 1000;

    // For wildcard resolver, user needs ALL requirements to pass (AND logic)
    const allowed =
      matchedPermissions.length > 0 &&
      requirements.every((req) => {
        const { matched } = this.matchSingleRequirementSync(
          userPermissions,
          req
        );
        return matched;
      });

    return {
      allowed,
      cached: false, // Wildcard matching is never cached at this level
      matchedPermissions: [...new Set(matchedPermissions)], // Remove duplicates
      patternsEvaluated,
      contextLoadTime,
      patternMatchTime,
      patterns,
    };
  }

  /**
   * Match a single permission requirement against user permissions
   *
   * @param userPermissions - User permission set
   * @param requirement - Single permission requirement
   * @returns Match result with metadata
   */
  private async matchSingleRequirement(
    userPermissions: Set<string>,
    requirement: string
  ): Promise<{
    matched: boolean;
    matchingPermissions: string[];
    evaluatedCount: number;
  }> {
    const matchingPermissions: string[] = [];
    let evaluatedCount = 0;

    // If requirement contains wildcards, use pattern matching
    if (this.containsWildcards(requirement)) {
      const pattern = this.getOrCreatePattern(requirement);

      for (const permission of userPermissions) {
        evaluatedCount++;
        if (pattern.regex.test(permission)) {
          matchingPermissions.push(permission);
          pattern.stats.matches++;
        } else {
          pattern.stats.misses++;
        }
      }

      pattern.stats.lastUsed = Date.now();
    } else {
      // Direct lookup for non-wildcard requirements
      evaluatedCount = 1;
      if (userPermissions.has(requirement)) {
        matchingPermissions.push(requirement);
      }
    }

    return {
      matched: matchingPermissions.length > 0,
      matchingPermissions,
      evaluatedCount,
    };
  }

  /**
   * Synchronous version of single requirement matching (for final validation)
   *
   * @param userPermissions - User permission set
   * @param requirement - Single permission requirement
   * @returns Match result
   */
  private matchSingleRequirementSync(
    userPermissions: Set<string>,
    requirement: string
  ): { matched: boolean; matchingPermissions: string[] } {
    const matchingPermissions: string[] = [];

    if (this.containsWildcards(requirement)) {
      const pattern = this.getOrCreatePattern(requirement);

      for (const permission of userPermissions) {
        if (pattern.regex.test(permission)) {
          matchingPermissions.push(permission);
        }
      }
    } else {
      if (userPermissions.has(requirement)) {
        matchingPermissions.push(requirement);
      }
    }

    return {
      matched: matchingPermissions.length > 0,
      matchingPermissions,
    };
  }

  // ============================================================================
  // PATTERN MATCHING UTILITIES
  // ============================================================================

  /**
   * Check if a requirement contains wildcard patterns
   *
   * @param requirement - Permission requirement
   * @returns True if requirement contains wildcards
   */
  private containsWildcards(requirement: string): boolean {
    return requirement.includes('*') || requirement.includes('?');
  }

  /**
   * Get or create compiled pattern for requirement
   *
   * @param requirement - Permission requirement with wildcards
   * @returns Compiled pattern cache entry
   */
  private getOrCreatePattern(requirement: string): PatternCacheEntry {
    let pattern = this.patternCache.get(requirement);

    if (pattern) {
      this.stats.patternCacheHits++;
      return pattern;
    }

    this.stats.patternCacheMisses++;

    // Create new pattern
    pattern = {
      regex: this.compileWildcardPattern(requirement),
      pattern: requirement,
      stats: {
        matches: 0,
        misses: 0,
        lastUsed: Date.now(),
      },
    };

    // Store in cache with size limit
    if (this.patternCache.size >= this.maxPatternCacheSize) {
      this.evictOldestPattern();
    }

    this.patternCache.set(requirement, pattern);
    return pattern;
  }

  /**
   * Compile wildcard pattern to regular expression
   *
   * @param pattern - Wildcard pattern
   * @returns Compiled regular expression
   */
  private compileWildcardPattern(pattern: string): RegExp {
    // Escape special regex characters except * and ?
    let regexPattern = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '__DOUBLE_STAR__') // Temporary placeholder
      .replace(/\*/g, '[^:]*') // * matches any characters except ':'
      .replace(/__DOUBLE_STAR__/g, '.*'); // ** matches any characters including ':'

    // Support for ? wildcard (single character)
    regexPattern = regexPattern.replace(/\?/g, '[^:]');

    // Anchor the pattern to match the entire string
    regexPattern = `^${regexPattern}$`;

    return new RegExp(regexPattern);
  }

  /**
   * Evict the least recently used pattern from cache
   */
  private evictOldestPattern(): void {
    let oldestKey: string | null = null;
    let oldestTime = Date.now();

    for (const [key, entry] of this.patternCache.entries()) {
      if (entry.stats.lastUsed < oldestTime) {
        oldestTime = entry.stats.lastUsed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.patternCache.delete(oldestKey);
    }
  }

  // ============================================================================
  // UTILITIES AND HELPERS
  // ============================================================================

  /**
   * Generate hash for requirement array (for caching)
   *
   * @param requirements - Permission requirements
   * @returns Hash string
   */
  private hashRequirement(requirements: string[]): string {
    return Buffer.from(requirements.sort().join('|'))
      .toString('base64')
      .substring(0, 8);
  }

  /**
   * Generate human-readable denial reason
   *
   * @param requirements - Permission requirements
   * @param matchResult - Match result metadata
   * @returns Formatted denial reason
   */
  private generateDenialReason(
    requirements: string[],
    matchResult: any
  ): string {
    const unmatched = requirements.filter((req) => {
      const { matched } = this.matchSingleRequirementSync(
        new Set(matchResult.matchedPermissions || []),
        req
      );
      return !matched;
    });

    if (unmatched.length === 1) {
      return `Permission denied: ${unmatched[0]}`;
    } else if (unmatched.length === requirements.length) {
      return `All permissions denied: ${requirements.join(', ')}`;
    } else {
      return `Partial permissions denied: ${unmatched.join(', ')}`;
    }
  }

  /**
   * Update performance statistics
   *
   * @param startTime - Operation start time
   * @param patternsEvaluated - Number of patterns evaluated
   * @returns Resolution time in microseconds
   */
  private updatePerformanceStats(
    startTime: bigint,
    patternsEvaluated: number
  ): number {
    const resolutionTime = Number(process.hrtime.bigint() - startTime) / 1000;

    // Update average resolution time
    if (this.stats.averageResolutionTimeUs === 0) {
      this.stats.averageResolutionTimeUs = resolutionTime;
    } else {
      this.stats.averageResolutionTimeUs =
        this.stats.averageResolutionTimeUs * 0.9 + resolutionTime * 0.1;
    }

    // Update average patterns evaluated
    if (this.stats.averagePatternsEvaluated === 0) {
      this.stats.averagePatternsEvaluated = patternsEvaluated;
    } else {
      this.stats.averagePatternsEvaluated =
        this.stats.averagePatternsEvaluated * 0.9 + patternsEvaluated * 0.1;
    }

    return resolutionTime;
  }

  /**
   * Log resolution result
   *
   * @param userId - User ID
   * @param requirements - Permission requirements
   * @param result - Check result
   */
  private logResolutionResult(
    userId: string,
    requirements: string[],
    result: PermissionCheckResult
  ): void {
    if (process.env.NODE_ENV === 'development') {
      const symbol = result.allowed ? '✅' : '❌';
      console.debug(
        `${symbol} Wildcard resolver [${userId}]: ${requirements.join(', ')} (${result.resolutionTimeUs.toFixed(1)}μs, ${result.metadata?.permissionsEvaluated} patterns)`
      );
    }

    // Log slow resolutions
    if (result.resolutionTimeUs > 50000) {
      // > 50ms
      console.warn(
        `🐌 Slow wildcard resolution: ${result.resolutionTimeUs.toFixed(1)}μs for ${requirements.join(', ')} (user: ${userId}, patterns: ${result.metadata?.permissionsEvaluated})`
      );
    }
  }

  /**
   * Initialize statistics
   */
  private initializeStats(): WildcardResolverStats {
    return {
      totalChecks: 0,
      allowedChecks: 0,
      deniedChecks: 0,
      patternCacheHits: 0,
      patternCacheMisses: 0,
      sourceCacheHits: 0,
      sourceCacheMisses: 0,
      averageResolutionTimeUs: 0,
      averagePatternMatchTimeUs: 0,
      averagePatternsEvaluated: 0,
      loadFailures: 0,
      lastCheck: 0,
    };
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get current resolver statistics
   */
  public getStats(): WildcardResolverStats {
    return { ...this.stats };
  }

  /**
   * Get pattern cache statistics
   */
  public getPatternCacheStats(): {
    size: number;
    maxSize: number;
    hitRate: number;
    topPatterns: Array<{ pattern: string; matches: number; misses: number }>;
  } {
    const total = this.stats.patternCacheHits + this.stats.patternCacheMisses;
    const hitRate = total > 0 ? (this.stats.patternCacheHits / total) * 100 : 0;

    const topPatterns = Array.from(this.patternCache.entries())
      .map(([pattern, entry]) => ({
        pattern,
        matches: entry.stats.matches,
        misses: entry.stats.misses,
      }))
      .sort((a, b) => b.matches + b.misses - (a.matches + a.misses))
      .slice(0, 10);

    return {
      size: this.patternCache.size,
      maxSize: this.maxPatternCacheSize,
      hitRate: Math.round(hitRate * 100) / 100,
      topPatterns,
    };
  }

  /**
   * Get performance summary
   */
  public getPerformanceSummary(): {
    type: string;
    totalChecks: number;
    successRate: number;
    cacheHitRate: number;
    averageLatency: string;
    averagePatternsEvaluated: number;
    patternCacheEfficiency: string;
  } {
    const successRate =
      this.stats.totalChecks > 0
        ? (this.stats.allowedChecks / this.stats.totalChecks) * 100
        : 0;

    const sourceTotal =
      this.stats.sourceCacheHits + this.stats.sourceCacheMisses;
    const sourceCacheHitRate =
      sourceTotal > 0 ? (this.stats.sourceCacheHits / sourceTotal) * 100 : 0;

    const patternTotal =
      this.stats.patternCacheHits + this.stats.patternCacheMisses;
    const patternCacheHitRate =
      patternTotal > 0 ? (this.stats.patternCacheHits / patternTotal) * 100 : 0;

    return {
      type: 'Wildcard (Pattern Matching)',
      totalChecks: this.stats.totalChecks,
      successRate: Math.round(successRate * 100) / 100,
      cacheHitRate: Math.round(sourceCacheHitRate * 100) / 100,
      averageLatency: `${this.stats.averageResolutionTimeUs.toFixed(1)}μs`,
      averagePatternsEvaluated:
        Math.round(this.stats.averagePatternsEvaluated * 100) / 100,
      patternCacheEfficiency: `${patternCacheHitRate.toFixed(1)}%`,
    };
  }

  /**
   * Clear pattern cache
   */
  public clearPatternCache(): void {
    this.patternCache.clear();
    console.log('🧹 Wildcard resolver pattern cache cleared');
  }

  /**
   * Reset resolver statistics
   */
  public resetStats(): void {
    Object.assign(this.stats, this.initializeStats());
    console.log('📊 Wildcard resolver statistics reset');
  }

  /**
   * Get health status
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
      }
    }

    // Check performance
    if (this.stats.averageResolutionTimeUs > 20000) {
      // > 20ms
      issues.push(
        `High average latency: ${this.stats.averageResolutionTimeUs.toFixed(1)}μs`
      );
      recommendations.push(
        'Consider optimizing wildcard patterns or increasing cache'
      );
    }

    // Check pattern cache efficiency
    const patternTotal =
      this.stats.patternCacheHits + this.stats.patternCacheMisses;
    if (patternTotal > 50) {
      const hitRate = (this.stats.patternCacheHits / patternTotal) * 100;
      if (hitRate < 60) {
        issues.push(`Low pattern cache hit rate: ${hitRate.toFixed(1)}%`);
        recommendations.push('Consider increasing pattern cache size');
      }
    }

    // Check patterns evaluated per request
    if (this.stats.averagePatternsEvaluated > 1000) {
      issues.push(
        `High pattern evaluation count: ${this.stats.averagePatternsEvaluated.toFixed(0)}`
      );
      recommendations.push(
        'Consider optimizing permission structure or using pre-expansion'
      );
    }

    return {
      healthy: issues.length === 0,
      issues,
      recommendations,
    };
  }
}
