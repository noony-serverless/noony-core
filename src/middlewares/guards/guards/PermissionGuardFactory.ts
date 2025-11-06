/**
 * Permission Guard Factory
 *
 * Factory for creating optimized permission guards tailored to specific endpoint requirements.
 * This factory generates specialized guards that use the most appropriate permission resolution
 * strategy based on the permission requirements, maximizing performance while maintaining security.
 *
 * Key Features:
 * - Automatic resolver selection based on requirement patterns
 * - Optimized guard generation for specific permission types
 * - Caching strategy optimization per guard type
 * - Performance monitoring and metrics collection
 * - Configuration-driven guard customization
 * - Built-in error handling and logging
 *
 * Guard Types:
 * - PlainPermissionGuard: For simple permission lists (fastest)
 * - WildcardPermissionGuard: For hierarchical wildcard patterns
 * - ExpressionPermissionGuard: For complex boolean expressions
 * - CompositePermissionGuard: For mixed permission requirements
 *
 * Performance Optimization:
 * - Pre-compiled permission validators
 * - Strategy-specific caching configurations
 * - Minimal overhead per request
 * - Smart cache key generation
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import { Service } from 'typedi';
import { Context } from '../../../core/core';
import { BaseMiddleware } from '../../../core/handler';
import { AuthenticationError, SecurityError } from '../../../core/errors';
import { CacheAdapter } from '../cache/CacheAdapter';
import { GuardConfiguration } from '../config/GuardConfiguration';
import {
  FastUserContextService,
  UserContext,
  PermissionCheckOptions,
} from '../services/FastUserContextService';
import {
  PermissionResolverType,
  PermissionCheckResult,
  PermissionExpression,
} from '../resolvers/PermissionResolver';

/**
 * Guard configuration for specific permission requirements
 */
export interface GuardConfig {
  requireAuth: boolean;
  permissions:
    | string
    | string[]
    | PermissionExpression
    | Record<string, unknown>; // Can be string[], wildcard patterns, or expressions
  resolverType?: PermissionResolverType;
  cacheResults: boolean;
  auditTrail: boolean;
  errorMessage?: string;
  allowPartialMatch?: boolean;
  requireAllPermissions?: boolean; // AND vs OR logic
}

/**
 * Permission guard result
 */
export interface PermissionGuardResult {
  allowed: boolean;
  user?: UserContext;
  checkResult: PermissionCheckResult;
  guardType: string;
  processingTimeUs: number;
}

/**
 * Abstract base class for all permission guards
 */
abstract class BasePermissionGuard implements BaseMiddleware {
  protected readonly config: GuardConfig;
  protected readonly userContextService: FastUserContextService;
  protected readonly guardConfig: GuardConfiguration;
  protected readonly cache: CacheAdapter;

  // Performance tracking
  protected checkCount = 0;
  protected successCount = 0;
  protected failureCount = 0;
  protected totalProcessingTimeUs = 0;

  constructor(
    config: GuardConfig,
    userContextService: FastUserContextService,
    guardConfig: GuardConfiguration,
    cache: CacheAdapter
  ) {
    this.config = config;
    this.userContextService = userContextService;
    this.guardConfig = guardConfig;
    this.cache = cache;
  }

  async before(context: Context): Promise<void> {
    const startTime = process.hrtime.bigint();
    this.checkCount++;

    try {
      // Check authentication requirement
      if (this.config.requireAuth) {
        const user = context.businessData.get('user') as UserContext;
        if (!user) {
          throw new AuthenticationError(
            'Authentication required for this endpoint'
          );
        }
      }

      // Perform permission check
      const result = await this.checkPermissions(context);

      if (!result.allowed) {
        this.failureCount++;
        throw new SecurityError(
          this.config.errorMessage ||
            `Access denied: ${result.checkResult.reason}`
        );
      }

      this.successCount++;

      // Store result in context for downstream use
      context.businessData.set('permissionGuardResult', result);

      // Log successful authorization if audit trail is enabled
      if (this.config.auditTrail) {
        this.logAuthorizationEvent('granted', result, context);
      }
    } catch (error) {
      this.failureCount++;

      // Log authorization failure
      if (this.config.auditTrail) {
        this.logAuthorizationEvent('denied', null, context, error);
      }

      throw error;
    } finally {
      const endTime = process.hrtime.bigint();
      this.totalProcessingTimeUs += Number(endTime - startTime) / 1000;
    }
  }

  /**
   * Abstract method for permission checking - implemented by subclasses
   */
  abstract checkPermissions(context: Context): Promise<PermissionGuardResult>;

  /**
   * Get performance statistics
   */
  getStats() {
    return {
      guardType: this.getGuardType(),
      checkCount: this.checkCount,
      successCount: this.successCount,
      failureCount: this.failureCount,
      successRate:
        this.checkCount > 0 ? (this.successCount / this.checkCount) * 100 : 100,
      averageProcessingTimeUs:
        this.checkCount > 0 ? this.totalProcessingTimeUs / this.checkCount : 0,
      totalProcessingTimeUs: this.totalProcessingTimeUs,
    };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.checkCount = 0;
    this.successCount = 0;
    this.failureCount = 0;
    this.totalProcessingTimeUs = 0;
  }

  /**
   * Get guard type name
   */
  abstract getGuardType(): string;

  /**
   * Log authorization event
   */
  private logAuthorizationEvent(
    result: 'granted' | 'denied',
    guardResult: PermissionGuardResult | null,
    context: Context,
    error?: any
  ): void {
    const emoji = result === 'granted' ? '✅' : '❌';
    const user = context.businessData.get('user') as UserContext;

    console.log(`${emoji} Authorization ${result}`, {
      guardType: this.getGuardType(),
      userId: user?.userId,
      permissions: this.config.permissions,
      processingTimeUs: guardResult?.processingTimeUs,
      reason:
        guardResult?.checkResult.reason ||
        (error instanceof Error ? error.message : 'Unknown'),
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
    });
  }
}

/**
 * Plain Permission Guard - For simple permission lists
 */
class PlainPermissionGuard extends BasePermissionGuard {
  async checkPermissions(context: Context): Promise<PermissionGuardResult> {
    const startTime = process.hrtime.bigint();
    const user = context.businessData.get('user') as UserContext;

    if (!user) {
      throw new AuthenticationError('User context required');
    }

    const permissions = this.config.permissions as string[];
    const options: PermissionCheckOptions = {
      resolverType: PermissionResolverType.PLAIN,
      useCache: this.config.cacheResults,
      auditTrail: this.config.auditTrail,
    };

    const checkResult = await this.userContextService.checkPermission(
      user.userId,
      permissions,
      options
    );

    const processingTimeUs = Number(process.hrtime.bigint() - startTime) / 1000;

    return {
      allowed: checkResult.allowed,
      user,
      checkResult,
      guardType: this.getGuardType(),
      processingTimeUs,
    };
  }

  getGuardType(): string {
    return 'PlainPermissionGuard';
  }
}

/**
 * Wildcard Permission Guard - For hierarchical wildcard patterns
 */
class WildcardPermissionGuard extends BasePermissionGuard {
  async checkPermissions(context: Context): Promise<PermissionGuardResult> {
    const startTime = process.hrtime.bigint();
    const user = context.businessData.get('user') as UserContext;

    if (!user) {
      throw new AuthenticationError('User context required');
    }

    const wildcardPatterns = this.config.permissions as string[];
    const options: PermissionCheckOptions = {
      resolverType: PermissionResolverType.WILDCARD,
      useCache: this.config.cacheResults,
      auditTrail: this.config.auditTrail,
    };

    const checkResult = await this.userContextService.checkPermission(
      user.userId,
      wildcardPatterns,
      options
    );

    const processingTimeUs = Number(process.hrtime.bigint() - startTime) / 1000;

    return {
      allowed: checkResult.allowed,
      user,
      checkResult,
      guardType: this.getGuardType(),
      processingTimeUs,
    };
  }

  getGuardType(): string {
    return 'WildcardPermissionGuard';
  }
}

/**
 * Expression Permission Guard - For complex boolean expressions
 */
class ExpressionPermissionGuard extends BasePermissionGuard {
  async checkPermissions(context: Context): Promise<PermissionGuardResult> {
    const startTime = process.hrtime.bigint();
    const user = context.businessData.get('user') as UserContext;

    if (!user) {
      throw new AuthenticationError('User context required');
    }

    const expression = this.config.permissions as PermissionExpression;
    const options: PermissionCheckOptions = {
      resolverType: PermissionResolverType.EXPRESSION,
      useCache: this.config.cacheResults,
      auditTrail: this.config.auditTrail,
    };

    const checkResult = await this.userContextService.checkPermission(
      user.userId,
      expression,
      options
    );

    const processingTimeUs = Number(process.hrtime.bigint() - startTime) / 1000;

    return {
      allowed: checkResult.allowed,
      user,
      checkResult,
      guardType: this.getGuardType(),
      processingTimeUs,
    };
  }

  getGuardType(): string {
    return 'ExpressionPermissionGuard';
  }
}

/**
 * Composite Permission Guard - For mixed permission requirements
 */
class CompositePermissionGuard extends BasePermissionGuard {
  private readonly subRequirements: Array<{
    permissions:
      | string
      | string[]
      | PermissionExpression
      | Record<string, unknown>;
    resolverType: PermissionResolverType;
    required: boolean;
  }>;

  constructor(
    config: GuardConfig,
    userContextService: FastUserContextService,
    guardConfig: GuardConfiguration,
    cache: CacheAdapter,
    subRequirements: Array<{
      permissions:
        | string
        | string[]
        | PermissionExpression
        | Record<string, unknown>;
      resolverType: PermissionResolverType;
      required: boolean;
    }>
  ) {
    super(config, userContextService, guardConfig, cache);
    this.subRequirements = subRequirements;
  }

  async checkPermissions(context: Context): Promise<PermissionGuardResult> {
    const startTime = process.hrtime.bigint();
    const user = context.businessData.get('user') as UserContext;

    if (!user) {
      throw new AuthenticationError('User context required');
    }

    const checkResults: PermissionCheckResult[] = [];
    let allRequiredPassed = true;
    let anyOptionalPassed = false;

    // Check all sub-requirements
    for (const subReq of this.subRequirements) {
      const options: PermissionCheckOptions = {
        resolverType: subReq.resolverType,
        useCache: this.config.cacheResults,
        auditTrail: this.config.auditTrail,
      };

      const result = await this.userContextService.checkPermission(
        user.userId,
        subReq.permissions,
        options
      );

      checkResults.push(result);

      if (subReq.required && !result.allowed) {
        allRequiredPassed = false;
      }

      if (!subReq.required && result.allowed) {
        anyOptionalPassed = true;
      }
    }

    // Determine overall result based on logic
    const hasOptionalRequirements = this.subRequirements.some(
      (r) => !r.required
    );
    const allowed =
      allRequiredPassed && (!hasOptionalRequirements || anyOptionalPassed);

    const processingTimeUs = Number(process.hrtime.bigint() - startTime) / 1000;

    // Create composite result
    const compositeResult: PermissionCheckResult = {
      allowed,
      resolverType: PermissionResolverType.EXPRESSION, // Composite type
      resolutionTimeUs: processingTimeUs,
      cached: checkResults.some((r) => r.cached),
      reason: allowed ? undefined : 'Composite permission check failed',
      matchedPermissions: allowed
        ? checkResults.flatMap((r) => r.matchedPermissions || [])
        : undefined,
    };

    return {
      allowed,
      user,
      checkResult: compositeResult,
      guardType: this.getGuardType(),
      processingTimeUs,
    };
  }

  getGuardType(): string {
    return 'CompositePermissionGuard';
  }
}

/**
 * Permission Guard Factory Implementation
 */
@Service()
export class PermissionGuardFactory {
  private readonly userContextService: FastUserContextService;
  private readonly guardConfig: GuardConfiguration;
  private readonly cache: CacheAdapter;

  // Guard instance cache for reuse
  private readonly guardCache = new Map<string, BasePermissionGuard>();

  constructor(
    userContextService: FastUserContextService,
    guardConfig: GuardConfiguration,
    cache: CacheAdapter
  ) {
    this.userContextService = userContextService;
    this.guardConfig = guardConfig;
    this.cache = cache;
  }

  /**
   * Create a plain permission guard for simple permission lists
   *
   * @param permissions - Array of required permissions
   * @param config - Optional guard configuration
   * @returns Plain permission guard instance
   */
  createPlainGuard(
    permissions: string[],
    config: Partial<GuardConfig> = {}
  ): BasePermissionGuard {
    const fullConfig: GuardConfig = {
      requireAuth: true,
      permissions,
      resolverType: PermissionResolverType.PLAIN,
      cacheResults: true,
      auditTrail: false,
      ...config,
    };

    const cacheKey = this.generateCacheKey('plain', fullConfig);

    if (!this.guardCache.has(cacheKey)) {
      const guard = new PlainPermissionGuard(
        fullConfig,
        this.userContextService,
        this.guardConfig,
        this.cache
      );
      this.guardCache.set(cacheKey, guard);
    }

    return this.guardCache.get(cacheKey)!;
  }

  /**
   * Create a wildcard permission guard for hierarchical patterns
   *
   * @param wildcardPatterns - Array of wildcard patterns
   * @param config - Optional guard configuration
   * @returns Wildcard permission guard instance
   */
  createWildcardGuard(
    wildcardPatterns: string[],
    config: Partial<GuardConfig> = {}
  ): BasePermissionGuard {
    const fullConfig: GuardConfig = {
      requireAuth: true,
      permissions: wildcardPatterns,
      resolverType: PermissionResolverType.WILDCARD,
      cacheResults: true,
      auditTrail: false,
      ...config,
    };

    const cacheKey = this.generateCacheKey('wildcard', fullConfig);

    if (!this.guardCache.has(cacheKey)) {
      const guard = new WildcardPermissionGuard(
        fullConfig,
        this.userContextService,
        this.guardConfig,
        this.cache
      );
      this.guardCache.set(cacheKey, guard);
    }

    return this.guardCache.get(cacheKey)!;
  }

  /**
   * Create an expression permission guard for complex boolean logic
   *
   * @param expression - Permission expression
   * @param config - Optional guard configuration
   * @returns Expression permission guard instance
   */
  createExpressionGuard(
    expression: PermissionExpression,
    config: Partial<GuardConfig> = {}
  ): BasePermissionGuard {
    const fullConfig: GuardConfig = {
      requireAuth: true,
      permissions: expression,
      resolverType: PermissionResolverType.EXPRESSION,
      cacheResults: true,
      auditTrail: false,
      ...config,
    };

    const cacheKey = this.generateCacheKey('expression', fullConfig);

    if (!this.guardCache.has(cacheKey)) {
      const guard = new ExpressionPermissionGuard(
        fullConfig,
        this.userContextService,
        this.guardConfig,
        this.cache
      );
      this.guardCache.set(cacheKey, guard);
    }

    return this.guardCache.get(cacheKey)!;
  }

  /**
   * Create a composite guard for mixed permission requirements
   *
   * @param requirements - Array of sub-requirements with different resolver types
   * @param config - Optional guard configuration
   * @returns Composite permission guard instance
   */
  createCompositeGuard(
    requirements: Array<{
      permissions:
        | string
        | string[]
        | PermissionExpression
        | Record<string, unknown>;
      resolverType: PermissionResolverType;
      required: boolean;
    }>,
    config: Partial<GuardConfig> = {}
  ): BasePermissionGuard {
    const fullConfig: GuardConfig = {
      requireAuth: true,
      permissions: requirements as any, // Store requirements as permissions for cache key (complex composite type)
      cacheResults: true,
      auditTrail: false,
      ...config,
    };

    const cacheKey = this.generateCacheKey('composite', fullConfig);

    if (!this.guardCache.has(cacheKey)) {
      const guard = new CompositePermissionGuard(
        fullConfig,
        this.userContextService,
        this.guardConfig,
        this.cache,
        requirements
      );
      this.guardCache.set(cacheKey, guard);
    }

    return this.guardCache.get(cacheKey)!;
  }

  /**
   * Create guard with automatic resolver selection
   *
   * Analyzes the permission requirements and automatically selects
   * the most appropriate resolver type for optimal performance.
   *
   * @param permissions - Permission requirements of any type
   * @param config - Optional guard configuration
   * @returns Optimally configured permission guard
   */
  createAutoGuard(
    permissions:
      | string
      | string[]
      | PermissionExpression
      | Record<string, unknown>,
    config: Partial<GuardConfig> = {}
  ): BasePermissionGuard {
    const resolverType = this.selectOptimalResolver(permissions);

    switch (resolverType) {
      case PermissionResolverType.PLAIN:
        return this.createPlainGuard(permissions as string[], config);

      case PermissionResolverType.WILDCARD:
        return this.createWildcardGuard(permissions as string[], config);

      case PermissionResolverType.EXPRESSION:
        return this.createExpressionGuard(
          permissions as PermissionExpression,
          config
        );

      default:
        // Fallback to plain guard
        return this.createPlainGuard(
          Array.isArray(permissions)
            ? (permissions as string[])
            : [permissions as string],
          config
        );
    }
  }

  /**
   * Get factory statistics
   */
  getStats() {
    const guardStats = Array.from(this.guardCache.values()).map((guard) =>
      guard.getStats()
    );

    return {
      totalGuards: this.guardCache.size,
      guardsByType: this.getGuardCountsByType(),
      individualGuardStats: guardStats,
      aggregatedStats: this.aggregateGuardStats(guardStats),
    };
  }

  /**
   * Clear guard cache
   */
  clearCache(): void {
    this.guardCache.clear();
    console.log('🧹 Permission guard factory cache cleared');
  }

  /**
   * Select optimal resolver based on permission requirements
   */
  private selectOptimalResolver(
    permissions:
      | string
      | string[]
      | PermissionExpression
      | Record<string, unknown>
  ): PermissionResolverType {
    // Expression detection
    if (
      permissions &&
      typeof permissions === 'object' &&
      !Array.isArray(permissions)
    ) {
      if (
        permissions.and ||
        permissions.or ||
        permissions.not ||
        permissions.permission
      ) {
        return PermissionResolverType.EXPRESSION;
      }
    }

    // Array analysis
    if (Array.isArray(permissions)) {
      const hasWildcards = permissions.some(
        (p) => typeof p === 'string' && p.includes('*')
      );
      if (hasWildcards) {
        return PermissionResolverType.WILDCARD;
      }
      return PermissionResolverType.PLAIN;
    }

    // Single string analysis
    if (typeof permissions === 'string') {
      return permissions.includes('*')
        ? PermissionResolverType.WILDCARD
        : PermissionResolverType.PLAIN;
    }

    // Default to plain
    return PermissionResolverType.PLAIN;
  }

  /**
   * Generate cache key for guard instance reuse
   */
  private generateCacheKey(type: string, config: GuardConfig): string {
    const key = `${type}:${JSON.stringify({
      permissions: config.permissions,
      resolverType: config.resolverType,
      requireAuth: config.requireAuth,
      cacheResults: config.cacheResults,
      auditTrail: config.auditTrail,
      allowPartialMatch: config.allowPartialMatch,
      requireAllPermissions: config.requireAllPermissions,
    })}`;

    // Hash long keys to prevent memory issues
    if (key.length > 200) {
      return `${type}:${this.simpleHash(key)}`;
    }

    return key;
  }

  /**
   * Simple hash function for cache keys
   */
  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Get guard counts by type
   */
  private getGuardCountsByType(): Record<string, number> {
    const counts: Record<string, number> = {};

    for (const guard of this.guardCache.values()) {
      const type = guard.getGuardType();
      counts[type] = (counts[type] || 0) + 1;
    }

    return counts;
  }

  /**
   * Aggregate statistics from all guards
   */
  private aggregateGuardStats(guardStats: any[]): any {
    if (guardStats.length === 0) {
      return {
        totalChecks: 0,
        totalSuccesses: 0,
        totalFailures: 0,
        overallSuccessRate: 100,
        averageProcessingTimeUs: 0,
      };
    }

    const totals = guardStats.reduce(
      (acc, stats) => ({
        checkCount:
          (acc.checkCount as number) + ((stats.checkCount as number) || 0),
        successCount:
          (acc.successCount as number) + ((stats.successCount as number) || 0),
        failureCount:
          (acc.failureCount as number) + ((stats.failureCount as number) || 0),
        totalProcessingTimeUs:
          (acc.totalProcessingTimeUs as number) +
          ((stats.totalProcessingTimeUs as number) || 0),
      }),
      {
        checkCount: 0,
        successCount: 0,
        failureCount: 0,
        totalProcessingTimeUs: 0,
      }
    );

    return {
      totalChecks: totals.checkCount,
      totalSuccesses: totals.successCount,
      totalFailures: totals.failureCount,
      overallSuccessRate:
        (totals.checkCount as number) > 0
          ? ((totals.successCount as number) / (totals.checkCount as number)) *
            100
          : 100,
      averageProcessingTimeUs:
        (totals.checkCount as number) > 0
          ? (totals.totalProcessingTimeUs as number) /
            (totals.checkCount as number)
          : 0,
    };
  }
}
