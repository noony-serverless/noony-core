/**
 * Permission Resolver Factory
 *
 * Factory for creating and managing different types of permission resolvers
 * in the Guard System Showcase. Provides centralized resolver instantiation,
 * strategy selection, and performance comparison across resolver types.
 *
 * Features:
 * - Support for all three resolution strategies (Plain, Wildcard, Expression)
 * - Automatic resolver selection based on requirement analysis
 * - Performance monitoring and comparison
 * - Resolver health monitoring and failover
 * - A/B testing capabilities for resolver strategies
 *
 * @module PermissionResolverFactory
 * @version 1.0.0
 */

import {
  PermissionResolver,
  PermissionResolverType,
} from '@noony-serverless/core';
import { PermissionSource } from './permission-source';
import { PlainPermissionResolver } from './resolvers/plain-permission-resolver';
import { WildcardPermissionResolver } from './resolvers/wildcard-permission-resolver';
import { ExpressionPermissionResolver } from './resolvers/expression-permission-resolver';
import {
  PermissionCheckResult,
  PermissionExpression,
} from '@/types/auth.types';

/**
 * Resolver factory configuration
 */
export interface ResolverFactoryConfig {
  /** Default resolver strategy */
  defaultStrategy: PermissionResolverType;

  /** Enable automatic strategy selection */
  enableAutoSelection: boolean;

  /** Enable resolver performance comparison */
  enablePerformanceComparison: boolean;

  /** Enable resolver health monitoring */
  enableHealthMonitoring: boolean;

  /** Health check interval (milliseconds) */
  healthCheckInterval: number;

  /** Enable A/B testing between resolvers */
  enableABTesting: boolean;

  /** A/B testing traffic split (percentage for alternative resolver) */
  abTestingTrafficSplit: number;

  /** Alternative resolver for A/B testing */
  abTestingAlternativeStrategy?: PermissionResolverType;
}

/**
 * Resolver performance comparison result
 */
export interface ResolverPerformanceComparison {
  /** Requirement that was tested */
  requirement: string | string[] | PermissionExpression;

  /** User ID tested */
  userId: string;

  /** Results from each resolver */
  results: {
    [PermissionResolverType.PLAIN]?: PermissionCheckResult;
    [PermissionResolverType.WILDCARD]?: PermissionCheckResult;
    [PermissionResolverType.EXPRESSION]?: PermissionCheckResult;
  };

  /** Performance analysis */
  analysis: {
    fastestResolver: PermissionResolverType;
    slowestResolver: PermissionResolverType;
    performanceDifference: number; // microseconds
    consistentResults: boolean;
    recommendedResolver: PermissionResolverType;
  };

  /** Comparison timestamp */
  timestamp: string;
}

/**
 * Resolver health status
 */
export interface ResolverHealthStatus {
  /** Resolver type */
  type: PermissionResolverType;

  /** Whether resolver is healthy */
  healthy: boolean;

  /** Performance metrics */
  performance: {
    averageLatency: number;
    errorRate: number;
    successRate: number;
    checksPerSecond: number;
  };

  /** Current issues */
  issues: string[];

  /** Recommendations */
  recommendations: string[];

  /** Last health check */
  lastCheck: string;
}

/**
 * Permission Resolver Factory
 *
 * Centralized factory for creating and managing permission resolvers with:
 * - Multi-strategy support with automatic selection
 * - Performance monitoring and comparison
 * - Health monitoring and failover
 * - A/B testing capabilities
 */
export class PermissionResolverFactory {
  private static instance: PermissionResolverFactory;

  private readonly permissionSource: PermissionSource;
  private readonly config: ResolverFactoryConfig;
  private readonly resolvers = new Map<
    PermissionResolverType,
    PermissionResolver
  >();
  private readonly healthStatus = new Map<
    PermissionResolverType,
    ResolverHealthStatus
  >();
  private readonly performanceComparisons: ResolverPerformanceComparison[] = [];
  private healthMonitoringInterval?: NodeJS.Timeout;

  constructor(
    permissionSource: PermissionSource,
    config: ResolverFactoryConfig
  ) {
    this.permissionSource = permissionSource;
    this.config = this.validateConfig(config);

    // Initialize all resolvers
    this.initializeResolvers();

    // Start health monitoring if enabled
    if (this.config.enableHealthMonitoring) {
      this.startHealthMonitoring();
    }

    console.log(
      `🏭 Permission Resolver Factory initialized (default: ${this.config.defaultStrategy})`
    );
  }

  /**
   * Get singleton instance
   */
  public static getInstance(
    permissionSource?: PermissionSource,
    config?: ResolverFactoryConfig
  ): PermissionResolverFactory {
    if (!PermissionResolverFactory.instance) {
      if (!permissionSource || !config) {
        throw new Error(
          'Permission source and config required for first factory instantiation'
        );
      }
      PermissionResolverFactory.instance = new PermissionResolverFactory(
        permissionSource,
        config
      );
    }
    return PermissionResolverFactory.instance;
  }

  // ============================================================================
  // RESOLVER CREATION AND MANAGEMENT
  // ============================================================================

  /**
   * Get resolver by type
   *
   * @param type - Resolver type
   * @returns Permission resolver instance
   * @throws Error if resolver type not supported
   */
  public getResolver(type?: PermissionResolverType): PermissionResolver {
    const targetType = type || this.config.defaultStrategy;

    const resolver = this.resolvers.get(targetType);
    if (!resolver) {
      throw new Error(`Resolver not available: ${targetType}`);
    }

    return resolver;
  }

  /**
   * Get optimal resolver for a specific requirement
   *
   * @param requirement - Permission requirement to analyze
   * @returns Optimal resolver and analysis
   */
  public getOptimalResolver(
    requirement: string | string[] | PermissionExpression
  ): {
    resolver: PermissionResolver;
    type: PermissionResolverType;
    reason: string;
  } {
    if (!this.config.enableAutoSelection) {
      const resolver = this.getResolver();
      return {
        resolver,
        type: resolver.getType(),
        reason: 'Using configured default resolver',
      };
    }

    const analysis = this.analyzeRequirement(requirement);
    const optimalType = this.selectOptimalResolverType(analysis);
    const resolver = this.getResolver(optimalType);

    return {
      resolver,
      type: optimalType,
      reason: this.generateSelectionReason(analysis, optimalType),
    };
  }

  /**
   * Check permission with automatic resolver selection
   *
   * @param userId - User ID to check permissions for
   * @param requirement - Permission requirement
   * @param context - Additional context
   * @returns Promise resolving to permission check result
   */
  public async checkPermission(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    context: Record<string, unknown> = {}
  ): Promise<PermissionCheckResult> {
    // Handle A/B testing
    if (this.config.enableABTesting && this.shouldUseABTestingResolver()) {
      return this.performABTestCheck(userId, requirement, context);
    }

    // Get optimal resolver
    const { resolver, type, reason } = this.getOptimalResolver(requirement);

    // Perform check with performance comparison if enabled
    if (this.config.enablePerformanceComparison) {
      return this.performCheckWithComparison(
        userId,
        requirement,
        context,
        type
      );
    }

    // Standard check
    const result = await (
      resolver as unknown as Record<string, unknown> & {
        checkPermission: (
          userId: string,
          permission: string,
          context?: Record<string, unknown>
        ) => Promise<PermissionCheckResult>;
      }
    ).checkPermission(userId, requirement as string, context);

    // Add resolver selection metadata
    if (result.metadata) {
      result.metadata.resolverSelection = {
        selectedType: type,
        reason,
        autoSelected: this.config.enableAutoSelection,
      };
    }

    return result;
  }

  // ============================================================================
  // REQUIREMENT ANALYSIS AND SELECTION
  // ============================================================================

  /**
   * Analyze requirement to determine optimal resolver
   *
   * @param requirement - Permission requirement
   * @returns Analysis result
   */
  private analyzeRequirement(
    requirement: string | string[] | PermissionExpression
  ): {
    type: 'simple' | 'array' | 'wildcard' | 'expression';
    complexity: number;
    hasWildcards: boolean;
    hasLogicalOperators: boolean;
    itemCount: number;
    estimatedCost: number;
  } {
    if (typeof requirement === 'string') {
      const hasWildcards =
        requirement.includes('*') || requirement.includes('?');
      const hasLogical = /\b(AND|OR|NOT)\b|\|\||&&|!|\(|\)/.test(requirement);

      return {
        type: hasLogical ? 'expression' : hasWildcards ? 'wildcard' : 'simple',
        complexity: this.calculateStringComplexity(requirement),
        hasWildcards,
        hasLogicalOperators: hasLogical,
        itemCount: 1,
        estimatedCost: hasLogical ? 100 : hasWildcards ? 50 : 1,
      };
    }

    if (Array.isArray(requirement)) {
      const hasWildcards = requirement.some(
        (req) => req.includes('*') || req.includes('?')
      );

      return {
        type: hasWildcards ? 'wildcard' : 'array',
        complexity: requirement.length,
        hasWildcards,
        hasLogicalOperators: false,
        itemCount: requirement.length,
        estimatedCost: requirement.length * (hasWildcards ? 50 : 1),
      };
    }

    // Expression object
    return {
      type: 'expression',
      complexity: this.calculateExpressionComplexity(requirement),
      hasWildcards: this.expressionContainsWildcards(requirement),
      hasLogicalOperators: true,
      itemCount: this.countExpressionNodes(requirement),
      estimatedCost: this.calculateExpressionComplexity(requirement) * 20,
    };
  }

  /**
   * Select optimal resolver type based on analysis
   *
   * @param analysis - Requirement analysis
   * @returns Optimal resolver type
   */
  private selectOptimalResolverType(
    analysis: Record<string, unknown>
  ): PermissionResolverType {
    // Simple cases - use Plain resolver
    if (
      analysis.type === 'simple' ||
      (analysis.type === 'array' &&
        !analysis.hasWildcards &&
        (analysis.itemCount as number) <= 3)
    ) {
      return PermissionResolverType.PLAIN;
    }

    // Complex expressions - use Expression resolver
    if (analysis.type === 'expression' || analysis.hasLogicalOperators) {
      return PermissionResolverType.EXPRESSION;
    }

    // Wildcard patterns - use Wildcard resolver
    if (analysis.hasWildcards) {
      return PermissionResolverType.WILDCARD;
    }

    // Arrays without wildcards - depends on size
    if (analysis.type === 'array') {
      return (analysis.itemCount as number) <= 5
        ? PermissionResolverType.PLAIN
        : PermissionResolverType.WILDCARD;
    }

    // Default fallback
    return this.config.defaultStrategy;
  }

  /**
   * Generate human-readable reason for resolver selection
   *
   * @param analysis - Requirement analysis
   * @param selectedType - Selected resolver type
   * @returns Selection reason
   */
  private generateSelectionReason(
    analysis: Record<string, unknown>,
    selectedType: PermissionResolverType
  ): string {
    switch (selectedType) {
      case PermissionResolverType.PLAIN:
        if (analysis.type === 'simple') {
          return 'Simple permission - Plain resolver optimal for O(1) lookup';
        }
        return `Small array (${analysis.itemCount} items) - Plain resolver efficient`;

      case PermissionResolverType.WILDCARD:
        if (analysis.hasWildcards) {
          return 'Wildcard patterns detected - Wildcard resolver required';
        }
        return `Large array (${analysis.itemCount} items) - Wildcard resolver handles efficiently`;

      case PermissionResolverType.EXPRESSION:
        return 'Complex expression detected - Expression resolver required for boolean logic';

      default:
        return `Using default resolver: ${selectedType}`;
    }
  }

  // ============================================================================
  // PERFORMANCE COMPARISON
  // ============================================================================

  /**
   * Perform permission check with performance comparison
   *
   * @param userId - User ID
   * @param requirement - Permission requirement
   * @param context - Additional context
   * @param primaryType - Primary resolver type
   * @returns Permission check result with comparison data
   */
  private async performCheckWithComparison(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    context: Record<string, unknown>,
    primaryType: PermissionResolverType
  ): Promise<PermissionCheckResult> {
    const results: Record<string, PermissionCheckResult | null> = {};
    const resolverTypes = [
      PermissionResolverType.PLAIN,
      PermissionResolverType.WILDCARD,
      PermissionResolverType.EXPRESSION,
    ];

    try {
      // Run all applicable resolvers in parallel
      const promises = resolverTypes
        .filter((type) => this.isResolverApplicable(type, requirement))
        .map(async (type) => {
          try {
            const resolver = this.getResolver(type);
            const result = await (
              resolver as unknown as Record<string, unknown> & {
                checkPermission: (
                  userId: string,
                  permission: string,
                  context?: Record<string, unknown>
                ) => Promise<PermissionCheckResult>;
              }
            ).checkPermission(userId, requirement as string, context);
            return { type, result };
          } catch (error) {
            console.warn(
              `⚠️ Resolver ${type} failed during comparison:`,
              error
            );
            return { type, result: null };
          }
        });

      const resolverResults = await Promise.all(promises);

      // Collect results
      resolverResults.forEach(({ type, result }) => {
        if (result) {
          results[type] = result;
        }
      });

      // Analyze comparison - filter out null results
      const validResults: Record<string, PermissionCheckResult> = {};
      Object.entries(results).forEach(([key, value]) => {
        if (value !== null) {
          validResults[key] = value;
        }
      });

      const comparison = this.analyzePerformanceComparison(
        requirement,
        userId,
        validResults as Record<PermissionResolverType, PermissionCheckResult>
      );
      this.storePerformanceComparison(comparison);

      // Return primary result with comparison metadata
      const primaryResult = results[primaryType];
      if (primaryResult && primaryResult.metadata) {
        primaryResult.metadata.performanceComparison = {
          compared: Object.keys(results).length,
          fastestResolver: comparison.analysis.fastestResolver,
          performanceDifference: comparison.analysis.performanceDifference,
          recommendedResolver: comparison.analysis.recommendedResolver,
        };
      }

      return (
        primaryResult ||
        this.createErrorResult(primaryType, 'Primary resolver failed')
      );
    } catch (error) {
      console.error('❌ Performance comparison failed:', error);
      // Fallback to primary resolver only
      const resolver = this.getResolver(primaryType);
      return await (
        resolver as unknown as Record<string, unknown> & {
          checkPermission: (
            userId: string,
            permission: string,
            context?: Record<string, unknown>
          ) => Promise<PermissionCheckResult>;
        }
      ).checkPermission(userId, requirement as string, context);
    }
  }

  /**
   * Analyze performance comparison results
   *
   * @param requirement - Permission requirement
   * @param userId - User ID
   * @param results - Results from different resolvers
   * @returns Performance analysis
   */
  private analyzePerformanceComparison(
    requirement: string | string[] | PermissionExpression,
    userId: string,
    results: Record<PermissionResolverType, PermissionCheckResult>
  ): ResolverPerformanceComparison {
    const resolverTypes = Object.keys(results) as PermissionResolverType[];

    if (resolverTypes.length === 0) {
      throw new Error('No resolver results to compare');
    }

    // Find fastest and slowest
    let fastestType = resolverTypes[0];
    let slowestType = resolverTypes[0];
    let fastestTime = results[fastestType].resolutionTimeUs;
    let slowestTime = results[slowestType].resolutionTimeUs;

    for (const type of resolverTypes) {
      const time = results[type].resolutionTimeUs;
      if (time < fastestTime) {
        fastestTime = time;
        fastestType = type;
      }
      if (time > slowestTime) {
        slowestTime = time;
        slowestType = type;
      }
    }

    // Check result consistency
    const firstResult = results[resolverTypes[0]].allowed;
    const consistentResults = resolverTypes.every(
      (type) => results[type].allowed === firstResult
    );

    // Determine recommended resolver
    const recommendedResolver = this.determineRecommendedResolver(
      results,
      fastestType
    );

    return {
      requirement,
      userId,
      results,
      analysis: {
        fastestResolver: fastestType,
        slowestResolver: slowestType,
        performanceDifference: slowestTime - fastestTime,
        consistentResults,
        recommendedResolver,
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Determine recommended resolver based on results
   *
   * @param results - Resolver results
   * @param fastestType - Fastest resolver type
   * @returns Recommended resolver type
   */
  private determineRecommendedResolver(
    results: Record<PermissionResolverType, PermissionCheckResult>,
    fastestType: PermissionResolverType
  ): PermissionResolverType {
    // If Plain resolver is available and fast enough, prefer it
    if (results[PermissionResolverType.PLAIN]) {
      const plainTime = results[PermissionResolverType.PLAIN].resolutionTimeUs;
      const fastestTime = results[fastestType].resolutionTimeUs;

      // If Plain is within 50% of fastest, recommend it for simplicity
      if (plainTime <= fastestTime * 1.5) {
        return PermissionResolverType.PLAIN;
      }
    }

    // Otherwise, return the fastest
    return fastestType;
  }

  /**
   * Store performance comparison for analysis
   *
   * @param comparison - Performance comparison result
   */
  private storePerformanceComparison(
    comparison: ResolverPerformanceComparison
  ): void {
    this.performanceComparisons.push(comparison);

    // Keep only recent comparisons to prevent memory growth
    const maxComparisons = 1000;
    if (this.performanceComparisons.length > maxComparisons) {
      this.performanceComparisons.splice(
        0,
        this.performanceComparisons.length - maxComparisons
      );
    }
  }

  // ============================================================================
  // A/B TESTING
  // ============================================================================

  /**
   * Check if should use A/B testing resolver
   *
   * @returns True if should use A/B testing
   */
  private shouldUseABTestingResolver(): boolean {
    if (
      !this.config.enableABTesting ||
      !this.config.abTestingAlternativeStrategy
    ) {
      return false;
    }

    return Math.random() * 100 < this.config.abTestingTrafficSplit;
  }

  /**
   * Perform A/B test permission check
   *
   * @param userId - User ID
   * @param requirement - Permission requirement
   * @param context - Additional context
   * @returns Permission check result
   */
  private async performABTestCheck(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    context: Record<string, unknown>
  ): Promise<PermissionCheckResult> {
    const alternativeType = this.config.abTestingAlternativeStrategy!;
    const controlType = this.config.defaultStrategy;

    try {
      // Run both resolvers
      const [controlResult, testResult] = await Promise.all([
        (
          this.getResolver(controlType) as unknown as Record<
            string,
            unknown
          > & {
            checkPermission: (
              userId: string,
              permission: string,
              context?: Record<string, unknown>
            ) => Promise<PermissionCheckResult>;
          }
        ).checkPermission(userId, requirement as string, context),
        (
          this.getResolver(alternativeType) as unknown as Record<
            string,
            unknown
          > & {
            checkPermission: (
              userId: string,
              permission: string,
              context?: Record<string, unknown>
            ) => Promise<PermissionCheckResult>;
          }
        ).checkPermission(userId, requirement as string, context),
      ]);

      // Log A/B test result
      this.logABTestResult(userId, requirement, controlResult, testResult);

      // Return control result (standard behavior)
      if (controlResult.metadata) {
        controlResult.metadata.abTest = {
          controlResolver: controlType,
          testResolver: alternativeType,
          performanceDifference:
            testResult.resolutionTimeUs - controlResult.resolutionTimeUs,
          consistentResult: controlResult.allowed === testResult.allowed,
        };
      }

      return controlResult;
    } catch (error) {
      console.error('❌ A/B test failed, falling back to control:', error);
      return (
        this.getResolver(controlType) as unknown as Record<string, unknown> & {
          checkPermission: (
            userId: string,
            permission: string,
            context?: Record<string, unknown>
          ) => Promise<PermissionCheckResult>;
        }
      ).checkPermission(userId, requirement as string, context);
    }
  }

  /**
   * Log A/B test result for analysis
   *
   * @param userId - User ID
   * @param requirement - Permission requirement
   * @param controlResult - Control resolver result
   * @param testResult - Test resolver result
   */
  private logABTestResult(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    controlResult: PermissionCheckResult,
    testResult: PermissionCheckResult
  ): void {
    console.log('🧪 A/B Test Result:', {
      userId: userId.substring(0, 8) + '...',
      control: {
        resolver: this.config.defaultStrategy,
        allowed: controlResult.allowed,
        time: `${controlResult.resolutionTimeUs.toFixed(1)}μs`,
      },
      test: {
        resolver: this.config.abTestingAlternativeStrategy,
        allowed: testResult.allowed,
        time: `${testResult.resolutionTimeUs.toFixed(1)}μs`,
      },
      consistent: controlResult.allowed === testResult.allowed,
      performanceDiff: `${(testResult.resolutionTimeUs - controlResult.resolutionTimeUs).toFixed(1)}μs`,
      timestamp: new Date().toISOString(),
    });
  }

  // ============================================================================
  // HEALTH MONITORING
  // ============================================================================

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    this.healthMonitoringInterval = setInterval(() => {
      this.performHealthChecks();
    }, this.config.healthCheckInterval);

    console.log(
      `❤️ Resolver health monitoring started (interval: ${this.config.healthCheckInterval}ms)`
    );
  }

  /**
   * Perform health checks on all resolvers
   */
  private performHealthChecks(): void {
    for (const [type, resolver] of this.resolvers) {
      try {
        const health = this.checkResolverHealth(resolver);
        this.healthStatus.set(type, health);
      } catch (error) {
        console.error(`❌ Health check failed for ${type}:`, error);
      }
    }
  }

  /**
   * Check individual resolver health
   *
   * @param resolver - Resolver to check
   * @returns Health status
   */
  private checkResolverHealth(
    resolver: PermissionResolver
  ): ResolverHealthStatus {
    const type = resolver.getType();
    let stats: Record<string, unknown> = {};
    let issues: string[] = [];
    let recommendations: string[] = [];

    // Get resolver-specific stats
    if ('getStats' in resolver) {
      stats = (
        resolver as unknown as Record<string, unknown> & {
          getStats: () => Record<string, unknown>;
        }
      ).getStats();
    }

    // Get health status if available
    if ('getHealthStatus' in resolver) {
      const healthInfo = (
        resolver as unknown as Record<string, unknown> & {
          getHealthStatus: () => Record<string, unknown>;
        }
      ).getHealthStatus();
      issues = (healthInfo.issues as string[]) || [];
      recommendations = (healthInfo.recommendations as string[]) || [];
    }

    // Calculate performance metrics
    const performance = {
      averageLatency: (stats.averageResolutionTimeUs as number) || 0,
      errorRate:
        (stats.totalChecks as number) > 0
          ? (((stats.loadFailures as number) || 0) /
              (stats.totalChecks as number)) *
            100
          : 0,
      successRate:
        (stats.totalChecks as number) > 0
          ? (((stats.allowedChecks as number) || 0) /
              (stats.totalChecks as number)) *
            100
          : 100,
      checksPerSecond: this.calculateChecksPerSecond(stats),
    };

    return {
      type,
      healthy: issues.length === 0,
      performance,
      issues,
      recommendations,
      lastCheck: new Date().toISOString(),
    };
  }

  /**
   * Calculate checks per second for resolver
   *
   * @param stats - Resolver statistics
   * @returns Checks per second
   */
  private calculateChecksPerSecond(stats: Record<string, unknown>): number {
    if (!stats.lastCheck || !stats.totalChecks) {
      return 0;
    }

    const timeSinceLastCheck = Date.now() - (stats.lastCheck as number);
    const secondsSince = Math.max(timeSinceLastCheck / 1000, 1);

    return Math.round((stats.totalChecks as number) / secondsSince);
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Initialize all resolvers
   */
  private initializeResolvers(): void {
    this.resolvers.set(
      PermissionResolverType.PLAIN,
      new PlainPermissionResolver(this.permissionSource)
    );

    this.resolvers.set(
      PermissionResolverType.WILDCARD,
      new WildcardPermissionResolver(this.permissionSource)
    );

    this.resolvers.set(
      PermissionResolverType.EXPRESSION,
      new ExpressionPermissionResolver(this.permissionSource)
    );
  }

  /**
   * Check if resolver is applicable for requirement
   *
   * @param type - Resolver type
   * @param requirement - Permission requirement
   * @returns True if resolver can handle requirement
   */
  private isResolverApplicable(
    type: PermissionResolverType,
    requirement: string | string[] | PermissionExpression
  ): boolean {
    switch (type) {
      case PermissionResolverType.PLAIN:
        // Plain can handle simple strings and simple arrays
        return (
          typeof requirement === 'string' ||
          (Array.isArray(requirement) && requirement.length <= 10)
        );

      case PermissionResolverType.WILDCARD:
        // Wildcard can handle strings and arrays
        return typeof requirement === 'string' || Array.isArray(requirement);

      case PermissionResolverType.EXPRESSION:
        // Expression can handle all types
        return true;

      default:
        return false;
    }
  }

  /**
   * Create error result for resolver failures
   *
   * @param type - Resolver type
   * @param error - Error message
   * @returns Error result
   */
  private createErrorResult(
    type: PermissionResolverType,
    error: string
  ): PermissionCheckResult {
    return {
      allowed: false,
      resolverType: type,
      resolutionTimeUs: 0,
      cached: false,
      reason: error,
      metadata: {
        error,
      },
    };
  }

  /**
   * Calculate string complexity for analysis
   *
   * @param str - String to analyze
   * @returns Complexity score
   */
  private calculateStringComplexity(str: string): number {
    let complexity = str.length;

    // Add complexity for special characters
    if (str.includes('*')) complexity += 10;
    if (str.includes('?')) complexity += 5;
    if (str.includes('(') || str.includes(')')) complexity += 15;
    if (/\b(AND|OR|NOT)\b/.test(str)) complexity += 20;

    return complexity;
  }

  /**
   * Calculate expression complexity
   *
   * @param expr - Expression to analyze
   * @returns Complexity score
   */
  private calculateExpressionComplexity(expr: PermissionExpression): number {
    if (expr.permission) return 1;
    if (expr.and)
      return (
        1 +
        expr.and.reduce(
          (sum, e) => sum + this.calculateExpressionComplexity(e),
          0
        )
      );
    if (expr.or)
      return (
        1 +
        expr.or.reduce(
          (sum, e) => sum + this.calculateExpressionComplexity(e),
          0
        )
      );
    if (expr.not) return 1 + this.calculateExpressionComplexity(expr.not);
    return 1;
  }

  /**
   * Check if expression contains wildcards
   *
   * @param expr - Expression to check
   * @returns True if contains wildcards
   */
  private expressionContainsWildcards(expr: PermissionExpression): boolean {
    if (expr.permission)
      return expr.permission.includes('*') || expr.permission.includes('?');
    if (expr.and)
      return expr.and.some((e) => this.expressionContainsWildcards(e));
    if (expr.or)
      return expr.or.some((e) => this.expressionContainsWildcards(e));
    if (expr.not) return this.expressionContainsWildcards(expr.not);
    return false;
  }

  /**
   * Count nodes in expression
   *
   * @param expr - Expression to count
   * @returns Node count
   */
  private countExpressionNodes(expr: PermissionExpression): number {
    if (expr.permission) return 1;
    if (expr.and)
      return (
        1 + expr.and.reduce((sum, e) => sum + this.countExpressionNodes(e), 0)
      );
    if (expr.or)
      return (
        1 + expr.or.reduce((sum, e) => sum + this.countExpressionNodes(e), 0)
      );
    if (expr.not) return 1 + this.countExpressionNodes(expr.not);
    return 1;
  }

  /**
   * Validate factory configuration
   *
   * @param config - Configuration to validate
   * @returns Validated configuration with defaults
   */
  private validateConfig(config: ResolverFactoryConfig): ResolverFactoryConfig {
    return {
      ...config,
      enableAutoSelection: config.enableAutoSelection ?? true,
      enablePerformanceComparison: config.enablePerformanceComparison ?? false,
      enableHealthMonitoring: config.enableHealthMonitoring ?? true,
      healthCheckInterval: config.healthCheckInterval ?? 60000, // 1 minute
      enableABTesting: config.enableABTesting ?? false,
      abTestingTrafficSplit: config.abTestingTrafficSplit ?? 10, // 10%
    };
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get all available resolver types
   */
  public getAvailableResolvers(): PermissionResolverType[] {
    return Array.from(this.resolvers.keys());
  }

  /**
   * Get resolver statistics summary
   */
  public getResolverStatsSummary(): Record<
    PermissionResolverType,
    Record<string, unknown>
  > {
    const summary: Record<string, Record<string, unknown>> = {};

    for (const [type, resolver] of this.resolvers) {
      if ('getPerformanceSummary' in resolver) {
        summary[type] = (
          resolver as unknown as Record<string, unknown> & {
            getPerformanceSummary: () => Record<string, unknown>;
          }
        ).getPerformanceSummary();
      } else if ('getStats' in resolver) {
        summary[type] = (
          resolver as unknown as Record<string, unknown> & {
            getStats: () => Record<string, unknown>;
          }
        ).getStats();
      }
    }

    return summary;
  }

  /**
   * Get recent performance comparisons
   *
   * @param limit - Maximum number of comparisons to return
   * @returns Recent performance comparisons
   */
  public getPerformanceComparisons(
    limit = 50
  ): ResolverPerformanceComparison[] {
    return this.performanceComparisons.slice(-limit);
  }

  /**
   * Get current health status of all resolvers
   */
  public getHealthStatus(): Map<PermissionResolverType, ResolverHealthStatus> {
    return new Map(this.healthStatus);
  }

  /**
   * Reset statistics for all resolvers
   */
  public resetAllStats(): void {
    for (const [, resolver] of this.resolvers) {
      if ('resetStats' in resolver) {
        (
          resolver as unknown as Record<string, unknown> & {
            resetStats: () => void;
          }
        ).resetStats();
      }
    }

    this.performanceComparisons.length = 0;
    console.log('📊 All resolver statistics reset');
  }

  /**
   * Shutdown factory and cleanup resources
   */
  public shutdown(): void {
    if (this.healthMonitoringInterval) {
      clearInterval(this.healthMonitoringInterval);
    }

    console.log('🏭 Permission Resolver Factory shutdown complete');
  }
}
