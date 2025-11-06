/**
 * Expression Permission Resolver
 *
 * Advanced permission resolver supporting complex boolean expressions with
 * AND, OR, and NOT operations. Limited to 2-level nesting to prevent
 * performance degradation while maintaining flexibility for complex
 * authorization scenarios.
 *
 * Supported Expression Structure:
 * - Leaf permissions: { permission: "admin.users" }
 * - AND operations: { and: [expr1, expr2, ...] }
 * - OR operations: { or: [expr1, expr2, ...] }
 * - NOT operations: { not: expr }
 * - Maximum 2-level nesting depth
 *
 * Performance Features:
 * - Result caching for expensive expression evaluations
 * - Short-circuit evaluation (AND stops at first false, OR stops at first true)
 * - Expression normalization for consistent cache keys
 * - Performance metrics and monitoring
 *
 * Example Expressions:
 * ```
 * // Simple OR: user needs admin OR manager role
 * { or: [{ permission: "admin.platform" }, { permission: "role.manager" }] }
 *
 * // Complex AND/OR: (admin OR (manager AND finance))
 * {
 *   or: [
 *     { permission: "admin.platform" },
 *     { and: [{ permission: "role.manager" }, { permission: "department.finance" }] }
 *   ]
 * }
 * ```
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import {
  PermissionResolver,
  PermissionResolverType,
  PerformanceCharacteristics,
  PermissionCheckResult,
  PermissionExpression,
  PermissionUtils,
} from './PermissionResolver';
import { CacheAdapter, CacheKeyBuilder } from '../cache/CacheAdapter';

/**
 * Expression evaluation result for detailed analysis
 */
interface ExpressionEvaluationResult {
  result: boolean;
  evaluatedPaths: string[];
  shortCircuited: boolean;
  evaluationTimeUs: number;
}

/**
 * Expression permission resolver for complex boolean logic
 */
export class ExpressionPermissionResolver extends PermissionResolver<PermissionExpression> {
  private readonly cache: CacheAdapter;
  private readonly maxNestingDepth = 2;

  // Performance tracking
  private checkCount = 0;
  private totalResolutionTimeUs = 0;
  private cacheHits = 0;
  private cacheMisses = 0;
  private expressionComplexityStats = {
    simple: 0, // Single permission checks
    moderate: 0, // 1-level nesting
    complex: 0, // 2-level nesting
  };

  constructor(cache: CacheAdapter) {
    super();
    this.cache = cache;
  }

  /**
   * Check if user permissions satisfy the permission expression
   *
   * @param userPermissions - Set of user's permissions for O(1) lookup
   * @param expression - Permission expression to evaluate
   * @returns Promise resolving to true if expression evaluates to true
   */
  async check(
    userPermissions: Set<string>,
    expression: PermissionExpression
  ): Promise<boolean> {
    const startTime = process.hrtime.bigint();

    try {
      // Validate expression structure
      if (!PermissionUtils.isValidExpression(expression)) {
        throw new Error('Invalid permission expression structure');
      }

      // Generate cache key for this evaluation
      const userPermissionArray = Array.from(userPermissions).sort();
      const cacheKey = CacheKeyBuilder.expressionResult(
        expression,
        userPermissionArray
      );

      // Check cache first
      const cachedResult = await this.cache.get<boolean>(cacheKey);
      if (cachedResult !== null) {
        this.cacheHits++;
        return cachedResult;
      }

      this.cacheMisses++;

      // Evaluate expression
      const result = this.evaluateExpression(userPermissions, expression, 0);

      // Track complexity
      this.trackComplexity(expression);

      // Cache result for 1 minute (configurable)
      await this.cache.set(cacheKey, result, 60 * 1000);

      return result;
    } finally {
      // Track performance metrics
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      this.checkCount++;
      this.totalResolutionTimeUs += resolutionTimeUs;
    }
  }

  /**
   * Check permissions with detailed result information
   */
  async checkWithResult(
    userPermissions: Set<string>,
    expression: PermissionExpression
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();
    let cached = false;

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

      if (!expression) {
        return {
          allowed: false,
          resolverType: this.getType(),
          resolutionTimeUs: 0,
          cached: false,
          reason: 'No expression provided',
        };
      }

      // Validate expression structure
      if (!PermissionUtils.isValidExpression(expression)) {
        return {
          allowed: false,
          resolverType: this.getType(),
          resolutionTimeUs: 0,
          cached: false,
          reason: 'Invalid expression structure',
        };
      }

      // Check cache
      const userPermissionArray = Array.from(userPermissions).sort();
      const cacheKey = CacheKeyBuilder.expressionResult(
        expression,
        userPermissionArray
      );
      const cachedResult = await this.cache.get<boolean>(cacheKey);

      if (cachedResult !== null) {
        cached = true;
        const endTime = process.hrtime.bigint();
        const resolutionTimeUs = Number(endTime - startTime) / 1000;

        return {
          allowed: cachedResult,
          resolverType: this.getType(),
          resolutionTimeUs,
          cached: true,
          reason: cachedResult ? undefined : 'Expression evaluation failed',
        };
      }

      // Evaluate with detailed result
      const evaluationResult = this.evaluateExpressionWithDetails(
        userPermissions,
        expression,
        0
      );

      // Cache result
      await this.cache.set(cacheKey, evaluationResult.result, 60 * 1000);

      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      return {
        allowed: evaluationResult.result,
        resolverType: this.getType(),
        resolutionTimeUs,
        cached: false,
        reason: evaluationResult.result
          ? undefined
          : 'Expression requirements not met',
        matchedPermissions: evaluationResult.result
          ? evaluationResult.evaluatedPaths
          : undefined,
      };
    } catch (error) {
      const endTime = process.hrtime.bigint();
      const resolutionTimeUs = Number(endTime - startTime) / 1000;

      return {
        allowed: false,
        resolverType: this.getType(),
        resolutionTimeUs,
        cached,
        reason:
          error instanceof Error ? error.message : 'Unknown evaluation error',
      };
    }
  }

  /**
   * Evaluate permission expression recursively
   *
   * @param userPermissions - User's permissions as Set for O(1) lookup
   * @param expression - Expression to evaluate
   * @param depth - Current nesting depth
   * @returns Boolean result of expression evaluation
   */
  private evaluateExpression(
    userPermissions: Set<string>,
    expression: PermissionExpression,
    depth: number
  ): boolean {
    // Enforce maximum nesting depth
    if (depth > this.maxNestingDepth) {
      throw new Error(
        `Expression nesting depth exceeds maximum of ${this.maxNestingDepth}`
      );
    }

    // Leaf node: direct permission check
    if (expression.permission) {
      return userPermissions.has(expression.permission);
    }

    // AND operation: all sub-expressions must be true
    if (expression.and && Array.isArray(expression.and)) {
      for (const subExpression of expression.and) {
        if (
          !this.evaluateExpression(userPermissions, subExpression, depth + 1)
        ) {
          return false; // Short-circuit: AND fails on first false
        }
      }
      return true;
    }

    // OR operation: at least one sub-expression must be true
    if (expression.or && Array.isArray(expression.or)) {
      for (const subExpression of expression.or) {
        if (
          this.evaluateExpression(userPermissions, subExpression, depth + 1)
        ) {
          return true; // Short-circuit: OR succeeds on first true
        }
      }
      return false;
    }

    // NOT operation: sub-expression must be false
    if (expression.not) {
      return !this.evaluateExpression(
        userPermissions,
        expression.not,
        depth + 1
      );
    }

    // Invalid expression structure
    throw new Error(
      'Invalid expression: must have exactly one operation (permission, and, or, not)'
    );
  }

  /**
   * Evaluate expression with detailed result information
   */
  private evaluateExpressionWithDetails(
    userPermissions: Set<string>,
    expression: PermissionExpression,
    depth: number
  ): ExpressionEvaluationResult {
    const startTime = process.hrtime.bigint();
    const evaluatedPaths: string[] = [];
    let shortCircuited = false;

    // Enforce maximum nesting depth
    if (depth > this.maxNestingDepth) {
      throw new Error(
        `Expression nesting depth exceeds maximum of ${this.maxNestingDepth}`
      );
    }

    // Leaf node: direct permission check
    if (expression.permission) {
      const hasPermission = userPermissions.has(expression.permission);
      evaluatedPaths.push(
        `permission:${expression.permission}=${hasPermission}`
      );

      const endTime = process.hrtime.bigint();
      return {
        result: hasPermission,
        evaluatedPaths,
        shortCircuited: false,
        evaluationTimeUs: Number(endTime - startTime) / 1000,
      };
    }

    // AND operation: all sub-expressions must be true
    if (expression.and && Array.isArray(expression.and)) {
      for (let i = 0; i < expression.and.length; i++) {
        const subResult = this.evaluateExpressionWithDetails(
          userPermissions,
          expression.and[i],
          depth + 1
        );

        evaluatedPaths.push(`and[${i}]=${subResult.result}`);

        if (!subResult.result) {
          shortCircuited = true;
          const endTime = process.hrtime.bigint();
          return {
            result: false,
            evaluatedPaths,
            shortCircuited,
            evaluationTimeUs: Number(endTime - startTime) / 1000,
          };
        }
      }

      const endTime = process.hrtime.bigint();
      return {
        result: true,
        evaluatedPaths,
        shortCircuited: false,
        evaluationTimeUs: Number(endTime - startTime) / 1000,
      };
    }

    // OR operation: at least one sub-expression must be true
    if (expression.or && Array.isArray(expression.or)) {
      for (let i = 0; i < expression.or.length; i++) {
        const subResult = this.evaluateExpressionWithDetails(
          userPermissions,
          expression.or[i],
          depth + 1
        );

        evaluatedPaths.push(`or[${i}]=${subResult.result}`);

        if (subResult.result) {
          shortCircuited = true;
          const endTime = process.hrtime.bigint();
          return {
            result: true,
            evaluatedPaths,
            shortCircuited,
            evaluationTimeUs: Number(endTime - startTime) / 1000,
          };
        }
      }

      const endTime = process.hrtime.bigint();
      return {
        result: false,
        evaluatedPaths,
        shortCircuited: false,
        evaluationTimeUs: Number(endTime - startTime) / 1000,
      };
    }

    // NOT operation: sub-expression must be false
    if (expression.not) {
      const subResult = this.evaluateExpressionWithDetails(
        userPermissions,
        expression.not,
        depth + 1
      );

      evaluatedPaths.push(`not=${!subResult.result}`);

      const endTime = process.hrtime.bigint();
      return {
        result: !subResult.result,
        evaluatedPaths,
        shortCircuited: false,
        evaluationTimeUs: Number(endTime - startTime) / 1000,
      };
    }

    throw new Error('Invalid expression: must have exactly one operation');
  }

  /**
   * Track expression complexity for analytics
   */
  private trackComplexity(expression: PermissionExpression): void {
    const depth = this.getExpressionDepth(expression);

    if (depth === 0) {
      this.expressionComplexityStats.simple++;
    } else if (depth === 1) {
      this.expressionComplexityStats.moderate++;
    } else {
      this.expressionComplexityStats.complex++;
    }
  }

  /**
   * Get the depth of an expression
   */
  private getExpressionDepth(expression: PermissionExpression): number {
    if (expression.permission) {
      return 0; // Leaf node
    }

    let maxDepth = 0;

    if (expression.and) {
      for (const subExpr of expression.and) {
        maxDepth = Math.max(maxDepth, this.getExpressionDepth(subExpr) + 1);
      }
    }

    if (expression.or) {
      for (const subExpr of expression.or) {
        maxDepth = Math.max(maxDepth, this.getExpressionDepth(subExpr) + 1);
      }
    }

    if (expression.not) {
      maxDepth = Math.max(
        maxDepth,
        this.getExpressionDepth(expression.not) + 1
      );
    }

    return maxDepth;
  }

  /**
   * Get resolver type for identification
   */
  getType(): PermissionResolverType {
    return PermissionResolverType.EXPRESSION;
  }

  /**
   * Get performance characteristics for monitoring
   */
  getPerformanceCharacteristics(): PerformanceCharacteristics {
    return {
      timeComplexity: 'O(n) with caching, bounded by expression complexity',
      memoryUsage: 'medium',
      cacheUtilization: 'high',
      recommendedFor: [
        'Complex authorization scenarios',
        'Multi-criteria permission checks',
        'Role-based access with conditions',
        'Hierarchical permission systems',
      ],
    };
  }

  /**
   * Get performance statistics
   */
  getStats(): {
    checkCount: number;
    averageResolutionTimeUs: number;
    totalResolutionTimeUs: number;
    cacheHitRate: number;
    cacheHits: number;
    cacheMisses: number;
    complexityDistribution: {
      simple: number;
      moderate: number;
      complex: number;
    };
  } {
    const totalCacheRequests = this.cacheHits + this.cacheMisses;

    return {
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
      complexityDistribution: { ...this.expressionComplexityStats },
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
    this.expressionComplexityStats = {
      simple: 0,
      moderate: 0,
      complex: 0,
    };
  }

  /**
   * Get resolver name for debugging
   */
  getName(): string {
    return 'ExpressionPermissionResolver';
  }

  /**
   * Check if this resolver can handle the given requirement type
   */
  canHandle(requirement: any): requirement is PermissionExpression {
    return (
      requirement &&
<<<<<<< Updated upstream
      typeof requirement === 'object' &&
      PermissionUtils.isValidExpression(requirement)
=======
        typeof requirement === 'object' &&
        PermissionUtils.isValidExpression(requirement as PermissionExpression)
>>>>>>> Stashed changes
    );
  }

  /**
   * Normalize expression for consistent cache keys
   *
   * Sorts arrays and standardizes structure for reliable caching
   */
  static normalizeExpression(
    expression: PermissionExpression
  ): PermissionExpression {
    if (expression.permission) {
      return { permission: expression.permission };
    }

    if (expression.and) {
      return {
        and: expression.and
          .map((subExpr) => this.normalizeExpression(subExpr))
          .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      };
    }

    if (expression.or) {
      return {
        or: expression.or
          .map((subExpr) => this.normalizeExpression(subExpr))
          .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      };
    }

    if (expression.not) {
      return {
        not: this.normalizeExpression(expression.not),
      };
    }

    throw new Error('Invalid expression structure');
  }
}
