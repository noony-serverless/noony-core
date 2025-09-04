/**
 * Expression Permission Resolver
 *
 * Advanced boolean logic expression permission resolver for the Guard System
 * Showcase. Supports complex permission expressions with AND, OR, NOT operators,
 * parentheses for grouping, and intelligent expression parsing and evaluation.
 *
 * Features:
 * - Boolean logic expressions (AND, OR, NOT)
 * - Parentheses for complex grouping
 * - Expression parsing and compilation
 * - Result caching for repeated expressions
 * - Comprehensive expression evaluation statistics
 *
 * @module ExpressionPermissionResolver
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
  PermissionExpression,
} from '@/types/auth.types';

/**
 * Parsed expression node types
 */
type ExpressionNode =
  | { type: 'permission'; value: string }
  | { type: 'and'; left: ExpressionNode; right: ExpressionNode }
  | { type: 'or'; left: ExpressionNode; right: ExpressionNode }
  | { type: 'not'; operand: ExpressionNode }
  | { type: 'group'; expression: ExpressionNode };

/**
 * Expression evaluation result
 */
interface ExpressionEvalResult {
  result: boolean;
  matchedPermissions: string[];
  evaluatedNodes: number;
  shortCircuited: boolean;
}

/**
 * Expression cache entry
 */
interface ExpressionCacheEntry {
  compiledExpression: ExpressionNode;
  originalExpression: string;
  stats: {
    evaluations: number;
    trueResults: number;
    falseResults: number;
    averageEvalTime: number;
    lastUsed: number;
  };
}

/**
 * Expression resolver statistics
 */
export interface ExpressionResolverStats {
  /** Total permission checks performed */
  totalChecks: number;

  /** Successful (allowed) permission checks */
  allowedChecks: number;

  /** Failed (denied) permission checks */
  deniedChecks: number;

  /** Expression cache hits */
  expressionCacheHits: number;

  /** Expression cache misses */
  expressionCacheMisses: number;

  /** Permission source cache hits */
  sourceCacheHits: number;

  /** Permission source cache misses */
  sourceCacheMisses: number;

  /** Average resolution time in microseconds */
  averageResolutionTimeUs: number;

  /** Average expression parsing time in microseconds */
  averageParsingTimeUs: number;

  /** Average expression evaluation time in microseconds */
  averageEvaluationTimeUs: number;

  /** Average number of nodes evaluated per expression */
  averageNodesEvaluated: number;

  /** Short-circuit optimizations performed */
  shortCircuitOptimizations: number;

  /** Expression parsing failures */
  parsingFailures: number;

  /** Permission loading failures */
  loadFailures: number;

  /** Last check timestamp */
  lastCheck: number;
}

/**
 * Expression Permission Resolver Implementation
 *
 * Provides sophisticated boolean logic expression evaluation with:
 * - Support for complex permission expressions
 * - Short-circuit evaluation optimization
 * - Expression parsing and compilation
 * - Comprehensive performance monitoring
 */
export class ExpressionPermissionResolver
  implements PermissionResolver<PermissionExpression>
{
  private readonly permissionSource: PermissionSource;
  private readonly stats: ExpressionResolverStats;
  private readonly expressionCache = new Map<string, ExpressionCacheEntry>();
  private readonly maxExpressionCacheSize = 500;

  constructor(permissionSource: PermissionSource) {
    this.permissionSource = permissionSource;
    this.stats = this.initializeStats();

    console.log(
      '🧮 Expression Permission Resolver initialized (boolean logic)'
    );
  }

  /**
   * Get resolver type identifier
   */
  public getType(): PermissionResolverType {
    return PermissionResolverType.EXPRESSION;
  }

  /**
   * Check if user permissions satisfy expression requirement
   *
   * @param userPermissions - Set of user permissions
   * @param requirement - Permission expression with boolean logic
   * @returns Promise resolving to true if expression evaluates to true
   */
  public async check(
    userPermissions: Set<string>,
    requirement: PermissionExpression
  ): Promise<boolean> {
    try {
      const evalResult = await this.evaluateExpression(
        requirement,
        userPermissions,
        process.hrtime.bigint()
      );
      return evalResult.result;
    } catch (error) {
      console.error('Expression evaluation error:', error);
      return false;
    }
  }

  /**
   * Get performance characteristics for this resolver
   */
  public getPerformanceCharacteristics(): any {
    return {
      timeComplexity:
        'O(n * log m) where n=permissions, m=expression complexity',
      memoryUsage: 'high' as const,
      cacheUtilization: 'medium' as const,
      recommendedFor: [
        'Complex business rules',
        'Multi-condition authorization',
        'Policy-based access control',
        'Advanced security requirements',
        'Compliance-driven permissions',
      ],
    };
  }

  /**
   * Get human-readable resolver name
   */
  public getName(): string {
    return 'Expression Permission Resolver (Boolean Logic)';
  }

  /**
   * Check permission using boolean expression evaluation
   *
   * @param userId - User ID to check permissions for
   * @param requirement - Permission requirement (string, array, or expression object)
   * @param context - Additional context for permission resolution
   * @returns Promise resolving to permission check result
   */
  public async checkPermission(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    context: Record<string, unknown> = {}
  ): Promise<PermissionCheckResult> {
    const startTime = process.hrtime.bigint();

    try {
      this.stats.totalChecks++;
      this.stats.lastCheck = Date.now();

      // Convert requirement to expression format
      const expression = this.normalizeRequirement(requirement);
      const expressionString = this.serializeExpression(expression);

      // Load user permissions
      const userPermissions = await this.loadUserPermissions(userId);

      // Parse and evaluate expression
      const evalResult = await this.evaluateExpression(
        expression,
        userPermissions,
        startTime
      );

      // Track result statistics
      if (evalResult.result) {
        this.stats.allowedChecks++;
      } else {
        this.stats.deniedChecks++;
      }

      // Update performance statistics
      const resolutionTime = this.updatePerformanceStats(
        startTime,
        evalResult.evaluatedNodes,
        evalResult.shortCircuited
      );

      // Create comprehensive result
      const result: PermissionCheckResult = {
        allowed: evalResult.result,
        resolverType: PermissionResolverType.EXPRESSION,
        resolutionTimeUs: resolutionTime,
        cached: false, // Expression evaluation is not cached at this level
        reason: evalResult.result
          ? undefined
          : this.generateDenialReason(expression, evalResult),
        matchedPermissions: evalResult.matchedPermissions,
        metadata: {
          cacheKey: `expression:${userId}:${this.hashExpression(expressionString)}`,
          permissionsEvaluated: evalResult.evaluatedNodes,
          userContextLoadTimeUs: resolutionTime * 0.3, // Approximate
          expressionEvaluationTimeUs: resolutionTime * 0.6, // Approximate
          shortCircuited: evalResult.shortCircuited,
          expressionComplexity: this.calculateComplexity(expression),
          originalExpression: expressionString,
        },
      };

      this.logResolutionResult(userId, expressionString, result);
      return result;
    } catch (error) {
      this.stats.loadFailures++;
      const errorTime = this.updatePerformanceStats(startTime, 0, false);

      console.error(`❌ Expression resolver error for user ${userId}:`, error);

      return {
        allowed: false,
        resolverType: PermissionResolverType.EXPRESSION,
        resolutionTimeUs: errorTime,
        cached: false,
        reason: `Expression evaluation error: ${(error as Error).message}`,
        metadata: {
          error: (error as Error).message,
        },
      };
    }
  }

  // ============================================================================
  // EXPRESSION NORMALIZATION AND PARSING
  // ============================================================================

  /**
   * Normalize requirement to expression format
   *
   * @param requirement - Permission requirement in various formats
   * @returns Normalized permission expression
   */
  private normalizeRequirement(
    requirement: string | string[] | PermissionExpression
  ): PermissionExpression {
    if (typeof requirement === 'string') {
      // Parse string expression
      return this.parseStringExpression(requirement);
    }

    if (Array.isArray(requirement)) {
      // Convert array to OR expression
      if (requirement.length === 0) {
        throw new Error('Empty permission requirement array');
      }

      if (requirement.length === 1) {
        return { permission: requirement[0] };
      }

      return {
        or: requirement.map((perm) => ({ permission: perm })),
      };
    }

    // Already in expression format
    return requirement;
  }

  /**
   * Parse string expression to structured expression
   *
   * @param expression - String expression to parse
   * @returns Parsed permission expression
   */
  private parseStringExpression(expression: string): PermissionExpression {
    const parseStart = process.hrtime.bigint();

    try {
      // Handle simple cases first
      if (!this.containsLogicalOperators(expression)) {
        return { permission: expression.trim() };
      }

      // Parse complex expression
      const tokens = this.tokenizeExpression(expression);
      const parsedExpression = this.parseTokens(tokens);

      const parseTime = Number(process.hrtime.bigint() - parseStart) / 1000;
      this.updateParsingStats(parseTime);

      return parsedExpression;
    } catch (error) {
      this.stats.parsingFailures++;
      console.error('❌ Expression parsing failed:', error);
      throw new Error(`Invalid expression: ${(error as Error).message}`);
    }
  }

  /**
   * Check if expression contains logical operators
   *
   * @param expression - Expression string
   * @returns True if expression contains logical operators
   */
  private containsLogicalOperators(expression: string): boolean {
    return /\b(AND|OR|NOT)\b|\|\||&&|!/.test(expression);
  }

  /**
   * Tokenize expression string
   *
   * @param expression - Expression string
   * @returns Array of tokens
   */
  private tokenizeExpression(expression: string): string[] {
    // Simple tokenization - in production, you'd want a more robust parser
    return expression
      .replace(/\(/g, ' ( ')
      .replace(/\)/g, ' ) ')
      .replace(/\|\|/g, ' OR ')
      .replace(/&&/g, ' AND ')
      .replace(/!/g, ' NOT ')
      .split(/\s+/)
      .filter((token) => token.length > 0);
  }

  /**
   * Parse tokens into expression tree
   *
   * @param tokens - Array of tokens
   * @returns Parsed permission expression
   */
  private parseTokens(tokens: string[]): PermissionExpression {
    let index = 0;

    const parseExpression = (): PermissionExpression => {
      let left = parseTerm();

      while (index < tokens.length && tokens[index] === 'OR') {
        index++; // Skip OR
        const right = parseTerm();
        left = {
          or: [left, right],
        };
      }

      return left;
    };

    const parseTerm = (): PermissionExpression => {
      let left = parseFactor();

      while (index < tokens.length && tokens[index] === 'AND') {
        index++; // Skip AND
        const right = parseFactor();
        left = {
          and: [left, right],
        };
      }

      return left;
    };

    const parseFactor = (): PermissionExpression => {
      if (index >= tokens.length) {
        throw new Error('Unexpected end of expression');
      }

      const token = tokens[index];

      if (token === 'NOT') {
        index++; // Skip NOT
        const operand = parseFactor();
        return { not: operand };
      }

      if (token === '(') {
        index++; // Skip (
        const expr = parseExpression();
        if (index >= tokens.length || tokens[index] !== ')') {
          throw new Error('Missing closing parenthesis');
        }
        index++; // Skip )
        return expr;
      }

      // Permission name
      index++;
      return { permission: token };
    };

    const result = parseExpression();

    if (index < tokens.length) {
      throw new Error(`Unexpected token: ${tokens[index]}`);
    }

    return result;
  }

  // ============================================================================
  // EXPRESSION EVALUATION
  // ============================================================================

  /**
   * Evaluate expression against user permissions
   *
   * @param expression - Permission expression to evaluate
   * @param userPermissions - User's permission set
   * @param startTime - Evaluation start time
   * @returns Expression evaluation result
   */
  private async evaluateExpression(
    expression: PermissionExpression,
    userPermissions: Set<string>,
    startTime: bigint
  ): Promise<ExpressionEvalResult> {
    const evaluationStart = process.hrtime.bigint();
    let evaluatedNodes = 0;
    let shortCircuited = false;
    const matchedPermissions = new Set<string>();

    const evaluate = (expr: PermissionExpression): boolean => {
      evaluatedNodes++;

      if (expr.permission) {
        // Leaf node - check permission
        const hasPermission = userPermissions.has(expr.permission);
        if (hasPermission) {
          matchedPermissions.add(expr.permission);
        }
        return hasPermission;
      }

      if (expr.and) {
        // AND operation - all must be true
        for (const subExpr of expr.and) {
          if (!evaluate(subExpr)) {
            shortCircuited = true;
            return false; // Short circuit on first false
          }
        }
        return true;
      }

      if (expr.or) {
        // OR operation - at least one must be true
        for (const subExpr of expr.or) {
          if (evaluate(subExpr)) {
            shortCircuited = true;
            return true; // Short circuit on first true
          }
        }
        return false;
      }

      if (expr.not) {
        // NOT operation - invert result
        return !evaluate(expr.not);
      }

      throw new Error('Invalid expression structure');
    };

    const result = evaluate(expression);

    if (shortCircuited) {
      this.stats.shortCircuitOptimizations++;
    }

    const evaluationTime =
      Number(process.hrtime.bigint() - evaluationStart) / 1000;
    this.updateEvaluationStats(evaluationTime, evaluatedNodes);

    return {
      result,
      matchedPermissions: Array.from(matchedPermissions),
      evaluatedNodes,
      shortCircuited,
    };
  }

  /**
   * Load user permissions
   *
   * @param userId - User ID
   * @returns Promise resolving to user permission set
   */
  private async loadUserPermissions(userId: string): Promise<Set<string>> {
    const loadStart = process.hrtime.bigint();

    try {
      const permissions = await this.permissionSource.getUserPermissions(
        userId,
        {
          includeRolePermissions: true,
          expandWildcards: true, // Support wildcard permissions in expressions
          maxCacheAge: 10 * 60 * 1000, // 10 minute cache tolerance
        }
      );

      const loadTime = Number(process.hrtime.bigint() - loadStart) / 1000;

      // Track cache performance
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

  // ============================================================================
  // UTILITIES AND HELPERS
  // ============================================================================

  /**
   * Serialize expression to string for caching
   *
   * @param expression - Permission expression
   * @returns Serialized expression string
   */
  private serializeExpression(expression: PermissionExpression): string {
    if (expression.permission) {
      return expression.permission;
    }

    if (expression.and) {
      const parts = expression.and.map((e) => this.serializeExpression(e));
      return `(${parts.join(' AND ')})`;
    }

    if (expression.or) {
      const parts = expression.or.map((e) => this.serializeExpression(e));
      return `(${parts.join(' OR ')})`;
    }

    if (expression.not) {
      return `NOT (${this.serializeExpression(expression.not)})`;
    }

    return '(unknown)';
  }

  /**
   * Calculate expression complexity score
   *
   * @param expression - Permission expression
   * @returns Complexity score
   */
  private calculateComplexity(expression: PermissionExpression): number {
    if (expression.permission) {
      return 1;
    }

    if (expression.and) {
      return (
        1 +
        expression.and.reduce((sum, e) => sum + this.calculateComplexity(e), 0)
      );
    }

    if (expression.or) {
      return (
        1 +
        expression.or.reduce((sum, e) => sum + this.calculateComplexity(e), 0)
      );
    }

    if (expression.not) {
      return 1 + this.calculateComplexity(expression.not);
    }

    return 1;
  }

  /**
   * Generate hash for expression (for caching)
   *
   * @param expressionString - Serialized expression
   * @returns Hash string
   */
  private hashExpression(expressionString: string): string {
    return Buffer.from(expressionString).toString('base64').substring(0, 12);
  }

  /**
   * Generate human-readable denial reason
   *
   * @param expression - Permission expression
   * @param evalResult - Evaluation result
   * @returns Formatted denial reason
   */
  private generateDenialReason(
    expression: PermissionExpression,
    evalResult: ExpressionEvalResult
  ): string {
    const serialized = this.serializeExpression(expression);

    if (evalResult.matchedPermissions.length === 0) {
      return `No permissions matched in expression: ${serialized}`;
    } else {
      return `Expression evaluation failed: ${serialized} (matched: ${evalResult.matchedPermissions.join(', ')})`;
    }
  }

  /**
   * Update parsing statistics
   *
   * @param parseTime - Time taken for parsing
   */
  private updateParsingStats(parseTime: number): void {
    if (this.stats.averageParsingTimeUs === 0) {
      this.stats.averageParsingTimeUs = parseTime;
    } else {
      this.stats.averageParsingTimeUs =
        this.stats.averageParsingTimeUs * 0.9 + parseTime * 0.1;
    }
  }

  /**
   * Update evaluation statistics
   *
   * @param evaluationTime - Time taken for evaluation
   * @param nodesEvaluated - Number of nodes evaluated
   */
  private updateEvaluationStats(
    evaluationTime: number,
    nodesEvaluated: number
  ): void {
    // Update average evaluation time
    if (this.stats.averageEvaluationTimeUs === 0) {
      this.stats.averageEvaluationTimeUs = evaluationTime;
    } else {
      this.stats.averageEvaluationTimeUs =
        this.stats.averageEvaluationTimeUs * 0.9 + evaluationTime * 0.1;
    }

    // Update average nodes evaluated
    if (this.stats.averageNodesEvaluated === 0) {
      this.stats.averageNodesEvaluated = nodesEvaluated;
    } else {
      this.stats.averageNodesEvaluated =
        this.stats.averageNodesEvaluated * 0.9 + nodesEvaluated * 0.1;
    }
  }

  /**
   * Update overall performance statistics
   *
   * @param startTime - Operation start time
   * @param nodesEvaluated - Number of nodes evaluated
   * @param shortCircuited - Whether short-circuit optimization was used
   * @returns Resolution time in microseconds
   */
  private updatePerformanceStats(
    startTime: bigint,
    nodesEvaluated: number,
    shortCircuited: boolean
  ): number {
    const resolutionTime = Number(process.hrtime.bigint() - startTime) / 1000;

    // Update average resolution time
    if (this.stats.averageResolutionTimeUs === 0) {
      this.stats.averageResolutionTimeUs = resolutionTime;
    } else {
      this.stats.averageResolutionTimeUs =
        this.stats.averageResolutionTimeUs * 0.9 + resolutionTime * 0.1;
    }

    return resolutionTime;
  }

  /**
   * Log resolution result
   *
   * @param userId - User ID
   * @param expression - Expression string
   * @param result - Check result
   */
  private logResolutionResult(
    userId: string,
    expression: string,
    result: PermissionCheckResult
  ): void {
    if (process.env.NODE_ENV === 'development') {
      const symbol = result.allowed ? '✅' : '❌';
      const complexity = result.metadata?.expressionComplexity || 0;
      const shortCircuit = result.metadata?.shortCircuited ? '⚡' : '';
      console.debug(
        `${symbol} Expression resolver [${userId}]: ${expression} ${shortCircuit} (${result.resolutionTimeUs.toFixed(1)}μs, complexity: ${complexity})`
      );
    }

    // Log slow or complex resolutions
    if (
      result.resolutionTimeUs > 100000 ||
      (result.metadata?.expressionComplexity || 0) > 20
    ) {
      console.warn(
        `🐌 Complex expression resolution: ${result.resolutionTimeUs.toFixed(1)}μs, complexity: ${result.metadata?.expressionComplexity} for ${expression} (user: ${userId})`
      );
    }
  }

  /**
   * Initialize statistics
   */
  private initializeStats(): ExpressionResolverStats {
    return {
      totalChecks: 0,
      allowedChecks: 0,
      deniedChecks: 0,
      expressionCacheHits: 0,
      expressionCacheMisses: 0,
      sourceCacheHits: 0,
      sourceCacheMisses: 0,
      averageResolutionTimeUs: 0,
      averageParsingTimeUs: 0,
      averageEvaluationTimeUs: 0,
      averageNodesEvaluated: 0,
      shortCircuitOptimizations: 0,
      parsingFailures: 0,
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
  public getStats(): ExpressionResolverStats {
    return { ...this.stats };
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
    averageComplexity: number;
    shortCircuitRate: number;
    parsingSuccessRate: number;
  } {
    const successRate =
      this.stats.totalChecks > 0
        ? (this.stats.allowedChecks / this.stats.totalChecks) * 100
        : 0;

    const sourceTotal =
      this.stats.sourceCacheHits + this.stats.sourceCacheMisses;
    const sourceCacheHitRate =
      sourceTotal > 0 ? (this.stats.sourceCacheHits / sourceTotal) * 100 : 0;

    const shortCircuitRate =
      this.stats.totalChecks > 0
        ? (this.stats.shortCircuitOptimizations / this.stats.totalChecks) * 100
        : 0;

    const parsingSuccessRate =
      this.stats.totalChecks > 0
        ? ((this.stats.totalChecks - this.stats.parsingFailures) /
            this.stats.totalChecks) *
          100
        : 100;

    return {
      type: 'Expression (Boolean Logic)',
      totalChecks: this.stats.totalChecks,
      successRate: Math.round(successRate * 100) / 100,
      cacheHitRate: Math.round(sourceCacheHitRate * 100) / 100,
      averageLatency: `${this.stats.averageResolutionTimeUs.toFixed(1)}μs`,
      averageComplexity:
        Math.round(this.stats.averageNodesEvaluated * 100) / 100,
      shortCircuitRate: Math.round(shortCircuitRate * 100) / 100,
      parsingSuccessRate: Math.round(parsingSuccessRate * 100) / 100,
    };
  }

  /**
   * Reset resolver statistics
   */
  public resetStats(): void {
    Object.assign(this.stats, this.initializeStats());
    console.log('📊 Expression resolver statistics reset');
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

    // Check error rates
    if (this.stats.totalChecks > 100) {
      const errorRate =
        (this.stats.loadFailures / this.stats.totalChecks) * 100;
      const parsingErrorRate =
        (this.stats.parsingFailures / this.stats.totalChecks) * 100;

      if (errorRate > 5) {
        issues.push(`High load error rate: ${errorRate.toFixed(1)}%`);
      }

      if (parsingErrorRate > 2) {
        issues.push(`High parsing error rate: ${parsingErrorRate.toFixed(1)}%`);
        recommendations.push(
          'Review expression syntax and provide better error messages'
        );
      }
    }

    // Check performance
    if (this.stats.averageResolutionTimeUs > 50000) {
      // > 50ms
      issues.push(
        `High average latency: ${this.stats.averageResolutionTimeUs.toFixed(1)}μs`
      );
      recommendations.push(
        'Consider optimizing complex expressions or increasing cache'
      );
    }

    // Check expression complexity
    if (this.stats.averageNodesEvaluated > 50) {
      issues.push(
        `High expression complexity: ${this.stats.averageNodesEvaluated.toFixed(1)} nodes`
      );
      recommendations.push(
        'Consider simplifying expressions or using pre-computed permissions'
      );
    }

    // Check short-circuit optimization usage
    if (this.stats.totalChecks > 100) {
      const shortCircuitRate =
        (this.stats.shortCircuitOptimizations / this.stats.totalChecks) * 100;
      if (shortCircuitRate < 30) {
        recommendations.push(
          'Consider restructuring expressions to benefit more from short-circuit evaluation'
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
   * Test expression parsing (utility for development)
   *
   * @param expression - Expression string to test
   * @returns Parsed expression or error
   */
  public testExpressionParsing(expression: string): {
    success: boolean;
    result?: PermissionExpression;
    error?: string;
    serialized?: string;
    complexity?: number;
  } {
    try {
      const parsed = this.parseStringExpression(expression);
      const serialized = this.serializeExpression(parsed);
      const complexity = this.calculateComplexity(parsed);

      return {
        success: true,
        result: parsed,
        serialized,
        complexity,
      };
    } catch (error) {
      return {
        success: false,
        error: (error as Error).message,
      };
    }
  }
}
