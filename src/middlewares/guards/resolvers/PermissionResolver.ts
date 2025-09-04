/**
 * Permission Resolution System
 *
 * Base interfaces and types for the three distinct permission resolution strategies:
 * - PlainPermissionResolver: Direct O(1) set membership checks
 * - WildcardPermissionResolver: Pattern matching with configurable strategies
 * - ExpressionPermissionResolver: Complex AND/OR/NOT expression evaluation
 *
 * Each resolver operates independently and cannot be combined on a single endpoint,
 * ensuring clear performance characteristics and simplified reasoning.
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

/**
 * Base interface for all permission resolvers
 *
 * Each resolver implements this interface with specific logic for handling
 * different types of permission requirements. The generic type T represents
 * the specific requirement format for each resolver.
 */
export abstract class PermissionResolver<T = any> {
  /**
   * Check if user permissions satisfy the requirement
   *
   * @param userPermissions - Set of user's permissions (for O(1) lookup)
   * @param requirement - The permission requirement to check against
   * @returns Promise resolving to true if user has access, false otherwise
   */
  abstract check(
    userPermissions: Set<string>,
    requirement: T
  ): Promise<boolean>;

  /**
   * Get the resolver type for debugging and metrics
   */
  abstract getType(): PermissionResolverType;

  /**
   * Get performance characteristics for monitoring
   */
  abstract getPerformanceCharacteristics(): PerformanceCharacteristics;
}

/**
 * Permission resolver types for identification
 */
export enum PermissionResolverType {
  PLAIN = 'plain',
  WILDCARD = 'wildcard',
  EXPRESSION = 'expression',
}

/**
 * Performance characteristics for each resolver type
 */
export interface PerformanceCharacteristics {
  /** Expected time complexity */
  timeComplexity: string;
  /** Memory usage pattern */
  memoryUsage: 'low' | 'medium' | 'high';
  /** Cache utilization */
  cacheUtilization: 'none' | 'low' | 'medium' | 'high';
  /** Recommended use cases */
  recommendedFor: string[];
}

/**
 * Permission expression types for complex permission requirements
 *
 * Supports AND/OR/NOT operations with maximum 2-level nesting to prevent
 * performance degradation from deeply nested expressions.
 */
export interface PermissionExpression {
  /** Logical AND operation - all sub-expressions must be true */
  and?: PermissionExpression[];

  /** Logical OR operation - at least one sub-expression must be true */
  or?: PermissionExpression[];

  /** Logical NOT operation - sub-expression must be false */
  not?: PermissionExpression;

  /** Leaf permission - actual permission string to check */
  permission?: string;
}

/**
 * Result of a permission check with additional metadata
 */
export interface PermissionCheckResult {
  /** Whether the permission check passed */
  allowed: boolean;

  /** Resolver type that performed the check */
  resolverType: PermissionResolverType;

  /** Time taken to resolve permission in microseconds */
  resolutionTimeUs: number;

  /** Whether the result was cached */
  cached: boolean;

  /** Reason for denial (if not allowed) */
  reason?: string;

  /** Matched permissions (for debugging) */
  matchedPermissions?: string[];
}

/**
 * Utility functions for working with permissions
 */
export class PermissionUtils {
  /**
   * Convert array of permissions to Set for O(1) lookups
   *
   * @param permissions - Array of permission strings
   * @returns Set of permissions for fast membership testing
   */
  static arrayToSet(permissions: string[]): Set<string> {
    return new Set(permissions);
  }

  /**
   * Validate permission string format
   *
   * Ensures permissions follow expected naming conventions:
   * - 2-3 levels separated by dots
   * - Only alphanumeric characters, dots, and hyphens
   * - No leading/trailing dots
   *
   * @param permission - Permission string to validate
   * @returns true if valid, false otherwise
   */
  static isValidPermission(permission: string): boolean {
    if (!permission || typeof permission !== 'string') {
      return false;
    }

    // Check for valid format: 2-3 levels, alphanumeric + dots + hyphens
    const validPattern = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+){1,2}$/;

    // Check for wildcard format: ends with .* for wildcards
    const wildcardPattern = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.\*$/;

    return validPattern.test(permission) || wildcardPattern.test(permission);
  }

  /**
   * Extract base permission from wildcard pattern
   *
   * @param wildcardPermission - Wildcard permission like "admin.*"
   * @returns Base permission like "admin"
   */
  static extractWildcardBase(wildcardPermission: string): string {
    if (wildcardPermission.endsWith('.*')) {
      return wildcardPermission.slice(0, -2);
    }
    return wildcardPermission;
  }

  /**
   * Check if a permission matches a wildcard pattern
   *
   * @param permission - Specific permission to test
   * @param wildcardPattern - Wildcard pattern to match against
   * @returns true if permission matches the pattern
   */
  static matchesWildcard(permission: string, wildcardPattern: string): boolean {
    if (!wildcardPattern.includes('*')) {
      return permission === wildcardPattern;
    }

    // Convert wildcard pattern to regex
    // "admin.*" becomes /^admin\.[^.]+$/
    // "admin.users.*" becomes /^admin\.users\.[^.]+$/
    const regexPattern = wildcardPattern
      .replace(/\./g, '\\.') // Escape dots
      .replace(/\*/g, '[^.]+'); // Replace * with non-dot characters

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(permission);
  }

  /**
   * Validate permission expression structure
   *
   * Ensures expressions follow the 2-level nesting limit and contain
   * valid permission strings.
   *
   * @param expression - Permission expression to validate
   * @param depth - Current nesting depth (internal use)
   * @returns true if valid, false otherwise
   */
  static isValidExpression(
    expression: PermissionExpression,
    depth: number = 0
  ): boolean {
    if (depth > 2) {
      return false; // Exceeds maximum nesting depth
    }

    // Must have exactly one operation type
    const operationCount = [
      expression.and ? 1 : 0,
      expression.or ? 1 : 0,
      expression.not ? 1 : 0,
      expression.permission ? 1 : 0,
    ].reduce((sum, count) => sum + count, 0);

    if (operationCount !== 1) {
      return false; // Must have exactly one operation
    }

    // Validate leaf permission
    if (expression.permission) {
      return this.isValidPermission(expression.permission);
    }

    // Validate AND operation
    if (expression.and) {
      if (!Array.isArray(expression.and) || expression.and.length === 0) {
        return false;
      }
      return expression.and.every((subExpr) =>
        this.isValidExpression(subExpr, depth + 1)
      );
    }

    // Validate OR operation
    if (expression.or) {
      if (!Array.isArray(expression.or) || expression.or.length === 0) {
        return false;
      }
      return expression.or.every((subExpr) =>
        this.isValidExpression(subExpr, depth + 1)
      );
    }

    // Validate NOT operation
    if (expression.not) {
      return this.isValidExpression(expression.not, depth + 1);
    }

    return false;
  }

  /**
   * Generate a stable hash for caching permission expressions
   *
   * @param expression - Permission expression to hash
   * @returns Stable string hash for cache keys
   */
  static hashExpression(expression: PermissionExpression): string {
    // Sort keys to ensure consistent serialization
    const sortedJson = JSON.stringify(
      expression,
      Object.keys(expression).sort()
    );
    return this.simpleHash(sortedJson);
  }

  /**
   * Simple hash function for string data (not cryptographically secure)
   */
  private static simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  }
}
