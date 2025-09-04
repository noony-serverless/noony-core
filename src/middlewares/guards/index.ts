/**
 * Noony Guards - High-Performance Permission System
 *
 * A comprehensive permission and authentication system designed for serverless
 * environments with sub-millisecond cached permission checks.
 *
 * Features:
 * - Multi-layer caching (L1 memory + L2 distributed)
 * - Three distinct permission resolution strategies
 * - Conservative cache invalidation for security
 * - NestJS-inspired guard decorators and middleware
 * - Framework-agnostic middleware integration
 * - Comprehensive monitoring and audit trails
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

// Main facade - primary entry point
export {
  RouteGuards,
  RouteGuardOptions,
  GuardSystemStats,
} from './RouteGuards';

// Configuration
export {
  GuardConfiguration,
  GuardEnvironmentProfile,
  PermissionResolutionStrategy,
  GuardSecurityConfig,
  GuardCacheConfig,
  GuardMonitoringConfig,
} from './config/GuardConfiguration';

// Cache system
export {
  CacheAdapter,
  CacheStats,
  CacheKeyBuilder,
} from './cache/CacheAdapter';
export { MemoryCacheAdapter } from './cache/MemoryCacheAdapter';
export { NoopCacheAdapter } from './cache/NoopCacheAdapter';
export {
  ConservativeCacheInvalidation,
  CacheInvalidationEvent,
  InvalidationType,
  InvalidationScope,
} from './cache/ConservativeCacheInvalidation';

// Permission resolvers
export {
  PermissionResolver,
  PermissionResolverType,
  PermissionCheckResult,
  PermissionExpression,
  PermissionUtils,
  PerformanceCharacteristics,
} from './resolvers/PermissionResolver';
export { PlainPermissionResolver } from './resolvers/PlainPermissionResolver';
export { WildcardPermissionResolver } from './resolvers/WildcardPermissionResolver';
export { ExpressionPermissionResolver } from './resolvers/ExpressionPermissionResolver';

// Permission registry
export { PermissionRegistry } from './registry/PermissionRegistry';

// Services
export {
  FastUserContextService,
  UserContext,
  UserPermissionSource,
  PermissionCheckOptions,
} from './services/FastUserContextService';

// Guards
export {
  FastAuthGuard,
  AuthenticationResult,
  AuthGuardConfig,
  TokenValidator,
} from './guards/FastAuthGuard';
export {
  PermissionGuardFactory,
  GuardConfig,
} from './guards/PermissionGuardFactory';

// Utility types and constants
export const GUARD_DEFAULTS = {
  CACHE_TTL_MS: 15 * 60 * 1000, // 15 minutes
  AUTH_TOKEN_TTL_MS: 5 * 60 * 1000, // 5 minutes
  MAX_CACHE_ENTRIES: 1000,
  MAX_EXPRESSION_COMPLEXITY: 100,
  MAX_PATTERN_DEPTH: 3,
  MAX_NESTING_DEPTH: 2,
} as const;

export const PERMISSION_PATTERNS = {
  VALID_PERMISSION:
    /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){1,2}(\*)?$/,
  WILDCARD_SUFFIX: /\*$/,
  PERMISSION_PARTS: /\./,
} as const;

// Import the types we need for the class methods
import {
  GuardEnvironmentProfile,
  PermissionResolutionStrategy,
} from './config/GuardConfiguration';

/**
 * Quick setup helper for common configurations
 */
export class GuardSetup {
  /**
   * Development environment setup
   */
  static development(): GuardEnvironmentProfile {
    return {
      environment: 'development',
      cacheType: 'memory',
      security: {
        permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
        conservativeCacheInvalidation: false,
        maxExpressionComplexity: 50,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      },
      cache: {
        maxEntries: 500,
        defaultTtlMs: 5 * 60 * 1000, // 5 minutes
        userContextTtlMs: 2 * 60 * 1000, // 2 minutes
        authTokenTtlMs: 2 * 60 * 1000, // 2 minutes
      },
      monitoring: {
        enablePerformanceTracking: true,
        enableDetailedLogging: true,
        logLevel: 'debug',
        metricsCollectionInterval: 30000, // 30 seconds
      },
    };
  }

  /**
   * Production environment setup
   */
  static production(): GuardEnvironmentProfile {
    return {
      environment: 'production',
      cacheType: 'memory', // Would be 'redis' in real production
      security: {
        permissionResolutionStrategy:
          PermissionResolutionStrategy.PRE_EXPANSION,
        conservativeCacheInvalidation: true,
        maxExpressionComplexity: 100,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      },
      cache: {
        maxEntries: 2000,
        defaultTtlMs: 15 * 60 * 1000, // 15 minutes
        userContextTtlMs: 10 * 60 * 1000, // 10 minutes
        authTokenTtlMs: 5 * 60 * 1000, // 5 minutes
      },
      monitoring: {
        enablePerformanceTracking: true,
        enableDetailedLogging: false,
        logLevel: 'info',
        metricsCollectionInterval: 60000, // 1 minute
      },
    };
  }

  /**
   * Serverless environment setup (optimized for cold starts)
   */
  static serverless(): GuardEnvironmentProfile {
    return {
      environment: 'serverless',
      cacheType: 'memory',
      security: {
        permissionResolutionStrategy:
          PermissionResolutionStrategy.PRE_EXPANSION,
        conservativeCacheInvalidation: true,
        maxExpressionComplexity: 75,
        maxPatternDepth: 2, // Reduced for faster cold starts
        maxNestingDepth: 2,
      },
      cache: {
        maxEntries: 1000,
        defaultTtlMs: 10 * 60 * 1000, // 10 minutes
        userContextTtlMs: 5 * 60 * 1000, // 5 minutes
        authTokenTtlMs: 3 * 60 * 1000, // 3 minutes
      },
      monitoring: {
        enablePerformanceTracking: true,
        enableDetailedLogging: false,
        logLevel: 'warn',
        metricsCollectionInterval: 120000, // 2 minutes
      },
    };
  }

  /**
   * Testing environment setup
   */
  static testing(): GuardEnvironmentProfile {
    return {
      environment: 'testing',
      cacheType: 'none', // Disable caching for predictable tests
      security: {
        permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
        conservativeCacheInvalidation: false,
        maxExpressionComplexity: 25,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      },
      cache: {
        maxEntries: 100,
        defaultTtlMs: 1000, // 1 second
        userContextTtlMs: 1000,
        authTokenTtlMs: 1000,
      },
      monitoring: {
        enablePerformanceTracking: false,
        enableDetailedLogging: true,
        logLevel: 'debug',
        metricsCollectionInterval: 1000, // 1 second
      },
    };
  }
}
