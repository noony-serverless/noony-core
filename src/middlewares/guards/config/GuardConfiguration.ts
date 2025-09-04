/**
 * Guard System Configuration
 *
 * Comprehensive configuration system for the high-performance guard system.
 * Provides type-safe configuration for different deployment environments with
 * configurable performance strategies and security policies.
 *
 * Key Features:
 * - Permission resolution strategy configuration (pre-expansion vs on-demand)
 * - Cache adapter injection for different environments
 * - Performance profiles for development, staging, and production
 * - Security policies with conservative cache invalidation
 * - Bounded complexity limits for patterns and expressions
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

/**
 * Permission resolution strategies for wildcard permissions
 *
 * PRE_EXPANSION: Expand wildcards at user context load time
 * - Pros: Faster runtime permission checks (O(1) set lookups)
 * - Cons: Higher memory usage, requires permission registry
 *
 * ON_DEMAND: Match wildcards at permission check time
 * - Pros: Lower memory usage, supports dynamic permissions
 * - Cons: Pattern matching overhead per request
 */
export enum PermissionResolutionStrategy {
  PRE_EXPANSION = 'pre-expansion',
  ON_DEMAND = 'on-demand',
}

/**
 * Cache invalidation strategies for security
 */
export enum CacheInvalidationStrategy {
  FLUSH_ALL = 'flush-all',
  USER_SPECIFIC = 'user-specific',
}

/**
 * Performance monitoring levels
 */
export enum MonitoringLevel {
  NONE = 'none',
  BASIC = 'basic',
  DETAILED = 'detailed',
  VERBOSE = 'verbose',
}

/**
 * Security configuration for the guard system
 */
export interface GuardSecurityConfig {
  permissionResolutionStrategy: PermissionResolutionStrategy;
  conservativeCacheInvalidation: boolean;
  maxExpressionComplexity: number;
  maxPatternDepth: number;
  maxNestingDepth: number;
}

/**
 * Cache configuration for the guard system
 */
export interface GuardCacheConfig {
  maxEntries: number;
  defaultTtlMs: number;
  userContextTtlMs: number;
  authTokenTtlMs: number;
}

/**
 * Monitoring configuration for the guard system
 */
export interface GuardMonitoringConfig {
  enablePerformanceTracking: boolean;
  enableDetailedLogging: boolean;
  logLevel: string;
  metricsCollectionInterval: number;
}

/**
 * Environment profile for guard system configuration
 */
export interface GuardEnvironmentProfile {
  environment: string;
  cacheType: 'memory' | 'redis' | 'none';
  security: GuardSecurityConfig;
  cache: GuardCacheConfig;
  monitoring: GuardMonitoringConfig;
}

/**
 * GuardConfiguration class implementation
 */
export class GuardConfiguration {
  public readonly security: GuardSecurityConfig;
  public readonly cache: GuardCacheConfig;
  public readonly monitoring: GuardMonitoringConfig;

  constructor(
    security: GuardSecurityConfig,
    cache: GuardCacheConfig,
    monitoring: GuardMonitoringConfig
  ) {
    this.security = security;
    this.cache = cache;
    this.monitoring = monitoring;
  }

  /**
   * Create GuardConfiguration from environment profile
   */
  static fromEnvironmentProfile(
    profile: GuardEnvironmentProfile
  ): GuardConfiguration {
    return new GuardConfiguration(
      profile.security,
      profile.cache,
      profile.monitoring
    );
  }

  /**
   * Create default development configuration
   */
  static development(): GuardConfiguration {
    return new GuardConfiguration(
      {
        permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
        conservativeCacheInvalidation: false,
        maxExpressionComplexity: 50,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      },
      {
        maxEntries: 500,
        defaultTtlMs: 5 * 60 * 1000, // 5 minutes
        userContextTtlMs: 2 * 60 * 1000, // 2 minutes
        authTokenTtlMs: 2 * 60 * 1000, // 2 minutes
      },
      {
        enablePerformanceTracking: true,
        enableDetailedLogging: true,
        logLevel: 'debug',
        metricsCollectionInterval: 30000, // 30 seconds
      }
    );
  }

  /**
   * Create default production configuration
   */
  static production(): GuardConfiguration {
    return new GuardConfiguration(
      {
        permissionResolutionStrategy:
          PermissionResolutionStrategy.PRE_EXPANSION,
        conservativeCacheInvalidation: true,
        maxExpressionComplexity: 100,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      },
      {
        maxEntries: 2000,
        defaultTtlMs: 15 * 60 * 1000, // 15 minutes
        userContextTtlMs: 10 * 60 * 1000, // 10 minutes
        authTokenTtlMs: 5 * 60 * 1000, // 5 minutes
      },
      {
        enablePerformanceTracking: true,
        enableDetailedLogging: false,
        logLevel: 'info',
        metricsCollectionInterval: 60000, // 1 minute
      }
    );
  }

  /**
   * Validate configuration
   */
  validate(): void {
    if (
      this.security.maxPatternDepth < 2 ||
      this.security.maxPatternDepth > 3
    ) {
      throw new Error('maxPatternDepth must be 2 or 3');
    }

    if (this.security.maxNestingDepth !== 2) {
      throw new Error('maxNestingDepth must be 2');
    }

    if (this.security.maxExpressionComplexity < 1) {
      throw new Error('maxExpressionComplexity must be positive');
    }

    if (this.cache.defaultTtlMs < 1000) {
      throw new Error('defaultTtlMs must be at least 1 second');
    }
  }
}
