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
 * Security configuration for the guard system.
 * Controls security policies and performance limits to prevent attacks.
 *
 * @example
 * High-security production configuration:
 * ```typescript
 * const securityConfig: GuardSecurityConfig = {
 *   permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
 *   conservativeCacheInvalidation: true,  // Clear related caches on any change
 *   maxExpressionComplexity: 100,         // Limit complex permission expressions
 *   maxPatternDepth: 3,                   // Limit wildcard nesting (admin.users.*)
 *   maxNestingDepth: 2                    // Limit boolean expression nesting
 * };
 * ```
 *
 * @example
 * Development configuration (more permissive):
 * ```typescript
 * const devSecurityConfig: GuardSecurityConfig = {
 *   permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
 *   conservativeCacheInvalidation: false, // Less aggressive caching for dev
 *   maxExpressionComplexity: 50,          // Lower limits for faster feedback
 *   maxPatternDepth: 3,
 *   maxNestingDepth: 2
 * };
 * ```
 */
export interface GuardSecurityConfig {
  /**
   * Strategy for resolving permissions (default: PRE_EXPANSION).
   * Controls when wildcards and expressions are processed for optimal performance.
   *
   * @example
   * Production setup with pre-expansion for performance:
   * ```typescript
   * permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION
   * ```
   */
  permissionResolutionStrategy?: PermissionResolutionStrategy;

  /**
   * Whether to use conservative cache invalidation (default: true).
   * When true, related cache entries are cleared on any permission change.
   * When false, only specific entries are invalidated (better performance).
   *
   * @example
   * High-security setup:
   * ```typescript
   * conservativeCacheInvalidation: true  // Clear all related caches on changes
   * ```
   */
  conservativeCacheInvalidation?: boolean;

  /**
   * Maximum complexity for permission expressions (default: 100).
   * Prevents DoS attacks through complex boolean expressions.
   *
   * @example
   * ```typescript
   * maxExpressionComplexity: 50  // Limit to moderate complexity
   * ```
   */
  maxExpressionComplexity?: number;

  /**
   * Maximum depth for wildcard patterns (default: 5).
   * Limits patterns like 'admin.users.groups.permissions.*' to prevent deep recursion.
   *
   * @example
   * ```typescript
   * maxPatternDepth: 3  // Allow up to 'admin.users.*' depth
   * ```
   */
  maxPatternDepth?: number;

  /**
   * Maximum nesting depth for boolean expressions (default: 3).
   * Prevents deeply nested expressions like '((((A AND B) OR C) AND D) OR E)'.
   *
   * @example
   * ```typescript
   * maxNestingDepth: 2  // Allow up to '(A AND B) OR (C AND D)' complexity
   * ```
   */
  maxNestingDepth?: number;
}

/**
 * Permission resolution strategies for wildcard permissions.
 * Determines how wildcard patterns are processed for optimal performance.
 *
 * @example
 * Pre-expansion strategy (production recommended):
 * ```typescript
 * const productionConfig = {
 *   permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
 *   // Expands "admin.*" to ["admin.users", "admin.reports", "admin.settings"]
 *   // at user context load time for O(1) runtime checks
 * };
 * ```
 *
 * @example
 * On-demand strategy (memory efficient):
 * ```typescript
 * const memoryEfficientConfig = {
 *   permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
 *   // Matches "admin.*" pattern against user permissions at runtime
 *   // Lower memory usage but requires pattern matching overhead
 * };
 * ```
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
 * Security configuration for the guard system.
 * Controls security policies and performance limits to prevent attacks.
 *
 * @example
 * High-security production configuration:
 * ```typescript
 * const securityConfig: GuardSecurityConfig = {
 *   permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
 *   conservativeCacheInvalidation: true,  // Clear related caches on any change
 *   maxExpressionComplexity: 100,         // Limit complex permission expressions
 *   maxPatternDepth: 3,                   // Limit wildcard nesting (admin.users.*)
 *   maxNestingDepth: 2                    // Limit boolean expression nesting
 * };
 * ```
 *
 * @example
 * Development configuration (more permissive):
 * ```typescript
 * const devSecurityConfig: GuardSecurityConfig = {
 *   permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
 *   conservativeCacheInvalidation: false, // Less aggressive caching for dev
 *   maxExpressionComplexity: 50,          // Lower limits for faster feedback
 *   maxPatternDepth: 3,
 *   maxNestingDepth: 2
/**
 * Cache configuration for the guard system.
 * Controls caching behavior for optimal performance with configurable TTL values.
 *
 * @example
 * Production cache configuration:
 * ```typescript
 * const cacheConfig: GuardCacheConfig = {
 *   maxEntries: 10000,         // Support up to 10k cached entries
 *   defaultTtlMs: 300000,      // 5 minutes default TTL
 *   userContextTtlMs: 600000,  // 10 minutes for user context
 *   authTokenTtlMs: 900000     // 15 minutes for auth tokens
 * };
 * ```
 *
 * @example
 * Development cache configuration (faster refresh):
 * ```typescript
 * const devCacheConfig: GuardCacheConfig = {
 *   maxEntries: 1000,          // Smaller cache for development
 *   defaultTtlMs: 60000,       // 1 minute default TTL
 *   userContextTtlMs: 120000,  // 2 minutes for user context
 *   authTokenTtlMs: 180000     // 3 minutes for auth tokens
 * };
 * ```
 */
export interface GuardCacheConfig {
  /**
   * Maximum number of entries to cache (default: 5000).
   * When limit is reached, LRU eviction is used.
   *
   * @example
   * ```typescript
   * maxEntries: 10000  // High-traffic production environment
   * ```
   */
  maxEntries: number;

  /**
   * Default TTL in milliseconds for cached entries (default: 300000 = 5 minutes).
   * Applied to general permission checks and guard evaluations.
   *
   * @example
   * ```typescript
   * defaultTtlMs: 600000  // 10 minutes for stable permissions
   * ```
   */
  defaultTtlMs: number;

  /**
   * TTL in milliseconds for user context cache (default: 600000 = 10 minutes).
   * User context includes roles, permissions, and session data.
   *
   * @example
   * ```typescript
   * userContextTtlMs: 900000  // 15 minutes for user sessions
   * ```
   */
  userContextTtlMs: number;

  /**
   * TTL in milliseconds for authentication token cache (default: 900000 = 15 minutes).
   * Controls how long validated tokens are cached before re-verification.
   *
   * @example
   * ```typescript
   * authTokenTtlMs: 1800000  // 30 minutes for production tokens
   * ```
   */
  authTokenTtlMs: number;
}

/**
 * Monitoring configuration for the guard system.
 * Controls performance tracking, logging, and metrics collection.
 *
 * @example
 * Production monitoring configuration:
 * ```typescript
 * const monitoringConfig: GuardMonitoringConfig = {
 *   enablePerformanceTracking: true,   // Track guard performance metrics
 *   enableDetailedLogging: false,      // Minimize log overhead in production
 *   logLevel: 'error',                 // Only log errors and warnings
 *   metricsCollectionInterval: 60000   // Collect metrics every minute
 * };
 * ```
 *
 * @example
 * Development monitoring configuration:
 * ```typescript
 * const devMonitoringConfig: GuardMonitoringConfig = {
 *   enablePerformanceTracking: true,   // Track performance for optimization
 *   enableDetailedLogging: true,       // Detailed logs for debugging
 *   logLevel: 'debug',                 // All log levels for development
 *   metricsCollectionInterval: 10000   // More frequent metrics collection
 * };
 * ```
 */
export interface GuardMonitoringConfig {
  /**
   * Enable performance tracking for guard operations (default: true).
   * Tracks timing data for permission resolution, cache hits/misses, etc.
   *
   * @example
   * ```typescript
   * enablePerformanceTracking: true  // Monitor guard performance
   * ```
   */
  enablePerformanceTracking: boolean;

  /**
   * Enable detailed logging for debugging (default: false in production).
   * Logs detailed information about guard evaluations and cache operations.
   *
   * @example
   * ```typescript
   * enableDetailedLogging: true  // Detailed logs for troubleshooting
   * ```
   */
  enableDetailedLogging: boolean;

  /**
   * Log level for guard system messages (default: 'info').
   * Controls verbosity of guard system logging.
   *
   * @example
   * ```typescript
   * logLevel: 'error'  // Only log errors in production
   * ```
   */
  logLevel: string;

  /**
   * Interval in milliseconds for metrics collection (default: 60000 = 1 minute).
   * Controls how often performance metrics are aggregated and reported.
   *
   * @example
   * ```typescript
   * metricsCollectionInterval: 30000  // Collect metrics every 30 seconds
   * ```
   */
  metricsCollectionInterval: number;
}

/**
 * Environment profile for guard system configuration.
 * Provides pre-configured profiles for different deployment environments.
 *
 * @example
 * Production environment profile:
 * ```typescript
 * const productionProfile: GuardEnvironmentProfile = {
 *   environment: 'production',
 *   cacheType: 'redis',                           // Redis for distributed caching
 *   security: {
 *     permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
 *     conservativeCacheInvalidation: true,
 *     maxExpressionComplexity: 100,
 *     maxPatternDepth: 5,
 *     maxNestingDepth: 3
 *   },
 *   cache: {
 *     maxEntries: 50000,
 *     defaultTtlMs: 600000,     // 10 minutes
 *     userContextTtlMs: 1800000, // 30 minutes
 *     authTokenTtlMs: 3600000   // 1 hour
 *   },
 *   monitoring: {
 *     enablePerformanceTracking: true,
 *     enableDetailedLogging: false,
 *     logLevel: 'error',
 *     metricsCollectionInterval: 60000
 *   }
 * };
 * ```
 *
 * @example
 * Development environment profile:
 * ```typescript
 * const developmentProfile: GuardEnvironmentProfile = {
 *   environment: 'development',
 *   cacheType: 'memory',                          // In-memory cache for dev
 *   security: {
 *     permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
 *     conservativeCacheInvalidation: false,
 *     maxExpressionComplexity: 50,
 *     maxPatternDepth: 3,
 *     maxNestingDepth: 2
 *   },
 *   cache: {
 *     maxEntries: 1000,
 *     defaultTtlMs: 60000,      // 1 minute
 *     userContextTtlMs: 120000, // 2 minutes
 *     authTokenTtlMs: 300000    // 5 minutes
 *   },
 *   monitoring: {
 *     enablePerformanceTracking: true,
 *     enableDetailedLogging: true,
 *     logLevel: 'debug',
 *     metricsCollectionInterval: 10000
 *   }
 * };
 * ```
 */
export interface GuardEnvironmentProfile {
  /**
   * Environment name identifier (e.g., 'development', 'staging', 'production').
   * Used for environment-specific logging and configuration selection.
   *
   * @example
   * ```typescript
   * environment: 'production'  // Identifies production environment
   * ```
   */
  environment: string;

  /**
   * Cache implementation type to use.
   * - 'memory': In-memory cache (single instance)
   * - 'redis': Redis distributed cache (multi-instance)
   * - 'none': No caching (testing/debug)
   *
   * @example
   * ```typescript
   * cacheType: 'redis'  // Use Redis for production distributed cache
   * ```
   */
  cacheType: 'memory' | 'redis' | 'none';

  /**
   * Security configuration for this environment.
   * Contains permission resolution strategies and security limits.
   */
  security: GuardSecurityConfig;

  /**
   * Cache configuration for this environment.
   * Contains cache size limits and TTL settings.
   */
  cache: GuardCacheConfig;

  /**
   * Monitoring configuration for this environment.
   * Contains logging and metrics collection settings.
   */
  monitoring: GuardMonitoringConfig;
}

/**
 * GuardConfiguration class implementation.
 * Immutable configuration object for the Noony guard system with factory methods
 * for creating configurations from environment profiles or predefined templates.
 *
 * @example
 * Create from environment profile:
 * ```typescript
 * import { GuardConfiguration } from '@noony/core';
 *
 * const config = GuardConfiguration.fromEnvironmentProfile({
 *   environment: 'production',
 *   cacheType: 'redis',
 *   security: { ... },
 *   cache: { ... },
 *   monitoring: { ... }
 * });
 * ```
 *
 * @example
 * Use predefined configurations:
 * ```typescript
 * // Development configuration
 * const devConfig = GuardConfiguration.development();
 *
 * // Production configuration
 * const prodConfig = GuardConfiguration.production();
 *
 * // Testing configuration
 * const testConfig = GuardConfiguration.testing();
 * ```
 *
 * @example
 * Manual configuration:
 * ```typescript
 * const customConfig = new GuardConfiguration(
 *   { permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION },
 *   { maxEntries: 10000, defaultTtlMs: 300000 },
 *   { enablePerformanceTracking: true, logLevel: 'info' }
 * );
 * ```
 */
export class GuardConfiguration {
  /**
   * Security configuration settings.
   * Contains permission resolution strategies and security limits.
   */
  public readonly security: GuardSecurityConfig;

  /**
   * Cache configuration settings.
   * Contains cache size limits and TTL values.
   */
  public readonly cache: GuardCacheConfig;

  /**
   * Monitoring configuration settings.
   * Contains logging and metrics collection settings.
   */
  public readonly monitoring: GuardMonitoringConfig;

  /**
   * Creates a new GuardConfiguration instance.
   *
   * @param security - Security configuration settings
   * @param cache - Cache configuration settings
   * @param monitoring - Monitoring configuration settings
   *
   * @example
   * ```typescript
   * const config = new GuardConfiguration(
   *   {
   *     permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
   *     conservativeCacheInvalidation: true,
   *     maxExpressionComplexity: 100
   *   },
   *   {
   *     maxEntries: 10000,
   *     defaultTtlMs: 300000,
   *     userContextTtlMs: 600000,
   *     authTokenTtlMs: 900000
   *   },
   *   {
   *     enablePerformanceTracking: true,
   *     enableDetailedLogging: false,
   *     logLevel: 'info',
   *     metricsCollectionInterval: 60000
   *   }
   * );
   * ```
   */
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
   * Create GuardConfiguration from environment profile.
   * Factory method that constructs a configuration from a complete environment profile.
   *
   * @param profile - Complete environment profile with all configuration sections
   * @returns New GuardConfiguration instance
   *
   * @example
   * Create from production profile:
   * ```typescript
   * const productionProfile: GuardEnvironmentProfile = {
   *   environment: 'production',
   *   cacheType: 'redis',
   *   security: {
   *     permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION,
   *     conservativeCacheInvalidation: true,
   *     maxExpressionComplexity: 100
   *   },
   *   cache: {
   *     maxEntries: 50000,
   *     defaultTtlMs: 600000,
   *     userContextTtlMs: 1800000,
   *     authTokenTtlMs: 3600000
   *   },
   *   monitoring: {
   *     enablePerformanceTracking: true,
   *     enableDetailedLogging: false,
   *     logLevel: 'error',
   *     metricsCollectionInterval: 60000
   *   }
   * };
   *
   * const config = GuardConfiguration.fromEnvironmentProfile(productionProfile);
   * ```
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
   * Create default development configuration.
   * Pre-configured settings optimized for development environments with fast refresh
   * and detailed logging for debugging.
   *
   * @returns GuardConfiguration optimized for development
   *
   * @example
   * ```typescript
   * const devConfig = GuardConfiguration.development();
   *
   * // Configuration includes:
   * // - On-demand permission resolution (lower memory, dynamic)
   * // - Conservative cache invalidation disabled (faster refresh)
   * // - Lower complexity limits for faster feedback
   * // - Shorter TTL values for rapid development cycles
   * // - Detailed logging and debug level
   * // - Frequent metrics collection (30 seconds)
   * ```
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
   * Create default production configuration.
   * Pre-configured settings optimized for production environments with high performance,
   * security, and stability.
   *
   * @returns GuardConfiguration optimized for production
   *
   * @example
   * ```typescript
   * const prodConfig = GuardConfiguration.production();
   *
   * // Configuration includes:
   * // - Pre-expansion permission resolution (high performance)
   * // - Conservative cache invalidation enabled (high security)
   * // - Higher complexity limits for production workloads
   * // - Longer TTL values for better performance
   * // - Performance tracking enabled, detailed logging disabled
   * // - Standard metrics collection (1 minute intervals)
   * ```
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
   * Validate configuration settings.
   * Ensures all configuration values are within acceptable bounds and constraints
   * to prevent security vulnerabilities and performance issues.
   *
   * @throws Error if any configuration value is invalid
   *
   * @example
   * ```typescript
   * const config = new GuardConfiguration(securityConfig, cacheConfig, monitoringConfig);
   *
   * try {
   *   config.validate();
   *   console.log('Configuration is valid');
   * } catch (error) {
   *   console.error('Invalid configuration:', error.message);
   *   // Handle configuration error
   * }
   * ```
   *
   * @example
   * Validation constraints:
   * ```typescript
   * // These will throw validation errors:
   * // maxPatternDepth must be 2 or 3 (prevents deep recursion)
   * // maxNestingDepth must be 2 (prevents complex expressions)
   * // maxExpressionComplexity must be positive
   * // defaultTtlMs must be at least 1000ms (1 second)
   * ```
   */
  /**
   * Check if caching is enabled via environment variable.
   *
   * Caching is disabled by default for security-first approach.
   * Only enabled when NOONY_GUARD_CACHE_ENABLE is explicitly set to 'true'.
   *
   * @returns true if caching should be enabled, false otherwise
   *
   * @example
   * ```typescript
   * // Caching disabled (default)
   * process.env.NOONY_GUARD_CACHE_ENABLE = undefined;
   * console.log(GuardConfiguration.isCachingEnabled()); // false
   *
   * // Caching enabled
   * process.env.NOONY_GUARD_CACHE_ENABLE = 'true';
   * console.log(GuardConfiguration.isCachingEnabled()); // true
   *
   * // Caching disabled (any other value)
   * process.env.NOONY_GUARD_CACHE_ENABLE = 'false';
   * console.log(GuardConfiguration.isCachingEnabled()); // false
   * ```
   */
  static isCachingEnabled(): boolean {
    return process.env.NOONY_GUARD_CACHE_ENABLE === 'true';
  }

  /**
   * Get effective cache type considering environment variable override.
   *
   * Environment variable takes precedence for security:
   * - If NOONY_GUARD_CACHE_ENABLE is not 'true', returns 'none'
   * - Otherwise returns the specified cacheType
   *
   * @param cacheType - Configured cache type
   * @returns Effective cache type after environment variable consideration
   *
   * @example
   * ```typescript
   * // Environment variable not set - caching disabled
   * process.env.NOONY_GUARD_CACHE_ENABLE = undefined;
   * console.log(GuardConfiguration.getEffectiveCacheType('memory')); // 'none'
   * console.log(GuardConfiguration.getEffectiveCacheType('redis')); // 'none'
   * console.log(GuardConfiguration.getEffectiveCacheType('none')); // 'none'
   *
   * // Environment variable enabled - respect cacheType
   * process.env.NOONY_GUARD_CACHE_ENABLE = 'true';
   * console.log(GuardConfiguration.getEffectiveCacheType('memory')); // 'memory'
   * console.log(GuardConfiguration.getEffectiveCacheType('redis')); // 'redis'
   * console.log(GuardConfiguration.getEffectiveCacheType('none')); // 'none'
   * ```
   */
  static getEffectiveCacheType(
    cacheType: 'memory' | 'redis' | 'none'
  ): 'memory' | 'redis' | 'none' {
    // If caching is disabled by environment variable, always return 'none'
    if (!GuardConfiguration.isCachingEnabled()) {
      return 'none';
    }

    // Otherwise return the specified cache type
    return cacheType;
  }

  validate(): void {
    if (
      this.security.maxPatternDepth !== undefined &&
      (this.security.maxPatternDepth < 2 || this.security.maxPatternDepth > 3)
    ) {
      throw new Error('maxPatternDepth must be 2 or 3');
    }

    if (
      this.security.maxNestingDepth !== undefined &&
      this.security.maxNestingDepth !== 2
    ) {
      throw new Error('maxNestingDepth must be 2');
    }

    if (
      this.security.maxExpressionComplexity !== undefined &&
      this.security.maxExpressionComplexity < 1
    ) {
      throw new Error('maxExpressionComplexity must be positive');
    }

    if (this.cache.defaultTtlMs < 1000) {
      throw new Error('defaultTtlMs must be at least 1 second');
    }
  }
}
