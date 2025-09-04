/**
 * Token Validator Factory
 *
 * Factory for creating and managing different types of token validators
 * in the Guard System Showcase. Provides centralized validator instantiation,
 * configuration management, and runtime switching between validators.
 *
 * Features:
 * - Support for multiple authentication providers (JWT, Firebase, Auth0, Custom)
 * - Lazy initialization for performance optimization
 * - Configuration validation and error handling
 * - Validator health monitoring and statistics
 * - Hot-swapping validators for A/B testing or failover
 *
 * @module TokenValidatorFactory
 * @version 1.0.0
 */

import {
  JWTTokenValidator,
  JWTValidatorConfig,
} from './token-validators/jwt-token-validator';
import {
  FirebaseTokenValidator,
  FirebaseValidatorConfig,
} from './token-validators/firebase-token-validator';
import { BaseTokenValidator } from './token-validators/base-token-validator';
import { AuthProviderType, TokenValidationResult } from '@/types/auth.types';

/**
 * Validator factory configuration
 */
export interface ValidatorFactoryConfig {
  /** Primary authentication provider */
  primaryProvider: AuthProviderType;

  /** Fallback providers (in order of preference) */
  fallbackProviders?: AuthProviderType[];

  /** Provider-specific configurations */
  providers: {
    [AuthProviderType.JWT]?: JWTValidatorConfig;
    [AuthProviderType.FIREBASE]?: FirebaseValidatorConfig;
    [AuthProviderType.AUTH0]?: Record<string, unknown>; // TODO: Implement Auth0 config
    [AuthProviderType.CUSTOM]?: Record<string, unknown>; // TODO: Implement custom config
  };

  /** Factory-wide settings */
  settings: {
    /** Enable automatic failover to fallback providers */
    enableFailover: boolean;

    /** Maximum failover attempts per request */
    maxFailoverAttempts: number;

    /** Circuit breaker threshold (consecutive failures) */
    circuitBreakerThreshold: number;

    /** Circuit breaker reset timeout (milliseconds) */
    circuitBreakerResetTimeout: number;

    /** Enable validator health monitoring */
    enableHealthMonitoring: boolean;

    /** Health check interval (milliseconds) */
    healthCheckInterval: number;
  };
}

/**
 * Validator health status
 */
export interface ValidatorHealth {
  /** Provider type */
  provider: AuthProviderType;

  /** Whether validator is healthy */
  healthy: boolean;

  /** Last health check timestamp */
  lastCheck: number;

  /** Consecutive failures */
  consecutiveFailures: number;

  /** Circuit breaker status */
  circuitBreakerOpen: boolean;

  /** Success rate (0-100) */
  successRate: number;

  /** Average response time (microseconds) */
  averageResponseTime: number;

  /** Error details (if unhealthy) */
  error?: string;
}

/**
 * Token Validator Factory
 *
 * Centralized factory for creating and managing token validators with:
 * - Multi-provider support with automatic failover
 * - Circuit breaker pattern for resilience
 * - Health monitoring and statistics
 * - Runtime validator switching
 * - Configuration validation and hot-reloading
 */
export class TokenValidatorFactory {
  private static instance: TokenValidatorFactory;
  private readonly config: ValidatorFactoryConfig;
  private readonly validators = new Map<AuthProviderType, BaseTokenValidator>();
  private readonly healthStatus = new Map<AuthProviderType, ValidatorHealth>();
  private healthMonitoringInterval?: NodeJS.Timeout;

  constructor(config: ValidatorFactoryConfig) {
    this.config = this.validateFactoryConfig(config);
    this.initializeHealthMonitoring();

    console.log(
      `🏭 Token Validator Factory initialized with primary provider: ${this.config.primaryProvider}`
    );
  }

  /**
   * Get singleton instance (if using singleton pattern)
   */
  public static getInstance(
    config?: ValidatorFactoryConfig
  ): TokenValidatorFactory {
    if (!TokenValidatorFactory.instance) {
      if (!config) {
        throw new Error(
          'Configuration required for first TokenValidatorFactory instantiation'
        );
      }
      TokenValidatorFactory.instance = new TokenValidatorFactory(config);
    }
    return TokenValidatorFactory.instance;
  }

  // ============================================================================
  // VALIDATOR CREATION AND MANAGEMENT
  // ============================================================================

  /**
   * Get validator for specified provider type
   *
   * @param providerType - Authentication provider type
   * @returns Token validator instance
   * @throws Error if provider not configured or validator creation fails
   */
  public getValidator(providerType?: AuthProviderType): BaseTokenValidator {
    const targetProvider = providerType || this.config.primaryProvider;

    // Check if validator is already created and healthy
    let validator = this.validators.get(targetProvider);
    if (validator && this.isValidatorHealthy(targetProvider)) {
      return validator;
    }

    // Create new validator if needed
    if (!validator) {
      validator = this.createValidator(targetProvider);
      this.validators.set(targetProvider, validator);
    }

    // Check circuit breaker status
    if (this.isCircuitBreakerOpen(targetProvider)) {
      throw new Error(`Circuit breaker open for provider: ${targetProvider}`);
    }

    return validator;
  }

  /**
   * Get primary validator with failover support
   *
   * @returns Primary token validator or fallback validator
   * @throws Error if no healthy validators available
   */
  public getPrimaryValidator(): BaseTokenValidator {
    try {
      return this.getValidator(this.config.primaryProvider);
    } catch (error) {
      if (
        this.config.settings.enableFailover &&
        this.config.fallbackProviders
      ) {
        return this.getFailoverValidator();
      }
      throw error;
    }
  }

  /**
   * Validate token using primary validator with automatic failover
   *
   * @param token - Token string to validate
   * @returns Promise resolving to validation result
   */
  public async validateToken(token: string): Promise<TokenValidationResult> {
    let lastError: Error = new Error('No providers attempted');
    let attempts = 0;
    const maxAttempts = this.config.settings.maxFailoverAttempts;

    // Try primary provider first
    const providers = [
      this.config.primaryProvider,
      ...(this.config.fallbackProviders || []),
    ];

    for (const provider of providers) {
      if (attempts >= maxAttempts) {
        break;
      }

      try {
        const validator = this.getValidator(provider);
        const result = await validator.validateToken(token);

        // Update health status on success
        this.updateValidatorHealth(provider, true);

        // Add provider info to result metadata
        if (result.metadata) {
          (result.metadata as Record<string, unknown>).validatorType = provider;
          (result.metadata as Record<string, unknown>).failoverAttempt =
            attempts;
        }

        return result;
      } catch (error) {
        lastError = error as Error;
        attempts++;

        // Update health status on failure
        this.updateValidatorHealth(provider, false, lastError.message);

        console.warn(
          `⚠️ Token validation failed for provider ${provider} (attempt ${attempts}):`,
          error
        );

        // Don't continue if failover is disabled
        if (!this.config.settings.enableFailover) {
          throw error;
        }
      }
    }

    // All providers failed
    throw new Error(
      `Token validation failed after ${attempts} attempts. Last error: ${lastError?.message}`
    );
  }

  // ============================================================================
  // VALIDATOR CREATION METHODS
  // ============================================================================

  /**
   * Create validator for specified provider type
   *
   * @param providerType - Authentication provider type
   * @returns Created validator instance
   * @throws Error if provider not supported or configuration invalid
   */
  private createValidator(providerType: AuthProviderType): BaseTokenValidator {
    const providerConfig = this.config.providers[providerType];
    if (!providerConfig) {
      throw new Error(`No configuration found for provider: ${providerType}`);
    }

    switch (providerType) {
      case AuthProviderType.JWT:
        return new JWTTokenValidator(providerConfig as JWTValidatorConfig);

      case AuthProviderType.FIREBASE:
        return new FirebaseTokenValidator(
          providerConfig as FirebaseValidatorConfig
        );

      case AuthProviderType.AUTH0:
        throw new Error('Auth0 validator not yet implemented');

      case AuthProviderType.CUSTOM:
        throw new Error('Custom validator not yet implemented');

      default:
        throw new Error(`Unsupported provider type: ${providerType}`);
    }
  }

  /**
   * Get fallback validator when primary fails
   *
   * @returns Fallback validator instance
   * @throws Error if no healthy fallback validators available
   */
  private getFailoverValidator(): BaseTokenValidator {
    if (!this.config.fallbackProviders) {
      throw new Error('No fallback providers configured');
    }

    for (const fallbackProvider of this.config.fallbackProviders) {
      try {
        if (this.isValidatorHealthy(fallbackProvider)) {
          console.log(`🔄 Failing over to provider: ${fallbackProvider}`);
          return this.getValidator(fallbackProvider);
        }
      } catch (error) {
        console.warn(
          `⚠️ Fallback provider ${fallbackProvider} also failed:`,
          error
        );
        continue;
      }
    }

    throw new Error('No healthy fallback validators available');
  }

  // ============================================================================
  // HEALTH MONITORING
  // ============================================================================

  /**
   * Initialize health monitoring system
   */
  private initializeHealthMonitoring(): void {
    if (!this.config.settings.enableHealthMonitoring) {
      return;
    }

    // Initialize health status for all configured providers
    Object.keys(this.config.providers).forEach((provider) => {
      this.healthStatus.set(provider as AuthProviderType, {
        provider: provider as AuthProviderType,
        healthy: true,
        lastCheck: Date.now(),
        consecutiveFailures: 0,
        circuitBreakerOpen: false,
        successRate: 100,
        averageResponseTime: 0,
      });
    });

    // Start health monitoring interval
    this.healthMonitoringInterval = setInterval(() => {
      this.performHealthChecks();
    }, this.config.settings.healthCheckInterval);

    console.log(
      `❤️ Health monitoring enabled (interval: ${this.config.settings.healthCheckInterval}ms)`
    );
  }

  /**
   * Perform health checks on all validators
   */
  private async performHealthChecks(): Promise<void> {
    for (const [provider] of this.healthStatus) {
      try {
        const validator = this.validators.get(provider);
        if (!validator) {
          continue;
        }

        // Perform basic health check (could be expanded to include connectivity tests)
        const stats = validator.getStats();
        const isHealthy =
          stats.successfulValidations > 0 || stats.totalValidations === 0;

        // Update health status
        this.updateHealthStatus(provider, {
          healthy: isHealthy,
          lastCheck: Date.now(),
          successRate: validator.getSuccessRate(),
          averageResponseTime: stats.averageValidationTimeUs,
        });
      } catch (error) {
        console.warn(`⚠️ Health check failed for provider ${provider}:`, error);
        this.updateHealthStatus(provider, {
          healthy: false,
          lastCheck: Date.now(),
          error: (error as Error).message,
        });
      }
    }
  }

  /**
   * Update validator health status
   *
   * @param provider - Provider type
   * @param success - Whether validation was successful
   * @param error - Error message (if failed)
   */
  private updateValidatorHealth(
    provider: AuthProviderType,
    success: boolean,
    error?: string
  ): void {
    const health = this.healthStatus.get(provider);
    if (!health) {
      return;
    }

    if (success) {
      // Reset consecutive failures on success
      this.updateHealthStatus(provider, {
        healthy: true,
        consecutiveFailures: 0,
        circuitBreakerOpen: false,
        error: undefined,
      });
    } else {
      // Increment consecutive failures
      const consecutiveFailures = health.consecutiveFailures + 1;
      const circuitBreakerOpen =
        consecutiveFailures >= this.config.settings.circuitBreakerThreshold;

      this.updateHealthStatus(provider, {
        healthy: false,
        consecutiveFailures,
        circuitBreakerOpen,
        error,
      });

      // Schedule circuit breaker reset
      if (circuitBreakerOpen && !health.circuitBreakerOpen) {
        console.warn(`⚠️ Circuit breaker opened for provider: ${provider}`);
        setTimeout(() => {
          this.resetCircuitBreaker(provider);
        }, this.config.settings.circuitBreakerResetTimeout);
      }
    }
  }

  /**
   * Update health status for provider
   *
   * @param provider - Provider type
   * @param updates - Health status updates
   */
  private updateHealthStatus(
    provider: AuthProviderType,
    updates: Partial<ValidatorHealth>
  ): void {
    const current = this.healthStatus.get(provider);
    if (!current) {
      return;
    }

    this.healthStatus.set(provider, {
      ...current,
      ...updates,
    });
  }

  /**
   * Reset circuit breaker for provider
   *
   * @param provider - Provider type
   */
  private resetCircuitBreaker(provider: AuthProviderType): void {
    console.log(`🔄 Resetting circuit breaker for provider: ${provider}`);
    this.updateHealthStatus(provider, {
      circuitBreakerOpen: false,
      consecutiveFailures: 0,
    });
  }

  /**
   * Check if validator is healthy
   *
   * @param provider - Provider type
   * @returns True if validator is healthy
   */
  private isValidatorHealthy(provider: AuthProviderType): boolean {
    const health = this.healthStatus.get(provider);
    return health?.healthy ?? true;
  }

  /**
   * Check if circuit breaker is open for provider
   *
   * @param provider - Provider type
   * @returns True if circuit breaker is open
   */
  private isCircuitBreakerOpen(provider: AuthProviderType): boolean {
    const health = this.healthStatus.get(provider);
    return health?.circuitBreakerOpen ?? false;
  }

  // ============================================================================
  // CONFIGURATION AND UTILITIES
  // ============================================================================

  /**
   * Validate factory configuration
   *
   * @param config - Configuration to validate
   * @returns Validated configuration with defaults
   * @throws Error if configuration is invalid
   */
  private validateFactoryConfig(
    config: ValidatorFactoryConfig
  ): ValidatorFactoryConfig {
    // Apply defaults
    const validated: ValidatorFactoryConfig = {
      ...config,
      settings: {
        ...config.settings,
        enableFailover: config.settings?.enableFailover ?? true,
        maxFailoverAttempts: config.settings?.maxFailoverAttempts ?? 3,
        circuitBreakerThreshold: config.settings?.circuitBreakerThreshold ?? 5,
        circuitBreakerResetTimeout:
          config.settings?.circuitBreakerResetTimeout ?? 60000, // 1 minute
        enableHealthMonitoring: config.settings?.enableHealthMonitoring ?? true,
        healthCheckInterval: config.settings?.healthCheckInterval ?? 30000, // 30 seconds
      },
    };

    // Validation checks
    if (!validated.primaryProvider) {
      throw new Error('Primary provider is required');
    }

    if (!validated.providers[validated.primaryProvider]) {
      throw new Error(
        `Configuration missing for primary provider: ${validated.primaryProvider}`
      );
    }

    // Validate fallback providers have configurations
    if (validated.fallbackProviders) {
      for (const fallbackProvider of validated.fallbackProviders) {
        if (!validated.providers[fallbackProvider]) {
          throw new Error(
            `Configuration missing for fallback provider: ${fallbackProvider}`
          );
        }
      }
    }

    return validated;
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get current health status for all providers
   */
  public getHealthStatus(): Map<AuthProviderType, ValidatorHealth> {
    return new Map(this.healthStatus);
  }

  /**
   * Get factory configuration (safe copy)
   */
  public getConfig(): ValidatorFactoryConfig {
    return JSON.parse(JSON.stringify(this.config));
  }

  /**
   * Get validator statistics
   */
  public getStatistics(): Record<AuthProviderType, Record<string, unknown>> {
    const stats: Record<string, Record<string, unknown>> = {};

    for (const [provider, validator] of this.validators) {
      stats[provider] = validator.getStats() as unknown as Record<
        string,
        unknown
      >;
    }

    return stats;
  }

  /**
   * Clear all validator caches
   */
  public clearAllCaches(): void {
    for (const [, validator] of this.validators) {
      if ('clearCache' in validator) {
        (
          validator as Record<string, unknown> & { clearCache: () => void }
        ).clearCache();
      }
    }
    console.log('🧹 All validator caches cleared');
  }

  /**
   * Shutdown factory and cleanup resources
   */
  public shutdown(): void {
    if (this.healthMonitoringInterval) {
      clearInterval(this.healthMonitoringInterval);
      this.healthMonitoringInterval = undefined;
    }

    this.validators.clear();
    this.healthStatus.clear();

    console.log('🏭 Token Validator Factory shutdown complete');
  }
}
