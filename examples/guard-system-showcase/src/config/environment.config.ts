/**
 * Environment Configuration Manager
 *
 * Centralized configuration management for the Guard System Showcase.
 * Provides type-safe environment variable loading with validation,
 * default values, and environment-specific optimizations.
 *
 * @module EnvironmentConfig
 * @version 1.0.0
 */

import { z } from 'zod';

// ============================================================================
// ENVIRONMENT VALIDATION SCHEMAS
// ============================================================================

/**
 * Base environment configuration schema
 */
const BaseConfigSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'staging', 'production'])
    .default('development'),
  PORT: z.coerce.number().min(1).max(65535).default(3000),
  FUNCTIONS_PORT: z.coerce.number().min(1).max(65535).default(8080),
});

/**
 * JWT authentication configuration schema
 */
const JWTConfigSchema = z.object({
  JWT_SECRET: z
    .string()
    .min(32)
    .describe('JWT signing secret - must be at least 32 characters'),
  JWT_ISSUER: z.string().default('noony-guard-showcase'),
  JWT_AUDIENCE: z.string().default('guard-demo-users'),
  JWT_EXPIRES_IN: z.string().default('24h'),
});

/**
 * Redis cache configuration schema
 */
const RedisConfigSchema = z.object({
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().min(1).max(65535).default(6379),
  REDIS_DB: z.coerce.number().min(0).max(15).default(0),
  REDIS_PASSWORD: z.string().optional(),
  ENABLE_REDIS_CACHE: z.coerce.boolean().default(false),
});

/**
 * Guard system configuration schema
 */
const GuardConfigSchema = z.object({
  GUARD_CACHE_TYPE: z.enum(['memory', 'redis', 'none']).default('memory'),
  GUARD_CACHE_MAX_ENTRIES: z.coerce.number().min(100).max(100000).default(2000),
  GUARD_CACHE_TTL_MS: z.coerce.number().min(60000).max(3600000).default(900000), // 15 minutes
  GUARD_USER_CONTEXT_TTL_MS: z.coerce
    .number()
    .min(60000)
    .max(1800000)
    .default(600000), // 10 minutes
  GUARD_AUTH_TOKEN_TTL_MS: z.coerce
    .number()
    .min(60000)
    .max(900000)
    .default(300000), // 5 minutes
  GUARD_PERMISSION_STRATEGY: z
    .enum(['pre-expansion', 'on-demand'])
    .default('pre-expansion'),
  GUARD_CONSERVATIVE_INVALIDATION: z.coerce.boolean().default(true),
});

/**
 * Security configuration schema
 */
const SecurityConfigSchema = z.object({
  ENABLE_RATE_LIMITING: z.coerce.boolean().default(true),
  RATE_LIMIT_MAX: z.coerce.number().min(10).max(10000).default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().min(1000).max(3600000).default(60000), // 1 minute
  ENABLE_SECURITY_HEADERS: z.coerce.boolean().default(true),
  ENABLE_AUDIT_LOGGING: z.coerce.boolean().default(true),
});

/**
 * Performance monitoring configuration schema
 */
const MonitoringConfigSchema = z.object({
  ENABLE_PERFORMANCE_TRACKING: z.coerce.boolean().default(true),
  ENABLE_DETAILED_LOGGING: z.coerce.boolean().default(false),
  METRICS_COLLECTION_INTERVAL: z.coerce
    .number()
    .min(5000)
    .max(300000)
    .default(30000), // 30 seconds
  ENABLE_PROMETHEUS_METRICS: z.coerce.boolean().default(false),
  LOG_LEVEL: z
    .enum(['error', 'warn', 'info', 'debug', 'trace'])
    .default('info'),
  PRETTY_LOGS: z.coerce.boolean().default(false),
});

/**
 * Demo and development configuration schema
 */
const DemoConfigSchema = z.object({
  ENABLE_DEMO_ENDPOINTS: z.coerce.boolean().default(true),
  ENABLE_TESTING_ENDPOINTS: z.coerce.boolean().default(false),
  AUTO_SEED_DEMO_DATA: z.coerce.boolean().default(true),
  DEMO_USER_COUNT: z.coerce.number().min(10).max(10000).default(100),
  ENABLE_SWAGGER_UI: z.coerce.boolean().default(false),
  ENABLE_DEBUG_ENDPOINTS: z.coerce.boolean().default(false),
});

/**
 * Complete environment configuration schema
 */
const EnvironmentConfigSchema = BaseConfigSchema.merge(JWTConfigSchema)
  .merge(RedisConfigSchema)
  .merge(GuardConfigSchema)
  .merge(SecurityConfigSchema)
  .merge(MonitoringConfigSchema)
  .merge(DemoConfigSchema);

// ============================================================================
// CONFIGURATION TYPES
// ============================================================================

/**
 * Typed environment configuration
 */
export type EnvironmentConfig = z.infer<typeof EnvironmentConfigSchema>;

/**
 * Environment-specific optimizations
 */
export interface EnvironmentOptimizations {
  /** Whether to enable development features */
  developmentMode: boolean;

  /** Whether to enable production optimizations */
  productionOptimizations: boolean;

  /** Recommended cache settings for environment */
  recommendedCacheSettings: {
    maxEntries: number;
    ttlMs: number;
    strategy: 'pre-expansion' | 'on-demand';
  };

  /** Security settings for environment */
  securitySettings: {
    conservativeInvalidation: boolean;
    enableDetailedLogging: boolean;
    enableTestingEndpoints: boolean;
  };
}

// ============================================================================
// CONFIGURATION MANAGER
// ============================================================================

/**
 * Environment Configuration Manager
 *
 * Provides centralized configuration management with:
 * - Type-safe environment variable validation
 * - Environment-specific defaults and optimizations
 * - Configuration change detection and reloading
 * - Validation and error handling
 */
export class EnvironmentConfigManager {
  private static instance: EnvironmentConfigManager;
  private config: EnvironmentConfig;
  private optimizations: EnvironmentOptimizations;

  private constructor() {
    this.config = this.loadAndValidateConfig();
    this.optimizations = this.calculateOptimizations();
  }

  /**
   * Get singleton instance of configuration manager
   */
  public static getInstance(): EnvironmentConfigManager {
    if (!EnvironmentConfigManager.instance) {
      EnvironmentConfigManager.instance = new EnvironmentConfigManager();
    }
    return EnvironmentConfigManager.instance;
  }

  /**
   * Get current configuration
   */
  public getConfig(): EnvironmentConfig {
    return this.config;
  }

  /**
   * Get environment-specific optimizations
   */
  public getOptimizations(): EnvironmentOptimizations {
    return this.optimizations;
  }

  /**
   * Check if running in development mode
   */
  public isDevelopment(): boolean {
    return this.config.NODE_ENV === 'development';
  }

  /**
   * Check if running in production mode
   */
  public isProduction(): boolean {
    return this.config.NODE_ENV === 'production';
  }

  /**
   * Check if running in test mode
   */
  public isTest(): boolean {
    return this.config.NODE_ENV === 'test';
  }

  /**
   * Get database connection URL (mock for demo)
   */
  public getDatabaseUrl(): string {
    return process.env.DATABASE_URL || 'mock://localhost/demo';
  }

  /**
   * Get Redis connection URL
   */
  public getRedisUrl(): string {
    const { REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB } = this.config;
    const auth = REDIS_PASSWORD ? `:${REDIS_PASSWORD}@` : '';
    return `redis://${auth}${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}`;
  }

  /**
   * Validate configuration for potential issues
   */
  public validateConfiguration(): ConfigValidationResult {
    const issues: string[] = [];
    const warnings: string[] = [];

    // Check JWT secret strength
    if (this.config.JWT_SECRET.length < 64) {
      warnings.push(
        'JWT_SECRET should be at least 64 characters for maximum security'
      );
    }

    // Check production settings
    if (this.isProduction()) {
      if (this.config.ENABLE_DEBUG_ENDPOINTS) {
        issues.push('Debug endpoints should be disabled in production');
      }
      if (this.config.ENABLE_TESTING_ENDPOINTS) {
        issues.push('Testing endpoints should be disabled in production');
      }
      if (this.config.PRETTY_LOGS) {
        warnings.push(
          'Pretty logging should be disabled in production for performance'
        );
      }
      if (
        this.config.LOG_LEVEL === 'debug' ||
        this.config.LOG_LEVEL === 'trace'
      ) {
        warnings.push(
          'Debug logging should be avoided in production for performance'
        );
      }
    }

    // Check cache settings
    if (this.config.GUARD_CACHE_MAX_ENTRIES < 1000 && this.isProduction()) {
      warnings.push('Cache size may be too small for production workloads');
    }

    // Check Redis configuration
    if (this.config.ENABLE_REDIS_CACHE && !process.env.REDIS_HOST) {
      issues.push('Redis is enabled but REDIS_HOST is not configured');
    }

    return {
      valid: issues.length === 0,
      issues,
      warnings,
    };
  }

  /**
   * Load and validate environment configuration
   */
  private loadAndValidateConfig(): EnvironmentConfig {
    try {
      // Load environment variables
      const rawConfig = {
        NODE_ENV: process.env.NODE_ENV,
        PORT: process.env.PORT,
        FUNCTIONS_PORT: process.env.FUNCTIONS_PORT,
        JWT_SECRET: process.env.JWT_SECRET || this.generateDefaultJWTSecret(),
        JWT_ISSUER: process.env.JWT_ISSUER,
        JWT_AUDIENCE: process.env.JWT_AUDIENCE,
        JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN,
        REDIS_HOST: process.env.REDIS_HOST,
        REDIS_PORT: process.env.REDIS_PORT,
        REDIS_DB: process.env.REDIS_DB,
        REDIS_PASSWORD: process.env.REDIS_PASSWORD,
        ENABLE_REDIS_CACHE: process.env.ENABLE_REDIS_CACHE,
        GUARD_CACHE_TYPE: process.env.GUARD_CACHE_TYPE,
        GUARD_CACHE_MAX_ENTRIES: process.env.GUARD_CACHE_MAX_ENTRIES,
        GUARD_CACHE_TTL_MS: process.env.GUARD_CACHE_TTL_MS,
        GUARD_USER_CONTEXT_TTL_MS: process.env.GUARD_USER_CONTEXT_TTL_MS,
        GUARD_AUTH_TOKEN_TTL_MS: process.env.GUARD_AUTH_TOKEN_TTL_MS,
        GUARD_PERMISSION_STRATEGY: process.env.GUARD_PERMISSION_STRATEGY,
        GUARD_CONSERVATIVE_INVALIDATION:
          process.env.GUARD_CONSERVATIVE_INVALIDATION,
        ENABLE_RATE_LIMITING: process.env.ENABLE_RATE_LIMITING,
        RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX,
        RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS,
        ENABLE_SECURITY_HEADERS: process.env.ENABLE_SECURITY_HEADERS,
        ENABLE_AUDIT_LOGGING: process.env.ENABLE_AUDIT_LOGGING,
        ENABLE_PERFORMANCE_TRACKING: process.env.ENABLE_PERFORMANCE_TRACKING,
        ENABLE_DETAILED_LOGGING: process.env.ENABLE_DETAILED_LOGGING,
        METRICS_COLLECTION_INTERVAL: process.env.METRICS_COLLECTION_INTERVAL,
        ENABLE_PROMETHEUS_METRICS: process.env.ENABLE_PROMETHEUS_METRICS,
        LOG_LEVEL: process.env.LOG_LEVEL,
        PRETTY_LOGS: process.env.PRETTY_LOGS,
        ENABLE_DEMO_ENDPOINTS: process.env.ENABLE_DEMO_ENDPOINTS,
        ENABLE_TESTING_ENDPOINTS: process.env.ENABLE_TESTING_ENDPOINTS,
        AUTO_SEED_DEMO_DATA: process.env.AUTO_SEED_DEMO_DATA,
        DEMO_USER_COUNT: process.env.DEMO_USER_COUNT,
        ENABLE_SWAGGER_UI: process.env.ENABLE_SWAGGER_UI,
        ENABLE_DEBUG_ENDPOINTS: process.env.ENABLE_DEBUG_ENDPOINTS,
      };

      // Validate and transform configuration
      const validated = EnvironmentConfigSchema.parse(rawConfig);

      console.log(
        `🔧 Configuration loaded for environment: ${validated.NODE_ENV}`
      );
      return validated;
    } catch (error) {
      if (error instanceof z.ZodError) {
        console.error('❌ Configuration validation failed:');
        error.errors.forEach((err) => {
          console.error(`  - ${err.path.join('.')}: ${err.message}`);
        });
        throw new Error('Invalid environment configuration');
      }
      throw error;
    }
  }

  /**
   * Calculate environment-specific optimizations
   */
  private calculateOptimizations(): EnvironmentOptimizations {
    const { NODE_ENV } = this.config;

    return {
      developmentMode: NODE_ENV === 'development',
      productionOptimizations: NODE_ENV === 'production',

      recommendedCacheSettings: {
        maxEntries:
          NODE_ENV === 'production'
            ? 5000
            : NODE_ENV === 'development'
              ? 500
              : 1000,
        ttlMs: NODE_ENV === 'production' ? 20 * 60 * 1000 : 5 * 60 * 1000, // 20min prod, 5min dev
        strategy: NODE_ENV === 'production' ? 'pre-expansion' : 'on-demand',
      },

      securitySettings: {
        conservativeInvalidation:
          NODE_ENV === 'production' || NODE_ENV === 'staging',
        enableDetailedLogging:
          NODE_ENV === 'development' || NODE_ENV === 'test',
        enableTestingEndpoints:
          NODE_ENV === 'development' || NODE_ENV === 'test',
      },
    };
  }

  /**
   * Generate a default JWT secret for development
   */
  private generateDefaultJWTSecret(): string {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'JWT_SECRET must be explicitly set in production environment'
      );
    }

    console.warn(
      '⚠️ Using generated JWT secret for development. Set JWT_SECRET in production!'
    );
    return (
      'dev-secret-' +
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15)
    );
  }
}

// ============================================================================
// CONFIGURATION VALIDATION RESULT
// ============================================================================

/**
 * Configuration validation result
 */
export interface ConfigValidationResult {
  /** Whether configuration is valid */
  valid: boolean;

  /** Critical issues that prevent startup */
  issues: string[];

  /** Warnings that should be addressed */
  warnings: string[];
}

// ============================================================================
// EXPORTS
// ============================================================================

/**
 * Get configuration instance
 */
export const config = EnvironmentConfigManager.getInstance();

/**
 * Get current environment configuration
 */
export const getConfig = (): EnvironmentConfig => config.getConfig();

/**
 * Get environment optimizations
 */
export const getOptimizations = (): EnvironmentOptimizations =>
  config.getOptimizations();
