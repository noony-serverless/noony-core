/**
 * Tests for GuardConfiguration
 *
 * Test suite for the guard configuration system covering
 * environment profiles, validation, and configuration creation.
 */

import {
  GuardConfiguration,
  PermissionResolutionStrategy,
  GuardSecurityConfig,
  GuardCacheConfig,
  GuardMonitoringConfig,
} from '../config/GuardConfiguration';

describe('GuardConfiguration', () => {
  describe('Configuration Creation', () => {
    it('should create configuration with provided values', () => {
      const security: GuardSecurityConfig = {
        permissionResolutionStrategy:
          PermissionResolutionStrategy.PRE_EXPANSION,
        conservativeCacheInvalidation: true,
        maxExpressionComplexity: 100,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      };

      const cache: GuardCacheConfig = {
        maxEntries: 2000,
        defaultTtlMs: 15 * 60 * 1000,
        userContextTtlMs: 10 * 60 * 1000,
        authTokenTtlMs: 5 * 60 * 1000,
      };

      const monitoring: GuardMonitoringConfig = {
        enablePerformanceTracking: true,
        enableDetailedLogging: false,
        logLevel: 'info',
        metricsCollectionInterval: 60000,
      };

      const config = new GuardConfiguration(security, cache, monitoring);

      expect(config.security).toEqual(security);
      expect(config.cache).toEqual(cache);
      expect(config.monitoring).toEqual(monitoring);
    });

    it('should create development configuration', () => {
      const config = GuardConfiguration.development();

      expect(config.security.permissionResolutionStrategy).toBe(
        PermissionResolutionStrategy.ON_DEMAND
      );
      expect(config.security.conservativeCacheInvalidation).toBe(false);
      expect(config.security.maxExpressionComplexity).toBe(50);
      expect(config.cache.maxEntries).toBe(500);
      expect(config.cache.defaultTtlMs).toBe(5 * 60 * 1000);
      expect(config.monitoring.enableDetailedLogging).toBe(true);
      expect(config.monitoring.logLevel).toBe('debug');
    });

    it('should create production configuration', () => {
      const config = GuardConfiguration.production();

      expect(config.security.permissionResolutionStrategy).toBe(
        PermissionResolutionStrategy.PRE_EXPANSION
      );
      expect(config.security.conservativeCacheInvalidation).toBe(true);
      expect(config.security.maxExpressionComplexity).toBe(100);
      expect(config.cache.maxEntries).toBe(2000);
      expect(config.cache.defaultTtlMs).toBe(15 * 60 * 1000);
      expect(config.monitoring.enableDetailedLogging).toBe(false);
      expect(config.monitoring.logLevel).toBe('info');
    });
  });

  describe('Configuration Validation', () => {
    let validSecurity: GuardSecurityConfig;
    let validCache: GuardCacheConfig;
    let validMonitoring: GuardMonitoringConfig;

    beforeEach(() => {
      validSecurity = {
        permissionResolutionStrategy:
          PermissionResolutionStrategy.PRE_EXPANSION,
        conservativeCacheInvalidation: true,
        maxExpressionComplexity: 100,
        maxPatternDepth: 3,
        maxNestingDepth: 2,
      };

      validCache = {
        maxEntries: 2000,
        defaultTtlMs: 15 * 60 * 1000,
        userContextTtlMs: 10 * 60 * 1000,
        authTokenTtlMs: 5 * 60 * 1000,
      };

      validMonitoring = {
        enablePerformanceTracking: true,
        enableDetailedLogging: false,
        logLevel: 'info',
        metricsCollectionInterval: 60000,
      };
    });

    it('should validate correct configuration', () => {
      const config = new GuardConfiguration(
        validSecurity,
        validCache,
        validMonitoring
      );
      expect(() => config.validate()).not.toThrow();
    });

    it('should reject invalid maxPatternDepth', () => {
      const invalidSecurity = {
        ...validSecurity,
        maxPatternDepth: 1,
      };

      const config = new GuardConfiguration(
        invalidSecurity,
        validCache,
        validMonitoring
      );
      expect(() => config.validate()).toThrow('maxPatternDepth must be 2 or 3');
    });

    it('should reject invalid maxNestingDepth', () => {
      const invalidSecurity = {
        ...validSecurity,
        maxNestingDepth: 3,
      };

      const config = new GuardConfiguration(
        invalidSecurity,
        validCache,
        validMonitoring
      );
      expect(() => config.validate()).toThrow('maxNestingDepth must be 2');
    });

    it('should reject zero maxExpressionComplexity', () => {
      const invalidSecurity = {
        ...validSecurity,
        maxExpressionComplexity: 0,
      };

      const config = new GuardConfiguration(
        invalidSecurity,
        validCache,
        validMonitoring
      );
      expect(() => config.validate()).toThrow(
        'maxExpressionComplexity must be positive'
      );
    });

    it('should reject low defaultTtlMs', () => {
      const invalidCache = {
        ...validCache,
        defaultTtlMs: 500,
      };

      const config = new GuardConfiguration(
        validSecurity,
        invalidCache,
        validMonitoring
      );
      expect(() => config.validate()).toThrow(
        'defaultTtlMs must be at least 1 second'
      );
    });
  });

  describe('Environment Profile Integration', () => {
    it('should create configuration from environment profile', () => {
      const profile = {
        environment: 'test',
        cacheType: 'memory' as const,
        security: {
          permissionResolutionStrategy: PermissionResolutionStrategy.ON_DEMAND,
          conservativeCacheInvalidation: false,
          maxExpressionComplexity: 25,
          maxPatternDepth: 2,
          maxNestingDepth: 2,
        },
        cache: {
          maxEntries: 100,
          defaultTtlMs: 1000,
          userContextTtlMs: 1000,
          authTokenTtlMs: 1000,
        },
        monitoring: {
          enablePerformanceTracking: false,
          enableDetailedLogging: true,
          logLevel: 'debug',
          metricsCollectionInterval: 1000,
        },
      };

      const config = GuardConfiguration.fromEnvironmentProfile(profile);

      expect(config.security).toEqual(profile.security);
      expect(config.cache).toEqual(profile.cache);
      expect(config.monitoring).toEqual(profile.monitoring);
    });
  });

  describe('Permission Resolution Strategy', () => {
    it('should support PRE_EXPANSION strategy', () => {
      expect(PermissionResolutionStrategy.PRE_EXPANSION).toBe('pre-expansion');
    });

    it('should support ON_DEMAND strategy', () => {
      expect(PermissionResolutionStrategy.ON_DEMAND).toBe('on-demand');
    });
  });

  describe('Configuration Properties', () => {
    it('should have readonly properties', () => {
      const config = GuardConfiguration.development();

      // Properties should be accessible
      expect(config.security).toBeDefined();
      expect(config.cache).toBeDefined();
      expect(config.monitoring).toBeDefined();

      // Properties should be readonly (TypeScript compile-time check)
      // Note: JavaScript doesn't enforce readonly at runtime, but TypeScript does at compile time
    });
  });
});
