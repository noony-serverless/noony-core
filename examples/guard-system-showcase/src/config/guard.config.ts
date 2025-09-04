/**
 * Guard Service Configuration
 *
 * Configuration for the Guard System Showcase including authentication,
 * permissions, and security settings.
 *
 * @module GuardConfig
 * @version 1.0.0
 */

import { AuthProviderType } from '@/types/auth.types';
import { PermissionResolverType } from '@noony-serverless/core';
import type { GuardServiceConfig } from '@/services/guard-service';

/**
 * Default Guard Service Configuration
 */
export const defaultGuardConfig: GuardServiceConfig = {
  authentication: {
    primaryProvider: AuthProviderType.JWT,
    fallbackProviders: [AuthProviderType.FIREBASE],
    providers: {
      [AuthProviderType.JWT]: {
        algorithm: 'HS256',
        issuer: 'guard-system-showcase',
        audience: 'demo-users',
        secret: process.env.JWT_SECRET || 'demo-secret-key-for-development',
        enableCaching: true,
        cacheTTL: 300000, // 5 minutes
        clockTolerance: 30, // 30 seconds
        requireIssuedAt: false,
      },
      [AuthProviderType.FIREBASE]: {
        projectId: process.env.FIREBASE_PROJECT_ID || 'demo-project',
        privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
        enableCaching: true,
        cacheTTL: 300000, // 5 minutes
        requireEmailVerified: false,
        clockTolerance: 30, // 30 seconds
      },
    },
    settings: {
      enableFailover: true,
      maxFailoverAttempts: 3,
      circuitBreakerThreshold: 5,
      circuitBreakerResetTimeout: 60000,
      enableHealthMonitoring: true,
      healthCheckInterval: 30000,
    },
  },

  permissions: {
    defaultStrategy: PermissionResolverType.PLAIN,
    enableAutoSelection: true,
    enablePerformanceComparison: process.env.NODE_ENV === 'development',
    enableHealthMonitoring: true,
    healthCheckInterval: 60000,
    enableABTesting: false,
    abTestingTrafficSplit: 10,
  },

  guard: {
    enablePreChecking: true,
    enableResultCaching: true,
    resultCacheTTL: 300000, // 5 minutes
    enableProfiling: process.env.NODE_ENV === 'development',
    enableSecurityMonitoring: true,
    maxConcurrentOperations: 100,
  },
};

/**
 * Get Guard Service configuration with environment overrides
 */
export function getGuardConfig(): GuardServiceConfig {
  return {
    ...defaultGuardConfig,
    // Environment-specific overrides can be added here
    guard: {
      ...defaultGuardConfig.guard,
      enableProfiling: process.env.ENABLE_PROFILING === 'true' || process.env.NODE_ENV === 'development',
      enableSecurityMonitoring: process.env.ENABLE_SECURITY_MONITORING !== 'false',
      maxConcurrentOperations: parseInt(process.env.MAX_CONCURRENT_OPERATIONS || '100'),
    },
  };
}