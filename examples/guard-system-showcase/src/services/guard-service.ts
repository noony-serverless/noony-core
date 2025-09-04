/**
 * Guard Service
 *
 * Main guard service that orchestrates all authentication and authorization
 * components for the Guard System Showcase. Provides a unified interface for
 * all guard operations with comprehensive monitoring, caching, and security
 * features.
 *
 * Features:
 * - Unified authentication and authorization API
 * - Integration with all permission resolution strategies
 * - Comprehensive performance monitoring and analytics
 * - Security incident detection and response
 * - Multi-layer caching with intelligent invalidation
 * - A/B testing and resolver performance comparison
 *
 * @module GuardService
 * @version 1.0.0
 */

import { PermissionResolverType } from '@noony-serverless/core';
import {
  AuthenticationService,
  AuthRequest,
  AuthResult,
} from '@/auth/authentication-service';
import {
  PermissionResolverFactory,
  ResolverFactoryConfig,
} from '@/permissions/permission-resolver-factory';
import { DemoPermissionSource } from '@/permissions/demo-permission-source';
import { UserContextManager } from '@/auth/user-context-manager';
import { ValidatorFactoryConfig } from '@/auth/token-validator-factory';
import {
  UserContext,
  PermissionCheckResult,
  PermissionExpression,
  AuthProviderType,
} from '@/types/auth.types';

/**
 * Guard operation request
 */
export interface GuardRequest extends AuthRequest {
  /** Permission requirement to check */
  requirement?: string | string[] | PermissionExpression;

  /** Preferred resolver type */
  resolverType?: PermissionResolverType;

  /** Additional permission context */
  permissionContext?: Record<string, unknown>;

  /** Request tracing ID */
  traceId?: string;
}

/**
 * Guard operation result
 */
export interface GuardResult extends AuthResult {
  /** Permission check result (if permission was requested) */
  permissionCheck?: PermissionCheckResult;

  /** Combined authorization result */
  authorized: boolean;

  /** Authorization failure reason */
  authorizationReason?: string;

  /** Performance breakdown */
  performanceBreakdown: {
    /** Total guard operation time */
    totalTimeUs: number;

    /** Authentication phase time */
    authenticationTimeUs: number;

    /** Permission check phase time */
    permissionCheckTimeUs: number;

    /** Cache operations time */
    cacheTimeUs: number;

    /** Security analysis time */
    securityAnalysisTimeUs: number;
  };

  /** Resolver selection metadata */
  resolverSelection?: {
    /** Selected resolver type */
    type: PermissionResolverType;

    /** Selection reason */
    reason: string;

    /** Whether auto-selection was used */
    autoSelected: boolean;
  };
}

/**
 * Guard service configuration
 */
export interface GuardServiceConfig {
  /** Authentication service configuration */
  authentication: ValidatorFactoryConfig;

  /** Permission resolver configuration */
  permissions: ResolverFactoryConfig;

  /** Guard-specific settings */
  guard: {
    /** Enable permission pre-checking */
    enablePreChecking: boolean;

    /** Cache guard results */
    enableResultCaching: boolean;

    /** Result cache TTL (milliseconds) */
    resultCacheTTL: number;

    /** Enable performance profiling */
    enableProfiling: boolean;

    /** Enable security monitoring */
    enableSecurityMonitoring: boolean;

    /** Maximum concurrent guard operations */
    maxConcurrentOperations: number;
  };
}

/**
 * Guard service statistics
 */
export interface GuardServiceStats {
  /** Total guard operations */
  totalOperations: number;

  /** Successful operations */
  successfulOperations: number;

  /** Failed operations */
  failedOperations: number;

  /** Authentication-only operations */
  authOnlyOperations: number;

  /** Full guard operations (auth + permissions) */
  fullGuardOperations: number;

  /** Average operation time by phase */
  averageTimeByPhase: {
    authentication: number;
    authorization: number;
    total: number;
  };

  /** Cache performance */
  cachePerformance: {
    hits: number;
    misses: number;
    hitRate: number;
  };

  /** Security events */
  securityEvents: {
    blocked: number;
    warnings: number;
    incidents: number;
  };

  /** Last operation timestamp */
  lastOperation: number;
}

/**
 * Guard Service Implementation
 *
 * Provides comprehensive guard services with:
 * - Unified authentication and authorization
 * - Multi-strategy permission resolution
 * - Performance optimization and monitoring
 * - Security incident detection
 * - Comprehensive analytics and reporting
 */
export class GuardService {
  private static instance: GuardService;

  private readonly authService: AuthenticationService;
  private readonly permissionSource: DemoPermissionSource;
  private readonly resolverFactory: PermissionResolverFactory;
  private readonly contextManager: UserContextManager;
  private readonly config: GuardServiceConfig;

  // Service statistics and monitoring
  private readonly stats: GuardServiceStats;
  private readonly resultCache = new Map<
    string,
    { result: GuardResult; expires: number }
  >();
  private readonly operationQueue = new Map<string, Promise<GuardResult>>();

  constructor(config: GuardServiceConfig) {
    this.config = this.validateConfig(config);
    this.stats = this.initializeStats();

    // Initialize core services
    this.permissionSource = new DemoPermissionSource();
    this.contextManager = UserContextManager.getInstance();
    this.authService = AuthenticationService.getInstance(
      this.config.authentication
    );
    this.resolverFactory = PermissionResolverFactory.getInstance(
      this.permissionSource,
      this.config.permissions
    );

    // Start monitoring and maintenance tasks
    this.startMaintenanceTasks();

    console.log(
      '🛡️ Guard Service initialized with comprehensive monitoring and security'
    );
  }

  /**
   * Get singleton instance
   */
  public static getInstance(config?: GuardServiceConfig): GuardService {
    if (!GuardService.instance) {
      if (!config) {
        throw new Error(
          'Configuration required for first GuardService instantiation'
        );
      }
      GuardService.instance = new GuardService(config);
    }
    return GuardService.instance;
  }

  // ============================================================================
  // CORE GUARD OPERATIONS
  // ============================================================================

  /**
   * Perform complete guard operation (authentication + authorization)
   *
   * @param request - Guard request with authentication and permission details
   * @returns Promise resolving to comprehensive guard result
   */
  public async guard(request: GuardRequest): Promise<GuardResult> {
    const startTime = process.hrtime.bigint();
    const operationId = this.generateOperationId(request);

    try {
      this.stats.totalOperations++;

      // Check for duplicate operation (prevent concurrent identical requests)
      const existingOperation = this.operationQueue.get(operationId);
      if (existingOperation) {
        const result = await existingOperation;
        this.trackCacheHit();
        return result;
      }

      // Create operation promise
      const operationPromise = this.performGuardOperation(request, startTime);
      this.operationQueue.set(operationId, operationPromise);

      try {
        const result = await operationPromise;
        return result;
      } finally {
        this.operationQueue.delete(operationId);
      }
    } catch (error) {
      this.stats.failedOperations++;
      console.error(`❌ Guard operation failed:`, error);

      return this.createErrorResult(request, error as Error, startTime);
    }
  }

  /**
   * Authenticate user only (no permission checking)
   *
   * @param request - Authentication request
   * @returns Promise resolving to authentication result
   */
  public async authenticate(request: AuthRequest): Promise<AuthResult> {
    try {
      this.stats.totalOperations++;
      this.stats.authOnlyOperations++;

      const authResult = await this.authService.authenticate(request);

      if (authResult.authenticated) {
        this.stats.successfulOperations++;
      } else {
        this.stats.failedOperations++;
      }

      return authResult;
    } catch (error) {
      this.stats.failedOperations++;
      throw error;
    }
  }

  /**
   * Check permissions for authenticated user
   *
   * @param userId - User ID to check permissions for
   * @param requirement - Permission requirement
   * @param context - Additional permission context
   * @param resolverType - Preferred resolver type
   * @returns Promise resolving to permission check result
   */
  public async checkPermissions(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    context: Record<string, unknown> = {},
    resolverType?: PermissionResolverType
  ): Promise<PermissionCheckResult> {
    try {
      // Check result cache first
      const cacheKey = this.getPermissionCacheKey(
        userId,
        requirement,
        resolverType
      );
      const cachedResult = this.getCachedPermissionResult(cacheKey);

      if (cachedResult) {
        this.trackCacheHit();
        return cachedResult;
      }

      // Perform permission check
      const result = await this.resolverFactory.checkPermission(
        userId,
        requirement,
        context
      );

      // Cache the result if caching is enabled
      if (this.config.guard.enableResultCaching) {
        this.cachePermissionResult(cacheKey, result);
      }

      this.trackCacheMiss();
      return result;
    } catch (error) {
      console.error(`❌ Permission check failed for user ${userId}:`, error);
      throw error;
    }
  }

  // ============================================================================
  // INTERNAL GUARD OPERATION
  // ============================================================================

  /**
   * Perform the core guard operation
   *
   * @param request - Guard request
   * @param startTime - Operation start time
   * @returns Promise resolving to guard result
   */
  private async performGuardOperation(
    request: GuardRequest,
    startTime: bigint
  ): Promise<GuardResult> {
    const phases: Record<string, bigint> = { start: startTime };

    try {
      // Phase 1: Authentication
      phases.authStart = process.hrtime.bigint();
      const authResult = await this.authService.authenticate(request);
      phases.authEnd = process.hrtime.bigint();

      let permissionResult: PermissionCheckResult | undefined;
      let authorized = authResult.authenticated;
      let authorizationReason: string | undefined;

      // Phase 2: Authorization (if authentication succeeded and permission required)
      if (authResult.authenticated && request.requirement && authResult.user) {
        phases.permStart = process.hrtime.bigint();

        permissionResult = await this.checkPermissions(
          authResult.user.userId,
          request.requirement,
          request.permissionContext || {},
          request.resolverType
        );

        phases.permEnd = process.hrtime.bigint();

        authorized = authorized && permissionResult.allowed;

        if (!permissionResult.allowed) {
          authorizationReason = permissionResult.reason || 'Permission denied';
        }
      }

      // Phase 3: Security Analysis
      phases.securityStart = process.hrtime.bigint();
      await this.performSecurityAnalysis(request, authResult, permissionResult);
      phases.securityEnd = process.hrtime.bigint();

      // Update statistics
      if (authorized) {
        this.stats.successfulOperations++;
      } else {
        this.stats.failedOperations++;
      }

      if (request.requirement) {
        this.stats.fullGuardOperations++;
      } else {
        this.stats.authOnlyOperations++;
      }

      // Calculate performance breakdown
      const totalTime = Number(process.hrtime.bigint() - startTime) / 1000;
      const performanceBreakdown = this.calculatePerformanceBreakdown(
        phases,
        totalTime
      );

      // Update average timing statistics
      this.updateTimingStats(performanceBreakdown);

      // Create comprehensive result
      const result: GuardResult = {
        // Inherit all authentication result fields
        ...authResult,

        // Add authorization fields
        permissionCheck: permissionResult,
        authorized,
        authorizationReason,
        performanceBreakdown,

        // Add resolver selection metadata if available
        resolverSelection: permissionResult?.metadata?.resolverSelection
          ? {
              type: permissionResult.metadata.resolverSelection.selectedType,
              reason: permissionResult.metadata.resolverSelection.reason,
              autoSelected:
                permissionResult.metadata.resolverSelection.autoSelected,
            }
          : undefined,
      };

      // Log comprehensive operation result
      this.logGuardOperation(request, result);

      return result;
    } catch (error) {
      console.error(`❌ Guard operation failed:`, error);
      throw error;
    }
  }

  /**
   * Perform security analysis on the guard operation
   *
   * @param request - Guard request
   * @param authResult - Authentication result
   * @param permissionResult - Permission check result
   * @returns Security analysis result
   */
  private async performSecurityAnalysis(
    request: GuardRequest,
    authResult: AuthResult,
    permissionResult?: PermissionCheckResult
  ): Promise<{
    riskScore: number;
    warnings: string[];
    blocked: boolean;
  }> {
    if (!this.config.guard.enableSecurityMonitoring) {
      return { riskScore: 0, warnings: [], blocked: false };
    }

    const warnings: string[] = [];
    let riskScore = authResult.security.riskScore;
    const blocked = authResult.security.blocked;

    // Analyze permission patterns
    if (permissionResult && authResult.user) {
      // Check for privilege escalation attempts
      if (
        request.requirement &&
        this.isPrivilegeEscalationAttempt(request.requirement, authResult.user)
      ) {
        riskScore += 40;
        warnings.push('Potential privilege escalation attempt detected');

        this.stats.securityEvents.warnings++;
      }

      // Check for unusual permission patterns
      if (
        request.requirement &&
        this.isUnusualPermissionPattern(request.requirement)
      ) {
        riskScore += 20;
        warnings.push('Unusual permission pattern detected');
      }
    }

    // Update security event statistics
    if (blocked) {
      this.stats.securityEvents.blocked++;
    }

    return { riskScore, warnings, blocked };
  }

  /**
   * Check if request represents a privilege escalation attempt
   *
   * @param requirement - Permission requirement
   * @param user - User context
   * @returns True if potential privilege escalation
   */
  private isPrivilegeEscalationAttempt(
    requirement: string | string[] | PermissionExpression,
    user: UserContext
  ): boolean {
    // Check for admin-level permissions from non-admin users
    const adminPermissions = [
      'admin:*',
      'system:*',
      'users:delete',
      'roles:manage',
    ];
    const isAdminUser =
      user.roles.includes('admin') || user.roles.includes('system-admin');

    if (isAdminUser) {
      return false; // Admin users are allowed admin permissions
    }

    // Check if requirement includes admin permissions
    const requirementString = JSON.stringify(requirement).toLowerCase();
    return adminPermissions.some((adminPerm) =>
      requirementString.includes(adminPerm.toLowerCase())
    );
  }

  /**
   * Check if permission pattern is unusual
   *
   * @param requirement - Permission requirement
   * @returns True if pattern is unusual
   */
  private isUnusualPermissionPattern(
    requirement: string | string[] | PermissionExpression
  ): boolean {
    // Check for very complex expressions
    const requirementString = JSON.stringify(requirement);

    // Very long requirement strings might indicate probing
    if (requirementString.length > 1000) {
      return true;
    }

    // Multiple different resource types in a single request
    if (Array.isArray(requirement) && requirement.length > 20) {
      return true;
    }

    // Complex nested expressions
    const nestingLevel = (requirementString.match(/\(/g) || []).length;
    if (nestingLevel > 10) {
      return true;
    }

    return false;
  }

  // ============================================================================
  // CACHING IMPLEMENTATION
  // ============================================================================

  /**
   * Get permission cache key
   *
   * @param userId - User ID
   * @param requirement - Permission requirement
   * @param resolverType - Resolver type
   * @returns Cache key
   */
  private getPermissionCacheKey(
    userId: string,
    requirement: string | string[] | PermissionExpression,
    resolverType?: PermissionResolverType
  ): string {
    const requirementHash = this.hashRequirement(requirement);
    const resolver = resolverType || 'auto';
    return `perm:${userId}:${resolver}:${requirementHash}`;
  }

  /**
   * Get cached permission result
   *
   * @param cacheKey - Cache key
   * @returns Cached result or null
   */
  private getCachedPermissionResult(
    cacheKey: string
  ): PermissionCheckResult | null {
    const entry = this.resultCache.get(cacheKey);

    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expires) {
      this.resultCache.delete(cacheKey);
      return null;
    }

    // Mark as cached
    const cachedResult = { ...entry.result.permissionCheck! };
    cachedResult.cached = true;

    return cachedResult;
  }

  /**
   * Cache permission result
   *
   * @param cacheKey - Cache key
   * @param result - Permission result to cache
   */
  private cachePermissionResult(
    cacheKey: string,
    result: PermissionCheckResult
  ): void {
    if (!result.allowed) {
      return; // Don't cache denials for security
    }

    const guardResult: Partial<GuardResult> = {
      permissionCheck: result,
    };

    this.resultCache.set(cacheKey, {
      result: guardResult as GuardResult,
      expires: Date.now() + this.config.guard.resultCacheTTL,
    });

    // Periodic cleanup
    if (this.resultCache.size > 10000) {
      this.cleanupCache();
    }
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.resultCache.entries()) {
      if (now > entry.expires) {
        this.resultCache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.debug(
        `🧹 Guard cache cleanup: removed ${cleaned} expired entries`
      );
    }
  }

  // ============================================================================
  // UTILITIES AND HELPERS
  // ============================================================================

  /**
   * Generate operation ID for deduplication
   *
   * @param request - Guard request
   * @returns Operation ID
   */
  private generateOperationId(request: GuardRequest): string {
    const components = [
      request.token,
      request.requirement
        ? this.hashRequirement(request.requirement)
        : 'auth-only',
      request.resolverType || 'auto',
      request.clientIp || 'unknown-ip',
    ];

    return Buffer.from(components.join('|'))
      .toString('base64')
      .substring(0, 16);
  }

  /**
   * Hash requirement for caching and deduplication
   *
   * @param requirement - Permission requirement
   * @returns Hash string
   */
  private hashRequirement(
    requirement: string | string[] | PermissionExpression
  ): string {
    const normalized = JSON.stringify(requirement);
    return Buffer.from(normalized).toString('base64').substring(0, 12);
  }

  /**
   * Calculate performance breakdown from phases
   *
   * @param phases - Phase timing information
   * @param totalTime - Total operation time
   * @returns Performance breakdown
   */
  private calculatePerformanceBreakdown(
    phases: Record<string, bigint>,
    totalTime: number
  ): GuardResult['performanceBreakdown'] {
    const authTime =
      phases.authEnd && phases.authStart
        ? Number(phases.authEnd - phases.authStart) / 1000
        : 0;

    const permTime =
      phases.permEnd && phases.permStart
        ? Number(phases.permEnd - phases.permStart) / 1000
        : 0;

    const securityTime =
      phases.securityEnd && phases.securityStart
        ? Number(phases.securityEnd - phases.securityStart) / 1000
        : 0;

    const cacheTime = Math.max(
      0,
      totalTime - authTime - permTime - securityTime
    );

    return {
      totalTimeUs: totalTime,
      authenticationTimeUs: authTime,
      permissionCheckTimeUs: permTime,
      cacheTimeUs: cacheTime,
      securityAnalysisTimeUs: securityTime,
    };
  }

  /**
   * Update timing statistics
   *
   * @param breakdown - Performance breakdown
   */
  private updateTimingStats(
    breakdown: GuardResult['performanceBreakdown']
  ): void {
    // Update authentication timing
    const currentAuthAvg = this.stats.averageTimeByPhase.authentication;
    this.stats.averageTimeByPhase.authentication =
      currentAuthAvg > 0
        ? (currentAuthAvg + breakdown.authenticationTimeUs) / 2
        : breakdown.authenticationTimeUs;

    // Update authorization timing
    const currentAuthzAvg = this.stats.averageTimeByPhase.authorization;
    this.stats.averageTimeByPhase.authorization =
      currentAuthzAvg > 0
        ? (currentAuthzAvg + breakdown.permissionCheckTimeUs) / 2
        : breakdown.permissionCheckTimeUs;

    // Update total timing
    const currentTotalAvg = this.stats.averageTimeByPhase.total;
    this.stats.averageTimeByPhase.total =
      currentTotalAvg > 0
        ? (currentTotalAvg + breakdown.totalTimeUs) / 2
        : breakdown.totalTimeUs;
  }

  /**
   * Track cache hit
   */
  private trackCacheHit(): void {
    this.stats.cachePerformance.hits++;
    this.updateCacheHitRate();
  }

  /**
   * Track cache miss
   */
  private trackCacheMiss(): void {
    this.stats.cachePerformance.misses++;
    this.updateCacheHitRate();
  }

  /**
   * Update cache hit rate
   */
  private updateCacheHitRate(): void {
    const total =
      this.stats.cachePerformance.hits + this.stats.cachePerformance.misses;
    this.stats.cachePerformance.hitRate =
      total > 0 ? (this.stats.cachePerformance.hits / total) * 100 : 0;
  }

  /**
   * Create error result for failed operations
   *
   * @param request - Original request
   * @param error - Error that occurred
   * @param startTime - Operation start time
   * @returns Error result
   */
  private createErrorResult(
    _request: GuardRequest,
    error: Error,
    startTime: bigint
  ): GuardResult {
    const totalTime = Number(process.hrtime.bigint() - startTime) / 1000;

    return {
      authenticated: false,
      authorized: false,
      tokenValidation: {
        valid: false,
        error: error.message,
        metadata: {
          validationTimeUs: 0,
          cached: false,
          validatorType: 'unknown',
        },
      },
      security: {
        riskScore: 0,
        warnings: [`Operation error: ${error.message}`],
        blocked: false,
      },
      performance: {
        totalTimeUs: totalTime,
        tokenValidationTimeUs: 0,
        userContextTimeUs: 0,
        cached: false,
      },
      tracking: {
        requestId: `error_${Date.now()}`,
        provider: AuthProviderType.JWT,
        timestamp: new Date().toISOString(),
      },
      performanceBreakdown: {
        totalTimeUs: totalTime,
        authenticationTimeUs: 0,
        permissionCheckTimeUs: 0,
        cacheTimeUs: 0,
        securityAnalysisTimeUs: 0,
      },
      authorizationReason: `Operation failed: ${error.message}`,
    };
  }

  /**
   * Log guard operation for monitoring
   *
   * @param request - Guard request
   * @param result - Guard result
   */
  private logGuardOperation(request: GuardRequest, result: GuardResult): void {
    const symbol = result.authorized
      ? '✅'
      : result.authenticated
        ? '🟡'
        : '❌';

    if (process.env.NODE_ENV === 'development') {
      console.debug(`${symbol} Guard operation:`, {
        authenticated: result.authenticated,
        authorized: result.authorized,
        user: result.user?.userId,
        permission: request.requirement
          ? this.hashRequirement(request.requirement)
          : 'none',
        resolver: result.resolverSelection?.type,
        totalTime: `${result.performanceBreakdown.totalTimeUs.toFixed(1)}μs`,
        breakdown: {
          auth: `${result.performanceBreakdown.authenticationTimeUs.toFixed(1)}μs`,
          authz: `${result.performanceBreakdown.permissionCheckTimeUs.toFixed(1)}μs`,
          security: `${result.performanceBreakdown.securityAnalysisTimeUs.toFixed(1)}μs`,
        },
      });
    }

    // Log slow operations
    if (result.performanceBreakdown.totalTimeUs > 100000) {
      // > 100ms
      console.warn(
        `🐌 Slow guard operation: ${result.performanceBreakdown.totalTimeUs.toFixed(1)}μs`,
        {
          user: result.user?.userId,
          permission: request.requirement,
          resolver: result.resolverSelection?.type,
        }
      );
    }
  }

  /**
   * Start maintenance tasks
   */
  private startMaintenanceTasks(): void {
    // Cache cleanup every 5 minutes
    setInterval(
      () => {
        this.cleanupCache();
      },
      5 * 60 * 1000
    );

    // Statistics reset every hour
    setInterval(
      () => {
        this.resetPeriodicStats();
      },
      60 * 60 * 1000
    );
  }

  /**
   * Reset periodic statistics (keep cumulative counters)
   */
  private resetPeriodicStats(): void {
    // Reset cache performance to get fresh hit rates
    this.stats.cachePerformance = {
      hits: 0,
      misses: 0,
      hitRate: 0,
    };

    console.debug('📊 Guard service periodic statistics reset');
  }

  /**
   * Validate guard service configuration
   *
   * @param config - Configuration to validate
   * @returns Validated configuration with defaults
   */
  private validateConfig(config: GuardServiceConfig): GuardServiceConfig {
    return {
      ...config,
      guard: {
        ...config.guard,
        enablePreChecking: config.guard?.enablePreChecking ?? false,
        enableResultCaching: config.guard?.enableResultCaching ?? true,
        resultCacheTTL: config.guard?.resultCacheTTL ?? 5 * 60 * 1000, // 5 minutes
        enableProfiling: config.guard?.enableProfiling ?? true,
        enableSecurityMonitoring:
          config.guard?.enableSecurityMonitoring ?? true,
        maxConcurrentOperations: config.guard?.maxConcurrentOperations ?? 1000,
      },
    };
  }

  /**
   * Initialize statistics
   */
  private initializeStats(): GuardServiceStats {
    return {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      authOnlyOperations: 0,
      fullGuardOperations: 0,
      averageTimeByPhase: {
        authentication: 0,
        authorization: 0,
        total: 0,
      },
      cachePerformance: {
        hits: 0,
        misses: 0,
        hitRate: 0,
      },
      securityEvents: {
        blocked: 0,
        warnings: 0,
        incidents: 0,
      },
      lastOperation: 0,
    };
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get guard service statistics
   */
  public getStats(): GuardServiceStats {
    return { ...this.stats };
  }

  /**
   * Get comprehensive service status
   */
  public getStatus(): {
    healthy: boolean;
    services: {
      authentication: Record<string, unknown>;
      permissions: Record<string, unknown>;
      context: Record<string, unknown>;
    };
    performance: GuardServiceStats;
    cache: {
      size: number;
      hitRate: number;
    };
  } {
    const authHealth = this.authService.getHealthStatus();
    const resolverHealth = this.resolverFactory.getHealthStatus();
    const contextStatus = this.contextManager.getCacheStatus();

    return {
      healthy:
        authHealth.healthy &&
        Array.from(resolverHealth.values()).every((r) => r.healthy),
      services: {
        authentication: authHealth,
        permissions: Object.fromEntries(resolverHealth),
        context: contextStatus,
      },
      performance: this.getStats(),
      cache: {
        size: this.resultCache.size,
        hitRate: this.stats.cachePerformance.hitRate,
      },
    };
  }

  /**
   * Reset service statistics
   */
  public resetStats(): void {
    Object.assign(this.stats, this.initializeStats());
    this.authService.getMetrics(); // Trigger reset if available
    this.resolverFactory.resetAllStats();
    this.resultCache.clear();
    console.log('📊 Guard service statistics reset');
  }

  /**
   * Shutdown guard service
   */
  public shutdown(): void {
    this.authService.shutdown();
    this.resolverFactory.shutdown();
    this.contextManager.shutdown();
    this.resultCache.clear();
    this.operationQueue.clear();
    console.log('🛡️ Guard Service shutdown complete');
  }
}
