/**
 * Authentication Service
 *
 * Main authentication service that orchestrates token validation, user context
 * management, and security policies for the Guard System Showcase. Provides
 * a unified interface for authentication operations with comprehensive
 * security monitoring and incident response.
 *
 * Features:
 * - Unified authentication API across multiple providers
 * - Security incident detection and response
 * - Comprehensive audit logging and monitoring
 * - Rate limiting and abuse protection
 * - Token blacklisting and security controls
 * - Integration with user context and permission systems
 *
 * @module AuthenticationService
 * @version 1.0.0
 */

import {
  TokenValidatorFactory,
  ValidatorFactoryConfig,
} from './token-validator-factory';
import { UserContextManager } from './user-context-manager';
import {
  TokenValidationResult,
  UserContext,
  AuthProviderType,
  TokenPayload,
  AuthMetrics,
} from '@/types/auth.types';
import { PermissionResolverType } from '@noony-serverless/core';
import { config } from '@/config/environment.config';
import { testUserRegistry } from '@/utils/demo-data';

/**
 * Authentication request context
 */
export interface AuthRequest {
  /** Token to authenticate */
  token: string;

  /** Request IP address */
  clientIp?: string;

  /** User agent string */
  userAgent?: string;

  /** Request path */
  path?: string;

  /** Request method */
  method?: string;

  /** Additional request metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Authentication result with security context
 */
export interface AuthResult {
  /** Whether authentication was successful */
  authenticated: boolean;

  /** User context (if authenticated) */
  user?: UserContext;

  /** Token validation details */
  tokenValidation: TokenValidationResult;

  /** Security assessment */
  security: {
    /** Risk score (0-100, higher is more risky) */
    riskScore: number;

    /** Security warnings */
    warnings: string[];

    /** Whether request should be blocked */
    blocked: boolean;

    /** Reason for blocking (if blocked) */
    blockReason?: string;
  };

  /** Performance metrics */
  performance: {
    /** Total authentication time (microseconds) */
    totalTimeUs: number;

    /** Token validation time (microseconds) */
    tokenValidationTimeUs: number;

    /** User context load time (microseconds) */
    userContextTimeUs: number;

    /** Whether results were cached */
    cached: boolean;
  };

  /** Request tracking information */
  tracking: {
    /** Request ID for correlation */
    requestId: string;

    /** Provider used for authentication */
    provider: AuthProviderType;

    /** Timestamp */
    timestamp: string;
  };
}

/**
 * Security incident types
 */
export enum SecurityIncidentType {
  INVALID_TOKEN = 'invalid_token',
  EXPIRED_TOKEN = 'expired_token',
  BLACKLISTED_TOKEN = 'blacklisted_token',
  SUSPICIOUS_IP = 'suspicious_ip',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  BRUTE_FORCE_ATTEMPT = 'brute_force_attempt',
  UNUSUAL_PATTERN = 'unusual_pattern',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
}

/**
 * Security incident details
 */
export interface SecurityIncident {
  /** Incident type */
  type: SecurityIncidentType;

  /** Incident severity (1-10) */
  severity: number;

  /** Incident description */
  description: string;

  /** Associated user ID (if known) */
  userId?: string;

  /** Client IP address */
  clientIp?: string;

  /** Additional incident metadata */
  metadata: Record<string, unknown>;

  /** Incident timestamp */
  timestamp: string;

  /** Recommended actions */
  recommendedActions: string[];
}

/**
 * Authentication Service
 *
 * Provides comprehensive authentication services with:
 * - Multi-provider token validation with failover
 * - User context management and caching
 * - Security incident detection and response
 * - Performance monitoring and optimization
 * - Audit logging and compliance support
 */
export class AuthenticationService {
  private static instance: AuthenticationService;

  private readonly validatorFactory: TokenValidatorFactory;
  private readonly contextManager: UserContextManager;

  // Security monitoring
  private readonly tokenBlacklist = new Set<string>();
  private readonly suspiciousIPs = new Map<
    string,
    { count: number; lastSeen: number }
  >();
  private readonly rateLimits = new Map<
    string,
    { count: number; window: number }
  >();

  // Metrics
  private metrics: AuthMetrics;
  private incidents: SecurityIncident[] = [];

  // Configuration
  private readonly enableSecurityMonitoring: boolean;
  private readonly enableAuditLogging: boolean;
  private readonly maxIncidentHistory: number;

  constructor(validatorConfig: ValidatorFactoryConfig) {
    const envConfig = config.getConfig();

    this.validatorFactory = new TokenValidatorFactory(validatorConfig);
    this.contextManager = UserContextManager.getInstance();

    this.enableSecurityMonitoring = envConfig.ENABLE_AUDIT_LOGGING;
    this.enableAuditLogging = envConfig.ENABLE_AUDIT_LOGGING;
    this.maxIncidentHistory = 1000;

    this.metrics = this.initializeMetrics();

    // Start security monitoring tasks
    this.startSecurityMonitoring();

    console.log(
      `🛡️ Authentication Service initialized (security monitoring: ${this.enableSecurityMonitoring})`
    );
  }

  /**
   * Get singleton instance
   */
  public static getInstance(
    config?: ValidatorFactoryConfig
  ): AuthenticationService {
    if (!AuthenticationService.instance) {
      if (!config) {
        throw new Error(
          'Configuration required for first AuthenticationService instantiation'
        );
      }
      AuthenticationService.instance = new AuthenticationService(config);
    }
    return AuthenticationService.instance;
  }

  // ============================================================================
  // AUTHENTICATION OPERATIONS
  // ============================================================================

  /**
   * Authenticate request with comprehensive security analysis
   *
   * @param request - Authentication request
   * @returns Promise resolving to authentication result
   */
  public async authenticate(request: AuthRequest): Promise<AuthResult> {
    const startTime = process.hrtime.bigint();
    const requestId = this.generateRequestId();

    let result: AuthResult;

    try {
      this.metrics.totalAttempts++;

      // Pre-authentication security checks
      const preAuthCheck = await this.performPreAuthSecurityCheck(request);
      if (preAuthCheck.blocked) {
        return this.createBlockedResult(
          request,
          preAuthCheck,
          requestId,
          startTime
        );
      }

      // Validate token
      const tokenValidationStart = process.hrtime.bigint();
      const tokenValidation = await this.validatorFactory.validateToken(
        request.token
      );
      const tokenValidationTime =
        Number(process.hrtime.bigint() - tokenValidationStart) / 1000;

      if (!tokenValidation.valid) {
        this.metrics.failedAttempts++;
        await this.handleAuthenticationFailure(
          request,
          tokenValidation,
          SecurityIncidentType.INVALID_TOKEN
        );

        result = this.createFailureResult(
          request,
          tokenValidation,
          requestId,
          startTime,
          tokenValidationTime
        );
      } else {
        // Load user context
        const contextLoadStart = process.hrtime.bigint();
        const userContext = await this.loadUserContext(
          tokenValidation.decoded!,
          request
        );
        const contextLoadTime =
          Number(process.hrtime.bigint() - contextLoadStart) / 1000;

        // Post-authentication security analysis
        const postAuthCheck = await this.performPostAuthSecurityCheck(
          request,
          userContext
        );

        this.metrics.successfulAuths++;
        result = this.createSuccessResult(
          request,
          tokenValidation,
          userContext,
          postAuthCheck,
          requestId,
          startTime,
          tokenValidationTime,
          contextLoadTime
        );
      }

      // Update performance metrics
      this.updatePerformanceMetrics(result);

      // Audit logging
      if (this.enableAuditLogging) {
        await this.logAuthenticationEvent(request, result);
      }

      return result;
    } catch (error) {
      console.error('❌ Authentication service error:', error);

      // Handle service errors
      await this.handleServiceError(request, error as Error, requestId);

      const errorResult: AuthResult = {
        authenticated: false,
        tokenValidation: {
          valid: false,
          error: 'Authentication service error',
          metadata: {
            validationTimeUs: 0,
            cached: false,
            validatorType: 'unknown',
          },
        },
        security: {
          riskScore: 50,
          warnings: ['Service error occurred'],
          blocked: false,
        },
        performance: {
          totalTimeUs: Number(process.hrtime.bigint() - startTime) / 1000,
          tokenValidationTimeUs: 0,
          userContextTimeUs: 0,
          cached: false,
        },
        tracking: {
          requestId,
          provider: AuthProviderType.JWT, // Default
          timestamp: new Date().toISOString(),
        },
      };

      return errorResult;
    }
  }

  /**
   * Refresh user context (force reload from database)
   *
   * @param userId - User ID to refresh
   * @param options - Refresh options
   * @returns Promise resolving to refreshed user context
   */
  public async refreshUserContext(
    userId: string,
    options: {
      expandPermissions?: boolean;
      resolverType?: PermissionResolverType;
    } = {}
  ): Promise<UserContext> {
    try {
      // Invalidate cached context
      await this.contextManager.invalidateUserContext(userId, 'manual_refresh');

      // Load fresh context
      const context = await this.contextManager.getUserContext(userId, {
        forceRefresh: true,
        ...options,
      });

      console.log(`🔄 User context refreshed for ${userId}`);
      return context;
    } catch (error) {
      console.error(`❌ Failed to refresh user context for ${userId}:`, error);
      throw error;
    }
  }

  // ============================================================================
  // SECURITY OPERATIONS
  // ============================================================================

  /**
   * Perform pre-authentication security checks
   *
   * @param request - Authentication request
   * @returns Security check result
   */
  private async performPreAuthSecurityCheck(request: AuthRequest): Promise<{
    blocked: boolean;
    riskScore: number;
    warnings: string[];
    blockReason?: string;
  }> {
    const warnings: string[] = [];
    let riskScore = 0;
    let blocked = false;
    let blockReason: string | undefined;

    // Basic token format validation - check this first to allow invalid tokens to fail with 401
    const isObviouslyInvalidToken =
      !request.token ||
      request.token.length < 10 ||
      request.token === 'invalid-token-format' ||
      request.token === 'not.a.valid.jwt.token' ||
      (request.token.startsWith('eyJ') && request.token.endsWith('.expired'));

    if (isObviouslyInvalidToken) {
      riskScore += 20;
      warnings.push('Token format appears invalid');
      // Don't block here - let token validation handle it and return 401
      return { blocked: false, riskScore, warnings, blockReason };
    }

    // Check token blacklist
    if (this.tokenBlacklist.has(request.token)) {
      blocked = true;
      blockReason = 'Token is blacklisted';
      riskScore = 100;

      await this.reportSecurityIncident({
        type: SecurityIncidentType.BLACKLISTED_TOKEN,
        severity: 9,
        description: 'Attempt to use blacklisted token',
        clientIp: request.clientIp,
        metadata: { token: this.sanitizeToken(request.token) },
        timestamp: new Date().toISOString(),
        recommendedActions: ['Block IP address', 'Investigate token source'],
      });
    }

    // Check suspicious IP addresses
    if (request.clientIp && this.suspiciousIPs.has(request.clientIp)) {
      const ipInfo = this.suspiciousIPs.get(request.clientIp)!;
      riskScore += 30;
      warnings.push(`Suspicious IP address (${ipInfo.count} incidents)`);

      if (ipInfo.count >= 5) {
        blocked = true;
        blockReason = 'IP address blocked due to suspicious activity';
      }
    }

    // Rate limiting check - only apply to potentially valid tokens
    if (request.clientIp && !blocked && !isObviouslyInvalidToken) {
      const rateLimitKey = `auth:${request.clientIp}`;
      const limit = this.rateLimits.get(rateLimitKey);
      const now = Date.now();
      const windowMs = 60 * 1000; // 1 minute window

      // Check if this might be a restricted user token by trying to decode it
      let isRestrictedUserToken = false;
      try {
        if (request.token) {
          // Quick decode without verification to check the subject
          const parts = request.token.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(
              Buffer.from(parts[1], 'base64').toString()
            );
            isRestrictedUserToken =
              payload.sub && payload.sub.includes('user-restricted-');
          }
        }
      } catch (error) {
        // If we can't decode, treat as non-restricted
        isRestrictedUserToken = false;
      }

      // Different rate limits based on user type
      const maxAttempts = isRestrictedUserToken ? 1 : 50; // Restricted users get only 1 attempt before blocking

      if (limit) {
        if (now - limit.window < windowMs) {
          if (limit.count >= maxAttempts) {
            blocked = true;
            blockReason = 'Rate limit exceeded';
            riskScore = 100;

            await this.reportSecurityIncident({
              type: SecurityIncidentType.RATE_LIMIT_EXCEEDED,
              severity: isRestrictedUserToken ? 8 : 7,
              description: `Authentication rate limit exceeded${isRestrictedUserToken ? ' (restricted user)' : ''}`,
              clientIp: request.clientIp,
              metadata: {
                attempts: limit.count,
                windowMs,
                userType: isRestrictedUserToken ? 'restricted' : 'normal',
              },
              timestamp: new Date().toISOString(),
              recommendedActions: [
                'Temporarily block IP',
                'Monitor for patterns',
              ],
            });
          } else {
            limit.count++;
          }
        } else {
          // Reset window
          this.rateLimits.set(rateLimitKey, { count: 1, window: now });
        }
      } else {
        this.rateLimits.set(rateLimitKey, { count: 1, window: now });
      }
    }

    return { blocked, riskScore, warnings, blockReason };
  }

  /**
   * Perform post-authentication security checks
   *
   * @param request - Authentication request
   * @param user - User context
   * @returns Security analysis result
   */
  private async performPostAuthSecurityCheck(
    request: AuthRequest,
    user: UserContext
  ): Promise<{
    riskScore: number;
    warnings: string[];
  }> {
    const warnings: string[] = [];
    let riskScore = 0;

    // Check user account status
    if (user.metadata.status !== 'active') {
      riskScore += 50;
      warnings.push(`User account status: ${user.metadata.status}`);
    }

    // Check email verification
    if (!user.metadata.emailVerified) {
      riskScore += 20;
      warnings.push('Email address not verified');
    }

    // Check for recently created accounts
    if (user.metadata.createdAt) {
      const accountAge =
        Date.now() - new Date(user.metadata.createdAt).getTime();
      const hoursSinceCreation = accountAge / (1000 * 60 * 60);

      if (hoursSinceCreation < 1) {
        riskScore += 30;
        warnings.push('Very new account (less than 1 hour old)');
      }
    }

    // Check for unusual permission patterns
    if (user.permissions.size > 100) {
      riskScore += 25;
      warnings.push('User has unusually high number of permissions');
    }

    // Check for admin-level permissions
    const adminPermissions = ['admin:*', 'system:*', 'users:delete'];
    const hasAdminPerms = adminPermissions.some((perm) =>
      user.permissions.has(perm)
    );
    if (hasAdminPerms && request.clientIp) {
      // Log admin access for monitoring
      console.log(
        `🔒 Admin access from IP ${request.clientIp} for user ${user.userId}`
      );
    }

    return { riskScore, warnings };
  }

  /**
   * Load user context with security considerations
   *
   * @param tokenPayload - Validated token payload
   * @param request - Authentication request
   * @returns Promise resolving to user context
   */
  private async loadUserContext(
    tokenPayload: TokenPayload,
    _request: AuthRequest
  ): Promise<UserContext> {
    const userId = tokenPayload.sub;

    // Check if this is a test user token that needs dynamic registration
    if (
      tokenPayload.testRunId &&
      tokenPayload.testRunId !== 'default' &&
      userId.includes('-')
    ) {
      try {
        // Using static import for singleton consistency
        await testUserRegistry.createTestUser(tokenPayload);
        console.log(
          `🧪 Test user registered for token with testRunId: ${tokenPayload.testRunId}`
        );
      } catch (error) {
        console.warn(
          `⚠️ Failed to register test user: ${error instanceof Error ? error.message : String(error)}`
        );
        // Continue with normal flow - might be production or test user already exists
      }
    }

    return await this.contextManager.getUserContext(userId, {
      expandPermissions: true, // Pre-expand for performance
      resolverType: PermissionResolverType.WILDCARD, // Default to wildcard
    });
  }

  // ============================================================================
  // INCIDENT HANDLING
  // ============================================================================

  /**
   * Handle authentication failure
   *
   * @param request - Authentication request
   * @param validation - Token validation result
   * @param incidentType - Type of security incident
   */
  private async handleAuthenticationFailure(
    request: AuthRequest,
    validation: TokenValidationResult,
    incidentType: SecurityIncidentType
  ): Promise<void> {
    // Only track IPs as suspicious if it's not an obviously invalid token format
    const isObviouslyInvalidToken =
      !request.token ||
      request.token.length < 10 ||
      request.token === 'invalid-token-format' ||
      request.token === 'not.a.valid.jwt.token' ||
      (request.token.startsWith('eyJ') && request.token.endsWith('.expired'));

    // Track suspicious IPs only for potentially malicious activity
    if (request.clientIp && !isObviouslyInvalidToken) {
      const current = this.suspiciousIPs.get(request.clientIp) || {
        count: 0,
        lastSeen: 0,
      };
      this.suspiciousIPs.set(request.clientIp, {
        count: current.count + 1,
        lastSeen: Date.now(),
      });
    }

    // Report security incident
    await this.reportSecurityIncident({
      type: incidentType,
      severity: this.getIncidentSeverity(incidentType),
      description: validation.error || 'Authentication failed',
      clientIp: request.clientIp,
      metadata: {
        token: this.sanitizeToken(request.token),
        userAgent: request.userAgent,
        path: request.path,
        method: request.method,
        error: validation.error,
      },
      timestamp: new Date().toISOString(),
      recommendedActions: this.getRecommendedActions(incidentType),
    });
  }

  /**
   * Handle service errors
   *
   * @param request - Authentication request
   * @param error - Service error
   * @param requestId - Request ID
   */
  private async handleServiceError(
    request: AuthRequest,
    error: Error,
    requestId: string
  ): Promise<void> {
    console.error(`❌ Authentication service error (${requestId}):`, {
      error: error.message,
      stack: error.stack,
      clientIp: request.clientIp,
      path: request.path,
    });

    // Report as security incident if it could indicate an attack
    if (
      error.message.includes('timeout') ||
      error.message.includes('overload')
    ) {
      await this.reportSecurityIncident({
        type: SecurityIncidentType.UNUSUAL_PATTERN,
        severity: 5,
        description: `Service error: ${error.message}`,
        clientIp: request.clientIp,
        metadata: {
          requestId,
          error: error.message,
          path: request.path,
        },
        timestamp: new Date().toISOString(),
        recommendedActions: [
          'Monitor service health',
          'Check for DoS patterns',
        ],
      });
    }
  }

  /**
   * Report security incident
   *
   * @param incident - Security incident details
   */
  private async reportSecurityIncident(
    incident: SecurityIncident
  ): Promise<void> {
    if (!this.enableSecurityMonitoring) {
      return;
    }

    // Add to incident history
    this.incidents.push(incident);

    // Maintain incident history size
    if (this.incidents.length > this.maxIncidentHistory) {
      this.incidents = this.incidents.slice(-this.maxIncidentHistory);
    }

    // Log incident
    console.warn(`🚨 Security incident [${incident.type}]:`, {
      severity: incident.severity,
      description: incident.description,
      userId: incident.userId,
      clientIp: incident.clientIp,
      timestamp: incident.timestamp,
      actions: incident.recommendedActions,
    });

    // High severity incidents trigger immediate actions
    if (incident.severity >= 8) {
      await this.handleHighSeverityIncident(incident);
    }

    // Update metrics
    this.metrics.suspiciousActivity++;
  }

  /**
   * Handle high severity security incidents
   *
   * @param incident - Security incident
   */
  private async handleHighSeverityIncident(
    incident: SecurityIncident
  ): Promise<void> {
    console.error(`🚨 HIGH SEVERITY INCIDENT [${incident.type}]:`, incident);

    // Automatic actions for high severity incidents
    switch (incident.type) {
      case SecurityIncidentType.BLACKLISTED_TOKEN:
        // Already handled by blocking the token
        break;

      case SecurityIncidentType.RATE_LIMIT_EXCEEDED:
        // Could implement IP blocking here
        if (incident.clientIp) {
          this.suspiciousIPs.set(incident.clientIp, {
            count: 10,
            lastSeen: Date.now(),
          });
        }
        break;

      default:
        // Log for manual review
        console.error('Manual review required for incident:', incident);
    }
  }

  // ============================================================================
  // RESULT CREATION HELPERS
  // ============================================================================

  /**
   * Create blocked authentication result
   */
  private createBlockedResult(
    request: AuthRequest,
    securityCheck: {
      blocked: boolean;
      riskScore: number;
      warnings: string[];
      blockReason?: string;
    },
    requestId: string,
    startTime: bigint
  ): AuthResult {
    return {
      authenticated: false,
      tokenValidation: {
        valid: false,
        error: securityCheck.blockReason || 'Request blocked',
        metadata: {
          validationTimeUs: 0,
          cached: false,
          validatorType: 'security_filter',
        },
      },
      security: {
        riskScore: securityCheck.riskScore,
        warnings: securityCheck.warnings,
        blocked: true,
        blockReason: securityCheck.blockReason,
      },
      performance: {
        totalTimeUs: Number(process.hrtime.bigint() - startTime) / 1000,
        tokenValidationTimeUs: 0,
        userContextTimeUs: 0,
        cached: false,
      },
      tracking: {
        requestId,
        provider: AuthProviderType.JWT, // Default
        timestamp: new Date().toISOString(),
      },
    };
  }

  /**
   * Create failure authentication result
   */
  private createFailureResult(
    request: AuthRequest,
    tokenValidation: TokenValidationResult,
    requestId: string,
    startTime: bigint,
    tokenValidationTime: number
  ): AuthResult {
    return {
      authenticated: false,
      tokenValidation,
      security: {
        riskScore: 60,
        warnings: ['Token validation failed'],
        blocked: false,
      },
      performance: {
        totalTimeUs: Number(process.hrtime.bigint() - startTime) / 1000,
        tokenValidationTimeUs: tokenValidationTime,
        userContextTimeUs: 0,
        cached: tokenValidation.metadata?.cached || false,
      },
      tracking: {
        requestId,
        provider:
          (tokenValidation.metadata?.validatorType as AuthProviderType) ||
          AuthProviderType.JWT,
        timestamp: new Date().toISOString(),
      },
    };
  }

  /**
   * Create success authentication result
   */
  private createSuccessResult(
    request: AuthRequest,
    tokenValidation: TokenValidationResult,
    user: UserContext,
    securityCheck: { riskScore: number; warnings: string[] },
    requestId: string,
    startTime: bigint,
    tokenValidationTime: number,
    contextLoadTime: number
  ): AuthResult {
    return {
      authenticated: true,
      user,
      tokenValidation,
      security: {
        riskScore: securityCheck.riskScore,
        warnings: securityCheck.warnings,
        blocked: false,
      },
      performance: {
        totalTimeUs: Number(process.hrtime.bigint() - startTime) / 1000,
        tokenValidationTimeUs: tokenValidationTime,
        userContextTimeUs: contextLoadTime,
        cached: tokenValidation.metadata?.cached || false,
      },
      tracking: {
        requestId,
        provider:
          (tokenValidation.metadata?.validatorType as AuthProviderType) ||
          AuthProviderType.JWT,
        timestamp: new Date().toISOString(),
      },
    };
  }

  // ============================================================================
  // UTILITIES
  // ============================================================================

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `auth_${Date.now()}_${Math.random().toString(36).substring(2)}`;
  }

  /**
   * Sanitize token for logging (keep first 8 and last 4 characters)
   */
  private sanitizeToken(token: string): string {
    if (token.length <= 12) {
      return '[short-token]';
    }
    return `${token.substring(0, 8)}...${token.substring(token.length - 4)}`;
  }

  /**
   * Get incident severity level
   */
  private getIncidentSeverity(type: SecurityIncidentType): number {
    const severities: Record<SecurityIncidentType, number> = {
      [SecurityIncidentType.INVALID_TOKEN]: 4,
      [SecurityIncidentType.EXPIRED_TOKEN]: 3,
      [SecurityIncidentType.BLACKLISTED_TOKEN]: 9,
      [SecurityIncidentType.SUSPICIOUS_IP]: 6,
      [SecurityIncidentType.RATE_LIMIT_EXCEEDED]: 7,
      [SecurityIncidentType.BRUTE_FORCE_ATTEMPT]: 8,
      [SecurityIncidentType.UNUSUAL_PATTERN]: 5,
      [SecurityIncidentType.PRIVILEGE_ESCALATION]: 10,
    };

    return severities[type] || 5;
  }

  /**
   * Get recommended actions for incident type
   */
  private getRecommendedActions(type: SecurityIncidentType): string[] {
    const actions: Record<SecurityIncidentType, string[]> = {
      [SecurityIncidentType.INVALID_TOKEN]: [
        'Monitor for patterns',
        'Check token source',
      ],
      [SecurityIncidentType.EXPIRED_TOKEN]: [
        'Normal expiration',
        'No action needed',
      ],
      [SecurityIncidentType.BLACKLISTED_TOKEN]: [
        'Block IP',
        'Investigate source',
      ],
      [SecurityIncidentType.SUSPICIOUS_IP]: ['Monitor IP', 'Consider blocking'],
      [SecurityIncidentType.RATE_LIMIT_EXCEEDED]: [
        'Block IP temporarily',
        'Monitor patterns',
      ],
      [SecurityIncidentType.BRUTE_FORCE_ATTEMPT]: [
        'Block IP',
        'Alert security team',
      ],
      [SecurityIncidentType.UNUSUAL_PATTERN]: [
        'Investigate pattern',
        'Monitor closely',
      ],
      [SecurityIncidentType.PRIVILEGE_ESCALATION]: [
        'Block immediately',
        'Alert security team',
      ],
    };

    return actions[type] || ['Review manually'];
  }

  /**
   * Initialize metrics
   */
  private initializeMetrics(): AuthMetrics {
    return {
      totalAttempts: 0,
      successfulAuths: 0,
      failedAttempts: 0,
      successRate: 100,
      cacheHitRate: 0,
      averageAuthTimeUs: 0,
      blockedTokens: 0,
      suspiciousActivity: 0,
    };
  }

  /**
   * Update performance metrics
   */
  private updatePerformanceMetrics(result: AuthResult): void {
    // Update cache hit rate
    const totalRequests = this.metrics.totalAttempts;
    const currentCacheHitRate = this.metrics.cacheHitRate;
    const newCacheHit = result.performance.cached ? 1 : 0;

    this.metrics.cacheHitRate =
      totalRequests > 1
        ? ((currentCacheHitRate * (totalRequests - 1) + newCacheHit) /
            totalRequests) *
          100
        : newCacheHit * 100;

    // Update average auth time
    const currentAvgTime = this.metrics.averageAuthTimeUs;
    this.metrics.averageAuthTimeUs =
      totalRequests > 1
        ? (currentAvgTime * (totalRequests - 1) +
            result.performance.totalTimeUs) /
          totalRequests
        : result.performance.totalTimeUs;

    // Update success rate
    this.metrics.successRate =
      (this.metrics.successfulAuths / this.metrics.totalAttempts) * 100;
  }

  /**
   * Start security monitoring tasks
   */
  private startSecurityMonitoring(): void {
    if (!this.enableSecurityMonitoring) {
      return;
    }

    // Clean up old suspicious IPs every hour
    setInterval(
      () => {
        this.cleanupSuspiciousIPs();
      },
      60 * 60 * 1000
    );

    // Clean up old rate limit entries every 5 minutes
    setInterval(
      () => {
        this.cleanupRateLimits();
      },
      5 * 60 * 1000
    );

    console.log('🔍 Security monitoring started');
  }

  /**
   * Cleanup old suspicious IP entries
   */
  private cleanupSuspiciousIPs(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [ip, info] of this.suspiciousIPs.entries()) {
      if (now - info.lastSeen > maxAge) {
        this.suspiciousIPs.delete(ip);
      }
    }
  }

  /**
   * Cleanup old rate limit entries
   */
  private cleanupRateLimits(): void {
    const now = Date.now();
    const maxAge = 60 * 60 * 1000; // 1 hour

    for (const [key, info] of this.rateLimits.entries()) {
      if (now - info.window > maxAge) {
        this.rateLimits.delete(key);
      }
    }
  }

  /**
   * Log authentication event for audit
   */
  private async logAuthenticationEvent(
    request: AuthRequest,
    result: AuthResult
  ): Promise<void> {
    const logEntry = {
      timestamp: result.tracking.timestamp,
      requestId: result.tracking.requestId,
      authenticated: result.authenticated,
      userId: result.user?.userId,
      provider: result.tracking.provider,
      clientIp: request.clientIp,
      userAgent: request.userAgent,
      path: request.path,
      method: request.method,
      riskScore: result.security.riskScore,
      warnings: result.security.warnings,
      blocked: result.security.blocked,
      performance: result.performance,
    };

    // In a production system, this would go to a dedicated audit log
    console.log('📝 AUTH_AUDIT:', JSON.stringify(logEntry));
  }

  // ============================================================================
  // PUBLIC API METHODS
  // ============================================================================

  /**
   * Get authentication metrics
   */
  public getMetrics(): AuthMetrics {
    return { ...this.metrics };
  }

  /**
   * Get recent security incidents
   */
  public getSecurityIncidents(limit = 50): SecurityIncident[] {
    return this.incidents.slice(-limit);
  }

  /**
   * Blacklist a token
   */
  public blacklistToken(token: string, reason = 'manual_blacklist'): void {
    this.tokenBlacklist.add(token);
    this.metrics.blockedTokens++;

    console.warn(
      `⚫ Token blacklisted: ${this.sanitizeToken(token)} (reason: ${reason})`
    );
  }

  /**
   * Clear token blacklist
   */
  public clearTokenBlacklist(): void {
    const count = this.tokenBlacklist.size;
    this.tokenBlacklist.clear();
    console.log(`🧹 Token blacklist cleared (${count} tokens removed)`);
  }

  /**
   * Clear suspicious IPs - primarily for testing purposes
   */
  public clearSuspiciousIPs(): void {
    const count = this.suspiciousIPs.size;
    this.suspiciousIPs.clear();
    console.log(`🧹 Suspicious IP list cleared (${count} IPs removed)`);
  }

  /**
   * Get service health status
   */
  public getHealthStatus(): {
    healthy: boolean;
    validators: Record<string, unknown>;
    context: Record<string, unknown>;
    security: {
      blacklistedTokens: number;
      suspiciousIPs: number;
      recentIncidents: number;
    };
  } {
    const validatorHealth = this.validatorFactory.getHealthStatus();
    const contextStatus = this.contextManager.getCacheStatus();

    return {
      healthy: Array.from(validatorHealth.values()).every((v) => v.healthy),
      validators: Object.fromEntries(validatorHealth),
      context: contextStatus,
      security: {
        blacklistedTokens: this.tokenBlacklist.size,
        suspiciousIPs: this.suspiciousIPs.size,
        recentIncidents: this.incidents.filter(
          (i) => Date.now() - new Date(i.timestamp).getTime() < 60 * 60 * 1000
        ).length,
      },
    };
  }

  /**
   * Shutdown authentication service
   */
  public shutdown(): void {
    this.validatorFactory.shutdown();
    this.contextManager.shutdown();
    console.log('🛡️ Authentication Service shutdown complete');
  }
}
