/**
 * Authentication API Handlers
 *
 * API handlers demonstrating authentication capabilities of the Guard System
 * Showcase. Provides comprehensive examples of token validation, user context
 * management, and authentication monitoring.
 *
 * Features:
 * - Multiple authentication provider demonstrations
 * - Token validation and refresh endpoints
 * - User context management
 * - Authentication performance monitoring
 * - Security incident response
 *
 * @module AuthHandlers
 * @version 1.0.0
 */

import { Request, Response } from 'express';
import {
  AuthenticationService,
  AuthRequest,
} from '@/auth/authentication-service';
import { TokenValidatorFactory } from '@/auth/token-validator-factory';
import { UserContextManager } from '@/auth/user-context-manager';
import { GuardService } from '@/services/guard-service';
import { getGuardConfig } from '@/config/guard.config';
import { AuthProviderType } from '@/types/auth.types';
import { config } from '@/config/environment.config';

/**
 * Authentication API Handlers
 *
 * Provides REST API endpoints for authentication operations with
 * comprehensive examples and monitoring capabilities.
 */
export class AuthHandlers {
  private readonly guardService: GuardService;
  private readonly authService: AuthenticationService;
  private readonly contextManager: UserContextManager;

  constructor(guardService: GuardService) {
    this.guardService = guardService;
    this.authService = AuthenticationService.getInstance();
    this.contextManager = UserContextManager.getInstance();
  }

  // ============================================================================
  // AUTHENTICATION ENDPOINTS
  // ============================================================================

  /**
   * Authenticate user with token
   *
   * POST /api/auth/authenticate
   *
   * Demonstrates comprehensive token validation with multiple providers,
   * security analysis, and performance monitoring.
   */
  public authenticate = async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();

    try {
      const authRequest: AuthRequest = {
        token: this.extractToken(req),
        clientIp: this.getClientIp(req),
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        metadata: {
          sessionId: req.get('X-Session-ID'),
          requestId: req.get('X-Request-ID'),
          acceptLanguage: req.get('Accept-Language'),
        },
      };

      const authResult = await this.guardService.authenticate(authRequest);

      const response = {
        success: authResult.authenticated,
        user: authResult.user
          ? {
              userId: authResult.user.userId,
              name: authResult.user.name,
              email: authResult.user.email,
              roles: authResult.user.roles,
              permissions: Array.from(authResult.user.permissions).sort(),
              metadata: {
                status: authResult.user.metadata.status,
                emailVerified: authResult.user.metadata.emailVerified,
                department: authResult.user.metadata.department,
                title: authResult.user.metadata.title,
                lastLoginAt: authResult.user.metadata.lastLoginAt,
              },
            }
          : undefined,
        security: {
          riskScore: authResult.security.riskScore,
          warnings: authResult.security.warnings,
          blocked: authResult.security.blocked,
          blockReason: authResult.security.blockReason,
        },
        performance: {
          totalTime: `${authResult.performance.totalTimeUs.toFixed(1)}μs`,
          tokenValidation: `${authResult.performance.tokenValidationTimeUs.toFixed(1)}μs`,
          userContext: `${authResult.performance.userContextTimeUs.toFixed(1)}μs`,
          cached: authResult.performance.cached,
        },
        tracking: {
          requestId: authResult.tracking.requestId,
          provider: authResult.tracking.provider,
          timestamp: authResult.tracking.timestamp,
        },
        error: authResult.authenticated
          ? undefined
          : authResult.tokenValidation.error,
      };

      // Log authentication attempt
      console.log(`🔐 Authentication attempt:`, {
        success: authResult.authenticated,
        user: authResult.user?.userId,
        ip: authRequest.clientIp,
        provider: authResult.tracking.provider,
        riskScore: authResult.security.riskScore,
        time: response.performance.totalTime,
      });

      const statusCode = authResult.security.blocked
        ? 423 // Locked
        : authResult.authenticated
          ? 200
          : 401;

      res.status(statusCode).json(response);
    } catch (error) {
      console.error('❌ Authentication endpoint error:', error);

      // Check if this is an authentication-related error
      if (
        (error as Error).message.includes('authentication token') ||
        (error as Error).message.includes('No authentication')
      ) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          performance: {
            totalTime: `${Date.now() - startTime}ms`,
          },
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Authentication service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
        performance: {
          totalTime: `${Date.now() - startTime}ms`,
        },
      });
    }
  };

  /**
   * Validate token without full authentication
   *
   * POST /api/auth/validate
   *
   * Lightweight token validation for API gateways and proxy services.
   * Returns minimal user information for performance optimization.
   */
  public validateToken = async (req: Request, res: Response): Promise<void> => {
    const startTime = process.hrtime.bigint();

    try {
      const token = this.extractToken(req);
      const provider = (req.body.provider as AuthProviderType) || undefined;

      // Use the validator factory with configuration for lightweight validation
      const guardConfig = getGuardConfig();
      const validatorFactory = TokenValidatorFactory.getInstance(
        guardConfig.authentication
      );
      const validator = validatorFactory.getValidator(provider);
      const validationResult = await validator.validateToken(token);

      const validationTime = Number(process.hrtime.bigint() - startTime) / 1000;

      const response = {
        valid: validationResult.valid,
        user: validationResult.decoded
          ? {
              userId: validationResult.decoded.sub,
              email: validationResult.decoded.email,
              name: validationResult.decoded.name,
              roles: validationResult.decoded.roles || [],
            }
          : undefined,
        metadata: {
          validationTime: `${validationTime.toFixed(1)}μs`,
          cached: validationResult.metadata?.cached || false,
          validatorType: validationResult.metadata?.validatorType,
        },
        error: validationResult.valid ? undefined : validationResult.error,
      };

      res.status(validationResult.valid ? 200 : 401).json(response);
    } catch (error) {
      console.error('❌ Token validation error:', error);

      res.status(500).json({
        valid: false,
        error: 'Token validation service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
      });
    }
  };

  /**
   * Refresh user context
   *
   * POST /api/auth/refresh-context
   *
   * Force refresh of user context from the source, bypassing cache.
   * Useful for immediate permission updates after role changes.
   */
  public refreshUserContext = async (
    req: Request,
    res: Response
  ): Promise<void> => {
    const startTime = process.hrtime.bigint();

    try {
      const { userId, expandPermissions = true } = req.body;

      if (!userId) {
        res.status(400).json({
          success: false,
          error: 'userId is required',
        });
        return;
      }

      // Refresh user context
      const refreshedContext = await this.contextManager.getUserContext(
        userId,
        {
          forceRefresh: true,
          expandPermissions,
        }
      );

      const refreshTime = Number(process.hrtime.bigint() - startTime) / 1000;

      const response = {
        success: true,
        user: {
          userId: refreshedContext.userId,
          name: refreshedContext.name,
          email: refreshedContext.email,
          roles: refreshedContext.roles,
          permissions: Array.from(refreshedContext.permissions).sort(),
          expandedPermissions: refreshedContext.expandedPermissions
            ? Array.from(refreshedContext.expandedPermissions).sort()
            : undefined,
          metadata: refreshedContext.metadata,
        },
        performance: {
          refreshTime: `${refreshTime.toFixed(1)}μs`,
          permissionCount: refreshedContext.permissions.size,
          expandedCount: refreshedContext.expandedPermissions?.size || 0,
        },
        timestamp: new Date().toISOString(),
      };

      console.log(`🔄 User context refreshed:`, {
        userId,
        permissionCount: refreshedContext.permissions.size,
        expandedCount: refreshedContext.expandedPermissions?.size || 0,
        time: response.performance.refreshTime,
      });

      res.status(200).json(response);
    } catch (error) {
      console.error('❌ Context refresh error:', error);

      res.status(500).json({
        success: false,
        error: 'Context refresh service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
      });
    }
  };

  // ============================================================================
  // USER INFORMATION ENDPOINTS
  // ============================================================================

  /**
   * Get current user information
   *
   * GET /api/auth/me
   *
   * Returns comprehensive user information for authenticated requests.
   */
  public getCurrentUser = async (
    req: Request,
    res: Response
  ): Promise<void> => {
    try {
      const authRequest: AuthRequest = {
        token: this.extractToken(req),
        clientIp: this.getClientIp(req),
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
      };

      const authResult = await this.guardService.authenticate(authRequest);

      if (!authResult.authenticated || !authResult.user) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
        });
        return;
      }

      const response = {
        success: true,
        user: {
          userId: authResult.user.userId,
          name: authResult.user.name,
          email: authResult.user.email,
          roles: authResult.user.roles,
          permissions: Array.from(authResult.user.permissions).sort(),
          metadata: {
            status: authResult.user.metadata.status,
            emailVerified: authResult.user.metadata.emailVerified,
            department: authResult.user.metadata.department,
            title: authResult.user.metadata.title,
            createdAt: authResult.user.metadata.createdAt,
            lastLoginAt: authResult.user.metadata.lastLoginAt,
            updatedAt: authResult.user.metadata.updatedAt,
          },
          lastUpdated: authResult.user.lastUpdated,
          expiresAt: authResult.user.expiresAt,
        },
        performance: {
          totalTime: `${authResult.performance.totalTimeUs.toFixed(1)}μs`,
          cached: authResult.performance.cached,
        },
      };

      res.status(200).json(response);
    } catch (error) {
      console.error('❌ Get current user error:', error);

      // Check if this is an authentication-related error
      if (
        (error as Error).message.includes('authentication token') ||
        (error as Error).message.includes('No authentication')
      ) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
      });
    }
  };

  /**
   * Get user permissions
   *
   * GET /api/auth/permissions
   *
   * Returns detailed permission information for the authenticated user.
   */
  public getUserPermissions = async (
    req: Request,
    res: Response
  ): Promise<void> => {
    try {
      const { expand = 'false', format = 'array' } = req.query;
      const expandPermissions = expand === 'true';

      const authRequest: AuthRequest = {
        token: this.extractToken(req),
        clientIp: this.getClientIp(req),
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
      };

      const authResult = await this.guardService.authenticate(authRequest);

      if (!authResult.authenticated || !authResult.user) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
        });
        return;
      }

      // Get expanded permissions if requested
      let expandedPermissions: Set<string> | undefined;
      if (expandPermissions && !authResult.user.expandedPermissions) {
        const refreshedContext = await this.contextManager.getUserContext(
          authResult.user.userId,
          { expandPermissions: true }
        );
        expandedPermissions = refreshedContext.expandedPermissions;
      } else {
        expandedPermissions = authResult.user.expandedPermissions;
      }

      // Format permissions based on request
      const formatPermissions = (permissions: Set<string>) => {
        if (format === 'grouped') {
          return this.groupPermissionsByResource(Array.from(permissions));
        }
        return Array.from(permissions).sort();
      };

      const response = {
        success: true,
        userId: authResult.user.userId,
        permissions: {
          base: formatPermissions(authResult.user.permissions),
          expanded: expandedPermissions
            ? formatPermissions(expandedPermissions)
            : undefined,
          count: {
            base: authResult.user.permissions.size,
            expanded: expandedPermissions?.size || 0,
          },
        },
        roles: authResult.user.roles,
        metadata: {
          expandedPermissions: expandPermissions,
          format,
          cached: authResult.performance.cached,
          lastUpdated: authResult.user.lastUpdated,
        },
      };

      res.status(200).json(response);
    } catch (error) {
      console.error('❌ Get user permissions error:', error);

      // Check if this is an authentication-related error
      if (
        (error as Error).message.includes('authentication token') ||
        (error as Error).message.includes('No authentication')
      ) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
      });
    }
  };

  // ============================================================================
  // MONITORING AND DEBUGGING ENDPOINTS
  // ============================================================================

  /**
   * Get authentication statistics
   *
   * GET /api/auth/stats
   *
   * Returns authentication service statistics for monitoring.
   */
  public getAuthStats = async (req: Request, res: Response): Promise<void> => {
    try {
      // Check if user has admin permissions
      const authRequest: AuthRequest = {
        token: this.extractToken(req),
        clientIp: this.getClientIp(req),
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
      };

      const guardResult = await this.guardService.guard({
        ...authRequest,
        requirement: 'admin:system',
      });

      if (!guardResult.authorized) {
        res.status(403).json({
          success: false,
          error: 'Admin privileges required',
        });
        return;
      }

      const authMetrics = this.authService.getMetrics();
      const guardStats = this.guardService.getStats();
      const contextStats = this.contextManager.getStatistics();

      const response = {
        success: true,
        statistics: {
          authentication: {
            totalAttempts: authMetrics.totalAttempts,
            successfulAuths: authMetrics.successfulAuths,
            failedAttempts: authMetrics.failedAttempts,
            successRate: authMetrics.successRate,
            cacheHitRate: authMetrics.cacheHitRate,
            averageAuthTime: `${authMetrics.averageAuthTimeUs.toFixed(1)}μs`,
            blockedTokens: authMetrics.blockedTokens,
            suspiciousActivity: authMetrics.suspiciousActivity,
          },
          guard: {
            totalOperations: guardStats.totalOperations,
            successfulOperations: guardStats.successfulOperations,
            failedOperations: guardStats.failedOperations,
            authOnlyOperations: guardStats.authOnlyOperations,
            fullGuardOperations: guardStats.fullGuardOperations,
            averageTimeByPhase: {
              authentication: `${guardStats.averageTimeByPhase.authentication.toFixed(1)}μs`,
              authorization: `${guardStats.averageTimeByPhase.authorization.toFixed(1)}μs`,
              total: `${guardStats.averageTimeByPhase.total.toFixed(1)}μs`,
            },
            cachePerformance: {
              hitRate: `${guardStats.cachePerformance.hitRate.toFixed(1)}%`,
              hits: guardStats.cachePerformance.hits,
              misses: guardStats.cachePerformance.misses,
            },
          },
          userContext: {
            totalRequests: contextStats.totalRequests,
            cacheHitRate: `${((contextStats.cacheHits.total / (contextStats.cacheHits.total + contextStats.cacheMisses)) * 100).toFixed(1)}%`,
            averageLoadTime: `${contextStats.averageLoadTime.overall.toFixed(1)}μs`,
            permissionExpansion: {
              totalExpansions: contextStats.permissionExpansion.totalExpansions,
              averageExpansionTime: `${contextStats.permissionExpansion.averageExpansionTime.toFixed(1)}μs`,
              averagePermissionCount: Math.round(
                contextStats.permissionExpansion.averagePermissionCount
              ),
            },
          },
        },
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error) {
      console.error('❌ Get auth stats error:', error);

      res.status(500).json({
        success: false,
        error: 'Service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
      });
    }
  };

  /**
   * Get security incidents
   *
   * GET /api/auth/incidents
   *
   * Returns recent security incidents for monitoring and analysis.
   */
  public getSecurityIncidents = async (
    req: Request,
    res: Response
  ): Promise<void> => {
    try {
      const { limit = '50' } = req.query;

      // Check if user has admin permissions
      const authRequest: AuthRequest = {
        token: this.extractToken(req),
        clientIp: this.getClientIp(req),
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
      };

      const guardResult = await this.guardService.guard({
        ...authRequest,
        requirement: 'admin:security',
      });

      if (!guardResult.authorized) {
        res.status(403).json({
          success: false,
          error: 'Admin privileges required',
        });
        return;
      }

      const incidents = this.authService.getSecurityIncidents(
        parseInt(limit as string)
      );

      const response = {
        success: true,
        incidents: incidents.map((incident) => ({
          type: incident.type,
          severity: incident.severity,
          description: incident.description,
          userId: incident.userId,
          clientIp: incident.clientIp,
          timestamp: incident.timestamp,
          recommendedActions: incident.recommendedActions,
          metadata: incident.metadata,
        })),
        summary: {
          totalIncidents: incidents.length,
          severityBreakdown: this.groupIncidentsBySeverity(incidents),
          typeBreakdown: this.groupIncidentsByType(incidents),
        },
        timestamp: new Date().toISOString(),
      };

      res.status(200).json(response);
    } catch (error) {
      console.error('❌ Get security incidents error:', error);

      res.status(500).json({
        success: false,
        error: 'Service error',
        details:
          process.env.NODE_ENV === 'development'
            ? (error as Error).message
            : undefined,
      });
    }
  };

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  /**
   * Extract authentication token from request
   *
   * @param req - Express request
   * @returns Token string
   * @throws Error if no token found
   */
  private extractToken(req: Request): string {
    const authHeader = req.get('Authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Also check for token in body (for POST requests)
    if (req.body && req.body.token) {
      return req.body.token;
    }

    // Check query parameter (not recommended for production)
    if (req.query.token) {
      return req.query.token as string;
    }

    throw new Error('No authentication token provided');
  }

  /**
   * Get client IP address from request
   *
   * @param req - Express request
   * @returns Client IP address
   */
  private getClientIp(req: Request): string {
    return (
      req.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
      req.get('X-Real-IP') ||
      req.connection.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Group permissions by resource for structured display
   *
   * @param permissions - Array of permissions
   * @returns Grouped permissions object
   */
  private groupPermissionsByResource(
    permissions: string[]
  ): Record<string, string[]> {
    const grouped: Record<string, string[]> = {};

    for (const permission of permissions) {
      const parts = permission.split(':');
      const resource = parts[0] || 'global';
      const action = parts.slice(1).join(':') || 'access';

      if (!grouped[resource]) {
        grouped[resource] = [];
      }
      grouped[resource].push(action);
    }

    // Sort actions within each resource
    Object.keys(grouped).forEach((resource) => {
      grouped[resource] = grouped[resource].sort();
    });

    return grouped;
  }

  /**
   * Group security incidents by severity
   *
   * @param incidents - Array of incidents
   * @returns Severity breakdown
   */
  private groupIncidentsBySeverity(incidents: any[]): Record<string, number> {
    const groups: Record<string, number> = {};

    for (const incident of incidents) {
      const severityLevel =
        incident.severity >= 8
          ? 'high'
          : incident.severity >= 5
            ? 'medium'
            : 'low';
      groups[severityLevel] = (groups[severityLevel] || 0) + 1;
    }

    return groups;
  }

  /**
   * Group security incidents by type
   *
   * @param incidents - Array of incidents
   * @returns Type breakdown
   */
  private groupIncidentsByType(incidents: any[]): Record<string, number> {
    const groups: Record<string, number> = {};

    for (const incident of incidents) {
      groups[incident.type] = (groups[incident.type] || 0) + 1;
    }

    return groups;
  }
}

// Export singleton instance for easy use in server routes
export const authHandlers = new AuthHandlers(
  GuardService.getInstance(getGuardConfig())
);
