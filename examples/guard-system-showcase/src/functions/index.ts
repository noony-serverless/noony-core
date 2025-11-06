/**
 * Google Cloud Functions for Guard System Showcase
 *
 * Serverless functions demonstrating different permission resolution
 * strategies and authentication methods.
 *
 * @module CloudFunctions
 * @version 1.0.0
 */

import { Request, Response } from '@google-cloud/functions-framework';
import { getGuardConfig } from '@/config/guard.config';
import { GuardService } from '@/services/guard-service';
import { PermissionResolverType } from '@noony-serverless/core';

// Initialize Guard Service with configuration
const guardService = GuardService.getInstance(getGuardConfig());

/**
 * Demo function using Plain Permission Resolver
 */
export const demoPlainPermissions = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { authorization } = req.headers;
    const { userId, permissions } = req.body;

    if (!authorization || !userId || !permissions) {
      res.status(400).json({
        error: 'Missing required fields',
        required: ['authorization header', 'userId', 'permissions'],
      });
      return;
    }

    // Extract token from Authorization header
    const token = authorization.replace('Bearer ', '');

    // Authenticate first
    const authResult = await guardService.authenticate({
      token,
    });

    if (!authResult.authenticated) {
      res.status(401).json({
        error: 'Authentication failed',
        details: authResult.tokenValidation?.error,
      });
      return;
    }

    // Plain resolver only supports single permission checks
    // If multiple permissions provided, use the first one
    const singlePermission = Array.isArray(permissions)
      ? permissions[0]
      : permissions;

    if (!singlePermission) {
      res.status(400).json({
        error: 'Plain resolver requires at least one permission',
        received: permissions,
      });
      return;
    }

    // Check permissions using Plain resolver
    const permissionResult = await guardService.checkPermissions(
      userId,
      singlePermission,
      {},
      PermissionResolverType.PLAIN
    );

    res.json({
      success: true,
      resolver: 'Plain Permission Resolver',
      authentication: {
        validatorType: authResult.tokenValidation?.metadata?.validatorType,
        userId: authResult.user?.userId,
      },
      permissions: {
        allowed: permissionResult.allowed,
        checked: permissions,
        matched: permissionResult.matchedPermissions,
        resolutionTime: `${permissionResult.resolutionTimeUs}μs`,
        cached: permissionResult.cached,
      },
      metadata: permissionResult.metadata,
    });
  } catch (error) {
    console.error('Plain permissions demo error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
};

/**
 * Demo function using Wildcard Permission Resolver
 */
export const demoWildcardPermissions = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { authorization } = req.headers;
    const { userId, permissions } = req.body;

    if (!authorization || !userId || !permissions) {
      res.status(400).json({
        error: 'Missing required fields',
        required: ['authorization header', 'userId', 'permissions'],
      });
      return;
    }

    const token = authorization.replace('Bearer ', '');

    const authResult = await guardService.authenticate({
      token,
    });

    if (!authResult.authenticated) {
      res.status(401).json({
        error: 'Authentication failed',
        details: authResult.tokenValidation?.error,
      });
      return;
    }

    // Check permissions using Wildcard resolver
    const permissionResult = await guardService.checkPermissions(
      userId,
      permissions,
      {},
      PermissionResolverType.WILDCARD
    );

    res.json({
      success: true,
      resolver: 'Wildcard Permission Resolver',
      authentication: {
        validatorType: authResult.tokenValidation?.metadata?.validatorType,
        userId: authResult.user?.userId,
      },
      permissions: {
        allowed: permissionResult.allowed,
        checked: permissions,
        matched: permissionResult.matchedPermissions,
        patterns: permissionResult.metadata?.patterns,
        resolutionTime: `${permissionResult.resolutionTimeUs}μs`,
        cached: permissionResult.cached,
      },
      metadata: permissionResult.metadata,
    });
  } catch (error) {
    console.error('Wildcard permissions demo error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
};

/**
 * Demo function using Expression Permission Resolver
 */
export const demoExpressionPermissions = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { authorization } = req.headers;
    const { userId, expression } = req.body;

    if (!authorization || !userId || !expression) {
      res.status(400).json({
        error: 'Missing required fields',
        required: ['authorization header', 'userId', 'expression'],
      });
      return;
    }

    const token = authorization.replace('Bearer ', '');

    const authResult = await guardService.authenticate({
      token,
    });

    if (!authResult.authenticated) {
      res.status(401).json({
        error: 'Authentication failed',
        details: authResult.tokenValidation?.error,
      });
      return;
    }

    // Check permissions using Expression resolver
    const permissionResult = await guardService.checkPermissions(
      userId,
      expression,
      {},
      PermissionResolverType.EXPRESSION
    );

    res.json({
      success: true,
      resolver: 'Expression Permission Resolver',
      authentication: {
        validatorType: authResult.tokenValidation?.metadata?.validatorType,
        userId: authResult.user?.userId,
      },
      permissions: {
        allowed: permissionResult.allowed,
        expression: expression,
        complexity: permissionResult.metadata?.expressionComplexity,
        evaluationTime: permissionResult.metadata?.expressionEvaluationTimeUs,
        resolutionTime: `${permissionResult.resolutionTimeUs}μs`,
        cached: permissionResult.cached,
      },
      metadata: permissionResult.metadata,
    });
  } catch (error) {
    console.error('Expression permissions demo error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
};

/**
 * Complete guard demo with authentication and authorization
 */
export const demoCompleteGuard = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { authorization } = req.headers;
    const { userId, permissions, context } = req.body;

    if (!authorization || !userId || !permissions) {
      res.status(400).json({
        error: 'Missing required fields',
        required: ['authorization header', 'userId', 'permissions'],
      });
      return;
    }

    const token = authorization.replace('Bearer ', '');

    // Perform complete guard operation
    const guardResult = await guardService.guard({
      token,
      requirement: permissions,
      permissionContext: context || {},
    });

    res.json({
      success: true,
      operation: 'Complete Guard Check',
      result: {
        authenticated: guardResult.authenticated,
        authorized: guardResult.authorized,
        validatorType: guardResult.tokenValidation?.metadata?.validatorType,
        user: guardResult.user,
        permissions: {
          allowed: guardResult.permissionCheck?.allowed,
          checked: permissions,
          matched: guardResult.permissionCheck?.matchedPermissions,
          resolver: guardResult.permissionCheck?.resolverType,
          resolutionTime: guardResult.permissionCheck?.resolutionTimeUs,
        },
        performance: {
          totalTime: `${guardResult.performanceBreakdown.totalTimeUs}μs`,
          authTime: `${guardResult.performanceBreakdown.authenticationTimeUs}μs`,
          permissionTime: `${guardResult.performanceBreakdown.permissionCheckTimeUs}μs`,
          securityTime: `${guardResult.performanceBreakdown.securityAnalysisTimeUs}μs`,
        },
        security: guardResult.security,
      },
    });
  } catch (error) {
    console.error('Complete guard demo error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: (error as Error).message,
    });
  }
};
