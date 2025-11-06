import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { AuthenticationError, HttpError, SecurityError } from '../core/errors';
import { logger } from '../core/logger';

/**
 * Interface for custom token verification implementations.
 * Allows integration with various authentication providers (JWT, OAuth, custom tokens).
 *
 * @template T - The type of user data returned after successful token verification
 *
 * @example
 * JWT token verification:
 * ```typescript
 * import jwt from 'jsonwebtoken';
 * import { CustomTokenVerificationPort } from '@noony-serverless/core';
 *
 * interface User {
 *   id: string;
 *   email: string;
 *   roles: string[];
 * }
 *
 * class JWTVerificationPort implements CustomTokenVerificationPort<User> {
 *   constructor(private secret: string) {}
 *
 *   async verifyToken(token: string): Promise<User> {
 *     try {
 *       const payload = jwt.verify(token, this.secret) as any;
 *       return {
 *         id: payload.sub,
 *         email: payload.email,
 *         roles: payload.roles || []
 *       };
 *     } catch (error) {
 *       throw new Error('Invalid token');
 *     }
 *   }
 * }
 * ```
 *
 * @example
 * Custom API token verification:
 * ```typescript
 * class APIKeyVerificationPort implements CustomTokenVerificationPort<{ apiKey: string; permissions: string[] }> {
 *   async verifyToken(token: string): Promise<{ apiKey: string; permissions: string[] }> {
 *     const apiKey = await this.validateAPIKey(token);
 *     if (!apiKey) {
 *       throw new Error('Invalid API key');
 *     }
 *     return {
 *       apiKey: token,
 *       permissions: apiKey.permissions
 *     };
 *   }
 *
 *   private async validateAPIKey(key: string) {
 *     // Validate against database or external service
 *     return { permissions: ['read', 'write'] };
 *   }
 * }
 * ```
 */
export interface CustomTokenVerificationPort<T> {
  verifyToken(token: string): Promise<T>;
}

/**
 * Standard JWT payload interface with common claims.
 * Extends the payload with custom properties as needed.
 *
 * @example
 * Basic JWT payload usage:
 * ```typescript
 * import { JWTPayload } from '@noony-serverless/core';
 *
 * interface CustomJWTPayload extends JWTPayload {
 *   userId: string;
 *   email: string;
 *   roles: string[];
 * }
 *
 * const payload: CustomJWTPayload = {
 *   sub: 'user-123',
 *   exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
 *   iat: Math.floor(Date.now() / 1000),
 *   iss: 'my-app',
 *   aud: 'my-app-users',
 *   userId: 'user-123',
 *   email: 'user@example.com',
 *   roles: ['user', 'admin']
 * };
 * ```
 *
 * @example
 * Token validation with custom claims:
 * ```typescript
 * function validateCustomClaims(payload: JWTPayload & { roles?: string[] }) {
 *   if (!payload.roles || payload.roles.length === 0) {
 *     throw new Error('User must have at least one role');
 *   }
 *
 *   if (payload.exp && payload.exp < Date.now() / 1000) {
 *     throw new Error('Token has expired');
 *   }
 * }
 * ```
 */
export interface JWTPayload {
  exp?: number; // Expiration time (seconds since epoch)
  iat?: number; // Issued at time (seconds since epoch)
  nbf?: number; // Not before time (seconds since epoch)
  jti?: string; // JWT ID for token blacklisting
  iss?: string; // Issuer
  aud?: string | string[]; // Audience
  sub?: string; // Subject
  [key: string]: unknown;
}

/**
 * Configuration options for authentication middleware.
 * Provides comprehensive security controls and validation settings.
 *
 * @example
 * Basic authentication options:
 * ```typescript
 * import { AuthenticationOptions } from '@noony-serverless/core';
 *
 * const basicOptions: AuthenticationOptions = {
 *   maxTokenAge: 3600, // 1 hour
 *   clockTolerance: 60, // 1 minute
 *   requiredClaims: {
 *     issuer: 'my-app',
 *     audience: 'my-app-users'
 *   }
 * };
 * ```
 *
 * @example
 * Advanced options with rate limiting and blacklisting:
 * ```typescript
 * const advancedOptions: AuthenticationOptions = {
 *   maxTokenAge: 7200, // 2 hours
 *   clockTolerance: 30,
 *   rateLimiting: {
 *     maxAttempts: 5,
 *     windowMs: 15 * 60 * 1000 // 15 minutes
 *   },
 *   isTokenBlacklisted: async (tokenId) => {
 *     // Check Redis or database for blacklisted tokens
 *     return await redis.sismember('blacklisted_tokens', tokenId);
 *   },
 *   requiredClaims: {
 *     issuer: 'secure-app',
 *     audience: ['web-app', 'mobile-app']
 *   }
 * };
 * ```
 *
 * @example
 * Production security configuration:
 * ```typescript
 * const productionOptions: AuthenticationOptions = {
 *   maxTokenAge: 1800, // 30 minutes - short for security
 *   clockTolerance: 10, // Tight tolerance
 *   rateLimiting: {
 *     maxAttempts: 3, // Strict rate limiting
 *     windowMs: 30 * 60 * 1000 // 30 minutes lockout
 *   },
 *   isTokenBlacklisted: async (tokenId) => {
 *     const result = await database.query(
 *       'SELECT 1 FROM revoked_tokens WHERE jti = ?',
 *       [tokenId]
 *     );
 *     return result.length > 0;
 *   },
 *   requiredClaims: {
 *     issuer: 'production-auth-server',
 *     audience: 'production-api'
 *   }
 * };
 * ```
 */
export interface AuthenticationOptions {
  /**
   * Maximum token age in seconds (overrides exp claim validation)
   */
  maxTokenAge?: number;

  /**
   * Clock tolerance in seconds for time-based validations
   * @default 60
   */
  clockTolerance?: number;

  /**
   * Token blacklist checker function
   */
  isTokenBlacklisted?: (tokenId?: string) => Promise<boolean> | boolean;

  /**
   * Rate limiting per user/IP
   */
  rateLimiting?: {
    maxAttempts: number;
    windowMs: number;
  };

  /**
   * Required token claims
   */
  requiredClaims?: {
    issuer?: string;
    audience?: string | string[];
  };
}

// Simple in-memory store for rate limiting (use Redis in production)
const rateLimitStore = new Map<
  string,
  { attempts: number; resetTime: number }
>();

/**
 * Enhanced JWT validation with comprehensive security checks
 */
const validateJWTSecurity = (
  payload: JWTPayload,
  options: AuthenticationOptions = {},
  clientIP?: string
): void => {
  const now = Math.floor(Date.now() / 1000);
  const clockTolerance = options.clockTolerance || 60;

  // Validate expiration time
  if (payload.exp !== undefined) {
    if (payload.exp <= now - clockTolerance) {
      logger.warn('Token expired', {
        expiredAt: new Date(payload.exp * 1000).toISOString(),
        currentTime: new Date(now * 1000).toISOString(),
        clientIP,
      });
      throw new AuthenticationError('Token expired');
    }
  }

  // Validate not-before time
  if (payload.nbf !== undefined) {
    if (payload.nbf > now + clockTolerance) {
      logger.warn('Token used before valid time', {
        notBefore: new Date(payload.nbf * 1000).toISOString(),
        currentTime: new Date(now * 1000).toISOString(),
        clientIP,
      });
      throw new AuthenticationError('Token not yet valid');
    }
  }

  // Validate issued-at time if maxTokenAge is specified
  if (options.maxTokenAge && payload.iat !== undefined) {
    const tokenAge = now - payload.iat;
    if (tokenAge > options.maxTokenAge) {
      logger.warn('Token too old', {
        tokenAge: `${tokenAge}s`,
        maxAge: `${options.maxTokenAge}s`,
        clientIP,
      });
      throw new AuthenticationError('Token too old');
    }
  }

  // Validate required claims
  if (options.requiredClaims) {
    if (
      options.requiredClaims.issuer &&
      payload.iss !== options.requiredClaims.issuer
    ) {
      logger.warn('Invalid token issuer', {
        expected: options.requiredClaims.issuer,
        received: payload.iss,
        clientIP,
      });
      throw new SecurityError('Invalid token issuer');
    }

    if (options.requiredClaims.audience) {
      const requiredAud = options.requiredClaims.audience;
      const tokenAud = payload.aud;

      let isValidAudience = false;
      if (Array.isArray(requiredAud)) {
        isValidAudience = Array.isArray(tokenAud)
          ? tokenAud.some((aud) => requiredAud.includes(aud))
          : requiredAud.includes(tokenAud || '');
      } else {
        isValidAudience = Array.isArray(tokenAud)
          ? tokenAud.includes(requiredAud)
          : tokenAud === requiredAud;
      }

      if (!isValidAudience) {
        logger.warn('Invalid token audience', {
          expected: requiredAud,
          received: tokenAud,
          clientIP,
        });
        throw new SecurityError('Invalid token audience');
      }
    }
  }
};

/**
 * Check rate limiting for authentication attempts
 */
const checkRateLimit = (
  identifier: string,
  options: AuthenticationOptions
): void => {
  if (!options.rateLimiting) return;

  const now = Date.now();
  const key = `auth:${identifier}`;
  const limit = rateLimitStore.get(key);

  if (limit && now < limit.resetTime) {
    if (limit.attempts >= options.rateLimiting.maxAttempts) {
      logger.warn('Rate limit exceeded for authentication', {
        identifier,
        attempts: limit.attempts,
        resetTime: new Date(limit.resetTime).toISOString(),
      });
      throw new SecurityError(
        'Too many authentication attempts. Please try again later.'
      );
    }
    limit.attempts++;
  } else {
    rateLimitStore.set(key, {
      attempts: 1,
      resetTime: now + options.rateLimiting.windowMs,
    });
  }
};

async function verifyToken<TUser, TBody = unknown>(
  tokenVerificationPort: CustomTokenVerificationPort<TUser>,
  context: Context<TBody, TUser>,
  options: AuthenticationOptions = {}
): Promise<void> {
  const authHeader = context.req.headers?.authorization;
  const clientIP =
    context.req.ip ||
    (context.req.headers?.['x-forwarded-for'] as string) ||
    'unknown';
  const userAgent = context.req.headers?.['user-agent'] as string;

  if (!authHeader) {
    logger.warn('Missing authorization header', { clientIP, userAgent });
    throw new HttpError(401, 'No authorization header');
  }

  const authHeaderString = Array.isArray(authHeader)
    ? authHeader[0]
    : authHeader;
  const token = authHeaderString?.split('Bearer ')[1];

  if (!token) {
    logger.warn('Invalid token format', { clientIP, userAgent });
    throw new AuthenticationError('Invalid token format');
  }

  // Check rate limiting
  checkRateLimit(clientIP, options);

  try {
    // Verify token through port
    const user = await tokenVerificationPort.verifyToken(token);

    // If user has JWT payload, validate security aspects
    if (user && typeof user === 'object' && 'exp' in user) {
      validateJWTSecurity(user as JWTPayload, options, clientIP);

      // Check token blacklist if configured
      if (options.isTokenBlacklisted && 'jti' in user) {
        const isBlacklisted = await options.isTokenBlacklisted(
          (user as JWTPayload).jti
        );
        if (isBlacklisted) {
          logger.warn('Blacklisted token used', {
            tokenId: (user as JWTPayload).jti,
            clientIP,
            userAgent,
          });
          throw new SecurityError('Token has been revoked');
        }
      }
    }

    context.user = user;
    logger.debug('Successful authentication', {
      userId:
        typeof user === 'object' && user && 'sub' in user
          ? String(user.sub)
          : 'unknown',
      clientIP,
    });
  } catch (error) {
    // Log failed authentication attempt
    logger.warn('Authentication failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      clientIP,
      userAgent,
      tokenPreview: token.substring(0, 10) + '...',
    });

    if (error instanceof HttpError) {
      throw error;
    }
    throw new AuthenticationError('Invalid authentication');
  }
}

/**
 * Class-based authentication middleware with comprehensive security features.
 * Provides JWT validation, rate limiting, token blacklisting, and security logging.
 *
 * @template TUser - The type of user data returned by the token verification port
 * @template TBody - The type of the request body payload (preserves type chain)
 *
 * @example
 * Basic JWT authentication:
 * ```typescript
 * import { Handler, AuthenticationMiddleware } from '@noony-serverless/core';
 * import jwt from 'jsonwebtoken';
 *
 * interface User {
 *   id: string;
 *   email: string;
 *   roles: string[];
 * }
 *
 * class JWTVerifier implements CustomTokenVerificationPort<User> {
 *   async verifyToken(token: string): Promise<User> {
 *     const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
 *     return {
 *       id: payload.sub,
 *       email: payload.email,
 *       roles: payload.roles || []
 *     };
 *   }
 * }
 *
 * const protectedHandler = new Handler()
 *   .use(new AuthenticationMiddleware(new JWTVerifier()))
 *   .handle(async (request, context) => {
 *     const user = context.user as User;
 *     return {
 *       success: true,
 *       data: { message: `Hello ${user.email}`, userId: user.id }
 *     };
 *   });
 * ```
 *
 * @example
 * Advanced authentication with security options:
 * ```typescript
 * const secureAuthMiddleware = new AuthenticationMiddleware(
 *   new JWTVerifier(),
 *   {
 *     maxTokenAge: 1800, // 30 minutes
 *     rateLimiting: {
 *       maxAttempts: 5,
 *       windowMs: 15 * 60 * 1000 // 15 minutes
 *     },
 *     isTokenBlacklisted: async (tokenId) => {
 *       return await redis.sismember('revoked_tokens', tokenId);
 *     },
 *     requiredClaims: {
 *       issuer: 'my-auth-server',
 *       audience: 'my-api'
 *     }
 *   }
 * );
 *
 * const secureHandler = new Handler()
 *   .use(secureAuthMiddleware)
 *   .handle(async (request, context) => {
 *     // Only authenticated users reach here
 *     return { success: true, data: 'Secure data' };
 *   });
 * ```
 *
 * @example
 * Google Cloud Functions integration:
 * ```typescript
 * import { http } from '@google-cloud/functions-framework';
 *
 * const userProfileHandler = new Handler()
 *   .use(new AuthenticationMiddleware(new JWTVerifier()))
 *   .handle(async (request, context) => {
 *     const user = context.user as User;
 *     const profile = await getUserProfile(user.id);
 *     return { success: true, data: profile };
 *   });
 *
 * export const getUserProfile = http('getUserProfile', (req, res) => {
 *   return userProfileHandler.execute(req, res);
 * });
 * ```
 */
export class AuthenticationMiddleware<TUser = unknown, TBody = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  constructor(
    private tokenVerificationPort: CustomTokenVerificationPort<TUser>,
    private options: AuthenticationOptions = {}
  ) {}

  async before(context: Context<TBody, TUser>): Promise<void> {
    await verifyToken<TUser, TBody>(
      this.tokenVerificationPort,
      context,
      this.options
    );
  }
}

/**
 * Factory function that creates an authentication middleware with token verification.
 * Provides a functional approach for authentication setup.
 *
 * @template TUser - The type of user data returned by the token verification port
 * @template TBody - The type of the request body payload (preserves type chain)
 * @param tokenVerificationPort - The token verification implementation
 * @param options - Authentication configuration options
 * @returns A BaseMiddleware object with authentication logic
 *
 * @example
 * Simple JWT authentication:
 * ```typescript
 * import { Handler, verifyAuthTokenMiddleware } from '@noony-serverless/core';
 *
 * class SimpleJWTVerifier implements CustomTokenVerificationPort<{ userId: string }> {
 *   async verifyToken(token: string): Promise<{ userId: string }> {
 *     // Simple token verification logic
 *     if (token === 'valid-token') {
 *       return { userId: 'user-123' };
 *     }
 *     throw new Error('Invalid token');
 *   }
 * }
 *
 * const handler = new Handler()
 *   .use(verifyAuthTokenMiddleware(new SimpleJWTVerifier()))
 *   .handle(async (request, context) => {
 *     const user = context.user as { userId: string };
 *     return { success: true, userId: user.userId };
 *   });
 * ```
 *
 * @example
 * API key authentication with rate limiting:
 * ```typescript
 * interface APIKeyUser {
 *   keyId: string;
 *   permissions: string[];
 *   organization: string;
 * }
 *
 * class APIKeyVerifier implements CustomTokenVerificationPort<APIKeyUser> {
 *   async verifyToken(token: string): Promise<APIKeyUser> {
 *     const keyData = await this.validateAPIKey(token);
 *     if (!keyData) {
 *       throw new Error('Invalid API key');
 *     }
 *     return keyData;
 *   }
 *
 *   private async validateAPIKey(key: string): Promise<APIKeyUser | null> {
 *     // Database lookup or external validation
 *     return {
 *       keyId: 'key-123',
 *       permissions: ['read', 'write'],
 *       organization: 'org-456'
 *     };
 *   }
 * }
 *
 * const apiHandler = new Handler()
 *   .use(verifyAuthTokenMiddleware(
 *     new APIKeyVerifier(),
 *     {
 *       rateLimiting: {
 *         maxAttempts: 100,
 *         windowMs: 60 * 1000 // 1 minute
 *       }
 *     }
 *   ))
 *   .handle(async (request, context) => {
 *     const apiUser = context.user as APIKeyUser;
 *     return {
 *       success: true,
 *       data: { organization: apiUser.organization }
 *     };
 *   });
 * ```
 *
 * @example
 * Express-style middleware chain:
 * ```typescript
 * import { Handler, verifyAuthTokenMiddleware, errorHandler } from '@noony-serverless/core';
 *
 * const authMiddleware = verifyAuthTokenMiddleware(
 *   new JWTVerifier(),
 *   {
 *     maxTokenAge: 3600,
 *     requiredClaims: {
 *       issuer: 'my-app',
 *       audience: 'api-users'
 *     }
 *   }
 * );
 *
 * const protectedEndpoint = new Handler()
 *   .use(authMiddleware)
 *   .use(errorHandler())
 *   .handle(async (request, context) => {
 *     // Authenticated user available in context.user
 *     return { success: true, data: 'Protected resource' };
 *   });
 * ```
 *
 * @example
 * Multiple authentication strategies:
 * ```typescript
 * // Different handlers for different auth types
 * const jwtHandler = new Handler()
 *   .use(verifyAuthTokenMiddleware(new JWTVerifier()))
 *   .handle(jwtLogic);
 *
 * const apiKeyHandler = new Handler()
 *   .use(verifyAuthTokenMiddleware(new APIKeyVerifier()))
 *   .handle(apiKeyLogic);
 *
 * // Route based on authentication type
 * export const handleRequest = (req: any, res: any) => {
 *   const authHeader = req.headers.authorization;
 *   if (authHeader?.startsWith('Bearer jwt.')) {
 *     return jwtHandler.execute(req, res);
 *   } else if (authHeader?.startsWith('Bearer ak_')) {
 *     return apiKeyHandler.execute(req, res);
 *   } else {
 *     res.status(401).json({ error: 'Authentication required' });
 *   }
 * };
 * ```
 */
export const verifyAuthTokenMiddleware = <TUser = unknown, TBody = unknown>(
  tokenVerificationPort: CustomTokenVerificationPort<TUser>,
  options: AuthenticationOptions = {}
): BaseMiddleware<TBody, TUser> => ({
  async before(context: Context<TBody, TUser>): Promise<void> {
    await verifyToken<TUser, TBody>(tokenVerificationPort, context, options);
  },
});

/*
// Example protected endpoint
const protectedHandler = new Handler()
  .use(verifyAuthTokenMiddleware(customTokenVerificationPort))
  .use(errorHandler())
  .use(responseWrapperMiddleware<any>())
  .handle(async (context: Context) => {
    const user = context.user;
    setResponseData(context, {
      message: 'Protected endpoint',
      user,
    });
  });
*/
