import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { AuthenticationError, HttpError, SecurityError } from '../core/errors';
import { logger } from '../core/logger';

export interface CustomTokenVerificationPort<T> {
  verifyToken(token: string): Promise<T>;
}

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

async function verifyToken<T>(
  tokenVerificationPort: CustomTokenVerificationPort<T>,
  context: Context,
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

export class AuthenticationMiddleware<T> implements BaseMiddleware {
  constructor(
    private tokenVerificationPort: CustomTokenVerificationPort<T>,
    private options: AuthenticationOptions = {}
  ) {}

  async before(context: Context): Promise<void> {
    await verifyToken(this.tokenVerificationPort, context, this.options);
  }
}

export const verifyAuthTokenMiddleware = <T>(
  tokenVerificationPort: CustomTokenVerificationPort<T>,
  options: AuthenticationOptions = {}
): BaseMiddleware => ({
  async before(context: Context): Promise<void> {
    await verifyToken(tokenVerificationPort, context, options);
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
