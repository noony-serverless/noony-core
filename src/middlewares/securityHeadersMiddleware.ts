import { BaseMiddleware, Context } from '../core';

export interface SecurityHeadersOptions {
  /**
   * Content Security Policy directive
   * @default "default-src 'self'"
   */
  contentSecurityPolicy?: string;

  /**
   * Strict-Transport-Security max-age in seconds
   * @default 31536000 (1 year)
   */
  hstsMaxAge?: number;

  /**
   * Enable HSTS includeSubDomains
   * @default true
   */
  hstsIncludeSubDomains?: boolean;

  /**
   * Frame options policy
   * @default 'DENY'
   */
  frameOptions?: 'DENY' | 'SAMEORIGIN' | 'ALLOW-FROM';

  /**
   * X-Content-Type-Options
   * @default 'nosniff'
   */
  contentTypeOptions?: 'nosniff';

  /**
   * Referrer Policy
   * @default 'strict-origin-when-cross-origin'
   */
  referrerPolicy?: string;

  /**
   * Permissions Policy (formerly Feature Policy)
   * @default 'geolocation=(), microphone=(), camera=()'
   */
  permissionsPolicy?: string;

  /**
   * Cross-Origin-Embedder-Policy
   * @default 'require-corp'
   */
  crossOriginEmbedderPolicy?: string;

  /**
   * Cross-Origin-Opener-Policy
   * @default 'same-origin'
   */
  crossOriginOpenerPolicy?: string;

  /**
   * Cross-Origin-Resource-Policy
   * @default 'same-origin'
   */
  crossOriginResourcePolicy?: string;

  /**
   * CORS configuration
   */
  cors?: {
    origin?: string | string[] | boolean;
    methods?: string[];
    allowedHeaders?: string[];
    exposedHeaders?: string[];
    credentials?: boolean;
    maxAge?: number;
  };

  /**
   * Remove server identification headers
   * @default true
   */
  removeServerHeader?: boolean;

  /**
   * Remove X-Powered-By headers
   * @default true
   */
  removePoweredBy?: boolean;
}

const DEFAULT_OPTIONS: Required<Omit<SecurityHeadersOptions, 'cors'>> & {
  cors?: SecurityHeadersOptions['cors'];
} = {
  contentSecurityPolicy:
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
  hstsMaxAge: 31536000, // 1 year
  hstsIncludeSubDomains: true,
  frameOptions: 'DENY',
  contentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy:
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()',
  crossOriginEmbedderPolicy: 'require-corp',
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginResourcePolicy: 'same-origin',
  removeServerHeader: true,
  removePoweredBy: true,
};

/**
 * Validates CORS origin against allowed patterns
 */
const isOriginAllowed = (
  origin: string,
  allowedOrigins: string | string[] | boolean
): boolean => {
  if (allowedOrigins === true) return true;
  if (allowedOrigins === false) return false;
  if (typeof allowedOrigins === 'string') return origin === allowedOrigins;
  if (Array.isArray(allowedOrigins)) {
    return allowedOrigins.some((allowed) => {
      // Support wildcard patterns like *.example.com
      if (allowed.includes('*')) {
        const regex = new RegExp('^' + allowed.replace(/\*/g, '.*') + '$');
        return regex.test(origin);
      }
      return origin === allowed;
    });
  }
  return false;
};

/**
 * Security Headers Middleware
 * Implements comprehensive security headers following OWASP recommendations
 */
export class SecurityHeadersMiddleware implements BaseMiddleware {
  private options: Required<Omit<SecurityHeadersOptions, 'cors'>> & {
    cors?: SecurityHeadersOptions['cors'];
  };

  constructor(options: SecurityHeadersOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  async before(context: Context): Promise<void> {
    const headers: Record<string, string> = {};

    // Content Security Policy
    headers['Content-Security-Policy'] = this.options.contentSecurityPolicy;

    // Strict Transport Security (HTTPS only)
    const hstsValue = `max-age=${this.options.hstsMaxAge}${
      this.options.hstsIncludeSubDomains ? '; includeSubDomains' : ''
    }; preload`;
    headers['Strict-Transport-Security'] = hstsValue;

    // Frame Options
    headers['X-Frame-Options'] = this.options.frameOptions;

    // Content Type Options
    headers['X-Content-Type-Options'] = this.options.contentTypeOptions;

    // Referrer Policy
    headers['Referrer-Policy'] = this.options.referrerPolicy;

    // Permissions Policy
    headers['Permissions-Policy'] = this.options.permissionsPolicy;

    // Cross-Origin Policies
    headers['Cross-Origin-Embedder-Policy'] =
      this.options.crossOriginEmbedderPolicy;
    headers['Cross-Origin-Opener-Policy'] =
      this.options.crossOriginOpenerPolicy;
    headers['Cross-Origin-Resource-Policy'] =
      this.options.crossOriginResourcePolicy;

    // Remove identifying headers
    if (this.options.removeServerHeader) {
      delete headers['Server'];
    }
    if (this.options.removePoweredBy) {
      delete headers['X-Powered-By'];
    }

    // CORS headers
    if (this.options.cors) {
      const originHeader = context.req.headers?.['origin'];
      const origin = Array.isArray(originHeader)
        ? originHeader[0]
        : originHeader || '';
      const requestMethod =
        context.req.headers?.['access-control-request-method'];
      const requestHeaders =
        context.req.headers?.['access-control-request-headers'];

      // Handle preflight requests
      if (
        context.req.method === 'OPTIONS' &&
        (requestMethod || requestHeaders)
      ) {
        if (
          this.options.cors.origin &&
          isOriginAllowed(origin, this.options.cors.origin)
        ) {
          headers['Access-Control-Allow-Origin'] = origin;
        }

        if (this.options.cors.methods) {
          headers['Access-Control-Allow-Methods'] =
            this.options.cors.methods.join(', ');
        }

        if (this.options.cors.allowedHeaders) {
          headers['Access-Control-Allow-Headers'] =
            this.options.cors.allowedHeaders.join(', ');
        }

        if (this.options.cors.maxAge !== undefined) {
          headers['Access-Control-Max-Age'] = String(this.options.cors.maxAge);
        }

        if (this.options.cors.credentials) {
          headers['Access-Control-Allow-Credentials'] = 'true';
        }

        // Apply headers and return early for preflight
        Object.entries(headers).forEach(([key, value]) => {
          if (value !== undefined) {
            context.res.header(key, value);
          }
        });
        context.res.status(204).json({});
        return;
      }

      // Handle actual requests
      if (
        this.options.cors.origin &&
        isOriginAllowed(origin, this.options.cors.origin)
      ) {
        headers['Access-Control-Allow-Origin'] = origin;
      }

      if (this.options.cors.exposedHeaders) {
        headers['Access-Control-Expose-Headers'] =
          this.options.cors.exposedHeaders.join(', ');
      }

      if (this.options.cors.credentials) {
        headers['Access-Control-Allow-Credentials'] = 'true';
      }
    }

    // Apply headers to response
    Object.entries(headers).forEach(([key, value]) => {
      if (value !== undefined) {
        context.res.header(key, value);
      }
    });
  }
}

/**
 * Security Headers Middleware Factory
 * @param options Security headers configuration
 * @returns BaseMiddleware
 */
export const securityHeaders = (
  options: SecurityHeadersOptions = {}
): BaseMiddleware => new SecurityHeadersMiddleware(options);

/**
 * Predefined security configurations
 */
export const SecurityPresets = {
  /**
   * Strict security configuration for high-security applications
   */
  STRICT: {
    contentSecurityPolicy:
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self';",
    hstsMaxAge: 63072000, // 2 years
    frameOptions: 'DENY' as const,
    crossOriginEmbedderPolicy: 'require-corp',
    crossOriginOpenerPolicy: 'same-origin',
    crossOriginResourcePolicy: 'same-origin',
  } satisfies SecurityHeadersOptions,

  /**
   * Balanced security configuration for most applications
   */
  BALANCED: {
    contentSecurityPolicy:
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
    hstsMaxAge: 31536000, // 1 year
    frameOptions: 'SAMEORIGIN' as const,
  } satisfies SecurityHeadersOptions,

  /**
   * Permissive security configuration for development
   */
  DEVELOPMENT: {
    contentSecurityPolicy:
      "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' ws: wss:;",
    hstsMaxAge: 0,
    frameOptions: 'SAMEORIGIN' as const,
    cors: {
      origin: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    },
  } satisfies SecurityHeadersOptions,
} as const;
