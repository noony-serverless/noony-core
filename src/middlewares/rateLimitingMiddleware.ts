import { BaseMiddleware, Context, SecurityError } from '../core';
import { logger } from '../core/logger';

export interface RateLimitOptions {
  /**
   * Maximum number of requests per window
   * @default 100
   */
  maxRequests?: number;

  /**
   * Time window in milliseconds
   * @default 60000 (1 minute)
   */
  windowMs?: number;

  /**
   * Function to generate rate limiting key
   * @default Uses IP address
   */
  keyGenerator?: (context: Context) => string;

  /**
   * Custom error message
   * @default 'Too many requests, please try again later'
   */
  message?: string;

  /**
   * HTTP status code for rate limit exceeded
   * @default 429
   */
  statusCode?: number;

  /**
   * Skip rate limiting for certain requests
   */
  skip?: (context: Context) => boolean;

  /**
   * Headers to include in response
   */
  headers?: boolean;

  /**
   * Different limits for different request types
   */
  dynamicLimits?: {
    [key: string]: {
      maxRequests: number;
      windowMs: number;
      matcher: (context: Context) => boolean;
    };
  };

  /**
   * Storage backend (default: in-memory)
   * Use Redis or other persistent storage in production
   */
  store?: RateLimitStore;
}

export interface RateLimitStore {
  increment(
    key: string,
    windowMs: number
  ): Promise<{ count: number; resetTime: number }>;
  get(key: string): Promise<{ count: number; resetTime: number } | null>;
  reset(key: string): Promise<void>;
}

export interface RateLimitInfo {
  limit: number;
  current: number;
  remaining: number;
  resetTime: number;
}

/**
 * In-memory rate limit store (use Redis in production)
 */
class MemoryStore implements RateLimitStore {
  private store = new Map<string, { count: number; resetTime: number }>();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Cleanup expired entries every 5 minutes
    this.cleanupInterval = setInterval(
      () => {
        this.cleanup();
      },
      5 * 60 * 1000
    );
  }

  async increment(
    key: string,
    windowMs: number
  ): Promise<{ count: number; resetTime: number }> {
    const now = Date.now();
    const resetTime = now + windowMs;
    const existing = this.store.get(key);

    if (existing && now < existing.resetTime) {
      existing.count++;
      return existing;
    } else {
      const newEntry = { count: 1, resetTime };
      this.store.set(key, newEntry);
      return newEntry;
    }
  }

  async get(key: string): Promise<{ count: number; resetTime: number } | null> {
    const entry = this.store.get(key);
    if (entry && Date.now() < entry.resetTime) {
      return entry;
    }
    if (entry) {
      this.store.delete(key);
    }
    return null;
  }

  async reset(key: string): Promise<void> {
    this.store.delete(key);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now >= entry.resetTime) {
        this.store.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}

/**
 * Default key generator using IP address with user identification
 */
const defaultKeyGenerator = (context: Context): string => {
  const ip =
    context.req.ip ||
    (Array.isArray(context.req.headers?.['x-forwarded-for'])
      ? context.req.headers['x-forwarded-for'][0]
      : context.req.headers?.['x-forwarded-for']) ||
    'unknown';

  // Include user ID if authenticated for per-user limits
  const userId =
    context.user && typeof context.user === 'object' && 'sub' in context.user
      ? context.user.sub
      : null;

  return userId ? `user:${userId}` : `ip:${ip}`;
};

/**
 * Apply rate limit headers to response
 */
const setRateLimitHeaders = (context: Context, info: RateLimitInfo): void => {
  context.res.header('X-RateLimit-Limit', String(info.limit));
  context.res.header(
    'X-RateLimit-Remaining',
    String(Math.max(0, info.remaining))
  );
  context.res.header(
    'X-RateLimit-Reset',
    String(Math.ceil(info.resetTime / 1000))
  );
  context.res.header(
    'Retry-After',
    String(Math.ceil((info.resetTime - Date.now()) / 1000))
  );
};

/**
 * Determine the appropriate rate limit for the request
 */
const getRateLimit = (
  context: Context,
  options: RateLimitOptions
): { maxRequests: number; windowMs: number } => {
  // Check dynamic limits first
  if (options.dynamicLimits) {
    for (const [name, config] of Object.entries(options.dynamicLimits)) {
      if (config.matcher(context)) {
        logger.debug('Applied dynamic rate limit', {
          limitName: name,
          maxRequests: config.maxRequests,
          windowMs: config.windowMs,
        });
        return { maxRequests: config.maxRequests, windowMs: config.windowMs };
      }
    }
  }

  // Default limits
  return {
    maxRequests: options.maxRequests || 100,
    windowMs: options.windowMs || 60000,
  };
};

/**
 * Rate Limiting Middleware
 * Implements sliding window rate limiting with comprehensive features
 */
export class RateLimitingMiddleware implements BaseMiddleware {
  private store: RateLimitStore;
  private options: Required<
    Omit<RateLimitOptions, 'keyGenerator' | 'skip' | 'dynamicLimits' | 'store'>
  > &
    Pick<RateLimitOptions, 'keyGenerator' | 'skip' | 'dynamicLimits' | 'store'>;

  constructor(options: RateLimitOptions = {}) {
    this.store = options.store || new MemoryStore();
    this.options = {
      maxRequests: 100,
      windowMs: 60000,
      message: 'Too many requests, please try again later',
      statusCode: 429,
      headers: true,
      keyGenerator: options.keyGenerator || defaultKeyGenerator,
      skip: options.skip,
      dynamicLimits: options.dynamicLimits,
      store: options.store,
    };
  }

  async before(context: Context): Promise<void> {
    // Skip rate limiting if configured
    if (this.options.skip && this.options.skip(context)) {
      return;
    }

    const key = this.options.keyGenerator!(context);
    const { maxRequests, windowMs } = getRateLimit(context, this.options);

    try {
      const result = await this.store.increment(key, windowMs);

      const rateLimitInfo: RateLimitInfo = {
        limit: maxRequests,
        current: result.count,
        remaining: Math.max(0, maxRequests - result.count),
        resetTime: result.resetTime,
      };

      // Set rate limit headers
      if (this.options.headers) {
        setRateLimitHeaders(context, rateLimitInfo);
      }

      // Check if limit exceeded
      if (result.count > maxRequests) {
        logger.warn('Rate limit exceeded', {
          key,
          count: result.count,
          limit: maxRequests,
          resetTime: new Date(result.resetTime).toISOString(),
          userAgent: context.req.headers?.['user-agent'],
          endpoint: context.req.path || context.req.url,
        });

        throw new SecurityError(this.options.message);
      }

      // Log approaching limit
      if (result.count > maxRequests * 0.8) {
        logger.debug('Approaching rate limit', {
          key,
          count: result.count,
          limit: maxRequests,
          percentage: Math.round((result.count / maxRequests) * 100),
        });
      }
    } catch (error) {
      if (error instanceof SecurityError) {
        throw error;
      }

      // Log store errors but don't block requests
      logger.error('Rate limiting store error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        key,
      });
    }
  }
}

/**
 * Rate Limiting Middleware Factory
 * @param options Rate limiting configuration
 * @returns BaseMiddleware
 */
export const rateLimiting = (options: RateLimitOptions = {}): BaseMiddleware =>
  new RateLimitingMiddleware(options);

/**
 * Predefined rate limit configurations
 */
export const RateLimitPresets = {
  /**
   * Very strict limits for sensitive endpoints
   */
  STRICT: {
    maxRequests: 5,
    windowMs: 60000, // 1 minute
    message: 'Too many requests to sensitive endpoint',
  } satisfies RateLimitOptions,

  /**
   * Standard API limits
   */
  API: {
    maxRequests: 100,
    windowMs: 60000, // 1 minute
    dynamicLimits: {
      authenticated: {
        maxRequests: 1000,
        windowMs: 60000,
        matcher: (context: Context) => !!context.user,
      },
    },
  } satisfies RateLimitOptions,

  /**
   * Authentication endpoint limits
   */
  AUTH: {
    maxRequests: 10,
    windowMs: 60000, // 1 minute
    message: 'Too many authentication attempts',
  } satisfies RateLimitOptions,

  /**
   * Public endpoint limits
   */
  PUBLIC: {
    maxRequests: 50,
    windowMs: 60000, // 1 minute
  } satisfies RateLimitOptions,

  /**
   * Development mode - very permissive
   */
  DEVELOPMENT: {
    maxRequests: 10000,
    windowMs: 60000, // 1 minute
  } satisfies RateLimitOptions,
} as const;

/**
 * Export memory store for testing and custom implementations
 */
export { MemoryStore };
