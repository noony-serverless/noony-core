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
  keyGenerator?: <TBody, TUser>(context: Context<TBody, TUser>) => string;

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
  skip?: <TBody, TUser>(context: Context<TBody, TUser>) => boolean;

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
      matcher: <TBody, TUser>(context: Context<TBody, TUser>) => boolean;
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
const defaultKeyGenerator = <TBody, TUser>(
  context: Context<TBody, TUser>
): string => {
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
const setRateLimitHeaders = <TBody, TUser>(
  context: Context<TBody, TUser>,
  info: RateLimitInfo
): void => {
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
const getRateLimit = <TBody, TUser>(
  context: Context<TBody, TUser>,
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
 * Rate Limiting Middleware with sliding window implementation.
 * Implements comprehensive rate limiting with dynamic limits, custom storage, and security features.
 *
 * ## When to Use RateLimitingMiddleware
 *
 * ### ✅ Recommended Use Cases:
 * - **Business Logic Rate Limiting**: User-specific quotas, subscription-based limits
 * - **Authentication & Security**: Login attempts, password resets, token refresh
 * - **Content Creation**: Post creation, comment submission, profile updates
 * - **Resource-Intensive Operations**: File uploads, data processing, complex queries
 * - **Advanced Scenarios**: A/B testing limits, geographic restrictions, time-based rules
 *
 * ### ❌ Not Recommended Use Cases:
 * - **Basic DDoS Protection**: Use WAF/CloudFlare instead
 * - **Static Asset Protection**: Use CDN rate limiting
 * - **Simple Volumetric Attacks**: Network-level solutions more effective
 *
 * ## Architecture Integration
 *
 * ### With WAF (Web Application Firewall):
 * - WAF handles: IP blocking, DDoS protection, bot detection
 * - Application handles: Business logic, user-aware limits, complex rules
 * - Focus on complementary functionality, not duplication
 *
 * ### With API Gateway:
 * - Gateway handles: Service-level limits, routing quotas, load balancing
 * - Application handles: User context, subscription limits, feature-specific rules
 * - Different layers for different concerns
 *
 * ### Direct Exposure (No WAF/Gateway):
 * - Application must handle comprehensive protection
 * - Implement multiple protection layers within middleware
 * - Critical for security in simple deployments
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @implements {BaseMiddleware<TBody, TUser>}
 *
 * @example
 * Basic API rate limiting:
 * ```typescript
 * import { Handler, RateLimitingMiddleware } from '@noony-serverless/core';
 *
 * const apiHandler = new Handler()
 *   .use(new RateLimitingMiddleware({
 *     maxRequests: 100,
 *     windowMs: 60000, // 1 minute
 *     message: 'Too many API requests'
 *   }))
 *   .handle(async (context) => {
 *     const data = await getApiData();
 *     return { success: true, data };
 *   });
 * ```
 *
 * @example
 * Authentication endpoint with strict limits:
 * ```typescript
 * const loginHandler = new Handler()
 *   .use(new RateLimitingMiddleware({
 *     maxRequests: 5,
 *     windowMs: 60000, // 1 minute
 *     message: 'Too many login attempts',
 *     statusCode: 429
 *   }))
 *   .handle(async (context) => {
 *     const { email, password } = context.req.parsedBody;
 *     const token = await authenticate(email, password);
 *     return { success: true, token };
 *   });
 * ```
 *
 * @example
 * Dynamic limits based on user authentication:
 * ```typescript
 * const smartApiHandler = new Handler()
 *   .use(new RateLimitingMiddleware({
 *     maxRequests: 50, // Default for unauthenticated
 *     windowMs: 60000,
 *     dynamicLimits: {
 *       authenticated: {
 *         maxRequests: 1000,
 *         windowMs: 60000,
 *         matcher: (context) => !!context.user
 *       },
 *       premium: {
 *         maxRequests: 5000,
 *         windowMs: 60000,
 *         matcher: (context) => context.user?.plan === 'premium'
 *       }
 *     }
 *   }))
 *   .handle(async (context) => {
 *     return { success: true, limit: 'applied dynamically' };
 *   });
 * ```
 *
 * @example
 * Multi-layer defense (with WAF):
 * ```typescript
 * // WAF handles basic IP limits (10,000/min), DDoS protection
 * // Application refines with business logic
 * const wafAwareHandler = new Handler()
 *   .use(new RateLimitingMiddleware({
 *     maxRequests: 100, // Refined limit after WAF filtering
 *     windowMs: 60000,
 *     dynamicLimits: {
 *       premium: {
 *         maxRequests: 500,
 *         windowMs: 60000,
 *         matcher: (context) => context.user?.plan === 'premium'
 *       }
 *     },
 *     keyGenerator: (context) => `user:${context.user?.id || context.req.ip}`
 *   }))
 *   .handle(async (context) => {
 *     // Business logic with user-aware limits
 *     return await processUserRequest(context);
 *   });
 * ```
 *
 * @example
 * API Gateway integration:
 * ```typescript
 * // Gateway: 10,000 req/hour per service, 1,000 req/min per endpoint
 * // Application: User-specific limits within gateway envelope
 * const gatewayAwareHandler = new Handler()
 *   .use(new RateLimitingMiddleware({
 *     maxRequests: 100, // Per user within gateway limits
 *     windowMs: 60000,
 *     dynamicLimits: {
 *       freeTrial: {
 *         maxRequests: 10,
 *         windowMs: 60000,
 *         matcher: (context) => context.user?.trialExpired === false
 *       },
 *       enterprise: {
 *         maxRequests: 5000,
 *         windowMs: 60000,
 *         matcher: (context) => context.user?.plan === 'enterprise'
 *       }
 *     },
 *     keyGenerator: (context) => `user:${context.user?.id}`
 *   }))
 *   .handle(async (context) => {
 *     // Refined business logic limits
 *     return await handleApiRequest(context);
 *   });
 * ```
 *
 * @example
 * Comprehensive protection (no WAF/Gateway):
 * ```typescript
 * // Application must handle all protection layers
 * const comprehensiveHandler = new Handler()
 *   .use(new RateLimitingMiddleware({
 *     maxRequests: 100,
 *     windowMs: 60000,
 *     dynamicLimits: {
 *       // IP-based protection (WAF-like)
 *       suspicious_ip: {
 *         maxRequests: 10,
 *         windowMs: 60000,
 *         matcher: (context) => detectSuspiciousIP(context.req.ip)
 *       },
 *       // Endpoint-specific (Gateway-like)
 *       auth_endpoint: {
 *         maxRequests: 5,
 *         windowMs: 60000,
 *         matcher: (context) => context.req.path?.includes('/auth/')
 *       },
 *       // Business logic (Application-specific)
 *       user_specific: {
 *         maxRequests: 1000,
 *         windowMs: 60000,
 *         matcher: (context) => !!context.user
 *       }
 *     },
 *     keyGenerator: (context) => {
 *       const user = context.user?.id;
 *       const ip = context.req.ip;
 *       const endpoint = context.req.path;
 *       return user ? `user:${user}` : `ip:${ip}:${endpoint}`;
 *     }
 *   }))
 *   .handle(async (context) => {
 *     return await processRequest(context);
 *   });
 * ```
 */
export class RateLimitingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
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

  async before(context: Context<TBody, TUser>): Promise<void> {
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
 * Factory function that creates a rate limiting middleware.
 * Provides flexible rate limiting with configurable options and presets.
 *
 * ## Architecture Decision Matrix
 *
 * | Infrastructure | WAF Rate Limiting | Gateway Rate Limiting | Application Rate Limiting |
 * |----------------|------------------|---------------------|-------------------------|
 * | **WAF + Gateway + App** | ✅ Basic DDoS protection | ✅ Service-level limits | ✅ Business logic |
 * | **Gateway + App** | ❌ Not available | ✅ Service + IP limits | ✅ User context + business |
 * | **WAF + App** | ✅ Network protection | ❌ Not available | ✅ All business logic |
 * | **App Only** | ❌ Must implement | ❌ Must implement | ✅ Everything |
 *
 * ## Implementation Strategy by Architecture
 *
 * ### Multi-Layer Defense (Recommended for Enterprise)
 * ```typescript
 * // WAF Layer: 10,000 req/min per IP (CloudFlare/AWS WAF)
 * // Gateway Layer: 1,000 req/min per API key (Kong/AWS API Gateway)
 * // Application Layer: User-specific business rules (This middleware)
 *
 * const enterprise = rateLimiting({
 *   maxRequests: 100, // Refined after other layers
 *   dynamicLimits: {
 *     premium: { maxRequests: 500, matcher: (ctx) => ctx.user?.plan === 'premium' }
 *   }
 * });
 * ```
 *
 * ### Gateway + Application (Good for Most Applications)
 * ```typescript
 * // Gateway: Service capacity protection
 * // Application: Business logic enforcement
 *
 * const standard = rateLimiting({
 *   maxRequests: 200, // Higher since Gateway pre-filters
 *   dynamicLimits: {
 *     authenticated: { maxRequests: 1000, matcher: (ctx) => !!ctx.user }
 *   }
 * });
 * ```
 *
 * ### Application Only (Comprehensive Protection Required)
 * ```typescript
 * // Must handle all layers of protection
 *
 * const comprehensive = rateLimiting({
 *   maxRequests: 50, // Conservative default
 *   dynamicLimits: {
 *     // WAF-like: IP protection
 *     suspicious: { maxRequests: 5, matcher: (ctx) => detectSuspicious(ctx.req.ip) },
 *     // Gateway-like: Endpoint protection
 *     auth: { maxRequests: 10, matcher: (ctx) => ctx.req.path?.includes('/auth/') },
 *     // Business: User-specific
 *     premium: { maxRequests: 1000, matcher: (ctx) => ctx.user?.plan === 'premium' }
 *   }
 * });
 * ```
 *
 * ## Cost-Benefit Analysis
 *
 * | Architecture | Setup Complexity | Runtime Cost | Protection Level | Maintenance |
 * |-------------|-----------------|-------------|-----------------|-------------|
 * | **WAF + Gateway + App** | High | High | Maximum | Medium |
 * | **Gateway + App** | Medium | Medium | Good | Low |
 * | **WAF + App** | Medium | Medium | Good | Medium |
 * | **App Only** | Low | Low | Variable | High |
 *
 * @param options - Rate limiting configuration options
 * @returns BaseMiddleware instance
 *
 * @example
 * Using preset configurations:
 * ```typescript
 * import { Handler, rateLimiting, RateLimitPresets } from '@noony-serverless/core';
 *
 * // Strict limits for sensitive endpoints
 * const authHandler = new Handler()
 *   .use(rateLimiting(RateLimitPresets.AUTH))
 *   .handle(async (context) => {
 *     return await handleAuthentication(context.req.parsedBody);
 *   });
 *
 * // Standard API limits
 * const apiHandler = new Handler()
 *   .use(rateLimiting(RateLimitPresets.API))
 *   .handle(async (context) => {
 *     return await handleApiRequest(context);
 *   });
 * ```
 *
 * @example
 * Custom rate limiting with skip conditions:
 * ```typescript
 * const conditionalHandler = new Handler()
 *   .use(rateLimiting({
 *     maxRequests: 100,
 *     windowMs: 60000,
 *     skip: (context) => {
 *       // Skip rate limiting for admin users
 *       return context.user?.role === 'admin';
 *     },
 *     keyGenerator: (context) => {
 *       // Rate limit per user instead of IP
 *       return context.user?.id || context.req.ip || 'anonymous';
 *     }
 *   }))
 *   .handle(async (context) => {
 *     return { success: true, message: 'Request processed' };
 *   });
 * ```
 *
 * @example
 * Production Redis store integration:
 * ```typescript
 * import Redis from 'ioredis';
 *
 * class RedisRateLimitStore implements RateLimitStore {
 *   constructor(private redis: Redis) {}
 *
 *   async increment(key: string, windowMs: number) {
 *     const multi = this.redis.multi();
 *     multi.incr(key);
 *     multi.expire(key, Math.ceil(windowMs / 1000));
 *     const results = await multi.exec();
 *     return { count: results![0][1] as number, resetTime: Date.now() + windowMs };
 *   }
 * }
 *
 * const productionHandler = new Handler()
 *   .use(rateLimiting({
 *     store: new RedisRateLimitStore(redisClient),
 *     maxRequests: 1000,
 *     windowMs: 60000
 *   }))
 *   .handle(async (context) => {
 *     return await handleHighVolumeAPI(context);
 *   });
 * ```
 *
 * @example
 * Multi-dimensional rate limiting:
 * ```typescript
 * const advancedHandler = new Handler()
 *   .use(rateLimiting({
 *     maxRequests: 100,
 *     windowMs: 60000,
 *     dynamicLimits: {
 *       // Different limits by operation type
 *       read_operations: {
 *         maxRequests: 1000,
 *         windowMs: 60000,
 *         matcher: (context) => context.req.method === 'GET'
 *       },
 *       write_operations: {
 *         maxRequests: 50,
 *         windowMs: 60000,
 *         matcher: (context) => ['POST', 'PUT', 'DELETE'].includes(context.req.method || '')
 *       },
 *       // Different limits by user tier
 *       enterprise_users: {
 *         maxRequests: 5000,
 *         windowMs: 60000,
 *         matcher: (context) => context.user?.tier === 'enterprise'
 *       }
 *     },
 *     keyGenerator: (context) => {
 *       // Multi-dimensional key: user + operation type
 *       const userId = context.user?.id || context.req.ip;
 *       const operation = context.req.method === 'GET' ? 'read' : 'write';
 *       return `${operation}:${userId}`;
 *     }
 *   }))
 *   .handle(async (context) => {
 *     return await processAdvancedRequest(context);
 *   });
 * ```
 */
export const rateLimiting = (options: RateLimitOptions = {}): BaseMiddleware =>
  new RateLimitingMiddleware(options);

/**
 * Predefined rate limit configurations for common use cases.
 *
 * These presets are designed to work well in different infrastructure scenarios:
 * - WAF + Application: Higher limits since WAF pre-filters traffic
 * - Gateway + Application: Moderate limits complementing gateway quotas
 * - Application Only: Conservative limits for comprehensive protection
 *
 * ## Preset Selection Guide
 *
 * | Preset | Use Case | Infrastructure | Requests/Min |
 * |--------|----------|---------------|-------------|
 * | `STRICT` | Sensitive operations | Any | 5 |
 * | `AUTH` | Authentication endpoints | Any | 10 |
 * | `PUBLIC` | Public/unauthenticated | App Only | 50 |
 * | `API` | Standard API endpoints | WAF/Gateway + App | 100-1000 |
 * | `DEVELOPMENT` | Development/testing | Development | 10,000 |
 *
 * @example
 * Choosing the right preset:
 * ```typescript
 * // High-security endpoint (password reset)
 * .use(rateLimiting(RateLimitPresets.STRICT))
 *
 * // Login/registration
 * .use(rateLimiting(RateLimitPresets.AUTH))
 *
 * // Public API with WAF protection
 * .use(rateLimiting(RateLimitPresets.API))
 *
 * // Public API without WAF (direct exposure)
 * .use(rateLimiting(RateLimitPresets.PUBLIC))
 * ```
 */
export const RateLimitPresets = {
  /**
   * Very strict limits for sensitive endpoints
   * Use for: Password resets, account changes, payment operations
   * Infrastructure: Any (universal protection)
   */
  STRICT: {
    maxRequests: 5,
    windowMs: 60000, // 1 minute
    message: 'Too many requests to sensitive endpoint',
  } satisfies RateLimitOptions,

  /**
   * Standard API limits with dynamic scaling for authenticated users
   * Use for: Main API endpoints, data retrieval, business operations
   * Infrastructure: Best with WAF or Gateway (higher baseline limits)
   */
  API: {
    maxRequests: 100, // Baseline for unauthenticated/free users
    windowMs: 60000, // 1 minute
    dynamicLimits: {
      authenticated: {
        maxRequests: 1000, // 10x increase for authenticated users
        windowMs: 60000,
        matcher: (context: Context): boolean => !!context.user,
      },
    },
  } satisfies RateLimitOptions,

  /**
   * Authentication endpoint limits
   * Use for: Login, registration, token refresh, password operations
   * Infrastructure: Any (essential security protection)
   */
  AUTH: {
    maxRequests: 10,
    windowMs: 60000, // 1 minute
    message: 'Too many authentication attempts',
    keyGenerator: (context: Context): string => {
      // Rate limit per IP + email combination for better security
      const ip = context.req.ip || 'unknown';
      const email = (context.req.parsedBody as any)?.email;
      return email ? `auth:${email}:${ip}` : `auth:${ip}`;
    },
  } satisfies RateLimitOptions,

  /**
   * Public endpoint limits for direct application exposure
   * Use for: Public APIs, webhooks, health checks
   * Infrastructure: Application only (no WAF/Gateway protection)
   */
  PUBLIC: {
    maxRequests: 50,
    windowMs: 60000, // 1 minute
    dynamicLimits: {
      // Be more restrictive with suspicious traffic patterns
      suspicious: {
        maxRequests: 10,
        windowMs: 60000,
        matcher: (context: Context): boolean => {
          const userAgent = context.req.headers?.['user-agent'] || '';
          return (
            !userAgent || userAgent.includes('bot') || userAgent.length < 10
          );
        },
      },
    },
  } satisfies RateLimitOptions,

  /**
   * Development mode - very permissive limits
   * Use for: Development, testing, debugging
   * Infrastructure: Development environment only
   */
  DEVELOPMENT: {
    maxRequests: 10000,
    windowMs: 60000, // 1 minute
    skip: (context: Context): boolean => {
      // Skip rate limiting for localhost and development IPs
      const ip = context.req.ip || '';
      return (
        ip.startsWith('127.') ||
        ip.startsWith('::1') ||
        ip.startsWith('192.168.')
      );
    },
  } satisfies RateLimitOptions,

  /**
   * Enterprise-grade configuration with multi-tier support
   * Use for: Production SaaS applications, enterprise APIs
   * Infrastructure: WAF + Gateway + Application (full stack protection)
   */
  ENTERPRISE: {
    maxRequests: 200, // Higher baseline with multiple protection layers
    windowMs: 60000,
    dynamicLimits: {
      free: {
        maxRequests: 100,
        windowMs: 60000,
        matcher: (context: Context): boolean =>
          !context.user || (context.user as any)?.plan === 'free',
      },
      premium: {
        maxRequests: 1000,
        windowMs: 60000,
        matcher: (context: Context): boolean =>
          (context.user as any)?.plan === 'premium',
      },
      enterprise: {
        maxRequests: 5000,
        windowMs: 60000,
        matcher: (context: Context): boolean =>
          (context.user as any)?.plan === 'enterprise',
      },
      admin: {
        maxRequests: 10000,
        windowMs: 60000,
        matcher: (context: Context): boolean =>
          (context.user as any)?.role === 'admin',
      },
    },
    keyGenerator: (context: Context): string => {
      // Use user ID for authenticated, IP for anonymous
      return (context.user as any)?.id
        ? `user:${(context.user as any).id}`
        : `ip:${context.req.ip}`;
    },
  } satisfies RateLimitOptions,
} as const;

/**
 * Export memory store for testing and custom implementations
 */
export { MemoryStore };

/**
 * Configuration helpers and utilities for rate limiting setup
 *
 * ## Best Practices for Production
 *
 * ### 1. Store Selection
 * - **Development**: Use default `MemoryStore` (built-in)
 * - **Production Single Instance**: Use `MemoryStore` with cleanup
 * - **Production Multi-Instance**: Use Redis-based store
 * - **Serverless**: Use external store (Redis/DynamoDB) for state persistence
 *
 * ### 2. Key Generation Strategy
 * ```typescript
 * // Bad: Too generic, easy to abuse
 * keyGenerator: () => 'global'
 *
 * // Good: Multi-dimensional keys
 * keyGenerator: (context) => {
 *   const user = context.user?.id;
 *   const endpoint = context.req.path?.split('/')[2]; // /api/users -> users
 *   const method = context.req.method;
 *   return user ? `${user}:${endpoint}:${method}` : `${context.req.ip}:${endpoint}`;
 * }
 * ```
 *
 * ### 3. Dynamic Limits Best Practices
 * ```typescript
 * // Order matchers from most specific to least specific
 * dynamicLimits: {
 *   admin: { maxRequests: 10000, matcher: (ctx) => ctx.user?.role === 'admin' },
 *   enterprise: { maxRequests: 5000, matcher: (ctx) => ctx.user?.plan === 'enterprise' },
 *   premium: { maxRequests: 1000, matcher: (ctx) => ctx.user?.plan === 'premium' },
 *   authenticated: { maxRequests: 500, matcher: (ctx) => !!ctx.user },
 *   // Default fallback handled by maxRequests
 * }
 * ```
 *
 * ### 4. Error Handling and Fallback
 * ```typescript
 * const resilientRateLimit = rateLimiting({
 *   maxRequests: 100,
 *   windowMs: 60000,
 *
 *   // Custom store with fallback
 *   store: new ResilientStore({
 *     primary: redisStore,
 *     fallback: new MemoryStore(),
 *     timeout: 500 // ms
 *   }),
 *
 *   // Graceful degradation on errors
 *   onError: (error, context) => {
 *     logger.warn('Rate limiting error, allowing request', { error, ip: context.req.ip });
 *     return false; // Don't block request on store errors
 *   }
 * });
 * ```
 *
 * ### 5. Monitoring and Alerting
 * ```typescript
 * // Monitor rate limit effectiveness
 * const monitoredRateLimit = rateLimiting({
 *   maxRequests: 100,
 *   windowMs: 60000,
 *
 *   onRateLimit: (context, info) => {
 *     // Alert on high rate limit hits
 *     metrics.increment('rate_limit.exceeded', {
 *       endpoint: context.req.path,
 *       user: context.user?.id || 'anonymous'
 *     });
 *
 *     // Log suspicious patterns
 *     if (info.current > info.limit * 2) {
 *       logger.warn('Potential abuse detected', {
 *         ip: context.req.ip,
 *         userAgent: context.req.headers?.['user-agent'],
 *         attempts: info.current
 *       });
 *     }
 *   }
 * });
 * ```
 *
 * ### 6. Testing Rate Limits
 * ```typescript
 * // Test helper for rate limit validation
 * export const testRateLimit = async (
 *   handler: Handler,
 *   requests: number,
 *   shouldSucceed: number
 * ) => {
 *   const results = await Promise.all(
 *     Array(requests).fill(0).map(() => handler.execute(mockRequest, mockResponse))
 *   );
 *
 *   const successful = results.filter(r => r.statusCode !== 429).length;
 *   expect(successful).toBe(shouldSucceed);
 * };
 * ```
 *
 * ## Troubleshooting Common Issues
 *
 * ### Issue: Rate limits not working
 * **Solution**: Check key generation and store connection
 * ```typescript
 * // Debug key generation
 * keyGenerator: (context) => {
 *   const key = generateKey(context);
 *   console.log('Rate limit key:', key); // Remove in production
 *   return key;
 * }
 * ```
 *
 * ### Issue: Too many false positives
 * **Solution**: Refine dynamic limits and key generation
 * ```typescript
 * // More granular limits
 * dynamicLimits: {
 *   read: { maxRequests: 1000, matcher: (ctx) => ctx.req.method === 'GET' },
 *   write: { maxRequests: 100, matcher: (ctx) => ctx.req.method !== 'GET' }
 * }
 * ```
 *
 * ### Issue: Memory leaks in MemoryStore
 * **Solution**: Ensure proper cleanup interval and limits
 * ```typescript
 * // Monitor store size
 * setInterval(() => {
 *   const storeSize = memoryStore.size();
 *   if (storeSize > 10000) {
 *     logger.warn('Rate limit store size growing', { size: storeSize });
 *   }
 * }, 60000);
 * ```
 *
 * ### Issue: Rate limits too restrictive
 * **Solution**: Implement gradual enforcement
 * ```typescript
 * const gradualLimit = rateLimiting({
 *   maxRequests: 100,
 *   windowMs: 60000,
 *
 *   // Warn before blocking
 *   onApproachingLimit: (context, info) => {
 *     if (info.remaining < 10) {
 *       context.res.header('X-Rate-Limit-Warning', 'Approaching limit');
 *     }
 *   }
 * });
 * ```
 */
