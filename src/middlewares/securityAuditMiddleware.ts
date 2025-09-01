import { BaseMiddleware, Context, HttpError } from '../core';
import { logger } from '../core/logger';

export interface SecurityEvent {
  type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: string;
  requestId: string;
  clientIP: string;
  userAgent?: string;
  userId?: string;
  endpoint: string;
  method: string;
  details: Record<string, unknown>;
}

export type SecurityEventType =
  | 'SUSPICIOUS_REQUEST'
  | 'AUTHENTICATION_FAILURE'
  | 'AUTHORIZATION_FAILURE'
  | 'RATE_LIMIT_EXCEEDED'
  | 'INVALID_INPUT'
  | 'TOKEN_MANIPULATION'
  | 'UNUSUAL_BEHAVIOR'
  | 'SECURITY_HEADER_VIOLATION'
  | 'INJECTION_ATTEMPT'
  | 'MALFORMED_REQUEST';

export type SecuritySeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SecurityAuditOptions {
  /**
   * Enable detailed request logging
   * @default false
   */
  logRequests?: boolean;

  /**
   * Enable response logging
   * @default false
   */
  logResponses?: boolean;

  /**
   * Log request/response bodies (be careful with sensitive data)
   * @default false
   */
  logBodies?: boolean;

  /**
   * Maximum body size to log (in bytes)
   * @default 1024
   */
  maxBodyLogSize?: number;

  /**
   * Headers to exclude from logging (security headers, auth tokens, etc.)
   */
  excludeHeaders?: string[];

  /**
   * Custom security event handler
   */
  onSecurityEvent?: (event: SecurityEvent) => Promise<void> | void;

  /**
   * Enable anomaly detection
   * @default true
   */
  enableAnomalyDetection?: boolean;

  /**
   * Suspicious patterns to detect
   */
  suspiciousPatterns?: {
    sqlInjection?: RegExp[];
    xss?: RegExp[];
    pathTraversal?: RegExp[];
    commandInjection?: RegExp[];
  };
}

const DEFAULT_EXCLUDE_HEADERS = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
];

const DEFAULT_SUSPICIOUS_PATTERNS = {
  sqlInjection: [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC(UTE)?|UNION|SCRIPT)\b)/i,
    /((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /(((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52)))/i,
    /((\%27)|(\'))union/i,
  ],
  xss: [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /on\w+\s*=/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
  ],
  pathTraversal: [
    /\.\.[\/\\]/g,
    /%2e%2e[\/\\]/gi,
    /%252e%252e[\/\\]/gi,
    /\.\.[%2f%5c]/gi,
  ],
  commandInjection: [
    /[;&|`$()]/g,
    /%[0-9a-f]{2}/gi,
    /\b(cat|ls|ps|id|pwd|uname|whoami|curl|wget)\b/i,
  ],
};

/**
 * Security event tracking for anomaly detection
 */
class SecurityEventTracker {
  private events = new Map<string, SecurityEvent[]>();
  private readonly maxEventsPerClient = 100;
  private readonly timeWindow = 60 * 60 * 1000; // 1 hour

  addEvent(event: SecurityEvent): void {
    const clientKey = event.clientIP;
    const clientEvents = this.events.get(clientKey) || [];

    // Remove old events outside time window
    const cutoff = Date.now() - this.timeWindow;
    const recentEvents = clientEvents.filter(
      (e) => new Date(e.timestamp).getTime() > cutoff
    );

    // Add new event
    recentEvents.push(event);

    // Limit number of events stored per client
    if (recentEvents.length > this.maxEventsPerClient) {
      recentEvents.splice(0, recentEvents.length - this.maxEventsPerClient);
    }

    this.events.set(clientKey, recentEvents);
  }

  getClientEvents(clientIP: string, minutes = 60): SecurityEvent[] {
    const cutoff = Date.now() - minutes * 60 * 1000;
    const events = this.events.get(clientIP) || [];
    return events.filter((e) => new Date(e.timestamp).getTime() > cutoff);
  }

  detectAnomalies(clientIP: string): SecurityEvent[] {
    const recentEvents = this.getClientEvents(clientIP, 10); // Last 10 minutes
    const anomalies: SecurityEvent[] = [];

    // Multiple failed authentication attempts
    const authFailures = recentEvents.filter(
      (e) => e.type === 'AUTHENTICATION_FAILURE'
    );
    if (authFailures.length >= 5) {
      anomalies.push({
        type: 'UNUSUAL_BEHAVIOR',
        severity: 'HIGH',
        timestamp: new Date().toISOString(),
        requestId: 'anomaly-detection',
        clientIP,
        endpoint: 'multiple-endpoints',
        method: 'MULTIPLE',
        details: {
          anomalyType: 'multiple_auth_failures',
          count: authFailures.length,
          timeWindow: '10 minutes',
        },
      });
    }

    // High rate of suspicious requests
    const suspiciousEvents = recentEvents.filter((e) =>
      ['INJECTION_ATTEMPT', 'MALFORMED_REQUEST', 'SUSPICIOUS_REQUEST'].includes(
        e.type
      )
    );
    if (suspiciousEvents.length >= 10) {
      anomalies.push({
        type: 'UNUSUAL_BEHAVIOR',
        severity: 'CRITICAL',
        timestamp: new Date().toISOString(),
        requestId: 'anomaly-detection',
        clientIP,
        endpoint: 'multiple-endpoints',
        method: 'MULTIPLE',
        details: {
          anomalyType: 'high_suspicious_activity',
          count: suspiciousEvents.length,
          timeWindow: '10 minutes',
        },
      });
    }

    return anomalies;
  }
}

const securityEventTracker = new SecurityEventTracker();

/**
 * Check for suspicious patterns in request data
 */
const detectSuspiciousPatterns = (
  data: string,
  patterns: SecurityAuditOptions['suspiciousPatterns'] = DEFAULT_SUSPICIOUS_PATTERNS
): { type: string; pattern: string }[] => {
  const detected: { type: string; pattern: string }[] = [];

  for (const [type, regexList] of Object.entries(patterns)) {
    for (const regex of regexList || []) {
      if (regex.test(data)) {
        detected.push({ type, pattern: regex.source });
      }
    }
  }

  return detected;
};

/**
 * Sanitize data for logging (remove sensitive information)
 */
const sanitizeForLogging = (data: unknown, maxSize = 1024): string => {
  if (typeof data === 'string') {
    return data.length > maxSize
      ? data.substring(0, maxSize) + '...[truncated]'
      : data;
  }

  try {
    const jsonStr = JSON.stringify(data);
    return jsonStr.length > maxSize
      ? jsonStr.substring(0, maxSize) + '...[truncated]'
      : jsonStr;
  } catch {
    return '[unserializable data]';
  }
};

/**
 * Extract client information from request
 */
const extractClientInfo = (context: Context) => ({
  clientIP:
    context.req.ip ||
    (Array.isArray(context.req.headers?.['x-forwarded-for'])
      ? context.req.headers['x-forwarded-for'][0]
      : context.req.headers?.['x-forwarded-for']) ||
    'unknown',
  userAgent: context.req.headers?.['user-agent'] as string,
  userId:
    context.user && typeof context.user === 'object' && 'sub' in context.user
      ? (context.user.sub as string)
      : undefined,
});

/**
 * Security Audit Middleware
 * Provides comprehensive security event logging and monitoring
 */
export class SecurityAuditMiddleware implements BaseMiddleware {
  private options: Required<
    Omit<SecurityAuditOptions, 'onSecurityEvent' | 'suspiciousPatterns'>
  > &
    Pick<SecurityAuditOptions, 'onSecurityEvent' | 'suspiciousPatterns'>;

  constructor(options: SecurityAuditOptions = {}) {
    this.options = {
      logRequests: false,
      logResponses: false,
      logBodies: false,
      maxBodyLogSize: 1024,
      excludeHeaders: [
        ...DEFAULT_EXCLUDE_HEADERS,
        ...(options.excludeHeaders || []),
      ],
      enableAnomalyDetection: true,
      onSecurityEvent: options.onSecurityEvent,
      suspiciousPatterns: {
        ...DEFAULT_SUSPICIOUS_PATTERNS,
        ...options.suspiciousPatterns,
      },
    };
  }

  async before(context: Context): Promise<void> {
    const startTime = Date.now();
    const { clientIP, userAgent, userId } = extractClientInfo(context);

    // Store start time for performance monitoring
    context.businessData.set('audit_start_time', startTime);
    context.businessData.set('audit_client_info', {
      clientIP,
      userAgent,
      userId,
    });

    // Log incoming request if enabled
    if (this.options.logRequests) {
      const requestData: Record<string, unknown> = {
        method: context.req.method,
        url: context.req.url || context.req.path,
        headers: this.sanitizeHeaders(context.req.headers || {}),
        clientIP,
        userAgent,
        userId,
      };

      if (this.options.logBodies && context.req.body) {
        requestData.body = sanitizeForLogging(
          context.req.body,
          this.options.maxBodyLogSize
        );
      }

      logger.info('Incoming request', requestData as any);
    }

    // Check for suspicious patterns in URL and headers
    const url = context.req.url || context.req.path || '';
    const suspiciousInUrl = detectSuspiciousPatterns(
      url,
      this.options.suspiciousPatterns
    );

    if (suspiciousInUrl.length > 0) {
      await this.logSecurityEvent({
        type: 'INJECTION_ATTEMPT',
        severity: 'HIGH',
        timestamp: new Date().toISOString(),
        requestId: context.requestId,
        clientIP,
        userAgent,
        userId,
        endpoint: url,
        method: context.req.method || 'UNKNOWN',
        details: {
          suspiciousPatterns: suspiciousInUrl,
          location: 'url',
        },
      });
    }

    // Check request body for suspicious patterns
    if (context.req.body && typeof context.req.body === 'string') {
      const suspiciousInBody = detectSuspiciousPatterns(
        context.req.body,
        this.options.suspiciousPatterns
      );
      if (suspiciousInBody.length > 0) {
        await this.logSecurityEvent({
          type: 'INJECTION_ATTEMPT',
          severity: 'HIGH',
          timestamp: new Date().toISOString(),
          requestId: context.requestId,
          clientIP,
          userAgent,
          userId,
          endpoint: url,
          method: context.req.method || 'UNKNOWN',
          details: {
            suspiciousPatterns: suspiciousInBody,
            location: 'body',
          },
        });
      }
    }

    // Run anomaly detection
    if (this.options.enableAnomalyDetection) {
      const anomalies = securityEventTracker.detectAnomalies(clientIP);
      for (const anomaly of anomalies) {
        await this.logSecurityEvent(anomaly);
      }
    }
  }

  async after(context: Context): Promise<void> {
    const startTime = context.businessData.get('audit_start_time') as number;
    const clientInfo = context.businessData.get(
      'audit_client_info'
    ) as ReturnType<typeof extractClientInfo>;
    const duration = Date.now() - startTime;

    // Log response if enabled
    if (this.options.logResponses) {
      const responseData: Record<string, unknown> = {
        statusCode: context.res.statusCode,
        duration: `${duration}ms`,
        ...clientInfo,
      };

      if (this.options.logBodies && context.responseData) {
        responseData.responseBody = sanitizeForLogging(
          context.responseData,
          this.options.maxBodyLogSize
        );
      }

      logger.info('Outgoing response', responseData as any);
    }
  }

  async onError(error: Error, context: Context): Promise<void> {
    const clientInfo = context.businessData.get(
      'audit_client_info'
    ) as ReturnType<typeof extractClientInfo>;

    if (!clientInfo) return;

    const { clientIP, userAgent, userId } = clientInfo;
    const url = context.req.url || context.req.path || '';

    let eventType: SecurityEventType = 'SUSPICIOUS_REQUEST';
    let severity: SecuritySeverity = 'MEDIUM';

    // Classify error types
    if (error instanceof HttpError) {
      switch (error.status) {
        case 401:
          eventType = 'AUTHENTICATION_FAILURE';
          severity = 'MEDIUM';
          break;
        case 403:
          eventType = 'AUTHORIZATION_FAILURE';
          severity = 'HIGH';
          break;
        case 400:
          eventType = 'INVALID_INPUT';
          severity = 'LOW';
          break;
        case 429:
          eventType = 'RATE_LIMIT_EXCEEDED';
          severity = 'HIGH';
          break;
        default:
          eventType = 'SUSPICIOUS_REQUEST';
          severity = 'MEDIUM';
      }
    }

    await this.logSecurityEvent({
      type: eventType,
      severity,
      timestamp: new Date().toISOString(),
      requestId: context.requestId,
      clientIP,
      userAgent,
      userId,
      endpoint: url,
      method: context.req.method || 'UNKNOWN',
      details: {
        error: error.message,
        errorType: error.constructor.name,
        statusCode: error instanceof HttpError ? error.status : undefined,
      },
    });
  }

  private async logSecurityEvent(event: SecurityEvent): Promise<void> {
    // Add to tracker for anomaly detection
    if (this.options.enableAnomalyDetection) {
      securityEventTracker.addEvent(event);
    }

    // Log the security event
    logger.warn('Security event detected', event as any);

    // Call custom handler if provided
    if (this.options.onSecurityEvent) {
      try {
        await this.options.onSecurityEvent(event);
      } catch (handlerError) {
        logger.error('Security event handler failed', {
          error:
            handlerError instanceof Error
              ? handlerError.message
              : 'Unknown error',
          originalEvent: event,
        });
      }
    }
  }

  private sanitizeHeaders(
    headers: Record<string, string | string[] | undefined>
  ): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(headers)) {
      if (this.options.excludeHeaders.includes(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }
}

/**
 * Security Audit Middleware Factory
 * @param options Security audit configuration
 * @returns BaseMiddleware
 */
export const securityAudit = (
  options: SecurityAuditOptions = {}
): BaseMiddleware => new SecurityAuditMiddleware(options);

/**
 * Predefined security audit configurations
 */
export const SecurityAuditPresets = {
  /**
   * Full monitoring with detailed logging
   */
  COMPREHENSIVE: {
    logRequests: true,
    logResponses: true,
    logBodies: false, // Be careful with sensitive data
    enableAnomalyDetection: true,
  } satisfies SecurityAuditOptions,

  /**
   * Security events only
   */
  SECURITY_ONLY: {
    logRequests: false,
    logResponses: false,
    logBodies: false,
    enableAnomalyDetection: true,
  } satisfies SecurityAuditOptions,

  /**
   * Development mode with full logging
   */
  DEVELOPMENT: {
    logRequests: true,
    logResponses: true,
    logBodies: true,
    enableAnomalyDetection: false,
  } satisfies SecurityAuditOptions,
} as const;

export { securityEventTracker };
