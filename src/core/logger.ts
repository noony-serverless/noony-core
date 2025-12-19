import type { Span, Context as OtelContext } from '@opentelemetry/api';
import {
  createOTELMixin,
  getOTELContextFromSpan,
  type OTELLogContext,
} from '../utils/otel.helper';

// Import trace for dynamic OTEL operations
let trace: typeof import('@opentelemetry/api').trace | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  trace = require('@opentelemetry/api').trace;
} catch {
  // OTEL not available
  trace = null;
}

type LogLevel = 'info' | 'error' | 'warn' | 'debug';

export interface LogOptions {
  structuredData?: boolean;
  [key: string]: boolean | string | number | object | undefined;
}

export interface LoggerConfig {
  enableOTEL?: boolean;
  structuredLogging?: boolean;
  debugMode?: boolean;
}

interface LogData {
  timestamp: string;
  level: LogLevel;
  message: string;
  [key: string]: unknown;
}

// Performance optimization: Object pool for log data to reduce GC pressure
class LogDataPool {
  private pool: LogData[] = [];
  private maxPoolSize = 50;

  acquire(): LogData {
    return (
      this.pool.pop() || {
        timestamp: '',
        level: 'info' as LogLevel,
        message: '',
      }
    );
  }

  release(logData: LogData): void {
    if (this.pool.length < this.maxPoolSize) {
      // Reset object properties
      logData.timestamp = '';
      logData.level = 'info';
      logData.message = '';

      // Remove any additional properties
      const keys = Object.keys(logData);
      for (let i = 3; i < keys.length; i++) {
        delete logData[keys[i]];
      }

      this.pool.push(logData);
    }
  }
}

// Performance optimization: Dynamic method references for testing compatibility
const getLogMethod = (level: LogLevel): typeof console.log => {
  switch (level) {
    case 'error':
      return console.error;
    case 'warn':
      return console.warn;
    case 'debug':
      return console.debug;
    default:
      return console.log;
  }
};

class Logger {
  private logDataPool = new LogDataPool();
  private isDebugEnabled: boolean;
  private timestampCache: string = '';
  private lastTimestamp: number = 0;
  private enableOTEL: boolean;
  private otelContext?: OTELLogContext;

  constructor(config?: LoggerConfig) {
    // Performance optimization: Cache debug mode check
    this.isDebugEnabled =
      config?.debugMode ??
      (process.env.NODE_ENV === 'development' ||
        process.env.DEBUG === 'true' ||
        process.env.LOG_LEVEL === 'debug');

    // Enable OTEL integration if configured or in production
    this.enableOTEL =
      config?.enableOTEL ??
      (process.env.OTEL_ENABLED === 'true' ||
        process.env.NODE_ENV === 'production');
  }

  /**
   * Performance optimized timestamp generation with caching
   * Cache timestamps for up to 1 second to reduce Date object creation
   */
  private getTimestamp(): string {
    const now = Date.now();
    // Cache timestamp for 1 second to reduce object creation
    if (now - this.lastTimestamp > 1000) {
      this.timestampCache = new Date(now).toISOString();
      this.lastTimestamp = now;
    }
    return this.timestampCache;
  }

  /**
   * Optimized log method with object pooling and lazy evaluation
   * Includes automatic OTEL trace/span ID injection when enabled
   */
  private log(level: LogLevel, message: string, options?: LogOptions): void {
    // Performance optimization: Early return for debug logs in production
    if (level === 'debug' && !this.isDebugEnabled) {
      return;
    }

    const logData = this.logDataPool.acquire();

    // Performance optimization: Lazy timestamp generation
    logData.timestamp = this.getTimestamp();
    logData.level = level;
    logData.message = message;

    // Add OTEL context if enabled (automatic trace/span ID injection)
    if (this.enableOTEL) {
      // Use stored context if available (from withSpan/withOTEL)
      // Otherwise, get from active span (createOTELMixin)
      const otelContext = this.otelContext || createOTELMixin();
      if (otelContext && Object.keys(otelContext).length > 0) {
        Object.assign(logData, otelContext);
      }
    }

    // Add options if provided (options override OTEL context if keys conflict)
    if (options) {
      Object.assign(logData, options);
    }

    // Use dynamic method reference for testing compatibility
    const logMethod = getLogMethod(level);

    // For testing: create a copy of the data to avoid pool interference
    const logDataCopy = { ...logData };
    logMethod(logDataCopy);

    // Always return object to pool
    this.logDataPool.release(logData);
  }

  /**
   * Performance optimized logging methods with level checks
   */
  info(message: string, options?: LogOptions): void {
    this.log('info', message, options);
  }

  error(message: string, options?: LogOptions): void {
    this.log('error', message, options);
  }

  warn(message: string, options?: LogOptions): void {
    this.log('warn', message, options);
  }

  debug(message: string, options?: LogOptions): void {
    // Performance optimization: Early return for debug in production
    if (!this.isDebugEnabled) return;
    this.log('debug', message, options);
  }

  /**
   * Performance monitoring method for internal framework use
   */
  logPerformance(
    operation: string,
    duration: number,
    metadata?: Record<string, unknown>
  ): void {
    if (this.isDebugEnabled) {
      this.debug(`Performance: ${operation}`, {
        duration: `${duration}ms`,
        ...metadata,
      });
    }
  }

  /**
   * Create a child logger with a specific span context
   *
   * This method creates a new logger instance that will automatically include
   * the trace/span IDs from the provided span in all log entries.
   *
   * Useful for passing logger instances to services/functions that need
   * to log within a specific span context.
   *
   * @param span - OpenTelemetry span to attach to logs
   * @returns New logger instance with span context
   *
   * @example
   * ```typescript
   * import { trace } from '@opentelemetry/api';
   * import { logger } from '@noony-serverless/core';
   *
   * const tracer = trace.getTracer('my-service');
   * const span = tracer.startSpan('process-order');
   *
   * const spanLogger = logger.withSpan(span);
   * spanLogger.info('Processing order'); // Includes span's trace/span IDs
   *
   * span.end();
   * ```
   */
  withSpan(span: Span): Logger {
    const childLogger = new Logger({
      enableOTEL: this.enableOTEL,
      debugMode: this.isDebugEnabled,
    });
    childLogger.otelContext = getOTELContextFromSpan(span);
    return childLogger;
  }

  /**
   * Create a child logger with a specific OTEL context
   *
   * This method creates a new logger instance that will automatically include
   * trace/span IDs from the provided OTEL context in all log entries.
   *
   * Useful when working with OTEL Context propagation (e.g., Pub/Sub messages).
   *
   * @param context - OpenTelemetry context to extract span from
   * @returns New logger instance with context
   *
   * @example
   * ```typescript
   * import { context, propagation } from '@opentelemetry/api';
   * import { logger } from '@noony-serverless/core';
   *
   * // Extract context from Pub/Sub message
   * const extractedContext = propagation.extract(
   *   context.active(),
   *   message.attributes
   * );
   *
   * const contextLogger = logger.withOTEL(extractedContext);
   * contextLogger.info('Processing message'); // Includes trace/span IDs
   * ```
   */
  withOTEL(otelContext: OtelContext): Logger {
    if (!trace) {
      // OTEL not available, return this logger unchanged
      return this;
    }

    const span = trace.getSpan(otelContext);
    if (!span) {
      return this;
    }

    return this.withSpan(span);
  }

  /**
   * Create a child logger with custom OTEL context
   *
   * This method creates a new logger instance with manually specified
   * trace/span IDs. Useful when you have trace context from external sources.
   *
   * @param context - OTEL log context with trace/span IDs
   * @returns New logger instance with custom context
   *
   * @example
   * ```typescript
   * import { logger } from '@noony-serverless/core';
   *
   * const customLogger = logger.withContext({
   *   traceId: '13ea7e3c2d3b4547baaa399062df1f2d',
   *   spanId: '1234567890123456',
   *   traceFlags: 1
   * });
   *
   * customLogger.info('Custom trace context'); // Includes specified IDs
   * ```
   */
  withContext(context: OTELLogContext): Logger {
    const childLogger = new Logger({
      enableOTEL: this.enableOTEL,
      debugMode: this.isDebugEnabled,
    });
    childLogger.otelContext = context;
    return childLogger;
  }

  /**
   * Get logger statistics for monitoring
   */
  getStats(): {
    poolSize: number;
    maxPoolSize: number;
    debugEnabled: boolean;
    otelEnabled: boolean;
  } {
    return {
      poolSize: this.logDataPool['pool'].length,
      maxPoolSize: this.logDataPool['maxPoolSize'],
      debugEnabled: this.isDebugEnabled,
      otelEnabled: this.enableOTEL,
    };
  }
}

export const logger = new Logger();

// Export the Logger class for testing purposes
export { Logger };
