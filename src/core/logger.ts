type LogLevel = 'info' | 'error' | 'warn' | 'debug';

interface LogOptions {
  structuredData?: boolean;
  [key: string]: boolean | string | number | object | undefined;
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

  constructor() {
    // Performance optimization: Cache debug mode check
    this.isDebugEnabled =
      process.env.NODE_ENV === 'development' ||
      process.env.DEBUG === 'true' ||
      process.env.LOG_LEVEL === 'debug';
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

    // Add options if provided
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
   * Get logger statistics for monitoring
   */
  getStats(): {
    poolSize: number;
    maxPoolSize: number;
    debugEnabled: boolean;
  } {
    return {
      poolSize: this.logDataPool['pool'].length,
      maxPoolSize: this.logDataPool['maxPoolSize'],
      debugEnabled: this.isDebugEnabled,
    };
  }
}

export const logger = new Logger();

// Export the Logger class for testing purposes
export { Logger };
