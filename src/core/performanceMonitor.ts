/**
 * Performance monitoring utilities for production use
 * Provides lightweight performance tracking without impacting application performance
 */

import { logger } from './logger';

// Interface for individual performance metrics (currently unused but may be needed for future features)

interface AggregatedMetrics {
  count: number;
  totalDuration: number;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  p95Duration: number;
}

class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  private readonly maxMetricsPerOperation = 1000; // Limit memory usage
  private isEnabled: boolean;

  constructor() {
    // Enable performance monitoring based on environment
    this.isEnabled =
      process.env.NODE_ENV === 'development' ||
      process.env.PERFORMANCE_MONITORING === 'true';
  }

  /**
   * Start timing an operation
   */
  startTiming(operationName: string): () => void {
    if (!this.isEnabled) {
      return () => {}; // No-op function for production
    }

    const startTime = process.hrtime.bigint();

    return () => {
      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
      this.recordMetric(operationName, duration);
    };
  }

  /**
   * Time an async operation
   */
  async timeAsync<T>(
    operationName: string,
    operation: () => Promise<T>
  ): Promise<T> {
    if (!this.isEnabled) {
      return operation();
    }

    const stopTiming = this.startTiming(operationName);
    try {
      const result = await operation();
      return result;
    } finally {
      stopTiming();
    }
  }

  /**
   * Time a synchronous operation
   */
  timeSync<T>(operationName: string, operation: () => T): T {
    if (!this.isEnabled) {
      return operation();
    }

    const stopTiming = this.startTiming(operationName);
    try {
      const result = operation();
      return result;
    } finally {
      stopTiming();
    }
  }

  /**
   * Record a metric manually
   */
  recordMetric(
    operationName: string,
    duration: number,
    metadata?: Record<string, unknown>
  ): void {
    if (!this.isEnabled) return;

    // Get or create metrics array for this operation
    let operationMetrics = this.metrics.get(operationName);
    if (!operationMetrics) {
      operationMetrics = [];
      this.metrics.set(operationName, operationMetrics);
    }

    // Add the metric
    operationMetrics.push(duration);

    // Maintain size limit to prevent memory leaks
    if (operationMetrics.length > this.maxMetricsPerOperation) {
      operationMetrics.shift(); // Remove oldest metric
    }

    // Log slow operations
    if (duration > 100) {
      // Log operations over 100ms
      logger.logPerformance(operationName, duration, metadata);
    }
  }

  /**
   * Get aggregated metrics for an operation
   */
  getMetrics(operationName: string): AggregatedMetrics | null {
    const metrics = this.metrics.get(operationName);
    if (!metrics || metrics.length === 0) {
      return null;
    }

    const sortedMetrics = [...metrics].sort((a, b) => a - b);
    const count = metrics.length;
    const totalDuration = metrics.reduce((sum, duration) => sum + duration, 0);
    const p95Index = Math.ceil(count * 0.95) - 1;

    return {
      count,
      totalDuration,
      averageDuration: totalDuration / count,
      minDuration: sortedMetrics[0],
      maxDuration: sortedMetrics[count - 1],
      p95Duration: sortedMetrics[p95Index],
    };
  }

  /**
   * Get all metrics summary
   */
  getAllMetrics(): Record<string, AggregatedMetrics> {
    const summary: Record<string, AggregatedMetrics> = {};

    for (const [operationName] of this.metrics) {
      const metrics = this.getMetrics(operationName);
      if (metrics) {
        summary[operationName] = metrics;
      }
    }

    return summary;
  }

  /**
   * Reset all metrics
   */
  reset(): void {
    this.metrics.clear();
  }

  /**
   * Get performance summary for health checks
   */
  getHealthSummary(): {
    isEnabled: boolean;
    trackedOperations: number;
    totalMetrics: number;
    slowOperations: Array<{ name: string; avgDuration: number }>;
  } {
    const allMetrics = this.getAllMetrics();
    const slowOperations = Object.entries(allMetrics)
      .filter(([_, metrics]) => metrics.averageDuration > 50) // Operations over 50ms average
      .map(([name, metrics]) => ({
        name,
        avgDuration: metrics.averageDuration,
      }))
      .sort((a, b) => b.avgDuration - a.avgDuration);

    const totalMetrics = Array.from(this.metrics.values()).reduce(
      (sum, metrics) => sum + metrics.length,
      0
    );

    return {
      isEnabled: this.isEnabled,
      trackedOperations: this.metrics.size,
      totalMetrics,
      slowOperations,
    };
  }

  /**
   * Enable or disable monitoring
   */
  setEnabled(enabled: boolean): void {
    this.isEnabled = enabled;
    if (!enabled) {
      this.reset();
    }
  }
}

// Global performance monitor instance
export const performanceMonitor = new PerformanceMonitor();

/**
 * Decorator for timing method calls
 */
export function timed(operationName?: string): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return function (
    target: any,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    const name =
      operationName || `${target.constructor.name}.${String(propertyKey)}`;

    descriptor.value = async function (...args: unknown[]): Promise<unknown> {
      return performanceMonitor.timeAsync(name, () =>
        originalMethod.apply(this, args)
      );
    };

    return descriptor;
  };
}

/**
 * Decorator for timing synchronous method calls
 */
export function timedSync(operationName?: string): MethodDecorator {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return function (
    target: any,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    const name =
      operationName || `${target.constructor.name}.${String(propertyKey)}`;

    descriptor.value = function (...args: unknown[]): unknown {
      return performanceMonitor.timeSync(name, () =>
        originalMethod.apply(this, args)
      );
    };

    return descriptor;
  };
}
