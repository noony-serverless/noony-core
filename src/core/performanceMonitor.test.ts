/**
 * Comprehensive tests for PerformanceMonitor
 */

import { logger } from './logger';
import { performanceMonitor, timed, timedSync } from './performanceMonitor';

// Mock logger
jest.mock('./logger', () => ({
  logger: {
    logPerformance: jest.fn(),
  },
}));

describe('PerformanceMonitor', () => {
  beforeEach(() => {
    performanceMonitor.reset();
    jest.clearAllMocks();
    // Enable monitoring for tests
    performanceMonitor.setEnabled(true);
  });

  afterEach(() => {
    performanceMonitor.reset();
  });

  describe('constructor and environment detection', () => {
    it('should be enabled in development environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      // Create new instance to test constructor
      const PerformanceMonitorClass =
        performanceMonitor.constructor as new () => typeof performanceMonitor;
      const testMonitor = new PerformanceMonitorClass();
      const health = testMonitor.getHealthSummary();
      expect(health.isEnabled).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    it('should be enabled when PERFORMANCE_MONITORING is true', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalPerf = process.env.PERFORMANCE_MONITORING;

      process.env.NODE_ENV = 'production';
      process.env.PERFORMANCE_MONITORING = 'true';

      const testMonitor = new (performanceMonitor.constructor as any)();
      const health = testMonitor.getHealthSummary();
      expect(health.isEnabled).toBe(true);

      process.env.NODE_ENV = originalEnv;
      process.env.PERFORMANCE_MONITORING = originalPerf;
    });

    it('should be disabled in production without explicit flag', () => {
      const originalEnv = process.env.NODE_ENV;
      const originalPerf = process.env.PERFORMANCE_MONITORING;

      process.env.NODE_ENV = 'production';
      delete process.env.PERFORMANCE_MONITORING;

      const testMonitor = new (performanceMonitor.constructor as any)();
      const health = testMonitor.getHealthSummary();
      expect(health.isEnabled).toBe(false);

      process.env.NODE_ENV = originalEnv;
      process.env.PERFORMANCE_MONITORING = originalPerf;
    });
  });

  describe('startTiming', () => {
    it('should return a function that records timing', async () => {
      const stopTiming = performanceMonitor.startTiming('test-operation');

      // Simulate some work
      await new Promise((resolve) => setTimeout(resolve, 10));

      stopTiming();

      const metrics = performanceMonitor.getMetrics('test-operation');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1);
      expect(metrics!.totalDuration).toBeGreaterThan(0);
    });

    it('should return no-op function when disabled', () => {
      performanceMonitor.setEnabled(false);

      const stopTiming = performanceMonitor.startTiming('test-operation');
      stopTiming();

      const metrics = performanceMonitor.getMetrics('test-operation');
      expect(metrics).toBeNull();
    });

    it('should handle multiple concurrent timings', async () => {
      const stop1 = performanceMonitor.startTiming('operation-1');
      const stop2 = performanceMonitor.startTiming('operation-2');

      await new Promise((resolve) => setTimeout(resolve, 5));
      stop1();

      await new Promise((resolve) => setTimeout(resolve, 5));
      stop2();

      const metrics1 = performanceMonitor.getMetrics('operation-1');
      const metrics2 = performanceMonitor.getMetrics('operation-2');

      expect(metrics1).not.toBeNull();
      expect(metrics2).not.toBeNull();
      expect(metrics1!.count).toBe(1);
      expect(metrics2!.count).toBe(1);
    });
  });

  describe('timeAsync', () => {
    it('should time async operations and return result', async () => {
      const testValue = 'test-result';
      const operation = jest.fn().mockResolvedValue(testValue);

      const result = await performanceMonitor.timeAsync(
        'async-test',
        operation
      );

      expect(result).toBe(testValue);
      expect(operation).toHaveBeenCalledTimes(1);

      const metrics = performanceMonitor.getMetrics('async-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1);
    });

    it('should handle async operation errors', async () => {
      const error = new Error('Test error');
      const operation = jest.fn().mockRejectedValue(error);

      await expect(
        performanceMonitor.timeAsync('async-error-test', operation)
      ).rejects.toThrow('Test error');

      const metrics = performanceMonitor.getMetrics('async-error-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1);
    });

    it('should not time when disabled', async () => {
      performanceMonitor.setEnabled(false);

      const operation = jest.fn().mockResolvedValue('result');
      const result = await performanceMonitor.timeAsync(
        'disabled-test',
        operation
      );

      expect(result).toBe('result');
      expect(operation).toHaveBeenCalledTimes(1);

      const metrics = performanceMonitor.getMetrics('disabled-test');
      expect(metrics).toBeNull();
    });
  });

  describe('timeSync', () => {
    it('should time synchronous operations and return result', () => {
      const testValue = 'sync-result';
      const operation = jest.fn().mockReturnValue(testValue);

      const result = performanceMonitor.timeSync('sync-test', operation);

      expect(result).toBe(testValue);
      expect(operation).toHaveBeenCalledTimes(1);

      const metrics = performanceMonitor.getMetrics('sync-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1);
    });

    it('should handle synchronous operation errors', () => {
      const error = new Error('Sync error');
      const operation = jest.fn().mockImplementation(() => {
        throw error;
      });

      expect(() =>
        performanceMonitor.timeSync('sync-error-test', operation)
      ).toThrow('Sync error');

      const metrics = performanceMonitor.getMetrics('sync-error-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1);
    });

    it('should not time when disabled', () => {
      performanceMonitor.setEnabled(false);

      const operation = jest.fn().mockReturnValue('result');
      const result = performanceMonitor.timeSync(
        'disabled-sync-test',
        operation
      );

      expect(result).toBe('result');
      expect(operation).toHaveBeenCalledTimes(1);

      const metrics = performanceMonitor.getMetrics('disabled-sync-test');
      expect(metrics).toBeNull();
    });
  });

  describe('recordMetric', () => {
    it('should record metrics manually', () => {
      performanceMonitor.recordMetric('manual-test', 50);
      performanceMonitor.recordMetric('manual-test', 75);

      const metrics = performanceMonitor.getMetrics('manual-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(2);
      expect(metrics!.totalDuration).toBe(125);
      expect(metrics!.averageDuration).toBe(62.5);
    });

    it('should log slow operations', () => {
      const metadata = { userId: 'test-user' };
      performanceMonitor.recordMetric('slow-operation', 150, metadata);

      expect(logger.logPerformance).toHaveBeenCalledWith(
        'slow-operation',
        150,
        metadata
      );
    });

    it('should not log fast operations', () => {
      performanceMonitor.recordMetric('fast-operation', 50);

      expect(logger.logPerformance).not.toHaveBeenCalled();
    });

    it('should maintain size limit', () => {
      // Add more than maxMetricsPerOperation (1000) metrics
      for (let i = 0; i < 1005; i++) {
        performanceMonitor.recordMetric('size-limit-test', i);
      }

      const metrics = performanceMonitor.getMetrics('size-limit-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1000); // Should be limited to 1000
    });

    it('should not record when disabled', () => {
      performanceMonitor.setEnabled(false);
      performanceMonitor.recordMetric('disabled-record-test', 100);

      const metrics = performanceMonitor.getMetrics('disabled-record-test');
      expect(metrics).toBeNull();
    });
  });

  describe('getMetrics', () => {
    it('should return null for non-existent operation', () => {
      const metrics = performanceMonitor.getMetrics('non-existent');
      expect(metrics).toBeNull();
    });

    it('should return null for operation with no metrics', () => {
      performanceMonitor.recordMetric('empty-test', 50);
      performanceMonitor.reset();

      const metrics = performanceMonitor.getMetrics('empty-test');
      expect(metrics).toBeNull();
    });

    it('should calculate metrics correctly', () => {
      const durations = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      durations.forEach((duration) => {
        performanceMonitor.recordMetric('metrics-test', duration);
      });

      const metrics = performanceMonitor.getMetrics('metrics-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(10);
      expect(metrics!.totalDuration).toBe(550);
      expect(metrics!.averageDuration).toBe(55);
      expect(metrics!.minDuration).toBe(10);
      expect(metrics!.maxDuration).toBe(100);
      expect(metrics!.p95Duration).toBe(100); // 95th percentile
    });

    it('should handle single metric correctly', () => {
      performanceMonitor.recordMetric('single-test', 42);

      const metrics = performanceMonitor.getMetrics('single-test');
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(1);
      expect(metrics!.totalDuration).toBe(42);
      expect(metrics!.averageDuration).toBe(42);
      expect(metrics!.minDuration).toBe(42);
      expect(metrics!.maxDuration).toBe(42);
      expect(metrics!.p95Duration).toBe(42);
    });
  });

  describe('getAllMetrics', () => {
    it('should return empty object when no metrics exist', () => {
      const allMetrics = performanceMonitor.getAllMetrics();
      expect(allMetrics).toEqual({});
    });

    it('should return all operation metrics', () => {
      performanceMonitor.recordMetric('operation-1', 10);
      performanceMonitor.recordMetric('operation-2', 20);
      performanceMonitor.recordMetric('operation-1', 15);

      const allMetrics = performanceMonitor.getAllMetrics();

      expect(Object.keys(allMetrics)).toHaveLength(2);
      expect(allMetrics['operation-1']).toBeDefined();
      expect(allMetrics['operation-2']).toBeDefined();
      expect(allMetrics['operation-1'].count).toBe(2);
      expect(allMetrics['operation-2'].count).toBe(1);
    });
  });

  describe('reset', () => {
    it('should clear all metrics', () => {
      performanceMonitor.recordMetric('test-1', 10);
      performanceMonitor.recordMetric('test-2', 20);

      expect(performanceMonitor.getMetrics('test-1')).not.toBeNull();
      expect(performanceMonitor.getMetrics('test-2')).not.toBeNull();

      performanceMonitor.reset();

      expect(performanceMonitor.getMetrics('test-1')).toBeNull();
      expect(performanceMonitor.getMetrics('test-2')).toBeNull();
    });
  });

  describe('getHealthSummary', () => {
    it('should return correct health summary', () => {
      performanceMonitor.recordMetric('fast-op', 25);
      performanceMonitor.recordMetric('slow-op', 75);
      performanceMonitor.recordMetric('slow-op', 100);

      const health = performanceMonitor.getHealthSummary();

      expect(health.isEnabled).toBe(true);
      expect(health.trackedOperations).toBe(2);
      expect(health.totalMetrics).toBe(3);
      expect(health.slowOperations).toHaveLength(1);
      expect(health.slowOperations[0].name).toBe('slow-op');
      expect(health.slowOperations[0].avgDuration).toBe(87.5);
    });

    it('should handle empty metrics', () => {
      const health = performanceMonitor.getHealthSummary();

      expect(health.isEnabled).toBe(true);
      expect(health.trackedOperations).toBe(0);
      expect(health.totalMetrics).toBe(0);
      expect(health.slowOperations).toHaveLength(0);
    });

    it('should sort slow operations by average duration', () => {
      performanceMonitor.recordMetric('medium-op', 60);
      performanceMonitor.recordMetric('very-slow-op', 200);
      performanceMonitor.recordMetric('slow-op', 100);

      const health = performanceMonitor.getHealthSummary();

      expect(health.slowOperations).toHaveLength(3);
      expect(health.slowOperations[0].name).toBe('very-slow-op');
      expect(health.slowOperations[1].name).toBe('slow-op');
      expect(health.slowOperations[2].name).toBe('medium-op');
    });
  });

  describe('setEnabled', () => {
    it('should enable and disable monitoring', () => {
      performanceMonitor.setEnabled(false);
      let health = performanceMonitor.getHealthSummary();
      expect(health.isEnabled).toBe(false);

      performanceMonitor.setEnabled(true);
      health = performanceMonitor.getHealthSummary();
      expect(health.isEnabled).toBe(true);
    });

    it('should clear metrics when disabled', () => {
      performanceMonitor.recordMetric('test-op', 50);
      expect(performanceMonitor.getMetrics('test-op')).not.toBeNull();

      performanceMonitor.setEnabled(false);
      expect(performanceMonitor.getMetrics('test-op')).toBeNull();
    });
  });

  describe('decorators', () => {
    describe('@timed', () => {
      class TestClass {
        @timed('custom-async-name')
        async customNamedMethod(): Promise<string> {
          await new Promise((resolve) => setTimeout(resolve, 1));
          return 'custom-result';
        }

        @timed()
        async defaultNamedMethod(): Promise<string> {
          await new Promise((resolve) => setTimeout(resolve, 1));
          return 'default-result';
        }

        @timed()
        async errorMethod(): Promise<string> {
          throw new Error('Decorator error');
        }
      }

      it('should time async methods with custom name', async () => {
        const instance = new TestClass();
        const result = await instance.customNamedMethod();

        expect(result).toBe('custom-result');

        const metrics = performanceMonitor.getMetrics('custom-async-name');
        expect(metrics).not.toBeNull();
        expect(metrics!.count).toBe(1);
      });

      it('should time async methods with default name', async () => {
        const instance = new TestClass();
        const result = await instance.defaultNamedMethod();

        expect(result).toBe('default-result');

        const metrics = performanceMonitor.getMetrics(
          'TestClass.defaultNamedMethod'
        );
        expect(metrics).not.toBeNull();
        expect(metrics!.count).toBe(1);
      });

      it('should handle errors in decorated async methods', async () => {
        const instance = new TestClass();

        await expect(instance.errorMethod()).rejects.toThrow('Decorator error');

        const metrics = performanceMonitor.getMetrics('TestClass.errorMethod');
        expect(metrics).not.toBeNull();
        expect(metrics!.count).toBe(1);
      });
    });

    describe('@timedSync', () => {
      class TestSyncClass {
        @timedSync('custom-sync-name')
        customNamedSyncMethod(): string {
          return 'custom-sync-result';
        }

        @timedSync()
        defaultNamedSyncMethod(): string {
          return 'default-sync-result';
        }

        @timedSync()
        errorSyncMethod(): string {
          throw new Error('Sync decorator error');
        }
      }

      it('should time sync methods with custom name', () => {
        const instance = new TestSyncClass();
        const result = instance.customNamedSyncMethod();

        expect(result).toBe('custom-sync-result');

        const metrics = performanceMonitor.getMetrics('custom-sync-name');
        expect(metrics).not.toBeNull();
        expect(metrics!.count).toBe(1);
      });

      it('should time sync methods with default name', () => {
        const instance = new TestSyncClass();
        const result = instance.defaultNamedSyncMethod();

        expect(result).toBe('default-sync-result');

        const metrics = performanceMonitor.getMetrics(
          'TestSyncClass.defaultNamedSyncMethod'
        );
        expect(metrics).not.toBeNull();
        expect(metrics!.count).toBe(1);
      });

      it('should handle errors in decorated sync methods', () => {
        const instance = new TestSyncClass();

        expect(() => instance.errorSyncMethod()).toThrow(
          'Sync decorator error'
        );

        const metrics = performanceMonitor.getMetrics(
          'TestSyncClass.errorSyncMethod'
        );
        expect(metrics).not.toBeNull();
        expect(metrics!.count).toBe(1);
      });
    });
  });

  describe('edge cases and stress tests', () => {
    it('should handle very small durations', () => {
      performanceMonitor.recordMetric('tiny-operation', 0.001);

      const metrics = performanceMonitor.getMetrics('tiny-operation');
      expect(metrics).not.toBeNull();
      expect(metrics!.minDuration).toBe(0.001);
    });

    it('should handle very large durations', () => {
      performanceMonitor.recordMetric('huge-operation', 999999);

      const metrics = performanceMonitor.getMetrics('huge-operation');
      expect(metrics).not.toBeNull();
      expect(metrics!.maxDuration).toBe(999999);
    });

    it('should handle special operation names', () => {
      const specialNames = [
        '',
        ' ',
        '🚀',
        '操作',
        'op-with-spaces and symbols!@#',
      ];

      specialNames.forEach((name, index) => {
        performanceMonitor.recordMetric(name, index * 10);
      });

      specialNames.forEach((name) => {
        const metrics = performanceMonitor.getMetrics(name);
        expect(metrics).not.toBeNull();
      });
    });

    it('should handle rapid consecutive operations', () => {
      const operationName = 'rapid-operations';

      for (let i = 0; i < 100; i++) {
        const stop = performanceMonitor.startTiming(operationName);
        stop();
      }

      const metrics = performanceMonitor.getMetrics(operationName);
      expect(metrics).not.toBeNull();
      expect(metrics!.count).toBe(100);
    });
  });
});
