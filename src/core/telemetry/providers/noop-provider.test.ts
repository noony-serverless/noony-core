import { NoopProvider } from './noop-provider';
import { Context } from '../../core';
import { TelemetryConfig } from '../provider';

describe('NoopProvider', () => {
  let provider: NoopProvider;

  beforeEach(() => {
    provider = new NoopProvider();
  });

  describe('validate', () => {
    it('should always return valid', async () => {
      const result = await provider.validate();
      expect(result.valid).toBe(true);
    });
  });

  describe('initialize', () => {
    it('should initialize without errors', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'test',
      };

      await expect(provider.initialize(config)).resolves.not.toThrow();
    });

    it('should handle minimal config', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test',
        serviceVersion: '1.0.0',
        environment: 'test',
      };

      await expect(provider.initialize(config)).resolves.not.toThrow();
    });
  });

  describe('createSpan', () => {
    let context: Context;

    beforeEach(() => {
      context = {
        req: {
          method: 'GET',
          path: '/api/users',
          url: '/api/users',
        },
        res: {},
        requestId: 'req-123',
        businessData: new Map(),
      } as Context;
    });

    it('should always return undefined', () => {
      const span = provider.createSpan(context);
      expect(span).toBeUndefined();
    });

    it('should return undefined for different context', () => {
      const differentContext = {
        req: {
          method: 'POST',
          path: '/api/orders',
        },
        res: {},
        requestId: 'req-456',
        businessData: new Map(),
      } as Context;

      const span = provider.createSpan(differentContext);
      expect(span).toBeUndefined();
    });
  });

  describe('recordMetric', () => {
    it('should not throw when called', () => {
      expect(() => {
        provider.recordMetric('http.request.duration', 123.45);
      }).not.toThrow();
    });

    it('should not throw with attributes', () => {
      expect(() => {
        provider.recordMetric('http.request.count', 1, {
          method: 'GET',
          status: 200,
        });
      }).not.toThrow();
    });

    it('should not throw with empty attributes', () => {
      expect(() => {
        provider.recordMetric('test.metric', 0, {});
      }).not.toThrow();
    });
  });

  describe('log', () => {
    it('should not throw when called', () => {
      expect(() => {
        provider.log('info', 'Test message');
      }).not.toThrow();
    });

    it('should not throw with attributes', () => {
      expect(() => {
        provider.log('error', 'Error message', { userId: '123' });
      }).not.toThrow();
    });

    it('should not throw with different log levels', () => {
      expect(() => {
        provider.log('debug', 'Debug message');
        provider.log('warn', 'Warning message');
        provider.log('error', 'Error message');
        provider.log('fatal', 'Fatal message');
      }).not.toThrow();
    });
  });

  describe('isReady', () => {
    it('should always return true', () => {
      expect(provider.isReady()).toBe(true);
    });

    it('should return true after initialize', async () => {
      await provider.initialize({
        serviceName: 'test',
        serviceVersion: '1.0.0',
        environment: 'test',
      });

      expect(provider.isReady()).toBe(true);
    });

    it('should return true after shutdown', async () => {
      await provider.shutdown();
      expect(provider.isReady()).toBe(true);
    });
  });

  describe('shutdown', () => {
    it('should not throw when called', async () => {
      await expect(provider.shutdown()).resolves.not.toThrow();
    });

    it('should not throw when called multiple times', async () => {
      await expect(provider.shutdown()).resolves.not.toThrow();
      await expect(provider.shutdown()).resolves.not.toThrow();
      await expect(provider.shutdown()).resolves.not.toThrow();
    });
  });

  describe('name', () => {
    it('should have name "noop"', () => {
      expect(provider.name).toBe('noop');
    });
  });

  describe('integration', () => {
    it('should work as safe fallback provider', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
      };

      // Initialize
      await provider.initialize(config);
      expect(provider.isReady()).toBe(true);

      // Create span
      const context = {
        req: { method: 'GET', path: '/' },
        res: {},
        requestId: 'req-1',
        businessData: new Map(),
      } as Context;
      const span = provider.createSpan(context);
      expect(span).toBeUndefined();

      // Record metric
      expect(() => provider.recordMetric('test', 100)).not.toThrow();

      // Log
      expect(() => provider.log('info', 'test')).not.toThrow();

      // Shutdown
      await provider.shutdown();
      expect(provider.isReady()).toBe(true); // Still ready
    });
  });
});
