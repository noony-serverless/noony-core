import { ConsoleProvider } from './console-provider';
import { Context } from '../../core';
import { TelemetryConfig } from '../provider';

describe('ConsoleProvider', () => {
  let provider: ConsoleProvider;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    provider = new ConsoleProvider();
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    jest.restoreAllMocks();
  });

  describe('validate', () => {
    it('should always return valid', async () => {
      const result = await provider.validate();
      expect(result.valid).toBe(true);
    });
  });

  describe('initialize', () => {
    it('should initialize with service name and version', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.2.3',
        environment: 'development',
      };

      await provider.initialize(config);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] Console provider initialized'
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] Service:',
        'test-service'
      );
      expect(consoleSpy).toHaveBeenCalledWith('[Telemetry] Version:', '1.2.3');
      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] Environment:',
        'development'
      );
    });

    it('should handle missing version', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: undefined as any,
        environment: 'production',
      };

      await provider.initialize(config);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] Version:',
        'unknown'
      );
    });

    it('should handle missing environment', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: undefined as any,
      };

      await provider.initialize(config);

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] Environment:',
        'development'
      );
    });

    it('should not enable if config.enabled is false', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
        enabled: false,
      };

      await provider.initialize(config);

      expect(consoleSpy).not.toHaveBeenCalled();
      expect(provider.isReady()).toBe(false);
    });
  });

  describe('createSpan', () => {
    let context: Context;

    beforeEach(async () => {
      context = {
        req: {
          method: 'GET',
          path: '/api/users',
          url: '/api/users?page=1',
        },
        res: {},
        requestId: 'req-123',
        businessData: new Map(),
      } as Context;

      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
      });
    });

    it('should create span and log start', () => {
      const span = provider.createSpan(context);

      expect(span).toBeDefined();
      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] 🟢 Span started:',
        expect.objectContaining({
          method: 'GET',
          path: '/api/users',
          requestId: 'req-123',
        })
      );
    });

    it('should return undefined when provider is not enabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
        enabled: false,
      });

      const span = provider.createSpan(context);

      expect(span).toBeUndefined();
    });

    it('should log attributes when setAttributes is called', () => {
      const span = provider.createSpan(context);
      span?.setAttributes({ userId: '123', status: 'active' });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] 📊 Span attributes:',
        {
          userId: '123',
          status: 'active',
        }
      );
    });

    it('should log exception when recordException is called', () => {
      const consoleErrorSpy = jest.spyOn(console, 'error');
      const span = provider.createSpan(context);
      const error = new Error('Test error');

      span?.recordException(error);

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        '[Telemetry] ❌ Exception:',
        expect.objectContaining({
          message: 'Test error',
          name: 'Error',
        })
      );
    });

    it('should log status with success icon when code is 0', () => {
      const span = provider.createSpan(context);
      span?.setStatus({ code: 0 });

      expect(consoleSpy).toHaveBeenCalledWith('[Telemetry] ✅ Span status:', {
        code: 0,
      });
    });

    it('should log status with warning icon when code is not 0', () => {
      const span = provider.createSpan(context);
      span?.setStatus({ code: 1, message: 'Error occurred' });

      expect(consoleSpy).toHaveBeenCalledWith('[Telemetry] ⚠️ Span status:', {
        code: 1,
        message: 'Error occurred',
      });
    });

    it('should log duration when span ends', () => {
      jest.useFakeTimers();
      const span = provider.createSpan(context);

      jest.advanceTimersByTime(100);
      span?.end();

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] 🔴 Span ended:',
        expect.objectContaining({
          duration: expect.stringContaining('ms'),
        })
      );

      jest.useRealTimers();
    });

    it('should use url as path fallback', async () => {
      const contextWithoutPath = {
        req: {
          method: 'POST',
          url: '/api/orders',
        },
        res: {},
        requestId: 'req-456',
        businessData: new Map(),
      } as Context;

      const span = provider.createSpan(contextWithoutPath);

      expect(span).toBeDefined();
      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] 🟢 Span started:',
        expect.objectContaining({
          path: '/api/orders',
        })
      );
    });
  });

  describe('recordMetric', () => {
    beforeEach(async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
      });
    });

    it('should log metric with name and value', () => {
      provider.recordMetric('http.request.duration', 123.45);

      expect(consoleSpy).toHaveBeenCalledWith('[Telemetry] 📈 Metric:', {
        name: 'http.request.duration',
        value: 123.45,
        attributes: undefined,
      });
    });

    it('should log metric with attributes', () => {
      provider.recordMetric('http.request.count', 1, {
        method: 'GET',
        status: 200,
      });

      expect(consoleSpy).toHaveBeenCalledWith('[Telemetry] 📈 Metric:', {
        name: 'http.request.count',
        value: 1,
        attributes: { method: 'GET', status: 200 },
      });
    });

    it('should not log when provider is disabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
        enabled: false,
      });

      consoleSpy.mockClear();
      provider.recordMetric('test.metric', 100);

      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('log', () => {
    beforeEach(async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
      });
    });

    it('should log info level with info icon', () => {
      provider.log('info', 'Test info message', { userId: '123' });

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] ℹ️ Log [info]:',
        'Test info message',
        { userId: '123' }
      );
    });

    it('should log error level with error icon', () => {
      provider.log('error', 'Test error message');

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] ❌ Log [error]:',
        'Test error message',
        undefined
      );
    });

    it('should log warn level with warn icon', () => {
      provider.log('warn', 'Test warning message');

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] ⚠️ Log [warn]:',
        'Test warning message',
        undefined
      );
    });

    it('should log debug level with debug icon', () => {
      provider.log('debug', 'Test debug message');

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] 🔍 Log [debug]:',
        'Test debug message',
        undefined
      );
    });

    it('should use default icon for unknown level', () => {
      provider.log('custom', 'Custom level message');

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] 📝 Log [custom]:',
        'Custom level message',
        undefined
      );
    });

    it('should not log when provider is disabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
        enabled: false,
      });

      consoleSpy.mockClear();
      provider.log('info', 'Test message');

      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });

  describe('isReady', () => {
    it('should return true when enabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
      });

      expect(provider.isReady()).toBe(true);
    });

    it('should return false when disabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
        enabled: false,
      });

      expect(provider.isReady()).toBe(false);
    });
  });

  describe('shutdown', () => {
    it('should log shutdown message when enabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
      });

      consoleSpy.mockClear();
      await provider.shutdown();

      expect(consoleSpy).toHaveBeenCalledWith(
        '[Telemetry] Console provider shutdown'
      );
      expect(provider.isReady()).toBe(false);
    });

    it('should not log when disabled', async () => {
      await provider.initialize({
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'development',
        enabled: false,
      });

      consoleSpy.mockClear();
      await provider.shutdown();

      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });
});
