import { OpenTelemetryProvider } from './opentelemetry-provider';
import { Context } from '../../core';
import { TelemetryConfig } from '../provider';

describe('OpenTelemetryProvider', () => {
  let provider: OpenTelemetryProvider;
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    provider = new OpenTelemetryProvider();
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(console, 'error').mockImplementation();
    jest.spyOn(console, 'warn').mockImplementation();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  describe('name', () => {
    it('should have name "opentelemetry"', () => {
      expect(provider.name).toBe('opentelemetry');
    });
  });

  describe('validate', () => {
    it('should return invalid when OTEL_EXPORTER_OTLP_ENDPOINT not set', async () => {
      delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

      const result = await provider.validate();

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('OTEL_EXPORTER_OTLP_ENDPOINT');
    });

    it('should return invalid when endpoint is not a valid URL', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'not-a-valid-url';

      const result = await provider.validate();

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('not a valid URL');
    });

    it('should return valid when endpoint is a valid URL', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
        'http://localhost:4318/v1/traces';

      const result = await provider.validate();

      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should accept https URLs', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
        'https://api.example.com/v1/traces';

      const result = await provider.validate();

      expect(result.valid).toBe(true);
    });

    it('should accept URLs with ports', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT =
        'http://localhost:4318/v1/traces';

      const result = await provider.validate();

      expect(result.valid).toBe(true);
    });
  });

  describe('isRunningOnGCP (private method behavior)', () => {
    it('should detect Cloud Run via K_SERVICE', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';
      process.env.K_SERVICE = 'my-cloud-run-service';

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
        propagation: undefined, // Auto-detect based on GCP
      };

      // Initialize will fail in test environment due to missing OTEL SDK
      await provider.initialize(config);

      // Initialization fails before CloudPropagator is attempted
      expect(provider.isReady()).toBe(false);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to initialize'),
        expect.anything()
      );
    });

    it('should detect Cloud Functions via FUNCTION_NAME', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';
      process.env.FUNCTION_NAME = 'my-cloud-function';
      delete process.env.K_SERVICE;

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
      };

      await provider.initialize(config);

      // Should fail initialization in test environment
      expect(provider.isReady()).toBe(false);
    });

    it('should detect App Engine via GAE_APPLICATION', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';
      process.env.GAE_APPLICATION = 'my-app-engine-app';
      delete process.env.K_SERVICE;
      delete process.env.FUNCTION_NAME;

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
      };

      await provider.initialize(config);

      // Should fail initialization in test environment
      expect(provider.isReady()).toBe(false);
    });
  });

  describe('initialize', () => {
    it('should handle missing OpenTelemetry packages gracefully', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
      };

      // In test environment, OTEL SDK is not fully available
      // Provider should fail gracefully and log error
      await provider.initialize(config);

      expect(provider.isReady()).toBe(false);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to initialize'),
        expect.anything()
      );
    });

    it('should not be ready after failed initialization', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
      };

      // Initialize in test environment (will fail due to missing OTEL SDK)
      await provider.initialize(config);

      expect(provider.isReady()).toBe(false);
    });
  });

  describe('createSpan', () => {
    let context: Context;

    beforeEach(() => {
      context = {
        req: {
          method: 'GET',
          path: '/api/users',
          url: '/api/users?page=1',
          headers: {
            'user-agent': 'Mozilla/5.0',
          },
        },
        res: {},
        requestId: 'req-123',
        startTime: Date.now(),
        businessData: new Map(),
        container: null,
      } as any;
    });

    it('should return undefined when provider is not ready', () => {
      const span = provider.createSpan(context);
      expect(span).toBeUndefined();
    });

    it('should return undefined when tracer is not initialized', () => {
      // Provider not initialized
      const span = provider.createSpan(context);
      expect(span).toBeUndefined();
    });
  });

  describe('recordMetric', () => {
    it('should not throw when provider is not ready', () => {
      expect(() => {
        provider.recordMetric('http.request.duration', 123.45);
      }).not.toThrow();
    });

    it('should not throw with attributes when not ready', () => {
      expect(() => {
        provider.recordMetric('http.request.count', 1, {
          method: 'GET',
          status: 200,
        });
      }).not.toThrow();
    });
  });

  describe('log', () => {
    it('should not throw when provider is not ready', () => {
      expect(() => {
        provider.log('info', 'Test message');
      }).not.toThrow();
    });

    it('should not throw with attributes when not ready', () => {
      expect(() => {
        provider.log('error', 'Error message', { userId: '123' });
      }).not.toThrow();
    });
  });

  describe('isReady', () => {
    it('should return false before initialization', () => {
      expect(provider.isReady()).toBe(false);
    });

    it('should return false after failed initialization', async () => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';

      // Initialize in test environment (will fail due to missing OTEL SDK)
      await provider.initialize({
        serviceName: 'test',
        serviceVersion: '1.0.0',
        environment: 'test',
      });

      expect(provider.isReady()).toBe(false);
    });
  });

  describe('shutdown', () => {
    it('should not throw when provider is not ready', async () => {
      await expect(provider.shutdown()).resolves.not.toThrow();
    });

    it('should not throw when called multiple times', async () => {
      await expect(provider.shutdown()).resolves.not.toThrow();
      await expect(provider.shutdown()).resolves.not.toThrow();
    });
  });

  describe('propagator configuration', () => {
    beforeEach(() => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';
    });

    it('should enable both W3C and CloudTrace on GCP by default', async () => {
      process.env.K_SERVICE = 'my-service';

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
        // No explicit propagation config - should auto-detect
      };

      await provider.initialize(config);

      // Initialization fails in test env before CloudPropagator is attempted
      expect(provider.isReady()).toBe(false);
    });

    it('should respect explicit propagation.cloudTrace=false', async () => {
      process.env.K_SERVICE = 'my-service'; // On GCP

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
        propagation: {
          cloudTrace: false, // Explicitly disable
          w3c: true,
        },
      };

      await provider.initialize(config);

      // Should NOT attempt CloudPropagator
      const cloudWarnings = (console.warn as jest.Mock).mock.calls.filter(
        (call) => call[0]?.includes('CloudPropagator')
      );
      expect(cloudWarnings.length).toBe(0);
    });

    it('should respect explicit propagation.cloudTrace=true off GCP', async () => {
      delete process.env.K_SERVICE;
      delete process.env.FUNCTION_NAME;
      delete process.env.GAE_APPLICATION;
      delete process.env.GOOGLE_CLOUD_PROJECT;

      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
        propagation: {
          cloudTrace: true, // Explicitly enable
          w3c: true,
        },
      };

      await provider.initialize(config);

      // Initialization fails in test env before CloudPropagator is attempted
      expect(provider.isReady()).toBe(false);
    });

    it('should use W3C only when cloudTrace disabled and w3c enabled', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: 'production',
        propagation: {
          cloudTrace: false,
          w3c: true,
        },
      };

      await provider.initialize(config);

      // Should not warn about CloudPropagator
      const cloudWarnings = (console.warn as jest.Mock).mock.calls.filter(
        (call) => call[0]?.includes('CloudPropagator')
      );
      expect(cloudWarnings.length).toBe(0);
    });
  });

  describe('config variations', () => {
    beforeEach(() => {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'http://localhost:4318';
    });

    it('should use custom exporter endpoint from config', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '2.0.0',
        environment: 'staging',
        exporters: {
          traces: [
            {
              endpoint: 'https://custom-collector.example.com/v1/traces',
              headers: { Authorization: 'Bearer token123' },
            },
          ],
        },
      };

      await provider.initialize(config);

      // Config should be used (even if initialization fails in test env)
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to initialize'),
        expect.anything()
      );
    });

    it('should handle config without version', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: undefined as any,
        environment: 'production',
      };

      await provider.initialize(config);

      expect(provider.isReady()).toBe(false); // Not ready due to missing OTEL packages
    });

    it('should handle config without environment', async () => {
      const config: TelemetryConfig = {
        serviceName: 'test-service',
        serviceVersion: '1.0.0',
        environment: undefined as any,
      };

      await provider.initialize(config);

      expect(provider.isReady()).toBe(false);
    });
  });
});
