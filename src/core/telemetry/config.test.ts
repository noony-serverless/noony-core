import {
  TelemetryPresets,
  isRunningOnGCP,
  getDefaultTelemetryConfig,
} from './config';

describe('TelemetryConfig', () => {
  describe('TelemetryPresets', () => {
    it('should have GCP preset with Cloud Trace enabled', () => {
      expect(TelemetryPresets.GCP.propagation.cloudTrace).toBe(true);
      expect(TelemetryPresets.GCP.propagation.w3c).toBe(true);
    });

    it('should have NEW_RELIC preset without Cloud Trace', () => {
      expect(TelemetryPresets.NEW_RELIC.propagation.cloudTrace).toBe(false);
      expect(TelemetryPresets.NEW_RELIC.propagation.w3c).toBe(true);
    });

    it('should have DATADOG preset without Cloud Trace', () => {
      expect(TelemetryPresets.DATADOG.propagation.cloudTrace).toBe(false);
      expect(TelemetryPresets.DATADOG.propagation.w3c).toBe(true);
    });

    it('should have OTLP preset without Cloud Trace', () => {
      expect(TelemetryPresets.OTLP.propagation.cloudTrace).toBe(false);
      expect(TelemetryPresets.OTLP.propagation.w3c).toBe(true);
    });

    it('should have JAEGER_LOCAL preset with localhost endpoint', () => {
      expect(TelemetryPresets.JAEGER_LOCAL.exporters?.traces).toHaveLength(1);
      expect(
        TelemetryPresets.JAEGER_LOCAL.exporters?.traces?.[0].endpoint
      ).toBe('http://localhost:4318/v1/traces');
      expect(TelemetryPresets.JAEGER_LOCAL.propagation.cloudTrace).toBe(false);
      expect(TelemetryPresets.JAEGER_LOCAL.propagation.w3c).toBe(true);
    });

    it('should have DEVELOPMENT preset without Cloud Trace', () => {
      expect(TelemetryPresets.DEVELOPMENT.propagation.cloudTrace).toBe(false);
      expect(TelemetryPresets.DEVELOPMENT.propagation.w3c).toBe(true);
    });

    it('should have DISABLED preset with all propagation disabled', () => {
      expect(TelemetryPresets.DISABLED.propagation.cloudTrace).toBe(false);
      expect(TelemetryPresets.DISABLED.propagation.w3c).toBe(false);
    });
  });

  describe('isRunningOnGCP', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...originalEnv };
    });

    afterAll(() => {
      process.env = originalEnv;
    });

    it('should return false when no GCP env vars are set', () => {
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.GCLOUD_PROJECT;
      delete process.env.GCP_PROJECT;
      delete process.env.K_SERVICE;
      delete process.env.FUNCTION_NAME;
      delete process.env.GAE_APPLICATION;

      expect(isRunningOnGCP()).toBe(false);
    });

    it('should return true when GOOGLE_CLOUD_PROJECT is set', () => {
      process.env.GOOGLE_CLOUD_PROJECT = 'my-project';
      expect(isRunningOnGCP()).toBe(true);
    });

    it('should return true when GCLOUD_PROJECT is set', () => {
      process.env.GCLOUD_PROJECT = 'my-project';
      expect(isRunningOnGCP()).toBe(true);
    });

    it('should return true when GCP_PROJECT is set', () => {
      process.env.GCP_PROJECT = 'my-project';
      expect(isRunningOnGCP()).toBe(true);
    });

    it('should return true when K_SERVICE is set (Cloud Run)', () => {
      process.env.K_SERVICE = 'my-service';
      expect(isRunningOnGCP()).toBe(true);
    });

    it('should return true when FUNCTION_NAME is set (Cloud Functions)', () => {
      process.env.FUNCTION_NAME = 'my-function';
      expect(isRunningOnGCP()).toBe(true);
    });

    it('should return true when GAE_APPLICATION is set (App Engine)', () => {
      process.env.GAE_APPLICATION = 'my-app';
      expect(isRunningOnGCP()).toBe(true);
    });
  });

  describe('getDefaultTelemetryConfig', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...originalEnv };
    });

    afterAll(() => {
      process.env = originalEnv;
    });

    it('should return default config with noony-service name', () => {
      delete process.env.OTEL_SERVICE_NAME;
      delete process.env.SERVICE_NAME;
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.K_SERVICE;
      delete process.env.FUNCTION_NAME;
      delete process.env.GAE_APPLICATION;

      const config = getDefaultTelemetryConfig();

      expect(config.serviceName).toBe('noony-service');
      expect(config.serviceVersion).toBe('1.0.0');
      expect(config.environment).toBe(process.env.NODE_ENV || 'production');
      expect(config.propagation?.cloudTrace).toBe(false);
      expect(config.propagation?.w3c).toBe(true);
    });

    it('should use OTEL_SERVICE_NAME when set', () => {
      process.env.OTEL_SERVICE_NAME = 'my-otel-service';
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.K_SERVICE;

      const config = getDefaultTelemetryConfig();

      expect(config.serviceName).toBe('my-otel-service');
    });

    it('should use SERVICE_NAME when OTEL_SERVICE_NAME not set', () => {
      delete process.env.OTEL_SERVICE_NAME;
      process.env.SERVICE_NAME = 'my-service';
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.K_SERVICE;

      const config = getDefaultTelemetryConfig();

      expect(config.serviceName).toBe('my-service');
    });

    it('should use OTEL_SERVICE_VERSION when set', () => {
      process.env.OTEL_SERVICE_VERSION = '2.3.4';
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.K_SERVICE;

      const config = getDefaultTelemetryConfig();

      expect(config.serviceVersion).toBe('2.3.4');
    });

    it('should use SERVICE_VERSION when OTEL_SERVICE_VERSION not set', () => {
      delete process.env.OTEL_SERVICE_VERSION;
      process.env.SERVICE_VERSION = '3.4.5';
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.K_SERVICE;

      const config = getDefaultTelemetryConfig();

      expect(config.serviceVersion).toBe('3.4.5');
    });

    it('should use NODE_ENV for environment', () => {
      process.env.NODE_ENV = 'staging';
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.K_SERVICE;

      const config = getDefaultTelemetryConfig();

      expect(config.environment).toBe('staging');
    });

    it('should enable Cloud Trace propagation when running on GCP', () => {
      process.env.K_SERVICE = 'my-cloud-run-service';

      const config = getDefaultTelemetryConfig();

      expect(config.propagation?.cloudTrace).toBe(true);
      expect(config.propagation?.w3c).toBe(true);
    });

    it('should disable Cloud Trace propagation when not on GCP', () => {
      delete process.env.GOOGLE_CLOUD_PROJECT;
      delete process.env.GCLOUD_PROJECT;
      delete process.env.GCP_PROJECT;
      delete process.env.K_SERVICE;
      delete process.env.FUNCTION_NAME;
      delete process.env.GAE_APPLICATION;

      const config = getDefaultTelemetryConfig();

      expect(config.propagation?.cloudTrace).toBe(false);
      expect(config.propagation?.w3c).toBe(true);
    });
  });
});
