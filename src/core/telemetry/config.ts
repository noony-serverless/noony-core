/**
 * Telemetry Configuration
 *
 * Centralized configuration for OpenTelemetry setup including:
 * - Service resource attributes
 * - Trace exporters and propagators
 * - Metrics configuration
 * - Platform-specific presets
 */

/**
 * Telemetry configuration interface
 */
export interface TelemetryConfig {
  /**
   * Service name for identification in traces
   * @example 'order-service'
   */
  serviceName: string;

  /**
   * Service version for deployment tracking
   * @example '2.1.0'
   */
  serviceVersion: string;

  /**
   * Deployment environment
   * @example 'production', 'staging', 'development'
   */
  environment: string;

  /**
   * Trace exporters configuration
   */
  exporters?: {
    traces?: Array<{
      endpoint: string;
      headers?: Record<string, string>;
    }>;
    metrics?: Array<{
      endpoint: string;
      headers?: Record<string, string>;
    }>;
  };

  /**
   * Sampling configuration for traces
   */
  sampling?: {
    ratio: number; // 0.0 to 1.0
  };

  /**
   * Propagation format configuration
   * Controls which trace context formats to support
   */
  propagation?: {
    /**
     * Enable Cloud Trace propagation for Google Cloud Platform
     * Uses X-Cloud-Trace-Context header format
     * @default true when running on GCP
     */
    cloudTrace?: boolean;

    /**
     * Enable W3C Trace Context propagation
     * Uses traceparent/tracestate header format
     * @default true
     */
    w3c?: boolean;

    /**
     * Additional custom propagators
     */
    custom?: string[];
  };
}

/**
 * Platform-specific telemetry presets
 */
export const TelemetryPresets = {
  /**
   * Google Cloud Platform preset with Cloud Trace integration
   */
  GCP: {
    propagation: {
      cloudTrace: true,
      w3c: true,
    },
  },

  /**
   * New Relic APM preset
   */
  NEW_RELIC: {
    propagation: {
      cloudTrace: false,
      w3c: true,
    },
  },

  /**
   * Datadog APM preset
   */
  DATADOG: {
    propagation: {
      cloudTrace: false,
      w3c: true,
    },
  },

  /**
   * Standard OpenTelemetry preset (OTLP)
   */
  OTLP: {
    propagation: {
      cloudTrace: false,
      w3c: true,
    },
  },

  /**
   * Jaeger local development preset
   */
  JAEGER_LOCAL: {
    exporters: {
      traces: [{ endpoint: 'http://localhost:4318/v1/traces' }],
    },
    propagation: {
      cloudTrace: false,
      w3c: true,
    },
  },

  /**
   * Development preset (console output only)
   */
  DEVELOPMENT: {
    propagation: {
      cloudTrace: false,
      w3c: true,
    },
  },

  /**
   * Disabled preset (no telemetry)
   */
  DISABLED: {
    propagation: {
      cloudTrace: false,
      w3c: false,
    },
  },
} as const;

/**
 * Detect if running on Google Cloud Platform
 */
export function isRunningOnGCP(): boolean {
  return !!(
    process.env.GOOGLE_CLOUD_PROJECT ||
    process.env.GCLOUD_PROJECT ||
    process.env.GCP_PROJECT ||
    process.env.K_SERVICE || // Cloud Run
    process.env.FUNCTION_NAME || // Cloud Functions
    process.env.GAE_APPLICATION // App Engine
  );
}

/**
 * Get default telemetry configuration based on environment
 */
export function getDefaultTelemetryConfig(): Partial<TelemetryConfig> {
  const isGCP = isRunningOnGCP();

  return {
    serviceName:
      process.env.OTEL_SERVICE_NAME ||
      process.env.SERVICE_NAME ||
      'noony-service',
    serviceVersion:
      process.env.OTEL_SERVICE_VERSION ||
      process.env.SERVICE_VERSION ||
      '1.0.0',
    environment: process.env.NODE_ENV || 'production',
    propagation: {
      cloudTrace: isGCP, // Enable Cloud Trace propagation on GCP
      w3c: true, // Always enable W3C Trace Context
    },
  };
}
