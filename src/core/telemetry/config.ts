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
 * Span processor configuration for aggressive export in serverless environments
 */
export interface SpanProcessorConfig {
  /**
   * Maximum queue size before dropping spans
   * @default 100
   */
  maxQueueSize?: number;

  /**
   * Maximum number of spans to export in a single batch
   * For scale-to-zero environments, set to 1 for immediate export
   * @default 1 (immediate export for serverless)
   */
  maxExportBatchSize?: number;

  /**
   * Delay in milliseconds between export attempts
   * For scale-to-zero environments, use aggressive timing (100ms)
   * @default 100 (very aggressive for Cloud Run)
   */
  scheduledDelayMillis?: number;

  /**
   * Timeout in milliseconds for export operations
   * @default 30000 (30 seconds)
   */
  exportTimeoutMillis?: number;

  /**
   * Enable detailed export logging for debugging
   * @default false
   */
  enableExportLogging?: boolean;
}

/**
 * HTTP instrumentation configuration
 */
export interface HttpInstrumentationConfig {
  /**
   * Enable HTTP instrumentation
   * @default true
   */
  enabled?: boolean;

  /**
   * Require parent span for incoming HTTP requests
   * Set to false to create root spans for all requests
   * @default false (creates root spans)
   */
  requireParentforIncomingSpans?: boolean;

  /**
   * Require parent span for outgoing HTTP requests
   * @default false
   */
  requireParentforOutgoingSpans?: boolean;

  /**
   * Ignore health check endpoints
   * @default true
   */
  ignoreHealthChecks?: boolean;

  /**
   * Trace OPTIONS requests (CORS preflight)
   * @default false (reduces noise)
   */
  traceOptionsRequests?: boolean;

  /**
   * Custom URL patterns to ignore (regex strings)
   */
  ignoreUrls?: string[];
}

/**
 * Auto-instrumentation configuration
 */
export interface InstrumentationConfig {
  /**
   * Enable HTTP instrumentation
   * @default true
   */
  http?: boolean | HttpInstrumentationConfig;

  /**
   * Enable MongoDB instrumentation
   * @default true
   */
  mongodb?: boolean;

  /**
   * Enable Pino logger instrumentation
   * @default true
   */
  pino?: boolean;

  /**
   * Enable Fastify instrumentation
   * WARNING: Should be disabled when using HTTP instrumentation to prevent duplicates
   * @default false (prevents duplicate spans)
   */
  fastify?: boolean;

  /**
   * Enable DNS instrumentation
   * @default false (reduces noise)
   */
  dns?: boolean;

  /**
   * Enable Net instrumentation
   * @default false (reduces noise)
   */
  net?: boolean;

  /**
   * Enable FS instrumentation
   * @default false (reduces noise)
   */
  fs?: boolean;
}

/**
 * Metrics configuration
 */
export interface MetricsConfig {
  /**
   * Enable metrics collection
   * @default true
   */
  enabled?: boolean;

  /**
   * Export interval in milliseconds
   * @default 60000 (60 seconds)
   */
  exportIntervalMillis?: number;
}

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

  /**
   * Span processor configuration for aggressive export
   * Optimized for scale-to-zero serverless environments
   */
  spanProcessor?: SpanProcessorConfig;

  /**
   * Auto-instrumentation configuration
   * Controls which libraries are automatically instrumented
   */
  instrumentation?: InstrumentationConfig;

  /**
   * Metrics configuration
   */
  metrics?: MetricsConfig;

  /**
   * Auto-initialize SDK at module load
   * When true, OTEL SDK initializes automatically when telemetry.config.ts is imported
   * @default false (manual initialization via middleware)
   */
  autoInitialize?: boolean;
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
   * Cloud Run optimized preset with aggressive span export
   * Prevents data loss during scale-to-zero container termination
   */
  CLOUD_RUN: {
    propagation: {
      cloudTrace: true,
      w3c: true,
    },
    spanProcessor: {
      maxQueueSize: 100,
      maxExportBatchSize: 1, // Immediate export
      scheduledDelayMillis: 100, // Very aggressive (vs 5s default)
      exportTimeoutMillis: 30000,
      enableExportLogging: true,
    },
    instrumentation: {
      http: {
        enabled: true,
        requireParentforIncomingSpans: false, // Create root spans
        ignoreHealthChecks: true,
        traceOptionsRequests: false,
      },
      mongodb: true,
      pino: true,
      fastify: false, // Prevent duplicate spans
      dns: false,
      net: false,
      fs: false,
    },
    metrics: {
      enabled: true,
      exportIntervalMillis: 60000,
    },
    autoInitialize: true,
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
