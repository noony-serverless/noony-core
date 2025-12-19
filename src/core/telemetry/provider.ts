import { Context } from '../core';

/**
 * Validation result from TelemetryProvider.validate()
 */
export interface ValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Generic span interface that works across different telemetry providers
 * This provides a common interface for OTEL, New Relic, Datadog, etc.
 */
export interface GenericSpan {
  setAttributes(attributes: Record<string, unknown>): void;
  recordException(error: Error): void;
  setStatus(status: { code: number; message?: string }): void;
  end(): void;
}

/**
 * Base interface for telemetry providers
 *
 * This interface allows custom implementations for different APM platforms:
 * - Standard OpenTelemetry SDK
 * - New Relic Agent
 * - Datadog Tracer
 * - Custom implementations
 *
 * All providers must implement validation to ensure graceful degradation
 * when configuration is missing or invalid.
 */
export interface TelemetryProvider {
  /**
   * Provider name for identification
   * Examples: 'opentelemetry', 'newrelic', 'datadog', 'console', 'noop'
   */
  readonly name: string;

  /**
   * Validate provider configuration before initialization
   *
   * This method checks:
   * - Required environment variables are set
   * - Required npm packages are installed
   * - Configuration is valid (e.g., valid URLs)
   *
   * @returns Validation result with optional reason if invalid
   *
   * @example
   * const result = await provider.validate();
   * if (!result.valid) {
   *   console.warn(`Provider validation failed: ${result.reason}`);
   *   // Fall back to NoopProvider
   * }
   */
  validate(): Promise<ValidationResult>;

  /**
   * Initialize the telemetry provider with configuration
   *
   * This is called once at application startup, not per-request.
   * Providers should set up SDK, exporters, and any global configuration.
   *
   * @param config Telemetry configuration
   * @throws Should not throw - errors should be caught and logged internally
   *
   * @example
   * await provider.initialize({
   *   serviceName: 'order-service',
   *   serviceVersion: '1.0.0',
   *   environment: 'production'
   * });
   */
  initialize(config: TelemetryConfig): Promise<void>;

  /**
   * Create a span for the current request
   *
   * This is called in the middleware `before` hook for each request.
   * Returns undefined if provider is not ready or span creation fails.
   *
   * @param context The Noony request context
   * @returns Span object or undefined if span creation fails
   *
   * @example
   * const span = provider.createSpan(context);
   * if (span) {
   *   span.setAttributes({ 'user.id': context.user?.id });
   *   context.businessData.set('otel_span', span);
   * }
   */
  createSpan(context: Context<unknown, unknown>): GenericSpan | undefined;

  /**
   * Record a metric (histogram, counter, gauge, etc.)
   *
   * @param name Metric name (e.g., 'http.request.duration')
   * @param value Metric value
   * @param attributes Optional metric attributes/tags
   *
   * @example
   * provider.recordMetric('http.request.duration', 123.45, {
   *   'http.method': 'POST',
   *   'http.status_code': 200
   * });
   */
  recordMetric(
    name: string,
    value: number,
    attributes?: Record<string, unknown>
  ): void;

  /**
   * Log with trace correlation
   *
   * Logs should include trace and span IDs when available for correlation.
   *
   * @param level Log level (info, error, warn, debug)
   * @param message Log message
   * @param attributes Additional log attributes
   *
   * @example
   * provider.log('error', 'Request failed', {
   *   'error.type': 'ValidationError',
   *   'user.id': userId
   * });
   */
  log(
    level: string,
    message: string,
    attributes?: Record<string, unknown>
  ): void;

  /**
   * Check if provider is initialized and ready to use
   *
   * @returns True if provider is ready, false otherwise
   *
   * @example
   * if (!provider.isReady()) {
   *   console.warn('Provider not ready, skipping telemetry');
   * }
   */
  isReady(): boolean;

  /**
   * Shutdown the provider gracefully
   *
   * Called during application shutdown to flush any pending telemetry data.
   *
   * @example
   * process.on('SIGTERM', async () => {
   *   await provider.shutdown();
   *   process.exit(0);
   * });
   */
  shutdown(): Promise<void>;
}

/**
 * Telemetry configuration interface
 */
export interface TelemetryConfig {
  /** Enable telemetry (defaults to true) */
  enabled?: boolean;

  /** Service name for telemetry */
  serviceName: string;

  /** Service version (optional) */
  serviceVersion?: string;

  /** Environment (e.g., 'production', 'staging', 'development') */
  environment?: string;

  /** Exporter configurations */
  exporters?: {
    traces?: OTLPExporterConfig[];
    metrics?: OTLPExporterConfig[];
    logs?: OTLPExporterConfig[];
  };

  /** Sampling configuration */
  sampling?: {
    /** Sampling ratio (0.0 to 1.0) */
    ratio?: number;
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
 * OTLP Exporter configuration
 */
export interface OTLPExporterConfig {
  /** Exporter endpoint URL */
  endpoint: string;

  /** Optional headers (e.g., API keys) */
  headers?: Record<string, string>;

  /** Timeout in milliseconds (optional) */
  timeout?: number;
}
