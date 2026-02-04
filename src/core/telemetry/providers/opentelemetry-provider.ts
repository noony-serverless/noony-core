import { Context } from '../../core';
import {
  TelemetryProvider,
  ValidationResult,
  GenericSpan,
  TelemetryConfig,
} from '../provider';

/**
 * Standard OpenTelemetry SDK 2.0 Provider
 *
 * Implements telemetry using the official OpenTelemetry JavaScript SDK.
 * Supports OTLP exporters for traces, metrics, and logs.
 *
 * Requirements:
 * - Node.js >= 18.19.0 or >= 20.6.0
 * - OTEL_EXPORTER_OTLP_ENDPOINT environment variable
 * - @opentelemetry/sdk-node and related packages installed
 *
 * Auto-selected when OTEL_EXPORTER_OTLP_ENDPOINT is set.
 *
 * @example
 * // Environment setup
 * OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces
 *
 * // Usage
 * const provider = new OpenTelemetryProvider();
 * const validation = await provider.validate();
 * if (validation.valid) {
 *   await provider.initialize({
 *     serviceName: 'my-service',
 *     serviceVersion: '1.0.0'
 *   });
 * }
 */
export class OpenTelemetryProvider implements TelemetryProvider {
  readonly name = 'opentelemetry';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private sdk?: any; // NodeSDK
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private tracer?: any; // Tracer
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private meter?: any; // Meter
  private ready = false;

  /**
   * Validate OpenTelemetry configuration
   *
   * Checks:
   * 1. OTEL_EXPORTER_OTLP_ENDPOINT is set
   * 2. Endpoint is a valid URL
   * 3. Required packages are available (checked lazily during init)
   */
  async validate(): Promise<ValidationResult> {
    const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

    if (!endpoint) {
      return {
        valid: false,
        reason: 'OTEL_EXPORTER_OTLP_ENDPOINT environment variable not set',
      };
    }

    try {
      new URL(endpoint);
    } catch {
      return {
        valid: false,
        reason: `OTEL_EXPORTER_OTLP_ENDPOINT is not a valid URL: ${endpoint}`,
      };
    }

    return { valid: true };
  }

  /**
   * Initialize OpenTelemetry SDK
   *
   * Sets up:
   * - Resource attributes (service name, version, environment)
   * - OTLP trace exporter
   * - Composite propagator (W3C + Cloud Trace)
   * - Tracer and Meter providers
   */
  async initialize(config: TelemetryConfig): Promise<void> {
    try {
      // Dynamic require to avoid compile-time dependency on OTEL packages

      const otelApi = require('@opentelemetry/api');
      const { trace, metrics } = otelApi;

      const sdkNode = require('@opentelemetry/sdk-node');
      const { NodeSDK } = sdkNode;

      const exporterHttp = require('@opentelemetry/exporter-trace-otlp-http');
      const { OTLPTraceExporter } = exporterHttp;

      const resources = require('@opentelemetry/resources');
      const { Resource } = resources;

      const semConv = require('@opentelemetry/semantic-conventions');
      const { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } = semConv;

      // Create resource with service metadata
      const resource = new Resource({
        [ATTR_SERVICE_NAME]: config.serviceName,
        [ATTR_SERVICE_VERSION]: config.serviceVersion || '1.0.0',
        environment: config.environment || 'production',
      });

      // Configure trace exporter
      const traceExporter = new OTLPTraceExporter({
        url:
          config.exporters?.traces?.[0]?.endpoint ||
          process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
        headers: config.exporters?.traces?.[0]?.headers,
        timeoutMillis: config.exporters?.traces?.[0]?.timeout,
      });

      // Configure composite propagator for W3C + Cloud Trace support
      const textMapPropagator = this.createPropagator(config);

      // Initialize SDK
      this.sdk = new NodeSDK({
        resource,
        traceExporter,
        textMapPropagator, // Use composite propagator
      });

      await this.sdk.start();

      // Get tracer and meter
      this.tracer = trace.getTracer(
        config.serviceName,
        config.serviceVersion || '1.0.0'
      );
      this.meter = metrics.getMeter(
        config.serviceName,
        config.serviceVersion || '1.0.0'
      );

      this.ready = true;

      console.log('[Telemetry] OpenTelemetry provider initialized');
      console.log(
        '[Telemetry] Exporting to:',
        config.exporters?.traces?.[0]?.endpoint ||
          process.env.OTEL_EXPORTER_OTLP_ENDPOINT
      );
    } catch (error) {
      console.error(
        '[Telemetry] Failed to initialize OpenTelemetry provider:',
        error
      );
      this.ready = false;

      // Check if error is due to missing packages
      if (
        error instanceof Error &&
        error.message.includes('Cannot find module')
      ) {
        console.error('[Telemetry] OpenTelemetry packages not installed. Run:');
        console.error(
          '  npm install @opentelemetry/api @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http @opentelemetry/resources @opentelemetry/semantic-conventions'
        );
      }
    }
  }

  /**
   * Create an OpenTelemetry span
   *
   * Creates a SERVER span with HTTP semantic conventions.
   * Returns undefined if provider is not ready.
   */
  createSpan(context: Context<unknown, unknown>): GenericSpan | undefined {
    if (!this.ready || !this.tracer) return undefined;

    try {
      // Dynamic import for SpanKind
      const SpanKind = 1; // SERVER = 1 in OpenTelemetry

      const span = this.tracer.startSpan('http.request', {
        kind: SpanKind,
        attributes: {
          'http.method': context.req.method,
          'http.url': context.req.url || context.req.path,
          'http.target': context.req.path || '/',
          'request.id': context.requestId,
          'http.user_agent': context.req.headers?.['user-agent'] || '',
        },
      });

      return {
        setAttributes: (attrs: Record<string, unknown>): void => {
          span.setAttributes(attrs);
        },

        recordException: (error: Error): void => {
          span.recordException(error);
        },

        setStatus: (status: { code: number; message?: string }): void => {
          span.setStatus(status);
        },

        end: (): void => {
          span.end();
        },
      };
    } catch (error) {
      console.error('[Telemetry] Failed to create span:', error);
      return undefined;
    }
  }

  /**
   * Record a metric as a histogram
   */
  recordMetric(
    name: string,
    value: number,
    attributes?: Record<string, unknown>
  ): void {
    if (!this.ready || !this.meter) return;

    try {
      const histogram = this.meter.createHistogram(name, {
        description: `Histogram for ${name}`,
        unit: 'ms',
      });
      histogram.record(value, attributes);
    } catch (error) {
      console.error('[Telemetry] Failed to record metric:', error);
    }
  }

  /**
   * Log with trace correlation
   *
   * Adds trace and span IDs to log output when available.
   */
  log(
    level: string,
    message: string,
    attributes?: Record<string, unknown>
  ): void {
    if (!this.ready) return;

    try {
      // Try to get active span for correlation

      const { trace } = require('@opentelemetry/api');
      const span = trace.getActiveSpan();

      const traceContext = span
        ? {
            traceId: span.spanContext().traceId,
            spanId: span.spanContext().spanId,
            traceFlags: span.spanContext().traceFlags,
          }
        : {};

      console.log(
        JSON.stringify({
          level,
          message,
          ...traceContext,
          ...attributes,
          timestamp: new Date().toISOString(),
        })
      );
    } catch (error) {
      // Fallback to simple logging
      console.log(JSON.stringify({ level, message, ...attributes }));
    }
  }

  /**
   * Check if OpenTelemetry provider is ready
   */
  isReady(): boolean {
    return this.ready;
  }

  /**
   * Shutdown OpenTelemetry SDK
   *
   * Flushes pending telemetry data and closes exporters.
   */
  async shutdown(): Promise<void> {
    if (this.ready && this.sdk) {
      try {
        await this.sdk.shutdown();
        console.log('[Telemetry] OpenTelemetry provider shutdown complete');
      } catch (error) {
        console.error('[Telemetry] Error during shutdown:', error);
      } finally {
        this.ready = false;
      }
    }
  }

  /**
   * Create composite propagator based on configuration
   *
   * Supports:
   * - W3C Trace Context (traceparent/tracestate)
   * - Google Cloud Trace Context (X-Cloud-Trace-Context)
   *
   * When running on GCP, both formats are enabled by default for compatibility.
   * This allows trace IDs to be synchronized between Cloud Run Load Balancer
   * and your application.
   *
   * @param config Telemetry configuration
   * @returns Configured propagator (W3C, Cloud Trace, or Composite)
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private createPropagator(config: TelemetryConfig): any {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const propagators: any[] = [];

      // Determine which propagators to use
      const useCloudTrace =
        config.propagation?.cloudTrace ?? this.isRunningOnGCP();
      const useW3C = config.propagation?.w3c ?? true;

      // Add Cloud Trace propagator (priority 1 - reads X-Cloud-Trace-Context from GCP)
      if (useCloudTrace) {
        try {
          const cloudPropagator = require('@google-cloud/opentelemetry-cloud-trace-propagator');
          const { CloudPropagator } = cloudPropagator;
          propagators.push(new CloudPropagator());
          console.log(
            '[Telemetry] CloudPropagator enabled for GCP trace compatibility'
          );
        } catch (error) {
          console.warn(
            '[Telemetry] CloudPropagator requested but package not installed:',
            error instanceof Error ? error.message : error
          );
          console.warn(
            '[Telemetry] Install with: npm install @google-cloud/opentelemetry-cloud-trace-propagator'
          );
        }
      }

      // Add W3C Trace Context propagator (priority 2 - standard traceparent)
      if (useW3C) {
        const otelCore = require('@opentelemetry/core');
        const { W3CTraceContextPropagator } = otelCore;
        propagators.push(new W3CTraceContextPropagator());
        console.log('[Telemetry] W3CTraceContextPropagator enabled');
      }

      // If multiple propagators, use CompositePropagator
      if (propagators.length > 1) {
        const otelCore = require('@opentelemetry/core');
        const { CompositePropagator } = otelCore;
        return new CompositePropagator({ propagators });
      }

      // If only one propagator, use it directly
      if (propagators.length === 1) {
        return propagators[0];
      }

      // Fallback to W3C if no propagators configured

      const otelCore = require('@opentelemetry/core');
      const { W3CTraceContextPropagator } = otelCore;
      return new W3CTraceContextPropagator();
    } catch (error) {
      console.error('[Telemetry] Failed to create propagator:', error);
      // Return W3C propagator as safe fallback
      try {
        const otelCore = require('@opentelemetry/core');
        const { W3CTraceContextPropagator } = otelCore;
        return new W3CTraceContextPropagator();
      } catch (fallbackError) {
        console.error(
          '[Telemetry] Failed to create fallback propagator:',
          fallbackError
        );
        return undefined;
      }
    }
  }

  /**
   * Detect if running on Google Cloud Platform
   */
  private isRunningOnGCP(): boolean {
    return !!(
      process.env.GOOGLE_CLOUD_PROJECT ||
      process.env.GCLOUD_PROJECT ||
      process.env.GCP_PROJECT ||
      process.env.K_SERVICE || // Cloud Run
      process.env.FUNCTION_NAME || // Cloud Functions
      process.env.GAE_APPLICATION // App Engine
    );
  }
}
