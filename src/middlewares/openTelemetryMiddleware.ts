import { BaseMiddleware, Context } from '../core';
import {
  TelemetryProvider,
  TelemetryConfig,
  GenericSpan,
} from '../core/telemetry/provider';
import {
  NoopProvider,
  ConsoleProvider,
  OpenTelemetryProvider,
} from '../core/telemetry/providers';
import {
  isPubSubMessage,
  extractTraceContext,
  createParentContext,
} from '../utils/pubsub-trace.utils';

/**
 * OpenTelemetry Middleware Options
 */
export interface OpenTelemetryOptions {
  /**
   * Telemetry provider (auto-detects if not provided)
   * @default Auto-detected based on environment variables
   */
  provider?: TelemetryProvider;

  /**
   * Enable telemetry
   * @default true for production, false for NODE_ENV=test
   */
  enabled?: boolean;

  /**
   * Extract custom attributes from context
   * @default Extracts http.method, http.url, request.id, http.user_agent
   */
  extractAttributes?: (
    context: Context<unknown, unknown>
  ) => Record<string, unknown>;

  /**
   * Filter which requests to trace
   * @default Traces all requests
   *
   * @example
   * shouldTrace: (context) => context.req.path !== '/health'
   */
  shouldTrace?: (context: Context<unknown, unknown>) => boolean;

  /**
   * Custom error handler for telemetry errors
   * @default Logs error to console
   */
  onError?: (error: Error, context: Context<unknown, unknown>) => void;

  /**
   * Fail silently on telemetry errors (never throw)
   * @default true (telemetry errors never break application)
   */
  failSilently?: boolean;

  /**
   * Enable trace context propagation for Google Cloud Pub/Sub messages
   *
   * When enabled:
   * - Extracts W3C Trace Context from incoming Pub/Sub message attributes
   * - Links new spans to parent trace from publisher
   * - Allows distributed tracing across Pub/Sub producers and consumers
   *
   * Trace context is stored in message attributes as:
   * - `traceparent`: W3C Trace Context version-traceid-spanid-flags
   * - `tracestate`: Vendor-specific trace state (optional)
   *
   * @default true
   */
  propagatePubSubTraces?: boolean;
}

/**
 * OpenTelemetry Middleware
 *
 * Provides distributed tracing and metrics collection with:
 * - Auto-detection of telemetry provider from environment
 * - Graceful degradation when configuration is missing
 * - Zero-configuration local development support
 * - Type-safe generics to preserve middleware chain
 *
 * Provider Auto-Detection Priority:
 * 1. Explicit provider via options.provider
 * 2. New Relic (if NEW_RELIC_LICENSE_KEY set)
 * 3. Datadog (if DD_API_KEY or DD_SERVICE set)
 * 4. Standard OTEL (if OTEL_EXPORTER_OTLP_ENDPOINT set)
 * 5. Console (if NODE_ENV=development and no OTEL endpoint)
 * 6. Noop (if NODE_ENV=test or no configuration)
 *
 * @template TBody - Request body type
 * @template TUser - Authenticated user type
 *
 * @example
 * // Zero configuration (auto-detects provider)
 * const handler = new Handler()
 *   .use(new OpenTelemetryMiddleware())
 *   .handle(async (context) => {
 *     // Your business logic
 *   });
 *
 * @example
 * // With custom filtering
 * const handler = new Handler()
 *   .use(new OpenTelemetryMiddleware({
 *     shouldTrace: (context) => context.req.path !== '/health'
 *   }))
 *   .handle(async (context) => {
 *     // Your business logic
 *   });
 */
export class OpenTelemetryMiddleware<
  TBody = unknown,
  TUser = unknown,
> implements BaseMiddleware<TBody, TUser> {
  private provider: TelemetryProvider;
  private enabled: boolean;
  private failSilently: boolean;
  private propagatePubSubTraces: boolean;
  private extractAttributes: (
    context: Context<unknown, unknown>
  ) => Record<string, unknown>;
  private shouldTrace: (context: Context<unknown, unknown>) => boolean;
  private customErrorHandler: (
    error: Error,
    context: Context<unknown, unknown>
  ) => void;
  private initialized = false;

  constructor(options: OpenTelemetryOptions = {}) {
    this.enabled = options.enabled ?? process.env.NODE_ENV !== 'test';
    this.failSilently = options.failSilently ?? true;
    this.propagatePubSubTraces = options.propagatePubSubTraces ?? true;

    this.extractAttributes =
      options.extractAttributes || this.defaultExtractAttributes;
    this.shouldTrace = options.shouldTrace || ((): boolean => true);
    this.customErrorHandler = options.onError || this.defaultOnError;

    // Use NoopProvider if disabled
    if (!this.enabled) {
      this.provider = new NoopProvider();
      return;
    }

    // Use provided provider or auto-detect
    this.provider = options.provider || this.autoDetectProvider();
  }

  /**
   * Auto-detect telemetry provider based on environment
   */
  private autoDetectProvider(): TelemetryProvider {
    // Priority 1: New Relic (check for license key and package)
    if (process.env.NEW_RELIC_LICENSE_KEY) {
      try {
        require.resolve('newrelic');
        console.log('[Telemetry] Detected New Relic configuration');
        // Note: NewRelicProvider would be imported here when implemented
        // const { NewRelicProvider } = require('../core/telemetry/providers/newrelic-provider');
        // return new NewRelicProvider();
      } catch {
        console.warn(
          '[Telemetry] NEW_RELIC_LICENSE_KEY set but newrelic package not installed'
        );
      }
    }

    // Priority 2: Datadog (check for API key or service name and package)
    if (process.env.DD_API_KEY || process.env.DD_SERVICE) {
      try {
        require.resolve('dd-trace');
        console.log('[Telemetry] Detected Datadog configuration');
        // Note: DatadogProvider would be imported here when implemented
        // const { DatadogProvider } = require('../core/telemetry/providers/datadog-provider');
        // return new DatadogProvider();
      } catch {
        console.warn(
          '[Telemetry] Datadog config detected but dd-trace package not installed'
        );
      }
    }

    // Priority 3: Standard OTEL (check for OTLP endpoint)
    if (process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
      console.log('[Telemetry] Using standard OpenTelemetry provider');
      return new OpenTelemetryProvider();
    }

    // Priority 4: Console (development mode without OTEL endpoint)
    if (
      process.env.NODE_ENV === 'development' &&
      !process.env.OTEL_EXPORTER_OTLP_ENDPOINT
    ) {
      console.log('[Telemetry] Using console provider for local development');
      return new ConsoleProvider();
    }

    // Priority 5: Noop (no configuration found)
    console.log(
      '[Telemetry] No telemetry configuration detected, using Noop provider'
    );
    return new NoopProvider();
  }

  /**
   * Initialize provider with configuration
   *
   * This should be called once at application startup.
   * If not called explicitly, it will be initialized on first request.
   *
   * @param config Telemetry configuration
   */
  async initialize(config: TelemetryConfig): Promise<void> {
    if (this.initialized) return;

    if (!this.enabled) {
      this.initialized = true;
      return;
    }

    try {
      // Validate provider before initialization
      const validation = await this.provider.validate();

      if (!validation.valid) {
        console.warn(
          `[Telemetry] Provider '${this.provider.name}' validation failed: ${validation.reason}`
        );
        console.warn('[Telemetry] Falling back to Noop provider');
        this.provider = new NoopProvider();
        this.initialized = true;
        return;
      }

      // Initialize provider
      await this.provider.initialize(config);

      // Check if provider is ready
      if (!this.provider.isReady()) {
        console.warn(
          `[Telemetry] Provider '${this.provider.name}' initialization failed, falling back to Noop`
        );
        this.provider = new NoopProvider();
      } else {
        console.log(
          `[Telemetry] Provider '${this.provider.name}' initialized successfully`
        );
      }

      this.initialized = true;
    } catch (error) {
      console.error('[Telemetry] Failed to initialize provider:', error);
      this.provider = new NoopProvider();
      this.initialized = true;
    }
  }

  /**
   * Before hook - Create span and store in context
   *
   * If propagatePubSubTraces is enabled and the request is a Pub/Sub message:
   * 1. Extracts W3C Trace Context from message attributes
   * 2. Creates a child span linked to the publisher's trace
   * 3. Enables end-to-end distributed tracing across Pub/Sub
   */
  async before(context: Context<TBody, TUser>): Promise<void> {
    if (!this.enabled) return;

    // Auto-initialize with minimal config if not initialized
    if (!this.initialized) {
      await this.initialize({
        serviceName: process.env.SERVICE_NAME || 'noony-service',
        serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'production',
      });
    }

    // Check if should trace
    if (!this.shouldTrace(context as Context<unknown, unknown>)) {
      return;
    }

    try {
      // Extract trace context from Pub/Sub message if enabled
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let parentContext: any = undefined;

      if (this.propagatePubSubTraces && isPubSubMessage(context.req.body)) {
        const traceContext = extractTraceContext(context.req.body);

        if (traceContext.traceparent) {
          // Store trace context for span creation
          const carrier = createParentContext(traceContext);

          // Try to extract parent context using OpenTelemetry API
          try {
            const otelApi = require('@opentelemetry/api');
            const { propagation, context: otelContext } = otelApi;

            // Extract parent context from carrier
            parentContext = propagation.extract(otelContext.active(), carrier);

            console.log('[Telemetry] Extracted Pub/Sub trace context:', {
              traceparent: traceContext.traceparent,
              tracestate: traceContext.tracestate,
            });
          } catch (err) {
            // OpenTelemetry API not available, continue without parent context
            console.warn(
              '[Telemetry] Failed to extract Pub/Sub trace context:',
              err
            );
          }
        }
      }

      // Create span (with parent context if available)
      const span = this.provider.createSpan(
        context as Context<unknown, unknown>
      );

      if (!span) return;

      // If we have a parent context from Pub/Sub, link the span
      if (parentContext) {
        span.setAttributes({
          'messaging.system': 'pubsub',
          'messaging.operation': 'process',
          'pubsub.message_id':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (context.req.body as any)?.message?.messageId || 'unknown',
        });
      }

      // Add custom attributes
      const customAttributes = this.extractAttributes(
        context as Context<unknown, unknown>
      );
      span.setAttributes(customAttributes);

      // Store span and provider name in businessData
      context.businessData.set('otel_span', span);
      context.businessData.set('otel_provider', this.provider.name);
    } catch (error) {
      if (!this.failSilently) throw error;
      console.error('[Telemetry] Error in before hook:', error);
    }
  }

  /**
   * After hook - End span with success status and add X-Trace-Id header
   */
  async after(context: Context<TBody, TUser>): Promise<void> {
    if (!this.enabled) return;

    try {
      const span = context.businessData.get('otel_span') as
        | GenericSpan
        | undefined;

      if (span) {
        // Add response attributes
        span.setAttributes({
          'http.status_code': context.res.statusCode || 200,
          'request.duration_ms': Date.now() - context.startTime,
        });

        // Add X-Trace-Id header with clean trace ID
        try {
          const otelApi = require('@opentelemetry/api');
          const { context: otelContext, trace } = otelApi;

          // Get span from active context
          const activeContext = otelContext.active();
          const activeSpan = trace.getSpan(activeContext);

          if (activeSpan) {
            const spanContext = activeSpan.spanContext();
            if (spanContext.traceId) {
              // Add custom header with clean trace ID (32 hex chars)
              context.res.header('X-Trace-Id', spanContext.traceId);
            }
          }
        } catch (headerError) {
          // Non-critical error - don't fail the request
          console.warn(
            '[Telemetry] Failed to add X-Trace-Id header:',
            headerError
          );
        }

        // Set success status (code 0 = OK in OTEL)
        span.setStatus({ code: 0 });

        // End span
        span.end();
      }
    } catch (error) {
      if (!this.failSilently) throw error;
      console.error('[Telemetry] Error in after hook:', error);
    }
  }

  /**
   * Error hook - Record exception and end span
   */
  async onError(error: Error, context: Context<TBody, TUser>): Promise<void> {
    if (!this.enabled) return;

    try {
      const span = context.businessData.get('otel_span') as
        | GenericSpan
        | undefined;

      if (span) {
        // Record exception
        span.recordException(error);

        // Set error status (code 1 = ERROR in OTEL, code 2 = ERROR in some systems)
        span.setStatus({
          code: 1,
          message: error.message,
        });

        // End span
        span.end();
      }

      // Call custom error handler
      this.customErrorHandler(error, context as Context<unknown, unknown>);
    } catch (err) {
      if (!this.failSilently) throw err;
      console.error('[Telemetry] Error in onError hook:', err);
    }
  }

  /**
   * Default attribute extractor
   */
  private defaultExtractAttributes(
    context: Context<unknown, unknown>
  ): Record<string, unknown> {
    return {
      'http.method': context.req.method,
      'http.url': context.req.url || context.req.path,
      'http.target': context.req.path || '/',
      'request.id': context.requestId,
      'http.user_agent': context.req.headers?.['user-agent'] || '',
    };
  }

  /**
   * Default error handler
   */
  private defaultOnError(
    error: Error,
    _context: Context<unknown, unknown>
  ): void {
    console.error('[Telemetry] Request error:', {
      name: error.name,
      message: error.message,
    });
  }

  /**
   * Get current provider (useful for testing)
   */
  getProvider(): TelemetryProvider {
    return this.provider;
  }

  /**
   * Shutdown telemetry provider
   *
   * Should be called during application shutdown to flush pending data.
   */
  async shutdown(): Promise<void> {
    if (this.provider) {
      await this.provider.shutdown();
    }
  }
}

/**
 * Factory function for OpenTelemetry middleware
 *
 * @example
 * const handler = new Handler()
 *   .use(openTelemetry({ shouldTrace: ctx => ctx.req.path !== '/health' }))
 *   .handle(async (context) => { });
 */
export const openTelemetry = <TBody = unknown, TUser = unknown>(
  options: OpenTelemetryOptions = {}
): OpenTelemetryMiddleware<TBody, TUser> => {
  return new OpenTelemetryMiddleware<TBody, TUser>(options);
};
