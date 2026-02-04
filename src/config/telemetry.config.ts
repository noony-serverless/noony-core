/**
 * OpenTelemetry SDK Initialization for Cloud Run Production
 *
 * This file provides automatic OpenTelemetry initialization optimized for Google Cloud Run
 * scale-to-zero environments. Import this file FIRST in your entry point to ensure
 * instrumentation hooks are registered before any other libraries load.
 *
 * @example
 * ```typescript
 * // server.ts - CRITICAL: Import OTEL first
 * import '@config/telemetry.config';  // MUST BE FIRST
 *
 * import 'reflect-metadata';
 * import { FastifyAdapter } from '@adapters/fastify.adapter';
 * // ... other imports
 * ```
 *
 * @see https://cloud.google.com/trace/docs/setup/nodejs-ot
 * @see https://opentelemetry.io/docs/languages/js/getting-started/nodejs/
 */

/**
 * Type definitions for OpenTelemetry components
 */
interface ReadableSpan {
  name: string;
  kind: number;
  spanContext(): { traceId: string; spanId: string; traceFlags: number };
}

interface ExportResult {
  code: number;
  error?: Error;
}

interface SpanExporter {
  export(
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void;
}

interface NodeSDKInstance {
  start(): void;
  shutdown(): Promise<void>;
}

interface InstrumentedHttpRequest {
  url?: string;
  method?: string;
}

/**
 * Global SDK instance (singleton)
 */
let otelSDK: NodeSDKInstance | null = null;

/**
 * Lazy-loaded OTEL modules (optional dependencies)
 * These are loaded dynamically to avoid compile-time dependency on OTEL packages
 */
let NodeSDK: new (config: unknown) => NodeSDKInstance;
let Resource: new (attributes: Record<string, unknown>) => unknown;
let ATTR_SERVICE_NAME: string;
let ATTR_SERVICE_VERSION: string;
let ATTR_DEPLOYMENT_ENVIRONMENT: string;
let BatchSpanProcessor: new (
  exporter: SpanExporter,
  config?: unknown
) => unknown;
let OTLPTraceExporter: new (config?: unknown) => SpanExporter;
let OTLPMetricExporter: new (config?: unknown) => unknown;
let PeriodicExportingMetricReader: new (config: unknown) => unknown;
let getNodeAutoInstrumentations: (config?: unknown) => unknown[];
let CompositePropagator: new (config: { propagators: unknown[] }) => unknown;
let W3CTraceContextPropagator: new () => unknown;
let ParentBasedSampler: new (config: { root: unknown }) => unknown;
let AlwaysOnSampler: new () => unknown;
let CloudPropagator: (new () => unknown) | null;

/**
 * Load OTEL modules (called once during initialization)
 */
function loadOTELModules(): boolean {
  try {
    // Load SDK

    const sdkNode = require('@opentelemetry/sdk-node');
    NodeSDK = sdkNode.NodeSDK;

    // Load resources

    const resources = require('@opentelemetry/resources');
    Resource = resources.Resource;

    // Load semantic conventions

    const semConv = require('@opentelemetry/semantic-conventions');
    ATTR_SERVICE_NAME = semConv.ATTR_SERVICE_NAME;
    ATTR_SERVICE_VERSION = semConv.ATTR_SERVICE_VERSION;
    ATTR_DEPLOYMENT_ENVIRONMENT = semConv.ATTR_DEPLOYMENT_ENVIRONMENT;

    // Load trace SDK

    const traceNode = require('@opentelemetry/sdk-trace-node');
    BatchSpanProcessor = traceNode.BatchSpanProcessor;

    // Load exporters

    const traceExporter = require('@opentelemetry/exporter-trace-otlp-http');
    OTLPTraceExporter = traceExporter.OTLPTraceExporter;

    const metricExporter = require('@opentelemetry/exporter-metrics-otlp-http');
    OTLPMetricExporter = metricExporter.OTLPMetricExporter;

    // Load metrics SDK

    const metricsSDK = require('@opentelemetry/sdk-metrics');
    PeriodicExportingMetricReader = metricsSDK.PeriodicExportingMetricReader;

    // Load auto-instrumentations

    const autoInst = require('@opentelemetry/auto-instrumentations-node');
    getNodeAutoInstrumentations = autoInst.getNodeAutoInstrumentations;

    // Load core

    const core = require('@opentelemetry/core');
    CompositePropagator = core.CompositePropagator;
    W3CTraceContextPropagator = core.W3CTraceContextPropagator;

    // Load samplers

    const traceBase = require('@opentelemetry/sdk-trace-base');
    ParentBasedSampler = traceBase.ParentBasedSampler;
    AlwaysOnSampler = traceBase.AlwaysOnSampler;

    // Try to load CloudPropagator (optional)
    try {
      const cloudProp = require('@google-cloud/opentelemetry-cloud-trace-propagator');
      CloudPropagator = cloudProp.CloudPropagator;
    } catch {
      CloudPropagator = null;
    }

    return true;
  } catch (error) {
    console.error('[OTEL] Failed to load OpenTelemetry packages:', error);
    console.error('[OTEL] Install required packages with:');
    console.error(
      '  npm install @opentelemetry/api @opentelemetry/sdk-node @opentelemetry/auto-instrumentations-node'
    );
    return false;
  }
}

/**
 * Determine if OpenTelemetry should be enabled
 *
 * OTEL automatically activates in these scenarios:
 * 1. Explicitly enabled via OTEL_ENABLED=true
 * 2. Running in production (NODE_ENV=production)
 * 3. Running in Cloud Run (K_SERVICE env var present)
 */
export function isOtelEnabled(): boolean {
  const explicitlyEnabled = process.env.OTEL_ENABLED === 'true';
  const isProduction = process.env.NODE_ENV === 'production';
  const isCloudRun = !!process.env.K_SERVICE;
  const isCloudFunction = !!process.env.FUNCTION_NAME;
  const isAppEngine = !!process.env.GAE_APPLICATION;

  return (
    explicitlyEnabled ||
    isProduction ||
    isCloudRun ||
    isCloudFunction ||
    isAppEngine
  );
}

/**
 * Get service name from environment or default
 */
function getServiceName(): string {
  return (
    process.env.OTEL_SERVICE_NAME ||
    process.env.K_SERVICE ||
    process.env.FUNCTION_NAME ||
    process.env.GAE_SERVICE ||
    'noony-serverless-api'
  );
}

/**
 * Get deployment environment
 */
function getEnvironment(): string {
  return (
    process.env.NODE_ENV || process.env.DEPLOYMENT_ENVIRONMENT || 'development'
  );
}

/**
 * Get service version from package.json or environment
 */
function getServiceVersion(): string {
  try {
    const packageJson = require('../../package.json');
    return packageJson.version || '0.0.0';
  } catch {
    return process.env.SERVICE_VERSION || '0.0.0';
  }
}

/**
 * Create resource with service metadata
 *
 * Automatically adds Cloud Run-specific attributes when running on GCP:
 * - cloud.platform: gcp_cloud_run
 * - cloud.provider: gcp
 * - service.instance.id: K_REVISION
 * - cloud.region: CLOUD_RUN_REGION
 */
function createResource(): unknown {
  const attributes: Record<string, string> = {
    [ATTR_SERVICE_NAME]: getServiceName(),
    [ATTR_SERVICE_VERSION]: getServiceVersion(),
    [ATTR_DEPLOYMENT_ENVIRONMENT]: getEnvironment(),
  };

  // Add Cloud Run specific attributes if available
  if (process.env.K_SERVICE) {
    attributes['cloud.platform'] = 'gcp_cloud_run';
    attributes['cloud.provider'] = 'gcp';
    attributes['service.instance.id'] = process.env.K_REVISION || 'unknown';
    attributes['cloud.region'] = process.env.CLOUD_RUN_REGION || 'unknown';
  }

  // Add Cloud Function specific attributes
  if (process.env.FUNCTION_NAME) {
    attributes['cloud.platform'] = 'gcp_cloud_functions';
    attributes['cloud.provider'] = 'gcp';
    attributes['faas.name'] = process.env.FUNCTION_NAME;
    attributes['cloud.region'] = process.env.FUNCTION_REGION || 'unknown';
  }

  // Add App Engine specific attributes
  if (process.env.GAE_APPLICATION) {
    attributes['cloud.platform'] = 'gcp_app_engine';
    attributes['cloud.provider'] = 'gcp';
    attributes['service.instance.id'] = process.env.GAE_INSTANCE || 'unknown';
  }

  return new Resource(attributes);
}

/**
 * Create composite propagator supporting both GCP and W3C formats
 *
 * Priority order:
 * 1. CloudPropagator (X-Cloud-Trace-Context) - GCP format from browser/LB
 * 2. W3CTraceContextPropagator (traceparent) - Standard format
 *
 * This enables trace synchronization between:
 * - Cloud Run Load Balancer → Application
 * - Application → Cloud Trace UI
 * - Application → Downstream services
 */
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function createPropagator() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const propagators: any[] = [];

  // Add CloudPropagator first (priority) if available
  if (CloudPropagator) {
    propagators.push(new CloudPropagator());
  }

  // Always add W3C propagator as fallback
  propagators.push(new W3CTraceContextPropagator());

  return new CompositePropagator({ propagators });
}

/**
 * Create sampler for trace sampling decisions
 *
 * Uses ParentBasedSampler with AlwaysOnSampler root:
 * - If parent span exists: use parent's sampling decision
 * - If no parent: always sample (AlwaysOnSampler)
 */
function createSampler(): unknown {
  return new ParentBasedSampler({
    root: new AlwaysOnSampler(),
  });
}

/**
 * Create aggressive span processor optimized for scale-to-zero environments
 *
 * Cloud Run can terminate containers quickly (within ~10 seconds after SIGTERM).
 * This configuration exports spans immediately to prevent data loss:
 *
 * - maxExportBatchSize: 1 (export each span immediately)
 * - scheduledDelayMillis: 100ms (check every 100ms, vs 5s default)
 * - exportTimeoutMillis: 30s (allow time for network latency)
 *
 * Also wraps the exporter with enhanced logging for debugging export attempts.
 *
 * @param traceExporter - The trace exporter to use (OTLP, GCP, etc.)
 */
function createSpanProcessor(traceExporter: SpanExporter): unknown {
  // Enhanced logging wrapper for export attempts with detailed span info
  const originalExport = traceExporter.export.bind(traceExporter);
  traceExporter.export = (
    spans: ReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void => {
    // Log each span being exported with full details
    const spanDetails = spans.map((s) => ({
      traceId: s.spanContext().traceId,
      spanId: s.spanContext().spanId,
      name: s.name,
      kind: s.kind,
    }));

    console.log('[OTEL-EXPORT] Exporting spans', {
      spanCount: spans.length,
      spans: spanDetails,
    });

    return originalExport(spans, (result: ExportResult) => {
      if (result.code !== 0) {
        console.error('[OTEL-EXPORT] Export failed', {
          code: result.code,
          error: result.error?.message,
        });
      } else {
        console.log('[OTEL-EXPORT] Export successful');
      }
      resultCallback(result);
    });
  };

  // Aggressive export settings for scale-to-zero environments
  // Export immediately (batch size 1) with minimal delay (100ms)
  return new BatchSpanProcessor(traceExporter, {
    maxQueueSize: 100,
    maxExportBatchSize: 1, // Export each span immediately
    scheduledDelayMillis: 100, // Check every 100ms (very aggressive)
    exportTimeoutMillis: 30000, // 30 second timeout
  });
}

/**
 * Create HTTP instrumentation configuration
 *
 * Key settings:
 * - requireParentforIncomingSpans: false - Creates root spans for all requests
 * - Filters out health checks and OPTIONS requests to reduce noise
 * - Configurable OPTIONS tracing via OTEL_OPTION_REQ_ENABLE
 */
function createHttpInstrumentationConfig(): {
  enabled: boolean;
  requireParentforIncomingSpans: boolean;
  requireParentforOutgoingSpans: boolean;
  ignoreIncomingRequestHook: (request: unknown) => boolean;
} {
  const enableOptionsTracing = process.env.OTEL_OPTION_REQ_ENABLE === 'true';

  return {
    enabled: true,
    // Create spans for all incoming requests (including those without parent)
    // This ensures we have a root span for every request
    requireParentforIncomingSpans: false,
    requireParentforOutgoingSpans: false,
    // Ignore internal/health check and OPTIONS requests to reduce noise
    ignoreIncomingRequestHook: (request: unknown): boolean => {
      const req = request as InstrumentedHttpRequest;
      const url = req.url || '';
      const method = req.method || '';

      // Always ignore health checks and internal requests
      if (
        url.includes('/health') ||
        url.includes('/_ah/') ||
        url === '' ||
        url === undefined
      ) {
        return true;
      }

      // Ignore OPTIONS requests unless explicitly enabled
      if (method === 'OPTIONS' && !enableOptionsTracing) {
        return true;
      }

      return false;
    },
  };
}

/**
 * Create selective auto-instrumentation array
 *
 * Enabled instrumentations:
 * - @opentelemetry/instrumentation-http: HTTP requests (root span creator)
 * - @opentelemetry/instrumentation-mongodb: Database queries
 * - @opentelemetry/instrumentation-pino: Log correlation
 *
 * Disabled instrumentations:
 * - @opentelemetry/instrumentation-fastify: Prevents duplicate spans with HTTP instrumentation
 * - @opentelemetry/instrumentation-dns: Reduces noise
 * - @opentelemetry/instrumentation-net: Reduces noise
 * - @opentelemetry/instrumentation-fs: Reduces noise
 *
 * IMPORTANT: Fastify instrumentation is disabled to prevent duplicate spans.
 * HTTP instrumentation already creates root spans for all HTTP requests.
 */
function createInstrumentations(): unknown[] {
  return [
    getNodeAutoInstrumentations({
      '@opentelemetry/instrumentation-dns': { enabled: false },
      '@opentelemetry/instrumentation-net': { enabled: false },
      '@opentelemetry/instrumentation-fs': { enabled: false },
      '@opentelemetry/instrumentation-fastify': { enabled: false }, // Completely disabled
      '@opentelemetry/instrumentation-http': createHttpInstrumentationConfig(),
      '@opentelemetry/instrumentation-mongodb': { enabled: true },
      '@opentelemetry/instrumentation-pino': { enabled: true },
    }),
  ];
}

/**
 * Setup graceful shutdown handler for SIGTERM/SIGINT
 *
 * When Cloud Run sends SIGTERM (shutdown signal), this handler forces
 * all pending spans to export before the process terminates.
 *
 * Has a 2-second timeout as a safety measure to prevent hanging processes.
 */
function setupShutdownHandler(sdk: NodeSDKInstance): void {
  const shutdownWithFlush = async (): Promise<void> => {
    console.log('[OTEL] SIGTERM received - forcing span flush...');
    try {
      // The SDK.shutdown() should flush all pending spans
      // But we're in a race against Cloud Run termination
      const shutdownPromise = sdk.shutdown();

      // Wait up to 2 seconds for shutdown to complete
      // This gives BatchSpanProcessor time to export pending spans
      const timeoutPromise = new Promise((resolve) =>
        setTimeout(() => {
          console.log('[OTEL] Shutdown timeout - forcing exit');
          resolve('timeout');
        }, 2000)
      );

      await Promise.race([shutdownPromise, timeoutPromise]);
      console.log('[OTEL] OpenTelemetry SDK shut down successfully');
    } catch (error) {
      console.error('[OTEL] Error shutting down OpenTelemetry SDK', error);
    }
  };

  process.on('SIGTERM', shutdownWithFlush);
  process.on('SIGINT', shutdownWithFlush);
}

/**
 * Initialize OpenTelemetry SDK with production-optimized configuration
 *
 * This function assembles all OTEL components and starts the SDK.
 * It's automatically called at module load time if OTEL is enabled.
 *
 * Configuration includes:
 * - Resource metadata (service name, version, environment, Cloud Run details)
 * - Aggressive span processor (100ms export interval, batch size 1)
 * - Composite propagator (CloudPropagator + W3C)
 * - Selective auto-instrumentation (HTTP, MongoDB, Pino)
 * - Metrics exporter (60s interval)
 * - Graceful shutdown handlers (SIGTERM/SIGINT)
 *
 * @returns NodeSDK instance or null if OTEL is disabled
 */
export function initializeTelemetry(): NodeSDKInstance | null {
  if (!isOtelEnabled()) {
    console.log('[OTEL] OpenTelemetry disabled');
    return null;
  }

  // Load OTEL modules
  if (!loadOTELModules()) {
    console.error(
      '[OTEL] Failed to load OpenTelemetry packages - initialization aborted'
    );
    return null;
  }

  console.log('[OTEL] Initializing OpenTelemetry SDK', {
    serviceName: getServiceName(),
    environment: getEnvironment(),
    version: getServiceVersion(),
    cloudPropagatorAvailable: !!CloudPropagator,
  });

  try {
    const resource = createResource();
    const traceExporter = new OTLPTraceExporter();
    const spanProcessor = createSpanProcessor(traceExporter);
    const sampler = createSampler();

    const metricReader = new PeriodicExportingMetricReader({
      exporter: new OTLPMetricExporter(),
      exportIntervalMillis: 60000, // Export metrics every 60 seconds
    });

    const sdk = new NodeSDK({
      resource,
      spanProcessor,
      sampler,
      metricReader,
      textMapPropagator: createPropagator(),
      instrumentations: createInstrumentations(),
    });

    sdk.start();

    // Log detailed configuration for debugging
    const optionsTracingEnabled = process.env.OTEL_OPTION_REQ_ENABLE === 'true';
    console.log('[OTEL] OpenTelemetry SDK initialized successfully', {
      propagators: CloudPropagator
        ? 'CloudPropagator + W3CTraceContextPropagator'
        : 'W3CTraceContextPropagator only (CloudPropagator not installed)',
      sampler: 'ParentBasedSampler with AlwaysOnSampler root',
      spanProcessor:
        'BatchSpanProcessor (100ms interval, max 1 span/batch - immediate export)',
      exportInterval: '100ms (very aggressive for scale-to-zero)',
      instrumentations:
        'http (root spans - ONLY), mongodb (db operations), pino (logging)',
      fastifyInstrumentation: 'DISABLED (prevents duplicate spans)',
      httpConfig: 'requireParentforIncomingSpans=false (creates root spans)',
      optionsTracing: optionsTracingEnabled ? 'ENABLED' : 'DISABLED (default)',
    });

    setupShutdownHandler(sdk);

    return sdk;
  } catch (error) {
    console.error('[OTEL] Failed to initialize OpenTelemetry SDK', error);
    return null;
  }
}

/**
 * Get the global SDK instance (if initialized)
 */
export function getOtelSDK(): NodeSDKInstance | null {
  return otelSDK;
}

/**
 * Auto-initialize at module load time
 *
 * IMPORTANT: This runs when the module is imported, ensuring OTEL hooks
 * are registered before any other libraries (Fastify, MongoDB, etc.) load.
 */
if (isOtelEnabled()) {
  otelSDK = initializeTelemetry();
}
