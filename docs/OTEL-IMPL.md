I'll explain each OpenTelemetry configuration with actual code snippets from your project.

## **1. Core OTEL Initialization** - telemetry.config.ts

### **Enable/Disable Logic**
```typescript
export function isOtelEnabled(): boolean {
  // Enable OTEL if:
  // 1. Explicitly enabled via env var
  // 2. Running in production
  // 3. Running in Cloud Run (K_SERVICE is set by Cloud Run)
  const explicitlyEnabled = process.env.OTEL_ENABLED === 'true';
  const isProduction = process.env.NODE_ENV === 'production';
  const isCloudRun = !!process.env.K_SERVICE;

  return explicitlyEnabled || isProduction || isCloudRun;
}
```
**Explanation**: OTEL automatically activates in production or Cloud Run environments, but can be manually enabled with `OTEL_ENABLED=true`.

---

### **Resource Creation (Service Metadata)**
```typescript
function createResource(): Resource {
  const attributes: Record<string, string> = {
    'service.name': getServiceName(),
    'service.version': packageJson.version,
    'deployment.environment': getEnvironment(),
  };

  // Add Cloud Run specific attributes if available
  if (process.env.K_SERVICE) {
    attributes['cloud.platform'] = 'gcp_cloud_run';
    attributes['cloud.provider'] = 'gcp';
    attributes['service.instance.id'] = process.env.K_REVISION || 'unknown';
    attributes['cloud.region'] = process.env.CLOUD_RUN_REGION || 'unknown';
  }

  return resourceFromAttributes(attributes);
}
```
**Explanation**: Creates resource metadata identifying your service in Cloud Trace. When running in Cloud Run, it automatically adds cloud-specific attributes from environment variables.

---

### **Composite Propagator (Dual Format Support)**
```typescript
function createPropagator() {
  return new CompositePropagator({
    propagators: [
      new CloudPropagator(), // Read/write X-Cloud-Trace-Context (GCP format) - FIRST
      new W3CTraceContextPropagator(), // Read/write traceparent (W3C standard) - SECOND
    ],
  });
}
```
**Explanation**: Supports both GCP's proprietary `X-Cloud-Trace-Context` header (from browser) and W3C's standard `traceparent` header. CloudPropagator is first to prioritize GCP format for browser-to-backend correlation.

---

### **Aggressive Span Processor (Scale-to-Zero Optimized)**
```typescript
function createSpanProcessor(traceExporter: TraceExporter): BatchSpanProcessor {
  // Enhanced logging wrapper for export attempts with detailed span info
  const originalExport = traceExporter.export.bind(traceExporter);
  traceExporter.export = async (spans, resultCallback) => {
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

    return originalExport(spans, (result) => {
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
```
**Explanation**: Cloud Run can terminate containers quickly (scale-to-zero). This configuration exports spans immediately (batch size 1) every 100ms to prevent data loss. It also wraps the exporter to log all export attempts for debugging.

---

### **HTTP Instrumentation (Root Span Creator)**
```typescript
function createHttpInstrumentationConfig() {
  const enableOptionsTracing = process.env.OTEL_OPTION_REQ_ENABLE === 'true';

  return {
    enabled: true,
    // Create spans for all incoming requests (including those without parent)
    // This ensures we have a root span for every request
    requireParentforIncomingSpans: false,
    requireParentforOutgoingSpans: false,
    // Ignore internal/health check and OPTIONS requests to reduce noise
    ignoreIncomingRequestHook: (request: unknown) => {
      const req = request as { url?: string; method?: string };
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
```
**Explanation**: Creates root spans for all HTTP requests. Filters out health checks and OPTIONS (CORS preflight) requests by default to reduce noise. Set `requireParentforIncomingSpans: false` to ensure every request gets a span even without a parent trace.

---

### **Instrumentation Array (Selective Auto-Instrumentation)**
```typescript
function createInstrumentations() {
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
```
**Explanation**: 
- ✅ **HTTP**: Enabled - creates root spans for requests
- ✅ **MongoDB**: Enabled - traces database queries
- ✅ **Pino**: Enabled - correlates logs with traces
- ❌ **Fastify**: **DISABLED** - prevents duplicate spans (HTTP instrumentation handles this)
- ❌ **DNS/Net/FS**: Disabled - reduces noise

---

### **Graceful Shutdown Handler**
```typescript
function setupShutdownHandler(sdk: NodeSDK): void {
  const shutdownWithFlush = async () => {
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
```
**Explanation**: When Cloud Run sends SIGTERM (shutdown signal), this handler forces all pending spans to export before the process terminates. Has a 2-second timeout as a safety measure.

---

### **SDK Initialization**
```typescript
export function initializeTelemetry(): NodeSDK | null {
  if (!isOtelEnabled()) {
    console.log('[OTEL] OpenTelemetry disabled');
    return null;
  }

  console.log('[OTEL] Initializing OpenTelemetry SDK', {
    serviceName: getServiceName(),
    environment: getEnvironment(),
    version: packageJson.version,
  });

  try {
    const resource = createResource();
    const traceExporter = new TraceExporter();
    const spanProcessor = createSpanProcessor(traceExporter);
    const sampler = createSampler();

    const metricReader = new PeriodicExportingMetricReader({
      exporter: new MetricExporter(),
      exportIntervalMillis: 60000,
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

    // Using standard @opentelemetry/instrumentation-fastify (not @fastify/otel)
    const optionsTracingEnabled = process.env.OTEL_OPTION_REQ_ENABLE === 'true';
    console.log('[OTEL] OpenTelemetry SDK initialized successfully', {
      propagators: 'CloudPropagator + W3CTraceContextPropagator',
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

// Auto-initialize at module load time
if (isOtelEnabled()) {
  otelSDK = initializeTelemetry();
}
```
**Explanation**: Assembles all components and starts the SDK. Auto-initializes when the module is imported. Logs detailed configuration for debugging.

---

## **2. Entry Point Configuration**

### **Main Server** - server.ts
```typescript
// IMPORTANT: Initialize OpenTelemetry BEFORE any other imports
// This ensures all instrumentation hooks are registered before libraries are loaded
import '@config/telemetry.config';

import 'reflect-metadata';
import { Container } from 'typedi';
import { FastifyAdapter } from '@adapters/fastify.adapter';
// ... other imports
```
**Explanation**: **CRITICAL** - The telemetry config MUST be imported first. This ensures OTEL's monkey-patching happens before Fastify, MongoDB, etc. are loaded. If you import Fastify first, instrumentation won't work.

---

### **Async Processor** - async-processor.ts
```typescript
/**
 * Cloud Run entry point for async message processing
 * Listens to Pub/Sub messages and processes them using the async processing service
 */

// IMPORTANT: Initialize OpenTelemetry BEFORE any other imports
import '@config/telemetry.config';

import 'reflect-metadata';
import { Container } from 'typedi';
import { MongoClient, Db } from 'mongodb';
// ... other imports
```
**Explanation**: Same critical import order for the async job processor. This ensures Pub/Sub message processing is also traced.

---

## **3. Fastify Adapter** - fastify.adapter.ts

### **OTEL Comment (Important!)**
```typescript
private async setupMiddleware(): Promise<void> {
  // OpenTelemetry instrumentation is handled automatically by @fastify/otel
  // via auto-instrumentation in telemetry.config.ts
  // DO NOT register as plugin - it causes double instrumentation and 9s+ latency!

  // CORS
  await this.app.register(cors, this.config.cors);
  // ...
}
```
**Explanation**: Documents that `@fastify/otel` should NOT be registered as a plugin because HTTP instrumentation already handles it. Registering both causes duplicate spans and massive latency.

---

### **Trace Context Extraction**
```typescript
import { trace } from '@opentelemetry/api';
import { parseCloudTraceContext } from '@utils/trace-context.helper';

// Inside setupLoggingHooks():
this.app.addHook('onRequest', async (request: FastifyRequest) => {
  const traceContext = parseCloudTraceContext(
    request.headers['x-cloud-trace-context'] as string | undefined
  );

  // NOTE: OpenTelemetry's CloudPropagator + @fastify/otel will automatically
  // extract trace context from X-Cloud-Trace-Context header and propagate it
  // through the request lifecycle. This code is for logging/debugging only.

  if (traceContext) {
    // Get the active OTEL span to verify propagation is working
    const activeSpan = trace.getActiveSpan();
    const otelTraceId = activeSpan?.spanContext().traceId;

    this.logger.debug('Extracted trace context from GCP header', {
      headerTraceId: traceContext.traceId,
      headerSpanId: traceContext.spanId,
      otelTraceId: otelTraceId || 'none',
      match: traceContext.traceId === otelTraceId,
    });
  }

  // The @fastify/otel instrumentation will create spans with the same trace ID
  // as the incoming X-Cloud-Trace-Context header automatically
});
```
**Explanation**: Demonstrates how to manually parse GCP's trace header for validation. The CloudPropagator automatically extracts this, but this code validates that propagation is working correctly.

---

### **Request Logging with Trace ID**
```typescript
this.app.addHook('onResponse', async (request, reply) => {
  const duration = Date.now() - (request.requestTime ?? Date.now());
  const traceId =
    traceContext?.traceId || trace.getActiveSpan()?.spanContext().traceId;

  this.logger.info(
    `${request.method} ${request.url} - ${reply.statusCode} (${duration}ms)`,
    {
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      duration: `${duration}ms`,
      traceId,
      requestId: (request as any).requestId,
    }
  );
});
```
**Explanation**: Logs include the trace ID so you can correlate logs with traces in Cloud Trace UI.

---

## **4. Distributed Tracing via Pub/Sub** - pubsub.service.ts

### **Trace Context Injection**
```typescript
import { trace, context, propagation } from '@opentelemetry/api';

async publishMessage(message: PubSubMessage): Promise<string> {
  // ... setup code ...

  // Inject OpenTelemetry trace context for distributed tracing
  const currentContext = context.active();
  propagation.inject(currentContext, attributes);

  // Extract trace ID for logging
  const activeSpan = trace.getActiveSpan();
  const traceId = activeSpan?.spanContext().traceId;

  const messageId = await this.topic.publishMessage({
    data,
    attributes,
    orderingKey: `${message.tenantId}-${message.type}`,
  });

  this.logger.info('Published Pub/Sub message', {
    messageId,
    jobId: message.jobId,
    type: message.type,
    tenantId: message.tenantId,
    traceId, // Include trace ID for correlation
  });

  return messageId;
}
```
**Explanation**: `propagation.inject()` embeds the current trace context into Pub/Sub message attributes. When the async processor receives the message, it can extract this context and continue the same distributed trace.

---

### **Trace Context Extraction** - async-processor.ts
```typescript
import { context, propagation, trace } from '@opentelemetry/api';

private async processMessage(message: Message): Promise<void> {
  // Extract trace context from Pub/Sub message
  const extractedContext = propagation.extract(
    context.active(),
    message.attributes
  );

  // Continue the trace from the publisher
  return context.with(extractedContext, async () => {
    const activeSpan = trace.getSpan(extractedContext);
    const traceId = activeSpan?.spanContext().traceId;

    this.logger.info('Processing Pub/Sub message', {
      messageId: message.id,
      traceId,
      attributes: message.attributes,
    });

    // Process the job within the extracted trace context
    await this.processingService.processJob(jobId, type, payload);
  });
}
```
**Explanation**: `propagation.extract()` retrieves the trace context from message attributes. `context.with()` makes this the active context so all operations inside continue the same trace.

---

## **5. Logger Integration**

### **OTEL Mixin** - otel.helper.ts
```typescript
import { trace } from '@opentelemetry/api';

export const createOTELMixin = () => {
  const span = trace.getActiveSpan();
  if (!span) return {};

  const spanContext = span.spanContext();
  return {
    traceId: spanContext.traceId,
    spanId: spanContext.spanId,
    traceFlags: spanContext.traceFlags,
  };
};
```
**Explanation**: Pino mixin that automatically adds trace/span IDs to every log entry. Used when `OTEL_ENABLED=true`.

---

### **Logger Config** - logger.ts
```typescript
const createPinoConfig = (config: AdvancedLoggerConfig): pino.LoggerOptions => {
  return {
    level: config.level,
    mixin: config.otel?.enabled ? createOTELMixin : undefined,
    // ... other config
  };
};

export const createLoggerConfig = (moduleName?: string): AdvancedLoggerConfig => {
  const config: AdvancedLoggerConfig = {
    // ...
    enableOTEL: process.env.OTEL_ENABLED === 'true' || isProduction,
    otel: {
      enabled: process.env.OTEL_ENABLED === 'true' || isProduction,
      serviceName: process.env.OTEL_SERVICE_NAME || 'convivencialdia-api',
      endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
      headers: process.env.OTEL_EXPORTER_OTLP_HEADERS
        ? JSON.parse(process.env.OTEL_EXPORTER_OTLP_HEADERS)
        : undefined,
    },
  };
  return config;
};
```
**Explanation**: Configures logger to include OTEL mixin when enabled. Every log will have `traceId` and `spanId` fields for correlation in Cloud Logging.

---

### **Logger Service Methods** - logger.service.ts
```typescript
import { trace, Span, Context } from '@opentelemetry/api';

export class Logger implements IAdvancedLogger {
  // Manual span attachment
  withSpan(span: Span): Logger {
    const spanContext = span.spanContext();
    return this.withContext({
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      traceFlags: spanContext.traceFlags,
    });
  }

  // Attach current OTEL context
  withOTEL(context: Context): Logger {
    const span = trace.getSpan(context);
    return span ? this.withSpan(span) : this;
  }

  // Extract current OTEL context
  private getOTELContext(): LogContext {
    const span = trace.getActiveSpan();
    if (!span) return {};

    const spanContext = span.spanContext();
    return {
      traceId: spanContext.traceId,
      spanId: spanContext.spanId,
      traceFlags: spanContext.traceFlags,
    };
  }
}
```
**Explanation**: Provides methods to manually correlate logs with traces. `withOTEL()` creates a child logger with trace context embedded.

---

## **6. Telemetry Middleware (Optional)** - telemetry.middleware.ts

```typescript
import { trace, Span, SpanStatusCode } from '@opentelemetry/api';
import type { AuthenticatedUser } from '@auth';

export class TelemetryMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Get the active span created by @fastify/otel
    const activeSpan = trace.getActiveSpan();

    if (activeSpan) {
      try {
        // Add user context attributes if authenticated
        const user = context.user as AuthenticatedUser | undefined;
        if (user) {
          activeSpan.setAttributes({
            'user.id': user.id,
            'user.email': user.email || 'unknown',
            'user.role': user.role || 'unknown',
            'user.tenant_id': user.tenantId || 'unknown',
            'user.organization_id': user.currentOrganization || 'unknown',
          });
        }

        // Store span reference for later use
        (context as unknown as ContextWithSpan).otelSpan = activeSpan;
      } catch (error) {
        console.error('[Telemetry] Failed to enrich span:', error);
      }
    }
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    const span = (context as unknown as ContextWithSpan).otelSpan;
    if (span) {
      try {
        // Add response status code
        const statusCode = context.res.statusCode || 200;
        span.setAttribute('http.status_code', statusCode);

        // Set span status based on HTTP status code
        if (statusCode >= 400) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: `HTTP ${statusCode}`,
          });
        } else {
          span.setStatus({ code: SpanStatusCode.OK });
        }
      } catch (error) {
        console.error('[Telemetry] Failed to update span after response:', error);
      }
    }
  }

  async onError(error: Error, context: Context<TBody, TUser>): Promise<void> {
    const span = (context as unknown as ContextWithSpan).otelSpan;
    if (span) {
      try {
        // Record exception in span
        span.recordException(error);
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error.message || 'Unknown error',
        });

        // Add error attributes
        span.setAttributes({
          'error.type': error.name,
          'error.message': error.message,
          'error.stack': error.stack || 'unknown',
        });
      } catch (err) {
        console.error('[Telemetry] Failed to record error in span:', err);
      }
    }
  }
}
```
**Explanation**: Noony middleware that enriches spans with:
- **User context** (ID, email, role, tenant)
- **HTTP status codes**
- **Error details** with stack traces

This is optional - basic HTTP instrumentation works without it, but this adds business context to your traces.

---

## **7. Environment Configuration**

### **Example Configuration** - .env.example
```bash
# ============================================================================
# OpenTelemetry Configuration (Automatic Tracing & Metrics)
# ============================================================================
# OTEL auto-instruments Fastify, MongoDB, HTTP for traces sent to Cloud Trace
# Metrics are sent to Cloud Monitoring for observability dashboards
#
# Local Development (OTEL_ENABLED=false):
#   ✅ No overhead, faster startup, simpler debugging
#   ✅ Use when developing features locally
#
# Production/Cloud Run (OTEL_ENABLED=true):
#   ✅ Automatic distributed tracing across all endpoints
#   ✅ Performance metrics and SLOs in Cloud Monitoring
#   ✅ Correlated logs with traceId/spanId in Cloud Logging
#   ⚠️  Requires IAM roles: roles/cloudtrace.agent, roles/monitoring.metricWriter
#
# Cloud Run automatically sets K_SERVICE, no need to configure credentials
OTEL_ENABLED=false
OTEL_SERVICE_NAME=convivencialdia-api
# OTEL_LOG_LEVEL=info  # Optional: debug, info, warn, error
```

---

## **Summary: How It All Works Together**

1. **Startup**: `import '@config/telemetry.config'` initializes OTEL SDK first
2. **Incoming Request**: HTTP instrumentation creates root span
3. **CloudPropagator**: Extracts trace ID from browser's `X-Cloud-Trace-Context` header
4. **HTTP Handler**: Fastify processes request within trace context
5. **Logger**: Automatically includes `traceId`/`spanId` in all logs
6. **Pub/Sub**: `propagation.inject()` embeds trace context into messages
7. **Async Worker**: `propagation.extract()` continues the distributed trace
8. **Export**: Spans sent to Cloud Trace every 100ms
9. **Shutdown**: SIGTERM triggers force flush of pending spans

This creates end-to-end distributed tracing from browser → API → Pub/Sub → async worker, with all logs correlated to traces.