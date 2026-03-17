# Telemetry Reference

Complete reference for Noony's OpenTelemetry integration, covering provider configuration, auto-detection, presets, and environment variables.

## Architecture

```
OpenTelemetryMiddleware
  ├── Provider Auto-Detection (from env vars)
  ├── TelemetryProvider interface
  │     ├── OpenTelemetryProvider  (OTLP SDK)
  │     ├── ConsoleProvider        (development logging)
  │     └── NoopProvider           (disabled / test)
  ├── Span Lifecycle (before → after/onError)
  └── Pub/Sub Trace Propagation
```

The middleware creates spans in `before`, records attributes and status in `after`, and captures exceptions in `onError`. Providers are pluggable and auto-detected from environment variables.

## OpenTelemetryMiddleware

### Constructor Options

```typescript
interface OpenTelemetryOptions {
  provider?: TelemetryProvider;
  enabled?: boolean;
  extractAttributes?: (context: Context<unknown, unknown>) => Record<string, unknown>;
  shouldTrace?: (context: Context<unknown, unknown>) => boolean;
  onError?: (error: Error, context: Context<unknown, unknown>) => void;
  failSilently?: boolean;
  propagatePubSubTraces?: boolean;
}
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `provider` | `TelemetryProvider` | Auto-detected | Explicit provider instance |
| `enabled` | `boolean` | `true` (except `NODE_ENV=test`) | Enable/disable telemetry |
| `extractAttributes` | Function | Extracts method, url, request ID, user-agent | Custom attribute extractor |
| `shouldTrace` | Function | Traces all requests | Filter which requests to trace |
| `onError` | Function | Logs to console | Custom telemetry error handler |
| `failSilently` | `boolean` | `true` | Never throw on telemetry errors |
| `propagatePubSubTraces` | `boolean` | `true` | Extract/propagate Pub/Sub trace context |

### Usage

```typescript
import { Handler, OpenTelemetryMiddleware } from '@noony-serverless/core';

// Zero configuration -- auto-detects provider
const handler = new Handler()
  .use(new OpenTelemetryMiddleware())
  .handle(async (context) => { /* ... */ });

// With custom options
const handler = new Handler()
  .use(new OpenTelemetryMiddleware({
    shouldTrace: (ctx) => ctx.req.path !== '/health',
    extractAttributes: (ctx) => ({
      'http.method': ctx.req.method,
      'http.url': ctx.req.url,
      'user.id': ctx.user?.id,
    }),
  }))
  .handle(async (context) => { /* ... */ });

// Factory function form
const handler = new Handler()
  .use(openTelemetry({ shouldTrace: ctx => ctx.req.path !== '/health' }))
  .handle(async (context) => { /* ... */ });
```

### Lifecycle

**before hook**:
1. Auto-initializes provider if not yet initialized (uses `SERVICE_NAME` and `SERVICE_VERSION` env vars)
2. Checks `shouldTrace()` filter
3. If Pub/Sub message detected, extracts W3C trace context from message attributes
4. Creates span via provider
5. Adds custom attributes via `extractAttributes()`
6. Stores span in `context.businessData.set('otel_span', span)`

**after hook**:
1. Retrieves span from `context.businessData`
2. Adds `http.status_code` and `request.duration_ms` attributes
3. Sets `X-Trace-Id` response header (32-char hex trace ID)
4. Sets span status to OK (code 0)
5. Ends span

**onError hook**:
1. Retrieves span from `context.businessData`
2. Records exception on span
3. Sets span status to ERROR (code 1)
4. Ends span
5. Calls custom error handler

### businessData Keys

| Key | Type | Set By |
|-----|------|--------|
| `otel_span` | `GenericSpan` | `before` hook |
| `otel_provider` | `string` | `before` hook |

These keys are reserved. Do not overwrite them in custom middlewares.

## Provider Auto-Detection

When no explicit provider is passed, the middleware auto-detects based on environment variables in this priority order:

| Priority | Condition | Provider |
|----------|-----------|----------|
| 1 | `options.provider` set | Explicit provider |
| 2 | `NEW_RELIC_LICENSE_KEY` + `newrelic` package | New Relic (planned) |
| 3 | `DD_API_KEY` or `DD_SERVICE` + `dd-trace` package | Datadog (planned) |
| 4 | `OTEL_EXPORTER_OTLP_ENDPOINT` set | `OpenTelemetryProvider` |
| 5 | `NODE_ENV=development` (no OTEL endpoint) | `ConsoleProvider` |
| 6 | `NODE_ENV=test` or no config | `NoopProvider` |

If a provider's required npm package is not installed, detection falls through to the next priority.

## Providers

### TelemetryProvider Interface

All providers implement this interface:

```typescript
interface TelemetryProvider {
  readonly name: string;
  validate(): Promise<ValidationResult>;
  initialize(config: TelemetryConfig): Promise<void>;
  createSpan(context: Context<unknown, unknown>): GenericSpan | undefined;
  recordMetric(name: string, value: number, attributes?: Record<string, unknown>): void;
  log(level: string, message: string, attributes?: Record<string, unknown>): void;
  isReady(): boolean;
  shutdown(): Promise<void>;
}
```

### GenericSpan Interface

```typescript
interface GenericSpan {
  setAttributes(attributes: Record<string, unknown>): void;
  recordException(error: Error): void;
  setStatus(status: { code: number; message?: string }): void;
  end(): void;
}
```

### OpenTelemetryProvider

The standard OTLP provider. Uses `@opentelemetry/sdk-node` to export traces.

**Auto-selected when**: `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

**Required packages**:

```bash
npm install @opentelemetry/api @opentelemetry/sdk-node \
  @opentelemetry/exporter-trace-otlp-http @opentelemetry/resources \
  @opentelemetry/semantic-conventions @opentelemetry/core
```

**Optional for GCP**:

```bash
npm install @google-cloud/opentelemetry-cloud-trace-propagator
```

**Initialization**:
- Creates `Resource` with service name, version, and environment
- Configures `OTLPTraceExporter` pointing to the OTLP endpoint
- Sets up composite propagator (W3C + Cloud Trace if on GCP)
- Starts `NodeSDK`
- Obtains tracer and meter instances

**Span creation**: Creates `SERVER` spans with HTTP semantic convention attributes (`http.method`, `http.url`, `http.target`, `request.id`, `http.user_agent`).

**Metrics**: Records histograms via `meter.createHistogram()`.

**Logging**: JSON-structured logs with trace correlation (traceId, spanId, traceFlags).

### ConsoleProvider

Logs all telemetry to stdout for local development.

**Auto-selected when**: `NODE_ENV=development` and no `OTEL_EXPORTER_OTLP_ENDPOINT`.

**No additional packages required.**

Outputs span start/end, attributes, exceptions, status, metrics, and logs to the console with descriptive prefixes.

### NoopProvider

Does nothing. Used as fallback.

**Auto-selected when**: `NODE_ENV=test`, telemetry disabled, or no configuration found.

All methods are no-ops. `createSpan()` returns `undefined`. `isReady()` always returns `true`.

### BaseProvider (Abstract)

Convenience base class for custom providers. Provides default implementations for `validate()`, `initialize()`, `isReady()`, `recordMetric()`, `log()`, and `shutdown()`. Subclasses must implement `createSpan()`.

## TelemetryConfig

Configuration passed to `provider.initialize()`:

```typescript
interface TelemetryConfig {
  serviceName: string;
  serviceVersion?: string;
  environment?: string;
  enabled?: boolean;

  exporters?: {
    traces?: OTLPExporterConfig[];
    metrics?: OTLPExporterConfig[];
    logs?: OTLPExporterConfig[];
  };

  sampling?: {
    ratio?: number;  // 0.0 to 1.0
  };

  propagation?: {
    cloudTrace?: boolean;  // X-Cloud-Trace-Context
    w3c?: boolean;         // traceparent/tracestate
    custom?: string[];
  };

  spanProcessor?: SpanProcessorConfig;
  instrumentation?: InstrumentationConfig;
  metrics?: MetricsConfig;
  autoInitialize?: boolean;
}
```

### SpanProcessorConfig

Configures batch span export behavior. Optimized for serverless (scale-to-zero) environments:

| Field | Default | Description |
|-------|---------|-------------|
| `maxQueueSize` | 100 | Maximum queue size before dropping spans |
| `maxExportBatchSize` | 1 | Spans per export batch (1 = immediate) |
| `scheduledDelayMillis` | 100 | Delay between export attempts |
| `exportTimeoutMillis` | 30000 | Timeout for export operations |
| `enableExportLogging` | false | Log export operations for debugging |

### InstrumentationConfig

Controls which libraries are auto-instrumented:

| Field | Default | Description |
|-------|---------|-------------|
| `http` | `true` | HTTP client/server instrumentation |
| `mongodb` | `true` | MongoDB driver instrumentation |
| `pino` | `true` | Pino logger instrumentation |
| `fastify` | `false` | Fastify instrumentation (disable to prevent duplicate spans with HTTP) |
| `dns` | `false` | DNS resolution instrumentation |
| `net` | `false` | TCP/IPC connection instrumentation |
| `fs` | `false` | Filesystem operation instrumentation |

### HttpInstrumentationConfig

When `instrumentation.http` is an object:

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable HTTP instrumentation |
| `requireParentforIncomingSpans` | `false` | Require parent span for incoming requests |
| `requireParentforOutgoingSpans` | `false` | Require parent span for outgoing requests |
| `ignoreHealthChecks` | `true` | Ignore `/health` endpoint traces |
| `traceOptionsRequests` | `false` | Trace CORS preflight requests |
| `ignoreUrls` | `[]` | Regex patterns for URLs to ignore |

## Presets

Use `TelemetryPresets` for pre-configured settings per platform:

```typescript
import { TelemetryPresets } from '@noony-serverless/core';
```

| Preset | Propagation | Notes |
|--------|-------------|-------|
| `GCP` | Cloud Trace + W3C | Basic GCP setup |
| `CLOUD_RUN` | Cloud Trace + W3C | Aggressive span export (batch=1, delay=100ms), auto-initialize, full instrumentation |
| `NEW_RELIC` | W3C only | For New Relic APM |
| `DATADOG` | W3C only | For Datadog APM |
| `OTLP` | W3C only | Standard OTLP collector |
| `JAEGER_LOCAL` | W3C only | Exports to `localhost:4318` |
| `DEVELOPMENT` | W3C only | Console output |
| `DISABLED` | None | No telemetry |

### Cloud Run Preset Detail

The `CLOUD_RUN` preset is optimized for scale-to-zero environments where containers can be terminated at any time:

```typescript
TelemetryPresets.CLOUD_RUN = {
  propagation: { cloudTrace: true, w3c: true },
  spanProcessor: {
    maxQueueSize: 100,
    maxExportBatchSize: 1,         // Export each span immediately
    scheduledDelayMillis: 100,     // 100ms vs 5s default
    exportTimeoutMillis: 30000,
    enableExportLogging: true,
  },
  instrumentation: {
    http: {
      enabled: true,
      requireParentforIncomingSpans: false,
      ignoreHealthChecks: true,
      traceOptionsRequests: false,
    },
    mongodb: true,
    pino: true,
    fastify: false,  // Prevent duplicate spans
    dns: false,
    net: false,
    fs: false,
  },
  metrics: { enabled: true, exportIntervalMillis: 60000 },
  autoInitialize: true,
};
```

## GCP Cloud Trace Integration

When running on GCP, Noony automatically enables Cloud Trace propagation. This synchronizes trace IDs between the GCP Load Balancer (which adds `X-Cloud-Trace-Context` headers) and your application.

### GCP Detection

The `isRunningOnGCP()` function checks for these environment variables:

| Variable | GCP Service |
|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Any GCP service |
| `GCLOUD_PROJECT` | Legacy GCP variable |
| `GCP_PROJECT` | Custom GCP variable |
| `K_SERVICE` | Cloud Run |
| `FUNCTION_NAME` | Cloud Functions |
| `GAE_APPLICATION` | App Engine |

### Composite Propagator

When on GCP, the `OpenTelemetryProvider` creates a `CompositePropagator` that supports both:

1. **CloudPropagator** -- Reads/writes `X-Cloud-Trace-Context` header (GCP format)
2. **W3CTraceContextPropagator** -- Reads/writes `traceparent`/`tracestate` headers (standard format)

This ensures trace IDs from the GCP Load Balancer are preserved through your application. Install the Cloud Trace propagator package:

```bash
npm install @google-cloud/opentelemetry-cloud-trace-propagator
```

If the package is not installed, the provider falls back to W3C-only propagation with a console warning.

## Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | `http://localhost:4318/v1/traces` |
| `OTEL_SERVICE_NAME` | Service name for traces | `order-service` |
| `OTEL_SERVICE_VERSION` | Service version | `2.1.0` |
| `SERVICE_NAME` | Fallback service name | `order-service` |
| `SERVICE_VERSION` | Fallback service version | `1.0.0` |
| `NODE_ENV` | Environment detection | `production`, `development`, `test` |
| `NEW_RELIC_LICENSE_KEY` | New Relic detection | (license key) |
| `DD_API_KEY` | Datadog detection | (API key) |
| `DD_SERVICE` | Datadog service name | `my-service` |
| `GOOGLE_CLOUD_PROJECT` | GCP detection | `my-project-id` |
| `K_SERVICE` | Cloud Run detection | `my-service` |
| `FUNCTION_NAME` | Cloud Functions detection | `myFunction` |

## Shutdown

Always shut down the telemetry provider during application termination to flush pending spans:

```typescript
const otelMiddleware = new OpenTelemetryMiddleware();

process.on('SIGTERM', async () => {
  await otelMiddleware.shutdown();
  process.exit(0);
});
```

The `shutdown()` method calls the provider's shutdown, which flushes any buffered trace data to the collector.

## Creating a Custom Provider

Extend `BaseProvider` or implement `TelemetryProvider` directly:

```typescript
import { BaseProvider } from '@noony-serverless/core';
import { Context, GenericSpan, TelemetryConfig, ValidationResult } from '@noony-serverless/core';

export class MyCustomProvider extends BaseProvider {
  readonly name = 'my-custom';

  async validate(): Promise<ValidationResult> {
    if (!process.env.MY_CUSTOM_API_KEY) {
      return { valid: false, reason: 'MY_CUSTOM_API_KEY not set' };
    }
    return { valid: true };
  }

  async initialize(config: TelemetryConfig): Promise<void> {
    await super.initialize(config);
    // Set up your custom SDK here
  }

  createSpan(context: Context<unknown, unknown>): GenericSpan | undefined {
    if (!this.enabled) return undefined;

    // Create and return a GenericSpan
    return {
      setAttributes: (attrs) => { /* ... */ },
      recordException: (error) => { /* ... */ },
      setStatus: (status) => { /* ... */ },
      end: () => { /* ... */ },
    };
  }
}

// Use it
const handler = new Handler()
  .use(new OpenTelemetryMiddleware({
    provider: new MyCustomProvider(),
  }))
  .handle(async (context) => { /* ... */ });
```

## Related

- [Performance Tuning Guide](../guides/performance-tuning.md) -- Optimizing telemetry overhead
- [OpenTelemetry Middleware Reference](../reference/middlewares/opentelemetry.md) -- Middleware-specific API details
- [Pub/Sub Workflows Guide](../guides/pubsub-workflows.md) -- Trace propagation through Pub/Sub
