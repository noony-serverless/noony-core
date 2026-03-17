# OpenTelemetry Middleware

Adds distributed tracing spans to requests with automatic provider detection.

> **Related:** [Middleware Index](./INDEX.md) | [API Reference](../api.md)

## Purpose

The OpenTelemetry Middleware creates trace spans around each request, records attributes and exceptions, and auto-detects the appropriate telemetry provider from environment variables. It supports Pub/Sub trace context propagation, custom attribute extraction, and graceful degradation when no provider is configured.

## When to Use

- Adding distributed tracing to HTTP or Pub/Sub handlers
- Correlating requests across microservices
- Monitoring request latency and error rates in production

## Import

```typescript
import {
  OpenTelemetryMiddleware,
  openTelemetry,
  OpenTelemetryOptions,
} from '@noony-serverless/core';
```

## Constructor

### Class: `OpenTelemetryMiddleware<TBody, TUser>`

```typescript
new OpenTelemetryMiddleware(options?: OpenTelemetryOptions)
```

### Factory: `openTelemetry()`

```typescript
openTelemetry<TBody, TUser>(options?: OpenTelemetryOptions): OpenTelemetryMiddleware<TBody, TUser>
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `provider` | `TelemetryProvider` | Auto-detected | Explicit telemetry provider instance |
| `enabled` | `boolean` | `true` (false if `NODE_ENV=test`) | Enable or disable telemetry |
| `extractAttributes` | `(context) => Record<string, unknown>` | Extracts method, url, request ID, user-agent | Custom attribute extractor |
| `shouldTrace` | `(context) => boolean` | Traces all requests | Filter which requests to trace |
| `onError` | `(error, context) => void` | Logs to console | Custom telemetry error handler |
| `failSilently` | `boolean` | `true` | Never throw on telemetry errors |
| `propagatePubSubTraces` | `boolean` | `true` | Extract W3C Trace Context from Pub/Sub message attributes |

## Provider Auto-Detection Priority

| Priority | Condition | Provider |
|---|---|---|
| 1 | Explicit `options.provider` | Provided instance |
| 2 | `NEW_RELIC_LICENSE_KEY` env var | New Relic (planned) |
| 3 | `DD_API_KEY` or `DD_SERVICE` env var | Datadog (planned) |
| 4 | `OTEL_EXPORTER_OTLP_ENDPOINT` env var | Standard OpenTelemetry |
| 5 | `NODE_ENV=development` (no OTEL endpoint) | Console |
| 6 | No configuration / `NODE_ENV=test` | Noop |

## Usage

### Basic (zero configuration)

```typescript
const handler = new Handler()
  .use(new OpenTelemetryMiddleware())
  .handle(async (context) => {
    return { message: 'Traced request' };
  });
```

### With filtering

```typescript
const handler = new Handler()
  .use(openTelemetry({
    shouldTrace: (context) => context.req.path !== '/health',
    extractAttributes: (context) => ({
      'http.method': context.req.method,
      'app.tenant_id': context.req.headers?.['x-tenant-id'],
    }),
  }))
  .handle(async (context) => {
    return { message: 'Filtered tracing' };
  });
```

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | Auto-initializes provider if needed, creates span, extracts Pub/Sub trace context, sets custom attributes, stores span in `context.businessData` |
| `after` | Adds `http.status_code` and `request.duration_ms` attributes, sets `X-Trace-Id` response header, ends span with OK status |
| `onError` | Records exception on span, sets ERROR status, ends span, calls custom error handler |

## Methods

| Method | Description |
|---|---|
| `initialize(config: TelemetryConfig)` | Explicitly initialize the provider (auto-called on first request if not called) |
| `getProvider()` | Returns current `TelemetryProvider` instance |
| `shutdown()` | Gracefully shuts down the provider -- call during application shutdown |

## See Also

- [API Reference -- OpenTelemetry](../api.md)
- [Security Audit Middleware](./security-audit.md)
