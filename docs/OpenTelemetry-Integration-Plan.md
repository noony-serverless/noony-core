# OpenTelemetry Integration Plan for Noony Framework

> **⚠️ HISTORICAL DOCUMENT - DESIGN PHASE ONLY**
> 
> This document contains the **original design plan** from January 2025, before implementation.
> Many features described here were implemented differently or not implemented at all.
> 
> **❌ DO NOT use this as implementation guide**
> **✅ For current implementation, see: [OTEL_NOONY.md](../OTEL_NOONY.md)**
> 
> **Key differences from actual implementation:**
> - ❌ `@fastify/otel` is NOT used (causes conflicts)
> - ❌ `NewRelicProvider` and `DatadogProvider` not implemented
> - ✅ `OpenTelemetryMiddleware` works differently than planned
> - ✅ Pub/Sub tracing uses different utilities than planned

## Overview

This document outlines the strategy for integrating OpenTelemetry (OTEL) SDK 2.0 into the Noony serverless middleware framework to extend observability to platforms like New Relic, Datadog, Jaeger, and other OTEL-compatible systems.

**Updated:** January 2025 - Aligned with Noony v0.3.4 and OpenTelemetry SDK 2.0

## Current Observability Infrastructure

The Noony framework (v0.3.4) already has a solid observability foundation:

### Existing Components

1. **Performance Monitor** (`src/core/performanceMonitor.ts`)
   - Built-in timing with `process.hrtime.bigint()`
   - Metrics aggregation (count, avg, min, max, P95)
   - Memory-efficient with configurable limits (1000 metrics per operation)
   - Decorator support (`@timed`, `@timedSync`)
   - Environment-based enable/disable (development or PERFORMANCE_MONITORING=true)
   - Health summary for monitoring endpoints
   - Currently limited to local in-memory storage

2. **Structured Logger** (`src/core/logger.ts`)
   - Performance-optimized with object pooling (max 50 log objects)
   - Timestamp caching (1-second cache to reduce Date creation)
   - Dynamic log method references for testing compatibility
   - Environment-based debug mode (development or DEBUG=true or LOG_LEVEL=debug)
   - Performance logging integration with duration tracking
   - Supports info, error, warn, debug levels

3. **Security Audit Middleware** (`src/middlewares/securityAuditMiddleware.ts`)
   - Comprehensive security event tracking (8 event types)
   - Anomaly detection with time-based windows (1 hour window, 100 events per client max)
   - Suspicious pattern detection (SQL injection, XSS, path traversal, command injection)
   - Client behavior analysis with IP tracking
   - Custom security event handlers via callbacks
   - Type-safe with generics `SecurityAuditMiddleware<TBody, TUser>`

4. **Middleware Architecture** (`src/core/handler.ts`)
   - BaseMiddleware interface with `before`/`after`/`onError` hooks
   - Type-safe generics: `BaseMiddleware<TBody, TUser>` for type chain preservation
   - Pre-computed middleware arrays for performance optimization
   - Error propagation in reverse middleware order
   - Framework-agnostic design: `execute()` for GCP Functions, `executeGeneric()` for Fastify/Express
   - Container pooling for dependency injection (max 15 containers)

5. **Rich Context System** (`src/core/core.ts`)
   - Request tracking with `requestId` (format: `req_{timestamp}_{random}`) and `startTime`
   - Modern types: `NoonyRequest<TBody>` and `NoonyResponse` (framework-agnostic)
   - User context integration: `Context<TBody, TUser>` with dual generics
   - Business data Map for shared state across middlewares
   - Timeout signal support with AbortSignal
   - Framework adapters: `adaptGCPRequest()` and `adaptGCPResponse()`
   - Container instance from containerPool (not Container.of())

6. **Container Pool** (`src/core/containerPool.ts`)
   - TypeDI container pooling for performance (max 15 containers)
   - Warm-up capability (pre-creates 3 containers)
   - Automatic container acquisition and release
   - Reset mechanism to prevent cross-request contamination
   - Pool statistics for monitoring

## Integration Strategy

### Key Integration Points

1. **Middleware Pipeline**: Perfect for distributed tracing spans with `before`/`after`/`onError` hooks
2. **Context Object**: Already contains essential telemetry data (`requestId`, `startTime`, `user`, `businessData`)
3. **Performance Monitor**: Can export metrics via OTEL while maintaining existing API
4. **Security Events**: Can be exported as OTEL events and metrics
5. **Logger**: Can be enhanced with trace correlation while preserving object pooling
6. **Container Pool**: Store telemetry providers as singletons, not per-request

### Core Design Principles

1. **Fail-Safe**: Telemetry errors must never break the application
2. **Graceful Degradation**: Falls back to NoopProvider if validation fails
3. **Zero Configuration**: Auto-detects provider from environment variables
4. **Extensible**: Plugin-based system for custom providers (New Relic, Datadog, etc.)
5. **Type-Safe**: Preserves `BaseMiddleware<TBody, TUser>` type chain
6. **Performance**: Singleton providers, no per-request initialization

## Implementation Plan

### Phase 1: Core OTEL Infrastructure

#### 1.1 TelemetryProvider Interface (Extensibility Point)

Create `src/core/telemetry/provider.ts`:

```typescript
export interface TelemetryProvider {
  readonly name: string;

  /** Validate configuration before initialization */
  validate(): Promise<{ valid: boolean; reason?: string }>;

  /** Initialize with configuration */
  initialize(config: TelemetryConfig): Promise<void>;

  /** Create span for current request */
  createSpan(context: Context<unknown, unknown>): Span | undefined;

  /** Record metric */
  recordMetric(name: string, value: number, attributes?: Record<string, unknown>): void;

  /** Log with trace correlation */
  log(level: string, message: string, attributes?: Record<string, unknown>): void;

  /** Check if provider is ready */
  isReady(): boolean;

  /** Shutdown provider */
  shutdown(): Promise<void>;
}
```

#### 1.2 Built-in Providers

1. **NoopProvider**: Disabled/fallback provider (does nothing, always valid)
2. **ConsoleProvider**: Local development provider (logs to console for debugging)
3. **OpenTelemetryProvider**: Standard OTEL SDK 2.0 provider with OTLP exporters
4. **NewRelicProvider**: Official New Relic agent integration (requires `newrelic` package)
5. **DatadogProvider**: Official Datadog tracer integration (requires `dd-trace` package)

#### 1.3 Dependencies to Add (SDK 2.0 - March 2025)

```json
{
  "dependencies": {
    "@opentelemetry/api": "^1.9.0",
    "@opentelemetry/sdk-node": "^2.0.0",
    "@opentelemetry/resources": "^2.0.0",
    "@opentelemetry/semantic-conventions": "^1.28.0",
    "@opentelemetry/instrumentation-http": "^0.200.0",
    "@opentelemetry/exporter-trace-otlp-http": "^0.205.0",
    "@opentelemetry/exporter-metrics-otlp-http": "^0.205.0",
    "@opentelemetry/exporter-logs-otlp-http": "^0.205.0",
    "@opentelemetry/auto-instrumentations-node": "^0.200.0",
    "@fastify/otel": "^1.0.0"
  },
  "peerDependencies": {
    "newrelic": "^12.0.0",
    "dd-trace": "^5.0.0"
  }
}
```

**Breaking Changes in SDK 2.0:**

- Minimum Node.js: ^18.19.0 || >=20.6.0 (drops 14/16 support)
- Minimum TypeScript: 5.0.4
- Compilation target: ES2022 (from ES2017)
- Package versioning: Stable >=2.0.0, Unstable >=0.200.0
- Deprecated `@opentelemetry/instrumentation-fastify` → Use `@fastify/otel`

### Phase 2: OpenTelemetry Middleware (with Auto-Detection)

#### 2.1 Smart Middleware with Provider Validation

Create `src/middlewares/openTelemetryMiddleware.ts`:

```typescript
export interface OpenTelemetryOptions {
  provider?: TelemetryProvider;  // Custom provider or auto-detect
  enabled?: boolean;              // Default: NODE_ENV !== 'test'
  extractAttributes?: (context: Context<unknown, unknown>) => Record<string, unknown>;
  shouldTrace?: (context: Context<unknown, unknown>) => boolean;
  onError?: (error: Error, context: Context<unknown, unknown>) => void;
  failSilently?: boolean;         // Default: true (never break app)
}

export class OpenTelemetryMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  // Auto-detects provider from environment:
  // 1. Check NEW_RELIC_LICENSE_KEY → NewRelicProvider
  // 2. Check DD_API_KEY/DD_SERVICE → DatadogProvider
  // 3. Check OTEL_EXPORTER_OTLP_ENDPOINT → OpenTelemetryProvider
  // 4. NODE_ENV=development → ConsoleProvider
  // 5. Fallback → NoopProvider

  async before(context: Context<TBody, TUser>): Promise<void> {
    // Validate provider before creating span
    // Store span in context.businessData
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    // End span with status and duration
  }

  async onError(error: Error, context: Context<TBody, TUser>): Promise<void> {
    // Record exception, never throw
  }
}
```

#### 2.2 Provider Auto-Detection Logic

**Priority Order:**

1. **Explicit Provider**: Use `options.provider` if provided
2. **New Relic**: If `NEW_RELIC_LICENSE_KEY` env var set and `newrelic` package installed
3. **Datadog**: If `DD_API_KEY` or `DD_SERVICE` env var set and `dd-trace` package installed
4. **Standard OTEL**: If `OTEL_EXPORTER_OTLP_ENDPOINT` env var set
5. **Console** (Dev): If `NODE_ENV=development` and no OTEL endpoint
6. **Noop** (Disabled): If `NODE_ENV=test` or no configuration found

#### 2.3 Graceful Degradation

Each provider implements `validate()` which checks:

- Required environment variables
- Required npm packages installed
- Configuration validity

If validation fails, middleware falls back to `NoopProvider` and logs warning.

### Phase 3: Provider Implementations

#### 3.1 NoopProvider (Fallback/Disabled)

```typescript
// src/core/telemetry/providers/noop-provider.ts
export class NoopProvider implements TelemetryProvider {
  readonly name = 'noop';

  async validate(): Promise<{ valid: boolean }> {
    return { valid: true };
  }

  async initialize(_config: TelemetryConfig): Promise<void> {}
  createSpan(_context: Context<unknown, unknown>): undefined { return undefined; }
  recordMetric(_name: string, _value: number, _attributes?: Record<string, unknown>): void {}
  log(_level: string, _message: string, _attributes?: Record<string, unknown>): void {}
  isReady(): boolean { return true; }
  async shutdown(): Promise<void> {}
}
```

#### 3.2 ConsoleProvider (Local Testing)

```typescript
// src/core/telemetry/providers/console-provider.ts
export class ConsoleProvider implements TelemetryProvider {
  readonly name = 'console';
  private enabled = false;

  async validate(): Promise<{ valid: boolean }> {
    return { valid: true }; // Always valid for local testing
  }

  async initialize(config: TelemetryConfig): Promise<void> {
    this.enabled = config.enabled !== false;
    if (this.enabled) {
      console.log('[Telemetry] Console provider initialized for:', config.serviceName);
    }
  }

  createSpan(context: Context<unknown, unknown>): any {
    if (!this.enabled) return undefined;

    const spanData = {
      startTime: Date.now(),
      method: context.req.method,
      path: context.req.path || context.req.url,
      requestId: context.requestId
    };

    console.log('[Telemetry] Span started:', spanData);

    return {
      setAttributes: (attrs: Record<string, unknown>) => {
        console.log('[Telemetry] Span attributes:', attrs);
      },
      recordException: (error: Error) => {
        console.error('[Telemetry] Exception:', error.message);
      },
      setStatus: (status: { code: number; message?: string }) => {
        console.log('[Telemetry] Span status:', status);
      },
      end: () => {
        console.log('[Telemetry] Span ended:', {
          ...spanData,
          duration: Date.now() - spanData.startTime
        });
      }
    };
  }

  recordMetric(name: string, value: number, attributes?: Record<string, unknown>): void {
    if (this.enabled) {
      console.log('[Telemetry] Metric:', { name, value, attributes });
    }
  }

  log(level: string, message: string, attributes?: Record<string, unknown>): void {
    if (this.enabled) {
      console.log(`[Telemetry] Log [${level}]:`, message, attributes);
    }
  }

  isReady(): boolean { return true; }
  async shutdown(): Promise<void> {}
}
```

#### 3.3 OpenTelemetryProvider (Standard OTEL SDK 2.0)

```typescript
// src/core/telemetry/providers/opentelemetry-provider.ts
import { trace, metrics, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';

export class OpenTelemetryProvider implements TelemetryProvider {
  readonly name = 'opentelemetry';
  private sdk?: NodeSDK;
  private tracer?: Tracer;
  private meter?: Meter;
  private ready = false;

  async validate(): Promise<{ valid: boolean; reason?: string }> {
    if (!process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
      return {
        valid: false,
        reason: 'OTEL_EXPORTER_OTLP_ENDPOINT environment variable not set'
      };
    }

    try {
      new URL(process.env.OTEL_EXPORTER_OTLP_ENDPOINT);
    } catch {
      return {
        valid: false,
        reason: 'OTEL_EXPORTER_OTLP_ENDPOINT is not a valid URL'
      };
    }

    return { valid: true };
  }

  async initialize(config: TelemetryConfig): Promise<void> {
    try {
      const resource = new Resource({
        [ATTR_SERVICE_NAME]: config.serviceName,
        'service.version': config.serviceVersion || '1.0.0',
        'environment': config.environment || 'production'
      });

      this.sdk = new NodeSDK({
        resource,
        traceExporter: new OTLPTraceExporter({
          url: config.exporters.traces?.[0]?.endpoint || process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
          headers: config.exporters.traces?.[0]?.headers
        })
      });

      await this.sdk.start();

      this.tracer = trace.getTracer(config.serviceName, config.serviceVersion);
      this.meter = metrics.getMeter(config.serviceName, config.serviceVersion);
      this.ready = true;
    } catch (error) {
      console.error('[Telemetry] Failed to initialize OTEL provider:', error);
      this.ready = false;
    }
  }

  createSpan(context: Context<unknown, unknown>): Span | undefined {
    if (!this.ready || !this.tracer) return undefined;

    try {
      return this.tracer.startSpan('http.request', {
        kind: SpanKind.SERVER,
        attributes: {
          'http.method': context.req.method,
          'http.url': context.req.url || context.req.path,
          'request.id': context.requestId
        }
      });
    } catch (error) {
      console.error('[Telemetry] Failed to create span:', error);
      return undefined;
    }
  }

  recordMetric(name: string, value: number, attributes?: Record<string, unknown>): void {
    if (!this.ready || !this.meter) return;
    try {
      const histogram = this.meter.createHistogram(name);
      histogram.record(value, attributes);
    } catch (error) {
      console.error('[Telemetry] Failed to record metric:', error);
    }
  }

  log(level: string, message: string, attributes?: Record<string, unknown>): void {
    if (!this.ready) return;
    const span = trace.getActiveSpan();
    const traceContext = span ? {
      traceId: span.spanContext().traceId,
      spanId: span.spanContext().spanId
    } : {};
    console.log(JSON.stringify({ level, message, ...traceContext, ...attributes }));
  }

  isReady(): boolean { return this.ready; }

  async shutdown(): Promise<void> {
    if (this.ready && this.sdk) {
      await this.sdk.shutdown();
      this.ready = false;
    }
  }
}
```

#### 3.4 NewRelicProvider (Official Agent Integration)

```typescript
// src/core/telemetry/providers/newrelic-provider.ts
export class NewRelicProvider implements TelemetryProvider {
  readonly name = 'newrelic';
  private ready = false;
  private newrelic?: typeof import('newrelic');

  async validate(): Promise<{ valid: boolean; reason?: string }> {
    if (!process.env.NEW_RELIC_LICENSE_KEY) {
      return {
        valid: false,
        reason: 'NEW_RELIC_LICENSE_KEY environment variable not set'
      };
    }

    try {
      require.resolve('newrelic');
      return { valid: true };
    } catch {
      return {
        valid: false,
        reason: 'newrelic package not installed (run: npm install newrelic)'
      };
    }
  }

  async initialize(config: TelemetryConfig): Promise<void> {
    try {
      this.newrelic = require('newrelic');
      this.ready = true;
    } catch (error) {
      console.error('[Telemetry] Failed to initialize New Relic:', error);
      this.ready = false;
    }
  }

  createSpan(context: Context<unknown, unknown>): any {
    if (!this.ready || !this.newrelic) return undefined;

    try {
      const transaction = this.newrelic.getTransaction();
      return {
        setAttributes: (attrs: Record<string, unknown>) => {
          this.newrelic?.addCustomAttributes(attrs);
        },
        recordException: (error: Error) => {
          this.newrelic?.noticeError(error);
        },
        setStatus: () => {},
        end: () => {}
      };
    } catch (error) {
      console.error('[Telemetry] Failed to create New Relic span:', error);
      return undefined;
    }
  }

  recordMetric(name: string, value: number, attributes?: Record<string, unknown>): void {
    if (!this.ready || !this.newrelic) return;
    try {
      this.newrelic.recordMetric(name, value);
      if (attributes) {
        this.newrelic.addCustomAttributes(attributes);
      }
    } catch (error) {
      console.error('[Telemetry] Failed to record New Relic metric:', error);
    }
  }

  log(level: string, message: string, attributes?: Record<string, unknown>): void {
    if (!this.ready || !this.newrelic) return;
    try {
      this.newrelic.recordLogEvent({ message, level, ...attributes });
    } catch (error) {
      console.error('[Telemetry] Failed to log to New Relic:', error);
    }
  }

  isReady(): boolean { return this.ready; }

  async shutdown(): Promise<void> {
    if (this.ready && this.newrelic) {
      await this.newrelic.shutdown({ collectPendingData: true, timeout: 5000 });
      this.ready = false;
    }
  }
}
```

#### 3.5 DatadogProvider (Official Tracer Integration)

```typescript
// src/core/telemetry/providers/datadog-provider.ts
export class DatadogProvider implements TelemetryProvider {
  readonly name = 'datadog';
  private ready = false;
  private tracer?: typeof import('dd-trace');

  async validate(): Promise<{ valid: boolean; reason?: string }> {
    if (!process.env.DD_API_KEY && !process.env.DD_SERVICE) {
      return {
        valid: false,
        reason: 'DD_API_KEY or DD_SERVICE environment variable not set'
      };
    }

    try {
      require.resolve('dd-trace');
      return { valid: true };
    } catch {
      return {
        valid: false,
        reason: 'dd-trace package not installed (run: npm install dd-trace)'
      };
    }
  }

  async initialize(config: TelemetryConfig): Promise<void> {
    try {
      this.tracer = require('dd-trace');
      this.tracer.init({
        service: config.serviceName,
        env: config.environment,
        version: config.serviceVersion,
        logInjection: true
      });
      this.ready = true;
    } catch (error) {
      console.error('[Telemetry] Failed to initialize Datadog:', error);
      this.ready = false;
    }
  }

  createSpan(context: Context<unknown, unknown>): any {
    if (!this.ready || !this.tracer) return undefined;

    try {
      const span = this.tracer.startSpan('http.request', {
        resource: `${context.req.method} ${context.req.path}`,
        type: 'web'
      });

      return {
        setAttributes: (attrs: Record<string, unknown>) => {
          span.setTags(attrs);
        },
        recordException: (error: Error) => {
          span.setTag('error', error);
        },
        setStatus: (status: { code: number }) => {
          if (status.code !== 0) {
            span.setTag('error', true);
          }
        },
        end: () => span.finish()
      };
    } catch (error) {
      console.error('[Telemetry] Failed to create Datadog span:', error);
      return undefined;
    }
  }

  recordMetric(name: string, value: number, attributes?: Record<string, unknown>): void {
    if (!this.ready || !this.tracer) return;
    try {
      this.tracer.dogstatsd?.histogram(
        name,
        value,
        attributes ? Object.entries(attributes).map(([k, v]) => `${k}:${v}`) : []
      );
    } catch (error) {
      console.error('[Telemetry] Failed to record Datadog metric:', error);
    }
  }

  log(level: string, message: string, attributes?: Record<string, unknown>): void {
    // Datadog log injection happens automatically with logInjection: true
  }

  isReady(): boolean { return this.ready; }

  async shutdown(): Promise<void> {
    if (this.ready && this.tracer) {
      await this.tracer.flush();
      this.ready = false;
    }
  }
}
```

### Phase 4: Configuration System

#### 4.1 Telemetry Configuration

Create `src/core/telemetry/config.ts`:

```typescript
export interface TelemetryConfig {
  enabled: boolean;
  serviceName: string;
  serviceVersion?: string;
  environment?: string;
  exporters: {
    traces?: OTLPExporterConfig[];
    metrics?: OTLPExporterConfig[];
    logs?: OTLPExporterConfig[];
  };
  sampling?: {
    ratio?: number;  // 0.0 to 1.0
  };
}

export interface OTLPExporterConfig {
  endpoint: string;
  headers?: Record<string, string>;
}
```

#### 4.2 Platform Presets

```typescript
export const TelemetryPresets = {
  NEW_RELIC: {
    exporters: {
      traces: [{
        endpoint: 'https://otlp.nr-data.net:4318/v1/traces',
        headers: { 'api-key': process.env.NEW_RELIC_LICENSE_KEY || '' }
      }]
    }
  },

  DATADOG: {
    exporters: {
      traces: [{
        endpoint: 'https://api.datadoghq.com/api/v2/otlp/v1/traces',
        headers: { 'DD-API-KEY': process.env.DD_API_KEY || '' }
      }]
    }
  },

  JAEGER_LOCAL: {
    exporters: {
      traces: [{
        endpoint: 'http://localhost:4318/v1/traces'
      }]
    }
  },

  DEVELOPMENT: {
    exporters: {
      traces: [{ endpoint: 'http://localhost:4318/v1/traces' }]
    },
    sampling: { ratio: 1.0 }
  }
} as const;
```

### Phase 5: File Structure

#### 5.1 New Files to Create

```
src/
├── core/
│   └── telemetry/
│       ├── provider.ts                        # TelemetryProvider interface
│       ├── providers/
│       │   ├── noop-provider.ts               # Disabled provider
│       │   ├── console-provider.ts            # Local testing provider
│       │   ├── opentelemetry-provider.ts      # Standard OTEL SDK 2.0
│       │   ├── newrelic-provider.ts           # New Relic integration
│       │   ├── datadog-provider.ts            # Datadog integration
│       │   └── index.ts                       # Export all providers
│       ├── config.ts                          # Configuration interfaces
│       └── index.ts                           # Main telemetry exports
├── middlewares/
│   └── openTelemetryMiddleware.ts             # Main middleware
└── types/
    └── telemetry.ts                           # Type definitions
```

#### 5.2 Files to Update

- `src/middlewares/index.ts` - Export OpenTelemetryMiddleware
- `src/core/index.ts` - Export telemetry modules
- `package.json` - Add OTEL dependencies
- `CLAUDE.md` - Document OTEL usage

## Usage Examples

### Zero Configuration (Auto-Detect)

```typescript
import { Handler, OpenTelemetryMiddleware } from '@noony-serverless/core';

// Auto-detects provider based on environment:
// - NODE_ENV=development → ConsoleProvider (logs to console)
// - NODE_ENV=test → NoopProvider (disabled)
// - NEW_RELIC_LICENSE_KEY set → NewRelicProvider
// - OTEL_EXPORTER_OTLP_ENDPOINT set → OpenTelemetryProvider
// - Nothing configured → NoopProvider

const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware())
  .handle(async (context) => {
    // Works everywhere, gracefully degrades
  });
```

### Local Development (Console Logs)

```bash
# .env.development
NODE_ENV=development
# No OTEL endpoint → uses ConsoleProvider
```

```typescript
const handler = new Handler()
  .use(new OpenTelemetryMiddleware()) // Logs spans to console
  .handle(async (context) => { /* ... */ });
```

### Disable in Tests

```typescript
const handler = new Handler()
  .use(new OpenTelemetryMiddleware({
    enabled: process.env.NODE_ENV !== 'test'
  }))
  .handle(async (context) => { /* ... */ });
```

### Custom Filtering

```typescript
const handler = new Handler()
  .use(new OpenTelemetryMiddleware({
    shouldTrace: (context) => {
      // Skip health checks and metrics endpoints
      return !['/health', '/metrics'].includes(context.req.path || '');
    }
  }))
  .handle(async (context) => { /* ... */ });
```

### New Relic Integration

```bash
# .env
NEW_RELIC_LICENSE_KEY=your-key-here
NEW_RELIC_APP_NAME=order-service
```

```typescript
import { Handler, OpenTelemetryMiddleware, NewRelicProvider } from '@noony-serverless/core';

const telemetryMiddleware = new OpenTelemetryMiddleware({
  provider: new NewRelicProvider(),
  extractAttributes: (context) => ({
    'user.id': context.user?.id,
    'tenant.id': process.env.TENANT_ID
  })
});

await telemetryMiddleware.initialize({
  serviceName: 'order-service',
  serviceVersion: '1.0.0',
  environment: 'production'
});

const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(telemetryMiddleware)
  .handle(async (context) => {
    // Traced by New Relic
  });
```

### Standard OTEL with Custom Exporter

```bash
# .env
OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.example.com:4318/v1/traces
OTEL_EXPORTER_OTLP_HEADERS=api-key=your-key
```

```typescript
const handler = new Handler()
  .use(new OpenTelemetryMiddleware()) // Auto-detects OTEL endpoint
  .handle(async (context) => { /* ... */ });
```

### Fastify Integration with @fastify/otel

```typescript
import Fastify from 'fastify';
import otelPlugin from '@fastify/otel';
import { Handler, OpenTelemetryMiddleware } from '@noony-serverless/core';

const fastify = Fastify();

// Register Fastify OTEL plugin
fastify.register(otelPlugin, {
  serviceName: 'order-service',
  exposeHttpApi: true
});

const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware())
  .handle(async (context) => {
    // Business logic
  });

fastify.post('/orders', async (request, reply) => {
  await handler.executeGeneric(
    request as NoonyRequest<CreateOrderRequest>,
    reply as NoonyResponse
  );
});
```

## Environment Variables Reference

### Standard OTEL

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces
OTEL_EXPORTER_OTLP_HEADERS=api-key=your-key
```

### New Relic

```bash
NEW_RELIC_LICENSE_KEY=your-license-key
NEW_RELIC_APP_NAME=my-service
```

### Datadog

```bash
DD_API_KEY=your-api-key
DD_SERVICE=my-service
DD_ENV=production
DD_VERSION=1.0.0
```

### Control Telemetry

```bash
NODE_ENV=test              # Disables telemetry
NODE_ENV=development       # Uses ConsoleProvider if no OTEL endpoint
```

## Benefits

### For Observability

- **Multi-platform support**: Export to any OTEL-compatible system
- **Distributed tracing**: Complete request lifecycle visibility
- **Rich context correlation**: Security, auth, and business data in traces
- **Custom metrics**: Business-specific observability

### For Performance

- **Leverages existing optimizations**: Built on current performance monitoring
- **Singleton providers**: No per-request initialization overhead
- **Lazy initialization**: Minimal impact when disabled
- **Backward compatibility**: Existing monitoring continues to work

### For Development

- **Framework-agnostic**: Works with GCP Functions, Fastify, Express
- **Zero configuration**: Auto-detects from environment
- **Fail-safe**: Never breaks your application
- **Local friendly**: Console provider for development, disabled in tests
- **Easy integration**: Single middleware addition

## Implementation Tasks

1. ✅ Create `TelemetryProvider` interface with `validate()` method
2. ✅ Implement `NoopProvider` (disabled/fallback)
3. ✅ Implement `ConsoleProvider` (local testing)
4. ✅ Implement `OpenTelemetryProvider` with validation
5. ✅ Implement `NewRelicProvider` with validation
6. ✅ Implement `DatadogProvider` with validation
7. ✅ Create smart `OpenTelemetryMiddleware` with auto-detection
8. ✅ Add graceful degradation and fail-silently mode
9. ✅ Add provider validation before initialization
10. ✅ Update dependencies with SDK 2.0 packages
11. ✅ Create comprehensive tests for all providers
12. ✅ Document local testing and troubleshooting guide

## Next Steps

1. Review and approve this plan
2. Implement Phase 1 (Core infrastructure with provider interface)
3. Implement Phase 2 (OpenTelemetry middleware with auto-detection)
4. Implement Phase 3 (All provider implementations)
5. Implement Phase 4 (Configuration system)
6. Test with local development (ConsoleProvider)
7. Test with production-like workloads (standard OTEL, New Relic, Datadog)
8. Document performance impact and optimization guidelines
9. Update CLAUDE.md with usage examples
10. Create platform-specific setup guides
