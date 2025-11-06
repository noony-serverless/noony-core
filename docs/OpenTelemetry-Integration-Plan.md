# OpenTelemetry Integration Plan for Noony Framework

## Overview

This document outlines the strategy for integrating OpenTelemetry (OTEL) into the Noony serverless middleware framework to extend observability to platforms like New Relic, Datadog, Jaeger, and other OTEL-compatible systems.

## Current Observability Infrastructure

The Noony framework already has a solid observability foundation:

### Existing Components

1. **Performance Monitor** (`src/core/performanceMonitor.ts`)
   - Built-in timing with `process.hrtime.bigint()`
   - Metrics aggregation (count, avg, min, max, P95)
   - Memory-efficient with configurable limits
   - Decorator support (`@timed`, `@timedSync`)
   - Limited to local storage

2. **Structured Logger** (`src/core/logger.ts`)
   - Performance-optimized with object pooling
   - Timestamp caching (1-second cache)
   - Dynamic log method references
   - Environment-based debug mode
   - Performance logging integration

3. **Security Audit Middleware** (`src/middlewares/securityAuditMiddleware.ts`)
   - Comprehensive security event tracking
   - Anomaly detection with time-based windows
   - Suspicious pattern detection (SQL injection, XSS, etc.)
   - Client behavior analysis
   - Custom security event handlers

4. **Middleware Architecture**
   - BaseMiddleware interface with `before`/`after`/`onError` hooks
   - Pre-computed middleware arrays for performance
   - Error propagation in reverse middleware order
   - Framework-agnostic design (GCP Functions, Fastify, Express)

5. **Rich Context System** (`src/core/core.ts`)
   - Request tracking with `requestId` and `startTime`
   - User context integration
   - Business data map for shared state
   - Timeout signal support
   - Framework adapters for GCP Functions

## Integration Strategy

### Key Integration Points

1. **Middleware Pipeline**: Perfect for distributed tracing spans
2. **Context Object**: Already contains essential telemetry data
3. **Performance Monitor**: Can export metrics via OTEL
4. **Security Events**: Can be exported as OTEL metrics and traces
5. **Logger**: Can be enhanced with trace correlation

## Implementation Plan

### Phase 1: Core OTEL Integration

#### 1.1 OpenTelemetry Middleware
Create `src/middlewares/openTelemetryMiddleware.ts`:

```typescript
interface OTELOptions {
  serviceName: string;
  serviceVersion?: string;
  exporters: {
    traces?: ExporterConfig[];
    metrics?: ExporterConfig[];
    logs?: ExporterConfig[];
  };
  sampling?: SamplingConfig;
  enableAutoInstrumentation?: boolean;
}

class OpenTelemetryMiddleware implements BaseMiddleware {
  // Integrates with existing middleware pipeline
  // Creates spans for each middleware execution
  // Propagates trace context
}
```

#### 1.2 Dependencies to Add
```json
{
  "@opentelemetry/sdk-node": "^0.45.0",
  "@opentelemetry/exporter-otlp-http": "^0.45.0",
  "@opentelemetry/exporter-jaeger": "^1.18.0",
  "@opentelemetry/exporter-prometheus": "^0.45.0",
  "@opentelemetry/instrumentation-http": "^0.45.0",
  "@opentelemetry/instrumentation-fastify": "^0.32.0"
}
```

### Phase 2: Enhanced Performance Monitoring

#### 2.1 Extend PerformanceMonitor
Enhance `src/core/performanceMonitor.ts`:

```typescript
class PerformanceMonitor {
  private otelMetrics?: Metrics;
  
  // Add OTEL metric instruments
  private requestDurationHistogram: Histogram;
  private operationCounter: Counter;
  private activeRequestsGauge: UpDownCounter;
  
  // Export existing metrics via OTEL
  exportToOTEL(): void {
    // Convert existing aggregated metrics to OTEL format
  }
}
```

#### 2.2 Custom Metrics
- Middleware execution times
- Request rates by endpoint
- Error rates by type
- Security event frequencies
- Business operation metrics

### Phase 3: Distributed Tracing

#### 3.1 Trace Context Propagation
- Automatic trace context extraction from incoming requests
- Context injection for outgoing HTTP calls
- Correlation across middleware chain

#### 3.2 Span Creation Strategy
```typescript
// Each middleware gets its own span
// Root span for entire request lifecycle
// Child spans for:
// - Authentication operations
// - Validation steps
// - Business logic execution
// - Database operations
// - External API calls
```

#### 3.3 Span Attributes
- Request ID (`context.requestId`)
- User information (`context.user`)
- Endpoint and method
- Custom business data from `context.businessData`
- Security event details

### Phase 4: Logging Integration

#### 4.1 Enhance Logger
Extend `src/core/logger.ts`:

```typescript
class Logger {
  private otelLogger?: logs.Logger;
  
  // Add trace correlation to log entries
  // Export structured logs via OTEL
  // Maintain existing performance optimizations
}
```

#### 4.2 Log Correlation
- Automatic trace ID injection
- Span ID correlation
- Structured logging with OTEL format

### Phase 5: Security & Business Metrics

#### 5.1 Security Event Export
Enhance `src/middlewares/securityAuditMiddleware.ts`:

```typescript
class SecurityAuditMiddleware {
  // Export security events as OTEL metrics
  // Create traces for security incidents
  // Track anomaly detection results
}
```

#### 5.2 Authentication Metrics
- Login attempt rates
- Failed authentication patterns
- Token validation performance
- Permission check latencies

### Phase 6: Configuration System

#### 6.1 Telemetry Configuration
Create `src/core/telemetry/config.ts`:

```typescript
interface TelemetryConfig {
  enabled: boolean;
  serviceName: string;
  environment: string;
  exporters: {
    newRelic?: NewRelicConfig;
    datadog?: DatadogConfig;
    jaeger?: JaegerConfig;
    otlp?: OTLPConfig;
  };
  sampling: SamplingConfig;
  performance: PerformanceConfig;
}
```

#### 6.2 Platform Presets
```typescript
export const TelemetryPresets = {
  NEW_RELIC: {
    // New Relic specific configuration
  },
  DATADOG: {
    // Datadog specific configuration
  },
  JAEGER: {
    // Jaeger specific configuration
  },
  DEVELOPMENT: {
    // Development mode with console exporters
  }
};
```

### Phase 7: Platform-Specific Integrations

#### 7.1 New Relic Integration
- OTLP exporter configuration
- Custom attributes mapping
- APM integration
- Infrastructure correlation

#### 7.2 Datadog Integration
- Datadog exporter setup
- Tag standardization
- APM and Infrastructure correlation
- Custom metrics and events

#### 7.3 Other Platforms
- Jaeger for local development
- Prometheus for metrics
- Console exporters for debugging

## Implementation Files

### New Files to Create

```
src/
├── core/
│   └── telemetry/
│       ├── config.ts              # Configuration interfaces and presets
│       ├── exporters.ts           # Platform-specific exporter configurations
│       ├── instrumentation.ts     # Auto-instrumentation setup
│       └── index.ts              # Main telemetry exports
├── middlewares/
│   └── openTelemetryMiddleware.ts # Main OTEL middleware
└── types/
    └── telemetry.ts              # OTEL-related type definitions
```

### Files to Enhance

```
src/
├── core/
│   ├── performanceMonitor.ts     # Add OTEL metric export
│   ├── logger.ts                 # Add trace correlation
│   └── core.ts                   # Add telemetry context
├── middlewares/
│   ├── securityAuditMiddleware.ts # Export security metrics
│   └── index.ts                  # Export new middleware
└── package.json                  # Add OTEL dependencies
```

### Documentation Updates

```
docs/
├── OpenTelemetry-Setup-Guide.md
├── Platform-Integration-Guides/
│   ├── NewRelic-Setup.md
│   ├── Datadog-Setup.md
│   ├── Jaeger-Setup.md
│   └── Custom-Exporters.md
└── Examples/
    ├── production-telemetry/
    └── development-observability/
```

## Usage Examples

### Basic Setup

```typescript
import { Handler, OpenTelemetryMiddleware } from '@noony-serverless/core';

const handler = new Handler()
  .use(new OpenTelemetryMiddleware({
    serviceName: 'my-service',
    exporters: {
      traces: [{ type: 'otlp', endpoint: process.env.OTEL_ENDPOINT }],
      metrics: [{ type: 'prometheus' }]
    }
  }))
  .use(new AuthenticationMiddleware())
  .handle(async (context) => {
    // Your business logic
    // Automatically instrumented with traces and metrics
  });
```

### New Relic Integration

```typescript
import { TelemetryPresets } from '@noony-serverless/core';

const handler = new Handler()
  .use(new OpenTelemetryMiddleware({
    ...TelemetryPresets.NEW_RELIC,
    serviceName: 'my-service',
    exporters: {
      traces: [{
        type: 'otlp',
        endpoint: 'https://otlp.nr-data.net:4317',
        headers: { 'api-key': process.env.NEW_RELIC_LICENSE_KEY }
      }]
    }
  }))
  .handle(async (context) => {
    // Traces and metrics automatically sent to New Relic
  });
```

## Benefits

### For Observability
- **Multi-platform support**: Export to any OTEL-compatible system
- **Distributed tracing**: Complete request lifecycle visibility
- **Rich context correlation**: Security, auth, and business data in traces
- **Custom metrics**: Business-specific observability

### For Performance
- **Leverages existing optimizations**: Built on current performance monitoring
- **Configurable sampling**: Control overhead in production
- **Lazy initialization**: Minimal impact when disabled
- **Backward compatibility**: Existing monitoring continues to work

### for Development
- **Framework-agnostic**: Works with GCP Functions, Fastify, Express
- **Easy integration**: Single middleware addition
- **Rich debugging**: Local Jaeger traces for development
- **Production-ready**: Battle-tested OTEL ecosystem

## Performance Considerations

1. **Sampling Strategy**: Implement head-based sampling for high-traffic services
2. **Batch Export**: Use batch exporters to reduce network overhead
3. **Resource Detection**: Automatic service discovery in cloud environments
4. **Memory Management**: Leverage existing object pooling and caching
5. **Conditional Instrumentation**: Enable/disable based on environment

## Migration Strategy

1. **Phase 1**: Add OTEL middleware alongside existing monitoring
2. **Phase 2**: Gradually migrate to OTEL metrics while maintaining compatibility
3. **Phase 3**: Optimize and fine-tune based on production usage
4. **Phase 4**: Consider deprecating legacy monitoring (optional)

## Next Steps

1. Review and approve this plan
2. Set up development environment with Jaeger
3. Implement Phase 1 (Core OTEL Integration)
4. Create examples and documentation
5. Test with production-like workloads
6. Implement platform-specific integrations
7. Document performance impact and optimization guidelines