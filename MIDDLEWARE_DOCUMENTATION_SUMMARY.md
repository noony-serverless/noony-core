# Noony Middleware Components - JSDoc Documentation Summary

This document provides an overview of all exportable middleware components with their JSDoc documentation and usage examples.

## Authentication Middleware

### `AuthenticationMiddleware<T>`
Class-based middleware for JWT and custom token authentication with comprehensive security features.

**Key Features:**
- JWT validation with security checks
- Rate limiting per user/IP
- Token blacklisting support
- Clock tolerance for time-based validations

### `verifyAuthTokenMiddleware<T>`
Factory function for authentication middleware setup.

### `CustomTokenVerificationPort<T>`
Interface for implementing custom token verification strategies.

### `JWTPayload`
Standard JWT payload interface with common claims.

## Body Processing Middleware

### `BodyParserMiddleware<T>`
Enhanced body parser with async parsing and performance optimizations.

**Key Features:**
- Async JSON parsing for large payloads
- Size limits to prevent DoS attacks
- Base64 decoding for Pub/Sub messages
- Non-blocking parsing using setImmediate

### `bodyParser<T>`
Factory function for body parsing middleware.

### `BodyValidationMiddleware<T>`
Body validation using Zod schemas for runtime type checking.

### `bodyValidatorMiddleware<T>`
Factory function for body validation middleware.

## Dependency Injection Middleware

### `DependencyInjectionMiddleware`
Middleware for injecting services into request context using typedi.

**Key Features:**
- Service container management
- Shared services across handlers
- Clean dependency management

### `dependencyInjection`
Factory function for dependency injection setup.

## Error Handling Middleware

### `ErrorHandlerMiddleware`
Comprehensive error handling with logging and appropriate JSON responses.

**Key Features:**
- Development vs production error responses
- Security-conscious error details
- Request context logging

### `errorHandler`
Factory function for error handling middleware.

## Header and Parameter Middleware

### `HeaderVariablesMiddleware`
Validates presence of required HTTP headers.

### `headerVariablesMiddleware`
Factory function for header validation.

### `PathParametersMiddleware`
Extracts path parameters from URL segments.

### `pathParameters`
Factory function for path parameter extraction.

### `headerVariablesValidator`
Alternative header validation middleware.

### `validatedQueryParameters`
Query parameter validation using Zod schemas.

### `QueryParametersMiddleware`
Validates and processes query parameters from request URL.

### `queryParametersMiddleware`
Factory function for query parameter processing.

## Response Handling Middleware

### `ResponseWrapperMiddleware<T>`
Wraps response data in standardized format with success flag and timestamp.

### `responseWrapperMiddleware<T>`
Factory function for response wrapping.

### `setResponseData<T>`
Helper function to set response data in context for wrapping.

## Security Middleware

### `RateLimitingMiddleware`
Sliding window rate limiting with comprehensive features.

**Key Features:**
- Dynamic limits based on request context
- Custom storage backend support
- Anomaly detection
- Comprehensive monitoring

### `rateLimiting`
Factory function for rate limiting setup.

### `RateLimitPresets`
Predefined rate limit configurations (STRICT, API, AUTH, PUBLIC, DEVELOPMENT).

### `SecurityAuditMiddleware`
Comprehensive security event logging and monitoring.

**Key Features:**
- Suspicious pattern detection
- Anomaly detection
- Security event tracking
- Configurable logging levels

### `securityAudit`
Factory function for security audit middleware.

### `SecurityAuditPresets`
Predefined security audit configurations.

### `SecurityHeadersMiddleware`
Implements comprehensive security headers following OWASP recommendations.

**Key Features:**
- Content Security Policy
- CORS configuration
- Security header management
- Multiple security presets

### `securityHeaders`
Factory function for security headers setup.

### `SecurityPresets`
Predefined security configurations (STRICT, BALANCED, DEVELOPMENT).

## Validation Middleware

### `ValidationMiddleware`
Validates request data using Zod schemas (body or query parameters).

### `validationMiddleware`
Factory function for general validation middleware.

## OpenTelemetry Integration

### `OpenTelemetryMiddleware<T, U>`
Distributed tracing and observability middleware with automatic provider detection.

**Key Features:**
- Auto-detects telemetry providers from environment (OTEL, New Relic, Datadog)
- Zero-configuration local development with ConsoleProvider
- W3C Trace Context propagation for Google Cloud Pub/Sub messages
- Type-safe with full generic support `<TBody, TUser>`
- Graceful degradation when packages not installed
- Fail-safe operation (telemetry errors never break application)
- Custom attribute extraction from context
- Request filtering capabilities
- Graceful shutdown support

**Provider Auto-Detection Priority:**
1. Explicit provider (options.provider)
2. New Relic (NEW_RELIC_LICENSE_KEY + newrelic package)
3. Datadog (DD_API_KEY/DD_SERVICE + dd-trace package)
4. Standard OTEL (OTEL_EXPORTER_OTLP_ENDPOINT)
5. Console (NODE_ENV=development)
6. Noop (NODE_ENV=test or no configuration)

### `openTelemetry<T, U>`
Factory function for creating OpenTelemetry middleware instances.

**Usage Example:**
```typescript
import {
  Handler,
  OpenTelemetryMiddleware,
  injectTraceContext,
  Context
} from '@noony-serverless/core';

// Basic usage - auto-detects provider
const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware<CreateOrderRequest, AuthUser>())
  .handle(async (context) => {
    const order = await orderService.create(context.req.validatedBody!);
    return { orderId: order.id };
  });

// With custom attributes and filtering
const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware<CreateOrderRequest, AuthUser>({
    shouldTrace: (context) => context.req.path !== '/health',
    extractAttributes: (context) => ({
      'http.method': context.req.method,
      'user.id': context.user?.id,
      'tenant.id': context.businessData.get('tenantId')
    })
  }))
  .handle(async (context) => {
    // Business logic with full tracing
  });
```

### Pub/Sub Trace Propagation Utilities

**`injectTraceContext(message, context?)`**
Injects W3C Trace Context into Pub/Sub message attributes for distributed tracing.

**`extractTraceContext(pubsubMessage)`**
Extracts W3C Trace Context from incoming Pub/Sub message attributes.

**`isPubSubMessage(body)`**
Type guard to check if request body is a Pub/Sub message.

**`createParentContext(traceContext)`**
Internal utility to create parent context from extracted trace headers.

**Pub/Sub Distributed Tracing Example:**
```typescript
import { PubSub } from '@google-cloud/pubsub';
import {
  Handler,
  OpenTelemetryMiddleware,
  BodyParserMiddleware,
  injectTraceContext
} from '@noony-serverless/core';

const pubsub = new PubSub();

// Publisher - Inject trace context
const publisherHandler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware<CreateOrderRequest, AuthUser>())
  .handle(async (context) => {
    const order = await orderService.create(context.req.validatedBody!);

    // Inject trace context into message
    const message = injectTraceContext({
      data: Buffer.from(JSON.stringify({ orderId: order.id })).toString('base64'),
      attributes: { eventType: 'order.created' }
    }, context);

    await pubsub.topic('orders').publish(message);
    return { orderId: order.id };
  });

// Subscriber - Automatically extract trace context
const subscriberHandler = new Handler()
  .use(new BodyParserMiddleware())
  .use(new OpenTelemetryMiddleware({
    propagatePubSubTraces: true  // default: true
  }))
  .handle(async (context) => {
    // Automatically linked to publisher's trace!
    const { orderId } = context.req.parsedBody;
    await inventoryService.reserveStock(orderId);
    return { success: true };
  });
```

### Telemetry Providers

**`TelemetryProvider`** - Interface for all telemetry provider implementations
**`NoopProvider`** - Fallback provider when telemetry is disabled
**`ConsoleProvider`** - Local development provider that logs to console
**`OpenTelemetryProvider`** - Standard OpenTelemetry SDK 2.0 implementation

### Configuration Interfaces

**`OpenTelemetryOptions`**
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

**`TelemetryConfig`**
```typescript
interface TelemetryConfig {
  serviceName: string;
  serviceVersion: string;
  environment: string;
  exporters?: {
    traces?: Array<{ endpoint: string; headers?: Record<string, string> }>;
    metrics?: Array<{ endpoint: string; headers?: Record<string, string> }>;
  };
  sampling?: { ratio: number };
}
```

**`GenericSpan`** - Framework-agnostic span interface
**`TraceContext`** - W3C Trace Context structure (traceparent, tracestate)
**`PubSubMessage`** - Google Cloud Pub/Sub message type

**Environment Variables:**
```bash
# Standard OTEL
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector:4318/v1/traces
OTEL_SERVICE_NAME=order-service
OTEL_SERVICE_VERSION=2.1.0

# New Relic
NEW_RELIC_LICENSE_KEY=your-key
NEW_RELIC_APP_NAME=order-service

# Datadog
DD_API_KEY=your-key
DD_SERVICE=order-service
DD_ENV=production
DD_VERSION=1.0.0

# Local Development
NODE_ENV=development  # Uses ConsoleProvider

# GCP Cloud Trace (optional)
# Automatically enabled on GCP (Cloud Run, Cloud Functions, App Engine)
```

**Cloud Trace Integration (Google Cloud Platform):**

When running on GCP, Noony automatically integrates with Cloud Trace using **CloudPropagator**:

```bash
npm install @google-cloud/opentelemetry-cloud-trace-propagator --save-optional
```

**Benefits:**
- Synchronizes trace IDs with Cloud Run Load Balancer
- Complete end-to-end traces in Cloud Trace UI
- Automatic correlation with Cloud Logging
- Multiple response headers for debugging

**Response headers:**
```http
X-Cloud-Trace-Context: 13ea7e3c2d3b4547baaa399062df1f2d/1234567890123456;o=1
X-Trace-Id: 13ea7e3c2d3b4547baaa399062df1f2d
traceparent: 00-13ea7e3c2d3b4547baaa399062df1f2d-1234567890123456-01
```

All three headers contain the **same trace ID**.

**Auto-detection:** Enabled when `K_SERVICE`, `FUNCTION_NAME`, or `GAE_APPLICATION` env vars are present.

**See also:**
- [OTEL_NOONY.md](./OTEL_NOONY.md) - Complete OpenTelemetry documentation
- [OTEL_NOONY.md - Cloud Trace Integration](./OTEL_NOONY.md#cloud-trace-integration-google-cloud-platform) - GCP-specific details

## Guards System

### `RouteGuards`
Main facade for the comprehensive permission system.

**Key Features:**
- Multi-layer caching (L1 memory + L2 distributed)
- Three distinct permission resolution strategies
- Conservative cache invalidation for security
- Framework-agnostic middleware integration

### `GuardSetup`
Quick setup helper for common guard configurations.

**Methods:**
- `development()` - Development environment setup
- `production()` - Production environment setup
- `serverless()` - Serverless environment setup
- `testing()` - Testing environment setup

### Additional Guard Components
- `CacheAdapter`, `MemoryCacheAdapter`, `NoopCacheAdapter`
- `ConservativeCacheInvalidation`
- `PermissionResolver` family
- `PermissionRegistry`
- `FastUserContextService`
- `FastAuthGuard`
- `PermissionGuardFactory`

## Usage Patterns

### Basic Handler Setup
```typescript
import { Handler, bodyParser, errorHandler, responseWrapperMiddleware } from '@noony-serverless/core';

const apiHandler = new Handler()
  .use(bodyParser())
  .use(errorHandler())
  .use(responseWrapperMiddleware())
  .handle(async (context) => {
    return { success: true, data: 'API response' };
  });
```

### Secure API Endpoint
```typescript
const secureHandler = new Handler()
  .use(rateLimiting(RateLimitPresets.API))
  .use(securityHeaders(SecurityPresets.BALANCED))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(bodyParser())
  .use(validationMiddleware(requestSchema))
  .use(responseWrapperMiddleware())
  .use(errorHandler())
  .handle(async (context) => {
    // Authenticated and validated request handling
    return { success: true, data: processSecureRequest(context) };
  });
```

### Microservice with Dependencies
```typescript
const microserviceHandler = new Handler()
  .use(dependencyInjection(services))
  .use(securityAudit(SecurityAuditPresets.COMPREHENSIVE))
  .use(bodyParser())
  .use(responseWrapperMiddleware())
  .use(errorHandler())
  .handle(async (context) => {
    const userService = context.container?.get(UserService);
    const result = await userService.processRequest(context.req.parsedBody);
    setResponseData(context, result);
  });
```

## Key Benefits

1. **Type Safety**: Full TypeScript support with generics
2. **Performance**: Optimized for serverless environments
3. **Security**: Comprehensive security features built-in
4. **Flexibility**: Both class-based and factory function approaches
5. **Composability**: Easy to combine multiple middlewares
6. **Monitoring**: Built-in logging and performance tracking
7. **Standards Compliance**: Follows industry best practices

All middleware components include comprehensive JSDoc documentation with multiple usage examples for different scenarios.
