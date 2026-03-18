# Noony Framework — Core Elements

Complete map of every core element in the Noony Framework.

---

## Core Engine (`src/core/`)

| Element | File | Purpose |
|---------|------|---------|
| **Handler\<T, U\>** | `core/handler.ts` | Main orchestrator — chains middlewares (before/after/onError), executes controllers, supports GCP + Express + Fastify |
| **Context\<T, U\>** | `core/core.ts` | Type-safe request context carrying `req`, `res`, `container`, `user`, `businessData`, `error`, `requestId` |
| **BaseMiddleware\<T, U\>** | `core/core.ts` | Interface all middlewares implement — `before()`, `after()`, `onError()` hooks |
| **GenericRequest / GenericResponse** | `core/core.ts` | Framework-agnostic HTTP abstractions with adapters for GCP, Express, Fastify |
| **ContainerPool** | `core/containerPool.ts` | Zero-copy DI — global services shared across requests, proxy containers isolated per-request (~99% memory savings) |
| **Error Classes** | `core/errors.ts` | HTTP error hierarchy: `ValidationError` (400), `UnauthorizedError` (401), `ForbiddenError` (403), `NotFoundError` (404), `ConflictError` (409), `TimeoutError` (408), `TooLargeError` (413), `InternalServerError` (500), `SecurityError`, `ServiceError` |
| **ErrorCategorizer** | `core/error-categorizer.ts` | Pattern-based error classification (DATABASE, TIMEOUT, EXTERNAL_SERVICE, INTERNAL) with regex matchers |
| **Logger** | `core/logger.ts` | Performance-optimized logging with OTEL trace/span injection, object pooling, lazy timestamp caching, child loggers |
| **PerformanceMonitor** | `core/performanceMonitor.ts` | Non-blocking operation timing with histogram metrics (min/max/avg/p95), `@timed()` decorator |
| **Constants** | `core/constants.ts` | Central config values — HTTP limits, cache TTLs, container keys, environment detection |

## Telemetry System (`src/core/telemetry/`)

| Element | File | Purpose |
|---------|------|---------|
| **TelemetryProvider** | `telemetry/provider.ts` | Interface for all providers — `createSpan()`, `recordMetric()`, `log()`, `shutdown()` |
| **OpenTelemetryProvider** | `telemetry/providers/opentelemetry-provider.ts` | Full OTEL SDK 2.0 integration — OTLP exporters, W3C + Cloud Trace propagation |
| **ConsoleProvider** | `telemetry/providers/console-provider.ts` | Dev/debug — pretty-prints span lifecycle to console |
| **NoopProvider** | `telemetry/providers/noop-provider.ts` | Graceful fallback — no-op, never throws |
| **TelemetryConfig** | `telemetry/config.ts` | Presets: `GCP`, `CLOUD_RUN`, `NEW_RELIC`, `DATADOG`, `JAEGER_LOCAL`, `DEVELOPMENT`, `DISABLED` |

## Middlewares (`src/middlewares/`)

| Middleware | Purpose |
|------------|---------|
| **BodyParserMiddleware** | Async JSON parsing + Base64 Pub/Sub decoding with security validation |
| **BodyValidationMiddleware** | Zod schema validation on request bodies |
| **ErrorHandlerMiddleware** | Converts errors to JSON responses with categorization; debug mode in dev |
| **QueryParametersMiddleware** | Extracts + validates required query params from URL |
| **HeaderVariablesMiddleware** | Validates required HTTP headers (case-insensitive) |
| **DependencyInjectionMiddleware** | Registers services in global or request-local scope via TypeDI |
| **AuthenticationMiddleware** | JWT verification with rate limiting, token blacklist, clock tolerance |
| **OpenTelemetryMiddleware** | Auto-detects provider, propagates traces (including Pub/Sub), injects X-Trace-Id |
| **SecurityHeadersMiddleware** | CSP, HSTS, CORS, frame options — presets: STRICT, BALANCED, DEVELOPMENT |
| **RateLimitingMiddleware** | Sliding window rate limiting with dynamic limits, custom keys, pluggable stores |
| **ResponseWrapperMiddleware** | Standardizes responses to `{ success, payload, timestamp }` |
| **HttpAttributesMiddleware** | HTTP attribute tracking on requests |
| **ProcessingMiddleware** | Request processing hooks |
| **SecurityAuditMiddleware** | Security event logging/auditing |
| **ValidationMiddleware** | Generic validation middleware |

## Route Guards (`src/middlewares/guards/`)

| Element | Purpose |
|---------|---------|
| **RouteGuards** | Facade for permission-based access control |
| **FastAuthGuard** | High-performance authentication guard |
| **PermissionGuardFactory** | Creates guards with caching |
| **PermissionRegistry** | Stores permission configurations |
| **PlainPermissionResolver** | Simple permission list matching |
| **WildcardPermissionResolver** | Hierarchical pattern matching (e.g., `admin.*`) |
| **ExpressionPermissionResolver** | Boolean expressions (`read AND write`) |
| **MemoryCacheAdapter / NoopCacheAdapter** | Cache strategies for permission lookups |
| **FastUserContextService** | Cached user permission loading |

## Utilities (`src/utils/`)

| Utility | Purpose |
|---------|---------|
| **container.utils.ts** | `getService<T>()` — type-safe DI service resolution |
| **query-param.utils.ts** | `asString()`, `asNumber()`, `asBoolean()`, `asStringArray()` — query param coercion |
| **otel.helper.ts** | OTEL helpers — Pino mixin, trace context extraction, GCP Cloud Logging formatting |
| **pubsub-trace.utils.ts** | Pub/Sub trace propagation — extract/inject W3C Trace Context from messages |
| **http-wrapper-base.ts** | Shared HTTP utils — response-sent checks, error logging, 500 fallback |
| **fastify-wrapper.ts** | `createFastifyHandler()` — adapts GCP Functions handler to Fastify with WeakMap body caching |
| **wrapper-utils.ts** | `createHttpFunction()` / `wrapNoonyHandler()` — generic framework wrappers |

## Config (`src/config/`)

| File | Purpose |
|------|---------|
| **telemetry.config.ts** | Default telemetry configuration |

---

## Key Architectural Patterns

1. **Generic Type Chain** — `Handler<TBody, TUser>` flows through every middleware and into `Context<TBody, TUser>`, ensuring end-to-end type safety
2. **Dual API** — Every middleware has both a class (`new BodyParserMiddleware()`) and a factory function (`bodyParser()`)
3. **Zero-Copy DI** — Global services shared via proxy; only request-scoped data is per-request
4. **Framework Agnostic** — Adapters normalize GCP/Express/Fastify into `GenericRequest`/`GenericResponse`
5. **Middleware Lifecycle** — `before` runs in order, `after`/`onError` run in reverse order
6. **Graceful Degradation** — NoopProvider, fallback error handling, optional features degrade silently
7. **Performance-First** — Object pooling in Logger, pre-computed middleware arrays in Handler, lazy timestamps, async body parsing
