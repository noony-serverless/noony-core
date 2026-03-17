# Middleware Reference

Complete reference for all 15 built-in middlewares in the Noony Serverless Framework.

## Pipeline Execution Order

Middlewares are added to a handler via `.use()` and execute in a defined order:

- **`before` hooks** run top-to-bottom (in `.use()` order)
- **`after` hooks** run bottom-to-top (reverse `.use()` order)
- **`onError` hooks** run bottom-to-top (reverse `.use()` order)

This means the first middleware registered gets the first look at the request and the last look at the response or error.

## Complete Middleware Catalogue

| # | Middleware | Purpose | Key Option | Reference |
|---|-----------|---------|------------|-----------|
| 1 | `ErrorHandlerMiddleware` | Catches pipeline errors, maps to HTTP status codes | `options?: ErrorHandlerOptions` | [error-handler.md](./error-handler.md) |
| 2 | `DependencyInjectionMiddleware` | Populates `context.container` with registered services | `services: ServiceDefinition[]` | [dependency-injection.md](./dependency-injection.md) |
| 3 | `BodyParserMiddleware` | Decodes JSON/Pub/Sub body into `context.req.parsedBody` | `maxSize?: number` | [body-parser.md](./body-parser.md) |
| 4 | `BodyValidationMiddleware` | Validates `parsedBody` against a Zod schema; sets `context.req.validatedBody` | `schema: ZodType<T>` | [body-validation.md](./body-validation.md) |
| 5 | `HeaderVariablesMiddleware` | Asserts required headers are present and non-empty | `requiredHeaders: string[]` | [headers.md](./headers.md) |
| 6 | `QueryParametersMiddleware` | Parses and optionally validates required query string params | `requiredParams?: string[]` | [query-params.md](./query-params.md) |
| 7 | `ResponseWrapperMiddleware` | Wraps controller return value in a standard `{ success, payload, timestamp }` envelope | `defaultStatusCode?: number` | [response-wrapper.md](./response-wrapper.md) |
| 8 | `AuthenticationMiddleware` | Validates auth tokens via a pluggable verification port; sets `context.user` | `tokenVerificationPort: CustomTokenVerificationPort<TUser>` | [authentication.md](./authentication.md) |
| 9 | `OpenTelemetryMiddleware` | Adds distributed tracing spans with auto-detected provider | `options?: OpenTelemetryOptions` | [opentelemetry.md](./opentelemetry.md) |
| 10 | `SecurityHeadersMiddleware` | Sets security response headers (HSTS, CSP, CORS, X-Frame-Options, etc.) | `options?: SecurityHeadersOptions` | [security-headers.md](./security-headers.md) |
| 11 | `RateLimitingMiddleware` | Per-client request rate limiting with dynamic tiers and pluggable storage | `options?: RateLimitOptions` | [rate-limiting.md](./rate-limiting.md) |
| 12 | `SecurityAuditMiddleware` | Logs security-relevant events, detects injection attempts and anomalies | `options?: SecurityAuditOptions` | [security-audit.md](./security-audit.md) |
| 13 | `ProcessingMiddleware` | Consolidated body parsing, query processing, and HTTP attribute extraction | `config?: ProcessingMiddlewareConfig` | [processing.md](./processing.md) |
| 14 | `HttpAttributesMiddleware` | Extracts path parameters, validates headers, validates query params via Zod | (see individual factories) | [http-attributes.md](./http-attributes.md) |
| 15 | `ValidationMiddleware` | Generic Zod validation -- validates body (non-GET) or query params (GET) automatically | `schema: ZodSchema` | [validation.md](./validation.md) |

## Canonical Middleware Ordering

Add middlewares to `.use()` in this order. See [Middleware Ordering Guide](../../guides/middleware-ordering.md) for detailed rationale and variations.

| Position | Middleware | Rationale |
|----------|-----------|-----------|
| 1 | `ErrorHandlerMiddleware` | Must be first so its `onError` hook fires last and can shape every error response |
| 2 | `OpenTelemetryMiddleware` | Creates the tracing span early; `after`/`onError` hooks close it with full context |
| 3 | `SecurityHeadersMiddleware` | Sets response headers before any downstream middleware can send a response |
| 4 | `SecurityAuditMiddleware` | Detects injection attempts and suspicious patterns before processing |
| 5 | `RateLimitingMiddleware` | Reject over-limit requests before any expensive work |
| 6 | `DependencyInjectionMiddleware` | Services must exist before any middleware that calls them |
| 7 | `HeaderVariablesMiddleware` | Cheap fail-fast check for required headers |
| 8 | `HttpAttributesMiddleware` / path params | Extract path parameters needed by auth/guard middleware |
| 9 | `QueryParametersMiddleware` | Parse query params before business logic inspects them |
| 10 | `BodyParserMiddleware` | Body must be parsed before it can be validated |
| 11 | `BodyValidationMiddleware` / `ValidationMiddleware` | Must follow parser; rejects invalid payloads |
| 12 | `AuthenticationMiddleware` | Runs after all inputs are available |
| 13 | Auth guards / custom middlewares | Application-specific authorization checks |
| last | `ResponseWrapperMiddleware` | Runs `after` hook after the controller returns to wrap the response |

> **Tip:** `ProcessingMiddleware` can replace positions 8-10 (`HttpAttributesMiddleware` + `QueryParametersMiddleware` + `BodyParserMiddleware`) in a single middleware when you want a consolidated setup.

## Constructor Signatures

```typescript
// --- Error Handling ---
new ErrorHandlerMiddleware(options?: ErrorHandlerOptions)
errorHandler(options?: ErrorHandlerOptions)                          // factory

// --- Dependency Injection ---
new DependencyInjectionMiddleware(
  services: ServiceDefinition[],
  options?: { scope?: 'global' | 'local' }
)

// --- Body Parsing ---
new BodyParserMiddleware<TBody>(maxSize?: number)                    // default 1MB
bodyParser<TBody>(maxSize?: number)                                  // factory

// --- Body Validation ---
new BodyValidationMiddleware<TBody, TUser>(schema: ZodType<TBody>)
bodyValidatorMiddleware<TBody, TUser>(schema: ZodType<TBody>)        // factory

// --- Header Validation ---
new HeaderVariablesMiddleware(requiredHeaders: string[])
headerVariablesMiddleware(requiredHeaders: string[])                  // factory

// --- Query Parameters ---
new QueryParametersMiddleware(requiredParams?: string[])
queryParametersMiddleware(requiredParams?: string[])                  // factory

// --- Response Wrapping ---
new ResponseWrapperMiddleware(defaultStatusCode?: number)
responseWrapperMiddleware<T>()                                        // factory

// --- Authentication ---
new AuthenticationMiddleware<TUser>(
  tokenVerificationPort: CustomTokenVerificationPort<TUser>,
  options?: AuthenticationOptions
)
verifyAuthTokenMiddleware<TUser>(                                     // factory
  tokenVerificationPort: CustomTokenVerificationPort<TUser>,
  options?: AuthenticationOptions
)

// --- OpenTelemetry ---
new OpenTelemetryMiddleware(options?: OpenTelemetryOptions)
openTelemetry(options?: OpenTelemetryOptions)                         // factory

// --- Security Headers ---
new SecurityHeadersMiddleware(options?: SecurityHeadersOptions)
securityHeaders(options?: SecurityHeadersOptions)                     // factory
// Presets: SecurityPresets.STRICT | SecurityPresets.BALANCED | SecurityPresets.DEVELOPMENT

// --- Rate Limiting ---
new RateLimitingMiddleware(options?: RateLimitOptions)
rateLimiting(options?: RateLimitOptions)                              // factory
// Presets: RateLimitPresets.STRICT | .API | .AUTH | .PUBLIC | .DEVELOPMENT | .ENTERPRISE

// --- Security Audit ---
new SecurityAuditMiddleware(options?: SecurityAuditOptions)
securityAudit(options?: SecurityAuditOptions)                         // factory
// Presets: SecurityAuditPresets.COMPREHENSIVE | .SECURITY_ONLY | .DEVELOPMENT

// --- Processing (consolidated) ---
new ProcessingMiddleware(config?: ProcessingMiddlewareConfig)
createProcessingMiddleware.api()                                      // factory preset
createProcessingMiddleware.pubsub()                                   // factory preset
createProcessingMiddleware.lightweight()                              // factory preset
createProcessingMiddleware.complete()                                 // factory preset

// --- HTTP Attributes (path params, header validator, query validator) ---
new PathParametersMiddleware()
pathParameters()                                                      // factory
headerVariablesValidator(requiredHeaders: string[])                   // factory
validatedQueryParameters(schema: ZodSchema)                           // factory

// --- Generic Validation ---
new ValidationMiddleware(schema: ZodSchema)
validationMiddleware(schema: ZodSchema)                               // factory
```

## See Also

- [Middleware Ordering Guide](../../guides/middleware-ordering.md) -- detailed ordering rules and common pipeline recipes
- [Creating Custom Middlewares](../../guides/custom-middleware.md) -- implement `BaseMiddleware<TBody, TUser>` with `before`, `after`, and `onError` hooks
- [Pipeline Architecture](../../explanation/architecture.md) -- how the Handler orchestrates the middleware chain internally
