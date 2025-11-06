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
