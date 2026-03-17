# Security Headers Middleware

Applies OWASP-recommended security headers and CORS configuration to responses.

> **Related:** [Middleware Index](./INDEX.md) | [Security Audit Middleware](./security-audit.md)

## Purpose

The Security Headers Middleware sets a comprehensive suite of HTTP security headers on every response, including Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, and cross-origin policies. It also handles CORS preflight and actual request headers, with support for wildcard origin matching.

## When to Use

- Hardening API responses against XSS, clickjacking, and MIME-type attacks
- Configuring CORS for browser-based clients
- Applying consistent security headers across all endpoints

## Import

```typescript
import {
  SecurityHeadersMiddleware,
  securityHeaders,
  SecurityHeadersOptions,
  SecurityPresets,
} from '@noony-serverless/core';
```

## Constructor

### Class: `SecurityHeadersMiddleware<TBody, TUser>`

```typescript
new SecurityHeadersMiddleware(options?: SecurityHeadersOptions)
```

### Factory: `securityHeaders()`

```typescript
securityHeaders(options?: SecurityHeadersOptions): BaseMiddleware
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `contentSecurityPolicy` | `string` | `"default-src 'self'; script-src 'self'; ..."` | Content-Security-Policy directive |
| `hstsMaxAge` | `number` | `31536000` (1 year) | Strict-Transport-Security max-age in seconds |
| `hstsIncludeSubDomains` | `boolean` | `true` | Include subdomains in HSTS |
| `frameOptions` | `'DENY' \| 'SAMEORIGIN' \| 'ALLOW-FROM'` | `'DENY'` | X-Frame-Options value |
| `contentTypeOptions` | `'nosniff'` | `'nosniff'` | X-Content-Type-Options value |
| `referrerPolicy` | `string` | `'strict-origin-when-cross-origin'` | Referrer-Policy value |
| `permissionsPolicy` | `string` | `'geolocation=(), microphone=(), camera=(), ...'` | Permissions-Policy directive |
| `crossOriginEmbedderPolicy` | `string` | `'require-corp'` | Cross-Origin-Embedder-Policy value |
| `crossOriginOpenerPolicy` | `string` | `'same-origin'` | Cross-Origin-Opener-Policy value |
| `crossOriginResourcePolicy` | `string` | `'same-origin'` | Cross-Origin-Resource-Policy value |
| `cors` | `CORSConfig` (see below) | -- | CORS configuration object |
| `removeServerHeader` | `boolean` | `true` | Remove `Server` header |
| `removePoweredBy` | `boolean` | `true` | Remove `X-Powered-By` header |

### CORS Configuration

| Field | Type | Description |
|---|---|---|
| `origin` | `string \| string[] \| boolean` | Allowed origins (supports `*` wildcards in array entries) |
| `methods` | `string[]` | Allowed HTTP methods |
| `allowedHeaders` | `string[]` | Allowed request headers |
| `exposedHeaders` | `string[]` | Headers exposed to the browser |
| `credentials` | `boolean` | Allow credentials |
| `maxAge` | `number` | Preflight cache duration in seconds |

## Presets

| Preset | Description |
|---|---|
| `SecurityPresets.STRICT` | CSP `default-src 'none'`, 2-year HSTS, frame-ancestors `'none'` |
| `SecurityPresets.BALANCED` | CSP allows `'unsafe-inline'` styles, 1-year HSTS, `SAMEORIGIN` frames |
| `SecurityPresets.DEVELOPMENT` | Permissive CSP, HSTS disabled, CORS `origin: true` with all methods |

## Usage

### Basic

```typescript
const handler = new Handler()
  .use(new SecurityHeadersMiddleware())
  .handle(async (context) => {
    return { data: 'secured' };
  });
```

### With CORS

```typescript
const handler = new Handler()
  .use(securityHeaders({
    cors: {
      origin: ['https://app.example.com', 'https://*.staging.example.com'],
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
      maxAge: 86400,
    },
  }))
  .handle(async (context) => {
    return { data: 'cors-enabled' };
  });
```

### Using presets

```typescript
// Production
.use(securityHeaders(SecurityPresets.STRICT))

// Development
.use(securityHeaders(SecurityPresets.DEVELOPMENT))
```

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | Sets all security headers on `context.res`. For CORS preflight (`OPTIONS` with request method/headers), responds with `204` and returns early. |
| `after` | -- |
| `onError` | -- |

## See Also

- [Security Audit Middleware](./security-audit.md)
- [Rate Limiting Middleware](./rate-limiting.md)
- [Authentication Middleware](./authentication.md)
