# Security Audit Middleware

Logs security events, detects injection attempts, and tracks anomalous client behavior.

> **Related:** [Middleware Index](./INDEX.md) | [Security Headers Middleware](./security-headers.md)

## Purpose

The Security Audit Middleware provides comprehensive security monitoring by logging incoming requests and outgoing responses, scanning URLs and bodies for injection patterns (SQL injection, XSS, path traversal, command injection), and tracking per-client event histories to detect anomalies like repeated authentication failures or high rates of suspicious activity.

## When to Use

- Monitoring production APIs for security threats
- Detecting and logging injection attempts (SQLi, XSS, path traversal)
- Tracking authentication failures and rate limit violations per client
- Feeding security events to external SIEM or alerting systems

## Import

```typescript
import {
  SecurityAuditMiddleware,
  securityAudit,
  SecurityAuditOptions,
  SecurityAuditPresets,
  SecurityEvent,
  SecurityEventType,
  SecuritySeverity,
} from '@noony-serverless/core';
```

## Constructor

### Class: `SecurityAuditMiddleware<TBody, TUser>`

```typescript
new SecurityAuditMiddleware(options?: SecurityAuditOptions)
```

### Factory: `securityAudit()`

```typescript
securityAudit(options?: SecurityAuditOptions): BaseMiddleware
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `logRequests` | `boolean` | `false` | Log incoming request details |
| `logResponses` | `boolean` | `false` | Log outgoing response details |
| `logBodies` | `boolean` | `false` | Include request/response bodies in logs (be careful with sensitive data) |
| `maxBodyLogSize` | `number` | `1024` | Maximum body size in bytes to include in logs |
| `excludeHeaders` | `string[]` | `['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token']` | Headers to redact from logs (merged with defaults) |
| `onSecurityEvent` | `(event: SecurityEvent) => Promise<void> \| void` | -- | Custom handler for security events (e.g., send to SIEM) |
| `enableAnomalyDetection` | `boolean` | `true` | Track client events and detect anomalous patterns |
| `suspiciousPatterns` | `SuspiciousPatterns` | Built-in patterns | Custom regex patterns for injection detection |

## Presets

| Preset | Description |
|---|---|
| `SecurityAuditPresets.COMPREHENSIVE` | Request + response logging, anomaly detection, no body logging |
| `SecurityAuditPresets.SECURITY_ONLY` | No request/response logging, anomaly detection only |
| `SecurityAuditPresets.DEVELOPMENT` | Full logging including bodies, no anomaly detection |

## Security Event Types

| Type | Description |
|---|---|
| `SUSPICIOUS_REQUEST` | General suspicious activity |
| `AUTHENTICATION_FAILURE` | Failed authentication (401) |
| `AUTHORIZATION_FAILURE` | Failed authorization (403) |
| `RATE_LIMIT_EXCEEDED` | Rate limit hit (429) |
| `INVALID_INPUT` | Bad request (400) |
| `TOKEN_MANIPULATION` | Token tampering detected |
| `UNUSUAL_BEHAVIOR` | Anomaly detection alert |
| `SECURITY_HEADER_VIOLATION` | Security header issue |
| `INJECTION_ATTEMPT` | SQL/XSS/path traversal/command injection detected |
| `MALFORMED_REQUEST` | Malformed request structure |

## Severity Levels

`LOW` | `MEDIUM` | `HIGH` | `CRITICAL`

## `SecurityEvent` Interface

```typescript
interface SecurityEvent {
  type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: string;
  requestId: string;
  clientIP: string;
  userAgent?: string;
  userId?: string;
  endpoint: string;
  method: string;
  details: Record<string, unknown>;
}
```

## Usage

### Basic

```typescript
const handler = new Handler()
  .use(new SecurityAuditMiddleware())
  .handle(async (context) => {
    return { data: 'monitored' };
  });
```

### With SIEM integration

```typescript
const handler = new Handler()
  .use(securityAudit({
    logRequests: true,
    enableAnomalyDetection: true,
    onSecurityEvent: async (event) => {
      if (event.severity === 'CRITICAL') {
        await sendToSIEM(event);
        await notifySecurityTeam(event);
      }
    },
  }))
  .handle(async (context) => {
    return { data: 'audited' };
  });
```

### Using presets

```typescript
// Production
.use(securityAudit(SecurityAuditPresets.COMPREHENSIVE))

// Development
.use(securityAudit(SecurityAuditPresets.DEVELOPMENT))
```

## Middleware Lifecycle

| Hook | Behavior |
|---|---|
| `before` | Stores start time and client info, logs request if enabled, scans URL and body for injection patterns, runs anomaly detection |
| `after` | Calculates request duration, logs response if enabled |
| `onError` | Classifies error by HTTP status (401 -> `AUTHENTICATION_FAILURE`, 403 -> `AUTHORIZATION_FAILURE`, etc.), logs security event |

## Anomaly Detection

The built-in `SecurityEventTracker` monitors per-client events over a 1-hour sliding window:

| Anomaly | Trigger | Severity |
|---|---|---|
| Multiple auth failures | 5+ `AUTHENTICATION_FAILURE` events in 10 minutes | HIGH |
| High suspicious activity | 10+ injection/malformed/suspicious events in 10 minutes | CRITICAL |

## Built-in Injection Patterns

| Category | Examples Detected |
|---|---|
| SQL Injection | `SELECT`, `UNION`, `DROP`, encoded quotes |
| XSS | `<script>`, `javascript:`, `on*=` event handlers, `<iframe>` |
| Path Traversal | `../`, URL-encoded variants (`%2e%2e`) |
| Command Injection | Shell metacharacters (`;`, `|`, backticks), common commands |

## See Also

- [Security Headers Middleware](./security-headers.md)
- [Rate Limiting Middleware](./rate-limiting.md)
- [Authentication Middleware](./authentication.md)
- [Error Classes Reference](../errors.md)
