# Processing Middleware

Consolidated middleware for body parsing, query processing, and HTTP attribute extraction.

> **Related:** [Middleware Index](./INDEX.md) | [HTTP Attributes Middleware](./http-attributes.md)

## Purpose

The Processing Middleware replaces three separate middlewares (body parser, query parameters, HTTP attributes) with a single configurable middleware. It parses JSON and Pub/Sub message bodies, processes query parameters with type coercion, and extracts client attributes like IP address and user agent -- all in one `before` hook.

## When to Use

- Setting up request processing for API endpoints in a single middleware
- Parsing JSON bodies with size limits and async parsing for large payloads
- Decoding Google Cloud Pub/Sub base64-encoded messages
- Extracting client IP, user agent, and other request attributes

## Import

```typescript
import {
  ProcessingMiddleware,
  ProcessingMiddlewareConfig,
  BodyParserConfig,
  QueryProcessingConfig,
  AttributesConfig,
  createProcessingMiddleware,
} from '@noony-serverless/core';
```

## Constructor

### Class: `ProcessingMiddleware<TBody, TUser>`

```typescript
new ProcessingMiddleware(config?: ProcessingMiddlewareConfig)
```

### Factory Helpers: `createProcessingMiddleware`

| Factory | Description |
|---|---|
| `createProcessingMiddleware.api()` | JSON parsing (1MB), numbers/booleans in query, IP + user agent |
| `createProcessingMiddleware.pubsub()` | Pub/Sub support (2MB), async parsing, IP + timestamp |
| `createProcessingMiddleware.lightweight()` | Minimal parsing (64KB), no query coercion, no attributes |
| `createProcessingMiddleware.complete()` | All features enabled (5MB), all query coercion, all attributes, trust proxy |

## Configuration

### `ProcessingMiddlewareConfig`

| Option | Type | Default | Description |
|---|---|---|---|
| `parser` | `BodyParserConfig` | See below | Body parsing configuration |
| `query` | `QueryProcessingConfig` | See below | Query parameter processing |
| `attributes` | `AttributesConfig` | See below | HTTP attribute extraction |
| `skipProcessing` | `(context) => boolean` | -- | Skip all processing for certain requests |

### `BodyParserConfig`

| Option | Type | Default | Description |
|---|---|---|---|
| `maxSize` | `number` | `1048576` (1MB) | Maximum body size in bytes |
| `supportPubSub` | `boolean` | `true` | Decode Pub/Sub base64 messages |
| `allowEmptyBody` | `boolean` | `true` | Allow requests with no body |
| `customParser` | `(body: unknown) => unknown` | -- | Custom parsing function |
| `enableAsyncParsing` | `boolean` | `true` | Non-blocking JSON parse for large payloads |
| `asyncThreshold` | `number` | `10000` (10KB) | Size threshold for async parsing |

### `QueryProcessingConfig`

| Option | Type | Default | Description |
|---|---|---|---|
| `parseArrays` | `boolean` | `false` | Split comma-delimited values into arrays |
| `parseNumbers` | `boolean` | `false` | Convert numeric strings to numbers |
| `parseBooleans` | `boolean` | `false` | Convert `'true'`/`'false'` to booleans |
| `maxKeys` | `number` | `1000` | Maximum number of query parameters |
| `delimiter` | `string` | `'&'` | Query string delimiter |
| `arrayDelimiter` | `string` | `','` | Array value delimiter |
| `customParser` | `(query) => Record<string, unknown>` | -- | Custom query parser |

### `AttributesConfig`

| Option | Type | Default | Description |
|---|---|---|---|
| `extractIP` | `boolean` | `true` | Extract client IP to `req.ip` |
| `extractUserAgent` | `boolean` | `true` | Extract user agent to `req.userAgent` |
| `extractTimestamp` | `boolean` | `false` | Add request timestamp |
| `extractContentLength` | `boolean` | -- | Extract content length |
| `extractAcceptLanguage` | `boolean` | -- | Extract accept language |
| `extractReferer` | `boolean` | -- | Extract referer header |
| `customExtractors` | `Record<string, (req) => unknown>` | -- | Custom attribute extractors |
| `trustProxy` | `boolean` | `false` | Trust `X-Forwarded-For` / `X-Real-IP` headers |

## Usage

### Basic API setup

```typescript
const handler = new Handler()
  .use(createProcessingMiddleware.api())
  .handle(async (context) => {
    const body = context.req.parsedBody;
    const ip = context.req.ip;
    return { received: body, from: ip };
  });
```

### Full configuration

```typescript
const handler = new Handler()
  .use(new ProcessingMiddleware({
    parser: {
      maxSize: 1024 * 1024,
      supportPubSub: true,
      enableAsyncParsing: true,
    },
    query: {
      parseArrays: true,
      parseNumbers: true,
      parseBooleans: true,
      maxKeys: 100,
    },
    attributes: {
      extractIP: true,
      extractUserAgent: true,
      extractTimestamp: true,
      trustProxy: true,
    },
  }))
  .handle(async (context) => {
    return { message: 'Fully processed' };
  });
```

### Pub/Sub handler

```typescript
const handler = new Handler()
  .use(createProcessingMiddleware.pubsub())
  .handle(async (context) => {
    // context.req.parsedBody contains decoded Pub/Sub message data
    // context.req.pubsubMetadata contains publishTime, messageId, attributes
    return { processed: true };
  });
```

## Processing Order

1. **Attribute extraction** (lightweight) -- IP, user agent, etc.
2. **Query parameter processing** (moderate) -- coercion, array splitting
3. **Body parsing** (most expensive) -- JSON parse, Pub/Sub decode, size checks

## Error Behavior

| Condition | Error Thrown |
|---|---|
| Body exceeds `maxSize` | `TooLargeError` (413) |
| Invalid JSON body | `ValidationError` (400) |
| Empty body when `allowEmptyBody: false` | `ValidationError` (400) |
| Too many query parameters | `ValidationError` (400) |
| Invalid Pub/Sub base64 format | `ValidationError` (400) |

## See Also

- [HTTP Attributes Middleware](./http-attributes.md) -- individual path/header/query middlewares
- [Validation Middleware](./validation.md) -- Zod schema validation for parsed bodies
- [Error Classes Reference](../errors.md)
