# Pub/Sub Workflows

How Noony handles Google Cloud Pub/Sub messages through Cloud Functions, including body parsing, trace propagation, and handler setup.

## How Pub/Sub Works with Noony

Google Cloud Pub/Sub delivers messages to Cloud Functions as HTTP POST requests. The message payload arrives as a JSON envelope with a base64-encoded `data` field:

```json
{
  "message": {
    "data": "eyJ1c2VySWQiOiAiMTIzIiwgImFjdGlvbiI6ICJDUkVBVEUifQ==",
    "messageId": "123456789",
    "publishTime": "2024-01-15T12:00:00.000Z",
    "attributes": {
      "type": "user.created",
      "traceparent": "00-abc123-def456-01",
      "tracestate": "vendor=value"
    }
  }
}
```

Noony automatically detects this format and decodes the base64 data into your typed payload.

## Basic Pub/Sub Handler

```typescript
import { http } from '@google-cloud/functions-framework';
import { z } from 'zod';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyParserMiddleware,
  BodyValidationMiddleware,
} from '@noony-serverless/core';

// Define message schema
const messageSchema = z.object({
  userId: z.string().uuid(),
  action: z.enum(['CREATE', 'UPDATE', 'DELETE']),
  payload: z.record(z.unknown()),
});

type PubSubPayload = z.infer<typeof messageSchema>;

// Create handler
const pubsubHandler = new Handler<PubSubPayload, unknown>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())       // Decodes base64 Pub/Sub data
  .use(new BodyValidationMiddleware(messageSchema))
  .handle(async (context) => {
    const { userId, action, payload } = context.req.validatedBody!;

    switch (action) {
      case 'CREATE':
        await handleCreate(userId, payload);
        break;
      case 'UPDATE':
        await handleUpdate(userId, payload);
        break;
      case 'DELETE':
        await handleDelete(userId, payload);
        break;
    }

    context.res.status(200).json({ success: true });
  });

// Export Cloud Function
export const processMessage = http('processMessage', (req, res) => {
  return pubsubHandler.execute(req, res);
});
```

## Body Parsing for Pub/Sub

The `BodyParserMiddleware` automatically handles Pub/Sub messages:

1. **Detection** -- Checks if the request body matches the Pub/Sub envelope structure (`body.message.data` exists)
2. **Base64 validation** -- Validates the base64 format with strict security checks (alphabet, padding, length)
3. **Decoding** -- Decodes base64 data to UTF-8 string using `Buffer.from(data, 'base64')`
4. **JSON parsing** -- Parses the decoded string into a typed object
5. **Assignment** -- Sets the result on `context.req.parsedBody`

### Size Limits

The body parser enforces size limits to prevent DoS attacks:

| Limit | Default | Purpose |
|-------|---------|---------|
| JSON body | 1 MB | Maximum raw JSON payload |
| Base64 data | 1.5 MB | Accounts for base64 encoding overhead |

Configure custom limits:

```typescript
// 2 MB limit for larger messages
.use(new BodyParserMiddleware(2 * 1024 * 1024))

// Or using the function form (filters by HTTP method)
.use(bodyParser<PubSubPayload>(2 * 1024 * 1024))
```

### Performance Optimization

The parser uses async processing for large payloads to avoid blocking the event loop:

- Payloads under 10 KB: synchronous `JSON.parse` (fastest path)
- Payloads under 1 KB base64: synchronous `Buffer.from` decode
- Larger payloads: `setImmediate`-based async parsing

### Class vs Function Form

| Form | Use Case | HTTP Method Filtering |
|------|----------|-----------------------|
| `new BodyParserMiddleware()` | Pub/Sub handlers (no method check) | No -- parses all requests |
| `bodyParser()` | HTTP API handlers | Yes -- only POST, PUT, PATCH |

For Pub/Sub handlers, use `BodyParserMiddleware` (class form) since Pub/Sub messages may not have an HTTP method set.

## Distributed Tracing Through Pub/Sub

Noony supports W3C Trace Context propagation through Pub/Sub messages, enabling end-to-end distributed tracing across publishers and subscribers.

### How It Works

```
Publisher Service              Pub/Sub              Subscriber Service
     |                           |                        |
     | injectTraceContext()      |                        |
     |------ message + -------->|                        |
     |       traceparent        |                        |
     |       tracestate         |--- deliver message --->|
     |                           |                        |
     |                           |   extractTraceContext() |
     |                           |   (via middleware)      |
     |                           |                        |
     |<---------- linked trace spans across services ---->|
```

### Publishing with Trace Context

Use `injectTraceContext()` to propagate the current span's trace context into Pub/Sub message attributes:

```typescript
import { injectTraceContext } from '@noony-serverless/core';

// Inside a handler or middleware with active telemetry
const message = {
  data: Buffer.from(JSON.stringify({ userId: '123' })).toString('base64'),
  attributes: {
    type: 'user.created',
  },
};

// Inject trace context from the current span
const tracedMessage = injectTraceContext(message, context);
await pubsub.topic('users').publish(tracedMessage);

// tracedMessage.attributes now includes:
// {
//   type: 'user.created',
//   traceparent: '00-<traceId>-<spanId>-01',
//   tracestate: '<vendor-specific>'
// }
```

You can also call `injectTraceContext(message)` without the context parameter. In that case, it uses the active OpenTelemetry span from the current execution context.

### Consuming with Trace Context

The `OpenTelemetryMiddleware` automatically extracts trace context from incoming Pub/Sub messages when `propagatePubSubTraces` is enabled (default: `true`):

```typescript
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyParserMiddleware,
  OpenTelemetryMiddleware,
  BodyValidationMiddleware,
} from '@noony-serverless/core';

const handler = new Handler<PubSubPayload, unknown>()
  .use(new ErrorHandlerMiddleware())
  .use(new OpenTelemetryMiddleware({
    propagatePubSubTraces: true,  // default
  }))
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(messageSchema))
  .handle(async (context) => {
    // The span created here is linked to the publisher's trace
    const { userId, action } = context.req.validatedBody!;
    // ...
  });
```

The middleware performs these steps:

1. Detects if the request body is a Pub/Sub message using `isPubSubMessage()`
2. Extracts `traceparent` and `tracestate` from `message.attributes`
3. Creates a parent context using `propagation.extract()` from the OpenTelemetry API
4. Creates a child span linked to the publisher's trace
5. Adds `messaging.system: 'pubsub'` and `messaging.operation: 'process'` attributes

### Trace Context Utilities

| Function | Purpose |
|----------|---------|
| `isPubSubMessage(body)` | Type guard to check if a request body is a Pub/Sub envelope |
| `extractTraceContext(message)` | Extract W3C Trace Context (`traceparent`, `tracestate`) from message attributes |
| `injectTraceContext(message, context?)` | Inject current span's trace context into message attributes for publishing |
| `createParentContext(traceContext)` | Internal utility to create a carrier object for OpenTelemetry propagation |

## Deployment

### Cloud Functions

```bash
gcloud functions deploy processMessage \
  --runtime nodejs20 \
  --trigger-topic my-topic \
  --entry-point processMessage
```

### Cloud Functions with Tracing

```bash
gcloud functions deploy processMessage \
  --runtime nodejs20 \
  --trigger-topic my-topic \
  --entry-point processMessage \
  --set-env-vars OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector:4318/v1/traces,SERVICE_NAME=my-subscriber
```

## Common Patterns

### Multi-Event Pub/Sub Handler

```typescript
const eventSchema = z.discriminatedUnion('eventType', [
  z.object({
    eventType: z.literal('user.created'),
    userId: z.string(),
    email: z.string().email(),
  }),
  z.object({
    eventType: z.literal('user.deleted'),
    userId: z.string(),
  }),
]);

type EventPayload = z.infer<typeof eventSchema>;

const eventHandler = new Handler<EventPayload, unknown>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(eventSchema))
  .handle(async (context) => {
    const event = context.req.validatedBody!;

    switch (event.eventType) {
      case 'user.created':
        await sendWelcomeEmail(event.email);
        break;
      case 'user.deleted':
        await cleanupUserData(event.userId);
        break;
    }

    context.res.status(200).json({ processed: true });
  });
```

### Pub/Sub with Dependency Injection

```typescript
const handler = new Handler<PubSubPayload, unknown>()
  .use(new ErrorHandlerMiddleware())
  .use(new OpenTelemetryMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(messageSchema))
  .use(new DependencyInjectionMiddleware())
  .handle(async (context) => {
    const userService = getService<UserService>(context, 'userService');
    const { userId, action } = context.req.validatedBody!;

    await userService.processAction(userId, action);
    context.res.status(200).json({ success: true });
  });
```

## Related

- [Body Parser Middleware Reference](../reference/middlewares/body-parser.md) -- Full API and configuration options
- [Telemetry Reference](../reference/telemetry.md) -- OpenTelemetry setup and provider configuration
- [Error Handling Guide](./error-handling.md) -- How errors are handled in Pub/Sub context
