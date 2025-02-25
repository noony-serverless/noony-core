# Request Handler with Body Parser

A type-safe request body parser for Google Cloud Functions and Firebase that automatically handles JSON and Pub/Sub message decoding.

## Features

- Automatic Pub/Sub message decoding from base64
- JSON string parsing
- Type-safe request handling
- Supports both regular HTTP and Pub/Sub messages
- Seamless integration with Handler framework

## Installation

```bash
npm install @noony/core
```

## Basic Usage

### Regular HTTP Requests

```typescript
import { Handler, bodyParser } from '@noony/core';

interface UserPayload {
  name: string;
  email: string;
}

const processUserRequest = new Handler()
  .use(errorHandler())
  .use(bodyParser<UserPayload>())
  .handle(async (context) => {
    const { parsedBody } = context.req;
    // parsedBody is typed as UserPayload
    console.log(parsedBody.name);
  });
```

### Pub/Sub Messages

```typescript
interface PubSubPayload {
  action: string;
  data: Record<string, unknown>;
}

const processPubSubMessage = new Handler()
  .use(errorHandler())
  .use(bodyParser<PubSubPayload>()) // Automatically decodes base64
  .handle(async (context) => {
    const { parsedBody } = context.req;
    // parsedBody is decoded and typed as PubSubPayload
  });
```

## Type Safety

```typescript
interface CustomPayload {
  id: string;
  metadata: Record<string, unknown>;
}

const customHandler = new Handler()
  .use(bodyParser<CustomPayload>())
  .handle(async (context) => {
    const { parsedBody } = context.req; // Type: CustomPayload
    const { id, metadata } = parsedBody; // Fully typed
  });
```

## Error Handling

The parser throws validation errors for:
- Invalid JSON format
- Invalid Pub/Sub message format
- Base64 decoding failures

```typescript
const handler = new Handler()
  .use(errorHandler())
  .use(bodyParser())
  .handle(async (context) => {
    try {
      const { parsedBody } = context.req;
      // Use parsed body
    } catch (error) {
      // Handle parsing errors
    }
  });
```

## Testing

```typescript
describe('Body Parser', () => {
  it('parses JSON body', async () => {
    const handler = new Handler()
      .use(bodyParser<TestType>())
      .handle(async (context) => {
        // Test logic
      });

    const req = { body: JSON.stringify({ test: 'data' }) };
    const res = {};
    
    await handler.execute(req, res);
  });
});
```

## Best Practices

1. **Always specify types**
   ```typescript
   bodyParser<YourType>()
   ```

2. **Use with error handler**
   ```typescript
   .use(errorHandler())
   .use(bodyParser())
   ```

3. **Handle both content types**
   ```typescript
   // Handler will automatically detect and parse
   // both JSON and Pub/Sub messages
   ```
