# Custom Framework Adapters

How to create adapters for frameworks beyond the built-in GCP Cloud Functions, Express, and Fastify support. This guide uses Koa as an example, but the pattern applies to any HTTP framework (Hapi, NestJS, etc.).

## Overview

Noony's framework-agnostic design is built on two interfaces:

- **`GenericRequest<T>`** -- Normalized incoming request
- **`GenericResponse`** -- Normalized outgoing response

Any framework can integrate with Noony by adapting its native request/response objects to these interfaces, then calling `handler.executeGeneric()`.

```
Framework Request  -->  GenericRequest<T>  -->  Handler Pipeline  -->  GenericResponse  -->  Framework Response
```

## Step 1: Implement GenericRequest Adapter

Map all properties from the framework's request object to `GenericRequest<T>`:

```typescript
// src/adapters/koa.adapter.ts
import { GenericRequest, GenericResponse } from '@noony-serverless/core';
import { Context as KoaContext } from 'koa';

export function adaptKoaRequest<T = unknown>(
  koaContext: KoaContext
): GenericRequest<T> {
  return {
    method: koaContext.method,
    url: koaContext.url,
    path: koaContext.path,
    headers: koaContext.headers as Record<string, string | string[]>,
    query: koaContext.query as Record<string, string | string[]>,
    params: koaContext.params as Record<string, string>,
    body: koaContext.request.body as unknown,
    parsedBody: koaContext.request.body as T,  // Required for validation middleware
    ip: koaContext.ip,
    userAgent: koaContext.headers['user-agent'],
  };
}
```

### Required Properties

| Property | Type | Notes |
|----------|------|-------|
| `method` | `string` | HTTP method (GET, POST, etc.) |
| `url` | `string` | Full request URL |
| `path` | `string` | URL path without query string |
| `headers` | `Record<string, string \| string[]>` | Request headers |
| `query` | `Record<string, string \| string[]>` | Query parameters |
| `params` | `Record<string, string>` | Path parameters |
| `body` | `unknown` | Raw request body |
| `parsedBody` | `T` | Parsed body (set from framework's body parser) |

Setting `parsedBody` is critical. If your framework already parses the body (most do via middleware), assign it here. The `BodyValidationMiddleware` reads from `parsedBody`, not `body`.

## Step 2: Implement GenericResponse Adapter

Map all response methods to the framework's response API. All methods must be chainable (return `this`), and you must track `headersSent` to prevent double-send errors:

```typescript
export function adaptKoaResponse(koaContext: KoaContext): GenericResponse {
  let statusCode = 200;
  let headersSent = false;

  return {
    status(code: number): GenericResponse {
      statusCode = code;
      koaContext.status = code;
      return this;
    },

    json(data: unknown): GenericResponse {
      if (!headersSent) {
        koaContext.type = 'application/json';
        koaContext.body = data;
        headersSent = true;
      }
      return this;
    },

    send(data: unknown): GenericResponse {
      if (!headersSent) {
        koaContext.body = data;
        headersSent = true;
      }
      return this;
    },

    header(name: string, value: string): GenericResponse {
      koaContext.set(name, value);
      return this;
    },

    headers(headers: Record<string, string>): GenericResponse {
      Object.entries(headers).forEach(([key, val]) => {
        koaContext.set(key, val);
      });
      return this;
    },

    end(): void {
      headersSent = true;
    },

    get statusCode(): number {
      return statusCode;
    },

    get headersSent(): boolean {
      return headersSent;
    },
  };
}
```

### Required Methods and Properties

| Member | Type | Notes |
|--------|------|-------|
| `status(code)` | Method | Set HTTP status code, return `this` |
| `json(data)` | Method | Send JSON response, return `this` |
| `send(data)` | Method | Send raw response, return `this` |
| `header(name, value)` | Method | Set single header, return `this` |
| `headers(headers)` | Method | Set multiple headers, return `this` |
| `end()` | Method | End response (mark as sent) |
| `statusCode` | Read-only property | Current status code |
| `headersSent` | Read-only property | Whether response was already sent |

## Step 3: Create Handler Wrapper

The wrapper connects your framework's routing to Noony's handler pipeline:

```typescript
// src/adapters/koa-handler.wrapper.ts
import { Handler } from '@noony-serverless/core';
import { Context as KoaContext } from 'koa';
import { adaptKoaRequest, adaptKoaResponse } from './koa.adapter';

export function createKoaHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies?: () => Promise<void>
) {
  return async (koaContext: KoaContext) => {
    try {
      if (initializeDependencies) {
        await initializeDependencies();
      }

      const genericReq = adaptKoaRequest(koaContext);
      const genericRes = adaptKoaResponse(koaContext);

      await noonyHandler.executeGeneric(genericReq, genericRes);
    } catch (error) {
      // RESPONSE_SENT is expected when response was already sent
      if (error instanceof Error && error.message === 'RESPONSE_SENT') {
        return;
      }

      console.error(`[${functionName}] Unexpected error`, error);

      if (!koaContext.res.headersSent) {
        koaContext.status = 500;
        koaContext.body = {
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred',
          },
        };
      }
    }
  };
}
```

Key points:

- Use `executeGeneric()`, not `execute()`. The `execute()` method is for native GCP Cloud Functions req/res objects.
- Handle `RESPONSE_SENT` errors gracefully. This error indicates the response was already sent by a middleware, which is normal behavior.
- Check `headersSent` before sending error responses to avoid double-send.

## Step 4: Integrate with Framework Server

```typescript
// src/server.ts
import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';
import { createKoaHandler } from './adapters/koa-handler.wrapper';
import { createProductHandler } from './handlers/product.handlers';

const app = new Koa();
const router = new Router();

app.use(bodyParser());

router.post(
  '/api/products',
  createKoaHandler(createProductHandler, 'createProduct')
);

app.use(router.routes());

app.listen(3000, () => {
  console.log('Listening on http://localhost:3000');
});
```

## Testing Adapters

Test both the request and response adaptation independently:

```typescript
describe('Koa Adapter', () => {
  it('should adapt Koa context to GenericRequest', () => {
    const mockKoaCtx = {
      method: 'POST',
      url: '/api/products',
      path: '/api/products',
      headers: { 'content-type': 'application/json' },
      query: {},
      params: {},
      request: {
        body: { name: 'Product A', price: 99.99, category: 'electronics' },
      },
      ip: '127.0.0.1',
    };

    const genericReq = adaptKoaRequest(mockKoaCtx);

    expect(genericReq.method).toBe('POST');
    expect(genericReq.parsedBody.name).toBe('Product A');
    expect(genericReq.path).toBe('/api/products');
  });

  it('should handle responses with headersSent tracking', () => {
    const mockKoaCtx = {
      status: 200,
      body: null,
      set: jest.fn(),
    };

    const genericRes = adaptKoaResponse(mockKoaCtx as any);

    genericRes.status(201).json({ success: true });

    expect(mockKoaCtx.status).toBe(201);
    expect(mockKoaCtx.body).toEqual({ success: true });
    expect(genericRes.headersSent).toBe(true);

    // Second call should be ignored
    genericRes.json({ overwrite: true });
    expect(mockKoaCtx.body).toEqual({ success: true }); // unchanged
  });
});
```

## Adapter Checklist

Before considering your adapter complete, verify:

- [ ] `GenericRequest<T>` -- all properties implemented
- [ ] `parsedBody` set from framework's parsed body
- [ ] `GenericResponse` -- all methods implemented
- [ ] All response methods return `this` (chainable)
- [ ] `headersSent` tracked and checked before sending
- [ ] `RESPONSE_SENT` errors handled in wrapper
- [ ] `statusCode` and `headersSent` are read-only getters
- [ ] Framework request is not mutated during adaptation
- [ ] Unit tests cover request and response adaptation

## Common Mistakes

### Not Setting parsedBody

```typescript
// Wrong -- BodyValidationMiddleware won't work
return {
  body: koaContext.request.body,
  // Missing parsedBody!
};

// Correct -- validation middleware reads from parsedBody
return {
  body: koaContext.request.body,
  parsedBody: koaContext.request.body as T,
};
```

### Missing headersSent Guard

```typescript
// Wrong -- can send response twice
json(data: unknown): GenericResponse {
  koaContext.body = data;
  return this;
}

// Correct -- prevents double-send
json(data: unknown): GenericResponse {
  if (!headersSent) {
    koaContext.body = data;
    headersSent = true;
  }
  return this;
}
```

### Using execute() Instead of executeGeneric()

```typescript
// Wrong -- execute() expects native GCP/Express req/res
await noonyHandler.execute(koaContext.req, koaContext.res);

// Correct -- executeGeneric() accepts adapted interfaces
await noonyHandler.executeGeneric(genericReq, genericRes);
```

## Related

- [Architecture Explanation](../explanation/architecture.md) -- How Handler, Context, and middleware pipeline work
- [API Reference](../reference/api.md) -- Full GenericRequest and GenericResponse interface definitions
- [Middleware Ordering Guide](./middleware-ordering.md) -- Correct middleware chain setup
