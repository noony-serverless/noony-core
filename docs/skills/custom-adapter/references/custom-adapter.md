# Resource: Custom Framework Adapter

## Complete Koa Adapter Example

Building adapters for unsupported frameworks (Koa, Hapi, NestJS, Express.js with native types) by implementing `GenericRequest<T>` and `GenericResponse` interfaces.

### Step 1: Define Adapter Interfaces

```typescript
// src/adapters/koa.adapter.ts
import { GenericRequest, GenericResponse } from '@noony-serverless/core';
import { Context as KoaContext } from 'koa';

/**
 * Adapt Koa's context to Noony's GenericRequest interface
 */
export function adaptKoaRequest<T = unknown>(koaContext: KoaContext): GenericRequest<T> {
  return {
    method: koaContext.method,
    url: koaContext.url,
    path: koaContext.path,
    headers: koaContext.headers as Record<string, string | string[]>,
    query: koaContext.query as Record<string, string | string[]>,
    params: koaContext.params as Record<string, string>,
    body: koaContext.request.body as unknown,
    parsedBody: koaContext.request.body as T,  // Assume parsed by middleware
    ip: koaContext.ip,
    userAgent: koaContext.headers['user-agent']
  };
}

/**
 * Adapt Noony's GenericResponse to Koa's context.response
 */
export function adaptKoaResponse(koaContext: KoaContext): GenericResponse {
  let statusCode = 200;
  let headersSent = false;

  return {
    status: function(code: number): GenericResponse {
      statusCode = code;
      koaContext.status = code;
      return this;
    },

    json: function(data: unknown): GenericResponse {
      if (!headersSent) {
        koaContext.type = 'application/json';
        koaContext.body = data;
        headersSent = true;
      }
      return this;
    },

    send: function(data: unknown): GenericResponse {
      if (!headersSent) {
        koaContext.body = data;
        headersSent = true;
      }
      return this;
    },

    header: function(name: string, value: string): GenericResponse {
      koaContext.set(name, value);
      return this;
    },

    headers: function(headers: Record<string, string>): GenericResponse {
      Object.entries(headers).forEach(([key, val]) => {
        koaContext.set(key, val);
      });
      return this;
    },

    end: function(): void {
      headersSent = true;
    },

    get statusCode(): number {
      return statusCode;
    },

    get headersSent(): boolean {
      return headersSent;
    }
  };
}
```

### Step 2: Handler Definition

```typescript
// src/handlers/product.handlers.ts
import { z } from 'zod';
import { Handler, Context } from '@noony-serverless/core';
import {
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  ResponseWrapperMiddleware
} from '@noony-serverless/core';

const createProductSchema = z.object({
  name: z.string().min(1),
  price: z.number().min(0),
  category: z.string()
});

type CreateProductRequest = z.infer<typeof createProductSchema>;

interface AuthUser {
  id: string;
  role: 'admin' | 'user';
}

export const createProductHandler = new Handler<CreateProductRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateProductRequest, AuthUser>())
  .use(new BodyValidationMiddleware<CreateProductRequest, AuthUser>(createProductSchema))
  .use(new ResponseWrapperMiddleware<CreateProductRequest, AuthUser>())
  .handle(async (context: Context<CreateProductRequest, AuthUser>) => {
    const { name, price, category } = context.req.validatedBody!;

    const product = await productService.create({
      name,
      price,
      category,
      createdBy: context.user?.id
    });

    return { data: product };
  });
```

### Step 3: Koa Route Handler Wrapper

```typescript
// src/adapters/koa-handler.wrapper.ts
import { Handler } from '@noony-serverless/core';
import { Context as KoaContext } from 'koa';
import { adaptKoaRequest, adaptKoaResponse } from './koa.adapter';

/**
 * Wraps Noony handler for use with Koa routing
 */
export function createKoaHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies?: () => Promise<void>
) {
  return async (koaContext: KoaContext) => {
    try {
      // Initialize dependencies if provided
      if (initializeDependencies) {
        await initializeDependencies();
      }

      // Adapt Koa context to Noony interfaces
      const genericReq = adaptKoaRequest(koaContext);
      const genericRes = adaptKoaResponse(koaContext);

      // Execute handler
      await noonyHandler.executeGeneric(genericReq, genericRes);
    } catch (error) {
      // Handle errors gracefully
      if (error instanceof Error && error.message === 'RESPONSE_SENT') {
        // Response already sent, ignore
        return;
      }

      // Log unexpected errors
      console.error(`[${functionName}] Unexpected error`, error);

      // Send error response if not already sent
      if (!koaContext.res.headersSent) {
        koaContext.status = 500;
        koaContext.body = {
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred'
          }
        };
      }
    }
  };
}
```

### Step 4: Koa Server Integration

```typescript
// src/server.ts
import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';
import { createKoaHandler } from './adapters/koa-handler.wrapper';
import { createProductHandler } from './handlers/product.handlers';
import { initializeDependencies, cleanup } from './core/initialization';

const app = new Koa();
const router = new Router();

// Body parsing middleware
app.use(bodyParser());

// Initialize dependencies on server startup
app.on('server', async (server) => {
  try {
    await initializeDependencies();
    console.log('[Server] Dependencies initialized');
  } catch (error) {
    console.error('[Server] Initialization failed', error);
    process.exit(1);
  }
});

// Register routes
router.post('/api/products',
  createKoaHandler(createProductHandler, 'createProduct', () => Promise.resolve())
);

app.use(router.routes());

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[Server] SIGTERM received, shutting down...');
  await cleanup();
  process.exit(0);
});

// Start server
app.listen(3000, () => {
  console.log('[Server] Listening on http://localhost:3000');
});
```

## Testing the Adapter

```typescript
// src/adapters/koa.adapter.test.ts
import { adaptKoaRequest, adaptKoaResponse } from './koa.adapter';
import { createKoaHandler } from './koa-handler.wrapper';
import { createProductHandler } from '../handlers/product.handlers';

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
        body: { name: 'Product A', price: 99.99, category: 'electronics' }
      },
      ip: '127.0.0.1'
    };

    const genericReq = adaptKoaRequest(mockKoaCtx);

    expect(genericReq.method).toBe('POST');
    expect(genericReq.parsedBody.name).toBe('Product A');
    expect(genericReq.path).toBe('/api/products');
  });

  it('should handle responses correctly', async () => {
    const mockKoaCtx = {
      method: 'POST',
      url: '/api/products',
      status: 200,
      body: null,
      headers: {},
      set: jest.fn(),
      request: { body: { name: 'Test', price: 10, category: 'test' } },
      res: { headersSent: false }
    };

    const genericRes = adaptKoaResponse(mockKoaCtx as any);

    genericRes.status(201).json({ success: true });

    expect(mockKoaCtx.status).toBe(201);
    expect(mockKoaCtx.body).toEqual({ success: true });
  });

  it('should handle handler execution via Koa wrapper', async () => {
    const mockKoaCtx = {
      method: 'POST',
      url: '/api/products',
      status: 200,
      body: null,
      headers: {},
      set: jest.fn(),
      path: '/api/products',
      query: {},
      params: {},
      request: {
        body: { name: 'Test Product', price: 50, category: 'test' }
      },
      ip: '127.0.0.1',
      res: { headersSent: false }
    };

    const handler = createKoaHandler(createProductHandler, 'createProduct');
    await handler(mockKoaCtx);

    // Response should be wrapped by ResponseWrapperMiddleware
    expect(mockKoaCtx.status).toBe(200);
    expect(mockKoaCtx.body.success).toBe(true);
  });
});
```

## Adapter Checklist

- [ ] Implements `GenericRequest<T>` interface completely
- [ ] Implements `GenericResponse` interface completely
- [ ] Preserves all headers from framework request
- [ ] Handles query parameters correctly (string or string[])
- [ ] Handles path parameters (`:id` style extracted)
- [ ] Sets `parsedBody` from framework's parsed body
- [ ] Prevents double-send via `headersSent` tracking
- [ ] Handles `RESPONSE_SENT` errors gracefully
- [ ] Supports method chaining on response methods
- [ ] Has `status()`, `json()`, `send()`, `header()`, `headers()`, `end()` methods
- [ ] Read-only properties: `statusCode`, `headersSent`
- [ ] Tested with unit tests for both request and response adaptation

## Common Gotchas

### ❌ Forgetting to Track headersSent

```typescript
// WRONG - Can send twice
json: function(data: unknown): GenericResponse {
  koaContext.body = data;  // No check
  return this;
}
```

### ✅ Correct: Check Before Sending

```typescript
// CORRECT - Prevents double-send
json: function(data: unknown): GenericResponse {
  if (!headersSent) {
    koaContext.body = data;
    headersSent = true;
  }
  return this;
}
```

### ❌ Not Setting parsedBody

```typescript
// WRONG - BodyValidationMiddleware won't work
return {
  // Missing parsedBody
  body: koaContext.request.body
};
```

### ✅ Correct: Set Parsed Body

```typescript
// CORRECT - Validation works
return {
  body: koaContext.request.body,
  parsedBody: koaContext.request.body,  // BodyValidationMiddleware needs this
  // ...
};
```
