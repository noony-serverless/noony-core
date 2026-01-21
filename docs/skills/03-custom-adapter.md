# Skill 3: Custom Adapter for New Framework

## Triggers

When user asks to:
- "Add support for [Koa/Hapi/Express/etc.]"
- "Create adapter for [framework]"
- "I want to use Noony with [framework]"
- "How do I integrate with [framework]?"
- "Make Noony work with my existing [framework] server"

## What it provides

Template for creating adapters for frameworks not yet supported by Noony (Koa, Hapi, NestJS, etc.).

## Complete Example Template

### Step 1: Request Adapter

```typescript
// src/adapters/adapt-koa-request.ts
import type { Context as KoaContext } from 'koa';
import type { GenericRequest } from '@noony-serverless/core';

/**
 * Adapt Koa Context to GenericRequest for Noony handlers
 */
export function adaptKoaRequest<T = unknown>(
  ctx: KoaContext
): GenericRequest<T> {
  const genericReq: GenericRequest<T> = {
    method: ctx.method,
    url: ctx.url,
    path: ctx.path,
    headers: ctx.headers as Record<string, string | string[] | undefined>,
    query: ctx.query as Record<string, string | string[] | undefined>,
    params: ctx.params || {},
    body: ctx.request.body,
    parsedBody: ctx.request.body as T,
    ip: ctx.ip,
    userAgent: ctx.get('user-agent'),
  };

  return genericReq;
}
```

### Step 2: Response Adapter

```typescript
// src/adapters/adapt-koa-response.ts
import type { Context as KoaContext } from 'koa';
import type { GenericResponse } from '@noony-serverless/core';

/**
 * Adapt Koa Context to GenericResponse for Noony handlers
 */
export function adaptKoaResponse(ctx: KoaContext): GenericResponse {
  let statusCode = 200;
  let headersSent = false;

  const response: GenericResponse = {
    status(code: number) {
      statusCode = code;
      ctx.status = code;
      return response;
    },

    json(data: unknown) {
      if (headersSent || ctx.respond === false) return response;
      headersSent = true;
      ctx.body = data;
      ctx.type = 'application/json';
      return response;
    },

    send(data: unknown) {
      if (headersSent || ctx.respond === false) return response;
      headersSent = true;
      ctx.body = data;
      return response;
    },

    header(name: string, value: string) {
      ctx.set(name, value);
      return response;
    },

    headers(headers: Record<string, string>) {
      for (const key in headers) {
        ctx.set(key, headers[key]);
      }
      return response;
    },

    end() {
      if (headersSent || ctx.respond === false) return;
      headersSent = true;
      ctx.body = ctx.body || '';
    },

    get statusCode() {
      return statusCode;
    },

    get headersSent() {
      return headersSent || ctx.respond === false;
    },
  };

  return response;
}
```

### Step 3: Handler Wrapper

```typescript
// src/adapters/create-koa-handler.ts
import type { Context as KoaContext, Next } from 'koa';
import type { Handler } from '@noony-serverless/core';
import { adaptKoaRequest, adaptKoaResponse } from './adapters';
import { logger } from '@noony-serverless/core';

/**
 * Create a Koa middleware from a Noony handler
 */
export function createKoaHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (ctx: KoaContext, next: Next) => Promise<void> {
  const errorLogPrefix = `${functionName} handler error`;

  return async (ctx: KoaContext, next: Next): Promise<void> => {
    const requestId = `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;

    try {
      // Initialize dependencies
      await initializeDependencies();

      // Adapt Koa context to GenericRequest/GenericResponse
      const genericReq = adaptKoaRequest(ctx);
      const genericRes = adaptKoaResponse(ctx);

      // Execute Noony handler
      await noonyHandler.executeGeneric(genericReq, genericRes);
    } catch (error) {
      // Ignore RESPONSE_SENT errors
      if (error instanceof Error && error.message === 'RESPONSE_SENT') {
        return;
      }

      logger.error(errorLogPrefix, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        requestId,
      });

      // Send error response if not already sent
      if (ctx.respond !== false) {
        ctx.status = 500;
        ctx.body = {
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

### Step 4: Usage Example

```typescript
// src/server.ts
import Koa from 'koa';
import Router from '@koa/router';
import { createKoaHandler } from './adapters/create-koa-handler';
import { loginHandler } from './handlers/auth.handlers';

const app = new Koa();
const router = new Router();

// Use Noony handler with Koa
router.post(
  '/api/auth/login',
  createKoaHandler(loginHandler, 'login', initializeDependencies)
);

app.use(router.routes());
app.listen(3000);
```

## When to use

- Need to integrate Noony with a framework not yet officially supported
- Have existing Koa/Hapi/NestJS application
- Want to add Noony handlers to existing infrastructure
- Building custom HTTP framework integration
