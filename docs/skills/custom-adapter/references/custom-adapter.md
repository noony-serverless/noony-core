# Resource: Custom Framework Adapter

## Fastify Adapter with rawBody

Use this pattern when a Fastify route needs `context.req.rawBody` — for example, webhook signature verification where the original payload bytes must be preserved.

### Step 1: Capture Raw Bytes in Content-Type Parser

Register BEFORE routes on the Fastify server. GCF passes `req.rawBody` (Buffer) as the `server.inject()` payload — this parser receives it and stores it.

```typescript
// src/functions.ts
server.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body as string, 'utf8');
  (req as unknown as { rawBodyBuffer: Buffer }).rawBodyBuffer = buf;
  try {
    done(null, JSON.parse(buf.toString('utf8')));
  } catch (err) {
    done(err as Error, undefined);
  }
});
```

### Step 2: Fastify Request Adapter with rawBody

```typescript
import type { FastifyRequest } from 'fastify';
import type { GenericRequest } from '@noony-serverless/core';

function adaptFastifyRequestWithRawBody<T = unknown>(req: FastifyRequest): GenericRequest<T> {
  const rawBuf = (req as unknown as { rawBodyBuffer?: Buffer }).rawBodyBuffer;
  return {
    method: req.method,
    url: req.url,
    path: (req.routeOptions as unknown as { url?: string })?.url ?? req.url,
    headers: req.headers as Record<string, string | string[] | undefined>,
    query: (req.query as Record<string, string | string[] | undefined>) ?? {},
    params: (req.params as Record<string, string>) ?? {},
    body: req.body,
    parsedBody: req.body as T,
    rawBody: rawBuf,          // ← the original bytes; undefined falls back gracefully
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  };
}
```

### Step 3: Fastify Response Adapter

```typescript
import type { FastifyReply } from 'fastify';
import type { GenericResponse } from '@noony-serverless/core';

function adaptFastifyReply(reply: FastifyReply): GenericResponse {
  let statusCode = 200;
  let headersSent = false;
  const res: GenericResponse = {
    status(code)      { statusCode = code; reply.code(code); return res; },
    json(data)        { if (reply.sent) return res; headersSent = true; reply.send(data); return res; },
    send(data)        { if (reply.sent) return res; headersSent = true; reply.send(data); return res; },
    header(name, val) { reply.header(name, val); return res; },
    headers(hdrs)     { for (const k in hdrs) reply.header(k, hdrs[k]); return res; },
    end()             { if (!reply.sent) { headersSent = true; reply.send(); } },
    get statusCode()  { return statusCode; },
    get headersSent() { return headersSent || reply.sent; },
  };
  return res;
}
```

### Step 4: executeGeneric Wrapper

```typescript
import type { Handler } from '@noony-serverless/core';
import { isResponseAlreadySent, INTERNAL_ERROR_RESPONSE } from '@noony-serverless/core';

function adaptWithRawBody(handler: Handler<any, any>, initFn: () => Promise<void>) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    await initFn();
    try {
      const genericReq = adaptFastifyRequestWithRawBody(req);
      const genericRes = adaptFastifyReply(reply);
      await handler.executeGeneric(genericReq, genericRes);
    } catch (error) {
      if (isResponseAlreadySent(error)) return;
      if (!reply.sent) reply.code(500).send(INTERNAL_ERROR_RESPONSE);
    }
  };
}
```

### Step 5: Route Registration

Mix standard and custom adapters on the same Fastify server:

```typescript
// Routes that need rawBody — use executeGeneric with custom adapter
server.get('/webhook/ebay/notifications/:marketplaceId', adaptWithRawBody(challengeHandler, init));
server.post('/webhook/ebay/notifications/:marketplaceId', adaptWithRawBody(notificationHandler, init));

// Standard routes — use createFastifyHandler (no rawBody needed)
server.post('/api/orders', createFastifyHandler(orderHandler, 'order', init));
server.get('/health', createFastifyHandler(healthHandler, 'health', init));
```

### Step 6: GCF Entry Point — Pass rawBody Through inject()

```typescript
import { http } from '@google-cloud/functions-framework';
import { extractAndStoreRequestBody, CloudFunctionRequest } from '@noony-serverless/core';

http('myHandler', async (req, res) => {
  await ensureServerReady();

  // GCF sets req.rawBody as Buffer with the original bytes before JSON parsing.
  // Pass it as payload so addContentTypeParser receives the real bytes.
  const gcfRawBody: Buffer | undefined = (req as any).rawBody;
  extractAndStoreRequestBody(req);
  const payload = gcfRawBody ?? (req as unknown as CloudFunctionRequest).__rawBody;

  const response = await server.inject({
    method: req.method as any,
    url: req.url || '/',
    headers: req.headers as Record<string, string>,
    payload,  // ← Buffer flows through to addContentTypeParser → rawBodyBuffer
  });

  res.statusCode = response.statusCode;
  for (const [key, value] of Object.entries(response.headers)) {
    if (value !== undefined) res.setHeader(key, value as string);
  }
  res.end(response.payload);
});
```

### Step 7: Read rawBody in Middleware

```typescript
// In any middleware before() method:
const rawBodyRaw = context.req.rawBody;
const rawBody: string = Buffer.isBuffer(rawBodyRaw)
  ? rawBodyRaw.toString('utf8')
  : typeof rawBodyRaw === 'string'
    ? rawBodyRaw
    : JSON.stringify(context.req.body ?? {});  // fallback for routes without rawBody
```

---

## Complete Koa Adapter Example

Building adapters for unsupported frameworks (Koa, Hapi, NestJS, Express.js with native types).

### Koa Request Adapter

```typescript
import { GenericRequest, GenericResponse } from '@noony-serverless/core';
import { Context as KoaContext } from 'koa';

export function adaptKoaRequest<T = unknown>(koaContext: KoaContext): GenericRequest<T> {
  return {
    method: koaContext.method,
    url: koaContext.url,
    path: koaContext.path,
    headers: koaContext.headers as Record<string, string | string[]>,
    query: koaContext.query as Record<string, string | string[]>,
    params: koaContext.params as Record<string, string>,
    body: koaContext.request.body as unknown,
    parsedBody: koaContext.request.body as T,
    ip: koaContext.ip,
    userAgent: koaContext.headers['user-agent'],
  };
}

export function adaptKoaResponse(koaContext: KoaContext): GenericResponse {
  let statusCode = 200;
  let headersSent = false;

  return {
    status(code) { statusCode = code; koaContext.status = code; return this; },
    json(data)   { if (!headersSent) { koaContext.type = 'application/json'; koaContext.body = data; headersSent = true; } return this; },
    send(data)   { if (!headersSent) { koaContext.body = data; headersSent = true; } return this; },
    header(name, value) { koaContext.set(name, value); return this; },
    headers(headers) { Object.entries(headers).forEach(([k, v]) => koaContext.set(k, v)); return this; },
    end() { headersSent = true; },
    get statusCode() { return statusCode; },
    get headersSent() { return headersSent; },
  };
}
```

### Koa Handler Wrapper

```typescript
import { Handler } from '@noony-serverless/core';
import { Context as KoaContext } from 'koa';

export function createKoaHandler(noonyHandler: Handler<unknown>, functionName: string, initFn?: () => Promise<void>) {
  return async (koaContext: KoaContext) => {
    try {
      if (initFn) await initFn();
      const genericReq = adaptKoaRequest(koaContext);
      const genericRes = adaptKoaResponse(koaContext);
      await noonyHandler.executeGeneric(genericReq, genericRes);
    } catch (error) {
      if (error instanceof Error && error.message === 'RESPONSE_SENT') return;
      console.error(`[${functionName}] Unexpected error`, error);
      if (!koaContext.res.headersSent) {
        koaContext.status = 500;
        koaContext.body = { success: false, error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected error occurred' } };
      }
    }
  };
}
```

---

## Adapter Checklist

- [ ] `addContentTypeParser` registered BEFORE routes (Fastify rawBody pattern)
- [ ] `rawBodyBuffer` stored on Fastify request in content-type parser
- [ ] `GenericRequest.rawBody` set from `rawBodyBuffer` (Buffer, not re-serialized string)
- [ ] GCF entry passes `req.rawBody` Buffer as `server.inject()` payload
- [ ] Implements `GenericRequest<T>` interface completely
- [ ] Implements `GenericResponse` interface completely
- [ ] `parsedBody` set from framework's parsed body
- [ ] Prevents double-send via `headersSent` tracking
- [ ] All response methods return `this` (chainable)
- [ ] Has `status()`, `json()`, `send()`, `header()`, `headers()`, `end()` methods
- [ ] Read-only `statusCode` and `headersSent` properties
- [ ] `executeGeneric()` called — never `execute()` for adapted requests
- [ ] `isResponseAlreadySent` errors handled gracefully in wrapper

## Common Gotchas

### ❌ Using JSON.stringify as rawBody

```typescript
// WRONG — re-serialized bytes differ from original; signature verification fails
const rawBody = JSON.stringify(req.body);
```

```typescript
// CORRECT — use the captured Buffer
const rawBodyRaw = context.req.rawBody;
const rawBody = Buffer.isBuffer(rawBodyRaw) ? rawBodyRaw.toString('utf8') : ...;
```

### ❌ Bypassing Fastify for Routes That Need rawBody

```typescript
// WRONG — pattern-matching URLs in the GCF handler loses Fastify routing/logging
if (url.startsWith('/webhook/')) {
  await handler.execute(req, res);  // bypasses Fastify entirely
}
```

```typescript
// CORRECT — stay inside Fastify, use executeGeneric with custom adapter
server.post('/webhook/:id', adaptWithRawBody(handler, init));
```

### ❌ Forgetting headersSent Check

```typescript
// WRONG — can send twice
json(data) { reply.send(data); return res; }
```

```typescript
// CORRECT
json(data) { if (reply.sent) return res; headersSent = true; reply.send(data); return res; }
```

### ❌ Not Setting parsedBody

```typescript
// WRONG — BodyValidationMiddleware reads parsedBody, not body
return { body: req.body };
```

```typescript
// CORRECT
return { body: req.body, parsedBody: req.body as T };
```
