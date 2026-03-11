# How to Validate Required HTTP Headers

Asserts that specified headers are present and non-empty before the controller runs. Missing headers result in a `ValidationError` (→ 400) thrown during the `before` hook.

## Prerequisites

- `HeaderVariablesMiddleware` (or `headerVariablesMiddleware`) imported from `@/middlewares`

## Primary Workflow

**1. Declare which headers are required.**

Pass an array of lowercase header names. HTTP headers are matched case-insensitively — always pass lowercase keys here.

**2. Add `HeaderVariablesMiddleware` early in the chain** (after `ErrorHandlerMiddleware` and DI, before any expensive logic).

**3. Access headers from `context.req.headers` inside the controller.**

```typescript
import { Handler } from '@/core/handler';
import { HeaderVariablesMiddleware } from '@/middlewares';

const secureApiHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type', 'x-api-key']))
  .handle(async (context) => {
    const auth = context.req.headers.authorization as string;
    const contentType = context.req.headers['content-type'] as string;
    const apiKey = context.req.headers['x-api-key'] as string;

    // All three are guaranteed non-empty here
    const result = await processSecureRequest({ auth, contentType, apiKey });
    return { success: true, result };
  });
```

## If You Need Bearer Token Extraction

The middleware only checks presence — format validation is your responsibility:

```typescript
const bearerAuthHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .handle(async (context) => {
    const authHeader = context.req.headers.authorization as string;

    if (!authHeader.startsWith('Bearer ')) {
      throw new ValidationError('Authorization header must use Bearer token format');
    }

    const token = authHeader.substring(7);
    const decoded = await validateJWTToken(token);

    context.user = decoded;
    return { success: true, user: decoded };
  });
```

## If You Need API Key Validation

```typescript
const apiKeyHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-api-key']))
  .handle(async (context) => {
    const apiKey = context.req.headers['x-api-key'] as string;

    const keyData = await validateApiKey(apiKey);
    if (!keyData) {
      throw new AuthenticationError('Invalid API key');
    }

    return {
      success: true,
      client: { id: keyData.clientId, tier: keyData.tier },
    };
  });
```

## If You Need Multi-Tenant Headers

```typescript
interface TenantHeaders {
  'x-tenant-id': string;
  'authorization': string;
}

const multiTenantHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-tenant-id', 'authorization']))
  .handle(async (context) => {
    const headers = context.req.headers as TenantHeaders;

    const tenant = await getTenant(headers['x-tenant-id']);
    if (!tenant || !tenant.active) {
      throw new ValidationError('Invalid or inactive tenant');
    }

    const authResult = await authenticateInTenant(headers.authorization, headers['x-tenant-id']);
    if (!authResult.valid) {
      throw new AuthenticationError('Authentication failed for tenant');
    }

    return {
      success: true,
      tenant: { id: tenant.id, name: tenant.name },
      user: authResult.user,
    };
  });
```

## If You Need Webhook Signature Headers

```typescript
const webhookHandler = new Handler()
  .use(new HeaderVariablesMiddleware([
    'x-webhook-signature',
    'x-webhook-timestamp',
    'content-type',
  ]))
  .handle(async (context) => {
    const signature = context.req.headers['x-webhook-signature'] as string;
    const timestamp = context.req.headers['x-webhook-timestamp'] as string;

    // Replay-attack protection
    const timestampMs = parseInt(timestamp) * 1000;
    if (Date.now() - timestampMs > 5 * 60 * 1000) {
      throw new SecurityError('Webhook timestamp too old');
    }

    const expected = await computeWebhookSignature(
      context.req.body,
      timestamp,
      process.env.WEBHOOK_SECRET!
    );

    if (signature !== expected) {
      throw new SecurityError('Invalid webhook signature');
    }

    const result = await processWebhookPayload(context.req.body);
    return { success: true, result };
  });
```

## Functional Alias

Use `headerVariablesMiddleware()` when you prefer a functional style:

```typescript
import { headerVariablesMiddleware } from '@/middlewares';

new Handler()
  .use(headerVariablesMiddleware(['authorization', 'x-api-key']))
  .handle(/* ... */);
```

## Anti-Patterns

**Don't pass headers in mixed case** (`'Authorization'`, `'X-API-Key'`). HTTP headers are case-insensitive, but the middleware normalises to lowercase internally — always pass lowercase keys to avoid mismatches.

**Don't hardcode expected header values inside the middleware call.** The middleware only checks presence. Validate values (token format, API key lookup) inside the controller or a dedicated auth middleware.

**Don't skip `HeaderVariablesMiddleware` and access headers directly in the controller.** Direct access will silently produce `undefined` for missing headers rather than returning a 400 to the caller.

**Don't place expensive middleware before this check.** `HeaderVariablesMiddleware` is cheap. Put it first (after `ErrorHandlerMiddleware`) so malformed requests fail before any database or external service call runs.

```typescript
// Wrong — expensive auth runs even when the header is missing
new Handler()
  .use(expensiveAuthMiddleware)
  .use(new HeaderVariablesMiddleware(['authorization']))

// Correct — fail fast
new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .use(expensiveAuthMiddleware)
```

## Related

- [How to Compose Middleware Pipelines](./07-integration-guide.md) — canonical ordering with headers
