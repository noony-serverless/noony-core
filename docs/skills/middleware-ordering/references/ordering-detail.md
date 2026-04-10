# Resource: Middleware Execution Order Detail

## Visual Timeline: Complete Request Lifecycle

```
Request arrives
    ↓
Middleware1.before()  ← position 0 runs first
    ↓
Middleware2.before()  ← position 1 runs second
    ↓
Middleware3.before()  ← position 2 runs third
    ↓
Handler (business logic)
    ↓
    ├─ [If error thrown]
    │  ↓
    │  Middleware3.onError()  ← reverse: position 2 first
    │  ↓
    │  Middleware2.onError()  ← reverse: position 1 second
    │  ↓
    │  Middleware1.onError()  ← reverse: position 0 third (last say on response)
    │
    └─ [If success]
       ↓
       Middleware3.after()  ← reverse: position 2 first
       ↓
       Middleware2.after()  ← reverse: position 1 second
       ↓
       Middleware1.after()  ← reverse: position 0 third
    ↓
Response sent
```

## Canonical Middleware Order Table

| Position | Middleware | Lifecycle | Reason |
|----------|------------|-----------|--------|
| **1** | ErrorHandlerMiddleware | onError runs last (reverse) — final authority | Catches ALL errors in reverse order; position 0's onError runs LAST |
| **2** | OpenTelemetryMiddleware | before first, after second | Wraps full request lifecycle for complete tracing |
| **3** | AuthenticationMiddleware | before second, after second | Validates JWT after telemetry; populates context.user |
| **4** | BodyParserMiddleware | before third | Parses JSON/Pub/Sub before validation |
| **5** | BodyValidationMiddleware | before fourth | Validates parsed body with Zod schema |
| **N-1** | (Custom middlewares) | Middle of pipeline | Business-specific logic |
| **N** | ResponseWrapperMiddleware | after runs first (reverse) — wraps return value | Wraps `context.responseData` before any other after() hook |

**Why This Order Matters:**

- **before** runs 0→N: Each middleware prepares data for the next
- **after** runs N→0: Each middleware processes the result in reverse
- **onError** runs N→0: Each middleware handles errors in reverse, with first-position middleware having final say

## Common Mistakes & How to Fix

### Mistake 1: ErrorHandlerMiddleware Not First (❌)

**What happens:**
```typescript
const handler = new Handler()
  .use(new AuthenticationMiddleware())     // position 0 — onError runs last
  .use(new BodyValidationMiddleware())     // position 1 — onError runs second
  .use(new ErrorHandlerMiddleware())       // position 2 — onError runs first (TOO EARLY!)
  .handle(controller);
```

When `BodyValidationMiddleware` throws `ValidationError`:
1. `ErrorHandlerMiddleware.onError()` runs FIRST (position 2)
2. Catches the error and sends response
3. But error originated in position 1 — ErrorHandler should be BEFORE it, not after
4. Result: Errors from position 0-1 not caught properly, or caught too late

**The Fix:**
```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())       // position 0 — onError runs LAST (final say!)
  .use(new AuthenticationMiddleware())     // position 1
  .use(new BodyValidationMiddleware())     // position 2
  .handle(controller);
```

Now ErrorHandler's onError runs LAST in the reverse chain, giving it final authority over all error responses.

### Mistake 2: ResponseWrapperMiddleware Not Last (❌)

**What happens:**
```typescript
const handler = new Handler()
  .use(new ResponseWrapperMiddleware())    // position 0 — after runs LAST (wrong!)
  .use(new BodyValidationMiddleware())     // position 1 — after runs second
  .use(new ErrorHandlerMiddleware())       // position 2 — after runs first
  .handle(controller);
```

When handler returns `{ data: user }`:
1. `ErrorHandlerMiddleware.after()` runs FIRST
2. Gets `context.responseData = { data: user }`
3. Might send response directly
4. Then `ResponseWrapperMiddleware.after()` runs LAST
5. Can't wrap anymore — headers already sent or response incomplete

**The Fix:**
```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())       // position 0
  .use(new BodyValidationMiddleware())     // position 1
  .use(new ResponseWrapperMiddleware())    // position 2 — after runs FIRST (wraps immediately!)
  .handle(controller);
```

Now ResponseWrapper's after runs FIRST in the reverse chain, wrapping the return value before any other after() hook sees it.

### Mistake 3: OpenTelemetryMiddleware Too Late (❌)

**What happens:**
```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())       // position 0
  .use(new AuthenticationMiddleware())     // position 1 — auth before OTEL span started
  .use(new OpenTelemetryMiddleware())      // position 2 — span starts HERE (too late!)
  .handle(controller);
```

`AuthenticationMiddleware` runs before OTEL span starts:
- JWT verification time not traced
- Auth latency invisible in spans
- Incomplete trace for full request lifecycle

**The Fix:**
```typescript
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())       // position 0
  .use(new OpenTelemetryMiddleware())      // position 1 — span starts early (includes auth)
  .use(new AuthenticationMiddleware())     // position 2
  .handle(controller);
```

OTEL span now wraps the entire request, including authentication latency.

## Inter-Middleware Communication Patterns

### Via context.responseData (Response Wrapping)

When handler returns a value, Handler sets `context.responseData`:

```typescript
// Handler returns
return { success: true, data: user };

// Inside ResponseWrapperMiddleware.after()
async after(context: Context): Promise<void> {
  if (context.responseData) {
    // Wrap it into standard format
    const wrapped = {
      success: true,
      payload: context.responseData,
      timestamp: new Date().toISOString()
    };
    context.res.json(wrapped);
  }
}
```

**Rule:** Always return the value from the handler — never call `context.res` from a controller or handler callback.

```typescript
// ✅ CORRECT — return the value, ResponseWrapperMiddleware sends it
return { data: user };

// ❌ WRONG — never call context.res from a handler/controller
context.res.status(201).json({ data: user });
```

`context.res` is for framework internals only (e.g., `ResponseWrapperMiddleware.after()`). Calling it from a handler bypasses wrapping, logging, and the error path — and causes the FASTIFY-WRAPPER to log spurious "handler error called" messages.

### Via context.businessData (Inter-Middleware State)

Use Map to pass data between middlewares without modifying Context interface:

```typescript
// Timing Middleware - records start time
class TimingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    context.businessData.set('startTime', Date.now());
  }

  async after(context: Context<TBody, TUser>): Promise<void> {
    const startTime = context.businessData.get('startTime') as number;
    const elapsed = Date.now() - startTime;
    console.log(`[Timing] Request took ${elapsed}ms`);
  }
}

// Logging Middleware - reads timing data
class LoggingMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async after(context: Context<TBody, TUser>): Promise<void> {
    const elapsed = context.businessData.get('startTime');
    const statusCode = context.res.statusCode;
    console.log(`[Logging] ${context.req.method} ${context.req.path} ${statusCode} (+${elapsed}ms)`);
  }
}

// Handler
const handler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new TimingMiddleware())    // Sets 'startTime'
  .use(new LoggingMiddleware())   // Reads 'startTime' and status
  .handle(controller);
```

**Important:** Don't overwrite reserved keys:
- `'otel_span'` — Reserved by OpenTelemetryMiddleware for span tracking

## RESPONSE_SENT Error: What It Means

This error occurs when you try to send a response twice:

```typescript
// Inside middleware.after() that runs in wrong order
context.res.json({ data: user });  // First send ✅
// ... later in execution

// Another middleware's after() (running in reverse)
context.res.json({ wrapped: true });  // Second send ❌ RESPONSE_SENT error
```

**Prevention Checklist:**
1. Only ONE middleware calls `context.res.json()` in after() — usually ResponseWrapperMiddleware
2. Handler either returns value (for wrapping) OR calls `context.res.json()`, never both
3. Check `context.res.headersSent` before sending in custom after() hooks:

```typescript
async after(context: Context): Promise<void> {
  if (!context.res.headersSent) {
    context.res.json({ custom: 'data' });  // Safe
  }
}
```

## Response Sending Decision Tree

```
Handler execution complete
    │
    └─ Did handler return a value?
          │
          ├─ YES (returned object/data)      ← ✅ THE ONLY CORRECT PATTERN
          │  │
          │  └─ context.responseData = { returned value }
          │     ResponseWrapperMiddleware.after() runs
          │     ✅ Response wrapped in standard format: { success: true, payload: ... }
          │
          └─ NO (returned nothing)
             │
             └─ context.responseData = undefined
                ResponseWrapperMiddleware.after() does nothing
                ❌ Risk: 204 No Content or incomplete response

NOTE: Never call context.res.json() or context.res.status().send() from a handler.
      That path bypasses wrapping and logging, and produces spurious framework error logs.
      context.res is for framework internals (ResponseWrapperMiddleware, ErrorHandlerMiddleware) only.
```

</content>
</invoke>