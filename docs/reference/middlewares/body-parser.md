# How to Parse Request Bodies

Adds `context.req.parsedBody` to every request, decoding JSON and Pub/Sub message envelopes automatically.

## Prerequisites

- `Handler` imported from `@/core/handler`
- `BodyParserMiddleware` (or `bodyParser`) imported from `@/middlewares/bodyParserMiddleware`

## Primary Workflow

**1. Define the expected body shape.**

```typescript
interface CreateUserRequest {
  name: string;
  email: string;
  age: number;
}
```

**2. Add `BodyParserMiddleware` before any middleware that reads the body.**

```typescript
import { Handler } from '@/core/handler';
import { BodyParserMiddleware } from '@/middlewares/bodyParserMiddleware';

const createUserHandler = new Handler<CreateUserRequest>()
  .use(new BodyParserMiddleware<CreateUserRequest>())
  .handle(async (context) => {
    const userData = context.req.parsedBody as CreateUserRequest;

    return {
      success: true,
      user: { id: generateId(), ...userData },
    };
  });
```

**3. Access parsed body via `context.req.parsedBody`.**

The middleware always sets `parsedBody` before the controller runs. If the raw body cannot be decoded, it throws and `ErrorHandlerMiddleware` (if present) converts it to a 400 response.

## If Parsing Pub/Sub Messages

Pub/Sub wraps payloads inside a `message.data` base-64 field. `BodyParserMiddleware` detects this envelope and decodes it automatically — no extra configuration needed.

```typescript
interface OrderEvent {
  orderId: string;
  status: string;
}

const orderEventHandler = new Handler<OrderEvent>()
  .use(new BodyParserMiddleware<OrderEvent>())
  .handle(async (context) => {
    // For Pub/Sub triggers, parsedBody is already the decoded inner payload
    const event = context.req.parsedBody as OrderEvent;

    await processOrderStatusChange(event.orderId, event.status);
    return { success: true };
  });
```

Don't manually decode `message.data` — the middleware handles it.

## If You Need a Size Limit

Pass `maxBytes` as the first constructor argument (or function parameter). The default is no limit.

```typescript
// Class approach — 2 MB limit
new BodyParserMiddleware<UploadRequest>(2 * 1024 * 1024)

// Functional approach — identical behaviour
import { bodyParser } from '@/middlewares/bodyParserMiddleware';
bodyParser<UploadRequest>(2 * 1024 * 1024)
```

Requests that exceed the limit are rejected before the controller runs.

## Real-World Example: Order Creation

```typescript
interface OrderItem {
  productId: string;
  quantity: number;
  customization?: Record<string, string>;
}

interface CreateOrderRequest {
  items: OrderItem[];
  shippingAddress: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
  paymentMethod: {
    type: 'credit_card' | 'paypal' | 'bank_transfer';
    token: string;
  };
  priority: 'standard' | 'express' | 'overnight';
}

export const createOrderHandler = new Handler<CreateOrderRequest>()
  .use(new BodyParserMiddleware<CreateOrderRequest>())
  .handle(async (context) => {
    const orderData = context.req.parsedBody as CreateOrderRequest;

    console.log(`Order with ${orderData.items.length} items`);
    console.log(`Shipping to: ${orderData.shippingAddress.city}`);
    console.log(`Payment: ${orderData.paymentMethod.type}`);
    console.log(`Priority: ${orderData.priority}`);

    const order = await createOrder(orderData);
    return { success: true, order };
  });
```

## Anti-Patterns

**Don't place `BodyValidationMiddleware` before `BodyParserMiddleware`.** Validation reads `parsedBody`, which only exists after parsing.

```typescript
// Wrong — validation runs before the body exists
new Handler()
  .use(new BodyValidationMiddleware(schema))
  .use(new BodyParserMiddleware())

// Correct
new Handler()
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(schema))
```

**Don't use `as any` to work around generic type errors.** Fix the generic instead — `as any` silently breaks the type chain downstream.

**Don't catch parser errors in the controller.** Let `ErrorHandlerMiddleware` handle them; it already maps parse failures to 400.

## Next Step

To validate the shape and content of `parsedBody`, add `BodyValidationMiddleware` immediately after. See [How to Validate Request Bodies with Zod](./body-validation.md).
