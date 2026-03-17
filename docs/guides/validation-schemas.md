# Validation Schemas

How to use Zod schemas with Noony's `BodyValidationMiddleware` for runtime type-safe request validation, including custom transforms, async validation, and Pub/Sub message handling.

**Related links:** [Body Validation Middleware Reference](../reference/middlewares/body-validation.md) | [Middleware Ordering](./middleware-ordering.md) | [Error Handling](./error-handling.md)

## Prerequisites

- `zod` installed as a dependency
- `@noony-serverless/core` installed
- Understanding of the Noony middleware pipeline

---

## How Validation Works in Noony

Validation is a two-step process handled by two middlewares that must be used in order:

1. **`BodyParserMiddleware`** converts the raw request body into `context.req.parsedBody`.
2. **`BodyValidationMiddleware`** validates `parsedBody` against a Zod schema and populates `context.req.validatedBody`.

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())           // 1. Parse raw body
  .use(new BodyValidationMiddleware(schema)) // 2. Validate parsed body
  .handle(async (context) => {
    const body = context.req.validatedBody!; // Type: CreateUserRequest
  });
```

If validation fails, `BodyValidationMiddleware` throws a `ValidationError` (HTTP 400) automatically. The handler is never reached. When `ErrorHandlerMiddleware` is present, it formats the error into a structured JSON response.

## parsedBody vs validatedBody

Understanding the difference between these two properties is important:

| Property | Set By | Type | When to Use |
|----------|--------|------|-------------|
| `body` | HTTP framework | `unknown` | Never directly -- always use parsedBody or validatedBody |
| `parsedBody` | `BodyParserMiddleware` | `unknown` | Only if you need raw parsed data before validation |
| `validatedBody` | `BodyValidationMiddleware` | `T` (your schema type) | Always -- this is the type-safe, validated data |

## Defining Schemas

### Basic Object Schema

Define the schema, infer the TypeScript type from it (never define the interface separately), and pass it to the handler.

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string()
    .min(1, 'Name is required')
    .max(100, 'Name too long'),

  email: z.string()
    .email('Invalid email format'),

  age: z.number()
    .min(18, 'Must be 18 or older')
    .max(120, 'Invalid age'),

  phone: z.string().optional(),

  role: z.enum(['user', 'admin']).default('user')
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    const { name, email, age, phone, role } = context.req.validatedBody!;
    // All fields are fully typed
  });
```

### Nested Objects

```typescript
const createOrderSchema = z.object({
  productId: z.string().uuid(),
  quantity: z.number().min(1).max(1000),

  shippingAddress: z.object({
    street: z.string().min(1),
    city: z.string().min(1),
    state: z.string().length(2),
    zipCode: z.string().regex(/^\d{5}(-\d{4})?$/, 'Invalid ZIP code'),
    country: z.string().default('US')
  }),

  billingAddress: z.object({
    street: z.string(),
    city: z.string()
  }).optional()
});

type CreateOrderRequest = z.infer<typeof createOrderSchema>;
```

### Array Validation

```typescript
const createProjectSchema = z.object({
  name: z.string(),
  tasks: z.array(
    z.object({
      title: z.string(),
      priority: z.enum(['low', 'medium', 'high']),
      assignedTo: z.string().email().optional()
    })
  ).min(1, 'At least one task required')
});
```

### Enum and Union Types

```typescript
const updateProfileSchema = z.object({
  theme: z.enum(['light', 'dark', 'auto']),

  notifications: z.object({
    email: z.boolean(),
    push: z.boolean(),
    sms: z.boolean().optional()
  }),

  subscriptionTier: z.union([
    z.literal('free'),
    z.literal('pro'),
    z.literal('enterprise')
  ])
});
```

## Custom Transforms and Refinements

### Refinements for Custom Validation Logic

Use `.refine()` for validation rules that go beyond basic type checking.

```typescript
const createPaymentSchema = z.object({
  amount: z.number()
    .min(0.01, 'Amount must be positive')
    .refine(
      (val) => Number((val * 100).toFixed(0)) === val * 100,
      'Amount must have at most 2 decimal places'
    ),

  cardNumber: z.string()
    .refine(
      (val) => /^\d{16}$/.test(val),
      'Invalid card number'
    )
    .refine(
      (val) => luhnCheck(val),
      'Card number failed checksum validation'
    ),

  expiryDate: z.string()
    .regex(/^\d{2}\/\d{2}$/, 'Format: MM/YY')
    .refine((val) => {
      const [month, year] = val.split('/').map(Number);
      const expiry = new Date(2000 + year, month);
      return expiry > new Date();
    }, 'Card has expired')
});
```

### Transforms for Data Conversion

Transforms change the shape or type of data during validation. Be aware that the output type differs from the input type.

```typescript
const schema = z.object({
  // String date becomes a Date object after validation
  date: z.string().transform(d => new Date(d)),

  // String number becomes a number
  count: z.string().transform(Number)
});

// z.infer gives you the OUTPUT type (after transforms)
type Result = z.infer<typeof schema>;
// { date: Date; count: number }
```

## Async Validation

For validation that requires database lookups or external API calls, use async refinements with the `{ async: true }` option on the middleware.

```typescript
const registerUserSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3)
}).refine(
  async (data) => {
    const exists = await userService.findByEmail(data.email);
    return !exists;
  },
  {
    message: 'Email already registered',
    path: ['email']
  }
);

const handler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(registerUserSchema, { async: true }))
  .handle(async (context) => {
    const { email, username } = context.req.validatedBody!;
  });
```

**Performance note:** Only use async validation when necessary. Synchronous validation is significantly faster. Place expensive `.refine()` checks last in the chain so that cheap checks (string format, length) fail first.

## Error Handling

### Automatic Error Response

When `ErrorHandlerMiddleware` is present, validation failures produce a structured 400 response:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      { "path": ["name"], "message": "String must contain at least 1 character(s)" },
      { "path": ["email"], "message": "Invalid email" }
    ]
  }
}
```

### Custom Error Messages

Zod supports custom error messages on every validator:

```typescript
const schema = z.object({
  email: z.string()
    .email('Please provide a valid email address')
    .min(1, 'Email is required'),

  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain an uppercase letter')
    .regex(/[0-9]/, 'Must contain a number')
});
```

## Pub/Sub Message Validation

Pub/Sub messages carry their payload as a base64-encoded string inside a `data` field. Validate the envelope first, then validate the decoded content.

```typescript
const pubsubMessageSchema = z.object({
  message: z.object({
    data: z.string().transform((base64) => {
      const json = Buffer.from(base64, 'base64').toString('utf-8');
      return JSON.parse(json);
    }),
    attributes: z.record(z.string()),
    messageId: z.string(),
    publishTime: z.string()
  })
});

const orderEventSchema = z.object({
  orderId: z.string(),
  status: z.enum(['pending', 'confirmed', 'shipped']),
  timestamp: z.string().datetime()
});

const handler = new Handler<any, void>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(pubsubMessageSchema))
  .handle(async (context) => {
    const decodedData = context.req.validatedBody.message.data;
    const orderEvent = orderEventSchema.parse(decodedData);
    await eventService.handle(orderEvent);
  });
```

## Schema Reuse Patterns

Define schemas once and derive variants for different operations:

```typescript
// Base schema
export const userSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18),
  role: z.enum(['user', 'admin']).default('user')
});

// Create: all fields required (with defaults)
export const createUserSchema = userSchema;

// Update: all fields optional
export const updateUserSchema = userSchema.partial();

// Patch: specific fields optional
export const patchUserSchema = userSchema.pick({ name: true, email: true }).partial();
```

## Testing Validation Schemas

### Unit Test: Valid Data

```typescript
describe('createUserSchema', () => {
  it('should validate correct user data', () => {
    const validData = {
      name: 'John Doe',
      email: 'john@example.com',
      age: 30,
      role: 'user'
    };

    expect(() => createUserSchema.parse(validData)).not.toThrow();
    const result = createUserSchema.parse(validData);
    expect(result.role).toBe('user');
  });
});
```

### Unit Test: Invalid Data

```typescript
it('should reject invalid email', () => {
  const invalidData = { name: 'John', email: 'not-an-email', age: 30 };
  expect(() => createUserSchema.parse(invalidData)).toThrow();
});

it('should provide specific error messages', () => {
  const invalidData = { name: '', email: 'john@example.com', age: 10 };

  try {
    createUserSchema.parse(invalidData);
  } catch (error) {
    if (error instanceof ZodError) {
      const errors = error.flatten().fieldErrors;
      expect(errors.name).toBeDefined();
      expect(errors.age).toBeDefined();
    }
  }
});
```

### Integration Test with Handler

```typescript
describe('createUserHandler', () => {
  it('should return 400 for invalid request', async () => {
    const context = {
      req: { parsedBody: { name: '', email: 'invalid' } },
      res: {
        statusCode: 200,
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis()
      }
    } as any;

    const middleware = new BodyValidationMiddleware(createUserSchema);
    await expect(middleware.before!(context)).rejects.toThrow(ValidationError);
  });
});
```

## Performance Considerations

1. **Schema reuse.** Define schemas at module scope, not inside handlers. Schema compilation happens once.
2. **Lazy refinements.** Place expensive `.refine()` checks after cheap format checks so invalid data fails fast.
3. **Async validation.** Only enable `{ async: true }` when the schema contains async refinements. Synchronous parsing is faster.

## Anti-Patterns

### Accessing body directly without validation

```typescript
// WRONG -- unsafe, untyped
const { email } = context.req.body as any;

// CORRECT -- type-safe after validation
const { email } = context.req.validatedBody!;
```

### Skipping BodyParserMiddleware

```typescript
// WRONG -- parsedBody will be undefined, validation has nothing to work with
.use(new BodyValidationMiddleware(schema))

// CORRECT -- parse first, then validate
.use(new BodyParserMiddleware())
.use(new BodyValidationMiddleware(schema))
```

### Defining interfaces separately from Zod schemas

```typescript
// WRONG -- duplicates the type, can drift out of sync
interface CreateUserRequest {
  name: string;
  email: string;
}
const schema = z.object({ name: z.string(), email: z.string().email() });

// CORRECT -- single source of truth
const schema = z.object({ name: z.string(), email: z.string().email() });
type CreateUserRequest = z.infer<typeof schema>;
```

### Validating inside the handler instead of middleware

```typescript
// WRONG -- defeats the middleware pipeline benefits
.handle(async (context) => {
  const result = schema.safeParse(context.req.body);
  if (!result.success) throw new ValidationError(...);
});

// CORRECT -- let middleware handle it
.use(new BodyValidationMiddleware(schema))
.handle(async (context) => {
  const body = context.req.validatedBody!;
});
```

### Using async schema without the async option

```typescript
// WRONG -- async refinement silently broken
.use(new BodyValidationMiddleware(asyncSchema))

// CORRECT -- enable async mode
.use(new BodyValidationMiddleware(asyncSchema, { async: true }))
```

### Missing ErrorHandlerMiddleware

Without `ErrorHandlerMiddleware`, a `ValidationError` from the validation middleware crashes the function instead of returning a clean 400 response.

## Common Gotchas

**Type inference with transforms.** `z.infer<typeof schema>` gives you the *output* type. If your schema transforms a string date into a `Date` object, the inferred type will have `date: Date`, not `date: string`.

**Using `Handler<unknown>` with validation.** If you pass `unknown` as the Handler's body type parameter, `validatedBody` will be typed as `unknown` even after validation. Always use the inferred type: `Handler<z.infer<typeof schema>>`.

## See Also

- [Body Validation Middleware Reference](../reference/middlewares/body-validation.md) -- Full API for BodyValidationMiddleware
- [Middleware Ordering](./middleware-ordering.md) -- Where validation fits in the pipeline
- [Error Handling](./error-handling.md) -- How ValidationError maps to HTTP 400
- [Testing Handlers](../tutorials/04-testing-handlers.md) -- Testing validation with mock requests
