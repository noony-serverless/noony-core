# Resource: Validation Schema Patterns

## Middleware Order

Critical ordering pattern — parser before validator, error handler wrapping both:

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())           // 1. Parse raw body → context.req.parsedBody
  .use(new BodyValidationMiddleware(schema)) // 2. Validate → context.req.validatedBody
  .handle(async (context) => {
    const body = context.req.validatedBody!; // Type: CreateUserRequest
  });
```

**Why This Order Matters:**
- BodyParserMiddleware converts raw request body to `parsedBody`
- BodyValidationMiddleware validates `parsedBody` and populates `validatedBody`
- ErrorHandlerMiddleware catches ValidationError and returns structured 400

## parsedBody vs validatedBody

```typescript
interface GenericRequest<T> {
  body: unknown;           // Raw request body (string/Buffer) — never use directly
  parsedBody: T;           // Parsed JSON (type: unknown at runtime)
  validatedBody?: T;       // Zod validated (type: T) — always use this
}
```

## Basic Object Schema

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  email: z.string().email('Invalid email format'),
  age: z.number().min(18, 'Must be 18 or older').max(120, 'Invalid age'),
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
    // All fields fully typed
  });
```

## Nested Objects

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

## Array Validation

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

type CreateProjectRequest = z.infer<typeof createProjectSchema>;
```

## Custom Refinements

Use `.refine()` for validation rules beyond basic type checking:

```typescript
const createPaymentSchema = z.object({
  amount: z.number()
    .min(0.01, 'Amount must be positive')
    .refine(
      (val) => Number((val * 100).toFixed(0)) === val * 100,
      'Amount must have at most 2 decimal places'
    ),

  cardNumber: z.string()
    .refine((val) => /^\d{16}$/.test(val), 'Invalid card number')
    .refine((val) => luhnCheck(val), 'Card number failed checksum'),

  expiryDate: z.string()
    .regex(/^\d{2}\/\d{2}$/, 'Format: MM/YY')
    .refine((val) => {
      const [month, year] = val.split('/').map(Number);
      const expiry = new Date(2000 + year, month);
      return expiry > new Date();
    }, 'Card has expired')
});
```

## Schema Reuse

Define once, derive variants:

```typescript
export const userSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18),
  role: z.enum(['user', 'admin']).default('user')
});

export const createUserSchema = userSchema;
export const updateUserSchema = userSchema.partial();
export const patchUserSchema = userSchema.pick({ name: true, email: true }).partial();
```

## Pub/Sub Message Validation

Pub/Sub messages carry payload as base64-encoded string. Validate envelope first, then decoded content:

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

type OrderEvent = z.infer<typeof orderEventSchema>;

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

## Async Validation

For database lookups or external API calls, use async refinements with `{ async: true }`:

```typescript
const registerUserSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3)
}).refine(
  async (data) => {
    const exists = await userService.findByEmail(data.email);
    return !exists;
  },
  { message: 'Email already registered', path: ['email'] }
);

const handler = new Handler<any, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(registerUserSchema, { async: true }))
  .handle(async (context) => {
    const { email, username } = context.req.validatedBody!;
  });
```

**Performance note:** Only use async when necessary. Place expensive `.refine()` checks last so cheap checks fail first.

## Error Response Format

When `ErrorHandlerMiddleware` is present, validation failures return structured 400:

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

Custom error messages are supported on every Zod validator:

```typescript
const schema = z.object({
  email: z.string().email('Please provide a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain an uppercase letter')
    .regex(/[0-9]/, 'Must contain a number')
});
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
  try {
    createUserSchema.parse({ name: '', email: 'john@example.com', age: 10 });
  } catch (error) {
    if (error instanceof ZodError) {
      const errors = error.flatten().fieldErrors;
      expect(errors.name).toBeDefined();
      expect(errors.age).toBeDefined();
    }
  }
});
```

### Integration Test with Middleware

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

## Anti-Patterns

### Validation Without Parsing

```typescript
// WRONG — parsedBody will be undefined
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(schema)) // Missing BodyParserMiddleware!
  .handle(async (context) => {
    const body = context.req.validatedBody; // undefined!
  });

// CORRECT
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyParserMiddleware())           // Parse first
  .use(new BodyValidationMiddleware(schema)) // Validate second
  .handle(async (context) => {
    const body = context.req.validatedBody!; // Guaranteed populated
  });
```

### Async Validation Without Option

```typescript
// WRONG — async refinement silently broken
.use(new BodyValidationMiddleware(asyncSchema))

// CORRECT — enable async mode
.use(new BodyValidationMiddleware(asyncSchema, { async: true }))
```

### Type Inference Gotcha with Transforms

```typescript
// z.infer gives OUTPUT type (after transforms)
const schema = z.object({
  date: z.string().transform(d => new Date(d)) // Returns Date, not string!
});
type Result = z.infer<typeof schema>; // { date: Date }
```
