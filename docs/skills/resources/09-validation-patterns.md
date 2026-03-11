# Skill 09: Validation Schemas - Complete Patterns

## Overview

Zod schema validation provides runtime type safety for incoming requests. The Noony Framework validates data through the `BodyValidationMiddleware` and makes validated data available at `context.req.validatedBody`.

## Middleware Order: BodyParser → BodyValidation

Critical ordering pattern:

```typescript
// ✅ CORRECT ORDER
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())        // 1. Parse raw body → context.req.parsedBody
  .use(new BodyValidationMiddleware(schema)) // 2. Validate → context.req.validatedBody
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const body = context.req.validatedBody!; // Type: CreateUserRequest
  });
```

**Why This Order Matters:**
- BodyParserMiddleware converts raw request body to `parsedBody`
- BodyValidationMiddleware validates `parsedBody` and populates `validatedBody`
- Authentication comes after validation (validate input before checking permissions)

## parsedBody vs validatedBody

```typescript
interface GenericRequest<T> {
  body: unknown;           // Raw request body (string/Buffer)
  parsedBody: T;           // Parsed JSON (type: unknown)
  validatedBody?: T;       // Zod validated (type: T)
}
```

**Example Flow:**

```typescript
const createUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  age: z.number().min(18)
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    // Request body: { "name": "", "email": "invalid", "age": "abc" }

    // After BodyParserMiddleware:
    context.req.parsedBody; // { name: "", email: "invalid", age: "abc" } (type: unknown)

    // After BodyValidationMiddleware (if valid):
    context.req.validatedBody; // { name: "...", email: "...", age: 25 } (type: CreateUserRequest)

    // If invalid, BodyValidationMiddleware throws ValidationError (400)
    // validatedBody is never populated
  });
```

## Schema Patterns

### 1. Basic Object Schema

```typescript
import { z } from 'zod';

const createUserSchema = z.object({
  // Required string field
  name: z.string()
    .min(1, 'Name is required')
    .max(100, 'Name too long'),

  // Email validation
  email: z.string()
    .email('Invalid email format'),

  // Number with range
  age: z.number()
    .min(18, 'Must be 18 or older')
    .max(120, 'Invalid age'),

  // Optional field
  phone: z.string().optional(),

  // Field with default value
  role: z.enum(['user', 'admin']).default('user')
});

type CreateUserRequest = z.infer<typeof createUserSchema>;
```

**Usage:**

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    const { name, email, age, phone, role } = context.req.validatedBody!;
    // All fields fully typed!
  });
```

### 2. Nested Objects

```typescript
const createOrderSchema = z.object({
  productId: z.string().uuid(),
  quantity: z.number().min(1).max(1000),

  // Nested object
  shippingAddress: z.object({
    street: z.string().min(1),
    city: z.string().min(1),
    state: z.string().length(2),
    zipCode: z.string().regex(/^\d{5}(-\d{4})?$/, 'Invalid ZIP code'),
    country: z.string().default('US')
  }),

  // Nested with optional
  billingAddress: z.object({
    street: z.string(),
    city: z.string()
  }).optional()
});

type CreateOrderRequest = z.infer<typeof createOrderSchema>;

const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new BodyValidationMiddleware(createOrderSchema))
  .handle(async (context) => {
    const { shippingAddress, billingAddress } = context.req.validatedBody!;

    if (billingAddress) {
      // billingAddress is now typed correctly
      console.log(billingAddress.street);
    }
  });
```

### 3. Array Validation

```typescript
// Array of strings
const tagsSchema = z.object({
  tags: z.array(z.string().min(1).max(50))
    .min(1, 'At least one tag required')
    .max(10, 'Too many tags')
});

// Array of objects
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

const handler = new Handler<CreateProjectRequest, AuthUser>()
  .use(new BodyValidationMiddleware(createProjectSchema))
  .handle(async (context) => {
    const { name, tasks } = context.req.validatedBody!;

    // tasks is fully typed as array of task objects
    tasks.forEach(task => {
      console.log(task.title, task.priority); // Full type safety
    });
  });
```

### 4. Enum Validation

```typescript
const updateProfileSchema = z.object({
  theme: z.enum(['light', 'dark', 'auto']),

  // Enum with multiple values
  notifications: z.object({
    email: z.boolean(),
    push: z.boolean(),
    sms: z.boolean().optional()
  }),

  // Union of enums
  subscriptionTier: z.union([
    z.literal('free'),
    z.literal('pro'),
    z.literal('enterprise')
  ])
});

type UpdateProfileRequest = z.infer<typeof updateProfileSchema>;
```

### 5. Custom Validation

```typescript
const createPaymentSchema = z.object({
  amount: z.number()
    .min(0.01, 'Amount must be positive')
    .refine(
      (val) => val % 0.01 === 0, // 2 decimal places
      'Amount must have at most 2 decimal places'
    ),

  cardNumber: z.string()
    .refine(
      (val) => /^\d{16}$/.test(val),
      'Invalid card number'
    )
    .refine(
      (val) => luhnCheck(val), // Custom function
      'Card number failed validation'
    ),

  expiryDate: z.string()
    .regex(/^\d{2}\/\d{2}$/, 'Format: MM/YY')
    .refine((val) => {
      const [month, year] = val.split('/').map(Number);
      const expiry = new Date(2000 + year, month);
      return expiry > new Date();
    }, 'Card has expired')
});

type CreatePaymentRequest = z.infer<typeof createPaymentSchema>;

function luhnCheck(cardNumber: string): boolean {
  // Implementation of Luhn algorithm
  return true; // Simplified
}
```

### 6. Async Validation

```typescript
const registerUserSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3)
}).refine(
  async (data) => {
    // Check if email already exists in database
    const exists = await userService.findByEmail(data.email);
    return !exists;
  },
  {
    message: 'Email already registered',
    path: ['email']
  }
);

// Must use parseAsync instead of parse
const handler = new Handler<any, AuthUser>()
  .use(new BodyValidationMiddleware(registerUserSchema, { async: true }))
  .handle(async (context) => {
    // validatedBody only populated if async validation passes
    const { email, username } = context.req.validatedBody!;
  });
```

## Error Handling for Validation Failures

### Automatic Error Handling

BodyValidationMiddleware throws `ValidationError` (400) automatically:

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware()) // Catches ValidationError
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    // If validation fails, handler never reaches here
    // ErrorHandlerMiddleware returns 400 with Zod error details
  });

// Invalid request body: { "name": "", "email": "invalid" }
// Response: 400 Bad Request
// Body: {
//   "success": false,
//   "error": {
//     "code": "VALIDATION_ERROR",
//     "message": "Request validation failed",
//     "details": [
//       { "path": ["name"], "message": "String must contain at least 1 character(s)" },
//       { "path": ["email"], "message": "Invalid email" }
//     ]
//   }
// }
```

### Custom Error Messages

```typescript
const schema = z.object({
  email: z.string()
    .email('Please provide a valid email address')
    .min(1, 'Email is required'),

  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain uppercase letter')
    .regex(/[0-9]/, 'Must contain a number')
});

// Validation error response includes your custom messages
```

### Handling Within Middleware

```typescript
const customValidationMiddleware = <TBody = unknown, TUser = unknown>():
  BaseMiddleware<TBody, TUser> => ({
  before: async (context: Context<TBody, TUser>) => {
    try {
      const validated = await schema.parseAsync(context.req.parsedBody);
      context.req.validatedBody = validated;
    } catch (error) {
      if (error instanceof ZodError) {
        // Custom error handling
        throw new ValidationError(
          'Custom validation failed: ' + error.errors[0].message,
          error.errors
        );
      }
      throw error;
    }
  }
});
```

## Pub/Sub Message Validation

Pub/Sub messages require special handling - the actual message is in `data` field:

```typescript
const pubsubMessageSchema = z.object({
  message: z.object({
    data: z.string().transform((base64) => {
      // Decode base64 and parse JSON
      const json = Buffer.from(base64, 'base64').toString('utf-8');
      return JSON.parse(json);
    }),
    attributes: z.record(z.string()),
    messageId: z.string(),
    publishTime: z.string()
  })
});

// Then validate the decoded data
const orderEventSchema = z.object({
  orderId: z.string(),
  status: z.enum(['pending', 'confirmed', 'shipped']),
  timestamp: z.string().datetime()
});

type OrderEvent = z.infer<typeof orderEventSchema>;

const handler = new Handler<any, void>()
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(pubsubMessageSchema))
  .handle(async (context) => {
    const decodedData = context.req.validatedBody.message.data;

    // Validate decoded data
    const orderEvent = orderEventSchema.parse(decodedData);
    const { orderId, status } = orderEvent;

    // Process event
    await eventService.handle(orderEvent);
  });
```

## Testing Validation Schemas

### Unit Test Valid Data

```typescript
import { createUserSchema } from './schemas';

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

### Unit Test Invalid Data

```typescript
it('should reject invalid email', () => {
  const invalidData = {
    name: 'John',
    email: 'not-an-email',
    age: 30
  };

  expect(() => createUserSchema.parse(invalidData)).toThrow();
});

it('should provide specific error messages', () => {
  const invalidData = {
    name: '',
    email: 'john@example.com',
    age: 10 // Too young
  };

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
      req: {
        parsedBody: { name: '', email: 'invalid' }
      },
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

## Anti-Patterns to Avoid

### ❌ Validation Without Parsing

```typescript
// WRONG - validatedBody will be undefined
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(schema)) // Missing BodyParserMiddleware!
  .handle(async (context) => {
    const body = context.req.validatedBody; // undefined!
  });
```

### ✅ Correct Pattern

```typescript
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyParserMiddleware())           // Parse first
  .use(new BodyValidationMiddleware(schema)) // Validate second
  .handle(async (context) => {
    const body = context.req.validatedBody!; // Guaranteed populated
  });
```

### ❌ Redundant Validation

```typescript
// WRONG - Validating twice
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(schema1))
  .use(new BodyValidationMiddleware(schema2)) // Redundant!
  .handle(async (context) => {
    // Second validation overwrites first
  });
```

### ❌ Async Validation Without Option

```typescript
// WRONG - Async validation not enabled
const asyncSchema = z.object({
  email: z.string().refine(
    async (email) => !(await userService.exists(email)),
    'Email exists'
  )
});

const handler = new Handler<any, AuthUser>()
  .use(new BodyValidationMiddleware(asyncSchema)) // Missing async option!
  .handle(async (context) => {
    // Async validation will not work
  });
```

### ✅ Correct Async Pattern

```typescript
const handler = new Handler<any, AuthUser>()
  .use(new BodyValidationMiddleware(asyncSchema, { async: true }))
  .handle(async (context) => {
    // Now async validation works
  });
```

## Common Gotchas and Solutions

### Gotcha 1: Type Inference Not Working

```typescript
// ❌ WRONG - Type not inferred
const handler = new Handler<unknown>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // context.req.validatedBody is type unknown!
  });

// ✅ CORRECT - Explicit type
type CreateUserRequest = z.infer<typeof schema>;
const handler = new Handler<CreateUserRequest>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // context.req.validatedBody is CreateUserRequest
  });
```

### Gotcha 2: Transform Losing Type

```typescript
// ❌ WRONG - Type lost in transform
const schema = z.object({
  date: z.string().transform(d => new Date(d)) // Returns Date, not string!
});

type Req = z.infer<typeof schema>;
const handler = new Handler<Req>()
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // context.req.validatedBody.date is Date, not string
  });
```

### Gotcha 3: Missing Error Handler

```typescript
// ❌ WRONG - ValidationError not caught
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware(schema)) // No error handler!
  .handle(async (context) => {
    // If validation fails, unhandled error crashes function
  });

// ✅ CORRECT
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware()) // Catches validation errors
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // Validation errors are handled and return 400
  });
```

## Performance Considerations

1. **Schema Reuse**: Define schemas once, reuse across handlers
   ```typescript
   export const createUserSchema = z.object({...});
   export const updateUserSchema = createUserSchema.partial();
   ```

2. **Lazy Validation**: Use `.refine()` for expensive checks last
   ```typescript
   z.object({
     email: z.string().email() // Fast check first
       .refine(async (email) => {
         const exists = await db.findByEmail(email); // Slow check last
         return !exists;
       })
   });
   ```

3. **Async Validation**: Only use async when necessary (database checks)
   ```typescript
   // ✅ Sync only - fast
   z.object({ email: z.string().email() })

   // ⚠️ Async - slower, only when needed
   z.object({ email: z.string().refine(async (e) => {...}) })
   ```
