# Noony Framework Validation & Schema Rules

## Zod Schema Integration

### Basic Schema Patterns with TypeScript Integration

```typescript
import { z } from 'zod';

// ✅ CORRECT: Always use z.infer for type extraction
const createUserSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Must be a valid email address'),
  age: z.number().min(18, 'Must be 18 or older').max(120, 'Invalid age'),
  role: z.enum(['user', 'admin', 'moderator']).default('user'),
  preferences: z.object({
    newsletter: z.boolean().default(false),
    theme: z.enum(['light', 'dark']).default('light')
  }).optional()
});

// Extract TypeScript type from schema
type CreateUserRequest = z.infer<typeof createUserSchema>;

// Use in handler with full type safety
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .handle(async (context) => {
    const userData = context.req.validatedBody!; // Type: CreateUserRequest
    // TypeScript knows exactly what properties are available
    const { name, email, age, role, preferences } = userData;
  });
```

### Advanced Schema Patterns

```typescript
// Complex nested validation
const orderSchema = z.object({
  customerId: z.string().uuid('Invalid customer ID format'),
  items: z.array(z.object({
    productId: z.string().uuid(),
    quantity: z.number().min(1).max(99),
    price: z.number().positive(),
    customization: z.object({
      color: z.string().optional(),
      size: z.enum(['S', 'M', 'L', 'XL']).optional(),
      engraving: z.string().max(50).optional()
    }).optional()
  })).min(1, 'At least one item is required').max(20, 'Maximum 20 items per order'),
  
  shippingAddress: z.object({
    street: z.string().min(5),
    city: z.string().min(2),
    state: z.string().length(2),
    zipCode: z.string().regex(/^\d{5}(-\d{4})?$/, 'Invalid ZIP code format'),
    country: z.string().default('US')
  }),
  
  couponCode: z.string().regex(/^[A-Z0-9]{6,12}$/).optional(),
  
  // Custom validation methods
  notes: z.string().max(500).refine(
    (val) => !val.includes('<script>'), 
    'Notes cannot contain script tags'
  ).optional()
}).refine(
  // Cross-field validation
  (data) => data.items.reduce((total, item) => total + item.price * item.quantity, 0) > 0,
  'Order total must be greater than zero'
);

type CreateOrderRequest = z.infer<typeof orderSchema>;
```

### Conditional and Dynamic Schemas

```typescript
// Conditional validation based on other fields
const userUpdateSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(2).optional(),
  email: z.string().email().optional(),
  role: z.enum(['user', 'admin', 'moderator']).optional(),
  
  // Admin-specific fields
  permissions: z.array(z.string()).optional(),
  department: z.string().optional(),
  
  // Password change fields
  currentPassword: z.string().optional(),
  newPassword: z.string().min(8).optional(),
}).refine(
  // If changing password, both fields are required
  (data) => {
    if (data.newPassword && !data.currentPassword) {
      return false;
    }
    if (data.currentPassword && !data.newPassword) {
      return false;
    }
    return true;
  },
  {
    message: 'Both current and new password are required for password change',
    path: ['newPassword']
  }
).refine(
  // Admin fields only allowed for admin role updates
  (data) => {
    if ((data.permissions || data.department) && data.role !== 'admin') {
      return false;
    }
    return true;
  },
  {
    message: 'Admin-specific fields only allowed when setting role to admin',
    path: ['role']
  }
);

type UpdateUserRequest = z.infer<typeof userUpdateSchema>;
```

## Body Validation Middleware Usage

### Basic Body Validation

```typescript
// ✅ CORRECT: Body validation after parsing
const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new BodyParserMiddleware<CreateUserRequest, AuthenticatedUser>())      // Parse first
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(   // Then validate
    createUserSchema
  ))
  .handle(async (context) => {
    // context.req.validatedBody is fully typed and validated
    const userData = context.req.validatedBody!; // Type: CreateUserRequest
  });

// ❌ INCORRECT: Validation without parsing
const badHandler = new Handler()
  .use(new BodyValidationMiddleware(schema)) // Will fail - no parsed body
  .handle(async (context) => {
    // Won't work properly
  });
```

### Custom Validation Messages

```typescript
const userSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address')
    .max(254, 'Email address is too long'),
    
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password is too long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain at least one lowercase, uppercase, number, and special character'
    ),
    
  confirmPassword: z.string()
}).refine(
  (data) => data.password === data.confirmPassword,
  {
    message: 'Passwords do not match',
    path: ['confirmPassword'] // Error will be attached to confirmPassword field
  }
);
```

## Query Parameter Validation

### Query Parameters Middleware

```typescript
class QueryValidationMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(private querySchema: z.ZodSchema<any>) {}
  
  async before(context: Context<T, U>): Promise<void> {
    try {
      const validatedQuery = this.querySchema.parse(context.req.query || {});
      context.businessData?.set('validatedQuery', validatedQuery);
    } catch (error) {
      if (error instanceof z.ZodError) {
        const messages = error.errors.map(err => `${err.path.join('.')}: ${err.message}`);
        throw new ValidationError(`Invalid query parameters: ${messages.join(', ')}`);
      }
      throw error;
    }
  }
}

// Usage with query validation
const listUsersQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(10),
  search: z.string().optional(),
  role: z.enum(['user', 'admin', 'moderator']).optional(),
  sortBy: z.enum(['name', 'email', 'createdAt']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
});

type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;

const listUsersHandler = new Handler<unknown, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<unknown, AuthenticatedUser>())
  .use(new QueryValidationMiddleware<unknown, AuthenticatedUser>(listUsersQuerySchema))
  .handle(async (context) => {
    const query = context.businessData?.get('validatedQuery') as ListUsersQuery;
    
    // Query parameters are now validated and typed
    const users = await userService.list({
      page: query.page,
      limit: query.limit,
      search: query.search,
      role: query.role,
      sortBy: query.sortBy,
      sortOrder: query.sortOrder
    });
    
    context.res.json({ users });
  });
```

## Cross-Field Validation Techniques

### Business Rule Validation

```typescript
const transferMoneySchema = z.object({
  fromAccountId: z.string().uuid(),
  toAccountId: z.string().uuid(),
  amount: z.number().positive(),
  currency: z.string().length(3),
  description: z.string().max(200).optional()
}).refine(
  // Cannot transfer to same account
  (data) => data.fromAccountId !== data.toAccountId,
  {
    message: 'Cannot transfer money to the same account',
    path: ['toAccountId']
  }
).refine(
  // Amount validation based on currency
  (data) => {
    if (data.currency === 'USD' && data.amount < 0.01) return false;
    if (data.currency === 'JPY' && data.amount < 1) return false;
    return true;
  },
  {
    message: 'Amount too small for selected currency',
    path: ['amount']
  }
);

// Advanced cross-field validation middleware
class BusinessValidationMiddleware<T extends TransferMoneyRequest, U> 
  implements BaseMiddleware<T, U> {
  
  constructor(private accountService: AccountService) {}
  
  async before(context: Context<T, U>): Promise<void> {
    const transfer = context.req.validatedBody!;
    
    // Validate accounts exist and user has access
    const [fromAccount, toAccount] = await Promise.all([
      this.accountService.getAccount(transfer.fromAccountId),
      this.accountService.getAccount(transfer.toAccountId)
    ]);
    
    if (!fromAccount) {
      throw new ValidationError('Source account not found');
    }
    if (!toAccount) {
      throw new ValidationError('Destination account not found');
    }
    
    // Validate user owns source account
    if (fromAccount.userId !== context.user!.id) {
      throw new SecurityError('You do not own the source account');
    }
    
    // Validate sufficient balance
    if (fromAccount.balance < transfer.amount) {
      throw new ValidationError('Insufficient funds');
    }
    
    // Validate currency compatibility
    if (fromAccount.currency !== transfer.currency) {
      throw new ValidationError('Currency mismatch with source account');
    }
    
    // Store validated accounts for use in handler
    context.businessData?.set('fromAccount', fromAccount);
    context.businessData?.set('toAccount', toAccount);
  }
}
```

### Date and Time Validation

```typescript
const eventSchema = z.object({
  title: z.string().min(3).max(100),
  description: z.string().max(1000).optional(),
  startDate: z.string().datetime('Invalid start date format'),
  endDate: z.string().datetime('Invalid end date format'),
  timeZone: z.string().default('UTC'),
  maxAttendees: z.number().min(1).max(1000).optional()
}).refine(
  // End date must be after start date
  (data) => new Date(data.endDate) > new Date(data.startDate),
  {
    message: 'End date must be after start date',
    path: ['endDate']
  }
).refine(
  // Event must be in the future
  (data) => new Date(data.startDate) > new Date(),
  {
    message: 'Event start date must be in the future',
    path: ['startDate']
  }
).refine(
  // Event duration must be reasonable (not longer than 30 days)
  (data) => {
    const start = new Date(data.startDate);
    const end = new Date(data.endDate);
    const diffDays = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24);
    return diffDays <= 30;
  },
  {
    message: 'Event duration cannot exceed 30 days',
    path: ['endDate']
  }
);
```

## File Upload Validation

### File Upload Schema

```typescript
const fileUploadSchema = z.object({
  filename: z.string().min(1).max(255),
  mimeType: z.enum([
    'image/jpeg',
    'image/png', 
    'image/gif',
    'application/pdf',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]),
  size: z.number().min(1).max(50 * 1024 * 1024), // 50MB max
  content: z.string().base64('File content must be base64 encoded'),
  tags: z.array(z.string().max(50)).max(10).optional()
}).refine(
  // Validate filename extension matches MIME type
  (data) => {
    const ext = data.filename.split('.').pop()?.toLowerCase();
    const mimeExtMap: Record<string, string[]> = {
      'image/jpeg': ['jpg', 'jpeg'],
      'image/png': ['png'],
      'image/gif': ['gif'],
      'application/pdf': ['pdf'],
      'text/plain': ['txt'],
      'application/msword': ['doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx']
    };
    
    const allowedExts = mimeExtMap[data.mimeType];
    return allowedExts && allowedExts.includes(ext || '');
  },
  {
    message: 'File extension does not match MIME type',
    path: ['filename']
  }
);
```

## Custom Validation Functions

### Reusable Validation Helpers

```typescript
// Custom validation functions
const validationHelpers = {
  // Password strength validation
  strongPassword: (message = 'Password does not meet security requirements') =>
    z.string().refine(
      (val) => {
        const hasLower = /[a-z]/.test(val);
        const hasUpper = /[A-Z]/.test(val);
        const hasNumber = /\d/.test(val);
        const hasSpecial = /[@$!%*?&]/.test(val);
        const isLongEnough = val.length >= 8;
        return hasLower && hasUpper && hasNumber && hasSpecial && isLongEnough;
      },
      message
    ),
  
  // Phone number validation
  phoneNumber: (message = 'Invalid phone number format') =>
    z.string().refine(
      (val) => /^\+?[1-9]\d{1,14}$/.test(val.replace(/\s|-/g, '')),
      message
    ),
  
  // Credit card validation (simple Luhn algorithm)
  creditCard: (message = 'Invalid credit card number') =>
    z.string().refine(
      (val) => {
        const num = val.replace(/\s/g, '');
        if (!/^\d{13,19}$/.test(num)) return false;
        
        // Luhn algorithm
        let sum = 0;
        let shouldDouble = false;
        for (let i = num.length - 1; i >= 0; i--) {
          let digit = parseInt(num[i]);
          if (shouldDouble) {
            digit *= 2;
            if (digit > 9) digit -= 9;
          }
          sum += digit;
          shouldDouble = !shouldDouble;
        }
        return sum % 10 === 0;
      },
      message
    ),
  
  // URL validation with specific protocols
  httpUrl: (message = 'Must be a valid HTTP/HTTPS URL') =>
    z.string().refine(
      (val) => {
        try {
          const url = new URL(val);
          return ['http:', 'https:'].includes(url.protocol);
        } catch {
          return false;
        }
      },
      message
    )
};

// Usage in schemas
const userRegistrationSchema = z.object({
  email: z.string().email(),
  password: validationHelpers.strongPassword(),
  phone: validationHelpers.phoneNumber(),
  website: validationHelpers.httpUrl().optional()
});
```

## Validation Error Handling

### Custom Validation Error Middleware

```typescript
class ValidationErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    if (error instanceof z.ZodError) {
      // Format Zod errors for better UX
      const formattedErrors = error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
        code: err.code,
        value: err.input
      }));
      
      context.res.status(400).json({
        success: false,
        error: {
          type: 'validation_error',
          message: 'Request validation failed',
          details: formattedErrors
        }
      });
      return;
    }
    
    if (error instanceof ValidationError) {
      context.res.status(400).json({
        success: false,
        error: {
          type: 'validation_error',
          message: error.message
        }
      });
      return;
    }
    
    // Let other middleware handle non-validation errors
    throw error;
  }
}
```

## Performance Optimization

### Schema Caching and Reuse

```typescript
// ✅ CORRECT: Define schemas once and reuse
const schemas = {
  createUser: z.object({
    name: z.string().min(2),
    email: z.string().email()
  }),
  
  updateUser: z.object({
    id: z.string().uuid(),
    name: z.string().min(2).optional(),
    email: z.string().email().optional()
  }).partial(),
  
  listUsers: z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(10)
  })
};

// Reuse across handlers
const createHandler = new Handler<z.infer<typeof schemas.createUser>, User>()
  .use(new BodyValidationMiddleware(schemas.createUser));

const updateHandler = new Handler<z.infer<typeof schemas.updateUser>, User>()
  .use(new BodyValidationMiddleware(schemas.updateUser));

// ❌ INCORRECT: Defining schemas inline repeatedly
const badHandler1 = new Handler()
  .use(new BodyValidationMiddleware(z.object({ name: z.string() })));

const badHandler2 = new Handler()
  .use(new BodyValidationMiddleware(z.object({ name: z.string() }))); // Duplicate
```

## Testing Validation

### Schema Testing Patterns

```typescript
describe('User Validation Schemas', () => {
  describe('createUserSchema', () => {
    it('should validate valid user data', () => {
      const validData = {
        name: 'John Doe',
        email: 'john@example.com',
        age: 25
      };
      
      expect(() => createUserSchema.parse(validData)).not.toThrow();
    });
    
    it('should reject invalid email', () => {
      const invalidData = {
        name: 'John Doe',
        email: 'invalid-email',
        age: 25
      };
      
      expect(() => createUserSchema.parse(invalidData)).toThrow(z.ZodError);
    });
    
    it('should reject underage users', () => {
      const invalidData = {
        name: 'John Doe',  
        email: 'john@example.com',
        age: 17
      };
      
      const result = createUserSchema.safeParse(invalidData);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.errors).toContainEqual(
          expect.objectContaining({
            path: ['age'],
            message: 'Must be 18 or older'
          })
        );
      }
    });
  });
});
```

## Best Practices

1. **Always use `z.infer<typeof schema>`** to extract TypeScript types
2. **Define schemas once and reuse** them across handlers
3. **Use meaningful validation messages** for better user experience
4. **Implement cross-field validation** for complex business rules
5. **Validate query parameters** in addition to request bodies
6. **Handle validation errors gracefully** with custom error middleware
7. **Test validation schemas thoroughly** with both valid and invalid data
8. **Use custom validation helpers** for reusable validation logic
9. **Consider performance impact** of complex validation rules
10. **Document validation requirements** in API documentation