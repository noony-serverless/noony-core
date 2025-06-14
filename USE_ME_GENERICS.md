# Noony Serverless Framework - Advanced Type Safety Guide

This guide demonstrates the advanced type safety features of the Noony serverless framework, showing how to leverage TypeScript generics for maximum type safety and developer experience.

## Type Safety Architecture

### Generic Context System

The framework's context system provides compile-time type safety through generics:

```typescript
interface Context<T = unknown, U = unknown> {
  req: CustomRequest<T>;     // Request with typed body data
  res: CustomResponse;       // Response object
  container?: Container;     // TypeDI dependency injection
  error?: Error | null;      // Error handling
  businessData: Map<string, unknown>; // Inter-middleware data
  user?: U;                  // Authenticated user data
}
```

**Generic Parameters:**
- `T`: Type for request body data (parsed and validated)
- `U`: Type for authenticated user data
- Both parameters flow through the entire middleware chain
- Default to `unknown` for maximum flexibility

### Typed Handler Pipeline

The `Handler` class propagates types through the entire middleware chain:

```typescript
// Define your data types
interface CreateUserRequest {
  name: string;
  email: string;
  age: number;
}

interface AuthenticatedUser {
  userId: string;
  role: 'admin' | 'user';
  permissions: string[];
}

// Create fully-typed handler
const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // TypeScript knows exact types - no casting needed!
    const userData = context.req.validatedBody!; // CreateUserRequest
    const user = context.user!; // AuthenticatedUser
    
    // Full IntelliSense and compile-time checking
    if (user.role === 'admin' && userData.age >= 18) {
      // Your logic here
    }
  });
```

**Type Flow:**
1. Handler generic types are defined once
2. All middlewares inherit these types
3. Context is fully typed throughout the pipeline
4. No type casting required in business logic

### Type-Safe Middleware Interface

All middlewares implement the generic `BaseMiddleware` interface:

```typescript
interface BaseMiddleware<T = unknown, U = unknown> {
  before?: (context: Context<T, U>) => Promise<void>;
  after?: (context: Context<T, U>) => Promise<void>;
  onError?: (error: Error, context: Context<T, U>) => Promise<void>;
}

// Example: Custom typed middleware
class TypedValidationMiddleware<T> implements BaseMiddleware<T, unknown> {
  constructor(private schema: z.ZodSchema<T>) {}
  
  async before(context: Context<T, unknown>): Promise<void> {
    try {
      // Parse and validate with full type safety
      const parsed = this.schema.parse(context.req.parsedBody);
      context.req.validatedBody = parsed; // Type T is preserved
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError('Validation failed', error.errors);
      }
      throw error;
    }
  }
}
```

## Advanced Type Patterns

### 1. Schema-First Type Generation

Leverage Zod for runtime validation and compile-time types:

```typescript
import { z } from 'zod';

// Define schema once
const userRegistrationSchema = z.object({
  personal: z.object({
    firstName: z.string().min(2),
    lastName: z.string().min(2),
    dateOfBirth: z.string().datetime(),
  }),
  contact: z.object({
    email: z.string().email(),
    phone: z.string().regex(/^\+?[1-9]\d{1,14}$/),
  }),
  preferences: z.object({
    newsletter: z.boolean().default(false),
    theme: z.enum(['light', 'dark']).default('light'),
  }).optional(),
});

// Automatically infer TypeScript type
type UserRegistration = z.infer<typeof userRegistrationSchema>;

// Use in handler with full type safety
const registerUserHandler = new Handler<UserRegistration, AdminUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(userRegistrationSchema))
  .handle(async (context) => {
    const registration = context.req.validatedBody!;
    
    // Full IntelliSense for nested objects
    const fullName = `${registration.personal.firstName} ${registration.personal.lastName}`;
    const email = registration.contact.email;
    const theme = registration.preferences?.theme ?? 'light';
    
    // Type-safe business logic
    await createUser({
      name: fullName,
      email,
      preferences: { theme }
    });
  });
```

### 2. Conditional Type Validation

Create middleware that validates based on user roles:

```typescript
// Define role-based schemas
const adminUserSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  role: z.literal('admin'),
  permissions: z.array(z.string()),
  department: z.string(),
});

const regularUserSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  role: z.literal('user'),
  preferences: z.object({
    theme: z.enum(['light', 'dark']),
    notifications: z.boolean(),
  }),
});

// Union type for different user types
type User = z.infer<typeof adminUserSchema> | z.infer<typeof regularUserSchema>;

// Middleware that handles conditional validation
class ConditionalValidationMiddleware implements BaseMiddleware<User, any> {
  async before(context: Context<User, any>): Promise<void> {
    const body = context.req.parsedBody as any;
    
    let validatedData: User;
    
    if (body.role === 'admin') {
      validatedData = adminUserSchema.parse(body);
    } else {
      validatedData = regularUserSchema.parse(body);
    }
    
    context.req.validatedBody = validatedData;
  }
}

// Usage in handler
const userHandler = new Handler<User, any>()
  .use(new ConditionalValidationMiddleware())
  .handle(async (context) => {
    const user = context.req.validatedBody!;
    
    // TypeScript knows this is a discriminated union
    if (user.role === 'admin') {
      // TypeScript knows user is AdminUser here
      console.log(`Admin ${user.name} from ${user.department}`);
      console.log(`Permissions: ${user.permissions.join(', ')}`);
    } else {
      // TypeScript knows user is RegularUser here
      console.log(`User ${user.name} prefers ${user.preferences.theme} theme`);
    }
  });
```

### 3. Multi-Schema Validation Pipeline

Handle complex validation scenarios with multiple schemas:

```typescript
// Define multiple validation schemas
const headerSchema = z.object({
  'x-api-version': z.enum(['v1', 'v2']),
  'authorization': z.string().startsWith('Bearer '),
  'content-type': z.literal('application/json'),
});

const querySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  sort: z.enum(['name', 'created', 'updated']).default('created'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

const bodySchema = z.object({
  filters: z.object({
    status: z.enum(['active', 'inactive']).optional(),
    category: z.string().optional(),
    dateRange: z.object({
      start: z.string().datetime(),
      end: z.string().datetime(),
    }).optional(),
  }),
});

// Infer types
type ValidatedHeaders = z.infer<typeof headerSchema>;
type ValidatedQuery = z.infer<typeof querySchema>;
type ValidatedBody = z.infer<typeof bodySchema>;

// Combined request type
interface ComplexRequest {
  headers: ValidatedHeaders;
  query: ValidatedQuery;
  body: ValidatedBody;
}

// Multi-validation middleware
class MultiValidationMiddleware implements BaseMiddleware<ComplexRequest, any> {
  async before(context: Context<ComplexRequest, any>): Promise<void> {
    const validatedHeaders = headerSchema.parse(context.req.headers);
    const validatedQuery = querySchema.parse(context.req.query);
    const validatedBody = bodySchema.parse(context.req.parsedBody);
    
    // Combine all validated data
    context.req.validatedBody = {
      headers: validatedHeaders,
      query: validatedQuery,
      body: validatedBody,
    };
  }
}

// Usage with full type safety
const complexSearchHandler = new Handler<ComplexRequest, AdminUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new MultiValidationMiddleware())
  .handle(async (context) => {
    const { headers, query, body } = context.req.validatedBody!;
    
    // All properties are fully typed
    const apiVersion = headers['x-api-version'];
    const pagination = { page: query.page, limit: query.limit };
    const filters = body.filters;
    
    // Type-safe database query
    const results = await searchDatabase({
      ...filters,
      pagination,
      sort: { field: query.sort, order: query.order },
    });
    
    context.res.json({
      data: results,
      pagination,
      apiVersion,
    });
  });
```

### 4. Type-Safe Error Handling

Leverage TypeScript's type system for comprehensive error handling:

```typescript
// Define custom error types with specific data
class BusinessLogicError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details: Record<string, any>
  ) {
    super(message);
    this.name = 'BusinessLogicError';
  }
}

class ValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
    public readonly value: any
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

// Type-safe error handler middleware
class TypedErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    if (error instanceof ValidationError) {
      context.res.status(400).json({
        error: 'Validation Failed',
        field: error.field,
        value: error.value,
        message: error.message,
      });
    } else if (error instanceof BusinessLogicError) {
      context.res.status(422).json({
        error: 'Business Logic Error',
        code: error.code,
        details: error.details,
        message: error.message,
      });
    } else {
      // Generic error handling
      context.res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong',
      });
    }
  }
}

// Usage in business logic
const businessHandler = new Handler<OrderRequest, CustomerUser>()
  .use(new TypedErrorHandlerMiddleware())
  .handle(async (context) => {
    const order = context.req.validatedBody!;
    
    // Type-safe error throwing
    if (order.total < 0) {
      throw new ValidationError(
        'Order total cannot be negative',
        'total',
        order.total
      );
    }
    
    if (!await hasInventory(order.items)) {
      throw new BusinessLogicError(
        'Insufficient inventory',
        'INVENTORY_SHORTAGE',
        { items: order.items }
      );
    }
    
    // Process order...
  });
```

## Advanced Type Safety Best Practices

### 1. Schema Evolution and Versioning

```typescript
// Version your schemas for backward compatibility
const userSchemaV1 = z.object({
  name: z.string(),
  email: z.string().email(),
});

const userSchemaV2 = z.object({
  firstName: z.string(),
  lastName: z.string(),
  email: z.string().email(),
  profile: z.object({
    avatar: z.string().url().optional(),
    bio: z.string().max(500).optional(),
  }).optional(),
});

// Type-safe version handling
type UserV1 = z.infer<typeof userSchemaV1>;
type UserV2 = z.infer<typeof userSchemaV2>;
type User = UserV1 | UserV2;

class VersionedValidationMiddleware implements BaseMiddleware<User, any> {
  async before(context: Context<User, any>): Promise<void> {
    const apiVersion = context.req.headers['x-api-version'];
    
    let validatedUser: User;
    
    switch (apiVersion) {
      case 'v1':
        validatedUser = userSchemaV1.parse(context.req.parsedBody);
        break;
      case 'v2':
        validatedUser = userSchemaV2.parse(context.req.parsedBody);
        break;
      default:
        throw new ValidationError('Unsupported API version', 'version', apiVersion);
    }
    
    context.req.validatedBody = validatedUser;
  }
}
```

### 2. Type-Safe Business Data Patterns

```typescript
// Create typed keys for business data
const BusinessDataKeys = {
  USER_PROFILE: 'userProfile' as const,
  CALCULATED_TOTAL: 'calculatedTotal' as const,
  PROCESSED_ITEMS: 'processedItems' as const,
} as const;

// Type-safe business data access
class TypedBusinessData {
  constructor(private data: Map<string, unknown>) {}
  
  set<T>(key: string, value: T): void {
    this.data.set(key, value);
  }
  
  get<T>(key: string): T | undefined {
    return this.data.get(key) as T | undefined;
  }
  
  require<T>(key: string): T {
    const value = this.get<T>(key);
    if (value === undefined) {
      throw new Error(`Required business data '${key}' not found`);
    }
    return value;
  }
}

// Usage in middleware
class UserProfileMiddleware implements BaseMiddleware<any, AuthenticatedUser> {
  async before(context: Context<any, AuthenticatedUser>): Promise<void> {
    const businessData = new TypedBusinessData(context.businessData);
    
    const userProfile = await this.userService.getProfile(context.user!.userId);
    businessData.set(BusinessDataKeys.USER_PROFILE, userProfile);
  }
}

class OrderCalculationMiddleware implements BaseMiddleware<OrderRequest, any> {
  async before(context: Context<OrderRequest, any>): Promise<void> {
    const businessData = new TypedBusinessData(context.businessData);
    const order = context.req.validatedBody!;
    
    const total = order.items.reduce((sum, item) => sum + item.price * item.quantity, 0);
    businessData.set(BusinessDataKeys.CALCULATED_TOTAL, total);
  }
}

// In main handler
const handler = new Handler<OrderRequest, AuthenticatedUser>()
  .use(new UserProfileMiddleware())
  .use(new OrderCalculationMiddleware())
  .handle(async (context) => {
    const businessData = new TypedBusinessData(context.businessData);
    
    // Type-safe access to business data
    const userProfile = businessData.require<UserProfile>(BusinessDataKeys.USER_PROFILE);
    const total = businessData.require<number>(BusinessDataKeys.CALCULATED_TOTAL);
    
    // Use with full type safety
    console.log(`Processing order for ${userProfile.name}, total: $${total}`);
  });
```

### 3. Generic Utility Types

```typescript
// Utility types for common patterns
type WithPagination<T> = T & {
  pagination: {
    page: number;
    limit: number;
    total?: number;
  };
};

type WithTimestamps<T> = T & {
  createdAt: string;
  updatedAt: string;
};

type ApiResponse<T> = {
  success: boolean;
  data: T;
  timestamp: string;
  version: string;
};

// Use utility types in handlers
type PaginatedUserList = WithPagination<{
  users: WithTimestamps<User>[];
}>;

const listUsersHandler = new Handler<any, AdminUser>()
  .handle(async (context) => {
    const users = await getUserList();
    
    const response: ApiResponse<PaginatedUserList> = {
      success: true,
      data: {
        users: users.map(user => ({
          ...user,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        })),
        pagination: {
          page: 1,
          limit: 20,
          total: users.length,
        },
      },
      timestamp: new Date().toISOString(),
      version: 'v2',
    };
    
    context.res.json(response);
  });
```

## Conclusion

The Noony serverless framework's type system provides:

1. **Compile-time Safety**: Catch errors during development
2. **IntelliSense Support**: Full autocomplete and documentation
3. **Refactoring Confidence**: Safe code changes across the codebase
4. **Runtime Validation**: Zod schemas ensure runtime type safety
5. **Developer Experience**: Reduced debugging and faster development

By leveraging these advanced type patterns, you can build robust, maintainable serverless applications with confidence.


