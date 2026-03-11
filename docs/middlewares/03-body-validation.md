# BodyValidationMiddleware Complete Guide

This comprehensive guide shows you how to use the `BodyValidationMiddleware` and `bodyValidatorMiddleware` with Zod schemas for type-safe request validation in your Noony Framework applications.

> **Important**: The `BodyValidationMiddleware` supports dual generics `<T, U>` where `T` is the request body type and `U` is the user/context type. This enables full type safety across your entire middleware chain.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Two Approaches Comparison](#two-approaches-comparison)
3. [Basic Usage Examples](#basic-usage-examples)
4. [Advanced Patterns](#advanced-patterns)
5. [Integration with Other Middlewares](#integration-with-other-middlewares)
6. [Error Handling](#error-handling)
7. [Real-World Examples](#real-world-examples)
8. [Best Practices](#best-practices)
9. [Common Patterns](#common-patterns)

## Quick Start

The BodyValidationMiddleware provides runtime type checking using Zod schemas, ensuring your request data is valid before it reaches your handler logic.

### Basic Setup

```typescript
import { z } from 'zod';
import { Handler, Context } from '@/core/handler';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';

// 1. Define Zod schema
const userSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  age: z.number().min(18)
});

// 2. Auto-generate TypeScript type
type UserRequest = z.infer<typeof userSchema>;

// 3. Create handler with type safety
async function handleCreateUser(context: Context<UserRequest>) {
  const user = context.req.validatedBody!; // Fully typed!
  console.log(`Creating user: ${user.name} (${user.email}), age: ${user.age}`);
  return { success: true, user: { id: '123', ...user } };
}

// 4. Use validation middleware
const createUserHandler = new Handler<UserRequest>()
  .use(new BodyValidationMiddleware(userSchema))
  .handle(handleCreateUser);
```

## Two Approaches Comparison

The framework provides two ways to validate request bodies:

### 1. Class-based Approach: `BodyValidationMiddleware<T, U>`

```typescript
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';

// Full dual generics support: <RequestType, UserType>
const handler = new Handler<UserRequest, AuthenticatedUser>()
  .use(new BodyValidationMiddleware<UserRequest, AuthenticatedUser>(userSchema))
  .handle(async (context) => {
    const data = context.req.validatedBody!; // Type: UserRequest
    const user = context.user!; // Type: AuthenticatedUser
    return { success: true };
  });
```

### 2. Functional Approach: `bodyValidatorMiddleware<T, U>()`

```typescript
import { bodyValidatorMiddleware } from '@/middlewares/bodyValidationMiddleware';

// Full dual generics support: <RequestType, UserType>
const handler = new Handler<UserRequest, AuthenticatedUser>()
  .use(bodyValidatorMiddleware<UserRequest, AuthenticatedUser>(userSchema))
  .handle(async (context) => {
    const data = context.req.parsedBody as UserRequest; // Type: UserRequest
    const user = context.user!; // Type: AuthenticatedUser  
    return { success: true };
  });
```

### When to Use Each

| Feature | Class Approach | Functional Approach |
|---------|----------------|-------------------|
| **Data Location** | `context.req.validatedBody` | `context.req.parsedBody` |
| **Usage Style** | Object instantiation | Function call |
| **Type Safety** | Explicit via generics | Requires type assertion |
| **Recommended For** | New projects, explicit APIs | Quick setup, functional style |

## Dual Generics Pattern

The `BodyValidationMiddleware` supports dual generics `<T, U>` for complete type safety:

- **T**: Request body type (validated data)  
- **U**: User/context type (authenticated user)

### Complete Integration Example

```typescript
import { Handler, Context } from '@/core/handler';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';
import { AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';

// 1. Define request schema and type
const createUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  role: z.enum(['user', 'admin']).default('user')
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

// 2. Define authenticated user type  
interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

// 3. Handler with full dual generic type safety
async function handleCreateUser(context: Context<CreateUserRequest, AuthenticatedUser>) {
  const userData = context.req.validatedBody!; // Type: CreateUserRequest
  const currentUser = context.user!; // Type: AuthenticatedUser
  
  console.log(`${currentUser.name} creating user: ${userData.name}`);
  
  return {
    success: true,
    user: {
      id: `user_${Date.now()}`,
      ...userData,
      createdBy: currentUser.id
    }
  };
}

// 4. Complete middleware chain with dual generics
export const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new AuthenticationMiddleware<AuthenticatedUser>(tokenVerifier))
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .handle(handleCreateUser);
```

### Benefits of Dual Generics

✅ **Full Type Safety**: Both request data and user context are typed  
✅ **IntelliSense Support**: Auto-completion for all properties  
✅ **Compile-time Validation**: Catch type errors during development  
✅ **Middleware Compatibility**: Works seamlessly with other typed middlewares  

## Basic Usage Examples

### Simple User Registration

```typescript
// schemas/user-schemas.ts
import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  password: z.string().min(8),
  age: z.number().int().min(18).max(120),
  newsletter: z.boolean().optional().default(false)
});

export type RegisterRequest = z.infer<typeof registerSchema>;
```

```typescript
// handlers/auth-handlers.ts
import { Handler, Context } from '@/core/handler';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';
import { registerSchema, RegisterRequest } from '../schemas/user-schemas';

async function handleUserRegistration(context: Context<RegisterRequest>) {
  const userData = context.req.validatedBody!;
  
  // Full type safety and IntelliSense
  console.log(`Registering ${userData.name} with email ${userData.email}`);
  console.log(`Newsletter subscription: ${userData.newsletter}`);
  console.log(`User age: ${userData.age}`);
  
  // Mock user creation
  const user = {
    id: `user_${Date.now()}`,
    name: userData.name,
    email: userData.email,
    age: userData.age,
    newsletterSubscribed: userData.newsletter,
    createdAt: new Date(),
    emailVerified: false
  };
  
  return { 
    success: true, 
    user,
    message: `User ${userData.name} registered successfully` 
  };
}

export const registerHandler = new Handler<RegisterRequest>()
  .use(new BodyValidationMiddleware(registerSchema))
  .handle(handleUserRegistration);
```

### Product Creation with Nested Objects

```typescript
// schemas/product-schemas.ts
export const productSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(1000),
  price: z.number().positive().multipleOf(0.01),
  category: z.enum(['electronics', 'clothing', 'books', 'home']),
  tags: z.array(z.string()).max(10),
  specifications: z.record(z.string()), // { [key: string]: string }
  availability: z.object({
    inStock: z.boolean(),
    quantity: z.number().int().min(0),
    restockDate: z.string().datetime().optional()
  }),
  metadata: z.object({
    brand: z.string(),
    model: z.string().optional(),
    warranty: z.number().int().min(0).max(120) // months
  })
});

export type ProductRequest = z.infer<typeof productSchema>;
```

```typescript
// handlers/product-handlers.ts
async function handleCreateProduct(context: Context<ProductRequest>) {
  const productData = context.req.validatedBody!;
  
  // Type-safe access to nested objects
  console.log(`Creating product: ${productData.name}`);
  console.log(`Price: $${productData.price.toFixed(2)}`);
  console.log(`Category: ${productData.category}`);
  console.log(`Brand: ${productData.metadata.brand}`);
  
  // Validate business logic
  if (!productData.availability.inStock && productData.availability.quantity > 0) {
    return {
      success: false,
      error: 'Product cannot have quantity when marked as out of stock'
    };
  }
  
  // Access specifications with full type safety
  const specs = Object.entries(productData.specifications)
    .map(([key, value]) => `${key}: ${value}`)
    .join(', ');
  
  console.log(`Specifications: ${specs}`);
  
  const product = {
    id: `prod_${Date.now()}`,
    ...productData,
    createdAt: new Date(),
    updatedAt: new Date()
  };
  
  return { success: true, product };
}

export const createProductHandler = new Handler<ProductRequest>()
  .use(new BodyValidationMiddleware(productSchema))
  .handle(handleCreateProduct);
```

## Advanced Patterns

### 1. Partial Updates with Refinement

```typescript
// schemas/update-schemas.ts
export const updateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  age: z.number().int().min(18).max(120).optional(),
  preferences: z.object({
    newsletter: z.boolean(),
    theme: z.enum(['light', 'dark']),
    language: z.string().length(2) // ISO 2-letter codes
  }).optional()
}).refine(
  data => Object.keys(data).length > 0,
  { 
    message: "At least one field must be provided for update",
    path: ['root']
  }
);

export type UpdateUserRequest = z.infer<typeof updateUserSchema>;
```

```typescript
// handlers/user-update-handlers.ts
async function handleUpdateUser(context: Context<UpdateUserRequest>) {
  const updates = context.req.validatedBody!;
  const userId = context.req.params?.id;
  
  console.log(`Updating user ${userId} with:`, Object.keys(updates));
  
  if (updates.name) {
    console.log(`New name: ${updates.name}`);
  }
  
  if (updates.email) {
    console.log(`New email: ${updates.email}`);
  }
  
  if (updates.preferences) {
    console.log(`New preferences:`, updates.preferences);
  }
  
  // Mock update operation
  const updatedUser = {
    id: userId,
    ...updates,
    updatedAt: new Date()
  };
  
  return { success: true, user: updatedUser };
}

export const updateUserHandler = new Handler<UpdateUserRequest>()
  .use(new BodyValidationMiddleware(updateUserSchema))
  .handle(handleUpdateUser);
```

### 2. Conditional Schema Validation

```typescript
// Dynamic validation based on request type
const baseActionSchema = z.object({
  action: z.enum(['create', 'update', 'delete']),
  timestamp: z.string().datetime()
});

const createActionSchema = baseActionSchema.extend({
  data: z.object({
    name: z.string().min(1),
    description: z.string()
  })
});

const updateActionSchema = baseActionSchema.extend({
  id: z.string().uuid(),
  data: z.object({
    name: z.string().min(1).optional(),
    description: z.string().optional()
  }).refine(data => Object.keys(data).length > 0)
});

const deleteActionSchema = baseActionSchema.extend({
  id: z.string().uuid(),
  confirm: z.literal(true)
});

async function handleDynamicAction(context: Context) {
  // First, validate the base schema to determine action type
  const baseData = baseActionSchema.parse(context.req.parsedBody);
  
  let validatedData;
  
  switch (baseData.action) {
    case 'create':
      validatedData = createActionSchema.parse(context.req.parsedBody);
      console.log(`Creating item: ${validatedData.data.name}`);
      break;
    case 'update':
      validatedData = updateActionSchema.parse(context.req.parsedBody);
      console.log(`Updating item ${validatedData.id}`);
      break;
    case 'delete':
      validatedData = deleteActionSchema.parse(context.req.parsedBody);
      console.log(`Deleting item ${validatedData.id} (confirmed: ${validatedData.confirm})`);
      break;
  }
  
  return { success: true, action: baseData.action, data: validatedData };
}

export const dynamicActionHandler = new Handler()
  .use(bodyValidatorMiddleware(baseActionSchema))
  .handle(handleDynamicAction);
```

### 3. Custom Validation with Transform

```typescript
// schemas/transform-schemas.ts
export const signupSchema = z.object({
  name: z.string().min(1).transform(name => name.trim()), // Auto-trim names
  email: z.string().email().transform(email => email.toLowerCase()), // Normalize emails
  password: z.string().min(8),
  confirmPassword: z.string(),
  birthDate: z.string().transform(str => new Date(str)), // Convert to Date
  tags: z.string().transform(str => str.split(',').map(tag => tag.trim())), // String to array
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"]
}).refine(data => {
  const age = new Date().getFullYear() - data.birthDate.getFullYear();
  return age >= 18;
}, {
  message: "Must be at least 18 years old",
  path: ["birthDate"]
});

export type SignupRequest = z.infer<typeof signupSchema>;
```

```typescript
// handlers/signup-handlers.ts
async function handleSignup(context: Context<SignupRequest>) {
  const signupData = context.req.validatedBody!;
  
  // Data is automatically transformed
  console.log(`Name (trimmed): "${signupData.name}"`);
  console.log(`Email (lowercase): ${signupData.email}`);
  console.log(`Birth date (Date object):`, signupData.birthDate);
  console.log(`Tags (array):`, signupData.tags);
  
  const user = {
    id: `user_${Date.now()}`,
    name: signupData.name, // Already trimmed
    email: signupData.email, // Already lowercase
    birthDate: signupData.birthDate, // Already a Date object
    tags: signupData.tags, // Already an array
    createdAt: new Date()
  };
  
  return { success: true, user };
}

export const signupHandler = new Handler<SignupRequest>()
  .use(new BodyValidationMiddleware(signupSchema))
  .handle(handleSignup);
```

## Integration with Other Middlewares

### With Authentication Middleware

```typescript
// handlers/authenticated-handlers.ts
import { AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';

interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

const profileUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  bio: z.string().max(500).optional(),
  preferences: z.object({
    privacy: z.enum(['public', 'private']),
    notifications: z.boolean()
  }).optional()
});

type ProfileUpdateRequest = z.infer<typeof profileUpdateSchema>;

async function handleUpdateProfile(context: Context<ProfileUpdateRequest, AuthenticatedUser>) {
  const updates = context.req.validatedBody!; // Typed as ProfileUpdateRequest
  const user = context.user!; // Typed as AuthenticatedUser
  
  console.log(`User ${user.name} (${user.email}) updating profile`);
  
  if (updates.name) {
    console.log(`Changing name from "${user.name}" to "${updates.name}"`);
  }
  
  const updatedProfile = {
    ...user,
    ...updates,
    updatedAt: new Date()
  };
  
  return { success: true, profile: updatedProfile };
}

export const updateProfileHandler = new Handler<ProfileUpdateRequest, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(profileUpdateSchema))
  .handle(handleUpdateProfile);
```

### With Dependency Injection

```typescript
// handlers/service-integrated-handlers.ts
import { DependencyInjectionMiddleware } from '@/middlewares/dependencyInjectionMiddleware';
import { UserService, EmailService } from '../services';

const userCreationSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  department: z.string().optional()
});

type UserCreationRequest = z.infer<typeof userCreationSchema>;

// Setup services
const services = [
  { id: UserService, value: new UserService() },
  { id: EmailService, value: new EmailService({ apiKey: 'test-key' }) }
];

async function handleCreateUserWithServices(context: Context<UserCreationRequest>) {
  const userData = context.req.validatedBody!;
  
  // Get services from DI container
  const userService = context.container?.get(UserService);
  const emailService = context.container?.get(EmailService);
  
  // Create user with validated data
  const user = await userService.create({
    name: userData.name,
    email: userData.email,
    department: userData.department || 'General'
  });
  
  // Send welcome email
  await emailService.sendWelcomeEmail(user.email, user.name);
  
  return { success: true, user, emailSent: true };
}

export const createUserWithServicesHandler = new Handler<UserCreationRequest>()
  .use(new DependencyInjectionMiddleware(services))
  .use(new BodyValidationMiddleware(userCreationSchema))
  .handle(handleCreateUserWithServices);
```

### Middleware Order and Best Practices

```typescript
// Complete middleware stack example
const completeUserHandler = new Handler<UserCreationRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware()) // 1. First - catches all errors
  .use(new DependencyInjectionMiddleware(services)) // 2. Setup DI container
  .use(new AuthenticationMiddleware(tokenVerifier)) // 3. Authenticate user
  .use(new BodyValidationMiddleware(userCreationSchema)) // 4. Validate request
  .use(new ResponseWrapperMiddleware()) // 5. Last - wraps response
  .handle(handleCreateUserWithServices);
```

## Error Handling

### Custom Validation Errors

```typescript
import { ValidationError } from '@/core/errors';

const businessValidationSchema = z.object({
  email: z.string().email(),
  companySize: z.number().int().min(1).max(10000),
  industry: z.string().min(1)
});

async function handleBusinessSignup(context: Context) {
  try {
    const data = context.req.validatedBody!;
    
    // Additional business validation beyond schema
    if (data.email.endsWith('@tempmail.com')) {
      throw new ValidationError('Business email required', [
        {
          code: 'invalid_email_domain',
          path: ['email'],
          message: 'Temporary email domains not allowed for business accounts'
        }
      ]);
    }
    
    if (data.companySize > 1000 && !data.industry.includes('Enterprise')) {
      throw new ValidationError('Large company validation failed', [
        {
          code: 'company_size_industry_mismatch',
          path: ['companySize', 'industry'],
          message: 'Companies with 1000+ employees must specify Enterprise industry'
        }
      ]);
    }
    
    return { success: true, message: 'Business signup successful' };
    
  } catch (error) {
    if (error instanceof ValidationError) {
      return {
        success: false,
        error: error.message,
        validationErrors: error.details
      };
    }
    throw error; // Re-throw non-validation errors
  }
}
```

### Handling Zod Validation Errors

```typescript
import { z } from 'zod';

// The middleware automatically handles ZodError and converts to ValidationError
// But you can also handle them manually for custom behavior

async function customValidationHandler(context: Context) {
  try {
    const schema = z.object({
      name: z.string().min(2, 'Name must be at least 2 characters'),
      age: z.number().min(18, 'Must be at least 18 years old')
    });
    
    const validatedData = await schema.parseAsync(context.req.parsedBody);
    return { success: true, data: validatedData };
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Custom error formatting
      const formattedErrors = error.errors.map(err => ({
        field: err.path.join('.'),
        message: err.message,
        value: err.input
      }));
      
      return {
        success: false,
        error: 'Validation failed',
        details: formattedErrors
      };
    }
    
    throw error;
  }
}
```

## Real-World Examples

### E-commerce Order Creation

```typescript
// schemas/order-schemas.ts
const orderItemSchema = z.object({
  productId: z.string().uuid(),
  quantity: z.number().int().min(1).max(99),
  customization: z.record(z.string()).optional()
});

const shippingAddressSchema = z.object({
  street: z.string().min(1),
  city: z.string().min(1),
  state: z.string().length(2), // US state codes
  zipCode: z.string().regex(/^\d{5}(-\d{4})?$/), // US zip codes
  country: z.string().length(2).default('US')
});

export const createOrderSchema = z.object({
  items: z.array(orderItemSchema).min(1).max(50),
  shippingAddress: shippingAddressSchema,
  billingAddress: shippingAddressSchema.optional(),
  paymentMethodId: z.string().uuid(),
  promoCode: z.string().optional(),
  notes: z.string().max(500).optional(),
  priority: z.enum(['standard', 'express', 'overnight']).default('standard')
});

export type CreateOrderRequest = z.infer<typeof createOrderSchema>;
```

```typescript
// handlers/order-handlers.ts
async function handleCreateOrder(context: Context<CreateOrderRequest, AuthenticatedUser>) {
  const orderData = context.req.validatedBody!;
  const user = context.user!;
  
  console.log(`Creating order for ${user.name} with ${orderData.items.length} items`);
  
  // Calculate totals
  let totalAmount = 0;
  const processedItems = [];
  
  for (const item of orderData.items) {
    console.log(`Item: ${item.productId}, Quantity: ${item.quantity}`);
    
    // Mock price calculation
    const unitPrice = 29.99; // Would fetch from database
    const itemTotal = unitPrice * item.quantity;
    totalAmount += itemTotal;
    
    processedItems.push({
      ...item,
      unitPrice,
      totalPrice: itemTotal
    });
  }
  
  // Apply promo code discount
  if (orderData.promoCode) {
    console.log(`Applying promo code: ${orderData.promoCode}`);
    totalAmount *= 0.9; // 10% discount
  }
  
  // Add shipping based on priority
  const shippingCosts = {
    standard: 5.99,
    express: 12.99,
    overnight: 24.99
  };
  
  const shippingCost = shippingCosts[orderData.priority];
  const finalTotal = totalAmount + shippingCost;
  
  console.log(`Order total: $${finalTotal.toFixed(2)} (shipping: $${shippingCost})`);
  
  const order = {
    id: `order_${Date.now()}`,
    userId: user.id,
    items: processedItems,
    shippingAddress: orderData.shippingAddress,
    billingAddress: orderData.billingAddress || orderData.shippingAddress,
    paymentMethodId: orderData.paymentMethodId,
    promoCode: orderData.promoCode,
    notes: orderData.notes,
    priority: orderData.priority,
    subtotal: totalAmount,
    shippingCost,
    totalAmount: finalTotal,
    status: 'pending',
    createdAt: new Date()
  };
  
  return { 
    success: true, 
    order,
    estimatedDelivery: new Date(Date.now() + (orderData.priority === 'overnight' ? 1 : orderData.priority === 'express' ? 2 : 5) * 24 * 60 * 60 * 1000)
  };
}

export const createOrderHandler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .handle(handleCreateOrder);
```

### Blog Post Management

```typescript
// schemas/blog-schemas.ts
const blogPostSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(100),
  excerpt: z.string().max(300).optional(),
  tags: z.array(z.string()).max(10),
  category: z.string().min(1),
  featured: z.boolean().default(false),
  publishAt: z.string().datetime().optional(),
  seoMetadata: z.object({
    metaTitle: z.string().max(60).optional(),
    metaDescription: z.string().max(160).optional(),
    canonicalUrl: z.string().url().optional()
  }).optional()
});

export type BlogPostRequest = z.infer<typeof blogPostSchema>;
```

```typescript
// handlers/blog-handlers.ts
async function handleCreateBlogPost(context: Context<BlogPostRequest, AuthenticatedUser>) {
  const postData = context.req.validatedBody!;
  const author = context.user!;
  
  // Check if user can create featured posts
  if (postData.featured && !author.roles.includes('editor')) {
    return {
      success: false,
      error: 'Only editors can create featured posts'
    };
  }
  
  // Auto-generate excerpt if not provided
  const excerpt = postData.excerpt || postData.content.substring(0, 297) + '...';
  
  // Auto-generate SEO metadata if not provided
  const seoMetadata = {
    metaTitle: postData.seoMetadata?.metaTitle || postData.title,
    metaDescription: postData.seoMetadata?.metaDescription || excerpt,
    canonicalUrl: postData.seoMetadata?.canonicalUrl
  };
  
  const blogPost = {
    id: `post_${Date.now()}`,
    title: postData.title,
    content: postData.content,
    excerpt,
    tags: postData.tags,
    category: postData.category,
    featured: postData.featured,
    publishAt: postData.publishAt ? new Date(postData.publishAt) : new Date(),
    seoMetadata,
    author: {
      id: author.id,
      name: author.name,
      email: author.email
    },
    status: postData.publishAt ? 'scheduled' : 'published',
    createdAt: new Date(),
    updatedAt: new Date()
  };
  
  console.log(`Blog post "${postData.title}" created by ${author.name}`);
  console.log(`Tags: ${postData.tags.join(', ')}`);
  console.log(`Category: ${postData.category}`);
  console.log(`Status: ${blogPost.status}`);
  
  return { success: true, post: blogPost };
}

export const createBlogPostHandler = new Handler<BlogPostRequest, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(blogPostSchema))
  .handle(handleCreateBlogPost);
```

## Best Practices

### 1. Schema Organization

```typescript
// ✅ Good: Organized schema structure
schemas/
├── user/
│   ├── create-user.schema.ts
│   ├── update-user.schema.ts
│   └── index.ts
├── product/
│   ├── create-product.schema.ts
│   ├── update-product.schema.ts
│   └── index.ts
└── common/
    ├── pagination.schema.ts
    ├── address.schema.ts
    └── index.ts
```

```typescript
// schemas/common/address.schema.ts
export const addressSchema = z.object({
  street: z.string().min(1),
  city: z.string().min(1),
  state: z.string().length(2),
  zipCode: z.string().regex(/^\d{5}(-\d{4})?$/),
  country: z.string().length(2).default('US')
});

// schemas/common/pagination.schema.ts
export const paginationSchema = z.object({
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('asc')
});

// Reuse common schemas
const userWithAddressSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  address: addressSchema
});
```

### 2. Type Safety Best Practices

```typescript
// ✅ Good: Use Handler generics for full type safety
async function handleTypedRequest(context: Context<UserRequest, AuthenticatedUser>) {
  const userData = context.req.validatedBody!; // Type: UserRequest
  const user = context.user!; // Type: AuthenticatedUser
  // Both are fully typed
}

const typedHandler = new Handler<UserRequest, AuthenticatedUser>()
  .use(new BodyValidationMiddleware(userSchema))
  .handle(handleTypedRequest);

// ❌ Avoid: Losing type information
const untypedHandler = new Handler()
  .use(new BodyValidationMiddleware(userSchema))
  .handle(async (context) => {
    const userData = context.req.validatedBody; // Type: unknown
    // No type safety
  });
```

### 3. Error Handling Best Practices

```typescript
// ✅ Good: Centralized error handling
import { ErrorHandlerMiddleware } from '@/middlewares/errorHandlerMiddleware';

const robustHandler = new Handler<UserRequest>()
  .use(new ErrorHandlerMiddleware()) // Handles ValidationError automatically
  .use(new BodyValidationMiddleware(userSchema))
  .handle(async (context) => {
    // Focus on business logic, errors are handled by middleware
    const user = context.req.validatedBody!;
    return await createUser(user);
  });
```

### 4. Schema Versioning

```typescript
// schemas/user/v1.schema.ts
export const createUserSchemaV1 = z.object({
  name: z.string().min(1),
  email: z.string().email()
});

// schemas/user/v2.schema.ts  
export const createUserSchemaV2 = createUserSchemaV1.extend({
  age: z.number().min(18),
  preferences: z.object({
    newsletter: z.boolean()
  }).optional()
});

// Version-aware handlers
export const createUserV1Handler = new Handler()
  .use(new BodyValidationMiddleware(createUserSchemaV1))
  .handle(handleCreateUserV1);

export const createUserV2Handler = new Handler()
  .use(new BodyValidationMiddleware(createUserSchemaV2))
  .handle(handleCreateUserV2);
```

## Common Patterns

### 1. Request/Response Pattern

```typescript
async function withValidation<TRequest, TResponse>(
  schema: z.ZodType<TRequest>,
  handler: (data: TRequest, context: Context) => Promise<TResponse>
) {
  return async (context: Context) => {
    const validatedData = await schema.parseAsync(context.req.parsedBody);
    return await handler(validatedData, context);
  };
}

// Usage
const createUserLogic = async (userData: UserRequest, context: Context) => {
  console.log(`Creating user: ${userData.name}`);
  return { success: true, user: { id: '123', ...userData } };
};

const createUserHandler = new Handler()
  .handle(withValidation(userSchema, createUserLogic));
```

### 2. Multi-Step Validation

```typescript
// Step 1: Basic validation
const stepOneSchema = z.object({
  email: z.string().email(),
  step: z.literal('verify_email')
});

// Step 2: Code verification
const stepTwoSchema = z.object({
  email: z.string().email(),
  verificationCode: z.string().length(6),
  step: z.literal('verify_code')
});

// Step 3: Complete registration
const stepThreeSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1),
  password: z.string().min(8),
  step: z.literal('complete_registration')
});

async function handleMultiStepRegistration(context: Context) {
  const baseData = z.object({ step: z.string() }).parse(context.req.parsedBody);
  
  switch (baseData.step) {
    case 'verify_email':
      const emailData = stepOneSchema.parse(context.req.parsedBody);
      return await sendVerificationEmail(emailData.email);
      
    case 'verify_code':
      const codeData = stepTwoSchema.parse(context.req.parsedBody);
      return await verifyCode(codeData.email, codeData.verificationCode);
      
    case 'complete_registration':
      const regData = stepThreeSchema.parse(context.req.parsedBody);
      return await completeRegistration(regData);
      
    default:
      throw new ValidationError('Invalid step', [{ 
        code: 'invalid_step', 
        path: ['step'], 
        message: 'Step must be verify_email, verify_code, or complete_registration' 
      }]);
  }
}
```

### 3. Conditional Field Validation

```typescript
const orderSchema = z.object({
  items: z.array(z.object({
    productId: z.string(),
    quantity: z.number().min(1)
  })),
  shippingMethod: z.enum(['pickup', 'delivery']),
  // Conditional fields
  deliveryAddress: z.object({
    street: z.string(),
    city: z.string(),
    zipCode: z.string()
  }).optional(),
  pickupStore: z.string().optional()
}).refine((data) => {
  if (data.shippingMethod === 'delivery') {
    return !!data.deliveryAddress;
  }
  if (data.shippingMethod === 'pickup') {
    return !!data.pickupStore;
  }
  return true;
}, {
  message: "Delivery address required when shipping method is 'delivery'",
  path: ["deliveryAddress"]
}).refine((data) => {
  if (data.shippingMethod === 'pickup') {
    return !!data.pickupStore;
  }
  return true;
}, {
  message: "Pickup store required when shipping method is 'pickup'",
  path: ["pickupStore"]
});
```

This comprehensive guide shows you how to use the BodyValidationMiddleware effectively with Zod schemas for type-safe, validated request handling in your Noony Framework applications. The combination of runtime validation and compile-time type safety provides a robust foundation for building reliable APIs.
