# BodyParserMiddleware Complete Guide

This comprehensive guide shows you how to use the `BodyParserMiddleware` and `bodyParser` function with generics for type-safe request body parsing in your Noony Framework applications.

> **Important**: The `BodyParserMiddleware` supports generic type `<T>` where `T` is the expected parsed body type. This enables full type safety for your request data with automatic JSON parsing, Pub/Sub message decoding, and size validation.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Two Approaches Comparison](#two-approaches-comparison)
3. [Basic Usage Examples](#basic-usage-examples)
4. [Advanced Patterns](#advanced-patterns)
5. [Pub/Sub Message Handling](#pubsub-message-handling)
6. [Integration with Other Middlewares](#integration-with-other-middlewares)
7. [Error Handling](#error-handling)
8. [Real-World Examples](#real-world-examples)
9. [Best Practices](#best-practices)
10. [Performance Features](#performance-features)
11. [Common Patterns](#common-patterns)

## Quick Start

The BodyParserMiddleware provides automatic request body parsing with support for JSON, Pub/Sub messages, and configurable size limits. It parses the raw request body and makes it available as a typed object.

### Basic Setup

```typescript
import { Handler, Context } from '@/core/handler';
import { BodyParserMiddleware } from '@/middlewares/bodyParserMiddleware';

// 1. Define your request type
interface CreateUserRequest {
  name: string;
  email: string;
  age: number;
  preferences: {
    newsletter: boolean;
    theme: 'light' | 'dark';
  };
}

// 2. Use BodyParserMiddleware with generic type
const createUserHandler = new Handler<CreateUserRequest>()
  .use(new BodyParserMiddleware<CreateUserRequest>())
  .handle(async (context) => {
    // context.req.parsedBody is now typed as CreateUserRequest
    const userData = context.req.parsedBody as CreateUserRequest;
    
    console.log(`Creating user: ${userData.name} (${userData.email})`);
    console.log(`Age: ${userData.age}, Newsletter: ${userData.preferences.newsletter}`);
    
    return { 
      success: true, 
      userId: generateId(), 
      data: userData 
    };
  });
```

## Two Approaches Comparison

The framework provides two ways to parse request bodies:

### 1. Class-based Approach: `BodyParserMiddleware<T>`

```typescript
import { BodyParserMiddleware } from '@/middlewares/bodyParserMiddleware';

// Full generic support with custom size limit
const handler = new Handler<ProductRequest>()
  .use(new BodyParserMiddleware<ProductRequest>(2 * 1024 * 1024)) // 2MB limit
  .handle(async (context) => {
    const product = context.req.parsedBody as ProductRequest;
    return { success: true, product };
  });
```

### 2. Functional Approach: `bodyParser<T>()`

```typescript
import { bodyParser } from '@/middlewares/bodyParserMiddleware';

// Functional style with generic type and custom size
const handler = new Handler<ProductRequest>()
  .use(bodyParser<ProductRequest>(2 * 1024 * 1024)) // 2MB limit
  .handle(async (context) => {
    const product = context.req.parsedBody as ProductRequest;
    return { success: true, product };
  });
```

### When to Use Each

| Feature | Class Approach | Functional Approach |
|---------|----------------|-------------------|
| **Usage Style** | Object instantiation | Function call |
| **Data Location** | `context.req.parsedBody` | `context.req.parsedBody` |
| **Type Safety** | Via generic `<T>` | Via generic `<T>` |
| **Customization** | Constructor parameters | Function parameters |
| **Recommended For** | Explicit object-oriented style | Functional programming style |

Both approaches provide identical functionality and type safety.

## Basic Usage Examples

### Simple API Request Parsing

```typescript
// types/api-types.ts
interface CreateProductRequest {
  name: string;
  description: string;
  price: number;
  category: string;
  tags: string[];
  inStock: boolean;
}

// handlers/product-handlers.ts
import { Handler, Context } from '@/core/handler';
import { BodyParserMiddleware } from '@/middlewares/bodyParserMiddleware';

async function handleCreateProduct(context: Context<CreateProductRequest>) {
  const productData = context.req.parsedBody as CreateProductRequest;
  
  // Full type safety and IntelliSense
  console.log(`Creating product: ${productData.name}`);
  console.log(`Price: $${productData.price.toFixed(2)}`);
  console.log(`Category: ${productData.category}`);
  console.log(`Tags: ${productData.tags.join(', ')}`);
  console.log(`In Stock: ${productData.inStock}`);
  
  // Mock product creation
  const product = {
    id: `prod_${Date.now()}`,
    ...productData,
    createdAt: new Date(),
    updatedAt: new Date()
  };
  
  return { 
    success: true, 
    product,
    message: `Product "${productData.name}" created successfully` 
  };
}

export const createProductHandler = new Handler<CreateProductRequest>()
  .use(new BodyParserMiddleware<CreateProductRequest>())
  .handle(handleCreateProduct);
```

### Complex Nested Objects

```typescript
// types/order-types.ts
interface OrderItem {
  productId: string;
  quantity: number;
  customization?: Record<string, string>;
}

interface ShippingAddress {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

interface CreateOrderRequest {
  items: OrderItem[];
  shippingAddress: ShippingAddress;
  billingAddress?: ShippingAddress;
  paymentMethod: {
    type: 'credit_card' | 'paypal' | 'bank_transfer';
    token: string;
  };
  notes?: string;
  priority: 'standard' | 'express' | 'overnight';
}

// handlers/order-handlers.ts
async function handleCreateOrder(context: Context<CreateOrderRequest>) {
  const orderData = context.req.parsedBody as CreateOrderRequest;
  
  // Type-safe access to nested objects
  console.log(`Order with ${orderData.items.length} items`);
  console.log(`Shipping to: ${orderData.shippingAddress.city}, ${orderData.shippingAddress.state}`);
  console.log(`Payment method: ${orderData.paymentMethod.type}`);
  console.log(`Priority: ${orderData.priority}`);
  
  // Process each item with full type safety
  const processedItems = orderData.items.map(item => {
    console.log(`Item ${item.productId}: quantity ${item.quantity}`);
    
    if (item.customization) {
      const customizations = Object.entries(item.customization)
        .map(([key, value]) => `${key}: ${value}`)
        .join(', ');
      console.log(`  Customizations: ${customizations}`);
    }
    
    return {
      ...item,
      unitPrice: 29.99, // Would fetch from database
      totalPrice: 29.99 * item.quantity
    };
  });
  
  const totalAmount = processedItems.reduce((sum, item) => sum + item.totalPrice, 0);
  
  const order = {
    id: `order_${Date.now()}`,
    items: processedItems,
    shippingAddress: orderData.shippingAddress,
    billingAddress: orderData.billingAddress || orderData.shippingAddress,
    paymentMethod: orderData.paymentMethod,
    notes: orderData.notes,
    priority: orderData.priority,
    totalAmount,
    status: 'pending',
    createdAt: new Date()
  };
  
  return { success: true, order };
}

export const createOrderHandler = new Handler<CreateOrderRequest>()
  .use(new BodyParserMiddleware<CreateOrderRequest>())
  .handle(handleCreateOrder);
```

### Array and Union Types

```typescript
// types/batch-types.ts
interface BatchCreateUsersRequest {
  users: Array<{
    name: string;
    email: string;
    role: 'admin' | 'user' | 'moderator';
    department?: string;
  }>;
  notify: boolean;
  template?: 'welcome' | 'business' | 'custom';
}

// handlers/batch-handlers.ts
async function handleBatchCreateUsers(context: Context<BatchCreateUsersRequest>) {
  const batchData = context.req.parsedBody as BatchCreateUsersRequest;
  
  console.log(`Creating ${batchData.users.length} users`);
  console.log(`Notifications enabled: ${batchData.notify}`);
  console.log(`Template: ${batchData.template || 'default'}`);
  
  const createdUsers = [];
  
  for (const userData of batchData.users) {
    console.log(`Creating user: ${userData.name} (${userData.email})`);
    console.log(`Role: ${userData.role}`);
    
    if (userData.department) {
      console.log(`Department: ${userData.department}`);
    }
    
    const user = {
      id: `user_${Date.now()}_${Math.random()}`,
      ...userData,
      createdAt: new Date()
    };
    
    createdUsers.push(user);
  }
  
  return {
    success: true,
    created: createdUsers.length,
    users: createdUsers,
    notificationsSent: batchData.notify
  };
}

export const batchCreateUsersHandler = new Handler<BatchCreateUsersRequest>()
  .use(new BodyParserMiddleware<BatchCreateUsersRequest>())
  .handle(handleBatchCreateUsers);
```

## Advanced Patterns

### 1. Custom Size Limits for Different Endpoints

```typescript
// Small payloads (default 1MB)
const userHandler = new Handler<UserRequest>()
  .use(new BodyParserMiddleware<UserRequest>()) // Default 1MB
  .handle(handleCreateUser);

// Medium payloads (5MB for file uploads)
const uploadHandler = new Handler<FileUploadRequest>()
  .use(new BodyParserMiddleware<FileUploadRequest>(5 * 1024 * 1024)) // 5MB
  .handle(handleFileUpload);

// Large payloads (10MB for bulk operations)
const bulkHandler = new Handler<BulkOperationRequest>()
  .use(new BodyParserMiddleware<BulkOperationRequest>(10 * 1024 * 1024)) // 10MB
  .handle(handleBulkOperation);

// Functional approach with custom sizes
const customSizeHandler = new Handler<DataImportRequest>()
  .use(bodyParser<DataImportRequest>(20 * 1024 * 1024)) // 20MB
  .handle(handleDataImport);
```

### 2. Dynamic Type Parsing

```typescript
// Base type for all actions
interface BaseActionRequest {
  action: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

// Specific action types
interface CreateActionRequest extends BaseActionRequest {
  action: 'create';
  data: {
    name: string;
    description: string;
  };
}

interface UpdateActionRequest extends BaseActionRequest {
  action: 'update';
  id: string;
  data: Partial<{
    name: string;
    description: string;
  }>;
}

interface DeleteActionRequest extends BaseActionRequest {
  action: 'delete';
  id: string;
  confirm: boolean;
}

type DynamicActionRequest = CreateActionRequest | UpdateActionRequest | DeleteActionRequest;

async function handleDynamicAction(context: Context<DynamicActionRequest>) {
  const actionData = context.req.parsedBody as DynamicActionRequest;
  
  console.log(`Processing ${actionData.action} action at ${actionData.timestamp}`);
  
  switch (actionData.action) {
    case 'create':
      console.log(`Creating item: ${actionData.data.name}`);
      console.log(`Description: ${actionData.data.description}`);
      return { success: true, action: 'create', created: true };
      
    case 'update':
      console.log(`Updating item ${actionData.id}`);
      console.log(`Updates:`, actionData.data);
      return { success: true, action: 'update', updated: true };
      
    case 'delete':
      console.log(`Deleting item ${actionData.id}`);
      console.log(`Confirmed: ${actionData.confirm}`);
      
      if (!actionData.confirm) {
        return { success: false, error: 'Delete action requires confirmation' };
      }
      
      return { success: true, action: 'delete', deleted: true };
      
    default:
      return { success: false, error: 'Invalid action type' };
  }
}

export const dynamicActionHandler = new Handler<DynamicActionRequest>()
  .use(new BodyParserMiddleware<DynamicActionRequest>())
  .handle(handleDynamicAction);
```

### 3. Generic Utility Functions

```typescript
// Utility function for creating typed body parser handlers
function createTypedHandler<T>(
  parser: (data: T) => Promise<any>,
  maxSize?: number
) {
  return new Handler<T>()
    .use(new BodyParserMiddleware<T>(maxSize))
    .handle(async (context) => {
      const data = context.req.parsedBody as T;
      return await parser(data);
    });
}

// Usage examples
interface BlogPostRequest {
  title: string;
  content: string;
  tags: string[];
}

const createBlogPostLogic = async (data: BlogPostRequest) => {
  console.log(`Creating blog post: ${data.title}`);
  console.log(`Content length: ${data.content.length}`);
  console.log(`Tags: ${data.tags.join(', ')}`);
  
  return {
    success: true,
    post: {
      id: `post_${Date.now()}`,
      ...data,
      createdAt: new Date()
    }
  };
};

// Create handler with automatic type safety
export const createBlogPostHandler = createTypedHandler<BlogPostRequest>(
  createBlogPostLogic,
  2 * 1024 * 1024 // 2MB limit for blog posts
);
```

## Pub/Sub Message Handling

The BodyParserMiddleware automatically handles Google Cloud Pub/Sub messages by detecting the message format and decoding base64 data.

### Basic Pub/Sub Handler

```typescript
// types/pubsub-types.ts
interface UserEventData {
  eventType: 'user.created' | 'user.updated' | 'user.deleted';
  userId: string;
  timestamp: string;
  payload: {
    name?: string;
    email?: string;
    previousValues?: Record<string, any>;
  };
  metadata: {
    source: string;
    version: string;
  };
}

// handlers/pubsub-handlers.ts
async function handleUserEvent(context: Context<UserEventData>) {
  // BodyParserMiddleware automatically decodes the Pub/Sub base64 message
  const eventData = context.req.parsedBody as UserEventData;
  
  console.log(`Processing ${eventData.eventType} for user ${eventData.userId}`);
  console.log(`Event timestamp: ${eventData.timestamp}`);
  console.log(`Source: ${eventData.metadata.source}`);
  
  switch (eventData.eventType) {
    case 'user.created':
      console.log(`New user created: ${eventData.payload.name} (${eventData.payload.email})`);
      await sendWelcomeEmail(eventData.payload.email!, eventData.payload.name!);
      break;
      
    case 'user.updated':
      console.log(`User updated: ${eventData.userId}`);
      console.log(`Changes:`, eventData.payload);
      console.log(`Previous values:`, eventData.payload.previousValues);
      break;
      
    case 'user.deleted':
      console.log(`User deleted: ${eventData.userId}`);
      await cleanupUserData(eventData.userId);
      break;
  }
  
  return { 
    success: true, 
    eventType: eventData.eventType,
    userId: eventData.userId,
    processed: true 
  };
}

export const userEventHandler = new Handler<UserEventData>()
  .use(new BodyParserMiddleware<UserEventData>())
  .handle(handleUserEvent);

// Mock functions
async function sendWelcomeEmail(email: string, name: string) {
  console.log(`Sending welcome email to ${email} for ${name}`);
}

async function cleanupUserData(userId: string) {
  console.log(`Cleaning up data for user ${userId}`);
}
```

### Complex Pub/Sub Event Processing

```typescript
// types/order-events.ts
interface OrderEventData {
  eventType: 'order.placed' | 'order.paid' | 'order.shipped' | 'order.delivered' | 'order.cancelled';
  orderId: string;
  userId: string;
  timestamp: string;
  payload: {
    order?: {
      id: string;
      items: Array<{
        productId: string;
        quantity: number;
        price: number;
      }>;
      totalAmount: number;
      shippingAddress: {
        street: string;
        city: string;
        state: string;
        zipCode: string;
      };
    };
    payment?: {
      transactionId: string;
      amount: number;
      method: string;
    };
    shipping?: {
      trackingNumber: string;
      carrier: string;
      estimatedDelivery: string;
    };
    cancellation?: {
      reason: string;
      refundAmount: number;
    };
  };
  metadata: {
    source: string;
    correlationId: string;
    version: string;
  };
}

// handlers/order-event-handlers.ts
async function handleOrderEvent(context: Context<OrderEventData>) {
  const eventData = context.req.parsedBody as OrderEventData;
  
  console.log(`Processing ${eventData.eventType} for order ${eventData.orderId}`);
  console.log(`User: ${eventData.userId}`);
  console.log(`Correlation ID: ${eventData.metadata.correlationId}`);
  
  switch (eventData.eventType) {
    case 'order.placed':
      if (eventData.payload.order) {
        const order = eventData.payload.order;
        console.log(`Order placed: ${order.id}`);
        console.log(`Items: ${order.items.length}`);
        console.log(`Total: $${order.totalAmount.toFixed(2)}`);
        console.log(`Shipping to: ${order.shippingAddress.city}, ${order.shippingAddress.state}`);
        
        // Process each item
        for (const item of order.items) {
          console.log(`- Product ${item.productId}: ${item.quantity} × $${item.price.toFixed(2)}`);
        }
        
        await sendOrderConfirmation(eventData.userId, order);
        await updateInventory(order.items);
      }
      break;
      
    case 'order.paid':
      if (eventData.payload.payment) {
        const payment = eventData.payload.payment;
        console.log(`Payment processed: ${payment.transactionId}`);
        console.log(`Amount: $${payment.amount.toFixed(2)}`);
        console.log(`Method: ${payment.method}`);
        
        await sendPaymentConfirmation(eventData.userId, payment);
        await initiateShipping(eventData.orderId);
      }
      break;
      
    case 'order.shipped':
      if (eventData.payload.shipping) {
        const shipping = eventData.payload.shipping;
        console.log(`Order shipped with ${shipping.carrier}`);
        console.log(`Tracking: ${shipping.trackingNumber}`);
        console.log(`Estimated delivery: ${shipping.estimatedDelivery}`);
        
        await sendShippingNotification(eventData.userId, shipping);
      }
      break;
      
    case 'order.delivered':
      console.log(`Order delivered: ${eventData.orderId}`);
      await sendDeliveryConfirmation(eventData.userId);
      await requestReview(eventData.userId, eventData.orderId);
      break;
      
    case 'order.cancelled':
      if (eventData.payload.cancellation) {
        const cancellation = eventData.payload.cancellation;
        console.log(`Order cancelled: ${cancellation.reason}`);
        console.log(`Refund amount: $${cancellation.refundAmount.toFixed(2)}`);
        
        await processRefund(eventData.userId, cancellation.refundAmount);
        await sendCancellationNotification(eventData.userId, cancellation);
      }
      break;
  }
  
  return { 
    success: true, 
    eventType: eventData.eventType,
    orderId: eventData.orderId,
    processed: true,
    timestamp: new Date()
  };
}

export const orderEventHandler = new Handler<OrderEventData>()
  .use(new BodyParserMiddleware<OrderEventData>())
  .handle(handleOrderEvent);

// Mock functions
async function sendOrderConfirmation(userId: string, order: any) {
  console.log(`Sending order confirmation to user ${userId}`);
}

async function updateInventory(items: any[]) {
  console.log(`Updating inventory for ${items.length} items`);
}

async function sendPaymentConfirmation(userId: string, payment: any) {
  console.log(`Sending payment confirmation to user ${userId}`);
}

async function initiateShipping(orderId: string) {
  console.log(`Initiating shipping for order ${orderId}`);
}

async function sendShippingNotification(userId: string, shipping: any) {
  console.log(`Sending shipping notification to user ${userId}`);
}

async function sendDeliveryConfirmation(userId: string) {
  console.log(`Sending delivery confirmation to user ${userId}`);
}

async function requestReview(userId: string, orderId: string) {
  console.log(`Requesting review from user ${userId} for order ${orderId}`);
}

async function processRefund(userId: string, amount: number) {
  console.log(`Processing refund of $${amount.toFixed(2)} for user ${userId}`);
}

async function sendCancellationNotification(userId: string, cancellation: any) {
  console.log(`Sending cancellation notification to user ${userId}`);
}
```

### Pub/Sub with Functional Approach

```typescript
// Simple event handler using functional approach
interface SimpleEventData {
  type: string;
  data: Record<string, any>;
  timestamp: string;
}

const simpleEventHandler = new Handler<SimpleEventData>()
  .use(bodyParser<SimpleEventData>()) // Uses functional approach
  .handle(async (context) => {
    const event = context.req.parsedBody as SimpleEventData;
    
    console.log(`Processing event: ${event.type}`);
    console.log(`Data:`, event.data);
    console.log(`Timestamp: ${event.timestamp}`);
    
    return { success: true, eventType: event.type };
  });
```

## Integration with Other Middlewares

### With Authentication Middleware

```typescript
// types/authenticated-types.ts
interface UpdateProfileRequest {
  name?: string;
  bio?: string;
  avatar?: string;
  preferences: {
    theme: 'light' | 'dark';
    notifications: boolean;
    privacy: 'public' | 'private';
  };
}

interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

// handlers/authenticated-handlers.ts
import { AuthenticationMiddleware } from '@/middlewares/authenticationMiddleware';

async function handleUpdateProfile(context: Context<UpdateProfileRequest, AuthenticatedUser>) {
  const profileData = context.req.parsedBody as UpdateProfileRequest;
  const user = context.user!; // Populated by AuthenticationMiddleware
  
  console.log(`User ${user.name} (${user.email}) updating profile`);
  
  if (profileData.name) {
    console.log(`Changing name from "${user.name}" to "${profileData.name}"`);
  }
  
  if (profileData.bio) {
    console.log(`New bio: ${profileData.bio}`);
  }
  
  if (profileData.avatar) {
    console.log(`New avatar: ${profileData.avatar}`);
  }
  
  console.log(`Preferences:`, profileData.preferences);
  
  const updatedProfile = {
    id: user.id,
    email: user.email,
    name: profileData.name || user.name,
    bio: profileData.bio,
    avatar: profileData.avatar,
    preferences: profileData.preferences,
    roles: user.roles,
    updatedAt: new Date()
  };
  
  return { success: true, profile: updatedProfile };
}

export const updateProfileHandler = new Handler<UpdateProfileRequest, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyParserMiddleware<UpdateProfileRequest>())
  .handle(handleUpdateProfile);
```

### With Body Validation Middleware

```typescript
import { z } from 'zod';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';

// Define schema for validation
const createPostSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(100),
  tags: z.array(z.string()).max(10),
  category: z.string().min(1),
  publishAt: z.string().datetime().optional()
});

type CreatePostRequest = z.infer<typeof createPostSchema>;

async function handleCreatePost(context: Context<CreatePostRequest, AuthenticatedUser>) {
  // Body is parsed by BodyParserMiddleware and validated by BodyValidationMiddleware
  const postData = context.req.validatedBody!; // From validation middleware
  const parsedData = context.req.parsedBody as CreatePostRequest; // From body parser
  const author = context.user!; // From authentication middleware
  
  console.log(`${author.name} creating post: "${postData.title}"`);
  console.log(`Content length: ${postData.content.length}`);
  console.log(`Tags: ${postData.tags.join(', ')}`);
  console.log(`Category: ${postData.category}`);
  
  const post = {
    id: `post_${Date.now()}`,
    ...postData,
    authorId: author.id,
    authorName: author.name,
    publishAt: postData.publishAt ? new Date(postData.publishAt) : new Date(),
    createdAt: new Date()
  };
  
  return { success: true, post };
}

export const createPostHandler = new Handler<CreatePostRequest, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyParserMiddleware<CreatePostRequest>()) // Parse first
  .use(new BodyValidationMiddleware(createPostSchema)) // Then validate
  .handle(handleCreatePost);
```

### With Dependency Injection

```typescript
import { DependencyInjectionMiddleware } from '@/middlewares/dependencyInjectionMiddleware';
import { UserService, EmailService, LoggingService } from '../services';

interface ServiceBasedRequest {
  email: string;
  action: 'create' | 'update' | 'delete';
  data: Record<string, any>;
}

// Setup services for DI
const services = [
  { id: UserService, value: new UserService() },
  { id: EmailService, value: new EmailService({ apiKey: 'test-key' }) },
  { id: LoggingService, value: new LoggingService() }
];

async function handleServiceBasedRequest(context: Context<ServiceBasedRequest>) {
  const requestData = context.req.parsedBody as ServiceBasedRequest;
  
  // Get services from DI container
  const userService = context.container?.get(UserService);
  const emailService = context.container?.get(EmailService);
  const logger = context.container?.get(LoggingService);
  
  logger?.info(`Processing ${requestData.action} request for ${requestData.email}`);
  
  switch (requestData.action) {
    case 'create':
      const user = await userService?.create(requestData.data);
      await emailService?.sendWelcomeEmail(requestData.email, user?.name);
      logger?.info(`User created: ${user?.id}`);
      return { success: true, user };
      
    case 'update':
      const updatedUser = await userService?.update(requestData.email, requestData.data);
      logger?.info(`User updated: ${updatedUser?.id}`);
      return { success: true, user: updatedUser };
      
    case 'delete':
      await userService?.delete(requestData.email);
      await emailService?.sendGoodbyeEmail(requestData.email);
      logger?.info(`User deleted: ${requestData.email}`);
      return { success: true, deleted: true };
      
    default:
      logger?.error(`Invalid action: ${requestData.action}`);
      return { success: false, error: 'Invalid action' };
  }
}

export const serviceBasedHandler = new Handler<ServiceBasedRequest>()
  .use(new DependencyInjectionMiddleware(services))
  .use(new BodyParserMiddleware<ServiceBasedRequest>())
  .handle(handleServiceBasedRequest);
```

### Complete Middleware Stack

```typescript
import { ErrorHandlerMiddleware } from '@/middlewares/errorHandlerMiddleware';
import { ResponseWrapperMiddleware } from '@/middlewares/responseWrapperMiddleware';

// Complete production-ready handler
const completeHandler = new Handler<CreatePostRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware()) // 1. First - catches all errors
  .use(new DependencyInjectionMiddleware(services)) // 2. Setup services
  .use(new AuthenticationMiddleware(tokenVerifier)) // 3. Authenticate
  .use(new BodyParserMiddleware<CreatePostRequest>()) // 4. Parse body
  .use(new BodyValidationMiddleware(createPostSchema)) // 5. Validate
  .use(new ResponseWrapperMiddleware()) // 6. Last - format response
  .handle(handleCreatePost);
```

## Error Handling

The BodyParserMiddleware handles various error scenarios and throws appropriate error types.

### Common Error Types

```typescript
import { ValidationError, TooLargeError } from '@/core/errors';

// Error scenarios handled automatically:
// 1. Invalid JSON format -> ValidationError
// 2. Request body too large -> TooLargeError  
// 3. Invalid base64 in Pub/Sub messages -> ValidationError
// 4. Malformed Pub/Sub message structure -> ValidationError

async function handleWithErrorHandling(context: Context<any>) {
  try {
    const data = context.req.parsedBody;
    console.log('Parsed data:', data);
    
    return { success: true, data };
    
  } catch (error) {
    if (error instanceof ValidationError) {
      console.error('Validation error:', error.message);
      console.error('Details:', error.details);
      
      return {
        success: false,
        error: 'Invalid request format',
        details: error.details
      };
    }
    
    if (error instanceof TooLargeError) {
      console.error('Request too large:', error.message);
      
      return {
        success: false,
        error: 'Request body too large',
        maxSize: '1MB'
      };
    }
    
    // Re-throw unexpected errors
    throw error;
  }
}

// The ErrorHandlerMiddleware automatically handles these errors
const errorSafeHandler = new Handler()
  .use(new ErrorHandlerMiddleware()) // Handles ValidationError and TooLargeError
  .use(new BodyParserMiddleware())
  .handle(handleWithErrorHandling);
```

### Custom Error Handling

```typescript
// Custom error handling for specific use cases
interface StrictDataRequest {
  requiredField: string;
  numericField: number;
  emailField: string;
}

async function handleStrictValidation(context: Context<StrictDataRequest>) {
  const data = context.req.parsedBody as StrictDataRequest;
  
  // Additional custom validation beyond parsing
  const errors: Array<{ field: string; message: string }> = [];
  
  if (!data.requiredField || data.requiredField.trim().length === 0) {
    errors.push({ field: 'requiredField', message: 'Required field cannot be empty' });
  }
  
  if (typeof data.numericField !== 'number' || data.numericField < 0) {
    errors.push({ field: 'numericField', message: 'Must be a non-negative number' });
  }
  
  if (!data.emailField.includes('@') || !data.emailField.includes('.')) {
    errors.push({ field: 'emailField', message: 'Must be a valid email address' });
  }
  
  if (errors.length > 0) {
    throw new ValidationError('Request validation failed', errors);
  }
  
  return { success: true, data };
}

const strictHandler = new Handler<StrictDataRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware<StrictDataRequest>())
  .handle(handleStrictValidation);
```

### Size Limit Error Handling

```typescript
// Different size limits for different endpoints
const smallDataHandler = new Handler<SmallDataRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware<SmallDataRequest>(100 * 1024)) // 100KB limit
  .handle(async (context) => {
    const data = context.req.parsedBody as SmallDataRequest;
    return { success: true, message: 'Small data processed', data };
  });

const largeDataHandler = new Handler<LargeDataRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware<LargeDataRequest>(10 * 1024 * 1024)) // 10MB limit
  .handle(async (context) => {
    const data = context.req.parsedBody as LargeDataRequest;
    return { success: true, message: 'Large data processed', size: JSON.stringify(data).length };
  });
```

## Real-World Examples

### E-commerce Product Management

```typescript
// types/product-types.ts
interface ProductVariant {
  sku: string;
  size?: string;
  color?: string;
  price: number;
  inventory: number;
}

interface ProductImage {
  url: string;
  alt: string;
  primary: boolean;
}

interface SEOMetadata {
  title: string;
  description: string;
  keywords: string[];
  canonicalUrl?: string;
}

interface CreateProductRequest {
  name: string;
  description: string;
  shortDescription: string;
  category: string;
  subcategory?: string;
  brand: string;
  tags: string[];
  variants: ProductVariant[];
  images: ProductImage[];
  specifications: Record<string, string>;
  seo: SEOMetadata;
  status: 'draft' | 'active' | 'archived';
  featured: boolean;
  weight?: number;
  dimensions?: {
    length: number;
    width: number;
    height: number;
    unit: 'cm' | 'in';
  };
}

// handlers/product-management-handlers.ts
async function handleCreateProduct(context: Context<CreateProductRequest, AuthenticatedUser>) {
  const productData = context.req.parsedBody as CreateProductRequest;
  const user = context.user!;
  
  console.log(`${user.name} creating product: "${productData.name}"`);
  console.log(`Brand: ${productData.brand}`);
  console.log(`Category: ${productData.category}${productData.subcategory ? ` > ${productData.subcategory}` : ''}`);
  console.log(`Variants: ${productData.variants.length}`);
  console.log(`Images: ${productData.images.length}`);
  console.log(`Status: ${productData.status}`);
  console.log(`Featured: ${productData.featured}`);
  
  // Process variants
  const processedVariants = productData.variants.map(variant => {
    console.log(`Variant ${variant.sku}: ${variant.size || 'N/A'} ${variant.color || 'N/A'} - $${variant.price.toFixed(2)} (${variant.inventory} in stock)`);
    
    return {
      ...variant,
      id: `var_${Date.now()}_${Math.random()}`,
      createdAt: new Date()
    };
  });
  
  // Process images
  const processedImages = productData.images.map((image, index) => {
    console.log(`Image ${index + 1}: ${image.url} ${image.primary ? '(PRIMARY)' : ''}`);
    
    return {
      ...image,
      id: `img_${Date.now()}_${index}`,
      order: index
    };
  });
  
  // Process specifications
  console.log('Specifications:');
  Object.entries(productData.specifications).forEach(([key, value]) => {
    console.log(`  ${key}: ${value}`);
  });
  
  // Process dimensions if provided
  if (productData.dimensions) {
    console.log(`Dimensions: ${productData.dimensions.length}×${productData.dimensions.width}×${productData.dimensions.height} ${productData.dimensions.unit}`);
  }
  
  if (productData.weight) {
    console.log(`Weight: ${productData.weight} kg`);
  }
  
  // SEO metadata
  console.log(`SEO Title: ${productData.seo.title}`);
  console.log(`SEO Description: ${productData.seo.description}`);
  console.log(`SEO Keywords: ${productData.seo.keywords.join(', ')}`);
  
  const product = {
    id: `prod_${Date.now()}`,
    name: productData.name,
    description: productData.description,
    shortDescription: productData.shortDescription,
    category: productData.category,
    subcategory: productData.subcategory,
    brand: productData.brand,
    tags: productData.tags,
    variants: processedVariants,
    images: processedImages,
    specifications: productData.specifications,
    seo: productData.seo,
    status: productData.status,
    featured: productData.featured,
    weight: productData.weight,
    dimensions: productData.dimensions,
    createdBy: user.id,
    createdAt: new Date(),
    updatedAt: new Date()
  };
  
  return { 
    success: true, 
    product,
    message: `Product "${productData.name}" created successfully`
  };
}

export const createProductHandler = new Handler<CreateProductRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyParserMiddleware<CreateProductRequest>(5 * 1024 * 1024)) // 5MB for images
  .handle(handleCreateProduct);
```

### Customer Support Ticket System

```typescript
// types/support-types.ts
interface TicketAttachment {
  filename: string;
  contentType: string;
  size: number;
  data: string; // base64 encoded
}

interface CreateTicketRequest {
  subject: string;
  description: string;
  category: 'technical' | 'billing' | 'general' | 'feature_request' | 'bug_report';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  tags: string[];
  customerInfo: {
    name: string;
    email: string;
    phone?: string;
    company?: string;
  };
  technicalDetails?: {
    browser?: string;
    operatingSystem?: string;
    appVersion?: string;
    errorMessage?: string;
    reproductionSteps?: string[];
  };
  attachments: TicketAttachment[];
}

// handlers/support-handlers.ts
async function handleCreateTicket(context: Context<CreateTicketRequest>) {
  const ticketData = context.req.parsedBody as CreateTicketRequest;
  
  console.log(`New support ticket: "${ticketData.subject}"`);
  console.log(`Category: ${ticketData.category}`);
  console.log(`Priority: ${ticketData.priority}`);
  console.log(`Customer: ${ticketData.customerInfo.name} (${ticketData.customerInfo.email})`);
  
  if (ticketData.customerInfo.company) {
    console.log(`Company: ${ticketData.customerInfo.company}`);
  }
  
  if (ticketData.customerInfo.phone) {
    console.log(`Phone: ${ticketData.customerInfo.phone}`);
  }
  
  console.log(`Description: ${ticketData.description}`);
  
  if (ticketData.tags.length > 0) {
    console.log(`Tags: ${ticketData.tags.join(', ')}`);
  }
  
  // Process technical details
  if (ticketData.technicalDetails) {
    console.log('Technical Details:');
    
    if (ticketData.technicalDetails.browser) {
      console.log(`  Browser: ${ticketData.technicalDetails.browser}`);
    }
    
    if (ticketData.technicalDetails.operatingSystem) {
      console.log(`  OS: ${ticketData.technicalDetails.operatingSystem}`);
    }
    
    if (ticketData.technicalDetails.appVersion) {
      console.log(`  App Version: ${ticketData.technicalDetails.appVersion}`);
    }
    
    if (ticketData.technicalDetails.errorMessage) {
      console.log(`  Error Message: ${ticketData.technicalDetails.errorMessage}`);
    }
    
    if (ticketData.technicalDetails.reproductionSteps) {
      console.log(`  Reproduction Steps:`);
      ticketData.technicalDetails.reproductionSteps.forEach((step, index) => {
        console.log(`    ${index + 1}. ${step}`);
      });
    }
  }
  
  // Process attachments
  if (ticketData.attachments.length > 0) {
    console.log(`Attachments: ${ticketData.attachments.length}`);
    ticketData.attachments.forEach((attachment, index) => {
      console.log(`  ${index + 1}. ${attachment.filename} (${attachment.contentType}, ${(attachment.size / 1024).toFixed(2)} KB)`);
    });
  }
  
  // Generate ticket ID based on category and priority
  const categoryPrefix = {
    technical: 'TECH',
    billing: 'BILL',
    general: 'GEN',
    feature_request: 'FEAT',
    bug_report: 'BUG'
  }[ticketData.category];
  
  const priorityCode = {
    low: 'L',
    medium: 'M', 
    high: 'H',
    urgent: 'U'
  }[ticketData.priority];
  
  const ticketId = `${categoryPrefix}-${priorityCode}-${Date.now()}`;
  
  const ticket = {
    id: ticketId,
    subject: ticketData.subject,
    description: ticketData.description,
    category: ticketData.category,
    priority: ticketData.priority,
    tags: ticketData.tags,
    customerInfo: ticketData.customerInfo,
    technicalDetails: ticketData.technicalDetails,
    attachments: ticketData.attachments,
    status: 'open' as const,
    assignedTo: null,
    createdAt: new Date(),
    updatedAt: new Date()
  };
  
  console.log(`Ticket created with ID: ${ticketId}`);
  
  // Auto-assign based on category and priority
  if (ticketData.priority === 'urgent') {
    console.log('Auto-assigning urgent ticket to on-call support');
    // ticket.assignedTo = 'on-call-support';
  } else if (ticketData.category === 'technical') {
    console.log('Routing technical ticket to engineering team');
    // ticket.assignedTo = 'engineering-team';
  } else if (ticketData.category === 'billing') {
    console.log('Routing billing ticket to finance team');
    // ticket.assignedTo = 'finance-team';
  }
  
  return { 
    success: true, 
    ticket,
    ticketId,
    estimatedResponse: ticketData.priority === 'urgent' ? '1 hour' : ticketData.priority === 'high' ? '4 hours' : '24 hours'
  };
}

export const createTicketHandler = new Handler<CreateTicketRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware<CreateTicketRequest>(10 * 1024 * 1024)) // 10MB for attachments
  .handle(handleCreateTicket);
```

### Analytics and Reporting

```typescript
// types/analytics-types.ts
interface AnalyticsEvent {
  eventName: string;
  timestamp: string;
  userId?: string;
  sessionId: string;
  properties: Record<string, any>;
}

interface PageViewEvent extends AnalyticsEvent {
  eventName: 'page_view';
  properties: {
    path: string;
    title: string;
    referrer?: string;
    userAgent: string;
    loadTime: number;
  };
}

interface UserActionEvent extends AnalyticsEvent {
  eventName: 'user_action';
  properties: {
    action: 'click' | 'scroll' | 'form_submit' | 'download' | 'search';
    element: string;
    elementId?: string;
    value?: string;
    coordinates?: { x: number; y: number };
  };
}

interface ConversionEvent extends AnalyticsEvent {
  eventName: 'conversion';
  properties: {
    type: 'purchase' | 'signup' | 'subscription' | 'lead';
    value: number;
    currency?: string;
    items?: Array<{
      id: string;
      name: string;
      category: string;
      quantity: number;
      price: number;
    }>;
  };
}

type AnalyticsEventData = PageViewEvent | UserActionEvent | ConversionEvent;

interface BatchAnalyticsRequest {
  events: AnalyticsEventData[];
  batchId: string;
  clientInfo: {
    userAgent: string;
    ipAddress: string;
    country?: string;
    region?: string;
  };
}

// handlers/analytics-handlers.ts
async function handleBatchAnalytics(context: Context<BatchAnalyticsRequest>) {
  const analyticsData = context.req.parsedBody as BatchAnalyticsRequest;
  
  console.log(`Processing analytics batch: ${analyticsData.batchId}`);
  console.log(`Events: ${analyticsData.events.length}`);
  console.log(`Client: ${analyticsData.clientInfo.userAgent}`);
  console.log(`Location: ${analyticsData.clientInfo.country || 'Unknown'}, ${analyticsData.clientInfo.region || 'Unknown'}`);
  
  const processedEvents = [];
  const eventCounts = { page_view: 0, user_action: 0, conversion: 0 };
  
  for (const event of analyticsData.events) {
    console.log(`\nProcessing ${event.eventName} event:`);
    console.log(`  Timestamp: ${event.timestamp}`);
    console.log(`  Session: ${event.sessionId}`);
    
    if (event.userId) {
      console.log(`  User: ${event.userId}`);
    }
    
    switch (event.eventName) {
      case 'page_view':
        console.log(`  Page: ${event.properties.path}`);
        console.log(`  Title: ${event.properties.title}`);
        console.log(`  Load Time: ${event.properties.loadTime}ms`);
        
        if (event.properties.referrer) {
          console.log(`  Referrer: ${event.properties.referrer}`);
        }
        
        eventCounts.page_view++;
        break;
        
      case 'user_action':
        console.log(`  Action: ${event.properties.action}`);
        console.log(`  Element: ${event.properties.element}`);
        
        if (event.properties.elementId) {
          console.log(`  Element ID: ${event.properties.elementId}`);
        }
        
        if (event.properties.value) {
          console.log(`  Value: ${event.properties.value}`);
        }
        
        if (event.properties.coordinates) {
          console.log(`  Coordinates: (${event.properties.coordinates.x}, ${event.properties.coordinates.y})`);
        }
        
        eventCounts.user_action++;
        break;
        
      case 'conversion':
        console.log(`  Type: ${event.properties.type}`);
        console.log(`  Value: ${event.properties.currency || '$'}${event.properties.value.toFixed(2)}`);
        
        if (event.properties.items) {
          console.log(`  Items: ${event.properties.items.length}`);
          event.properties.items.forEach((item, index) => {
            console.log(`    ${index + 1}. ${item.name} (${item.category}) - ${item.quantity}x $${item.price.toFixed(2)}`);
          });
        }
        
        eventCounts.conversion++;
        break;
    }
    
    // Process event (would normally save to database/analytics service)
    const processedEvent = {
      ...event,
      id: `evt_${Date.now()}_${Math.random()}`,
      batchId: analyticsData.batchId,
      clientInfo: analyticsData.clientInfo,
      processedAt: new Date()
    };
    
    processedEvents.push(processedEvent);
  }
  
  console.log(`\nBatch Summary:`);
  console.log(`  Page Views: ${eventCounts.page_view}`);
  console.log(`  User Actions: ${eventCounts.user_action}`);
  console.log(`  Conversions: ${eventCounts.conversion}`);
  console.log(`  Total Events: ${processedEvents.length}`);
  
  return { 
    success: true, 
    batchId: analyticsData.batchId,
    processed: processedEvents.length,
    eventCounts,
    processedAt: new Date()
  };
}

export const batchAnalyticsHandler = new Handler<BatchAnalyticsRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware<BatchAnalyticsRequest>(2 * 1024 * 1024)) // 2MB for large batches
  .handle(handleBatchAnalytics);
```

## Best Practices

### 1. Type Safety and Organization

```typescript
// ✅ Good: Organized type definitions
// types/api-types.ts
export interface UserRequest {
  name: string;
  email: string;
  age: number;
}

export interface ProductRequest {
  name: string;
  price: number;
  category: string;
}

// handlers/user-handlers.ts
import { UserRequest } from '../types/api-types';

export const createUserHandler = new Handler<UserRequest>()
  .use(new BodyParserMiddleware<UserRequest>())
  .handle(async (context) => {
    const user = context.req.parsedBody as UserRequest; // Fully typed
    return { success: true, user };
  });

// ❌ Avoid: Inline types without reusability
const badHandler = new Handler()
  .use(new BodyParserMiddleware()) // No type information
  .handle(async (context) => {
    const data = context.req.parsedBody; // Type: unknown
    // No type safety or IntelliSense
  });
```

### 2. Size Limit Configuration

```typescript
// ✅ Good: Appropriate size limits for different use cases
const CONFIG = {
  SMALL_PAYLOAD: 100 * 1024, // 100KB - for simple forms
  MEDIUM_PAYLOAD: 1024 * 1024, // 1MB - default for most APIs
  LARGE_PAYLOAD: 5 * 1024 * 1024, // 5MB - for file uploads
  BULK_PAYLOAD: 10 * 1024 * 1024, // 10MB - for bulk operations
};

const formHandler = new Handler<FormRequest>()
  .use(new BodyParserMiddleware<FormRequest>(CONFIG.SMALL_PAYLOAD))
  .handle(handleForm);

const uploadHandler = new Handler<UploadRequest>()
  .use(new BodyParserMiddleware<UploadRequest>(CONFIG.LARGE_PAYLOAD))
  .handle(handleUpload);

const bulkHandler = new Handler<BulkRequest>()
  .use(new BodyParserMiddleware<BulkRequest>(CONFIG.BULK_PAYLOAD))
  .handle(handleBulk);
```

### 3. Error Handling Strategy

```typescript
// ✅ Good: Centralized error handling with ErrorHandlerMiddleware
import { ErrorHandlerMiddleware } from '@/middlewares/errorHandlerMiddleware';

const robustHandler = new Handler<RequestType>()
  .use(new ErrorHandlerMiddleware()) // Handles all middleware errors
  .use(new BodyParserMiddleware<RequestType>())
  .handle(async (context) => {
    // Focus on business logic, errors are handled automatically
    const data = context.req.parsedBody as RequestType;
    return await processData(data);
  });

// ❌ Avoid: Manual error handling for every middleware
const fragileHandler = new Handler<RequestType>()
  .use(new BodyParserMiddleware<RequestType>())
  .handle(async (context) => {
    try {
      const data = context.req.parsedBody as RequestType;
      return await processData(data);
    } catch (error) {
      // Repetitive error handling in every handler
      return { success: false, error: error.message };
    }
  });
```

### 4. Middleware Ordering

```typescript
// ✅ Good: Logical middleware order
const correctOrder = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware()) // 1. Error handling first
  .use(new DependencyInjectionMiddleware(services)) // 2. Setup services
  .use(new AuthenticationMiddleware(tokenVerifier)) // 3. Authentication
  .use(new BodyParserMiddleware<RequestType>()) // 4. Parse body
  .use(new BodyValidationMiddleware(schema)) // 5. Validate parsed data
  .use(new ResponseWrapperMiddleware()) // 6. Response formatting last
  .handle(handleRequest);

// ❌ Avoid: Incorrect middleware order
const incorrectOrder = new Handler<RequestType, UserType>()
  .use(new BodyValidationMiddleware(schema)) // Can't validate unparsed body
  .use(new BodyParserMiddleware<RequestType>()) // Should be before validation
  .use(new AuthenticationMiddleware(tokenVerifier)) // Should be earlier
  .use(new ErrorHandlerMiddleware()) // Should be first
  .handle(handleRequest);
```

### 5. Functional vs Class Approach Selection

```typescript
// ✅ Good: Use functional approach for simple cases
const simpleHandler = new Handler<SimpleRequest>()
  .use(bodyParser<SimpleRequest>()) // Clean and concise
  .handle(handleSimpleRequest);

// ✅ Good: Use class approach for complex configuration
const complexHandler = new Handler<ComplexRequest>()
  .use(new BodyParserMiddleware<ComplexRequest>(
    10 * 1024 * 1024 // Custom size limit
  ))
  .handle(handleComplexRequest);

// ✅ Good: Consistent style within a project
// Choose one approach and stick with it throughout your codebase
```

## Performance Features

### 1. Async Parsing for Large Payloads

The middleware automatically uses async parsing for large JSON payloads to prevent blocking the event loop:

```typescript
// Automatic async parsing for payloads > 10KB
const largeDataHandler = new Handler<LargeDataRequest>()
  .use(new BodyParserMiddleware<LargeDataRequest>())
  .handle(async (context) => {
    // Large JSON is parsed asynchronously using setImmediate
    const data = context.req.parsedBody as LargeDataRequest;
    return { success: true, size: JSON.stringify(data).length };
  });
```

### 2. Size Validation and Security

```typescript
// Built-in protection against DoS attacks via large payloads
const secureHandler = new Handler<SecureRequest>()
  .use(new BodyParserMiddleware<SecureRequest>(512 * 1024)) // 512KB limit
  .handle(async (context) => {
    // Middleware automatically rejects requests exceeding size limit
    const data = context.req.parsedBody as SecureRequest;
    return { success: true, data };
  });
```

### 3. Base64 Decoding Optimization

For Pub/Sub messages, the middleware provides optimized base64 decoding:

```typescript
// Automatic base64 validation and decoding for Pub/Sub
const pubsubHandler = new Handler<PubSubEventData>()
  .use(new BodyParserMiddleware<PubSubEventData>())
  .handle(async (context) => {
    // Base64 data is automatically validated and decoded
    const eventData = context.req.parsedBody as PubSubEventData;
    return { success: true, eventData };
  });
```

### 4. Early Content-Length Validation

```typescript
// Middleware checks Content-Length header before processing
// This prevents unnecessary processing of oversized requests
const optimizedHandler = new Handler<OptimizedRequest>()
  .use(new BodyParserMiddleware<OptimizedRequest>(1024 * 1024))
  .handle(async (context) => {
    // Request is rejected early if Content-Length exceeds limit
    const data = context.req.parsedBody as OptimizedRequest;
    return { success: true, data };
  });
```

## Common Patterns

### 1. Request/Response Wrapper Pattern

```typescript
async function withBodyParsing<T, R>(
  handler: (data: T, context: Context) => Promise<R>,
  maxSize?: number
) {
  return new Handler<T>()
    .use(new BodyParserMiddleware<T>(maxSize))
    .handle(async (context) => {
      const data = context.req.parsedBody as T;
      return await handler(data, context);
    });
}

// Usage
const processUserData = async (userData: UserRequest, context: Context) => {
  console.log(`Processing user: ${userData.name}`);
  return { success: true, user: { id: '123', ...userData } };
};

export const createUserHandler = withBodyParsing(processUserData);
```

### 2. Multi-Format Support Pattern

```typescript
// Handler that supports both direct JSON and Pub/Sub messages
interface FlexibleEventData {
  type: string;
  payload: Record<string, any>;
  timestamp: string;
}

const flexibleHandler = new Handler<FlexibleEventData>()
  .use(new BodyParserMiddleware<FlexibleEventData>())
  .handle(async (context) => {
    const eventData = context.req.parsedBody as FlexibleEventData;
    
    // Works for both direct HTTP requests and Pub/Sub messages
    console.log(`Event type: ${eventData.type}`);
    console.log(`Payload:`, eventData.payload);
    
    return { success: true, processed: true };
  });
```

### 3. Conditional Parsing Pattern

```typescript
// Different parsing based on request method
const conditionalHandler = new Handler()
  .use(bodyParser()) // Only parses for POST, PUT, PATCH methods
  .handle(async (context) => {
    const method = context.req.method;
    
    if (['POST', 'PUT', 'PATCH'].includes(method || '')) {
      const data = context.req.parsedBody;
      console.log('Request data:', data);
      return { success: true, data };
    } else {
      console.log('No body parsing needed for', method);
      return { success: true, message: 'No data required' };
    }
  });
```

### 4. Type-Safe Factory Pattern

```typescript
// Factory for creating typed handlers with body parsing
class TypedHandlerFactory {
  static create<T>(
    handler: (data: T, context: Context<T>) => Promise<any>,
    options?: { maxSize?: number; validate?: boolean }
  ) {
    const handlerInstance = new Handler<T>();
    
    if (options?.maxSize) {
      handlerInstance.use(new BodyParserMiddleware<T>(options.maxSize));
    } else {
      handlerInstance.use(new BodyParserMiddleware<T>());
    }
    
    return handlerInstance.handle(async (context) => {
      const data = context.req.parsedBody as T;
      return await handler(data, context);
    });
  }
}

// Usage
interface OrderRequest {
  items: Array<{ id: string; quantity: number }>;
  total: number;
}

const orderLogic = async (order: OrderRequest, context: Context<OrderRequest>) => {
  console.log(`Processing order with ${order.items.length} items`);
  console.log(`Total: $${order.total.toFixed(2)}`);
  return { success: true, orderId: `order_${Date.now()}` };
};

export const orderHandler = TypedHandlerFactory.create<OrderRequest>(
  orderLogic,
  { maxSize: 2 * 1024 * 1024 } // 2MB limit
);
```

### 5. Batch Processing Pattern

```typescript
interface BatchRequest<T> {
  items: T[];
  batchId: string;
  metadata?: Record<string, any>;
}

// Generic batch processing handler
function createBatchHandler<T>(
  processor: (item: T, index: number, batch: BatchRequest<T>) => Promise<any>,
  maxSize?: number
) {
  return new Handler<BatchRequest<T>>()
    .use(new BodyParserMiddleware<BatchRequest<T>>(maxSize))
    .handle(async (context) => {
      const batchData = context.req.parsedBody as BatchRequest<T>;
      
      console.log(`Processing batch ${batchData.batchId} with ${batchData.items.length} items`);
      
      const results = [];
      for (let i = 0; i < batchData.items.length; i++) {
        try {
          const result = await processor(batchData.items[i], i, batchData);
          results.push({ index: i, success: true, data: result });
        } catch (error) {
          results.push({ 
            index: i, 
            success: false, 
            error: error instanceof Error ? error.message : 'Unknown error' 
          });
        }
      }
      
      const successful = results.filter(r => r.success).length;
      const failed = results.length - successful;
      
      return { 
        success: true, 
        batchId: batchData.batchId,
        processed: results.length,
        successful,
        failed,
        results 
      };
    });
}

// Usage
interface UserBatchItem {
  name: string;
  email: string;
}

const processUser = async (user: UserBatchItem, index: number) => {
  console.log(`Processing user ${index + 1}: ${user.name}`);
  return { id: `user_${Date.now()}_${index}`, ...user };
};

export const batchUserHandler = createBatchHandler<UserBatchItem>(
  processUser,
  5 * 1024 * 1024 // 5MB for large batches
);
```

This comprehensive guide provides everything you need to effectively use the BodyParserMiddleware with full generic type support for building robust, type-safe APIs in the Noony Framework. The middleware's automatic JSON parsing, Pub/Sub message handling, and performance optimizations make it an essential tool for handling request data reliably and efficiently.