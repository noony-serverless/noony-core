# HTTP Attributes Middleware Guide

A comprehensive guide to using HTTP attribute extraction middlewares for processing path parameters, headers, and query validation in the Noony Framework.

## Table of Contents

1. [Overview](#overview)
2. [PathParametersMiddleware](#pathparametersmiddleware)
3. [HeaderVariablesValidator](#headervariablesvalidator)
4. [ValidatedQueryParameters](#validatedqueryparameters)
5. [TypeScript Generics Integration](#typescript-generics-integration)
6. [Advanced Examples](#advanced-examples)
7. [Error Handling](#error-handling)
8. [Performance Considerations](#performance-considerations)
9. [Best Practices](#best-practices)

## Overview

The httpAttributesMiddleware.ts file contains multiple middleware functions that work together to extract and validate different types of HTTP request attributes:

- **PathParametersMiddleware**: Extracts path parameters from URLs (e.g., `/users/:id` → `{ id: "123" }`)
- **HeaderVariablesValidator**: Validates required HTTP headers are present
- **ValidatedQueryParameters**: Validates query parameters using Zod schemas

### Key Features
- **RESTful API Support**: Extract path parameters for resource-based routing
- **Header Validation**: Ensure required headers are present for security/functionality
- **Schema Validation**: Type-safe query parameter validation with Zod
- **TypeScript Integration**: Full generic type support for all middleware
- **Error Handling**: Comprehensive validation error reporting

## PathParametersMiddleware

Extracts path parameters from URL segments for RESTful API patterns.

### How It Works

```typescript
// URL Pattern: /users/:userId/posts/:postId
// Actual URL: /users/123/posts/456

// Results in:
context.req.params = {
  userId: "123",
  postId: "456"
}
```

### Basic Usage

```typescript
import { Handler, PathParametersMiddleware } from '@/middlewares';

// Simple resource access
const getUserHandler = new Handler()
  .use(new PathParametersMiddleware())
  .handle(async (context) => {
    const { userId } = context.req.params || {};
    
    const user = await getUserById(userId);
    return { success: true, user };
  });
```

### TypeScript Integration

```typescript
interface UserParams {
  userId: string;
}

interface UserResponse {
  success: boolean;
  user: User;
}

const typedUserHandler = new Handler<UserParams, UserResponse>()
  .use(new PathParametersMiddleware())
  .handle(async (context) => {
    // Type-safe parameter access
    const { userId } = context.req.params as UserParams;
    
    const user = await getUserById(userId);
    return { success: true, user };
  });
```

### Advanced RESTful Patterns

```typescript
// Nested resource pattern: /organizations/:orgId/projects/:projectId/tasks/:taskId
interface NestedResourceParams {
  orgId: string;
  projectId: string;
  taskId: string;
}

const nestedResourceHandler = new Handler<NestedResourceParams, TaskResponse>()
  .use(new PathParametersMiddleware())
  .handle(async (context) => {
    const { orgId, projectId, taskId } = context.req.params as NestedResourceParams;
    
    // Validate hierarchy
    const org = await getOrganization(orgId);
    const project = await getProjectInOrganization(projectId, orgId);
    const task = await getTaskInProject(taskId, projectId);
    
    return {
      success: true,
      task,
      context: { organization: org, project }
    };
  });
```

### E-commerce API Example

```typescript
// Product catalog: /categories/:category/products/:productId
interface ProductParams {
  category: string;
  productId: string;
}

const productDetailHandler = new Handler<ProductParams, ProductDetailResponse>()
  .use(new PathParametersMiddleware())
  .handle(async (context) => {
    const { category, productId } = context.req.params as ProductParams;
    
    // Validate product belongs to category
    const product = await getProduct(productId);
    if (product.category !== category) {
      throw new ValidationError('Product not found in specified category');
    }
    
    const recommendations = await getRecommendations(category, productId);
    const reviews = await getProductReviews(productId);
    
    return {
      success: true,
      product,
      recommendations,
      reviews,
      breadcrumb: { category, productId }
    };
  });
```

### Factory Function Pattern

```typescript
import { pathParameters } from '@/middlewares';

// Simple factory usage
const blogPostHandler = new Handler()
  .use(pathParameters())
  .handle(async (context) => {
    const { category, postId } = context.req.params || {};
    
    const post = await getBlogPost(category, postId);
    const relatedPosts = await getRelatedPosts(category);
    
    return { success: true, post, related: relatedPosts };
  });
```

### Generic Path Parameter Factory

```typescript
// Generic factory for typed path parameters
function createResourceHandler<TParams extends Record<string, string>, TResponse>(
  handler: (params: TParams) => Promise<TResponse>
) {
  return new Handler<TParams, TResponse>()
    .use(new PathParametersMiddleware())
    .handle(async (context) => {
      const params = context.req.params as TParams;
      return await handler(params);
    });
}

// Usage with specific types
interface OrderParams {
  userId: string;
  orderId: string;
}

const orderHandler = createResourceHandler<OrderParams, OrderResponse>(
  async ({ userId, orderId }) => {
    const order = await getOrderForUser(orderId, userId);
    const items = await getOrderItems(orderId);
    
    return {
      success: true,
      order,
      items,
      user: { id: userId }
    };
  }
);
```

## HeaderVariablesValidator

Validates that required HTTP headers are present in the request.

### Basic Header Validation

```typescript
import { headerVariablesValidator } from '@/middlewares';

// API key authentication
const secureApiHandler = new Handler()
  .use(headerVariablesValidator(['authorization', 'x-api-key']))
  .handle(async (context) => {
    const authToken = context.req.headers.authorization;
    const apiKey = context.req.headers['x-api-key'];
    
    // Headers are guaranteed to exist after validation
    const isValid = await validateCredentials(authToken as string, apiKey as string);
    return { success: isValid, authenticated: true };
  });
```

### Multi-Tenant Applications

```typescript
interface TenantHeaders {
  'x-tenant-id': string;
  'x-client-version': string;
  'authorization': string;
}

const multiTenantHandler = new Handler()
  .use(headerVariablesValidator(['x-tenant-id', 'x-client-version', 'authorization']))
  .handle(async (context) => {
    const headers = context.req.headers as TenantHeaders;
    
    const tenantId = headers['x-tenant-id'];
    const clientVersion = headers['x-client-version'];
    const auth = headers.authorization;
    
    // Validate tenant access
    const tenant = await validateTenantAccess(tenantId, auth);
    const config = await getTenantConfig(tenantId, clientVersion);
    
    return {
      success: true,
      tenant,
      config,
      client: { version: clientVersion }
    };
  });
```

### Content Negotiation

```typescript
// Content type and language requirements
const internationalApiHandler = new Handler()
  .use(headerVariablesValidator(['accept', 'accept-language', 'content-type']))
  .handle(async (context) => {
    const accept = context.req.headers.accept as string;
    const acceptLang = context.req.headers['accept-language'] as string;
    const contentType = context.req.headers['content-type'] as string;
    
    // Parse language preferences
    const preferredLang = parseAcceptLanguage(acceptLang);
    
    // Validate content type
    if (!contentType.includes('application/json')) {
      throw new ValidationError('Only JSON content type is supported');
    }
    
    const localizedResponse = await getLocalizedContent(preferredLang);
    return { success: true, data: localizedResponse, language: preferredLang };
  });
```

### Webhook Security

```typescript
// Webhook signature validation
interface WebhookHeaders {
  'x-webhook-signature': string;
  'x-webhook-timestamp': string;
  'content-type': string;
  'user-agent': string;
}

const webhookHandler = new Handler()
  .use(headerVariablesValidator([
    'x-webhook-signature',
    'x-webhook-timestamp', 
    'content-type'
  ]))
  .handle(async (context) => {
    const headers = context.req.headers as WebhookHeaders;
    
    const signature = headers['x-webhook-signature'];
    const timestamp = headers['x-webhook-timestamp'];
    const body = context.req.body;
    
    // Validate webhook authenticity
    const isValid = await validateWebhookSignature(signature, timestamp, body);
    if (!isValid) {
      throw new SecurityError('Invalid webhook signature');
    }
    
    // Process webhook payload
    const result = await processWebhookPayload(body);
    return { success: true, processed: result };
  });
```

## ValidatedQueryParameters

Validates query parameters using Zod schemas for type-safe parameter processing.

### Basic Zod Validation

```typescript
import { z } from 'zod';
import { validatedQueryParameters } from '@/middlewares';

// Pagination schema
const paginationSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).default('1'),
  limit: z.string().regex(/^\d+$/).transform(Number).default('10'),
  sort: z.enum(['asc', 'desc']).default('asc')
});

const paginatedListHandler = new Handler()
  .use(validatedQueryParameters(paginationSchema))
  .handle(async (context) => {
    // Query parameters are validated and transformed
    const { page, limit, sort } = context.req.query;
    
    const users = await getUsersPaginated({
      page,
      limit: Math.min(limit, 100), // Cap at 100
      sort
    });
    
    return { 
      success: true, 
      users: users.items,
      pagination: { page, limit, sort, total: users.total }
    };
  });
```

### Complex Search Validation

```typescript
// Advanced search schema with multiple filters
const searchSchema = z.object({
  q: z.string().min(1, 'Search query is required'),
  category: z.string().optional(),
  price_min: z.string().regex(/^\d+(\.\d{2})?$/, 'Invalid price format').optional(),
  price_max: z.string().regex(/^\d+(\.\d{2})?$/, 'Invalid price format').optional(),
  in_stock: z.enum(['true', 'false']).optional(),
  brand: z.string().optional(),
  rating_min: z.string().regex(/^[1-5]$/, 'Rating must be 1-5').optional(),
  sort_by: z.enum(['price', 'rating', 'name', 'popularity']).default('name'),
  sort_order: z.enum(['asc', 'desc']).default('asc')
});

type SearchQuery = z.infer<typeof searchSchema>;

const productSearchHandler = new Handler<SearchQuery, SearchResponse>()
  .use(validatedQueryParameters(searchSchema))
  .handle(async (context) => {
    const query = context.req.query as SearchQuery;
    
    // Build search filters from validated parameters
    const searchFilters: ProductSearchFilters = {
      query: query.q,
      category: query.category,
      priceRange: {
        min: query.price_min ? parseFloat(query.price_min) : undefined,
        max: query.price_max ? parseFloat(query.price_max) : undefined
      },
      inStock: query.in_stock === 'true',
      brand: query.brand,
      minRating: query.rating_min ? parseInt(query.rating_min) : undefined,
      sort: {
        field: query.sort_by,
        order: query.sort_order
      }
    };
    
    const results = await searchProducts(searchFilters);
    
    return {
      success: true,
      products: results.items,
      filters: searchFilters,
      meta: {
        total: results.total,
        query: query.q
      }
    };
  });
```

### Date Range and Reporting

```typescript
// Analytics reporting with date validation
const reportingSchema = z.object({
  start_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be YYYY-MM-DD format'),
  end_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be YYYY-MM-DD format'),
  granularity: z.enum(['hour', 'day', 'week', 'month']).default('day'),
  metrics: z.string().transform(val => val.split(',').map(m => m.trim())).optional(),
  segment: z.string().optional(),
  format: z.enum(['json', 'csv', 'excel']).default('json')
}).refine(data => {
  const start = new Date(data.start_date);
  const end = new Date(data.end_date);
  return start < end;
}, {
  message: "start_date must be before end_date"
});

const analyticsHandler = new Handler()
  .use(validatedQueryParameters(reportingSchema))
  .handle(async (context) => {
    const params = context.req.query;
    
    const reportConfig: ReportConfiguration = {
      dateRange: {
        start: new Date(params.start_date),
        end: new Date(params.end_date)
      },
      granularity: params.granularity,
      metrics: params.metrics || ['views', 'clicks', 'conversions'],
      segment: params.segment,
      format: params.format
    };
    
    const report = await generateAnalyticsReport(reportConfig);
    
    // Return appropriate format
    if (params.format === 'csv') {
      context.res.header('Content-Type', 'text/csv');
      return report.csv;
    }
    
    return {
      success: true,
      report: report.data,
      config: reportConfig
    };
  });
```

## TypeScript Generics Integration

### Combined Middleware with Full Type Safety

```typescript
// Complete type-safe request handler
interface UserResourceParams {
  userId: string;
}

interface UserUpdateQuery {
  notify: 'true' | 'false';
  include_profile: 'true' | 'false';
}

interface UserUpdateHeaders {
  'content-type': string;
  'authorization': string;
  'x-client-id': string;
}

interface UserUpdateResponse {
  success: boolean;
  user: User;
  profile?: UserProfile;
  notifications_sent: boolean;
}

// Zod schema for query validation
const userUpdateQuerySchema = z.object({
  notify: z.enum(['true', 'false']).default('false'),
  include_profile: z.enum(['true', 'false']).default('false')
});

const updateUserHandler = new Handler<UserResourceParams, UserUpdateResponse>()
  .use(new PathParametersMiddleware()) // Extract userId from path
  .use(headerVariablesValidator(['content-type', 'authorization', 'x-client-id'])) // Validate headers
  .use(validatedQueryParameters(userUpdateQuerySchema)) // Validate query params
  .handle(async (context) => {
    // All parameters are validated and type-safe
    const { userId } = context.req.params as UserResourceParams;
    const headers = context.req.headers as UserUpdateHeaders;
    const query = context.req.query as UserUpdateQuery;
    
    // Authenticate request
    const user = await authenticateUser(headers.authorization);
    if (user.id !== userId && !user.isAdmin) {
      throw new SecurityError('Unauthorized to update this user');
    }
    
    // Update user
    const updatedUser = await updateUser(userId, context.req.body);
    
    // Optional profile inclusion
    let profile: UserProfile | undefined;
    if (query.include_profile === 'true') {
      profile = await getUserProfile(userId);
    }
    
    // Optional notifications
    let notificationsSent = false;
    if (query.notify === 'true') {
      await sendUpdateNotification(userId);
      notificationsSent = true;
    }
    
    return {
      success: true,
      user: updatedUser,
      profile,
      notifications_sent: notificationsSent
    };
  });
```

### Generic Middleware Factory

```typescript
// Factory for creating type-safe resource handlers
function createResourceHandler<
  TParams extends Record<string, string>,
  TQuery extends Record<string, any>,
  TResponse
>(options: {
  requiredHeaders: string[];
  querySchema?: z.ZodSchema<TQuery>;
  handler: (params: TParams, query: TQuery, headers: Record<string, string>, context: Context) => Promise<TResponse>;
}) {
  const middlewares: BaseMiddleware[] = [
    new PathParametersMiddleware(),
    headerVariablesValidator(options.requiredHeaders)
  ];
  
  if (options.querySchema) {
    middlewares.push(validatedQueryParameters(options.querySchema));
  }
  
  return new Handler<TParams, TResponse>()
    .use(...middlewares)
    .handle(async (context) => {
      const params = context.req.params as TParams;
      const query = (context.req.query as TQuery) || ({} as TQuery);
      const headers = context.req.headers;
      
      return await options.handler(params, query, headers, context);
    });
}

// Usage
interface ProductParams { productId: string; }
const productQuerySchema = z.object({
  include_reviews: z.enum(['true', 'false']).default('false')
});

const productHandler = createResourceHandler<
  ProductParams,
  z.infer<typeof productQuerySchema>,
  ProductResponse
>({
  requiredHeaders: ['authorization'],
  querySchema: productQuerySchema,
  handler: async (params, query, headers) => {
    const product = await getProduct(params.productId);
    const reviews = query.include_reviews === 'true' ? 
      await getProductReviews(params.productId) : undefined;
    
    return { success: true, product, reviews };
  }
});
```

## Error Handling

### Comprehensive Error Patterns

```typescript
const robustHandler = new Handler()
  .use(new PathParametersMiddleware())
  .use(headerVariablesValidator(['authorization']))
  .use(validatedQueryParameters(z.object({
    page: z.string().regex(/^\d+$/).transform(Number)
  })))
  .handle(async (context) => {
    try {
      const { userId } = context.req.params || {};
      const { page } = context.req.query;
      
      // Additional business validation
      if (!userId || userId.length < 3) {
        throw new ValidationError('userId must be at least 3 characters');
      }
      
      const data = await getUserData(userId, page);
      return { success: true, data };
      
    } catch (error) {
      if (error instanceof ValidationError) {
        return {
          success: false,
          error: error.message,
          code: 'VALIDATION_ERROR',
          details: error.details
        };
      }
      
      if (error instanceof z.ZodError) {
        return {
          success: false,
          error: 'Query parameter validation failed',
          code: 'QUERY_VALIDATION_ERROR',
          details: error.errors
        };
      }
      
      throw error; // Re-throw unknown errors
    }
  });
```

## Performance Considerations

### Middleware Ordering

```typescript
// Good: Cheap validations first, expensive operations last
const optimizedHandler = new Handler()
  .use(headerVariablesValidator(['authorization'])) // Fast header check
  .use(new PathParametersMiddleware()) // Fast path parsing
  .use(validatedQueryParameters(simpleSchema)) // Schema validation
  .use(expensiveAuthenticationMiddleware) // Expensive auth check last
  .handle(async (context) => {
    // Business logic only runs if all validations pass
  });

// Avoid: Expensive operations before cheap validations
const poorHandler = new Handler()
  .use(expensiveAuthenticationMiddleware) // Expensive operation first
  .use(headerVariablesValidator(['required-header'])) // Cheap validation last
  .handle(async (context) => {
    // May do expensive work even for invalid requests
  });
```

### Caching Parsed Results

```typescript
import { LRUCache } from 'lru-cache';

const parameterCache = new LRUCache<string, any>({
  max: 1000,
  ttl: 60 * 1000 // 1 minute
});

const cachedParameterHandler = new Handler()
  .use(new PathParametersMiddleware())
  .handle(async (context) => {
    const { resourceId } = context.req.params || {};
    
    // Cache expensive parameter processing
    const cacheKey = `resource:${resourceId}`;
    let resourceData = parameterCache.get(cacheKey);
    
    if (!resourceData) {
      resourceData = await loadResourceData(resourceId);
      parameterCache.set(cacheKey, resourceData);
    }
    
    return { success: true, data: resourceData };
  });
```

## Best Practices

### 1. Middleware Composition

```typescript
// Good: Compose related middlewares together
const createSecureApiHandler = (requiredHeaders: string[], querySchema?: z.ZodSchema) => {
  const middlewares: BaseMiddleware[] = [
    new PathParametersMiddleware(),
    headerVariablesValidator(requiredHeaders)
  ];
  
  if (querySchema) {
    middlewares.push(validatedQueryParameters(querySchema));
  }
  
  return new Handler().use(...middlewares);
};

// Usage
const userApiHandler = createSecureApiHandler(
  ['authorization', 'content-type'],
  userQuerySchema
).handle(async (context) => {
  // Implementation
});
```

### 2. Error Message Clarity

```typescript
// Good: Specific, actionable error messages
const validateResourceParams = (params: any) => {
  if (!params.userId) {
    throw new ValidationError('userId parameter is required in path');
  }
  
  if (!/^[a-zA-Z0-9-_]+$/.test(params.userId)) {
    throw new ValidationError('userId must contain only letters, numbers, hyphens, and underscores');
  }
  
  if (params.userId.length < 3 || params.userId.length > 50) {
    throw new ValidationError('userId must be between 3 and 50 characters');
  }
};

// Avoid: Vague error messages
const poorValidation = (params: any) => {
  if (!params.userId || params.userId.length < 3) {
    throw new ValidationError('Invalid user ID');
  }
};
```

### 3. Type Safety Best Practices

```typescript
// Good: Explicit type definitions and assertions
interface ResourceParams {
  organizationId: string;
  projectId: string;
  resourceId: string;
}

const typedHandler = new Handler<ResourceParams, ResourceResponse>()
  .use(new PathParametersMiddleware())
  .handle(async (context) => {
    const params = context.req.params as ResourceParams;
    
    // Type-safe parameter access with runtime validation
    validateUUID(params.organizationId, 'organizationId');
    validateUUID(params.projectId, 'projectId');
    validateUUID(params.resourceId, 'resourceId');
    
    return await processResource(params);
  });

// Utility function for common validations
const validateUUID = (value: string, paramName: string): void => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  if (!uuidRegex.test(value)) {
    throw new ValidationError(`${paramName} must be a valid UUID`);
  }
};
```

### 4. Documentation and Testing

```typescript
/**
 * User Resource API Handler
 * 
 * Path Parameters:
 * - userId: User identifier (UUID format)
 * 
 * Required Headers:
 * - Authorization: Bearer token for authentication
 * - Content-Type: Must be application/json
 * 
 * Query Parameters:
 * - include_profile: Include user profile data (true/false, default: false)
 * - format: Response format (json/xml, default: json)
 * 
 * Example: GET /api/users/550e8400-e29b-41d4-a716-446655440000?include_profile=true
 */
const documentedUserHandler = new Handler()
  .use(new PathParametersMiddleware())
  .use(headerVariablesValidator(['authorization', 'content-type']))
  .use(validatedQueryParameters(userQuerySchema))
  .handle(async (context) => {
    // Well-documented implementation
  });

// Testing helper
export const testHttpAttributesMiddleware = {
  createMockContext: (
    params: Record<string, string>,
    headers: Record<string, string>,
    query: Record<string, string>
  ) => ({
    req: {
      params,
      headers,
      query,
      url: '/test/url'
    },
    res: {},
    businessData: new Map()
  }),
  
  expectValidationError: async (handler: Handler, mockContext: Context, expectedMessage: string) => {
    try {
      await handler.execute(mockContext.req as any, mockContext.res as any);
      throw new Error('Expected validation error');
    } catch (error) {
      expect(error).toBeInstanceOf(ValidationError);
      expect(error.message).toContain(expectedMessage);
    }
  }
};
```

These middleware functions work together to provide comprehensive request attribute processing, from URL paths to headers to query parameters, all with full TypeScript support and robust validation.