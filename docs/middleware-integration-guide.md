# Middleware Integration Guide

A comprehensive guide showing how QueryParametersMiddleware, HeaderVariablesMiddleware, and HTTP Attributes middleware work together to create robust, type-safe request processing pipelines in the Noony Framework.

## Table of Contents

1. [Overview](#overview)
2. [How They Complement Each Other](#how-they-complement-each-other)
3. [Complete Integration Patterns](#complete-integration-patterns)
4. [Real-World Examples](#real-world-examples)
5. [TypeScript Generic Patterns](#typescript-generic-patterns)
6. [Error Handling Strategies](#error-handling-strategies)
7. [Performance Optimization](#performance-optimization)
8. [Testing Strategies](#testing-strategies)
9. [Best Practices](#best-practices)

## Overview

The three middleware types work together to provide comprehensive request attribute processing:

- **HeaderVariablesMiddleware**: Validates required HTTP headers
- **PathParametersMiddleware** (from httpAttributesMiddleware): Extracts URL path parameters  
- **QueryParametersMiddleware**: Processes URL query string parameters

### The Request Processing Pipeline

```
HTTP Request → Headers → Path Params → Query Params → Business Logic
              ↓         ↓              ↓
           Auth/Security  Resource ID    Filters/Options
           Content Type   User ID        Pagination
           API Keys       Entity ID      Search Terms
```

### Complementary Functionality

| Aspect | Headers | Path Parameters | Query Parameters |
|--------|---------|-----------------|------------------|
| **Purpose** | Authentication, metadata | Resource identification | Options, filters |
| **Required** | Often mandatory | Usually mandatory | Usually optional |
| **Caching** | Affects cache keys | Defines resource | Affects cache keys |
| **Security** | Critical for auth | Defines scope | Input validation |
| **Validation** | Format validation | Resource existence | Type conversion |

## How They Complement Each Other

### Data Flow Integration

```typescript
// Complete request processing flow
interface CompleteRequest {
  // From Headers
  auth: {
    token: string;
    apiKey: string;
    clientId: string;
  };
  
  // From Path Parameters
  resource: {
    userId: string;
    organizationId: string;
    projectId: string;
  };
  
  // From Query Parameters  
  options: {
    page: number;
    limit: number;
    sort: string;
    filters: Record<string, any>;
  };
}
```

### Security Layer Integration

```typescript
// Headers provide authentication context
const securityContext = validateHeaders(headers);

// Path parameters define authorization scope
const resourceScope = extractPathParams(url);

// Query parameters refine access permissions
const accessOptions = parseQueryParams(queryString);

// Combined security check
const hasAccess = checkPermissions(securityContext, resourceScope, accessOptions);
```

### Validation Chain

```typescript
// 1. Headers: Validate request is properly formatted and authenticated
// 2. Path: Validate resource exists and user has access
// 3. Query: Validate options are within allowed limits
// 4. Business Logic: Process with validated, typed data
```

## Complete Integration Patterns

### Basic Integration Pattern

```typescript
import { 
  Handler, 
  HeaderVariablesMiddleware, 
  PathParametersMiddleware, 
  QueryParametersMiddleware 
} from '@/middlewares';

// Basic integrated handler
const basicIntegratedHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware(['page']))
  .handle(async (context) => {
    // Headers validated and available
    const auth = context.req.headers.authorization;
    
    // Path parameters extracted
    const { userId } = context.req.params || {};
    
    // Query parameters validated
    const { page, limit = '10' } = context.req.query;
    
    const user = await authenticateUser(auth as string);
    const data = await getUserData(userId, {
      page: parseInt(page as string),
      limit: parseInt(limit as string)
    });
    
    return { success: true, user, data };
  });
```

### Advanced Generic Integration

```typescript
// Type-safe integration with full generic support
interface RequestContext<TParams, TQuery, THeaders> {
  params: TParams;
  query: TQuery;
  headers: THeaders;
}

function createIntegratedHandler<
  TParams extends Record<string, string>,
  TQuery extends Record<string, any>,
  THeaders extends Record<string, any>,
  TResponse
>(config: {
  requiredHeaders: (keyof THeaders)[];
  requiredParams?: (keyof TParams)[];
  requiredQuery?: (keyof TQuery)[];
  handler: (context: RequestContext<TParams, TQuery, THeaders>) => Promise<TResponse>;
}) {
  return new Handler<TParams, TResponse>()
    .use(new HeaderVariablesMiddleware(config.requiredHeaders as string[]))
    .use(new PathParametersMiddleware())
    .use(new QueryParametersMiddleware(config.requiredQuery as string[] || []))
    .handle(async (context) => {
      const requestContext: RequestContext<TParams, TQuery, THeaders> = {
        params: context.req.params as TParams,
        query: context.req.query as TQuery,
        headers: context.req.headers as THeaders
      };
      
      return await config.handler(requestContext);
    });
}

// Usage with specific types
interface UserParams { userId: string; }
interface UserQuery { 
  include_posts?: string;
  page?: string;
  limit?: string;
}
interface UserHeaders {
  'authorization': string;
  'accept': string;
}

const typedUserHandler = createIntegratedHandler<UserParams, UserQuery, UserHeaders, UserResponse>({
  requiredHeaders: ['authorization', 'accept'],
  handler: async ({ params, query, headers }) => {
    const user = await authenticateAndGetUser(headers.authorization, params.userId);
    
    const options = {
      includePosts: query.include_posts === 'true',
      page: parseInt(query.page || '1'),
      limit: parseInt(query.limit || '10')
    };
    
    const userData = await enrichUserData(user, options);
    
    return {
      success: true,
      user: userData,
      options,
      contentType: headers.accept
    };
  }
});
```

### Factory Pattern Integration

```typescript
// Reusable factory for common integration patterns
class MiddlewareFactory {
  static createRESTHandler<TParams, TResponse>(
    resourceConfig: {
      pathParams: (keyof TParams)[];
      requireAuth?: boolean;
      requireContentType?: boolean;
      allowQuery?: boolean;
    },
    handler: (context: {
      params: TParams;
      query?: Record<string, any>;
      user?: any;
    }) => Promise<TResponse>
  ) {
    const requiredHeaders: string[] = [];
    
    if (resourceConfig.requireAuth) {
      requiredHeaders.push('authorization');
    }
    
    if (resourceConfig.requireContentType) {
      requiredHeaders.push('content-type');
    }
    
    const middlewares = [
      ...(requiredHeaders.length > 0 ? [new HeaderVariablesMiddleware(requiredHeaders)] : []),
      new PathParametersMiddleware(),
      ...(resourceConfig.allowQuery ? [new QueryParametersMiddleware()] : [])
    ];
    
    return new Handler<TParams, TResponse>()
      .use(...middlewares)
      .handle(async (context) => {
        let user;
        if (resourceConfig.requireAuth) {
          user = await authenticateUser(context.req.headers.authorization as string);
        }
        
        return await handler({
          params: context.req.params as TParams,
          query: resourceConfig.allowQuery ? context.req.query : undefined,
          user
        });
      });
  }
  
  static createSearchHandler<TQuery, TResponse>(
    searchConfig: {
      requiredQuery: (keyof TQuery)[];
      requireAuth?: boolean;
      allowFilters?: boolean;
    },
    handler: (context: {
      query: TQuery;
      user?: any;
    }) => Promise<TResponse>
  ) {
    const requiredHeaders: string[] = [];
    if (searchConfig.requireAuth) {
      requiredHeaders.push('authorization');
    }
    
    return new Handler<any, TResponse>()
      .use(...(requiredHeaders.length > 0 ? [new HeaderVariablesMiddleware(requiredHeaders)] : []))
      .use(new QueryParametersMiddleware(searchConfig.requiredQuery as string[]))
      .handle(async (context) => {
        let user;
        if (searchConfig.requireAuth) {
          user = await authenticateUser(context.req.headers.authorization as string);
        }
        
        return await handler({
          query: context.req.query as TQuery,
          user
        });
      });
  }
}

// Usage examples
interface ProductParams { 
  productId: string; 
}

const productHandler = MiddlewareFactory.createRESTHandler<ProductParams, ProductResponse>({
  pathParams: ['productId'],
  requireAuth: true,
  allowQuery: true
}, async ({ params, query, user }) => {
  const product = await getProduct(params.productId, user.id);
  const includeReviews = query?.include_reviews === 'true';
  
  return {
    success: true,
    product,
    reviews: includeReviews ? await getReviews(params.productId) : undefined
  };
});

interface SearchQuery {
  q: string;
  category?: string;
  sort?: string;
}

const searchHandler = MiddlewareFactory.createSearchHandler<SearchQuery, SearchResponse>({
  requiredQuery: ['q'],
  requireAuth: false,
  allowFilters: true
}, async ({ query }) => {
  const results = await searchProducts({
    query: query.q,
    category: query.category,
    sort: query.sort || 'relevance'
  });
  
  return { success: true, results, query };
});
```

## Real-World Examples

### E-commerce API

```typescript
// Complete e-commerce product API with all three middleware types
interface ProductHeaders {
  'authorization': string;
  'x-client-version': string;
  'accept-language': string;
}

interface ProductParams {
  categoryId: string;
  productId: string;
}

interface ProductQuery {
  include_reviews?: string;
  include_recommendations?: string;
  review_limit?: string;
  currency?: string;
}

interface ProductResponse {
  success: boolean;
  product: Product;
  reviews?: Review[];
  recommendations?: Product[];
  pricing: {
    currency: string;
    price: number;
    formatted: string;
  };
  localization: {
    language: string;
    region: string;
  };
}

const ecommerceProductHandler = new Handler<ProductParams, ProductResponse>()
  .use(new HeaderVariablesMiddleware(['authorization', 'accept-language']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware()) // No required query params
  .handle(async (context) => {
    const headers = context.req.headers as ProductHeaders;
    const params = context.req.params as ProductParams;
    const query = context.req.query as ProductQuery;
    
    // Authenticate user
    const user = await authenticateUser(headers.authorization);
    
    // Parse language preferences
    const language = parseAcceptLanguage(headers['accept-language']);
    
    // Validate product exists in category
    const product = await getProductInCategory(params.productId, params.categoryId);
    if (!product) {
      throw new ValidationError('Product not found in specified category');
    }
    
    // Get localized product data
    const localizedProduct = await localizeProduct(product, language);
    
    // Handle optional includes
    const includes: any = {};
    
    if (query.include_reviews === 'true') {
      const reviewLimit = parseInt(query.review_limit || '5');
      includes.reviews = await getProductReviews(params.productId, {
        limit: Math.min(reviewLimit, 50), // Cap at 50
        language
      });
    }
    
    if (query.include_recommendations === 'true') {
      includes.recommendations = await getRecommendations(
        params.productId,
        params.categoryId,
        user.preferences
      );
    }
    
    // Get pricing in requested currency
    const currency = query.currency || user.preferredCurrency || 'USD';
    const pricing = await getPricingInCurrency(product.price, currency);
    
    return {
      success: true,
      product: localizedProduct,
      ...includes,
      pricing: {
        currency,
        price: pricing.amount,
        formatted: pricing.formatted
      },
      localization: {
        language: language.code,
        region: language.region
      }
    };
  });
```

### Multi-Tenant Analytics API

```typescript
// Analytics API with tenant isolation and complex querying
interface AnalyticsHeaders {
  'authorization': string;
  'x-tenant-id': string;
  'x-timezone': string;
}

interface AnalyticsParams {
  reportType: string;
  reportId: string;
}

interface AnalyticsQuery {
  start_date: string;
  end_date: string;
  granularity?: 'hour' | 'day' | 'week' | 'month';
  metrics?: string; // Comma-separated
  dimensions?: string; // Comma-separated
  filters?: string; // JSON-encoded filters
  format?: 'json' | 'csv' | 'excel';
}

const analyticsHandler = new Handler<AnalyticsParams, AnalyticsResponse>()
  .use(new HeaderVariablesMiddleware(['authorization', 'x-tenant-id']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware(['start_date', 'end_date']))
  .handle(async (context) => {
    const headers = context.req.headers as AnalyticsHeaders;
    const params = context.req.params as AnalyticsParams;
    const query = context.req.query as AnalyticsQuery;
    
    // Authenticate and verify tenant access
    const user = await authenticateUser(headers.authorization);
    const tenantAccess = await verifyTenantAccess(user.id, headers['x-tenant-id']);
    
    if (!tenantAccess) {
      throw new SecurityError('Access denied to tenant');
    }
    
    // Validate report type and ID
    const report = await getReportDefinition(params.reportType, params.reportId);
    if (!report || report.tenantId !== headers['x-tenant-id']) {
      throw new ValidationError('Report not found or access denied');
    }
    
    // Parse and validate date range
    const startDate = new Date(query.start_date);
    const endDate = new Date(query.end_date);
    
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format. Use YYYY-MM-DD');
    }
    
    if (startDate >= endDate) {
      throw new ValidationError('start_date must be before end_date');
    }
    
    // Parse timezone
    const timezone = headers['x-timezone'] || 'UTC';
    if (!isValidTimezone(timezone)) {
      throw new ValidationError('Invalid timezone');
    }
    
    // Parse optional parameters
    const metrics = query.metrics ? query.metrics.split(',').map(m => m.trim()) : report.defaultMetrics;
    const dimensions = query.dimensions ? query.dimensions.split(',').map(d => d.trim()) : [];
    const filters = query.filters ? JSON.parse(query.filters) : {};
    
    // Build analytics query
    const analyticsQuery = {
      reportId: params.reportId,
      tenantId: headers['x-tenant-id'],
      dateRange: { start: startDate, end: endDate },
      granularity: query.granularity || 'day',
      metrics,
      dimensions,
      filters,
      timezone
    };
    
    // Generate report
    const reportData = await generateAnalyticsReport(analyticsQuery);
    
    // Format response based on requested format
    const format = query.format || 'json';
    switch (format) {
      case 'csv':
        context.res.header('Content-Type', 'text/csv');
        context.res.header('Content-Disposition', `attachment; filename="${params.reportType}-${params.reportId}.csv"`);
        return convertToCSV(reportData);
        
      case 'excel':
        context.res.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        context.res.header('Content-Disposition', `attachment; filename="${params.reportType}-${params.reportId}.xlsx"`);
        return await convertToExcel(reportData);
        
      default:
        return {
          success: true,
          report: reportData,
          query: analyticsQuery,
          meta: {
            generatedAt: new Date().toISOString(),
            timezone,
            format
          }
        };
    }
  });
```

### User Management API

```typescript
// User management with role-based access and comprehensive validation
interface UserMgmtHeaders {
  'authorization': string;
  'x-admin-role': string;
  'content-type': string;
}

interface UserMgmtParams {
  organizationId: string;
  userId: string;
}

interface UserMgmtQuery {
  action?: 'activate' | 'deactivate' | 'reset_password' | 'update_role';
  notify?: 'true' | 'false';
  reason?: string;
  new_role?: string;
}

const userManagementHandler = new Handler<UserMgmtParams, UserMgmtResponse>()
  .use(new HeaderVariablesMiddleware(['authorization', 'x-admin-role', 'content-type']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware())
  .handle(async (context) => {
    const headers = context.req.headers as UserMgmtHeaders;
    const params = context.req.params as UserMgmtParams;
    const query = context.req.query as UserMgmtQuery;
    
    // Authenticate admin user
    const admin = await authenticateUser(headers.authorization);
    
    // Verify admin role
    const adminRole = headers['x-admin-role'];
    const hasPermission = await verifyAdminPermission(
      admin.id,
      adminRole,
      params.organizationId,
      'user_management'
    );
    
    if (!hasPermission) {
      throw new SecurityError('Insufficient permissions for user management');
    }
    
    // Validate content type for modification operations
    if (context.req.method !== 'GET' && headers['content-type'] !== 'application/json') {
      throw new ValidationError('Content-Type must be application/json for modifications');
    }
    
    // Get target user
    const targetUser = await getUserInOrganization(params.userId, params.organizationId);
    if (!targetUser) {
      throw new ValidationError('User not found in organization');
    }
    
    // Prevent admin from modifying higher-level admins
    if (targetUser.role === 'super_admin' && adminRole !== 'super_admin') {
      throw new SecurityError('Cannot modify super admin users');
    }
    
    let result: any = { user: targetUser };
    
    // Process action if specified
    if (query.action) {
      const actionContext = {
        adminId: admin.id,
        targetUserId: params.userId,
        organizationId: params.organizationId,
        notify: query.notify === 'true',
        reason: query.reason
      };
      
      switch (query.action) {
        case 'activate':
          result.actionResult = await activateUser(actionContext);
          break;
          
        case 'deactivate':
          if (!query.reason) {
            throw new ValidationError('Reason is required for user deactivation');
          }
          result.actionResult = await deactivateUser(actionContext);
          break;
          
        case 'reset_password':
          result.actionResult = await resetUserPassword(actionContext);
          break;
          
        case 'update_role':
          if (!query.new_role) {
            throw new ValidationError('new_role is required for role updates');
          }
          
          // Validate role hierarchy
          const canAssignRole = await validateRoleAssignment(
            adminRole,
            query.new_role,
            params.organizationId
          );
          
          if (!canAssignRole) {
            throw new SecurityError('Cannot assign role higher than your own');
          }
          
          result.actionResult = await updateUserRole({
            ...actionContext,
            newRole: query.new_role
          });
          break;
          
        default:
          throw new ValidationError('Invalid action specified');
      }
      
      // Log admin action
      await logAdminAction({
        adminId: admin.id,
        action: query.action,
        targetUserId: params.userId,
        organizationId: params.organizationId,
        details: { reason: query.reason, newRole: query.new_role }
      });
    }
    
    return {
      success: true,
      ...result,
      admin: {
        id: admin.id,
        role: adminRole
      },
      organization: params.organizationId
    };
  });
```

## TypeScript Generic Patterns

### Complete Type Safety Pattern

```typescript
// Comprehensive type-safe integration
interface CompleteRequestData<TParams, TQuery, THeaders, TBody = any> {
  params: TParams;
  query: TQuery;
  headers: THeaders;
  body?: TBody;
  user?: AuthenticatedUser;
}

interface MiddlewareConfig<TParams, TQuery, THeaders> {
  requiredHeaders: (keyof THeaders)[];
  optionalHeaders?: (keyof THeaders)[];
  requiredParams?: (keyof TParams)[];
  requiredQuery?: (keyof TQuery)[];
  requireAuth?: boolean;
  validateBody?: boolean;
}

function createTypedHandler<
  TParams extends Record<string, string>,
  TQuery extends Record<string, any>,
  THeaders extends Record<string, any>,
  TBody = any,
  TResponse = any
>(
  config: MiddlewareConfig<TParams, TQuery, THeaders>,
  handler: (data: CompleteRequestData<TParams, TQuery, THeaders, TBody>) => Promise<TResponse>
): Handler<any, TResponse> {
  const middlewares: BaseMiddleware[] = [];
  
  // Add header validation
  if (config.requiredHeaders.length > 0) {
    middlewares.push(new HeaderVariablesMiddleware(config.requiredHeaders as string[]));
  }
  
  // Add path parameter extraction
  middlewares.push(new PathParametersMiddleware());
  
  // Add query parameter validation
  if (config.requiredQuery && config.requiredQuery.length > 0) {
    middlewares.push(new QueryParametersMiddleware(config.requiredQuery as string[]));
  } else {
    middlewares.push(new QueryParametersMiddleware()); // Allow optional query params
  }
  
  return new Handler<any, TResponse>()
    .use(...middlewares)
    .handle(async (context) => {
      const requestData: CompleteRequestData<TParams, TQuery, THeaders, TBody> = {
        params: context.req.params as TParams,
        query: context.req.query as TQuery,
        headers: context.req.headers as THeaders,
        body: context.req.body as TBody
      };
      
      // Add authentication if required
      if (config.requireAuth) {
        const authHeader = (context.req.headers as any).authorization;
        if (!authHeader) {
          throw new AuthenticationError('Authentication required');
        }
        requestData.user = await authenticateUser(authHeader);
      }
      
      return await handler(requestData);
    });
}

// Usage with full type safety
interface OrderParams {
  customerId: string;
  orderId: string;
}

interface OrderQuery {
  include_items?: 'true' | 'false';
  include_shipping?: 'true' | 'false';
  currency?: string;
}

interface OrderHeaders {
  'authorization': string;
  'accept': string;
  'x-client-version': string;
}

interface OrderUpdateBody {
  status?: 'pending' | 'confirmed' | 'shipped' | 'delivered' | 'cancelled';
  notes?: string;
  shipping_address?: Address;
}

const typedOrderHandler = createTypedHandler<
  OrderParams,
  OrderQuery,
  OrderHeaders,
  OrderUpdateBody,
  OrderResponse
>({
  requiredHeaders: ['authorization', 'accept'],
  requiredParams: ['customerId', 'orderId'],
  requireAuth: true,
  validateBody: true
}, async ({ params, query, headers, body, user }) => {
  // All parameters are fully typed and validated
  const order = await getOrder(params.orderId, params.customerId);
  
  // Verify user has access to this customer's orders
  if (!await canAccessCustomerOrders(user!.id, params.customerId)) {
    throw new SecurityError('Access denied to customer orders');
  }
  
  // Update order if body provided
  if (body && Object.keys(body).length > 0) {
    await updateOrder(params.orderId, body, user!.id);
  }
  
  // Include optional data based on query parameters
  const enrichedOrder = await enrichOrder(order, {
    includeItems: query.include_items === 'true',
    includeShipping: query.include_shipping === 'true',
    currency: query.currency || 'USD'
  });
  
  return {
    success: true,
    order: enrichedOrder,
    customer: params.customerId,
    includes: {
      items: query.include_items === 'true',
      shipping: query.include_shipping === 'true'
    }
  };
});
```

### Generic Validation Factory

```typescript
// Factory with built-in validation patterns
interface ValidationRules<T> {
  required?: (keyof T)[];
  patterns?: Partial<Record<keyof T, RegExp>>;
  custom?: Partial<Record<keyof T, (value: any) => boolean>>;
  transform?: Partial<Record<keyof T, (value: any) => any>>;
}

function createValidatedIntegration<
  TParams extends Record<string, string>,
  TQuery extends Record<string, any>,
  THeaders extends Record<string, any>,
  TResponse
>(config: {
  headers: {
    required: (keyof THeaders)[];
    rules?: ValidationRules<THeaders>;
  };
  params: {
    rules?: ValidationRules<TParams>;
  };
  query: {
    required?: (keyof TQuery)[];
    rules?: ValidationRules<TQuery>;
  };
  handler: (validated: {
    params: TParams;
    query: TQuery;
    headers: THeaders;
  }) => Promise<TResponse>;
}) {
  return new Handler<any, TResponse>()
    .use(new HeaderVariablesMiddleware(config.headers.required as string[]))
    .use(new PathParametersMiddleware())
    .use(new QueryParametersMiddleware(config.query.required as string[] || []))
    .handle(async (context) => {
      const params = context.req.params as TParams;
      const query = context.req.query as TQuery;
      const headers = context.req.headers as THeaders;
      
      // Validate and transform params
      const validatedParams = validateAndTransform(params, config.params.rules);
      
      // Validate and transform query
      const validatedQuery = validateAndTransform(query, config.query.rules);
      
      // Validate and transform headers  
      const validatedHeaders = validateAndTransform(headers, config.headers.rules);
      
      return await config.handler({
        params: validatedParams,
        query: validatedQuery,
        headers: validatedHeaders
      });
    });
}

function validateAndTransform<T extends Record<string, any>>(
  data: T,
  rules?: ValidationRules<T>
): T {
  if (!rules) return data;
  
  const result = { ...data };
  
  // Check required fields
  if (rules.required) {
    for (const field of rules.required) {
      if (!data[field]) {
        throw new ValidationError(`${String(field)} is required`);
      }
    }
  }
  
  // Apply pattern validation
  if (rules.patterns) {
    for (const [field, pattern] of Object.entries(rules.patterns)) {
      const value = data[field];
      if (value && !pattern.test(String(value))) {
        throw new ValidationError(`${field} format is invalid`);
      }
    }
  }
  
  // Apply custom validation
  if (rules.custom) {
    for (const [field, validator] of Object.entries(rules.custom)) {
      const value = data[field];
      if (value && !validator(value)) {
        throw new ValidationError(`${field} validation failed`);
      }
    }
  }
  
  // Apply transformations
  if (rules.transform) {
    for (const [field, transformer] of Object.entries(rules.transform)) {
      const value = data[field];
      if (value) {
        result[field] = transformer(value);
      }
    }
  }
  
  return result;
}

// Usage with validation rules
interface ProductParams {
  productId: string;
  categoryId: string;
}

interface ProductQuery {
  page: string;
  limit: string;
  sort: string;
}

interface ProductHeaders {
  'authorization': string;
  'accept-language': string;
}

const validatedProductHandler = createValidatedIntegration<
  ProductParams,
  ProductQuery,
  ProductHeaders,
  ProductResponse
>({
  headers: {
    required: ['authorization', 'accept-language'],
    rules: {
      patterns: {
        'accept-language': /^[a-z]{2}(-[A-Z]{2})?$/
      }
    }
  },
  params: {
    rules: {
      patterns: {
        productId: /^[a-zA-Z0-9-]+$/,
        categoryId: /^[a-zA-Z0-9-]+$/
      }
    }
  },
  query: {
    rules: {
      patterns: {
        page: /^\d+$/,
        limit: /^\d+$/
      },
      transform: {
        page: (value) => Math.max(1, parseInt(value)),
        limit: (value) => Math.min(100, Math.max(1, parseInt(value)))
      },
      custom: {
        sort: (value) => ['name', 'price', 'rating', 'date'].includes(value)
      }
    }
  },
  handler: async ({ params, query, headers }) => {
    // All data is validated and transformed
    const products = await getProducts({
      categoryId: params.categoryId,
      productId: params.productId,
      page: query.page, // Now a number
      limit: query.limit, // Now a number  
      sort: query.sort,
      language: headers['accept-language']
    });
    
    return { success: true, products };
  }
});
```

## Error Handling Strategies

### Comprehensive Error Integration

```typescript
// Centralized error handling for all middleware types
interface ErrorContext {
  source: 'headers' | 'params' | 'query' | 'business';
  middleware: string;
  originalError: Error;
  requestData: {
    headers?: Record<string, any>;
    params?: Record<string, any>;
    query?: Record<string, any>;
  };
}

class IntegratedErrorHandler {
  static handleMiddlewareError(error: Error, context: Context): ErrorResponse {
    const errorContext: Partial<ErrorContext> = {
      requestData: {
        headers: context.req.headers,
        params: context.req.params,
        query: context.req.query
      }
    };
    
    if (error instanceof ValidationError) {
      // Determine which middleware failed
      const errorMessage = error.message.toLowerCase();
      
      if (errorMessage.includes('header')) {
        errorContext.source = 'headers';
        errorContext.middleware = 'HeaderVariablesMiddleware';
      } else if (errorMessage.includes('parameter')) {
        errorContext.source = 'query';
        errorContext.middleware = 'QueryParametersMiddleware';
      } else {
        errorContext.source = 'params';
        errorContext.middleware = 'PathParametersMiddleware';
      }
      
      return {
        success: false,
        error: error.message,
        code: 'VALIDATION_ERROR',
        source: errorContext.source,
        details: this.generateValidationDetails(error, errorContext)
      };
    }
    
    if (error instanceof AuthenticationError) {
      return {
        success: false,
        error: 'Authentication failed',
        code: 'AUTHENTICATION_ERROR',
        source: 'headers'
      };
    }
    
    if (error instanceof SecurityError) {
      return {
        success: false,
        error: 'Security violation',
        code: 'SECURITY_ERROR',
        source: 'business'
      };
    }
    
    // Unknown error
    return {
      success: false,
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    };
  }
  
  private static generateValidationDetails(error: ValidationError, context: Partial<ErrorContext>) {
    const details: any = {};
    
    switch (context.source) {
      case 'headers':
        details.receivedHeaders = Object.keys(context.requestData?.headers || {});
        details.missingHeaders = this.extractMissingHeaders(error.message);
        break;
        
      case 'params':
        details.receivedParams = Object.keys(context.requestData?.params || {});
        details.expectedFormat = 'Path parameters should be URL segments';
        break;
        
      case 'query':
        details.receivedQuery = Object.keys(context.requestData?.query || {});
        details.missingQuery = this.extractMissingQuery(error.message);
        break;
    }
    
    return details;
  }
  
  private static extractMissingHeaders(errorMessage: string): string[] {
    const match = errorMessage.match(/Missing required header: ([^,]+)/g);
    return match ? match.map(m => m.replace('Missing required header: ', '')) : [];
  }
  
  private static extractMissingQuery(errorMessage: string): string[] {
    const match = errorMessage.match(/Missing required query parameter: ([^,]+)/g);
    return match ? match.map(m => m.replace('Missing required query parameter: ', '')) : [];
  }
}

// Usage in handlers
const errorAwareHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware(['page']))
  .handle(async (context) => {
    try {
      // Business logic here
      return await processRequest(context);
      
    } catch (error) {
      return IntegratedErrorHandler.handleMiddlewareError(error, context);
    }
  });
```

### Validation Chain Error Handling

```typescript
// Sequential validation with detailed error reporting
class ValidationChain {
  private errors: ValidationError[] = [];
  
  validateHeaders(headers: Record<string, any>, required: string[]): this {
    try {
      for (const header of required) {
        if (!headers[header.toLowerCase()]) {
          this.errors.push(new ValidationError(`Missing required header: ${header}`));
        }
      }
    } catch (error) {
      this.errors.push(error);
    }
    return this;
  }
  
  validateParams(params: Record<string, any>, patterns: Record<string, RegExp>): this {
    try {
      for (const [param, pattern] of Object.entries(patterns)) {
        const value = params[param];
        if (value && !pattern.test(value)) {
          this.errors.push(new ValidationError(`Invalid format for parameter: ${param}`));
        }
      }
    } catch (error) {
      this.errors.push(error);
    }
    return this;
  }
  
  validateQuery(query: Record<string, any>, rules: {
    required?: string[];
    types?: Record<string, 'string' | 'number' | 'boolean'>;
  }): this {
    try {
      if (rules.required) {
        for (const param of rules.required) {
          if (!query[param]) {
            this.errors.push(new ValidationError(`Missing required query parameter: ${param}`));
          }
        }
      }
      
      if (rules.types) {
        for (const [param, expectedType] of Object.entries(rules.types)) {
          const value = query[param];
          if (value && !this.isCorrectType(value, expectedType)) {
            this.errors.push(new ValidationError(`Invalid type for query parameter ${param}: expected ${expectedType}`));
          }
        }
      }
    } catch (error) {
      this.errors.push(error);
    }
    return this;
  }
  
  throwIfErrors(): void {
    if (this.errors.length > 0) {
      throw new ValidationError('Multiple validation errors', JSON.stringify(this.errors.map(e => e.message)));
    }
  }
  
  private isCorrectType(value: any, expectedType: string): boolean {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return !isNaN(Number(value));
      case 'boolean':
        return value === 'true' || value === 'false';
      default:
        return false;
    }
  }
}

// Usage with comprehensive validation
const chainValidatedHandler = new Handler()
  .use(new HeaderVariablesMiddleware([])) // Don't validate here, do it in chain
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware([]))
  .handle(async (context) => {
    // Comprehensive validation chain
    const validator = new ValidationChain()
      .validateHeaders(context.req.headers, ['authorization', 'content-type'])
      .validateParams(context.req.params, {
        userId: /^[a-zA-Z0-9-]+$/,
        organizationId: /^[a-zA-Z0-9-]+$/
      })
      .validateQuery(context.req.query, {
        required: ['page'],
        types: {
          page: 'number',
          limit: 'number',
          active: 'boolean'
        }
      });
    
    // Throw all validation errors at once
    validator.throwIfErrors();
    
    // Process with validated data
    return await processValidatedRequest(context);
  });
```

## Performance Optimization

### Middleware Ordering Optimization

```typescript
// Optimal middleware ordering for performance
const optimizedHandler = new Handler()
  // 1. Cheapest validation first - headers (in-memory check)
  .use(new HeaderVariablesMiddleware(['authorization']))
  
  // 2. Next cheapest - path parameters (URL parsing)
  .use(new PathParametersMiddleware())
  
  // 3. Query parameters (string parsing)
  .use(new QueryParametersMiddleware(['page']))
  
  // 4. Expensive operations last - authentication (database/network)
  .use(authenticationMiddleware)
  
  .handle(async (context) => {
    // Business logic only runs if all validations pass
    return await processRequest(context);
  });

// Poor ordering example (avoid this)
const poorlyOrderedHandler = new Handler()
  .use(expensiveAuthMiddleware) // Expensive operation first
  .use(databaseValidationMiddleware) // Another expensive operation
  .use(new HeaderVariablesMiddleware(['authorization'])) // Cheap validation last
  .handle(async (context) => {
    // May do expensive work even for invalid requests
  });
```

### Caching Integration

```typescript
// Integrated caching across all middleware types
import { LRUCache } from 'lru-cache';

interface CacheKey {
  headers: string;
  params: string;
  query: string;
}

const requestCache = new LRUCache<string, any>({
  max: 10000,
  ttl: 60 * 1000 // 1 minute
});

const cachedIntegratedHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware())
  .handle(async (context) => {
    // Generate cache key from all request attributes
    const cacheKey = generateCacheKey({
      headers: JSON.stringify(context.req.headers),
      params: JSON.stringify(context.req.params),
      query: JSON.stringify(context.req.query)
    });
    
    // Check cache first
    const cached = requestCache.get(cacheKey);
    if (cached) {
      return { ...cached, cached: true };
    }
    
    // Process request
    const result = await processRequest(context);
    
    // Cache result
    requestCache.set(cacheKey, result);
    
    return { ...result, cached: false };
  });

function generateCacheKey(parts: CacheKey): string {
  // Create deterministic cache key
  return Buffer.from(JSON.stringify(parts)).toString('base64');
}
```

### Parallel Validation

```typescript
// Parallel validation for independent middleware
const parallelValidatedHandler = new Handler()
  .handle(async (context) => {
    // Run all validations in parallel
    const validations = await Promise.allSettled([
      validateHeaders(context.req.headers, ['authorization', 'content-type']),
      validatePathParams(context.req.params, ['userId', 'organizationId']),
      validateQueryParams(context.req.query, ['page', 'limit'])
    ]);
    
    // Check for validation failures
    const failures = validations
      .map((result, index) => ({ result, index }))
      .filter(({ result }) => result.status === 'rejected')
      .map(({ result, index }) => ({
        source: ['headers', 'params', 'query'][index],
        error: (result as PromiseRejectedResult).reason
      }));
    
    if (failures.length > 0) {
      throw new ValidationError('Multiple validation failures', JSON.stringify(failures));
    }
    
    // All validations passed, process request
    return await processRequest(context);
  });

async function validateHeaders(headers: any, required: string[]): Promise<void> {
  for (const header of required) {
    if (!headers[header.toLowerCase()]) {
      throw new ValidationError(`Missing header: ${header}`);
    }
  }
}

async function validatePathParams(params: any, required: string[]): Promise<void> {
  for (const param of required) {
    if (!params[param]) {
      throw new ValidationError(`Missing path parameter: ${param}`);
    }
  }
}

async function validateQueryParams(query: any, required: string[]): Promise<void> {
  for (const param of required) {
    if (!query[param]) {
      throw new ValidationError(`Missing query parameter: ${param}`);
    }
  }
}
```

## Testing Strategies

### Comprehensive Testing Utilities

```typescript
// Testing utilities for integrated middleware
export class MiddlewareTestUtils {
  static createMockContext(data: {
    headers?: Record<string, string>;
    params?: Record<string, string>;
    query?: Record<string, string>;
    body?: any;
    method?: string;
    url?: string;
  }): Context {
    return {
      req: {
        headers: data.headers || {},
        params: data.params || {},
        query: data.query || {},
        body: data.body,
        method: data.method || 'GET',
        url: data.url || '/test',
        connection: { remoteAddress: '127.0.0.1' }
      },
      res: {
        header: jest.fn(),
        status: jest.fn(),
        json: jest.fn()
      },
      businessData: new Map(),
      requestId: 'test-request-id',
      startTime: Date.now(),
      timeoutSignal: new AbortController().signal
    } as any;
  }
  
  static async expectValidationError(
    handler: Handler,
    context: Context,
    expectedMessage: string,
    expectedSource?: 'headers' | 'params' | 'query'
  ): Promise<void> {
    try {
      await handler.execute(context.req as any, context.res as any);
      throw new Error('Expected validation error but none was thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ValidationError);
      expect(error.message).toContain(expectedMessage);
      
      if (expectedSource) {
        // Additional source-specific assertions
        switch (expectedSource) {
          case 'headers':
            expect(error.message).toMatch(/header/i);
            break;
          case 'params':
            expect(error.message).toMatch(/parameter/i);
            break;
          case 'query':
            expect(error.message).toMatch(/query/i);
            break;
        }
      }
    }
  }
  
  static async testSuccessfulIntegration(
    handler: Handler,
    testCases: Array<{
      name: string;
      context: Context;
      expectedResponse: any;
    }>
  ): Promise<void> {
    for (const testCase of testCases) {
      const result = await handler.execute(
        testCase.context.req as any,
        testCase.context.res as any
      );
      
      expect(result).toEqual(expect.objectContaining(testCase.expectedResponse));
    }
  }
}

// Example test suite
describe('Integrated Middleware', () => {
  const handler = new Handler()
    .use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
    .use(new PathParametersMiddleware())
    .use(new QueryParametersMiddleware(['page']))
    .handle(async (context) => {
      return {
        success: true,
        headers: context.req.headers,
        params: context.req.params,
        query: context.req.query
      };
    });
  
  test('should handle valid request with all middleware', async () => {
    const context = MiddlewareTestUtils.createMockContext({
      headers: {
        'authorization': 'Bearer token123',
        'content-type': 'application/json'
      },
      params: { userId: 'user123' },
      query: { page: '1', limit: '10' }
    });
    
    const result = await handler.execute(context.req as any, context.res as any);
    
    expect(result).toEqual({
      success: true,
      headers: expect.objectContaining({
        'authorization': 'Bearer token123',
        'content-type': 'application/json'
      }),
      params: { userId: 'user123' },
      query: { page: '1', limit: '10' }
    });
  });
  
  test('should fail with missing required header', async () => {
    const context = MiddlewareTestUtils.createMockContext({
      headers: { 'content-type': 'application/json' }, // Missing authorization
      params: { userId: 'user123' },
      query: { page: '1' }
    });
    
    await MiddlewareTestUtils.expectValidationError(
      handler,
      context,
      'Missing required header: authorization',
      'headers'
    );
  });
  
  test('should fail with missing required query parameter', async () => {
    const context = MiddlewareTestUtils.createMockContext({
      headers: {
        'authorization': 'Bearer token123',
        'content-type': 'application/json'
      },
      params: { userId: 'user123' },
      query: {} // Missing page parameter
    });
    
    await MiddlewareTestUtils.expectValidationError(
      handler,
      context,
      'Missing required query parameter: page',
      'query'
    );
  });
  
  test('batch test successful integrations', async () => {
    await MiddlewareTestUtils.testSuccessfulIntegration(handler, [
      {
        name: 'minimal valid request',
        context: MiddlewareTestUtils.createMockContext({
          headers: { 'authorization': 'Bearer token', 'content-type': 'application/json' },
          params: { userId: 'user1' },
          query: { page: '1' }
        }),
        expectedResponse: { success: true }
      },
      {
        name: 'request with additional parameters',
        context: MiddlewareTestUtils.createMockContext({
          headers: { 'authorization': 'Bearer token', 'content-type': 'application/json', 'accept': 'application/json' },
          params: { userId: 'user2', organizationId: 'org1' },
          query: { page: '2', limit: '20', sort: 'name' }
        }),
        expectedResponse: { success: true }
      }
    ]);
  });
});
```

## Best Practices

### 1. Middleware Order and Composition

```typescript
// Good: Logical order from fastest to slowest validation
const wellOrderedHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization'])) // Fast: memory check
  .use(new PathParametersMiddleware()) // Fast: URL parsing
  .use(new QueryParametersMiddleware(['q'])) // Medium: parameter parsing
  .use(rateLimitingMiddleware()) // Medium: cache/memory check
  .use(authenticationMiddleware) // Slow: token validation
  .use(authorizationMiddleware) // Slow: database check
  .handle(async (context) => {
    // Business logic with validated data
  });
```

### 2. Type Safety and Validation

```typescript
// Good: Comprehensive type safety
interface CompleteAPIRequest {
  headers: {
    authorization: string;
    'content-type': string;
    'accept-language'?: string;
  };
  params: {
    resourceId: string;
    subResourceId: string;
  };
  query: {
    page: number;
    limit: number;
    sort?: string;
    filters?: Record<string, any>;
  };
}

const typesSafeHandler = new Handler<any, APIResponse>()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware(['page', 'limit']))
  .handle(async (context) => {
    // Type assertion with confidence due to middleware validation
    const request = context.req as CompleteAPIRequest;
    
    // Runtime validation for complex types
    const page = parseInt(request.query.page as unknown as string);
    const limit = Math.min(100, parseInt(request.query.limit as unknown as string));
    
    if (isNaN(page) || page < 1) {
      throw new ValidationError('Page must be a positive integer');
    }
    
    if (isNaN(limit) || limit < 1 || limit > 100) {
      throw new ValidationError('Limit must be between 1 and 100');
    }
    
    // Process with validated, typed data
    return await processTypedRequest({
      ...request,
      query: { ...request.query, page, limit }
    });
  });
```

### 3. Error Handling and User Experience

```typescript
// Good: User-friendly error messages with context
const userFriendlyHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware(['page']))
  .handle(async (context) => {
    try {
      return await processRequest(context);
    } catch (error) {
      if (error instanceof ValidationError) {
        return {
          success: false,
          error: {
            message: error.message,
            code: 'VALIDATION_ERROR',
            help: generateHelpMessage(error, context),
            examples: generateExamples(context.req.url)
          }
        };
      }
      throw error;
    }
  });

function generateHelpMessage(error: ValidationError, context: Context): string {
  const message = error.message.toLowerCase();
  
  if (message.includes('header')) {
    return 'Make sure to include all required headers in your request';
  } else if (message.includes('parameter')) {
    return 'Check that all required parameters are included in the URL';
  } else if (message.includes('query')) {
    return 'Verify that required query parameters are present in the URL';
  }
  
  return 'Please check your request format and try again';
}

function generateExamples(url: string): any {
  return {
    validHeaders: {
      'Authorization': 'Bearer your-token-here',
      'Content-Type': 'application/json'
    },
    validURL: url.replace(/:[^/]+/g, match => `{${match.slice(1)}}`),
    validQuery: '?page=1&limit=10&sort=name'
  };
}
```

### 4. Documentation and Maintenance

```typescript
/**
 * Complete User Management API Handler
 * 
 * This handler demonstrates the integration of all three middleware types:
 * - HeaderVariablesMiddleware: Authentication and content type validation
 * - PathParametersMiddleware: User and organization ID extraction  
 * - QueryParametersMiddleware: Pagination and filtering options
 * 
 * Required Headers:
 * - Authorization: Bearer token for authentication
 * - Content-Type: Must be application/json for POST/PUT requests
 * - X-Client-Version: Client application version for compatibility
 * 
 * Path Parameters:
 * - organizationId: Organization identifier (UUID format)
 * - userId: User identifier (UUID format)
 * 
 * Query Parameters:
 * - page: Page number for pagination (required, min: 1)
 * - limit: Items per page (optional, default: 10, max: 100)
 * - include: Comma-separated list of fields to include (optional)
 * - sort: Sort field and order, e.g., "name:asc" (optional)
 * 
 * Example Requests:
 * GET /api/organizations/550e8400-e29b-41d4-a716-446655440000/users/123e4567-e89b-12d3-a456-426614174000?page=1&limit=20&include=profile,permissions&sort=name:asc
 * 
 * Error Responses:
 * - 400: Missing required headers, invalid parameters, or validation errors
 * - 401: Invalid or expired authentication token
 * - 403: Insufficient permissions for the requested operation
 * - 404: User or organization not found
 * - 429: Rate limit exceeded
 * 
 * @param context - Request context with validated headers, params, and query
 * @returns Promise<UserManagementResponse> - User data with pagination info
 */
const documentedUserManagementHandler = new Handler<UserParams, UserManagementResponse>()
  .use(new HeaderVariablesMiddleware([
    'authorization',
    'content-type',
    'x-client-version'
  ]))
  .use(new PathParametersMiddleware())
  .use(new QueryParametersMiddleware(['page']))
  .handle(async (context) => {
    // Implementation with comprehensive error handling and logging
    return await processUserManagementRequest(context);
  });
```

This integration guide demonstrates how the three middleware types work together to create robust, type-safe, and user-friendly APIs. By combining header validation, path parameter extraction, and query parameter processing, you can build comprehensive request handling pipelines that validate all aspects of incoming HTTP requests while maintaining excellent developer experience and runtime performance.