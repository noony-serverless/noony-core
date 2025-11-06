# QueryParametersMiddleware Guide

A comprehensive guide to using the QueryParametersMiddleware for extracting and validating URL query parameters in the Noony Framework.

## Table of Contents

1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [Basic Usage](#basic-usage)
4. [TypeScript Generics Integration](#typescript-generics-integration)
5. [Advanced Examples](#advanced-examples)
6. [Validation Patterns](#validation-patterns)
7. [Error Handling](#error-handling)
8. [Performance Considerations](#performance-considerations)
9. [Best Practices](#best-practices)

## Overview

The QueryParametersMiddleware extracts query parameters from the request URL and validates that required parameters are present. It parses URL query strings like `?page=1&limit=10&sort=name` and makes them available as `context.req.query`.

### Key Features
- **Automatic Extraction**: Parses query strings into structured objects
- **Required Parameter Validation**: Ensures critical parameters are present
- **Type Safety**: Works seamlessly with TypeScript generics
- **Array Support**: Handles multiple values for the same parameter
- **Flexible Configuration**: Optional or required parameter patterns

### When to Use
- **API Endpoints**: Pagination, filtering, sorting parameters
- **Search Functionality**: Query terms, categories, filters
- **Configuration Options**: Feature flags, display preferences
- **Data Filtering**: Date ranges, status filters, category selection

## How It Works

The middleware processes the request URL and extracts query parameters:

```typescript
// URL: /api/products?category=electronics&page=1&limit=10&sort=name&sort=price

// Results in:
context.req.query = {
  category: "electronics",
  page: "1", 
  limit: "10",
  sort: ["name", "price"] // Multiple values become arrays
}
```

### Internal Process
1. **URL Parsing**: Extracts the query string from `context.req.url`
2. **Parameter Extraction**: Uses `URLSearchParams` to parse key-value pairs
3. **Type Conversion**: Converts parsed values to strings or string arrays
4. **Required Validation**: Checks that all required parameters are present
5. **Context Assignment**: Sets `context.req.query` with parsed values

## Basic Usage

### Simple Query Parameter Extraction

```typescript
import { Handler, QueryParametersMiddleware } from '@/middlewares';

// No required parameters - all are optional
const searchHandler = new Handler()
  .use(new QueryParametersMiddleware()) // Empty array = no required params
  .handle(async (context) => {
    const { q, category, sort } = context.req.query || {};
    
    const results = await searchProducts({
      query: q,
      category,
      sortBy: sort || 'relevance'
    });
    
    return { success: true, results, params: { q, category, sort } };
  });
```

### Required Parameter Validation

```typescript
// Require specific parameters
const paginatedListHandler = new Handler()
  .use(new QueryParametersMiddleware(['page', 'limit'])) // These are required
  .handle(async (context) => {
    const { page, limit, sort } = context.req.query;
    
    const items = await getItems({
      page: parseInt(page as string),
      limit: parseInt(limit as string),
      sort: sort as string
    });
    
    return { success: true, items, pagination: { page, limit } };
  });
```

### Factory Function Usage

```typescript
import { queryParametersMiddleware } from '@/middlewares';

const flexibleApiHandler = new Handler()
  .use(queryParametersMiddleware(['q'])) // Only 'q' is required
  .handle(async (context) => {
    const { q, category, price_min, price_max } = context.req.query;
    
    const filters = {
      query: q as string,
      category: category as string,
      priceRange: {
        min: price_min ? parseFloat(price_min as string) : undefined,
        max: price_max ? parseFloat(price_max as string) : undefined
      }
    };
    
    return await searchWithFilters(filters);
  });
```

## TypeScript Generics Integration

### Type-Safe Query Parameters

```typescript
import { Handler } from '@/core/handler';
import { QueryParametersMiddleware } from '@/middlewares';

// Define query parameter types
interface SearchQuery {
  q: string;
  category?: string;
  sort?: 'name' | 'price' | 'rating';
  page?: string;
  limit?: string;
}

interface SearchResponse {
  products: Product[];
  pagination: {
    page: number;
    limit: number;
    total: number;
  };
  filters: SearchQuery;
}

// Type-safe handler with generics
const searchProductsHandler = new Handler<SearchQuery, SearchResponse>()
  .use(new QueryParametersMiddleware(['q'])) // 'q' is required
  .handle(async (context) => {
    // context.req.query is now typed, but still needs runtime parsing
    const query = context.req.query as unknown as SearchQuery;
    
    const page = parseInt(query.page || '1');
    const limit = parseInt(query.limit || '10');
    
    const products = await searchProducts({
      query: query.q,
      category: query.category,
      sort: query.sort || 'name',
      pagination: { page, limit }
    });
    
    return {
      products: products.items,
      pagination: {
        page,
        limit, 
        total: products.total
      },
      filters: query
    };
  });
```

### Advanced Generic Pattern with Validation

```typescript
// Generic query parameter handler factory
function createQueryHandler<TQuery extends Record<string, any>, TResponse>(
  requiredParams: (keyof TQuery)[],
  handler: (query: TQuery) => Promise<TResponse>
) {
  return new Handler<TQuery, TResponse>()
    .use(new QueryParametersMiddleware(requiredParams as string[]))
    .handle(async (context) => {
      const query = context.req.query as unknown as TQuery;
      return await handler(query);
    });
}

// Usage with specific types
interface PaginationQuery {
  page: string;
  limit: string;
  sort?: 'asc' | 'desc';
}

interface UserListResponse {
  users: User[];
  meta: {
    page: number;
    limit: number;
    total: number;
    sort: string;
  };
}

const userListHandler = createQueryHandler<PaginationQuery, UserListResponse>(
  ['page', 'limit'], // Required parameters
  async (query) => {
    const page = parseInt(query.page);
    const limit = Math.min(parseInt(query.limit), 100); // Cap at 100
    
    const users = await getUsersPaginated({
      page,
      limit,
      sort: query.sort || 'asc'
    });
    
    return {
      users: users.items,
      meta: {
        page,
        limit,
        total: users.total,
        sort: query.sort || 'asc'
      }
    };
  }
);
```

## Advanced Examples

### E-commerce Product Filtering

```typescript
interface ProductFilterQuery {
  category: string;        // Required
  brand?: string;
  price_min?: string;
  price_max?: string;
  in_stock?: 'true' | 'false';
  rating_min?: string;
  sort?: 'price' | 'rating' | 'name';
  page?: string;
  limit?: string;
}

const productFilterHandler = new Handler<ProductFilterQuery, ProductResponse>()
  .use(new QueryParametersMiddleware(['category'])) // Category is required
  .handle(async (context) => {
    const query = context.req.query as unknown as ProductFilterQuery;
    
    // Parse and validate parameters
    const filters: ProductFilters = {
      category: query.category,
      brand: query.brand,
      priceRange: {
        min: query.price_min ? parseFloat(query.price_min) : undefined,
        max: query.price_max ? parseFloat(query.price_max) : undefined
      },
      inStock: query.in_stock === 'true',
      minRating: query.rating_min ? parseFloat(query.rating_min) : undefined,
      sort: query.sort || 'name',
      pagination: {
        page: parseInt(query.page || '1'),
        limit: Math.min(parseInt(query.limit || '20'), 100)
      }
    };
    
    const products = await searchProducts(filters);
    
    return {
      success: true,
      products: products.items,
      filters: query,
      pagination: products.pagination
    };
  });
```

### Analytics and Reporting Parameters

```typescript
interface AnalyticsQuery {
  start_date: string;      // Required: YYYY-MM-DD format
  end_date: string;        // Required: YYYY-MM-DD format
  granularity?: 'hour' | 'day' | 'week' | 'month';
  metrics?: string;        // Comma-separated list
  segment?: string;
  format?: 'json' | 'csv' | 'excel';
}

const analyticsHandler = new Handler<AnalyticsQuery, AnalyticsResponse>()
  .use(new QueryParametersMiddleware(['start_date', 'end_date']))
  .handle(async (context) => {
    const query = context.req.query as unknown as AnalyticsQuery;
    
    // Validate date formats
    const startDate = new Date(query.start_date);
    const endDate = new Date(query.end_date);
    
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format. Use YYYY-MM-DD');
    }
    
    if (startDate >= endDate) {
      throw new ValidationError('start_date must be before end_date');
    }
    
    const reportConfig: ReportConfig = {
      dateRange: { start: startDate, end: endDate },
      granularity: query.granularity || 'day',
      metrics: query.metrics ? query.metrics.split(',') : ['views', 'clicks'],
      segment: query.segment,
      format: query.format || 'json'
    };
    
    const report = await generateReport(reportConfig);
    
    return {
      success: true,
      report,
      config: reportConfig
    };
  });
```

### Search with Advanced Filtering

```typescript
interface SearchQuery {
  q: string;               // Required search term
  type?: 'product' | 'article' | 'user';
  tags?: string;           // Comma-separated tags
  created_after?: string;  // ISO date string
  created_before?: string; // ISO date string
  author?: string;
  status?: 'published' | 'draft' | 'archived';
  include_content?: 'true' | 'false';
}

const searchHandler = new Handler<SearchQuery, SearchResponse>()
  .use(new QueryParametersMiddleware(['q']))
  .handle(async (context) => {
    const query = context.req.query as unknown as SearchQuery;
    
    // Parse complex parameters
    const searchParams: SearchParameters = {
      query: query.q,
      type: query.type || 'product',
      tags: query.tags ? query.tags.split(',').map(tag => tag.trim()) : [],
      dateRange: {
        after: query.created_after ? new Date(query.created_after) : undefined,
        before: query.created_before ? new Date(query.created_before) : undefined
      },
      author: query.author,
      status: query.status,
      includeContent: query.include_content === 'true'
    };
    
    const results = await performSearch(searchParams);
    
    return {
      success: true,
      results: results.items,
      total: results.total,
      query: searchParams
    };
  });
```

## Validation Patterns

### Custom Parameter Validation

```typescript
// Custom validation middleware factory
function createValidatedQueryHandler<T>(
  requiredParams: string[],
  validator: (query: Record<string, any>) => T,
  handler: (validatedQuery: T) => Promise<any>
) {
  return new Handler()
    .use(new QueryParametersMiddleware(requiredParams))
    .handle(async (context) => {
      try {
        const validatedQuery = validator(context.req.query);
        return await handler(validatedQuery);
      } catch (error) {
        throw new ValidationError(`Query validation failed: ${error.message}`);
      }
    });
}

// Usage with custom validation
interface PaginationParams {
  page: number;
  limit: number;
  sort: 'asc' | 'desc';
}

const paginationValidator = (query: Record<string, any>): PaginationParams => {
  const page = parseInt(query.page);
  const limit = parseInt(query.limit);
  
  if (isNaN(page) || page < 1) {
    throw new Error('page must be a positive integer');
  }
  
  if (isNaN(limit) || limit < 1 || limit > 100) {
    throw new Error('limit must be between 1 and 100');
  }
  
  if (query.sort && !['asc', 'desc'].includes(query.sort)) {
    throw new Error('sort must be "asc" or "desc"');
  }
  
  return {
    page,
    limit,
    sort: query.sort || 'asc'
  };
};

const validatedPaginationHandler = createValidatedQueryHandler(
  ['page', 'limit'],
  paginationValidator,
  async (params: PaginationParams) => {
    const data = await getPaginatedData(params);
    return { success: true, data, params };
  }
);
```

### Integration with Zod Schemas

```typescript
import { z } from 'zod';

// Zod schema for query validation
const searchQuerySchema = z.object({
  q: z.string().min(1, 'Search query cannot be empty'),
  category: z.string().optional(),
  price_min: z.string().regex(/^\d+(\.\d{2})?$/, 'Invalid price format').optional(),
  price_max: z.string().regex(/^\d+(\.\d{2})?$/, 'Invalid price format').optional(),
  sort: z.enum(['price', 'rating', 'name']).default('name'),
  page: z.string().regex(/^\d+$/).transform(Number).default('1'),
  limit: z.string().regex(/^\d+$/).transform(Number).default('10')
});

type SearchQuery = z.infer<typeof searchQuerySchema>;

const zodValidatedHandler = new Handler<SearchQuery, SearchResponse>()
  .use(new QueryParametersMiddleware(['q']))
  .handle(async (context) => {
    // Validate with Zod
    const validatedQuery = searchQuerySchema.parse(context.req.query);
    
    const results = await searchProducts({
      query: validatedQuery.q,
      category: validatedQuery.category,
      priceRange: {
        min: validatedQuery.price_min ? parseFloat(validatedQuery.price_min) : undefined,
        max: validatedQuery.price_max ? parseFloat(validatedQuery.price_max) : undefined
      },
      sort: validatedQuery.sort,
      pagination: {
        page: validatedQuery.page,
        limit: Math.min(validatedQuery.limit, 100)
      }
    });
    
    return {
      success: true,
      results: results.items,
      pagination: results.pagination,
      appliedFilters: validatedQuery
    };
  });
```

## Error Handling

### Validation Error Patterns

```typescript
const robustQueryHandler = new Handler()
  .use(new QueryParametersMiddleware(['required_param']))
  .handle(async (context) => {
    try {
      const { required_param, optional_param } = context.req.query;
      
      // Custom validation logic
      if (required_param && typeof required_param === 'string' && required_param.length < 3) {
        throw new ValidationError('required_param must be at least 3 characters');
      }
      
      return await processQuery({ required_param, optional_param });
      
    } catch (error) {
      if (error instanceof ValidationError) {
        return {
          success: false,
          error: error.message,
          code: 'VALIDATION_ERROR'
        };
      }
      throw error;
    }
  });
```

### Missing Parameter Handling

```typescript
// The middleware automatically throws ValidationError for missing required parameters
// Handle this in your error middleware or catch it explicitly

const handleQueryErrors = new Handler()
  .use(new QueryParametersMiddleware(['page', 'limit']))
  .handle(async (context) => {
    // This will only execute if page and limit are present
    const { page, limit } = context.req.query;
    
    return await getPaginatedResults({
      page: parseInt(page as string),
      limit: parseInt(limit as string)
    });
  });

// If page or limit is missing, middleware throws:
// ValidationError: Missing required query parameter: page
```

## Performance Considerations

### Query Parameter Complexity

```typescript
// Good: Simple, focused parameter sets
const simpleHandler = new Handler()
  .use(new QueryParametersMiddleware(['id']))
  .handle(async (context) => {
    const { id } = context.req.query;
    return await getById(id as string);
  });

// Be careful with: Complex parameter parsing
const complexHandler = new Handler()
  .use(new QueryParametersMiddleware([]))
  .handle(async (context) => {
    const query = context.req.query;
    
    // Expensive operations on every request
    const filters = Object.keys(query)
      .filter(key => key.startsWith('filter_'))
      .reduce((acc, key) => {
        const filterName = key.replace('filter_', '');
        acc[filterName] = parseComplexFilter(query[key] as string);
        return acc;
      }, {} as Record<string, any>);
    
    return await searchWithComplexFilters(filters);
  });
```

### Caching Query Results

```typescript
import { LRUCache } from 'lru-cache';

const queryCache = new LRUCache<string, any>({
  max: 1000,
  ttl: 5 * 60 * 1000 // 5 minutes
});

const cachedQueryHandler = new Handler()
  .use(new QueryParametersMiddleware(['category']))
  .handle(async (context) => {
    const { category, sort, page = '1', limit = '10' } = context.req.query;
    
    // Create cache key from query parameters
    const cacheKey = `products:${category}:${sort}:${page}:${limit}`;
    
    // Check cache first
    let results = queryCache.get(cacheKey);
    if (!results) {
      results = await getProducts({ category, sort, page: parseInt(page as string), limit: parseInt(limit as string) });
      queryCache.set(cacheKey, results);
    }
    
    return { success: true, results, cached: !!queryCache.get(cacheKey) };
  });
```

## Best Practices

### 1. Parameter Naming Conventions

```typescript
// Good: Consistent, clear naming
interface StandardQuery {
  page: string;           // Pagination
  limit: string;          // Page size
  sort: string;           // Sort field
  order: 'asc' | 'desc';  // Sort direction
  search: string;         // Search term
  filter_category: string;// Namespaced filters
}

// Avoid: Inconsistent or unclear names
interface PoorQuery {
  p: string;              // What does 'p' mean?
  num: string;            // Number of what?
  s: string;              // Sort? Search? Status?
}
```

### 2. Required vs Optional Parameters

```typescript
// Good: Clear separation of concerns
const searchHandler = new Handler()
  .use(new QueryParametersMiddleware(['q'])) // Search term is always required
  .handle(async (context) => {
    const { q, category, sort = 'relevance' } = context.req.query;
    // Handle optional parameters with defaults
  });

// Consider: Business logic requirements
const analyticsHandler = new Handler()
  .use(new QueryParametersMiddleware(['start_date', 'end_date'])) // Date range always required for analytics
  .handle(async (context) => {
    // Date parameters are guaranteed to exist
  });
```

### 3. Type Safety and Validation

```typescript
// Good: Explicit type checking and validation
const typeSafeHandler = new Handler()
  .use(new QueryParametersMiddleware(['page']))
  .handle(async (context) => {
    const { page, limit } = context.req.query;
    
    // Validate types explicitly
    const pageNum = parseInt(page as string);
    const limitNum = limit ? parseInt(limit as string) : 10;
    
    if (isNaN(pageNum) || pageNum < 1) {
      throw new ValidationError('page must be a positive integer');
    }
    
    if (limitNum < 1 || limitNum > 100) {
      throw new ValidationError('limit must be between 1 and 100');
    }
    
    return await getData({ page: pageNum, limit: limitNum });
  });
```

### 4. Documentation and Examples

```typescript
/**
 * Product search endpoint
 * 
 * Query Parameters:
 * - q (required): Search term
 * - category (optional): Product category filter
 * - price_min (optional): Minimum price filter (decimal)
 * - price_max (optional): Maximum price filter (decimal)
 * - sort (optional): Sort order [price|rating|name] (default: name)
 * - page (optional): Page number (default: 1)
 * - limit (optional): Results per page (default: 10, max: 100)
 * 
 * Example: /api/products?q=laptop&category=electronics&price_min=100&price_max=1000&sort=price&page=1&limit=20
 */
const documentedSearchHandler = new Handler()
  .use(new QueryParametersMiddleware(['q']))
  .handle(async (context) => {
    // Implementation with clear parameter handling
  });
```

This middleware is essential for building flexible, queryable APIs and works seamlessly with other request processing middlewares to provide complete request parameter handling.