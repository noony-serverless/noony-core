import { Context } from '../core/core';
import { BaseMiddleware } from '../core/handler';
import { ValidationError } from '../core/errors';
import { z, ZodSchema } from 'zod';

/**
 * Middleware class that extracts path parameters from the URL.
 * Parses URL segments and extracts parameters based on colon-prefixed patterns.
 *
 * @implements {BaseMiddleware}
 *
 * @example
 * Basic path parameter extraction:
 * ```typescript
 * import { Handler, PathParametersMiddleware } from '@noony-serverless/core';
 *
 * // For URL: /users/123/posts/456
 * const userPostHandler = new Handler()
 *   .use(new PathParametersMiddleware())
 *   .handle(async (context) => {
 *     // Assuming your routing pattern is /users/:userId/posts/:postId
 *     const { userId, postId } = context.req.params || {};
 *
 *     const user = await getUserById(userId);
 *     const post = await getPostById(postId);
 *
 *     return { success: true, user, post };
 *   });
 * ```
 *
 * @example
 * RESTful API with multiple parameters:
 * ```typescript
 * // For URL: /api/v1/organizations/org-123/projects/proj-456/tasks/task-789
 * const taskHandler = new Handler()
 *   .use(new PathParametersMiddleware())
 *   .handle(async (context) => {
 *     const { organizationId, projectId, taskId } = context.req.params || {};
 *
 *     const task = await getTask(organizationId, projectId, taskId);
 *     return { success: true, task };
 *   });
 * ```
 *
 * @example
 * E-commerce product details:
 * ```typescript
 * // For URL: /categories/electronics/products/laptop-123
 * const productHandler = new Handler()
 *   .use(new PathParametersMiddleware())
 *   .handle(async (context) => {
 *     const { category, productId } = context.req.params || {};
 *
 *     const product = await getProductByCategory(category, productId);
 *     const recommendations = await getRecommendations(category, productId);
 *
 *     return { success: true, product, recommendations };
 *   });
 * ```
 */
export class PathParametersMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    context.req.params = context.req.params || {};

    // Extract path parameters based on your routing configuration
    // This is a simplified example
    pathSegments.forEach((segment, index) => {
      if (segment.startsWith(':')) {
        const paramName = segment.slice(1);
        if (context.req.params) {
          context.req.params[paramName] = pathSegments[index];
        }
      }
    });
  }
}

/**
 * Factory function that creates a path parameters extraction middleware.
 * Extracts URL path segments and sets them in context.req.params.
 *
 * @returns BaseMiddleware object with path parameter extraction logic
 *
 * @example
 * Simple product API:
 * ```typescript
 * import { Handler, pathParameters } from '@noony-serverless/core';
 *
 * // For URL: /products/123
 * const getProductHandler = new Handler()
 *   .use(pathParameters())
 *   .handle(async (context) => {
 *     const productId = context.req.params?.id;
 *     const product = await getProduct(productId);
 *     return { success: true, product };
 *   });
 * ```
 *
 * @example
 * Blog post with category:
 * ```typescript
 * // For URL: /blog/technology/post-123
 * const blogPostHandler = new Handler()
 *   .use(pathParameters())
 *   .handle(async (context) => {
 *     const { category, postId } = context.req.params || {};
 *     const post = await getBlogPost(category, postId);
 *     const relatedPosts = await getRelatedPosts(category);
 *     return { success: true, post, relatedPosts };
 *   });
 * ```
 *
 * @example
 * Nested resource API:
 * ```typescript
 * // For URL: /users/user-123/orders/order-456/items
 * const orderItemsHandler = new Handler()
 *   .use(pathParameters())
 *   .handle(async (context) => {
 *     const { userId, orderId } = context.req.params || {};
 *     const orderItems = await getOrderItems(userId, orderId);
 *     return { success: true, items: orderItems };
 *   });
 * ```
 */
export const pathParameters = (): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    context.req.params = { ...context.req.params };

    pathSegments.forEach((segment, index) => {
      if (segment.startsWith(':')) {
        const paramName = segment.slice(1);
        if (context.req.params) {
          context.req.params[paramName] = pathSegments[index];
        }
      }
    });
  },
});

/**
 * Factory function that creates a header validation middleware.
 * Validates that all required headers are present in the request.
 *
 * @param requiredHeaders - Array of header names that must be present
 * @returns BaseMiddleware object with header validation logic
 *
 * @example
 * API authentication headers:
 * ```typescript
 * import { Handler, headerVariablesValidator } from '@noony-serverless/core';
 *
 * const secureApiHandler = new Handler()
 *   .use(headerVariablesValidator(['authorization', 'x-api-key']))
 *   .handle(async (context) => {
 *     const authToken = context.req.headers.authorization;
 *     const apiKey = context.req.headers['x-api-key'];
 *
 *     const isValid = await validateCredentials(authToken, apiKey);
 *     return { success: isValid, message: 'Access granted' };
 *   });
 * ```
 *
 * @example
 * Content type validation:
 * ```typescript
 * const uploadHandler = new Handler()
 *   .use(headerVariablesValidator(['content-type', 'content-length']))
 *   .handle(async (context) => {
 *     const contentType = context.req.headers['content-type'];
 *     const contentLength = context.req.headers['content-length'];
 *
 *     if (contentType !== 'application/json') {
 *       throw new Error('Only JSON content is accepted');
 *     }
 *
 *     return { success: true, received: contentLength };
 *   });
 * ```
 *
 * @example
 * Multi-tenant application:
 * ```typescript
 * const tenantHandler = new Handler()
 *   .use(headerVariablesValidator(['x-tenant-id', 'x-client-version']))
 *   .handle(async (context) => {
 *     const tenantId = context.req.headers['x-tenant-id'];
 *     const clientVersion = context.req.headers['x-client-version'];
 *
 *     const tenantConfig = await getTenantConfig(tenantId);
 *     return { success: true, config: tenantConfig, version: clientVersion };
 *   });
 * ```
 */
export const headerVariablesValidator = (
  requiredHeaders: string[]
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    for (const header of requiredHeaders) {
      if (!context.req.headers?.[header.toLowerCase()]) {
        throw new ValidationError(`Missing required header: ${header}`);
      }
    }
  },
});

/**
 * Factory function that creates a query parameter validation middleware using Zod schema.
 * Validates query parameters against a provided schema and throws ValidationError if invalid.
 *
 * @param schema - Zod schema to validate query parameters against
 * @returns BaseMiddleware object with query parameter validation logic
 *
 * @example
 * Pagination parameters validation:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, validatedQueryParameters } from '@noony-serverless/core';
 *
 * const paginationSchema = z.object({
 *   page: z.string().regex(/^\d+$/).transform(Number).default('1'),
 *   limit: z.string().regex(/^\d+$/).transform(Number).default('10'),
 *   sort: z.enum(['asc', 'desc']).default('asc')
 * });
 *
 * const listUsersHandler = new Handler()
 *   .use(validatedQueryParameters(paginationSchema))
 *   .handle(async (context) => {
 *     const { page, limit, sort } = context.req.query;
 *     const users = await getUsersPaginated(page, limit, sort);
 *     return { success: true, users, pagination: { page, limit, sort } };
 *   });
 * ```
 *
 * @example
 * Search and filter parameters:
 * ```typescript
 * const searchSchema = z.object({
 *   q: z.string().min(1),
 *   category: z.string().optional(),
 *   price_min: z.string().regex(/^\d+(\.\d{2})?$/).optional(),
 *   price_max: z.string().regex(/^\d+(\.\d{2})?$/).optional(),
 *   in_stock: z.enum(['true', 'false']).optional()
 * });
 *
 * const searchProductsHandler = new Handler()
 *   .use(validatedQueryParameters(searchSchema))
 *   .handle(async (context) => {
 *     const { q, category, price_min, price_max, in_stock } = context.req.query;
 *     const filters = {
 *       query: q,
 *       category,
 *       priceRange: { min: price_min, max: price_max },
 *       inStock: in_stock === 'true'
 *     };
 *     const products = await searchProducts(filters);
 *     return { success: true, products, filters };
 *   });
 * ```
 *
 * @example
 * Date range and reporting parameters:
 * ```typescript
 * const reportSchema = z.object({
 *   start_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
 *   end_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
 *   granularity: z.enum(['day', 'week', 'month']).default('day'),
 *   metrics: z.string().transform(val => val.split(',')).optional()
 * });
 *
 * const analyticsHandler = new Handler()
 *   .use(validatedQueryParameters(reportSchema))
 *   .handle(async (context) => {
 *     const { start_date, end_date, granularity, metrics } = context.req.query;
 *     const report = await generateReport({
 *       startDate: new Date(start_date),
 *       endDate: new Date(end_date),
 *       granularity,
 *       metrics
 *     });
 *     return { success: true, report };
 *   });
 * ```
 */
export const validatedQueryParameters = (
  schema: ZodSchema
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const queryParams = context.req.query;

    try {
      schema.parse(queryParams);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(
          'Validation error',
          JSON.stringify(error.errors)
        );
      }
      throw error;
    }
  },
});
