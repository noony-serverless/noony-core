import { BaseMiddleware, Context, ValidationError } from '../core';
import { ParsedQs } from 'qs';

const validateQueryParameters = (
  requiredParams: string[],
  query: Record<string, string | string[]>
): void => {
  for (const param of requiredParams) {
    if (!query[param]) {
      throw new ValidationError(`Missing required query parameter: ${param}`);
    }
  }
};

const convertQueryToRecord = (
  query: ParsedQs
): Record<string, string | string[]> => {
  const result: Record<string, string | string[]> = {};
  for (const key in query) {
    if (query[key] !== undefined) {
      result[key] = Array.isArray(query[key])
        ? query[key].map(String)
        : String(query[key]);
    }
  }
  return result;
};

/**
 * Middleware class that validates and processes query parameters from the request URL.
 * Extracts query parameters and validates that required parameters are present.
 *
 * @implements {BaseMiddleware}
 *
 * @example
 * Basic query parameter validation:
 * ```typescript
 * import { Handler, QueryParametersMiddleware } from '@noony-serverless/core';
 *
 * const searchHandler = new Handler()
 *   .use(new QueryParametersMiddleware(['q', 'type']))
 *   .handle(async (context) => {
 *     const { q, type } = context.req.query;
 *     const results = await search(q, type);
 *     return { success: true, results, query: q, type };
 *   });
 * ```
 *
 * @example
 * Pagination with required parameters:
 * ```typescript
 * const listHandler = new Handler()
 *   .use(new QueryParametersMiddleware(['page', 'limit']))
 *   .handle(async (context) => {
 *     const { page, limit, sort } = context.req.query;
 *     const items = await getItems(parseInt(page), parseInt(limit), sort);
 *     return { success: true, items, pagination: { page, limit } };
 *   });
 * ```
 *
 * @example
 * Optional parameters (empty required array):
 * ```typescript
 * const flexibleHandler = new Handler()
 *   .use(new QueryParametersMiddleware([])) // No required parameters
 *   .handle(async (context) => {
 *     const { filter, sort, category } = context.req.query || {};
 *     const data = await getData({ filter, sort, category });
 *     return { success: true, data };
 *   });
 * ```
 */
export class QueryParametersMiddleware implements BaseMiddleware {
  constructor(private readonly requiredParams: string[] = []) {}

  async before(context: Context): Promise<void> {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    context.req.query = Object.fromEntries(url.searchParams);
    const query = convertQueryToRecord(context.req.query);
    validateQueryParameters(this.requiredParams, query);
  }
}

/**
 * Factory function that creates a query parameter processing middleware.
 * Extracts and validates query parameters from the request URL.
 *
 * @param requiredParams - Array of parameter names that must be present (default: empty array)
 * @returns BaseMiddleware object with query parameter processing logic
 *
 * @example
 * API endpoint with required search parameters:
 * ```typescript
 * import { Handler, queryParametersMiddleware } from '@noony-serverless/core';
 *
 * const searchApiHandler = new Handler()
 *   .use(queryParametersMiddleware(['q'])) // 'q' parameter is required
 *   .handle(async (context) => {
 *     const { q, category, sort } = context.req.query;
 *     const searchResults = await performSearch(q, { category, sort });
 *     return { success: true, results: searchResults };
 *   });
 * ```
 *
 * @example
 * E-commerce product listing with filters:
 * ```typescript
 * const productListHandler = new Handler()
 *   .use(queryParametersMiddleware(['category'])) // Category is required
 *   .handle(async (context) => {
 *     const { category, price_min, price_max, brand, sort } = context.req.query;
 *     const products = await getProducts({
 *       category,
 *       priceRange: { min: price_min, max: price_max },
 *       brand,
 *       sortBy: sort || 'name'
 *     });
 *     return { success: true, products, filters: { category, brand, sort } };
 *   });
 * ```
 *
 * @example
 * Flexible API with optional parameters:
 * ```typescript
 * const dataHandler = new Handler()
 *   .use(queryParametersMiddleware()) // No required parameters
 *   .handle(async (context) => {
 *     const queryParams = context.req.query || {};
 *     const {
 *       page = '1',
 *       limit = '10',
 *       sort = 'created_at',
 *       order = 'desc'
 *     } = queryParams;
 *
 *     const data = await fetchData({
 *       pagination: { page: parseInt(page), limit: parseInt(limit) },
 *       sorting: { field: sort, order }
 *     });
 *
 *     return { success: true, data, meta: { page, limit, sort, order } };
 *   });
 * ```
 */
export const queryParametersMiddleware = (
  requiredParams: string[] = []
): BaseMiddleware => ({
  async before(context: Context): Promise<void> {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    context.req.query = Object.fromEntries(url.searchParams);
    const query = convertQueryToRecord(context.req.query);
    validateQueryParameters(requiredParams, query);
  },
});
