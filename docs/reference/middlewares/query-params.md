# How to Extract and Validate Query Parameters

Parses the URL query string into `context.req.query` and optionally asserts that specified parameters are present.

## Prerequisites

- `QueryParametersMiddleware` (or `queryParametersMiddleware`) imported from `@/middlewares`

## Primary Workflow

**1. Decide which parameters are required vs optional.**

Pass required parameter names to the constructor. Omit a parameter from the array to make it optional.

**2. Add `QueryParametersMiddleware` to the handler chain.**

**3. Access parsed values from `context.req.query`.**

All values arrive as strings (or string arrays for repeated keys). Cast and coerce them explicitly.

```typescript
import { Handler } from '@/core/handler';
import { QueryParametersMiddleware } from '@/middlewares';

// category is required; sort, page, limit are optional
const productFilterHandler = new Handler()
  .use(new QueryParametersMiddleware(['category']))
  .handle(async (context) => {
    const { category, brand, sort, page = '1', limit = '20' } = context.req.query;

    const products = await searchProducts({
      category: category as string,
      brand: brand as string | undefined,
      sort: (sort as string) || 'name',
      page: parseInt(page as string),
      limit: Math.min(parseInt(limit as string), 100),
    });

    return { success: true, products };
  });
```

If a required parameter is missing, the middleware throws a `ValidationError` before the controller runs — no boilerplate needed inside the controller.

## If Using Zod for Validation

`QueryParametersMiddleware` validates presence; Zod validates format, type, and transforms. Combine them:

```typescript
import { z } from 'zod';
import { QueryParametersMiddleware } from '@/middlewares';

const searchSchema = z.object({
  q: z.string().min(1, 'Search query cannot be empty'),
  sort: z.enum(['price', 'rating', 'name']).default('name'),
  page: z.string().regex(/^\d+$/).transform(Number).default('1'),
  limit: z.string().regex(/^\d+$/).transform(Number).default('10'),
  price_min: z.string().regex(/^\d+(\.\d{2})?$/).optional(),
  price_max: z.string().regex(/^\d+(\.\d{2})?$/).optional(),
});

type SearchQuery = z.infer<typeof searchSchema>;

const searchHandler = new Handler<SearchQuery>()
  .use(new QueryParametersMiddleware(['q'])) // presence check
  .handle(async (context) => {
    // Format / type validation with transforms
    const query = searchSchema.parse(context.req.query);

    const results = await searchProducts({
      query: query.q,
      sort: query.sort,
      page: query.page,
      limit: Math.min(query.limit, 100),
      priceMin: query.price_min ? parseFloat(query.price_min) : undefined,
      priceMax: query.price_max ? parseFloat(query.price_max) : undefined,
    });

    return { success: true, results, appliedFilters: query };
  });
```

## If Parameters Are Optional

Pass an empty array (or omit the argument) to skip required-param enforcement. All parameters become optional.

```typescript
// All params optional — useful for open-ended search or listing endpoints
const listHandler = new Handler()
  .use(new QueryParametersMiddleware()) // no required params
  .handle(async (context) => {
    const { q, category, sort } = context.req.query || {};

    const results = await searchProducts({
      query: q as string | undefined,
      category: category as string | undefined,
      sortBy: (sort as string) || 'relevance',
    });

    return { success: true, results };
  });
```

## If You Need Analytics / Date Ranges

```typescript
const analyticsHandler = new Handler()
  .use(new QueryParametersMiddleware(['start_date', 'end_date']))
  .handle(async (context) => {
    const { start_date, end_date, granularity, format } = context.req.query;

    const startDate = new Date(start_date as string);
    const endDate = new Date(end_date as string);

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format. Use YYYY-MM-DD');
    }

    if (startDate >= endDate) {
      throw new ValidationError('start_date must be before end_date');
    }

    const report = await generateReport({
      dateRange: { start: startDate, end: endDate },
      granularity: (granularity as string) || 'day',
      format: (format as string) || 'json',
    });

    return { success: true, report };
  });
```

## Functional Alias

```typescript
import { queryParametersMiddleware } from '@/middlewares';

new Handler()
  .use(queryParametersMiddleware(['q']))
  .handle(/* ... */);
```

## Anti-Patterns

**Don't trust raw query params without coercion.** All values from `context.req.query` are strings. `parseInt(undefined)` returns `NaN` and `parseFloat('abc')` returns `NaN` — always validate or use Zod transforms before using numeric values.

**Don't mix presence checks in the middleware with format validation in the schema** inconsistently. A clear pattern: middleware for "is it there?", Zod for "is it valid?".

**Don't validate query params before confirming required headers are present.** Headers are cheaper to check and must come first (see [canonical ordering](../../guides/middleware-ordering.md)).

## Related

- [How to Compose Middleware Pipelines](../../guides/middleware-ordering.md) — combining with headers and path params
- [How to Validate Required HTTP Headers](./headers.md)
