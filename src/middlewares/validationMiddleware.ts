import { ValidationError, BaseMiddleware, Context } from '../core';
import { z } from 'zod';

const validate = async (
  schema: z.ZodSchema,
  context: Context
): Promise<void> => {
  try {
    const data =
      context.req.method === 'GET' ? context.req.query : context.req.parsedBody;
    const validated = await schema.parseAsync(data);

    if (context.req.method === 'GET') {
      context.req.query = validated;
    } else {
      context.req.validatedBody = validated;
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new ValidationError(
        'Validation error',
        JSON.stringify(error.errors)
      );
    }
    throw error;
  }
};

/**
 * Middleware class that validates request data (body or query parameters) using Zod schemas.
 * Automatically detects GET requests and validates query parameters, or validates body for other methods.
 *
 * @implements {BaseMiddleware}
 *
 * @example
 * User registration validation:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, ValidationMiddleware } from '@noony-serverless/core';
 *
 * const userRegistrationSchema = z.object({
 *   email: z.string().email(),
 *   password: z.string().min(8),
 *   firstName: z.string().min(1),
 *   lastName: z.string().min(1),
 *   age: z.number().int().min(18).max(120)
 * });
 *
 * const registerHandler = new Handler()
 *   .use(bodyParser())
 *   .use(new ValidationMiddleware(userRegistrationSchema))
 *   .handle(async (context) => {
 *     const validatedUser = context.req.validatedBody;
 *     const newUser = await createUser(validatedUser);
 *     return { success: true, userId: newUser.id };
 *   });
 * ```
 *
 * @example
 * GET request query parameter validation:
 * ```typescript
 * const searchSchema = z.object({
 *   q: z.string().min(1),
 *   page: z.string().regex(/^\d+$/).transform(Number).default('1'),
 *   limit: z.string().regex(/^\d+$/).transform(Number).default('10'),
 *   category: z.string().optional()
 * });
 *
 * const searchHandler = new Handler()
 *   .use(new ValidationMiddleware(searchSchema))
 *   .handle(async (context) => {
 *     const { q, page, limit, category } = context.req.query;
 *     const results = await searchItems(q, { page, limit, category });
 *     return { success: true, results, query: { q, page, limit, category } };
 *   });
 * ```
 *
 * @example
 * Product creation with nested validation:
 * ```typescript
 * const productSchema = z.object({
 *   name: z.string().min(1).max(100),
 *   description: z.string().max(1000),
 *   price: z.number().positive(),
 *   category: z.enum(['electronics', 'clothing', 'books', 'home']),
 *   specifications: z.record(z.string()),
 *   images: z.array(z.string().url()).max(5),
 *   inventory: z.object({
 *     inStock: z.boolean(),
 *     quantity: z.number().int().min(0),
 *     warehouse: z.string()
 *   })
 * });
 *
 * const createProductHandler = new Handler()
 *   .use(bodyParser())
 *   .use(new ValidationMiddleware(productSchema))
 *   .handle(async (context) => {
 *     const productData = context.req.validatedBody;
 *     const product = await createProduct(productData);
 *     return { success: true, productId: product.id };
 *   });
 * ```
 */
export class ValidationMiddleware implements BaseMiddleware {
  constructor(private readonly schema: z.ZodSchema) {}

  async before(context: Context): Promise<void> {
    await validate(this.schema, context);
  }
}

/**
 * Factory function that creates a validation middleware using Zod schema.
 * Automatically validates request body for non-GET requests or query parameters for GET requests.
 *
 * @param schema - Zod schema to validate against
 * @returns BaseMiddleware object with validation logic
 *
 * @example
 * Login endpoint validation:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, validationMiddleware } from '@noony-serverless/core';
 *
 * const loginSchema = z.object({
 *   email: z.string().email(),
 *   password: z.string().min(1),
 *   rememberMe: z.boolean().optional()
 * });
 *
 * const loginHandler = new Handler()
 *   .use(bodyParser())
 *   .use(validationMiddleware(loginSchema))
 *   .handle(async (context) => {
 *     const { email, password, rememberMe } = context.req.validatedBody;
 *     const token = await authenticate(email, password);
 *     return { success: true, token, rememberMe };
 *   });
 * ```
 *
 * @example
 * API filtering with query validation:
 * ```typescript
 * const filterSchema = z.object({
 *   status: z.enum(['active', 'inactive', 'pending']).optional(),
 *   sort: z.enum(['name', 'date', 'status']).default('name'),
 *   order: z.enum(['asc', 'desc']).default('asc'),
 *   limit: z.coerce.number().int().min(1).max(100).default(10)
 * });
 *
 * const getItemsHandler = new Handler()
 *   .use(validationMiddleware(filterSchema))
 *   .handle(async (context) => {
 *     const filters = context.req.query;
 *     const items = await getFilteredItems(filters);
 *     return { success: true, items, appliedFilters: filters };
 *   });
 * ```
 *
 * @example
 * File upload validation:
 * ```typescript
 * const uploadSchema = z.object({
 *   filename: z.string().min(1),
 *   mimeType: z.string().regex(/^(image|document)\//),
 *   size: z.number().max(10 * 1024 * 1024), // 10MB max
 *   description: z.string().max(200).optional(),
 *   tags: z.array(z.string()).max(10).optional()
 * });
 *
 * const uploadHandler = new Handler()
 *   .use(bodyParser())
 *   .use(validationMiddleware(uploadSchema))
 *   .handle(async (context) => {
 *     const fileData = context.req.validatedBody;
 *     const upload = await processFileUpload(fileData);
 *     return { success: true, fileId: upload.id };
 *   });
 * ```
 */
export const validationMiddleware = (schema: z.ZodSchema): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    await validate(schema, context);
  },
});
