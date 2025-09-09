import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { z } from 'zod';
import { ValidationError } from '../core/errors';

const validateBody = async <T>(
  schema: z.ZodType<T>,
  data: unknown
): Promise<T> => {
  try {
    return await schema.parseAsync(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new ValidationError('Validation error', error.errors);
    }
    throw error;
  }
};

/**
 * Body validation middleware using Zod schemas for runtime type checking.
 * Validates the parsed request body against a provided Zod schema and sets
 * the validated result in context.req.validatedBody.
 *
 * @template T - The expected type of the validated body data
 * @implements {BaseMiddleware}
 *
 * @example
 * Basic user registration validation:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, BodyValidationMiddleware, bodyParser } from '@noony-serverless/core';
 *
 * const userSchema = z.object({
 *   name: z.string().min(1).max(100),
 *   email: z.string().email(),
 *   age: z.number().int().min(18).max(120),
 *   preferences: z.object({
 *     newsletter: z.boolean(),
 *     theme: z.enum(['light', 'dark'])
 *   }).optional()
 * });
 *
 * type UserData = z.infer<typeof userSchema>;
 *
 * const registerHandler = new Handler()
 *   .use(bodyParser<UserData>())
 *   .use(new BodyValidationMiddleware(userSchema))
 *   .handle(async (context) => {
 *     const validatedUser = context.req.validatedBody as UserData;
 *     console.log('Valid user:', validatedUser.name, validatedUser.email);
 *     return { success: true, userId: 'user-123' };
 *   });
 * ```
 *
 * @example
 * Product creation with nested validation:
 * ```typescript
 * const productSchema = z.object({
 *   name: z.string().min(1),
 *   price: z.number().positive(),
 *   category: z.enum(['electronics', 'clothing', 'books']),
 *   specifications: z.record(z.string()),
 *   tags: z.array(z.string()).max(10),
 *   availability: z.object({
 *     inStock: z.boolean(),
 *     quantity: z.number().int().min(0),
 *     restockDate: z.string().datetime().optional()
 *   })
 * });
 *
 * const createProductHandler = new Handler()
 *   .use(bodyParser())
 *   .use(new BodyValidationMiddleware(productSchema))
 *   .handle(async (context) => {
 *     const product = context.req.validatedBody;
 *     const savedProduct = await saveProduct(product);
 *     return { success: true, productId: savedProduct.id };
 *   });
 * ```
 *
 * @example
 * API endpoint with conditional validation:
 * ```typescript
 * const updateUserSchema = z.object({
 *   name: z.string().min(1).optional(),
 *   email: z.string().email().optional(),
 *   settings: z.object({
 *     notifications: z.boolean(),
 *     privacy: z.enum(['public', 'private'])
 *   }).optional()
 * }).refine(data =>
 *   Object.keys(data).length > 0,
 *   { message: "At least one field must be provided" }
 * );
 *
 * const updateUserHandler = new Handler()
 *   .use(bodyParser())
 *   .use(new BodyValidationMiddleware(updateUserSchema))
 *   .handle(async (context) => {
 *     const updates = context.req.validatedBody;
 *     const updatedUser = await updateUser(context.params.id, updates);
 *     return { success: true, user: updatedUser };
 *   });
 * ```
 */
export class BodyValidationMiddleware<T = unknown> implements BaseMiddleware {
  constructor(private readonly schema: z.ZodSchema<T>) {}

  async before(context: Context): Promise<void> {
    context.req.validatedBody = await validateBody(
      this.schema,
      context.req.parsedBody
    );
  }
}

/**
 * Factory function that creates a body validation middleware with Zod schema validation.
 * This function validates and parses the request body, setting the result in context.req.parsedBody.
 *
 * @template T - The expected type of the validated body data
 * @param schema - Zod schema to validate against
 * @returns A BaseMiddleware object with validation logic
 *
 * @example
 * Simple validation with factory function:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, bodyValidatorMiddleware } from '@noony-serverless/core';
 *
 * const loginSchema = z.object({
 *   username: z.string().min(3),
 *   password: z.string().min(8),
 *   rememberMe: z.boolean().optional()
 * });
 *
 * const loginHandler = new Handler()
 *   .use(bodyValidatorMiddleware(loginSchema))
 *   .handle(async (context) => {
 *     const credentials = context.req.parsedBody;
 *     const token = await authenticate(credentials.username, credentials.password);
 *     return { success: true, token };
 *   });
 * ```
 *
 * @example
 * Chaining multiple validation middlewares:
 * ```typescript
 * const baseSchema = z.object({
 *   action: z.enum(['create', 'update', 'delete']),
 *   timestamp: z.string().datetime()
 * });
 *
 * const createSchema = baseSchema.extend({
 *   data: z.object({
 *     name: z.string(),
 *     description: z.string()
 *   })
 * });
 *
 * const actionHandler = new Handler()
 *   .use(bodyValidatorMiddleware(baseSchema))
 *   .use(async (context, next) => {
 *     if (context.req.parsedBody.action === 'create') {
 *       // Additional validation for create action
 *       await createSchema.parseAsync(context.req.body);
 *     }
 *     return next();
 *   })
 *   .handle(async (context) => {
 *     const validatedAction = context.req.parsedBody;
 *     return { success: true, action: validatedAction.action };
 *   });
 * ```
 *
 * @example
 * Dynamic schema validation:
 * ```typescript
 * const getDynamicSchema = (userRole: string) => {
 *   const baseSchema = z.object({
 *     title: z.string(),
 *     content: z.string()
 *   });
 *
 *   if (userRole === 'admin') {
 *     return baseSchema.extend({
 *       featured: z.boolean(),
 *       priority: z.number().min(1).max(10)
 *     });
 *   }
 *
 *   return baseSchema;
 * };
 *
 * const createPostHandler = new Handler()
 *   .use(async (context, next) => {
 *     const userRole = context.user?.role || 'user';
 *     const schema = getDynamicSchema(userRole);
 *     return bodyValidatorMiddleware(schema).before(context);
 *   })
 *   .handle(async (context) => {
 *     const post = context.req.parsedBody;
 *     return { success: true, postId: await createPost(post) };
 *   });
 * ```
 */
// Modified to fix type instantiation error
export const bodyValidatorMiddleware = <T>(
  schema: z.ZodType<T>
): { before: (context: Context) => Promise<void> } => ({
  before: async (context: Context): Promise<void> => {
    context.req.parsedBody = await validateBody(schema, context.req.body);
  },
});
