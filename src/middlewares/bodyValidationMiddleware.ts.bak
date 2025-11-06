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
 * Simple user creation with type safety:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, BodyValidationMiddleware } from '@noony-serverless/core';
 *
 * const userSchema = z.object({
 *   name: z.string().min(1),
 *   email: z.string().email(),
 *   age: z.number().min(18)
 * });
 *
 * type UserRequest = z.infer<typeof userSchema>;
 *
 * async function handleCreateUser(context: Context<UserRequest, AuthenticatedUser>) {
 *   const user = context.req.validatedBody!; // Fully typed
 *   return { success: true, user: { id: '123', ...user } };
 * }
 *
 * const createUserHandler = new Handler<UserRequest, AuthenticatedUser>()
 *   .use(new BodyValidationMiddleware<UserRequest, AuthenticatedUser>(userSchema))
 *   .handle(handleCreateUser);
 * ```
 */
export class BodyValidationMiddleware<T = unknown, U = unknown>
  implements BaseMiddleware<T, U>
{
  constructor(private readonly schema: z.ZodSchema<T>) {}

  async before(context: Context<T, U>): Promise<void> {
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
 * Simple login validation:
 * ```typescript
 * import { z } from 'zod';
 * import { Handler, bodyValidatorMiddleware } from '@noony-serverless/core';
 *
 * const loginSchema = z.object({
 *   username: z.string().min(3),
 *   password: z.string().min(8)
 * });
 *
 * type LoginRequest = z.infer<typeof loginSchema>;
 *
 * async function handleLogin(context: Context<LoginRequest, AuthenticatedUser>) {
 *   const credentials = context.req.parsedBody as LoginRequest;
 *   const token = await authenticate(credentials.username, credentials.password);
 *   return { success: true, token };
 * }
 *
 * const loginHandler = new Handler<LoginRequest, AuthenticatedUser>()
 *   .use(bodyValidatorMiddleware<LoginRequest, AuthenticatedUser>(loginSchema))
 *   .handle(handleLogin);
 * ```
 */
// Modified to fix type instantiation error
export const bodyValidatorMiddleware = <T, U = unknown>(
  schema: z.ZodType<T>
): { before: (context: Context<T, U>) => Promise<void> } => ({
  before: async (context: Context<T, U>): Promise<void> => {
    context.req.parsedBody = await validateBody(schema, context.req.body);
  },
});
