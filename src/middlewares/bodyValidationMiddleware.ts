import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { z } from 'zod';
import { ValidationError } from '../core/errors';
import { requestBodyMap } from '../utils/fastify-wrapper';

// Reusable error objects for common cases (avoid allocations)
const VALIDATION_ERROR_INVALID_JSON = new ValidationError(
  'Invalid JSON in request body',
  [
    {
      code: 'custom',
      path: [],
      message: 'Request body must be valid JSON',
    },
  ]
);

const VALIDATION_ERROR_MISSING_BODY = new ValidationError(
  'Request body is required',
  [
    {
      code: 'custom',
      path: [],
      message: 'Request body is missing or empty',
    },
  ]
);

// Use synchronous parse for better performance (Zod's parseAsync adds overhead)
const validateWithZod = <T>(schema: z.ZodType<T>, data: unknown): T => {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new ValidationError('Validation error', error.issues);
    }
    throw error;
  }
};

/**
 * Comprehensive body validation function that handles retrieval from multiple sources,
 * JSON parsing, and Zod schema validation.
 * @internal
 */
const validateBody = <T, U = unknown>(
  schema: z.ZodType<T>,
  context: Context<T, U>
): T => {
  // Try to get body from the original Fastify request via WeakMap
  // This fixes the issue where req.body becomes undefined after Handler.executeGeneric copies properties
  const originalReq = requestBodyMap.get(context.req) as any;

  // Fast path: check most common case first (originalReq.body)
  let bodyData = originalReq?.body;
  if (!bodyData) {
    bodyData =
      context.req.validatedBody ?? context.req.parsedBody ?? context.req.body;
  }

  // If no parsed body found, try the raw body string (from Cloud Functions wrapper) and parse it
  if (!bodyData && originalReq?.__rawBody) {
    try {
      bodyData = JSON.parse(originalReq.__rawBody);
    } catch {
      throw VALIDATION_ERROR_INVALID_JSON;
    }
  }

  if (!bodyData) {
    throw VALIDATION_ERROR_MISSING_BODY;
  }

  // Validate with Zod schema
  return validateWithZod(schema, bodyData);
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
export class BodyValidationMiddleware<
  T = unknown,
  U = unknown,
> implements BaseMiddleware<T, U> {
  constructor(private readonly schema: z.ZodSchema<T>) {}

  async before(context: Context<T, U>): Promise<void> {
    context.req.validatedBody = validateBody(this.schema, context);
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
export const bodyValidatorMiddleware = <T, U = unknown>(
  schema: z.ZodType<T>
): { before: (context: Context<T, U>) => Promise<void> } => {
  return {
    before: async (context: Context<T, U>): Promise<void> => {
      context.req.validatedBody = validateBody(schema, context);
    },
  };
};
