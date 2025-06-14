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

export class BodyValidationMiddleware<T = unknown> implements BaseMiddleware {
  constructor(private readonly schema: z.ZodSchema<T>) {}

  async before(context: Context): Promise<void> {
    context.req.validatedBody = await validateBody(
      this.schema,
      context.req.parsedBody
    );
  }
}

// Modified to fix type instantiation error
export const bodyValidatorMiddleware = <T>(
  schema: z.ZodType<T>
): { before: (context: Context) => Promise<void> } => ({
  before: async (context: Context): Promise<void> => {
    context.req.parsedBody = await validateBody(schema, context.req.body);
  },
});
