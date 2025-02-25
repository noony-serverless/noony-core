import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { z } from 'zod';
import { ValidationError } from '../core/errors';

export const validateBody = async <T = unknown>(
  schema: z.ZodSchema<T>,
  data: unknown
): Promise<T> => {
  try {
    return (await schema.parseAsync(data)) as T;
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

export class BodyValidationMiddleware<T = unknown> implements BaseMiddleware {
  constructor(private readonly schema: z.ZodSchema<T>) {}

  async before(context: Context): Promise<void> {
    context.req.validatedBody = await validateBody(
      this.schema,
      context.req.parsedBody
    );
  }
}

export const bodyValidator = <T = unknown>(
  schema: z.ZodSchema<T>
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    context.req.parsedBody = await validateBody(schema, context.req.body);
  },
});
