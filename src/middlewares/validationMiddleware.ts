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

export class ValidationMiddleware implements BaseMiddleware {
  constructor(private readonly schema: z.ZodSchema) {}

  async before(context: Context): Promise<void> {
    await validate(this.schema, context);
  }
}

export const validationMiddleware = (schema: z.ZodSchema): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    await validate(schema, context);
  },
});
