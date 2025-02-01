import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';
import { z } from 'zod';
import { ValidationError } from '../core/errors';

export class ValidationMiddleware implements BaseMiddleware {
  constructor(private readonly schema: z.ZodSchema) {}

  async before(context: Context): Promise<void> {
    try {
      const data =
        context.req.method === 'GET'
          ? context.req.query
          : context.req.parsedBody;
      const validated = await this.schema.parseAsync(data);

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
  }
}
