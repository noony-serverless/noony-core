import { Context } from '../core/core';
import { BaseMiddleware } from '../core/handler';
import { ValidationError } from '../core/errors';
import { z, ZodSchema } from 'zod';

export class PathParametersMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    context.req.params = context.req.params || {};

    // Extract path parameters based on your routing configuration
    // This is a simplified example
    pathSegments.forEach((segment, index) => {
      if (segment.startsWith(':')) {
        const paramName = segment.slice(1);
        if (context.req.params) {
          context.req.params[paramName] = pathSegments[index];
        }
      }
    });
  }
}

export const pathParameters = (): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const host =
      (Array.isArray(context.req.headers.host)
        ? context.req.headers.host[0]
        : context.req.headers.host) || 'localhost';
    const url = new URL(context.req.url, `http://${host}`);
    const pathSegments = url.pathname.split('/').filter(Boolean);

    context.req.params = { ...context.req.params };

    pathSegments.forEach((segment, index) => {
      if (segment.startsWith(':')) {
        const paramName = segment.slice(1);
        if (context.req.params) {
          context.req.params[paramName] = pathSegments[index];
        }
      }
    });
  },
});

export const headerVariablesValidator = (
  requiredHeaders: string[]
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    for (const header of requiredHeaders) {
      if (!context.req.headers?.[header.toLowerCase()]) {
        throw new ValidationError(`Missing required header: ${header}`);
      }
    }
  },
});

export const validatedQueryParameters = (
  schema: ZodSchema
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const queryParams = context.req.query;

    try {
      schema.parse(queryParams);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError(
          'Validation error',
          JSON.stringify(error.errors)
        );
      }
      throw error;
    }
  },
});
