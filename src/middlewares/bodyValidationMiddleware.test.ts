import {
  BodyValidationMiddleware,
  bodyValidatorMiddleware,
} from './bodyValidationMiddleware';
import { Context } from '../core/core';
import { z } from 'zod';
import { ValidationError } from '../core/errors';

describe('BodyValidationMiddleware', () => {
  let middleware: BodyValidationMiddleware;
  let context: Context;

  beforeEach(() => {
    context = {
      req: {
        parsedBody: {},
      },
      res: {},
    } as Context;
  });

  it('validates and sets validatedBody on context for valid input', async () => {
    const schema = z.object({ name: z.string() });
    middleware = new BodyValidationMiddleware(schema);
    context.req.parsedBody = { name: 'John Doe' };

    await middleware.before(context);

    expect(context.req.validatedBody).toEqual({ name: 'John Doe' });
  });

  it('throws ValidationError for invalid input', async () => {
    const schema = z.object({ name: z.string() });
    middleware = new BodyValidationMiddleware(schema);
    context.req.parsedBody = { name: 123 };

    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('throws original error if not a ZodError', async () => {
    const schema = z.object({ name: z.string() });
    middleware = new BodyValidationMiddleware(schema);
    context.req.parsedBody = null;

    await expect(middleware.before(context)).rejects.toThrow();
  });
});

describe('bodyValidator', () => {
  let context: Context;

  beforeEach(() => {
    context = {
      req: {
        body: {},
      },
      res: {},
    } as Context;
  });

  it('validates and sets validatedBody on context for valid input', async () => {
    const schema = z.object({ name: z.string() });
    const middleware = bodyValidatorMiddleware(schema);
    context.req.body = { name: 'John Doe' };

    if (middleware.before) {
      await middleware.before(context);
    }

    expect(context.req.body).toEqual({ name: 'John Doe' });
    expect(context.req.parsedBody).toEqual({ name: 'John Doe' });
  });

  it('throws ValidationError for invalid input', async () => {
    const schema = z.object({ name: z.string() });
    const middleware = bodyValidatorMiddleware(schema);
    context.req.body = { name: 123 };

    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('throws original error if not a ZodError', async () => {
    const schema = z.object({ name: z.string() });
    const middleware = bodyValidatorMiddleware(schema);
    context.req.body = null;

    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow();
    }
  });
});
