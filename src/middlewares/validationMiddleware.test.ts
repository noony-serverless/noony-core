import {
  validationMiddleware,
  ValidationMiddleware,
} from './validationMiddleware';
import { Context, ValidationError } from '../core';
import { z } from 'zod';

describe('ValidationMiddleware', () => {
  let context: Context;
  let middleware: ValidationMiddleware;

  beforeEach(() => {
    context = {
      req: { method: 'GET', query: {}, parsedBody: {} },
      res: {},
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('validates query parameters for GET request', async () => {
    const schema = z.object({ name: z.string() });
    middleware = new ValidationMiddleware(schema);
    context.req.query = { name: 'John' };

    await middleware.before(context);

    expect(context.req.query).toEqual({ name: 'John' });
  });

  it('validates body parameters for non-GET request', async () => {
    const schema = z.object({ age: z.number() });
    middleware = new ValidationMiddleware(schema);
    context.req.method = 'POST';
    context.req.parsedBody = { age: 30 };

    await middleware.before(context);

    expect(context.req.validatedBody).toEqual({ age: 30 });
  });

  it('throws ValidationError for invalid query parameters', async () => {
    const schema = z.object({ name: z.string() });
    middleware = new ValidationMiddleware(schema);
    context.req.query = { name: 123 as unknown as string }; // Ensure the value is invalid

    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });
  it('throws ValidationError for invalid body parameters', async () => {
    const schema = z.object({ age: z.number() });
    middleware = new ValidationMiddleware(schema);
    context.req.method = 'POST';
    context.req.parsedBody = { age: 'thirty' };

    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('handles empty query parameters gracefully', async () => {
    const schema = z.object({ name: z.string().optional() });
    middleware = new ValidationMiddleware(schema);
    context.req.query = {};

    await middleware.before(context);

    expect(context.req.query).toEqual({});
  });

  it('handles empty body parameters gracefully', async () => {
    const schema = z.object({ age: z.number().optional() });
    middleware = new ValidationMiddleware(schema);
    context.req.method = 'POST';
    context.req.parsedBody = {};

    await middleware.before(context);

    expect(context.req.validatedBody).toEqual({});
  });
});

describe('validationMiddleware', () => {
  let context: Context;
  let middleware: ReturnType<typeof validationMiddleware>;

  beforeEach(() => {
    context = {
      req: { method: 'GET', query: {}, parsedBody: {} },
      res: {},
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('validates query parameters for GET request', async () => {
    const schema = z.object({ name: z.string() });
    middleware = validationMiddleware(schema);
    context.req.query = { name: 'John' };

    if (middleware.before) {
      await middleware.before(context);
    }

    expect(context.req.query).toEqual({ name: 'John' });
  });

  it('validates body parameters for non-GET request', async () => {
    const schema = z.object({ age: z.number() });
    middleware = validationMiddleware(schema);
    context.req.method = 'POST';
    context.req.parsedBody = { age: 30 };

    if (middleware.before) {
      await middleware.before(context);
    }

    expect(context.req.validatedBody).toEqual({ age: 30 });
  });

  it('throws ValidationError for invalid query parameters', async () => {
    const schema = z.object({ name: z.string() });
    middleware = validationMiddleware(schema);
    context.req.query = { name: 123 as unknown as string };

    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('throws ValidationError for invalid body parameters', async () => {
    const schema = z.object({ age: z.number() });
    middleware = validationMiddleware(schema);
    context.req.method = 'POST';
    context.req.parsedBody = { age: 'thirty' };

    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('handles empty query parameters gracefully', async () => {
    const schema = z.object({ name: z.string().optional() });
    middleware = validationMiddleware(schema);
    context.req.query = {};

    if (middleware.before) {
      await middleware.before(context);
    }

    expect(context.req.query).toEqual({});
  });

  it('handles empty body parameters gracefully', async () => {
    const schema = z.object({ age: z.number().optional() });
    middleware = validationMiddleware(schema);
    context.req.method = 'POST';
    context.req.parsedBody = {};

    if (middleware.before) {
      await middleware.before(context);
    }

    expect(context.req.validatedBody).toEqual({});
  });
});
