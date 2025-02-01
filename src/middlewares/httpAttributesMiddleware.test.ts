import {
  PathParametersMiddleware,
  pathParameters,
  headerVariablesValidator,
  validatedQueryParameters,
} from './httpAttributesMiddleware';
import { Context, ValidationError } from '../core';
import { z } from 'zod';

describe('PathParametersMiddleware', () => {
  let context: Context;
  let middleware: PathParametersMiddleware;

  beforeEach(() => {
    context = {
      req: { url: '', headers: { host: 'localhost' }, params: {} },
      res: {},
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
    middleware = new PathParametersMiddleware();
  });

  it('extracts path parameters correctly', async () => {
    context.req.url = '/users/:userId/orders/:orderId';
    await middleware.before(context);
    expect(context.req.params).toEqual({
      userId: ':userId',
      orderId: ':orderId',
    });
  });

  it('handles URLs without parameters gracefully', async () => {
    context.req.url = '/users/orders';
    await middleware.before(context);
    expect(context.req.params).toEqual({});
  });

  it('handles empty URL gracefully', async () => {
    context.req.url = '';
    await middleware.before(context);
    expect(context.req.params).toEqual({});
  });

  it('handles URL with only one parameter', async () => {
    context.req.url = '/users/:userId';
    await middleware.before(context);
    expect(context.req.params).toEqual({ userId: ':userId' });
  });

  it('does not overwrite existing params', async () => {
    context.req.url = '/users/:userId';
    context.req.params = { existingParam: 'value' };
    await middleware.before(context);
    expect(context.req.params).toEqual({
      existingParam: 'value',
      userId: ':userId',
    });
  });
});

describe('pathParameters', () => {
  let context: Context;
  let middleware: ReturnType<typeof pathParameters>;

  beforeEach(() => {
    context = {
      req: { url: '', headers: { host: 'localhost' }, params: {} },
      res: {},
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('extracts path parameters correctly', async () => {
    context.req.url = '/users/:userId/orders/:orderId';
    middleware = pathParameters();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.params).toEqual({
      userId: ':userId',
      orderId: ':orderId',
    });
  });

  it('handles URLs without parameters gracefully', async () => {
    context.req.url = '/users/orders';
    middleware = pathParameters();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.params).toEqual({});
  });

  it('handles empty URL gracefully', async () => {
    context.req.url = '';
    middleware = pathParameters();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.params).toEqual({});
  });

  it('handles URL with only one parameter', async () => {
    context.req.url = '/users/:userId';
    middleware = pathParameters();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.params).toEqual({ userId: ':userId' });
  });

  it('does not overwrite existing params', async () => {
    context.req.url = '/users/:userId';
    context.req.params = { existingParam: 'value' };
    middleware = pathParameters();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.params).toEqual({
      existingParam: 'value',
      userId: ':userId',
    });
  });
});

describe('headerVariablesValidator', () => {
  let context: Context;
  let middleware: ReturnType<typeof headerVariablesValidator>;

  beforeEach(() => {
    context = {
      req: { headers: {} },
      res: {},
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('validates presence of required headers', async () => {
    context.req.headers = { 'x-required-header': 'value' };
    middleware = headerVariablesValidator(['x-required-header']);
    if (middleware.before) {
      await middleware.before(context);
    }
  });

  it('throws ValidationError if required header is missing', async () => {
    context.req.headers = {};
    middleware = headerVariablesValidator(['x-required-header']);
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });
});

describe('validatedQueryParameters', () => {
  let context: Context;
  let middleware: ReturnType<typeof validatedQueryParameters>;

  beforeEach(() => {
    context = {
      req: { query: {} },
      res: {},
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('validates query parameters correctly', async () => {
    const schema = z.object({ name: z.string() });
    middleware = validatedQueryParameters(schema);
    context.req.query = { name: 'John' };
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.query).toEqual({ name: 'John' });
  });

  it('throws ValidationError for invalid query parameters', async () => {
    const schema = z.object({ name: z.string() });
    middleware = validatedQueryParameters(schema);
    context.req.query = { name: 123 as unknown as string };
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });
});
