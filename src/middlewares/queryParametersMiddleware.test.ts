import {
  queryParametersMiddleware,
  QueryParametersMiddleware,
} from './queryParametersMiddleware';
import { Context, ValidationError } from '../core';

describe('QueryParametersMiddleware', () => {
  let context: Context;
  let middleware: QueryParametersMiddleware;

  beforeEach(() => {
    context = {
      req: {
        url: '/test?param1=value1',
        headers: {
          host: 'localhost',
        },
        query: {},
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('throws ValidationError if a required query parameter is missing', async () => {
    middleware = new QueryParametersMiddleware(['param2']);
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('does not throw an error if all required query parameters are present', async () => {
    middleware = new QueryParametersMiddleware(['param1']);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('does not throw an error if no required query parameters are specified', async () => {
    middleware = new QueryParametersMiddleware([]);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('throws ValidationError if multiple required query parameters are missing', async () => {
    middleware = new QueryParametersMiddleware(['param1', 'param2']);
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('does not throw an error if multiple required query parameters are present', async () => {
    context.req.url = '/test?param1=value1&param2=value2';
    middleware = new QueryParametersMiddleware(['param1', 'param2']);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('handles case-sensitive query parameter names', async () => {
    context.req.url = '/test?Param1=value1';
    middleware = new QueryParametersMiddleware(['param1']);
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });
});

describe('queryParametersMiddleware', () => {
  let context: Context;
  let middleware: ReturnType<typeof queryParametersMiddleware>;

  beforeEach(() => {
    context = {
      req: {
        url: '/test?param1=value1',
        headers: {
          host: 'localhost',
        },
        query: {},
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
    } as unknown as Context;
  });

  it('throws ValidationError if a required query parameter is missing', async () => {
    middleware = queryParametersMiddleware(['param2']);
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('does not throw an error if all required query parameters are present', async () => {
    middleware = queryParametersMiddleware(['param1']);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('does not throw an error if no required query parameters are specified', async () => {
    middleware = queryParametersMiddleware([]);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('throws ValidationError if multiple required query parameters are missing', async () => {
    middleware = queryParametersMiddleware(['param1', 'param2']);
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('does not throw an error if multiple required query parameters are present', async () => {
    context.req.url = '/test?param1=value1&param2=value2';
    middleware = queryParametersMiddleware(['param1', 'param2']);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('handles case-sensitive query parameter names', async () => {
    context.req.url = '/test?Param1=value1';
    middleware = queryParametersMiddleware(['param1']);
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });
});
