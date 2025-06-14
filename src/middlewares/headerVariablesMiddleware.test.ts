import {
  headerVariablesMiddleware,
  HeaderVariablesMiddleware,
} from './headerVariablesMiddleware';
import { Context, ValidationError } from '../core';

describe('HeaderVariablesMiddleware', () => {
  let context: Context;
  let middleware: HeaderVariablesMiddleware;

  beforeEach(() => {
    context = {
      req: {
        method: 'GET',
        url: '/',
        headers: {},
        query: {},
        params: {},
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        send: jest.fn(),
        header: jest.fn().mockReturnThis(),
        headers: jest.fn().mockReturnThis(),
        end: jest.fn(),
        statusCode: 200,
        headersSent: false,
      },
      container: null,
      error: null,
      businessData: new Map(),
      startTime: Date.now(),
      requestId: 'test-req-id',
    } as unknown as Context;
  });

  it('throws ValidationError if a required header is missing', async () => {
    middleware = new HeaderVariablesMiddleware(['Authorization']);
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('does not throw an error if all required headers are present', async () => {
    context.req.headers['authorization'] = 'Bearer token';
    middleware = new HeaderVariablesMiddleware(['Authorization']);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('handles case-insensitive header names', async () => {
    context.req.headers['authorization'] = 'Bearer token';
    middleware = new HeaderVariablesMiddleware(['authorization']);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('does not throw an error if no required headers are specified', async () => {
    middleware = new HeaderVariablesMiddleware([]);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });

  it('throws ValidationError if multiple required headers are missing', async () => {
    middleware = new HeaderVariablesMiddleware([
      'Authorization',
      'Content-Type',
    ]);
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('does not throw an error if multiple required headers are present', async () => {
    context.req.headers['authorization'] = 'Bearer token';
    context.req.headers['content-type'] = 'application/json';
    middleware = new HeaderVariablesMiddleware([
      'Authorization',
      'Content-Type',
    ]);
    await expect(middleware.before(context)).resolves.not.toThrow();
  });
});

describe('headerVariablesMiddleware', () => {
  let context: Context;
  let middleware: ReturnType<typeof headerVariablesMiddleware>;

  beforeEach(() => {
    context = {
      req: {
        method: 'GET',
        url: '/',
        headers: {},
        query: {},
        params: {},
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        send: jest.fn(),
        header: jest.fn().mockReturnThis(),
        headers: jest.fn().mockReturnThis(),
        end: jest.fn(),
        statusCode: 200,
        headersSent: false,
      },
      container: null,
      error: null,
      businessData: new Map(),
      startTime: Date.now(),
      requestId: 'test-req-id',
    } as unknown as Context;
  });

  it('throws ValidationError if a required header is missing', async () => {
    middleware = headerVariablesMiddleware(['Authorization']);
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('does not throw an error if all required headers are present', async () => {
    context.req.headers['authorization'] = 'Bearer token';
    middleware = headerVariablesMiddleware(['Authorization']);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('handles case-insensitive header names', async () => {
    context.req.headers['authorization'] = 'Bearer token';
    middleware = headerVariablesMiddleware(['authorization']);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('does not throw an error if no required headers are specified', async () => {
    middleware = headerVariablesMiddleware([]);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });

  it('throws ValidationError if multiple required headers are missing', async () => {
    middleware = headerVariablesMiddleware(['Authorization', 'Content-Type']);
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('does not throw an error if multiple required headers are present', async () => {
    context.req.headers['authorization'] = 'Bearer token';
    context.req.headers['content-type'] = 'application/json';
    middleware = headerVariablesMiddleware(['Authorization', 'Content-Type']);
    if (middleware.before) {
      await expect(middleware.before(context)).resolves.not.toThrow();
    }
  });
});
