import { bodyParser, BodyParserMiddleware } from './bodyParserMiddleware';
import { Context, ValidationError } from '../core';

describe('BodyParserMiddleware', () => {
  let context: Context;

  beforeEach(() => {
    context = {
      req: {
        body: null,
        method: 'POST',
        parsedBody: undefined, // Ensure parsedBody is initialized to undefined
      },
      res: {},
    } as Context;
  });

  it('parses JSON body correctly', async () => {
    context.req.body = '{"key": "value"}';
    const middleware = new BodyParserMiddleware();
    await middleware.before(context);
    expect(context.req.parsedBody).toEqual({ key: 'value' });
  });

  it('throws ValidationError for invalid JSON body', async () => {
    context.req.body = 'invalid json';
    const middleware = new BodyParserMiddleware();
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('parses Pub/Sub message correctly', async () => {
    context.req.body = {
      message: {
        data: Buffer.from(JSON.stringify({ key: 'value' })).toString('base64'),
      },
    };
    const middleware = new BodyParserMiddleware();
    await middleware.before(context);
    expect(context.req.parsedBody).toEqual({ key: 'value' });
  });

  it('throws ValidationError for invalid Pub/Sub message', async () => {
    context.req.body = {
      message: {
        data: Buffer.from('invalid json').toString('base64'),
      },
    };
    const middleware = new BodyParserMiddleware();
    await expect(middleware.before(context)).rejects.toThrow(ValidationError);
  });

  it('does nothing if body is not a string or Pub/Sub message', async () => {
    context.req.body = { key: 'value' };
    const middleware = new BodyParserMiddleware();
    await middleware.before(context);
    expect(context.req.parsedBody).toEqual({ key: 'value' });
  });
});

describe('bodyParser', () => {
  let context: Context;

  beforeEach(() => {
    context = {
      req: {
        body: null,
        method: 'POST',
        parsedBody: undefined, // Ensure parsedBody is initialized to undefined
      },
      res: {},
    } as Context;
  });

  it('parses JSON body correctly', async () => {
    context.req.body = '{"key": "value"}';
    const middleware = bodyParser();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.parsedBody).toEqual({ key: 'value' });
  });

  it('throws ValidationError for invalid JSON body', async () => {
    context.req.body = 'invalid json';

    const middleware = bodyParser();
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('parses Pub/Sub message correctly', async () => {
    context.req.body = {
      message: {
        data: Buffer.from(JSON.stringify({ key: 'value' })).toString('base64'),
      },
    };
    const middleware = bodyParser();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.parsedBody).toEqual({ key: 'value' });
  });

  it('throws ValidationError for invalid Pub/Sub message', async () => {
    context.req.body = {
      message: {
        data: Buffer.from('invalid json').toString('base64'),
      },
    };
    const middleware = bodyParser();
    if (middleware.before) {
      await expect(middleware.before(context)).rejects.toThrow(ValidationError);
    }
  });

  it('does nothing if body is not a string or Pub/Sub message', async () => {
    context.req.body = { key: 'value' };
    const middleware = bodyParser();
    if (middleware.before) {
      await middleware.before(context);
    }
    expect(context.req.parsedBody).toEqual({ key: 'value' });
  });
});
