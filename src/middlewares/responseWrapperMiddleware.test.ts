import {
  responseWrapperMiddleware,
  ResponseWrapperMiddleware,
} from './responseWrapperMiddleware';
import { Context } from '../core';

describe('ResponseWrapperMiddleware', () => {
  let context: Context;
  let middleware: ResponseWrapperMiddleware<never>;

  beforeEach(() => {
    context = {
      req: { method: 'GET', url: '/', headers: {}, query: {}, params: {} },
      res: {
        headersSent: false,
        statusCode: 200,
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        send: jest.fn(),
        header: jest.fn().mockReturnThis(),
        headers: jest.fn().mockReturnThis(),
        end: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
      startTime: Date.now(),
      requestId: 'test-req-id',
      responseData: { key: 'value' },
    } as unknown as Context;
    middleware = new ResponseWrapperMiddleware();
  });

  it('wraps response if headers are not sent', async () => {
    await middleware.after(context);
    expect(context.res.status).toHaveBeenCalledWith(200);
    expect(context.res.json).toHaveBeenCalledWith({
      success: true,
      payload: { key: 'value' },
      timestamp: expect.any(String),
    });
  });

  it('does not wrap response if headers are already sent', async () => {
    context.res.headersSent = true;
    await middleware.after(context);
    expect(context.res.status).not.toHaveBeenCalled();
    expect(context.res.json).not.toHaveBeenCalled();
  });

  it('uses default status code 200 if status code is not set', async () => {
    context.res.statusCode = null as unknown as number;
    await middleware.after(context);
    expect(context.res.status).toHaveBeenCalledWith(200);
  });

  it('uses provided status code if set', async () => {
    context.res.statusCode = 201;
    await middleware.after(context);
    expect(context.res.status).toHaveBeenCalledWith(201);
  });

  it('handles empty response body', async () => {
    context.responseData = undefined;
    await middleware.after(context);
    expect(context.res.json).toHaveBeenCalledWith({
      success: true,
      payload: undefined,
      timestamp: expect.any(String),
    });
  });
});

describe('responseWrapperMiddleware', () => {
  let context: Context;
  let middleware: ReturnType<typeof responseWrapperMiddleware>;

  beforeEach(() => {
    context = {
      req: { method: 'GET', url: '/', headers: {}, query: {}, params: {} },
      res: {
        headersSent: false,
        statusCode: 200,
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        send: jest.fn(),
        header: jest.fn().mockReturnThis(),
        headers: jest.fn().mockReturnThis(),
        end: jest.fn(),
      },
      container: null,
      error: null,
      businessData: new Map(),
      startTime: Date.now(),
      requestId: 'test-req-id',
      responseData: { key: 'value' },
    } as unknown as Context;
  });

  it('wraps response if headers are not sent', async () => {
    middleware = responseWrapperMiddleware();
    if (middleware.after) {
      await middleware.after(context);
      expect(context.res.status).toHaveBeenCalledWith(200);
      expect(context.res.json).toHaveBeenCalledWith({
        success: true,
        payload: { key: 'value' },
        timestamp: expect.any(String),
      });
    }
  });

  it('does not wrap response if headers are already sent', async () => {
    context.res.headersSent = true;
    middleware = responseWrapperMiddleware();
    if (middleware.after) {
      await middleware.after(context);
      expect(context.res.status).not.toHaveBeenCalled();
      expect(context.res.json).not.toHaveBeenCalled();
    }
  });

  it('uses default status code 200 if status code is not set', async () => {
    context.res.statusCode = null as unknown as number;
    middleware = responseWrapperMiddleware();
    if (middleware.after) {
      await middleware.after(context);
      expect(context.res.status).toHaveBeenCalledWith(200);
    }
  });

  it('uses provided status code if set', async () => {
    context.res.statusCode = 201;
    middleware = responseWrapperMiddleware();
    if (middleware.after) {
      await middleware.after(context);
      expect(context.res.status).toHaveBeenCalledWith(201);
    }
  });

  it('handles empty response body', async () => {
    context.responseData = undefined;
    middleware = responseWrapperMiddleware();
    if (middleware.after) {
      await middleware.after(context);
      expect(context.res.json).toHaveBeenCalledWith({
        success: true,
        payload: undefined,
        timestamp: expect.any(String),
      });
    }
  });
});
