import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';

const wrapResponse = <T>(context: Context): void => {
  if (!context.res.headersSent) {
    const statusCode = context.res.statusCode || 200;
    const body = context.responseData as T;
    context.res.status(statusCode).json({
      success: true,
      payload: body,
      timestamp: new Date().toISOString(),
    });
  }
};

export class ResponseWrapperMiddleware<T> implements BaseMiddleware {
  async after(context: Context): Promise<void> {
    wrapResponse<T>(context);
  }
}

export const responseWrapperMiddleware = <T>(): BaseMiddleware => ({
  after: async (context: Context): Promise<void> => {
    wrapResponse<T>(context);
  },
});

/**
 * Helper function to set response data in context for later wrapping
 */
export function setResponseData<T>(context: Context, data: T): void {
  context.responseData = data;
}
