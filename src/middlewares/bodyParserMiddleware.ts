import { BaseMiddleware, Context, ValidationError } from '../core';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const parseBody = (body: any): any => {
  if (typeof body === 'string') {
    try {
      return JSON.parse(body);
    } catch (error: unknown) {
      throw new ValidationError('Invalid JSON body', (error as Error).stack);
    }
  }

  if (body?.message?.data) {
    try {
      const decoded = Buffer.from(body.message.data, 'base64').toString();
      return JSON.parse(decoded);
    } catch (error: unknown) {
      throw new ValidationError(
        'Invalid Pub/Sub message',
        (error as Error).stack
      );
    }
  }

  return body;
};

export class BodyParserMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    context.req.parsedBody = parseBody(context.req.body);
  }
}

export const bodyParser = (): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const { method, body } = context.req;

    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      context.req.parsedBody = parseBody(body);
    }
  },
});
