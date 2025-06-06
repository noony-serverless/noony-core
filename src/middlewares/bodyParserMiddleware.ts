import { BaseMiddleware, Context, ValidationError } from '../core';

interface PubSubMessage {
  message: {
    data: string;
    // Add other PubSub message properties if needed
  };
}

// Type guard to check if the body is a PubSub message
const isPubSubMessage = (body: unknown): body is PubSubMessage => {
  return (
    !!body &&
    typeof body === 'object' &&
    'message' in body &&
    typeof (body as PubSubMessage).message === 'object' &&
    'data' in (body as PubSubMessage).message
  );
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const parseBody = <T = unknown>(body: unknown): T => {
  if (typeof body === 'string') {
    try {
      return JSON.parse(body) as T;
    } catch (error: unknown) {
      throw new ValidationError('Invalid JSON body', (error as Error).stack);
    }
  }

  if (isPubSubMessage(body)) {
    try {
      const decoded = Buffer.from(body.message.data, 'base64').toString();
      return JSON.parse(decoded) as T;
    } catch (error: unknown) {
      throw new ValidationError(
        'Invalid Pub/Sub message',
        (error as Error).stack
      );
    }
  }

  return body as T;
};

/**
 * BodyParserMiddleware is a middleware that parses the request body and attaches the parsed result
 * to the request object in the context.
 *
 * This middleware intercepts the request before it reaches the intended handling logic
 * and processes the body, converting it into a parsed representation. The parsed body
 * is then assigned to `context.req.parsedBody` for downstream usage.
 *
 * @template T - The expected type of the parsed body. Defaults to unknown if not specified.
 * @implements {BaseMiddleware}
 */
export class BodyParserMiddleware<T = unknown> implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    context.req.parsedBody = parseBody<T>(context.req.body);
  }
}

/**
 * Middleware function for parsing the request body in specific HTTP methods (POST, PUT, PATCH).
 *
 * This middleware intercepts the request before it reaches the intended handling logic
 * and processes the body, converting it into a parsed representation. The parsed body
 * is then assigned to `context.req.parsedBody` for downstream usage.
 *
 * @template T - The expected type of the parsed request body.
 * @returns {BaseMiddleware} A middleware object containing a `before` hook.
 */
export const bodyParser = <T = unknown>(): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const { method, body } = context.req;

    if (method && ['POST', 'PUT', 'PATCH'].includes(method)) {
      context.req.parsedBody = parseBody<T>(body);
    }
  },
});
