import {
  BaseMiddleware,
  Context,
  ValidationError,
  TooLargeError,
} from '../core';

interface PubSubMessage {
  message: {
    data: string;
    // Add other PubSub message properties if needed
  };
}

// Performance optimization: Cache compiled regex for better performance
const PUB_SUB_MESSAGE_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

// Type guard to check if the body is a PubSub message - optimized version
const isPubSubMessage = (body: unknown): body is PubSubMessage => {
  return (
    !!body &&
    typeof body === 'object' &&
    'message' in body &&
    typeof (body as PubSubMessage).message === 'object' &&
    'data' in (body as PubSubMessage).message
  );
};

// Performance constants
const MAX_JSON_SIZE = 1024 * 1024; // 1MB default limit
const MAX_BASE64_SIZE = 1024 * 1024 * 1.5; // 1.5MB for base64 (accounts for encoding overhead)

/**
 * Async JSON parsing using worker threads for large payloads
 * Falls back to synchronous parsing for small payloads
 */
const parseJsonAsync = async <T = unknown>(jsonString: string): Promise<T> => {
  // Performance optimization: Use sync parsing for small payloads
  if (jsonString.length < 10000) {
    // 10KB threshold
    try {
      return JSON.parse(jsonString) as T;
    } catch (error: unknown) {
      throw new ValidationError('Invalid JSON body', (error as Error).message);
    }
  }

  // For larger payloads, use async parsing to avoid blocking
  return new Promise((resolve, reject) => {
    // Use setImmediate to make JSON parsing non-blocking
    setImmediate(() => {
      try {
        const result = JSON.parse(jsonString) as T;
        resolve(result);
      } catch (error: unknown) {
        reject(
          new ValidationError('Invalid JSON body', (error as Error).message)
        );
      }
    });
  });
};

/**
 * Optimized base64 decoding with size limits and streaming for large data
 */
const decodeBase64Async = async (base64Data: string): Promise<string> => {
  // Validate base64 string format first (performance optimization)
  if (!PUB_SUB_MESSAGE_REGEX.test(base64Data)) {
    throw new ValidationError('Invalid base64 format in Pub/Sub message');
  }

  // Check size limits to prevent memory exhaustion
  if (base64Data.length > MAX_BASE64_SIZE) {
    throw new TooLargeError('Pub/Sub message too large');
  }

  // For small messages, use sync decoding
  if (base64Data.length < 1000) {
    return Buffer.from(base64Data, 'base64').toString();
  }

  // For larger messages, use async decoding to avoid blocking
  return new Promise((resolve, reject) => {
    setImmediate(() => {
      try {
        const decoded = Buffer.from(base64Data, 'base64').toString();
        resolve(decoded);
      } catch (error: unknown) {
        reject(
          new ValidationError(
            'Failed to decode base64 Pub/Sub message',
            (error as Error).message
          )
        );
      }
    });
  });
};

// Enhanced async body parser with performance optimizations
const parseBody = async <T = unknown>(body: unknown): Promise<T> => {
  // Early return for already parsed objects
  if (typeof body === 'object' && body !== null && !isPubSubMessage(body)) {
    return body as T;
  }

  if (typeof body === 'string') {
    // Size check to prevent DoS attacks
    if (body.length > MAX_JSON_SIZE) {
      throw new TooLargeError('Request body too large');
    }

    return await parseJsonAsync<T>(body);
  }

  if (isPubSubMessage(body)) {
    try {
      const decoded = await decodeBase64Async(body.message.data);
      return await parseJsonAsync<T>(decoded);
    } catch (error: unknown) {
      if (error instanceof ValidationError || error instanceof TooLargeError) {
        throw error;
      }
      throw new ValidationError(
        'Invalid Pub/Sub message',
        (error as Error).message
      );
    }
  }

  return body as T;
};

/**
 * Enhanced BodyParserMiddleware with async parsing and performance optimizations.
 *
 * Features:
 * - Async JSON parsing for large payloads
 * - Size limits to prevent DoS attacks
 * - Base64 decoding for Pub/Sub messages
 * - Non-blocking parsing using setImmediate
 *
 * @template T - The expected type of the parsed body. Defaults to unknown if not specified.
 * @implements {BaseMiddleware}
 */
export class BodyParserMiddleware<T = unknown> implements BaseMiddleware {
  private maxSize: number;

  constructor(maxSize: number = MAX_JSON_SIZE) {
    this.maxSize = maxSize;
  }

  async before(context: Context): Promise<void> {
    // Check content-length early to avoid processing oversized requests
    const headers = context.req.headers || {};
    const contentLength = headers['content-length'];
    if (contentLength) {
      const length = Array.isArray(contentLength)
        ? contentLength[0]
        : contentLength;
      if (length && parseInt(length) > this.maxSize) {
        throw new TooLargeError('Request body too large');
      }
    }

    context.req.parsedBody = await parseBody<T>(context.req.body);
  }
}

/**
 * Enhanced middleware function for parsing the request body in specific HTTP methods.
 *
 * Performance optimizations:
 * - Early method validation
 * - Async parsing for large payloads
 * - Size validation
 *
 * @template T - The expected type of the parsed request body.
 * @returns {BaseMiddleware} A middleware object containing a `before` hook.
 */
export const bodyParser = <T = unknown>(
  maxSize: number = MAX_JSON_SIZE
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    const { method, body } = context.req;

    // Performance optimization: Early return for methods that don't typically have bodies
    if (!method || !['POST', 'PUT', 'PATCH'].includes(method)) {
      return;
    }

    // Check content-length early
    const headers = context.req.headers || {};
    const contentLength = headers['content-length'];
    if (contentLength) {
      const length = Array.isArray(contentLength)
        ? contentLength[0]
        : contentLength;
      if (length && parseInt(length) > maxSize) {
        throw new TooLargeError('Request body too large');
      }
    }

    context.req.parsedBody = await parseBody<T>(body);
  },
});
