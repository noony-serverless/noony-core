import type { FastifyRequest, FastifyReply } from 'fastify';
import type { GenericRequest, GenericResponse } from '../core/core';
import { Handler } from '../core/handler';
import { logger } from '../core/logger';
import {
  isResponseAlreadySent,
  INTERNAL_ERROR_RESPONSE,
  logHandlerError,
} from './http-wrapper-base';
type FastifyHeaderValue = string | string[] | undefined;

// Global WeakMap to store the original Fastify request for each GenericRequest
// This allows middlewares to access the original request and its body
// even after the GenericRequest properties have been copied by Handler.executeGeneric
export const requestBodyMap = new WeakMap<any, FastifyRequest>();

// Pre-allocated empty objects to avoid allocations in hot path
const EMPTY_QUERY = Object.freeze({});
const EMPTY_PARAMS = Object.freeze({});

/**
 * Adapt Fastify Request to GenericRequest for Noony handlers
 *
 * IMPORTANT: Stores the original Fastify request in a WeakMap so middlewares
 * can access the body even after properties are copied by Handler.executeGeneric
 *
 * @internal
 */
function adaptFastifyRequest<T = unknown>(
  req: FastifyRequest
): GenericRequest<T> {
  // Fast path: use pre-allocated empty objects when no query/params
  const query = req.query || EMPTY_QUERY;
  const params = req.params || EMPTY_PARAMS;

  // Inline path extraction to avoid optional chaining overhead
  const routeUrl = (req.routeOptions as any)?.url;
  const path = routeUrl || req.url;

  const genericReq: GenericRequest<T> = {
    method: req.method,
    url: req.url,
    path,
    headers: req.headers as Record<string, FastifyHeaderValue>,
    query: query as Record<string, FastifyHeaderValue>,
    params: params as Record<string, string>,
    body: req.body,
    parsedBody: req.body as T,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  };

  // Store the original Fastify request in the WeakMap for middleware access
  requestBodyMap.set(genericReq, req);

  return genericReq;
}

/**
 * Adapt Fastify Reply to GenericResponse for Noony handlers
 *
 * @internal
 */
function adaptFastifyResponse(reply: FastifyReply): GenericResponse {
  let statusCode = 200;
  let headersSent = false;

  const response: GenericResponse = {
    status(code: number) {
      statusCode = code;
      reply.code(code);
      return response;
    },
    json(data: unknown) {
      // Early return if already sent (avoid duplicate sends)
      if (reply.sent) return response;

      headersSent = true;
      reply.send(data);
      return response;
    },
    send(data: unknown) {
      // Early return if already sent (avoid duplicate sends)
      if (reply.sent) return response;

      headersSent = true;
      reply.send(data);
      return response;
    },
    header(name: string, value: string) {
      reply.header(name, value);
      return response;
    },
    headers(headers: Record<string, string>) {
      // Optimized header setting - direct iteration instead of Object.entries
      for (const key in headers) {
        reply.header(key, headers[key]);
      }
      return response;
    },
    end() {
      // Early return if already sent (avoid duplicate sends)
      if (reply.sent) return;

      headersSent = true;
      reply.send();
    },
    get statusCode() {
      return statusCode;
    },
    get headersSent() {
      return headersSent || reply.sent;
    },
  };

  return response;
}

/**
 * Create a Fastify route handler wrapper for a Noony handler
 *
 * Wraps a Noony handler into a Fastify route handler for use with Fastify server.
 * This pattern enables running Noony handlers with Fastify's high-performance HTTP framework.
 *
 * @param noonyHandler - The Noony handler to wrap (contains middleware chain and controller)
 * @param functionName - Name for error logging purposes
 * @param initializeDependencies - Async function that initializes dependencies (database, services, etc.)
 *                                  Uses singleton pattern to prevent re-initialization across requests
 * @returns Fastify route handler: `(req: FastifyRequest, reply: FastifyReply) => Promise<void>`
 *
 * @remarks
 * This wrapper ensures:
 * - Dependencies are initialized before handler execution (singleton pattern for efficiency)
 * - Noony handlers work seamlessly with Fastify routing
 * - Errors are caught and returned as proper HTTP responses
 * - Response is not sent twice (`reply.sent` check)
 * - `RESPONSE_SENT` errors are ignored (response already sent by middleware)
 * - Real errors return 500 with generic message for security
 *
 * @example
 * Creating Fastify app with multiple routes:
 * ```typescript
 * import Fastify from 'fastify';
 * import { createFastifyHandler } from '@noony-serverless/core';
 * import { loginHandler, getConfigHandler } from './handlers';
 *
 * // Initialize dependencies once per app startup
 * let initialized = false;
 * async function initializeDependencies(): Promise<void> {
 *   if (initialized) return;
 *   const db = await databaseService.connect();
 *   await initializeServices(db);
 *   initialized = true;
 * }
 *
 * const server = Fastify({ logger: true });
 *
 * // Helper shorthand
 * const adapt = (handler, name) => createFastifyHandler(handler, name, initializeDependencies);
 *
 * // Auth routes
 * server.post('/api/auth/login', adapt(loginHandler, 'login'));
 *
 * // Config routes
 * server.get('/api/config', adapt(getConfigHandler, 'getConfig'));
 *
 * // Start server
 * server.listen({ port: 3000 }, (err) => {
 *   if (err) throw err;
 *   console.log('Server running on port 3000');
 * });
 * ```
 *
 * @example
 * Fastify routing with path parameters:
 * ```typescript
 * const server = Fastify();
 *
 * // Routes with path parameters work seamlessly
 * server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));
 * server.patch('/api/config/sections/:sectionId', adapt(updateSectionHandler, 'updateSection'));
 *
 * // Path parameters available in Noony handler via context.req.params
 * ```
 *
 * @see {@link createHttpFunction} for Cloud Functions Framework integration (production deployment)
 * @see {@link wrapNoonyHandler} for Express integration
 */

export interface CloudFunctionRequest {
  method?: string;
  body?: unknown;
  url?: string;
  headers?: Record<string, string | string[] | undefined>;
  __rawBody?: string;
  rawBody?: string | Buffer;
  readableEnded?: boolean;
  complete?: boolean;
}

// Helper: Extract and store request body for later use
export function extractAndStoreRequestBody(req: CloudFunctionRequest): void {
  if (!['POST', 'PUT', 'PATCH'].includes(req.method || '')) {
    return;
  }

  // Check if already has __rawBody from previous processing
  if (req.__rawBody) {
    return;
  }

  const body = req.body;
  if (!body) return;

  // Use safe JSON stringify to handle circular references
  try {
    req.__rawBody = typeof body === 'string' ? body : JSON.stringify(body);
  } catch (error) {
    // If circular reference or other serialization error, skip storing __rawBody
    if (process.env.NODE_ENV === 'development') {
      logger.debug(
        '[helper] Failed to stringify body, skipping __rawBody storage',
        {
          error: error instanceof Error ? error.message : String(error),
        }
      );
    }
    return;
  }

  if (process.env.NODE_ENV === 'development') {
    logger.debug('[helper] Extracted and stored __rawBody', {
      bodyLength: req.__rawBody.length,
      bodyType: typeof body,
    });
  }
}

export function createFastifyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (req: FastifyRequest, reply: FastifyReply) => Promise<void> {
  // Pre-bind the error log prefix to avoid string concatenation in hot path
  const errorLogPrefix = `${functionName} handler error`;

  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const requestId = `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
    console.log(`[FASTIFY-WRAPPER] ${errorLogPrefix} called`, {
      requestId,
      url: req.url,
      method: req.method,
      timestamp: new Date().toISOString(),
    });

    try {
      // Ensure dependencies are initialized
      await initializeDependencies();

      // Adapt Fastify req/reply to GenericRequest/GenericResponse
      const genericReq = adaptFastifyRequest(req);
      const genericRes = adaptFastifyResponse(reply);

      // Execute Noony handler with adapted request/response
      await noonyHandler.executeGeneric(genericReq, genericRes);

      console.log(`[FASTIFY-WRAPPER] ${errorLogPrefix} completed`, {
        requestId,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      // Fast path: check RESPONSE_SENT first (most common error to ignore)
      if (isResponseAlreadySent(error)) {
        return;
      }

      // Log error and send response
      logHandlerError(functionName, error);

      // Graceful error handling - only send if response not already sent
      if (!reply.sent) {
        reply.code(500).send(INTERNAL_ERROR_RESPONSE);
      }
    }
  };
}
