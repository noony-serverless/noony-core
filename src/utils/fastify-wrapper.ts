import type { FastifyRequest, FastifyReply } from 'fastify';
import type { GenericRequest, GenericResponse } from '../core/core';
import { Handler } from '../core/handler';
import { logger } from '../core/logger';

/**
 * Adapt Fastify Request to GenericRequest for Noony handlers
 *
 * @internal
 */
function adaptFastifyRequest<T = unknown>(
  req: FastifyRequest
): GenericRequest<T> {
  return {
    method: req.method,
    url: req.url,
    path: (req.routeOptions as { url?: string })?.url || req.url,
    headers: req.headers as Record<string, string | string[] | undefined>,
    query: (req.query || {}) as Record<string, string | string[] | undefined>,
    params: (req.params || {}) as Record<string, string>,
    body: req.body,
    // Fastify already parses the body, so set parsedBody for BodyValidationMiddleware
    parsedBody: req.body as T,
    ip: req.ip,
    userAgent: req.headers['user-agent'] as string | undefined,
  };
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
      headersSent = true;
      reply.send(data);
      return response;
    },
    send(data: unknown) {
      headersSent = true;
      reply.send(data);
      return response;
    },
    header(name: string, value: string) {
      reply.header(name, value);
      return response;
    },
    headers(headers: Record<string, string>) {
      Object.entries(headers).forEach(([key, value]) => {
        reply.header(key, value);
      });
      return response;
    },
    end() {
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
export function createFastifyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (req: FastifyRequest, reply: FastifyReply) => Promise<void> {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      // Ensure dependencies are initialized
      await initializeDependencies();

      // Adapt Fastify req/reply to GenericRequest/GenericResponse
      const genericReq = adaptFastifyRequest(req);
      const genericRes = adaptFastifyResponse(reply);

      // Execute Noony handler with adapted request/response
      await noonyHandler.executeGeneric(genericReq, genericRes);
    } catch (error) {
      // Ignore RESPONSE_SENT markers (response already sent by middleware)
      if (error instanceof Error && error.message === 'RESPONSE_SENT') {
        return;
      }

      logger.error(`${functionName} handler error`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      // Graceful error handling - only send if response not already sent
      if (!reply.sent) {
        reply.status(500).send({
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred',
          },
        });
      }
    }
  };
}
