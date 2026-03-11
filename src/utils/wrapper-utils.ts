import type { HttpFunction } from '@google-cloud/functions-framework';
import type { Request, Response } from 'express';
import type { GenericRequest, GenericResponse } from '../core/core';
import { Handler } from '../core/handler';
import { handleWrapperError } from './http-wrapper-base';

/**
 * Create an HttpFunction wrapper for a Noony handler
 *
 * Wraps a Noony handler into a Google Cloud Functions `HttpFunction` for production deployment.
 * This pattern ensures proper initialization, error handling, and prevents double responses.
 *
 * @param noonyHandler - The Noony handler to wrap (contains middleware chain and controller)
 * @param functionName - Name for error logging purposes
 * @param initializeDependencies - Async function that initializes dependencies (database, services, etc.)
 *                                  Uses singleton pattern to prevent re-initialization on warm starts
 * @returns HttpFunction compatible with `@google-cloud/functions-framework`
 *
 * @remarks
 * This function ensures:
 * - Dependencies are initialized before handler execution (optimized for cold/warm starts)
 * - Errors are caught and returned as proper HTTP responses
 * - Response is not sent twice (`headersSent` check)
 * - `RESPONSE_SENT` errors are ignored (response already sent by middleware)
 * - Real errors return 500 with generic message for security
 *
 * @example
 * Creating and registering Cloud Functions:
 * ```typescript
 * import { http } from '@google-cloud/functions-framework';
 * import { createHttpFunction } from '@noony-serverless/core';
 * import { loginHandler } from './handlers/auth.handlers';
 *
 * // Initialize dependencies once per cold start
 * let initialized = false;
 * async function initializeDependencies(): Promise<void> {
 *   if (initialized) return;
 *   const db = await databaseService.connect();
 *   await initializeServices(db);
 *   initialized = true;
 * }
 *
 * // Create and register function
 * const loginFunction = createHttpFunction(
 *   loginHandler,
 *   'login',
 *   initializeDependencies
 * );
 * http('login', loginFunction);
 * export const login = loginFunction;
 * ```
 *
 * @example
 * Execution flow:
 * ```
 * HTTP Request → createHttpFunction wrapper
 *                    │
 *                    ▼
 *            initializeDependencies() (only on cold start)
 *                    │
 *                    ▼
 *            noonyHandler.execute(req, res)
 *                    │
 *                    ├─── errorHandler()
 *                    ├─── authMiddleware()
 *                    ├─── requirePermission()
 *                    ├─── bodyValidator()
 *                    ├─── ResponseWrapperMiddleware
 *                    └─── Controller function
 *                              │
 *                              ▼
 *                      HTTP Response
 * ```
 *
 * @see {@link wrapNoonyHandler} for Express integration (local development)
 */
export function createHttpFunction(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): HttpFunction {
  return async (req, res) => {
    try {
      // Ensure dependencies are initialized
      await initializeDependencies();

      // Execute Noony handler (runs middleware chain + controller)
      await noonyHandler.execute(
        req as unknown as GenericRequest<unknown>,
        res as unknown as GenericResponse
      );
    } catch (error) {
      handleWrapperError(error, functionName, res);
    }
  };
}

/**
 * Wrap a Noony handler for use with Express routing
 *
 * Wraps a Noony handler into an Express route handler for local development environments.
 * This pattern enables running all endpoints through a single Express app with standard
 * Express routing, middleware, and error handling.
 *
 * @param noonyHandler - The Noony handler to wrap (contains middleware chain and controller)
 * @param functionName - Name for error logging purposes
 * @param initializeDependencies - Async function that initializes dependencies (database, services, etc.)
 *                                  Uses singleton pattern to prevent re-initialization across requests
 * @returns Express route handler compatible with Express Router: `(req: Request, res: Response) => Promise<void>`
 *
 * @remarks
 * This wrapper ensures:
 * - Dependencies are initialized before handler execution (singleton pattern for efficiency)
 * - Noony handlers work seamlessly with Express routing and middleware
 * - Errors are caught and returned as proper HTTP responses
 * - Response is not sent twice (`headersSent` check)
 * - `RESPONSE_SENT` errors are ignored (response already sent by middleware)
 * - Real errors return 500 with generic message for security
 *
 * **Differences from createHttpFunction:**
 *
 * | Aspect | createHttpFunction | wrapNoonyHandler |
 * |--------|-------------------|------------------|
 * | **Use case** | Production deployment | Local development |
 * | **Framework** | Cloud Functions Framework | Express |
 * | **Return type** | `HttpFunction` | Express handler |
 * | **Registration** | `http('name', fn)` | `app.get('/path', fn)` |
 * | **Deployment** | Individual functions | Single Express app |
 *
 * @example
 * Creating Express app with multiple routes:
 * ```typescript
 * import express, { Express } from 'express';
 * import { wrapNoonyHandler } from '@noony-serverless/core';
 * import { loginHandler, logoutHandler, getConfigHandler } from './handlers';
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
 * function createExpressApp(): Express {
 *   const app = express();
 *
 *   // Global Express middleware
 *   app.use(cors());
 *   app.use(express.json());
 *
 *   // Health check (no DB required)
 *   app.get('/health', (_req, res) => {
 *     res.json({ success: true, data: { status: 'healthy' } });
 *   });
 *
 *   // Auth routes
 *   app.post('/api/auth/login', wrapNoonyHandler(loginHandler, 'login', initializeDependencies));
 *   app.post('/api/auth/logout', wrapNoonyHandler(logoutHandler, 'logout', initializeDependencies));
 *
 *   // Config routes
 *   app.get('/api/config', wrapNoonyHandler(getConfigHandler, 'getConfig', initializeDependencies));
 *
 *   // 404 handler
 *   app.use((_req, res) => {
 *     res.status(404).json({
 *       success: false,
 *       error: { code: 'NOT_FOUND', message: 'Endpoint not found' }
 *     });
 *   });
 *
 *   return app;
 * }
 *
 * // Start server
 * const app = createExpressApp();
 * const PORT = process.env.PORT || 3000;
 * app.listen(PORT, () => {
 *   console.log(`Server running on port ${PORT}`);
 * });
 * ```
 *
 * @example
 * Express routing with path parameters:
 * ```typescript
 * const app = express();
 *
 * // Routes with path parameters work seamlessly
 * app.get('/api/users/:userId', wrapNoonyHandler(getUserHandler, 'getUser', initializeDependencies));
 * app.patch('/api/config/sections/:sectionId', wrapNoonyHandler(updateSectionHandler, 'updateSection', initializeDependencies));
 * app.delete('/api/config/sections/:sectionId', wrapNoonyHandler(deleteSectionHandler, 'deleteSection', initializeDependencies));
 *
 * // Path parameters available in Noony handler via context.req.params
 * ```
 *
 * @see {@link createHttpFunction} for Cloud Functions Framework integration (production deployment)
 */
export function wrapNoonyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (req: Request, res: Response) => Promise<void> {
  return async (req: Request, res: Response): Promise<void> => {
    try {
      // Ensure dependencies are initialized
      await initializeDependencies();

      // Execute Noony handler with Express req/res
      await noonyHandler.executeGeneric(
        req as unknown as GenericRequest<unknown>,
        res as unknown as GenericResponse
      );
    } catch (error) {
      handleWrapperError(error, functionName, res);
    }
  };
}
