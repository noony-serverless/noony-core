// Container import removed - now using containerPool for performance
import {
  Context,
  CustomRequest,
  CustomResponse,
  GenericRequest,
  GenericResponse,
  createContext,
  adaptGCPRequest,
  adaptGCPResponse,
} from './core';
import { containerPool } from './containerPool';
import { Request, Response } from '@google-cloud/functions-framework';

/**
 * Interface representing a base structure for middleware with optional lifecycle methods.
 *
 * This interface is designed to provide hooks for execution during different
 * stages of a middleware's lifecycle. It allows for defining logic to be
 * executed before and after a process, as well as handling errors that
 * occur during the process.
 *
 * @template T - The type of the request or input context. Defaults to unknown.
 * @template U - The type of the response or output context. Defaults to unknown.
 */
export interface BaseMiddleware<T = unknown, U = unknown> {
  before?: (context: Context<T, U>) => Promise<void>;
  after?: (context: Context<T, U>) => Promise<void>;
  onError?: (error: Error, context: Context<T, U>) => Promise<void>;
}

/**
 * The Handler class is responsible for managing and executing middleware functions
 * and a main handler function in a sequential and controlled manner.
 *
 * This class provides a mechanism for registering middlewares that can
 * process a request/response flow either before the main handler (via `before`),
 * after the main handler (via `after`), or handle errors (via `onError`).
 *
 * interface MessagePayload {
 *   action: string;
 *   data: Record<string, unknown>;
 * }
 *
 * const handler = new Handler<MessagePayload>()
 *   .use(errorHandler())
 *   .use(bodyParser())
 *   .handle(async (context) => {
 *     const { req } = context;
 *     // Handle the request
 *   });
 * @template T Type for the input request data.
 * @template U Type for the additional context or response data.
 */
export class Handler<T = unknown, U = unknown> {
  private baseMiddlewares: BaseMiddleware<T, U>[] = [];
  private handler!: (context: Context<T, U>) => Promise<void>;

  // Performance optimization: Pre-computed middleware arrays
  private reversedMiddlewares: BaseMiddleware<T, U>[] = [];
  private errorMiddlewares: BaseMiddleware<T, U>[] = [];
  private middlewaresPrecomputed = false;

  static use<T = unknown, U = unknown>(
    middleware: BaseMiddleware<T, U>
  ): Handler<T, U> {
    const handler = new Handler<T, U>();
    handler.baseMiddlewares.push(middleware);
    return handler;
  }

  use<NewT = T, NewU = U>(
    middleware: BaseMiddleware<NewT, NewU>
  ): Handler<NewT, NewU> {
    const handler = new Handler<NewT, NewU>();
    handler.baseMiddlewares = [
      ...(this.baseMiddlewares as unknown as BaseMiddleware<NewT, NewU>[]),
      middleware,
    ];
    return handler;
  }

  handle(handler: (context: Context<T, U>) => Promise<void>): Handler<T, U> {
    this.handler = handler;
    this.precomputeMiddlewareArrays();
    return this;
  }

  /**
   * Performance optimization: Pre-compute middleware arrays to avoid runtime array operations
   */
  private precomputeMiddlewareArrays(): void {
    if (this.middlewaresPrecomputed) return;

    // Pre-compute reversed array for after/error middlewares
    this.reversedMiddlewares = [...this.baseMiddlewares].reverse();

    this.errorMiddlewares = this.reversedMiddlewares.filter((m) => m.onError);

    this.middlewaresPrecomputed = true;
  }

  async execute(req: CustomRequest<T>, res: CustomResponse): Promise<void> {
    const genericReq = adaptGCPRequest<T>(req as unknown as Request);
    const genericRes = adaptGCPResponse(res as unknown as Response);

    // Performance optimization: Use container pool instead of creating new containers
    const container = containerPool.acquire();
    const context = createContext<T, U>(genericReq, genericRes, {
      container,
    });

    try {
      // Execute before middlewares with performance optimizations
      await this.executeBeforeMiddlewares(context);

      await this.handler(context);

      // Execute after middlewares in reverse order using pre-computed array
      await this.executeAfterMiddlewares(context);
    } catch (error) {
      context.error = error as Error;
      // Execute error handlers using pre-computed array
      await this.executeErrorMiddlewares(error as Error, context);
    } finally {
      // Always return container to pool for reuse
      containerPool.release(container);
    }
  }

  /**
   * Execute before middlewares with optimized batching for independent middlewares
   */
  private async executeBeforeMiddlewares(
    context: Context<T, U>
  ): Promise<void> {
    // For backward compatibility and simpler logic, execute all before middlewares in order
    for (const middleware of this.baseMiddlewares) {
      if (middleware.before) {
        await middleware.before(context);
      }
    }
  }

  /**
   * Execute after middlewares using pre-computed reversed array
   */
  private async executeAfterMiddlewares(context: Context<T, U>): Promise<void> {
    // For backward compatibility and simpler logic, execute all after middlewares in reverse order
    for (const middleware of this.reversedMiddlewares) {
      if (middleware.after) {
        await middleware.after(context);
      }
    }
  }

  /**
   * Execute error middlewares using pre-computed array
   */
  private async executeErrorMiddlewares(
    error: Error,
    context: Context<T, U>
  ): Promise<void> {
    for (const middleware of this.errorMiddlewares) {
      if (middleware.onError) {
        await middleware.onError(error, context);
      }
    }
  }

  /**
   * Framework-agnostic execute method that works with GenericRequest/GenericResponse
   */
  async executeGeneric(
    req: GenericRequest<T>,
    res: GenericResponse
  ): Promise<void> {
    // Performance optimization: Use container pool instead of creating new containers
    const container = containerPool.acquire();
    const context = createContext<T, U>(req, res, {
      container,
    });

    try {
      // Execute before middlewares with performance optimizations
      await this.executeBeforeMiddlewares(context);

      await this.handler(context);

      // Execute after middlewares in reverse order using pre-computed array
      await this.executeAfterMiddlewares(context);
    } catch (error) {
      context.error = error as Error;
      // Execute error handlers using pre-computed array
      await this.executeErrorMiddlewares(error as Error, context);
    } finally {
      // Always return container to pool for reuse
      containerPool.release(container);
    }
  }
}
