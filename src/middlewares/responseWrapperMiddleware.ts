import { BaseMiddleware } from '../core/handler';
import { Context } from '../core/core';

const wrapResponse = <T, TBody = unknown, TUser = unknown>(
  context: Context<TBody, TUser>,
  defaultStatusCode?: number
): void => {
  if (!context.res.headersSent) {
    // Use defaultStatusCode if provided, otherwise use context.res.statusCode, finally default to 200
    const statusCode = defaultStatusCode || context.res.statusCode || 200;
    const body = context.responseData as T;
    context.res.status(statusCode).json({
      success: true,
      payload: body,
      timestamp: new Date().toISOString(),
    });
  }
};

/**
 * Middleware class that wraps response data in a standardized format.
 * Automatically wraps the response with success flag, payload, and timestamp.
 *
 * @template T - The type of response data being wrapped
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @implements {BaseMiddleware}
 *
 * @remarks
 * **Important:** Do not use the deprecated `setResponseData()` helper function.
 * Simply return values from your handler - the Handler automatically sets context.responseData.
 *
 * @example
 * Basic response wrapping:
 * ```typescript
 * import { Handler, ResponseWrapperMiddleware } from '@noony-serverless/core';
 *
 * interface UserResponse {
 *   id: string;
 *   name: string;
 *   email: string;
 * }
 *
 * const getUserHandler = new Handler()
 *   .use(new ResponseWrapperMiddleware<UserResponse>())
 *   .handle(async (context) => {
 *     const user = await getUser(context.params.id);
 *     return user;  // Handler automatically sets context.responseData
 *     // Response will be: { success: true, payload: user, timestamp: "..." }
 *   });
 * ```
 *
 * @example
 * API response with metadata:
 * ```typescript
 * interface ApiResponse {
 *   items: any[];
 *   pagination: { page: number; total: number };
 * }
 *
 * const listItemsHandler = new Handler()
 *   .use(new ResponseWrapperMiddleware<ApiResponse>())
 *   .handle(async (context) => {
 *     const items = await getItems();
 *     return {
 *       items,
 *       pagination: { page: 1, total: items.length }
 *     };
 *   });
 * ```
 *
 * @example
 * Combination with error handling:
 * ```typescript
 * const secureHandler = new Handler()
 *   .use(new AuthenticationMiddleware())
 *   .use(new ResponseWrapperMiddleware<any>())
 *   .use(new ErrorHandlerMiddleware())
 *   .handle(async (context) => {
 *     const data = await getSecureData(context.user.id);
 *     return data;
 *   });
 * ```
 */
export class ResponseWrapperMiddleware<
  T = unknown,
  TBody = unknown,
  TUser = unknown,
> implements BaseMiddleware<TBody, TUser>
{
  constructor(private defaultStatusCode?: number) {}

  async after(context: Context<TBody, TUser>): Promise<void> {
    wrapResponse<T, TBody, TUser>(context, this.defaultStatusCode);
  }
}

/**
 * Factory function that creates a response wrapper middleware.
 * Automatically wraps response data in a standardized format with success flag and timestamp.
 *
 * @template T - The type of response data being wrapped
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @returns BaseMiddleware object with response wrapping logic
 *
 * @remarks
 * **Important:** Do not use the deprecated `setResponseData()` helper function.
 * Simply return values from your handler - the Handler automatically sets context.responseData.
 *
 * @example
 * Simple API endpoint:
 * ```typescript
 * import { Handler, responseWrapperMiddleware } from '@noony-serverless/core';
 *
 * const healthCheckHandler = new Handler()
 *   .use(responseWrapperMiddleware<{ status: string; uptime: number }>())
 *   .handle(async (context) => {
 *     return {
 *       status: 'healthy',
 *       uptime: process.uptime()
 *     };
 *     // Response: { success: true, payload: { status: "healthy", uptime: 12345 }, timestamp: "..." }
 *   });
 * ```
 *
 * @example
 * RESTful CRUD operations:
 * ```typescript
 * const createUserHandler = new Handler()
 *   .use(bodyParser())
 *   .use(responseWrapperMiddleware<{ id: string; message: string }>())
 *   .handle(async (context) => {
 *     const userData = context.req.parsedBody;
 *     const newUser = await createUser(userData);
 *     return {
 *       id: newUser.id,
 *       message: 'User created successfully'
 *     };
 *   });
 * ```
 *
 * @example
 * Microservice communication:
 * ```typescript
 * const orderProcessingHandler = new Handler()
 *   .use(authenticationMiddleware)
 *   .use(responseWrapperMiddleware<{ orderId: string; status: string; estimatedDelivery: string }>())
 *   .handle(async (context) => {
 *     const order = await processOrder(context.req.parsedBody);
 *     return {
 *       orderId: order.id,
 *       status: order.status,
 *       estimatedDelivery: order.estimatedDelivery
 *     };
 *   });
 * ```
 */
export const responseWrapperMiddleware = <
  T = unknown,
  TBody = unknown,
  TUser = unknown,
>(
  defaultStatusCode?: number
): BaseMiddleware<TBody, TUser> => ({
  after: async (context: Context<TBody, TUser>): Promise<void> => {
    wrapResponse<T, TBody, TUser>(context, defaultStatusCode);
  },
});
