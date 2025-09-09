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

/**
 * Middleware class that wraps response data in a standardized format.
 * Automatically wraps the response with success flag, payload, and timestamp.
 *
 * @template T - The type of response data being wrapped
 * @implements {BaseMiddleware}
 *
 * @example
 * Basic response wrapping:
 * ```typescript
 * import { Handler, ResponseWrapperMiddleware, setResponseData } from '@noony-serverless/core';
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
 *     setResponseData(context, user);
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
 *     const response: ApiResponse = {
 *       items,
 *       pagination: { page: 1, total: items.length }
 *     };
 *     setResponseData(context, response);
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
 *     setResponseData(context, data);
 *   });
 * ```
 */
export class ResponseWrapperMiddleware<T> implements BaseMiddleware {
  async after(context: Context): Promise<void> {
    wrapResponse<T>(context);
  }
}

/**
 * Factory function that creates a response wrapper middleware.
 * Automatically wraps response data in a standardized format with success flag and timestamp.
 *
 * @template T - The type of response data being wrapped
 * @returns BaseMiddleware object with response wrapping logic
 *
 * @example
 * Simple API endpoint:
 * ```typescript
 * import { Handler, responseWrapperMiddleware, setResponseData } from '@noony-serverless/core';
 *
 * const healthCheckHandler = new Handler()
 *   .use(responseWrapperMiddleware<{ status: string; uptime: number }>())
 *   .handle(async (context) => {
 *     setResponseData(context, {
 *       status: 'healthy',
 *       uptime: process.uptime()
 *     });
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
 *     setResponseData(context, {
 *       id: newUser.id,
 *       message: 'User created successfully'
 *     });
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
 *     setResponseData(context, {
 *       orderId: order.id,
 *       status: order.status,
 *       estimatedDelivery: order.estimatedDelivery
 *     });
 *   });
 * ```
 */
export const responseWrapperMiddleware = <T>(): BaseMiddleware => ({
  after: async (context: Context): Promise<void> => {
    wrapResponse<T>(context);
  },
});

/**
 * Helper function to set response data in context for later wrapping.
 * This function should be used in handlers when using ResponseWrapperMiddleware.
 *
 * @template T - The type of data being set
 * @param context - The request context
 * @param data - The data to be included in the response payload
 *
 * @example
 * Setting simple response data:
 * ```typescript
 * import { setResponseData } from '@noony-serverless/core';
 *
 * const handler = new Handler()
 *   .use(responseWrapperMiddleware())
 *   .handle(async (context) => {
 *     const message = "Hello, World!";
 *     setResponseData(context, { message, timestamp: new Date().toISOString() });
 *   });
 * ```
 *
 * @example
 * Setting complex response data:
 * ```typescript
 * const dashboardHandler = new Handler()
 *   .use(responseWrapperMiddleware())
 *   .handle(async (context) => {
 *     const stats = await getDashboardStats(context.user.id);
 *     const notifications = await getNotifications(context.user.id);
 *
 *     setResponseData(context, {
 *       user: context.user,
 *       stats,
 *       notifications,
 *       lastLogin: new Date().toISOString()
 *     });
 *   });
 * ```
 *
 * @example
 * Conditional response data:
 * ```typescript
 * const userProfileHandler = new Handler()
 *   .use(responseWrapperMiddleware())
 *   .handle(async (context) => {
 *     const userId = context.params.id;
 *     const user = await getUser(userId);
 *
 *     if (user) {
 *       setResponseData(context, { user, found: true });
 *     } else {
 *       context.res.status(404);
 *       setResponseData(context, { message: 'User not found', found: false });
 *     }
 *   });
 * ```
 */
export function setResponseData<T>(context: Context, data: T): void {
  context.responseData = data;
}
