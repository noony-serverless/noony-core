import type { Context } from '../core/core';

/**
 * Get a service from the dependency injection container
 *
 * Type-safe utility to resolve services from the TypeDI container
 * without casting.
 *
 * @template T The service type to resolve
 * @param context - Request context containing the DI container
 * @param serviceClass - Service class constructor
 * @returns Service instance
 * @throws Error if container is not initialized
 *
 * @example
 * ```typescript
 * import { getService } from '@noony-serverless/core';
 * import { UserService } from '../services/user.service';
 *
 * export async function createUserController(context: Context<CreateUserRequest>) {
 *   const userService = getService(context, UserService); // Type-safe!
 *
 *   const user = await userService.createUser(context.req.parsedBody);
 *   context.res.status(201).json({ data: user });
 * }
 * ```
 */
export function getService<T>(
  context: Context<unknown, unknown>,
  serviceClass: new (...args: any[]) => T
): T {
  if (!context.container) {
    throw new Error(
      'Container not initialized. Did you forget to add DependencyInjectionMiddleware?'
    );
  }
  return context.container.get(serviceClass);
}
