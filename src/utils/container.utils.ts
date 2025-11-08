import type { Context } from '../core/core';

/**
 * Get a service from the dependency injection container
 *
 * Type-safe utility to resolve services from the TypeDI container.
 * Supports both class constructors and string identifiers.
 *
 * @template T The service type to resolve
 * @param context - Request context containing the DI container
 * @param serviceIdentifier - Service class constructor OR string identifier
 * @returns Service instance
 * @throws Error if container is not initialized
 *
 * @example
 * ```typescript
 * import { getService } from '@noony-serverless/core';
 * import { UserService } from '../services/user.service';
 *
 * // ✅ Best: Class-based access (type inferred automatically)
 * export async function handler(context: Context) {
 *   const userService = getService(context, UserService);
 *   // userService is typed as UserService automatically
 *   const users = await userService.getUsers();
 * }
 *
 * // ✅ Good: String-based with explicit generic (when manual instantiation required)
 * export async function handler(context: Context) {
 *   const planRepo = getService<ActionPlanRepository>(context, 'ActionPlanRepository');
 *   // planRepo is typed as ActionPlanRepository via explicit generic
 *   const plan = await planRepo.findById(id);
 * }
 *
 * // ⚠️ Avoid: String without generic (only for quick prototypes)
 * export async function handler(context: Context) {
 *   const repo = getService(context, 'ActionPlanRepository');
 *   // repo has type 'unknown' - requires manual type assertion
 * }
 * ```
 */
export function getService<T>(
  context: Context<unknown, unknown>,
  serviceIdentifier: (new (...args: any[]) => T) | string
): T {
  if (!context.container) {
    throw new Error(
      'Container not initialized. Did you forget to add DependencyInjectionMiddleware?'
    );
  }
  return context.container.get(serviceIdentifier as any);
}
