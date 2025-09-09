/* eslint-disable @typescript-eslint/no-explicit-any */

import { Container } from 'typedi';
import { BaseMiddleware, Context } from '../core';

/**
 * Middleware to inject dependencies into the request context using typedi.
 * This allows handlers to access shared services or data via context.container.
 * Example usage:
 *  // Initialize services
 * const services = [
 *   { id: 'businessData', value: new Map<string, any>() },
 *   { id: UserService, value: new UserService(new Map<string, any>()) }
 * ];
 *
 * // Create an instance of DependencyInjectionMiddleware with the services
 * const diMiddleware = new DependencyInjectionMiddleware(services);
 *
 * // Example handler using the middleware
 * const exampleHandler = new Handler()
 *   .use(diMiddleware)
 *   .use(errorHandler())
 *   .use(responseWrapperMiddleware<any>())
 *   .handle(async (context: Context) => {
 *     const businessData = context.container?.get('businessData');
 *     setResponseData(context, { message: 'Dependency Injection Middleware example', businessData });
 *   });
 */
export class DependencyInjectionMiddleware implements BaseMiddleware {
  constructor(private services: { id: any; value: any }[]) {}

  async before(context: Context): Promise<void> {
    this.services.forEach((service) => {
      Container.set(service.id, service.value);
    });
    context.container = Container;
  }
}

export const dependencyInjection = (
  services: { id: any; value: any }[] = []
): BaseMiddleware => ({
  before: async (context: Context): Promise<void> => {
    services.forEach((service) => {
      Container.set(service.id, service.value);
    });
    context.container = Container.of();
  },
});

/*
// Initialize services
const services = [
  { id: 'businessData', value: new Map<string, any>() },
  { id: UserService, value: new UserService(new Map<string, any>()) }
];

// Create an instance of DependencyInjectionMiddleware with the services
const diMiddleware = new DependencyInjectionMiddleware(services);

// Example handler using the middleware
const exampleHandler = new Handler()
  .use(diMiddleware)
  .use(errorHandler())
  .use(responseWrapperMiddleware<any>())
  .handle(async (context: Context) => {
    const businessData = context.container?.get('businessData');
    setResponseData(context, { message: 'Dependency Injection Middleware example', businessData });
  });
*/
