/* eslint-disable @typescript-eslint/no-explicit-any */

import { Container } from 'typedi';
import { BaseMiddleware, Context } from '../core';

/**
 * Middleware to inject dependencies into the request context using typedi.
 * This allows handlers to access shared services or data via context.container.
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @implements {BaseMiddleware<TBody, TUser>}
 *
 * @example
 * Basic service injection:
 * ```typescript
 * import { Container } from 'typedi';
 * import { Handler, DependencyInjectionMiddleware } from '@noony-serverless/core';
 *
 * // Define services
 * class UserService {
 *   constructor(private userRepo: Map<string, any>) {}
 *
 *   async findById(id: string) {
 *     return this.userRepo.get(id);
 *   }
 *
 *   async create(userData: any) {
 *     const id = generateId();
 *     this.userRepo.set(id, { id, ...userData });
 *     return { id, ...userData };
 *   }
 * }
 *
 * class EmailService {
 *   async sendWelcomeEmail(email: string) {
 *     console.log(`Sending welcome email to ${email}`);
 *     return { sent: true, email };
 *   }
 * }
 *
 * // Initialize services
 * const services = [
 *   { id: UserService, value: new UserService(new Map()) },
 *   { id: EmailService, value: new EmailService() },
 *   { id: 'config', value: { apiUrl: 'https://api.example.com' } }
 * ];
 *
 * const userHandler = new Handler()
 *   .use(new DependencyInjectionMiddleware(services))
 *   .handle(async (context) => {
 *     const userService = context.container?.get(UserService);
 *     const emailService = context.container?.get(EmailService);
 *     const config = context.container?.get('config');
 *
 *     const user = await userService.create({ name: 'John', email: 'john@example.com' });
 *     await emailService.sendWelcomeEmail(user.email);
 *
 *     return { success: true, user, apiUrl: config.apiUrl };
 *   });
 * ```
 *
 * @example
 * Database and caching services:
 * ```typescript
 * class DatabaseService {
 *   async query(sql: string, params: any[]) {
 *     // Mock database query
 *     return { rows: [{ id: 1, name: 'Test' }] };
 *   }
 * }
 *
 * class CacheService {
 *   private cache = new Map();
 *
 *   get(key: string) {
 *     return this.cache.get(key);
 *   }
 *
 *   set(key: string, value: any, ttl: number = 3600) {
 *     this.cache.set(key, value);
 *     setTimeout(() => this.cache.delete(key), ttl * 1000);
 *   }
 * }
 *
 * const services = [
 *   { id: 'db', value: new DatabaseService() },
 *   { id: 'cache', value: new CacheService() }
 * ];
 *
 * const dataHandler = new Handler()
 *   .use(new DependencyInjectionMiddleware(services))
 *   .handle(async (context) => {
 *     const db = context.container?.get('db');
 *     const cache = context.container?.get('cache');
 *
 *     const cacheKey = `users:${context.params.id}`;
 *     let user = cache.get(cacheKey);
 *
 *     if (!user) {
 *       const result = await db.query('SELECT * FROM users WHERE id = ?', [context.params.id]);
 *       user = result.rows[0];
 *       cache.set(cacheKey, user);
 *     }
 *
 *     return { success: true, user, fromCache: !!cache.get(cacheKey) };
 *   });
 * ```
 *
 * @example
 * Business logic services with complex dependencies:
 * ```typescript
 * class PaymentService {
 *   async processPayment(amount: number, method: string) {
 *     return { transactionId: 'txn_123', status: 'completed', amount };
 *   }
 * }
 *
 * class OrderService {
 *   constructor(
 *     private paymentService: PaymentService,
 *     private emailService: EmailService,
 *     private inventoryService: any
 *   ) {}
 *
 *   async createOrder(orderData: any) {
 *     // Complex business logic
 *     const payment = await this.paymentService.processPayment(orderData.total, orderData.paymentMethod);
 *     await this.emailService.sendWelcomeEmail(orderData.customerEmail);
 *     return { orderId: 'order_123', payment };
 *   }
 * }
 *
 * const paymentService = new PaymentService();
 * const emailService = new EmailService();
 * const inventoryService = { checkStock: () => true };
 *
 * const services = [
 *   { id: PaymentService, value: paymentService },
 *   { id: EmailService, value: emailService },
 *   { id: 'inventory', value: inventoryService },
 *   { id: OrderService, value: new OrderService(paymentService, emailService, inventoryService) }
 * ];
 *
 * const checkoutHandler = new Handler()
 *   .use(new DependencyInjectionMiddleware(services))
 *   .handle(async (context) => {
 *     const orderService = context.container?.get(OrderService);
 *     const order = await orderService.createOrder(context.req.parsedBody);
 *     return { success: true, order };
 *   });
 * ```
 */
export class DependencyInjectionMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  constructor(private services: { id: any; value: any }[]) {}

  async before(context: Context<TBody, TUser>): Promise<void> {
    this.services.forEach((service) => {
      Container.set(service.id, service.value);
    });
    context.container = Container.of();
  }
}

/**
 * Factory function that creates a dependency injection middleware.
 * Creates a new container instance for each request to avoid shared state issues.
 *
 * @template TBody - The type of the request body payload (preserves type chain)
 * @template TUser - The type of the authenticated user (preserves type chain)
 * @param services - Array of service definitions with id and value
 * @returns BaseMiddleware object with dependency injection logic
 *
 * @example
 * Simple services injection:
 * ```typescript
 * import { Handler, dependencyInjection } from '@noony-serverless/core';
 *
 * const logger = {
 *   info: (msg: string) => console.log(`[INFO] ${msg}`),
 *   error: (msg: string) => console.error(`[ERROR] ${msg}`)
 * };
 *
 * const config = {
 *   apiKey: process.env.API_KEY,
 *   environment: process.env.NODE_ENV
 * };
 *
 * const services = [
 *   { id: 'logger', value: logger },
 *   { id: 'config', value: config }
 * ];
 *
 * const apiHandler = new Handler()
 *   .use(dependencyInjection(services))
 *   .handle(async (context) => {
 *     const logger = context.container?.get('logger');
 *     const config = context.container?.get('config');
 *
 *     logger.info(`Processing request in ${config.environment}`);
 *     return { success: true, environment: config.environment };
 *   });
 * ```
 *
 * @example
 * Repository pattern with database:
 * ```typescript
 * class UserRepository {
 *   constructor(private db: any) {}
 *
 *   async findAll() {
 *     return await this.db.users.findMany();
 *   }
 *
 *   async findById(id: string) {
 *     return await this.db.users.findUnique({ where: { id } });
 *   }
 * }
 *
 * const mockDb = {
 *   users: {
 *     findMany: () => Promise.resolve([{ id: '1', name: 'John' }]),
 *     findUnique: ({ where }: any) => Promise.resolve({ id: where.id, name: 'John' })
 *   }
 * };
 *
 * const userRepo = new UserRepository(mockDb);
 *
 * const userHandler = new Handler()
 *   .use(dependencyInjection([
 *     { id: UserRepository, value: userRepo },
 *     { id: 'database', value: mockDb }
 *   ]))
 *   .handle(async (context) => {
 *     const repo = context.container?.get(UserRepository);
 *     const users = await repo.findAll();
 *     return { success: true, users };
 *   });
 * ```
 *
 * @example
 * Empty services for middleware registration:
 * ```typescript
 * // Sometimes you just want to enable DI without initial services
 * const baseHandler = new Handler()
 *   .use(dependencyInjection()) // Empty services array
 *   .use(async (context, next) => {
 *     // Add services dynamically based on request
 *     const requestService = new RequestSpecificService(context.req.headers);
 *     context.container?.set('requestService', requestService);
 *     return next();
 *   })
 *   .handle(async (context) => {
 *     const service = context.container?.get('requestService');
 *     return { success: true, data: service.process() };
 *   });
 * ```
 */
export const dependencyInjection = <TBody = unknown, TUser = unknown>(
  services: { id: any; value: any }[] = []
): BaseMiddleware<TBody, TUser> => ({
  before: async (context: Context<TBody, TUser>): Promise<void> => {
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
