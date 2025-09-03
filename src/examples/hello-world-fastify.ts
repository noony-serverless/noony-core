/**
 * Production-Ready Fastify Integration Example
 *
 * This example demonstrates a complete production-ready integration of the Noony
 * serverless middleware framework with Fastify, showcasing enterprise patterns.
 *
 * Key Features Demonstrated:
 * 1. Complete TypeScript generics throughout the middleware stack
 * 2. Multi-endpoint API with different authentication requirements
 * 3. Advanced error handling and response standardization
 * 4. Dependency injection with TypeDI for clean architecture
 * 5. Framework-agnostic design (easily portable to Express/Koa/etc.)
 * 6. Production middleware patterns (rate limiting, security headers, audit logging)
 * 7. Query parameter validation and URL parameter handling
 * 8. Comprehensive API documentation patterns
 *
 * Production API Endpoints:
 * POST   /api/users              - Create user (authenticated)
 * GET    /api/users/:id          - Get user by ID (authenticated)
 * GET    /api/users              - List users with pagination (admin only)
 * GET    /health                 - Health check (public)
 *
 * Example Requests:
 * POST /api/users
 * Headers: { "Authorization": "Bearer valid-token", "x-api-version": "v1" }
 * Body: { "name": "John Doe", "email": "john@example.com", "age": 30 }
 *
 * GET /api/users?page=1&limit=10&search=john
 * Headers: { "Authorization": "Bearer valid-admin-token" }
 */

import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { Container } from 'typedi';
import {
  Handler,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  AuthenticationMiddleware,
  HeaderVariablesMiddleware,
  ResponseWrapperMiddleware,
  DependencyInjectionMiddleware,
  QueryParametersMiddleware,
  GenericRequest,
  Context,
  BaseMiddleware,
} from '../core';
import { ValidationError } from '../core/errors';

// Production-ready validation schemas with comprehensive rules
const createUserSchema = z.object({
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name cannot exceed 50 characters')
    .regex(/^[a-zA-Z\s]+$/, 'Name can only contain letters and spaces'),
  email: z
    .string()
    .email('Must be a valid email address')
    .max(100, 'Email cannot exceed 100 characters'),
  age: z
    .number()
    .int('Age must be a whole number')
    .min(18, 'Must be at least 18 years old')
    .max(120, 'Age cannot exceed 120'),
  department: z.string().optional(),
  phoneNumber: z
    .string()
    .regex(/^\+?[\d\s-()]+$/, 'Invalid phone number format')
    .optional(),
});

const getUserParamsSchema = z.object({
  id: z.string().uuid('Must be a valid UUID'),
});

const listUsersQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10),
  search: z.string().optional(),
  department: z.string().optional(),
  sortBy: z.enum(['name', 'email', 'createdAt', 'age']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

// Infer TypeScript types from Zod schemas
type CreateUserRequest = z.infer<typeof createUserSchema>;
type GetUserParams = z.infer<typeof getUserParamsSchema>;
type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;

// Enhanced user entity type for production
interface User {
  id: string;
  name: string;
  email: string;
  age: number;
  department?: string;
  phoneNumber?: string;
  createdAt: string;
  updatedAt?: string;
}

// Authenticated user type for context
interface AuthenticatedUser {
  userId: string;
  role: 'user' | 'admin' | 'moderator';
  permissions: string[];
  email: string;
}

// Enhanced production service with comprehensive features
class UserService {
  private users = new Map<string, User>();
  private emailIndex = new Map<string, string>(); // email -> userId mapping

  createUser(userData: CreateUserRequest): { id: string; user: User } {
    // Check if email already exists
    if (this.emailIndex.has(userData.email)) {
      throw new Error('Email already exists');
    }

    const id = crypto.randomUUID();
    const user: User = {
      id,
      ...userData,
      createdAt: new Date().toISOString(),
    };

    this.users.set(id, user);
    this.emailIndex.set(userData.email, id);

    return { id, user };
  }

  getUserById(id: string): User | null {
    return this.users.get(id) || null;
  }

  updateUser(id: string, updateData: Partial<CreateUserRequest>): User | null {
    const user = this.users.get(id);
    if (!user) return null;

    const updatedUser: User = {
      ...user,
      ...updateData,
      updatedAt: new Date().toISOString(),
    };

    this.users.set(id, updatedUser);
    return updatedUser;
  }

  deleteUser(id: string): boolean {
    const user = this.users.get(id);
    if (!user) return false;

    this.users.delete(id);
    this.emailIndex.delete(user.email);
    return true;
  }

  getAllUsers(query: ListUsersQuery): {
    users: User[];
    total: number;
    pagination: {
      page: number;
      limit: number;
      totalPages: number;
      hasNextPage: boolean;
      hasPreviousPage: boolean;
    };
  } {
    let users = Array.from(this.users.values());

    // Apply search filter
    if (query.search) {
      const searchTerm = query.search.toLowerCase();
      users = users.filter(
        (user) =>
          user.name.toLowerCase().includes(searchTerm) ||
          user.email.toLowerCase().includes(searchTerm)
      );
    }

    // Apply department filter
    if (query.department) {
      users = users.filter((user) => user.department === query.department);
    }

    // Apply sorting
    users.sort((a, b) => {
      const aValue = a[query.sortBy as keyof User] as string;
      const bValue = b[query.sortBy as keyof User] as string;

      if (query.sortOrder === 'asc') {
        return aValue.localeCompare(bValue);
      } else {
        return bValue.localeCompare(aValue);
      }
    });

    const total = users.length;
    const startIndex = (query.page - 1) * query.limit;
    const paginatedUsers = users.slice(startIndex, startIndex + query.limit);

    return {
      users: paginatedUsers,
      total,
      pagination: {
        page: query.page,
        limit: query.limit,
        totalPages: Math.ceil(total / query.limit),
        hasNextPage: startIndex + query.limit < total,
        hasPreviousPage: query.page > 1,
      },
    };
  }
}

// Register service in TypeDI container
Container.set('userService', new UserService());

// Production token verification implementation
const userTokenVerifier = {
  async verifyToken(token: string): Promise<AuthenticatedUser> {
    // Mock JWT verification - replace with actual JWT library (jsonwebtoken, jose, etc.)
    if (token === 'valid-token') {
      return {
        userId: '123',
        role: 'user',
        permissions: ['user:read', 'user:write'],
        email: 'user@example.com',
      };
    }
    if (token === 'valid-admin-token') {
      return {
        userId: 'admin-456',
        role: 'admin',
        permissions: ['user:read', 'user:write', 'user:delete', 'admin:all'],
        email: 'admin@example.com',
      };
    }
    throw new Error('Invalid or expired token');
  },
};

/**
 * Create User Handler - POST /api/users
 * Production-ready handler with comprehensive middleware stack
 */
const createUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new HeaderVariablesMiddleware(['authorization', 'x-api-version']))
  .use(new AuthenticationMiddleware(userTokenVerifier))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(
    new DependencyInjectionMiddleware([
      { id: 'userService', value: new UserService() },
    ])
  )
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as UserService;
    const userData = context.req.validatedBody as CreateUserRequest;
    const currentUser = context.user as AuthenticatedUser;

    try {
      // Business logic with full type safety
      const result = userService.createUser(userData);

      context.res.status(201).json({
        id: result.id,
        user: result.user,
        createdBy: currentUser.userId,
        createdAt: result.user.createdAt,
      });
    } catch (error: unknown) {
      if (error instanceof Error && error.message === 'Email already exists') {
        context.res
          .status(409)
          .json({ error: 'Email address is already in use' });
      } else {
        throw error; // Let ErrorHandlerMiddleware handle it
      }
    }
  });

/**
 * Get User Handler - GET /api/users/:id
 * Demonstrates: URL parameters, query parameters, authentication
 */
const getUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(userTokenVerifier))
  .use(new QueryParametersMiddleware())
  .use(
    new DependencyInjectionMiddleware([
      { id: 'userService', value: new UserService() },
    ])
  )
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as UserService;

    // Extract URL parameters (Fastify specific)
    const { id } = (
      context.req as GenericRequest & {
        params: GetUserParams;
      }
    ).params;

    // Validate the ID parameter
    const validatedParams = getUserParamsSchema.parse({ id });

    // Business logic with full type safety
    const user = userService.getUserById(validatedParams.id);

    if (!user) {
      context.res.status(404).json({ error: 'User not found' });
      return;
    }

    // Include query parameters in response for demonstration
    const queryParams = context.req.query || {};

    context.res.json({
      user,
      queryParams,
      requestedBy: (context.user as AuthenticatedUser).userId,
    });
  });

// Custom query parameter validation middleware
class QueryValidationMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(private querySchema: z.ZodSchema) {}

  async before(context: Context<T, U>): Promise<void> {
    try {
      const validatedQuery = this.querySchema.parse(context.req.query || {});
      context.businessData?.set('validatedQuery', validatedQuery);
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new ValidationError('Invalid query parameters', error.errors);
      }
      throw error;
    }
  }
}

/**
 * List Users Handler - GET /api/users
 * Demonstrates: Query parameter validation, pagination, filtering with admin authentication
 */
const listUsersHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(userTokenVerifier))
  .use(new QueryValidationMiddleware(listUsersQuerySchema))
  .use(
    new DependencyInjectionMiddleware([
      { id: 'userService', value: new UserService() },
    ])
  )
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context) => {
    const userService = Container.get('userService') as UserService;
    const currentUser = context.user as AuthenticatedUser;

    // Check admin permissions
    if (
      !currentUser.permissions.includes('admin:all') &&
      currentUser.role !== 'admin'
    ) {
      context.res.status(403).json({ error: 'Admin access required' });
      return;
    }

    // Get validated query parameters
    const query = context.businessData?.get('validatedQuery') as ListUsersQuery;

    // Business logic with full type safety and pagination
    const result = userService.getAllUsers(query);

    context.res.json({
      users: result.users,
      total: result.total,
      pagination: result.pagination,
      requestedBy: currentUser.userId,
    });
  });

// Type for our handler
interface NoonyHandler {
  execute(req: unknown, res: unknown): Promise<void>;
  executeGeneric?(req: unknown, res: unknown): Promise<void>;
}

// Response adapter interface
interface ResponseAdapter {
  status(code: number): ResponseAdapter;
  json(data: unknown): void;
  send(data: unknown): void;
}

/**
 * Create and configure production-ready Fastify server
 *
 * This demonstrates the framework-agnostic nature of Noony handlers.
 * The same handlers can work with GCP Functions, Express, Koa, or any HTTP framework.
 */
export function createFastifyServer(): ReturnType<typeof Fastify> {
  const fastify = Fastify({
    logger: {
      level: 'info',
    },
    trustProxy: true,
  });

  // Helper function to adapt Fastify request/reply to Noony's GenericRequest/GenericResponse
  const executeHandler = async (
    handler: NoonyHandler,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    // Create GenericRequest-compatible object
    const req = {
      method: request.method,
      url: request.url,
      path: request.url.split('?')[0], // Use URL path instead of routerPath
      headers: request.headers as Record<string, string | string[]>,
      query: (request.query as Record<string, string>) || {},
      params: (request.params as Record<string, string>) || {},
      body: request.body,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    };

    // Create GenericResponse-compatible object
    const res: ResponseAdapter = {
      status: (code: number): ResponseAdapter => {
        reply.status(code);
        return res;
      },
      json: (data: unknown): void => {
        reply.type('application/json').send(data);
      },
      send: (data: unknown): void => {
        reply.send(data);
      },
    };

    try {
      // Use the framework-agnostic executeGeneric method
      if (handler.executeGeneric) {
        await handler.executeGeneric(req, res);
      } else {
        await handler.execute(req, res);
      }
    } catch (error) {
      // This should be caught by ErrorHandlerMiddleware, but just in case
      fastify.log.error('Unhandled error in handler:', error);
      if (!reply.sent) {
        reply.status(500).send({ error: 'Internal Server Error' });
      }
    }
  };

  // Register routes
  fastify.post('/api/users', async (request, reply) => {
    await executeHandler(createUserHandler, request, reply);
  });

  fastify.get('/api/users/:id', async (request, reply) => {
    await executeHandler(getUserHandler, request, reply);
  });

  fastify.get('/api/users', async (request, reply) => {
    await executeHandler(listUsersHandler, request, reply);
  });

  // Health check endpoint
  fastify.get('/health', async (_request, _reply) => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });

  return fastify;
}

/**
 * Start the server (for development/testing)
 */
export async function startServer(port: number = 3000): Promise<void> {
  const server = createFastifyServer();

  try {
    await server.listen({ port, host: '0.0.0.0' });
    console.log(`🚀 Fastify server running on http://localhost:${port}`);
    console.log('\nAvailable endpoints:');
    console.log('POST /api/users - Create a new user');
    console.log('GET /api/users/:id - Get user by ID');
    console.log('GET /api/users - List all users');
    console.log('GET /health - Health check');
    console.log('\nExample request:');
    console.log('curl -X POST http://localhost:3000/api/users \\');
    console.log('  -H "Content-Type: application/json" \\');
    console.log('  -H "Authorization: Bearer valid-token" \\');
    console.log('  -H "x-api-version: v1" \\');
    console.log(
      '  -d \'{"name":"John Doe","email":"john@example.com","age":30}\''
    );
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

// Export handlers for testing
export { createUserHandler, getUserHandler, listUsersHandler };
