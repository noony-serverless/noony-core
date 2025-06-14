/**
 * Hello World Example - Fastify Integration
 *
 * This example demonstrates how to integrate the Noony serverless middleware framework
 * with Fastify, a fast and low overhead web framework for Node.js.
 *
 * This shows how to:
 * 1. Create a Fastify server with the Noony middleware system
 * 2. Use multiple middlewares including authentication and validation
 * 3. Handle different HTTP methods and routes
 * 4. Demonstrate error handling across the middleware chain
 * 5. Show how to use dependency injection with TypeDI
 *
 * Usage:
 * POST /api/users
 * Headers: { "Authorization": "Bearer your-jwt-token", "x-api-version": "v1" }
 * Body: { "name": "John Doe", "email": "john@example.com", "age": 30 }
 *
 * GET /api/users/123
 * Headers: { "Authorization": "Bearer your-jwt-token" }
 */

import Fastify, {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from 'fastify';
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
} from '../core';

// Define schemas for different endpoints
const createUserSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Must be a valid email address'),
  age: z.number().min(18, 'Must be at least 18 years old').max(120),
});

const getUserParamsSchema = z.object({
  id: z.string().uuid('Must be a valid UUID'),
});

// Types for better TypeScript support
type CreateUserRequest = z.infer<typeof createUserSchema>;
type GetUserParams = z.infer<typeof getUserParamsSchema>;

// User entity type
interface User {
  id: string;
  name: string;
  email: string;
  age: number;
  createdAt: string;
}

// Mock service for demonstration
class UserService {
  private users = new Map<string, User>();

  createUser(userData: CreateUserRequest): {
    id: string;
    user: User;
  } {
    const id = crypto.randomUUID();
    const user: User = { id, ...userData, createdAt: new Date().toISOString() };
    this.users.set(id, user);
    return { id, user };
  }

  getUserById(id: string): User | null {
    return this.users.get(id) || null;
  }

  getAllUsers(): User[] {
    return Array.from(this.users.values());
  }
}

// Register service in TypeDI container
Container.set('userService', new UserService());

// Token verification implementation
const tokenVerificationPort = {
  async verifyToken(token: string): Promise<{ userId: string; role: string }> {
    // Mock JWT verification - in real app, verify with actual JWT library
    if (token === 'valid-token') {
      return { userId: '123', role: 'user' };
    }
    throw new Error('Invalid token');
  },
};

/**
 * Create User Handler - POST /api/users
 * Demonstrates: Body validation, authentication, dependency injection
 */
const createUserHandler = Handler.use(new ErrorHandlerMiddleware())
  .use(new HeaderVariablesMiddleware(['authorization', 'x-api-version']))
  .use(new AuthenticationMiddleware(tokenVerificationPort))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(
    new DependencyInjectionMiddleware([
      { id: 'userService', value: new UserService() },
    ])
  )
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const userService = Container.get('userService') as UserService;
    const userData = context.req.validatedBody as CreateUserRequest;

    // Business logic
    const result = userService.createUser(userData);

    context.res.status(201).json({
      id: result.id,
      user: result.user,
      createdBy: (context.user as { userId: string })?.userId,
    });
  });

/**
 * Get User Handler - GET /api/users/:id
 * Demonstrates: URL parameters, query parameters, authentication
 */
const getUserHandler = Handler.use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerificationPort))
  .use(new QueryParametersMiddleware())
  .use(
    new DependencyInjectionMiddleware([
      { id: 'userService', value: new UserService() },
    ])
  )
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const userService = Container.get('userService') as UserService;

    // Extract URL parameters (Fastify specific)
    const { id } = (
      context.req as GenericRequest & {
        params: GetUserParams;
      }
    ).params;

    // Validate the ID parameter
    const validatedParams = getUserParamsSchema.parse({ id });

    // Business logic
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
      requestedBy: (context.user as { userId: string })?.userId,
    });
  });

// Admin token verification implementation
const adminTokenVerificationPort = {
  async verifyToken(token: string): Promise<{ userId: string; role: string }> {
    // Mock JWT verification - in real app, verify with actual JWT library
    if (token === 'valid-token') {
      return { userId: '123', role: 'admin' };
    }
    throw new Error('Invalid token');
  },
};

/**
 * List Users Handler - GET /api/users
 * Demonstrates: Simple GET endpoint with authentication
 */
const listUsersHandler = Handler.use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(adminTokenVerificationPort))
  .use(new QueryParametersMiddleware())
  .use(
    new DependencyInjectionMiddleware([
      { id: 'userService', value: new UserService() },
    ])
  )
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const userService = Container.get('userService') as UserService;

    // Business logic
    const users = userService.getAllUsers();
    const queryParams = context.req.query || {};

    // Simple filtering based on query parameters
    let filteredUsers = users;
    if (queryParams.name) {
      filteredUsers = users.filter((user: User) =>
        user.name
          .toLowerCase()
          .includes((queryParams.name as string).toLowerCase())
      );
    }

    context.res.json({
      users: filteredUsers,
      total: filteredUsers.length,
      filters: queryParams,
    });
  });

// Type for our handler
interface NoonyHandler {
  execute(req: unknown, res: unknown): Promise<void>;
}

// Response adapter interface
interface ResponseAdapter {
  status(code: number): ResponseAdapter;
  json(data: unknown): void;
  send(data: unknown): void;
}

/**
 * Create and configure Fastify server
 */
export function createFastifyServer(): FastifyInstance {
  const fastify = Fastify({
    logger: true,
  });

  // Helper function to convert Fastify request/reply to our handler format
  const executeHandler = async (
    handler: NoonyHandler,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    // Create a request object compatible with our middleware system
    const req = {
      ...request,
      headers: request.headers,
      body: request.body,
      query: request.query,
      params: request.params,
    };

    // Create a response object compatible with our middleware system
    const res: ResponseAdapter = {
      status: (code: number): ResponseAdapter => {
        reply.status(code);
        return res;
      },
      json: (data: unknown): void => {
        reply.send(data);
      },
      send: (data: unknown): void => {
        reply.send(data);
      },
    };

    try {
      await handler.execute(req, res);
    } catch (error) {
      reply.status(500).send({ error: 'Internal Server Error' });
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
