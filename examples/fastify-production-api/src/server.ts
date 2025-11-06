import 'reflect-metadata';

/**
 * Fastify Production Server - Dual-Mode Development Setup
 *
 * This server provides a production-ready Fastify HTTP server that runs the same
 * handlers that can be deployed to Google Cloud Functions. This dual-mode approach
 * allows for:
 *
 * 1. **Fast Development**: Rapid iteration with Fastify's hot reload
 * 2. **Production Parity**: Same handlers work in both environments
 * 3. **Rich Debugging**: Full Node.js debugging capabilities
 * 4. **Framework Agnostic**: Noony handlers are portable to any HTTP framework
 *
 * Features Demonstrated:
 * - Complete REST API with authentication
 * - Request/response adaptation between Fastify and Noony
 * - Environment-based configuration
 * - Health checks and monitoring endpoints
 * - Error handling and logging
 * - CORS configuration for development
 *
 * @author Noony Framework Team
 * @version 1.0.0
 */

import Fastify, {
  FastifyRequest,
  FastifyReply,
  FastifyInstance,
} from 'fastify';
import { Container } from 'typedi';
import {
  createUserHandler,
  getUserHandler,
  listUsersHandler,
  updateUserHandler,
  deleteUserHandler,
} from '@/handlers/user.handlers';
import { UserService } from '@/services/user.service';
import { AuthService } from '@/services/auth.service';

/**
 * Handler interface for Noony handlers
 */
interface NoonyHandler {
  execute(req: unknown, res: unknown): Promise<void>;
  executeGeneric?(req: unknown, res: unknown): Promise<void>;
}

/**
 * Response adapter interface for Noony compatibility
 */
interface ResponseAdapter {
  status(code: number): ResponseAdapter;
  json(data: unknown): void;
  send(data: unknown): void;
  statusCode?: number;
}

/**
 * Application configuration loaded from environment
 */
const config = {
  port: parseInt(process.env.FASTIFY_PORT || '3000', 10),
  host: process.env.FASTIFY_HOST || '0.0.0.0',
  environment: process.env.NODE_ENV || 'development',
  logLevel: process.env.LOG_LEVEL || 'info',
  cors: {
    origin: process.env.CORS_ORIGIN?.split(',') || [
      'http://localhost:3000',
      'http://localhost:8080',
    ],
    credentials: process.env.CORS_CREDENTIALS === 'true',
  },
};

/**
 * Create and configure the Fastify server instance
 */
export function createFastifyServer(): FastifyInstance {
  // Create Fastify instance with appropriate configuration
  const fastify = Fastify({
    logger: {
      level: config.logLevel,
    },
    trustProxy: true,
    maxParamLength: 200,
    bodyLimit: 1048576 * 10, // 10MB
  });

  // Register CORS plugin for development
  if (config.environment === 'development') {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cors = require('@fastify/cors');
    fastify.register(cors, {
      origin: config.cors.origin,
      credentials: config.cors.credentials,
    });
  }

  /**
   * Execute Noony handler with Fastify request/response adaptation
   *
   * This function adapts Fastify's request/response objects to work with
   * Noony's framework-agnostic GenericRequest/GenericResponse interfaces.
   *
   * @param handler - Noony handler to execute
   * @param request - Fastify request object
   * @param reply - Fastify reply object
   */
  const executeHandler = async (
    handler: NoonyHandler,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<void> => {
    // Adapt Fastify request to Noony GenericRequest format
    const req = {
      method: request.method,
      url: request.url,
      path: request.url.split('?')[0],
      headers: request.headers as Record<string, string | string[]>,
      query: (request.query as Record<string, string>) || {},
      params: (request.params as Record<string, string>) || {},
      body: request.body,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    };

    // Create response adapter that bridges to Fastify reply
    const res: ResponseAdapter = {
      status: (code: number): ResponseAdapter => {
        reply.status(code);
        res.statusCode = code;
        return res;
      },
      json: (data: unknown): void => {
        reply.type('application/json').send(data);
      },
      send: (data: unknown): void => {
        reply.send(data);
      },
      statusCode: 200,
    };

    try {
      // Execute the Noony handler with adapted request/response
      if (handler.executeGeneric) {
        await handler.executeGeneric(req, res);
      } else {
        await handler.execute(req, res);
      }
    } catch (error) {
      // This should be caught by ErrorHandlerMiddleware, but just in case
      fastify.log.error(`Unhandled error in handler: ${error}`);
      if (!reply.sent) {
        reply.status(500).send({
          success: false,
          payload: { error: 'Internal Server Error' },
          timestamp: new Date().toISOString(),
        });
      }
    }
  };

  // =============================================================================
  // API ROUTES - USER MANAGEMENT
  // =============================================================================

  /**
   * POST /api/users - Create a new user
   * Requires authentication and user:create permission
   */
  fastify.post('/api/users', async (request, reply) => {
    await executeHandler(createUserHandler, request, reply);
  });

  /**
   * GET /api/users/:id - Get user by ID
   * Requires authentication, users can access own profile
   */
  fastify.get('/api/users/:id', async (request, reply) => {
    await executeHandler(getUserHandler, request, reply);
  });

  /**
   * GET /api/users - List users with pagination and filtering
   * Requires authentication and user:list permission
   */
  fastify.get('/api/users', async (request, reply) => {
    await executeHandler(listUsersHandler, request, reply);
  });

  /**
   * PUT /api/users/:id - Update user by ID
   * Requires authentication, users can update own profile
   */
  fastify.put('/api/users/:id', async (request, reply) => {
    await executeHandler(updateUserHandler, request, reply);
  });

  /**
   * DELETE /api/users/:id - Soft delete user by ID
   * Requires authentication and user:delete permission
   */
  fastify.delete('/api/users/:id', async (request, reply) => {
    await executeHandler(deleteUserHandler, request, reply);
  });

  // =============================================================================
  // HEALTH CHECK AND MONITORING ENDPOINTS
  // =============================================================================

  /**
   * GET /health - Basic health check
   * Public endpoint for load balancers and monitoring systems
   */
  fastify.get('/health', async (request, reply) => {
    const userService = Container.get('userService') as UserService;
    const authService = Container.get('authService') as AuthService;

    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '1.0.0',
      environment: config.environment,
      server: 'fastify',
      services: {
        userService: 'healthy',
        authService: 'healthy',
      },
      metrics: {
        memory: process.memoryUsage(),
        userServiceMetrics: userService.getMetrics(),
        authServiceMetrics: authService.getMetrics(),
      },
    };

    reply.send(health);
  });

  /**
   * GET /health/ready - Readiness probe
   * Used by Kubernetes and other orchestrators
   */
  fastify.get('/health/ready', async (request, reply) => {
    // In a real application, this would check database connections,
    // external service availability, etc.
    reply.send({
      status: 'ready',
      timestamp: new Date().toISOString(),
      checks: {
        database: 'ready',
        redis: 'ready',
        externalServices: 'ready',
      },
    });
  });

  /**
   * GET /health/live - Liveness probe
   * Used by Kubernetes to determine if the pod should be restarted
   */
  fastify.get('/health/live', async (request, reply) => {
    reply.send({
      status: 'alive',
      timestamp: new Date().toISOString(),
      pid: process.pid,
      uptime: process.uptime(),
    });
  });

  // =============================================================================
  // DEVELOPMENT AND DEBUGGING ENDPOINTS
  // =============================================================================

  if (config.environment === 'development') {
    /**
     * GET /dev/info - Development information
     * Only available in development mode
     */
    fastify.get('/dev/info', async (request, reply) => {
      reply.send({
        environment: config.environment,
        nodeVersion: process.version,
        fastifyVersion: fastify.version,
        config: {
          port: config.port,
          host: config.host,
          logLevel: config.logLevel,
          cors: config.cors,
        },
        routes: fastify.printRoutes(),
      });
    });

    /**
     * GET /dev/metrics - Service metrics for debugging
     * Only available in development mode
     */
    fastify.get('/dev/metrics', async (request, reply) => {
      const userService = Container.get('userService') as UserService;
      const authService = Container.get('authService') as AuthService;

      reply.send({
        timestamp: new Date().toISOString(),
        process: {
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          uptime: process.uptime(),
        },
        services: {
          userService: userService.getMetrics(),
          authService: authService.getMetrics(),
        },
      });
    });
  }

  // =============================================================================
  // ERROR HANDLING
  // =============================================================================

  /**
   * Global error handler
   * Catches any errors not handled by individual routes
   */
  fastify.setErrorHandler(async (error, request, reply) => {
    fastify.log.error(
      `💥 Unhandled server error: ${error.message} - URL: ${request.url} - Method: ${request.method}`
    );

    const isDevelopment = config.environment === 'development';

    reply.status(error.statusCode || 500).send({
      success: false,
      payload: {
        error: isDevelopment ? error.message : 'Internal Server Error',
        code: 'INTERNAL_ERROR',
        ...(isDevelopment && { stack: error.stack }),
      },
      timestamp: new Date().toISOString(),
    });
  });

  /**
   * 404 Not Found handler
   */
  fastify.setNotFoundHandler(async (request, reply) => {
    reply.status(404).send({
      success: false,
      payload: {
        error: `Route ${request.method} ${request.url} not found`,
        code: 'NOT_FOUND',
        availableRoutes:
          config.environment === 'development'
            ? [
                'POST /api/users',
                'GET /api/users',
                'GET /api/users/:id',
                'PUT /api/users/:id',
                'DELETE /api/users/:id',
                'GET /health',
                'GET /health/ready',
                'GET /health/live',
              ]
            : undefined,
      },
      timestamp: new Date().toISOString(),
    });
  });

  return fastify;
}

/**
 * Start the Fastify server
 *
 * @param port - Port number to listen on
 * @param host - Host to bind to
 */
export async function startServer(
  port: number = config.port,
  host: string = config.host
): Promise<FastifyInstance> {
  const server = createFastifyServer();

  try {
    // Start the server
    await server.listen({ port, host });

    console.log(`🚀 Fastify server running on http://${host}:${port}`);
    console.log(`📊 Environment: ${config.environment}`);
    console.log(`📝 Log level: ${config.logLevel}`);
    console.log('');
    console.log('📋 Available endpoints:');
    console.log(
      `   POST   http://${host}:${port}/api/users                - Create user`
    );
    console.log(
      `   GET    http://${host}:${port}/api/users                - List users`
    );
    console.log(
      `   GET    http://${host}:${port}/api/users/:id            - Get user by ID`
    );
    console.log(
      `   PUT    http://${host}:${port}/api/users/:id            - Update user`
    );
    console.log(
      `   DELETE http://${host}:${port}/api/users/:id            - Delete user`
    );
    console.log(
      `   GET    http://${host}:${port}/health                   - Health check`
    );
    console.log('');
    console.log('🔐 Authentication required for all /api endpoints');
    console.log(
      '💡 Use demo credentials: email="john.doe@example.com", password="password123"'
    );
    console.log('');

    if (config.environment === 'development') {
      console.log('🛠️  Development endpoints:');
      console.log(
        `   GET    http://${host}:${port}/dev/info                - Server info`
      );
      console.log(
        `   GET    http://${host}:${port}/dev/metrics             - Service metrics`
      );
      console.log('');
    }

    return server;
  } catch (err) {
    server.log.error(`Failed to start server: ${err}`);
    process.exit(1);
  }
}

// Start server if this file is run directly
if (require.main === module) {
  startServer().catch((error) => {
    console.error('Server startup failed:', error);
    process.exit(1);
  });
}

export default startServer;
