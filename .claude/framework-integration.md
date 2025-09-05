# Noony Framework Integration Rules

## Google Cloud Functions Integration

### Legacy GCP Functions Pattern

```typescript
// ✅ CORRECT: Standard GCP Functions integration
import { http, HttpFunction } from '@google-cloud/functions-framework';
import { Handler, ErrorHandlerMiddleware, ResponseWrapperMiddleware } from '@noony-serverless/core';

// Create handler with middleware pipeline
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware<CreateUserRequest, AuthenticatedUser>(tokenValidator))
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .use(new ResponseWrapperMiddleware<CreateUserRequest, AuthenticatedUser>())
  .handle(async (context) => {
    const userData = context.req.validatedBody!;
    const user = await userService.createUser(userData);
    context.res.status(201).json({ user });
  });

// Export as GCP Function using .execute()
export const createUser: HttpFunction = http('createUser', (req, res) => {
  return createUserHandler.execute(req, res);
});

// Alternative shorter syntax
export const updateUser: HttpFunction = http('updateUser', 
  new Handler<UpdateUserRequest, AuthenticatedUser>()
    .use(new ErrorHandlerMiddleware<UpdateUserRequest, AuthenticatedUser>())
    .use(new AuthenticationMiddleware<UpdateUserRequest, AuthenticatedUser>(tokenValidator))
    .use(new BodyValidationMiddleware<UpdateUserRequest, AuthenticatedUser>(updateUserSchema))
    .handle(async (context) => {
      // Business logic
    })
    .execute
);
```

### GCP Functions with Pub/Sub

```typescript
import { cloudEvent, CloudEventFunction } from '@google-cloud/functions-framework';

interface PubSubMessage {
  eventType: string;
  data: any;
  timestamp: string;
}

const processEventHandler = new Handler<PubSubMessage, unknown>()
  .use(new ErrorHandlerMiddleware<PubSubMessage, unknown>())
  .use(new BodyParserMiddleware<PubSubMessage, unknown>())
  .handle(async (context) => {
    const message = context.req.parsedBody!;
    
    switch (message.eventType) {
      case 'user.created':
        await emailService.sendWelcomeEmail(message.data.email);
        break;
      case 'order.completed':
        await inventoryService.updateStock(message.data.items);
        break;
      default:
        console.warn(`Unknown event type: ${message.eventType}`);
    }
    
    context.res.status(200).send('OK');
  });

export const processEvent: CloudEventFunction = cloudEvent('processEvent', (cloudEvent) => {
  // Convert CloudEvent to standard request format
  const adaptedRequest = {
    body: cloudEvent.data,
    headers: {},
    method: 'POST',
    path: '/event'
  };
  
  const adaptedResponse = {
    status: (code: number) => ({ statusCode: code }),
    json: (data: any) => data,
    send: (data: any) => data
  };
  
  return processEventHandler.executeGeneric(adaptedRequest as any, adaptedResponse as any);
});
```

### GCP Functions with Cold Start Optimization

```typescript
// Initialize services during cold start for better performance
let initialized = false;
const initializeServices = async () => {
  if (initialized) return;
  
  // Initialize database connections
  await DatabaseConfig.initialize();
  
  // Initialize guard system
  await RouteGuards.configure(
    GuardConfiguration.production(),
    new DatabasePermissionSource(),
    new JWTTokenValidator(),
    { jwtSecret: process.env.JWT_SECRET }
  );
  
  // Pre-warm container pool
  containerPool.register([
    UserService,
    EmailService,
    OrderService
  ]);
  
  initialized = true;
};

// ✅ CORRECT: Cold start optimization pattern
export const optimizedFunction: HttpFunction = http('optimizedFunction', async (req, res) => {
  // Initialize only on cold start
  await initializeServices();
  
  const handler = new Handler<RequestType, UserType>()
    .use(new ErrorHandlerMiddleware<RequestType, UserType>())
    .use(RouteGuards.requirePermissions(['function:execute']))
    .handle(async (context) => {
      // Business logic using pre-initialized services
      const service = containerPool.get(UserService);
      const result = await service.process(context.req.validatedBody!);
      context.res.json(result);
    });
  
  return handler.execute(req, res);
});
```

## Fastify Integration

### Basic Fastify Setup

```typescript
// server.ts - Fastify server with Noony handlers
import Fastify, { FastifyInstance } from 'fastify';
import { Handler } from '@noony-serverless/core';

const fastify: FastifyInstance = Fastify({
  logger: true
});

// Helper function to convert Noony handlers to Fastify routes
const noonyRoute = <T, U>(handler: Handler<T, U>) => {
  return async (request: any, reply: any) => {
    // Fastify request/response are already compatible with GenericRequest/GenericResponse
    return handler.executeGeneric(request, reply);
  };
};

// Register routes with Noony handlers
fastify.post('/users', noonyRoute(
  new Handler<CreateUserRequest, AuthenticatedUser>()
    .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
    .use(RouteGuards.requirePermissions(['user:create']))
    .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
    .handle(async (context) => {
      const userData = context.req.validatedBody!;
      const user = await userService.createUser(userData);
      context.res.status(201).json({ user });
    })
));

fastify.get('/users/:id', noonyRoute(
  new Handler<unknown, AuthenticatedUser>()
    .use(new ErrorHandlerMiddleware<unknown, AuthenticatedUser>())
    .use(RouteGuards.requirePermissions(['user:read']))
    .handle(async (context) => {
      const userId = context.req.params?.id;
      const user = await userService.findById(userId);
      if (!user) {
        throw new ValidationError('User not found');
      }
      context.res.json({ user });
    })
));

// Start server
const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
    console.log('Server running at http://localhost:3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
```

### Fastify with Route Organization

```typescript
// routes/users.ts - Organized route handlers
import { FastifyInstance } from 'fastify';
import { Handler } from '@noony-serverless/core';

export async function userRoutes(fastify: FastifyInstance) {
  // Route-specific middleware setup
  const createAuthenticatedHandler = <T>() => 
    new Handler<T, AuthenticatedUser>()
      .use(new ErrorHandlerMiddleware<T, AuthenticatedUser>())
      .use(RouteGuards.requireAuth());

  // User CRUD routes
  fastify.post<{ Body: CreateUserRequest }>('/users', {
    schema: {
      body: createUserSchema,
      response: {
        201: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            user: { type: 'object' }
          }
        }
      }
    }
  }, async (request, reply) => {
    const handler = createAuthenticatedHandler<CreateUserRequest>()
      .use(RouteGuards.requirePermissions(['user:create']))
      .use(new BodyValidationMiddleware(createUserSchema))
      .handle(async (context) => {
        const userData = context.req.validatedBody!;
        const user = await userService.createUser(userData);
        context.res.status(201).json({ success: true, user });
      });

    return handler.executeGeneric(request, reply);
  });

  fastify.get<{ Params: { id: string } }>('/users/:id', async (request, reply) => {
    const handler = createAuthenticatedHandler<unknown>()
      .use(RouteGuards.requirePermissions(['user:read']))
      .handle(async (context) => {
        const { id } = context.req.params!;
        const user = await userService.findById(id);
        if (!user) {
          throw new ValidationError('User not found');
        }
        context.res.json({ success: true, user });
      });

    return handler.executeGeneric(request, reply);
  });

  fastify.put<{ Params: { id: string }, Body: UpdateUserRequest }>('/users/:id', async (request, reply) => {
    const handler = createAuthenticatedHandler<UpdateUserRequest>()
      .use(RouteGuards.requirePermissions(['user:update']))
      .use(new BodyValidationMiddleware(updateUserSchema))
      .handle(async (context) => {
        const { id } = context.req.params!;
        const updateData = context.req.validatedBody!;
        const user = await userService.updateUser(id, updateData);
        context.res.json({ success: true, user });
      });

    return handler.executeGeneric(request, reply);
  });

  fastify.delete<{ Params: { id: string } }>('/users/:id', async (request, reply) => {
    const handler = createAuthenticatedHandler<unknown>()
      .use(RouteGuards.requirePermissions(['user:delete']))
      .handle(async (context) => {
        const { id } = context.req.params!;
        await userService.deleteUser(id);
        context.res.status(204).send();
      });

    return handler.executeGeneric(request, reply);
  });
}
```

### Production Fastify Configuration

```typescript
// app.ts - Production-ready Fastify setup
import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Handler } from '@noony-serverless/core';

// Create Fastify instance with production settings
const createApp = (): FastifyInstance => {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
      serializers: {
        req: (req) => ({
          method: req.method,
          url: req.url,
          headers: req.headers,
          remoteAddress: req.ip
        })
      }
    },
    trustProxy: true,
    bodyLimit: 1048576, // 1MB
    keepAliveTimeout: 30000
  });

  // Register plugins
  app.register(require('@fastify/cors'), {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
  });

  app.register(require('@fastify/helmet'), {
    contentSecurityPolicy: false // Customize as needed
  });

  app.register(require('@fastify/rate-limit'), {
    max: 100,
    timeWindow: '1 minute'
  });

  // Global error handler that works with Noony errors
  app.setErrorHandler(async (error, request, reply) => {
    // Noony error handler middleware will have already processed the error
    // This is just a fallback for any unhandled errors
    request.log.error(error);
    
    if (!reply.sent) {
      reply.status(500).send({
        success: false,
        error: {
          type: 'internal_error',
          message: 'An unexpected error occurred'
        }
      });
    }
  });

  return app;
};

// Application startup
const start = async () => {
  const app = createApp();

  // Initialize services
  await initializeServices();

  // Register routes
  await app.register(userRoutes, { prefix: '/api/v1' });
  await app.register(orderRoutes, { prefix: '/api/v1' });

  // Health check endpoint
  app.get('/health', async (request, reply) => {
    const health = await RouteGuards.healthCheck();
    reply.status(health.status === 'healthy' ? 200 : 503).send(health);
  });

  // Start server
  const port = parseInt(process.env.PORT || '3000');
  const host = process.env.HOST || '0.0.0.0';

  try {
    await app.listen({ port, host });
    console.log(`🚀 Server running at http://${host}:${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

if (require.main === module) {
  start();
}

export { createApp };
```

## Express Integration

### Express Middleware Adapter

```typescript
// adapters/express-adapter.ts - Convert Noony handlers to Express middleware
import { Request, Response, NextFunction } from 'express';
import { Handler } from '@noony-serverless/core';

export const noonyMiddleware = <T, U>(handler: Handler<T, U>) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Express objects are compatible with GenericRequest/GenericResponse
      await handler.executeGeneric(req as any, res as any);
      
      // If response wasn't sent, continue to next middleware
      if (!res.headersSent) {
        next();
      }
    } catch (error) {
      // Pass error to Express error handling
      next(error);
    }
  };
};

// Usage in Express routes
import express from 'express';
const app = express();

app.use(express.json());

app.post('/users', 
  noonyMiddleware(
    new Handler<CreateUserRequest, AuthenticatedUser>()
      .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
      .use(RouteGuards.requirePermissions(['user:create']))
      .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
      .handle(async (context) => {
        const userData = context.req.validatedBody!;
        const user = await userService.createUser(userData);
        context.res.status(201).json({ user });
      })
  )
);

// Express error handler to work with Noony errors
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  // Noony errors are already handled by ErrorHandlerMiddleware
  // This is just for any unhandled errors
  console.error('Unhandled error:', error);
  
  if (!res.headersSent) {
    res.status(500).json({
      success: false,
      error: {
        type: 'internal_error',
        message: 'An unexpected error occurred'
      }
    });
  }
});

app.listen(3000, () => {
  console.log('Express server running on port 3000');
});
```

### Express Router Organization

```typescript
// routes/user-router.ts - Express router with Noony handlers
import { Router } from 'express';
import { noonyMiddleware } from '../adapters/express-adapter';

const userRouter = Router();

// Create common handler factory
const createUserHandler = <T>() =>
  new Handler<T, AuthenticatedUser>()
    .use(new ErrorHandlerMiddleware<T, AuthenticatedUser>())
    .use(RouteGuards.requireAuth());

userRouter.post('/', 
  noonyMiddleware(
    createUserHandler<CreateUserRequest>()
      .use(RouteGuards.requirePermissions(['user:create']))
      .use(new BodyValidationMiddleware(createUserSchema))
      .handle(async (context) => {
        const userData = context.req.validatedBody!;
        const user = await userService.createUser(userData);
        context.res.status(201).json({ success: true, user });
      })
  )
);

userRouter.get('/:id',
  noonyMiddleware(
    createUserHandler<unknown>()
      .use(RouteGuards.requirePermissions(['user:read']))
      .handle(async (context) => {
        const { id } = context.req.params!;
        const user = await userService.findById(id);
        if (!user) {
          throw new ValidationError('User not found');
        }
        context.res.json({ success: true, user });
      })
  )
);

export { userRouter };
```

## AWS Lambda Integration

### Lambda Handler Pattern

```typescript
// lambda/user-handler.ts - AWS Lambda integration
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context as LambdaContext } from 'aws-lambda';
import { Handler } from '@noony-serverless/core';

// Convert Lambda event to GenericRequest
const adaptLambdaRequest = (event: APIGatewayProxyEvent): any => ({
  method: event.httpMethod,
  url: event.path,
  path: event.path,
  headers: event.headers || {},
  query: event.queryStringParameters || {},
  params: event.pathParameters || {},
  body: event.body ? JSON.parse(event.body) : undefined,
  ip: event.requestContext.identity.sourceIp
});

// Convert to Lambda response
const adaptLambdaResponse = (): any => {
  let response: APIGatewayProxyResult = {
    statusCode: 200,
    headers: {},
    body: ''
  };

  return {
    status: (code: number) => {
      response.statusCode = code;
      return this;
    },
    json: (data: any) => {
      response.headers!['Content-Type'] = 'application/json';
      response.body = JSON.stringify(data);
    },
    header: (name: string, value: string) => {
      response.headers![name] = value;
      return this;
    },
    getResponse: () => response
  };
};

export const createUser = async (
  event: APIGatewayProxyEvent,
  lambdaContext: LambdaContext
): Promise<APIGatewayProxyResult> => {
  const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
    .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
    .use(RouteGuards.requirePermissions(['user:create']))
    .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
    .handle(async (context) => {
      const userData = context.req.validatedBody!;
      const user = await userService.createUser(userData);
      context.res.status(201).json({ user });
    });

  const req = adaptLambdaRequest(event);
  const res = adaptLambdaResponse();

  try {
    await handler.executeGeneric(req, res);
    return res.getResponse();
  } catch (error) {
    console.error('Lambda handler error:', error);
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        success: false,
        error: {
          type: 'internal_error',
          message: 'An unexpected error occurred'
        }
      })
    };
  }
};
```

## Azure Functions Integration

### Azure Functions HTTP Trigger

```typescript
// azure/user-function.ts - Azure Functions integration
import { AzureFunction, Context as AzureContext, HttpRequest } from '@azure/functions';
import { Handler } from '@noony-serverless/core';

// Adapt Azure HTTP request to GenericRequest
const adaptAzureRequest = (req: HttpRequest): any => ({
  method: req.method || 'GET',
  url: req.url,
  path: req.url,
  headers: req.headers || {},
  query: req.query || {},
  params: req.params || {},
  body: req.body,
  rawBody: req.rawBody
});

// Adapt to Azure response
const adaptAzureResponse = (context: AzureContext): any => ({
  status: (code: number) => {
    context.res = { ...context.res, status: code };
    return this;
  },
  json: (data: any) => {
    context.res = {
      ...context.res,
      headers: { 'Content-Type': 'application/json' },
      body: data
    };
  },
  header: (name: string, value: string) => {
    context.res = {
      ...context.res,
      headers: { ...context.res?.headers, [name]: value }
    };
    return this;
  }
});

const httpTrigger: AzureFunction = async (context: AzureContext, req: HttpRequest): Promise<void> => {
  const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
    .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
    .use(RouteGuards.requirePermissions(['user:create']))
    .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
    .handle(async (handlerContext) => {
      const userData = handlerContext.req.validatedBody!;
      const user = await userService.createUser(userData);
      handlerContext.res.status(201).json({ user });
    });

  try {
    const adaptedReq = adaptAzureRequest(req);
    const adaptedRes = adaptAzureResponse(context);
    
    await handler.executeGeneric(adaptedReq, adaptedRes);
  } catch (error) {
    context.log.error('Azure function error:', error);
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: {
        success: false,
        error: {
          type: 'internal_error',
          message: 'An unexpected error occurred'
        }
      }
    };
  }
};

export default httpTrigger;
```

## Framework-Agnostic Best Practices

### Universal Handler Factory

```typescript
// utils/handler-factory.ts - Framework-agnostic handler creation
export class HandlerFactory {
  static createAuthenticatedHandler<T>(
    permissions: string[] = [],
    validationSchema?: z.ZodSchema<T>
  ): Handler<T, AuthenticatedUser> {
    const handler = new Handler<T, AuthenticatedUser>()
      .use(new ErrorHandlerMiddleware<T, AuthenticatedUser>())
      .use(RouteGuards.requireAuth());

    if (permissions.length > 0) {
      handler.use(RouteGuards.requirePermissions(permissions));
    }

    if (validationSchema) {
      handler.use(new BodyValidationMiddleware<T, AuthenticatedUser>(validationSchema));
    }

    return handler.use(new ResponseWrapperMiddleware<T, AuthenticatedUser>());
  }

  static createPublicHandler<T>(
    validationSchema?: z.ZodSchema<T>
  ): Handler<T, unknown> {
    const handler = new Handler<T, unknown>()
      .use(new ErrorHandlerMiddleware<T, unknown>());

    if (validationSchema) {
      handler.use(new BodyValidationMiddleware<T, unknown>(validationSchema));
    }

    return handler.use(new ResponseWrapperMiddleware<T, unknown>());
  }

  static createAdminHandler<T>(
    validationSchema?: z.ZodSchema<T>
  ): Handler<T, AuthenticatedUser> {
    return this.createAuthenticatedHandler(['admin.*'], validationSchema);
  }
}

// Usage across different frameworks
const createUserHandler = HandlerFactory
  .createAuthenticatedHandler(['user:create'], createUserSchema)
  .handle(async (context) => {
    const userData = context.req.validatedBody!;
    const user = await userService.createUser(userData);
    context.res.status(201).json({ user });
  });

// Works with GCP Functions
export const gcpCreateUser = http('createUser', (req, res) => 
  createUserHandler.execute(req, res)
);

// Works with Fastify
fastify.post('/users', async (request, reply) => 
  createUserHandler.executeGeneric(request, reply)
);

// Works with Express
app.post('/users', noonyMiddleware(createUserHandler));
```

### Environment Detection and Optimization

```typescript
// utils/environment.ts - Detect runtime environment and optimize accordingly
export class EnvironmentAdapter {
  static isServerless(): boolean {
    return !!(
      process.env.VERCEL ||
      process.env.AWS_LAMBDA_FUNCTION_NAME ||
      process.env.GOOGLE_CLOUD_PROJECT ||
      process.env.AZURE_FUNCTIONS_ENVIRONMENT
    );
  }

  static getOptimalConfiguration() {
    const isServerless = this.isServerless();
    
    return {
      useContainerPool: isServerless,
      cacheStrategy: isServerless ? 'memory' : 'redis',
      logLevel: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
      enablePerformanceMonitoring: !isServerless, // Less overhead in traditional servers
      coldStartOptimization: isServerless
    };
  }

  static async initializeForEnvironment() {
    const config = this.getOptimalConfiguration();

    if (config.coldStartOptimization) {
      // Pre-warm services for serverless
      await this.preWarmServices();
    }

    // Configure based on environment
    await this.configureServices(config);
  }

  private static async preWarmServices() {
    // Initialize database connections
    await DatabaseConfig.initialize();
    
    // Pre-warm container pool
    containerPool.register([
      UserService,
      OrderService,
      EmailService
    ]);
  }
}
```

## Best Practices

1. **Use `.executeGeneric()`** for framework-agnostic handlers
2. **Initialize services during cold start** for serverless functions
3. **Create adapter functions** for platform-specific request/response formats
4. **Use handler factories** to reduce code duplication across frameworks
5. **Implement proper error handling** for each platform's error format
6. **Optimize for the target platform** (serverless vs traditional servers)
7. **Use environment detection** to automatically configure optimization
8. **Test handlers across multiple frameworks** to ensure compatibility
9. **Document platform-specific setup** requirements
10. **Consider platform limits** (timeout, memory, payload size) in handler design