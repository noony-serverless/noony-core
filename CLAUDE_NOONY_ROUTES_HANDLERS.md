# Claude Code Rule: Noony Framework - Routes & Handlers

This rule provides guidance for working with the Noony Serverless Framework, emphasizing route creation, handler patterns, and API development best practices.

## 🎯 Framework Overview

**Noony** is a type-safe serverless middleware framework for Google Cloud Functions that provides a Middy-like experience. It's framework-agnostic and supports GCP Functions, Express, Fastify, and other HTTP frameworks.

### Key Concepts
- **Handler<T,U>**: Main orchestrator where T = request type, U = user type
- **RouteGuards**: Advanced authentication & authorization system with 3 permission strategies
- **Context<T,U>**: Type-safe request context with middleware data flow
- **BaseMiddleware**: Lifecycle hooks (before, after, onError)

## 🛡️ Route Handler Creation Patterns

### 1. Basic Route Handler Structure

```typescript
import { Handler, ErrorHandlerMiddleware, BodyValidationMiddleware, ResponseWrapperMiddleware } from '@noony/core';
import { RouteGuards } from '@noony/core';
import { z } from 'zod';

// 1. Define request schema and infer type
const createUserSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  age: z.number().min(18)
});
type CreateUserRequest = z.infer<typeof createUserSchema>;

// 2. Define user type for authentication
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user' | 'moderator';
  permissions: string[];
}

// 3. Create handler with proper middleware chain
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())                    // Always first
  .use(RouteGuards.requirePermissions([               // Authentication + Authorization
    'users.create', 
    'admin.users'
  ]))
  .use(new BodyValidationMiddleware(createUserSchema)) // Request validation
  .use(new ResponseWrapperMiddleware())                // Always last
  .handle(async (context) => {
    // Fully typed access to validated data
    const userData = context.req.validatedBody!;  // Type: CreateUserRequest
    const currentUser = context.user!;            // Type: AuthenticatedUser
    
    // Business logic with complete type safety
    const newUser = await userService.create({
      ...userData,
      createdBy: currentUser.id
    });
    
    return {
      success: true,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email
      }
    };
  });
```

### 2. Standard Middleware Chain Order

**ALWAYS follow this middleware execution order:**

```typescript
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())          // 1. Always first - catches all errors
  .use(RouteGuards.requirePermissions([...]))  // 2. Authentication + Authorization
  .use(new BodyValidationMiddleware(schema))   // 3. Request validation (for POST/PUT)
  .use(new ResponseWrapperMiddleware())        // 4. Always last - formats response
  .handle(async (context) => {
    // Your business logic here
  });
```

## 🔐 Permission-Based Route Handlers

### Plain Permissions (Fastest - O(1) lookups)
For simple permission checks with direct set membership:

```typescript
const getUserHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions([
    'users.read',
    'users.list'
  ]))  // OR logic - user needs ANY of these permissions
  .handle(async (context) => {
    const userId = context.req.params.id;
    return await userService.getById(userId);
  });
```

### Wildcard Permissions (Hierarchical patterns)
For role-based access with pattern matching:

```typescript
const adminReportHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions([
    'admin.*',           // Matches: admin.users, admin.reports, admin.settings
    'reports.*.view'     // Matches: reports.sales.view, reports.analytics.view
  ]))
  .handle(async (context) => {
    return await reportService.generateReport(context.user!.id);
  });
```

### Complex Expression Permissions (Boolean logic)
For advanced permission combinations:

```typescript
const moderatorHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { permission: 'admin.users' },
      { and: [
        { permission: 'moderator.content' },
        { permission: 'moderator.active' }
      ]}
    ]
  }))
  .handle(async (context) => {
    // User has: admin.users OR (moderator.content AND moderator.active)
    return await contentService.moderate(context.user!);
  });
```

## 🔄 Route Integration Patterns

### Google Cloud Functions Integration

```typescript
import { http } from '@google-cloud/functions-framework';

// Export each handler as a GCP Function
export const createUser = http('createUser', (req, res) => {
  return createUserHandler.execute(req, res);
});

export const getUser = http('getUser', (req, res) => {
  return getUserHandler.execute(req, res);
});

export const updateUser = http('updateUser', (req, res) => {
  return updateUserHandler.execute(req, res);
});
```

### Fastify Integration

```typescript
import Fastify from 'fastify';

const fastify = Fastify();

// Helper function for handler integration
const executeHandler = async (handler: Handler<any, any>, request: any, reply: any) => {
  const genericReq = {
    headers: request.headers,
    body: request.body,
    query: request.query,
    params: request.params,
    path: request.url,
    method: request.method
  };
  
  const genericRes = {
    status: (code: number) => reply.status(code),
    json: (data: any) => reply.send(data),
    send: (data: any) => reply.send(data)
  };
  
  await handler.executeGeneric(genericReq, genericRes);
};

// Register routes
fastify.post('/api/users', async (request, reply) => {
  await executeHandler(createUserHandler, request, reply);
});

fastify.get('/api/users/:id', async (request, reply) => {
  await executeHandler(getUserHandler, request, reply);
});

fastify.put('/api/users/:id', async (request, reply) => {
  await executeHandler(updateUserHandler, request, reply);
});

fastify.delete('/api/users/:id', async (request, reply) => {
  await executeHandler(deleteUserHandler, request, reply);
});
```

### Express Integration

```typescript
import express from 'express';

const app = express();

// Generic handler executor for Express
const executeHandler = async (handler: Handler<any, any>, req: express.Request, res: express.Response) => {
  const genericReq = {
    headers: req.headers,
    body: req.body,
    query: req.query,
    params: req.params,
    path: req.path,
    method: req.method
  };
  
  const genericRes = {
    status: (code: number) => res.status(code),
    json: (data: any) => res.json(data),
    send: (data: any) => res.send(data)
  };
  
  await handler.executeGeneric(genericReq, genericRes);
};

// Register routes
app.post('/api/users', (req, res) => executeHandler(createUserHandler, req, res));
app.get('/api/users/:id', (req, res) => executeHandler(getUserHandler, req, res));
app.put('/api/users/:id', (req, res) => executeHandler(updateUserHandler, req, res));
app.delete('/api/users/:id', (req, res) => executeHandler(deleteUserHandler, req, res));
```

## 📋 CRUD Route Handler Patterns

### CREATE Routes (POST)
```typescript
const createResourceSchema = z.object({
  // Define required fields
  name: z.string().min(1),
  description: z.string().optional()
});

const createResourceHandler = new Handler<z.infer<typeof createResourceSchema>, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['resource.create']))
  .use(new BodyValidationMiddleware(createResourceSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const data = context.req.validatedBody!;
    const user = context.user!;
    
    const resource = await resourceService.create({
      ...data,
      createdBy: user.id
    });
    
    return { id: resource.id, ...data };
  });
```

### READ Routes (GET)
```typescript
const getResourceHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions([
    'admin.*',
    'resource.read.own',
    'resource.read.all'
  ]))
  .handle(async (context) => {
    const resourceId = context.req.params.id;
    const user = context.user!;
    
    // Check ownership if not admin
    if (!user.permissions.includes('admin.resources')) {
      const resource = await resourceService.findById(resourceId);
      if (resource.createdBy !== user.id) {
        throw new SecurityError('Access denied to this resource');
      }
    }
    
    return await resourceService.getById(resourceId);
  });
```

### UPDATE Routes (PUT/PATCH)
```typescript
const updateResourceSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().optional()
}).refine(data => Object.keys(data).length > 0, {
  message: "At least one field must be provided"
});

const updateResourceHandler = new Handler<z.infer<typeof updateResourceSchema>, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { permission: 'admin.resources' },
      { and: [
        { permission: 'resource.update.own' },
        { permission: 'resource.read.own' }
      ]}
    ]
  }))
  .use(new BodyValidationMiddleware(updateResourceSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const resourceId = context.req.params.id;
    const updates = context.req.validatedBody!;
    const user = context.user!;
    
    return await resourceService.update(resourceId, updates, user.id);
  });
```

### DELETE Routes (DELETE)
```typescript
const deleteResourceHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions(['admin.*', 'resource.delete']))
  .handle(async (context) => {
    const resourceId = context.req.params.id;
    const user = context.user!;
    
    // Prevent self-deletion for user resources
    if (resourceId === user.id) {
      throw new SecurityError('Cannot delete your own resource');
    }
    
    await resourceService.delete(resourceId);
    return { success: true, message: 'Resource deleted' };
  });
```

## 🔧 Route Handler Configuration

### Guard System Setup (Required)
```typescript
// Configure once at application startup
await RouteGuards.configure(
  { 
    environment: 'production', 
    cacheType: 'memory',
    performance: {
      enableMetrics: true,
      enableAuditTrail: true
    }
  },
  {
    async getUserPermissions(userId: string): Promise<string[]> {
      return await userService.getUserPermissions(userId);
    }
  },
  {
    async verifyToken(token: string): Promise<AuthenticatedUser> {
      return jwt.verify(token, process.env.JWT_SECRET!) as AuthenticatedUser;
    }
  },
  {
    clockToleranceMs: 30000,
    enableTokenBlacklist: true,
    rateLimitConfig: { maxRequestsPerMinute: 100 }
  }
);
```

## ⚡ Performance Best Practices

### Use Performance Decorators
```typescript
import { timed, performanceMonitor } from '@noony/core';

class UserService {
  @timed('user-service-create')
  async create(userData: CreateUserRequest): Promise<User> {
    return await this.repository.save(userData);
  }
  
  @timed('user-service-find')
  async findById(id: string): Promise<User> {
    return await this.repository.findById(id);
  }
}
```

### Monitor Route Performance
```typescript
const handler = new Handler<RequestType, UserType>()
  .use({
    before: async (context) => {
      context.businessData.set('startTime', Date.now());
    },
    after: async (context) => {
      const duration = Date.now() - (context.businessData.get('startTime') as number);
      performanceMonitor.recordMetric('route-duration', duration, {
        route: context.req.path,
        method: context.req.method
      });
    }
  })
  .handle(async (context) => {
    // Business logic
  });
```

## 🚨 Error Handling

### Built-in Error Types
- **ValidationError (400)**: Schema validation failures
- **AuthenticationError (401)**: JWT token issues
- **SecurityError (403)**: Permission denied
- **BusinessError (422)**: Business logic errors
- **TimeoutError (408)**: Request timeouts

### Custom Error Handling
```typescript
const handler = new Handler<RequestType, UserType>()
  .use({
    onError: async (error: Error, context: Context) => {
      if (error instanceof CustomBusinessError) {
        context.res.status(422).json({
          error: 'Business rule violation',
          details: error.details
        });
      }
    }
  })
  .handle(async (context) => {
    // Business logic that might throw CustomBusinessError
  });
```

## 🧪 Testing Routes

### Use Guard System Testing
```bash
# Run comprehensive guard system tests
./test-guards.sh http://localhost:3000

# Tests all three permission strategies:
# 1. Plain Permissions (O(1) Set-based lookups)  
# 2. Wildcard Permissions (Pattern matching with caching)
# 3. Expression Permissions (Boolean logic evaluation)
```

### Development Commands
```bash
# Fast development with Fastify
npm run dev:fastify         # http://localhost:3000

# GCP Functions emulator (production parity)  
npm run dev:functions       # http://localhost:8080

# Run both for comparison
npm run dev:both           # Fastify:3000 + Functions:8080
```

## 📚 Additional Resources

- **Complete Guard Documentation**: See `NOONY_GUARD.md` 
- **Local Development Setup**: See `RUN_LOCALLY.md`
- **Production Examples**: `examples/fastify-production-api/`
- **Testing Guide**: Use `./test-guards.sh` for route validation

---

## Key Reminders

1. **Always use ErrorHandlerMiddleware first** in the middleware chain
2. **Configure RouteGuards system** before using any authentication features
3. **Follow the standard middleware order** for consistent behavior
4. **Use Zod schemas** for request validation and type inference
5. **Implement proper permission strategies** based on your security needs
6. **Test routes with both development modes** (Fastify + Functions)
7. **Monitor performance** with built-in decorators and metrics