# Noony Framework: Handler & .use() Method Guide

Concise guide focusing on Handler instantiation and middleware chaining with `.use()` method.

## 🎯 Handler Core Pattern

### Handler Instantiation
```typescript
import { Handler } from '@noony/core';

// Generic Handler with type safety
const handler = new Handler<RequestType, UserType>()
  .use(/* middleware */)
  .use(/* middleware */)
  .handle(async (context) => {
    // Business logic here
  });
```

**Generic Types:**
- `T` (RequestType): Type of validated request body
- `U` (UserType): Type of authenticated user data
- Types flow through entire middleware chain

## 🔗 Essential .use() Patterns

### 1. Standard Middleware Chain
```typescript
const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())                    // 1. Always first
  .use(RouteGuards.requirePermissions(['users.create']))// 2. Authentication
  .use(new BodyValidationMiddleware(userSchema))        // 3. Validation  
  .use(new ResponseWrapperMiddleware())                 // 4. Always last
  .handle(async (context) => {
    const userData = context.req.validatedBody!;  // Fully typed
    const currentUser = context.user!;            // Fully typed
    return await userService.create(userData);
  });
```

### 2. Class-Based Middleware with .use()
```typescript
// Use pre-built middleware classes
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new ResponseWrapperMiddleware());
```

### 3. RouteGuards with .use()

**Plain Permissions (O(1) lookups):**
```typescript
const handler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions([
    'users.read',
    'admin.users'
  ]))  // OR logic - user needs ANY permission
  .handle(async (context) => {
    return await userService.getById(context.req.params.id);
  });
```

**Wildcard Permissions:**
```typescript
const handler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions([
    'admin.*',           // Matches admin.users, admin.reports, etc.
    'department.*.read'  // Matches department.hr.read, department.sales.read
  ]))
  .handle(async (context) => {
    return await reportService.generate(context.user!.id);
  });
```

**Complex Expression Permissions:**
```typescript
const handler = new Handler<{}, AuthenticatedUser>()
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

### 4. Object-Based Middleware with .use()
```typescript
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use({
    before: async (context) => {
      console.log(`Request started: ${context.requestId}`);
      context.businessData.set('startTime', Date.now());
    },
    after: async (context) => {
      const duration = Date.now() - (context.businessData.get('startTime') as number);
      console.log(`Request completed in ${duration}ms`);
    },
    onError: async (error, context) => {
      console.error(`Request ${context.requestId} failed:`, error.message);
    }
  })
  .handle(async (context) => {
    // Business logic
  });
```

### 5. Performance Monitoring with .use()
```typescript
import { performanceMonitor } from '@noony/core';

const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use({
    before: async (context) => {
      context.businessData.set('perfStartTime', Date.now());
    },
    after: async (context) => {
      const duration = Date.now() - (context.businessData.get('perfStartTime') as number);
      performanceMonitor.recordMetric('route-duration', duration, {
        route: context.req.path,
        method: context.req.method
      });
    }
  })
  .use(RouteGuards.requirePermissions(['api.access']))
  .handle(async (context) => {
    return await businessService.process(context.req);
  });
```

## 🔄 Handler Execution Methods

### For Google Cloud Functions
```typescript
import { http } from '@google-cloud/functions-framework';

export const createUser = http('createUser', (req, res) => {
  return handler.execute(req, res);
});
```

### For Express/Fastify (Generic)
```typescript
// Generic execution for any framework
const executeHandler = async (request: any, reply: any) => {
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
    json: (data: any) => reply.send(data)
  };
  
  await handler.executeGeneric(genericReq, genericRes);
};

// Fastify route
fastify.post('/api/users', executeHandler);
```

## 📋 Common Handler + .use() Patterns

### CRUD Handler Patterns

**CREATE Handler:**
```typescript
const createSchema = z.object({
  name: z.string().min(1),
  email: z.string().email()
});

const createHandler = new Handler<z.infer<typeof createSchema>, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['resource.create']))
  .use(new BodyValidationMiddleware(createSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const data = context.req.validatedBody!;
    return await resourceService.create(data);
  });
```

**READ Handler:**
```typescript
const readHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions(['admin.*', 'resource.read.*']))
  .handle(async (context) => {
    const id = context.req.params.id;
    return await resourceService.getById(id);
  });
```

**UPDATE Handler:**
```typescript
const updateSchema = z.object({
  name: z.string().optional(),
  description: z.string().optional()
}).refine(data => Object.keys(data).length > 0);

const updateHandler = new Handler<z.infer<typeof updateSchema>, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireComplexPermissions({
    or: [
      { permission: 'admin.resources' },
      { permission: 'resource.update.own' }
    ]
  }))
  .use(new BodyValidationMiddleware(updateSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const updates = context.req.validatedBody!;
    const resourceId = context.req.params.id;
    return await resourceService.update(resourceId, updates);
  });
```

**DELETE Handler:**
```typescript
const deleteHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['admin.delete', 'resource.delete']))
  .use({
    before: async (context) => {
      // Safety check - prevent self-deletion
      if (context.req.params.id === context.user!.id) {
        throw new SecurityError('Cannot delete your own resource');
      }
    }
  })
  .handle(async (context) => {
    await resourceService.delete(context.req.params.id);
    return { success: true, message: 'Resource deleted' };
  });
```

## ⚡ Handler Best Practices

### 1. Middleware Order Matters
```typescript
// ✅ CORRECT ORDER
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())          // 1. Always first
  .use(RouteGuards.requirePermissions([...]))  // 2. Authentication
  .use(new BodyValidationMiddleware(schema))   // 3. Validation
  .use(new ResponseWrapperMiddleware())        // 4. Always last

// ❌ WRONG ORDER - will cause issues
const badHandler = new Handler<RequestType, UserType>()
  .use(new BodyValidationMiddleware(schema))   // Validation before auth!
  .use(RouteGuards.requirePermissions([...]))  // Auth after validation!
  .use(new ErrorHandlerMiddleware())          // Error handler not first!
```

### 2. Type Safety with .use()
```typescript
// Define types first
const userSchema = z.object({
  name: z.string(),
  email: z.string().email()
});
type UserRequest = z.infer<typeof userSchema>;

interface AuthenticatedUser {
  id: string;
  role: string;
  permissions: string[];
}

// Use generic types for type safety
const handler = new Handler<UserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['users.create']))
  .use(new BodyValidationMiddleware(userSchema))
  .handle(async (context) => {
    // Full type safety
    const userData = context.req.validatedBody!;  // Type: UserRequest
    const currentUser = context.user!;            // Type: AuthenticatedUser
  });
```

### 3. Handler Configuration Setup
```typescript
// Configure RouteGuards before using handlers
await RouteGuards.configure(
  { environment: 'production', cacheType: 'memory' },
  { async getUserPermissions(userId) { return [...] } },
  { async verifyToken(token) { return jwt.verify(token, secret) } }
);
```

## 💉 Dependency Injection with Handler & .use()

### Service Registration with .use()

```typescript
import { Service, Container } from 'typedi';
import { DependencyInjectionMiddleware } from '@noony/core';

// 1. Define services with @Service() decorator
@Service()
export class UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {}

  async createUser(userData: CreateUserRequest): Promise<User> {
    const user = await this.userRepository.create(userData);
    await this.emailService.sendWelcomeEmail(user.email);
    return user;
  }
}

@Service()
export class UserRepository {
  async create(userData: CreateUserRequest): Promise<User> {
    // Database logic
    return await database.users.create(userData);
  }
}

// 2. Register services with Handler using .use()
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['users.create']))
  .use(new BodyValidationMiddleware(userSchema))
  .use(new DependencyInjectionMiddleware([    // Register services
    UserService,
    UserRepository,
    EmailService
  ]))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    // Access services from Container
    const userService = Container.get(UserService);
    const user = await userService.createUser(context.req.validatedBody!);
    return { user };
  });
```

### Container Pool Optimization with .use()

```typescript
import { containerPool } from '@noony/core';

// Container pool middleware for serverless performance
const containerPoolHandler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use({
    before: async (context) => {
      // Acquire container from pool
      const container = containerPool.acquire();
      context.businessData.set('container', container);
    },
    after: async (context) => {
      // Release container back to pool
      const container = context.businessData.get('container');
      if (container) {
        containerPool.release(container);
      }
    }
  })
  .use(RouteGuards.requirePermissions(['api.access']))
  .handle(async (context) => {
    // Use pooled container for better performance
    const container = context.businessData.get('container');
    const userService = container.get(UserService);
    return await userService.processRequest(context.req);
  });

// Alternative: Automatic container pooling
const autoPoolHandler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    // Container is automatically pooled behind the scenes
    const userService = Container.get(UserService);
    return await userService.processRequest(context.req);
  });
```

### Request-Scoped Services with .use()

```typescript
// Custom middleware for request-scoped services
const requestScopedHandler = new Handler<RequestType, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['api.access']))
  .use({
    before: async (context) => {
      // Register request-specific data
      Container.set('requestId', context.requestId);
      Container.set('currentUser', context.user);
      Container.set('startTime', context.startTime);
      
      // Register scoped services
      Container.set('auditService', new AuditService(context.requestId));
      Container.set('cacheService', new CacheService(`req:${context.requestId}`));
    },
    after: async (context) => {
      // Clean up request-specific registrations
      Container.remove('requestId');
      Container.remove('currentUser');
      Container.remove('startTime');
      Container.remove('auditService');
      Container.remove('cacheService');
    }
  })
  .handle(async (context) => {
    // Access scoped services
    const auditService = Container.get('auditService');
    const cacheService = Container.get('cacheService');
    
    const result = await businessService.process(context.req);
    await auditService.log('operation_completed', result);
    
    return result;
  });
```

### Service Factory Pattern with .use()

```typescript
@Service()
export class ServiceFactory {
  constructor(
    private database: DatabaseConnection,
    private config: AppConfig
  ) {}

  createUserService(tenantId: string): UserService {
    const repository = new UserRepository(this.database, tenantId);
    const emailService = new EmailService(this.config.emailConfig);
    return new UserService(repository, emailService);
  }
}

// Use factory in Handler
const factoryHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['users.create']))
  .use(new DependencyInjectionMiddleware([ServiceFactory]))
  .use(new BodyValidationMiddleware(userSchema))
  .handle(async (context) => {
    // Use factory to create configured services
    const factory = Container.get(ServiceFactory);
    const userService = factory.createUserService(context.user!.tenantId);
    
    const user = await userService.createUser(context.req.validatedBody!);
    return { user };
  });
```

## 🏗️ Handler + Service Integration Patterns

### Repository Pattern with Handler

```typescript
// Base repository interface
interface BaseRepository<T> {
  findById(id: string): Promise<T | null>;
  create(data: Partial<T>): Promise<T>;
  update(id: string, data: Partial<T>): Promise<T>;
  delete(id: string): Promise<void>;
}

@Service()
export class UserRepository implements BaseRepository<User> {
  constructor(private database: DatabaseConnection) {}

  async findById(id: string): Promise<User | null> {
    return await this.database.users.findById(id);
  }
  
  async create(data: Partial<User>): Promise<User> {
    return await this.database.users.create({
      ...data,
      id: generateId(),
      createdAt: new Date()
    });
  }
  
  async update(id: string, data: Partial<User>): Promise<User> {
    return await this.database.users.update(id, data);
  }
  
  async delete(id: string): Promise<void> {
    await this.database.users.delete(id);
  }
}

// Complete CRUD handlers with repository pattern
const getUserHandler = new Handler<{}, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requireWildcardPermissions(['admin.*', 'user.read.*']))
  .use(new DependencyInjectionMiddleware([UserRepository]))
  .handle(async (context) => {
    const repository = Container.get(UserRepository);
    const user = await repository.findById(context.req.params.id);
    
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    return { user };
  });

const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['users.create']))
  .use(new BodyValidationMiddleware(createUserSchema))
  .use(new DependencyInjectionMiddleware([UserRepository]))
  .handle(async (context) => {
    const repository = Container.get(UserRepository);
    const user = await repository.create(context.req.validatedBody!);
    return { user };
  });
```

### Business Service Orchestration

```typescript
@Service()
export class OrderService {
  constructor(
    private orderRepository: OrderRepository,
    private inventoryService: InventoryService,
    private paymentService: PaymentService,
    private emailService: EmailService,
    private auditService: AuditService
  ) {}

  async createOrder(orderData: CreateOrderRequest, userId: string): Promise<Order> {
    // Multi-step business process with service coordination
    
    // 1. Validate inventory
    await this.inventoryService.validateAvailability(orderData.items);
    
    // 2. Process payment
    const paymentResult = await this.paymentService.processPayment({
      amount: orderData.total,
      paymentMethodId: orderData.paymentMethodId
    });
    
    // 3. Create order
    const order = await this.orderRepository.create({
      ...orderData,
      userId,
      paymentId: paymentResult.id,
      status: 'confirmed'
    });
    
    // 4. Reserve inventory
    await this.inventoryService.reserveItems(orderData.items, order.id);
    
    // 5. Send confirmation
    await this.emailService.sendOrderConfirmation(order);
    
    // 6. Audit trail
    await this.auditService.logOrderCreation(order.id, userId);
    
    return order;
  }
}

// Handler with complex service orchestration
const createOrderHandler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(RouteGuards.requirePermissions(['orders.create']))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(new DependencyInjectionMiddleware([
    OrderService,
    OrderRepository,
    InventoryService,
    PaymentService,
    EmailService,
    AuditService
  ]))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    const orderService = Container.get(OrderService);
    const order = await orderService.createOrder(
      context.req.validatedBody!,
      context.user!.id
    );
    
    return {
      success: true,
      order: {
        id: order.id,
        status: order.status,
        total: order.total
      }
    };
  });
```

### Configuration Service Integration

```typescript
@Service()
export class ConfigService {
  private config: Record<string, any>;
  
  constructor() {
    this.config = {
      database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432')
      },
      jwt: {
        secret: process.env.JWT_SECRET,
        expiresIn: process.env.JWT_EXPIRES_IN || '1h'
      },
      email: {
        apiKey: process.env.EMAIL_API_KEY,
        from: process.env.EMAIL_FROM
      }
    };
  }
  
  get<T>(key: string, defaultValue?: T): T {
    const keys = key.split('.');
    let value = this.config;
    
    for (const k of keys) {
      value = value?.[k];
    }
    
    return value !== undefined ? value : defaultValue;
  }
}

// Handler with configuration service
const configuredHandler = new Handler<RequestType, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new DependencyInjectionMiddleware([ConfigService, EmailService]))
  .handle(async (context) => {
    const configService = Container.get(ConfigService);
    const emailService = Container.get(EmailService);
    
    // Use configuration in business logic
    const emailFrom = configService.get('email.from');
    const jwtExpiration = configService.get('jwt.expiresIn');
    
    // Process with configured services
    const result = await businessService.process(context.req, {
      emailFrom,
      jwtExpiration
    });
    
    return result;
  });
```

## 🧪 Testing with DI & Handler

### Mock Service Registration

```typescript
describe('CreateUserHandler', () => {
  let handler: Handler<CreateUserRequest, AuthenticatedUser>;
  let mockUserService: jest.Mocked<UserService>;
  let mockAuditService: jest.Mocked<AuditService>;
  
  beforeEach(() => {
    // Create mocks
    mockUserService = {
      createUser: jest.fn()
    } as any;
    
    mockAuditService = {
      logUserCreation: jest.fn()
    } as any;
    
    // Register mocks in container
    Container.set(UserService, mockUserService);
    Container.set(AuditService, mockAuditService);
    
    // Create handler with mocked services
    handler = new Handler<CreateUserRequest, AuthenticatedUser>()
      .use(new ErrorHandlerMiddleware())
      .use(new DependencyInjectionMiddleware([UserService, AuditService]))
      .handle(async (context) => {
        const userService = Container.get(UserService);
        const auditService = Container.get(AuditService);
        
        const user = await userService.createUser(context.req.validatedBody!);
        await auditService.logUserCreation(user.id, context.user!.id);
        
        return { user };
      });
  });
  
  afterEach(() => {
    Container.reset();
  });
  
  it('should create user and log audit trail', async () => {
    const userData = { name: 'John', email: 'john@example.com' };
    const createdUser = { id: '123', ...userData };
    const mockUser = { id: 'user456' } as AuthenticatedUser;
    
    mockUserService.createUser.mockResolvedValue(createdUser);
    mockAuditService.logUserCreation.mockResolvedValue(undefined);
    
    const mockContext = {
      req: { validatedBody: userData },
      user: mockUser,
      res: { json: jest.fn() }
    } as any;
    
    const result = await handler.handle(mockContext);
    
    expect(mockUserService.createUser).toHaveBeenCalledWith(userData);
    expect(mockAuditService.logUserCreation).toHaveBeenCalledWith('123', 'user456');
    expect(result).toEqual({ user: createdUser });
  });
});
```

## ⚡ DI Performance Best Practices

### Container Pool Statistics

```typescript
const performanceHandler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use({
    before: async (context) => {
      // Monitor container pool usage
      const poolStats = containerPool.getStats();
      if (poolStats.available === 0) {
        console.warn('Container pool exhausted', poolStats);
      }
    }
  })
  .use(new DependencyInjectionMiddleware([BusinessService]))
  .handle(async (context) => {
    const service = Container.get(BusinessService);
    return await service.process(context.req);
  });
```

### Lazy Service Loading

```typescript
@Service()
export class LazyUserService {
  private _emailService: EmailService | null = null;
  
  private get emailService(): EmailService {
    if (!this._emailService) {
      this._emailService = Container.get(EmailService);
    }
    return this._emailService;
  }
  
  async createUser(userData: CreateUserRequest): Promise<User> {
    const user = await this.repository.create(userData);
    // Email service only loaded when needed
    await this.emailService.sendWelcomeEmail(user.email);
    return user;
  }
}
```

## 🎯 Key Rules

1. **Always start with ErrorHandlerMiddleware**: `.use(new ErrorHandlerMiddleware())`
2. **Authentication comes second**: `.use(RouteGuards.require...())`
3. **DI setup comes after auth**: `.use(new DependencyInjectionMiddleware([...]))`
4. **Validation comes after DI**: `.use(new BodyValidationMiddleware(schema))`
5. **Response wrapper comes last**: `.use(new ResponseWrapperMiddleware())`
6. **Use generic types**: `Handler<RequestType, UserType>` for full type safety
7. **Register services with @Service()**: Automatic TypeDI registration
8. **Use Container.get()**: Access services in `.handle()` method
9. **Configure guards first**: Set up RouteGuards before creating handlers
10. **Clean up containers**: Properly manage scoped container lifecycle
11. **Use container pool**: For serverless performance optimization
12. **Test with guard script**: Use `./test-guards.sh` to validate permission logic

## 📚 Quick Reference

```typescript
// Template for any route handler
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())                    // Required
  .use(RouteGuards.requirePermissions(['permission']))  // Choose strategy
  .use(new BodyValidationMiddleware(schema))            // If POST/PUT
  .use(new ResponseWrapperMiddleware())                 // Required
  .handle(async (context) => {
    // context.req.validatedBody! - typed request data
    // context.user! - typed user data
    // return response object
  });
```