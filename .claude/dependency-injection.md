# Noony Framework Dependency Injection Rules

## TypeDI Container Setup

### Service Registration Patterns

```typescript
import 'reflect-metadata'; // Required at application entry point
import { Service, Container, Inject } from 'typedi';

// ✅ CORRECT: Always use @Service() decorator for automatic registration
@Service()
export class UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService,
    private logger: Logger
  ) {}

  async createUser(userData: CreateUserRequest): Promise<User> {
    const user = await this.userRepository.create(userData);
    await this.emailService.sendWelcomeEmail(user.email);
    this.logger.info(`User created: ${user.id}`);
    return user;
  }
}

@Service()
export class UserRepository {
  constructor(private database: DatabaseConnection) {}

  async create(userData: CreateUserRequest): Promise<User> {
    return this.database.users.create({
      ...userData,
      id: generateId(),
      createdAt: new Date()
    });
  }
}

@Service()
export class EmailService {
  async sendWelcomeEmail(email: string): Promise<void> {
    // Email sending implementation
  }
}
```

### Container Pool for Serverless Performance

```typescript
// ✅ CORRECT: Use container pool for serverless cold start optimization
import { containerPool } from '@noony-serverless/core';

// Initialize services during cold start
const initializeServices = () => {
  containerPool.register([
    UserService,
    UserRepository,
    EmailService,
    DatabaseService,
    Logger
  ]);
};

// Call during application startup
await initializeServices();

// Use in handlers for optimal performance
const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .handle(async (context) => {
    // Get service from container pool (pre-warmed)
    const userService = containerPool.get(UserService);
    const user = await userService.createUser(context.req.validatedBody!);
    context.res.json({ user });
  });

// ❌ INCORRECT: Direct Container usage in serverless (slower cold starts)
const badHandler = new Handler()
  .handle(async (context) => {
    const userService = Container.get(UserService); // Slower initialization
  });
```

## Dependency Injection Middleware

### DependencyInjectionMiddleware Usage

```typescript
// ✅ CORRECT: Register services with middleware
const handler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new DependencyInjectionMiddleware<CreateUserRequest, AuthenticatedUser>([
    UserService,
    UserRepository,
    EmailService,
    AuditService
  ]))
  .handle(async (context) => {
    // Services are available in Container
    const userService = Container.get(UserService);
    const auditService = Container.get(AuditService);
    
    const user = await userService.createUser(context.req.validatedBody!);
    await auditService.logUserCreation(user.id, context.user!.id);
    
    context.res.json({ user });
  });
```

### Custom Service Registration

```typescript
// Manual service registration for complex scenarios
class CustomDependencyMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Register request-specific services
    Container.set('requestId', context.requestId);
    Container.set('startTime', context.startTime);
    Container.set('currentUser', context.user);
    
    // Register scoped services
    Container.set(AuditService, new AuditService(context.requestId));
    Container.set(NotificationService, new NotificationService(context.user?.id));
  }
  
  async after(context: Context<T, U>): Promise<void> {
    // Clean up request-specific registrations
    Container.remove('requestId');
    Container.remove('startTime');
    Container.remove('currentUser');
  }
}
```

## Service Patterns

### Repository Pattern Implementation

```typescript
// Base repository interface
interface BaseRepository<T, ID = string> {
  findById(id: ID): Promise<T | null>;
  findAll(): Promise<T[]>;
  create(data: Partial<T>): Promise<T>;
  update(id: ID, data: Partial<T>): Promise<T>;
  delete(id: ID): Promise<void>;
}

// Generic repository implementation
@Service()
export class GenericRepository<T, ID = string> implements BaseRepository<T, ID> {
  constructor(
    @Inject('database') private database: DatabaseConnection,
    @Inject('tableName') private tableName: string
  ) {}

  async findById(id: ID): Promise<T | null> {
    return this.database.table(this.tableName).findById(id);
  }

  async findAll(): Promise<T[]> {
    return this.database.table(this.tableName).findAll();
  }

  async create(data: Partial<T>): Promise<T> {
    return this.database.table(this.tableName).create(data);
  }

  async update(id: ID, data: Partial<T>): Promise<T> {
    return this.database.table(this.tableName).update(id, data);
  }

  async delete(id: ID): Promise<void> {
    return this.database.table(this.tableName).delete(id);
  }
}

// Specific repository implementations
@Service()
export class UserRepository extends GenericRepository<User> {
  constructor(@Inject('database') database: DatabaseConnection) {
    super(database, 'users');
  }

  // Additional user-specific methods
  async findByEmail(email: string): Promise<User | null> {
    return this.database.users.findOne({ email });
  }

  async findByRole(role: string): Promise<User[]> {
    return this.database.users.find({ role });
  }
}
```

### Service Layer Patterns

```typescript
// Business service with multiple dependencies
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
    // Multi-step business process with dependency coordination
    
    // 1. Validate inventory
    await this.inventoryService.validateAvailability(orderData.items);
    
    // 2. Calculate totals
    const totals = this.calculateOrderTotals(orderData.items);
    
    // 3. Process payment
    const paymentResult = await this.paymentService.processPayment({
      amount: totals.total,
      paymentMethodId: orderData.paymentMethodId
    });
    
    // 4. Create order record
    const order = await this.orderRepository.create({
      ...orderData,
      ...totals,
      userId,
      paymentId: paymentResult.id,
      status: 'confirmed'
    });
    
    // 5. Reserve inventory
    await this.inventoryService.reserveItems(orderData.items, order.id);
    
    // 6. Send confirmation
    await this.emailService.sendOrderConfirmation(order);
    
    // 7. Audit trail
    await this.auditService.logOrderCreation(order.id, userId);
    
    return order;
  }
}
```

### Factory Pattern with DI

```typescript
// Service factory for creating configured instances
@Service()
export class ServiceFactory {
  constructor(
    private database: DatabaseConnection,
    private logger: Logger,
    private config: AppConfig
  ) {}

  createUserService(tenantId: string): UserService {
    // Create tenant-scoped repository
    const repository = new UserRepository(this.database, tenantId);
    
    // Create configured email service
    const emailService = new EmailService({
      apiKey: this.config.emailApiKey,
      templateId: this.config.userTemplateId
    });
    
    return new UserService(repository, emailService, this.logger);
  }

  createOrderService(userId: string): OrderService {
    const orderRepo = new OrderRepository(this.database);
    const inventoryService = new InventoryService(this.database);
    const paymentService = new PaymentService(this.config.paymentConfig);
    const emailService = this.createEmailService(userId);
    
    return new OrderService(orderRepo, inventoryService, paymentService, emailService);
  }
}

// Use factory in handlers
const handler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new DependencyInjectionMiddleware([ServiceFactory]))
  .handle(async (context) => {
    const factory = Container.get(ServiceFactory);
    const orderService = factory.createOrderService(context.user!.id);
    
    const order = await orderService.createOrder(
      context.req.validatedBody!, 
      context.user!.id
    );
    
    context.res.json({ order });
  });
```

## Advanced DI Patterns

### Token-based Injection

```typescript
// Define injection tokens
const DATABASE_CONNECTION = Symbol('DATABASE_CONNECTION');
const LOGGER = Symbol('LOGGER');
const CONFIG = Symbol('CONFIG');

// Register with tokens
Container.set(DATABASE_CONNECTION, new DatabaseConnection(process.env.DATABASE_URL));
Container.set(LOGGER, new Logger({ level: process.env.LOG_LEVEL }));
Container.set(CONFIG, new AppConfig());

// Use tokens in services
@Service()
export class UserService {
  constructor(
    @Inject(DATABASE_CONNECTION) private database: DatabaseConnection,
    @Inject(LOGGER) private logger: Logger,
    @Inject(CONFIG) private config: AppConfig
  ) {}
}
```

### Conditional Service Registration

```typescript
// Environment-based service registration
const registerServices = () => {
  // Common services
  Container.set(Logger, new Logger());
  
  // Environment-specific services
  if (process.env.NODE_ENV === 'production') {
    Container.set(EmailService, new ProductionEmailService());
    Container.set(DatabaseService, new PostgreSQLService());
  } else {
    Container.set(EmailService, new MockEmailService());
    Container.set(DatabaseService, new InMemoryDatabaseService());
  }
  
  // Feature flag based registration
  if (process.env.ENABLE_ANALYTICS === 'true') {
    Container.set(AnalyticsService, new AnalyticsService());
  } else {
    Container.set(AnalyticsService, new NoOpAnalyticsService());
  }
};
```

### Scoped Container Management

```typescript
// Request-scoped container management
class ScopedContainerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Create request-scoped container
    const requestContainer = Container.of(context.requestId);
    
    // Register request-specific data
    requestContainer.set('requestId', context.requestId);
    requestContainer.set('user', context.user);
    requestContainer.set('startTime', context.startTime);
    
    // Register request-scoped services
    requestContainer.set(AuditService, new AuditService(context.requestId));
    requestContainer.set(CacheService, new CacheService(`request:${context.requestId}`));
    
    // Store container reference for cleanup
    context.businessData?.set('containerScope', context.requestId);
  }
  
  async after(context: Context<T, U>): Promise<void> {
    // Clean up request-scoped container
    const scopeId = context.businessData?.get('containerScope');
    if (scopeId) {
      Container.reset(scopeId);
    }
  }
}
```

## Configuration Management

### Configuration Service Pattern

```typescript
@Service()
export class ConfigService {
  private config: Record<string, any>;
  
  constructor() {
    this.config = this.loadConfiguration();
  }
  
  private loadConfiguration(): Record<string, any> {
    return {
      database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432'),
        name: process.env.DB_NAME || 'app',
        user: process.env.DB_USER || 'user',
        password: process.env.DB_PASSWORD || 'password'
      },
      jwt: {
        secret: process.env.JWT_SECRET || 'default-secret',
        expiresIn: process.env.JWT_EXPIRES_IN || '1h'
      },
      email: {
        apiKey: process.env.EMAIL_API_KEY,
        from: process.env.EMAIL_FROM || 'noreply@app.com'
      },
      features: {
        analytics: process.env.ENABLE_ANALYTICS === 'true',
        notifications: process.env.ENABLE_NOTIFICATIONS === 'true'
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

// Use configuration in services
@Service()
export class DatabaseService {
  constructor(private configService: ConfigService) {
    const dbConfig = this.configService.get('database');
    // Initialize database connection with config
  }
}
```

### Environment-Aware Service Factory

```typescript
@Service()
export class EnvironmentServiceFactory {
  constructor(private configService: ConfigService) {}
  
  createEmailService(): EmailService {
    const environment = process.env.NODE_ENV;
    const emailConfig = this.configService.get('email');
    
    switch (environment) {
      case 'production':
        return new SendGridEmailService(emailConfig);
      case 'staging':
        return new MailgunEmailService(emailConfig);
      case 'development':
        return new ConsoleEmailService();
      case 'test':
        return new MockEmailService();
      default:
        throw new Error(`Unknown environment: ${environment}`);
    }
  }
  
  createCacheService(): CacheService {
    if (process.env.REDIS_URL) {
      return new RedisCacheService(process.env.REDIS_URL);
    }
    return new InMemoryCacheService();
  }
}
```

## Testing with Dependency Injection

### Mock Service Registration

```typescript
describe('UserService', () => {
  let userService: UserService;
  let mockRepository: jest.Mocked<UserRepository>;
  let mockEmailService: jest.Mocked<EmailService>;
  
  beforeEach(() => {
    // Create mocks
    mockRepository = {
      create: jest.fn(),
      findById: jest.fn(),
      findByEmail: jest.fn()
    } as any;
    
    mockEmailService = {
      sendWelcomeEmail: jest.fn()
    } as any;
    
    // Register mocks in container
    Container.set(UserRepository, mockRepository);
    Container.set(EmailService, mockEmailService);
    
    // Get service instance with mocked dependencies
    userService = Container.get(UserService);
  });
  
  afterEach(() => {
    // Clean up container
    Container.reset();
  });
  
  it('should create user and send welcome email', async () => {
    const userData = { name: 'John', email: 'john@example.com' };
    const createdUser = { id: '123', ...userData };
    
    mockRepository.create.mockResolvedValue(createdUser);
    mockEmailService.sendWelcomeEmail.mockResolvedValue(undefined);
    
    const result = await userService.createUser(userData);
    
    expect(mockRepository.create).toHaveBeenCalledWith(userData);
    expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(userData.email);
    expect(result).toEqual(createdUser);
  });
});
```

### Integration Testing with Real Dependencies

```typescript
describe('User Integration Tests', () => {
  let handler: Handler<CreateUserRequest, AuthenticatedUser>;
  let testDatabase: TestDatabase;
  
  beforeAll(async () => {
    // Set up test database
    testDatabase = new TestDatabase();
    await testDatabase.setup();
    
    // Register real services with test database
    Container.set(DatabaseConnection, testDatabase.connection);
    Container.set(UserRepository, new UserRepository(testDatabase.connection));
    Container.set(EmailService, new MockEmailService()); // Mock external service
    
    // Create handler with real dependencies
    handler = new Handler<CreateUserRequest, AuthenticatedUser>()
      .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
      .use(new DependencyInjectionMiddleware<CreateUserRequest, AuthenticatedUser>([
        UserService,
        UserRepository
      ]))
      .handle(async (context) => {
        const userService = Container.get(UserService);
        const user = await userService.createUser(context.req.validatedBody!);
        context.res.json({ user });
      });
  });
  
  afterAll(async () => {
    await testDatabase.teardown();
    Container.reset();
  });
  
  it('should create user end-to-end', async () => {
    const mockContext = createMockContext({
      validatedBody: { name: 'John', email: 'john@test.com' }
    });
    
    await handler.handle(mockContext);
    
    // Verify user was created in database
    const userRepo = Container.get(UserRepository);
    const user = await userRepo.findByEmail('john@test.com');
    expect(user).toBeTruthy();
  });
});
```

## Performance Considerations

### Lazy Loading Pattern

```typescript
@Service()
export class LazyUserService {
  private _repository: UserRepository | null = null;
  private _emailService: EmailService | null = null;
  
  private get repository(): UserRepository {
    if (!this._repository) {
      this._repository = Container.get(UserRepository);
    }
    return this._repository;
  }
  
  private get emailService(): EmailService {
    if (!this._emailService) {
      this._emailService = Container.get(EmailService);
    }
    return this._emailService;
  }
  
  async createUser(userData: CreateUserRequest): Promise<User> {
    const user = await this.repository.create(userData);
    await this.emailService.sendWelcomeEmail(user.email);
    return user;
  }
}
```

### Singleton vs Transient Services

```typescript
// ✅ CORRECT: Singleton for stateless services (default)
@Service() // Singleton by default
export class ConfigService {
  // Stateless service - safe as singleton
}

// ✅ CORRECT: Transient for stateful services
@Service({ transient: true })
export class RequestContextService {
  constructor(
    private requestId: string,
    private userId: string
  ) {}
  
  // Stateful service - should be transient
}

// Factory for transient services
@Service()
export class RequestContextFactory {
  create(requestId: string, userId: string): RequestContextService {
    return new RequestContextService(requestId, userId);
  }
}
```

## Best Practices

1. **Always use `@Service()` decorator** for automatic registration
2. **Use container pool in serverless** environments for better performance
3. **Register dependencies early** in the application lifecycle
4. **Use tokens for interface-based injection** to improve testability
5. **Clean up scoped containers** to prevent memory leaks
6. **Mock external dependencies** in tests
7. **Use factory pattern** for complex service creation
8. **Implement proper error handling** in service constructors
9. **Consider service lifecycles** (singleton vs transient)
10. **Document service dependencies** and their purposes

## Common Anti-Patterns

```typescript
// ❌ INCORRECT: Direct instantiation instead of DI
class BadUserService {
  constructor() {
    this.repository = new UserRepository(); // Hard dependency
    this.emailService = new EmailService(); // Hard to test
  }
}

// ❌ INCORRECT: Service locator pattern
class BadService {
  async doSomething() {
    const service = Container.get(SomeService); // Service locator anti-pattern
    return service.process();
  }
}

// ❌ INCORRECT: Circular dependencies
@Service()
class ServiceA {
  constructor(private serviceB: ServiceB) {} // Circular reference
}

@Service()
class ServiceB {
  constructor(private serviceA: ServiceA) {} // Circular reference
}
```