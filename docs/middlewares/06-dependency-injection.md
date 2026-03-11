# DependencyInjectionMiddleware Complete Guide

This comprehensive guide shows you how to use the `DependencyInjectionMiddleware` with named functions for better code organization, reusability, and maintainability.

## Table of Contents

1. [Quick Comparison](#quick-comparison)
2. [Overview](#overview)
3. [Manual Service Registration (Without @Service)](#manual-service-registration-without-service)
4. [Automatic Service Registration (With @Service)](#automatic-service-registration-with-service)
5. [Reusable Handler Patterns](#reusable-handler-patterns)
6. [Testing Benefits](#testing-benefits)
7. [Best Practices](#best-practices)
8. [Migration Patterns](#migration-patterns)
9. [Common Patterns](#common-patterns)

## Quick Comparison

### Manual vs Automatic Service Registration

| Feature | Manual Registration | Automatic Registration (@Service) |
|---------|-------------------|-----------------------------------|
| **Setup Complexity** | 🟡 Medium - Explicit service creation | 🟢 Easy - Just add decorators |
| **Control Level** | 🟢 Full control over instantiation | 🟡 Framework-controlled |
| **Type Safety** | 🟢 Explicit and clear | 🟢 Excellent with generics |
| **Testing** | 🟢 Easy to mock services | 🟡 Requires container mocking |
| **Debugging** | 🟢 Clear dependency flow | 🟡 Can be harder to trace |
| **Performance** | 🟢 Predictable instantiation | 🟢 Singleton by default |
| **Framework Coupling** | 🟢 Low coupling | 🟡 Coupled to TypeDI |
| **Code Boilerplate** | 🟡 More setup code | 🟢 Less boilerplate |
| **Dependency Resolution** | 🟡 Manual wiring | 🟢 Automatic resolution |
| **Complex Dependencies** | 🟡 Manual management | 🟢 Handles automatically |

### When to Use Each Approach

#### Choose Manual Registration When

- ✅ You need **full control** over service lifecycle
- ✅ You want **explicit dependencies** that are easy to understand
- ✅ You're working with **existing classes** that can't be modified
- ✅ You need **different configurations** per environment
- ✅ You want **minimal framework coupling**
- ✅ You prefer **explicit over implicit** behavior
- ✅ You need to **conditionally instantiate** services
- ✅ Testing with **simple mocks** is a priority
- ✅ You want to use **reusable handler patterns** with explicit service passing

**Best for**: Small to medium applications, microservices, when you value explicitness and control.

#### Choose Automatic Registration When

- ✅ You want **reduced boilerplate** code
- ✅ You have **complex dependency graphs**
- ✅ You can modify your service classes to add decorators
- ✅ You want **automatic dependency resolution**
- ✅ You prefer **convention over configuration**
- ✅ You're building **large applications** with many services
- ✅ You want **singleton services** by default
- ✅ You're comfortable with **framework coupling**
- ✅ You want **reusable handler patterns** with automatic service resolution

**Best for**: Large applications, enterprise systems, when you want to focus on business logic over wiring.

#### Both Approaches Support Reusable Handler Patterns

**Reusable handler patterns** work excellently with both approaches:

- **Manual Registration**: Services are explicitly passed to reusable functions, making dependencies clear
- **Automatic Registration**: Services are automatically resolved within reusable functions via the container
- **Generic CRUD operations**: Both approaches support creating reusable CRUD handlers that work across entities
- **Permission validation**: Reusable permission checking functions work with both DI approaches  
- **Activity logging**: Cross-cutting concerns like logging work seamlessly with both patterns
- **Error handling**: Standardized error handling patterns are supported in both approaches

The choice between manual and automatic registration doesn't limit your ability to create reusable, composable handler functions.

### Feature Comparison At-a-Glance

| Aspect | Manual | @Service | Winner |
|--------|--------|----------|---------|
| **Learning Curve** | Low | Medium | Manual |
| **Initial Setup Time** | Higher | Lower | @Service |
| **Maintenance** | Higher | Lower | @Service |
| **Flexibility** | High | Medium | Manual |
| **Scalability** | Medium | High | @Service |
| **IDE Support** | Good | Excellent | @Service |
| **Error Messages** | Clear | Can be cryptic | Manual |
| **Runtime Performance** | Same | Same | Tie |
| **Bundle Size** | Smaller | Larger | Manual |
| **Enterprise Features** | Limited | Rich | @Service |

### Quick Decision Guide

```text
Are you building a large application with complex dependencies?
├─ Yes → Use @Service (Automatic)
└─ No
   ├─ Do you need full control over service instantiation?
   │  ├─ Yes → Use Manual Registration
   │  └─ No → Either approach works
   └─ Are you working with existing classes you can't modify?
      ├─ Yes → Use Manual Registration
      └─ No → Use @Service for less boilerplate
```

### Migration Path

| Current State | Recommended Next Step | Effort Level |
|---------------|----------------------|--------------|
| No DI | Start with Manual | Low |
| Manual DI | Stay with Manual or migrate gradually | Medium |
| @Service DI | Stay with @Service | None |
| Mixed approaches | Standardize on one approach | High |

## Overview

The `DependencyInjectionMiddleware` provides two approaches for managing services in your handlers:

1. **Manual Registration**: Explicitly create and register service instances
2. **Automatic Registration**: Use TypeDI's `@Service` decorator for automatic dependency injection

Both approaches work with **named functions** instead of anonymous functions, making your code more maintainable and testable.

### Why Named Functions?

```typescript
// ❌ Anonymous function - hard to test and reuse
const handler = new Handler()
  .use(diMiddleware)
  .handle(async (context) => {
    // Business logic here
  });

// ✅ Named function - testable and reusable
async function handleUserCreation(context: Context) {
  // Business logic here
}

const handler = new Handler()
  .use(diMiddleware)
  .handle(handleUserCreation);
```

## Manual Service Registration (Without @Service)

### Quick Summary - Manual Approach

Manual registration gives you **complete control** over how services are created and configured. You explicitly instantiate each service and register them with the DI container. This approach is straightforward, transparent, and perfect when you need precise control over your dependencies.

```typescript
// 1. Create services manually
const userService = new UserService();
const emailService = new EmailService({ apiKey: 'key-123' });

// 2. Register services
const services = [
  { id: UserService, value: userService },
  { id: EmailService, value: emailService }
];

// 3. Use in handler with named function
async function handleCreateUser(context: Context) {
  const userService = context.container?.get(UserService);
  const emailService = context.container?.get(EmailService);
  
  const user = await userService.create(context.req.parsedBody);
  await emailService.sendWelcomeEmail(user.email, user.name);
  
  return { success: true, user };
}

const createUserHandler = new Handler()
  .use(new DependencyInjectionMiddleware(services))
  .handle(handleCreateUser);
```

**Key Characteristics:**

- ✅ **Explicit control** - You decide exactly how services are created
- ✅ **Easy testing** - Simple to mock and replace services
- ✅ **Clear dependencies** - Dependencies are obvious and traceable
- ✅ **Environment flexibility** - Different configs for dev/test/prod
- ✅ **No decorators required** - Works with any existing classes

**Use when:** You have small-to-medium applications, need explicit control, working with existing classes, or prefer clear dependency management.

---

This approach gives you full control over service instantiation and dependencies.

### Basic Service Classes

```typescript
// services/core-services.ts
export class UserService {
  private users = new Map<string, any>();

  constructor(private database?: any) {}

  async findById(id: string) {
    return this.users.get(id) || null;
  }

  async create(userData: any) {
    const id = Date.now().toString();
    const user = { id, ...userData, createdAt: new Date() };
    this.users.set(id, user);
    return user;
  }

  async findAll() {
    return Array.from(this.users.values());
  }

  async update(id: string, updates: any) {
    const user = this.users.get(id);
    if (!user) return null;
    
    const updatedUser = { ...user, ...updates, updatedAt: new Date() };
    this.users.set(id, updatedUser);
    return updatedUser;
  }

  async delete(id: string) {
    return this.users.delete(id);
  }
}

export class EmailService {
  constructor(private config: { apiKey: string; fromEmail: string }) {}

  async sendEmail(to: string, subject: string, body: string) {
    console.log(`📧 Sending email to ${to}: ${subject}`);
    // In production: integrate with SendGrid, AWS SES, etc.
    return { messageId: `msg_${Date.now()}`, sent: true };
  }

  async sendWelcomeEmail(email: string, name: string) {
    return this.sendEmail(
      email,
      'Welcome to Our Platform!',
      `Hello ${name}, welcome to our platform!`
    );
  }

  async sendPasswordResetEmail(email: string, resetToken: string) {
    return this.sendEmail(
      email,
      'Password Reset Request',
      `Click here to reset your password: ${resetToken}`
    );
  }
}

export class LoggerService {
  constructor(private appName: string = 'MyApp') {}

  private formatMessage(level: string, message: string, meta?: any) {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
    return `[${this.appName}] ${timestamp} ${level.toUpperCase()}: ${message}${metaStr}`;
  }

  info(message: string, meta?: any) {
    console.log(this.formatMessage('info', message, meta));
  }

  error(message: string, meta?: any) {
    console.error(this.formatMessage('error', message, meta));
  }

  warn(message: string, meta?: any) {
    console.warn(this.formatMessage('warn', message, meta));
  }

  debug(message: string, meta?: any) {
    console.debug(this.formatMessage('debug', message, meta));
  }
}
```

### Service Registration and Named Handlers

```typescript
// handlers/user-handlers.ts
import { Handler, Context } from '@/core/handler';
import { DependencyInjectionMiddleware } from '@/middlewares/dependencyInjectionMiddleware';
import { UserService, EmailService, LoggerService } from '../services/core-services';

// 1. Create service instances with configuration
const userService = new UserService();
const emailService = new EmailService({
  apiKey: process.env.EMAIL_API_KEY || 'dev-key',
  fromEmail: process.env.FROM_EMAIL || 'noreply@myapp.com'
});
const loggerService = new LoggerService('UserAPI');

// 2. Additional configuration and utilities
const appConfig = {
  apiUrl: process.env.API_URL || 'https://api.myapp.com',
  version: process.env.APP_VERSION || '1.0.0',
  environment: process.env.NODE_ENV || 'development'
};

// 3. Register services for dependency injection
const services = [
  { id: UserService, value: userService },
  { id: EmailService, value: emailService },
  { id: LoggerService, value: loggerService },
  { id: 'config', value: appConfig },
  { id: 'startTime', value: Date.now() }
];

// 4. Create reusable DI middleware
const userDI = new DependencyInjectionMiddleware(services);

// 5. Named handler functions
async function handleCreateUser(context: Context) {
  const userService = context.container?.get(UserService);
  const emailService = context.container?.get(EmailService);
  const logger = context.container?.get(LoggerService);
  const config = context.container?.get('config');

  const userData = context.req.parsedBody;
  
  logger.info('Creating new user', { 
    email: userData.email,
    requestId: context.requestId
  });
  
  try {
    // Validate email format
    if (!userData.email || !userData.email.includes('@')) {
      throw new Error('Invalid email format');
    }

    // Create user
    const user = await userService.create(userData);
    
    // Send welcome email
    await emailService.sendWelcomeEmail(user.email, user.name);
    
    logger.info('User created successfully', { 
      userId: user.id, 
      email: userData.email 
    });
    
    return {
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt
      },
      apiUrl: config.apiUrl
    };
  } catch (error) {
    logger.error('User creation failed', { 
      error: error.message, 
      userData: { ...userData, password: '[REDACTED]' }
    });
    throw error;
  }
}

async function handleGetUser(context: Context) {
  const userService = context.container?.get(UserService);
  const logger = context.container?.get(LoggerService);
  
  const userId = context.req.params?.id;
  
  logger.info('Fetching user', { userId, requestId: context.requestId });
  
  if (!userId) {
    logger.warn('User ID not provided');
    return { success: false, error: 'User ID is required' };
  }
  
  const user = await userService.findById(userId);
  
  if (!user) {
    logger.warn('User not found', { userId });
    return { success: false, error: 'User not found' };
  }
  
  logger.info('User retrieved successfully', { userId });
  
  return { 
    success: true, 
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    }
  };
}

async function handleUpdateUser(context: Context) {
  const userService = context.container?.get(UserService);
  const logger = context.container?.get(LoggerService);
  
  const userId = context.req.params?.id;
  const updates = context.req.parsedBody;
  
  logger.info('Updating user', { userId, updates: Object.keys(updates) });
  
  const user = await userService.update(userId, updates);
  
  if (!user) {
    logger.warn('User not found for update', { userId });
    return { success: false, error: 'User not found' };
  }
  
  logger.info('User updated successfully', { userId });
  
  return {
    success: true,
    user,
    message: 'User updated successfully'
  };
}

async function handleDeleteUser(context: Context) {
  const userService = context.container?.get(UserService);
  const logger = context.container?.get(LoggerService);
  
  const userId = context.req.params?.id;
  
  logger.info('Deleting user', { userId });
  
  const deleted = await userService.delete(userId);
  
  if (!deleted) {
    logger.warn('User not found for deletion', { userId });
    return { success: false, error: 'User not found' };
  }
  
  logger.info('User deleted successfully', { userId });
  
  return {
    success: true,
    message: 'User deleted successfully'
  };
}

async function handleListUsers(context: Context) {
  const userService = context.container?.get(UserService);
  const logger = context.container?.get(LoggerService);
  const config = context.container?.get('config');
  
  const page = parseInt(context.req.query?.page || '1');
  const limit = parseInt(context.req.query?.limit || '10');
  const search = context.req.query?.search;
  
  logger.info('Fetching user list', { page, limit, search });
  
  let users = await userService.findAll();
  
  // Apply search filter
  if (search) {
    users = users.filter(user => 
      user.name.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  // Apply pagination
  const total = users.length;
  const startIndex = (page - 1) * limit;
  const paginatedUsers = users.slice(startIndex, startIndex + limit);
  
  logger.info('User list retrieved', { 
    total, 
    returned: paginatedUsers.length, 
    page 
  });
  
  return {
    success: true,
    users: paginatedUsers,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNextPage: startIndex + limit < total,
      hasPreviousPage: page > 1
    },
    version: config.version
  };
}

// 6. Export handlers using named functions
export const createUserHandler = new Handler()
  .use(userDI)
  .handle(handleCreateUser);

export const getUserHandler = new Handler()
  .use(userDI)
  .handle(handleGetUser);

export const updateUserHandler = new Handler()
  .use(userDI)
  .handle(handleUpdateUser);

export const deleteUserHandler = new Handler()
  .use(userDI)
  .handle(handleDeleteUser);

export const listUsersHandler = new Handler()
  .use(userDI)
  .handle(handleListUsers);

// Export named functions for testing
export {
  handleCreateUser,
  handleGetUser,
  handleUpdateUser,
  handleDeleteUser,
  handleListUsers
};
```

### Function-Based Services

```typescript
// services/utility-services.ts
export const createCacheService = (defaultTTL: number = 3600) => {
  const cache = new Map<string, { value: any; expires: number }>();
  
  return {
    get(key: string) {
      const item = cache.get(key);
      if (!item || item.expires < Date.now()) {
        cache.delete(key);
        return null;
      }
      return item.value;
    },
    
    set(key: string, value: any, ttlSeconds: number = defaultTTL) {
      cache.set(key, {
        value,
        expires: Date.now() + (ttlSeconds * 1000)
      });
    },
    
    delete(key: string) {
      return cache.delete(key);
    },
    
    clear() {
      cache.clear();
    },
    
    keys() {
      return Array.from(cache.keys());
    },
    
    size() {
      return cache.size;
    },
    
    stats() {
      const now = Date.now();
      const active = Array.from(cache.values()).filter(item => item.expires >= now).length;
      return {
        total: cache.size,
        active,
        expired: cache.size - active
      };
    }
  };
};

export const createMetricsService = () => {
  const metrics = {
    requests: 0,
    errors: 0,
    startTime: Date.now(),
    responseTimeSum: 0,
    slowRequests: 0
  };
  
  return {
    incrementRequests() {
      metrics.requests++;
    },
    
    incrementErrors() {
      metrics.errors++;
    },
    
    recordResponseTime(milliseconds: number) {
      metrics.responseTimeSum += milliseconds;
      if (milliseconds > 1000) { // Slow request threshold
        metrics.slowRequests++;
      }
    },
    
    getMetrics() {
      const uptime = Date.now() - metrics.startTime;
      const avgResponseTime = metrics.requests > 0 
        ? metrics.responseTimeSum / metrics.requests 
        : 0;
      
      return {
        ...metrics,
        uptime,
        errorRate: metrics.requests > 0 ? (metrics.errors / metrics.requests) * 100 : 0,
        averageResponseTime: Math.round(avgResponseTime),
        requestsPerSecond: metrics.requests / (uptime / 1000)
      };
    },
    
    reset() {
      Object.keys(metrics).forEach(key => {
        if (key !== 'startTime') {
          metrics[key] = 0;
        }
      });
      metrics.startTime = Date.now();
    }
  };
};

// Usage example
const utilityServices = [
  { id: 'cache', value: createCacheService(1800) }, // 30 minutes default TTL
  { id: 'metrics', value: createMetricsService() }
];

const utilityDI = new DependencyInjectionMiddleware(utilityServices);

async function handleCachedDataRequest(context: Context) {
  const cache = context.container?.get('cache');
  const metrics = context.container?.get('metrics');
  
  const startTime = Date.now();
  metrics.incrementRequests();
  
  try {
    const cacheKey = `data:${context.req.params?.id}`;
    let data = cache.get(cacheKey);
    
    if (!data) {
      // Simulate API call
      data = await fetchDataFromExternalAPI(context.req.params?.id);
      cache.set(cacheKey, data, 300); // Cache for 5 minutes
    }
    
    const responseTime = Date.now() - startTime;
    metrics.recordResponseTime(responseTime);
    
    return { 
      success: true, 
      data,
      fromCache: !!cache.get(cacheKey),
      responseTime,
      cacheStats: cache.stats()
    };
  } catch (error) {
    metrics.incrementErrors();
    const responseTime = Date.now() - startTime;
    metrics.recordResponseTime(responseTime);
    throw error;
  }
}

export const cachedDataHandler = new Handler()
  .use(utilityDI)
  .handle(handleCachedDataRequest);

async function fetchDataFromExternalAPI(id: string) {
  // Mock external API call
  await new Promise(resolve => setTimeout(resolve, 100));
  return { id, data: `External data for ${id}`, timestamp: new Date() };
}
```

## Automatic Service Registration (With @Service)

### Quick Summary - Automatic Approach

Automatic registration uses TypeDI's `@Service` decorator to automatically manage service instances and dependencies. Simply decorate your classes and TypeDI handles instantiation, dependency resolution, and lifecycle management. Perfect for complex applications with many interconnected services.

```typescript
// 1. Decorate services with @Service
@Service()
export class UserService {
  constructor(@Inject(() => DatabaseService) private db: DatabaseService) {}
  
  async create(userData: any) {
    return this.db.query('INSERT INTO users...', userData);
  }
}

@Service()
export class EmailService {
  async sendWelcomeEmail(email: string, name: string) {
    console.log(`📧 Welcome ${name}!`);
    return { sent: true, messageId: 'msg_123' };
  }
}

// 2. Use in handler with named function (no manual registration needed!)
async function handleCreateUser(context: Context) {
  // Services automatically available via Container
  const userService = Container.get(UserService);
  const emailService = Container.get(EmailService);
  
  const user = await userService.create(context.req.parsedBody);
  await emailService.sendWelcomeEmail(user.email, user.name);
  
  return { success: true, user };
}

const createUserHandler = new Handler()
  .use(dependencyInjection()) // Empty! Services auto-registered
  .handle(handleCreateUser);
```

**Key Characteristics:**

- 🚀 **Zero boilerplate** - No manual service instantiation
- 🔗 **Automatic dependency resolution** - Complex dependencies handled automatically
- 🏗️ **Singleton by default** - Efficient memory usage and state sharing
- 🧩 **Constructor injection** - Dependencies declared in constructor
- 📊 **Rich ecosystem** - Advanced features like scoping, factories, conditions

**Use when:** You have large applications, complex dependency graphs, can modify classes to add decorators, or want to focus purely on business logic.

---

This approach uses TypeDI's decorators for automatic dependency injection and service management.

### Services with @Service Decorator

```typescript
// services/decorated-services.ts
import { Service, Inject } from 'typedi';

@Service()
export class DatabaseService {
  private connected = false;
  private queryCount = 0;

  constructor() {
    this.connect();
  }

  private async connect() {
    // Mock database connection
    console.log('🗄️ Connecting to database...');
    await new Promise(resolve => setTimeout(resolve, 100));
    this.connected = true;
    console.log('✅ Database connected');
  }

  async query(sql: string, params: any[] = []) {
    if (!this.connected) {
      throw new Error('Database not connected');
    }
    
    this.queryCount++;
    console.log(`🗄️ Executing query #${this.queryCount}: ${sql}`, params);
    
    // Mock query execution
    await new Promise(resolve => setTimeout(resolve, 10));
    
    return { 
      rows: [{ id: 1, name: 'Test Data', created_at: new Date() }],
      rowCount: 1,
      queryId: this.queryCount
    };
  }

  async transaction<T>(operations: () => Promise<T>): Promise<T> {
    console.log('🔄 Starting transaction');
    
    try {
      const result = await operations();
      console.log('✅ Transaction committed');
      return result;
    } catch (error) {
      console.log('❌ Transaction rolled back');
      throw error;
    }
  }

  getStats() {
    return {
      connected: this.connected,
      totalQueries: this.queryCount,
      connectionUptime: Date.now() // Mock uptime
    };
  }
}

@Service()
export class CacheService {
  private cache = new Map<string, { value: any; expires: number; accessCount: number }>();
  private stats = { hits: 0, misses: 0, sets: 0, deletes: 0 };

  get(key: string) {
    const item = this.cache.get(key);
    
    if (!item || item.expires < Date.now()) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }
    
    item.accessCount++;
    this.stats.hits++;
    return item.value;
  }

  set(key: string, value: any, ttl = 3600) {
    this.cache.set(key, {
      value,
      expires: Date.now() + (ttl * 1000),
      accessCount: 0
    });
    this.stats.sets++;
  }

  delete(key: string) {
    const deleted = this.cache.delete(key);
    if (deleted) {
      this.stats.deletes++;
    }
    return deleted;
  }

  clear() {
    const size = this.cache.size;
    this.cache.clear();
    this.stats.deletes += size;
  }

  getStats() {
    return {
      ...this.stats,
      totalEntries: this.cache.size,
      hitRate: this.stats.hits + this.stats.misses > 0 
        ? (this.stats.hits / (this.stats.hits + this.stats.misses)) * 100 
        : 0
    };
  }
}

@Service()
export class NotificationService {
  constructor(
    @Inject(() => EmailService) private emailService: EmailService,
    @Inject(() => CacheService) private cacheService: CacheService
  ) {}

  async sendNotification(
    userId: string, 
    message: string, 
    type: 'email' | 'push' | 'sms' = 'email'
  ) {
    // Check user preferences from cache
    const userPrefsKey = `user_prefs:${userId}`;
    let userPrefs = this.cacheService.get(userPrefsKey);
    
    if (!userPrefs) {
      // Mock user preferences fetch
      userPrefs = {
        email: `user${userId}@example.com`,
        emailNotifications: true,
        pushNotifications: false,
        smsNotifications: false
      };
      this.cacheService.set(userPrefsKey, userPrefs, 1800); // Cache for 30 minutes
    }
    
    const notifications = [];
    
    if (type === 'email' && userPrefs.emailNotifications) {
      const result = await this.emailService.sendEmail(
        userPrefs.email, 
        'Notification', 
        message
      );
      notifications.push({ type: 'email', result });
    }
    
    if (type === 'push' && userPrefs.pushNotifications) {
      // Mock push notification
      notifications.push({ 
        type: 'push', 
        result: { sent: true, deviceId: `device_${userId}` }
      });
    }
    
    if (type === 'sms' && userPrefs.smsNotifications) {
      // Mock SMS notification
      notifications.push({ 
        type: 'sms', 
        result: { sent: true, phoneNumber: `+1555000${userId}` }
      });
    }
    
    return { 
      sent: notifications.length > 0, 
      notifications,
      userId,
      message
    };
  }

  async sendBulkNotification(userIds: string[], message: string, type: 'email' | 'push' | 'sms' = 'email') {
    const results = [];
    
    for (const userId of userIds) {
      try {
        const result = await this.sendNotification(userId, message, type);
        results.push({ userId, success: true, result });
      } catch (error) {
        results.push({ userId, success: false, error: error.message });
      }
    }
    
    return {
      totalUsers: userIds.length,
      successful: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      results
    };
  }
}

@Service()
export class UserRepository {
  constructor(
    @Inject(() => DatabaseService) private db: DatabaseService,
    @Inject(() => CacheService) private cache: CacheService
  ) {}

  async findById(id: string) {
    // Check cache first
    const cacheKey = `user:${id}`;
    const cached = this.cache.get(cacheKey);
    
    if (cached) {
      return { ...cached, fromCache: true };
    }

    // Query database
    const result = await this.db.query(
      'SELECT id, name, email, created_at, updated_at FROM users WHERE id = ?', 
      [id]
    );
    
    const user = result.rows[0];

    if (user) {
      this.cache.set(cacheKey, user, 300); // Cache for 5 minutes
      return { ...user, fromCache: false };
    }

    return null;
  }

  async findAll(filters: { search?: string; limit?: number; offset?: number } = {}) {
    let sql = 'SELECT id, name, email, created_at FROM users';
    const params = [];
    
    if (filters.search) {
      sql += ' WHERE name ILIKE ? OR email ILIKE ?';
      params.push(`%${filters.search}%`, `%${filters.search}%`);
    }
    
    sql += ' ORDER BY created_at DESC';
    
    if (filters.limit) {
      sql += ' LIMIT ?';
      params.push(filters.limit);
      
      if (filters.offset) {
        sql += ' OFFSET ?';
        params.push(filters.offset);
      }
    }
    
    const result = await this.db.query(sql, params);
    return result.rows;
  }

  async create(userData: { name: string; email: string; password?: string }) {
    return this.db.transaction(async () => {
      // Check if email already exists
      const existingUser = await this.db.query(
        'SELECT id FROM users WHERE email = ?',
        [userData.email]
      );
      
      if (existingUser.rows.length > 0) {
        throw new Error(`Email ${userData.email} already exists`);
      }
      
      // Create user
      const result = await this.db.query(
        'INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?) RETURNING id, name, email, created_at',
        [userData.name, userData.email, 'hashed_password', new Date()]
      );
      
      const user = result.rows[0];
      
      // Cache the new user
      this.cache.set(`user:${user.id}`, user);
      
      return user;
    });
  }

  async update(id: string, updates: { name?: string; email?: string }) {
    const user = await this.db.query(
      'UPDATE users SET name = COALESCE(?, name), email = COALESCE(?, email), updated_at = ? WHERE id = ? RETURNING id, name, email, updated_at',
      [updates.name, updates.email, new Date(), id]
    );
    
    if (user.rows.length === 0) {
      return null;
    }
    
    const updatedUser = user.rows[0];
    
    // Invalidate cache
    this.cache.delete(`user:${id}`);
    
    return updatedUser;
  }

  async delete(id: string) {
    const result = await this.db.query(
      'DELETE FROM users WHERE id = ? RETURNING id',
      [id]
    );
    
    if (result.rows.length > 0) {
      // Invalidate cache
      this.cache.delete(`user:${id}`);
      return true;
    }
    
    return false;
  }
}

// Re-declare EmailService with @Service for automatic injection
@Service()
export class EmailService {
  private sentEmails: Array<{ to: string; subject: string; timestamp: Date }> = [];

  constructor(
    @Inject('email.config') private config?: { apiKey: string; fromEmail: string }
  ) {
    this.config = this.config || {
      apiKey: process.env.EMAIL_API_KEY || 'default-key',
      fromEmail: process.env.FROM_EMAIL || 'noreply@example.com'
    };
  }

  async sendEmail(to: string, subject: string, body: string) {
    console.log(`📧 Sending email via ${this.config.apiKey}`);
    console.log(`   To: ${to}`);
    console.log(`   Subject: ${subject}`);
    console.log(`   From: ${this.config.fromEmail}`);
    
    // Mock email sending delay
    await new Promise(resolve => setTimeout(resolve, 50));
    
    const email = { to, subject, timestamp: new Date() };
    this.sentEmails.push(email);
    
    return { 
      messageId: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`, 
      sent: true,
      provider: 'mock-email-service'
    };
  }

  async sendWelcomeEmail(email: string, name: string) {
    return this.sendEmail(
      email,
      'Welcome to Our Platform!',
      `Hello ${name},\n\nWelcome to our platform! We're excited to have you on board.\n\nBest regards,\nThe Team`
    );
  }

  async sendPasswordResetEmail(email: string, resetToken: string) {
    return this.sendEmail(
      email,
      'Password Reset Request',
      `Hello,\n\nYou requested a password reset. Click the link below to reset your password:\n\nhttps://example.com/reset?token=${resetToken}\n\nIf you didn't request this, please ignore this email.\n\nBest regards,\nThe Team`
    );
  }

  getEmailStats() {
    return {
      totalSent: this.sentEmails.length,
      recentEmails: this.sentEmails.slice(-10), // Last 10 emails
      config: {
        fromEmail: this.config.fromEmail,
        hasApiKey: !!this.config.apiKey
      }
    };
  }
}
```

### Using @Service Decorated Classes with Named Functions

```typescript
// handlers/decorated-handlers.ts
import { Handler, Context } from '@/core/handler';
import { dependencyInjection } from '@/middlewares/dependencyInjectionMiddleware';
import { Container } from 'typedi';
import { 
  UserRepository, 
  NotificationService, 
  CacheService, 
  DatabaseService 
} from '../services/decorated-services';

// Named handler functions for @Service decorated classes
async function handleCreateUserWithNotification(context: Context) {
  // Services are automatically available through Container
  const userRepo = Container.get(UserRepository);
  const notificationService = Container.get(NotificationService);
  
  const userData = context.req.parsedBody;
  
  // Validate required fields
  if (!userData.name || !userData.email) {
    return {
      success: false,
      error: 'Name and email are required',
      code: 'VALIDATION_ERROR'
    };
  }
  
  try {
    const user = await userRepo.create(userData);
    
    // Send welcome notification
    const notificationResult = await notificationService.sendNotification(
      user.id, 
      `Welcome ${user.name}! Thanks for joining our platform.`,
      'email'
    );
    
    return { 
      success: true, 
      user,
      notification: notificationResult
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      code: error.message.includes('already exists') ? 'EMAIL_EXISTS' : 'CREATE_ERROR'
    };
  }
}

async function handleAdvancedUserRetrieval(context: Context) {
  const userRepo = context.container?.get(UserRepository);
  const cache = context.container?.get(CacheService);
  const db = context.container?.get(DatabaseService);
  
  // Manually registered services
  const version = context.container?.get('app.version');
  const featureFlags = context.container?.get('feature.flags');
  
  const userId = context.req.params?.id;
  
  if (!userId) {
    return { success: false, error: 'User ID is required' };
  }
  
  const user = await userRepo.findById(userId);
  
  if (!user) {
    return { success: false, error: 'User not found' };
  }
  
  return {
    success: true,
    user,
    meta: {
      version,
      features: featureFlags,
      cached: user.fromCache,
      cacheStats: cache.getStats(),
      dbStats: db.getStats()
    }
  };
}

async function handleBulkUserNotification(context: Context) {
  const notificationService = Container.get(NotificationService);
  
  const { userIds, message, type = 'email' } = context.req.parsedBody;
  
  if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
    return {
      success: false,
      error: 'userIds array is required'
    };
  }
  
  if (!message) {
    return {
      success: false,
      error: 'message is required'
    };
  }
  
  const result = await notificationService.sendBulkNotification(userIds, message, type);
  
  return {
    success: true,
    ...result
  };
}

async function handleUserSearch(context: Context) {
  const userRepo = Container.get(UserRepository);
  
  const search = context.req.query?.search;
  const page = parseInt(context.req.query?.page || '1');
  const limit = parseInt(context.req.query?.limit || '10');
  const offset = (page - 1) * limit;
  
  const users = await userRepo.findAll({ search, limit, offset });
  
  return {
    success: true,
    users,
    pagination: {
      page,
      limit,
      total: users.length // In real app, you'd get total count separately
    }
  };
}

async function handleSystemStats(context: Context) {
  const cache = Container.get(CacheService);
  const db = Container.get(DatabaseService);
  
  return {
    success: true,
    stats: {
      cache: cache.getStats(),
      database: db.getStats(),
      timestamp: new Date(),
      uptime: process.uptime()
    }
  };
}

// Handlers using named functions

// Method 1: Empty DI middleware (relies on @Service auto-registration)
export const simpleUserHandler = new Handler()
  .use(dependencyInjection()) // Empty services array
  .handle(handleCreateUserWithNotification);

// Method 2: Register additional non-decorated services
const hybridServices = [
  { id: 'app.version', value: process.env.APP_VERSION || '2.0.0' },
  { id: 'feature.flags', value: { 
    newUI: true, 
    betaFeatures: process.env.NODE_ENV === 'development',
    analytics: true
  }}
];

export const advancedUserHandler = new Handler()
  .use(dependencyInjection(hybridServices))
  .handle(handleAdvancedUserRetrieval);

export const bulkNotificationHandler = new Handler()
  .use(dependencyInjection())
  .handle(handleBulkUserNotification);

export const userSearchHandler = new Handler()
  .use(dependencyInjection())
  .handle(handleUserSearch);

export const systemStatsHandler = new Handler()
  .use(dependencyInjection())
  .handle(handleSystemStats);

// Export named functions for testing
export {
  handleCreateUserWithNotification,
  handleAdvancedUserRetrieval,
  handleBulkUserNotification,
  handleUserSearch,
  handleSystemStats
};
```

## Reusable Handler Patterns

Create reusable functions that can be shared across different handlers and endpoints.

### Generic CRUD Operations

```typescript
// handlers/reusable-patterns.ts
import { Context } from '@/core/handler';

// Validation helpers
export function validateRequiredFields(data: any, requiredFields: string[]): string | null {
  for (const field of requiredFields) {
    if (!data[field]) {
      return `${field} is required`;
    }
  }
  return null;
}

export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Permission and security helpers
export async function validateUserPermissions(
  context: Context, 
  requiredPermission: string
): Promise<boolean> {
  const user = context.user;
  
  if (!user) {
    throw new Error('Authentication required');
  }
  
  if (!user.permissions || !user.permissions.includes(requiredPermission)) {
    throw new Error(`Permission denied: ${requiredPermission} required`);
  }
  
  return true;
}

export async function logUserActivity(
  context: Context, 
  action: string, 
  details?: any
): Promise<void> {
  const logger = context.container?.get('logger') || context.container?.get(LoggerService);
  const auditService = context.container?.get('audit');
  
  const userId = context.user?.id || 'anonymous';
  const logData = {
    userId,
    action,
    details,
    ip: context.req.ip,
    userAgent: context.req.headers?.['user-agent'],
    timestamp: new Date(),
    requestId: context.requestId
  };
  
  if (logger) {
    logger.info(`User activity: ${action}`, logData);
  }
  
  if (auditService) {
    await auditService.logAction(logData);
  }
}

// Generic CRUD handler
export async function handleCRUDOperation(
  context: Context,
  operation: 'create' | 'read' | 'update' | 'delete',
  entityType: string,
  options: {
    requiredPermission?: string;
    requiredFields?: string[];
    validateEmail?: boolean;
    logActivity?: boolean;
  } = {}
) {
  // Validate permissions
  if (options.requiredPermission) {
    await validateUserPermissions(context, options.requiredPermission);
  }
  
  // Log activity
  if (options.logActivity !== false) {
    await logUserActivity(context, `${entityType}.${operation}`);
  }
  
  // Get the appropriate service
  const serviceName = `${entityType}Service`;
  const repository = context.container?.get(serviceName) || 
                    context.container?.get(`${entityType}Repository`);
  
  if (!repository) {
    throw new Error(`Service ${serviceName} not found`);
  }
  
  try {
    switch (operation) {
      case 'create': {
        const data = context.req.parsedBody;
        
        // Validate required fields
        if (options.requiredFields) {
          const error = validateRequiredFields(data, options.requiredFields);
          if (error) {
            return { success: false, error, code: 'VALIDATION_ERROR' };
          }
        }
        
        // Validate email if required
        if (options.validateEmail && data.email && !validateEmail(data.email)) {
          return { success: false, error: 'Invalid email format', code: 'VALIDATION_ERROR' };
        }
        
        const result = await repository.create(data);
        return { success: true, [entityType]: result };
      }
      
      case 'read': {
        const id = context.req.params?.id;
        if (!id) {
          return { success: false, error: 'ID is required' };
        }
        
        const result = await repository.findById(id);
        if (!result) {
          return { success: false, error: `${entityType} not found`, code: 'NOT_FOUND' };
        }
        
        return { success: true, [entityType]: result };
      }
      
      case 'update': {
        const id = context.req.params?.id;
        const updates = context.req.parsedBody;
        
        if (!id) {
          return { success: false, error: 'ID is required' };
        }
        
        // Validate email if being updated
        if (options.validateEmail && updates.email && !validateEmail(updates.email)) {
          return { success: false, error: 'Invalid email format', code: 'VALIDATION_ERROR' };
        }
        
        const result = await repository.update(id, updates);
        if (!result) {
          return { success: false, error: `${entityType} not found`, code: 'NOT_FOUND' };
        }
        
        return { success: true, [entityType]: result };
      }
      
      case 'delete': {
        const id = context.req.params?.id;
        if (!id) {
          return { success: false, error: 'ID is required' };
        }
        
        const result = await repository.delete(id);
        if (!result) {
          return { success: false, error: `${entityType} not found`, code: 'NOT_FOUND' };
        }
        
        return { success: true, message: `${entityType} deleted successfully` };
      }
      
      default:
        throw new Error(`Unsupported operation: ${operation}`);
    }
  } catch (error) {
    await logUserActivity(context, `${entityType}.${operation}.error`, { error: error.message });
    throw error;
  }
}

// Specific entity handlers using the generic pattern
export async function handleCreatePost(context: Context) {
  return handleCRUDOperation(context, 'create', 'post', {
    requiredPermission: 'post:create',
    requiredFields: ['title', 'content'],
    logActivity: true
  });
}

export async function handleUpdatePost(context: Context) {
  return handleCRUDOperation(context, 'update', 'post', {
    requiredPermission: 'post:update',
    logActivity: true
  });
}

export async function handleDeletePost(context: Context) {
  return handleCRUDOperation(context, 'delete', 'post', {
    requiredPermission: 'post:delete',
    logActivity: true
  });
}

export async function handleGetPost(context: Context) {
  return handleCRUDOperation(context, 'read', 'post', {
    requiredPermission: 'post:read',
    logActivity: false // Don't log read operations
  });
}

// User-specific handlers with email validation
export async function handleCreateUser(context: Context) {
  return handleCRUDOperation(context, 'create', 'user', {
    requiredPermission: 'user:create',
    requiredFields: ['name', 'email'],
    validateEmail: true,
    logActivity: true
  });
}

export async function handleUpdateUser(context: Context) {
  return handleCRUDOperation(context, 'update', 'user', {
    requiredPermission: 'user:update',
    validateEmail: true,
    logActivity: true
  });
}
```

### Error Handling and Response Formatting

```typescript
// handlers/response-helpers.ts
import { Context } from '@/core/handler';

export interface StandardResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
  meta?: {
    timestamp: string;
    requestId: string;
    version?: string;
    processingTime?: number;
  };
}

export function createSuccessResponse<T>(
  context: Context,
  data: T,
  meta?: Partial<StandardResponse['meta']>
): StandardResponse<T> {
  const processingTime = context.startTime ? Date.now() - context.startTime : undefined;
  
  return {
    success: true,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: context.requestId || 'unknown',
      processingTime,
      ...meta
    }
  };
}

export function createErrorResponse(
  context: Context,
  error: string,
  code?: string,
  statusCode?: number
): StandardResponse {
  const processingTime = context.startTime ? Date.now() - context.startTime : undefined;
  
  return {
    success: false,
    error,
    code,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: context.requestId || 'unknown',
      processingTime
    }
  };
}

export async function withErrorHandling<T>(
  context: Context,
  operation: () => Promise<T>
): Promise<StandardResponse<T>> {
  const logger = context.container?.get('logger');
  
  try {
    const result = await operation();
    return createSuccessResponse(context, result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    if (logger) {
      logger.error('Handler error', {
        error: errorMessage,
        requestId: context.requestId,
        stack: error instanceof Error ? error.stack : undefined
      });
    }
    
    // Map common errors to appropriate codes
    let code = 'INTERNAL_ERROR';
    if (errorMessage.includes('not found')) code = 'NOT_FOUND';
    if (errorMessage.includes('already exists')) code = 'CONFLICT';
    if (errorMessage.includes('Permission denied')) code = 'FORBIDDEN';
    if (errorMessage.includes('Authentication required')) code = 'UNAUTHORIZED';
    if (errorMessage.includes('validation') || errorMessage.includes('required')) code = 'VALIDATION_ERROR';
    
    return createErrorResponse(context, errorMessage, code);
  }
}

// Example usage of error handling helpers
export async function handleSafeUserCreation(context: Context) {
  return withErrorHandling(context, async () => {
    const userService = context.container?.get(UserService);
    const emailService = context.container?.get(EmailService);
    
    const userData = context.req.parsedBody;
    
    // Validation
    if (!userData.name || !userData.email) {
      throw new Error('Name and email are required');
    }
    
    if (!validateEmail(userData.email)) {
      throw new Error('Invalid email format');
    }
    
    // Create user
    const user = await userService.create(userData);
    
    // Send welcome email (non-blocking)
    emailService.sendWelcomeEmail(user.email, user.name)
      .catch(error => console.log('Failed to send welcome email:', error));
    
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt
      },
      message: 'User created successfully'
    };
  });
}
```

## Testing Benefits

Named functions make testing much easier and more reliable.

### Unit Testing Named Functions

```typescript
// tests/handlers.test.ts
import { describe, test, expect, beforeEach, vi } from 'vitest';
import { 
  handleCreateUser, 
  handleGetUser,
  handleUpdateUser,
  handleListUsers
} from '../handlers/user-handlers';
import { UserService, EmailService, LoggerService } from '../services/core-services';

// Mock context creator
function createMockContext(overrides: any = {}) {
  const mockContainer = {
    get: vi.fn((serviceId) => {
      if (serviceId === UserService) return mockUserService;
      if (serviceId === EmailService) return mockEmailService;
      if (serviceId === LoggerService) return mockLogger;
      if (serviceId === 'config') return mockConfig;
      return null;
    })
  };
  
  return {
    req: {
      parsedBody: {},
      params: {},
      query: {},
      ...overrides.req
    },
    container: mockContainer,
    requestId: 'test-request-123',
    startTime: Date.now(),
    user: overrides.user,
    ...overrides
  };
}

// Mock services
const mockUserService = {
  create: vi.fn(),
  findById: vi.fn(),
  findAll: vi.fn(),
  update: vi.fn(),
  delete: vi.fn()
};

const mockEmailService = {
  sendWelcomeEmail: vi.fn().mockResolvedValue({ messageId: 'test-msg', sent: true })
};

const mockLogger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn()
};

const mockConfig = {
  apiUrl: 'https://test-api.example.com',
  version: '1.0.0-test'
};

describe('User Handlers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('handleCreateUser', () => {
    test('should create user successfully', async () => {
      const userData = { name: 'John Doe', email: 'john@example.com' };
      const createdUser = { id: '123', ...userData, createdAt: new Date() };
      
      mockUserService.create.mockResolvedValue(createdUser);
      
      const context = createMockContext({
        req: { parsedBody: userData }
      });
      
      const result = await handleCreateUser(context);
      
      expect(result.success).toBe(true);
      expect(result.user).toEqual({
        id: '123',
        name: 'John Doe',
        email: 'john@example.com',
        createdAt: createdUser.createdAt
      });
      expect(mockUserService.create).toHaveBeenCalledWith(userData);
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith('john@example.com', 'John Doe');
      expect(mockLogger.info).toHaveBeenCalledWith('Creating new user', expect.any(Object));
    });

    test('should handle invalid email format', async () => {
      const userData = { name: 'John Doe', email: 'invalid-email' };
      
      const context = createMockContext({
        req: { parsedBody: userData }
      });
      
      await expect(handleCreateUser(context)).rejects.toThrow('Invalid email format');
      expect(mockUserService.create).not.toHaveBeenCalled();
      expect(mockLogger.error).toHaveBeenCalled();
    });

    test('should handle service errors', async () => {
      const userData = { name: 'John Doe', email: 'john@example.com' };
      
      mockUserService.create.mockRejectedValue(new Error('Database connection failed'));
      
      const context = createMockContext({
        req: { parsedBody: userData }
      });
      
      await expect(handleCreateUser(context)).rejects.toThrow('Database connection failed');
      expect(mockLogger.error).toHaveBeenCalledWith('User creation failed', expect.any(Object));
    });
  });

  describe('handleGetUser', () => {
    test('should retrieve user successfully', async () => {
      const user = { 
        id: '123', 
        name: 'John Doe', 
        email: 'john@example.com',
        createdAt: new Date()
      };
      
      mockUserService.findById.mockResolvedValue(user);
      
      const context = createMockContext({
        req: { params: { id: '123' } }
      });
      
      const result = await handleGetUser(context);
      
      expect(result.success).toBe(true);
      expect(result.user).toEqual(user);
      expect(mockUserService.findById).toHaveBeenCalledWith('123');
    });

    test('should handle user not found', async () => {
      mockUserService.findById.mockResolvedValue(null);
      
      const context = createMockContext({
        req: { params: { id: 'nonexistent' } }
      });
      
      const result = await handleGetUser(context);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('User not found');
      expect(mockLogger.warn).toHaveBeenCalledWith('User not found', { userId: 'nonexistent' });
    });

    test('should handle missing user ID', async () => {
      const context = createMockContext({
        req: { params: {} }
      });
      
      const result = await handleGetUser(context);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('User ID is required');
      expect(mockUserService.findById).not.toHaveBeenCalled();
    });
  });

  describe('handleListUsers', () => {
    test('should list users with pagination', async () => {
      const users = [
        { id: '1', name: 'User 1', email: 'user1@example.com' },
        { id: '2', name: 'User 2', email: 'user2@example.com' },
        { id: '3', name: 'User 3', email: 'user3@example.com' }
      ];
      
      mockUserService.findAll.mockResolvedValue(users);
      
      const context = createMockContext({
        req: { 
          query: { 
            page: '2', 
            limit: '2' 
          } 
        }
      });
      
      const result = await handleListUsers(context);
      
      expect(result.success).toBe(true);
      expect(result.users).toHaveLength(1); // Page 2 with limit 2 should return 1 user
      expect(result.pagination).toEqual({
        page: 2,
        limit: 2,
        total: 3,
        totalPages: 2,
        hasNextPage: false,
        hasPreviousPage: true
      });
    });

    test('should filter users by search term', async () => {
      const users = [
        { id: '1', name: 'John Doe', email: 'john@example.com' },
        { id: '2', name: 'Jane Smith', email: 'jane@example.com' },
        { id: '3', name: 'Bob Johnson', email: 'bob@example.com' }
      ];
      
      mockUserService.findAll.mockResolvedValue(users);
      
      const context = createMockContext({
        req: { 
          query: { 
            search: 'john',
            page: '1',
            limit: '10'
          } 
        }
      });
      
      const result = await handleListUsers(context);
      
      expect(result.success).toBe(true);
      expect(result.users).toHaveLength(2); // John Doe and Bob Johnson
      expect(result.users.some(u => u.name === 'John Doe')).toBe(true);
      expect(result.users.some(u => u.name === 'Bob Johnson')).toBe(true);
    });
  });
});

// Integration testing with real DI middleware
describe('User Handlers Integration', () => {
  test('should work with real DI middleware', async () => {
    const { userDI } = await import('../handlers/user-handlers');
    const { Handler } = await import('@/core/handler');
    
    // Create a real handler for testing
    const testHandler = new Handler()
      .use(userDI)
      .handle(handleCreateUser);
    
    // Mock request and response
    const mockReq = {
      body: JSON.stringify({ name: 'Test User', email: 'test@example.com' }),
      method: 'POST',
      url: '/users',
      headers: { 'content-type': 'application/json' }
    };
    
    const mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
      send: vi.fn()
    };
    
    // Execute the handler
    await testHandler.execute(mockReq, mockRes);
    
    // Verify response
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        user: expect.objectContaining({
          name: 'Test User',
          email: 'test@example.com'
        })
      })
    );
  });
});
```

### Testing @Service Decorated Classes

```typescript
// tests/decorated-handlers.test.ts
import { describe, test, expect, beforeEach, vi } from 'vitest';
import { Container } from 'typedi';
import { 
  handleCreateUserWithNotification,
  handleAdvancedUserRetrieval 
} from '../handlers/decorated-handlers';
import { UserRepository, NotificationService, CacheService } from '../services/decorated-services';

// Mock implementations
class MockUserRepository {
  create = vi.fn();
  findById = vi.fn();
  findAll = vi.fn();
  update = vi.fn();
  delete = vi.fn();
}

class MockNotificationService {
  sendNotification = vi.fn();
  sendBulkNotification = vi.fn();
}

class MockCacheService {
  get = vi.fn();
  set = vi.fn();
  delete = vi.fn();
  getStats = vi.fn().mockReturnValue({ hits: 10, misses: 2, hitRate: 83.3 });
}

describe('Decorated Handlers', () => {
  beforeEach(() => {
    // Reset Container and register mocks
    Container.reset();
    Container.set(UserRepository, new MockUserRepository());
    Container.set(NotificationService, new MockNotificationService());
    Container.set(CacheService, new MockCacheService());
    
    vi.clearAllMocks();
  });

  describe('handleCreateUserWithNotification', () => {
    test('should create user and send notification', async () => {
      const userData = { name: 'John Doe', email: 'john@example.com' };
      const createdUser = { id: '123', ...userData, createdAt: new Date() };
      const notificationResult = { sent: true, notifications: [{ type: 'email', result: { sent: true } }] };
      
      const mockUserRepo = Container.get(UserRepository) as MockUserRepository;
      const mockNotificationService = Container.get(NotificationService) as MockNotificationService;
      
      mockUserRepo.create.mockResolvedValue(createdUser);
      mockNotificationService.sendNotification.mockResolvedValue(notificationResult);
      
      const context = {
        req: { parsedBody: userData },
        container: Container
      };
      
      const result = await handleCreateUserWithNotification(context as any);
      
      expect(result.success).toBe(true);
      expect(result.user).toEqual(createdUser);
      expect(result.notification).toEqual(notificationResult);
      
      expect(mockUserRepo.create).toHaveBeenCalledWith(userData);
      expect(mockNotificationService.sendNotification).toHaveBeenCalledWith(
        '123',
        'Welcome John Doe! Thanks for joining our platform.',
        'email'
      );
    });

    test('should handle validation errors', async () => {
      const invalidUserData = { name: '', email: '' };
      
      const context = {
        req: { parsedBody: invalidUserData },
        container: Container
      };
      
      const result = await handleCreateUserWithNotification(context as any);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Name and email are required');
      expect(result.code).toBe('VALIDATION_ERROR');
      
      const mockUserRepo = Container.get(UserRepository) as MockUserRepository;
      expect(mockUserRepo.create).not.toHaveBeenCalled();
    });

    test('should handle email already exists error', async () => {
      const userData = { name: 'John Doe', email: 'john@example.com' };
      
      const mockUserRepo = Container.get(UserRepository) as MockUserRepository;
      mockUserRepo.create.mockRejectedValue(new Error('Email john@example.com already exists'));
      
      const context = {
        req: { parsedBody: userData },
        container: Container
      };
      
      const result = await handleCreateUserWithNotification(context as any);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Email john@example.com already exists');
      expect(result.code).toBe('EMAIL_EXISTS');
    });
  });

  describe('handleAdvancedUserRetrieval', () => {
    test('should retrieve user with metadata', async () => {
      const user = { 
        id: '123', 
        name: 'John Doe', 
        email: 'john@example.com',
        fromCache: true
      };
      
      const mockUserRepo = Container.get(UserRepository) as MockUserRepository;
      const mockCache = Container.get(CacheService) as MockCacheService;
      
      mockUserRepo.findById.mockResolvedValue(user);
      
      const context = {
        req: { params: { id: '123' } },
        container: {
          get: vi.fn((key) => {
            if (key === UserRepository) return mockUserRepo;
            if (key === CacheService) return mockCache;
            if (key === 'app.version') return '2.0.0';
            if (key === 'feature.flags') return { newUI: true };
            return null;
          })
        }
      };
      
      const result = await handleAdvancedUserRetrieval(context as any);
      
      expect(result.success).toBe(true);
      expect(result.user).toEqual(user);
      expect(result.meta).toEqual({
        version: '2.0.0',
        features: { newUI: true },
        cached: true,
        cacheStats: { hits: 10, misses: 2, hitRate: 83.3 },
        dbStats: undefined // Since we're not mocking db service
      });
    });
  });
});
```

## Best Practices

### 1. Service Organization

```typescript
// ✅ Good: Organized service structure
services/
├── core/
│   ├── database.service.ts      # Database operations
│   ├── cache.service.ts         # Caching operations
│   └── logger.service.ts        # Logging operations
├── business/
│   ├── user.service.ts          # User business logic
│   ├── notification.service.ts  # Notification logic
│   └── auth.service.ts          # Authentication logic
├── external/
│   ├── email.service.ts         # External email API
│   ├── payment.service.ts       # External payment API
│   └── analytics.service.ts     # External analytics API
└── utils/
    ├── validation.service.ts    # Validation utilities
    └── encryption.service.ts    # Encryption utilities
```

### 2. Environment-Based Configuration

```typescript
// config/services.config.ts
import { UserService, EmailService, LoggerService } from '../services';

export function createServicesConfig(env: string = process.env.NODE_ENV || 'development') {
  const baseConfig = {
    apiUrl: process.env.API_URL || 'http://localhost:3000',
    version: process.env.APP_VERSION || '1.0.0'
  };

  if (env === 'production') {
    return {
      services: [
        { id: UserService, value: new UserService(createProductionDatabase()) },
        { id: EmailService, value: new EmailService(createProductionEmailConfig()) },
        { id: LoggerService, value: new LoggerService('PROD') },
        { id: 'config', value: { ...baseConfig, logLevel: 'warn' } }
      ]
    };
  }

  if (env === 'test') {
    return {
      services: [
        { id: UserService, value: new UserService(createTestDatabase()) },
        { id: EmailService, value: new MockEmailService() },
        { id: LoggerService, value: new TestLoggerService() },
        { id: 'config', value: { ...baseConfig, logLevel: 'silent' } }
      ]
    };
  }

  // Development
  return {
    services: [
      { id: UserService, value: new UserService() },
      { id: EmailService, value: new EmailService(createDevEmailConfig()) },
      { id: LoggerService, value: new LoggerService('DEV') },
      { id: 'config', value: { ...baseConfig, logLevel: 'debug' } }
    ]
  };
}

// Usage in handlers
const servicesConfig = createServicesConfig();
const diMiddleware = new DependencyInjectionMiddleware(servicesConfig.services);
```

### 3. Type Safety with Generics

```typescript
// types/di.types.ts
export interface ServiceContainer {
  get<T>(serviceId: new () => T): T;
  get<T>(serviceId: string): T;
  get<T>(serviceId: any): T;
}

export interface TypedContext extends Context {
  container: ServiceContainer;
}

// Usage in handlers with proper typing
async function handleTypedUserCreation(context: TypedContext) {
  // Fully typed service access
  const userService = context.container.get(UserService); // Type: UserService
  const emailService = context.container.get(EmailService); // Type: EmailService
  const config = context.container.get<AppConfig>('config'); // Type: AppConfig
  
  // Rest of handler logic...
}
```

### 4. Service Health Checks

```typescript
// services/health.service.ts
@Service()
export class HealthService {
  constructor(
    @Inject(() => DatabaseService) private db: DatabaseService,
    @Inject(() => CacheService) private cache: CacheService,
    @Inject(() => EmailService) private email: EmailService
  ) {}

  async checkHealth() {
    const checks = await Promise.allSettled([
      this.checkDatabase(),
      this.checkCache(),
      this.checkEmail()
    ]);

    return {
      status: checks.every(check => check.status === 'fulfilled') ? 'healthy' : 'unhealthy',
      checks: {
        database: checks[0].status === 'fulfilled' ? 'ok' : 'error',
        cache: checks[1].status === 'fulfilled' ? 'ok' : 'error',
        email: checks[2].status === 'fulfilled' ? 'ok' : 'error'
      },
      timestamp: new Date().toISOString()
    };
  }

  private async checkDatabase() {
    await this.db.query('SELECT 1');
  }

  private async checkCache() {
    this.cache.set('health_check', 'ok', 1);
    const result = this.cache.get('health_check');
    if (result !== 'ok') throw new Error('Cache not working');
  }

  private async checkEmail() {
    // Mock email service check
    return true;
  }
}

// Health check handler
async function handleHealthCheck(context: Context) {
  const healthService = context.container?.get(HealthService);
  const health = await healthService.checkHealth();
  
  return {
    success: true,
    ...health
  };
}
```

## Migration Patterns

### From Manual to @Service

```typescript
// Step 1: Current manual setup
const services = [
  { id: UserService, value: new UserService(new DatabaseService()) }
];

// Step 2: Add @Service decorators
@Service()
export class DatabaseService { /* ... */ }

@Service()
export class UserService {
  constructor(@Inject(() => DatabaseService) private db: DatabaseService) {}
}

// Step 3: Remove manual instantiation
const services = []; // Now empty!

// Step 4: Handlers work the same
const handler = new Handler()
  .use(dependencyInjection(services))
  .handle(handleUserCreation); // No changes needed!
```

### Gradual Migration Strategy

```typescript
// Phase 1: Hybrid approach
const hybridServices = [
  // Keep some manual services
  { id: 'config', value: appConfig },
  { id: 'external-api', value: externalApiClient },
  
  // Start migrating core services to @Service
  // DatabaseService and UserService now use @Service decorator
];

// Phase 2: Move more services
const almostAutoServices = [
  // Only configuration and external dependencies remain manual
  { id: 'config', value: appConfig },
  { id: 'payment-gateway', value: paymentGateway },
];

// Phase 3: Fully automatic
const fullyAutoServices = [
  // Only configuration values
  { id: 'config', value: appConfig }
];
```

## Common Patterns

### 1. Request/Response Middleware Pattern

```typescript
async function withRequestResponseLogging(
  context: Context,
  operation: () => Promise<any>
) {
  const logger = context.container?.get(LoggerService);
  const startTime = Date.now();
  
  logger?.info('Request started', {
    method: context.req.method,
    url: context.req.url,
    requestId: context.requestId
  });
  
  try {
    const result = await operation();
    
    logger?.info('Request completed', {
      requestId: context.requestId,
      duration: Date.now() - startTime,
      success: true
    });
    
    return result;
  } catch (error) {
    logger?.error('Request failed', {
      requestId: context.requestId,
      duration: Date.now() - startTime,
      error: error.message
    });
    
    throw error;
  }
}

// Usage
async function handleUserCreationWithLogging(context: Context) {
  return withRequestResponseLogging(context, async () => {
    const userService = context.container?.get(UserService);
    return await userService.create(context.req.parsedBody);
  });
}
```

### 2. Caching Pattern

```typescript
async function withCaching<T>(
  context: Context,
  cacheKey: string,
  operation: () => Promise<T>,
  ttl: number = 300
): Promise<T> {
  const cache = context.container?.get(CacheService);
  
  if (cache) {
    const cached = cache.get(cacheKey);
    if (cached) {
      return cached;
    }
  }
  
  const result = await operation();
  
  if (cache) {
    cache.set(cacheKey, result, ttl);
  }
  
  return result;
}

// Usage
async function handleCachedUserRetrieval(context: Context) {
  const userId = context.req.params?.id;
  
  return withCaching(
    context,
    `user:${userId}`,
    async () => {
      const userService = context.container?.get(UserService);
      return await userService.findById(userId);
    },
    600 // 10 minutes
  );
}
```

### 3. Transaction Pattern

```typescript
async function withTransaction<T>(
  context: Context,
  operation: (tx: any) => Promise<T>
): Promise<T> {
  const db = context.container?.get(DatabaseService);
  
  return db.transaction(async () => {
    return await operation(db);
  });
}

// Usage
async function handleComplexUserUpdate(context: Context) {
  return withTransaction(context, async (db) => {
    const userService = context.container?.get(UserService);
    const auditService = context.container?.get(AuditService);
    
    const user = await userService.update(context.req.params?.id, context.req.parsedBody);
    await auditService.logUpdate(user.id, context.req.parsedBody);
    
    return user;
  });
}
```

This comprehensive guide shows you how to effectively use the `DependencyInjectionMiddleware` with named functions, making your code more maintainable, testable, and reusable while supporting both manual and automatic dependency injection patterns.
