# Noony Framework Testing Patterns Rules

## Jest Configuration and Setup

### Project Test Configuration

```typescript
// jest.config.js - Standard Noony framework Jest configuration
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',        // Exclude index files
    '!src/**/*.test.ts',    // Exclude test files
    '!src/**/__tests__/**'  // Exclude test directories
  ],
  setupFilesAfterEnv: ['<rootDir>/src/test-setup.ts'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1'  // Path mapping support
  },
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
```

### Test Setup File

```typescript
// src/test-setup.ts - Global test configuration
import 'reflect-metadata';
import { Container } from 'typedi';

// Global test setup
beforeEach(() => {
  // Reset TypeDI container before each test
  Container.reset();
  
  // Clear all timers
  jest.clearAllTimers();
  
  // Reset all mocks
  jest.clearAllMocks();
});

afterEach(() => {
  // Clean up after each test
  Container.reset();
});

// Global test utilities
global.createMockContext = (overrides = {}) => {
  return {
    req: {
      body: {},
      headers: {},
      query: {},
      params: {},
      method: 'POST',
      path: '/test',
      ...overrides.req
    },
    res: {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      header: jest.fn().mockReturnThis(),
      ...overrides.res
    },
    user: null,
    requestId: 'test-request-id',
    startTime: Date.now(),
    businessData: new Map(),
    ...overrides
  };
};
```

## Handler Testing Patterns

### Handler Integration Testing

```typescript
// handler.test.ts - Testing complete handler pipeline
import { Handler, ErrorHandlerMiddleware, BodyValidationMiddleware } from '@noony-serverless/core';
import { z } from 'zod';

describe('UserHandler Integration Tests', () => {
  const createUserSchema = z.object({
    name: z.string().min(2),
    email: z.string().email(),
    age: z.number().min(18)
  });

  type CreateUserRequest = z.infer<typeof createUserSchema>;
  
  interface TestUser {
    id: string;
    role: 'user' | 'admin';
  }

  let handler: Handler<CreateUserRequest, TestUser>;
  let mockUserService: jest.Mocked<UserService>;

  beforeEach(() => {
    // Create mocked service
    mockUserService = {
      createUser: jest.fn(),
      findById: jest.fn(),
      updateUser: jest.fn()
    } as any;

    // Register mock in container
    Container.set(UserService, mockUserService);

    // Create handler with full middleware stack
    handler = new Handler<CreateUserRequest, TestUser>()
      .use(new ErrorHandlerMiddleware<CreateUserRequest, TestUser>())
      .use(new BodyValidationMiddleware<CreateUserRequest, TestUser>(createUserSchema))
      .use(new DependencyInjectionMiddleware<CreateUserRequest, TestUser>([UserService]))
      .handle(async (context) => {
        const userService = Container.get(UserService);
        const user = await userService.createUser(context.req.validatedBody!);
        context.res.status(201).json({ user });
      });
  });

  it('should create user successfully with valid data', async () => {
    // Arrange
    const userData = { name: 'John Doe', email: 'john@example.com', age: 25 };
    const expectedUser = { id: '123', ...userData };
    mockUserService.createUser.mockResolvedValue(expectedUser);

    const mockContext = createMockContext({
      req: { validatedBody: userData },
      user: { id: 'admin-123', role: 'admin' }
    });

    // Act
    await handler.handle(mockContext);

    // Assert
    expect(mockUserService.createUser).toHaveBeenCalledWith(userData);
    expect(mockContext.res.status).toHaveBeenCalledWith(201);
    expect(mockContext.res.json).toHaveBeenCalledWith({ user: expectedUser });
  });

  it('should handle validation errors properly', async () => {
    // Arrange
    const invalidData = { name: 'J', email: 'invalid-email', age: 17 };
    const mockContext = createMockContext({
      req: { validatedBody: invalidData }
    });

    // Act & Assert
    await expect(handler.handle(mockContext)).rejects.toThrow();
    expect(mockUserService.createUser).not.toHaveBeenCalled();
  });

  it('should handle service errors properly', async () => {
    // Arrange
    const userData = { name: 'John Doe', email: 'john@example.com', age: 25 };
    mockUserService.createUser.mockRejectedValue(new BusinessError('Email already exists'));

    const mockContext = createMockContext({
      req: { validatedBody: userData }
    });

    // Act & Assert
    await expect(handler.handle(mockContext)).rejects.toThrow(BusinessError);
  });
});
```

### Handler Unit Testing (Business Logic Only)

```typescript
// handler-unit.test.ts - Testing handler business logic in isolation
describe('UserHandler Business Logic', () => {
  it('should execute business logic correctly', async () => {
    // Arrange - Mock all dependencies
    const mockUserService = {
      createUser: jest.fn().mockResolvedValue({ id: '123', name: 'John' })
    };
    
    Container.set(UserService, mockUserService);

    const businessLogic = async (context: Context<CreateUserRequest, TestUser>) => {
      const userService = Container.get(UserService);
      const user = await userService.createUser(context.req.validatedBody!);
      context.res.status(201).json({ user });
    };

    const mockContext = createMockContext({
      req: { validatedBody: { name: 'John', email: 'john@test.com', age: 25 } }
    });

    // Act
    await businessLogic(mockContext);

    // Assert
    expect(mockUserService.createUser).toHaveBeenCalled();
    expect(mockContext.res.status).toHaveBeenCalledWith(201);
  });
});
```

## Middleware Testing Strategies

### Middleware Unit Testing

```typescript
// middleware.test.ts - Testing middleware in isolation
describe('CustomValidationMiddleware', () => {
  let middleware: CustomValidationMiddleware<TestRequest, TestUser>;
  let mockContext: Context<TestRequest, TestUser>;
  let mockValidationService: jest.Mocked<ValidationService>;

  beforeEach(() => {
    mockValidationService = {
      validateBusinessRules: jest.fn()
    };
    
    middleware = new CustomValidationMiddleware(mockValidationService);
    
    mockContext = createMockContext({
      req: {
        validatedBody: { id: '123', name: 'Test User' }
      },
      user: { id: 'user-456', role: 'user' }
    }) as Context<TestRequest, TestUser>;
  });

  describe('before hook', () => {
    it('should validate business rules successfully', async () => {
      // Arrange
      mockValidationService.validateBusinessRules.mockResolvedValue(true);

      // Act
      await middleware.before!(mockContext);

      // Assert
      expect(mockValidationService.validateBusinessRules).toHaveBeenCalledWith(
        mockContext.req.validatedBody,
        mockContext.user
      );
      expect(mockContext.businessData?.get('validated')).toBe(true);
    });

    it('should throw ValidationError when business rules fail', async () => {
      // Arrange
      mockValidationService.validateBusinessRules.mockRejectedValue(
        new Error('Business rule violation')
      );

      // Act & Assert
      await expect(middleware.before!(mockContext)).rejects.toThrow(ValidationError);
    });
  });

  describe('after hook', () => {
    it('should log successful validation', async () => {
      // Arrange
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      mockContext.businessData?.set('validated', true);

      // Act
      await middleware.after!(mockContext);

      // Assert
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Validation completed')
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('onError hook', () => {
    it('should handle validation errors appropriately', async () => {
      // Arrange
      const error = new ValidationError('Test validation error');
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      // Act
      await middleware.onError!(error, mockContext);

      // Assert
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Validation error'),
        expect.objectContaining({ error: error.message })
      );
      
      consoleSpy.mockRestore();
    });
  });
});
```

### Middleware Chain Testing

```typescript
// middleware-chain.test.ts - Testing middleware interactions
describe('Middleware Chain Integration', () => {
  let handler: Handler<TestRequest, TestUser>;
  let authMiddleware: AuthenticationMiddleware<TestRequest, TestUser>;
  let validationMiddleware: BodyValidationMiddleware<TestRequest, TestUser>;
  let businessMiddleware: BusinessLogicMiddleware<TestRequest, TestUser>;

  beforeEach(() => {
    // Create middleware instances
    authMiddleware = new AuthenticationMiddleware(mockTokenValidator);
    validationMiddleware = new BodyValidationMiddleware(testSchema);
    businessMiddleware = new BusinessLogicMiddleware();

    // Create handler with middleware chain
    handler = new Handler<TestRequest, TestUser>()
      .use(new ErrorHandlerMiddleware<TestRequest, TestUser>())
      .use(authMiddleware)
      .use(validationMiddleware)
      .use(businessMiddleware)
      .handle(async (context) => {
        context.res.json({ success: true });
      });
  });

  it('should execute middleware in correct order', async () => {
    // Arrange
    const executionOrder: string[] = [];
    
    // Spy on middleware methods to track execution order
    jest.spyOn(authMiddleware, 'before').mockImplementation(async () => {
      executionOrder.push('auth-before');
    });
    jest.spyOn(validationMiddleware, 'before').mockImplementation(async () => {
      executionOrder.push('validation-before');
    });
    jest.spyOn(businessMiddleware, 'before').mockImplementation(async () => {
      executionOrder.push('business-before');
    });

    const mockContext = createMockContext({
      req: { headers: { authorization: 'Bearer valid-token' } }
    });

    // Act
    await handler.handle(mockContext);

    // Assert - Before hooks execute in registration order
    expect(executionOrder).toEqual([
      'auth-before',
      'validation-before', 
      'business-before'
    ]);
  });

  it('should execute after hooks in reverse order', async () => {
    // Test after hooks execute in reverse order
    // Implementation similar to above but tracking after hooks
  });

  it('should stop execution when middleware throws error', async () => {
    // Arrange
    jest.spyOn(authMiddleware, 'before').mockRejectedValue(
      new AuthenticationError('Invalid token')
    );
    const validationSpy = jest.spyOn(validationMiddleware, 'before');

    const mockContext = createMockContext();

    // Act & Assert
    await expect(handler.handle(mockContext)).rejects.toThrow(AuthenticationError);
    expect(validationSpy).not.toHaveBeenCalled(); // Subsequent middleware shouldn't execute
  });
});
```

## Service Testing Patterns

### Service Unit Testing with Mocks

```typescript
// service.test.ts - Service layer testing
describe('UserService', () => {
  let userService: UserService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockEmailService: jest.Mocked<EmailService>;
  let mockLogger: jest.Mocked<Logger>;

  beforeEach(() => {
    // Create mocks
    mockUserRepository = {
      create: jest.fn(),
      findById: jest.fn(),
      findByEmail: jest.fn(),
      update: jest.fn(),
      delete: jest.fn()
    };

    mockEmailService = {
      sendWelcomeEmail: jest.fn(),
      sendPasswordReset: jest.fn()
    };

    mockLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn()
    };

    // Create service with mocked dependencies
    userService = new UserService(mockUserRepository, mockEmailService, mockLogger);
  });

  describe('createUser', () => {
    it('should create user and send welcome email', async () => {
      // Arrange
      const userData = { name: 'John Doe', email: 'john@example.com', age: 25 };
      const expectedUser = { id: '123', ...userData, createdAt: new Date() };
      
      mockUserRepository.create.mockResolvedValue(expectedUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue();

      // Act
      const result = await userService.createUser(userData);

      // Assert
      expect(mockUserRepository.create).toHaveBeenCalledWith(userData);
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(userData.email);
      expect(mockLogger.info).toHaveBeenCalledWith(`User created: ${expectedUser.id}`);
      expect(result).toEqual(expectedUser);
    });

    it('should throw error when email already exists', async () => {
      // Arrange
      const userData = { name: 'John Doe', email: 'john@example.com', age: 25 };
      mockUserRepository.create.mockRejectedValue(
        new ValidationError('Email already exists')
      );

      // Act & Assert
      await expect(userService.createUser(userData)).rejects.toThrow(ValidationError);
      expect(mockEmailService.sendWelcomeEmail).not.toHaveBeenCalled();
    });

    it('should handle email service failures gracefully', async () => {
      // Arrange
      const userData = { name: 'John Doe', email: 'john@example.com', age: 25 };
      const expectedUser = { id: '123', ...userData };
      
      mockUserRepository.create.mockResolvedValue(expectedUser);
      mockEmailService.sendWelcomeEmail.mockRejectedValue(
        new Error('Email service unavailable')
      );

      // Act & Assert
      await expect(userService.createUser(userData)).rejects.toThrow();
      expect(mockUserRepository.create).toHaveBeenCalled();
      expect(mockLogger.error).toHaveBeenCalled();
    });
  });
});
```

### Integration Testing with Real Dependencies

```typescript
// integration.test.ts - Testing with real database
describe('UserService Integration Tests', () => {
  let userService: UserService;
  let testDatabase: TestDatabase;
  let realUserRepository: UserRepository;

  beforeAll(async () => {
    // Set up test database
    testDatabase = new TestDatabase();
    await testDatabase.setup();
    
    // Create real repository with test database
    realUserRepository = new UserRepository(testDatabase.connection);
    
    // Use real repository but mock external services
    const mockEmailService = {
      sendWelcomeEmail: jest.fn().mockResolvedValue()
    };
    
    userService = new UserService(
      realUserRepository, 
      mockEmailService as any, 
      console as any
    );
  });

  afterAll(async () => {
    await testDatabase.teardown();
  });

  beforeEach(async () => {
    // Clean database before each test
    await testDatabase.clean();
  });

  it('should create and retrieve user from database', async () => {
    // Arrange
    const userData = { name: 'John Doe', email: 'john@test.com', age: 25 };

    // Act
    const createdUser = await userService.createUser(userData);
    const retrievedUser = await realUserRepository.findById(createdUser.id);

    // Assert
    expect(retrievedUser).toBeTruthy();
    expect(retrievedUser?.email).toBe(userData.email);
    expect(retrievedUser?.name).toBe(userData.name);
  });

  it('should prevent duplicate email addresses', async () => {
    // Arrange
    const userData1 = { name: 'John Doe', email: 'john@test.com', age: 25 };
    const userData2 = { name: 'Jane Doe', email: 'john@test.com', age: 28 };

    // Act
    await userService.createUser(userData1);

    // Assert
    await expect(userService.createUser(userData2)).rejects.toThrow(ValidationError);
  });
});
```

## Mock Creation and Test Utilities

### Mock Factory Patterns

```typescript
// test-utils/mock-factory.ts - Centralized mock creation
export class MockFactory {
  static createMockUser(overrides: Partial<User> = {}): User {
    return {
      id: 'mock-user-id',
      name: 'Mock User',
      email: 'mock@example.com',
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...overrides
    };
  }

  static createMockContext<T, U>(overrides: Partial<Context<T, U>> = {}): Context<T, U> {
    return {
      req: {
        body: {},
        headers: {},
        query: {},
        params: {},
        method: 'POST',
        path: '/test',
        ...overrides.req
      },
      res: {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
        send: jest.fn().mockReturnThis(),
        header: jest.fn().mockReturnThis(),
        ...overrides.res
      },
      user: null,
      requestId: 'test-request-id',
      startTime: Date.now(),
      businessData: new Map(),
      ...overrides
    } as Context<T, U>;
  }

  static createMockUserService(): jest.Mocked<UserService> {
    return {
      createUser: jest.fn(),
      findById: jest.fn(),
      updateUser: jest.fn(),
      deleteUser: jest.fn(),
      listUsers: jest.fn()
    } as any;
  }

  static createMockRepository<T>(): jest.Mocked<BaseRepository<T>> {
    return {
      create: jest.fn(),
      findById: jest.fn(),
      findAll: jest.fn(),
      update: jest.fn(),
      delete: jest.fn()
    };
  }
}

// Usage in tests
describe('Example Test', () => {
  it('should use mock factory', () => {
    const mockUser = MockFactory.createMockUser({ role: 'admin' });
    const mockContext = MockFactory.createMockContext({ user: mockUser });
    const mockService = MockFactory.createMockUserService();
    
    // Test implementation
  });
});
```

### Custom Jest Matchers

```typescript
// test-utils/custom-matchers.ts - Custom Jest matchers for the framework
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidUser(): R;
      toHaveBeenCalledWithContext(): R;
      toThrowNoonyError(errorType: string): R;
    }
  }
}

expect.extend({
  toBeValidUser(received: any) {
    const pass = received &&
      typeof received.id === 'string' &&
      typeof received.email === 'string' &&
      received.email.includes('@') &&
      ['user', 'admin', 'moderator'].includes(received.role);

    return {
      message: () => `expected ${received} to be a valid user object`,
      pass
    };
  },

  toHaveBeenCalledWithContext(received: jest.Mock) {
    const calls = received.mock.calls;
    const pass = calls.some(call => 
      call[0] && 
      typeof call[0] === 'object' &&
      'req' in call[0] &&
      'res' in call[0] &&
      'requestId' in call[0]
    );

    return {
      message: () => `expected function to have been called with a Context object`,
      pass
    };
  },

  toThrowNoonyError(received: () => any, errorType: string) {
    let thrownError: any;
    try {
      received();
    } catch (error) {
      thrownError = error;
    }

    const pass = thrownError && thrownError.constructor.name === errorType;

    return {
      message: () => `expected function to throw ${errorType}, but got ${thrownError?.constructor?.name || 'no error'}`,
      pass
    };
  }
});
```

## Testing Async Operations and Timing

### Testing Promises and Async/Await

```typescript
describe('Async Operations', () => {
  it('should handle async operations correctly', async () => {
    // Arrange
    const mockAsyncService = {
      processData: jest.fn().mockResolvedValue({ processed: true })
    };

    // Act
    const result = await someAsyncFunction(mockAsyncService);

    // Assert
    expect(result).toBeTruthy();
    expect(mockAsyncService.processData).toHaveBeenCalled();
  });

  it('should handle async errors properly', async () => {
    // Arrange
    const mockAsyncService = {
      processData: jest.fn().mockRejectedValue(new Error('Async error'))
    };

    // Act & Assert
    await expect(someAsyncFunction(mockAsyncService)).rejects.toThrow('Async error');
  });

  it('should handle multiple async operations', async () => {
    // Test Promise.all scenarios
    const promises = [
      Promise.resolve('result1'),
      Promise.resolve('result2'),
      Promise.resolve('result3')
    ];

    const results = await Promise.all(promises);
    expect(results).toEqual(['result1', 'result2', 'result3']);
  });
});
```

### Testing Timeouts and Delays

```typescript
describe('Timeout Operations', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should handle timeout operations', async () => {
    // Arrange
    const timeoutPromise = new Promise((resolve) => {
      setTimeout(() => resolve('timeout-result'), 5000);
    });

    // Act
    const resultPromise = timeoutPromise;
    jest.advanceTimersByTime(5000);
    const result = await resultPromise;

    // Assert
    expect(result).toBe('timeout-result');
  });

  it('should test retry logic with delays', async () => {
    // Test implementation with fake timers
    const mockOperation = jest.fn()
      .mockRejectedValueOnce(new Error('First failure'))
      .mockRejectedValueOnce(new Error('Second failure'))
      .mockResolvedValueOnce('Success');

    const retryPromise = retryWithDelay(mockOperation, 3, 1000);
    
    // Advance timers for each retry
    jest.advanceTimersByTime(1000);
    jest.advanceTimersByTime(1000);
    
    const result = await retryPromise;
    expect(result).toBe('Success');
    expect(mockOperation).toHaveBeenCalledTimes(3);
  });
});
```

## End-to-End Testing Patterns

### HTTP Endpoint Testing

```typescript
// e2e.test.ts - End-to-end testing with supertest
import request from 'supertest';
import { app } from '../src/app';

describe('User API E2E Tests', () => {
  let testDatabase: TestDatabase;
  let authToken: string;

  beforeAll(async () => {
    testDatabase = new TestDatabase();
    await testDatabase.setup();
    
    // Get authentication token
    const loginResponse = await request(app)
      .post('/auth/login')
      .send({ email: 'admin@test.com', password: 'password' });
    
    authToken = loginResponse.body.token;
  });

  afterAll(async () => {
    await testDatabase.teardown();
  });

  beforeEach(async () => {
    await testDatabase.clean();
  });

  describe('POST /users', () => {
    it('should create user with valid data', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        age: 25
      };

      const response = await request(app)
        .post('/users')
        .set('Authorization', `Bearer ${authToken}`)
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.user).toBeDefined();
      expect(response.body.user.email).toBe(userData.email);
    });

    it('should return 400 for invalid data', async () => {
      const invalidData = {
        name: 'J', // Too short
        email: 'invalid-email',
        age: 17 // Too young
      };

      const response = await request(app)
        .post('/users')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.type).toBe('validation_error');
    });

    it('should return 401 without authentication', async () => {
      const userData = {
        name: 'John Doe',
        email: 'john@example.com',
        age: 25
      };

      await request(app)
        .post('/users')
        .send(userData)
        .expect(401);
    });
  });
});
```

## Performance Testing

### Load Testing with Jest

```typescript
describe('Performance Tests', () => {
  it('should handle concurrent requests efficiently', async () => {
    const concurrentRequests = 100;
    const startTime = Date.now();

    const promises = Array.from({ length: concurrentRequests }, () => {
      return mockService.processRequest({ data: 'test' });
    });

    await Promise.all(promises);
    
    const endTime = Date.now();
    const duration = endTime - startTime;

    // Assert performance requirements
    expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
  });

  it('should not have memory leaks', async () => {
    const initialMemory = process.memoryUsage().heapUsed;
    
    // Execute operations that might cause leaks
    for (let i = 0; i < 1000; i++) {
      await someOperation();
    }
    
    // Force garbage collection
    if (global.gc) {
      global.gc();
    }
    
    const finalMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = finalMemory - initialMemory;
    
    // Memory increase should be reasonable
    expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB
  });
});
```

## Best Practices

1. **Use TypeScript generics** in test types for better type safety
2. **Reset Container state** between tests to avoid interference
3. **Create reusable mock factories** for common objects
4. **Test both success and error scenarios** for every function
5. **Use integration tests** for complex middleware chains
6. **Mock external dependencies** but test with real databases when needed
7. **Use custom Jest matchers** for domain-specific assertions
8. **Test async operations** properly with proper error handling
9. **Use fake timers** for testing time-dependent code
10. **Write end-to-end tests** for critical user journeys
11. **Monitor test performance** and avoid slow tests
12. **Use descriptive test names** that explain the scenario
13. **Group related tests** with proper describe blocks
14. **Clean up resources** in afterEach/afterAll hooks