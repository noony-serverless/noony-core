import { Container } from 'typedi';
import { getService } from './container.utils';
import { Context } from '../core/core';

// Mock service classes for testing
class MockUserService {
  getUsers() {
    return ['user1', 'user2'];
  }
}

class MockEmailService {
  sendEmail() {
    return 'email sent';
  }
}

describe('Container Utilities', () => {
  describe('getService', () => {
    let mockContext: Context<unknown, unknown>;
    let testContainer: any;

    beforeEach(() => {
      // Create a scoped container for each test
      testContainer = Container.of('test-container');

      // Register mock services
      testContainer.set(MockUserService, new MockUserService());
      testContainer.set(MockEmailService, new MockEmailService());

      // Create mock context with container
      mockContext = {
        req: {
          method: 'GET',
          url: '/',
          headers: {},
          query: {},
          params: {},
        },
        res: {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
          send: jest.fn(),
          header: jest.fn().mockReturnThis(),
          headers: jest.fn().mockReturnThis(),
          end: jest.fn(),
        },
        container: testContainer,
        businessData: new Map(),
        startTime: Date.now(),
        requestId: 'test-req-id',
      } as any;
    });

    afterEach(() => {
      // Clean up container
      Container.reset('test-container');
    });

    it('should retrieve service from container', () => {
      const userService = getService(mockContext, MockUserService);

      expect(userService).toBeInstanceOf(MockUserService);
      expect(userService.getUsers()).toEqual(['user1', 'user2']);
    });

    it('should retrieve different services with type safety', () => {
      const userService = getService(mockContext, MockUserService);
      const emailService = getService(mockContext, MockEmailService);

      expect(userService).toBeInstanceOf(MockUserService);
      expect(emailService).toBeInstanceOf(MockEmailService);
      expect(userService.getUsers()).toEqual(['user1', 'user2']);
      expect(emailService.sendEmail()).toBe('email sent');
    });

    it('should throw error if container is not initialized', () => {
      const contextWithoutContainer = {
        ...mockContext,
        container: undefined,
      } as any;

      expect(() => {
        getService(contextWithoutContainer, MockUserService);
      }).toThrow(
        'Container not initialized. Did you forget to add DependencyInjectionMiddleware?'
      );
    });

    it('should throw error if container is null', () => {
      const contextWithNullContainer = {
        ...mockContext,
        container: null,
      } as any;

      expect(() => {
        getService(contextWithNullContainer, MockUserService);
      }).toThrow(
        'Container not initialized. Did you forget to add DependencyInjectionMiddleware?'
      );
    });

    it('should work with TypeDI Service decorator pattern', () => {
      // Simulating a service that would be decorated with @Service()
      class DecoratedService {
        getData() {
          return 'decorated data';
        }
      }

      testContainer.set(DecoratedService, new DecoratedService());

      const service = getService(mockContext, DecoratedService);

      expect(service).toBeInstanceOf(DecoratedService);
      expect(service.getData()).toBe('decorated data');
    });

    it('should throw if service not registered in container', () => {
      class UnregisteredService {}

      expect(() => {
        getService(mockContext, UnregisteredService);
      }).toThrow();
    });
  });

  describe('Type Safety', () => {
    it('should infer correct return type', () => {
      const testContainer = Container.of('type-test');
      testContainer.set(MockUserService, new MockUserService());

      const mockContext = {
        container: testContainer,
      } as any;

      // TypeScript should infer the return type as MockUserService
      const userService = getService(mockContext, MockUserService);

      // This should not cause TypeScript errors
      const users: string[] = userService.getUsers();

      expect(users).toEqual(['user1', 'user2']);

      Container.reset('type-test');
    });
  });

  describe('String Identifier Support', () => {
    let mockContext: Context<unknown, unknown>;
    let testContainer: any;

    beforeEach(() => {
      testContainer = Container.of('string-test');

      // Register services with string identifiers
      testContainer.set('UserRepository', new MockUserService());
      testContainer.set('EmailService', new MockEmailService());

      mockContext = {
        req: {
          method: 'GET',
          url: '/',
          headers: {},
          query: {},
          params: {},
        },
        res: {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
          send: jest.fn(),
          header: jest.fn().mockReturnThis(),
          headers: jest.fn().mockReturnThis(),
          end: jest.fn(),
        },
        container: testContainer,
        businessData: new Map(),
        startTime: Date.now(),
        requestId: 'test-req-id',
      } as any;
    });

    afterEach(() => {
      Container.reset('string-test');
    });

    it('should retrieve service using string identifier with explicit generic', () => {
      const userService = getService<MockUserService>(
        mockContext,
        'UserRepository'
      );

      expect(userService).toBeInstanceOf(MockUserService);
      expect(userService.getUsers()).toEqual(['user1', 'user2']);
    });

    it('should retrieve service using string identifier without generic (returns unknown)', () => {
      // Without generic, type is unknown - this is expected behavior
      const userService = getService(mockContext, 'UserRepository');

      // Type assertion needed when not using generic
      expect((userService as MockUserService).getUsers()).toEqual([
        'user1',
        'user2',
      ]);
    });

    it('should retrieve multiple services with string identifiers', () => {
      const userService = getService<MockUserService>(
        mockContext,
        'UserRepository'
      );
      const emailService = getService<MockEmailService>(
        mockContext,
        'EmailService'
      );

      expect(userService.getUsers()).toEqual(['user1', 'user2']);
      expect(emailService.sendEmail()).toBe('email sent');
    });

    it('should throw error for unregistered string identifier', () => {
      expect(() => {
        getService<MockUserService>(mockContext, 'UnregisteredService');
      }).toThrow();
    });

    it('should work with mixed usage (class and string identifiers)', () => {
      // Register class-based service
      testContainer.set(MockUserService, new MockUserService());

      // Get class-based service
      const userServiceClass = getService(mockContext, MockUserService);

      // Get string-based service
      const userServiceString = getService<MockUserService>(
        mockContext,
        'UserRepository'
      );

      expect(userServiceClass.getUsers()).toEqual(['user1', 'user2']);
      expect(userServiceString.getUsers()).toEqual(['user1', 'user2']);
    });

    it('should preserve type safety with string identifier and generic', () => {
      const userService = getService<MockUserService>(
        mockContext,
        'UserRepository'
      );

      // TypeScript should recognize all methods
      const users: string[] = userService.getUsers();

      expect(users).toEqual(['user1', 'user2']);
    });
  });
});
