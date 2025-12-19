import { ContainerPool, ServiceDefinition } from './containerPool';

describe('ContainerPool - Hybrid Proxy Container', () => {
  // Mock services for testing
  class DatabaseService {
    query(sql: string): string {
      return `Executing: ${sql}`;
    }
  }

  class LoggerService {
    log(msg: string): string {
      return `Log: ${msg}`;
    }
  }

  beforeEach(() => {
    // Clear global container before each test
    ContainerPool.clear();
  });

  afterEach(() => {
    // Clean up after each test
    ContainerPool.clear();
  });

  describe('Global Container Initialization', () => {
    it('should initialize global container with services', () => {
      const dbService = new DatabaseService();
      const loggerService = new LoggerService();

      const services: ServiceDefinition[] = [
        { id: 'db', value: dbService },
        { id: 'logger', value: loggerService },
      ];

      ContainerPool.initializeGlobal(services);

      const stats = ContainerPool.getStats();
      expect(stats.globalInitialized).toBe(true);
      expect(stats.useProxy).toBe(true);
    });

    it('should allow multiple calls to initializeGlobal (additive)', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const loggerService = new LoggerService();
      ContainerPool.initializeGlobal([{ id: 'logger', value: loggerService }]);

      const container = ContainerPool.createProxyContainer();
      expect(container.get('db')).toBe(dbService);
      expect(container.get('logger')).toBe(loggerService);
    });

    it('should create empty global container if none provided', () => {
      ContainerPool.initializeGlobal();
      const stats = ContainerPool.getStats();
      expect(stats.globalInitialized).toBe(true);
    });
  });

  describe('Proxy Container Creation', () => {
    it('should create proxy container even without global initialization', () => {
      const container = ContainerPool.createProxyContainer();
      expect(container).toBeDefined();
      expect(container.get).toBeDefined();
      expect(container.set).toBeDefined();
    });

    it('should create multiple independent proxy containers', () => {
      const container1 = ContainerPool.createProxyContainer();
      const container2 = ContainerPool.createProxyContainer();

      expect(container1).not.toBe(container2);
    });

    it('should create proxy container with global services accessible', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const container = ContainerPool.createProxyContainer();
      const retrievedDb = container.get<DatabaseService>('db');

      expect(retrievedDb).toBe(dbService);
      expect(retrievedDb.query('SELECT * FROM users')).toBe(
        'Executing: SELECT * FROM users'
      );
    });
  });

  describe('Global Fallback Behavior', () => {
    it('should read global services from proxy', () => {
      const dbService = new DatabaseService();
      const loggerService = new LoggerService();

      ContainerPool.initializeGlobal([
        { id: 'db', value: dbService },
        { id: 'logger', value: loggerService },
      ]);

      const container = ContainerPool.createProxyContainer();

      expect(container.get('db')).toBe(dbService);
      expect(container.get('logger')).toBe(loggerService);
    });

    it('should share global services across multiple proxies', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const container1 = ContainerPool.createProxyContainer();
      const container2 = ContainerPool.createProxyContainer();

      const db1 = container1.get('db');
      const db2 = container2.get('db');

      expect(db1).toBe(dbService);
      expect(db2).toBe(dbService);
      expect(db1).toBe(db2); // Same instance
    });
  });

  describe('Local Overrides (Request Scope)', () => {
    it('should set services locally without affecting global', () => {
      const globalDb = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: globalDb }]);

      const container1 = ContainerPool.createProxyContainer();
      const localDb = new DatabaseService();
      container1.set('db', localDb);

      const container2 = ContainerPool.createProxyContainer();

      // Container1 should have local override
      expect(container1.get('db')).toBe(localDb);

      // Container2 should still have global
      expect(container2.get('db')).toBe(globalDb);
    });

    it('should allow setting request-scoped services', () => {
      const container = ContainerPool.createProxyContainer();

      container.set('RequestId', 'req-123');
      container.set('TraceId', 'trace-456');
      container.set('CurrentUser', { id: '1', name: 'John' });

      expect(container.get('RequestId')).toBe('req-123');
      expect(container.get('TraceId')).toBe('trace-456');
      expect(container.get('CurrentUser')).toEqual({
        id: '1',
        name: 'John',
      });
    });

    it('should isolate local services between proxies', () => {
      const container1 = ContainerPool.createProxyContainer();
      const container2 = ContainerPool.createProxyContainer();

      container1.set('RequestId', 'req-123');
      container2.set('RequestId', 'req-456');

      expect(container1.get('RequestId')).toBe('req-123');
      expect(container2.get('RequestId')).toBe('req-456');
    });

    it('should prioritize local overrides over global services', () => {
      const globalLogger = new LoggerService();
      ContainerPool.initializeGlobal([{ id: 'logger', value: globalLogger }]);

      const container = ContainerPool.createProxyContainer();
      const localLogger = { log: (msg: string) => `LOCAL: ${msg}` };
      container.set('logger', localLogger);

      const retrieved = container.get('logger');
      expect(retrieved).toBe(localLogger);
      expect(retrieved).not.toBe(globalLogger);
    });
  });

  describe('Service Removal (Tombstone Pattern)', () => {
    it('should mark service as deleted locally without affecting global', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const container1 = ContainerPool.createProxyContainer();
      container1.remove('db');

      const container2 = ContainerPool.createProxyContainer();

      // Container1 should throw error
      expect(() => container1.get('db')).toThrow(
        'Service "db" not found (removed in request scope)'
      );

      // Container2 should still have access
      expect(container2.get('db')).toBe(dbService);
    });

    it('should mark locally-set service as deleted', () => {
      const container = ContainerPool.createProxyContainer();
      container.set('temp', 'value');

      expect(container.get('temp')).toBe('value');

      container.remove('temp');

      expect(() => container.get('temp')).toThrow(
        'Service "temp" not found (removed in request scope)'
      );
    });
  });

  describe('Reset Behavior', () => {
    it('should clear local overrides and revert to global state', () => {
      const globalDb = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: globalDb }]);

      const container = ContainerPool.createProxyContainer();
      const localDb = new DatabaseService();
      container.set('db', localDb);
      container.set('temp', 'value');

      // Before reset
      expect(container.get('db')).toBe(localDb);
      expect(container.get('temp')).toBe('value');

      // Reset
      container.reset();

      // After reset - should revert to global
      expect(container.get('db')).toBe(globalDb);

      // Temp service should no longer exist
      expect(() => container.get('temp')).toThrow();
    });

    it('should clear all local overrides on reset', () => {
      const container = ContainerPool.createProxyContainer();
      container.set('service1', 'value1');
      container.set('service2', 'value2');
      container.set('service3', 'value3');

      container.reset();

      expect(() => container.get('service1')).toThrow();
      expect(() => container.get('service2')).toThrow();
      expect(() => container.get('service3')).toThrow();
    });
  });

  describe('has() Method', () => {
    it('should check for global service existence', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const container = ContainerPool.createProxyContainer();

      expect(container.has('db')).toBe(true);
      expect(container.has('nonexistent')).toBe(false);
    });

    it('should check for local service existence', () => {
      const container = ContainerPool.createProxyContainer();
      container.set('local', 'value');

      expect(container.has('local')).toBe(true);
      expect(container.has('nonexistent')).toBe(false);
    });

    it('should return false for tombstoned services', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const container = ContainerPool.createProxyContainer();
      container.remove('db');

      expect(container.has('db')).toBe(false);
    });

    it('should prioritize local has over global', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      const container = ContainerPool.createProxyContainer();
      container.set('db', 'local-override');

      expect(container.has('db')).toBe(true);
    });
  });

  describe('Request Isolation (Concurrency Safety)', () => {
    it('should isolate services across concurrent requests', async () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      // Simulate 3 concurrent requests
      const request1 = Promise.resolve().then(() => {
        const container = ContainerPool.createProxyContainer();
        container.set('RequestId', 'req-1');
        container.set('UserId', 'user-1');
        return {
          requestId: container.get('RequestId'),
          userId: container.get('UserId'),
          db: container.get('db'),
        };
      });

      const request2 = Promise.resolve().then(() => {
        const container = ContainerPool.createProxyContainer();
        container.set('RequestId', 'req-2');
        container.set('UserId', 'user-2');
        return {
          requestId: container.get('RequestId'),
          userId: container.get('UserId'),
          db: container.get('db'),
        };
      });

      const request3 = Promise.resolve().then(() => {
        const container = ContainerPool.createProxyContainer();
        container.set('RequestId', 'req-3');
        container.set('UserId', 'user-3');
        return {
          requestId: container.get('RequestId'),
          userId: container.get('UserId'),
          db: container.get('db'),
        };
      });

      const [result1, result2, result3] = await Promise.all([
        request1,
        request2,
        request3,
      ]);

      // Each request should have isolated request-scoped data
      expect(result1.requestId).toBe('req-1');
      expect(result2.requestId).toBe('req-2');
      expect(result3.requestId).toBe('req-3');

      expect(result1.userId).toBe('user-1');
      expect(result2.userId).toBe('user-2');
      expect(result3.userId).toBe('user-3');

      // But all should share the same global DB instance
      expect(result1.db).toBe(dbService);
      expect(result2.db).toBe(dbService);
      expect(result3.db).toBe(dbService);
    });
  });

  describe('asMiddleware() Helper', () => {
    it('should create middleware factory with services', () => {
      const middleware = ContainerPool.asMiddleware([
        { id: 'RequestId', value: 'req-123' },
      ]);

      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });

    it('should create container with pre-set services', () => {
      const middleware = ContainerPool.asMiddleware([
        { id: 'RequestId', value: 'req-123' },
        { id: 'TraceId', value: 'trace-456' },
      ]);

      const container = middleware();

      expect(container.get('RequestId')).toBe('req-123');
      expect(container.get('TraceId')).toBe('trace-456');
    });

    it('should accept existing container and add services to it', () => {
      const existingContainer = ContainerPool.createProxyContainer();
      existingContainer.set('existing', 'value');

      const middleware = ContainerPool.asMiddleware([
        { id: 'new', value: 'new-value' },
      ]);

      const result = middleware(existingContainer);

      expect(result.get('existing')).toBe('value');
      expect(result.get('new')).toBe('new-value');
      expect(result).toBe(existingContainer); // Same instance
    });
  });

  describe('Statistics and Monitoring', () => {
    it('should track global initialization status', () => {
      let stats = ContainerPool.getStats();
      expect(stats.globalInitialized).toBe(false);

      ContainerPool.initializeGlobal([]);

      stats = ContainerPool.getStats();
      expect(stats.globalInitialized).toBe(true);
    });

    it('should report useProxy flag', () => {
      const stats = ContainerPool.getStats();
      expect(stats.useProxy).toBe(true);
    });
  });

  describe('Clear and Cleanup', () => {
    it('should clear global container', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: dbService }]);

      let stats = ContainerPool.getStats();
      expect(stats.globalInitialized).toBe(true);

      ContainerPool.clear();

      stats = ContainerPool.getStats();
      expect(stats.globalInitialized).toBe(false);
    });

    it('should allow re-initialization after clear', () => {
      const db1 = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: db1 }]);

      ContainerPool.clear();

      const db2 = new DatabaseService();
      ContainerPool.initializeGlobal([{ id: 'db', value: db2 }]);

      const container = ContainerPool.createProxyContainer();
      expect(container.get('db')).toBe(db2);
      expect(container.get('db')).not.toBe(db1);
    });
  });

  describe('Edge Cases', () => {
    it('should handle undefined service values', () => {
      const container = ContainerPool.createProxyContainer();
      container.set('undefined-service', undefined);

      expect(container.get('undefined-service')).toBeUndefined();
    });

    it('should handle null service values', () => {
      const container = ContainerPool.createProxyContainer();
      container.set('null-service', null);

      expect(container.get('null-service')).toBeNull();
    });

    it('should handle string service IDs with special characters', () => {
      const container = ContainerPool.createProxyContainer();
      container.set('service-with-dash', 'value1');
      container.set('service_with_underscore', 'value2');
      container.set('service.with.dot', 'value3');

      expect(container.get('service-with-dash')).toBe('value1');
      expect(container.get('service_with_underscore')).toBe('value2');
      expect(container.get('service.with.dot')).toBe('value3');
    });

    it('should handle class constructors as service IDs', () => {
      const dbService = new DatabaseService();
      ContainerPool.initializeGlobal([
        { id: DatabaseService, value: dbService },
      ]);

      const container = ContainerPool.createProxyContainer();
      const retrieved = container.get(DatabaseService);

      expect(retrieved).toBe(dbService);
    });
  });

  describe('Memory Efficiency', () => {
    it('should create lightweight proxies (no pre-allocated maps)', () => {
      const container = ContainerPool.createProxyContainer();

      // Proxy should be created but not allocate memory until services are set
      expect(container).toBeDefined();

      // Setting a service should allocate the local overrides map
      container.set('test', 'value');
      expect(container.get('test')).toBe('value');
    });

    it('should not duplicate global services in proxy', () => {
      const dbService = new DatabaseService();
      const loggerService = new LoggerService();

      ContainerPool.initializeGlobal([
        { id: 'db', value: dbService },
        { id: 'logger', value: loggerService },
      ]);

      const container1 = ContainerPool.createProxyContainer();
      const container2 = ContainerPool.createProxyContainer();

      // Both proxies should reference the same global services
      expect(container1.get('db')).toBe(container2.get('db'));
      expect(container1.get('logger')).toBe(container2.get('logger'));
    });
  });
});
