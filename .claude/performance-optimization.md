# Noony Framework Performance Optimization Rules

## Container Pool Optimization

### Use Container Pool for Serverless Cold Starts

```typescript
// ✅ CORRECT: Use containerPool for optimal serverless performance
import { containerPool } from '@noony-serverless/core';

// Initialize during cold start (outside handler)
const initializeServices = async () => {
  // Pre-register services for faster access
  containerPool.register([
    UserService,
    OrderService,
    EmailService,
    PaymentService,
    NotificationService
  ]);
  
  // Pre-warm critical services
  await containerPool.preWarm([
    DatabaseService,
    CacheService
  ]);
  
  console.log('🚀 Services pre-warmed for optimal performance');
};

// Call during cold start
await initializeServices();

// Use in handlers for ~10x faster service resolution
const handler = new Handler<RequestType, UserType>()
  .handle(async (context) => {
    // Fast service access from pre-warmed pool
    const userService = containerPool.get(UserService);    // ~0.1ms
    const orderService = containerPool.get(OrderService);  // ~0.1ms
    
    // vs Container.get() which can be ~1-5ms per service in cold starts
  });

// ❌ INCORRECT: Direct Container usage in serverless (slower)
const slowHandler = new Handler()
  .handle(async (context) => {
    const userService = Container.get(UserService); // Slower cold start resolution
  });
```

### Container Pool Configuration

```typescript
// Configure container pool for optimal performance
const optimizeContainerPool = () => {
  containerPool.configure({
    maxPoolSize: 50,           // Maximum services to pool
    preWarmCount: 10,          // Services to pre-instantiate
    cleanupInterval: 300000,   // 5 minutes cleanup interval
    enableMetrics: process.env.NODE_ENV === 'development'
  });
  
  // Priority services (loaded first)
  containerPool.setPriority([
    DatabaseService,
    CacheService,
    Logger
  ]);
};
```

## Caching Strategies

### Guard System Cache Optimization

```typescript
// Configure guard system for optimal performance
const optimizeGuardSystem = async () => {
  const cacheConfig = {
    // Aggressive caching for production
    maxEntries: process.env.NODE_ENV === 'production' ? 5000 : 1000,
    defaultTtlMs: 15 * 60 * 1000,      // 15 minutes
    userContextTtlMs: 10 * 60 * 1000,  // 10 minutes user context
    authTokenTtlMs: 5 * 60 * 1000,     // 5 minutes auth tokens
  };

  await RouteGuards.configure(
    {
      ...GuardConfiguration.production(),
      cache: cacheConfig,
      security: {
        permissionResolutionStrategy: PermissionResolutionStrategy.PRE_EXPANSION, // Fastest
        conservativeCacheInvalidation: true, // Security first
        maxExpressionComplexity: 50,
        maxPatternDepth: 3
      },
      monitoring: {
        enablePerformanceTracking: true,
        enableDetailedLogging: false, // Reduce overhead
        metricsCollectionInterval: 60000 // 1 minute
      }
    },
    permissionSource,
    tokenValidator,
    authConfig
  );
};

// Monitor cache performance
setInterval(() => {
  const stats = RouteGuards.getSystemStats();
  if (stats.systemHealth.cacheEfficiency < 85) {
    console.warn('Guard cache efficiency below optimal:', stats.systemHealth.cacheEfficiency);
  }
}, 300000); // Every 5 minutes
```

### Application-Level Caching

```typescript
// High-performance caching middleware
class PerformanceCacheMiddleware<T, U> implements BaseMiddleware<T, U> {
  private cache = new Map<string, { data: any; timestamp: number; ttl: number }>();
  
  constructor(
    private defaultTtl: number = 5 * 60 * 1000, // 5 minutes
    private maxSize: number = 1000
  ) {
    // Periodic cleanup to prevent memory leaks
    setInterval(() => this.cleanup(), 60000);
  }
  
  async before(context: Context<T, U>): Promise<void> {
    // Create cache key from request characteristics
    const cacheKey = this.createCacheKey(context);
    
    // Check cache
    const cached = this.cache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < cached.ttl) {
      // Cache hit - bypass handler execution
      context.res.json(cached.data);
      context.businessData?.set('cacheHit', true);
      return;
    }
    
    // Store key for after hook
    context.businessData?.set('cacheKey', cacheKey);
  }
  
  async after(context: Context<T, U>): Promise<void> {
    const cacheKey = context.businessData?.get('cacheKey');
    const cacheHit = context.businessData?.get('cacheHit');
    
    // Don't cache if it was a cache hit or if there was an error
    if (cacheHit || !cacheKey) return;
    
    // Extract response data for caching
    const responseData = this.extractResponseData(context);
    if (responseData) {
      this.set(cacheKey, responseData, this.defaultTtl);
    }
  }
  
  private createCacheKey(context: Context<T, U>): string {
    const userId = context.user?.id || 'anonymous';
    const method = context.req.method;
    const path = context.req.path;
    const queryString = new URLSearchParams(context.req.query as any).toString();
    
    return `${method}:${path}:${queryString}:${userId}`;
  }
  
  private set(key: string, data: any, ttl: number): void {
    // Implement LRU eviction if cache is full
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }
    
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    });
  }
  
  private cleanup(): void {
    const now = Date.now();
    for (const [key, value] of this.cache.entries()) {
      if ((now - value.timestamp) > value.ttl) {
        this.cache.delete(key);
      }
    }
  }
}

// Usage with different TTLs for different endpoints
const fastCacheHandler = new Handler<RequestType, UserType>()
  .use(new PerformanceCacheMiddleware(30000))  // 30 seconds for fast-changing data
  .handle(async (context) => {
    // Expensive operation that benefits from short-term caching
  });

const slowCacheHandler = new Handler<RequestType, UserType>()
  .use(new PerformanceCacheMiddleware(10 * 60 * 1000))  // 10 minutes for slow-changing data
  .handle(async (context) => {
    // Expensive operation that benefits from longer caching
  });
```

## Database Connection Optimization

### Connection Pooling and Optimization

```typescript
// Optimized database configuration
class OptimizedDatabaseConfig {
  private static connectionPool: any;
  
  static async initialize() {
    const poolConfig = {
      // Connection pool settings
      min: 2,                    // Minimum connections
      max: process.env.NODE_ENV === 'production' ? 20 : 10,
      acquireTimeoutMillis: 30000,
      createTimeoutMillis: 30000,
      idleTimeoutMillis: 30000,
      reapIntervalMillis: 1000,
      createRetryIntervalMillis: 100,
      
      // Performance optimizations
      propagateCreateError: false,
      
      // Connection validation
      testOnBorrow: true,
      
      // Performance monitoring
      afterCreate: (conn: any, done: Function) => {
        console.log('Database connection created');
        done(null, conn);
      }
    };
    
    this.connectionPool = await createPool({
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      
      // PostgreSQL performance settings
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      statement_timeout: 30000,
      query_timeout: 30000,
      connectionTimeoutMillis: 30000,
      
      // Connection pool
      ...poolConfig
    });
    
    // Monitor pool health
    setInterval(() => {
      const stats = this.connectionPool.pool.stats();
      if (stats.free < 2) {
        console.warn('Database connection pool running low:', stats);
      }
    }, 60000);
  }
  
  static getConnection() {
    return this.connectionPool;
  }
  
  static async closeAll() {
    if (this.connectionPool) {
      await this.connectionPool.end();
    }
  }
}

// Optimized repository with prepared statements
@Service()
export class OptimizedUserRepository {
  private preparedStatements = new Map<string, any>();
  
  constructor(private database: DatabaseConnection) {
    this.initializePreparedStatements();
  }
  
  private async initializePreparedStatements() {
    // Prepare frequently used queries for better performance
    this.preparedStatements.set('findById', await this.database.prepare(`
      SELECT id, name, email, role, created_at, updated_at 
      FROM users 
      WHERE id = $1 AND deleted_at IS NULL
    `));
    
    this.preparedStatements.set('findByEmail', await this.database.prepare(`
      SELECT id, name, email, role, created_at, updated_at 
      FROM users 
      WHERE email = $1 AND deleted_at IS NULL
    `));
    
    this.preparedStatements.set('create', await this.database.prepare(`
      INSERT INTO users (id, name, email, role, created_at, updated_at) 
      VALUES ($1, $2, $3, $4, NOW(), NOW()) 
      RETURNING id, name, email, role, created_at, updated_at
    `));
  }
  
  async findById(id: string): Promise<User | null> {
    const stmt = this.preparedStatements.get('findById');
    const result = await stmt.get(id);
    return result || null;
  }
  
  async create(userData: CreateUserRequest): Promise<User> {
    const stmt = this.preparedStatements.get('create');
    const id = generateId();
    
    return await stmt.get(id, userData.name, userData.email, userData.role || 'user');
  }
}
```

### Query Optimization Patterns

```typescript
// Query optimization utilities
class QueryOptimizer {
  // Batch loading to reduce N+1 queries
  static async loadUsersWithRelations(userIds: string[]): Promise<UserWithRelations[]> {
    // Single query instead of N+1
    const query = `
      SELECT 
        u.id, u.name, u.email, u.role,
        o.id as order_id, o.total, o.status,
        p.permission_name
      FROM users u
      LEFT JOIN orders o ON u.id = o.user_id
      LEFT JOIN user_permissions up ON u.id = up.user_id
      LEFT JOIN permissions p ON up.permission_id = p.id
      WHERE u.id = ANY($1)
    `;
    
    const results = await db.query(query, [userIds]);
    
    // Group results to avoid duplicate user objects
    return this.groupUserResults(results);
  }
  
  // Pagination with cursor-based approach for better performance
  static buildCursorQuery(
    baseQuery: string,
    cursor?: string,
    limit: number = 10,
    sortField: string = 'created_at'
  ): { query: string; params: any[] } {
    const params: any[] = [limit];
    
    let query = baseQuery;
    if (cursor) {
      query += ` AND ${sortField} > $${params.length + 1}`;
      params.push(cursor);
    }
    
    query += ` ORDER BY ${sortField} ASC LIMIT $1`;
    
    return { query, params };
  }
  
  // Efficient counting for pagination
  static async getCountWithCache(
    countQuery: string,
    params: any[],
    cacheKey: string,
    ttl: number = 300000 // 5 minutes
  ): Promise<number> {
    const cached = cache.get(cacheKey);
    if (cached) return cached;
    
    const result = await db.query(countQuery, params);
    const count = parseInt(result.rows[0].count);
    
    cache.set(cacheKey, count, ttl);
    return count;
  }
}
```

## Memory Management and Cleanup

### Memory Leak Prevention

```typescript
// Memory-conscious middleware
class MemoryOptimizedMiddleware<T, U> implements BaseMiddleware<T, U> {
  private activeRequests = new Map<string, { startTime: number; memoryUsage: number }>();
  
  async before(context: Context<T, U>): Promise<void> {
    // Track memory usage per request
    const memoryUsage = process.memoryUsage().heapUsed;
    this.activeRequests.set(context.requestId, {
      startTime: Date.now(),
      memoryUsage
    });
    
    // Clean up old request tracking (prevent memory leaks)
    this.cleanupOldRequests();
  }
  
  async after(context: Context<T, U>): Promise<void> {
    const requestInfo = this.activeRequests.get(context.requestId);
    if (requestInfo) {
      const currentMemory = process.memoryUsage().heapUsed;
      const memoryDelta = currentMemory - requestInfo.memoryUsage;
      const duration = Date.now() - requestInfo.startTime;
      
      // Log memory usage for monitoring
      if (memoryDelta > 50 * 1024 * 1024) { // 50MB increase
        console.warn(`High memory usage detected:`, {
          requestId: context.requestId,
          memoryDelta: `${Math.round(memoryDelta / 1024 / 1024)}MB`,
          duration: `${duration}ms`
        });
      }
    }
    
    // Clean up request tracking
    this.activeRequests.delete(context.requestId);
    
    // Cleanup business data to prevent memory leaks
    context.businessData?.clear();
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Always clean up on error
    this.activeRequests.delete(context.requestId);
    context.businessData?.clear();
  }
  
  private cleanupOldRequests(): void {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    
    for (const [requestId, info] of this.activeRequests.entries()) {
      if (info.startTime < fiveMinutesAgo) {
        this.activeRequests.delete(requestId);
      }
    }
  }
}
```

### Garbage Collection Optimization

```typescript
// GC optimization utilities
class GCOptimizer {
  private static memoryPressureThreshold = 500 * 1024 * 1024; // 500MB
  
  static monitorMemoryPressure(): void {
    setInterval(() => {
      const memUsage = process.memoryUsage();
      
      if (memUsage.heapUsed > this.memoryPressureThreshold) {
        console.warn('Memory pressure detected:', {
          heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
          external: `${Math.round(memUsage.external / 1024 / 1024)}MB`
        });
        
        // Suggest garbage collection
        this.suggestGC();
      }
    }, 30000); // Check every 30 seconds
  }
  
  private static suggestGC(): void {
    if (global.gc) {
      console.log('Triggering garbage collection...');
      global.gc();
      
      const afterGC = process.memoryUsage();
      console.log('Memory after GC:', {
        heapUsed: `${Math.round(afterGC.heapUsed / 1024 / 1024)}MB`
      });
    }
  }
  
  // Clean up large objects explicitly
  static cleanupLargeObjects(objects: WeakMap<any, any>): void {
    // WeakMap allows automatic cleanup when objects are no longer referenced
    // This is preferred over Map for temporary object associations
  }
}

// Start memory monitoring in production
if (process.env.NODE_ENV === 'production') {
  GCOptimizer.monitorMemoryPressure();
}
```

## Async Operations Optimization

### Promise Pooling and Batching

```typescript
// Optimized async operations
class AsyncOptimizer {
  // Batch multiple async operations to reduce overhead
  static async batchProcess<T, R>(
    items: T[],
    processor: (item: T) => Promise<R>,
    batchSize: number = 10,
    concurrency: number = 3
  ): Promise<R[]> {
    const results: R[] = [];
    
    // Process in batches to control memory usage
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      
      // Limit concurrency to prevent overwhelming the system
      const batchResults = await Promise.all(
        batch.map(item => this.withRetry(() => processor(item), 3))
      );
      
      results.push(...batchResults);
      
      // Small delay between batches to prevent overwhelming downstream services
      if (i + batchSize < items.length) {
        await this.delay(10);
      }
    }
    
    return results;
  }
  
  // Promise pool for controlling concurrent operations
  static async processWithPool<T, R>(
    items: T[],
    processor: (item: T) => Promise<R>,
    poolSize: number = 5
  ): Promise<R[]> {
    const results: R[] = [];
    const executing = new Set<Promise<void>>();
    
    for (const item of items) {
      const promise = processor(item).then(result => {
        results.push(result);
        executing.delete(promise);
      });
      
      executing.add(promise);
      
      // Wait if pool is full
      if (executing.size >= poolSize) {
        await Promise.race(executing);
      }
    }
    
    // Wait for remaining promises
    await Promise.all(executing);
    return results;
  }
  
  // Retry mechanism with exponential backoff
  private static async withRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === maxRetries) break;
        
        // Exponential backoff with jitter
        const delay = baseDelay * Math.pow(2, attempt) + Math.random() * 1000;
        await this.delay(delay);
      }
    }
    
    throw lastError!;
  }
  
  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Usage in services
@Service()
export class OptimizedEmailService {
  async sendBulkEmails(recipients: string[], template: string): Promise<void> {
    // Process emails in optimized batches
    await AsyncOptimizer.batchProcess(
      recipients,
      async (email) => {
        return this.sendEmail(email, template);
      },
      50,  // 50 emails per batch
      5    // 5 concurrent batches
    );
  }
  
  async processUserNotifications(userIds: string[]): Promise<NotificationResult[]> {
    // Use promise pool to control concurrency
    return AsyncOptimizer.processWithPool(
      userIds,
      async (userId) => {
        const user = await userService.findById(userId);
        return this.createNotification(user);
      },
      10 // Maximum 10 concurrent operations
    );
  }
}
```

## Performance Monitoring

### Built-in Performance Tracking

```typescript
// Performance monitoring middleware
class PerformanceMonitorMiddleware<T, U> implements BaseMiddleware<T, U> {
  private static metrics = new Map<string, {
    count: number;
    totalTime: number;
    avgTime: number;
    minTime: number;
    maxTime: number;
    errors: number;
  }>();
  
  async before(context: Context<T, U>): Promise<void> {
    // Start performance timer
    context.businessData?.set('perfStartTime', process.hrtime.bigint());
  }
  
  async after(context: Context<T, U>): Promise<void> {
    this.recordMetrics(context, false);
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    this.recordMetrics(context, true);
  }
  
  private recordMetrics(context: Context<T, U>, isError: boolean): void {
    const startTime = context.businessData?.get('perfStartTime');
    if (!startTime) return;
    
    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    
    const endpoint = `${context.req.method}:${context.req.path}`;
    const current = PerformanceMonitorMiddleware.metrics.get(endpoint) || {
      count: 0,
      totalTime: 0,
      avgTime: 0,
      minTime: Infinity,
      maxTime: 0,
      errors: 0
    };
    
    current.count++;
    current.totalTime += duration;
    current.avgTime = current.totalTime / current.count;
    current.minTime = Math.min(current.minTime, duration);
    current.maxTime = Math.max(current.maxTime, duration);
    
    if (isError) {
      current.errors++;
    }
    
    PerformanceMonitorMiddleware.metrics.set(endpoint, current);
    
    // Log slow requests
    if (duration > 1000) {
      console.warn(`Slow request detected:`, {
        endpoint,
        duration: `${duration.toFixed(2)}ms`,
        requestId: context.requestId
      });
    }
  }
  
  static getMetrics(): Record<string, any> {
    const result: Record<string, any> = {};
    
    for (const [endpoint, metrics] of this.metrics.entries()) {
      result[endpoint] = {
        ...metrics,
        avgTime: Number(metrics.avgTime.toFixed(2)),
        errorRate: Number(((metrics.errors / metrics.count) * 100).toFixed(2))
      };
    }
    
    return result;
  }
  
  static resetMetrics(): void {
    this.metrics.clear();
  }
}

// Expose metrics endpoint
const metricsHandler = new Handler<unknown, unknown>()
  .handle(async (context) => {
    const metrics = {
      performance: PerformanceMonitorMiddleware.getMetrics(),
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      guards: RouteGuards.getSystemStats()
    };
    
    context.res.json(metrics);
  });
```

### APM Integration

```typescript
// Application Performance Monitoring integration
class APMIntegration {
  static initializeNewRelic(): void {
    if (process.env.NEW_RELIC_LICENSE_KEY) {
      require('newrelic');
      console.log('New Relic APM initialized');
    }
  }
  
  static initializeDatadog(): void {
    if (process.env.DD_API_KEY) {
      const tracer = require('dd-trace').init({
        service: process.env.SERVICE_NAME || 'noony-app',
        env: process.env.NODE_ENV || 'development'
      });
      console.log('Datadog APM initialized');
    }
  }
  
  // Custom metrics middleware for APM
  static createAPMMiddleware<T, U>(): BaseMiddleware<T, U> {
    return {
      async before(context: Context<T, U>): Promise<void> {
        // Create custom span/transaction
        const span = tracer.startSpan('noony.handler', {
          tags: {
            'http.method': context.req.method,
            'http.path': context.req.path,
            'user.id': context.user?.id
          }
        });
        
        context.businessData?.set('apmSpan', span);
      },
      
      async after(context: Context<T, U>): Promise<void> {
        const span = context.businessData?.get('apmSpan');
        if (span) {
          span.setTag('http.status_code', context.res.statusCode || 200);
          span.finish();
        }
      },
      
      async onError(error: Error, context: Context<T, U>): Promise<void> {
        const span = context.businessData?.get('apmSpan');
        if (span) {
          span.setTag('error', true);
          span.setTag('error.msg', error.message);
          span.setTag('error.type', error.constructor.name);
          span.finish();
        }
      }
    };
  }
}
```

## Best Practices Summary

### Performance Checklist

1. **✅ Use Container Pool** for serverless cold start optimization
2. **✅ Configure Guard Caching** with appropriate TTL values
3. **✅ Implement Database Pooling** with optimized connection settings
4. **✅ Use Prepared Statements** for frequently executed queries
5. **✅ Batch Async Operations** to reduce overhead
6. **✅ Control Concurrency** with promise pools
7. **✅ Monitor Memory Usage** and implement cleanup
8. **✅ Cache Expensive Operations** with appropriate TTL
9. **✅ Use Performance Monitoring** middleware
10. **✅ Profile and Measure** regularly

### Performance Monitoring Commands

```bash
# Monitor performance during development
npm run dev -- --inspect  # Enable Node.js inspector

# Memory profiling
node --max-old-space-size=4096 --inspect your-app.js

# CPU profiling
node --prof your-app.js

# Trace garbage collection
node --trace-gc your-app.js
```

### Production Optimization Settings

```typescript
// Production environment variables for optimal performance
const productionConfig = {
  NODE_ENV: 'production',
  
  // Node.js performance settings
  UV_THREADPOOL_SIZE: '128',           // Increase thread pool
  NODE_OPTIONS: '--max-old-space-size=2048 --optimize-for-size',
  
  // Database connection pool
  DB_POOL_MIN: '5',
  DB_POOL_MAX: '50',
  DB_CONNECTION_TIMEOUT: '30000',
  
  // Guard system cache
  GUARD_CACHE_MAX_ENTRIES: '5000',
  GUARD_CACHE_TTL_MS: '900000',        // 15 minutes
  
  // Container pool
  CONTAINER_POOL_SIZE: '100',
  CONTAINER_PREARM_COUNT: '20',
  
  // Performance monitoring
  ENABLE_PERFORMANCE_MONITORING: 'true',
  METRICS_COLLECTION_INTERVAL: '60000',  // 1 minute
  
  // APM
  NEW_RELIC_LICENSE_KEY: 'your-key',
  DD_API_KEY: 'your-datadog-key'
};
```