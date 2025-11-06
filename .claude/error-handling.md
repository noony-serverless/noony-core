# Noony Framework Error Handling Rules

## Built-in Error Classes Usage

### Framework Error Hierarchy

```typescript
// ✅ CORRECT: Always use framework's built-in error classes
import {
  HttpError,           // Base error with custom status code
  ValidationError,     // 400 - Input validation failures
  AuthenticationError, // 401 - Authentication failures
  SecurityError,       // 403 - Security violations
  TimeoutError,        // 408 - Request timeouts
  TooLargeError,      // 413 - Request size limits
  BusinessError,      // Custom business logic errors
  TooManyRequestsError // 429 - Rate limiting
} from '@noony-serverless/core';

// Use specific error types for proper HTTP status codes
throw new ValidationError('Email format is invalid');
throw new AuthenticationError('Invalid JWT token');
throw new SecurityError('Insufficient permissions for this operation');
throw new BusinessError('Insufficient account balance', 'INSUFFICIENT_FUNDS');

// ❌ INCORRECT: Generic Error class loses HTTP status information
throw new Error('Something went wrong'); // No status code context
```

### Custom Error Classes

```typescript
// ✅ CORRECT: Extend framework error classes for custom errors
class InsufficientInventoryError extends BusinessError {
  constructor(productId: string, requested: number, available: number) {
    super(
      `Insufficient inventory for product ${productId}. Requested: ${requested}, Available: ${available}`,
      'INSUFFICIENT_INVENTORY'
    );
    this.name = 'InsufficientInventoryError';
  }
}

class PaymentProcessingError extends BusinessError {
  constructor(message: string, paymentId?: string) {
    super(message, 'PAYMENT_FAILED');
    this.name = 'PaymentProcessingError';
    if (paymentId) {
      this.metadata = { paymentId };
    }
  }
}

class ExternalServiceError extends HttpError {
  constructor(service: string, statusCode: number, message: string) {
    super(statusCode, `External service ${service} error: ${message}`);
    this.name = 'ExternalServiceError';
    this.metadata = { service, externalStatusCode: statusCode };
  }
}
```

## Error Handler Middleware Patterns

### Comprehensive Error Handler (Always First)

```typescript
class ComprehensiveErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(
    private logger: Logger,
    private includeStackTrace: boolean = process.env.NODE_ENV === 'development'
  ) {}

  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Log error with full context
    this.logger.error(`Request ${context.requestId} failed:`, {
      error: error.message,
      stack: error.stack,
      requestId: context.requestId,
      userId: context.user?.id,
      path: context.req.path,
      method: context.req.method,
      duration: Date.now() - context.startTime
    });

    // Handle specific error types
    if (error instanceof ValidationError) {
      context.res.status(400).json({
        success: false,
        error: {
          type: 'validation_error',
          message: error.message,
          field: (error as any).field,
          ...(this.includeStackTrace && { stack: error.stack })
        },
        requestId: context.requestId
      });
      return;
    }

    if (error instanceof AuthenticationError) {
      context.res.status(401).json({
        success: false,
        error: {
          type: 'authentication_error',
          message: 'Authentication failed' // Generic message for security
        },
        requestId: context.requestId
      });
      return;
    }

    if (error instanceof SecurityError) {
      context.res.status(403).json({
        success: false,
        error: {
          type: 'access_denied',
          message: 'Access denied' // Generic message for security
        },
        requestId: context.requestId
      });
      return;
    }

    if (error instanceof BusinessError) {
      context.res.status(422).json({
        success: false,
        error: {
          type: 'business_error',
          message: error.message,
          code: error.code,
          metadata: error.metadata
        },
        requestId: context.requestId
      });
      return;
    }

    if (error instanceof TooManyRequestsError) {
      context.res.status(429).json({
        success: false,
        error: {
          type: 'rate_limit_exceeded',
          message: error.message
        },
        requestId: context.requestId
      });
      return;
    }

    if (error instanceof TimeoutError) {
      context.res.status(408).json({
        success: false,
        error: {
          type: 'timeout_error',
          message: 'Request timeout'
        },
        requestId: context.requestId
      });
      return;
    }

    // Handle unknown errors (never expose internal details)
    this.logger.error(`Unexpected error in request ${context.requestId}:`, error);
    context.res.status(500).json({
      success: false,
      error: {
        type: 'internal_error',
        message: 'An unexpected error occurred'
      },
      requestId: context.requestId
    });
  }
}

// ✅ CORRECT: Always place ErrorHandlerMiddleware first
const handler = new Handler<RequestType, UserType>()
  .use(new ComprehensiveErrorHandlerMiddleware<RequestType, UserType>(logger))
  .use(new AuthenticationMiddleware<RequestType, UserType>(tokenValidator))
  .use(new BodyValidationMiddleware<RequestType, UserType>(schema))
  .handle(async (context) => {
    // Any error thrown here will be properly handled
  });
```

### Specific Error Handling Middleware

```typescript
// Database error handler
class DatabaseErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Handle database-specific errors
    if (error.message.includes('duplicate key')) {
      const duplicateError = new ValidationError('Resource already exists');
      context.res.status(400).json({
        success: false,
        error: {
          type: 'duplicate_error',
          message: duplicateError.message
        }
      });
      return;
    }

    if (error.message.includes('connection timeout')) {
      const timeoutError = new TimeoutError('Database connection timeout');
      context.res.status(408).json({
        success: false,
        error: {
          type: 'database_timeout',
          message: 'Database operation timed out'
        }
      });
      return;
    }

    // Let other error handlers deal with non-database errors
    throw error;
  }
}

// External API error handler
class ExternalApiErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    if (error instanceof ExternalServiceError) {
      const statusCode = error.metadata?.externalStatusCode >= 500 ? 502 : 422;
      
      context.res.status(statusCode).json({
        success: false,
        error: {
          type: 'external_service_error',
          message: 'External service temporarily unavailable',
          service: error.metadata?.service
        }
      });
      return;
    }

    throw error; // Pass to next error handler
  }
}
```

## Business Logic Error Patterns

### Service Layer Error Handling

```typescript
@Service()
export class OrderService {
  constructor(
    private orderRepository: OrderRepository,
    private inventoryService: InventoryService,
    private paymentService: PaymentService
  ) {}

  async createOrder(orderData: CreateOrderRequest, userId: string): Promise<Order> {
    try {
      // 1. Validate inventory availability
      for (const item of orderData.items) {
        const available = await this.inventoryService.getAvailableStock(item.productId);
        if (available < item.quantity) {
          throw new InsufficientInventoryError(item.productId, item.quantity, available);
        }
      }

      // 2. Calculate totals
      const totals = this.calculateOrderTotals(orderData.items);
      if (totals.total <= 0) {
        throw new BusinessError('Order total must be greater than zero', 'INVALID_TOTAL');
      }

      // 3. Process payment
      let paymentResult;
      try {
        paymentResult = await this.paymentService.processPayment({
          amount: totals.total,
          paymentMethodId: orderData.paymentMethodId,
          customerId: userId
        });
      } catch (error) {
        if (error.code === 'INSUFFICIENT_FUNDS') {
          throw new BusinessError('Insufficient funds on payment method', 'INSUFFICIENT_FUNDS');
        }
        if (error.code === 'INVALID_PAYMENT_METHOD') {
          throw new ValidationError('Invalid payment method');
        }
        throw new PaymentProcessingError('Payment processing failed', error.paymentId);
      }

      // 4. Create order
      const order = await this.orderRepository.create({
        ...orderData,
        ...totals,
        userId,
        paymentId: paymentResult.id,
        status: 'confirmed'
      });

      // 5. Reserve inventory
      await this.inventoryService.reserveItems(orderData.items, order.id);

      return order;

    } catch (error) {
      // Re-throw known errors
      if (error instanceof ValidationError || 
          error instanceof BusinessError ||
          error instanceof InsufficientInventoryError ||
          error instanceof PaymentProcessingError) {
        throw error;
      }

      // Wrap unexpected errors
      throw new BusinessError('Order creation failed', 'ORDER_CREATION_FAILED');
    }
  }
}
```

### Repository Error Handling

```typescript
@Service()
export class UserRepository {
  constructor(private database: DatabaseConnection) {}

  async create(userData: CreateUserRequest): Promise<User> {
    try {
      return await this.database.users.create(userData);
    } catch (error) {
      // Handle database-specific errors
      if (error.code === '23505') { // PostgreSQL unique violation
        throw new ValidationError('Email address is already registered');
      }
      
      if (error.code === '23503') { // Foreign key violation
        throw new ValidationError('Invalid reference data');
      }
      
      if (error.message.includes('timeout')) {
        throw new TimeoutError('Database operation timed out');
      }
      
      // Wrap unknown database errors
      throw new BusinessError('User creation failed', 'DATABASE_ERROR');
    }
  }

  async findById(id: string): Promise<User | null> {
    try {
      return await this.database.users.findById(id);
    } catch (error) {
      if (error.message.includes('timeout')) {
        throw new TimeoutError('Database query timed out');
      }
      throw new BusinessError('Failed to retrieve user', 'DATABASE_ERROR');
    }
  }
}
```

## Async Error Handling Patterns

### Promise Chain Error Handling

```typescript
// ✅ CORRECT: Proper async error handling
class AsyncOperationService {
  async processDataPipeline(data: any): Promise<ProcessedData> {
    try {
      // Chain of async operations with individual error handling
      const validated = await this.validateData(data)
        .catch(error => {
          throw new ValidationError(`Data validation failed: ${error.message}`);
        });

      const transformed = await this.transformData(validated)
        .catch(error => {
          throw new BusinessError('Data transformation failed', 'TRANSFORM_ERROR');
        });

      const enriched = await this.enrichData(transformed)
        .catch(error => {
          // External service errors
          if (error.code === 'EXTERNAL_SERVICE_DOWN') {
            throw new ExternalServiceError('enrichment-service', 503, 'Service unavailable');
          }
          throw new BusinessError('Data enrichment failed', 'ENRICHMENT_ERROR');
        });

      const saved = await this.saveData(enriched)
        .catch(error => {
          throw new BusinessError('Failed to save processed data', 'SAVE_ERROR');
        });

      return saved;

    } catch (error) {
      // Log the error with context
      console.error('Data pipeline failed:', {
        error: error.message,
        data: JSON.stringify(data),
        step: this.getCurrentStep(error)
      });

      // Re-throw to be handled by error middleware
      throw error;
    }
  }
}
```

### Parallel Operations Error Handling

```typescript
class ParallelProcessingService {
  async processMultipleItems(items: ProcessItem[]): Promise<ProcessResult[]> {
    const results = await Promise.allSettled(
      items.map(async (item, index) => {
        try {
          return await this.processItem(item);
        } catch (error) {
          // Wrap individual item errors with context
          throw new BusinessError(
            `Failed to process item ${index}: ${error.message}`,
            'ITEM_PROCESSING_ERROR',
            { itemIndex: index, itemId: item.id }
          );
        }
      })
    );

    // Separate successful and failed results
    const successful: ProcessResult[] = [];
    const errors: Error[] = [];

    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        successful.push(result.value);
      } else {
        errors.push(result.reason);
      }
    });

    // Handle partial failures
    if (errors.length > 0) {
      if (errors.length === items.length) {
        // All failed
        throw new BusinessError(
          'All items failed to process',
          'BATCH_PROCESSING_FAILED',
          { errorCount: errors.length, errors: errors.map(e => e.message) }
        );
      } else {
        // Partial failure - log errors but return successful results
        console.warn('Partial batch processing failure:', {
          successCount: successful.length,
          errorCount: errors.length,
          errors: errors.map(e => e.message)
        });
      }
    }

    return successful;
  }
}
```

## Error Recovery Patterns

### Retry Logic with Exponential Backoff

```typescript
class RetryableService {
  async executeWithRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelayMs: number = 1000
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;

        // Don't retry certain errors
        if (error instanceof ValidationError ||
            error instanceof AuthenticationError ||
            error instanceof SecurityError) {
          throw error;
        }

        // Don't retry on last attempt
        if (attempt === maxRetries) {
          break;
        }

        // Exponential backoff delay
        const delay = baseDelayMs * Math.pow(2, attempt);
        await this.delay(delay);

        console.warn(`Operation failed, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries + 1}):`, error.message);
      }
    }

    // All retries exhausted
    throw new BusinessError(
      `Operation failed after ${maxRetries + 1} attempts: ${lastError.message}`,
      'RETRY_EXHAUSTED'
    );
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### Circuit Breaker Pattern

```typescript
class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';

  constructor(
    private threshold: number = 5,
    private timeout: number = 60000 // 1 minute
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime >= this.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new ExternalServiceError('circuit-breaker', 503, 'Service temporarily unavailable');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
    }
  }
}
```

## Error Monitoring and Alerting

### Error Tracking Middleware

```typescript
class ErrorTrackingMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(
    private errorTracker: ErrorTracker,
    private alertThresholds: Record<string, number> = {
      'validation_error': 100,  // Alert after 100 validation errors/hour
      'business_error': 50,     // Alert after 50 business errors/hour
      'internal_error': 10      // Alert after 10 internal errors/hour
    }
  ) {}

  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Track error metrics
    const errorType = this.getErrorType(error);
    await this.errorTracker.track({
      type: errorType,
      message: error.message,
      requestId: context.requestId,
      userId: context.user?.id,
      path: context.req.path,
      method: context.req.method,
      userAgent: context.req.userAgent,
      ip: context.req.ip,
      timestamp: new Date(),
      stackTrace: error.stack
    });

    // Check alert thresholds
    const recentErrorCount = await this.errorTracker.getRecentCount(errorType, 3600000); // 1 hour
    const threshold = this.alertThresholds[errorType];
    
    if (threshold && recentErrorCount >= threshold) {
      await this.sendAlert(errorType, recentErrorCount, threshold);
    }

    // Continue error propagation
    throw error;
  }

  private getErrorType(error: Error): string {
    if (error instanceof ValidationError) return 'validation_error';
    if (error instanceof BusinessError) return 'business_error';
    if (error instanceof AuthenticationError) return 'authentication_error';
    if (error instanceof SecurityError) return 'security_error';
    return 'internal_error';
  }
}
```

## Testing Error Scenarios

### Error Handling Test Patterns

```typescript
describe('OrderService Error Handling', () => {
  let orderService: OrderService;
  let mockInventoryService: jest.Mocked<InventoryService>;
  let mockPaymentService: jest.Mocked<PaymentService>;

  beforeEach(() => {
    mockInventoryService = {
      getAvailableStock: jest.fn(),
      reserveItems: jest.fn()
    };
    mockPaymentService = {
      processPayment: jest.fn()
    };
    
    orderService = new OrderService(
      mockOrderRepository,
      mockInventoryService,
      mockPaymentService
    );
  });

  it('should throw InsufficientInventoryError when stock is low', async () => {
    const orderData = { items: [{ productId: '123', quantity: 10 }] };
    mockInventoryService.getAvailableStock.mockResolvedValue(5);

    await expect(orderService.createOrder(orderData, 'user1'))
      .rejects
      .toThrow(InsufficientInventoryError);
  });

  it('should throw PaymentProcessingError when payment fails', async () => {
    mockInventoryService.getAvailableStock.mockResolvedValue(100);
    mockPaymentService.processPayment.mockRejectedValue(
      new Error('Payment gateway timeout')
    );

    await expect(orderService.createOrder(orderData, 'user1'))
      .rejects
      .toThrow(PaymentProcessingError);
  });

  it('should handle validation errors properly', async () => {
    const invalidOrderData = { items: [] }; // Empty items array

    await expect(orderService.createOrder(invalidOrderData, 'user1'))
      .rejects
      .toThrow(BusinessError);
  });
});
```

## Best Practices

1. **Always use ErrorHandlerMiddleware first** in the middleware chain
2. **Use specific error types** from the framework for proper HTTP status codes
3. **Never expose internal error details** in production responses
4. **Log errors with full context** for debugging
5. **Implement retry logic** for transient failures
6. **Use circuit breakers** for external service calls
7. **Monitor error rates** and set up alerting
8. **Test error scenarios** thoroughly
9. **Provide meaningful error messages** for validation errors
10. **Clean up resources** in error scenarios (use try/finally or use statements)

## Common Anti-Patterns

```typescript
// ❌ INCORRECT: Generic Error without proper typing
throw new Error('Something went wrong');

// ❌ INCORRECT: Swallowing errors silently
try {
  await riskyOperation();
} catch (error) {
  // Silent failure - very bad!
}

// ❌ INCORRECT: Exposing internal details
catch (error) {
  res.status(500).json({ error: error.stack }); // Exposes internals
}

// ❌ INCORRECT: Not using middleware for error handling
const badHandler = new Handler()
  .handle(async (context) => {
    try {
      // Business logic
    } catch (error) {
      // Inline error handling - should use middleware
      context.res.status(500).json({ error: 'Failed' });
    }
  });
```