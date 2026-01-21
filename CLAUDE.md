# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Build**: `npm run build` - Compiles TypeScript to build/ directory and copies package.json
- **Watch**: `npm run watch` - Continuous TypeScript compilation with watch mode
- **Test**: `npm run test` - Run all Jest tests
- **Test with Coverage**: `npm run test:coverage` - Run tests with coverage report
- **Test Single File**: `npm run test -- <filename>` - Run specific test file
- **Lint**: `npm run lint` - ESLint check for TypeScript files
- **Lint Fix**: `npm run lint:fix` - ESLint with auto-fix
- **Format**: `npm run format` - Prettier formatting for TypeScript, JS, JSON files
- **Format Check**: `npm run format:check` - Check formatting without fixing

## Architecture Overview

This is a **serverless middleware framework** for Google Cloud Functions that provides a Middy-like experience with full TypeScript support. The framework is designed to be framework-agnostic and supports both legacy GCP Functions and modern HTTP frameworks like Fastify and Express.

### Core Architecture Components

### 1. Handler System (`src/core/handler.ts`)
- **Handler class**: Manages middleware execution pipeline with `before`, `after`, and `onError` lifecycle hooks
- **BaseMiddleware interface**: Defines middleware contract with optional lifecycle methods
- **Fluent API**: Chain middlewares using `.use()` and define business logic with `.handle()`
- **Framework Agnostic**: Supports both legacy GCP Functions and generic HTTP frameworks via `execute()` and `executeGeneric()` methods
- **Type Safety (v0.7.0+)**: Invariant generics eliminate the need for `as any` type casts

**Type-Safe Handler Patterns (v0.7.0+):**

```typescript
import { Handler, createTypedHandler, Context } from '@noony-serverless/core';

// Pattern 1: Explicit Types (recommended for clear declarations)
interface LoginRequest {
  email: string;
  password: string;
}

interface AuthUser extends BaseAuthenticatedUser {
  id: string;
  role: 'admin' | 'user';
}

const loginHandler = new Handler<LoginRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<LoginRequest, AuthUser>())
  .use(new BodyValidationMiddleware<LoginRequest, AuthUser>(loginSchema))
  .handle(loginController);  // ✅ No 'as any' needed!

// Pattern 2: Type Inference (recommended for convenience)
async function loginController(context: Context<LoginRequest, AuthUser>) {
  const { email, password } = context.req.validatedBody!;
  const user = await authService.login(email, password);
  return { token: user.token };
}

const loginHandler = createTypedHandler(loginController)
  .use(new ErrorHandlerMiddleware())  // Types inferred automatically
  .use(new BodyValidationMiddleware(loginSchema))
  .handle(loginController);  // ✅ No 'as any' needed!
```

**Migration from v0.6.x**: See [CHANGELOG-v0.7.0.md](CHANGELOG-v0.7.0.md) for complete migration guide.

### 2. Context System (`src/core/core.ts`)
- **Context interface**: Enhanced with dual generics `Context<TBody, TUser>` for type-safe request body and user
- **NoonyRequest/NoonyResponse**: Framework-agnostic interfaces (aliases for GenericRequest/GenericResponse)
- **BaseAuthenticatedUser**: Base interface for authenticated users that can be extended
- **Container Integration**: Uses TypeDI `ContainerInstance` for dependency injection
- **Request Tracking**: Built-in `requestId`, `startTime`, `timeoutSignal`, and `responseData`
- **Legacy Support**: CustomRequest/CustomResponse maintained for backward compatibility

**Type-Safe Context Usage:**
```typescript
import { Context, BaseAuthenticatedUser } from '@noony-serverless/core';

// Define your user type
interface AuthenticatedUser extends BaseAuthenticatedUser {
  role: 'admin' | 'user';
  permissions: string[];
}

// Define your request type
interface CreateResourceRequest {
  name: string;
  description: string;
}

// Use both generics for full type safety
export async function handler(context: Context<CreateResourceRequest, AuthenticatedUser>) {
  const body = context.req.parsedBody;  // Type: CreateResourceRequest | undefined
  const user = context.user;            // Type: AuthenticatedUser | undefined

  // Full autocomplete and type checking!
  if (user?.role === 'admin') {
    // ...
  }
}
```

### 3. Error System (`src/core/errors.ts`)
Built-in error classes with proper HTTP status codes:
- **HttpError**: Base error with custom status codes
- **ValidationError**: 400 - Input validation failures
- **AuthenticationError**: 401 - Authentication failures (legacy)
- **UnauthorizedError**: 401 - Authentication required (recommended)
- **SecurityError**: 403 - Security violations
- **ForbiddenError**: 403 - Insufficient permissions (recommended for authorization)
- **NotFoundError**: 404 - Resource not found
- **TimeoutError**: 408 - Request timeouts
- **ConflictError**: 409 - Resource conflicts or duplicate entries
- **TooLargeError**: 413 - Request size limits
- **InternalServerError**: 500 - Unexpected errors with optional cause chaining
- **BusinessError**: Custom business logic errors
- **ServiceError**: Service layer errors with error codes (not HTTP-specific)

**Error Usage Examples:**
```typescript
import { NotFoundError, ForbiddenError, ConflictError, ServiceError } from '@noony-serverless/core';

// 404 - Resource not found
const user = await userService.getUser(userId);
if (!user) {
  throw new NotFoundError('User not found');
}

// 403 - Permission denied
if (!canAccess(user, resource)) {
  throw new ForbiddenError('You cannot access this resource');
}

// 409 - Conflict
const existing = await userService.findByEmail(email);
if (existing) {
  throw new ConflictError('User with this email already exists');
}

// Service layer error (business logic)
throw new ServiceError('Invalid operation', 'INVALID_STATE', { userId, action });

// 500 - Internal error with cause chaining
try {
  await externalAPI.call();
} catch (err) {
  throw new InternalServerError('External API failed', err as Error);
}
```

### 4. Hybrid Proxy Container (`src/core/containerPool.ts`)
**Zero-Copy Dependency Injection for Serverless**

The Hybrid Proxy Container replaces traditional container pooling with a lightweight proxy pattern optimized for serverless environments. It provides:
- **Process Lifetime (Global)**: Services initialized once and shared across all requests (DB connections, loggers)
- **Request Lifetime (Local)**: Services isolated per-request with zero memory overhead (trace IDs, current user)
- **99% Memory Reduction**: O(1) proxy wrapper instead of O(N) container cloning
- **True Isolation**: Local overrides shadow global services without mutation

**Architecture:**

```typescript
// Startup: Initialize global services once
containerPool.initializeGlobal([
  { id: 'Database', value: new DatabaseService() },
  { id: 'Logger', value: new LoggerService() }
]);

// Per-request: Create lightweight proxy
const container = containerPool.createProxyContainer();

// Read from global (zero-copy)
const db = container.get('Database');  // From global singleton

// Write to local (request-scoped)
container.set('RequestId', 'req-123');  // Local override only
container.set('CurrentUser', user);      // Local override only

// Isolation guaranteed
const nextRequestContainer = containerPool.createProxyContainer();
nextRequestContainer.get('Database');  // ✅ Same global DB
nextRequestContainer.get('RequestId'); // ❌ Throws - not in this request's scope
```

**Key Features:**

1. **Global Fallback**: Reads check local overrides first, then fall back to global container
2. **Local Shadowing**: Writes go to request-local Map, never mutate global state
3. **Tombstone Pattern**: `container.remove('service')` marks as deleted in local scope only
4. **Auto Cleanup**: No manual `release()` needed - proxy is garbage collected automatically
5. **Concurrency Safe**: Multiple requests can read global services simultaneously without locking

**Scope-Aware DI Middleware:**

```typescript
import { dependencyInjection } from '@noony-serverless/core';

// Global scope - process lifetime (use sparingly)
const globalMiddleware = dependencyInjection([
  { id: 'Database', value: new DatabaseService() },
  { id: 'Logger', value: new LoggerService() }
], { scope: 'global' });

// Local scope - request lifetime (recommended)
const localMiddleware = dependencyInjection([
  { id: 'RequestId', value: generateRequestId() },
  { id: 'TraceContext', value: extractTraceContext(req) }
], { scope: 'local' });  // Default

const handler = new Handler()
  .use(globalMiddleware)   // Initialize global services once
  .use(localMiddleware)    // Add request-scoped data per request
  .handle(async (context) => {
    const db = context.container.get('Database');        // From global
    const requestId = context.container.get('RequestId'); // From local
  });
```

**Performance Comparison:**

| Metric | Traditional Pool | Hybrid Proxy | Improvement |
|--------|------------------|--------------|-------------|
| Setup Time | O(N) clone | O(1) proxy | ~99% faster |
| Memory/Request | 15-30KB | < 2KB | ~95% reduction |
| Cleanup | Manual release() | Auto GC | Simpler |
| Isolation | Medium | High | Safer |

**Best Practices:**
- Use **global scope** for expensive-to-create, stateless services (DB connections, external API clients)
- Use **local scope** for request-specific data (trace IDs, authenticated user, request metadata)
- Never mutate global services during request processing
- Leverage `container.has()` to check service availability before accessing

### 5. Utility Functions (`src/utils/`)

#### Query Parameter Utilities (`src/utils/query-param.utils.ts`)
Type-safe utilities for handling query parameters that can be `string | string[] | undefined`:

```typescript
import { asString, asStringArray, asNumber, asBoolean } from '@noony-serverless/core';

export async function listUsersController(context: Context) {
  const query = context.req.query;

  // Type-safe query parameter handling
  const options = {
    search: asString(query.search),      // string | undefined
    page: asNumber(query.page) || 1,     // number (with default)
    limit: asNumber(query.limit) || 10,  // number (with default)
    active: asBoolean(query.active),     // boolean | undefined
    tags: asStringArray(query.tags),     // string[] | undefined
  };

  const users = await service.listUsers(options);
  context.res.status(200).json({ data: users });
}
```

**Available Functions:**
- `asString(value)` - Returns first string value or undefined
- `asStringArray(value)` - Returns array of strings or undefined
- `asNumber(value)` - Parses to number or undefined (uses parseInt base 10)
- `asBoolean(value)` - Returns true for "true" or "1", false otherwise

#### Container Helper (`src/utils/container.utils.ts`)
Type-safe service resolution from the dependency injection container:

```typescript
import { getService } from '@noony-serverless/core';
import { UserService } from '../services/user.service';

export async function createUserController(context: Context<CreateUserRequest>) {
  // Type-safe service resolution - no casting needed!
  const userService = getService(context, UserService);

  const user = await userService.createUser(context.req.parsedBody);
  context.res.status(201).json({ data: user });
}
```

**Benefits:**
- Eliminates boilerplate: `(context.container as ContainerInstance).get()`
- Type-safe service resolution with full autocomplete
- Clear error message if container not initialized

### 6. Middleware Ecosystem (`src/middlewares/`)
Built-in middlewares for common patterns:
- **openTelemetryMiddleware**: Distributed tracing with auto-provider detection and CloudPropagator for GCP
- **errorHandlerMiddleware**: Centralized error handling with custom error types
- **bodyParserMiddleware**: JSON and Pub/Sub message parsing
- **bodyValidationMiddleware**: Zod schema validation with TypeScript integration
- **authenticationMiddleware**: JWT token verification and context.user population
- **responseWrapperMiddleware**: Standardized response format
- **headerVariablesMiddleware**: Required header validation
- **queryParametersMiddleware**: Query string processing
- **dependencyInjectionMiddleware**: TypeDI container setup
- **httpAttributesMiddleware**: HTTP request attributes processing

### 7. Schema Validation with Zod (`src/middlewares/bodyValidationMiddleware.ts`)
**Zod Integration for Type-Safe Endpoint Validation:**

The framework integrates **Zod** for robust schema validation on all endpoints:

```typescript
import { z } from 'zod';
import { BodyValidationMiddleware } from '@/middlewares/bodyValidationMiddleware';

// 1. Define Zod schema
const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  age: z.number().min(18).max(120),
  role: z.enum(['user', 'admin']).default('user')
});

// 2. TypeScript type automatically inferred
type CreateUserRequest = z.infer<typeof createUserSchema>;

// 3. Use validation middleware
const handler = new Handler<CreateUserRequest, UserType>()
  .use(new BodyValidationMiddleware(createUserSchema))
  .handle(async (context) => {
    // context.req.validatedBody is now fully typed as CreateUserRequest
    const { name, email, age, role } = context.req.validatedBody!;
  });
```

**Key Validation Features:**
- **Type Safety**: `z.infer<typeof schema>` generates TypeScript types automatically
- **Runtime Validation**: Validates request data at runtime with detailed error messages
- **Error Handling**: Throws `ValidationError` (400) with Zod error details for invalid data
- **Async Validation**: Supports async validation with `schema.parseAsync()`
- **Nested Objects**: Full support for complex nested schema validation
- **Access Pattern**: Validated data available at `context.req.validatedBody`

### 8. OpenTelemetry Integration (`src/middlewares/openTelemetryMiddleware.ts`)
**Distributed Tracing and Observability:**

The **OpenTelemetryMiddleware** provides automatic distributed tracing with zero-configuration setup and multi-platform support:

```typescript
import { OpenTelemetryMiddleware } from '@/middlewares/openTelemetryMiddleware';

// Zero-config usage - auto-detects provider from environment
const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware<CreateOrderRequest, AuthUser>())
  .handle(async (context) => {
    // Automatically traced with full context
    const order = await orderService.create(context.req.validatedBody!);
    return { orderId: order.id };
  });
```

**Provider Auto-Detection (Priority Order):**
1. **Explicit Provider**: `options.provider` if provided
2. **New Relic**: `NEW_RELIC_LICENSE_KEY` + `newrelic` package
3. **Datadog**: `DD_API_KEY`/`DD_SERVICE` + `dd-trace` package
4. **Standard OTEL**: `OTEL_EXPORTER_OTLP_ENDPOINT`
5. **Console**: `NODE_ENV=development` (local development)
6. **Noop**: `NODE_ENV=test` or no configuration

**Google Cloud Platform Integration:**

When running on GCP (Cloud Run, Cloud Functions, App Engine), Noony automatically enables **CloudPropagator** for trace synchronization:

```typescript
// Install optional CloudPropagator for GCP
npm install @google-cloud/opentelemetry-cloud-trace-propagator --save-optional

// Auto-enabled on GCP - zero configuration needed
const handler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware<CreateOrderRequest, AuthUser>())
  .handle(async (context) => {
    // Trace IDs synchronized with Cloud Run Load Balancer
    // Three response headers automatically added:
    // - X-Cloud-Trace-Context (GCP format)
    // - traceparent (W3C format)
    // - X-Trace-Id (clean 32-char hex for debugging)
  });
```

**CloudPropagator Benefits:**
- **Trace ID Synchronization**: Same trace ID flows from Cloud Run LB → Application → Services
- **Cloud Trace UI**: Complete end-to-end traces visible in Google Cloud Console
- **Cloud Logging Correlation**: Automatic log correlation via trace ID
- **Zero Configuration**: Automatically enabled when `K_SERVICE`, `FUNCTION_NAME`, or `GAE_APPLICATION` env vars detected
- **Graceful Degradation**: Works with or without CloudPropagator package installed

**Response Headers on GCP:**
```http
X-Cloud-Trace-Context: 13ea7e3c2d3b4547baaa399062df1f2d/1234567890123456;o=1
traceparent: 00-13ea7e3c2d3b4547baaa399062df1f2d-1234567890123456-01
X-Trace-Id: 13ea7e3c2d3b4547baaa399062df1f2d
```

**Debugging with X-Trace-Id:**
```bash
# Extract trace ID from response for debugging
TRACE_ID=$(curl -i https://api.example.com/orders | grep -i "X-Trace-Id:" | cut -d' ' -f2)
echo "Trace ID: $TRACE_ID"

# View in Cloud Trace Console
gcloud logging read "trace=projects/my-project/traces/$TRACE_ID" --limit 50
```

**Pub/Sub Trace Propagation:**

Automatically propagate traces across Pub/Sub messages using W3C Trace Context:

```typescript
import { injectTraceContext } from '@noony-serverless/core';

// Publisher - inject trace context
const publisherHandler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new OpenTelemetryMiddleware<CreateOrderRequest, AuthUser>())
  .handle(async (context) => {
    const order = await orderService.create(context.req.validatedBody!);

    // Inject trace context into Pub/Sub message
    const message = injectTraceContext({
      data: Buffer.from(JSON.stringify({ orderId: order.id })).toString('base64'),
      attributes: { eventType: 'order.created' }
    }, context);

    await pubsub.topic('orders').publish(message);
  });

// Subscriber - automatically extracts trace context
const subscriberHandler = new Handler()
  .use(new BodyParserMiddleware())
  .use(new OpenTelemetryMiddleware({ propagatePubSubTraces: true }))
  .handle(async (context) => {
    // Automatically linked to publisher's trace!
    const { orderId } = context.req.parsedBody;
    await inventoryService.reserveStock(orderId);
  });
```

**Best Practices:**
1. **Always use OpenTelemetryMiddleware first** in middleware chain for complete request coverage
2. **Use injectTraceContext()** for all Pub/Sub publishes to maintain distributed traces
3. **Enable CloudPropagator on GCP** by installing the optional package for trace synchronization
4. **Use X-Trace-Id header** for debugging - clean format easier to work with than X-Cloud-Trace-Context
5. **Configure custom attributes** via `extractAttributes` option for business-specific metadata
6. **Filter health checks** using `shouldTrace` option to reduce noise in production

**See:** `OTEL_NOONY.md` for complete OpenTelemetry documentation including provider configuration, custom attributes, and troubleshooting.

### 9. Pub/Sub Utilities (`src/utils/pubsub-trace.utils.ts`)
**Trace Propagation for Google Cloud Pub/Sub:**

Utility functions for distributed tracing across Pub/Sub messages:

```typescript
import { injectTraceContext, extractTraceContext, isPubSubMessage } from '@noony-serverless/core';
```

**Available Functions:**
- `injectTraceContext(message, context?)` - Injects W3C Trace Context into Pub/Sub message attributes
- `extractTraceContext(pubsubMessage)` - Extracts trace context from incoming Pub/Sub messages
- `isPubSubMessage(body)` - Type guard to check if request body is a Pub/Sub message
- `createParentContext(traceContext)` - Creates OpenTelemetry parent context from trace headers

**See:** Section 7 (OpenTelemetry Integration) for complete Pub/Sub trace propagation examples.

### 10. JWT Authentication and User Context (`src/middlewares/authenticationMiddleware.ts`)
**JWT Token Validation and User Access:**

The **AuthenticationMiddleware** handles JWT token validation and populates `context.user`:

```typescript
import { AuthenticationMiddleware, CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';

// 1. Define user type from JWT payload
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
  permissions: string[];
  sub: string;  // JWT subject claim
  exp: number;  // JWT expiration
  iat: number;  // Issued at
}

// 2. Create token verification port
const tokenVerifier: CustomTokenVerificationPort<AuthenticatedUser> = {
  async verifyToken(token: string): Promise<AuthenticatedUser> {
    // Your JWT verification logic here
    return jwt.verify(token, secret) as AuthenticatedUser;
  }
};

// 3. Use authentication middleware
const handler = new Handler<RequestType, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // context.user is now populated with JWT payload
    const user = context.user!; // Type: AuthenticatedUser
    
    // Access user properties with full type safety
    console.log(`User: ${user.email}, Role: ${user.role}`);
    
    // Check permissions
    if (user.permissions.includes('admin:read')) {
      // Admin-only functionality
    }
  });
```

**JWT Authentication Flow:**
1. **Token Extraction**: Extracts JWT from `Authorization: Bearer <token>` header
2. **Token Verification**: Calls your custom `verifyToken()` implementation 
3. **Security Validation**: Validates JWT claims (exp, iss, aud, nbf, etc.)
4. **User Population**: Sets `context.user` with decoded JWT payload
5. **Type Safety**: Full TypeScript typing through generic `UserType` parameter

**JWT Security Features:**
- **Expiration Validation**: Checks `exp` claim with configurable clock tolerance
- **Not-Before Validation**: Validates `nbf` claim for token activation time
- **Issuer/Audience Validation**: Validates `iss` and `aud` claims
- **Token Blacklisting**: Optional callback for revoked token checking  
- **Rate Limiting**: Configurable rate limiting per IP/user
- **Security Logging**: Comprehensive audit logging for failed attempts

**Accessing Authenticated User:**
```typescript
.handle(async (context: Context<RequestType, AuthenticatedUser>) => {
  // Always access user after AuthenticationMiddleware
  const user = context.user!; // Type: AuthenticatedUser
  
  // Access JWT standard claims
  const userId = user.sub;      // JWT subject (user ID)
  const userEmail = user.email; // Custom claim
  const userRole = user.role;   // Custom claim
  
  // Use for business logic
  const userData = await userService.getProfile(user.id);
  return userData;
});
```

### Framework Integration Patterns

The framework supports multiple execution patterns for maximum portability:

#### handler.execute(req, res) - Cloud Functions & Express

Traditional method for Google Cloud Functions and Express:

```typescript
import { http } from '@google-cloud/functions-framework';

export const myFunction = http('myFunction', async (req, res) => {
  await initializeDependencies();
  await handler.execute(req, res);  // Built-in adapter for GCP/Express
});
```

#### handler.executeGeneric(genericReq, genericRes) - Any Framework

Framework-agnostic method using generic interfaces - works with **any** HTTP framework:

```typescript
import { adaptFastifyRequest, adaptFastifyResponse } from '@noony-serverless/core';

// Fastify example
server.post('/api/endpoint', async (req, reply) => {
  const genericReq = adaptFastifyRequest(req);
  const genericRes = adaptFastifyResponse(reply);
  await handler.executeGeneric(genericReq, genericRes);
});

// Or use the convenience wrapper
import { createFastifyHandler } from '@noony-serverless/core';
server.post('/api/endpoint',
  createFastifyHandler(handler, 'endpoint', initializeDependencies)
);
```

**When to use each:**
- **execute()**: Cloud Functions, Express (built-in support)
- **executeGeneric()**: Fastify, Koa, Hapi, NestJS, custom frameworks

**See Section 11: Framework-Agnostic Patterns** for complete integration guide.

### Key Framework Patterns

1. **Middleware Order Matters**: Execute `before` methods in order, `after` and `onError` in reverse order
2. **Type Safety**: Generics flow through Handler<T, U> for request/response typing
3. **Error Propagation**: Errors trigger `onError` handlers in reverse middleware order
4. **Shared State**: Use `context.businessData` Map to share data between middlewares
5. **Request Tracking**: Each request gets a unique `requestId` and timing information

### Middleware Type Chain Preservation (CRITICAL)

**IMPORTANT:** All middlewares MUST preserve the type chain to maintain Noony's framework-agnostic type safety.

#### The Problem
Middlewares that implement `BaseMiddleware` without proper generics break the type chain:

```typescript
// ❌ WRONG - Breaks type chain
export class SomeMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    // context loses TBody and TUser type information
  }
}
```

#### The Solution
ALL middlewares must implement `BaseMiddleware<TBody, TUser>` with proper generics:

```typescript
// ✅ CORRECT - Preserves type chain
export class SomeMiddleware<TBody = unknown, TUser = unknown>
  implements BaseMiddleware<TBody, TUser>
{
  async before(context: Context<TBody, TUser>): Promise<void> {
    // context preserves TBody and TUser type information
  }
}

// Factory function must also preserve types
export const someMiddleware = <TBody = unknown, TUser = unknown>():
  BaseMiddleware<TBody, TUser> => ({
  before: async (context: Context<TBody, TUser>): Promise<void> {
    // Implementation
  },
});
```

#### Reference Implementation
`BodyValidationMiddleware` is the gold standard - use it as a reference for all middleware implementations.

#### Impact on Type Safety
```typescript
// With proper type chain
const handler = new Handler<CreateUserRequest, AuthUser>()
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthUser>(schema))
  .use(new AuthenticationMiddleware<AuthUser, CreateUserRequest>(tokenVerifier))
  .use(new ResponseWrapperMiddleware<UserResponse, CreateUserRequest, AuthUser>())
  .handle(async (context) => {
    // ✅ Full type safety!
    const body = context.req.validatedBody;  // Type: CreateUserRequest
    const user = context.user;               // Type: AuthUser
  });
```

**See:** `docs/TYPE_CHAIN_FIX_SUMMARY.md` for complete details and list of fixed middlewares.

### Complete Example Usage Pattern
**Production-Ready Handler with Zod Validation and JWT Authentication:**

```typescript
import { z } from 'zod';
import { Handler } from '@/core/handler';
import { 
  ErrorHandlerMiddleware, 
  AuthenticationMiddleware, 
  BodyValidationMiddleware,
  ResponseWrapperMiddleware 
} from '@/middlewares';

// 1. Define Zod schema for request validation
const createOrderSchema = z.object({
  productId: z.string().uuid(),
  quantity: z.number().min(1).max(100),
  shippingAddress: z.object({
    street: z.string().min(1),
    city: z.string().min(1),
    zipCode: z.string().regex(/^\d{5}$/)
  }),
  paymentMethodId: z.string().min(1)
});

// 2. TypeScript types automatically inferred
type CreateOrderRequest = z.infer<typeof createOrderSchema>;

// 3. Define authenticated user type from JWT
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'customer' | 'admin';
  permissions: string[];
  sub: string;  // JWT subject claim
}

// 4. Create complete handler with validation and authentication
const createOrderHandler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())                    // 1. Always first - catches all errors
  .use(new AuthenticationMiddleware(tokenVerifier))     // 2. JWT validation -> context.user
  .use(new BodyValidationMiddleware(createOrderSchema)) // 3. Zod validation -> context.req.validatedBody
  .use(new ResponseWrapperMiddleware())                 // 4. Always last - wraps response
  .handle(async (context) => {
    // Full type safety for both validated request and authenticated user
    
    // Access validated request body (Type: CreateOrderRequest)
    const { productId, quantity, shippingAddress, paymentMethodId } = context.req.validatedBody!;
    
    // Access authenticated user (Type: AuthenticatedUser)
    const user = context.user!;
    
    // Business logic with complete type safety
    const order = await orderService.create({
      productId,
      quantity,
      userId: user.id,              // From JWT payload
      customerEmail: user.email,    // From JWT payload
      shippingAddress,              // Validated by Zod
      paymentMethodId,              // Validated by Zod
      createdAt: new Date()
    });
    
    // Permission-based logic
    if (user.role === 'admin') {
      await auditService.logAdminOrder(user.id, order.id);
    }
    
    return {
      success: true,
      orderId: order.id,
      estimatedDelivery: order.estimatedDelivery
    };
  });

// 5. Export for GCP Functions
export const createOrder = http('createOrder', (req, res) => {
  return createOrderHandler.execute(req, res);
});
```

**Key Integration Benefits:**
1. **Double Type Safety**: Both request (`CreateOrderRequest`) and user (`AuthenticatedUser`) are fully typed
2. **Runtime Validation**: Zod validates request structure before business logic
3. **Automatic Error Handling**: Invalid schemas throw `ValidationError` (400), auth failures throw `AuthenticationError` (401)
4. **Secure Access**: User context populated only after successful JWT verification
5. **Clean Business Logic**: Handler receives pre-validated data and authenticated user

## 11. Framework-Agnostic Patterns (Generic Approach)

Noony Framework is designed to be framework-agnostic - the same handler code works seamlessly across different HTTP frameworks and deployment environments. This "write once, deploy anywhere" approach is powered by generic interfaces and adapter functions.

### 11.1 Overview: Write Once, Deploy Anywhere

**The Promise:** Write your handler code once, and run it on any HTTP framework without modification.

**Architecture:**

```
┌────────────────────────────────────────────────────────────┐
│ Local Development (Fastify)  │  Production (Cloud Functions) │
├────────────────────────────────────────────────────────────┤
│ FastifyRequest                │  Cloud Functions Request     │
│        │                      │           │                  │
│        ▼                      │           ▼                  │
│ adaptFastifyRequest()         │  Built-in Adapter            │
│        │                      │           │                  │
│        ▼                      │           ▼                  │
│ GenericRequest ─────────────────────────────────────────────┤
│        │                                  │                  │
│        ▼                                  ▼                  │
│ ┌────────────────────────────────────────────────┐          │
│ │        Noony Handler (Same Code!)              │          │
│ │  .use(ErrorHandlerMiddleware)                  │          │
│ │  .use(BodyValidationMiddleware)                │          │
│ │  .use(AuthenticationMiddleware)                │          │
│ │  .handle(controller)                           │          │
│ └────────────────────────────────────────────────┘          │
│        │                                  │                  │
│        ▼                                  ▼                  │
│ GenericResponse ─────────────────────────────────────────────┤
│        │                      │           │                  │
│        ▼                      │           ▼                  │
│ adaptFastifyResponse()        │  Built-in Adapter            │
│        │                      │           │                  │
│        ▼                      │           ▼                  │
│ FastifyReply                  │  Cloud Functions Response    │
└────────────────────────────────────────────────────────────┘
```

**Key Benefits:**
- **Portability**: Same handler works everywhere without modification
- **Fast Local Development**: Use Fastify for rapid iteration (~2x faster than Cloud Functions emulator)
- **Production Ready**: Deploy to Cloud Functions with confidence
- **Type Safety**: Full TypeScript support preserved through adapters
- **Easy Testing**: Test with real HTTP framework instead of mocks

### 11.2 GenericRequest and GenericResponse Interfaces

**GenericRequest<T>** (alias: NoonyRequest<T>):

```typescript
interface GenericRequest<T = unknown> {
  method: string;              // HTTP method (GET, POST, PUT, DELETE, etc.)
  url: string;                 // Full URL path
  path: string;                // Route path (e.g., '/api/users/:userId')
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  params: Record<string, string>;  // Path parameters (e.g., { userId: '123' })
  body: unknown;               // Raw body
  parsedBody: T;               // Typed parsed body
  ip?: string;                 // Client IP address
  userAgent?: string;          // User-Agent header value
}
```

**GenericResponse** (alias: NoonyResponse):

```typescript
interface GenericResponse {
  // Set HTTP status code
  status(code: number): GenericResponse;

  // Send JSON response
  json(data: unknown): GenericResponse;

  // Send response (any format)
  send(data: unknown): GenericResponse;

  // Set single header
  header(name: string, value: string): GenericResponse;

  // Set multiple headers
  headers(headers: Record<string, string>): GenericResponse;

  // End response
  end(): void;

  // Read-only properties
  readonly statusCode: number;
  readonly headersSent: boolean;
}
```

**Why Generic Interfaces?**
- **Framework Agnostic**: Work with any HTTP framework
- **Type Safe**: Full TypeScript support
- **Chainable API**: Fluent method chaining
- **Standard Contract**: Consistent interface across frameworks

### 11.3 Adapter Functions

Adapter functions convert framework-specific request/response objects to/from Noony's generic interfaces.

#### adaptFastifyRequest<T>()

Converts Fastify's `FastifyRequest` to `GenericRequest<T>`:

```typescript
import { adaptFastifyRequest } from '@noony-serverless/core';

const genericReq = adaptFastifyRequest<CreateUserRequest>(fastifyRequest);
// Returns: GenericRequest<CreateUserRequest>
```

**Performance Optimizations:**
- Pre-allocated empty objects for queries/params
- WeakMap storage for original request (zero memory leaks)
- Inline path extraction (avoids optional chaining overhead)

#### adaptFastifyResponse()

Converts Fastify's `FastifyReply` to `GenericResponse`:

```typescript
import { adaptFastifyResponse } from '@noony-serverless/core';

const genericRes = adaptFastifyResponse(fastifyReply);
// Returns: GenericResponse with chainable methods
```

**Safety Features:**
- Duplicate send prevention
- Header tracking (`headersSent` property)
- Chainable API for fluent usage

**Note:** You typically don't call adapters directly - use `createFastifyHandler()` wrapper instead.

### 11.4 Handler Execution Methods

Noony handlers support two execution methods:

#### handler.execute(req, res) - Cloud Functions

Traditional method for Cloud Functions:

```typescript
import { http } from '@google-cloud/functions-framework';

export const myFunction = http('myFunction', async (req, res) => {
  await initializeDependencies();
  await myHandler.execute(req, res);  // Framework-specific req/res
});
```

#### handler.executeGeneric(genericReq, genericRes) - Any Framework

Framework-agnostic method for use with adapters:

```typescript
import { adaptFastifyRequest, adaptFastifyResponse } from '@noony-serverless/core';

server.post('/api/endpoint', async (req, reply) => {
  await initializeDependencies();

  const genericReq = adaptFastifyRequest(req);
  const genericRes = adaptFastifyResponse(reply);

  await myHandler.executeGeneric(genericReq, genericRes);  // Generic interfaces
});
```

**When to use each:**
- **execute()**: Cloud Functions, Express (built-in support)
- **executeGeneric()**: Fastify, Koa, Hapi, custom frameworks

### 11.5 Fastify Integration with createFastifyHandler()

The primary function for Fastify integration - wraps everything for you:

```typescript
import { createFastifyHandler } from '@noony-serverless/core';

function createFastifyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (req: FastifyRequest, reply: FastifyReply) => Promise<void>
```

**What it does:**
1. Ensures dependencies are initialized (singleton pattern)
2. Adapts Fastify req/reply to GenericRequest/GenericResponse
3. Executes Noony handler via `executeGeneric()`
4. Handles errors gracefully:
   - Ignores `RESPONSE_SENT` errors
   - Returns 500 for real errors
   - Checks `reply.sent` to prevent double responses

**Complete Example:**

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { loginHandler, getUserHandler } from './handlers';

const server = Fastify({ logger: true });

// Helper shorthand
const adapt = (handler, name) =>
  createFastifyHandler(handler, name, initializeDependencies);

// Register routes
server.post('/api/auth/login', adapt(loginHandler, 'login'));
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));

server.listen({ port: 3000 });
```

**Path Parameters:**

```typescript
const getUserHandler = new Handler<void, AuthUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // Access path params from context.req.params
    const userId = context.req.params.userId;
    const user = await userService.getById(userId);
    context.res.status(200).json({ data: user });
  });

// Fastify path parameter syntax
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));
server.patch('/api/users/:userId/sections/:sectionId',
  adapt(updateSectionHandler, 'updateSection')
);
```

### 11.6 Local Development vs Production Pattern

The same handler works in both environments with different entry points:

**Handler Definition (Write Once!):**

```typescript
// src/handlers/order.handlers.ts
export const createOrderHandler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateOrderRequest, AuthenticatedUser>) => {
    const { productId, quantity } = context.req.validatedBody!;
    const user = context.user!;

    const order = await orderService.create({
      productId,
      quantity,
      userId: user.id,
    });

    context.res.status(201).json({ data: order });
  });
```

**Local Development (Fastify) - src/server.ts:**

```typescript
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createOrderHandler } from './handlers/order.handlers';

const server = Fastify();

server.post('/api/orders',
  createFastifyHandler(createOrderHandler, 'createOrder', initializeDependencies)
);

server.listen({ port: 3000 });
```

**Production (Cloud Functions) - src/functions.ts:**

```typescript
import { http } from '@google-cloud/functions-framework';
import { createOrderHandler } from './handlers/order.handlers';

export const createOrder = http('createOrder', async (req, res) => {
  await initializeDependencies();
  await createOrderHandler.execute(req, res);
});
```

**Development Workflow:**

```bash
# Local development with Fastify
npm run dev  # Server on http://localhost:3000

# Test locally
curl -X POST http://localhost:3000/api/orders \
  -H "Content-Type: application/json" \
  -d '{"productId":"abc","quantity":2}'

# Deploy to Cloud Functions (same handler!)
npm run build
npm run deploy

# Test production
curl -X POST https://us-central1-myproject.cloudfunctions.net/createOrder \
  -H "Content-Type: application/json" \
  -d '{"productId":"abc","quantity":2}'
```

### 11.7 Performance Optimizations

The Fastify integration includes several performance optimizations:

1. **Pre-allocated Empty Objects**: Avoids allocations for empty query/params
   ```typescript
   const EMPTY_QUERY = Object.freeze({});
   const EMPTY_PARAMS = Object.freeze({});
   ```

2. **WeakMap for Request Storage**: Zero memory leak risk
   ```typescript
   export const requestBodyMap = new WeakMap<any, FastifyRequest>();
   ```

3. **Inline Path Extraction**: Avoids optional chaining overhead
   ```typescript
   const routeUrl = (req.routeOptions as any)?.url;
   const path = routeUrl || req.url;
   ```

4. **Pre-allocated Error Response**: Reduces allocations in error path
   ```typescript
   const INTERNAL_ERROR_RESPONSE = Object.freeze({
     success: false,
     error: Object.freeze({
       code: 'INTERNAL_SERVER_ERROR',
       message: 'An unexpected error occurred',
     }),
   });
   ```

5. **Fast Path Error Checking**: `RESPONSE_SENT` checked first
   ```typescript
   if (error instanceof Error && error.message === 'RESPONSE_SENT') {
     return;  // Fast path exit
   }
   ```

6. **Singleton Dependency Initialization**: Prevents redundant DB connections
   ```typescript
   let initialized = false;
   let initPromise: Promise<void> | null = null;

   async function initializeDependencies(): Promise<void> {
     if (initialized && containerPool.isInitialized()) return;
     if (initPromise) { await initPromise; return; }
     // Initialize once...
   }
   ```

**Benchmark Results:**
- **Fastify + Noony**: ~30,000 req/s (local development)
- **Express + Noony**: ~15,000 req/s (Cloud Functions)
- **Performance gain**: ~2x faster for local testing

### 11.8 Quick Start with NOONY_SKILLS.md

For copy-paste ready code examples, see [docs/NOONY_SKILLS.md](docs/NOONY_SKILLS.md):

- **Skill 1**: Create Type-Safe Fastify Server
- **Skill 2**: Convert Cloud Functions Handler to Fastify
- **Skill 3**: Custom Adapter for New Framework
- **Skill 4**: Path Parameters with Fastify
- **Skill 5**: Dependency Initialization Pattern
- **Skill 6**: Complete Dual-Entry Example
- **Skill 7**: Type Inference with createTypedHandler()

Each skill includes:
- **Triggers**: User phrases that activate the skill
- **Complete code example**: Ready to copy and use
- **When to use**: Guidance on appropriate usage

## Testing
- Tests use Jest with ts-jest preset
- All `*.test.ts` files in src/ are automatically discovered
- Coverage excludes index.ts files and test files
- Path mapping: `@/` maps to `src/`
- Run single test: `npm run test -- handler.test.ts`
- Test examples are available in examples/ directory

## Key Dependencies
- **@google-cloud/functions-framework**: Core GCP Functions runtime
- **@google-cloud/firestore**: Firestore database client
- **@google-cloud/pubsub**: Pub/Sub messaging
- **@opentelemetry/sdk-node**: OpenTelemetry SDK 2.0 for distributed tracing
- **@opentelemetry/api**: OpenTelemetry API for tracing and context propagation
- **@google-cloud/opentelemetry-cloud-trace-propagator**: (Optional) CloudPropagator for GCP trace synchronization
- **zod**: Schema validation
- **typedi**: Dependency injection
- **jsonwebtoken**: JWT handling
- **firebase-admin**: Firebase integration
- **firebase-functions**: Firebase Functions SDK
- **axios**: HTTP client for external API calls
- **fastify**: Optional Fastify integration support

## Project Structure
```
src/
├── core/                    # Core framework components
│   ├── handler.ts           # Main Handler class and middleware pipeline
│   ├── core.ts              # Context interfaces and type definitions
│   ├── errors.ts            # Built-in error classes
│   ├── logger.ts            # Logger utility
│   ├── containerPool.ts     # Container pool management
│   ├── performanceMonitor.ts # Performance monitoring
│   └── telemetry/           # OpenTelemetry integration
│       ├── config.ts        # Telemetry configuration and presets
│       ├── provider.ts      # TelemetryProvider interface
│       └── providers/       # Provider implementations (OTEL, Console, Noop)
├── middlewares/             # Built-in middleware implementations
│   ├── guards/              # Permission & auth guard system
│   ├── openTelemetryMiddleware.ts # OpenTelemetry middleware with CloudPropagator
│   └── *.ts                 # Individual middlewares
├── utils/                   # Utility functions (NEW in v0.3.0)
│   ├── query-param.utils.ts # Query parameter helpers
│   ├── container.utils.ts   # Container service resolution
│   ├── pubsub-trace.utils.ts # Pub/Sub trace propagation utilities
│   └── index.ts             # Utils exports
└── index.ts                 # Main exports
examples/
├── hello-world-simple/      # Basic usage examples
└── fastify-production-api/  # Production-ready Fastify integration
```

## Quick Start Skills

For common development tasks, refer to **[docs/NOONY_SKILLS.md](docs/NOONY_SKILLS.md)** - a collection of 7 copy-paste ready code patterns.

### Available Skills

1. **Create Type-Safe Fastify Server**
   - Complete Fastify server template for local development
   - Dependency initialization, route registration, graceful shutdown
   - **Use when**: Setting up local development environment

2. **Convert Cloud Functions Handler to Fastify**
   - Enable existing Cloud Functions handlers to work with Fastify
   - Same handler, dual entry points (local + production)
   - **Use when**: Want to test handlers locally without deploying

3. **Custom Adapter for New Framework**
   - Template for creating adapters for unsupported frameworks
   - Includes request/response adapters and handler wrapper
   - **Use when**: Integrating with Koa, Hapi, NestJS, or custom frameworks

4. **Path Parameters with Fastify**
   - Handlers that use path parameters (e.g., `/api/users/:userId`)
   - Type-safe parameter access patterns
   - **Use when**: Building RESTful APIs with resource IDs

5. **Dependency Initialization Pattern**
   - Singleton pattern for database connections and services
   - Prevents redundant initializations and memory leaks
   - **Use when**: Managing database connections or expensive resources

6. **Complete Dual-Entry Example**
   - End-to-end example with same handler in Fastify and Cloud Functions
   - Includes handler definition, server setup, deployment scripts
   - **Use when**: Learning the framework-agnostic pattern

7. **Type Inference with createTypedHandler()**
   - Automatic type inference from controller signature
   - Reduces boilerplate by ~50%
   - **Use when**: Controller already has explicit type annotations

### How Skills Work

Each skill includes:
- **Triggers**: User phrases that should activate this skill (for AI assistants)
- **Complete code example**: Production-ready, copy-paste code
- **When to use**: Clear guidance on appropriate usage
- **Benefits**: Why this pattern is recommended

### Example Usage

When you ask questions like:
- "How do I set up local development?" → **Skill 1** (Fastify Server)
- "I want to test without deploying" → **Skill 2** (Conversion Pattern)
- "How do I use path parameters?" → **Skill 4** (Path Parameters)
- "Reduce type boilerplate" → **Skill 7** (createTypedHandler)

The skills provide immediate, copy-paste ready solutions.