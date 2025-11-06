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

### 4. Utility Functions (`src/utils/`)

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

### 5. Middleware Ecosystem (`src/middlewares/`)
Built-in middlewares for common patterns:
- **errorHandlerMiddleware**: Centralized error handling with custom error types
- **bodyParserMiddleware**: JSON and Pub/Sub message parsing
- **bodyValidationMiddleware**: Zod schema validation with TypeScript integration
- **authenticationMiddleware**: JWT token verification and context.user population
- **responseWrapperMiddleware**: Standardized response format
- **headerVariablesMiddleware**: Required header validation
- **queryParametersMiddleware**: Query string processing
- **dependencyInjectionMiddleware**: TypeDI container setup
- **httpAttributesMiddleware**: HTTP request attributes processing

### 6. Schema Validation with Zod (`src/middlewares/bodyValidationMiddleware.ts`)
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

### 7. JWT Authentication and User Context (`src/middlewares/authenticationMiddleware.ts`)
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

The framework supports multiple execution patterns:

**GCP Functions (Legacy)**:
```typescript
export const myFunction = http('myFunction', (req, res) => {
  return handler.execute(req, res);
});
```

**Framework Agnostic**:
```typescript
// Works with Express, Fastify, etc.
await handler.executeGeneric(genericReq, genericRes);
```

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
│   └── performanceMonitor.ts # Performance monitoring
├── middlewares/             # Built-in middleware implementations
│   ├── guards/              # Permission & auth guard system
│   └── *.ts                 # Individual middlewares
├── utils/                   # Utility functions (NEW in v0.3.0)
│   ├── query-param.utils.ts # Query parameter helpers
│   ├── container.utils.ts   # Container service resolution
│   └── index.ts             # Utils exports
└── index.ts                 # Main exports
examples/
├── hello-world-simple/      # Basic usage examples
└── fastify-production-api/  # Production-ready Fastify integration
```