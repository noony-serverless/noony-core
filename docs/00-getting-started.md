# How to Use Noony Framework in This Project

> Practical guide to all Noony framework components used in this project with complete working examples from the actual source code.

## What's New in v0.6.0

🎉 **Major Type Safety Improvements:**

- **Dual Generics System**: `Handler<TBody, TUser>` and `Context<TBody, TUser>` for complete type safety
- **Type-Safe Middlewares**: All middlewares now support generics to preserve type information
- **ResponseWrapperMiddleware**: Now supports response type generics `ResponseWrapperMiddleware<TResponse, TBody, TUser>`
- **ErrorHandlerMiddleware**: New class-based error handler with generics support
- **BaseAuthenticatedUser**: New base interface for user types
- **Enhanced Examples**: Comprehensive examples showing dual generic patterns

**Migration Guide:**

```typescript
// ❌ Old way (still works)
const handler = new Handler<LoginRequest>()
  .use(errorHandler())
  .handle(async (context) => {
    const body = context.req.parsedBody as LoginRequest;
    const user = context.user as any;
  });

// ✅ New way (recommended)
const handler = new Handler<LoginRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<LoginRequest, AuthenticatedUser>())
  .handle(async (context: Context<LoginRequest, AuthenticatedUser>) => {
    const body = context.req.validatedBody!; // Type: LoginRequest
    const user = context.user!; // Type: AuthenticatedUser
  });
```

## Table of Contents

1. [Overview](#1-overview)
2. [Core Components](#2-core-components)
3. [Custom Middleware Reference](#3-custom-middleware-reference)
4. [Handler Patterns](#4-handler-patterns)
5. [Controller Patterns](#5-controller-patterns)
6. [Dependency Injection (ContainerPool)](#6-dependency-injection-containerpool)
7. [Cloud Functions Integration](#7-cloud-functions-integration)
8. [Fastify Integration](#8-fastify-integration)
9. [TypeScript Generics Patterns (NEW in v0.6.0)](#9-typescript-generics-patterns-new-in-v060)
10. [Best Practices](#10-best-practices)

---

## 1. Overview

### Package Information

```json
{
  "@noony-serverless/core": "^0.6.0"
}
```

### Files Using Noony Framework

| File                                       | Noony Components Used                            |
| ------------------------------------------ | ------------------------------------------------ |
| `src/handlers/auth.handlers.ts`            | Handler, errorHandler, ResponseWrapperMiddleware |
| `src/handlers/config.handlers.ts`          | Handler, errorHandler, ResponseWrapperMiddleware |
| `src/controllers/auth.controllers.ts`      | Context                                          |
| `src/controllers/config.controllers.ts`    | Context                                          |
| `src/middlewares/auth.middleware.ts`       | BaseMiddleware, Context                          |
| `src/middlewares/validation.middleware.ts` | BaseMiddleware, Context                          |
| `src/functions.ts`                         | Handler                                          |

### Architecture Flow

```
Request → Handler → Middleware Chain → Controller → Response
                ↓
         errorHandler()
                ↓
         authMiddleware()
                ↓
         requirePermission()
                ↓
         bodyValidator()
                ↓
         ResponseWrapperMiddleware
                ↓
         Controller Function
```

---

## 2. Core Components

### 2.1 Handler\<TBody, TUser\>

**What it is:** The central orchestrator that builds middleware chains and executes request handling with full TypeScript type safety using dual generics.

**Import:**

```typescript
import { Handler } from '@noony-serverless/core';
```

**Where used:** `src/handlers/auth.handlers.ts`, `src/handlers/config.handlers.ts`

**Why:** Provides a fluent API for chaining middleware and connecting to controller functions with complete type safety for both request body and authenticated user.

**How:** Use `.use()` to add middleware and `.handle()` to set the controller.

**Generic Parameters:**

- `TBody`: Type of the request body (defaults to `unknown`)
- `TUser`: Type of the authenticated user (defaults to `unknown`)

**Complete Example from Project:**

```typescript
// src/handlers/auth.handlers.ts

import {
  Handler,
  errorHandler,
  ResponseWrapperMiddleware,
} from '@noony-serverless/core';
import {
  loginRequestSchema,
  LoginRequest,
} from '../models/auth/auth.schemas.js';
import { bodyValidator } from '../middlewares/validation.middleware.js';
import { loginController } from '../controllers/auth.controllers.js';

/**
 * Login handler - POST /api/auth/login
 * Public endpoint - no authentication required
 */
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);
```

**Example with Both Generics (Request + User):**

```typescript
import { Handler, BaseAuthenticatedUser } from '@noony-serverless/core';
import { z } from 'zod';

// Define user type
interface AuthenticatedUser extends BaseAuthenticatedUser {
  role: 'admin' | 'user';
  permissions: string[];
}

// Define request schema
const createOrderSchema = z.object({
  productId: z.string().uuid(),
  quantity: z.number().min(1),
});

type CreateOrderRequest = z.infer<typeof createOrderSchema>;

// Handler with full type safety for both body and user
export const createOrderHandler = new Handler<
  CreateOrderRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    // ✅ context.req.validatedBody typed as CreateOrderRequest
    // ✅ context.user typed as AuthenticatedUser
    const { productId, quantity } = context.req.validatedBody!;
    const user = context.user!;

    if (user.role === 'admin') {
      // Full autocomplete and type checking!
    }
  });
```

---

### 2.2 Context\<TBody, TUser\>

**What it is:** The request/response context object that flows through the middleware chain with full type safety using dual generics.

**Import:**

```typescript
import { Context, BaseAuthenticatedUser } from '@noony-serverless/core';
```

**Where used:** `src/controllers/*.controllers.ts`, `src/middlewares/*.middleware.ts`

**Why:** Provides unified access to request data, response methods, authenticated user, and shared data with complete TypeScript type inference.

**Generic Parameters:**

- `TBody`: Type of the request body (defaults to `unknown`)
- `TUser`: Type of the authenticated user (defaults to `unknown`)

**Properties Reference:**

| Property            | Type                                              | Description                                       |
| ------------------- | ------------------------------------------------- | ------------------------------------------------- |
| `req`               | `NoonyRequest<TBody>`                             | Request object with typed body                    |
| `req.body`          | `unknown`                                         | Raw request body                                  |
| `req.parsedBody`    | `TBody \| undefined`                              | Validated/parsed request body (set by middleware) |
| `req.validatedBody` | `TBody \| undefined`                              | Alias for parsedBody (Zod validation)             |
| `req.params`        | `Record<string, string>`                          | URL path parameters                               |
| `req.headers`       | `Record<string, string \| string[] \| undefined>` | Request headers                                   |
| `req.query`         | `Record<string, string \| string[] \| undefined>` | Query parameters                                  |
| `req.ip`            | `string`                                          | Client IP address                                 |
| `res`               | `NoonyResponse`                                   | Response object                                   |
| `user`              | `TUser \| undefined`                              | Authenticated user (set by auth middleware)       |
| `container`         | `ContainerInstance`                               | TypeDI dependency injection container             |
| `businessData`      | `Map<string, unknown>`                            | Shared data between middlewares                   |
| `requestId`         | `string`                                          | Unique request identifier                         |
| `startTime`         | `number`                                          | Request start timestamp                           |

**Example 1: Public Endpoint (Body only):**

```typescript
// src/controllers/auth.controllers.ts

import { Context } from '@noony-serverless/core';
import { LoginRequest } from '../models/auth/auth.schemas.js';
import { containerPool } from '../core/container-pool.js';
import { AuthService } from '../services/auth.service.js';

export async function loginController(
  context: Context<LoginRequest>
): Promise<void> {
  // ✅ Access validated request body (typed as LoginRequest)
  const data = context.req.parsedBody!;

  // Full type safety and autocomplete
  const email = data.email;
  const password = data.password;

  // Access headers
  const userAgent = context.req.headers['user-agent'] as string | undefined;
  const forwardedFor = context.req.headers['x-forwarded-for'] as
    | string
    | undefined;
  const clientIp = forwardedFor || context.req.ip;

  // Get service from container
  const authService = containerPool.getByToken<AuthService>('AuthService');

  // Execute business logic
  const result = await authService.login(email, password, userAgent, clientIp);

  // Write response
  if (!result.success) {
    context.res.status(401).json({
      success: false,
      error: {
        message: result.error || 'Authentication failed',
        code: 'AUTH_FAILED',
      },
    });
    return;
  }

  context.res.status(200).json({
    success: true,
    data: result.data,
  });
}
```

**Example 2: Protected Endpoint (Body + User):**

```typescript
import { Context, BaseAuthenticatedUser } from '@noony-serverless/core';
import { CreateOrderRequest } from '../models/order.schemas.js';
import { getService } from '@noony-serverless/core';
import { OrderService } from '../services/order.service.js';

// Define authenticated user type
interface AuthenticatedUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'customer' | 'admin';
  permissions: string[];
}

export async function createOrderController(
  context: Context<CreateOrderRequest, AuthenticatedUser>
): Promise<void> {
  // ✅ Full type safety for both request and user
  const { productId, quantity, shippingAddress } = context.req.validatedBody!;
  const user = context.user!; // Type: AuthenticatedUser

  // Type-safe user properties access
  const userId = user.id;
  const userRole = user.role;
  const userEmail = user.email;

  // Get service from container
  const orderService = getService(context, OrderService);

  // Permission-based logic with type safety
  if (user.role === 'admin') {
    // Admin-specific functionality
  }

  // Create order with validated data
  const order = await orderService.create({
    productId,
    quantity,
    shippingAddress,
    userId,
    customerEmail: userEmail,
    createdAt: new Date(),
  });

  context.res.status(201).json({
    success: true,
    data: order,
  });
}
```

---

### 2.3 BaseMiddleware\<TBody, TUser\>

**What it is:** Interface for creating custom middleware with lifecycle methods and full type safety using dual generics.

**Import:**

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';
```

**Where used:** `src/middlewares/auth.middleware.ts`, `src/middlewares/validation.middleware.ts`

**Why:** Allows creating custom middleware that integrates with Noony's middleware chain while preserving type information.

**Interface:**

```typescript
interface BaseMiddleware<TBody = unknown, TUser = unknown> {
  before?(context: Context<TBody, TUser>): Promise<void>;
  after?(context: Context<TBody, TUser>): Promise<void>;
  onError?(error: Error, context: Context<TBody, TUser>): Promise<void>;
}
```

#### Type Chain Preservation (IMPORTANT)

All custom middlewares MUST use generics to preserve type information:

```typescript
// ❌ WRONG - Breaks type chain
export class MyMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    // Type information lost!
  }
}

// ✅ CORRECT - Preserves type chain
export class MyMiddleware<
  TBody = unknown,
  TUser = unknown,
> implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Type information preserved!
  }
}
```

**Complete Example from Project:**

```typescript
// src/middlewares/auth.middleware.ts

import { BaseMiddleware, Context } from '@noony-serverless/core';
import { containerPool } from '../core/container-pool.js';
import { JWTTokenValidator } from '../guards/jwt-token.validator.js';
import { MongoPermissionSource } from '../guards/mongo-permission.source.js';
import { AuthenticatedUser } from '../types/auth.types.js';

/**
 * Authentication middleware for Noony handlers
 * Validates JWT token and populates context.user with AuthenticatedUser
 */
export class AuthenticationMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    const authHeader = context.req.headers['authorization'];
    const token = extractBearerToken(authHeader);

    if (!token) {
      return; // No token - let requireAuth() handle enforcement
    }

    try {
      const tokenValidator =
        containerPool.getByToken<JWTTokenValidator>('TokenValidator');
      const validationResult = await tokenValidator.validateToken(token);

      if (!validationResult.valid || !validationResult.decoded) {
        return;
      }

      const permissionSource =
        containerPool.getByToken<MongoPermissionSource>('PermissionSource');
      const userId = tokenValidator.extractUserId(validationResult.decoded);
      const permissionResult =
        await permissionSource.getUserPermissions(userId);

      if (!permissionResult) {
        return;
      }

      // Set authenticated user on context
      const user: AuthenticatedUser = {
        id: userId,
        email: validationResult.decoded.email,
        role: validationResult.decoded.role,
        tenantId: validationResult.decoded.tenantId,
        permissions: permissionResult.permissions,
        status: 'active',
        firstName: permissionResult.metadata?.firstName as string | undefined,
        lastName: permissionResult.metadata?.lastName as string | undefined,
      };

      context.user = user;
    } catch (error) {
      // Silently fail - let requireAuth() handle enforcement
    }
  }
}

// Factory function for cleaner usage
export const authMiddleware = (): BaseMiddleware =>
  new AuthenticationMiddleware();
```

---

### 2.4 ErrorHandlerMiddleware\<TBody, TUser\>

**What it is:** Built-in middleware for centralized error handling with full type safety.

**Import:**

```typescript
import { ErrorHandlerMiddleware } from '@noony-serverless/core';
// OR legacy import
import { errorHandler } from '@noony-serverless/core';
```

**Why:** Catches all errors from subsequent middleware and controllers, providing consistent error responses. Integrates with built-in error types for automatic HTTP status code mapping.

**IMPORTANT:** Always use as the **FIRST** middleware in the chain.

**Generic Parameters:**

- `TBody`: Type of the request body (optional, defaults to `unknown`)
- `TUser`: Type of the authenticated user (optional, defaults to `unknown`)

**Built-in Error Types Integration:**

The ErrorHandlerMiddleware automatically maps Noony error types to HTTP status codes:

```typescript
import {
  ValidationError, // 400
  UnauthorizedError, // 401
  ForbiddenError, // 403
  NotFoundError, // 404
  ConflictError, // 409
  InternalServerError, // 500
} from '@noony-serverless/core';
```

**Example 1: Basic Usage (Legacy):**

```typescript
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler()) // ← ALWAYS FIRST
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);
```

**Example 2: With Generics (Recommended):**

```typescript
import { Handler, ErrorHandlerMiddleware } from '@noony-serverless/core';

interface CreateOrderRequest {
  productId: string;
  quantity: number;
}

interface AuthenticatedUser {
  id: string;
  role: 'customer' | 'admin';
}

export const createOrderHandler = new Handler<
  CreateOrderRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthenticatedUser>()) // ← ALWAYS FIRST
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context) => {
    // Throw built-in errors - automatically handled with correct status codes
    const product = await productService.getById(
      context.req.validatedBody!.productId
    );

    if (!product) {
      throw new NotFoundError('Product not found'); // → 404 response
    }

    if (product.stock < context.req.validatedBody!.quantity) {
      throw new ConflictError('Insufficient stock'); // → 409 response
    }

    // Create order logic...
  });
```

**Error Response Format:**

All errors are automatically formatted as:

```typescript
{
  success: false,
  error: {
    message: string,      // Error message
    code: string,         // Error code (e.g., 'NOT_FOUND')
    details?: unknown     // Optional additional details
  }
}
```

**Custom Error Handling:**

```typescript
import { HttpError } from '@noony-serverless/core';

// Throw custom HTTP error
throw new HttpError(418, "I'm a teapot", 'TEAPOT_ERROR');

// With details
throw new ValidationError('Invalid input', {
  field: 'email',
  reason: 'invalid format',
});
```

---

### 2.5 ResponseWrapperMiddleware\<TResponse, TBody, TUser\>

**What it is:** Built-in middleware that standardizes response format with optional type safety for response data.

**Import:**

```typescript
import { ResponseWrapperMiddleware } from '@noony-serverless/core';
```

**Why:** Ensures all responses follow a consistent format structure and provides type safety for response data.

**IMPORTANT:** Always use as the **LAST** middleware in the chain (before `.handle()`).

**Generic Parameters:**

- `TResponse`: Type of the response data (optional, defaults to `unknown`)
- `TBody`: Type of the request body (optional, defaults to `unknown`)
- `TUser`: Type of the authenticated user (optional, defaults to `unknown`)

**Example 1: Basic Usage (No Response Typing):**

```typescript
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware()) // ← ALWAYS LAST (before handle)
  .handle(loginController);
```

**Example 2: With Response Type Safety:**

```typescript
import { Handler, ResponseWrapperMiddleware } from '@noony-serverless/core';

interface CreateOrderResponse {
  orderId: string;
  estimatedDelivery: Date;
  total: number;
}

interface CreateOrderRequest {
  productId: string;
  quantity: number;
}

interface AuthenticatedUser {
  id: string;
  role: 'customer' | 'admin';
}

// Full type safety: Response, Request, and User
export const createOrderHandler = new Handler<
  CreateOrderRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(
    new ResponseWrapperMiddleware<
      CreateOrderResponse,
      CreateOrderRequest,
      AuthenticatedUser
    >()
  )
  .handle(async (context) => {
    // Return typed response data
    const order = await orderService.create(context.req.validatedBody!);

    return {
      orderId: order.id,
      estimatedDelivery: order.estimatedDelivery,
      total: order.total,
    } as CreateOrderResponse; // Type-safe return
  });
```

**Response Format:**

All responses are automatically wrapped in a standard format:

```typescript
// Success response
{
  success: true,
  data: CreateOrderResponse  // Your typed data
}

// Error response (handled by ErrorHandlerMiddleware)
{
  success: false,
  error: {
    message: string,
    code: string,
    details?: unknown
  }
}
```

---

## 3. Custom Middleware Reference

### 3.1 AuthenticationMiddleware

**Purpose:** Extracts JWT from Bearer token and validates it, populating `context.user`.

**File:** `src/middlewares/auth.middleware.ts`

**Factory Function:** `authMiddleware()`

**Full Implementation:**

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';
import { Logger } from '../services/logger.service.js';
import { containerPool } from '../core/container-pool.js';
import { JWTTokenValidator } from '../guards/jwt-token.validator.js';
import { MongoPermissionSource } from '../guards/mongo-permission.source.js';
import { AuthenticatedUser } from '../types/auth.types.js';

const logger = new Logger('AuthMiddleware');

/**
 * Extract Bearer token from Authorization header
 */
function extractBearerToken(
  authHeader: string | string[] | undefined
): string | null {
  if (!authHeader) return null;
  const header = Array.isArray(authHeader) ? authHeader[0] : authHeader;
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.substring(7);
}

/**
 * Authentication middleware for Noony handlers
 * Validates JWT token and populates context.user with AuthenticatedUser
 */
export class AuthenticationMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    const authHeader = context.req.headers['authorization'];
    const token = extractBearerToken(authHeader);

    if (!token) {
      logger.debug('No bearer token provided');
      return;
    }

    try {
      const tokenValidator =
        containerPool.getByToken<JWTTokenValidator>('TokenValidator');
      const validationResult = await tokenValidator.validateToken(token);

      if (!validationResult.valid || !validationResult.decoded) {
        logger.debug('Invalid token', { error: validationResult.error });
        return;
      }

      const permissionSource =
        containerPool.getByToken<MongoPermissionSource>('PermissionSource');
      const userId = tokenValidator.extractUserId(validationResult.decoded);
      const permissionResult =
        await permissionSource.getUserPermissions(userId);

      if (!permissionResult) {
        logger.debug('User not found for permissions', { userId });
        return;
      }

      const user: AuthenticatedUser = {
        id: userId,
        email: validationResult.decoded.email,
        role: validationResult.decoded.role,
        tenantId: validationResult.decoded.tenantId,
        permissions: permissionResult.permissions,
        status: 'active',
        firstName: permissionResult.metadata?.firstName as string | undefined,
        lastName: permissionResult.metadata?.lastName as string | undefined,
      };

      context.user = user;
      logger.debug('User authenticated', { userId, role: user.role });
    } catch (error) {
      logger.debug('Authentication failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}

export const authMiddleware = (): BaseMiddleware =>
  new AuthenticationMiddleware();
```

---

### 3.2 RequireAuthMiddleware

**Purpose:** Enforces that a user is authenticated, returning 401 if not.

**File:** `src/middlewares/auth.middleware.ts`

**Factory Function:** `requireAuth()`

**Full Implementation:**

```typescript
/**
 * Middleware that requires authentication (401 if not authenticated)
 */
export class RequireAuthMiddleware implements BaseMiddleware {
  async before(context: Context): Promise<void> {
    if (!context.user) {
      context.res.status(401).json({
        success: false,
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED',
        },
      });
      throw new Error('RESPONSE_SENT');
    }
  }
}

export const requireAuth = (): BaseMiddleware => new RequireAuthMiddleware();
```

---

### 3.3 RequirePermissionMiddleware

**Purpose:** Enforces that the authenticated user has a specific permission, returning 403 if not.

**File:** `src/middlewares/auth.middleware.ts`

**Factory Function:** `requirePermission(permission: string)`

**Full Implementation:**

```typescript
import { hasPermission } from '../types/auth.types.js';

/**
 * Middleware that requires specific permission (403 if not authorized)
 */
export class RequirePermissionMiddleware implements BaseMiddleware {
  constructor(private readonly permission: string) {}

  async before(context: Context): Promise<void> {
    const user = context.user as AuthenticatedUser | undefined;

    if (!user) {
      context.res.status(401).json({
        success: false,
        error: {
          message: 'Authentication required',
          code: 'UNAUTHORIZED',
        },
      });
      throw new Error('RESPONSE_SENT');
    }

    if (!hasPermission(user, this.permission)) {
      context.res.status(403).json({
        success: false,
        error: {
          message: 'Insufficient permissions',
          code: 'FORBIDDEN',
        },
      });
      throw new Error('RESPONSE_SENT');
    }
  }
}

export const requirePermission = (permission: string): BaseMiddleware =>
  new RequirePermissionMiddleware(permission);
```

---

### 3.4 BodyValidationMiddleware\<T\>

**Purpose:** Validates request body against a Zod schema and populates `context.req.parsedBody`.

**File:** `src/middlewares/validation.middleware.ts`

**Factory Function:** `bodyValidator<T>(schema)`

**Full Implementation:**

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';
import { ZodError, ZodTypeAny } from 'zod';

/**
 * Custom body validation middleware using local Zod version
 * This middleware validates request body against a Zod schema
 * and populates context.req.parsedBody with the validated data
 */
export class BodyValidationMiddleware<T> implements BaseMiddleware<T> {
  constructor(private readonly schema: ZodTypeAny) {}

  async before(context: Context<T>): Promise<void> {
    const body = context.req.body;

    const parseResult = this.schema.safeParse(body);

    if (!parseResult.success) {
      const zodError = parseResult.error as ZodError;
      context.res.status(400).json({
        success: false,
        error: {
          message: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: zodError.errors,
        },
      });
      throw new Error('RESPONSE_SENT');
    }

    // Set the validated body
    (context.req as { parsedBody?: T }).parsedBody = parseResult.data as T;
  }
}

export function bodyValidator<T>(schema: ZodTypeAny): BaseMiddleware<T> {
  return new BodyValidationMiddleware<T>(schema);
}
```

---

## 4. Handler Patterns

### 4.1 Public Endpoint (No Auth)

**When to use:** Login, registration, password reset, public APIs.

**Pattern:**

```typescript
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);
```

**Complete Example:**

```typescript
// src/handlers/auth.handlers.ts

/**
 * Login handler - POST /api/auth/login
 * Public endpoint - no authentication required
 */
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);

/**
 * Refresh token handler - POST /api/auth/refresh
 * Public endpoint - uses refresh token instead of access token
 */
export const refreshTokenHandler = new Handler<RefreshTokenRequest>()
  .use(errorHandler())
  .use(bodyValidator<RefreshTokenRequest>(refreshTokenRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(refreshTokenController);
```

---

### 4.2 Protected Endpoint (Auth Required)

**When to use:** User-specific actions that require authentication but no specific permissions.

**Pattern:**

```typescript
export const handler = new Handler<RequestType>()
  .use(errorHandler())
  .use(authMiddleware()) // Extract user from token
  .use(requireAuth()) // Enforce authentication
  .use(bodyValidator<RequestType>(schema))
  .use(new ResponseWrapperMiddleware())
  .handle(controller);
```

**Complete Example:**

```typescript
// src/handlers/auth.handlers.ts

/**
 * Logout handler - POST /api/auth/logout
 * Protected endpoint - requires authentication
 */
export const logoutHandler = new Handler<LogoutRequest>()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requireAuth())
  .use(bodyValidator<LogoutRequest>(logoutRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(logoutController);
```

---

### 4.3 Protected with Permissions

**When to use:** Actions that require specific permissions (RBAC).

**Pattern:**

```typescript
export const handler = new Handler()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('resource:action')) // Check specific permission
  .use(new ResponseWrapperMiddleware())
  .handle(controller);
```

**Complete Example:**

```typescript
// src/handlers/config.handlers.ts

/**
 * Get config handler - GET /api/config
 * Protected endpoint - requires config:read permission
 */
export const getConfigHandler = new Handler()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('config:read'))
  .use(new ResponseWrapperMiddleware())
  .handle(getConfigController);

/**
 * Replace config handler - PUT /api/config
 * Protected endpoint - requires config:write permission
 */
export const replaceConfigHandler = new Handler<ReplaceConfigRequest>()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('config:write'))
  .use(bodyValidator<ReplaceConfigRequest>(replaceConfigRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(replaceConfigController);
```

---

### 4.4 Protected with Body Validation

**When to use:** POST/PUT/PATCH endpoints that require both authentication and request body validation.

**Pattern:**

```typescript
export const handler = new Handler<RequestType>()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('resource:write'))
  .use(bodyValidator<RequestType>(schema)) // Validate request body
  .use(new ResponseWrapperMiddleware())
  .handle(controller);
```

**Complete Example:**

```typescript
// src/handlers/config.handlers.ts

/**
 * Create section handler - POST /api/config/sections
 * Protected endpoint - requires sections:write permission
 */
export const createSectionHandler = new Handler<CreateSectionRequest>()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('sections:write'))
  .use(bodyValidator<CreateSectionRequest>(createSectionRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(createSectionController);

/**
 * Update section handler - PATCH /api/config/sections/:sectionId
 * Protected endpoint - requires sections:write permission
 */
export const updateSectionHandler = new Handler<UpdateSectionRequest>()
  .use(errorHandler())
  .use(authMiddleware())
  .use(requirePermission('sections:write'))
  .use(bodyValidator<UpdateSectionRequest>(updateSectionRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(updateSectionController);
```

---

## 5. Controller Patterns

### 5.1 Accessing Request Data

```typescript
export async function myController(context: Context<MyRequest>): Promise<void> {
  // Validated request body (after bodyValidator middleware)
  const data = context.req.parsedBody as MyRequest;

  // URL path parameters (e.g., /sections/:sectionId)
  const sectionId = context.req.params.sectionId || '';

  // Request headers
  const userAgent = context.req.headers['user-agent'] as string | undefined;
  const customHeader = context.req.headers['x-custom-header'];

  // Query parameters
  const page = context.req.query.page as string | undefined;
  const limit = context.req.query.limit as string | undefined;

  // Client IP address
  const clientIp = context.req.ip;
}
```

---

### 5.2 Accessing User Context

```typescript
import { AuthenticatedUser } from '../types/auth.types.js';

export async function protectedController(context: Context): Promise<void> {
  // Cast to AuthenticatedUser type (after auth middleware)
  const user = context.user as AuthenticatedUser;

  // Access user properties
  const userId = user.id;
  const tenantId = user.tenantId;
  const userEmail = user.email;
  const userRole = user.role;
  const permissions = user.permissions;
}
```

---

### 5.3 Writing Responses

**Success Response (200):**

```typescript
context.res.status(200).json({
  success: true,
  data: result,
});
```

**Created Response (201):**

```typescript
context.res.status(201).json({
  success: true,
  data: createdResource,
});
```

**Error Response (4xx):**

```typescript
context.res.status(404).json({
  success: false,
  error: {
    message: 'Resource not found',
    code: 'NOT_FOUND',
  },
});
```

**Validation Error (400):**

```typescript
context.res.status(400).json({
  success: false,
  error: {
    message: 'Validation failed',
    code: 'VALIDATION_ERROR',
    details: validationErrors,
  },
});
```

---

### 5.4 Complete Controller Examples

**Login Controller (Public Endpoint):**

```typescript
// src/controllers/auth.controllers.ts

import { Context } from '@noony-serverless/core';
import { Logger } from '../services/logger.service.js';
import { AuthService } from '../services/auth.service.js';
import { containerPool } from '../core/container-pool.js';
import { LoginRequest } from '../models/auth/auth.schemas.js';

const logger = new Logger('AuthControllers');

export async function loginController(
  context: Context<LoginRequest>
): Promise<void> {
  const data = context.req.parsedBody as LoginRequest;
  logger.debug('Login request', { email: data.email });

  const authService = containerPool.getByToken<AuthService>('AuthService');

  const result = await authService.login(
    data.email,
    data.password,
    context.req.headers['user-agent'] as string | undefined,
    (context.req.headers['x-forwarded-for'] as string | undefined) ||
      context.req.ip
  );

  if (!result.success) {
    context.res.status(401).json({
      success: false,
      error: {
        message: result.error || 'Authentication failed',
        code: 'AUTH_FAILED',
      },
    });
    return;
  }

  context.res.status(200).json({
    success: true,
    data: result.data,
  });
}
```

**Create Section Controller (Protected + Body Validation):**

```typescript
// src/controllers/config.controllers.ts

import { Context } from '@noony-serverless/core';
import { Logger } from '../services/logger.service.js';
import { ConfigRepository } from '../repositories/config.repository.js';
import { containerPool } from '../core/container-pool.js';
import { CreateSectionRequest } from '../models/config/section.schemas.js';
import { AuthenticatedUser } from '../types/auth.types.js';

const logger = new Logger('ConfigControllers');

export async function createSectionController(
  context: Context<CreateSectionRequest>
): Promise<void> {
  const user = context.user as AuthenticatedUser;
  const data = context.req.parsedBody as CreateSectionRequest;
  logger.debug('Create section request', {
    tenantId: user.tenantId,
    type: data.type,
  });

  const configRepository =
    containerPool.getByToken<ConfigRepository>('ConfigRepository');

  const section = await configRepository.createSection(
    user.tenantId,
    data,
    user.id
  );

  if (!section) {
    context.res.status(404).json({
      success: false,
      error: {
        message: 'Configuration not found. Please initialize config first.',
        code: 'NOT_FOUND',
      },
    });
    return;
  }

  context.res.status(201).json({
    success: true,
    data: section,
  });
}
```

---

## 6. Dependency Injection (ContainerPool)

### 6.1 ContainerPool Class

**Purpose:** Singleton wrapper around TypeDI Container optimized for serverless cold/warm starts.

**File:** `src/core/container-pool.ts`

**Full Implementation:**

```typescript
import 'reflect-metadata';
import { Container } from 'typedi';
import { Logger } from '../services/logger.service.js';

type ServiceConstructor<T> = new (...args: unknown[]) => T;

/**
 * ContainerPool for serverless cold-start optimization
 * Manages service instances with pre-warming capabilities
 */
export class ContainerPool {
  private static instance: ContainerPool;
  private initialized = false;
  private readonly logger = new Logger('ContainerPool');
  private readonly registeredTokens = new Set<string>();

  private constructor() {
    // Private constructor for singleton
  }

  static getInstance(): ContainerPool {
    if (!ContainerPool.instance) {
      ContainerPool.instance = new ContainerPool();
    }
    return ContainerPool.instance;
  }

  /**
   * Register multiple service classes for pre-warming
   */
  register<T>(services: Array<ServiceConstructor<T>>): void {
    for (const ServiceClass of services) {
      try {
        Container.get(ServiceClass);
        this.logger.debug(`Service registered: ${ServiceClass.name}`);
      } catch (error) {
        this.logger.warn(`Failed to register service: ${ServiceClass.name}`, {
          error: (error as Error).message,
        });
      }
    }
  }

  /**
   * Register a service instance by token (string key)
   */
  registerInstance<T>(token: string, instance: T): void {
    Container.set(token, instance);
    this.registeredTokens.add(token);
    this.logger.debug(`Instance registered with token: ${token}`);
  }

  /**
   * Get a service by class
   */
  get<T>(serviceClass: ServiceConstructor<T>): T {
    return Container.get(serviceClass);
  }

  /**
   * Get a service by token (string key)
   */
  getByToken<T>(token: string): T {
    return Container.get(token) as T;
  }

  /**
   * Check if a token is registered
   */
  hasToken(token: string): boolean {
    return this.registeredTokens.has(token);
  }

  /**
   * Remove a service instance
   */
  remove(token: string): void {
    Container.remove(token);
    this.registeredTokens.delete(token);
  }

  /**
   * Reset all services
   */
  reset(): void {
    Container.reset();
    this.registeredTokens.clear();
    this.initialized = false;
    this.logger.info('ContainerPool reset');
  }

  /**
   * Mark container as initialized
   */
  setInitialized(): void {
    this.initialized = true;
    this.logger.info('ContainerPool initialized');
  }

  /**
   * Check if container is initialized
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  /**
   * Get the underlying TypeDI container for advanced usage
   */
  getContainer(): typeof Container {
    return Container;
  }
}

// Export singleton instance
export const containerPool = ContainerPool.getInstance();
```

---

### 6.2 Service Registration

**File:** `src/config/service-initialization.config.ts`

**Full Implementation:**

```typescript
import { Db } from 'mongodb';
import { Container } from 'typedi';
import { Logger } from '../services/logger.service.js';
import { UserRepository } from '../repositories/user.repository.js';
import { RefreshTokenRepository } from '../repositories/refresh-token.repository.js';
import { ConfigRepository } from '../repositories/config.repository.js';
import { AuthService } from '../services/auth.service.js';
import { initializeGuards } from './guard.config.js';
import { getEnvironment } from './environment.config.js';
import { containerPool } from '../core/container-pool.js';

const logger = new Logger('ServiceInitialization');

/**
 * Initialize all repositories and services
 */
export async function initializeServices(db: Db): Promise<void> {
  logger.info('Initializing services');

  const env = getEnvironment();

  // Register database instance
  Container.set(Db, db);
  Container.set('Database', db);

  // Initialize guard system (includes UserRepository)
  const guardEnv = env.nodeEnv === 'test' ? 'development' : env.nodeEnv;
  const guardSystem = await initializeGuards(db, env.jwt.secret, guardEnv);

  logger.info('Guard system initialized', {
    hasTokenValidator: !!guardSystem.tokenValidator,
    hasPermissionSource: !!guardSystem.permissionSource,
    hasUserRepository: !!guardSystem.userRepository,
  });

  // Initialize refresh token repository
  const refreshTokenRepository = new RefreshTokenRepository(db);
  containerPool.registerInstance(
    'RefreshTokenRepository',
    refreshTokenRepository
  );

  // Initialize auth service
  const authService = new AuthService(
    guardSystem.userRepository,
    refreshTokenRepository,
    guardSystem.tokenValidator
  );
  containerPool.registerInstance('AuthService', authService);

  // Initialize config repository
  const configRepository = new ConfigRepository(db);
  containerPool.registerInstance('ConfigRepository', configRepository);

  logger.info('All services initialized successfully');
}
```

---

### 6.3 Service Retrieval in Controllers

```typescript
import { containerPool } from '../core/container-pool.js';
import { AuthService } from '../services/auth.service.js';
import { ConfigRepository } from '../repositories/config.repository.js';

export async function myController(context: Context): Promise<void> {
  // Get service by string token
  const authService = containerPool.getByToken<AuthService>('AuthService');
  const configRepository =
    containerPool.getByToken<ConfigRepository>('ConfigRepository');

  // Use services
  const result = await authService.login(email, password);
  const config = await configRepository.getConfig(tenantId);
}
```

---

### 6.4 Initialization Flow

**Cold Start (First Request):**

```typescript
// src/functions.ts

let initialized = false;
let initializationPromise: Promise<void> | null = null;

async function initializeDependencies(): Promise<void> {
  // Skip if already initialized (warm start)
  if (initialized && containerPool.isInitialized()) {
    logger.debug('Reusing initialized dependencies (warm start)');
    return;
  }

  // Prevent parallel initialization (race condition protection)
  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  initializationPromise = (async () => {
    logger.info('Cold start: Initializing Cloud Functions dependencies');

    // Connect to database
    const db = await databaseService.connect();

    // Initialize all services
    await initializeServices(db);

    // Mark container as initialized
    containerPool.setInitialized();
    initialized = true;

    logger.info('Cloud Functions dependencies initialized successfully');
  })();

  await initializationPromise;
}
```

---

## 7. Cloud Functions Integration

### 7.1 initializeDependencies()

**Purpose:** Initializes all application dependencies (database, services, repositories) once per cold start. Uses singleton pattern to optimize warm starts.

**File:** `src/functions.ts`

**Why it's needed:**

- Cloud Functions have "cold starts" (first request) and "warm starts" (subsequent requests)
- Database connections and service initialization should only happen once
- Prevents race conditions when multiple requests arrive simultaneously during cold start

**How it works:**

```
Cold Start (First Request):
┌─────────────────────────────────────────────────────────────┐
│  1. Check if already initialized → NO                       │
│  2. Check if initialization in progress → NO                │
│  3. Start initialization:                                   │
│     a. Connect to MongoDB                                   │
│     b. Initialize all services (initializeServices)         │
│     c. Mark containerPool as initialized                    │
│     d. Set initialized = true                               │
│  4. Return (ready to handle request)                        │
└─────────────────────────────────────────────────────────────┘

Warm Start (Subsequent Requests):
┌─────────────────────────────────────────────────────────────┐
│  1. Check if already initialized → YES                      │
│  2. Return immediately (skip initialization)                │
└─────────────────────────────────────────────────────────────┘

Parallel Requests During Cold Start:
┌─────────────────────────────────────────────────────────────┐
│  Request 1: Starts initialization, sets initializationPromise│
│  Request 2: Sees initializationPromise exists, awaits it    │
│  Request 3: Sees initializationPromise exists, awaits it    │
│  → All requests wait for single initialization to complete  │
└─────────────────────────────────────────────────────────────┘
```

**Full Implementation:**

```typescript
// Initialization state (singleton pattern for warm starts)
let initialized = false;
let initializationPromise: Promise<void> | null = null;

/**
 * Initialize dependencies (called once per cold start)
 * Uses singleton pattern to prevent re-initialization on warm starts
 */
async function initializeDependencies(): Promise<void> {
  // Skip if already initialized (warm start)
  if (initialized && containerPool.isInitialized()) {
    logger.debug('Reusing initialized dependencies (warm start)');
    return;
  }

  // Prevent parallel initialization (race condition protection)
  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  initializationPromise = (async () => {
    const startTime = Date.now();

    try {
      logger.info('Cold start: Initializing Cloud Functions dependencies');

      // Connect to database
      const db = await databaseService.connect();
      logger.info('Database connected');

      // Initialize all services (repositories, guards, etc.)
      await initializeServices(db);
      logger.info('Services initialized');

      // Mark container as initialized
      containerPool.setInitialized();
      initialized = true;

      const duration = Date.now() - startTime;
      logger.info('Cloud Functions dependencies initialized successfully', {
        coldStartMs: duration,
      });
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Failed to initialize dependencies', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
        duration,
      });
      throw error;
    }
  })();

  await initializationPromise;
}
```

**Key Features:**

- **Singleton pattern**: `initialized` flag ensures initialization happens only once
- **Race condition protection**: `initializationPromise` prevents parallel initializations
- **Performance logging**: Tracks cold start duration for monitoring
- **Error propagation**: Throws errors so caller can handle failures

---

### 7.2 createHttpFunction()

**Purpose:** Wraps a Noony handler into a Google Cloud Functions `HttpFunction` for production deployment.

**File:** `src/functions.ts`

**When to use:** When deploying individual functions to Google Cloud Functions.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `noonyHandler` | `Handler<unknown>` | The Noony handler to wrap |
| `functionName` | `string` | Name for error logging |

**Returns:** `HttpFunction` - A function compatible with `@google-cloud/functions-framework`

**Full Implementation:**

```typescript
import { http, HttpFunction } from '@google-cloud/functions-framework';
import { Handler } from '@noony-serverless/core';

/**
 * Create an HttpFunction wrapper for a Noony handler
 * This pattern ensures:
 * - Dependencies are initialized before handler execution
 * - Errors are caught and returned as proper HTTP responses
 * - Response is not sent twice (headersSent check)
 */
function createHttpFunction(
  noonyHandler: Handler<unknown>,
  functionName: string
): HttpFunction {
  return async (req, res) => {
    try {
      // Ensure dependencies are initialized
      await initializeDependencies();

      // Execute Noony handler (runs middleware chain + controller)
      await noonyHandler.execute(req, res);
    } catch (error) {
      // Only handle errors if they're real errors (not RESPONSE_SENT markers)
      if (error instanceof Error && error.message === 'RESPONSE_SENT') {
        return;
      }

      logger.error(`${functionName} function error`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      // Graceful error handling - only send if headers not already sent
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred',
          },
        });
      }
    }
  };
}
```

**Usage - Creating and Registering Functions:**

```typescript
// 1. Create HttpFunction from Noony handler
const loginFunction: HttpFunction = createHttpFunction(loginHandler, 'login');
const logoutFunction: HttpFunction = createHttpFunction(
  logoutHandler,
  'logout'
);
const getConfigFunction: HttpFunction = createHttpFunction(
  getConfigHandler,
  'getConfig'
);

// 2. Register with Cloud Functions Framework
http('login', loginFunction);
http('logout', logoutFunction);
http('getConfig', getConfigFunction);

// 3. Export for deployment
export const login = loginFunction;
export const logout = logoutFunction;
export const getConfig = getConfigFunction;
```

**Execution Flow:**

```
HTTP Request → createHttpFunction wrapper
                    │
                    ▼
            initializeDependencies()
                    │
                    ▼
            noonyHandler.execute(req, res)
                    │
                    ├─── Middleware: errorHandler()
                    │
                    ├─── Middleware: authMiddleware()
                    │
                    ├─── Middleware: requirePermission()
                    │
                    ├─── Middleware: bodyValidator()
                    │
                    ├─── Middleware: ResponseWrapperMiddleware
                    │
                    └─── Controller function
                              │
                              ▼
                    context.res.json({...})
                              │
                              ▼
                      HTTP Response
```

**Error Handling:**

- `RESPONSE_SENT` errors are ignored (response already sent by middleware)
- Real errors return 500 with generic message
- `res.headersSent` check prevents double responses

---

### 7.3 wrapNoonyHandler()

**Purpose:** Wraps a Noony handler for use with Express routing in local development.

**File:** `src/functions.ts`

**When to use:** When running all endpoints through a single Express app for local development.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `noonyHandler` | `Handler<unknown>` | The Noony handler to wrap |
| `functionName` | `string` | Name for error logging |

**Returns:** Express route handler `(req: Request, res: Response) => Promise<void>`

**Full Implementation:**

```typescript
import express, { Express, Request, Response } from 'express';

/**
 * Wrap a Noony handler for use with Express
 */
function wrapNoonyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string
) {
  return async (req: Request, res: Response) => {
    try {
      // Ensure dependencies are initialized
      await initializeDependencies();

      // Execute Noony handler with Express req/res
      await noonyHandler.execute(req, res);
    } catch (error) {
      if (error instanceof Error && error.message === 'RESPONSE_SENT') {
        return;
      }

      logger.error(`${functionName} handler error`, {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          error: {
            code: 'INTERNAL_SERVER_ERROR',
            message: 'An unexpected error occurred',
          },
        });
      }
    }
  };
}
```

**Usage - Express App with All Routes:**

```typescript
function createExpressApp(): Express {
  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json());

  // Health check (no DB required)
  app.get('/health', (_req, res) => {
    res.json({ success: true, data: { status: 'healthy' } });
  });

  // Auth routes
  app.post('/api/auth/login', wrapNoonyHandler(loginHandler, 'login'));
  app.post('/api/auth/logout', wrapNoonyHandler(logoutHandler, 'logout'));
  app.post(
    '/api/auth/refresh',
    wrapNoonyHandler(refreshTokenHandler, 'refresh')
  );
  app.post(
    '/api/auth/forgot-password',
    wrapNoonyHandler(forgotPasswordHandler, 'forgotPassword')
  );
  app.post(
    '/api/auth/reset-password',
    wrapNoonyHandler(resetPasswordHandler, 'resetPassword')
  );

  // Config routes
  app.get('/api/config', wrapNoonyHandler(getConfigHandler, 'getConfig'));
  app.put(
    '/api/config',
    wrapNoonyHandler(replaceConfigHandler, 'replaceConfig')
  );
  app.patch(
    '/api/config/company',
    wrapNoonyHandler(updateCompanyHandler, 'updateCompany')
  );

  // Section routes
  app.get(
    '/api/config/sections',
    wrapNoonyHandler(getSectionsHandler, 'getSections')
  );
  app.post(
    '/api/config/sections',
    wrapNoonyHandler(createSectionHandler, 'createSection')
  );
  app.patch(
    '/api/config/sections/:sectionId',
    wrapNoonyHandler(updateSectionHandler, 'updateSection')
  );
  app.delete(
    '/api/config/sections/:sectionId',
    wrapNoonyHandler(deleteSectionHandler, 'deleteSection')
  );

  // 404 handler
  app.use((_req, res) => {
    res.status(404).json({
      success: false,
      error: { code: 'NOT_FOUND', message: 'Endpoint not found' },
    });
  });

  return app;
}
```

**Difference from createHttpFunction:**

| Aspect           | createHttpFunction        | wrapNoonyHandler       |
| ---------------- | ------------------------- | ---------------------- |
| **Use case**     | Production deployment     | Local development      |
| **Framework**    | Cloud Functions Framework | Express                |
| **Return type**  | `HttpFunction`            | Express handler        |
| **Registration** | `http('name', fn)`        | `app.get('/path', fn)` |
| **Deployment**   | Individual functions      | Single Express app     |

---

### 7.4 Handler.execute()

**Purpose:** Executes the complete Noony middleware chain with the provided request/response objects.

**How it works:**

```typescript
// Handler.execute() runs:
// 1. All middleware .before() methods in order (first to last)
// 2. The controller function (.handle())
// 3. All middleware .after() methods in reverse order (last to first)
// 4. Any .onError() methods if errors occur (reverse order)

await noonyHandler.execute(req, res);
```

**Middleware Execution Order:**

```
Request arrives
      │
      ▼
┌─────────────────────────────────────────┐
│  errorHandler.before()                  │ ← 1st
├─────────────────────────────────────────┤
│  authMiddleware.before()                │ ← 2nd
├─────────────────────────────────────────┤
│  requirePermission.before()             │ ← 3rd
├─────────────────────────────────────────┤
│  bodyValidator.before()                 │ ← 4th
├─────────────────────────────────────────┤
│  ResponseWrapperMiddleware.before()     │ ← 5th
├─────────────────────────────────────────┤
│  Controller function executes           │ ← 6th
├─────────────────────────────────────────┤
│  ResponseWrapperMiddleware.after()      │ ← 7th (reverse)
├─────────────────────────────────────────┤
│  bodyValidator.after()                  │ ← 8th
├─────────────────────────────────────────┤
│  requirePermission.after()              │ ← 9th
├─────────────────────────────────────────┤
│  authMiddleware.after()                 │ ← 10th
├─────────────────────────────────────────┤
│  errorHandler.after()                   │ ← 11th
└─────────────────────────────────────────┘
      │
      ▼
Response sent
```

**Compatibility:**

- Works with Cloud Functions `req`/`res` objects
- Works with Express `req`/`res` objects
- Works with any HTTP framework that provides similar request/response interfaces

---

## 8. Fastify Integration

### 8.1 Overview

Noony Framework provides first-class support for **Fastify** - a high-performance HTTP framework ideal for local development and testing. The Fastify integration uses adapter functions to convert between Fastify's request/response objects and Noony's framework-agnostic `GenericRequest`/`GenericResponse` interfaces.

**Why Use Fastify?**

- **High Performance**: One of the fastest Node.js HTTP frameworks
- **Fast Local Development**: Instant restarts and low overhead
- **Same Handler Code**: Write once, deploy to Cloud Functions without changes
- **Type Safety**: Full TypeScript support throughout the stack

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│ Local Development (Fastify)   │  Production (Cloud Functions) │
├─────────────────────────────────────────────────────────────┤
│ FastifyRequest                 │  Cloud Functions Request     │
│        │                       │           │                  │
│        ▼                       │           ▼                  │
│ adaptFastifyRequest()          │  adaptGCPRequest()           │
│        │                       │           │                  │
│        ▼                       │           ▼                  │
│ GenericRequest ──────────────────────────────────────────────┤
│        │                                   │                  │
│        ▼                                   ▼                  │
│ ┌─────────────────────────────────────────────────┐          │
│ │        Noony Handler (Same Code!)               │          │
│ │  .use(ErrorHandlerMiddleware)                   │          │
│ │  .use(BodyValidationMiddleware)                 │          │
│ │  .use(AuthenticationMiddleware)                 │          │
│ │  .handle(controller)                            │          │
│ └─────────────────────────────────────────────────┘          │
│        │                                   │                  │
│        ▼                                   ▼                  │
│ GenericResponse ──────────────────────────────────────────────┤
│        │                       │           │                  │
│        ▼                       │           ▼                  │
│ adaptFastifyResponse()         │  adaptGCPResponse()          │
│        │                       │           │                  │
│        ▼                       │           ▼                  │
│ FastifyReply                   │  Cloud Functions Response    │
└─────────────────────────────────────────────────────────────┘
```

---

### 8.2 adaptFastifyRequest()

**Purpose:** Converts Fastify's `FastifyRequest` to Noony's `GenericRequest<T>` format.

**Import:**

```typescript
import { adaptFastifyRequest } from '@noony-serverless/core';
// Note: This is typically not called directly - use createFastifyHandler() instead
```

**Function Signature:**

```typescript
function adaptFastifyRequest<T = unknown>(
  req: FastifyRequest
): GenericRequest<T>
```

**What it does:**

1. **Extracts request properties** from Fastify format
2. **Normalizes headers, query, params** to standard format
3. **Stores original request** in WeakMap for middleware access
4. **Zero-copy path extraction** for optimal performance

**Returned GenericRequest structure:**

```typescript
{
  method: string;              // HTTP method (GET, POST, etc.)
  url: string;                 // Full URL path
  path: string;                // Route path (e.g., '/api/users/:userId')
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, string | string[] | undefined>;
  params: Record<string, string>;  // Path parameters
  body: unknown;               // Raw body
  parsedBody: T;               // Typed parsed body
  ip?: string;                 // Client IP address
  userAgent?: string;          // User-Agent header value
}
```

**Performance Optimizations:**

- Pre-allocated empty objects for queries/params to avoid allocations
- WeakMap storage prevents memory leaks
- Inline path extraction avoids optional chaining overhead

**Note:** You typically don't call this function directly - it's used internally by `createFastifyHandler()`.

---

### 8.3 adaptFastifyResponse()

**Purpose:** Converts Fastify's `FastifyReply` to Noony's `GenericResponse` format.

**Import:**

```typescript
import { adaptFastifyResponse } from '@noony-serverless/core';
// Note: This is typically not called directly - use createFastifyHandler() instead
```

**Function Signature:**

```typescript
function adaptFastifyResponse(reply: FastifyReply): GenericResponse
```

**Returned GenericResponse methods:**

```typescript
{
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

**Safety Features:**

- **Duplicate send prevention**: Early return if `reply.sent` is true
- **Header tracking**: Monitors whether headers have been sent
- **Chainable API**: All methods return `GenericResponse` for fluent usage

**Note:** You typically don't call this function directly - it's used internally by `createFastifyHandler()`.

---

### 8.4 createFastifyHandler()

**Purpose:** Creates a Fastify route handler from a Noony handler. This is the **primary function** you'll use for Fastify integration.

**Import:**

```typescript
import { createFastifyHandler } from '@noony-serverless/core';
```

**Function Signature:**

```typescript
function createFastifyHandler(
  noonyHandler: Handler<unknown>,
  functionName: string,
  initializeDependencies: () => Promise<void>
): (req: FastifyRequest, reply: FastifyReply) => Promise<void>
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `noonyHandler` | `Handler<unknown>` | The Noony handler (with middleware chain and controller) |
| `functionName` | `string` | Name for error logging and debugging |
| `initializeDependencies` | `() => Promise<void>` | Async function that initializes dependencies (DB, services). Uses singleton pattern to prevent re-initialization. |

**Returns:** Fastify route handler function `(req, reply) => Promise<void>`

**What it does:**

1. **Ensures dependencies are initialized** before handler execution (singleton pattern)
2. **Adapts request/response** using `adaptFastifyRequest()` and `adaptFastifyResponse()`
3. **Executes Noony handler** via `noonyHandler.executeGeneric()`
4. **Handles errors gracefully**:
   - Ignores `RESPONSE_SENT` errors (response already sent by middleware)
   - Returns 500 for real errors with generic message for security
   - Checks `reply.sent` to prevent double responses
5. **Logs execution** with request ID for debugging

---

### 8.5 Complete Fastify Integration Example

**File:** `src/server.ts` (Fastify local development server)

```typescript
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { databaseService } from './services/database.service';
import { initializeServices } from './services/init.service';
import { containerPool } from '@noony-serverless/core';
import { logger } from '@noony-serverless/core';

// Import your Noony handlers
import { loginHandler } from './handlers/auth.handlers';
import { logoutHandler } from './handlers/auth.handlers';
import { getUserHandler } from './handlers/user.handlers';
import { updateUserHandler } from './handlers/user.handlers';
import { getConfigHandler } from './handlers/config.handlers';

// ============================================================================
// DEPENDENCY INITIALIZATION (Singleton Pattern)
// ============================================================================

let initialized = false;
let initializationPromise: Promise<void> | null = null;

/**
 * Initialize dependencies once per server startup
 * Uses singleton pattern to prevent re-initialization across requests
 */
async function initializeDependencies(): Promise<void> {
  // Skip if already initialized
  if (initialized && containerPool.isInitialized()) {
    logger.debug('[Fastify] Reusing initialized dependencies');
    return;
  }

  // Prevent parallel initialization
  if (initializationPromise) {
    await initializationPromise;
    return;
  }

  initializationPromise = (async () => {
    const startTime = Date.now();

    try {
      logger.info('[Fastify] Initializing dependencies');

      // Connect to database
      const db = await databaseService.connect();
      logger.info('[Fastify] Database connected');

      // Initialize all services (repositories, guards, etc.)
      await initializeServices(db);
      logger.info('[Fastify] Services initialized');

      // Mark container as initialized
      containerPool.setInitialized();
      initialized = true;

      const duration = Date.now() - startTime;
      logger.info('[Fastify] Dependencies initialized successfully', {
        durationMs: duration,
      });
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('[Fastify] Failed to initialize dependencies', {
        error: error instanceof Error ? error.message : 'Unknown error',
        durationMs: duration,
      });
      throw error;
    } finally {
      initializationPromise = null;
    }
  })();

  await initializationPromise;
}

// ============================================================================
// FASTIFY SERVER SETUP
// ============================================================================

const server = Fastify({
  logger: true,
  requestIdLogLabel: 'requestId',
  disableRequestLogging: process.env.NODE_ENV === 'production',
});

// ============================================================================
// HELPER: Adapter Shorthand
// ============================================================================

/**
 * Shorthand for creating Fastify handlers from Noony handlers
 * Usage: adapt(loginHandler, 'login')
 */
const adapt = (handler: Handler<unknown>, name: string) =>
  createFastifyHandler(handler, name, initializeDependencies);

// ============================================================================
// ROUTE REGISTRATION
// ============================================================================

// Auth routes
server.post('/api/auth/login', adapt(loginHandler, 'login'));
server.post('/api/auth/logout', adapt(logoutHandler, 'logout'));

// User routes
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));
server.patch('/api/users/:userId', adapt(updateUserHandler, 'updateUser'));

// Config routes
server.get('/api/config', adapt(getConfigHandler, 'getConfig'));

// Health check (no Noony handler needed)
server.get('/health', async (request, reply) => {
  reply.send({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

server.listen({ port: PORT, host: HOST }, (err, address) => {
  if (err) {
    logger.error('[Fastify] Server failed to start', { error: err.message });
    process.exit(1);
  }
  logger.info(`[Fastify] Server listening at ${address}`);
});

// Graceful shutdown
const gracefulShutdown = async () => {
  logger.info('[Fastify] Shutting down gracefully...');
  await server.close();
  await databaseService.disconnect();
  logger.info('[Fastify] Shutdown complete');
  process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
```

---

### 8.6 Type-Safe Fastify Integration

**Noony handlers maintain full type safety through Fastify integration:**

```typescript
import { z } from 'zod';
import { Handler, Context, createFastifyHandler } from '@noony-serverless/core';

// 1. Define request schema and type
const createUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
  role: z.enum(['user', 'admin']).default('user'),
});

type CreateUserRequest = z.infer<typeof createUserSchema>;

// 2. Define authenticated user type
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

// 3. Create type-safe Noony handler
const createUserHandler = new Handler<CreateUserRequest, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<CreateUserRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware<CreateUserRequest, AuthenticatedUser>(tokenVerifier))
  .use(new BodyValidationMiddleware<CreateUserRequest, AuthenticatedUser>(createUserSchema))
  .use(new ResponseWrapperMiddleware<CreateUserRequest, AuthenticatedUser>())
  .handle(async (context: Context<CreateUserRequest, AuthenticatedUser>) => {
    // ✅ Full type safety!
    const { name, email, role } = context.req.validatedBody!;  // Type: CreateUserRequest
    const currentUser = context.user!;  // Type: AuthenticatedUser

    // Business logic with complete type checking
    const newUser = await userService.create({ name, email, role });
    return { userId: newUser.id };
  });

// 4. Register with Fastify - full type safety preserved!
server.post('/api/users', adapt(createUserHandler, 'createUser'));
```

**Type Flow:**

```
Fastify Request
    ↓ adaptFastifyRequest<CreateUserRequest>()
GenericRequest<CreateUserRequest>
    ↓ Handler.executeGeneric()
Context<CreateUserRequest, AuthenticatedUser>
    ↓ controller function
✅ Full TypeScript type checking and autocomplete
```

---

### 8.7 Path Parameters with Fastify

**Fastify path parameters are automatically available in `context.req.params`:**

```typescript
// Define handler for user endpoint
const getUserHandler = new Handler<void, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<void, AuthenticatedUser>())
  .use(new AuthenticationMiddleware<void, AuthenticatedUser>(tokenVerifier))
  .use(new ResponseWrapperMiddleware<void, AuthenticatedUser>())
  .handle(async (context: Context<void, AuthenticatedUser>) => {
    // Access path parameters from context.req.params
    const userId = context.req.params.userId;  // Type: string

    const user = await userService.getById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }

    return { user };
  });

// Register with Fastify path parameter syntax
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));

// Also works with multiple path parameters
server.get(
  '/api/sections/:sectionId/items/:itemId',
  adapt(getItemHandler, 'getItem')
);

// Access in controller:
// const sectionId = context.req.params.sectionId;
// const itemId = context.req.params.itemId;
```

---

### 8.8 Local Development vs Production

**Same handler code works in both environments:**

```typescript
// ============================================================================
// HANDLER DEFINITION (Write once, use everywhere!)
// ============================================================================

const loginHandler = new Handler<LoginRequest, void>()
  .use(new ErrorHandlerMiddleware<LoginRequest, void>())
  .use(new BodyValidationMiddleware<LoginRequest, void>(loginSchema))
  .use(new ResponseWrapperMiddleware<LoginRequest, void>())
  .handle(async (context: Context<LoginRequest, void>) => {
    // Same business logic in local dev and production!
    const { email, password } = context.req.validatedBody!;
    const token = await authService.login(email, password);
    return { token };
  });

// ============================================================================
// LOCAL DEVELOPMENT (Fastify)
// ============================================================================

// File: src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';

const server = Fastify();
const adapt = (handler, name) =>
  createFastifyHandler(handler, name, initializeDependencies);

server.post('/api/auth/login', adapt(loginHandler, 'login'));

server.listen({ port: 3000 }, () => {
  console.log('Local server running on http://localhost:3000');
});

// ============================================================================
// PRODUCTION (Cloud Functions)
// ============================================================================

// File: src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { createHttpFunction } from '@noony-serverless/core';

const loginFunction = createHttpFunction(loginHandler, 'login', initializeDependencies);
http('login', loginFunction);
export const login = loginFunction;
```

**Development Workflow:**

```bash
# 1. Local development with Fastify (instant restarts)
npm run dev
# Server running on http://localhost:3000
# Test: curl -X POST http://localhost:3000/api/auth/login -d '{"email":"...","password":"..."}'

# 2. Deploy to Cloud Functions (same handler code!)
npm run deploy
# Function deployed: https://region-project.cloudfunctions.net/login
```

---

### 8.9 Error Handling in Fastify Integration

**Error handling works identically in Fastify and Cloud Functions:**

```typescript
const createOrderHandler = new Handler<CreateOrderRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<CreateOrderRequest, AuthUser>())  // ← Catches all errors
  .use(new AuthenticationMiddleware<CreateOrderRequest, AuthUser>(tokenVerifier))
  .use(new BodyValidationMiddleware<CreateOrderRequest, AuthUser>(orderSchema))
  .use(new ResponseWrapperMiddleware<CreateOrderRequest, AuthUser>())
  .handle(async (context: Context<CreateOrderRequest, AuthUser>) => {
    // Throw any error - ErrorHandlerMiddleware will format it properly
    if (!inventoryService.hasStock(context.req.validatedBody!.productId)) {
      throw new ConflictError('Product out of stock');  // ← 409 response
    }

    const order = await orderService.create(context.req.validatedBody!);
    return { orderId: order.id };
  });

// Fastify adapter automatically handles errors:
// - RESPONSE_SENT errors → ignored (response already sent)
// - HTTP errors (ValidationError, ConflictError, etc.) → formatted by ErrorHandlerMiddleware
// - Unexpected errors → 500 with generic message for security
server.post('/api/orders', adapt(createOrderHandler, 'createOrder'));
```

**Error Response Format (Consistent across Fastify and Cloud Functions):**

```json
{
  "success": false,
  "payload": {
    "error": "Product out of stock",
    "code": "CONFLICT"
  },
  "timestamp": "2024-01-15T10:30:45.125Z"
}
```

---

### 8.10 Performance Optimizations

**The Fastify integration includes several performance optimizations:**

1. **Pre-allocated Empty Objects**: Avoids allocations for empty query/params
2. **WeakMap for Request Storage**: Zero memory leak risk
3. **Inline Path Extraction**: Avoids optional chaining overhead
4. **Pre-allocated Error Response**: Reduces allocations in error path
5. **Fast Path Error Checking**: `RESPONSE_SENT` checked first (most common)
6. **Singleton Dependency Initialization**: Prevents redundant DB connections

**Benchmark Results:**

```
Fastify + Noony Handler:  ~30,000 req/s (local development)
Express + Noony Handler:  ~15,000 req/s (Cloud Functions)
Performance gain:         ~2x faster for local testing
```

---

### 8.11 Best Practices

**✅ DO:**

- Use `createFastifyHandler()` for all Fastify routes
- Implement singleton pattern for `initializeDependencies()`
- Use same handler code for local dev and production
- Create a helper shorthand: `const adapt = (handler, name) => createFastifyHandler(handler, name, initDeps)`
- Add health check endpoint without Noony handler
- Test locally with Fastify before deploying to Cloud Functions

**❌ DON'T:**

- Call `adaptFastifyRequest()` or `adaptFastifyResponse()` directly (use `createFastifyHandler()`)
- Re-initialize dependencies on every request (use singleton pattern)
- Create different handler implementations for Fastify vs Cloud Functions
- Forget to handle graceful shutdown (SIGTERM/SIGINT)

---

### 8.12 Troubleshooting

**Issue: "Dependencies not initialized" error**

**Solution:** Ensure `initializeDependencies()` completes before handling requests:

```typescript
let initialized = false;

async function initializeDependencies(): Promise<void> {
  if (initialized) return;  // ← Add this check
  // ... initialization logic
  initialized = true;
}
```

---

**Issue: "Response already sent" errors in logs**

**Solution:** These are normal and ignored by `createFastifyHandler()`. The `RESPONSE_SENT` error indicates a middleware already sent the response, which is expected behavior. The adapter automatically ignores these errors.

---

**Issue: Path parameters not available**

**Solution:** Ensure you're using Fastify parameter syntax and accessing via `context.req.params`:

```typescript
// ✅ Correct
server.get('/api/users/:userId', adapt(getUserHandler, 'getUser'));
// Access: context.req.params.userId

// ❌ Wrong
server.get('/api/users/' + userId, adapt(getUserHandler, 'getUser'));
```

---

**Issue: Type errors with `createFastifyHandler()`**

**Solution:** Ensure your handler uses proper generics:

```typescript
// ✅ Correct
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware<RequestType, UserType>())
  .handle(async (context: Context<RequestType, UserType>) => { ... });

// Then adapt to Fastify
server.post('/api/endpoint', adapt(handler, 'endpoint'));
```

---

## 9. TypeScript Generics Patterns (NEW in v0.6.0)

### 9.1 Understanding Dual Generics

Noony Framework now supports **dual generics** for complete type safety across your entire request handling pipeline:

- `TBody`: Type of the request body/payload
- `TUser`: Type of the authenticated user

**Benefits:**

- ✅ Full type inference in controllers and middlewares
- ✅ Autocomplete for request body and user properties
- ✅ Compile-time type checking prevents runtime errors
- ✅ Self-documenting code with explicit types

### 9.2 Generic Patterns by Use Case

#### Pattern 1: Public Endpoint (Body Only)

```typescript
import { Handler, Context } from '@noony-serverless/core';
import { z } from 'zod';

// Define request schema
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

type LoginRequest = z.infer<typeof loginSchema>;

// Handler with body type only
export const loginHandler = new Handler<LoginRequest>()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(loginSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<LoginRequest>) => {
    // ✅ Typed access to validated body
    const { email, password } = context.req.validatedBody!;

    // ✅ No user type needed (public endpoint)
    const result = await authService.login(email, password);

    return result;
  });
```

#### Pattern 2: Protected Endpoint (Body + User)

```typescript
import {
  Handler,
  Context,
  BaseAuthenticatedUser,
} from '@noony-serverless/core';
import { z } from 'zod';

// Define authenticated user type
interface AuthenticatedUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'customer' | 'admin';
  permissions: string[];
}

// Define request schema
const createProductSchema = z.object({
  name: z.string().min(1),
  price: z.number().positive(),
  categoryId: z.string().uuid(),
});

type CreateProductRequest = z.infer<typeof createProductSchema>;

// Handler with BOTH body and user types
export const createProductHandler = new Handler<
  CreateProductRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createProductSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateProductRequest, AuthenticatedUser>) => {
    // ✅ Typed access to both body and user
    const { name, price, categoryId } = context.req.validatedBody!;
    const user = context.user!;

    // ✅ Full type safety for user properties
    if (user.role !== 'admin') {
      throw new ForbiddenError('Only admins can create products');
    }

    const product = await productService.create({
      name,
      price,
      categoryId,
      createdBy: user.id,
    });

    return product;
  });
```

#### Pattern 3: GET Endpoint with User (No Body)

```typescript
import { Handler, Context } from '@noony-serverless/core';

interface AuthenticatedUser {
  id: string;
  email: string;
  tenantId: string;
}

// No body type needed (GET request), only user type
export const getUserProfileHandler = new Handler<unknown, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<unknown, AuthenticatedUser>) => {
    // ✅ Typed user access
    const user = context.user!;

    // No body to access (GET request)
    const profile = await userService.getProfile(user.id);

    return profile;
  });
```

#### Pattern 4: Response Type Safety (All Three Generics)

```typescript
import { Handler, ResponseWrapperMiddleware } from '@noony-serverless/core';

// Define response type
interface OrderResponse {
  orderId: string;
  status: 'pending' | 'confirmed';
  total: number;
  estimatedDelivery: Date;
}

interface CreateOrderRequest {
  productIds: string[];
  shippingAddressId: string;
}

interface AuthenticatedUser {
  id: string;
  email: string;
}

// Handler with response, body, and user types
export const createOrderHandler = new Handler<
  CreateOrderRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createOrderSchema))
  .use(
    new ResponseWrapperMiddleware<
      OrderResponse,
      CreateOrderRequest,
      AuthenticatedUser
    >()
  )
  .handle(async (context) => {
    const { productIds, shippingAddressId } = context.req.validatedBody!;
    const user = context.user!;

    const order = await orderService.create({
      userId: user.id,
      productIds,
      shippingAddressId,
    });

    // ✅ Return matches OrderResponse type
    return {
      orderId: order.id,
      status: order.status,
      total: order.total,
      estimatedDelivery: order.estimatedDelivery,
    } as OrderResponse;
  });
```

### 9.3 Type-Safe Custom Middleware

When creating custom middleware, ALWAYS preserve type information:

```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';

// ✅ CORRECT - Preserves type chain
export class CustomLoggingMiddleware<
  TBody = unknown,
  TUser = unknown,
> implements BaseMiddleware<TBody, TUser> {
  async before(context: Context<TBody, TUser>): Promise<void> {
    // Access typed context
    const requestId = context.requestId;
    const userId = context.user?.id;

    console.log(`[${requestId}] Request from user: ${userId}`);
  }
}

// Usage preserves types
const handler = new Handler<CreateOrderRequest, AuthenticatedUser>()
  .use(new CustomLoggingMiddleware<CreateOrderRequest, AuthenticatedUser>())
  .handle(async (context) => {
    // ✅ Full type safety preserved
    const body = context.req.validatedBody; // Type: CreateOrderRequest
    const user = context.user; // Type: AuthenticatedUser
  });
```

### 9.4 Common Type Patterns

#### BaseAuthenticatedUser Extension

```typescript
import { BaseAuthenticatedUser } from '@noony-serverless/core';

// Extend BaseAuthenticatedUser for your app
interface AppUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin' | 'moderator';
  tenantId: string;
  permissions: string[];
  metadata?: {
    firstName?: string;
    lastName?: string;
    avatar?: string;
  };
}
```

#### Zod Schema + Type Inference

```typescript
import { z } from 'zod';

// Define schema
const updateUserSchema = z.object({
  firstName: z.string().min(1).optional(),
  lastName: z.string().min(1).optional(),
  avatar: z.string().url().optional(),
  preferences: z
    .object({
      theme: z.enum(['light', 'dark']),
      language: z.string(),
    })
    .optional(),
});

// Auto-infer TypeScript type
type UpdateUserRequest = z.infer<typeof updateUserSchema>;

// Use in handler
const handler = new Handler<UpdateUserRequest, AppUser>()
  .use(new BodyValidationMiddleware(updateUserSchema))
  .handle(async (context) => {
    // ✅ Both types available
    const updates = context.req.validatedBody!;
    const user = context.user!;
  });
```

### 9.5 Type Safety Best Practices

1. **Always define types explicitly** for request bodies and users
2. **Use Zod schemas** for runtime validation + TypeScript types
3. **Extend BaseAuthenticatedUser** for consistent user type structure
4. **Preserve generics** in custom middleware using `<TBody, TUser>`
5. **Use non-null assertion (`!`)** only after middleware validation
6. **Type response data** using ResponseWrapperMiddleware generics

---

## 10. Best Practices

### 10.1 Middleware Order

**Always follow this order:**

```typescript
// Modern pattern with generics (Recommended)
new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware<RequestType, UserType>()) // 1. ALWAYS FIRST - catches all errors
  .use(new AuthenticationMiddleware(tokenVerifier)) // 2. Extract user from JWT
  .use(requireAuth()) // 3. Enforce authentication (optional)
  .use(requirePermission('resource:action')) // 4. Check permissions (optional)
  .use(new BodyValidationMiddleware(schema)) // 5. Validate request body (optional)
  .use(new ResponseWrapperMiddleware<ResponseType, RequestType, UserType>()) // 6. ALWAYS LAST
  .handle(controller);

// Legacy pattern (still supported)
new Handler<RequestType>()
  .use(errorHandler()) // 1. ALWAYS FIRST
  .use(authMiddleware()) // 2. Extract user
  .use(requireAuth()) // 3. Enforce auth (optional)
  .use(requirePermission('resource:action')) // 4. Check permissions (optional)
  .use(bodyValidator<RequestType>(schema)) // 5. Validate body (optional)
  .use(new ResponseWrapperMiddleware()) // 6. ALWAYS LAST
  .handle(controller);
```

---

### 10.2 Error Handling Pattern

**Modern Pattern: Use Built-in Error Types (Recommended):**

```typescript
import {
  NotFoundError,
  ForbiddenError,
  ConflictError,
  ValidationError,
} from '@noony-serverless/core';

export async function updateUserController(
  context: Context<UpdateUserRequest, AuthenticatedUser>
): Promise<void> {
  const { userId } = context.req.params;
  const user = context.user!;

  // 404 - Resource not found
  const targetUser = await userService.getById(userId);
  if (!targetUser) {
    throw new NotFoundError('User not found'); // → Auto 404 response
  }

  // 403 - Permission denied
  if (user.id !== userId && user.role !== 'admin') {
    throw new ForbiddenError('You cannot update this user'); // → Auto 403 response
  }

  // 409 - Conflict
  if (context.req.validatedBody!.email) {
    const existing = await userService.findByEmail(
      context.req.validatedBody!.email
    );
    if (existing && existing.id !== userId) {
      throw new ConflictError('Email already in use'); // → Auto 409 response
    }
  }

  // Update user logic...
}
```

**Legacy Pattern: `RESPONSE_SENT` Signal:**

```typescript
// In custom middleware
async before(context: Context): Promise<void> {
  if (someConditionFails) {
    context.res.status(401).json({
      success: false,
      error: { message: 'Error message', code: 'ERROR_CODE' },
    });
    throw new Error('RESPONSE_SENT');  // Exit middleware chain
  }
}

// In wrapper functions, catch and ignore RESPONSE_SENT
try {
  await handler.execute(req, res);
} catch (error) {
  if (error instanceof Error && error.message === 'RESPONSE_SENT') {
    return;  // Not an error - response was already sent
  }
  // Handle real errors
}
```

---

### 10.3 Type Safety with Dual Generics

**Always use dual generics for complete type safety:**

```typescript
import {
  Handler,
  Context,
  BaseAuthenticatedUser,
} from '@noony-serverless/core';
import { z } from 'zod';

// 1. Define user type
interface AppUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin';
}

// 2. Define request schema
const updateProfileSchema = z.object({
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  avatar: z.string().url().optional(),
});

type UpdateProfileRequest = z.infer<typeof updateProfileSchema>;

// 3. Handler with both generics
export const updateProfileHandler = new Handler<UpdateProfileRequest, AppUser>()
  .use(new ErrorHandlerMiddleware<UpdateProfileRequest, AppUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(updateProfileSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<UpdateProfileRequest, AppUser>) => {
    // ✅ Full type safety
    const { firstName, lastName, avatar } = context.req.validatedBody!;
    const user = context.user!;

    // Update profile with typed data
    return await userService.updateProfile(user.id, {
      firstName,
      lastName,
      avatar,
    });
  });
```

---

### 10.4 Container Usage

**Token-based registration pattern:**

```typescript
// Registration (at startup)
containerPool.registerInstance('AuthService', authService);
containerPool.registerInstance('ConfigRepository', configRepository);

// Retrieval (in controllers)
const authService = containerPool.getByToken<AuthService>('AuthService');
const configRepository =
  containerPool.getByToken<ConfigRepository>('ConfigRepository');
```

**Registered service tokens in this project:**

| Token                      | Service Type             |
| -------------------------- | ------------------------ |
| `'AuthService'`            | `AuthService`            |
| `'ConfigRepository'`       | `ConfigRepository`       |
| `'RefreshTokenRepository'` | `RefreshTokenRepository` |
| `'TokenValidator'`         | `JWTTokenValidator`      |
| `'PermissionSource'`       | `MongoPermissionSource`  |
| `'UserRepository'`         | `UserRepository`         |
| `'Database'`               | `Db` (MongoDB)           |
