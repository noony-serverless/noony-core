# How to Use Noony Framework in This Project

> Practical guide to all Noony framework components used in this project with complete working examples from the actual source code.

## Table of Contents

1. [Overview](#1-overview)
2. [Core Components](#2-core-components)
3. [Custom Middleware Reference](#3-custom-middleware-reference)
4. [Handler Patterns](#4-handler-patterns)
5. [Controller Patterns](#5-controller-patterns)
6. [Dependency Injection (ContainerPool)](#6-dependency-injection-containerpool)
7. [Cloud Functions Integration](#7-cloud-functions-integration)
8. [Best Practices](#8-best-practices)

---

## 1. Overview

### Package Information

```json
{
  "@noony-serverless/core": "^0.2.2"
}
```

### Files Using Noony Framework

| File | Noony Components Used |
|------|----------------------|
| `src/handlers/auth.handlers.ts` | Handler, errorHandler, ResponseWrapperMiddleware |
| `src/handlers/config.handlers.ts` | Handler, errorHandler, ResponseWrapperMiddleware |
| `src/controllers/auth.controllers.ts` | Context |
| `src/controllers/config.controllers.ts` | Context |
| `src/middlewares/auth.middleware.ts` | BaseMiddleware, Context |
| `src/middlewares/validation.middleware.ts` | BaseMiddleware, Context |
| `src/functions.ts` | Handler |

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

### 2.1 Handler\<T\>

**What it is:** The central orchestrator that builds middleware chains and executes request handling.

**Import:**
```typescript
import { Handler } from '@noony-serverless/core';
```

**Where used:** `src/handlers/auth.handlers.ts`, `src/handlers/config.handlers.ts`

**Why:** Provides a fluent API for chaining middleware and connecting to controller functions.

**How:** Use `.use()` to add middleware and `.handle()` to set the controller.

**Complete Example from Project:**

```typescript
// src/handlers/auth.handlers.ts

import { Handler, errorHandler, ResponseWrapperMiddleware } from '@noony-serverless/core';
import { loginRequestSchema, LoginRequest } from '../models/auth/auth.schemas.js';
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

---

### 2.2 Context\<T\>

**What it is:** The request/response context object that flows through the middleware chain.

**Import:**
```typescript
import { Context } from '@noony-serverless/core';
```

**Where used:** `src/controllers/*.controllers.ts`, `src/middlewares/*.middleware.ts`

**Why:** Provides unified access to request data, response methods, authenticated user, and shared data.

**Properties Reference:**

| Property | Type | Description |
|----------|------|-------------|
| `req` | `GenericRequest<T>` | Request object |
| `req.body` | `unknown` | Raw request body |
| `req.parsedBody` | `T` | Validated request body (set by validation middleware) |
| `req.params` | `Record<string, string>` | URL path parameters |
| `req.headers` | `Record<string, string \| string[] \| undefined>` | Request headers |
| `req.query` | `Record<string, string \| string[] \| undefined>` | Query parameters |
| `req.ip` | `string` | Client IP address |
| `res` | `GenericResponse` | Response object |
| `user` | `any` | Authenticated user (set by auth middleware) |
| `container` | `ContainerInstance` | TypeDI dependency injection container |
| `businessData` | `Map<string, unknown>` | Shared data between middlewares |

**Complete Example from Project:**

```typescript
// src/controllers/auth.controllers.ts

import { Context } from '@noony-serverless/core';
import { LoginRequest } from '../models/auth/auth.schemas.js';
import { AuthenticatedUser } from '../types/auth.types.js';
import { containerPool } from '../core/container-pool.js';
import { AuthService } from '../services/auth.service.js';

export async function loginController(context: Context<LoginRequest>): Promise<void> {
  // Access validated request body
  const data = context.req.parsedBody as LoginRequest;

  // Access headers
  const userAgent = context.req.headers['user-agent'] as string | undefined;
  const forwardedFor = context.req.headers['x-forwarded-for'] as string | undefined;
  const clientIp = forwardedFor || context.req.ip;

  // Get service from container
  const authService = containerPool.getByToken<AuthService>('AuthService');

  // Execute business logic
  const result = await authService.login(data.email, data.password, userAgent, clientIp);

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

---

### 2.3 BaseMiddleware\<T\>

**What it is:** Interface for creating custom middleware with lifecycle methods.

**Import:**
```typescript
import { BaseMiddleware, Context } from '@noony-serverless/core';
```

**Where used:** `src/middlewares/auth.middleware.ts`, `src/middlewares/validation.middleware.ts`

**Why:** Allows creating custom middleware that integrates with Noony's middleware chain.

**Interface:**
```typescript
interface BaseMiddleware<T = unknown> {
  before?(context: Context<T>): Promise<void>;
  after?(context: Context<T>): Promise<void>;
  onError?(error: Error, context: Context<T>): Promise<void>;
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
      const tokenValidator = containerPool.getByToken<JWTTokenValidator>('TokenValidator');
      const validationResult = await tokenValidator.validateToken(token);

      if (!validationResult.valid || !validationResult.decoded) {
        return;
      }

      const permissionSource = containerPool.getByToken<MongoPermissionSource>('PermissionSource');
      const userId = tokenValidator.extractUserId(validationResult.decoded);
      const permissionResult = await permissionSource.getUserPermissions(userId);

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
export const authMiddleware = (): BaseMiddleware => new AuthenticationMiddleware();
```

---

### 2.4 errorHandler()

**What it is:** Built-in middleware for centralized error handling.

**Import:**
```typescript
import { errorHandler } from '@noony-serverless/core';
```

**Why:** Catches all errors from subsequent middleware and controllers, providing consistent error responses.

**IMPORTANT:** Always use as the **FIRST** middleware in the chain.

**Example:**
```typescript
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())  // ← ALWAYS FIRST
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController);
```

---

### 2.5 ResponseWrapperMiddleware

**What it is:** Built-in middleware that standardizes response format.

**Import:**
```typescript
import { ResponseWrapperMiddleware } from '@noony-serverless/core';
```

**Why:** Ensures all responses follow a consistent format structure.

**IMPORTANT:** Always use as the **LAST** middleware in the chain (before `.handle()`).

**Example:**
```typescript
export const loginHandler = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())  // ← ALWAYS LAST (before handle)
  .handle(loginController);
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
function extractBearerToken(authHeader: string | string[] | undefined): string | null {
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
      const tokenValidator = containerPool.getByToken<JWTTokenValidator>('TokenValidator');
      const validationResult = await tokenValidator.validateToken(token);

      if (!validationResult.valid || !validationResult.decoded) {
        logger.debug('Invalid token', { error: validationResult.error });
        return;
      }

      const permissionSource = containerPool.getByToken<MongoPermissionSource>('PermissionSource');
      const userId = tokenValidator.extractUserId(validationResult.decoded);
      const permissionResult = await permissionSource.getUserPermissions(userId);

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

export const authMiddleware = (): BaseMiddleware => new AuthenticationMiddleware();
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
  .use(authMiddleware())      // Extract user from token
  .use(requireAuth())         // Enforce authentication
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
  .use(requirePermission('resource:action'))  // Check specific permission
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
  .use(bodyValidator<RequestType>(schema))  // Validate request body
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

export async function loginController(context: Context<LoginRequest>): Promise<void> {
  const data = context.req.parsedBody as LoginRequest;
  logger.debug('Login request', { email: data.email });

  const authService = containerPool.getByToken<AuthService>('AuthService');

  const result = await authService.login(
    data.email,
    data.password,
    context.req.headers['user-agent'] as string | undefined,
    (context.req.headers['x-forwarded-for'] as string | undefined) || context.req.ip
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
  logger.debug('Create section request', { tenantId: user.tenantId, type: data.type });

  const configRepository = containerPool.getByToken<ConfigRepository>('ConfigRepository');

  const section = await configRepository.createSection(user.tenantId, data, user.id);

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
  containerPool.registerInstance('RefreshTokenRepository', refreshTokenRepository);

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
  const configRepository = containerPool.getByToken<ConfigRepository>('ConfigRepository');

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
      logger.info('Cloud Functions dependencies initialized successfully', { coldStartMs: duration });
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
const logoutFunction: HttpFunction = createHttpFunction(logoutHandler, 'logout');
const getConfigFunction: HttpFunction = createHttpFunction(getConfigHandler, 'getConfig');

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
function wrapNoonyHandler(noonyHandler: Handler<unknown>, functionName: string) {
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
  app.post('/api/auth/refresh', wrapNoonyHandler(refreshTokenHandler, 'refresh'));
  app.post('/api/auth/forgot-password', wrapNoonyHandler(forgotPasswordHandler, 'forgotPassword'));
  app.post('/api/auth/reset-password', wrapNoonyHandler(resetPasswordHandler, 'resetPassword'));

  // Config routes
  app.get('/api/config', wrapNoonyHandler(getConfigHandler, 'getConfig'));
  app.put('/api/config', wrapNoonyHandler(replaceConfigHandler, 'replaceConfig'));
  app.patch('/api/config/company', wrapNoonyHandler(updateCompanyHandler, 'updateCompany'));

  // Section routes
  app.get('/api/config/sections', wrapNoonyHandler(getSectionsHandler, 'getSections'));
  app.post('/api/config/sections', wrapNoonyHandler(createSectionHandler, 'createSection'));
  app.patch('/api/config/sections/:sectionId', wrapNoonyHandler(updateSectionHandler, 'updateSection'));
  app.delete('/api/config/sections/:sectionId', wrapNoonyHandler(deleteSectionHandler, 'deleteSection'));

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

| Aspect | createHttpFunction | wrapNoonyHandler |
|--------|-------------------|------------------|
| **Use case** | Production deployment | Local development |
| **Framework** | Cloud Functions Framework | Express |
| **Return type** | `HttpFunction` | Express handler |
| **Registration** | `http('name', fn)` | `app.get('/path', fn)` |
| **Deployment** | Individual functions | Single Express app |

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

## 8. Best Practices

### 8.1 Middleware Order

**Always follow this order:**

```typescript
new Handler<RequestType>()
  .use(errorHandler())                    // 1. ALWAYS FIRST - catches all errors
  .use(authMiddleware())                  // 2. Extract user from JWT
  .use(requireAuth())                     // 3. Enforce authentication (optional)
  .use(requirePermission('resource:action')) // 4. Check permissions (optional)
  .use(bodyValidator<RequestType>(schema))   // 5. Validate request body (optional)
  .use(new ResponseWrapperMiddleware())   // 6. ALWAYS LAST - standardize responses
  .handle(controller);
```

---

### 8.2 Error Handling Pattern

**Use `RESPONSE_SENT` signal to exit middleware chain:**

```typescript
// In custom middleware
async before(context: Context): Promise<void> {
  if (someConditionFails) {
    context.res.status(4xx).json({
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

### 8.3 Type Safety

**Use generics for type-safe request handling:**

```typescript
// Handler generic for request body type
export const createHandler = new Handler<CreateResourceRequest>()
  .use(bodyValidator<CreateResourceRequest>(schema))
  .handle(createController);

// Controller with typed Context
export async function createController(
  context: Context<CreateResourceRequest>
): Promise<void> {
  const data = context.req.parsedBody as CreateResourceRequest;
  // data is now fully typed
}
```

---

### 8.4 Container Usage

**Token-based registration pattern:**

```typescript
// Registration (at startup)
containerPool.registerInstance('AuthService', authService);
containerPool.registerInstance('ConfigRepository', configRepository);

// Retrieval (in controllers)
const authService = containerPool.getByToken<AuthService>('AuthService');
const configRepository = containerPool.getByToken<ConfigRepository>('ConfigRepository');
```

**Registered service tokens in this project:**

| Token | Service Type |
|-------|-------------|
| `'AuthService'` | `AuthService` |
| `'ConfigRepository'` | `ConfigRepository` |
| `'RefreshTokenRepository'` | `RefreshTokenRepository` |
| `'TokenValidator'` | `JWTTokenValidator` |
| `'PermissionSource'` | `MongoPermissionSource` |
| `'UserRepository'` | `UserRepository` |
| `'Database'` | `Db` (MongoDB) |
