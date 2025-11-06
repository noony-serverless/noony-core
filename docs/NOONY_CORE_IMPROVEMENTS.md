# Noony Core Library Improvements

This document outlines recommended improvements to the `@noony-serverless/core` library based on patterns and utilities developed in the convivencialdia-api project.

## Table of Contents
- [Critical Fixes](#critical-fixes)
- [Recommended Additions](#recommended-additions)
- [Implementation Details](#implementation-details)
- [Migration Guide](#migration-guide)

---

## Critical Fixes

### 1. Fix Container Type Definition

**Current Issue:**
```typescript
// ❌ WRONG - Container is a static class, not an instance
import Container from 'typedi';

export interface Context<T = unknown> {
  container?: Container;  // This is incorrect!
  // ...
}
```

**Fix Required:**
```typescript
// ✅ CORRECT - ContainerInstance is the actual runtime type
import { ContainerInstance } from 'typedi';

export interface Context<T = unknown> {
  container?: ContainerInstance;  // Matches runtime behavior
  // ...
}
```

**Why This Matters:**
- The `Container` class from TypeDI only has **static methods**
- At runtime, Noony sets a `ContainerInstance` in `context.container`
- This type mismatch forces developers to cast: `context.container.get()`
- Fixing this enables type-safe container access without casts

**Files to Update in Noony:**
- `@noony-serverless/core/src/core/core.ts` (source)
- `@noony-serverless/core/build/core/core.d.ts` (generated)

---

## Recommended Additions

### 2. Standard HTTP Error Classes

**Purpose:** Provide standard error classes for common HTTP error scenarios.

**Location in Noony:** `@noony-serverless/core/errors` or `@noony-serverless/core/http`

**Classes to Add:**

```typescript
/**
 * Base HTTP error with status code
 */
export class HttpError extends Error {
  constructor(
    message: string,
    public statusCode: number
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

/**
 * 400 Bad Request - Validation errors
 */
export class ValidationError extends Error {
  constructor(
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * 401 Unauthorized - Authentication required
 */
export class UnauthorizedError extends Error {
  constructor(message: string = 'Authentication required') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

/**
 * 403 Forbidden - Insufficient permissions
 */
export class ForbiddenError extends Error {
  constructor(message: string = 'Access denied') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

/**
 * 404 Not Found - Resource not found
 */
export class NotFoundError extends Error {
  constructor(message: string = 'Resource not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}

/**
 * 409 Conflict - Resource already exists
 */
export class ConflictError extends Error {
  constructor(message: string = 'Resource already exists') {
    super(message);
    this.name = 'ConflictError';
  }
}

/**
 * 500 Internal Server Error - Unexpected errors
 */
export class InternalServerError extends Error {
  constructor(
    message: string = 'Internal server error',
    public cause?: Error
  ) {
    super(message);
    this.name = 'InternalServerError';
    if (cause) {
      this.stack = `${this.stack}\nCaused by: ${cause.stack}`;
    }
  }
}
```

**Usage Example:**
```typescript
import { NotFoundError, ForbiddenError } from '@noony-serverless/core';

export async function getUserController(context: Context) {
  const user = await service.getUser(userId);

  if (!user) {
    throw new NotFoundError('User not found');
  }

  if (!canAccess(user, context.user)) {
    throw new ForbiddenError('You cannot access this user');
  }

  context.res.status(200).json({ data: user });
}
```

**Benefits:**
- ✅ Standardized error handling across all Noony projects
- ✅ Clear HTTP status code mapping
- ✅ Better error messages and debugging
- ✅ Type-safe error classes (no need for `error.statusCode = 404` hacks)

---

### 3. Query Parameter Helpers

**Purpose:** Type-safe utilities for handling query parameters that can be `string | string[]`.

**Location in Noony:** `@noony-serverless/core/utils`

**Functions to Add:**

```typescript
/**
 * Convert query parameter to single string
 * @param value - Query parameter value
 * @returns First string value or undefined
 */
export function asString(
  value: string | string[] | undefined
): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

/**
 * Convert query parameter to string array
 * @param value - Query parameter value
 * @returns Array of strings or undefined
 */
export function asStringArray(
  value: string | string[] | undefined
): string[] | undefined {
  if (!value) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return value;
  }
  return [value];
}

/**
 * Convert query parameter to number
 * @param value - Query parameter value
 * @returns Parsed number or undefined
 */
export function asNumber(
  value: string | string[] | undefined
): number | undefined {
  const str = asString(value);
  if (!str) {
    return undefined;
  }
  const num = parseInt(str, 10);
  return isNaN(num) ? undefined : num;
}

/**
 * Convert query parameter to boolean
 * @param value - Query parameter value
 * @returns Boolean value or undefined
 */
export function asBoolean(
  value: string | string[] | undefined
): boolean | undefined {
  const str = asString(value);
  if (!str) {
    return undefined;
  }
  return str.toLowerCase() === 'true' || str === '1';
}
```

**Usage Example:**
```typescript
import { asString, asNumber, asBoolean } from '@noony-serverless/core';

export async function listUsersController(context: Context) {
  const query = context.req.query;

  const options = {
    search: asString(query.search),      // string | undefined
    page: asNumber(query.page) || 1,     // number
    limit: asNumber(query.limit) || 10,  // number
    active: asBoolean(query.active),     // boolean | undefined
  };

  const users = await service.listUsers(options);
  context.res.status(200).json({ data: users });
}
```

**Benefits:**
- ✅ Type-safe query parameter handling
- ✅ No need for manual array checking
- ✅ Consistent parsing across all controllers
- ✅ Prevents common bugs with query params

---

### 4. Container Helper Function

**Purpose:** Type-safe utility to get services from the container without casting.

**Location in Noony:** `@noony-serverless/core/utils`

**Function to Add:**

```typescript
import { ContainerInstance } from 'typedi';
import type { Context } from '../core';

/**
 * Get a service from the dependency injection container
 * @param context - Request context
 * @param serviceClass - Service class constructor
 * @returns Service instance
 * @throws Error if container is not initialized
 */
export function getService<T>(
  context: Context,
  serviceClass: new (...args: any[]) => T
): T {
  if (!context.container) {
    throw new Error(
      'Container not initialized. Did you forget to add DependencyInjectionMiddleware?'
    );
  }
  return (context.container as ContainerInstance).get(serviceClass);
}
```

**Note:** Once the container type is fixed to `ContainerInstance`, the cast can be removed:

```typescript
// After container type fix:
export function getService<T>(
  context: Context,
  serviceClass: new (...args: any[]) => T
): T {
  if (!context.container) {
    throw new Error(
      'Container not initialized. Did you forget to add DependencyInjectionMiddleware?'
    );
  }
  return context.container.get(serviceClass); // No cast needed!
}
```

**Usage Example:**
```typescript
import { getService } from '@noony-serverless/core';
import { UserService } from '../services/user.service';

export async function createUserController(context: Context<CreateUserRequest>) {
  const userService = getService(context, UserService); // Type-safe!

  const user = await userService.createUser(context.req.parsedBody);
  context.res.status(201).json({ data: user });
}
```

**Benefits:**
- ✅ Eliminates boilerplate: `context.container.get()`
- ✅ Type-safe service resolution
- ✅ Clear error message if container not initialized
- ✅ Cleaner controller code

---

### 5. Generic User Type in Context

**Purpose:** Type-safe user context without casting.

**Current Implementation:**
```typescript
export interface Context<T = unknown> {
  user?: unknown;  // Forces developers to cast
  // ...
}
```

**Improved Implementation:**
```typescript
export interface Context<TBody = unknown, TUser = unknown> {
  readonly req: NoonyRequest<TBody>;
  readonly res: NoonyResponse;
  container?: ContainerInstance;
  user?: TUser;  // Now type-safe!
  // ...
}
```

**Base User Interface:**
```typescript
/**
 * Base authenticated user interface
 * Projects can extend this with additional fields
 */
export interface BaseAuthenticatedUser {
  id: string;
  email?: string;
  name?: string;
  [key: string]: unknown; // Allow extension
}
```

**Usage Example:**
```typescript
import type { Context, BaseAuthenticatedUser } from '@noony-serverless/core';

// Project-specific user type
interface AuthenticatedUser extends BaseAuthenticatedUser {
  tenantId: string;
  organizationId?: string;
  role: string;
  permissions: string[];
}

// Type-safe controller - no casting needed!
export async function createResourceController(
  context: Context<CreateResourceRequest, AuthenticatedUser>
) {
  const user = context.user; // Type: AuthenticatedUser | undefined

  // Full type safety and autocomplete
  const userId = user?.id;
  const tenantId = user?.tenantId;
  const permissions = user?.permissions;

  // ...
}
```

**Benefits:**
- ✅ Eliminates `context.user as AuthenticatedUser` casts
- ✅ Full TypeScript autocomplete for user properties
- ✅ Type safety across entire controller
- ✅ Standardized user context pattern

---

### 6. Base Service Error Class

**Purpose:** Standardized error class for service layer with error codes.

**Location in Noony:** `@noony-serverless/core/errors`

**Class to Add:**

```typescript
/**
 * Service layer error with error code
 * Use this in service classes for business logic errors
 */
export class ServiceError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'ServiceError';
  }
}
```

**Usage Example:**
```typescript
import { ServiceError } from '@noony-serverless/core';

export class UserService {
  async createUser(data: CreateUserRequest): Promise<User> {
    // Check if user exists
    const existing = await this.repository.findByEmail(data.email);
    if (existing) {
      throw new ServiceError(
        'User with this email already exists',
        'USER_ALREADY_EXISTS',
        { email: data.email }
      );
    }

    // Create user
    return await this.repository.create(data);
  }
}
```

**Benefits:**
- ✅ Consistent error handling in service layer
- ✅ Error codes for better error categorization
- ✅ Structured error details
- ✅ Separates business logic errors from HTTP errors

---

## Implementation Details

### File Structure in Noony Core

```
@noony-serverless/core/
├── src/
│   ├── core/
│   │   ├── core.ts                    # Fix: container?: ContainerInstance
│   │   └── index.ts
│   ├── errors/
│   │   ├── http-errors.ts             # New: HTTP error classes
│   │   ├── service-error.ts           # New: ServiceError class
│   │   └── index.ts                   # Export all errors
│   ├── utils/
│   │   ├── container.utils.ts         # New: getService()
│   │   ├── query-param.utils.ts       # New: asString(), asNumber(), etc.
│   │   └── index.ts                   # Export all utils
│   └── index.ts                       # Main export
```

### Main Export File

```typescript
// @noony-serverless/core/src/index.ts

// Core
export * from './core';

// Errors
export {
  HttpError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  InternalServerError,
  ServiceError,
} from './errors';

// Utils
export {
  getService,
  asString,
  asStringArray,
  asNumber,
  asBoolean,
} from './utils';

// Types
export type { BaseAuthenticatedUser } from './core';
```

---

## Migration Guide

### Before (Current Pattern)

```typescript
import type { Context } from '@noony-serverless/core';
import { AuthenticatedUser } from '@auth';

export async function createUserController(context: Context) {
  // ❌ Manual casting everywhere
  const userService = context.container.get(UserService);
  const user = context.user as AuthenticatedUser;

  // ❌ Creating errors with any
  const error: any = new Error('User not found');
  error.statusCode = 404;
  throw error;

  // ❌ Manual query param handling
  const page = Array.isArray(context.req.query.page)
    ? parseInt(context.req.query.page[0], 10)
    : parseInt(context.req.query.page as string, 10);
}
```

### After (With Noony Improvements)

```typescript
import type { Context, BaseAuthenticatedUser } from '@noony-serverless/core';
import { getService, asNumber, NotFoundError } from '@noony-serverless/core';

interface AuthenticatedUser extends BaseAuthenticatedUser {
  tenantId: string;
  role: string;
}

export async function createUserController(
  context: Context<CreateUserRequest, AuthenticatedUser>
) {
  // ✅ Type-safe service resolution
  const userService = getService(context, UserService);

  // ✅ Type-safe user access (no cast needed)
  const user = context.user;

  // ✅ Standard error class
  throw new NotFoundError('User not found');

  // ✅ Clean query param handling
  const page = asNumber(context.req.query.page) || 1;
}
```

---

## Benefits Summary

### Developer Experience
- ✅ **Less boilerplate** - No more manual casts and error creation
- ✅ **Better autocomplete** - TypeScript knows exact types
- ✅ **Fewer bugs** - Type safety catches errors at compile time
- ✅ **Cleaner code** - Standard utilities reduce repetition

### Code Quality
- ✅ **Consistency** - All projects use same patterns
- ✅ **Maintainability** - Centralized utilities are easier to update
- ✅ **Testability** - Standard error classes are easier to test
- ✅ **Documentation** - Types serve as inline documentation

### Team Productivity
- ✅ **Faster onboarding** - New developers learn standard patterns
- ✅ **Less context switching** - Same utilities across all projects
- ✅ **Fewer code reviews** - Standard patterns are pre-approved
- ✅ **Better tooling support** - IDE understands types better

---

## Backward Compatibility

All additions are **100% backward compatible**:

1. **Container type fix** - Only improves existing type safety
2. **Error classes** - New exports, don't break existing code
3. **Query helpers** - Optional utilities, existing code unchanged
4. **getService helper** - Optional utility, existing code unchanged
5. **User generic** - Defaults to `unknown`, existing code unchanged

Projects can adopt these improvements incrementally without breaking changes.

---

## Implementation Checklist

- [ ] Fix `container?: ContainerInstance` type in core.ts
- [ ] Add HTTP error classes to errors/http-errors.ts
- [ ] Add ServiceError class to errors/service-error.ts
- [ ] Add query parameter helpers to utils/query-param.utils.ts
- [ ] Add getService helper to utils/container.utils.ts
- [ ] Add BaseAuthenticatedUser interface to core.ts
- [ ] Add second generic to Context: `Context<TBody, TUser>`
- [ ] Update index.ts to export all new utilities
- [ ] Update TypeScript build and generate .d.ts files
- [ ] Add JSDoc documentation for all new exports
- [ ] Add unit tests for all utilities
- [ ] Update Noony documentation with examples
- [ ] Publish new version to npm
- [ ] Update convivencialdia-api to use new utilities

---

## Version Recommendation

**Suggested Version:** `0.3.0` (minor version bump)

**Reasoning:**
- All changes are backward compatible
- Significant new features added
- No breaking changes to existing API
- Follows semantic versioning (MINOR = new features, no breaking changes)

---

## Additional Recommendations

### 7. Response Helper Functions (Future Enhancement)

```typescript
// Sugar for common response patterns
export function ok<T>(res: NoonyResponse, data: T) {
  res.status(200).json({ success: true, data });
}

export function created<T>(res: NoonyResponse, data: T) {
  res.status(201).json({ success: true, data });
}

export function noContent(res: NoonyResponse) {
  res.status(204).send('');
}
```

### 8. Validation Helper (Future Enhancement)

```typescript
import { z } from 'zod';
import { ValidationError } from './errors';

export function validate<T>(schema: z.ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new ValidationError('Validation failed', result.error.errors);
  }
  return result.data;
}
```

---

## Contact & Questions

For questions or feedback on these improvements, please contact the Noony maintainers or create an issue in the Noony repository.

---

**Document Version:** 1.0
**Last Updated:** 2025-11-05
**Prepared By:** convivencialdia-api team
