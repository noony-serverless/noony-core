/**
 * Type Safety Enhancement Example - v0.7.0
 *
 * This example demonstrates the type safety improvements introduced in v0.7.0.
 * It shows both the OLD approach (v0.6.x with `as any`) and the NEW approaches
 * (v0.7.0 with explicit types and createTypedHandler).
 *
 * @version 0.7.0
 * @author Noony Framework Team
 */

import { z } from 'zod';
import {
  Handler,
  createTypedHandler,
  Context,
  BaseAuthenticatedUser,
  ErrorHandlerMiddleware,
  BodyValidationMiddleware,
  AuthenticationMiddleware,
  ResponseWrapperMiddleware,
  CustomTokenVerificationPort,
} from '@noony-serverless/core';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

/**
 * Login Request Schema (Zod)
 */
const loginRequestSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  rememberMe: z.boolean().optional().default(false),
});

/**
 * TypeScript type inferred from Zod schema
 */
type LoginRequest = z.infer<typeof loginRequestSchema>;

/**
 * Authenticated User Type
 */
interface AuthUser extends BaseAuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
  permissions: string[];
}

/**
 * Login Response Type
 */
interface LoginResponse {
  token: string;
  expiresIn: number;
  user: {
    id: string;
    email: string;
    role: string;
  };
}

// =============================================================================
// TOKEN VERIFIER (Required for AuthenticationMiddleware)
// =============================================================================

/**
 * Mock token verifier for demonstration
 * In production, use Firebase Auth, Auth0, or your JWT implementation
 */
const tokenVerifier: CustomTokenVerificationPort<AuthUser> = {
  async verifyToken(_token: string): Promise<AuthUser> {
    // Mock implementation - replace with real JWT verification
    return {
      id: 'user-123',
      email: 'demo@example.com',
      role: 'user',
      permissions: ['user:read', 'user:write'],
      sub: 'user-123',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };
  },
};

// =============================================================================
// CONTROLLER FUNCTION
// =============================================================================

/**
 * Login Controller
 *
 * This controller has explicit Context<LoginRequest, AuthUser> types,
 * which enables full type safety and autocomplete.
 */
async function loginController(
  context: Context<LoginRequest, AuthUser>
): Promise<LoginResponse> {
  // ✅ Full type safety! context.req.validatedBody is typed as LoginRequest
  const { email, password, rememberMe } = context.req.validatedBody!;

  // Mock authentication logic
  // In production: verify credentials against database, hash comparison, etc.
  const authenticated =
    email === 'demo@example.com' && password === 'password123';

  if (!authenticated) {
    throw new Error('Invalid credentials');
  }

  // Generate token (mock)
  const token = `mock-jwt-token-${Date.now()}`;
  const expiresIn = rememberMe ? 30 * 24 * 60 * 60 : 24 * 60 * 60; // 30 days or 1 day

  return {
    token,
    expiresIn,
    user: {
      id: 'user-123',
      email,
      role: 'user',
    },
  };
}

// =============================================================================
// ❌ OLD APPROACH (v0.6.x) - REQUIRED `as any`
// =============================================================================

/**
 * v0.6.x Handler - Type drift through middleware chain
 *
 * Problem: The .use() method had covariant generics that allowed types to change,
 * causing TypeScript to lose track of the actual types by the time .handle() was called.
 *
 * Result: Had to use `as any` to bypass TypeScript errors.
 */
/*
// This is how it USED to work in v0.6.x (commented out because it no longer compiles)
const loginHandlerOld = new Handler<LoginRequest>()
  .use(errorHandler())
  .use(bodyValidator<LoginRequest>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(loginController as any);  // ❌ Type safety lost!
  //                       ^^^^^^^^^ Required because TypeScript couldn't verify types
*/

// =============================================================================
// ✅ NEW APPROACH 1 (v0.7.0) - EXPLICIT TYPES
// =============================================================================

/**
 * v0.7.0 Handler - Option 1: Explicit Type Parameters
 *
 * Recommended when:
 * - You want clear, upfront type declarations
 * - Team prefers seeing all types at handler definition
 * - You're defining handlers before controllers exist
 *
 * Benefits:
 * - Types declared once, apply to entire chain
 * - Clear documentation of what types the handler expects
 * - Middleware must match declared types (compile-time verification)
 */
const loginHandlerExplicit = new Handler<LoginRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<LoginRequest, AuthUser>())
  .use(new BodyValidationMiddleware<LoginRequest, AuthUser>(loginRequestSchema))
  .use(new ResponseWrapperMiddleware<LoginRequest, AuthUser>())
  .handle(loginController); // ✅ No 'as any' needed! Types match perfectly

// =============================================================================
// ✅ NEW APPROACH 2 (v0.7.0) - TYPE INFERENCE
// =============================================================================

/**
 * v0.7.0 Handler - Option 2: Type Inference with createTypedHandler()
 *
 * Recommended when:
 * - Controller already has explicit Context<T, U> types
 * - You want to avoid repeating type parameters
 * - You prefer convenience over explicit declarations
 *
 * Benefits:
 * - Types automatically inferred from controller signature
 * - Less boilerplate (no need to specify types on middleware)
 * - Same type safety as explicit approach
 *
 * Note: This is a PERMANENT feature, not a temporary workaround!
 */
const loginHandlerInferred = createTypedHandler(loginController)
  .use(new ErrorHandlerMiddleware()) // Types inferred automatically
  .use(new BodyValidationMiddleware(loginRequestSchema)) // Types inferred
  .use(new ResponseWrapperMiddleware()) // Types inferred
  .handle(loginController); // ✅ No 'as any' needed! Types inferred

// =============================================================================
// ✅ BACKWARD COMPATIBILITY (v0.7.0)
// =============================================================================

/**
 * Untyped Handler - Still Supported
 *
 * For cases where you don't need strict typing or are migrating incrementally,
 * the untyped pattern still works.
 *
 * Use when:
 * - Rapid prototyping
 * - Migrating existing code incrementally
 * - Handler doesn't need specific request/user types
 */
const genericHandler = new Handler() // Handler<unknown, unknown>
  .use(new ErrorHandlerMiddleware())
  .handle(async (_context: Context) => {
    // Manual typing inside handler (when needed)
    // const body = _context.req.parsedBody as LoginRequest;

    return {
      message: 'Generic handler - types checked manually',
    };
  });

// =============================================================================
// COMPLEX EXAMPLE - PUBLIC ENDPOINT (No Authentication)
// =============================================================================

/**
 * Public Registration Schema
 */
const registrationSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2).max(50),
  agreeToTerms: z.boolean().refine((val) => val === true, {
    message: 'Must agree to terms',
  }),
});

type RegistrationRequest = z.infer<typeof registrationSchema>;

/**
 * Registration controller (no user context)
 */
async function registrationController(
  context: Context<RegistrationRequest, void>
): Promise<{ userId: string; email: string }> {
  const { email } = context.req.validatedBody!;

  // Mock user creation
  // In production: would use password and name for account creation
  return {
    userId: `user-${Date.now()}`,
    email,
  };
}

/**
 * Public endpoint handler - no authentication needed
 * Note: Use void for TUser when no authentication is required
 */
const registrationHandler = createTypedHandler(registrationController)
  .use(new ErrorHandlerMiddleware())
  .use(new BodyValidationMiddleware(registrationSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(registrationController); // ✅ Types: Context<RegistrationRequest, void>

// =============================================================================
// COMPLEX EXAMPLE - AUTHENTICATED ENDPOINT WITH BODY
// =============================================================================

/**
 * Update Profile Schema
 */
const updateProfileSchema = z.object({
  name: z.string().min(2).max(50).optional(),
  bio: z.string().max(500).optional(),
  avatar: z.string().url().optional(),
});

type UpdateProfileRequest = z.infer<typeof updateProfileSchema>;

/**
 * Update profile controller - requires authentication
 */
async function updateProfileController(
  context: Context<UpdateProfileRequest, AuthUser>
): Promise<{ success: boolean; updated: boolean }> {
  const user = context.user!; // ✅ Type: AuthUser
  const updates = context.req.validatedBody!; // ✅ Type: UpdateProfileRequest

  // Mock update logic
  console.log(`Updating profile for user ${user.email}`, updates);

  return {
    success: true,
    updated: true,
  };
}

/**
 * Authenticated endpoint with request body
 */
const updateProfileHandler = new Handler<UpdateProfileRequest, AuthUser>()
  .use(new ErrorHandlerMiddleware<UpdateProfileRequest, AuthUser>())
  .use(
    new AuthenticationMiddleware<UpdateProfileRequest, AuthUser>(tokenVerifier)
  )
  .use(
    new BodyValidationMiddleware<UpdateProfileRequest, AuthUser>(
      updateProfileSchema
    )
  )
  .use(new ResponseWrapperMiddleware<UpdateProfileRequest, AuthUser>())
  .handle(updateProfileController); // ✅ Perfect type matching!

// =============================================================================
// COMPLEX EXAMPLE - AUTHENTICATED ENDPOINT WITHOUT BODY
// =============================================================================

/**
 * Get profile controller - no request body, only authentication
 */
async function getProfileController(
  context: Context<void, AuthUser>
): Promise<{ user: AuthUser }> {
  const user = context.user!; // ✅ Type: AuthUser

  return {
    user,
  };
}

/**
 * Authenticated endpoint without request body
 * Note: Use void for TBody when no request body is expected
 */
const getProfileHandler = createTypedHandler(getProfileController)
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new ResponseWrapperMiddleware())
  .handle(getProfileController); // ✅ Types: Context<void, AuthUser>

// =============================================================================
// COMPARISON SUMMARY
// =============================================================================

/**
 * ## Type Safety Evolution Summary
 *
 * ### v0.6.x (OLD) - Required `as any`:
 * ```typescript
 * const handler = new Handler<LoginRequest>()
 *   .use(middleware())
 *   .handle(controller as any);  // ❌ Type safety lost
 * ```
 *
 * ### v0.7.0 Option 1 - Explicit Types:
 * ```typescript
 * const handler = new Handler<LoginRequest, AuthUser>()
 *   .use(new Middleware<LoginRequest, AuthUser>())
 *   .handle(controller);  // ✅ Full type safety
 * ```
 *
 * ### v0.7.0 Option 2 - Type Inference:
 * ```typescript
 * const handler = createTypedHandler(controller)
 *   .use(new Middleware())  // Types inferred
 *   .handle(controller);    // ✅ Full type safety
 * ```
 *
 * ## When to Use Each Pattern
 *
 * ### Explicit Types:
 * - Handler defined before controller exists
 * - Team prefers upfront type declarations
 * - Documentation and readability priorities
 *
 * ### Type Inference (createTypedHandler):
 * - Controller already has explicit Context types
 * - Want to minimize boilerplate
 * - Prefer convenience without sacrificing safety
 *
 * ### Untyped (new Handler()):
 * - Rapid prototyping
 * - Incremental migration from v0.6.x
 * - Handler doesn't need specific types
 *
 * ## Migration Checklist
 *
 * ✅ Update package.json to "@noony-serverless/core": "^0.7.0"
 * ✅ Find all handlers using `as any` (search: .handle.*as any)
 * ✅ Choose pattern: explicit types vs createTypedHandler()
 * ✅ Add type parameters to Handler or use createTypedHandler()
 * ✅ Add type parameters to middleware (if using explicit types)
 * ✅ Remove all `as any` casts
 * ✅ Run TypeScript compiler to verify: npm run build
 * ✅ Run tests to ensure behavior unchanged: npm test
 *
 * ## Complete Migration Guide
 *
 * See CHANGELOG-v0.7.0.md for comprehensive migration guide with examples,
 * troubleshooting, and best practices.
 */

// Export handlers for use in application
export {
  loginHandlerExplicit,
  loginHandlerInferred,
  genericHandler,
  registrationHandler,
  updateProfileHandler,
  getProfileHandler,
};

// Export types for external use
export type { LoginRequest, LoginResponse, AuthUser, RegistrationRequest };
