# Noony Framework Authentication & Security Rules

## JWT Authentication Implementation

### Token Validator Interface

```typescript
// Always implement the TokenValidator interface for authentication
interface TokenValidator {
  validateToken(token: string): Promise<{
    valid: boolean;
    decoded?: any;
    error?: string;
  }>;
  
  extractUserId(decoded: any): string;
  isTokenExpired(decoded: any): boolean;
}

// ✅ CORRECT: Complete implementation
class JWTTokenValidator implements TokenValidator {
  constructor(private secret: string) {}
  
  async validateToken(token: string) {
    try {
      const decoded = jwt.verify(token, this.secret);
      return { valid: true, decoded };
    } catch (error) {
      return { 
        valid: false, 
        error: error.message 
      };
    }
  }
  
  extractUserId(decoded: any): string {
    return decoded.sub || decoded.userId || decoded.id;
  }
  
  isTokenExpired(decoded: any): boolean {
    return decoded.exp && (decoded.exp * 1000 < Date.now());
  }
}
```

### Authentication Middleware Usage

```typescript
// ✅ CORRECT: Proper authentication middleware setup
const tokenValidator = new JWTTokenValidator(process.env.JWT_SECRET!);

const handler = new Handler<RequestType, AuthenticatedUser>()
  .use(new ErrorHandlerMiddleware<RequestType, AuthenticatedUser>())
  .use(new AuthenticationMiddleware<RequestType, AuthenticatedUser>(tokenValidator))
  .handle(async (context) => {
    // User is guaranteed to be authenticated
    const user = context.user!; // Type: AuthenticatedUser
    console.log(`Authenticated user: ${user.id}`);
  });

// ❌ INCORRECT: Missing authentication
const unsecureHandler = new Handler<RequestType, any>()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    const user = context.user; // undefined - no authentication
  });
```

## JWT Authentication and context.user Access

### How AuthenticationMiddleware Populates context.user

The `AuthenticationMiddleware` validates JWT tokens and automatically sets `context.user` with the decoded payload:

```typescript
import { AuthenticationMiddleware, CustomTokenVerificationPort } from '@/middlewares/authenticationMiddleware';

// 1. Define your authenticated user type from JWT payload
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user' | 'moderator';
  permissions: string[];
  sub: string;    // JWT subject claim
  exp: number;    // JWT expiration
  iat: number;    // Issued at time
  tenantId?: string; // Optional tenant isolation
}

// 2. Create token verification port implementation
const tokenVerifier: CustomTokenVerificationPort<AuthenticatedUser> = {
  async verifyToken(token: string): Promise<AuthenticatedUser> {
    // Your JWT verification logic (e.g., using jsonwebtoken)
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    
    // Transform JWT payload to your user type
    return {
      id: decoded.sub,
      email: decoded.email,
      role: decoded.role,
      permissions: decoded.permissions || [],
      sub: decoded.sub,
      exp: decoded.exp,
      iat: decoded.iat,
      tenantId: decoded.tenantId
    };
  }
};

// 3. Use authentication middleware - it automatically populates context.user
const handler = new Handler<RequestType, AuthenticatedUser>()
  .use(new AuthenticationMiddleware(tokenVerifier))
  .handle(async (context) => {
    // AuthenticationMiddleware has validated JWT and set context.user
    const user = context.user!; // Type: AuthenticatedUser, guaranteed to exist
    
    // Access JWT claims with full type safety
    console.log(`User ID: ${user.id}`);           // From JWT sub claim
    console.log(`Email: ${user.email}`);          // Custom JWT claim
    console.log(`Role: ${user.role}`);            // Custom JWT claim
    console.log(`Tenant: ${user.tenantId}`);      // Optional claim
    console.log(`Token expires: ${new Date(user.exp * 1000)}`); // JWT exp claim
    
    // Use user data for business logic
    const userProfile = await userService.getProfile(user.id);
    return { user: userProfile };
  });
```

### JWT Authentication Flow and context.user Population

**Step-by-Step Process:**

1. **Token Extraction**: `AuthenticationMiddleware` extracts JWT from `Authorization: Bearer <token>` header
2. **Token Verification**: Calls your `CustomTokenVerificationPort.verifyToken()` method  
3. **Security Validation**: Validates JWT claims (exp, iss, aud, nbf, etc.) with comprehensive security checks
4. **User Population**: **Sets `context.user`** with the decoded JWT payload returned by your verification port
5. **Type Safety**: Full TypeScript typing through the generic `UserType` parameter

```typescript
// The middleware internally does this:
class AuthenticationMiddleware<T, U> implements BaseMiddleware<T, U> {
  async before(context: Context<T, U>): Promise<void> {
    // Extract and verify token
    const token = this.extractTokenFromHeader(context);
    const user = await this.tokenVerificationPort.verifyToken(token);
    
    // Validate JWT security (exp, iss, aud, rate limiting, etc.)
    this.validateJWTSecurity(user, context);
    
    // 🔑 KEY STEP: Set context.user with decoded JWT payload
    context.user = user; // Now accessible in your handler!
  }
}
```

### Accessing Authenticated User in Handlers

```typescript
.handle(async (context: Context<RequestType, AuthenticatedUser>) => {
  // Always access user after AuthenticationMiddleware
  const user = context.user!; // Type: AuthenticatedUser
  
  // Access JWT standard claims
  const userId = user.sub;      // JWT subject (user ID)  
  const userEmail = user.email; // Custom claim
  const userRole = user.role;   // Custom claim
  
  // Check token expiration
  const isExpiringSoon = (user.exp * 1000 - Date.now()) < (5 * 60 * 1000); // 5 minutes
  
  // Permission-based logic
  if (user.permissions.includes('admin:read')) {
    // Admin functionality
    const adminData = await adminService.getAdminDashboard();
    return adminData;
  }
  
  // Role-based logic
  if (user.role === 'moderator') {
    const moderationQueue = await moderationService.getQueue(user.id);
    return moderationQueue;
  }
  
  // Regular user logic
  const userData = await userService.getProfile(user.id);
  return userData;
});
```

### Custom Authentication Logic

```typescript
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user' | 'moderator';
  permissions: string[];
  tenantId?: string;
}

class CustomAuthenticationMiddleware<T, U extends AuthenticatedUser> 
  implements BaseMiddleware<T, U> {
  
  constructor(
    private tokenValidator: TokenValidator,
    private userService: UserService
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    // Extract token from Authorization header
    const authHeader = context.req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthenticationError('Authorization header required');
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer '
    
    // Validate token
    const tokenResult = await this.tokenValidator.validateToken(token);
    if (!tokenResult.valid) {
      throw new AuthenticationError(`Invalid token: ${tokenResult.error}`);
    }
    
    // Extract user ID and load full user context
    const userId = this.tokenValidator.extractUserId(tokenResult.decoded);
    const user = await this.userService.findById(userId);
    
    if (!user) {
      throw new AuthenticationError('User not found');
    }
    
    if (user.status !== 'active') {
      throw new AuthenticationError('User account is not active');
    }
    
    // Store authenticated user in context
    context.user = user as U;
    context.businessData?.set('tokenPayload', tokenResult.decoded);
  }
}
```

## Security Headers Middleware

### Essential Security Headers

```typescript
class SecurityHeadersMiddleware<T, U> implements BaseMiddleware<T, U> {
  async after(context: Context<T, U>): Promise<void> {
    const headers = {
      // Prevent XSS attacks
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      
      // HTTPS enforcement
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      
      // Content Security Policy
      'Content-Security-Policy': "default-src 'self'; script-src 'self'",
      
      // Hide server information
      'X-Powered-By': 'Noony-Framework',
      
      // Prevent MIME type sniffing
      'X-Download-Options': 'noopen',
      
      // Referrer policy
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    };
    
    Object.entries(headers).forEach(([name, value]) => {
      context.res.header(name, value);
    });
  }
}

// ✅ CORRECT: Include security headers in every handler
const secureHandler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware<RequestType, UserType>())
  .use(new SecurityHeadersMiddleware<RequestType, UserType>())
  .use(new AuthenticationMiddleware<RequestType, UserType>(tokenValidator))
  .handle(async (context) => {
    // Secure handler with proper headers
  });
```

### CORS Configuration

```typescript
class CORSMiddleware<T, U> implements BaseMiddleware<T, U> {
  constructor(
    private allowedOrigins: string[] = ['https://yourapp.com'],
    private allowedMethods: string[] = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    private allowedHeaders: string[] = ['Content-Type', 'Authorization']
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    const origin = context.req.headers.origin as string;
    
    // Check if origin is allowed
    if (this.allowedOrigins.includes('*') || this.allowedOrigins.includes(origin)) {
      context.res.header('Access-Control-Allow-Origin', origin);
    }
    
    context.res.header('Access-Control-Allow-Methods', this.allowedMethods.join(', '));
    context.res.header('Access-Control-Allow-Headers', this.allowedHeaders.join(', '));
    context.res.header('Access-Control-Max-Age', '86400'); // 24 hours
    
    // Handle preflight requests
    if (context.req.method === 'OPTIONS') {
      context.res.status(204).end();
      return;
    }
  }
}
```

## Security Audit Middleware

### Request Logging and Monitoring

```typescript
class SecurityAuditMiddleware<T, U extends { id: string }> 
  implements BaseMiddleware<T, U> {
  
  constructor(
    private auditLogger: AuditLogger,
    private suspiciousPatterns: RegExp[] = [
      /script/i,
      /javascript:/i,
      /<.*>/,
      /union.*select/i,
      /drop.*table/i
    ]
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    // Log security-relevant information
    const securityInfo = {
      requestId: context.requestId,
      timestamp: new Date(),
      ip: context.req.ip,
      userAgent: context.req.userAgent,
      method: context.req.method,
      path: context.req.path,
      userId: context.user?.id,
      headers: this.sanitizeHeaders(context.req.headers)
    };
    
    // Check for suspicious patterns
    const requestData = JSON.stringify(context.req.body || {});
    const hasSuspiciousContent = this.suspiciousPatterns.some(pattern => 
      pattern.test(requestData)
    );
    
    if (hasSuspiciousContent) {
      await this.auditLogger.logSuspiciousActivity({
        ...securityInfo,
        suspiciousContent: true,
        payload: requestData
      });
    }
    
    await this.auditLogger.logRequest(securityInfo);
  }
  
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Log security errors
    if (error instanceof AuthenticationError || error instanceof SecurityError) {
      await this.auditLogger.logSecurityError({
        requestId: context.requestId,
        error: error.message,
        userId: context.user?.id,
        ip: context.req.ip,
        timestamp: new Date()
      });
    }
  }
  
  private sanitizeHeaders(headers: Record<string, any>): Record<string, any> {
    const sanitized = { ...headers };
    delete sanitized.authorization; // Never log auth tokens
    delete sanitized.cookie; // Never log cookies
    return sanitized;
  }
}
```

## Rate Limiting and Throttling

### IP-based Rate Limiting

```typescript
class RateLimitingMiddleware<T, U> implements BaseMiddleware<T, U> {
  private requests = new Map<string, { count: number; resetTime: number }>();
  
  constructor(
    private maxRequests: number = 100,
    private windowMs: number = 15 * 60 * 1000, // 15 minutes
    private keyGenerator?: (context: Context<T, U>) => string
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    const key = this.keyGenerator ? 
      this.keyGenerator(context) : 
      this.getDefaultKey(context);
    
    const now = Date.now();
    const windowStart = now - this.windowMs;
    
    // Clean old entries
    this.cleanup(windowStart);
    
    const current = this.requests.get(key);
    if (!current) {
      this.requests.set(key, { count: 1, resetTime: now + this.windowMs });
      return;
    }
    
    if (now > current.resetTime) {
      // Reset window
      this.requests.set(key, { count: 1, resetTime: now + this.windowMs });
      return;
    }
    
    if (current.count >= this.maxRequests) {
      const resetIn = Math.ceil((current.resetTime - now) / 1000);
      context.res.header('X-RateLimit-Limit', this.maxRequests.toString());
      context.res.header('X-RateLimit-Remaining', '0');
      context.res.header('X-RateLimit-Reset', resetIn.toString());
      
      throw new TooManyRequestsError(`Rate limit exceeded. Try again in ${resetIn} seconds.`);
    }
    
    current.count++;
    const remaining = Math.max(0, this.maxRequests - current.count);
    
    context.res.header('X-RateLimit-Limit', this.maxRequests.toString());
    context.res.header('X-RateLimit-Remaining', remaining.toString());
    context.res.header('X-RateLimit-Reset', Math.ceil((current.resetTime - now) / 1000).toString());
  }
  
  private getDefaultKey(context: Context<T, U>): string {
    return context.req.ip || context.user?.id || 'anonymous';
  }
  
  private cleanup(windowStart: number): void {
    for (const [key, data] of this.requests.entries()) {
      if (data.resetTime < windowStart) {
        this.requests.delete(key);
      }
    }
  }
}
```

## Input Sanitization

### XSS Prevention Middleware

```typescript
import validator from 'validator';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

class InputSanitizationMiddleware<T, U> implements BaseMiddleware<T, U> {
  private window = new JSDOM('').window;
  private purify = DOMPurify(this.window);
  
  async before(context: Context<T, U>): Promise<void> {
    if (context.req.body && typeof context.req.body === 'object') {
      context.req.body = this.sanitizeObject(context.req.body);
    }
    
    if (context.req.query) {
      context.req.query = this.sanitizeObject(context.req.query);
    }
  }
  
  private sanitizeObject(obj: any): any {
    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }
    
    if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        const sanitizedKey = validator.escape(key);
        sanitized[sanitizedKey] = this.sanitizeObject(value);
      }
      return sanitized;
    }
    
    return obj;
  }
  
  private sanitizeString(str: string): string {
    // Remove HTML tags and escape special characters
    return this.purify.sanitize(str, { ALLOWED_TAGS: [] });
  }
}
```

## Permission-based Authorization

### Role-based Access Control

```typescript
class RoleAuthorizationMiddleware<T, U extends { role: string; permissions: string[] }> 
  implements BaseMiddleware<T, U> {
  
  constructor(
    private requiredRoles: string[] = [],
    private requiredPermissions: string[] = []
  ) {}
  
  async before(context: Context<T, U>): Promise<void> {
    const user = context.user;
    if (!user) {
      throw new AuthenticationError('Authentication required');
    }
    
    // Check role requirements
    if (this.requiredRoles.length > 0) {
      const hasRole = this.requiredRoles.includes(user.role);
      if (!hasRole) {
        throw new SecurityError(`Access denied. Required roles: ${this.requiredRoles.join(', ')}`);
      }
    }
    
    // Check permission requirements  
    if (this.requiredPermissions.length > 0) {
      const hasPermission = this.requiredPermissions.some(permission => 
        user.permissions.includes(permission)
      );
      if (!hasPermission) {
        throw new SecurityError(`Access denied. Required permissions: ${this.requiredPermissions.join(', ')}`);
      }
    }
    
    // Store authorization info for audit
    context.businessData?.set('authorizedRole', user.role);
    context.businessData?.set('authorizedPermissions', user.permissions);
  }
}

// Usage examples
const adminHandler = new Handler<RequestType, AdminUser>()
  .use(new ErrorHandlerMiddleware<RequestType, AdminUser>())
  .use(new AuthenticationMiddleware<RequestType, AdminUser>(tokenValidator))
  .use(new RoleAuthorizationMiddleware<RequestType, AdminUser>(['admin']))
  .handle(async (context) => {
    // Only admin users can access this
  });

const moderatorHandler = new Handler<RequestType, UserWithPermissions>()
  .use(new ErrorHandlerMiddleware<RequestType, UserWithPermissions>())
  .use(new AuthenticationMiddleware<RequestType, UserWithPermissions>(tokenValidator))
  .use(new RoleAuthorizationMiddleware<RequestType, UserWithPermissions>(
    [], // No role requirement
    ['moderate:content', 'review:posts'] // Must have at least one permission
  ))
  .handle(async (context) => {
    // Users with moderation permissions can access this
  });
```

## Security Best Practices

### Environment Variable Security

```typescript
// ✅ CORRECT: Validate environment variables at startup
const validateEnvironment = () => {
  const required = ['JWT_SECRET', 'DATABASE_URL'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // Validate JWT secret strength
  if (process.env.JWT_SECRET!.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }
};

// Call during application startup
validateEnvironment();
```

### Secure Error Responses

```typescript
class SecureErrorHandlerMiddleware<T, U> implements BaseMiddleware<T, U> {
  async onError(error: Error, context: Context<T, U>): Promise<void> {
    // Log full error details internally
    console.error(`Request ${context.requestId} failed:`, error);
    
    // Return sanitized error to client
    if (error instanceof ValidationError) {
      context.res.status(400).json({
        success: false,
        error: {
          type: 'validation_error',
          message: error.message // Safe to expose validation errors
        }
      });
    } else if (error instanceof AuthenticationError) {
      context.res.status(401).json({
        success: false,
        error: {
          type: 'authentication_error',
          message: 'Authentication failed' // Generic message
        }
      });
    } else if (error instanceof SecurityError) {
      context.res.status(403).json({
        success: false,
        error: {
          type: 'access_denied',
          message: 'Access denied' // Generic message
        }
      });
    } else {
      // Never expose internal error details
      context.res.status(500).json({
        success: false,
        error: {
          type: 'internal_error',
          message: 'An unexpected error occurred'
        }
      });
    }
  }
}
```

## Complete Workflow: Validation + Authentication Integration

### Production-Ready Handler Example

Here's a complete example showing how to integrate Zod validation, JWT authentication, and security best practices:

```typescript
import { z } from 'zod';
import { Handler } from '@/core/handler';
import { 
  ErrorHandlerMiddleware,
  AuthenticationMiddleware, 
  BodyValidationMiddleware,
  ResponseWrapperMiddleware,
  SecurityHeadersMiddleware,
  RateLimitingMiddleware
} from '@/middlewares';

// 1. Define Zod schema for complete validation
const updateProfileSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email(),
  phone: z.string().regex(/^\+?[1-9]\d{1,14}$/).optional(),
  preferences: z.object({
    newsletter: z.boolean().default(false),
    theme: z.enum(['light', 'dark']).default('light'),
    notifications: z.object({
      email: z.boolean().default(true),
      sms: z.boolean().default(false)
    })
  }),
  profileImage: z.object({
    filename: z.string().max(255),
    mimeType: z.enum(['image/jpeg', 'image/png', 'image/gif']),
    size: z.number().max(5 * 1024 * 1024), // 5MB max
    content: z.string().base64()
  }).optional()
}).refine(
  // Cross-field validation
  (data) => {
    if (data.preferences.notifications.sms && !data.phone) {
      return false;
    }
    return true;
  },
  {
    message: 'Phone number required for SMS notifications',
    path: ['phone']
  }
);

// 2. Extract TypeScript types
type UpdateProfileRequest = z.infer<typeof updateProfileSchema>;

// 3. Define authenticated user type
interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'user' | 'admin' | 'premium';
  permissions: string[];
  sub: string;
  exp: number;
  planType: 'free' | 'pro' | 'enterprise';
}

// 4. Custom token verifier with user loading
const tokenVerifier: CustomTokenVerificationPort<AuthenticatedUser> = {
  async verifyToken(token: string): Promise<AuthenticatedUser> {
    // Verify JWT and decode
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    
    // Load fresh user data from database
    const user = await userService.findById(decoded.sub);
    if (!user || user.status !== 'active') {
      throw new AuthenticationError('User not found or inactive');
    }
    
    // Transform to authenticated user type
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      sub: decoded.sub,
      exp: decoded.exp,
      planType: user.planType
    };
  }
};

// 5. Custom business validation that uses both Zod validation and JWT user
class ProfileValidationMiddleware<T extends UpdateProfileRequest, U extends AuthenticatedUser>
  implements BaseMiddleware<T, U> {
  
  async before(context: Context<T, U>): Promise<void> {
    const user = context.user!;                    // From JWT authentication
    const profileData = context.req.validatedBody!; // From Zod validation
    
    // Plan-based feature restrictions
    if (user.planType === 'free' && profileData.profileImage) {
      throw new ValidationError('Profile image upload requires Pro plan');
    }
    
    // Role-based email validation
    if (user.role !== 'admin' && profileData.email !== user.email) {
      throw new ValidationError('Only admins can change email addresses');
    }
    
    // Check if email is already taken (excluding current user)
    if (profileData.email !== user.email) {
      const existingUser = await userService.findByEmail(profileData.email);
      if (existingUser) {
        throw new ValidationError('Email address is already in use');
      }
    }
    
    // Store business data for handler
    context.businessData?.set('originalEmail', user.email);
    context.businessData?.set('emailChanged', profileData.email !== user.email);
  }
}

// 6. Complete production handler with full security stack
const updateProfileHandler = new Handler<UpdateProfileRequest, AuthenticatedUser>()
  // Security layer
  .use(new ErrorHandlerMiddleware())                           // 1. Error handling
  .use(new SecurityHeadersMiddleware())                        // 2. Security headers  
  .use(new RateLimitingMiddleware(10, 15 * 60 * 1000))         // 3. Rate limiting: 10 req/15min
  
  // Authentication & authorization
  .use(new AuthenticationMiddleware(tokenVerifier))            // 4. JWT auth -> context.user
  
  // Input validation
  .use(new BodyParserMiddleware())                             // 5. Parse body
  .use(new BodyValidationMiddleware(updateProfileSchema))      // 6. Zod validation -> context.req.validatedBody
  .use(new ProfileValidationMiddleware())                      // 7. Business validation
  
  // Response formatting
  .use(new ResponseWrapperMiddleware())                        // 8. Response wrapper
  
  .handle(async (context) => {
    // Both user and validated body are guaranteed and typed
    const user = context.user!;                    // Type: AuthenticatedUser
    const profileData = context.req.validatedBody!; // Type: UpdateProfileRequest
    
    // Business logic with complete type safety
    const emailChanged = context.businessData?.get('emailChanged') as boolean;
    
    // Update profile with validated data
    const updatedProfile = await userService.updateProfile(user.id, {
      name: profileData.name,                    // Validated by Zod
      email: profileData.email,                  // Validated by Zod + business rules
      phone: profileData.phone,                  // Validated by Zod
      preferences: profileData.preferences,      // Validated by Zod
    });
    
    // Handle profile image upload if provided
    if (profileData.profileImage) {
      const imageUrl = await imageService.upload({
        userId: user.id,                         // From JWT
        filename: profileData.profileImage.filename,
        content: profileData.profileImage.content,
        mimeType: profileData.profileImage.mimeType
      });
      updatedProfile.imageUrl = imageUrl;
    }
    
    // Send verification email if email changed
    if (emailChanged) {
      await emailService.sendVerificationEmail(profileData.email, user.id);
    }
    
    // Audit log with user context
    await auditService.log({
      userId: user.id,
      action: 'profile_updated',
      changes: profileData,
      emailChanged,
      timestamp: new Date()
    });
    
    return {
      success: true,
      profile: updatedProfile,
      emailVerificationRequired: emailChanged
    };
  });

// 7. Export for GCP Functions
export const updateProfile = http('updateProfile', (req, res) => {
  return updateProfileHandler.execute(req, res);
});
```

### Key Integration Benefits Demonstrated

1. **🔐 JWT Authentication**: `context.user` populated with full user context from JWT
2. **✅ Zod Validation**: `context.req.validatedBody` with runtime + compile-time type safety  
3. **🛡️ Security Stack**: Rate limiting, security headers, error handling
4. **🔗 Business Rules**: Cross-field validation using both user context and validated data
5. **📊 Type Safety**: Complete end-to-end TypeScript typing
6. **🎯 Role-Based Logic**: User permissions and plan restrictions
7. **📝 Audit Trail**: Security logging with user context

This pattern provides production-ready handlers with complete security, validation, and type safety.

### Security Checklist

1. **Always validate JWT tokens** with proper error handling
2. **Use HTTPS in production** - enforce with security headers
3. **Implement rate limiting** to prevent abuse
4. **Sanitize all inputs** to prevent XSS and injection attacks
5. **Log security events** for monitoring and auditing
6. **Never expose sensitive data** in error responses
7. **Validate environment variables** at startup
8. **Use strong secrets** - minimum 32 characters for JWT
9. **Implement CORS properly** - don't use wildcards in production
10. **Monitor for suspicious patterns** in request data
11. **🔑 NEW: Always authenticate before validation** when validation depends on user
12. **🔑 NEW: Use both `context.user` and `context.req.validatedBody`** for complete workflows