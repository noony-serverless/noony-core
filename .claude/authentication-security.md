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