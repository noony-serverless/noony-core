# HeaderVariablesMiddleware Guide

A comprehensive guide to using the HeaderVariablesMiddleware for validating and extracting HTTP headers in the Noony Framework.

## Table of Contents

1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [Basic Usage](#basic-usage)
4. [TypeScript Generics Integration](#typescript-generics-integration)
5. [Authentication Patterns](#authentication-patterns)
6. [Content Negotiation](#content-negotiation)
7. [Multi-Tenant Applications](#multi-tenant-applications)
8. [Security Considerations](#security-considerations)
9. [Advanced Examples](#advanced-examples)
10. [Error Handling](#error-handling)
11. [Performance Considerations](#performance-considerations)
12. [Best Practices](#best-practices)

## Overview

The HeaderVariablesMiddleware validates that required HTTP headers are present in incoming requests. It provides a simple yet powerful way to enforce header-based requirements for authentication, content negotiation, API versioning, and other HTTP protocol features.

### Key Features
- **Required Header Validation**: Ensures critical headers are present before processing
- **Case-Insensitive Matching**: Handles HTTP header name case variations automatically
- **Array Value Support**: Properly handles headers with multiple values
- **Type Safety**: Full TypeScript integration with generic support
- **Early Validation**: Fails fast if required headers are missing
- **Security Focus**: Essential for authentication and authorization workflows

### When to Use
- **API Authentication**: Validate `Authorization`, `X-API-Key` headers
- **Content Negotiation**: Ensure `Accept`, `Content-Type`, `Accept-Language` headers
- **Multi-Tenant Systems**: Require tenant identification headers
- **Webhook Security**: Validate signature and timestamp headers
- **API Versioning**: Enforce version specification headers
- **CORS and Security**: Validate origin and security headers

## How It Works

The middleware checks for the presence of required headers in the request:

```typescript
// Required headers: ['authorization', 'content-type', 'x-api-key']
// Request headers: { Authorization: 'Bearer token123', 'Content-Type': 'application/json' }

// Result: ValidationError - Missing required header: x-api-key
```

### Internal Process
1. **Header Normalization**: Converts header names to lowercase for comparison
2. **Presence Check**: Verifies each required header exists in the request
3. **Empty Value Check**: Ensures headers have non-empty values
4. **Array Handling**: Validates array-type headers aren't empty arrays
5. **Error Generation**: Creates descriptive error messages for missing headers

## Basic Usage

### Simple Header Validation

```typescript
import { Handler, HeaderVariablesMiddleware } from '@/middlewares';

// Require authentication header
const authRequiredHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .handle(async (context) => {
    const authHeader = context.req.headers.authorization;
    
    // Header is guaranteed to exist after middleware validation
    const token = authHeader?.replace('Bearer ', '');
    const user = await validateToken(token);
    
    return { success: true, user, authenticated: true };
  });
```

### Multiple Required Headers

```typescript
// API endpoint requiring multiple headers
const secureApiHandler = new Handler()
  .use(new HeaderVariablesMiddleware([
    'authorization',
    'content-type',
    'x-api-key'
  ]))
  .handle(async (context) => {
    const headers = context.req.headers;
    
    // All headers are guaranteed to exist
    const auth = headers.authorization;
    const contentType = headers['content-type'];
    const apiKey = headers['x-api-key'];
    
    console.log('Processing secure request with headers:', {
      hasAuth: !!auth,
      contentType,
      apiKeyPrefix: typeof apiKey === 'string' ? apiKey.substring(0, 8) + '...' : 'invalid'
    });
    
    return await processSecureRequest({ auth, contentType, apiKey });
  });
```

### Factory Function Pattern

```typescript
import { headerVariablesMiddleware } from '@/middlewares';

// Quick header validation setup
const webhookHandler = new Handler()
  .use(headerVariablesMiddleware([
    'x-webhook-signature',
    'x-webhook-timestamp',
    'content-type'
  ]))
  .handle(async (context) => {
    const signature = context.req.headers['x-webhook-signature'];
    const timestamp = context.req.headers['x-webhook-timestamp'];
    
    // Validate webhook authenticity
    const isValid = await validateWebhookSignature(
      signature as string,
      timestamp as string,
      context.req.body
    );
    
    if (!isValid) {
      throw new SecurityError('Invalid webhook signature');
    }
    
    return { success: true, message: 'Webhook processed' };
  });
```

## TypeScript Generics Integration

### Type-Safe Header Access

```typescript
import { Handler } from '@/core/handler';
import { HeaderVariablesMiddleware } from '@/middlewares';

// Define expected header structure
interface APIHeaders {
  authorization: string;
  'content-type': string;
  'x-api-key': string;
  'x-client-version'?: string;
}

interface APIResponse {
  success: boolean;
  data: any;
  client: {
    version: string;
    authenticated: boolean;
  };
}

const typedApiHandler = new Handler<any, APIResponse>()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type', 'x-api-key']))
  .handle(async (context) => {
    // Type assertion with confidence due to middleware validation
    const headers = context.req.headers as APIHeaders;
    
    const clientVersion = headers['x-client-version'] || 'unknown';
    const authResult = await authenticateRequest(headers.authorization, headers['x-api-key']);
    
    const data = await processApiRequest({
      contentType: headers['content-type'],
      clientVersion
    });
    
    return {
      success: true,
      data,
      client: {
        version: clientVersion,
        authenticated: authResult.valid
      }
    };
  });
```

### Generic Header Validation Factory

```typescript
// Generic factory for header-validated handlers
function createHeaderValidatedHandler<THeaders extends Record<string, any>, TResponse>(
  requiredHeaders: (keyof THeaders)[],
  handler: (headers: THeaders, context: Context) => Promise<TResponse>
) {
  return new Handler<any, TResponse>()
    .use(new HeaderVariablesMiddleware(requiredHeaders as string[]))
    .handle(async (context) => {
      const headers = context.req.headers as THeaders;
      return await handler(headers, context);
    });
}

// Usage with specific header types
interface TenantHeaders {
  'x-tenant-id': string;
  'authorization': string;
  'x-client-id': string;
}

const tenantHandler = createHeaderValidatedHandler<TenantHeaders, TenantResponse>(
  ['x-tenant-id', 'authorization', 'x-client-id'],
  async (headers) => {
    const tenant = await getTenantById(headers['x-tenant-id']);
    const client = await getClientById(headers['x-client-id']);
    
    return {
      success: true,
      tenant,
      client,
      context: {
        tenantId: headers['x-tenant-id'],
        clientId: headers['x-client-id']
      }
    };
  }
);
```

### Advanced Generic Pattern

```typescript
// Type-safe header extraction with validation
interface HeaderValidationConfig<T> {
  required: (keyof T)[];
  optional?: (keyof T)[];
  validator?: (headers: T) => void;
}

function createAdvancedHeaderHandler<
  THeaders extends Record<string, any>,
  TResponse
>(
  config: HeaderValidationConfig<THeaders>,
  handler: (headers: Required<Pick<THeaders, keyof THeaders>>, context: Context) => Promise<TResponse>
) {
  return new Handler<any, TResponse>()
    .use(new HeaderVariablesMiddleware(config.required as string[]))
    .handle(async (context) => {
      const headers = context.req.headers as THeaders;
      
      // Run custom validation if provided
      if (config.validator) {
        config.validator(headers);
      }
      
      return await handler(headers as Required<Pick<THeaders, keyof THeaders>>, context);
    });
}

// Usage
interface ComplexHeaders {
  'authorization': string;
  'x-tenant-id': string;
  'content-type': string;
  'accept': string;
  'x-client-version'?: string;
}

const complexHandler = createAdvancedHeaderHandler<ComplexHeaders, ComplexResponse>({
  required: ['authorization', 'x-tenant-id', 'content-type'],
  optional: ['accept', 'x-client-version'],
  validator: (headers) => {
    if (headers['content-type'] && !headers['content-type'].includes('application/json')) {
      throw new ValidationError('Content-Type must be application/json');
    }
  }
}, async (headers, context) => {
  // Headers are validated and typed
  return await processComplexRequest(headers, context.req.body);
});
```

## Authentication Patterns

### Bearer Token Authentication

```typescript
interface BearerAuthHeaders {
  authorization: string;
}

const bearerAuthHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization']))
  .handle(async (context) => {
    const authHeader = context.req.headers.authorization as string;
    
    // Validate Bearer token format
    if (!authHeader.startsWith('Bearer ')) {
      throw new ValidationError('Authorization header must use Bearer token format');
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    // Validate token
    const decoded = await validateJWTToken(token);
    if (!decoded) {
      throw new AuthenticationError('Invalid or expired token');
    }
    
    // Store user context
    context.user = decoded;
    
    return { success: true, user: decoded, authenticated: true };
  });
```

### API Key Authentication

```typescript
interface APIKeyHeaders {
  'x-api-key': string;
  'x-client-id'?: string;
}

const apiKeyHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-api-key']))
  .handle(async (context) => {
    const headers = context.req.headers as APIKeyHeaders;
    
    const apiKey = headers['x-api-key'];
    const clientId = headers['x-client-id'];
    
    // Validate API key
    const keyData = await validateApiKey(apiKey);
    if (!keyData) {
      throw new AuthenticationError('Invalid API key');
    }
    
    // Check client ID if provided
    if (clientId && keyData.clientId !== clientId) {
      throw new AuthenticationError('API key does not match client ID');
    }
    
    // Check key permissions and rate limits
    const usage = await checkApiKeyUsage(apiKey);
    if (usage.exceeded) {
      throw new SecurityError('API key rate limit exceeded');
    }
    
    return {
      success: true,
      client: {
        id: keyData.clientId,
        name: keyData.clientName,
        tier: keyData.tier
      },
      usage: {
        current: usage.current,
        limit: usage.limit,
        resetTime: usage.resetTime
      }
    };
  });
```

### Multi-Factor Authentication Headers

```typescript
interface MFAHeaders {
  'authorization': string;
  'x-mfa-token': string;
  'x-device-id': string;
}

const mfaHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'x-mfa-token', 'x-device-id']))
  .handle(async (context) => {
    const headers = context.req.headers as MFAHeaders;
    
    // Primary authentication
    const primaryAuth = await validateBearerToken(headers.authorization);
    if (!primaryAuth.valid) {
      throw new AuthenticationError('Invalid primary authentication');
    }
    
    // MFA token validation
    const mfaValid = await validateMFAToken(
      headers['x-mfa-token'],
      primaryAuth.userId
    );
    if (!mfaValid) {
      throw new AuthenticationError('Invalid MFA token');
    }
    
    // Device verification
    const deviceValid = await verifyDevice(
      headers['x-device-id'],
      primaryAuth.userId
    );
    if (!deviceValid) {
      throw new SecurityError('Unrecognized device');
    }
    
    return {
      success: true,
      user: primaryAuth.user,
      mfa: { verified: true },
      device: { verified: true, id: headers['x-device-id'] }
    };
  });
```

## Content Negotiation

### Accept Headers Processing

```typescript
interface ContentHeaders {
  'accept': string;
  'accept-language': string;
  'accept-encoding': string;
  'content-type'?: string;
}

const contentNegotiationHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['accept', 'accept-language']))
  .handle(async (context) => {
    const headers = context.req.headers as ContentHeaders;
    
    // Parse accept header
    const acceptedTypes = parseAcceptHeader(headers.accept);
    const supportedTypes = ['application/json', 'application/xml', 'text/csv'];
    const contentType = negotiateContentType(acceptedTypes, supportedTypes);
    
    if (!contentType) {
      throw new ValidationError('Unsupported content type requested');
    }
    
    // Parse language preferences
    const acceptedLangs = parseAcceptLanguageHeader(headers['accept-language']);
    const supportedLangs = ['en', 'es', 'fr', 'de'];
    const language = negotiateLanguage(acceptedLangs, supportedLangs) || 'en';
    
    // Get localized data
    const data = await getLocalizedData(language);
    
    // Format response according to negotiated content type
    let formattedData;
    switch (contentType) {
      case 'application/json':
        formattedData = data;
        break;
      case 'application/xml':
        formattedData = convertToXML(data);
        break;
      case 'text/csv':
        formattedData = convertToCSV(data);
        break;
    }
    
    // Set response headers
    context.res.header('Content-Type', contentType);
    context.res.header('Content-Language', language);
    
    return {
      success: true,
      data: formattedData,
      negotiation: {
        contentType,
        language,
        encoding: headers['accept-encoding']
      }
    };
  });
```

### Custom Content Types

```typescript
interface CustomContentHeaders {
  'accept': string;
  'x-response-format': string;
  'x-api-version': string;
}

const customContentHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['accept', 'x-response-format', 'x-api-version']))
  .handle(async (context) => {
    const headers = context.req.headers as CustomContentHeaders;
    
    const responseFormat = headers['x-response-format'];
    const apiVersion = headers['x-api-version'];
    
    // Validate custom format
    const allowedFormats = ['standard', 'minimal', 'detailed', 'debug'];
    if (!allowedFormats.includes(responseFormat)) {
      throw new ValidationError(`Unsupported response format: ${responseFormat}`);
    }
    
    // Validate API version
    const supportedVersions = ['v1', 'v2', 'v3'];
    if (!supportedVersions.includes(apiVersion)) {
      throw new ValidationError(`Unsupported API version: ${apiVersion}`);
    }
    
    // Get data with version-specific handler
    const data = await getVersionedData(apiVersion, {
      format: responseFormat,
      includeMetadata: responseFormat === 'debug'
    });
    
    return {
      success: true,
      data,
      meta: {
        version: apiVersion,
        format: responseFormat,
        timestamp: new Date().toISOString()
      }
    };
  });
```

## Multi-Tenant Applications

### Tenant Identification

```typescript
interface TenantHeaders {
  'x-tenant-id': string;
  'authorization': string;
  'x-client-version'?: string;
}

const multiTenantHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-tenant-id', 'authorization']))
  .handle(async (context) => {
    const headers = context.req.headers as TenantHeaders;
    
    const tenantId = headers['x-tenant-id'];
    const clientVersion = headers['x-client-version'];
    
    // Validate tenant exists and is active
    const tenant = await getTenant(tenantId);
    if (!tenant || !tenant.active) {
      throw new ValidationError('Invalid or inactive tenant');
    }
    
    // Authenticate within tenant context
    const authResult = await authenticateInTenant(
      headers.authorization,
      tenantId
    );
    
    if (!authResult.valid) {
      throw new AuthenticationError('Authentication failed for tenant');
    }
    
    // Check client version compatibility
    if (clientVersion) {
      const compatibility = checkVersionCompatibility(clientVersion, tenant.supportedVersions);
      if (!compatibility.supported) {
        throw new ValidationError(`Client version ${clientVersion} not supported`);
      }
    }
    
    // Load tenant-specific configuration
    const tenantConfig = await getTenantConfiguration(tenantId);
    
    return {
      success: true,
      tenant: {
        id: tenantId,
        name: tenant.name,
        plan: tenant.plan
      },
      user: authResult.user,
      config: tenantConfig,
      client: {
        version: clientVersion,
        supported: !!clientVersion
      }
    };
  });
```

### Tenant-Scoped Operations

```typescript
interface TenantOperationHeaders {
  'x-tenant-id': string;
  'x-organization-id': string;
  'authorization': string;
  'x-operation-context'?: string;
}

const tenantOperationHandler = new Handler()
  .use(new HeaderVariablesMiddleware([
    'x-tenant-id', 
    'x-organization-id', 
    'authorization'
  ]))
  .handle(async (context) => {
    const headers = context.req.headers as TenantOperationHeaders;
    
    const tenantId = headers['x-tenant-id'];
    const orgId = headers['x-organization-id'];
    const operationContext = headers['x-operation-context'];
    
    // Validate tenant-organization relationship
    const orgBelongsToTenant = await validateOrganizationTenant(orgId, tenantId);
    if (!orgBelongsToTenant) {
      throw new SecurityError('Organization does not belong to specified tenant');
    }
    
    // Authenticate and authorize within organization
    const authResult = await authenticateInOrganization(
      headers.authorization,
      orgId,
      tenantId
    );
    
    // Check operation context permissions
    if (operationContext) {
      const hasPermission = await checkOperationPermission(
        authResult.user.id,
        operationContext,
        orgId
      );
      if (!hasPermission) {
        throw new SecurityError(`Insufficient permissions for context: ${operationContext}`);
      }
    }
    
    // Perform tenant-scoped operation
    const result = await performTenantScopedOperation({
      tenantId,
      organizationId: orgId,
      userId: authResult.user.id,
      context: operationContext,
      data: context.req.body
    });
    
    return {
      success: true,
      result,
      scope: {
        tenant: tenantId,
        organization: orgId,
        user: authResult.user.id,
        context: operationContext
      }
    };
  });
```

## Security Considerations

### Security Header Validation

```typescript
interface SecurityHeaders {
  'x-forwarded-for'?: string;
  'x-real-ip'?: string;
  'user-agent': string;
  'origin'?: string;
  'referer'?: string;
  'x-requested-with'?: string;
}

const securityAwareHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['user-agent']))
  .handle(async (context) => {
    const headers = context.req.headers as SecurityHeaders;
    
    // Validate user agent (basic bot detection)
    const userAgent = headers['user-agent'];
    if (!userAgent || userAgent.length < 10) {
      throw new SecurityError('Invalid or missing User-Agent header');
    }
    
    // Check for suspicious patterns
    const suspiciousPatterns = ['bot', 'crawler', 'spider', 'scraper'];
    const isSuspicious = suspiciousPatterns.some(pattern => 
      userAgent.toLowerCase().includes(pattern)
    );
    
    if (isSuspicious && !isAllowedBot(userAgent)) {
      throw new SecurityError('Automated requests not allowed');
    }
    
    // Validate origin for CORS
    const origin = headers.origin;
    if (origin && !isAllowedOrigin(origin)) {
      throw new SecurityError('Origin not allowed');
    }
    
    // Check for CSRF protection
    const requestedWith = headers['x-requested-with'];
    const isAjax = requestedWith === 'XMLHttpRequest';
    
    if (context.req.method !== 'GET' && !isAjax && !origin) {
      // Require either X-Requested-With or Origin for non-GET requests
      throw new SecurityError('CSRF protection: missing required headers');
    }
    
    // Extract real IP address
    const realIP = getRealIPAddress({
      xForwardedFor: headers['x-forwarded-for'],
      xRealIP: headers['x-real-ip'],
      remoteAddress: context.req.connection?.remoteAddress
    });
    
    // Rate limiting based on IP
    await checkRateLimit(realIP);
    
    return {
      success: true,
      security: {
        realIP,
        userAgent,
        origin,
        suspicious: isSuspicious,
        ajax: isAjax
      },
      message: 'Security validation passed'
    };
  });
```

### Webhook Security Headers

```typescript
interface WebhookSecurityHeaders {
  'x-webhook-signature': string;
  'x-webhook-timestamp': string;
  'x-webhook-id': string;
  'content-type': string;
  'user-agent'?: string;
}

const secureWebhookHandler = new Handler()
  .use(new HeaderVariablesMiddleware([
    'x-webhook-signature',
    'x-webhook-timestamp',
    'x-webhook-id',
    'content-type'
  ]))
  .handle(async (context) => {
    const headers = context.req.headers as WebhookSecurityHeaders;
    
    const signature = headers['x-webhook-signature'];
    const timestamp = headers['x-webhook-timestamp'];
    const webhookId = headers['x-webhook-id'];
    
    // Validate timestamp freshness (prevent replay attacks)
    const timestampMs = parseInt(timestamp) * 1000;
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    
    if (now - timestampMs > maxAge) {
      throw new SecurityError('Webhook timestamp too old - potential replay attack');
    }
    
    // Validate webhook signature
    const expectedSignature = await computeWebhookSignature(
      context.req.body,
      timestamp,
      process.env.WEBHOOK_SECRET!
    );
    
    if (!constantTimeStringCompare(signature, expectedSignature)) {
      throw new SecurityError('Invalid webhook signature');
    }
    
    // Check webhook ID for duplicate processing
    const alreadyProcessed = await checkWebhookIdProcessed(webhookId);
    if (alreadyProcessed) {
      return { success: true, message: 'Webhook already processed', duplicate: true };
    }
    
    // Mark webhook as processing
    await markWebhookProcessing(webhookId);
    
    try {
      // Process webhook payload
      const result = await processWebhookPayload(context.req.body);
      
      // Mark as successfully processed
      await markWebhookProcessed(webhookId, result);
      
      return {
        success: true,
        result,
        webhook: {
          id: webhookId,
          timestamp: new Date(timestampMs).toISOString(),
          processed: true
        }
      };
    } catch (error) {
      // Mark as failed for retry logic
      await markWebhookFailed(webhookId, error.message);
      throw error;
    }
  });

// Utility function for constant-time string comparison
function constantTimeStringCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
```

## Advanced Examples

### Dynamic Header Requirements

```typescript
interface DynamicHeaders {
  'x-api-version': string;
  'authorization'?: string;
  'x-api-key'?: string;
  'x-guest-token'?: string;
}

const dynamicHeaderHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-api-version'])) // Only version is always required
  .handle(async (context) => {
    const headers = context.req.headers as DynamicHeaders;
    
    const apiVersion = headers['x-api-version'];
    
    // Different auth requirements based on API version
    let authResult;
    switch (apiVersion) {
      case 'v1':
        // v1 requires API key
        if (!headers['x-api-key']) {
          throw new ValidationError('x-api-key header required for API v1');
        }
        authResult = await validateApiKey(headers['x-api-key']);
        break;
        
      case 'v2':
        // v2 requires either Bearer token or API key
        if (!headers.authorization && !headers['x-api-key']) {
          throw new ValidationError('Either authorization or x-api-key header required for API v2');
        }
        
        if (headers.authorization) {
          authResult = await validateBearerToken(headers.authorization);
        } else {
          authResult = await validateApiKey(headers['x-api-key']!);
        }
        break;
        
      case 'v3':
        // v3 allows guest access with token
        if (headers.authorization) {
          authResult = await validateBearerToken(headers.authorization);
        } else if (headers['x-guest-token']) {
          authResult = await validateGuestToken(headers['x-guest-token']);
        } else {
          throw new ValidationError('Authentication required for API v3');
        }
        break;
        
      default:
        throw new ValidationError(`Unsupported API version: ${apiVersion}`);
    }
    
    const data = await getVersionedData(apiVersion, authResult);
    
    return {
      success: true,
      data,
      auth: {
        type: authResult.type,
        version: apiVersion,
        user: authResult.user
      }
    };
  });
```

### Header-Based Feature Flags

```typescript
interface FeatureHeaders {
  'x-feature-flags'?: string;
  'x-client-id': string;
  'authorization': string;
}

const featureFlagHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-client-id', 'authorization']))
  .handle(async (context) => {
    const headers = context.req.headers as FeatureHeaders;
    
    // Parse feature flags from header
    const featureFlagsHeader = headers['x-feature-flags'];
    const requestedFeatures = featureFlagsHeader ? 
      featureFlagsHeader.split(',').map(f => f.trim()) : [];
    
    // Get client and user context
    const clientId = headers['x-client-id'];
    const user = await authenticateUser(headers.authorization);
    
    // Resolve feature flags
    const enabledFeatures = await resolveFeatureFlags({
      clientId,
      userId: user.id,
      requestedFeatures,
      userTier: user.tier,
      clientTier: await getClientTier(clientId)
    });
    
    // Get data with enabled features
    const data = await getDataWithFeatures(enabledFeatures);
    
    return {
      success: true,
      data,
      features: {
        requested: requestedFeatures,
        enabled: enabledFeatures,
        available: await getAvailableFeatures(user.tier)
      }
    };
  });
```

## Error Handling

### Comprehensive Error Patterns

```typescript
const robustHeaderHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type']))
  .handle(async (context) => {
    try {
      const headers = context.req.headers;
      
      // Additional header validation after middleware
      const contentType = headers['content-type'] as string;
      if (!contentType.includes('application/json')) {
        throw new ValidationError('Content-Type must be application/json');
      }
      
      const authorization = headers.authorization as string;
      if (!authorization.startsWith('Bearer ')) {
        throw new ValidationError('Authorization must use Bearer token format');
      }
      
      // Process request
      const result = await processRequest(headers, context.req.body);
      return { success: true, result };
      
    } catch (error) {
      if (error instanceof ValidationError) {
        return {
          success: false,
          error: error.message,
          code: 'HEADER_VALIDATION_ERROR',
          details: {
            receivedHeaders: Object.keys(context.req.headers),
            requiredHeaders: ['authorization', 'content-type']
          }
        };
      }
      
      throw error; // Re-throw unknown errors
    }
  });
```

### Missing Header Debugging

```typescript
const debuggingHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['x-debug-mode']))
  .handle(async (context) => {
    const debugMode = context.req.headers['x-debug-mode'] === 'true';
    
    if (debugMode) {
      // Detailed header information for debugging
      const headerAnalysis = analyzeHeaders(context.req.headers);
      
      return {
        success: true,
        debug: true,
        headers: {
          received: context.req.headers,
          analysis: headerAnalysis,
          recommendations: generateHeaderRecommendations(headerAnalysis)
        }
      };
    }
    
    // Normal processing
    return await processNormalRequest(context);
  });

function analyzeHeaders(headers: Record<string, any>) {
  return {
    count: Object.keys(headers).length,
    hasAuth: !!headers.authorization,
    hasContentType: !!headers['content-type'],
    hasUserAgent: !!headers['user-agent'],
    customHeaders: Object.keys(headers).filter(key => key.startsWith('x-')),
    securityHeaders: ['authorization', 'x-api-key', 'x-csrf-token']
      .filter(header => !!headers[header])
  };
}
```

## Performance Considerations

### Header Validation Efficiency

```typescript
// Good: Validate essential headers first, expensive operations last
const efficientHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization'])) // Fast header check
  .use(rateLimitingMiddleware()) // Quick rate limit check
  .use(expensiveAuthMiddleware) // Expensive token validation last
  .handle(async (context) => {
    // Business logic only runs if all validations pass
  });

// Avoid: Expensive operations before basic validations
const inefficientHandler = new Handler()
  .use(expensiveAuthMiddleware) // Expensive operation first
  .use(new HeaderVariablesMiddleware(['authorization'])) // Basic validation last
  .handle(async (context) => {
    // May do expensive work even for requests missing basic headers
  });
```

### Header Processing Optimization

```typescript
// Cache parsed header values for complex processing
const headerCache = new Map<string, any>();

const optimizedHeaderHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'x-complex-header']))
  .handle(async (context) => {
    const complexHeader = context.req.headers['x-complex-header'] as string;
    
    // Cache complex header parsing
    let parsedHeader = headerCache.get(complexHeader);
    if (!parsedHeader) {
      parsedHeader = parseComplexHeader(complexHeader);
      headerCache.set(complexHeader, parsedHeader);
      
      // Clean cache periodically
      if (headerCache.size > 1000) {
        headerCache.clear();
      }
    }
    
    return await processWithParsedHeader(parsedHeader);
  });
```

## Best Practices

### 1. Header Naming Conventions

```typescript
// Good: Consistent, descriptive header names
interface StandardHeaders {
  'authorization': string;           // Standard HTTP header
  'content-type': string;           // Standard HTTP header
  'x-api-key': string;              // Custom header with x- prefix
  'x-tenant-id': string;            // Custom business header
  'x-client-version': string;       // Custom versioning header
}

// Avoid: Inconsistent or unclear names
interface PoorHeaders {
  'auth': string;                   // Too short, not standard
  'key': string;                    // Too generic
  'tid': string;                    // Unclear abbreviation
}
```

### 2. Required vs Optional Headers

```typescript
// Good: Clear separation of required and optional headers
const wellStructuredHandler = new Handler()
  .use(new HeaderVariablesMiddleware(['authorization', 'content-type'])) // Always required
  .handle(async (context) => {
    const headers = context.req.headers;
    
    // Required headers are guaranteed to exist
    const auth = headers.authorization as string;
    const contentType = headers['content-type'] as string;
    
    // Optional headers handled explicitly
    const clientVersion = headers['x-client-version'] as string | undefined;
    const debugMode = headers['x-debug-mode'] === 'true';
    
    return await processRequest({ auth, contentType, clientVersion, debugMode });
  });
```

### 3. Security Best Practices

```typescript
// Good: Comprehensive security header validation
const secureHandler = new Handler()
  .use(new HeaderVariablesMiddleware([
    'authorization',
    'x-csrf-token',
    'x-request-id'
  ]))
  .handle(async (context) => {
    const headers = context.req.headers;
    
    // Validate auth token format
    const auth = headers.authorization as string;
    if (!auth.match(/^Bearer [A-Za-z0-9-._~+/]+=*$/)) {
      throw new SecurityError('Invalid authorization token format');
    }
    
    // Validate CSRF token
    const csrfToken = headers['x-csrf-token'] as string;
    if (!await validateCSRFToken(csrfToken, context.session)) {
      throw new SecurityError('Invalid CSRF token');
    }
    
    // Log security events
    logSecurityEvent('header_validation_passed', {
      requestId: headers['x-request-id'],
      userAgent: headers['user-agent'],
      ip: context.req.ip
    });
    
    return await processSecureRequest(headers);
  });
```

### 4. Error Messages and Documentation

```typescript
/**
 * Secure API Endpoint
 * 
 * Required Headers:
 * - Authorization: Bearer token (JWT format)
 * - Content-Type: application/json
 * - X-API-Key: Your API key from the dashboard
 * - X-Client-Version: Your client application version
 * 
 * Optional Headers:
 * - X-Request-ID: Unique identifier for request tracking
 * - X-Debug-Mode: Set to 'true' for debug information
 * 
 * Example:
 * ```
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Content-Type: application/json
 * X-API-Key: sk_live_1234567890abcdef
 * X-Client-Version: 2.1.0
 * ```
 */
const documentedHandler = new Handler()
  .use(new HeaderVariablesMiddleware([
    'authorization', 
    'content-type', 
    'x-api-key', 
    'x-client-version'
  ]))
  .handle(async (context) => {
    // Well-documented implementation with clear header expectations
    return await processDocumentedRequest(context);
  });
```

The HeaderVariablesMiddleware is essential for building secure, well-structured APIs that properly validate and utilize HTTP headers for authentication, content negotiation, and business logic requirements.