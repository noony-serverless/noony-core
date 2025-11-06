# Hello World with Noony Guards - Examples

This directory contains examples showing how to integrate the **Noony Guard System** into a simple serverless function, progressing from basic usage to advanced guard configurations.

## 📁 Example Files

### 1. `src/index.ts` - Original Hello World

The original hello world example without guards - demonstrates basic Noony middleware usage.

### 2. `src/index-with-guards.ts` - Hello World with Guards

Enhanced version with the Noony Guard System integration, demonstrating:

- Plain permission strategy
- JWT authentication with caching
- Performance monitoring
- Multiple demo endpoints

## 🚀 Quick Start

### Prerequisites

```bash
npm install @noony-serverless/core
```

### Run the Guard-Enhanced Examples

```bash
# Start development server
npm run dev

# In another terminal, test the endpoints
./test-guards.sh
```

## 🛡️ Guard System Features Demonstrated

### 1. **Plain Permission Strategy**

- **Performance**: O(1) Set-based lookups (~0.1ms cached)
- **Use Case**: High-frequency operations requiring basic authorization
- **Example**: `greeting:create OR user:hello` permissions

### 2. **Authentication Integration**

- **JWT Token Verification**: Demo token format with user lookup
- **User Context Caching**: Sub-millisecond subsequent requests
- **Token Format**: `demo-{userId}` (e.g., `demo-user123`)

### 3. **Performance Monitoring**

- **Real-time Metrics**: Cache hit rates, authentication times
- **Development Logging**: Detailed performance insights
- **Production Optimization**: Minimal overhead logging

## 🧪 Demo Endpoints

| Endpoint | Auth Required | Permissions | Description |
|----------|---------------|-------------|-------------|
| `GET /systemStatus` | ❌ No | None | Guard system metrics and demo info |
| `POST /authTest` | ✅ Yes | None | Authentication test (any valid user) |
| `POST /guardedHelloWorld` | ✅ Yes | `greeting:create` OR `user:hello` | Protected greeting endpoint |

## 👥 Demo Users & Permissions

The example includes three mock users for testing:

### user123 (John Doe)

- **Token**: `demo-user123`
- **Permissions**: `greeting:create`, `user:profile`
- **Access**: Can use guardedHelloWorld endpoint

### admin456 (Jane Admin)

- **Token**: `demo-admin456`
- **Permissions**: `greeting:create`, `user:hello`, `admin:system`
- **Access**: Full access to all endpoints

### demo789 (Demo User)

- **Token**: `demo-demo789`
- **Permissions**: `user:hello`
- **Access**: Can use guardedHelloWorld endpoint (different permission)

## 📋 Testing Guide

### 1. System Status (No Authentication)
```bash
curl http://localhost:8080/systemStatus
```

**Expected Response:**
```json
{
  "success": true,
  "payload": {
    "guardSystem": {
      "configuration": { ... },
      "performance": { ... },
      "availableUsers": ["user123", "admin456", "demo789"]
    },
    "example": {
      "demoTokens": [...],
      "curlExample": "..."
    }
  }
}
```

### 2. Authentication Test
```bash
curl -X POST http://localhost:8080/authTest \
  -H "Authorization: Bearer demo-user123"
```

**Expected Response:**
```json
{
  "success": true,
  "payload": {
    "authenticated": true,
    "user": {
      "userId": "user123",
      "name": "John Doe",
      "permissions": ["greeting:create", "user:profile"],
      "roles": ["user"]
    }
  }
}
```

### 3. Protected Greeting Endpoint
```bash
curl -X POST http://localhost:8080/guardedHelloWorld \
  -H "Authorization: Bearer demo-user123" \
  -H "Content-Type: application/json" \
  -d '{"name": "Developer", "greeting": "Hello"}'
```

**Expected Response:**
```json
{
  "success": true,
  "payload": {
    "message": "Hello, Developer!",
    "userId": "user123",
    "permissions": ["greeting:create", "user:profile"],
    "timestamp": "2024-01-15T10:30:45.123Z"
  }
}
```

### 4. Test Different Users

#### Admin User (Multiple Permissions)
```bash
curl -X POST http://localhost:8080/guardedHelloWorld \
  -H "Authorization: Bearer demo-admin456" \
  -H "Content-Type: application/json" \
  -d '{"name": "Admin User"}'
```

#### Demo User (Different Permission)
```bash
curl -X POST http://localhost:8080/guardedHelloWorld \
  -H "Authorization: Bearer demo-demo789" \
  -H "Content-Type: application/json" \
  -d '{"name": "Demo User"}'
```

### 5. Test Authorization Failures

#### Invalid Token
```bash
curl -X POST http://localhost:8080/guardedHelloWorld \
  -H "Authorization: Bearer invalid-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test"}'
```

**Expected Response:** `401 Unauthorized`

#### Missing Authorization Header
```bash
curl -X POST http://localhost:8080/guardedHelloWorld \
  -H "Content-Type: application/json" \
  -d '{"name": "Test"}'
```

**Expected Response:** `401 Unauthorized`

#### User Without Required Permissions
Create a new mock user in the code with different permissions to test authorization failures.

## 📊 Performance Monitoring

When running in development mode, watch the console for guard system metrics:

```bash
🛡️ Guard System Performance: {
  authCacheHitRate: 95.5,
  userContextCacheHitRate: 98.2,
  averageAuthTime: '0.08ms',
  totalCacheEntries: 3
}
```

### Performance Expectations

| Metric | First Request | Cached Request |
|--------|---------------|----------------|
| Authentication | ~50-100ms | ~0.1ms |
| Permission Check | ~1-2ms | ~0.05ms |
| Total Guard Overhead | ~60ms | ~0.2ms |

## 🔧 Configuration Options

### Development vs Production

The example automatically configures guards based on `NODE_ENV`:

#### Development Configuration
- **Cache TTL**: 5 minutes
- **Cache Size**: 500 entries  
- **Logging**: Detailed performance metrics
- **Invalidation**: Less conservative for faster iteration

#### Production Configuration  
- **Cache TTL**: 15 minutes
- **Cache Size**: 2000 entries
- **Logging**: Essential metrics only
- **Invalidation**: Conservative security-first approach

### Environment Variables

```bash
# Set environment
export NODE_ENV=development  # or production

# Enable debug logging
export DEBUG=true

# Custom configuration
export GUARD_CACHE_TTL=300000  # 5 minutes in ms
export GUARD_MAX_ENTRIES=1000
```

## 🎯 Key Learning Points

### 1. **Guard Integration Patterns**
- Guards integrate seamlessly into existing middleware pipelines
- Place guards after error handling but before business logic
- Authentication and authorization happen in a single middleware

### 2. **Performance Optimization**
- First request includes authentication overhead
- Subsequent requests are sub-millisecond due to caching
- Monitor cache hit rates to optimize TTL settings

### 3. **Security Considerations**
- Conservative cache invalidation ensures immediate permission revocation
- JWT tokens are verified on every request (with caching)
- User context is refreshed based on TTL settings

### 4. **Error Handling**
- Guards throw standard HTTP errors (401, 403)
- ErrorHandlerMiddleware provides consistent error formatting
- Development mode includes detailed error information

## 🚀 Next Steps

1. **Explore Advanced Examples**: Check out the `fastify-production-api` example for:
   - Wildcard permissions (`admin.*`, `user.profile.*`)
   - Expression permissions with boolean logic
   - Redis cache integration
   - Production deployment patterns

2. **Custom Token Verification**: Replace the demo token verifier with:
   - Real JWT library integration
   - Database user lookups
   - External authentication services

3. **Permission Management**: Implement:
   - Dynamic permission assignment
   - Role-based permission inheritance
   - Permission caching strategies

4. **Monitoring Integration**: Add:
   - Metrics collection (Prometheus/DataDog)
   - Performance alerting
   - Cache hit rate monitoring

## 🔗 Related Documentation

- [Noony Guard System Documentation](../fastify-production-api/GUARD_SYSTEM_DEMO.md)
- [Production API Examples](../fastify-production-api/)
- [Core Framework Documentation](../../README.md)