# Noony Guard System - Production API Demo

This example demonstrates the **Noony Guard System**, a high-performance authentication and authorization middleware designed for serverless environments. The system provides sub-millisecond cached permission checks with three distinct resolution strategies.

## 🚀 Key Features Demonstrated

### High-Performance Caching
- **L1 Memory Cache**: LRU-based caching with configurable TTL
- **Conservative Invalidation**: Security-first cache invalidation strategy
- **Sub-millisecond Response**: Cached permission checks in <1ms
- **Serverless Optimized**: Cold start performance optimization

### Three Permission Resolution Strategies

#### 1. **Plain Permissions** (O(1) Set Lookups)
```typescript
// Used in: createUser, updateUser handlers
routeGuards.requirePlainPermissions(
  ['user:create', 'admin:users'], // OR logic
  { tokenVerifier }
)
```
- **Performance**: ~0.1ms per check (cached)
- **Memory Usage**: Low
- **Best For**: High-frequency CRUD operations
- **Use Cases**: Basic permission checks, common operations

#### 2. **Wildcard Permissions** (Pattern Matching)
```typescript
// Used in: getUser, deleteUser handlers
routeGuards.requireWildcardPermissions(
  ['admin.*', 'user.profile.*'], // Hierarchical patterns
  { tokenVerifier }
)
```
- **Performance**: ~0.2ms per check (pre-expanded)
- **Memory Usage**: Medium
- **Best For**: Role-based hierarchical permissions
- **Use Cases**: Admin operations, department-based access

#### 3. **Expression Permissions** (Boolean Logic)
```typescript
// Used in: listUsers handler
routeGuards.requireExpressionPermissions(
  '(admin.users AND admin.read) OR (user.list AND user.department)',
  { tokenVerifier }
)
```
- **Performance**: ~0.5ms per check (cached parsing)
- **Memory Usage**: Medium
- **Best For**: Complex business rules
- **Use Cases**: Fine-grained access control, conditional permissions

## 📊 Performance Characteristics

| Strategy | Avg Response Time | Memory Usage | Cache Strategy | Best Use Case |
|----------|------------------|--------------|----------------|---------------|
| Plain | ~0.1ms | Low | Set-based lookup | High-frequency ops |
| Wildcard | ~0.2ms | Medium | Pattern expansion | Hierarchical roles |
| Expression | ~0.5ms | Medium | AST parsing cache | Complex rules |

## 🛡️ Security Features

### Conservative Cache Invalidation
- **Immediate Revocation**: Permission changes flush ALL related caches
- **Security First**: Trades performance for maximum security
- **Configurable**: Less conservative in development environments
- **Audit Trail**: All permission changes are logged

### Authentication Integration
- **JWT Token Verification**: Seamless integration with existing auth systems
- **User Context Caching**: Authenticated user data cached for performance
- **Token Validation**: Configurable token verification with caching

## 🔧 Configuration Options

### Production Configuration
```typescript
const guardConfig = GuardConfiguration.fromEnvironmentProfile(
  GuardSetup.production()
);
```

**Settings:**
- **Strategy**: Pre-expansion for maximum runtime performance
- **Cache TTL**: 15 minutes for optimal memory usage
- **Cache Size**: 2000 entries maximum
- **Invalidation**: Conservative (security-first)
- **Monitoring**: Performance tracking enabled

### Development Configuration
```typescript
const guardConfig = GuardConfiguration.fromEnvironmentProfile(
  GuardSetup.development()
);
```

**Settings:**
- **Strategy**: On-demand matching for memory efficiency
- **Cache TTL**: 5 minutes for faster development cycles
- **Cache Size**: 500 entries maximum
- **Invalidation**: Less conservative for faster iteration
- **Monitoring**: Detailed logging enabled

## 📈 Monitoring and Metrics

### System Statistics
```typescript
const stats = routeGuards.getSystemStats();
console.log({
  cacheHitRate: stats.userContextService.cacheHitRate,
  averageAuthTime: stats.authentication.averageTokenVerificationTime,
  permissionCheckTimes: stats.userContextService.averagePermissionCheckTime,
  cacheMemoryUsage: stats.userContextService.cacheMemoryUsage
});
```

### Handler-Specific Metrics
Each handler exports metadata about its guard strategy:
```typescript
import { userHandlersMetadata, getGuardSystemMetrics } from './handlers/user.handlers';

// Get comprehensive system metrics
const metrics = getGuardSystemMetrics();
console.log(metrics);
```

## 🚦 API Endpoints with Guard Strategies

### POST `/api/users` - Create User
- **Strategy**: Plain Permissions
- **Permissions**: `user:create OR admin:users`
- **Performance**: Optimized for high-frequency operations
- **Use Case**: User registration, bulk user creation

### GET `/api/users/:id` - Get User
- **Strategy**: Wildcard Permissions  
- **Permissions**: `admin.* OR user.profile.*`
- **Performance**: Pattern matching with pre-expansion
- **Use Case**: Profile viewing, user lookup

### GET `/api/users` - List Users
- **Strategy**: Expression Permissions
- **Permissions**: `(admin.users AND admin.read) OR (user.list AND user.department)`
- **Performance**: Complex boolean evaluation
- **Use Case**: User management dashboards, reporting

### PUT `/api/users/:id` - Update User
- **Strategy**: Plain Permissions
- **Permissions**: `user:update OR admin:users`
- **Performance**: Maximum performance for frequent updates
- **Use Case**: Profile updates, user management

### DELETE `/api/users/:id` - Delete User
- **Strategy**: Wildcard Permissions
- **Permissions**: `admin.* OR system.users.*`
- **Performance**: Administrative operation optimization
- **Use Case**: User deactivation, administrative cleanup

## 🎯 Best Practices Demonstrated

### 1. Strategy Selection
- **80/20 Rule**: Use Plain permissions for 80% of endpoints
- **Hierarchy**: Use Wildcard for role-based systems
- **Complexity**: Use Expressions only when necessary

### 2. Performance Optimization
- **Cache Warming**: Pre-populate caches during initialization
- **Conservative TTLs**: Balance performance with security
- **Monitoring**: Track cache hit rates (target >95%)

### 3. Security Considerations
- **Principle of Least Privilege**: Grant minimum required permissions
- **Immediate Revocation**: Conservative cache invalidation
- **Audit Logging**: Comprehensive permission check logging

## 🔄 Migration from Custom Authorization

The example shows migration from custom authorization middleware:

### Before (Custom Middleware)
```typescript
.use(createAuthorizationMiddleware(['user:create', 'admin:users']))
```

### After (Guard System)
```typescript
.use(routeGuards.requirePlainPermissions(
  ['user:create', 'admin:users'],
  { tokenVerifier }
))
```

**Benefits of Migration:**
- **10x Performance**: Sub-millisecond cached checks
- **Better Security**: Conservative cache invalidation
- **Monitoring**: Built-in performance metrics
- **Flexibility**: Three distinct resolution strategies
- **Maintainability**: Centralized permission management

## 📚 Learning Path

1. **Start Simple**: Begin with Plain permissions for basic CRUD
2. **Add Hierarchy**: Introduce Wildcard patterns for roles
3. **Complex Rules**: Use Expressions for advanced business logic
4. **Monitor Performance**: Track metrics and optimize cache settings
5. **Scale Gradually**: Adjust configuration based on usage patterns

## 🚀 Getting Started

1. **Install Dependencies**:
   ```bash
   npm install @noony-serverless/core
   ```

2. **Initialize Guard System**:
   ```typescript
   import { RouteGuards, GuardSetup } from '@noony-serverless/core';
   
   const guardConfig = GuardConfiguration.fromEnvironmentProfile(
     GuardSetup.production()
   );
   const routeGuards = new RouteGuards(guardConfig);
   ```

3. **Integrate with Handlers**:
   ```typescript
   .use(routeGuards.requirePlainPermissions(['your:permission'], { tokenVerifier }))
   ```

4. **Monitor Performance**:
   ```typescript
   const stats = routeGuards.getSystemStats();
   ```

This production-ready example demonstrates how to build scalable, secure, and high-performance APIs using the Noony Guard System.