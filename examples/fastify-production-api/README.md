# Fastify Production API - Noony Serverless Framework

A comprehensive, production-ready API example demonstrating advanced patterns with the Noony Serverless Framework. This example showcases **dual-mode development** where the same handlers work seamlessly in both Fastify (for development) and Google Cloud Functions (for production).

## 🎯 What This Example Demonstrates

### Advanced Framework Features
- ✅ **Dual-Mode Development**: Same code runs in Fastify and Google Cloud Functions
- ✅ **Complete CRUD API**: Full user management with advanced features
- ✅ **JWT Authentication**: Production-ready token-based authentication
- ✅ **Role-Based Authorization**: Granular permissions and access control
- ✅ **Advanced Validation**: Comprehensive input validation with Zod
- ✅ **Pagination & Filtering**: Efficient data querying with search capabilities
- ✅ **Performance Monitoring**: Request tracking and metrics collection
- ✅ **Audit Logging**: Security event tracking and compliance logging
- ✅ **Error Handling**: Comprehensive error management with proper HTTP codes

### Production Patterns
- ✅ **Service Layer Architecture**: Clean separation of business logic
- ✅ **Dependency Injection**: TypeDI for testable, modular code
- ✅ **Security Best Practices**: Password hashing, token management, rate limiting
- ✅ **Health Checks**: Monitoring endpoints for orchestrators and load balancers
- ✅ **Environment Configuration**: Flexible configuration management
- ✅ **Request/Response Adapters**: Framework-agnostic handler design
- ✅ **Development Tools**: Debug endpoints, metrics, and logging

### TypeScript Excellence
- ✅ **End-to-End Type Safety**: From API schemas to business logic
- ✅ **Schema-Driven Development**: Zod schemas generate TypeScript types
- ✅ **Generic Programming**: Type-safe middleware composition
- ✅ **Interface Segregation**: Clean service and repository patterns

## 🚀 Quick Start

### Prerequisites

- **Node.js** v18+ and npm v9+
- **Google Cloud SDK** (for GCP Functions deployment)
- **curl** or **Postman** (for API testing)

### 1. Installation

```bash
# Navigate to example directory
cd examples/fastify-production-api

# Install dependencies (includes Fastify, TypeDI, JWT, bcrypt, etc.)
npm install
```

### 2. Environment Setup

```bash
# Copy environment template with comprehensive configuration
cp .env.example .env

# Review and customize settings (optional - has production-ready defaults)
cat .env
```

**Key Environment Variables:**
- `JWT_SECRET`: Change this in production!
- `FASTIFY_PORT`: Fastify server port (default: 3000)
- `FUNCTIONS_PORT`: GCP Functions emulator port (default: 8080)
- `LOG_LEVEL`: Logging verbosity (debug, info, warn, error)

### 3. Choose Your Development Mode

#### Option A: Fastify Only (Fastest Development)
```bash
npm run dev:fastify
# Server: http://localhost:3000
# Hot reload, rich debugging, fastest iteration
```

#### Option B: GCP Functions Only (Production Parity)
```bash
npm run dev:functions
# Server: http://localhost:8080  
# Exact GCP Functions environment, slower but accurate
```

#### Option C: Both Simultaneously (Best of Both Worlds)
```bash
npm run dev:both
# Fastify: http://localhost:3000
# Functions: http://localhost:8080
# Compare behavior, comprehensive testing
```

### 4. Test the API

#### Get Authentication Token
```bash
# Login with demo user (check console logs for other users)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john.doe@example.com", "password": "password123"}'

# Save the token from response
export TOKEN="your-jwt-token-here"
```

#### Test CRUD Operations
```bash
# Create a new user (admin only)
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "age": 28,
    "department": "Design"
  }'

# List users with pagination and filtering
curl -X GET "http://localhost:3000/api/users?page=1&limit=5&search=john&department=Engineering" \
  -H "Authorization: Bearer $TOKEN"

# Get specific user
curl -X GET http://localhost:3000/api/users/user-id-here \
  -H "Authorization: Bearer $TOKEN"

# Update user
curl -X PUT http://localhost:3000/api/users/user-id-here \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "John Updated", "age": 31}'

# Health check (no auth required)
curl http://localhost:3000/health
```

## 📋 Complete API Documentation

### Base URL
- **Fastify Development**: `http://localhost:3000`
- **Functions Development**: `http://localhost:8080`
- **Production**: `https://your-function-url.cloudfunctions.net`

### Authentication

All `/api/*` endpoints require JWT authentication via `Authorization: Bearer <token>` header.

#### Demo Accounts

| Email | Password | Role | Permissions |
|-------|----------|------|-------------|
| `john.doe@example.com` | `password123` | `admin` | All permissions |
| `jane.smith@example.com` | `password123` | `user` | Read/update own profile |
| `bob.johnson@example.com` | `password123` | `user` | Read/update own profile |

### API Endpoints

#### 🔐 Authentication
- **POST** `/api/auth/login` - Authenticate user and get JWT token
- **POST** `/api/auth/logout` - Revoke JWT token
- **POST** `/api/auth/change-password` - Change user password

#### 👤 User Management

##### **POST** `/api/users` - Create User
**Permissions**: `user:create` or `admin:users`

```json
{
  "name": "John Doe",
  "email": "john@example.com", 
  "age": 30,
  "department": "Engineering",
  "phoneNumber": "+1-555-0123",
  "bio": "Software engineer with 5 years experience"
}
```

**Response**: `201 Created`
```json
{
  "success": true,
  "payload": {
    "id": "uuid",
    "user": { /* user object */ },
    "createdBy": { "userId": "uuid", "name": "Admin User" },
    "createdAt": "2024-01-15T10:30:45.123Z"
  },
  "timestamp": "2024-01-15T10:30:45.125Z"
}
```

##### **GET** `/api/users` - List Users
**Permissions**: `user:list` or `admin:users`

**Query Parameters**:
- `page` (number): Page number (default: 1)
- `limit` (number): Items per page (default: 10, max: 100)
- `search` (string): Search name, email, department, bio
- `department` (string): Filter by department
- `sortBy` (enum): Sort field - `name`, `email`, `age`, `department`, `createdAt`, `updatedAt`
- `sortOrder` (enum): `asc` or `desc` (default: `desc`)
- `minAge`, `maxAge` (number): Age range filtering
- `includeDeleted` (boolean): Include soft-deleted users (admin only)

**Response**: `200 OK`
```json
{
  "success": true,
  "payload": {
    "items": [{ /* user objects */ }],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 25,
      "totalPages": 3,
      "hasNextPage": true,
      "hasPreviousPage": false
    },
    "filters": {
      "search": "john",
      "department": "Engineering",
      "sortBy": "createdAt",
      "sortOrder": "desc"
    }
  }
}
```

##### **GET** `/api/users/:id` - Get User
**Permissions**: `user:read` or `admin:users` (users can always read own profile)

**Response**: `200 OK` with user object

##### **PUT** `/api/users/:id` - Update User  
**Permissions**: `user:update` or `admin:users` (users can update own profile)

**Request Body**: Partial user object (same as create, all fields optional)

##### **DELETE** `/api/users/:id` - Delete User
**Permissions**: `user:delete` or `admin:users`

**Response**: `204 No Content`

**Note**: Soft deletion only - data preserved for audit

#### 🏥 Health & Monitoring

##### **GET** `/health` - Basic Health Check
**Public endpoint** for load balancers

```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:45.123Z",
  "uptime": 86400.5,
  "version": "1.0.0",
  "environment": "development",
  "server": "fastify",
  "services": {
    "userService": "healthy",
    "authService": "healthy"
  }
}
```

##### **GET** `/health/ready` - Readiness Probe
For Kubernetes and orchestrators

##### **GET** `/health/live` - Liveness Probe  
For Kubernetes pod restart decisions

#### 🛠 Development Endpoints (Development Only)

##### **GET** `/dev/info` - Server Information
Development configuration and route information

##### **GET** `/dev/metrics` - Service Metrics
Performance metrics and service statistics

### Error Responses

All errors follow consistent format:

```json
{
  "success": false,
  "payload": {
    "error": "Human-readable error message",
    "code": "MACHINE_READABLE_CODE",
    "details": [
      {
        "field": "fieldName",
        "message": "Field-specific error",
        "value": "invalid-value"
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:45.123Z"
}
```

**Common Error Codes**:
- `400` - Validation errors, malformed requests
- `401` - Authentication required or invalid
- `403` - Insufficient permissions
- `404` - Resource not found
- `409` - Conflict (e.g., email already exists)
- `429` - Rate limit exceeded
- `500` - Internal server error

## 🏗 Architecture Deep Dive

### Project Structure

```
fastify-production-api/
├── src/
│   ├── handlers/           # HTTP request handlers
│   │   ├── user.handlers.ts      # User CRUD operations
│   │   └── auth.handlers.ts      # Authentication endpoints
│   ├── services/           # Business logic layer
│   │   ├── user.service.ts       # User management service
│   │   └── auth.service.ts       # Authentication service
│   ├── types/             # TypeScript definitions
│   │   ├── api.types.ts          # API request/response types
│   │   └── domain.types.ts       # Business domain types
│   ├── middleware/         # Custom middleware
│   │   └── custom.middleware.ts  # Application-specific middleware
│   ├── utils/             # Utility functions
│   │   └── validation.utils.ts   # Validation helpers
│   ├── server.ts          # Fastify server setup
│   └── index.ts           # GCP Functions exports
├── docs/                  # Additional documentation
├── tests/                 # Test files
├── package.json           # Dependencies and scripts
├── tsconfig.json          # TypeScript configuration
├── .env.example           # Environment variables template
└── README.md             # This file
```

### Middleware Pipeline

Each handler uses a carefully ordered middleware pipeline:

```
Request → Error Handler → Auth → Authorization → Validation → Audit → Business Logic → Response Wrapper
```

1. **ErrorHandlerMiddleware**: Global error catching and formatting
2. **AuthenticationMiddleware**: JWT token verification  
3. **Authorization**: Role/permission checking
4. **BodyValidationMiddleware**: Zod schema validation
5. **AuditLoggingMiddleware**: Security and performance tracking
6. **ResponseWrapperMiddleware**: Consistent response formatting

### Service Layer Architecture

- **Handlers**: HTTP concerns, request/response processing
- **Services**: Business logic, validation, orchestration
- **Repositories**: Data access (simulated with in-memory storage)
- **Types**: Shared interfaces and data structures

### Security Model

#### Authentication
- JWT tokens with configurable expiration
- Secure password hashing with bcrypt
- Token blacklisting for secure logout
- Session tracking and management

#### Authorization  
- Role-based access control (RBAC)
- Granular permissions system
- Resource-level authorization
- Self-service capabilities (users can update own profiles)

#### Security Headers & Measures
- CORS configuration for cross-origin requests
- Request size limiting
- Rate limiting (configurable)
- Input validation and sanitization
- SQL injection prevention (parameterized queries)
- XSS prevention (output encoding)

## ⚙️ Configuration & Deployment

### Environment Variables

**Core Settings**:
```bash
NODE_ENV=development|staging|production
LOG_LEVEL=debug|info|warn|error
DEBUG=true|false
```

**Server Configuration**:
```bash
FASTIFY_PORT=3000              # Fastify development port
FUNCTIONS_PORT=8080            # GCP Functions emulator port
FASTIFY_HOST=0.0.0.0          # Bind address
```

**Security Configuration**:
```bash
JWT_SECRET=your-secret-key     # JWT signing secret (CHANGE IN PRODUCTION!)
JWT_EXPIRES_IN=24h             # Token expiration
BCRYPT_ROUNDS=12               # Password hashing rounds
RATE_LIMIT_MAX=100             # Requests per minute
```

**API Configuration**:
```bash
API_VERSION=v1                 # API version
API_PREFIX=/api/v1            # URL prefix
DEFAULT_PAGE_SIZE=10           # Pagination default
MAX_PAGE_SIZE=100             # Pagination maximum
```

### Production Deployment

#### Google Cloud Functions
```bash
# Build the project
npm run build

# Deploy individual functions
npm run deploy:functions

# Or deploy manually with custom settings
gcloud functions deploy createUser \
  --runtime nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 512MB \
  --timeout 60s \
  --set-env-vars="NODE_ENV=production,JWT_SECRET=your-production-secret"
```

#### Google Cloud Run (Containerized)
```bash
# Deploy Fastify server to Cloud Run
npm run deploy:run

# Or manually
gcloud run deploy fastify-api \
  --source . \
  --port 3000 \
  --allow-unauthenticated \
  --memory 1Gi \
  --set-env-vars="NODE_ENV=production"
```

#### Docker Deployment
```bash
# Build Docker image
docker build -t fastify-production-api .

# Run container
docker run -p 3000:3000 \
  -e NODE_ENV=production \
  -e JWT_SECRET=your-production-secret \
  fastify-production-api
```

### Performance Optimization

**Development**:
- Hot reload with nodemon
- Source map support
- Pretty printed logs
- Debug endpoints enabled

**Production**:
- Compiled TypeScript
- Minified output
- Structured JSON logging  
- Health checks enabled
- Security headers enforced

## 🧪 Testing & Development

### Running Tests
```bash
# Unit tests
npm test

# Watch mode for development
npm run test:watch

# Coverage report
npm run test:coverage

# End-to-end tests
npm run test:e2e
```

### Development Workflow

1. **Start Development Server**:
   ```bash
   npm run dev:fastify  # Fast development
   # or
   npm run dev:both     # Compare both modes
   ```

2. **Test API Endpoints**:
   - Use provided curl examples
   - Import Postman collection (if available)
   - Check `/dev/info` for route information

3. **Monitor Performance**:
   - Check `/dev/metrics` for service statistics
   - Review console logs for request timing
   - Monitor memory usage in development

4. **Validate Production Parity**:
   ```bash
   npm run dev:functions  # Test GCP Functions mode
   # Compare responses with Fastify mode
   ```

### Testing Scenarios

#### Authentication Flow
```bash
# 1. Login
curl -X POST http://localhost:3000/api/auth/login \
  -d '{"email":"john.doe@example.com","password":"password123"}'

# 2. Use token for authenticated requests
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/users

# 3. Test token expiration
# Wait for token to expire or logout
```

#### CRUD Operations
```bash
# Create → Read → Update → Delete flow
# Test with various user roles and permissions
# Verify authorization boundaries
```

#### Error Scenarios
```bash
# Invalid data
curl -X POST http://localhost:3000/api/users -d '{"invalid":"data"}'

# Missing authentication
curl http://localhost:3000/api/users

# Insufficient permissions
# Login as regular user, try admin operations
```

## 📊 Monitoring & Observability

### Built-in Metrics

The application provides comprehensive metrics:

**Authentication Metrics**:
- Login attempts (successful/failed)
- Token generation/revocation counts
- Password change events
- Session statistics

**User Service Metrics**:
- CRUD operation counts
- Query performance
- Data validation errors
- Business rule violations

**Performance Metrics**:
- Request processing time
- Memory usage tracking
- Error rates by endpoint
- Concurrent user sessions

### Health Checks

**Basic Health** (`/health`):
- Service status
- Uptime information
- Component health
- Basic metrics

**Readiness** (`/health/ready`):
- Database connectivity
- External service availability
- Configuration validation

**Liveness** (`/health/live`):
- Process health
- Memory constraints
- Error recovery status

### Logging

**Development Logging**:
- Pretty-printed console output
- Request/response details
- Debug information
- Performance timing

**Production Logging**:
- Structured JSON logs
- Security event tracking
- Error aggregation
- Audit trail maintenance

## 🔒 Security Considerations

### Authentication Security
- Strong JWT secrets (minimum 32 characters)
- Configurable token expiration
- Token revocation on logout
- Session tracking and limits

### Password Security
- bcrypt with configurable rounds (12+ recommended)
- Password complexity requirements
- Secure password reset (not implemented in demo)
- Account lockout policies (not implemented in demo)

### API Security
- Input validation on all endpoints
- SQL injection prevention
- XSS protection through output encoding
- CSRF protection (stateless JWT)
- Rate limiting to prevent abuse

### Deployment Security
- Environment variable security
- Secrets management (use Google Secret Manager in production)
- Network security (VPC, firewalls)
- Access logging and monitoring

## 🎓 Learning Progression

After mastering this example:

1. **Database Integration**: Replace in-memory storage with PostgreSQL/MongoDB
2. **Caching Layer**: Add Redis for performance optimization
3. **Message Queues**: Integrate with Pub/Sub for async processing
4. **Real-time Features**: Add WebSocket support with Socket.io
5. **Advanced Auth**: Implement OAuth, 2FA, password reset
6. **Monitoring**: Integrate with Datadog, New Relic, or Google Cloud Monitoring
7. **Testing**: Add comprehensive unit, integration, and E2E tests
8. **CI/CD**: Set up automated deployment pipelines

## 🤝 Contributing

Found an issue or want to improve this example?

1. Check existing [issues](../../issues)
2. Create new issue with `fastify-example` label
3. Submit pull request with improvements

## 📚 Additional Resources

- [Noony Framework Documentation](../../README.md)
- [Fastify Documentation](https://www.fastify.io/)
- [Google Cloud Functions](https://cloud.google.com/functions)
- [TypeDI Documentation](https://github.com/typestack/typedi)
- [Zod Schema Validation](https://zod.dev/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Ready to build production APIs?** 🚀 This example provides a solid foundation for building scalable, secure, and maintainable serverless APIs with the Noony framework!