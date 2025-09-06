# RUN_LOCALLY.md

# Noony Serverless Framework - Local Development Guide

This guide provides comprehensive instructions for setting up and running the Noony Serverless Framework locally, including the production-ready Fastify example that demonstrates dual-mode development (Fastify + Google Cloud Functions).

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Development Commands Explained](#development-commands-explained)
- [Dual-Mode Development Architecture](#dual-mode-development-architecture)
- [Local Testing & API Usage](#local-testing--api-usage)
- [Project Structure](#project-structure)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## 🔧 Prerequisites

Before starting, ensure you have the following installed:

### Required Software
- **Node.js** v18.0.0 or higher (v20+ recommended)
- **npm** v9+ or **yarn** v1.22+
- **Git** for version control

### Optional (For Production Deployment)
- **Google Cloud SDK** (`gcloud` CLI) - [Installation Guide](https://cloud.google.com/sdk/docs/install)
- **Docker** (for containerized deployments)
- **curl** or **Postman** (for API testing)

### Verify Installation
```bash
# Check Node.js version (should be v18+)
node --version

# Check npm version
npm --version

# Check Google Cloud SDK (optional)
gcloud --version
```

## 🚀 Quick Start

### 1. Clone and Setup the Main Framework

```bash
# Clone the repository
git clone https://github.com/noony-serverless/noony-core.git
cd noony-core

# Install dependencies for the main framework
npm install

# Build the framework
npm run build

# Run tests to verify everything works
npm test
```

### 2. Setup the Production API Example

```bash
# Navigate to the example directory
cd examples/fastify-production-api

# Install example dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Build the example
npm run build
```

### 3. Choose Your Development Mode

#### Option A: Fastify Only (Recommended for Development)
```bash
npm run dev:fastify
```
- **Server**: http://localhost:3000
- **Hot reload**: ✅ Enabled
- **Debug capabilities**: ✅ Full Node.js debugging
- **Speed**: ⚡ Fastest iteration cycle

#### Option B: GCP Functions Only (Production Parity)
```bash
npm run dev:functions
```
- **Server**: http://localhost:8080
- **Environment**: 🎯 Exact GCP Functions runtime
- **Speed**: 🐌 Slower but production-accurate

#### Option C: Both Simultaneously (Best Testing)
```bash
npm run dev:both
```
- **Fastify**: http://localhost:3000
- **Functions**: http://localhost:8080
- **Use case**: 🔄 Compare behavior between modes

## 📝 Development Commands Explained

### Core Framework Commands (Run from project root)
```bash
# Build the framework
npm run build                # Compile TypeScript to build/ directory

# Development
npm run watch               # Continuous TypeScript compilation
npm run test                # Run all Jest tests
npm run test:coverage       # Run tests with coverage report

# Code Quality
npm run lint                # ESLint check for TypeScript files
npm run lint:fix            # ESLint with auto-fix
npm run format              # Prettier formatting
npm run format:check        # Check formatting without fixing
```

### Example API Commands (Run from examples/fastify-production-api/)

#### Development Servers
```bash
npm run dev:fastify         # Fast development with Fastify server
npm run dev:functions       # GCP Functions emulator (createUser endpoint)
npm run dev:both           # Run both servers simultaneously

# Individual Function Testing
npm run dev:functions:createUser    # Test createUser function
npm run dev:functions:getUser       # Test getUser function  
npm run dev:functions:listUsers     # Test listUsers function
npm run dev:functions:health        # Test health function
```

#### Production Commands
```bash
npm run build              # Compile TypeScript to dist/
npm run start              # Start production Fastify server
npm run start:functions    # Start all functions in production mode
```

#### Testing & Quality
```bash
npm run test               # Run unit tests
npm run test:watch         # Watch mode for development
npm run test:coverage      # Coverage report
npm run test:e2e          # End-to-end integration tests

npm run lint              # Check code quality
npm run format            # Format code with Prettier
```

## 🏗 Dual-Mode Development Architecture

The Noony Framework supports **dual-mode development** where the same handlers work seamlessly in both Fastify (development) and Google Cloud Functions (production).

### How It Works

#### 1. Framework-Agnostic Handlers
```typescript
// Same handler works in both environments
const handler = new Handler<RequestType, UserType>()
  .use(new ErrorHandlerMiddleware())
  .use(new AuthenticationMiddleware())
  .use(new BodyValidationMiddleware(schema))
  .handle(async (context) => {
    // Business logic here
    return { success: true, data: result };
  });
```

#### 2. Fastify Integration (Development)
```typescript
// src/server.ts - Fastify adapter
fastify.post('/api/users', async (request, reply) => {
  await executeHandler(createUserHandler, request, reply);
});
```

#### 3. Google Cloud Functions Integration (Production)
```typescript
// src/createUser.ts - GCP Functions wrapper
export const createUser = http('createUser', (req, res) => {
  return createUserHandler.execute(req, res);
});
```

### Benefits of Dual-Mode Development

| Aspect | Fastify Mode | Functions Mode |
|--------|-------------|----------------|
| **Speed** | ⚡ Instant hot reload | 🐌 Slower, cold starts |
| **Debugging** | 🔍 Full Node.js debugger | ⚠️ Limited debugging |
| **Environment** | 🛠️ Development optimized | 🎯 Production identical |
| **Testing** | 💨 Rapid iteration | ✅ Production validation |
| **Use Case** | Daily development | Pre-deployment testing |

## 🧪 Local Testing & API Usage

### Authentication Setup

All `/api/*` endpoints require JWT authentication. Use the demo accounts:

```bash
# Login to get authentication token
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john.doe@example.com", "password": "password123"}'

# Save the token for subsequent requests
export TOKEN="your-jwt-token-here"
```

### Demo User Accounts

| Email | Password | Role | Permissions |
|-------|----------|------|-------------|
| `john.doe@example.com` | `password123` | `admin` | Full access to all endpoints |
| `jane.smith@example.com` | `password123` | `user` | Read/update own profile |
| `bob.johnson@example.com` | `password123` | `user` | Read/update own profile |

### API Testing Examples

#### User Management
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
curl -X GET "http://localhost:3000/api/users?page=1&limit=5&search=john" \
  -H "Authorization: Bearer $TOKEN"

# Get specific user
curl -X GET http://localhost:3000/api/users/user-id-here \
  -H "Authorization: Bearer $TOKEN"

# Update user
curl -X PUT http://localhost:3000/api/users/user-id-here \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name": "John Updated", "age": 31}'

# Delete user (soft delete)
curl -X DELETE http://localhost:3000/api/users/user-id-here \
  -H "Authorization: Bearer $TOKEN"
```

#### Health & Monitoring
```bash
# Basic health check (no auth required)
curl http://localhost:3000/health

# Readiness probe (Kubernetes)
curl http://localhost:3000/health/ready

# Liveness probe (Kubernetes)
curl http://localhost:3000/health/live

# Development endpoints (development mode only)
curl http://localhost:3000/dev/info
curl http://localhost:3000/dev/metrics
```

### Testing Different Modes

#### Compare Fastify vs Functions Mode
```bash
# Start both servers
npm run dev:both

# Test same endpoint in both modes
curl http://localhost:3000/api/users -H "Authorization: Bearer $TOKEN"  # Fastify
curl http://localhost:8080 -H "Authorization: Bearer $TOKEN"           # Functions

# Both should return identical responses
```

#### Guard System Testing
```bash
# Run automated guard system tests
./test-guards.sh

# Or specify custom base URL
./test-guards.sh http://localhost:3000
```

## 📁 Project Structure

### Main Framework Structure
```
noony-core/
├── src/
│   ├── core/                    # Core framework components
│   │   ├── handler.ts          # Main Handler class and middleware pipeline
│   │   ├── core.ts             # Context interfaces and types
│   │   └── errors.ts           # Built-in error classes
│   ├── middlewares/            # Built-in middleware implementations
│   │   ├── errorHandlerMiddleware.ts
│   │   ├── authenticationMiddleware.ts
│   │   ├── bodyValidationMiddleware.ts
│   │   └── ...
│   └── index.ts                # Main framework exports
├── examples/
│   └── fastify-production-api/ # Production-ready example
└── package.json                # Framework dependencies and scripts
```

### Example API Structure
```
examples/fastify-production-api/
├── src/
│   ├── handlers/               # HTTP request handlers
│   │   └── user.handlers.ts    # User CRUD operations
│   ├── services/               # Business logic layer
│   │   ├── user.service.ts     # User management service
│   │   └── auth.service.ts     # Authentication service
│   ├── types/                  # TypeScript definitions
│   │   ├── api.types.ts        # API request/response types
│   │   └── domain.types.ts     # Business domain types
│   ├── server.ts               # Fastify server setup
│   ├── createUser.ts           # GCP Function: Create user
│   ├── getUser.ts              # GCP Function: Get user
│   ├── listUsers.ts            # GCP Function: List users
│   └── health.ts               # GCP Function: Health check
├── .env.example                # Environment variables template
├── tsconfig.json               # TypeScript configuration
└── package.json                # Example dependencies and scripts
```

### Key Files Explained

#### Framework Files
- **`src/core/handler.ts`**: Core Handler class with middleware pipeline
- **`src/core/core.ts`**: Context interfaces and framework-agnostic types
- **`src/middlewares/`**: Built-in middleware for common patterns

#### Example Files
- **`src/server.ts`**: Fastify server that runs Noony handlers
- **`src/createUser.ts`**: Google Cloud Function wrapper for user creation
- **`src/handlers/user.handlers.ts`**: Business logic handlers
- **`src/services/user.service.ts`**: Service layer with business rules

## 🌐 Production Deployment

### Google Cloud Functions Deployment

#### Individual Function Deployment
```bash
# Build the project first
npm run build

# Deploy individual functions
gcloud functions deploy createUser \
  --runtime nodejs22 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 512MB \
  --timeout 60s \
  --set-env-vars="NODE_ENV=production,JWT_SECRET=your-production-secret"

gcloud functions deploy getUser \
  --runtime nodejs22 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 256MB

gcloud functions deploy listUsers \
  --runtime nodejs22 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 512MB

gcloud functions deploy health \
  --runtime nodejs22 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 128MB
```

#### Bulk Deployment (using npm script)
```bash
npm run deploy:functions
```

### Google Cloud Run Deployment

#### Deploy Fastify Server as Container
```bash
# Deploy using source code (recommended)
gcloud run deploy fastify-api \
  --source . \
  --port 3000 \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 1000m \
  --min-instances 0 \
  --max-instances 100 \
  --set-env-vars="NODE_ENV=production,JWT_SECRET=your-production-secret"

# Or use the npm script
npm run deploy:run
```

#### Using Dockerfile (Alternative)
```dockerfile
# Create Dockerfile in example directory
FROM node:22-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port
EXPOSE 3000

# Start application
CMD ["node", "dist/server.js"]
```

```bash
# Build and deploy with Docker
docker build -t gcr.io/PROJECT_ID/fastify-api .
docker push gcr.io/PROJECT_ID/fastify-api

gcloud run deploy fastify-api \
  --image gcr.io/PROJECT_ID/fastify-api \
  --platform managed \
  --allow-unauthenticated
```

### Environment Configuration for Production

#### Required Environment Variables
```bash
# Security (CRITICAL - Change in production!)
JWT_SECRET=your-super-secure-jwt-secret-min-32-chars
BCRYPT_ROUNDS=12

# Application
NODE_ENV=production
LOG_LEVEL=warn

# Server Configuration
FASTIFY_PORT=3000
FASTIFY_HOST=0.0.0.0

# API Settings
RATE_LIMIT_MAX=1000
DEFAULT_PAGE_SIZE=10
MAX_PAGE_SIZE=100

# Production Features
ENABLE_SECURITY_HEADERS=true
ENABLE_COMPRESSION=true
PRETTY_PRINT_LOGS=false
```

#### Google Cloud Configuration
```bash
# Set default project and region
gcloud config set project YOUR_PROJECT_ID
gcloud config set functions/region us-central1
gcloud config set run/region us-central1

# Enable required APIs
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### Deployment Best Practices

#### Cloud Functions
- **Use Node.js 22 runtime** (latest LTS)
- **Set appropriate memory limits** (128MB-1GB based on function complexity)
- **Configure timeout values** (30s-540s based on processing needs)
- **Use environment variables** for configuration
- **Enable IAM authentication** for production APIs

#### Cloud Run
- **Use multi-stage Docker builds** for smaller image size
- **Set CPU and memory limits** based on load testing
- **Configure autoscaling** (min/max instances)
- **Use Cloud Load Balancer** for high availability
- **Enable Cloud Monitoring** for observability

## 🚨 Troubleshooting

### Common Issues

#### 1. TypeScript Build Errors
```bash
# Clear build cache
rm -rf dist/ node_modules/
npm install
npm run build
```

#### 2. Port Already in Use
```bash
# Find and kill process using port 3000
lsof -ti:3000 | xargs kill -9

# Or use different port
FASTIFY_PORT=3001 npm run dev:fastify
```

#### 3. Authentication Issues
```bash
# Verify JWT token is valid
echo $TOKEN | base64 -d

# Check token expiration
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/users
```

#### 4. GCP Functions Deployment Errors
```bash
# Check Google Cloud authentication
gcloud auth list
gcloud config list

# Verify project and API enablement
gcloud services list --enabled
```

#### 5. TypeScript Path Resolution
```bash
# If imports fail, check tsconfig.json paths
npm install tsc-alias  # For production builds
```

### Debug Mode

#### Enable Debug Logging
```bash
# Set environment variables for verbose logging
export DEBUG=true
export LOG_LEVEL=debug

# Run with debug output
npm run dev:fastify
```

#### Function-specific Debugging
```bash
# Debug individual Cloud Functions
functions-framework --target=createUser --source=dist --debug
```

### Performance Issues

#### Memory Usage
```bash
# Monitor memory usage
curl http://localhost:3000/dev/metrics

# Check Node.js memory flags
node --max-old-space-size=4096 dist/server.js
```

#### Database Connections (If Using Real DB)
```bash
# Check connection pooling
# Implement connection health checks
# Monitor database performance metrics
```

### Getting Help

- **Framework Issues**: [GitHub Issues](https://github.com/noony-serverless/noony-core/issues)
- **Google Cloud Support**: [Cloud Console Support](https://cloud.google.com/support)
- **Community**: Check README.md for community links

---

## 🎉 You're Ready!

You should now have:
- ✅ Noony Framework running locally
- ✅ Fastify development server operational
- ✅ Google Cloud Functions emulator working
- ✅ Understanding of dual-mode development
- ✅ Knowledge of production deployment options

Start building your serverless APIs with the Noony Framework! 🚀