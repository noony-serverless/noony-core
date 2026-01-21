# Hello World Simple - Noony Serverless Framework

A comprehensive example demonstrating the fundamental concepts and best practices of the Noony Serverless Framework. This example serves as both a learning tool and a starter template for building type-safe serverless functions with Google Cloud Functions.

## 🎯 What You'll Learn

This example teaches the core concepts of the Noony framework through a simple yet complete implementation:

### Framework Fundamentals
- ✅ **Handler & Middleware Pattern**: Composable middleware pipeline
- ✅ **Type Safety**: End-to-end TypeScript with Zod validation
- ✅ **Error Handling**: Comprehensive error management with proper HTTP codes
- ✅ **Request Validation**: Schema-driven input validation and sanitization
- ✅ **Response Formatting**: Standardized API response structure

### Production Patterns
- ✅ **Environment Configuration**: Environment-based settings with defaults
- ✅ **Request Tracking**: Unique request IDs for debugging and monitoring
- ✅ **Performance Monitoring**: Request timing and metrics collection
- ✅ **Business Logic Separation**: Clean separation of concerns
- ✅ **Custom Validation**: Beyond schema validation with business rules

### Development Experience
- ✅ **Local Development**: Functions Framework for local testing
- ✅ **Hot Reload**: Automatic restart on code changes
- ✅ **Comprehensive Documentation**: Inline and README documentation
- ✅ **Testing Ready**: Structure prepared for unit and integration tests

## 🚀 Quick Start

### Prerequisites

- **Node.js** v18+ and npm v9+
- **Google Cloud SDK** (for deployment)
- Basic TypeScript knowledge

### 1. Installation

```bash
# Navigate to example directory
cd examples/hello-world-simple

# Install dependencies
npm install
```

### 2. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your preferences (optional - has sensible defaults)
```

### 3. Development

```bash
# Start the Functions Framework with hot reload
npm run dev

# Function available at: http://localhost:8080
```

### 4. Test the API

```bash
# Basic greeting
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"name": "World"}'

# Custom greeting
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "greeting": "Hi", "includeTimestamp": false}'
```

## 📋 API Documentation

### Endpoint: `POST /`

Creates a personalized greeting message with optional customization.

#### Request Body

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | ✅ Yes | - | Name to greet (1-100 chars) |
| `greeting` | string | ❌ Optional | "Hello" | Greeting prefix (max 50 chars) |
| `includeTimestamp` | boolean | ❌ Optional | `true` | Include response timestamp |
| `language` | string | ❌ Optional | - | 2-letter ISO language code |

#### Example Request

```json
{
  "name": "Developer",
  "greeting": "Welcome",
  "includeTimestamp": true,
  "language": "en"
}
```

#### Success Response (200 OK)

```json
{
  "success": true,
  "payload": {
    "message": "Welcome, Developer!",
    "timestamp": "2024-01-15T10:30:45.123Z",
    "requestId": "req_abc123def456",
    "language": "en"
  },
  "timestamp": "2024-01-15T10:30:45.125Z"
}
```

#### Error Response (400 Bad Request)

```json
{
  "success": false,
  "payload": {
    "error": "Validation failed",
    "details": [
      {
        "field": "name",
        "message": "Name must be at least 1 character long"
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:45.125Z"
}
```

## 🏗 Architecture Overview

### Middleware Pipeline

The handler uses a carefully ordered middleware pipeline:

```
Request → ErrorHandler → BodyValidation → BusinessValidation → ResponseWrapper → Handler
                                                                                    ↓
Response ← Performance ← ResponseWrapper ← BusinessValidation ← BodyValidation ← ErrorHandler
```

#### Middleware Details

1. **ErrorHandlerMiddleware** (First)
   - Catches all errors from subsequent middleware
   - Formats errors with proper HTTP status codes
   - Provides development vs production error details

2. **BodyValidationMiddleware**
   - Validates request against Zod schema
   - Provides type-safe `validatedBody` on context
   - Automatic error responses for validation failures

3. **Custom Business Validation**
   - Applies business-specific rules
   - Demonstrates custom middleware creation
   - Generates request tracking IDs

4. **ResponseWrapperMiddleware** (Before Handler)
   - Ensures consistent response format
   - Adds success/timestamp fields
   - Handles both success and error responses

5. **Performance Monitoring** (After Handler)
   - Tracks request timing and metrics
   - Logs performance data for optimization
   - Alerts on slow requests

### File Structure

```
hello-world-simple/
├── src/
│   ├── index.ts          # Main handler with comprehensive docs
│   └── types.ts          # TypeScript type definitions
├── docs/                 # Additional documentation
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── .env.example          # Environment variables template
└── README.md            # This file
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Application environment |
| `LOG_LEVEL` | `info` | Logging verbosity |
| `PORT` | `8080` | Functions Framework port |
| `DEBUG` | `false` | Enable debug logging |
| `DEFAULT_GREETING` | `Hello` | Default greeting prefix |
| `ENABLE_REQUEST_ID` | `false` | Generate request IDs |

### Development Configuration

The example includes comprehensive configuration for development:

- **TypeScript**: Strict mode with exact optional properties
- **ESLint**: Code quality and formatting rules
- **Prettier**: Consistent code formatting
- **Jest**: Testing framework setup (tests not included)

## 🧪 Testing Scenarios

### Valid Requests

```bash
# Minimal request
curl -X POST http://localhost:8080 -H "Content-Type: application/json" -d '{"name": "Test"}'

# Full request with all options
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"name": "Alice", "greeting": "Bonjour", "includeTimestamp": true, "language": "fr"}'

# Request without timestamp
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"name": "Bob", "includeTimestamp": false}'
```

### Error Scenarios

```bash
# Missing required field
curl -X POST http://localhost:8080 -H "Content-Type: application/json" -d '{}'

# Invalid data types
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"name": 123, "includeTimestamp": "yes"}'

# String too long
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"name": "'$(printf 'a%.0s' {1..101})'"}'

# Unsupported language
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"name": "Test", "language": "xyz"}'

# Inappropriate name (business rule)
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"name": "admin"}'
```

## 🚀 Deployment

### Local Development

```bash
# Development with hot reload
npm run dev

# Build TypeScript
npm run build

# Run compiled version
npm start
```

### Google Cloud Functions

```bash
# Deploy to GCP (requires gcloud CLI setup)
npm run deploy

# Deploy with custom settings
gcloud functions deploy helloWorld \
  --runtime nodejs18 \
  --trigger-http \
  --allow-unauthenticated \
  --memory 256MB \
  --timeout 60s \
  --source .
```

### Environment Setup for Deployment

1. **Install Google Cloud SDK**:
   ```bash
   # Follow instructions at: https://cloud.google.com/sdk/docs/install
   ```

2. **Authenticate and configure**:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

3. **Enable required APIs**:
   ```bash
   gcloud services enable cloudfunctions.googleapis.com
   gcloud services enable cloudbuild.googleapis.com
   ```

## ⚡ Fastify Integration for Local Development

The Noony framework supports **framework-agnostic handlers** that work with both Google Cloud Functions (production) and Fastify (local development). Using Fastify for local development provides ~2x faster startup and iteration compared to the Cloud Functions emulator.

### Why Fastify?

- **Faster Development**: ~2x faster than Cloud Functions emulator
- **Same Handler Code**: Write once, run in both environments
- **Production-Grade**: Fastify is a high-performance HTTP framework
- **Type-Safe**: Full TypeScript support maintained
- **Zero Changes**: Handler code requires no modifications

### Adding Fastify to Your Project

#### 1. Install Fastify

```bash
npm install fastify
```

#### 2. Create Fastify Server

Create a new file [src/server.ts](src/server.ts):

```typescript
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { helloWorldHandler } from './index';

// Initialize Fastify server
const server = Fastify({
  logger: {
    level: 'info',
    transport: {
      target: 'pino-pretty',
      options: {
        translateTime: 'HH:MM:ss Z',
        ignore: 'pid,hostname',
      },
    },
  },
});

// Dependency initialization (singleton pattern)
let initialized = false;
async function initializeDependencies(): Promise<void> {
  if (initialized) return;

  // Initialize your services here (database, external APIs, etc.)
  console.log('🚀 Dependencies initialized');
  initialized = true;
}

// Shorthand helper for creating Fastify handlers
const adapt = (handler: any, name: string) =>
  createFastifyHandler(handler, name, initializeDependencies);

// Register routes with the same handler used in Cloud Functions
server.post('/helloWorld', adapt(helloWorldHandler, 'helloWorld'));

// Health check endpoint
server.get('/health', async (request, reply) => {
  reply.send({ status: 'ok', timestamp: new Date().toISOString() });
});

// Graceful shutdown
const shutdown = async () => {
  console.log('🛑 Shutting down server...');
  await server.close();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start server
const start = async () => {
  try {
    const port = process.env.PORT ? parseInt(process.env.PORT) : 3000;
    const host = process.env.HOST || '0.0.0.0';

    await server.listen({ port, host });
    console.log(`✨ Fastify server running on http://${host}:${port}`);
    console.log(`📝 POST http://localhost:${port}/helloWorld - Hello World endpoint`);
    console.log(`🏥 GET  http://localhost:${port}/health - Health check`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();
```

#### 3. Update package.json Scripts

Add a new script to [package.json](package.json):

```json
{
  "scripts": {
    "dev": "functions-framework --target=helloWorld --port=8080",
    "dev:fastify": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "npm run build && functions-framework --target=helloWorld --port=8080",
    "deploy": "gcloud functions deploy helloWorld --runtime nodejs18 --trigger-http --allow-unauthenticated"
  },
  "devDependencies": {
    "tsx": "^4.7.0"
  }
}
```

#### 4. Run with Fastify

```bash
# Start Fastify server with hot reload
npm run dev:fastify

# Server available at: http://localhost:3000
```

#### 5. Test the Same Endpoint

```bash
# Test with Fastify (port 3000)
curl -X POST http://localhost:3000/helloWorld \
  -H "Content-Type: application/json" \
  -d '{"name": "Fastify"}'

# Test with Cloud Functions Framework (port 8080)
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"name": "Cloud Functions"}'
```

### How It Works: Framework-Agnostic Pattern

The same `helloWorldHandler` works in both environments through Noony's **Generic Approach**:

```typescript
// src/index.ts - Handler Definition (UNCHANGED!)
export const helloWorldHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .use(new BodyParserMiddleware())
  .use(new BodyValidationMiddleware(helloWorldSchema))
  .use({ before: validateBusinessRules })
  .use(new ResponseWrapperMiddleware())
  .use({ after: performanceMonitoring })
  .handle(async (context: Context) => {
    // Business logic here
  });

// Entry Point 1: Cloud Functions (Production)
export const helloWorld = http('helloWorld', async (req, res) => {
  await helloWorldHandler.execute(req, res);  // Built-in adapter
});

// Entry Point 2: Fastify (Local Development)
server.post('/helloWorld',
  createFastifyHandler(helloWorldHandler, 'helloWorld', initializeDependencies)
);
```

### Architecture: Adapter Flow

```
Fastify Request → adaptFastifyRequest() → GenericRequest
                                              ↓
                                       Handler.executeGeneric()
                                              ↓
                                       GenericResponse
                                              ↓
Fastify Reply   ← adaptFastifyResponse() ← GenericResponse
```

### Benefits of Dual-Entry Pattern

| Feature | Cloud Functions | Fastify |
|---------|----------------|---------|
| **Development Speed** | ~3-5s cold start | ~1-2s startup |
| **Hot Reload** | ✅ Supported | ✅ Supported |
| **Production Deploy** | ✅ Native | ❌ N/A |
| **Type Safety** | ✅ Full | ✅ Full |
| **Handler Code** | Same code | Same code |
| **Testing** | Functions Framework | Real HTTP server |

### Path Parameters with Fastify

Fastify supports dynamic route parameters seamlessly:

```typescript
// Handler that uses path parameters
const getUserHandler = new Handler()
  .use(new ErrorHandlerMiddleware())
  .handle(async (context) => {
    const userId = context.req.params.userId;  // Type-safe access
    const user = await getUserService(userId);
    context.res.json({ data: user });
  });

// Register with Fastify path syntax
server.get('/users/:userId', adapt(getUserHandler, 'getUser'));

// Test: curl http://localhost:3000/users/123
```

### Multiple Routes Example

```typescript
// Register multiple endpoints
server.post('/helloWorld', adapt(helloWorldHandler, 'helloWorld'));
server.get('/users/:userId', adapt(getUserHandler, 'getUser'));
server.post('/users', adapt(createUserHandler, 'createUser'));
server.patch('/users/:userId', adapt(updateUserHandler, 'updateUser'));
server.delete('/users/:userId', adapt(deleteUserHandler, 'deleteUser'));
```

### Development Workflow

**Recommended workflow for new features:**

1. **Develop with Fastify**: Use `npm run dev:fastify` for fast iteration
2. **Test locally**: Exercise all endpoints with curl/Postman
3. **Switch to Cloud Functions**: Use `npm run dev` to verify GCP compatibility
4. **Deploy**: Use `npm run deploy` to push to production

### Troubleshooting

**Port already in use:**
```bash
# Change port in src/server.ts or set environment variable
PORT=3001 npm run dev:fastify
```

**TypeScript errors:**
```bash
# Ensure fastify is installed
npm install fastify

# Check TypeScript version
npm install -D typescript@latest
```

**Handler not found:**
- Ensure you're exporting `helloWorldHandler` from [src/index.ts](src/index.ts)
- Check import path in [src/server.ts](src/server.ts)

### Additional Resources

- [Fastify Documentation](https://www.fastify.io/)
- [Noony Framework-Agnostic Patterns](../../docs/NOONY_SKILLS.md)
- [Complete Fastify Example](../fastify-production-api/)

## 🔧 Development Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start with Cloud Functions Framework (port 8080) |
| `npm run dev:fastify` | Start with Fastify for faster local dev (port 3000) |
| `npm run build` | Compile TypeScript |
| `npm start` | Run compiled version |
| `npm run deploy` | Deploy to GCP |
| `npm run lint` | Run ESLint |
| `npm run format` | Format with Prettier |
| `npm test` | Run tests (when added) |

## 📊 Performance Considerations

### Optimization Features

- **Request ID Generation**: Optional and lightweight
- **Timestamp Inclusion**: Configurable per request
- **Performance Monitoring**: Development-only by default
- **Memory Efficient**: Minimal object creation in hot path

### Monitoring

The example includes built-in performance monitoring:

- Request processing time tracking
- Memory usage monitoring (development)
- Slow request alerting
- Request correlation IDs for debugging

## 🎓 Learning Progression

After mastering this example, explore:

1. **[Fastify Production API](../fastify-production-api/)**: Advanced patterns with authentication, CRUD operations, and dual-mode development

2. **Custom Middleware**: Create your own middleware following the patterns shown

3. **Testing**: Add unit and integration tests using the provided Jest setup

4. **Monitoring**: Integrate with Google Cloud Monitoring or other observability tools

## 🤝 Contributing

Found an issue or want to improve this example?

1. Check the [main project issues](../../issues)
2. Create a new issue with the `example` label
3. Submit a pull request with improvements

## 📚 Additional Resources

- [Noony Framework Documentation](../../README.md)
- [Google Cloud Functions Documentation](https://cloud.google.com/functions/docs)
- [Zod Schema Validation](https://zod.dev/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)

---

**Ready to try it?** Start with `npm run dev` and explore the comprehensive logging output to understand the middleware execution flow!