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

## 🔧 Development Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start with hot reload |
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