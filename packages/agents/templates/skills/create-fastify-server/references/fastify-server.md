# Resource: Complete Fastify Server Setup

## Minimal Server

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler } from '@noony-serverless/core';
import { createUserHandler } from './handlers';
import { initializeDependencies } from './core/initialization';

const server = Fastify({ logger: true });

// Initialize dependencies on server startup
server.addHook('onReady', async () => {
  await initializeDependencies();
});

// Register route
server.post('/api/users',
  createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve())
);

// Start server
server.listen({ port: 3000 }, (err, address) => {
  if (err) {
    server.log.error(err);
    process.exit(1);
  }
  server.log.info(`Server listening at ${address}`);
});
```

## Production-Ready Server with Graceful Shutdown

```typescript
// src/server.ts
import Fastify, { FastifyInstance } from 'fastify';
import { logger } from '@noony-serverless/core';
import { createFastifyHandler } from '@noony-serverless/core';
import {
  createUserHandler,
  getUserHandler,
  updateUserHandler,
  deleteUserHandler
} from './handlers';
import { initializeDependencies, cleanup } from './core/initialization';

// Create Fastify instance
const server = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    transport: {
      target: 'pino-pretty',
      options: { colorize: true }
    }
  }
});

// === Lifecycle Hooks ===

// Initialize on server startup
server.addHook('onReady', async () => {
  try {
    await initializeDependencies();
    server.log.info('[Server] Dependencies initialized');
  } catch (error) {
    server.log.error('[Server] Initialization failed', error);
    process.exit(1);
  }
});

// Health check endpoint (before init)
server.get('/health', async (request, reply) => {
  return { status: 'ok', uptime: process.uptime() };
});

// === Routes ===

// User CRUD routes
const createUser = createFastifyHandler(createUserHandler, 'createUser', () => Promise.resolve());
const getUser = createFastifyHandler(getUserHandler, 'getUser', () => Promise.resolve());
const updateUser = createFastifyHandler(updateUserHandler, 'updateUser', () => Promise.resolve());
const deleteUser = createFastifyHandler(deleteUserHandler, 'deleteUser', () => Promise.resolve());

server.post('/api/users', createUser);
server.get('/api/users/:userId', getUser);
server.patch('/api/users/:userId', updateUser);
server.delete('/api/users/:userId', deleteUser);

// === Error Handling ===

// Global error handler
server.setErrorHandler((error, request, reply) => {
  server.log.error(error);

  if (error.statusCode) {
    reply.status(error.statusCode).send({
      success: false,
      error: {
        code: error.code || 'ERROR',
        message: error.message
      }
    });
  } else {
    reply.status(500).send({
      success: false,
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected error occurred'
      }
    });
  }
});

// === Graceful Shutdown ===

const gracefulShutdown = async (signal: string) => {
  server.log.info(`[Server] ${signal} received, shutting down...`);

  try {
    // Close HTTP server
    await server.close();
    server.log.info('[Server] HTTP server closed');

    // Cleanup resources
    await cleanup();
    server.log.info('[Server] Cleanup complete');

    process.exit(0);
  } catch (error) {
    server.log.error('[Server] Error during shutdown', error);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// === Start Server ===

const start = async () => {
  try {
    await server.listen({ port: 3000, host: '0.0.0.0' });
    server.log.info('[Server] Fastify server started on http://0.0.0.0:3000');
  } catch (error) {
    server.log.error('[Server] Failed to start server', error);
    process.exit(1);
  }
};

start();

// Export for testing
export default server;
```

## package.json Scripts

```json
{
  "scripts": {
    "dev": "ts-node src/server.ts",
    "start": "node dist/server.js",
    "build": "tsc",
    "watch": "tsc --watch",
    "test": "jest",
    "test:coverage": "jest --coverage",
    "lint": "eslint src --ext .ts",
    "lint:fix": "eslint src --ext .ts --fix",
    "format": "prettier --write \"src/**/*.ts\""
  },
  "dependencies": {
    "@noony-serverless/core": "^0.8.0",
    "fastify": "^4.25.0",
    "pino": "^8.17.0",
    "pino-pretty": "^10.2.3"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.3.0",
    "ts-node": "^10.9.0",
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0"
  }
}
```

## Development Workflow

### 1. Start Server

```bash
npm run dev
# Output: [Server] Fastify server started on http://0.0.0.0:3000
```

### 2. Test Locally

```bash
# Create user
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com"}'

# Get user
curl http://localhost:3000/api/users/123

# Update user
curl -X PATCH http://localhost:3000/api/users/123 \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice Updated"}'

# Delete user
curl -X DELETE http://localhost:3000/api/users/123

# Health check
curl http://localhost:3000/health
```

### 3. Run Tests

```bash
npm test
npm run test:coverage
```

### 4. Build for Production

```bash
npm run build
# Outputs to dist/ directory
```

## Deployment (Cloud Run)

```bash
# 1. Build Docker image
gcloud builds submit --tag gcr.io/[PROJECT_ID]/noony-server

# 2. Deploy to Cloud Run
gcloud run deploy noony-server \
  --image gcr.io/[PROJECT_ID]/noony-server \
  --platform managed \
  --region us-central1 \
  --memory 512Mi \
  --timeout 60 \
  --set-env-vars LOG_LEVEL=info

# 3. Test deployed service
curl https://noony-server-xxxxx.run.app/health
```

## Troubleshooting

### Port Already in Use

```bash
# Find and kill process on port 3000
lsof -i :3000
kill -9 <PID>

# Or use different port
npm run dev -- --port 3001
```

### Dependencies Not Initialized

```
Error: Service not found in container
```

**Fix:** Ensure `server.addHook('onReady', async () => { await initializeDependencies(); })`

### Graceful Shutdown Not Working

```bash
# Test graceful shutdown
npm run dev
# In another terminal:
kill -SIGTERM <PID>

# Should see: [Server] SIGTERM received, shutting down...
# And exit cleanly
```

### EACCES Permission Denied on Port 3000

```bash
# Use port > 1024 or run with sudo
npm run dev -- --port 8080

# Or if on Linux:
sudo npm run dev
```
