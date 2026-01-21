# Skill 6: Complete Dual-Entry Example

## Triggers

When user asks to:
- "Show me a complete example"
- "How do I use both Fastify and Cloud Functions?"
- "Write once, deploy anywhere"
- "Support both local and production"
- "Full integration example"
- "End-to-end setup"

## What it provides

Complete end-to-end example showing the same Noony handler working in both Fastify (local development) and Cloud Functions (production) with zero code changes.

## Complete Example

### 1. Handler Definition

```typescript
// src/handlers/product.handlers.ts
import { z } from 'zod';
import {
  Handler,
  Context,
  ErrorHandlerMiddleware,
  AuthenticationMiddleware,
  BodyValidationMiddleware,
  ResponseWrapperMiddleware,
  NotFoundError,
} from '@noony-serverless/core';

// Zod schema for request validation
const createProductSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().optional(),
  price: z.number().positive(),
  category: z.string().min(1),
  stock: z.number().int().min(0).default(0),
});

type CreateProductRequest = z.infer<typeof createProductSchema>;

interface AuthenticatedUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

/**
 * Create Product Handler
 * Works with BOTH Fastify and Cloud Functions without changes!
 */
export const createProductHandler = new Handler<
  CreateProductRequest,
  AuthenticatedUser
>()
  .use(new ErrorHandlerMiddleware<CreateProductRequest, AuthenticatedUser>())
  .use(new AuthenticationMiddleware(tokenVerifier))
  .use(new BodyValidationMiddleware(createProductSchema))
  .use(new ResponseWrapperMiddleware())
  .handle(async (context: Context<CreateProductRequest, AuthenticatedUser>) => {
    const { name, description, price, category, stock } = context.req.validatedBody!;
    const user = context.user!;

    // Permission check
    if (user.role !== 'admin') {
      throw new ForbiddenError('Only admins can create products');
    }

    const product = await productService.create({
      name,
      description,
      price,
      category,
      stock,
      createdBy: user.id,
    });

    context.res.status(201).json({ data: product });
  });

export const getProductHandler = new Handler<void, void>()
  .use(new ErrorHandlerMiddleware<void, void>())
  .handle(async (context: Context<void, void>) => {
    const productId = context.req.params.productId;

    const product = await productService.getById(productId);
    if (!product) {
      throw new NotFoundError('Product not found');
    }

    context.res.status(200).json({ data: product });
  });
```

### 2. Fastify Server (Local Development)

```typescript
// src/server.ts
import Fastify from 'fastify';
import { createFastifyHandler, logger } from '@noony-serverless/core';
import { initializeDependencies, cleanup } from './core/initialization';
import {
  createProductHandler,
  getProductHandler,
} from './handlers/product.handlers';

const server = Fastify({
  logger: true,
  requestIdLogLabel: 'reqId',
});

// Helper shorthand
const adapt = (handler, name) =>
  createFastifyHandler(handler, name, initializeDependencies);

// Register routes
server.post('/api/products', adapt(createProductHandler, 'createProduct'));
server.get('/api/products/:productId', adapt(getProductHandler, 'getProduct'));

// Health check
server.get('/health', async (request, reply) => {
  reply.send({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
const PORT = Number(process.env.PORT) || 3000;
server.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) {
    logger.error('[Server] Failed to start', { error: err.message });
    process.exit(1);
  }
  logger.info(`[Server] Listening at ${address}`);
});

// Graceful shutdown
const shutdown = async () => {
  await server.close();
  await cleanup();
  process.exit(0);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
```

### 3. Cloud Functions (Production)

```typescript
// src/functions.ts
import { http } from '@google-cloud/functions-framework';
import { initializeDependencies } from './core/initialization';
import {
  createProductHandler,
  getProductHandler,
} from './handlers/product.handlers';

/**
 * Create Product Cloud Function
 * POST /createProduct
 */
export const createProduct = http('createProduct', async (req, res) => {
  await initializeDependencies();
  await createProductHandler.execute(req, res);
});

/**
 * Get Product Cloud Function
 * GET /getProduct
 */
export const getProduct = http('getProduct', async (req, res) => {
  await initializeDependencies();
  await getProductHandler.execute(req, res);
});
```

### 4. Package.json Scripts

```json
{
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "deploy:dev": "gcloud functions deploy --gen2 --runtime=nodejs20 --region=us-central1 --source=. --env-vars-file=.env.dev.yaml",
    "deploy:prod": "gcloud functions deploy --gen2 --runtime=nodejs20 --region=us-central1 --source=. --env-vars-file=.env.prod.yaml",
    "test:local": "curl -X POST http://localhost:3000/api/products -H 'Content-Type: application/json' -d '{\"name\":\"Test Product\",\"price\":29.99,\"category\":\"electronics\"}'",
    "test:prod": "curl -X POST https://us-central1-myproject.cloudfunctions.net/createProduct -H 'Content-Type: application/json' -d '{\"name\":\"Test Product\",\"price\":29.99,\"category\":\"electronics\"}'"
  }
}
```

### 5. Testing Workflow

```bash
# Local development with Fastify
npm run dev

# Test locally
curl -X POST http://localhost:3000/api/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Laptop",
    "description": "Gaming laptop",
    "price": 1299.99,
    "category": "electronics",
    "stock": 10
  }'

# Deploy to production
npm run build
npm run deploy:prod

# Test production (same handler!)
curl -X POST https://us-central1-myproject.cloudfunctions.net/createProduct \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Laptop",
    "description": "Gaming laptop",
    "price": 1299.99,
    "category": "electronics",
    "stock": 10
  }'
```

## Key Benefits

- **Same Code**: Handler works in both environments without changes
- **Fast Local Iteration**: Test with Fastify (~2x faster than emulator)
- **Production Ready**: Deploy to Cloud Functions with confidence
- **Type Safety**: Full TypeScript support preserved
- **Easy Testing**: Local testing before cloud deployment

## When to use

- Starting a new project with Noony
- Want complete local development environment
- Need reference implementation
- Learning the framework-agnostic pattern
