# Complete Guide: Creating an Endpoint from Routing to MongoDB

Based on the comprehensive analysis of the convivencialdia-api codebase, here's a detailed guide for implementing endpoints following the established patterns and architecture.

## Architecture Overview

The system follows a clean layered architecture with dependency injection:

```
┌─────────────────┐
│   HTTP Routes   │ ← Request/Response handling, validation
├─────────────────┤
│   Service Layer │ ← Business logic, orchestration
├─────────────────┤
│ Repository Layer│ ← Data access, MongoDB operations
├─────────────────┤
│    MongoDB      │ ← Data persistence
└─────────────────┘
```

**Key Components:**

- **TypeDI Container** - Dependency injection management
- **Zod Schemas** - Input validation and type safety
- **Multi-tenant Architecture** - Tenant isolation at all layers
- **Unified Request/Response** - Works with both Fastify and Cloud Functions
- **Port-Adapter Pattern** - Abstracts infrastructure concerns from business logic

## Port-Adapter Pattern (Hexagonal Architecture)

The system implements the Port-Adapter pattern to decouple business logic from external infrastructure. This allows the same code to work with different adapters without changes.

### Concept

```text
┌─────────────────────────────────────────┐
│              Application Core           │
│  ┌─────────────────────────────────┐    │
│  │        Business Logic          │    │
│  │      (Services Layer)          │    │
│  └─────────────────────────────────┘    │
│              │        │                 │
│         ┌────▼────┐ ┌─▼────┐           │
│         │  PORT   │ │ PORT │           │
│         └─────────┘ └──────┘           │
└─────────────────────────────────────────┘
           │            │
    ┌──────▼──┐   ┌─────▼─────┐
    │ ADAPTER │   │  ADAPTER  │
    │(Fastify)│   │ (MongoDB) │
    └─────────┘   └───────────┘
```

### Server Adapters Example

**Port Interface (`src/types/server.types.ts`):**

```typescript
export interface ServerAdapter {
  start(): Promise<void>;
  stop(): Promise<void>;
  registerRoute(method: string, path: string, handler: RouteHandler): void;
}

export interface UnifiedRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, unknown>;
  params: Record<string, unknown>;
  body?: unknown;
  ip?: string;
  userAgent?: string;
  context?: unknown; // For authentication context
}

export interface UnifiedResponse {
  status(code: number): UnifiedResponse;
  json(data: unknown): void;
  send(data: unknown): void;
  header(name: string, value: string): UnifiedResponse;
  statusCode?: number;
}
```

**Fastify Adapter (`src/adapters/fastify.adapter.ts`):**

```typescript
export class FastifyAdapter implements ServerAdapter {
  private app: FastifyInstance;
  
  async start(): Promise<void> {
    await this.setupMiddleware();
    await this.app.listen({
      port: this.config.port,
      host: this.config.host,
    });
  }
  
  registerRoute(method: string, path: string, handler: RouteHandler): void {
    const fastifyHandler = async (request: FastifyRequest, reply: FastifyReply) => {
      const unifiedRequest = this.convertRequest(request);
      const unifiedResponse = this.convertResponse(reply);
      await handler(unifiedRequest, unifiedResponse);
    };
    
    this.app[method.toLowerCase()](path, fastifyHandler);
  }
  
  private convertRequest(request: FastifyRequest): UnifiedRequest {
    return {
      method: request.method,
      url: request.url,
      headers: request.headers as Record<string, string | string[]>,
      query: request.query as Record<string, unknown>,
      params: request.params as Record<string, unknown>,
      body: request.body,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    };
  }
  
  private convertResponse(reply: FastifyReply): UnifiedResponse {
    return {
      status: (code: number) => {
        reply.status(code);
        return this.convertResponse(reply);
      },
      json: (data: unknown) => reply.send(data),
      send: (data: unknown) => reply.send(data),
      header: (name: string, value: string) => {
        reply.header(name, value);
        return this.convertResponse(reply);
      },
      get statusCode() { return reply.statusCode; },
    };
  }
}
```

### Repository Port-Adapter Example

**Port Interface (`src/repositories/ports/session.repository.interface.ts`):**

```typescript
export interface ISessionRepository {
  create(session: SessionData): Promise<SessionDocument>;
  findBySessionId(sessionId: string): Promise<SessionDocument | null>;
  findByUserId(userId: string): Promise<SessionDocument[]>;
  findByRefreshToken(refreshToken: string): Promise<SessionDocument | null>;
  update(sessionId: string, updates: SessionUpdateData): Promise<SessionDocument | null>;
  delete(sessionId: string): Promise<boolean>;
  deleteByUserId(userId: string): Promise<number>;
  deactivate(sessionId: string): Promise<boolean>;
  cleanup(): Promise<number>;
}
```

**MongoDB Adapter (`src/repositories/adapters/mongo-session.repository.ts`):**

```typescript
export class MongoSessionRepository implements ISessionRepository {
  private collection: Collection<SessionDocument>;
  private logger: Logger;

  constructor(private db: Db) {
    this.collection = db.collection<SessionDocument>('sessions');
    this.logger = new Logger('MongoSessionRepository');
  }

  async create(sessionData: SessionData): Promise<SessionDocument> {
    try {
      const document = sessionDocumentSchema.parse({
        ...sessionData,
        createdAt: new Date(),
      });

      const result = await this.collection.insertOne(document);
      return { ...document, _id: result.insertedId.toString() };
    } catch (error) {
      this.logger.error('Failed to create session', { error, sessionData });
      throw error;
    }
  }

  async findByRefreshToken(refreshToken: string): Promise<SessionDocument | null> {
    try {
      return await this.collection.findOne({ refreshToken, isActive: true });
    } catch (error) {
      this.logger.error('Failed to find session by refresh token', { error });
      throw error;
    }
  }

  // ... other implementations
}
```

**Factory Pattern for Adapters (`src/repositories/session.repository.factory.ts`):**

```typescript
export class SessionRepositoryFactory {
  static create(config: SessionStorageConfig): ISessionRepository {
    switch (config.type) {
      case 'mongodb':
        return new MongoSessionRepository(config.database);
      case 'redis':
        return new RedisSessionRepository(config.redis);
      default:
        throw new Error(`Unsupported session storage type: ${config.type}`);
    }
  }
  
  static createMongoDB(database: Db): ISessionRepository {
    return new MongoSessionRepository(database);
  }
}
```

### Benefits of Port-Adapter Pattern

1. **Technology Independence**: Business logic doesn't depend on specific technologies
2. **Easy Testing**: Mock adapters for unit tests
3. **Deployment Flexibility**: Same code works with Fastify (dev) and Cloud Functions (prod)
4. **Adapter Swapping**: Switch from MongoDB to Redis without changing business logic
5. **Clean Boundaries**: Clear separation between business logic and infrastructure

### Usage in Route Handlers

Your route handlers work with unified interfaces, making them adapter-agnostic:

```typescript
export class ProductRoutes {
  async createProduct(req: UnifiedRequest, res: UnifiedResponse): Promise<void> {
    // This works identically whether running on:
    // - Fastify (development)
    // - Google Cloud Functions (production)
    // - AWS Lambda (if adapter is implemented)
    
    const user = req.context?.user;
    const productData = req.body;
    
    const result = await this.productService.createProduct(productData, user.tenantId, user.id);
    
    res.status(201).json({ success: true, data: result });
  }
}
```

## Step-by-Step Implementation Guide

### Step 1: Define Schemas

First, create validation schemas and document schemas:

**`src/schemas/product.schemas.ts`**
```typescript
import { z } from 'zod';

// Request validation schemas
export const createProductSchema = z.object({
  name: z.string().min(2).max(100),
  description: z.string().max(500).optional(),
  category: z.string().min(1),
  price: z.number().positive(),
  status: z.enum(['active', 'inactive']).default('active'),
});

export const updateProductSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  description: z.string().max(500).optional(),
  category: z.string().min(1).optional(),
  price: z.number().positive().optional(),
  status: z.enum(['active', 'inactive']).optional(),
});

export const listProductsQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  search: z.string().optional(),
  category: z.string().optional(),
  status: z.enum(['active', 'inactive']).optional(),
  sortBy: z.enum(['name', 'createdAt', 'price']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

// Response schemas
export const productResponseSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  category: z.string(),
  price: z.number(),
  status: z.enum(['active', 'inactive']),
  tenantId: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
});

// Type exports
export type CreateProductRequest = z.infer<typeof createProductSchema>;
export type UpdateProductRequest = z.infer<typeof updateProductSchema>;
export type ListProductsQuery = z.infer<typeof listProductsQuerySchema>;
export type ProductResponse = z.infer<typeof productResponseSchema>;
```

**Add to `src/schemas/document.schemas.ts`:**
```typescript
// Product document schema (MongoDB collection: products)
export const productDocumentSchema = z.object({
  _id: z.string().optional(),
  id: z.string(),
  name: z.string().min(2).max(100),
  description: z.string().max(500).optional(),
  category: z.string(),
  price: z.number().positive(),
  status: z.enum(['active', 'inactive']),
  tenantId: z.string(),
  createdBy: z.string(), // User ID
  createdAt: z.date(),
  updatedAt: z.date(),
});

// Add to indexes configuration
export const databaseIndexes = {
  // ... existing indexes
  products: [
    { fields: { id: 1 }, options: { unique: true } },
    { fields: { tenantId: 1 } },
    { fields: { category: 1, tenantId: 1 } },
    { fields: { status: 1, tenantId: 1 } },
    { fields: { createdAt: -1 } },
    { fields: { name: 1, tenantId: 1 } },
  ],
};

export type ProductDocument = z.infer<typeof productDocumentSchema>;
```

### Step 2: Create Repository

When creating repositories, follow the port-adapter pattern for better maintainability and testability.

**First, define the port interface (`src/repositories/ports/product.repository.interface.ts`):**

```typescript
export interface IProductRepository {
  create(productData: CreateProductData): Promise<ProductDocument>;
  findById(productId: string, tenantId: string): Promise<ProductDocument | null>;
  update(productId: string, tenantId: string, updates: UpdateProductData): Promise<ProductDocument | null>;
  delete(productId: string, tenantId: string): Promise<boolean>;
  list(filters: ProductQueryFilters, options: ProductListOptions): Promise<{ products: ProductDocument[]; total: number }>;
}

export interface CreateProductData {
  name: string;
  description?: string;
  category: string;
  price: number;
  status: 'active' | 'inactive';
  tenantId: string;
  createdBy: string;
}

export interface UpdateProductData {
  name?: string;
  description?: string;
  category?: string;
  price?: number;
  status?: 'active' | 'inactive';
}

export interface ProductQueryFilters {
  tenantId: string;
  search?: string;
  category?: string;
  status?: 'active' | 'inactive';
  createdBy?: string;
}

export interface ProductListOptions {
  page: number;
  limit: number;
  sortBy: 'name' | 'createdAt' | 'price';
  sortOrder: 'asc' | 'desc';
}
```

**Then, create the MongoDB adapter (`src/repositories/adapters/mongo-product.repository.ts`):**

```typescript
export class MongoProductRepository implements IProductRepository {
  private collection: Collection<ProductDocument>;
  private logger: Logger;

  constructor(private db: Db) {
    this.collection = db.collection<ProductDocument>('products');
    this.logger = new Logger('MongoProductRepository');
  }

  // Implementation methods...
}
```

**Create a factory (`src/repositories/product.repository.factory.ts`):**

```typescript
export class ProductRepositoryFactory {
  static create(config: { type: 'mongodb'; database: Db }): IProductRepository {
    switch (config.type) {
      case 'mongodb':
        return new MongoProductRepository(config.database);
      default:
        throw new Error(`Unsupported storage type: ${config.type}`);
    }
  }

  static createMongoDB(database: Db): IProductRepository {
    return new MongoProductRepository(database);
  }
}
```

**Legacy implementation for existing code (`src/repositories/product.repository.ts`):**

```typescript
// This class maintains backward compatibility while using the port-adapter pattern
export class ProductRepository implements IProductRepository {
  private adapter: IProductRepository;

  constructor(db: Db) {
    this.adapter = ProductRepositoryFactory.createMongoDB(db);
  }

  async create(productData: CreateProductData): Promise<ProductDocument> {
    return this.adapter.create(productData);
  }

  // Delegate all other methods to the adapter...
}
```

**Full MongoDB Implementation (`src/repositories/adapters/mongo-product.repository.ts`):**

```typescript
import { Db, Collection, Filter, UpdateFilter } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { ProductDocument, productDocumentSchema } from '../../schemas/document.schemas.js';
import { Logger } from '../../services/logger.service.js';
import { 
  IProductRepository, 
  CreateProductData, 
  UpdateProductData, 
  ProductQueryFilters, 
  ProductListOptions 
} from '../ports/product.repository.interface.js';

export class MongoProductRepository implements IProductRepository {
  private collection: Collection<ProductDocument>;
  private logger: Logger;

  constructor(private db: Db) {
    this.collection = db.collection<ProductDocument>('products');
    this.logger = new Logger('ProductRepository');
  }

  async create(productData: CreateProductData): Promise<ProductDocument> {
    try {
      const document: ProductDocument = productDocumentSchema.parse({
        id: uuidv4(),
        ...productData,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const result = await this.collection.insertOne(document);

      this.logger.info('Product created', {
        productId: document.id,
        name: document.name,
        tenantId: document.tenantId,
        createdBy: document.createdBy,
      });

      return { ...document, _id: result.insertedId.toString() };
    } catch (error) {
      this.logger.error('Failed to create product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productData,
      });
      throw error;
    }
  }

  async findById(productId: string, tenantId: string): Promise<ProductDocument | null> {
    try {
      const product = await this.collection.findOne({ 
        id: productId, 
        tenantId 
      });

      if (product) {
        this.logger.debug('Product found by ID', { productId, tenantId });
      }

      return product;
    } catch (error) {
      this.logger.error('Failed to find product by ID', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId,
        tenantId,
      });
      throw error;
    }
  }

  async update(
    productId: string,
    tenantId: string,
    updates: UpdateProductData
  ): Promise<ProductDocument | null> {
    try {
      const result = await this.collection.findOneAndUpdate(
        { id: productId, tenantId },
        {
          $set: {
            ...updates,
            updatedAt: new Date(),
          } as UpdateFilter<ProductDocument>['$set'],
        },
        { returnDocument: 'after' }
      );

      if (result) {
        this.logger.info('Product updated', {
          productId,
          tenantId,
          updatedFields: Object.keys(updates),
        });
      }

      return result;
    } catch (error) {
      this.logger.error('Failed to update product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId,
        tenantId,
      });
      throw error;
    }
  }

  async delete(productId: string, tenantId: string): Promise<boolean> {
    try {
      const result = await this.collection.deleteOne({ 
        id: productId, 
        tenantId 
      });

      this.logger.info('Product deletion attempted', {
        productId,
        tenantId,
        deleted: result.deletedCount > 0,
      });

      return result.deletedCount > 0;
    } catch (error) {
      this.logger.error('Failed to delete product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId,
        tenantId,
      });
      throw error;
    }
  }

  async list(
    filters: ProductQueryFilters,
    options: ProductListOptions
  ): Promise<{ products: ProductDocument[]; total: number }> {
    try {
      const query = this.buildQuery(filters);
      const sort = this.buildSort(options);
      const skip = (options.page - 1) * options.limit;

      const [products, total] = await Promise.all([
        this.collection
          .find(query)
          .sort(sort)
          .skip(skip)
          .limit(options.limit)
          .toArray(),
        this.collection.countDocuments(query),
      ]);

      this.logger.debug('Products listed', {
        filters,
        count: products.length,
        total,
      });

      return { products, total };
    } catch (error) {
      this.logger.error('Failed to list products', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        filters,
      });
      throw error;
    }
  }

  private buildQuery(filters: ProductQueryFilters): Filter<ProductDocument> {
    const query: Filter<ProductDocument> = {
      tenantId: filters.tenantId,
    } as Filter<ProductDocument>;

    if (filters.category) {
      query.category = filters.category;
    }

    if (filters.status) {
      query.status = filters.status;
    }

    if (filters.createdBy) {
      query.createdBy = filters.createdBy;
    }

    if (filters.search) {
      query.$or = [
        { name: { $regex: filters.search, $options: 'i' } },
        { description: { $regex: filters.search, $options: 'i' } },
      ];
    }

    return query;
  }

  private buildSort(options: ProductListOptions): Record<string, 1 | -1> {
    const sortOrder = options.sortOrder === 'asc' ? 1 : -1;
    return { [options.sortBy]: sortOrder };
  }
}
```

### Step 3: Create Service

**`src/services/product.service.ts`**
```typescript
import { ProductRepository } from '../repositories/product.repository.js';
import { Logger } from './logger.service.js';
import {
  CreateProductRequest,
  UpdateProductRequest,
  ProductResponse,
  ProductQueryFilters,
  ProductListOptions,
} from '../schemas/product.schemas.js';

export interface ProductServiceConfig {
  maxProductsPerTenant: number;
  allowedCategories: string[];
}

export class ProductService {
  private logger: Logger;

  constructor(
    private productRepository: ProductRepository,
    private config: ProductServiceConfig = {
      maxProductsPerTenant: 1000,
      allowedCategories: ['electronics', 'clothing', 'books', 'home', 'sports'],
    }
  ) {
    this.logger = new Logger('ProductService');
  }

  async createProduct(
    productData: CreateProductRequest,
    tenantId: string,
    userId: string
  ): Promise<{ success: boolean; data?: ProductResponse; error?: string }> {
    try {
      // Validate category
      if (!this.config.allowedCategories.includes(productData.category)) {
        return {
          success: false,
          error: `Invalid category. Allowed categories: ${this.config.allowedCategories.join(', ')}`,
        };
      }

      // Check tenant limits
      const { total } = await this.productRepository.list(
        { tenantId },
        { page: 1, limit: 1, sortBy: 'createdAt', sortOrder: 'desc' }
      );

      if (total >= this.config.maxProductsPerTenant) {
        return {
          success: false,
          error: `Maximum number of products (${this.config.maxProductsPerTenant}) reached for this tenant`,
        };
      }

      const product = await this.productRepository.create({
        ...productData,
        tenantId,
        createdBy: userId,
      });

      this.logger.info('Product created successfully', {
        productId: product.id,
        name: product.name,
        tenantId,
        createdBy: userId,
      });

      return {
        success: true,
        data: this.sanitizeProductForResponse(product),
      };
    } catch (error) {
      this.logger.error('Failed to create product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productData,
        tenantId,
        userId,
      });

      return {
        success: false,
        error: 'Failed to create product',
      };
    }
  }

  async getProduct(
    productId: string,
    tenantId: string
  ): Promise<ProductResponse | null> {
    try {
      const product = await this.productRepository.findById(productId, tenantId);
      
      if (!product) {
        return null;
      }

      return this.sanitizeProductForResponse(product);
    } catch (error) {
      this.logger.error('Failed to get product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId,
        tenantId,
      });
      throw error;
    }
  }

  async updateProduct(
    productId: string,
    updates: UpdateProductRequest,
    tenantId: string,
    userId: string
  ): Promise<{ success: boolean; data?: ProductResponse; error?: string }> {
    try {
      // Validate category if provided
      if (updates.category && !this.config.allowedCategories.includes(updates.category)) {
        return {
          success: false,
          error: `Invalid category. Allowed categories: ${this.config.allowedCategories.join(', ')}`,
        };
      }

      const product = await this.productRepository.update(productId, tenantId, updates);

      if (!product) {
        return {
          success: false,
          error: 'Product not found',
        };
      }

      this.logger.info('Product updated successfully', {
        productId,
        tenantId,
        updatedBy: userId,
        updatedFields: Object.keys(updates),
      });

      return {
        success: true,
        data: this.sanitizeProductForResponse(product),
      };
    } catch (error) {
      this.logger.error('Failed to update product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId,
        tenantId,
        updates,
      });

      return {
        success: false,
        error: 'Failed to update product',
      };
    }
  }

  async deleteProduct(
    productId: string,
    tenantId: string,
    userId: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const deleted = await this.productRepository.delete(productId, tenantId);

      if (!deleted) {
        return {
          success: false,
          error: 'Product not found',
        };
      }

      this.logger.info('Product deleted successfully', {
        productId,
        tenantId,
        deletedBy: userId,
      });

      return { success: true };
    } catch (error) {
      this.logger.error('Failed to delete product', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId,
        tenantId,
      });

      return {
        success: false,
        error: 'Failed to delete product',
      };
    }
  }

  async listProducts(
    filters: Omit<ProductQueryFilters, 'tenantId'>,
    options: ProductListOptions,
    tenantId: string
  ): Promise<{
    products: ProductResponse[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }> {
    try {
      const { products, total } = await this.productRepository.list(
        { ...filters, tenantId },
        options
      );

      return {
        products: products.map(product => this.sanitizeProductForResponse(product)),
        pagination: {
          page: options.page,
          limit: options.limit,
          total,
          totalPages: Math.ceil(total / options.limit),
        },
      };
    } catch (error) {
      this.logger.error('Failed to list products', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        filters,
        tenantId,
      });
      throw error;
    }
  }

  private sanitizeProductForResponse(product: any): ProductResponse {
    return {
      id: product.id,
      name: product.name,
      description: product.description,
      category: product.category,
      price: product.price,
      status: product.status,
      tenantId: product.tenantId,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
    };
  }
}
```

### Step 4: Create Route Handler

**`src/routes/product.routes.ts`**
```typescript
import { UnifiedRequest, UnifiedResponse } from '../types/server.types.js';
import { ProductService } from '../services/product.service.js';
import { UserContext } from '../services/user.service.js';
import {
  createProductSchema,
  updateProductSchema,
  listProductsQuerySchema,
} from '../schemas/product.schemas.js';
import { Logger } from '../services/logger.service.js';
import { Service } from 'typedi';

const logger = new Logger('ProductRoutes');

@Service()
export class ProductRoutes {
  constructor(private productService: ProductService) {}

  async createProduct(req: UnifiedRequest, res: UnifiedResponse): Promise<void> {
    try {
      const user = (req.context as { user?: UserContext })?.user;
      if (!user || !user.id) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
      }

      const parseResult = createProductSchema.safeParse(req.body);
      if (!parseResult.success) {
        logger.warn('Invalid create product request', {
          errors: parseResult.error.issues,
          userId: user.id,
        });

        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request data',
            details: parseResult.error.issues,
          },
        });
      }

      const result = await this.productService.createProduct(
        parseResult.data,
        user.tenantId,
        user.id
      );

      if (result.success) {
        logger.info('Product created successfully', {
          productId: result.data?.id,
          userId: user.id,
          tenantId: user.tenantId,
        });

        res.status(201).json({
          success: true,
          data: { product: result.data },
          message: 'Product created successfully',
        });
      } else {
        logger.warn('Product creation failed', {
          error: result.error,
          userId: user.id,
          tenantId: user.tenantId,
        });

        res.status(400).json({
          success: false,
          error: {
            code: 'CREATION_FAILED',
            message: result.error || 'Failed to create product',
          },
        });
      }
    } catch (error) {
      logger.error('Create product endpoint error', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        userId: (req.context as { user?: UserContext })?.user?.id,
      });

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    }
  }

  async getProduct(req: UnifiedRequest, res: UnifiedResponse): Promise<void> {
    try {
      const user = (req.context as { user?: UserContext })?.user;
      if (!user || !user.id) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
      }

      const productId = req.params?.productId as string;
      if (!productId) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Product ID is required',
          },
        });
      }

      const product = await this.productService.getProduct(productId, user.tenantId);

      if (!product) {
        return res.status(404).json({
          success: false,
          error: {
            code: 'PRODUCT_NOT_FOUND',
            message: 'Product not found',
          },
        });
      }

      logger.debug('Product retrieved successfully', {
        productId,
        userId: user.id,
        tenantId: user.tenantId,
      });

      res.status(200).json({
        success: true,
        data: { product },
      });
    } catch (error) {
      logger.error('Get product endpoint error', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId: req.params?.productId,
        userId: (req.context as { user?: UserContext })?.user?.id,
      });

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    }
  }

  async updateProduct(req: UnifiedRequest, res: UnifiedResponse): Promise<void> {
    try {
      const user = (req.context as { user?: UserContext })?.user;
      if (!user || !user.id) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
      }

      const productId = req.params?.productId as string;
      if (!productId) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Product ID is required',
          },
        });
      }

      const parseResult = updateProductSchema.safeParse(req.body);
      if (!parseResult.success) {
        logger.warn('Invalid update product request', {
          errors: parseResult.error.issues,
          productId,
          userId: user.id,
        });

        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request data',
            details: parseResult.error.issues,
          },
        });
      }

      const result = await this.productService.updateProduct(
        productId,
        parseResult.data,
        user.tenantId,
        user.id
      );

      if (result.success) {
        logger.info('Product updated successfully', {
          productId,
          userId: user.id,
          tenantId: user.tenantId,
        });

        res.status(200).json({
          success: true,
          data: { product: result.data },
          message: 'Product updated successfully',
        });
      } else {
        const statusCode = result.error === 'Product not found' ? 404 : 400;
        logger.warn('Product update failed', {
          error: result.error,
          productId,
          userId: user.id,
          tenantId: user.tenantId,
        });

        res.status(statusCode).json({
          success: false,
          error: {
            code: result.error === 'Product not found' ? 'PRODUCT_NOT_FOUND' : 'UPDATE_FAILED',
            message: result.error || 'Failed to update product',
          },
        });
      }
    } catch (error) {
      logger.error('Update product endpoint error', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId: req.params?.productId,
        userId: (req.context as { user?: UserContext })?.user?.id,
      });

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    }
  }

  async deleteProduct(req: UnifiedRequest, res: UnifiedResponse): Promise<void> {
    try {
      const user = (req.context as { user?: UserContext })?.user;
      if (!user || !user.id) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
      }

      const productId = req.params?.productId as string;
      if (!productId) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Product ID is required',
          },
        });
      }

      const result = await this.productService.deleteProduct(
        productId,
        user.tenantId,
        user.id
      );

      if (result.success) {
        logger.info('Product deleted successfully', {
          productId,
          userId: user.id,
          tenantId: user.tenantId,
        });

        res.status(200).json({
          success: true,
          message: 'Product deleted successfully',
        });
      } else {
        const statusCode = result.error === 'Product not found' ? 404 : 400;
        logger.warn('Product deletion failed', {
          error: result.error,
          productId,
          userId: user.id,
          tenantId: user.tenantId,
        });

        res.status(statusCode).json({
          success: false,
          error: {
            code: result.error === 'Product not found' ? 'PRODUCT_NOT_FOUND' : 'DELETE_FAILED',
            message: result.error || 'Failed to delete product',
          },
        });
      }
    } catch (error) {
      logger.error('Delete product endpoint error', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        productId: req.params?.productId,
        userId: (req.context as { user?: UserContext })?.user?.id,
      });

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    }
  }

  async listProducts(req: UnifiedRequest, res: UnifiedResponse): Promise<void> {
    try {
      const user = (req.context as { user?: UserContext })?.user;
      if (!user || !user.id) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
          },
        });
      }

      const parseResult = listProductsQuerySchema.safeParse(req.query);
      if (!parseResult.success) {
        logger.warn('Invalid list products request', {
          errors: parseResult.error.issues,
          userId: user.id,
        });

        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid query parameters',
            details: parseResult.error.issues,
          },
        });
      }

      const { page, limit, sortBy, sortOrder, ...filters } = parseResult.data;

      const result = await this.productService.listProducts(
        filters,
        { page, limit, sortBy, sortOrder },
        user.tenantId
      );

      logger.debug('Products listed successfully', {
        count: result.products.length,
        total: result.pagination.total,
        userId: user.id,
        tenantId: user.tenantId,
      });

      res.status(200).json({
        success: true,
        data: result,
      });
    } catch (error) {
      logger.error('List products endpoint error', {
        error: {
          name: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined,
        },
        userId: (req.context as { user?: UserContext })?.user?.id,
      });

      res.status(500).json({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: 'An unexpected error occurred',
        },
      });
    }
  }
}
```

### Step 5: Configure Dependency Injection

**Update `src/server.ts`:**
```typescript
// Add to imports
import { ProductRepository } from './repositories/product.repository.js';
import { ProductService } from './services/product.service.js';
import { ProductRoutes } from './routes/product.routes.js';

async function setupServer() {
  // ... existing setup code

  // Register product-related dependencies
  const productRepository = new ProductRepository(db);
  const productService = new ProductService(productRepository);
  
  Container.set(ProductRepository, productRepository);
  Container.set(ProductService, productService);

  // ... rest of setup
}

async function registerRoutes(server: FastifyAdapter) {
  // ... existing routes

  await registerProductRoutes(server);
}

async function registerProductRoutes(server: FastifyAdapter) {
  const productRoutes = Container.get(ProductRoutes);

  server.registerRoute(
    'POST',
    '/api/products',
    productRoutes.createProduct.bind(productRoutes)
  );
  server.registerRoute(
    'GET',
    '/api/products',
    productRoutes.listProducts.bind(productRoutes)
  );
  server.registerRoute(
    'GET',
    '/api/products/:productId',
    productRoutes.getProduct.bind(productRoutes)
  );
  server.registerRoute(
    'PUT',
    '/api/products/:productId',
    productRoutes.updateProduct.bind(productRoutes)
  );
  server.registerRoute(
    'DELETE',
    '/api/products/:productId',
    productRoutes.deleteProduct.bind(productRoutes)
  );

  logger.info('Product routes registered successfully');
}
```

## Best Practices & Conventions

### 1. **Error Handling**
- Always use try-catch blocks in route handlers
- Log errors with structured context
- Return consistent error response format
- Use specific error codes and HTTP status codes

### 2. **Validation**
- Use Zod schemas for all input validation
- Validate at the route layer before business logic
- Provide detailed error messages for validation failures
- Include field-specific error details

### 3. **Logging**
- Create service-specific loggers
- Include relevant context (userId, tenantId, resourceId)
- Log business events (create, update, delete operations)
- Use appropriate log levels (debug, info, warn, error)

### 4. **Multi-Tenancy**
- Always include tenantId in database queries
- Validate tenant access in all operations
- Include tenant isolation in database indexes
- Never expose data across tenants

### 5. **Security**
- Require authentication for all endpoints
- Extract user context from request
- Validate user permissions for operations
- Sanitize response data (remove sensitive fields)

### 6. **Database Operations**
- Use transactions for multi-collection operations
- Implement proper indexing for performance
- Handle MongoDB connection errors gracefully
- Use TTL indexes for temporary data

### 7. **Type Safety**
- Define TypeScript interfaces for all data structures
- Use Zod for runtime type validation
- Export types for use across the application
- Maintain consistency between schemas and interfaces

## Quick Checklist for New Endpoints

When implementing a new endpoint, follow this checklist:

- [ ] **Define Schemas** - Request, response, and document schemas with Zod
- [ ] **Create Repository** - Data access layer with proper error handling
- [ ] **Implement Service** - Business logic with validation and logging
- [ ] **Build Route Handler** - HTTP handling with authentication and validation
- [ ] **Register Dependencies** - Add to DI container in server.ts
- [ ] **Register Routes** - Add route registration function
- [ ] **Add Database Indexes** - Update document.schemas.ts indexes
- [ ] **Test Implementation** - Unit tests and integration tests
- [ ] **Update Documentation** - API documentation and endpoint list

## Testing with Port-Adapter Pattern

The port-adapter pattern makes testing much easier by allowing you to create mock implementations:

**Mock Repository for Testing (`src/repositories/adapters/mock-product.repository.ts`):**

```typescript
import { IProductRepository, CreateProductData, UpdateProductData, ProductQueryFilters, ProductListOptions } from '../ports/product.repository.interface.js';
import { ProductDocument } from '../../schemas/document.schemas.js';

export class MockProductRepository implements IProductRepository {
  private products: Map<string, ProductDocument> = new Map();
  
  async create(productData: CreateProductData): Promise<ProductDocument> {
    const product: ProductDocument = {
      id: `mock-${Date.now()}`,
      ...productData,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    this.products.set(product.id, product);
    return product;
  }
  
  async findById(productId: string, tenantId: string): Promise<ProductDocument | null> {
    const product = this.products.get(productId);
    return product && product.tenantId === tenantId ? product : null;
  }
  
  // ... other mock implementations
}
```

**Unit Test Example:**

```typescript
import { ProductService } from '../src/services/product.service.js';
import { MockProductRepository } from '../src/repositories/adapters/mock-product.repository.js';

describe('ProductService', () => {
  let productService: ProductService;
  let mockRepository: MockProductRepository;
  
  beforeEach(() => {
    mockRepository = new MockProductRepository();
    productService = new ProductService(mockRepository);
  });
  
  it('should create a product successfully', async () => {
    const productData = {
      name: 'Test Product',
      category: 'electronics',
      price: 99.99,
      status: 'active' as const,
    };
    
    const result = await productService.createProduct(
      productData,
      'tenant-123',
      'user-456'
    );
    
    expect(result.success).toBe(true);
    expect(result.data?.name).toBe('Test Product');
  });
});
```

## Implementation Checklist for Port-Adapter Pattern

When implementing new features with port-adapter pattern:

### Repository Layer

- [ ] **Define Port Interface** - Create interface in `ports/` directory
- [ ] **Implement MongoDB Adapter** - Create adapter in `adapters/` directory
- [ ] **Create Factory** - For creating different adapter implementations
- [ ] **Create Mock Adapter** - For testing purposes
- [ ] **Legacy Wrapper** - If needed for backward compatibility

### Service Layer

- [ ] **Use Port Interface** - Depend on interface, not concrete implementation
- [ ] **Inject via Constructor** - Use dependency injection for adapters
- [ ] **Mock in Tests** - Use mock adapters for unit testing

### Server Layer

- [ ] **Use Unified Interfaces** - Use UnifiedRequest/UnifiedResponse
- [ ] **Adapter-Agnostic Logic** - Write code that works with any server adapter
- [ ] **Register in DI Container** - Set up proper dependency injection

This comprehensive guide provides everything needed to implement new endpoints following the established patterns in the convivencialdia-api project, ensuring consistency, security, and maintainability.
