# Noony + Fastify Integration for Google Cloud Functions

This guide demonstrates how to integrate **Noony Serverless Framework** with **Fastify** using a simplified Clean Architecture approach to create high-performance, type-safe APIs for Google Cloud Functions and Cloud Run.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Complete Example Walkthrough](#complete-example-walkthrough)
- [Step-by-Step Implementation](#step-by-step-implementation)
- [Deployment Options](#deployment-options)
- [Production Considerations](#production-considerations)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

The combination of Noony and Fastify provides:

- 🚀 **High Performance**: Fastify's speed with Noony's middleware system
- 🛡️ **Type Safety**: Full TypeScript support throughout the stack
- 🔐 **Security**: Built-in authentication and validation middleware
- 🏗️ **Dependency Injection**: Clean separation of concerns with ports and adapters
- ☁️ **Cloud-Native**: Designed for serverless environments
- 📊 **Observability**: Structured logging and error handling


Install and use  `@noony-serverless/core` `0.0.4`. 

## Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GCP Cloud     │    │     Fastify     │    │      Noony      │
│   Functions     │───▶│     Server      │───▶│   Middleware    │
│                 │    │                 │    │     Chain       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────┐
                                              │   Chrome Layer  │
                                              │(Domain Business)│
                                              └─────────────────┘
                                                        │
                                                        ▼
                                              ┌─────────────────┐
                                              │ Infrastructure  │
                                              │    & Ports      │
                                              └─────────────────┘
```

## Project Structure

For a scalable Noony + Fastify project, we recommend the following simplified Clean Architecture structure:

```
my-noony-fastify-api/
├── package.json
├── tsconfig.json
├── jest.config.js
├── .env
├── .env.example
├── .gitignore
├── cloudbuild.yaml
├── Dockerfile
├── README.md
│
├── src/
│   ├── index.ts                    # Main entry point for Cloud Functions
│   │
│   ├── adapters/                   # External service adapters
│   │   ├── email.adapter.ts
│   │   ├── storage.adapter.ts
│   │   ├── crypto.adapter.ts
│   │   └── pubsub.adapter.ts
│   │
│   ├── chrome/                     # Main application layer
│   │   ├── domain/                 # Domain entities
│   │   │   ├── user.ts
│   │   │   ├── authToken.ts
│   │   │   └── index.ts
│   │   │
│   │   ├── handlers/               # Noony handlers (controllers)
│   │   │   ├── api/                # API route handlers
│   │   │   │   ├── userApi.ts
│   │   │   │   ├── authApi.ts
│   │   │   │   └── healthApi.ts
│   │   │   │
│   │   │   ├── dto/                # Data Transfer Objects
│   │   │   │   ├── user.dto.ts
│   │   │   │   ├── auth.dto.ts
│   │   │   │   └── common.dto.ts
│   │   │   │
│   │   │   ├── user.handlers.ts
│   │   │   ├── auth.handlers.ts
│   │   │   └── health.handlers.ts
│   │   │
│   │   ├── mappers/                # Domain ↔ DTO mappers
│   │   │   ├── userMapper.ts
│   │   │   ├── authMapper.ts
│   │   │   └── index.ts
│   │   │
│   │   ├── middleware/             # Custom Noony middlewares
│   │   │   ├── auth.middleware.ts
│   │   │   ├── validation.middleware.ts
│   │   │   ├── rateLimiting.middleware.ts
│   │   │   └── logging.middleware.ts
│   │   │
│   │   ├── routes/                 # Fastify route definitions
│   │   │   ├── user.route.ts
│   │   │   ├── auth.route.ts
│   │   │   ├── health.route.ts
│   │   │   └── index.ts
│   │   │
│   │   ├── services/               # Business logic services
│   │   │   ├── userService.ts
│   │   │   ├── authService.ts
│   │   │   ├── emailService.ts
│   │   │   └── index.ts
│   │   │
│   │   └── utils/                  # Chrome-specific utilities
│   │       ├── jwtUtil.ts
│   │       ├── passwordUtil.ts
│   │       └── validation.ts
│   │
│   ├── config/                     # Configuration
│   │   ├── container.ts            # Dependency injection
│   │   ├── environment.ts          # Environment variables
│   │   ├── database.ts             # Database config
│   │   └── server.ts               # Fastify server config
│   │
│   ├── infra/                      # Infrastructure layer
│   │   └── db/                     # Database layer
│   │       ├── schemas/            # Database schemas
│   │       │   ├── user.schema.ts
│   │       │   ├── token.schema.ts
│   │       │   └── index.ts
│   │       │
│   │       ├── mappers/            # DB ↔ Domain mappers
│   │       │   ├── user.mapper.ts
│   │       │   ├── token.mapper.ts
│   │       │   └── index.ts
│   │       │
│   │       ├── user.dao.ts         # Data Access Objects
│   │       ├── token.dao.ts
│   │       ├── firestore.dao.ts    # Base Firestore DAO
│   │       └── connection.ts       # Database connection
│   │
│   ├── port/                       # Ports (interfaces)
│   │   ├── user.port.ts            # User repository interface
│   │   ├── auth.port.ts            # Auth repository interface
│   │   ├── email.port.ts           # Email service interface
│   │   └── index.ts
│   │
│   ├── scripts/                    # Utility scripts
│   │   ├── generateToken.ts
│   │   ├── seedData.ts
│   │   └── migrate.ts
│   │
│   └── utils/                      # Global utilities
│       ├── logger.ts
│       ├── cors.ts
│       ├── uuid.util.ts
│       └── errors.ts
│
├── tests/                          # Tests
├── docs/                           # Documentation
└── deployment/                     # Deployment configs
```

### Directory Structure Explanation

#### Core Application (`src/`)

- **`index.ts`**: Main entry point for Cloud Functions. Exports the HTTP function and sets up Fastify server.

#### Adapters (`src/adapters/`)

External service implementations that implement port interfaces:
- Email services (SendGrid, SES)
- Storage services (GCS, S3)
- Cryptography services
- Event publishing services

#### Chrome Layer (`src/chrome/`)

The **main application layer** containing all business logic:

- **`domain/`**: Core business entities (User, AuthToken)
- **`handlers/`**: Noony handlers that act as controllers
- **`services/`**: Business logic and use case orchestration
- **`routes/`**: Fastify route definitions
- **`middleware/`**: Custom Noony middlewares
- **`mappers/`**: Transform data between layers
- **`utils/`**: Application-specific utilities

#### Infrastructure Layer (`src/infra/`)

Implementation details for data persistence:
- **`db/`**: Database access objects and schemas
- **`schemas/`**: Database-specific schemas
- **`mappers/`**: Transform between domain and database models

#### Ports (`src/port/`)

Interface contracts between chrome and infrastructure:
- Repository interfaces
- External service interfaces
- Enable dependency inversion and testing

#### Configuration (`src/config/`)

Environment-specific settings and dependency injection setup:
- Container configuration
- Database connections
- Server configuration

### Benefits of This Structure

1. **Simple & Clear**: Easy to navigate with logical groupings
2. **Separation of Concerns**: Each layer has a specific responsibility
3. **Testable**: Easy to mock dependencies via ports
4. **Maintainable**: Business logic is isolated in the chrome layer
5. **Type Safety**: Full TypeScript coverage across all layers
6. **Cloud-Native**: Optimized for serverless deployment patterns

## Complete Example Walkthrough

### Step 1: Define Domain Entity

**`src/chrome/domain/user.ts`**
```typescript
export class User {
  constructor(
    public readonly id: string,
    public readonly email: string,
    public readonly name: string,
    public readonly createdAt: Date,
    public readonly updatedAt: Date
  ) {}

  updateName(newName: string): User {
    return new User(
      this.id,
      this.email,
      newName,
      this.createdAt,
      new Date()
    );
  }

  static create(email: string, name: string): User {
    return new User(
      generateId(),
      email,
      name,
      new Date(),
      new Date()
    );
  }
}
```

### Step 2: Define Port Interface

**`src/port/user.port.ts`**
```typescript
import { User } from '../chrome/domain/user';

export interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  save(user: User): Promise<User>;
  update(id: string, updates: Partial<User>): Promise<User>;
  delete(id: string): Promise<void>;
  findAll(filters?: UserFilters): Promise<User[]>;
}

export interface IEmailService {
  sendWelcomeEmail(email: string, name: string): Promise<void>;
  sendPasswordResetEmail(email: string, token: string): Promise<void>;
}
```

### Step 3: Implement Business Service

**`src/chrome/services/userService.ts`**
```typescript
import { Service } from 'typedi';
import { IUserRepository, IEmailService } from '../../port';
import { User } from '../domain/user';
import { CreateUserDto } from '../handlers/dto/user.dto';

@Service()
export class UserService {
  constructor(
    private userRepository: IUserRepository,
    private emailService: IEmailService
  ) {}

  async createUser(userData: CreateUserDto): Promise<User> {
    // Business logic validation
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new Error('User already exists');
    }

    // Create domain entity
    const user = User.create(userData.email, userData.name);
    
    // Save to database
    const savedUser = await this.userRepository.save(user);
    
    // Send welcome email
    await this.emailService.sendWelcomeEmail(user.email, user.name);
    
    return savedUser;
  }

  async getUserById(id: string): Promise<User> {
    const user = await this.userRepository.findById(id);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  }

  async updateUser(id: string, updates: Partial<User>): Promise<User> {
    const user = await this.getUserById(id);
    return this.userRepository.update(id, updates);
  }
}
```

### Step 4: Create Noony Handler

**`src/chrome/handlers/user.handlers.ts`**
```typescript
import { NoonyHandler } from '@noony-org/core';
import { Container } from 'typedi';
import { UserService } from '../services/userService';
import { UserMapper } from '../mappers/userMapper';
import { CreateUserDto } from './dto/user.dto';

export const createUserHandler: NoonyHandler = async (context) => {
  const { body } = context;
  
  // Get service from container
  const userService = Container.get(UserService);
  
  // Validate and transform input
  const createUserDto = new CreateUserDto(body);
  
  // Execute business logic
  const user = await userService.createUser(createUserDto);
  
  // Transform response
  return {
    statusCode: 201,
    body: {
      data: UserMapper.toResponse(user),
      message: 'User created successfully'
    }
  };
};

export const getUserHandler: NoonyHandler = async (context) => {
  const { params } = context;
  const userService = Container.get(UserService);
  
  const user = await userService.getUserById(params.id);
  
  return {
    statusCode: 200,
    body: {
      data: UserMapper.toResponse(user)
    }
  };
};
```

### Step 5: Define DTOs

**`src/chrome/handlers/dto/user.dto.ts`**
```typescript
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  name: string;

  constructor(data: any) {
    this.email = data.email;
    this.name = data.name;
  }
}

export class UserResponseDto {
  id: string;
  email: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}
```

### Step 6: Create Mapper

**`src/chrome/mappers/userMapper.ts`**
```typescript
import { User } from '../domain/user';
import { UserResponseDto } from '../handlers/dto/user.dto';

export class UserMapper {
  static toResponse(user: User): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString()
    };
  }

  static fromRequest(data: any): User {
    return new User(
      data.id,
      data.email,
      data.name,
      new Date(data.createdAt),
      new Date(data.updatedAt)
    );
  }
}
```

### Step 7: Implement Infrastructure

**`src/infra/db/user.dao.ts`**
```typescript
import { Service } from 'typedi';
import { IUserRepository } from '../../port/user.port';
import { User } from '../../chrome/domain/user';
import { UserDbMapper } from './mappers/user.mapper';

@Service()
export class UserDAO implements IUserRepository {
  constructor(private db: FirestoreDatabase) {}

  async findById(id: string): Promise<User | null> {
    const doc = await this.db.collection('users').doc(id).get();
    return doc.exists ? UserDbMapper.toDomain(doc.data()) : null;
  }

  async findByEmail(email: string): Promise<User | null> {
    const snapshot = await this.db.collection('users')
      .where('email', '==', email)
      .limit(1)
      .get();
    
    if (snapshot.empty) return null;
    return UserDbMapper.toDomain(snapshot.docs[0].data());
  }

  async save(user: User): Promise<User> {
    const userData = UserDbMapper.toDatabase(user);
    await this.db.collection('users').doc(user.id).set(userData);
    return user;
  }

  async update(id: string, updates: Partial<User>): Promise<User> {
    const updateData = UserDbMapper.toDatabase(updates as User);
    await this.db.collection('users').doc(id).update(updateData);
    
    const updatedDoc = await this.db.collection('users').doc(id).get();
    return UserDbMapper.toDomain(updatedDoc.data()!);
  }

  async delete(id: string): Promise<void> {
    await this.db.collection('users').doc(id).delete();
  }

  async findAll(filters?: UserFilters): Promise<User[]> {
    let query = this.db.collection('users');
    
    if (filters?.email) {
      query = query.where('email', '==', filters.email);
    }
    
    const snapshot = await query.get();
    return snapshot.docs.map(doc => UserDbMapper.toDomain(doc.data()));
  }
}
```

### Step 8: Setup Routes

**`src/chrome/routes/user.route.ts`**
```typescript
import { FastifyInstance } from 'fastify';
import { createUserHandler, getUserHandler } from '../handlers/user.handlers';

export async function userRoutes(fastify: FastifyInstance) {
  // POST /users
  fastify.post('/users', {
    schema: {
      body: {
        type: 'object',
        required: ['email', 'name'],
        properties: {
          email: { type: 'string', format: 'email' },
          name: { type: 'string', minLength: 1 }
        }
      }
    },
    preHandler: [fastify.noonyMiddleware(createUserHandler)]
  });

  // GET /users/:id
  fastify.get('/users/:id', {
    schema: {
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' }
        }
      }
    },
    preHandler: [fastify.noonyMiddleware(getUserHandler)]
  });
}
```

### Step 9: Setup Dependency Injection

**`src/config/container.ts`**
```typescript
import { Container } from 'typedi';
import { UserDAO } from '../infra/db/user.dao';
import { EmailAdapter } from '../adapters/email.adapter';
import { IUserRepository, IEmailService } from '../port';

export function setupContainer() {
  // Register repository implementations
  Container.set('UserRepository', Container.get(UserDAO));
  Container.set('EmailService', Container.get(EmailAdapter));
  
  // Bind interfaces to implementations
  Container.set(IUserRepository, Container.get('UserRepository'));
  Container.set(IEmailService, Container.get('EmailService'));
}
```

### Step 10: Setup Server

**`src/config/server.ts`**
```typescript
import fastify from 'fastify';
import { NoonyCore } from '@noony-org/core';
import { setupContainer } from './container';
import { userRoutes } from '../chrome/routes/user.route';
import { authRoutes } from '../chrome/routes/auth.route';

export async function createServer() {
  const app = fastify({ 
    logger: true,
    disableRequestLogging: process.env.NODE_ENV === 'production'
  });

  // Setup dependency injection
  setupContainer();

  // Register Noony plugin
  await app.register(require('@noony-org/fastify-plugin'));

  // Setup middlewares
  await app.register(require('@fastify/cors'), {
    origin: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
  });

  // Register routes
  await app.register(userRoutes, { prefix: '/api/v1' });
  await app.register(authRoutes, { prefix: '/api/v1' });

  // Health check
  app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

  return app;
}
```

### Step 11: Cloud Function Entry Point

**`src/index.ts`**
```typescript
import { createServer } from './config/server';
import { logger } from './utils/logger';

let server: any;

export const api = async (req: any, res: any) => {
  if (!server) {
    try {
      server = await createServer();
      await server.ready();
      logger.info('Fastify server initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize server:', error);
      return res.status(500).send({ error: 'Server initialization failed' });
    }
  }

  return server.server.emit('request', req, res);
};

// For local development
if (require.main === module) {
  createServer().then(server => {
    server.listen({ port: 3000 }, (err, address) => {
      if (err) {
        logger.error(err);
        process.exit(1);
      }
      logger.info(`Server listening at ${address}`);
    });
  });
}
```

## Step-by-Step Implementation

### 1. Project Setup

```bash
npm init -y
npm install fastify @noony-org/core @noony-org/fastify-plugin
npm install -D typescript @types/node ts-node nodemon
npm install typedi class-validator class-transformer
npm install @google-cloud/firestore
```

### 2. TypeScript Configuration

**`tsconfig.json`**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### 3. Package.json Scripts

```json
{
  "scripts": {
    "dev": "nodemon --exec ts-node src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "deploy": "gcloud functions deploy api --runtime nodejs18 --trigger-http"
  }
}
```

## Deployment Options

### Cloud Functions

**`deployment/cloud-functions/main.yaml`**
```yaml
name: my-noony-api
runtime: nodejs18
trigger:
  httpsTrigger: {}
environmentVariables:
  NODE_ENV: production
  DATABASE_URL: your-firestore-url
```

### Cloud Run

**`deployment/cloud-run/main.yaml`**
```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: my-noony-api
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "100"
    spec:
      containers:
      - image: gcr.io/PROJECT_ID/my-noony-api
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: production
```

## Production Considerations

### 1. Environment Configuration

**`src/config/environment.ts`**
```typescript
export const config = {
  server: {
    port: process.env.PORT || 3000,
    host: process.env.HOST || '0.0.0.0'
  },
  database: {
    url: process.env.DATABASE_URL || 'firestore://localhost:8080',
    projectId: process.env.GCLOUD_PROJECT
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET,
    jwtExpiration: process.env.JWT_EXPIRATION || '24h'
  },
  cors: {
    origins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000']
  }
};
```

### 2. Error Handling

**`src/utils/errors.ts`**
```typescript
export class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number = 500,
    public code?: string
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class ValidationError extends AppError {
  constructor(message: string) {
    super(message, 400, 'VALIDATION_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string) {
    super(`${resource} not found`, 404, 'NOT_FOUND');
  }
}
```

### 3. Logging

**`src/utils/logger.ts`**
```typescript
import { createLogger, format, transports } from 'winston';

export const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' })
  ]
});
```

## Testing

### Unit Tests

**`tests/unit/chrome/services/userService.test.ts`**
```typescript
import { UserService } from '../../../../src/chrome/services/userService';
import { IUserRepository, IEmailService } from '../../../../src/port';

describe('UserService', () => {
  let userService: UserService;
  let mockUserRepository: jest.Mocked<IUserRepository>;
  let mockEmailService: jest.Mocked<IEmailService>;

  beforeEach(() => {
    mockUserRepository = {
      findById: jest.fn(),
      findByEmail: jest.fn(),
      save: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn()
    };
    
    mockEmailService = {
      sendWelcomeEmail: jest.fn(),
      sendPasswordResetEmail: jest.fn()
    };

    userService = new UserService(mockUserRepository, mockEmailService);
  });

  describe('createUser', () => {
    it('should create a new user when email is not taken', async () => {
      // Arrange
      mockUserRepository.findByEmail.mockResolvedValue(null);
      mockUserRepository.save.mockResolvedValue(mockUser);

      // Act
      const result = await userService.createUser(createUserDto);

      // Assert
      expect(mockUserRepository.save).toHaveBeenCalled();
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalled();
      expect(result).toEqual(mockUser);
    });
  });
});
```

### Integration Tests

**`tests/integration/userApi.test.ts`**
```typescript
import { createServer } from '../../src/config/server';
import { setupTestDatabase, cleanupTestDatabase } from '../helpers/testDatabase';

describe('User API Integration', () => {
  let app: any;

  beforeAll(async () => {
    await setupTestDatabase();
    app = await createServer();
  });

  afterAll(async () => {
    await cleanupTestDatabase();
    await app.close();
  });

  describe('POST /api/v1/users', () => {
    it('should create a new user', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/v1/users',
        payload: {
          email: 'test@example.com',
          name: 'Test User'
        }
      });

      expect(response.statusCode).toBe(201);
      expect(response.json().data).toMatchObject({
        email: 'test@example.com',
        name: 'Test User'
      });
    });
  });
});
```

## Troubleshooting

### Common Issues

1. **Cold Start Performance**: Use connection pooling and lazy initialization
2. **Memory Usage**: Monitor heap usage and optimize bundle size
3. **Timeout Issues**: Implement proper timeout handling for external services
4. **CORS Issues**: Configure CORS properly for your frontend domains

### Debug Configuration

**`.vscode/launch.json`**
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug API",
      "program": "${workspaceFolder}/src/index.ts",
      "outFiles": ["${workspaceFolder}/dist/**/*.js"],
      "runtimeArgs": ["-r", "ts-node/register"],
      "env": {
        "NODE_ENV": "development"
      }
    }
  ]
}
```

This simplified structure provides all the benefits of Clean Architecture while being easy to understand and maintain. The Noony + Fastify integration gives you high performance with excellent developer experience for building cloud-native APIs.