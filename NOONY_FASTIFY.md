# Noony + Fastify Integration for Google Cloud Functions

This guide demonstrates how to integrate **Noony Serverless Framework** with **Fastify** to create high-performance, type-safe APIs for Google Cloud Functions and Cloud Run.

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
- 🏗️ **Dependency Injection**: TypeDI integration for clean architecture
- ☁️ **Cloud-Native**: Designed for serverless environments
- 📊 **Observability**: Structured logging and error handling

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
                                              │   Business      │
                                              │     Logic       │
                                              └─────────────────┘
```

## Project Structure

For a scalable Noony + Fastify project, we recommend the following directory structure based on **Clean Architecture** principles:

```text
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
│   ├── index.ts                    # Main entry point (Cloud Function)
│   ├── server.ts                   # Fastify server setup
│   │
│   ├── handlers/                   # Noony handlers (controllers)
│   │   ├── index.ts
│   │   ├── users/
│   │   │   ├── createUser.handler.ts
│   │   │   ├── getUser.handler.ts
│   │   │   ├── updateUser.handler.ts
│   │   │   ├── deleteUser.handler.ts
│   │   │   └── listUsers.handler.ts
│   │   ├── auth/
│   │   │   ├── login.handler.ts
│   │   │   ├── register.handler.ts
│   │   │   └── refreshToken.handler.ts
│   │   └── health/
│   │       └── health.handler.ts
│   │
│   ├── middlewares/                # Custom Noony middlewares
│   │   ├── index.ts
│   │   ├── authentication.middleware.ts
│   │   ├── authorization.middleware.ts
│   │   ├── requestLogging.middleware.ts
│   │   ├── rateLimiting.middleware.ts
│   │   └── cors.middleware.ts
│   │
│   ├── schemas/                    # JSON schemas and validation
│   │   ├── index.ts
│   │   ├── users/
│   │   │   ├── createUser.schema.ts
│   │   │   ├── updateUser.schema.ts
│   │   │   └── userResponse.schema.ts
│   │   ├── auth/
│   │   │   ├── login.schema.ts
│   │   │   └── register.schema.ts
│   │   └── common/
│   │       ├── pagination.schema.ts
│   │       └── error.schema.ts
│   │
│   ├── domain/                     # Domain layer (business logic)
│   │   ├── entities/
│   │   │   ├── User.ts
│   │   │   ├── AuthToken.ts
│   │   │   └── index.ts
│   │   ├── repositories/           # Repository interfaces
│   │   │   ├── IUserRepository.ts
│   │   │   ├── ITokenRepository.ts
│   │   │   └── index.ts
│   │   ├── services/               # Domain services
│   │   │   ├── UserService.ts
│   │   │   ├── AuthService.ts
│   │   │   └── index.ts
│   │   └── exceptions/
│   │       ├── DomainException.ts
│   │       ├── UserNotFoundException.ts
│   │       └── index.ts
│   │
│   ├── infrastructure/             # Infrastructure layer
│   │   ├── database/
│   │   │   ├── firestore/
│   │   │   │   ├── FirestoreUserRepository.ts
│   │   │   │   ├── FirestoreTokenRepository.ts
│   │   │   │   └── connection.ts
│   │   │   └── mongodb/            # Alternative database implementation
│   │   │       ├── MongoUserRepository.ts
│   │   │       └── connection.ts
│   │   ├── external/               # External service integrations
│   │   │   ├── email/
│   │   │   │   ├── EmailService.ts
│   │   │   │   └── SendGridEmailService.ts
│   │   │   ├── storage/
│   │   │   │   ├── StorageService.ts
│   │   │   │   └── GcsStorageService.ts
│   │   │   └── pubsub/
│   │   │       ├── PubSubService.ts
│   │   │       └── GcpPubSubService.ts
│   │   └── monitoring/
│   │       ├── MetricsService.ts
│   │       └── LoggingService.ts
│   │
│   ├── presentation/               # Presentation layer
│   │   ├── routes/
│   │   │   ├── index.ts
│   │   │   ├── users.routes.ts
│   │   │   ├── auth.routes.ts
│   │   │   └── health.routes.ts
│   │   ├── dto/                    # Data Transfer Objects
│   │   │   ├── users/
│   │   │   │   ├── CreateUserDto.ts
│   │   │   │   ├── UpdateUserDto.ts
│   │   │   │   └── UserResponseDto.ts
│   │   │   └── auth/
│   │   │       ├── LoginDto.ts
│   │   │       └── RegisterDto.ts
│   │   └── transformers/           # Response transformers
│   │       ├── UserTransformer.ts
│   │       └── ErrorTransformer.ts
│   │
│   ├── application/                # Application layer (use cases)
│   │   ├── users/
│   │   │   ├── CreateUserUseCase.ts
│   │   │   ├── GetUserUseCase.ts
│   │   │   ├── UpdateUserUseCase.ts
│   │   │   ├── DeleteUserUseCase.ts
│   │   │   └── ListUsersUseCase.ts
│   │   ├── auth/
│   │   │   ├── LoginUseCase.ts
│   │   │   ├── RegisterUseCase.ts
│   │   │   └── RefreshTokenUseCase.ts
│   │   └── common/
│   │       ├── PaginationUseCase.ts
│   │       └── ValidationUseCase.ts
│   │
│   ├── config/                     # Configuration and environment
│   │   ├── index.ts
│   │   ├── database.config.ts
│   │   ├── auth.config.ts
│   │   ├── server.config.ts
│   │   └── environment.ts
│   │
│   ├── container/                  # Dependency injection container
│   │   ├── index.ts
│   │   ├── repositories.container.ts
│   │   ├── services.container.ts
│   │   └── usecases.container.ts
│   │
│   └── shared/                     # Shared utilities and types
│       ├── types/
│       │   ├── common.types.ts
│       │   ├── api.types.ts
│       │   └── index.ts
│       ├── utils/
│       │   ├── crypto.utils.ts
│       │   ├── date.utils.ts
│       │   ├── validation.utils.ts
│       │   └── index.ts
│       ├── constants/
│       │   ├── http.constants.ts
│       │   ├── error.constants.ts
│       │   └── index.ts
│       └── decorators/
│           ├── validate.decorator.ts
│           ├── authorize.decorator.ts
│           └── index.ts
│
├── deployment/                     # Deployment configurations
│   ├── cloud-functions/
│   │   ├── main.yaml
│   │   └── staging.yaml
│   ├── cloud-run/
│   │   ├── main.yaml
│   │   └── staging.yaml
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── scripts/
│       ├── deploy.sh
│       ├── migrate.sh
│       └── seed.sh
│
├── tests/                          # Test files
│   ├── unit/
│   │   ├── handlers/
│   │   ├── services/
│   │   ├── repositories/
│   │   └── middlewares/
│   ├── integration/
│   │   ├── api/
│   │   └── database/
│   ├── e2e/
│   │   ├── auth.e2e.test.ts
│   │   └── users.e2e.test.ts
│   ├── fixtures/
│   │   ├── users.fixture.ts
│   │   └── auth.fixture.ts
│   └── helpers/
│       ├── testDatabase.ts
│       ├── testServer.ts
│       └── mockServices.ts
│
├── docs/                           # Documentation
│   ├── api/
│   │   ├── openapi.yaml
│   │   └── postman-collection.json
│   ├── architecture/
│   │   ├── ADR-001-architecture-decisions.md
│   │   └── system-design.md
│   └── deployment/
│       ├── gcp-setup.md
│       └── monitoring.md
│
└── scripts/                        # Development and build scripts
    ├── build.sh
    ├── test.sh
    ├── lint.sh
    ├── dev.sh
    └── generate-docs.sh
```

### Directory Structure Explanation

#### Core Application (`src/`)

- **`index.ts`**: Main entry point for Cloud Functions. Exports the HTTP function and sets up Fastify server.
- **`server.ts`**: Fastify server configuration, plugin registration, and Noony middleware setup.

#### Handlers (`src/handlers/`)

Noony handlers act as **controllers** in the MVC pattern. They:

- Handle HTTP requests and responses
- Validate input using Noony middleware
- Delegate business logic to use cases
- Transform responses using DTOs

#### Middlewares (`src/middlewares/`)

Custom Noony middlewares for:

- Authentication and authorization
- Request logging and monitoring
- Rate limiting and security
- CORS and request preprocessing

#### Schemas (`src/schemas/`)

JSON Schema definitions for:

- Request validation (body, query parameters)
- Response serialization
- OpenAPI documentation generation

#### Domain Layer (`src/domain/`)

The **heart of your business logic**:

- **`entities/`**: Core business entities (User, AuthToken)
- **`repositories/`**: Repository interfaces (no implementation details)
- **`services/`**: Domain services with pure business logic
- **`exceptions/`**: Domain-specific exceptions

#### Infrastructure Layer (`src/infrastructure/`)

Implementation details for:

- **`database/`**: Database repositories (Firestore, MongoDB)
- **`external/`**: Third-party service integrations
- **`monitoring/`**: Logging and metrics implementation

#### Presentation Layer (`src/presentation/`)

HTTP-specific concerns:

- **`routes/`**: Fastify route definitions
- **`dto/`**: Data Transfer Objects for API contracts
- **`transformers/`**: Response transformation logic

#### Application Layer (`src/application/`)

**Use cases** that orchestrate:

- Domain services
- Repository operations
- Business workflows
- Transaction boundaries

#### Configuration (`src/config/`)

Environment-specific settings:

- Database connections
- Authentication settings
- Server configuration
- Feature flags

#### Dependency Injection (`src/container/`)

TypeDI container setup for:

- Repository implementations
- Service instances
- Use case orchestration

#### Shared (`src/shared/`)

Common utilities:

- **`types/`**: TypeScript type definitions
- **`utils/`**: Helper functions
- **`constants/`**: Application constants
- **`decorators/`**: Custom decorators

#### Testing (`tests/`)

Comprehensive test strategy:

- **`unit/`**: Isolated component testing
- **`integration/`**: Multi-component testing
- **`e2e/`**: End-to-end API testing
- **`fixtures/`**: Test data
- **`helpers/`**: Test utilities

#### Deployment (`deployment/`)

Infrastructure as Code:

- **`cloud-functions/`**: GCP Cloud Functions configs
- **`cloud-run/`**: GCP Cloud Run configs
- **`terraform/`**: Infrastructure provisioning
- **`scripts/`**: Deployment automation

### Benefits of This Structure

1. **Separation of Concerns**: Each layer has a single responsibility
2. **Testability**: Easy to unit test individual components
3. **Maintainability**: Clear boundaries between business logic and infrastructure
4. **Scalability**: New features follow established patterns
5. **Type Safety**: Full TypeScript coverage across all layers
6. **Cloud-Native**: Optimized for serverless deployment patterns

### Example Implementation Files

#### Handler Example (`src/handlers/users/createUser.handler.ts`)

```typescript
import { NoonyHandler } from "@noony-org/core";
import { Container } from "typedi";
import { CreateUserUseCase } from "../../application/users/CreateUserUseCase";
import { CreateUserDto } from "../../presentation/dto/users/CreateUserDto";

export const createUserHandler: NoonyHandler = async (context) => {
  const { body } = context;
  
  const createUserUseCase = Container.get(CreateUserUseCase);
  const createUserDto = new CreateUserDto(body);
  
  const user = await createUserUseCase.execute(createUserDto);
  
  return {
    statusCode: 201,
    body: { data: user, message: "User created successfully" }
  };
};
```

#### Server Setup (`src/server.ts`)

```typescript
import fastify from "fastify";
import { NoonyCore } from "@noony-org/core";
import { setupMiddleware } from "./middlewares";
import { setupRoutes } from "./presentation/routes";
import { setupContainer } from "./container";

export async function createServer() {
  const app = fastify({ logger: true });
  
  // Setup dependency injection
  setupContainer();
  
  // Setup Noony middleware
  setupMiddleware();
  
  // Setup Fastify routes
  await setupRoutes(app);
  
  return app;
}
```

#### Cloud Function Entry Point (`src/index.ts`)

```typescript
import { createServer } from "./server";
import { logger } from "./shared/utils/logger";

let server: any;

export const api = async (req: any, res: any) => {
  if (!server) {
    try {
      server = await createServer();
      await server.ready();
      logger.info("Fastify server initialized successfully");
    } catch (error) {
      logger.error("Failed to initialize server:", error);
      return res.status(500).send({ error: "Server initialization failed" });
    }
  }
  
  return server.server.emit("request", req, res);
};
```

This structure ensures your Noony + Fastify project is production-ready, maintainable, and follows industry best practices for serverless applications on Google Cloud Platform.
